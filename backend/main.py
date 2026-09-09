"""
main.py — PromptShield FastAPI Backend

WHAT THIS SERVER DOES:
1. Receives incident metadata from the Chrome extension (POST /api/incident)
2. Stores in SQLite (no cloud needed for hackathon)
3. Serves incident data to the dashboard (GET /api/incidents, /api/stats)
4. Streams real-time updates via Server-Sent Events (GET /api/stream)
5. Manages org-level policy (GET/PUT /api/policy)
6. Serves the static dashboard files

PRIVACY NOTE:
This server NEVER receives raw sensitive text — only metadata.
The extension only sends: category names, risk scores, timestamps.
Real secrets are tokenized and stay in the user's browser.

RUN:
  pip install fastapi uvicorn
  python main.py
  → http://localhost:8000
"""

import asyncio
import json
import os
import sqlite3
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ─── DATABASE SETUP ───────────────────────────────────────────────────────────

DB_PATH = "promptshield.db"

def get_db():
    """Get a database connection. Always close after use."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    c = conn.cursor()

    # Incidents table — only metadata, never raw text
    c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_hash   TEXT NOT NULL,       -- anonymized user ID
            categories  TEXT NOT NULL,       -- JSON array: ["EMAIL", "API_KEY"]
            risk_score  INTEGER NOT NULL,    -- 0-100
            ai_tool     TEXT NOT NULL,       -- chatgpt, claude, gemini, etc.
            is_file     INTEGER DEFAULT 0,   -- 1 if this was a file upload
            file_type   TEXT,               -- pdf, txt, py, etc.
            action_taken TEXT DEFAULT 'tokenized',  -- tokenized, blocked, redacted
            timestamp   REAL NOT NULL       -- unix timestamp
        )
    """)

    # Policy table — org-level settings
    c.execute("""
        CREATE TABLE IF NOT EXISTS policy (
            org_id              TEXT PRIMARY KEY,
            mode                TEXT DEFAULT 'tokenize',    -- tokenize | warn | block
            risk_threshold      INTEGER DEFAULT 30,         -- minimum score to trigger
            block_file_uploads  INTEGER DEFAULT 0           -- 0=scan only, 1=block
        )
    """)

    # Insert default policy if not exists
    c.execute("INSERT OR IGNORE INTO policy VALUES ('default', 'tokenize', 30, 0)")

    conn.commit()
    conn.close()

# ─── PYDANTIC MODELS (Request/Response schemas) ───────────────────────────────

class IncidentCreate(BaseModel):
    user_hash: str = Field(..., description="Anonymized user ID from extension")
    categories: List[str] = Field(..., description="Types of data detected, e.g. ['EMAIL', 'API_KEY']")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score 0-100")
    ai_tool: str = Field(..., description="Which AI tool: chatgpt, claude, gemini, etc.")
    is_file: bool = Field(False, description="Was this a file upload?")
    file_type: Optional[str] = Field(None, description="File extension: pdf, txt, etc.")
    action_taken: str = Field("tokenized", description="What PromptShield did: tokenized/blocked/redacted")

class IncidentResponse(BaseModel):
    id: int
    user_hash: str
    categories: List[str]
    risk_score: int
    ai_tool: str
    is_file: bool
    file_type: Optional[str]
    action_taken: str
    timestamp: float

class PolicyUpdate(BaseModel):
    mode: str = Field("tokenize", description="tokenize | warn | block")
    risk_threshold: int = Field(30, ge=0, le=100)
    block_file_uploads: bool = False

# ─── APP SETUP ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs on startup
    init_db()
    print("✅ PromptShield backend started")
    print("📊 Dashboard: http://localhost:8000")
    print("📡 API docs:  http://localhost:8000/docs")
    yield
    # Runs on shutdown
    print("Shutting down...")

app = FastAPI(
    title="PromptShield API",
    description="Backend for PromptShield browser extension",
    version="1.0.0",
    lifespan=lifespan,
)

# Allow requests from Chrome extension (which has no "origin" in the usual sense)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production: restrict to your dashboard domain
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def row_to_incident(row) -> dict:
    """Convert a database row to a dict, parsing JSON fields."""
    return {
        "id": row["id"],
        "user_hash": row["user_hash"],
        "categories": json.loads(row["categories"]),
        "risk_score": row["risk_score"],
        "ai_tool": row["ai_tool"],
        "is_file": bool(row["is_file"]),
        "file_type": row["file_type"],
        "action_taken": row["action_taken"],
        "timestamp": row["timestamp"],
    }

# ─── API ROUTES ───────────────────────────────────────────────────────────────

@app.post("/api/incident", summary="Log an incident from the extension")
async def log_incident(incident: IncidentCreate):
    """
    Called by the Chrome extension when it detects and tokenizes sensitive data.
    Only receives metadata — no raw sensitive text ever stored here.
    """
    conn = get_db()
    try:
        cursor = conn.execute(
            """INSERT INTO incidents
               (user_hash, categories, risk_score, ai_tool, is_file, file_type, action_taken, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                incident.user_hash,
                json.dumps(incident.categories),
                incident.risk_score,
                incident.ai_tool,
                int(incident.is_file),
                incident.file_type,
                incident.action_taken,
                time.time(),
            )
        )
        conn.commit()
        incident_id = cursor.lastrowid
    finally:
        conn.close()

    return {"status": "logged", "id": incident_id}


@app.get("/api/incidents", summary="Get recent incidents for dashboard")
async def get_incidents(limit: int = 100, tool: Optional[str] = None):
    """Returns recent incidents, optionally filtered by AI tool."""
    conn = get_db()
    try:
        if tool:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE ai_tool=? ORDER BY timestamp DESC LIMIT ?",
                (tool, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            ).fetchall()
    finally:
        conn.close()

    return [row_to_incident(r) for r in rows]


@app.get("/api/stats", summary="Get aggregate statistics")
async def get_stats():
    """Returns summary stats for the dashboard overview cards."""
    conn = get_db()
    try:
        total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        file_count = conn.execute("SELECT COUNT(*) FROM incidents WHERE is_file=1").fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM incidents WHERE action_taken='blocked'").fetchone()[0]
        avg_risk = conn.execute("SELECT AVG(risk_score) FROM incidents").fetchone()[0] or 0

        # Count by tool
        tool_rows = conn.execute(
            "SELECT ai_tool, COUNT(*) as cnt FROM incidents GROUP BY ai_tool"
        ).fetchall()
        tool_breakdown = {r["ai_tool"]: r["cnt"] for r in tool_rows}

        # Count by category (flatten the JSON arrays)
        cat_rows = conn.execute("SELECT categories FROM incidents").fetchall()
        category_counts = {}
        for row in cat_rows:
            for cat in json.loads(row["categories"]):
                category_counts[cat] = category_counts.get(cat, 0) + 1

        # Recent 24h
        since = time.time() - 86400
        recent_24h = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE timestamp > ?", (since,)
        ).fetchone()[0]

    finally:
        conn.close()

    return {
        "total_incidents": total,
        "file_incidents": file_count,
        "text_incidents": total - file_count,
        "blocked_incidents": blocked,
        "avg_risk_score": round(avg_risk, 1),
        "incidents_last_24h": recent_24h,
        "tool_breakdown": tool_breakdown,
        "category_breakdown": category_counts,
    }


@app.get("/api/policy", summary="Get current protection policy")
async def get_policy():
    """Returns the current org-level protection settings."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM policy WHERE org_id='default'"
        ).fetchone()
    finally:
        conn.close()

    return {
        "mode": row["mode"],
        "risk_threshold": row["risk_threshold"],
        "block_file_uploads": bool(row["block_file_uploads"]),
    }


@app.put("/api/policy", summary="Update protection policy")
async def update_policy(policy: PolicyUpdate):
    """Updates the org-level protection settings."""
    valid_modes = {"tokenize", "warn", "block"}
    if policy.mode not in valid_modes:
        raise HTTPException(400, f"mode must be one of: {valid_modes}")

    conn = get_db()
    try:
        conn.execute(
            "UPDATE policy SET mode=?, risk_threshold=?, block_file_uploads=? WHERE org_id='default'",
            (policy.mode, policy.risk_threshold, int(policy.block_file_uploads))
        )
        conn.commit()
    finally:
        conn.close()

    return {"status": "updated", "policy": policy.dict()}


@app.delete("/api/incidents", summary="Clear all incidents (for demo reset)")
async def clear_incidents():
    """Clears all incidents. Useful for resetting during demos."""
    conn = get_db()
    try:
        conn.execute("DELETE FROM incidents")
        conn.commit()
    finally:
        conn.close()
    return {"status": "cleared"}


# ─── SERVER-SENT EVENTS (Real-time dashboard updates) ────────────────────────

@app.get("/api/stream", summary="Real-time incident stream (SSE)")
async def stream_incidents():
    """
    Server-Sent Events endpoint. The dashboard connects here and receives
    new incidents in real-time as they come in from the extension.

    SSE format:
      data: {"id": 1, "categories": [...], ...}\n\n
    """
    async def event_generator():
        last_id = 0

        # Get the latest ID on connect (so we don't replay old events)
        conn = get_db()
        row = conn.execute("SELECT MAX(id) FROM incidents").fetchone()
        last_id = row[0] or 0
        conn.close()

        yield f"data: {json.dumps({'type': 'connected'})}\n\n"

        while True:
            await asyncio.sleep(1)
            conn = get_db()
            try:
                rows = conn.execute(
                    "SELECT * FROM incidents WHERE id > ? ORDER BY id ASC",
                    (last_id,)
                ).fetchall()
            finally:
                conn.close()

            for row in rows:
                last_id = row["id"]
                incident = row_to_incident(row)
                incident["type"] = "incident"
                yield f"data: {json.dumps(incident)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Important for Nginx proxy
        }
    )

# ─── SERVE STATIC DASHBOARD ───────────────────────────────────────────────────

# This must come AFTER all API routes
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Auto-reload on code changes during development
    )
