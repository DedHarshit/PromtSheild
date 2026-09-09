# PromptShield 🛡️

**Real-time AI data leakage prevention. Intercepts, tokenizes, and protects sensitive data before it reaches ChatGPT, Claude, or Gemini — without breaking your workflow.**

---

## What It Does

```
You type → "AWS key: AKIAIOSFODNN7EXAMPLE, email: john@corp.com"
              ↓
Extension intercepts BEFORE it leaves your browser
              ↓
Sends → "AWS key: [AWS_KEY_AB12], email: [EMAIL_CD34]"
              ↓
AI responds with tokens → Extension restores originals IN YOUR VIEW
              ↓
Your screen shows the real values. OpenAI never saw them.
```

**Also scans file uploads** (PDFs, text files, code files) before they're sent.

---

## Project Structure

```
promptshield/
├── extension/                  ← Chrome Extension (Load this in chrome://extensions)
│   ├── manifest.json           ← Extension config + permissions
│   ├── src/
│   │   ├── injected.js         ← ⭐ Core: overrides window.fetch in page context
│   │   ├── content_script.js   ← Bridges page ↔ extension, handles file uploads
│   │   └── background.js       ← Service worker: logs to backend, manages state
│   ├── popup/
│   │   ├── popup.html          ← Extension icon click UI
│   │   └── popup.js            ← Popup logic
│   └── icons/                  ← Extension icons
│
└── backend/                    ← Python FastAPI Server
    ├── main.py                 ← ⭐ API server + serves dashboard
    ├── requirements.txt
    └── static/
        └── index.html          ← ⭐ Admin dashboard (real-time, charts, policy)
```

---

## Quick Start

### Step 1 — Start the Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Visit → http://localhost:8000 (the dashboard)

### Step 2 — Load Chrome Extension

1. Open Chrome → go to `chrome://extensions`
2. Enable **Developer mode** (toggle, top right)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Pin PromptShield to toolbar

### Step 3 — Test It

1. Open [ChatGPT](https://chat.openai.com)
2. Type: `My AWS key is AKIAIOSFODNN7EXAMPLE and my email is test@company.com`
3. See the toast notification appear → "PromptShield — Data Tokenized"
4. Watch your dashboard at http://localhost:8000 update in real-time

---

## How Each File Works

### `extension/src/injected.js` (The Core)

This is the most important file. Chrome extensions run in an "isolated world" and can't override `window.fetch` directly. So `content_script.js` injects this as a `<script>` tag into the actual page, giving it access to the page's JavaScript context.

It:
- **Overrides `window.fetch`** and `XMLHttpRequest`
- Detects 12 types of sensitive data (API keys, SSNs, emails, JWTs, etc.)
- Replaces them with reversible tokens: `[EMAIL_AB12]`
- Stores `token → original` mapping in page memory
- Uses `MutationObserver` to restore tokens in the AI's response as it streams in
- Sends only metadata (no raw text) to `content_script.js` via `postMessage`

### `extension/src/content_script.js`

- Injects `injected.js` at `document_start` (before page JS runs)
- Listens for `postMessage` from `injected.js` → forwards to `background.js`
- **File upload interceptor**: watches for `<input type="file">` elements
- When a file is selected: reads it, scans for secrets, shows the redaction modal
- Shows the toast notification and warning modal UI

### `extension/src/background.js`

- Service worker (no DOM access)
- Receives `LOG_INCIDENT` messages from content scripts
- Generates anonymized user hash (stable per install, never real identity)
- POSTs metadata to FastAPI backend
- Updates the extension badge counter

### `backend/main.py`

FastAPI server with these endpoints:
- `POST /api/incident` — receive incident from extension
- `GET /api/incidents` — fetch all incidents for dashboard
- `GET /api/stats` — aggregate stats (totals, category breakdown, tool usage)
- `GET /api/stream` — Server-Sent Events for real-time dashboard updates
- `GET /api/policy` — get current protection settings
- `PUT /api/policy` — update protection settings
- `DELETE /api/incidents` — clear all data (for demos)

Uses SQLite (no external database needed). All data is stored in `promptshield.db`.

---

## Detection Patterns

| Type | Example | Severity |
|------|---------|----------|
| AWS Key | `AKIA...` | Critical |
| OpenAI Key | `sk-...` | Critical |
| Private Key | `-----BEGIN PRIVATE KEY-----` | Critical |
| Credit Card | `4111 1111 1111 1111` | Critical |
| SSN | `123-45-6789` | Critical |
| JWT Token | `eyJ...` | High |
| Password | `password=secret123` | High |
| API Secret | `api_key=abc...` | High |
| DB Connection | `postgresql://user:pass@...` | High |
| Email | `john@company.com` | Medium |
| Phone | `+1-555-123-4567` | Medium |
| IP Address | `192.168.1.1` | Low |

---

## Deploying to Production

### Backend (Railway / Render / Fly.io)

```bash
# Railway (easiest)
npm install -g @railway/cli
railway login
railway init
railway up
```

Change the CORS in `main.py` to your dashboard domain before deploying.

### Extension → Chrome Web Store

1. Zip the `extension/` folder
2. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
3. Upload the zip
4. Set your production backend URL in `background.js` as the default

---

## Demo Script (For Hackathon Stage)

```
1. Open ChatGPT → DevTools → Network tab visible on screen

2. Type: "My password=SuperSecret123 and AWS key AKIAIOSFODNN7EXAMPLE 
          are compromised. Email john@acme.com. Help me rotate them."

3. Show: Extension toast → "3 types detected · Risk: 90/100"

4. Show: Network tab → request body shows [PASSWORD_AB12], [AWS_KEY_CD34], [EMAIL_EF56]

5. ChatGPT responds → screen shows the REAL values (tokens restored by MutationObserver)

6. Open dashboard (http://localhost:8000) → incident logged live, charts updated

7. Upload a Python file containing: API_KEY="sk-abc123..."
   → Modal appears → "API_SECRET found in app.py"
   → Click "Redact & Upload" → redacted version sent

8. Show dashboard policy → change mode to "block" → demo it blocking a request
```

---

## Architecture Decision: Why Two JS Files?

**The problem:** Chrome extension content scripts run in an "isolated world". They share the DOM but NOT the JavaScript global scope with the page. So if content_script.js does `window.fetch = ...`, it only affects the extension's isolated world — ChatGPT's code still uses the real fetch.

**The solution:** Inject a `<script>` tag with `src = injected.js`. Scripts loaded this way run in the PAGE's context and can override the real `window.fetch`.

**Communication:** `injected.js` → `window.postMessage` → `content_script.js` → `chrome.runtime.sendMessage` → `background.js` → `fetch('/api/incident')` → Backend

This is the standard pattern for MV3 request interception.
