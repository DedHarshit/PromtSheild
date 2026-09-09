#!/bin/bash
# PromptShield — Complete Setup Script
# Run this once to install dependencies and start the backend.
# Then load the extension in Chrome manually.

set -e

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║         PromptShield Setup                 ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# ── BACKEND SETUP ─────────────────────────────────────────────────
echo "📦 Installing Python dependencies..."
cd "$(dirname "$0")/backend"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
  python3 -m venv venv
  echo "  ✓ Virtual environment created"
fi

# Activate and install
source venv/bin/activate
pip install -r requirements.txt -q
echo "  ✓ Dependencies installed"

# ── START BACKEND ─────────────────────────────────────────────────
echo ""
echo "🚀 Starting backend server..."
echo "  → Dashboard: http://localhost:8000"
echo "  → API Docs:  http://localhost:8000/docs"
echo ""
echo "─────────────────────────────────────────────"
echo "📌 CHROME EXTENSION SETUP (do this once):"
echo "  1. Open Chrome → chrome://extensions"
echo "  2. Enable 'Developer mode' (top right toggle)"
echo "  3. Click 'Load unpacked'"
echo "  4. Select the 'extension/' folder"
echo "  5. Pin PromptShield to your toolbar"
echo "  6. Open ChatGPT → type something with a secret"
echo "─────────────────────────────────────────────"
echo ""

# Start the server
python3 main.py
