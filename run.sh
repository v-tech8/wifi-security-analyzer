#!/bin/bash
# ============================================================
#  SecureNet Analyzer — Easy Run Script
#  Just double-click this file or run: bash run.sh
# ============================================================

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

echo ""
echo "============================================"
echo "   🛡️  SecureNet Wi-Fi Security Analyzer"
echo "============================================"

# ── 1. Find Python ──────────────────────────────────────────
PYTHON=""
for candidate in venv/bin/python3 venv/bin/python .venv/bin/python3 .venv/bin/python python3 python; do
    if [ -f "$PROJECT_DIR/$candidate" ] || command -v "$candidate" &>/dev/null; then
        PYTHON="$candidate"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo "❌ Python not found. Please install Python 3.9+"
    exit 1
fi

# ── 2. Create venv if missing ───────────────────────────────
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

PYTHON="$PROJECT_DIR/venv/bin/python"
PIP="$PROJECT_DIR/venv/bin/pip"

# ── 3. Install / update dependencies ────────────────────────
echo "📥 Installing dependencies (this only takes long on first run)..."
$PIP install -r requirements.txt -q

# ── 4. Train model if missing ────────────────────────────────
if [ ! -f "$PROJECT_DIR/model/wifi_risk_model.pkl" ]; then
    echo "🤖 Training ML model for the first time..."
    $PYTHON train_model.py
fi

# ── 5. Start the app ─────────────────────────────────────────
echo ""
echo "✅ Starting server at http://localhost:5001"
echo "   Open your browser and go to: http://localhost:5001"
echo "   Press Ctrl+C to stop."
echo ""
$PYTHON app.py
