#!/bin/bash
# Thirsty Quench — persistent launcher for Linux (mounted at /mnt)
set -euo pipefail
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$APP_DIR"
export TQ_PORT="${TQ_PORT:-5050}"
export TQ_HOST="${TQ_HOST:-0.0.0.0}"
export TQ_DATA_PATH="${TQ_DATA_PATH:-data/store.json}"
VENV=".venv"
PYTHON="$VENV/bin/python"
if [ ! -f "$PYTHON" ]; then
  echo "⚠ Venv not found — creating..."
  python3 -m venv "$VENV"
  "$PYTHON" -m pip install --quiet flask flask-talisman flask-limiter werkzeug openpyxl gunicorn flask-cors python-dotenv pyngrok twilio requests pillow 2>&1 | tail -3
  echo "✓ Venv ready."
fi
if ! "$PYTHON" -c "import flask, flask_talisman" >/dev/null 2>&1; then
  "$PYTHON" -m pip install --quiet flask flask-talisman flask-limiter werkzeug openpyxl gunicorn flask-cors python-dotenv pyngrok twilio requests pillow 2>&1 | tail -3
fi
PIDFILE="/tmp/tq_webapp.pid"
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "⏱ Server already running (PID $(cat "$PIDFILE")) on port $TQ_PORT"
  exit 0
fi
echo "🌐 Launching Thirsty Quench on $TQ_HOST:$TQ_PORT ..."
nohup "$PYTHON" app.py > tq_run.log 2>&1 &
echo $! > "$PIDFILE"
sleep 2
if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "✅ Running — PID $(cat "$PIDFILE")"
  echo "   Local: http://127.0.0.1:$TQ_PORT"
  echo "   LAN:   http://$(hostname -I 2>/dev/null | awk '{print $1}'):$TQ_PORT"
  echo "   Stop:  kill $(cat "$PIDFILE")"
else
  echo "❌ Failed. Log:"
  tail -20 tq_run.log
  rm -f "$PIDFILE"
  exit 1
fi
