#!/bin/sh
# Fly.io injects $PORT; the app reads $TQ_PORT. Bridge them.
export TQ_PORT=${PORT:-8080}
export TQ_HOST=0.0.0.0
# Persist data on the Fly volume mounted at /data
export TQ_DATA_PATH=/data/store.json
mkdir -p /data

# Use gunicorn for production (already in requirements)
exec gunicorn app:app --bind 0.0.0.0:${TQ_PORT} --workers 1 --timeout 120
