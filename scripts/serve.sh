#!/usr/bin/env bash
set -euo pipefail

# free ports 8000–8003 (graceful then force)
for p in 8000 8001 8002 8003; do
  lsof -tiTCP:$p -sTCP:LISTEN | xargs -r kill -15 || true
done
sleep 1
for p in 8000 8001 8002 8003; do
  lsof -tiTCP:$p -sTCP:LISTEN | xargs -r kill -9 || true
done

export UI_BUILD_ID="$(date +%Y%m%d-%H%M%S)"
export PYTHONPATH=.

python -m uvicorn api.main:app \
  --host 127.0.0.1 --port 8000 \
  --reload \
  --reload-include '*.html' \
  --reload-include '*.py'
