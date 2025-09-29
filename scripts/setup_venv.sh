#!/usr/bin/env bash
set -e
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -r requirements.txt
echo "✅ Virtual env ready. Activate with: source ./.venv/bin/activate"
