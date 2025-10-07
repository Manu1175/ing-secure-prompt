#!/usr/bin/env bash
set -euo pipefail
MODEL=${MODEL:-gpt-5-codex}
PROMPT_FILE="prompts/guardrails.system.txt"

codex edit \
  --model "$MODEL" \
  --system "$(cat "$PROMPT_FILE")" \
  --config ./.codexrc.json \
  --truncate \
  "$@"
