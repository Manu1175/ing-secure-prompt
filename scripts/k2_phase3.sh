#!/usr/bin/env bash
set -euo pipefail

file="README.md"
touch "$file"
if ! grep -q "Optional ML mode" "$file"; then
  cat >> "$file" <<'MD'

## Optional ML mode (K2)
- Set `SP_ENABLE_NER=1` to enable optional NER.
- Optional: `SP_NER_MODEL=dslim/bert-base-NER`
- Optional: `SP_CONF_FUSION=max|avg|weighted:0.7` (default `max`)
- Default behaviour is unchanged when ML is off. No model installs unless you explicitly opt in (`pip install -e .[ml]`).
MD
fi

git add "$file"
git commit -m "docs(K2): document optional NER mode and fusion" || echo "Nothing to commit."
echo "K2 Phase 3 OK"
