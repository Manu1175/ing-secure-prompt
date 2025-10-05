#!/usr/bin/env bash
set -euo pipefail
# ensure ARM shell
[ "$(uname -m)" = "arm64" ] || exec /usr/bin/arch -arm64 /bin/zsh -l

# ensure ARM brew python exists
command -v /opt/homebrew/bin/python3 >/dev/null \
  || { echo "Install ARM Homebrew python@3.12 first"; exit 1; }

# ensure venv
if [ ! -d .venv ]; then
  /opt/homebrew/bin/python3 -m venv .venv
fi
source .venv/bin/activate

# sanity echo
python - <<'PY'
import platform, sys
print("arch:", platform.machine(), "venv:", sys.prefix != sys.base_prefix)
PY
