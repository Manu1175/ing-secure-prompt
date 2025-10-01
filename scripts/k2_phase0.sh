#!/usr/bin/env bash
set -euo pipefail

ensure_gitignore() {
  local f=".gitignore"
  touch "$f"
  add_line() { local line="$1"; grep -qxF "$line" "$f" || printf '%s\n' "$line" >> "$f"; }
  add_line "# Runtime outputs (K2 preflight)"
  add_line "data/**"
  add_line "data.redacted/**"
  add_line "reports/baseline_counts.json"
  add_line "reports/baseline_counts.csv"
  add_line "*.jsonl"
  add_line "*.sqlite"
  add_line "*.db"
}

fix_pyproject() {
  local f="pyproject.toml"
  [ -f "$f" ] || { echo "pyproject.toml not found"; exit 1; }
  cp "$f" "${f}.bak.k2phase0"

  # Remove any stray "ml = [ ... ]" line anywhere
  sed -E '/^[[:space:]]*ml[[:space:]]*= *\[/d' "$f" > "${f}.tmp1"

  # Ensure the section exists
  grep -q '^\[project.optional-dependencies\]' "${f}.tmp1" || printf '\n[project.optional-dependencies]\n' >> "${f}.tmp1"

  # Insert correct ML extra exactly once inside the section
  awk '
    BEGIN{inopt=0; inserted=0}
    function print_ml(){
      if (!inserted){
        print "ml = [\"transformers>=4.40\", \"torch>=2; platform_system!=\x27Darwin\x27\"]"
        inserted=1
      }
    }
    {
      if ($0 ~ /^\[project\.optional-dependencies\]/){ inopt=1; print; next }
      if (inopt && $0 ~ /^\[/){ if (!inserted) print_ml(); inopt=0 }
      print
    }
    END{ if (inopt && !inserted) print_ml() }
  ' "${f}.tmp1" > "${f}.fixed"

  mv "${f}.fixed" "$f"
  rm -f "${f}.tmp1"
}

ensure_gitignore
fix_pyproject

git add .gitignore pyproject.toml
git commit -m "chore(K2): preflight cleanup (pyproject optional ml extra + gitignore)" || echo "Nothing to commit; already clean."

echo "K2 Phase 0 OK"
