import re, pathlib, sys

p = pathlib.Path("pyproject.toml")
b = p.read_bytes()

# 1) Decode robustly and force UTF-8 on write
try:
    text = b.decode("utf-8")
except UnicodeDecodeError as e:
    # Fallback: replace invalid bytes (likely stray high-bit chars)
    text = b.decode("utf-8", errors="replace")

# 2) Remove any stray "ml =" lines anywhere first (from earlier failed edits)
text = re.sub(r'(?m)^\s*ml\s*=\s*\[.*?\]\s*$', '', text)

# 3) Ensure the [project.optional-dependencies] section exists
if "[project.optional-dependencies]" not in text:
    text += "\n[project.optional-dependencies]\n"

# 4) Normalize that section and ensure EXACT ml line once
#    We capture the block content until the next [section] header.
pat = re.compile(r'(?ms)^(\[project\.optional-dependencies\]\s*)(.*?)(?=^\[)', re.M)
m = pat.search(text + "\n[__EOF__]\n")  # sentinel header at end
head, block = m.group(1), m.group(2)

# Remove any transformers/torch debris in the block and any existing ml line
lines = []
for ln in block.splitlines():
    if re.match(r'\s*ml\s*=', ln):
        continue
    if "transformers" in ln or "torch>=" in ln:
        # If these appear outside ml=..., they are debris from a broken edit
        continue
    lines.append(ln)

# Append the correct ml extra
lines = [ln for ln in lines if ln.strip() != ""] + [
    'ml = ["transformers>=4.40", "torch>=2; platform_system!=\'Darwin\'"]'
]
new_block = ("\n".join(lines).rstrip() + "\n")

# Rebuild file
text = text[:m.start(2)] + new_block + text[m.end(2):]

# 5) Write back as clean UTF-8
p.write_text(text, encoding="utf-8")
print("pyproject.toml repaired.")
