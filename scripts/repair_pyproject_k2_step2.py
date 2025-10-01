import re, pathlib

p = pathlib.Path("pyproject.toml")
txt = p.read_text(encoding="utf-8", errors="replace")

# Find [project.optional-dependencies] block
pat = re.compile(r'(?ms)^(\[project\.optional-dependencies\]\s*)(.*?)(?=^\[)', re.M)
m = pat.search(txt + "\n[__EOF__]\n")
if not m:
    raise SystemExit("optional-dependencies section not found")

head, block = m.group(1), m.group(2)

# 1) Drop any completely stray lines that are just ']' or '],'
clean_lines = []
open_depth = 0
for ln in block.splitlines():
    # crude bracket balance for multi-line arrays
    opens = ln.count('[')
    closes = ln.count(']')
    # if the line is ONLY a closing bracket and we're not inside an array, skip it
    if ln.strip() in {']', '],'} and open_depth == 0:
        continue
    clean_lines.append(ln)
    open_depth += opens - closes
    if open_depth < 0:
        open_depth = 0

block = "\n".join(clean_lines)

# 2) Remove any misplaced ml lines or debris
block = re.sub(r'(?m)^\s*ml\s*=\s*\[.*?\]\s*$', '', block)
block = "\n".join([ln for ln in block.splitlines() if not (
    "transformers" in ln or "torch>=" in ln
) or "ml =" in ln])

# 3) Ensure the correct ml extra appears exactly once at the end of the block
lines = [ln for ln in block.splitlines() if ln.strip() != ""]
ml_line = 'ml = ["transformers>=4.40", "torch>=2; platform_system!=\'Darwin\'"]'
if not any(re.match(r'\s*ml\s*=', ln) for ln in lines):
    lines.append(ml_line)
else:
    # replace any existing ml line with the canonical one
    lines = [ml_line if re.match(r'\s*ml\s*=', ln) else ln for ln in lines]

new_block = ("\n".join(lines).rstrip() + "\n")
txt = txt[:m.start(2)] + new_block + txt[m.end(2):]

p.write_text(txt, encoding="utf-8")
print("pyproject.toml: stray bracket removed and ml extra normalised.")
