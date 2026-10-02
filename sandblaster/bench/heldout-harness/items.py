#!/usr/bin/env python3
"""items.py: copy module-level functions out of a Rust file, verbatim.

  items.py FILE NAME[,NAME..] [--helpers] [--label PATH]
      print the items (with their doc comments and attributes)

H2's sampled functions live in files that need their crates' dependencies
(utils/src/rng.rs imports rand), so the held-out harness compiles each
sampled function's own text, copied out of its file: the unmodified source
for the rustc subject, the lowered copy for the optimized one. The only
edit is dropping `#[stability(..)]`, a commonware_macros attribute that
gates an item behind a cfg and has no effect on its code. `--helpers` also
copies every `__sandblaster_opt_*` helper the lowering appended (the
optimized subject's rewritten bodies call them).
"""
import re
import sys


def strip(text):
    """The text with comments, strings and char literals blanked (same length)."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        elif c == "'" and re.match(r"'(\\.|[^\\'])'", text[i : i + 4]):
            m = re.match(r"'(\\.|[^\\'])'", text[i : i + 4])
            for k in range(i + 1, i + m.end() - 1):
                out[k] = " "
            i += m.end()
        else:
            i += 1
    return "".join(out)


def item(text, name):
    """(start, end) of the module-level fn `name`, docs and attributes included."""
    s = strip(text)
    m = re.search(r"(?m)^(pub(\([^)]*\))? )?(const )?(unsafe )?fn " + re.escape(name) + r"\b", s)
    if not m:
        raise SystemExit(f"no module-level fn {name}")
    start = m.start()
    lines = text[:start].split("\n")[:-1]
    while lines and re.match(r"^\s*(///|#\[)", lines[-1]):
        lines.pop()
    start = sum(len(l) + 1 for l in lines)
    depth, i = 0, s.index("{", m.end())
    while True:
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return start, i + 1
        i += 1


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("names")
    ap.add_argument("--helpers", action="store_true")
    ap.add_argument("--label", help="the path named in the header (default: FILE)")
    a = ap.parse_args()
    path, names = a.file, a.names.split(",")
    text = open(path).read()
    if a.helpers:
        names += sorted(set(re.findall(r"(?m)^\s*(?:pub(?:\([^)]*\))? )?(?:const )?fn (__sandblaster_opt_\w+)", strip(text))))
    out = []
    for n in names:
        lo, hi = item(text, n)
        body = "\n".join(l for l in text[lo:hi].split("\n") if not re.match(r"^\s*#\[stability\(", l))
        out.append(body)
    print(f"// copied verbatim from {a.label or path} by items.py (only `#[stability(..)]` dropped)")
    print("\n\n".join(out))


if __name__ == "__main__":
    main()
