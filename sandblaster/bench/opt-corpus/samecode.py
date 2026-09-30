#!/usr/bin/env python3
"""samecode.py BIN: for every probe of the corpus harness binary, whether the current emission
(`cgen::probe::F`) and the O1 emission (`cgen_o1::probe::F`) compiled to the same machine code,
following calls into each emission's own crate. Prints JSON {"F": true | false}.

The timings of such a pair differ by code placement alone, so `run.sh` uses this to mark the
rows of gains.md that measure placement noise (the noise floor of that binary) rather than an
optimizer change. Instructions are compared after normalization: addresses dropped (branch
targets become offsets within the function), crate hashes and the crate names `cgen`/`cgen_o1`
unified, `nop` padding (alignment) dropped. Anything else, e.g. a different constant-pool
offset, counts as different code (conservative).
"""
import json
import re
import subprocess
import sys

OBJDUMP = "objdump"
FN = re.compile(r"^([0-9a-f]+) <(.+)>:$")
INS = re.compile(r"^\s*([0-9a-f]+):\s+(.*)$")
PROBE = re.compile(r"Cs[0-9A-Za-z]+_(4cgen|7cgen_o1)5probe(\d+)([0-9A-Za-z_]+)$")
CRATE = re.compile(r"Cs[0-9A-Za-z]+_(?:4cgen|7cgen_o1)(?=[0-9A-Z_]|$)")
REF = re.compile(r"(?:0x[0-9a-f]+ )?<([^>+]+)(\+0x[0-9a-f]+)?>")


def functions(binary):
    text = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", binary], capture_output=True, text=True, check=True).stdout
    fns, cur = {}, None
    for line in text.splitlines():
        m = FN.match(line)
        if m:
            cur = m.group(2)
            fns[cur] = []
            continue
        m = INS.match(line)
        if m and cur is not None:
            fns[cur].append(m.group(2).split(";")[0].strip())
    return fns


def crate_of(sym):
    m = re.search(r"_(4cgen|7cgen_o1)(?=[0-9A-Z_]|$)", sym)
    return m.group(1) if m else None


def normalize(sym, body):
    """(normalized instructions, [callee symbols in the same emission crate])"""
    out, calls = [], []
    for ins in body:
        if ins == "nop":
            continue
        refs = []

        def ref(m):
            target, off = m.group(1), m.group(2) or ""
            if target == sym:
                return f"<self{off}>"
            if crate_of(target) == crate_of(sym):
                refs.append(target)
            return f"<{CRATE.sub('CRATE', target)}{off}>"

        ins = REF.sub(ref, ins)
        ins = re.sub(r"^(adrp\s+\w+), 0x[0-9a-f]+", r"\1, PAGE", ins)
        out.append(ins)
        if re.match(r"^(bl|b)\s", ins):
            calls.extend(refs)
    return out, calls


def main():
    fns = functions(sys.argv[1])
    by_norm = {}
    for s in fns:
        if crate_of(s):
            by_norm[(crate_of(s), CRATE.sub("CRATE", s))] = s
    memo = {}

    def same(a, b):
        key = (a, b)
        if key in memo:
            return memo[key]
        memo[key] = True  # cycles: assume equal until shown otherwise
        (na, ca), (nb, cb) = normalize(a, fns[a]), normalize(b, fns[b])
        ok = na == nb and len(ca) == len(cb)
        if ok:
            for x, y in zip(ca, cb):
                if CRATE.sub("CRATE", x) != CRATE.sub("CRATE", y) or x not in fns or y not in fns or not same(x, y):
                    ok = False
                    break
        memo[key] = ok
        return ok

    result = {}
    for s in fns:
        m = PROBE.search(s)
        if not m or m.group(1) != "4cgen":
            continue
        name = m.group(3)[: int(m.group(2))]
        other = by_norm.get(("7cgen_o1", CRATE.sub("CRATE", s)))
        result[name] = bool(other) and same(s, other)
    print(json.dumps(dict(sorted(result.items())), indent=1))


if __name__ == "__main__":
    main()
