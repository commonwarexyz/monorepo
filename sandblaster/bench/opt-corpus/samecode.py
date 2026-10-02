#!/usr/bin/env python3
"""samecode.py BIN [--crates A,B[,C..]]: for every probe of a harness binary, whether the subjects
compiled to the same machine code, following calls into each subject's own crate.

Default (the corpus harness): whether the current emission (`cgen::probe::F`) and the O1 emission
(`cgen_o1::probe::F`) are the same code; prints JSON {"F": true | false}. With `--crates A,B,C..`
(the held-out harness: `subj_rustc,subj_rustc_aa,subj_opt`) every crate after the first is compared
with the first, `A::probe::F` against `X::probe::F`; prints JSON {"F": {"X": true | false, ..}}.
`--ignore-panic-locations` (the held-out harness, built with overflow checks) does not compare the
page offset of the address a `core::panicking` call receives: each subject crate has its own copy
of every panic `Location` constant, so identical code differs only there.

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
REF = re.compile(r"(?:0x[0-9a-f]+ )?<([^>+]+)(\+0x[0-9a-f]+)?>")
# --ignore-panic-locations: the page offset of the address passed to a `core::panicking`
# function (each crate's own copy of a panic `Location` constant) is not compared
PANIC_LOCATIONS = False
# the subject crates (v0-mangled `<len><name>` segments); set by main() from --crates
CRATES = ["cgen", "cgen_o1"]
SEGS = "|".join(f"{len(c)}{c}" for c in CRATES)
PROBE = re.compile(r"Cs[0-9A-Za-z]+_(" + SEGS + r")5probe(\d+)([0-9A-Za-z_]+)$")
CRATE = re.compile(r"Cs[0-9A-Za-z]+_(?:" + SEGS + r")(?=[0-9A-Z_]|$)")


def set_crates(crates):
    global CRATES, SEGS, PROBE, CRATE
    CRATES = crates
    SEGS = "|".join(f"{len(c)}{c}" for c in sorted(crates, key=len, reverse=True))
    PROBE = re.compile(r"Cs[0-9A-Za-z]+_(" + SEGS + r")5probe(\d+)([0-9A-Za-z_]+)$")
    CRATE = re.compile(r"Cs[0-9A-Za-z]+_(?:" + SEGS + r")(?=[0-9A-Z_]|$)")


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
    m = re.search(r"_(" + SEGS + r")(?=[0-9A-Z_]|$)", sym)
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
        if PANIC_LOCATIONS and re.match(r"^bl\s+<[^>]*core\d+panicking", ins):
            # the argument a panic call gets is the address of the crate's own copy of
            # its `Location` (or message) constant: drop its page (objdump names the page
            # after whatever symbol precedes it) and its page offset
            for k in range(len(out) - 1, max(len(out) - 5, -1), -1):
                out[k] = re.sub(r"^(add\s+(x\d+), \2), #0x[0-9a-f]+$", r"\1, PAGEOFF", out[k])
                out[k] = re.sub(r"^(adrp\s+\w+), <[^>]*>$", r"\1, PAGE", out[k])
        out.append(ins)
        if re.match(r"^(bl|b)\s", ins):
            calls.extend(refs)
    return out, calls


def main():
    global PANIC_LOCATIONS
    args = sys.argv[1:]
    if "--ignore-panic-locations" in args:
        PANIC_LOCATIONS = True
        args.remove("--ignore-panic-locations")
    if "--crates" in args:
        i = args.index("--crates")
        set_crates(args[i + 1].split(","))
        args = args[:i] + args[i + 2:]
    fns = functions(args[0])
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

    seg = lambda c: f"{len(c)}{c}"
    first, others = seg(CRATES[0]), [seg(c) for c in CRATES[1:]]
    result = {}
    for s in fns:
        m = PROBE.search(s)
        if not m or m.group(1) != first:
            continue
        name = m.group(3)[: int(m.group(2))]
        by = {}
        for o, c in zip(others, CRATES[1:]):
            other = by_norm.get((o, CRATE.sub("CRATE", s)))
            by[c] = bool(other) and same(s, other)
        result[name] = by[CRATES[1]] if len(CRATES) == 2 else by
    print(json.dumps(dict(sorted(result.items())), indent=1))


if __name__ == "__main__":
    main()
