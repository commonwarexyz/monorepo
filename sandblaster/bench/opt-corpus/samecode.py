#!/usr/bin/env python3
"""samecode.py BIN [--crates A,B[,C..]]: for every probe of a harness binary, whether the subjects
compiled to the same machine code, following calls into each subject's own crate.

Default (the corpus harness): whether the current emission (`cgen::probe::F`) and the O1 emission
(`cgen_o1::probe::F`) are the same code; prints JSON {"F": true | false}. With `--crates A,B,C..`
(the held-out harness: `subj_rustc,subj_rustc_aa,subj_opt`) every crate after the first is compared
with the first, `A::probe::F` against `X::probe::F`; prints JSON {"F": {"X": true | false, ..}}.
`--ignore-panic-locations` (the held-out harness, built with overflow checks) does not compare the
page and page offset of the addresses a panic entry point receives (core's `panicking` functions,
`expect_failed`, `unwrap_failed`, the slice index failures; each argument set up by `adrp`/`add`
into x0-x7 in the straight-line instructions before the call, at most 16): each subject crate has its own copy of
every panic `Location` and message constant, so identical code differs only there. Their contents
are not compared either (a panic's file and line come from the crate's own source path).

`--family SUBJECT=A+B..` (once per subject; the shipped-code harness, whose subjects each link their
own copies of library crates): crate `A` belongs to subject `SUBJECT` as its first family member,
`B` as its second, and so on, with the same number of members in every family. Calls are followed
into a subject's family crates as into the subject itself, and the k-th member of every family is
unified with the k-th of the others (`FAM<k>`), so the same library code compiled from two copies
compares equal.

`--data-blind` (a second, looser check, reported apart): every data address is dropped (an
`adrp` page and the page offset added or loaded through that register within the next three
instructions), so code that differs only in which crate's copy of a constant it addresses (a
lookup or jump table, an initial state) compares equal; the constants' contents are not compared.

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
# --ignore-panic-locations: the page and page offset of the addresses passed to a panic
# entry point (each crate's own copy of a panic `Location` or message constant) are not
# compared. The entry points: core's `panicking` functions and the panicking helpers that
# take such constants (`Option::expect`'s `expect_failed`, `Result::unwrap`'s and
# `expect`'s `unwrap_failed`, the slice index failures)
PANIC_LOCATIONS = False
# --data-blind (a second, looser check): every data address (an `adrp` page and the page
# offset added to that register right after) is dropped, so code that differs only in which
# copy of a constant it addresses (a crate's own lookup table, jump table or initial state)
# compares equal; the contents of those constants are not compared
DATA_BLIND = False
PANIC_CALL = re.compile(r"^bl\s+<[^>]*4core(\d+panicking|6option13expect_failed|6result13unwrap_failed|5slice5index\d+\w*fail)")
# the subject crates (v0-mangled `<len><name>` segments); set by main() from --crates
CRATES = ["cgen", "cgen_o1"]
SEGS = "|".join(f"{len(c)}{c}" for c in CRATES)
PROBE = re.compile(r"Cs[0-9A-Za-z]+_(" + SEGS + r")5probe(\d+)([0-9A-Za-z_]+)$")
CRATE = re.compile(r"Cs[0-9A-Za-z]+_(?:" + SEGS + r")(?=[0-9A-Z_]|$)")


# --family: family crate -> (subject crate, member index)
FAMILY = {}
FAM_SEGS = ""
FAM = None


def set_crates(crates):
    global CRATES, SEGS, PROBE, CRATE
    CRATES = crates
    SEGS = "|".join(f"{len(c)}{c}" for c in sorted(crates, key=len, reverse=True))
    PROBE = re.compile(r"Cs[0-9A-Za-z]+_(" + SEGS + r")5probe(\d+)([0-9A-Za-z_]+)$")
    CRATE = re.compile(r"Cs[0-9A-Za-z]+_(?:" + SEGS + r")(?=[0-9A-Z_]|$)")


def set_families(fams):
    """fams: {subject: [member crate, ..]} (every family the same length)."""
    global FAMILY, FAM_SEGS, FAM
    FAMILY = {m: (subj, k) for subj, members in fams.items() for k, m in enumerate(members)}
    FAM_SEGS = "|".join(f"{len(c)}{c}" for c in sorted(FAMILY, key=len, reverse=True))
    FAM = re.compile(r"Cs[0-9A-Za-z]+_(" + FAM_SEGS + r")(?=[0-9A-Z_]|$)") if FAMILY else None


# a v0 back-reference (`B<base-62>_`, a byte offset into the symbol) in the path positions
# where they occur (after a namespace tag `N<x>`, or opening generic arguments `I`): its
# offset depends on the lengths of the crate names and hashes before it
BACKREF = re.compile(r"(?:(?<=N[A-Za-z])|(?<=I))B[0-9A-Za-z]*_")


def unify(sym):
    """A symbol with its subject crate and family crates named generically, and
    its back-references, whose offsets the subject crates' names (of different
    lengths) and hashes shift."""
    sym = CRATE.sub("CRATE", sym)
    if FAM is not None:
        sym = FAM.sub(lambda m: f"FAM{FAMILY[strip_len(m.group(1))][1]}", sym)
    return BACKREF.sub("B_", sym)


def strip_len(seg):
    """`19sbx_ship_orig_storage` -> `sbx_ship_orig_storage` (a v0 `<len><name>` segment)."""
    return re.sub(r"^\d+", "", seg)


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
    """The subject a symbol belongs to (`<len><name>` of the subject crate): its
    own crate, or (`--family`) the subject of a family crate it is defined in."""
    m = re.search(r"_(" + SEGS + r")(?=[0-9A-Z_]|$)", sym)
    if m:
        return m.group(1)
    if FAM is not None:
        f = re.search(r"_(" + FAM_SEGS + r")(?=[0-9A-Z_]|$)", sym)
        if f:
            subj = FAMILY[strip_len(f.group(1))][0]
            return f"{len(subj)}{subj}"
    return None


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
            return f"<{unify(target)}{off}>"

        ins = REF.sub(ref, ins)
        ins = re.sub(r"^(adrp\s+\w+), 0x[0-9a-f]+", r"\1, PAGE", ins)
        if PANIC_LOCATIONS and PANIC_CALL.match(ins):
            # the arguments a panic call gets are the addresses of the crate's own copies
            # of its `Location` and message constants: in the argument setup before the
            # call (the straight-line instructions back to the previous branch or return,
            # at most 16), an `adrp`/`add` into an argument register (x0-x7) has its page
            # (objdump names it after whatever symbol precedes it) and page offset dropped
            for k in range(len(out) - 1, max(len(out) - 17, -1), -1):
                if re.match(r"^(b|bl|br|blr|ret|cbz|cbnz|tbz|tbnz|brk)(\s|$)|^b\.", out[k]):
                    break
                out[k] = re.sub(r"^(add\s+(x[0-7]), \2), #0x[0-9a-f]+$", r"\1, PAGEOFF", out[k])
                out[k] = re.sub(r"^(adrp\s+x[0-7]), <[^>]*>$", r"\1, PAGE", out[k])
        if DATA_BLIND:
            m = re.match(r"^adrp\s+(x\d+), ", ins)
            if m:
                ins = f"adrp\t{m.group(1)}, PAGE"
            else:
                m = re.match(r"^(add|ldr|ldrb|ldrh|ldrsw|str)\s+(\w+), (\[)?(x\d+), #0x[0-9a-f]+(\])?$", ins)
                if m and any(o == f"adrp\t{m.group(4)}, PAGE" for o in out[-3:]):
                    ins = re.sub(r"#0x[0-9a-f]+", "PAGEOFF", ins)
        out.append(ins)
        if re.match(r"^(bl|b)\s", ins):
            calls.extend(refs)
    return out, calls


def main():
    global PANIC_LOCATIONS, DATA_BLIND
    args = sys.argv[1:]
    if "--ignore-panic-locations" in args:
        PANIC_LOCATIONS = True
        args.remove("--ignore-panic-locations")
    if "--data-blind" in args:
        DATA_BLIND = True
        args.remove("--data-blind")
    if "--crates" in args:
        i = args.index("--crates")
        set_crates(args[i + 1].split(","))
        args = args[:i] + args[i + 2:]
    fams = {}
    while "--family" in args:
        i = args.index("--family")
        subj, members = args[i + 1].split("=", 1)
        fams[subj] = members.split("+")
        args = args[:i] + args[i + 2:]
    if fams:
        assert set(fams) == set(CRATES) and len({len(m) for m in fams.values()}) == 1, "--family: one per subject, the same length"
        set_families(fams)
    fns = functions(args[0])
    by_norm = {}
    for s in fns:
        if crate_of(s):
            by_norm[(crate_of(s), unify(s))] = s
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
                if unify(x) != unify(y) or x not in fns or y not in fns or not same(x, y):
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
            other = by_norm.get((o, unify(s)))
            by[c] = bool(other) and same(s, other)
        result[name] = by[CRATES[1]] if len(CRATES) == 2 else by
    print(json.dumps(dict(sorted(result.items())), indent=1))


if __name__ == "__main__":
    main()
