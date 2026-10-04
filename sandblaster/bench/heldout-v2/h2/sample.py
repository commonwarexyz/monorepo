#!/usr/bin/env python3
"""H2-v2 enumeration, static filter and seeded order (RULE.md sections 1-4).

    PYTHONDONTWRITEBYTECODE=1 python3 sandblaster/bench/heldout-v2/h2/sample.py [--out DIR]

Run from anywhere; paths resolve against the monorepo root. Writes, to DIR
(default: next to this file):

* candidates.tsv: every function that passes RULE.md sections 2-3, in the
  seeded order of section 4, with its generic parameters (section 3.1's
  instance is chosen by instance.py, which rewrites this file with the
  instance column);
* rejections.tsv: every function in a scope file that is not a candidate,
  with the first criterion it fails, and every block the enumeration does
  not enter (section 3: inline modules, macro bodies, a trait's own items).

Lexical only, as v1's sample.py (sandblaster/bench/heldout/h2/sample.py,
whose lexer this reuses verbatim): comments are dropped and string literals
kept as single tokens, then items are read with balanced brackets. No cargo,
no rustc. Every scope file must be the source commit's (checked with a
read-only `git diff` before enumerating; a file that differs stops the run).
"""
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../../.."))
SEED = "7bc58f68b25930aa17c68e7c870edb9a"
SOURCE_COMMIT = "2b3ec7cdc1f3d4fbd5c3001d385350477b140981"

# RULE.md section 1: (package, crate dir, src-relative prefixes; empty: the whole crate)
SCOPE = [
    ("commonware-actor", "actor", []),
    ("commonware-broadcast", "broadcast", []),
    ("commonware-collector", "collector", []),
    ("commonware-consensus", "consensus", []),
    ("commonware-glue", "glue", []),
    ("commonware-p2p", "p2p", []),
    ("commonware-resolver", "resolver", []),
    ("commonware-stream", "stream", []),
    ("commonware-storage", "storage", ["archive", "cache", "ordinal", "queue", "rmap"]),
]
SCOPE_DIRS = [d if not p else f"{d}/src/{x}" for _, d, p in SCOPE for x in (p or [None])]

# RULE.md section 2
TARGET_TOKENS = {"varint", "merkle", "mmr", "bmt", "qmdb", "sha256", "Sha256", "blake3", "Blake3", "keccak", "Keccak",
                 "bls12381", "ed25519", "reed_solomon", "ReedSolomon"}
MATRIX_NAMES = {"parse", "shape_go", "shape", "cswap", "mul_by_014", "verify_many", "mul"}
TEST_PATH_PARTS = {"tests", "test", "mocks", "mock", "test_utils", "fuzz", "benches", "bench", "examples"}
TEST_CFG_IDENTS = {"test", "fuzzing"}
TEST_CFG_STRINGS = {"mocks", "test-utils", "fuzzing", "arbitrary", "test"}
V1_CANDIDATES = os.path.join(REPO, "sandblaster/bench/heldout/h2/candidates.tsv")
PROBE_LOG = os.path.join(HERE, "PROBE-LOG.md")

# RULE.md section 3 (the lexical reading of v1's sample.py, plus v2's channel tokens)
IO_IDENTS = {
    "io", "fs", "net", "File", "TcpStream", "TcpListener", "UdpSocket",
    "tokio", "futures", "spawn", "thread", "Instant", "SystemTime",
    "Clock", "Spawner", "Storage", "Blob", "Network", "Sink", "Stream", "Metrics", "metrics", "Context",
    "tracing", "rand", "Rng", "RngCore", "CryptoRng", "rng",
    "Cell", "RefCell", "Mutex", "RwLock", "Arc", "Rc", "atomic",
    "mpsc", "oneshot", "Sender", "Receiver",
}
IO_MACROS = {"println", "eprintln", "print", "eprint", "dbg", "trace", "debug", "info", "warn", "error"}
CLOSURE_TRAITS = {"Fn", "FnMut", "FnOnce"}


# ---------------------------------------------------------------------------
# lexer (verbatim from v1's sample.py)
# ---------------------------------------------------------------------------

class Tok:
    __slots__ = ("kind", "text", "line")

    def __init__(self, kind, text, line):
        self.kind, self.text, self.line = kind, text, line

    def __repr__(self):
        return f"{self.kind}:{self.text}"


PUNCT2 = {"::", "->", "=>", "..", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "^=", "&=", "|=", "<<", ">>"}


def lex(src):
    toks, i, n, line = [], 0, len(src), 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif src.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    if src[i] == "\n":
                        line += 1
                    i += 1
            continue
        # raw strings r"..", r#".."#, br#".."#
        m = re.match(r'(b?r)(#*)"', src[i:i + 300])
        if m:
            hashes = m.group(2)
            end = src.find('"' + hashes, i + len(m.group(0)))
            if end < 0:
                end = n
            text = src[i + len(m.group(0)):end]
            toks.append(Tok("str", text, line))
            line += text.count("\n")
            i = end + 1 + len(hashes)
            continue
        if c == '"' or (c == "b" and i + 1 < n and src[i + 1] == '"'):
            j = i + (2 if c == "b" else 1)
            buf = []
            while j < n and src[j] != '"':
                if src[j] == "\\":
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                buf.append(src[j])
                j += 1
            text = "".join(buf)
            toks.append(Tok("str", text, line))
            line += text.count("\n")
            i = j + 1
            continue
        if c == "'" or (c == "b" and i + 1 < n and src[i + 1] == "'"):
            j = i + (1 if c == "'" else 2)
            # a character literal: '\..', or 'x' (one char then a quote)
            if j < n and src[j] == "\\":
                k = j + 1
                while k < n and src[k] != "'":
                    k += 1
                toks.append(Tok("char", src[j:k], line))
                i = k + 1
                continue
            if j + 1 < n and src[j + 1] == "'":
                toks.append(Tok("char", src[j], line))
                i = j + 2
                continue
            if c == "b":
                toks.append(Tok("ident", "b", line))
                i += 1
                continue
            # a lifetime or label
            m = re.match(r"'[A-Za-z_][A-Za-z0-9_]*", src[i:])
            if m:
                toks.append(Tok("life", m.group(0), line))
                i += len(m.group(0))
                continue
            toks.append(Tok("punct", "'", line))
            i += 1
            continue
        m = re.match(r"r#[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*", src[i:i + 200])
        if m:
            t = m.group(0)
            toks.append(Tok("ident", t[2:] if t.startswith("r#") else t, line))
            i += len(t)
            continue
        m = re.match(r"[0-9][0-9A-Za-z_]*(\.[0-9][0-9A-Za-z_]*)?", src[i:i + 100])
        if m:
            toks.append(Tok("num", m.group(0), line))
            i += len(m.group(0))
            continue
        two = src[i:i + 2]
        if two in PUNCT2:
            toks.append(Tok("punct", two, line))
            i += 2
            continue
        toks.append(Tok("punct", c, line))
        i += 1
    return toks


OPEN = {"(": ")", "[": "]", "{": "}"}


def close_of(toks, i):
    """Index of the bracket closing the one at i."""
    stack = []
    for j in range(i, len(toks)):
        t = toks[j]
        if t.kind != "punct":
            continue
        if t.text in OPEN:
            stack.append(OPEN[t.text])
        elif t.text in (")", "]", "}"):
            if not stack or stack[-1] != t.text:
                raise ValueError(f"unbalanced {t.text} at line {t.line}")
            stack.pop()
            if not stack:
                return j
    raise ValueError(f"unclosed bracket at line {toks[i].line}")


def skip_to_semi(toks, i):
    """Index of the `;` ending the item from i (brackets balanced), or the
    closing `}` of a braced item body when no `;` follows at depth 0."""
    j = i
    while j < len(toks):
        t = toks[j]
        if t.kind == "punct" and t.text in OPEN:
            k = close_of(toks, j)
            if t.text == "{":
                # a braced body ends the item unless an expression continues (`= {..};`)
                nxt = toks[k + 1] if k + 1 < len(toks) else None
                prev_eq = any(x.kind == "punct" and x.text == "=" for x in toks[i:j])
                if not prev_eq:
                    return k
                if nxt is not None and nxt.kind == "punct" and nxt.text == ";":
                    return k + 1
            j = k + 1
            continue
        if t.kind == "punct" and t.text == ";":
            return j
        j += 1
    return len(toks) - 1


# ---------------------------------------------------------------------------
# items
# ---------------------------------------------------------------------------

def attr_is_test_cfg(attr):
    """attr: the tokens inside `#[ .. ]` (RULE.md 2.4: a cfg that mentions
    test, mocks, test-utils, fuzzing or arbitrary)."""
    if not attr or attr[0].kind != "ident" or attr[0].text != "cfg":
        return False
    for t in attr[1:]:
        if t.kind == "ident" and t.text in TEST_CFG_IDENTS:
            return True
        if t.kind == "str" and t.text in TEST_CFG_STRINGS:
            return True
    return False


def attr_is_test_fn(attr):
    return len(attr) == 1 and attr[0].kind == "ident" and attr[0].text == "test" or (len(attr) >= 1 and attr[0].kind == "ident" and attr[0].text in ("test", "tokio") and any(t.text == "test" for t in attr))


def angle_close(toks, i):
    """toks[i] is `<`: the index after its matching `>` (`>>` closes two)."""
    depth, j = 0, i
    while j < len(toks):
        t = toks[j]
        if t.kind == "punct":
            if t.text == "<":
                depth += 1
            elif t.text == ">":
                depth -= 1
            elif t.text == ">>":
                depth -= 2
            elif t.text in ("(", "["):
                j = close_of(toks, j) + 1
                continue
            if depth <= 0 and t.text in (">", ">>"):
                return j + 1
        j += 1
    return j


def split_top(toks, sep=","):
    out, cur, depth = [], [], 0
    for t in toks:
        if t.kind == "punct" and t.text in ("(", "[", "{", "<"):
            depth += 1
        elif t.kind == "punct" and t.text in (")", "]", "}", ">"):
            depth -= 1
        elif t.kind == "punct" and t.text == ">>":
            depth -= 2
        if t.kind == "punct" and t.text == sep and depth == 0:
            out.append(cur)
            cur = []
            continue
        cur.append(t)
    if cur:
        out.append(cur)
    return out


def text_of(toks):
    """Tokens joined as written: a space only between two word tokens."""
    out, prev = [], False
    for t in toks:
        s = json.dumps(t.text) if t.kind == "str" else ("'" + t.text + "'" if t.kind == "char" else t.text)
        word = t.kind in ("ident", "life", "num")
        if out and word and prev:
            out.append(" ")
        out.append(s)
        prev = word
    return "".join(out)


def strip_generic_args(toks):
    """The tokens without any `<..>` group (RULE.md 4: generic arguments removed)."""
    out, j = [], 0
    while j < len(toks):
        t = toks[j]
        if t.kind == "punct" and t.text == "<":
            j = angle_close(toks, j)
            continue
        out.append(t)
        j += 1
    return out


def generics_inner(toks, i, end):
    """The tokens inside the `<..>` at toks[i] (end: after its `>`); a closing
    `>>` also closes the last bound's own `<`, which keeps its `>`."""
    inner = toks[i + 1:end - 1]
    if toks[end - 1].text == ">>":
        inner = inner + [Tok("punct", ">", toks[end - 1].line)]
    return inner


def parse_generics(toks):
    """The tokens inside `<..>` of a generics list: [{kind, name, bounds, ty}]."""
    params = []
    for p in split_top(toks):
        if not p:
            continue
        if p[0].kind == "life":
            params.append({"kind": "lifetime", "name": p[0].text, "bounds": text_of(p[2:]) if len(p) > 2 else ""})
            continue
        if p[0].kind == "ident" and p[0].text == "const":
            # const N: usize [= default]
            ty = p[3:]
            eq = [k for k, t in enumerate(ty) if t.kind == "punct" and t.text == "="]
            if eq:
                ty = ty[:eq[0]]
            params.append({"kind": "const", "name": p[1].text, "ty": text_of(ty), "bounds": ""})
            continue
        name = p[0].text
        rest = p[1:]
        eq = [k for k, t in enumerate(rest) if t.kind == "punct" and t.text == "=" and not any(x.text in ("<", "(") for x in rest[:k])]
        if eq:
            rest = rest[:eq[0]]
        bounds = rest[1:] if rest and rest[0].kind == "punct" and rest[0].text == ":" else []
        params.append({"kind": "type", "name": name, "bounds": text_of(bounds), "_btoks": bounds})
    return params


def parse_where(toks):
    """`where` predicates (tokens after `where`): [(lhs text, bounds text, bound tokens)]."""
    preds = []
    for p in split_top(toks):
        if not p:
            continue
        # `for<'a> T: ..` (higher-ranked): keep the predicate whole
        depth, colon = 0, None
        for k, t in enumerate(p):
            if t.kind == "punct" and t.text in ("<", "(", "["):
                depth += 1
            elif t.kind == "punct" and t.text in (">", ")", "]"):
                depth -= 1
            elif t.kind == "punct" and t.text == ">>":
                depth -= 2
            elif t.kind == "punct" and t.text == ":" and depth == 0:
                colon = k
                break
        if colon is None:
            continue
        preds.append({"lhs": text_of(p[:colon]), "bounds": text_of(p[colon + 1:]), "_btoks": p[colon + 1:], "_ltoks": p[:colon]})
    return preds


def impl_trait_params(params_toks):
    """`impl Trait` in argument position: one anonymous type parameter each,
    with the bound tokens that follow `impl` (to the end of that type)."""
    out = []
    for k, t in enumerate(params_toks):
        if t.kind == "ident" and t.text == "impl":
            depth, j, b = 0, k + 1, []
            while j < len(params_toks):
                x = params_toks[j]
                if x.kind == "punct" and x.text in ("(", "[", "<"):
                    depth += 1
                elif x.kind == "punct" and x.text in (")", "]", ">"):
                    if depth == 0:
                        break
                    depth -= 1
                elif x.kind == "punct" and x.text == ">>":
                    if depth <= 1:
                        if depth == 1:
                            b.append(Tok("punct", ">", x.line))
                        break
                    depth -= 2
                elif x.kind == "punct" and x.text == "," and depth == 0:
                    break
                b.append(x)
                j += 1
            out.append({"kind": "type", "name": f"impl#{len(out)}", "bounds": text_of(b), "_btoks": b, "impl_trait": True})
    return out


SKIPPED = []


class Fn:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def parse_items(toks, i, end, ctx, out, mods):
    """Reads the items of toks[i:end] (a module or impl/trait body)."""
    while i < end:
        attrs, testish = [], ctx["testish"]
        path_attr = None
        while i < end and toks[i].kind == "punct" and toks[i].text == "#":
            j = i + 1
            if toks[j].kind == "punct" and toks[j].text == "!":
                j += 1
            if toks[j].kind == "punct" and toks[j].text == "[":
                k = close_of(toks, j)
                a = toks[j + 1:k]
                attrs.append(a)
                if attr_is_test_cfg(a):
                    testish = True
                if len(a) >= 3 and a[0].text == "path" and a[2].kind == "str":
                    path_attr = a[2].text
                i = k + 1
            else:
                break
        if i >= end:
            break
        start = i
        if toks[i].kind == "ident" and toks[i].text == "pub":
            i += 1
            if i < end and toks[i].kind == "punct" and toks[i].text == "(":
                i = close_of(toks, i) + 1
        quals = []
        while i < end and toks[i].kind == "ident" and toks[i].text in ("const", "async", "unsafe", "extern", "default") and not (toks[i].text == "const" and i + 1 < end and toks[i + 1].kind != "ident"):
            if toks[i].text == "const" and i + 1 < end and toks[i + 1].kind == "ident" and toks[i + 1].text not in ("fn", "unsafe", "async", "extern"):
                break  # `const NAME: ..`
            quals.append(toks[i].text)
            i += 1
            if quals[-1] == "extern" and i < end and toks[i].kind == "str":
                i += 1
        t = toks[i]
        if t.kind == "punct" and t.text == ";":
            i += 1
            continue
        kw = t.text if t.kind == "ident" else None
        if kw == "fn":
            name = toks[i + 1].text
            j = i + 2
            gparams = []
            if toks[j].kind == "punct" and toks[j].text == "<":
                g_end = angle_close(toks, j)
                gparams = parse_generics(generics_inner(toks, j, g_end))
                j = g_end
            if not (toks[j].kind == "punct" and toks[j].text == "("):
                raise ValueError(f"fn {name}: no parameter list at line {toks[j].line}")
            pclose = close_of(toks, j)
            params = toks[j + 1:pclose]
            k = pclose + 1
            while k < end and not (toks[k].kind == "punct" and toks[k].text in ("{", ";")):
                if toks[k].kind == "punct" and toks[k].text in ("(", "["):
                    k = close_of(toks, k) + 1
                    continue
                k += 1
            ret = toks[pclose + 1:k]
            where = []
            w = [x for x, tt in enumerate(ret) if tt.kind == "ident" and tt.text == "where"]
            if w:
                where = parse_where(ret[w[0] + 1:])
                ret = ret[:w[0]]
            if toks[k].text == ";":
                body = None
                nxt = k + 1
            else:
                bclose = close_of(toks, k)
                body = toks[k + 1:bclose]
                nxt = bclose + 1
            out.append(Fn(name=name, line=toks[start].line, attrs=attrs, testish=testish, quals=quals, gparams=gparams, where=where,
                          params=params, ret=ret, body=body, sig=toks[start:k], ctx=dict(ctx), impl_traits=impl_trait_params(params)))
            i = nxt
            continue
        if kw in ("impl", "trait") or (kw == "auto" and toks[i + 1].text == "trait"):
            if kw == "auto":
                i += 1
            j = i + 1
            gparams = []
            if kw == "impl" and toks[j].kind == "punct" and toks[j].text == "<":
                g_end = angle_close(toks, j)
                gparams = parse_generics(generics_inner(toks, j, g_end))
                j = g_end
            hdr_start = j
            while not (toks[j].kind == "punct" and toks[j].text == "{"):
                if toks[j].kind == "punct" and toks[j].text in ("(", "["):
                    j = close_of(toks, j) + 1
                    continue
                if toks[j].kind == "punct" and toks[j].text == "<":
                    j = angle_close(toks, j)
                    continue
                j += 1
            hdr = toks[hdr_start:j]
            where = []
            wk = [x for x, tt in enumerate(hdr) if tt.kind == "ident" and tt.text == "where"]
            if wk:
                where = parse_where(hdr[wk[0] + 1:])
                hdr = hdr[:wk[0]]
            bclose = close_of(toks, j)
            sub = dict(ctx)
            sub["testish"] = testish
            sub.pop("_impls", None)
            if kw == "trait":
                sub["kind"] = "trait"
                sub["self_ty"] = toks[i + 1].text
            else:
                # `impl Trait for Type` at angle depth 0
                depth, for_at = 0, None
                for x, tt in enumerate(hdr):
                    if tt.kind == "punct" and tt.text == "<":
                        depth += 1
                    elif tt.kind == "punct" and tt.text == ">":
                        depth -= 1
                    elif tt.kind == "punct" and tt.text == ">>":
                        depth -= 2
                    elif tt.kind == "ident" and tt.text == "for" and depth == 0:
                        for_at = x
                        break
                trait_toks = hdr[:for_at] if for_at is not None else None
                ty_toks = hdr[for_at + 1:] if for_at is not None else hdr
                name, depth = None, 0
                for x in ty_toks:
                    if x.kind == "punct" and x.text == "<":
                        depth += 1
                    elif x.kind == "punct" and x.text in (">", ">>"):
                        depth -= 1 if x.text == ">" else 2
                    elif x.kind == "ident" and depth == 0 and x.text not in ("dyn", "mut", "for"):
                        name = x.text
                sub["kind"] = "trait_impl" if trait_toks is not None else "inherent"
                sub["self_ty"] = name
                sub["self_ty_full"] = text_of(ty_toks)
                sub["self_ty_id"] = text_of(strip_generic_args(ty_toks))
                sub["_self_toks"] = ty_toks
                sub["trait"] = None
                if trait_toks is not None:
                    tr = strip_generic_args(trait_toks)
                    sub["trait"] = tr[-1].text if tr and tr[-1].kind == "ident" else text_of(tr)
                    sub["trait_id"] = text_of(tr)
                    sub["trait_full"] = text_of(trait_toks)
                    sub["_trait_toks"] = trait_toks
            sub["impl_gparams"] = gparams
            sub["impl_where"] = where
            sub["impl_line"] = toks[i].line
            ctx.setdefault("_impls", []).append(sub)
            parse_items(toks, j + 1, bclose, sub, out, mods)
            i = bclose + 1
            continue
        if kw == "mod":
            name = toks[i + 1].text
            if toks[i + 2].kind == "punct" and toks[i + 2].text == ";":
                mods.append((name, testish, path_attr))
                i += 3
            else:
                k = close_of(toks, i + 2)
                nfn = sum(1 for x in toks[i + 2:k] if x.kind == "ident" and x.text == "fn")
                if nfn:
                    SKIPPED.append((toks[i].line, f"not enumerated: inline module `{name}` ({nfn} fn token(s); RULE.md 3)"))
                i = k + 1
            continue
        if kw == "macro_rules":
            j = i + 3
            kc = close_of(toks, j)
            nfn = sum(1 for x in toks[j:kc] if x.kind == "ident" and x.text == "fn")
            if nfn:
                SKIPPED.append((toks[i].line, f"not enumerated: inside `macro_rules! {toks[i + 2].text}` ({nfn} fn token(s); RULE.md 3)"))
            i = kc + 1
            if i < end and toks[i].kind == "punct" and toks[i].text == ";":
                i += 1
            continue
        j = i
        while j < end and (toks[j].kind == "ident" or (toks[j].kind == "punct" and toks[j].text == "::")):
            j += 1
        if j > i and j < end and toks[j].kind == "punct" and toks[j].text == "!" and kw not in ("struct", "enum", "union", "type", "use", "static", "const", "extern"):
            k = j + 1
            if toks[k].kind == "ident":
                k += 1
            kc = close_of(toks, k)
            nfn = sum(1 for x in toks[k:kc] if x.kind == "ident" and x.text == "fn")
            if nfn:
                SKIPPED.append((toks[i].line, f"not enumerated: inside the macro invocation `{''.join(x.text for x in toks[i:j])}!` ({nfn} fn token(s); RULE.md 3)"))
            i = kc + 1
            if i < end and toks[i].kind == "punct" and toks[i].text == ";":
                i += 1
            continue
        i = skip_to_semi(toks, i) + 1


def module_path(rel):
    """`src/a/b.rs` -> `a::b`; `src/a/mod.rs` -> `a`; `src/lib.rs` -> ``."""
    p = rel[len("src/"):-len(".rs")]
    parts = p.split("/")
    if parts[-1] == "mod":
        parts = parts[:-1]
    if parts in (["lib"], ["main"]):
        return ""
    return "::".join(parts)


def idents(toks):
    return {t.text for t in toks if t.kind == "ident"}


def macros(toks):
    return {toks[k].text for k in range(len(toks) - 1) if toks[k].kind == "ident" and toks[k + 1].kind == "punct" and toks[k + 1].text == "!"}


def corpus_names():
    names = set()
    text = open(os.path.join(REPO, "sandblaster/front/tests/opt_corpus/corpus.toml")).read()
    for m in re.finditer(r"^functions\s*=\s*\[(.*?)\]", text, re.M | re.S):
        for f in re.findall(r'"([^"]+)"', m.group(1)):
            names.add(f.rsplit("::", 1)[-1])
    return names


def v1_ids():
    with open(V1_CANDIDATES) as f:
        cols = f.readline().rstrip("\n").split("\t")
        k = cols.index("id")
        return {line.rstrip("\n").split("\t")[k] for line in f if line.strip()}


def seen_files():
    """RULE.md 0 and 2.6: scope files looked at during development, as
    PROBE-LOG.md lists them (`- seen: <repo path>`)."""
    if not os.path.exists(PROBE_LOG):
        return set()
    return {m.group(1).strip() for m in re.finditer(r"^- seen: `?([^`\s]+)`?", open(PROBE_LOG).read(), re.M)}


def all_params(f):
    """RULE.md 3.1: the impl block's parameters, then the function's, then one
    anonymous parameter per `impl Trait` argument, in declaration order."""
    return list(f.ctx.get("impl_gparams", [])) + list(f.gparams) + list(f.impl_traits)


def classify(f, pkg, rel, corpus, v1, seen, fid):
    """The first criterion f fails (RULE.md sections 2-3), or None."""
    sig_ids, body_ids = idents(f.sig), idents(f.body or [])
    allids = sig_ids | body_ids
    alltoks = f.sig + (f.body or [])
    parts = rel.split("/")
    # section 2, in its order
    hit = sorted(allids & TARGET_TOKENS)
    if hit:
        return f"excluded: names a target area ({', '.join(hit)}) (RULE.md 2.1)"
    if f.name in corpus:
        return f"excluded: named like a corpus.toml function `{f.name}` (RULE.md 2.2)"
    if f.name in MATRIX_NAMES:
        return f"excluded: named like a §15 workload function `{f.name}` (RULE.md 2.3)"
    if any(p in TEST_PATH_PARTS or os.path.splitext(p)[0] in TEST_PATH_PARTS for p in parts[1:]):
        return "excluded: test, mock or fuzz file (RULE.md 2.4)"
    if f.testish:
        return "excluded: under a test/mocks/fuzzing cfg (RULE.md 2.4)"
    if any(attr_is_test_fn(a) for a in f.attrs):
        return "excluded: a #[test] function (RULE.md 2.4)"
    if fid in v1:
        return "excluded: probed under held-out v1 (RULE.md 2.5)"
    if f.file in seen:
        return "excluded: seen during development (RULE.md 2.6)"
    # section 3, in its order
    hit = sorted(allids & IO_IDENTS) + sorted("Atomic*" for x in allids if x.startswith("Atomic"))[:1]
    mac = sorted(macros(alltoks) & IO_MACROS)
    static_mut = any(alltoks[k].text == "static" and alltoks[k + 1].text == "mut" for k in range(len(alltoks) - 1))
    if hit or mac or static_mut:
        why = hit + [m + "!" for m in mac] + (["static mut"] if static_mut else [])
        return f"not pure: names {', '.join(why)} (RULE.md 3, I/O or shared state)"
    if "unsafe" in f.quals or "extern" in f.quals or "unsafe" in body_ids:
        return "not pure: unsafe (RULE.md 3)"
    if "async" in f.quals or "async" in body_ids or "await" in body_ids:
        return "not pure: async (RULE.md 3)"
    if "dyn" in allids:
        return "not pure: a trait object, dyn (RULE.md 3)"
    bound_ids = set()
    for p in all_params(f):
        bound_ids |= idents(p.get("_btoks", []))
    for w in list(f.where) + list(f.ctx.get("impl_where", [])):
        bound_ids |= idents(w["_btoks"])
    if (idents(f.params) | bound_ids) & CLOSURE_TRAITS:
        return "not a candidate: a closure parameter, Fn/FnMut/FnOnce (RULE.md 3)"
    if f.body is None:
        return "not a candidate: no body (RULE.md 3)"
    return None


def out_of_line_mods(toks):
    """Every `mod name;` declaration of a file, wherever it is written (also
    inside a macro invocation such as `stability_scope!`, which declares the
    crate's modules), with whether its own attributes hold a test cfg and its
    `#[path]`: only to know which files sit under a test/mocks/fuzzing cfg."""
    mods = []
    for k in range(len(toks) - 2):
        if not (toks[k].kind == "ident" and toks[k].text == "mod" and toks[k + 1].kind == "ident" and toks[k + 2].kind == "punct" and toks[k + 2].text == ";"):
            continue
        j = k - 1
        # `pub`, `pub(..)`
        if j >= 0 and toks[j].kind == "punct" and toks[j].text == ")":
            d = 0
            while j >= 0:
                if toks[j].text == ")":
                    d += 1
                elif toks[j].text == "(":
                    d -= 1
                    if d == 0:
                        break
                j -= 1
            j -= 1
        if j >= 0 and toks[j].kind == "ident" and toks[j].text == "pub":
            j -= 1
        testish, path_attr = False, None
        while j >= 0 and toks[j].kind == "punct" and toks[j].text == "]":
            d, a = 0, j
            while a >= 0:
                if toks[a].text == "]":
                    d += 1
                elif toks[a].text == "[":
                    d -= 1
                    if d == 0:
                        break
                a -= 1
            attr = toks[a + 1:j]
            if attr_is_test_cfg(attr):
                testish = True
            if len(attr) >= 3 and attr[0].text == "path" and attr[2].kind == "str":
                path_attr = attr[2].text
            j = a - 1
            if j >= 0 and toks[j].kind == "punct" and toks[j].text == "#":
                j -= 1
        mods.append((toks[k + 1].text, testish, path_attr))
    return mods


def crate_files(d, prefixes):
    """The crate's .rs files in scope, with whether each is under a
    test/mocks/fuzzing cfg through its `mod` declaration (RULE.md 2.4)."""
    src = os.path.join(REPO, d, "src")
    testish = {}

    def walk(path, inherited):
        if path in testish or not os.path.exists(path):
            return
        testish[path] = inherited
        toks = lex(open(path, encoding="utf-8").read())
        mods = out_of_line_mods(toks)
        base = os.path.dirname(path)
        stem = os.path.splitext(os.path.basename(path))[0]
        child_dir = base if stem in ("lib", "mod", "main") else os.path.join(base, stem)
        for name, t, pa in mods:
            if pa:
                cands = [os.path.join(base if stem in ("lib", "mod", "main") else child_dir, pa)]
            else:
                cands = [os.path.join(child_dir, name + ".rs"), os.path.join(child_dir, name, "mod.rs")]
            for c in cands:
                if os.path.exists(c):
                    walk(os.path.normpath(c), inherited or t)
                    break

    walk(os.path.join(src, "lib.rs"), False)
    res = []
    for root, dirs, files in os.walk(src):
        dirs.sort()
        for fn in sorted(files):
            if not fn.endswith(".rs"):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, os.path.join(REPO, d))
            inner = rel[len("src/"):]
            if prefixes and not any(inner == p + ".rs" or inner.startswith(p + "/") for p in prefixes):
                continue
            res.append((rel, testish.get(os.path.normpath(path), False), path in testish or os.path.normpath(path) in testish))
    return res


def scope_files():
    for pkg, d, prefixes in SCOPE:
        for rel, t, reached in crate_files(d, prefixes):
            yield pkg, d, rel, t, reached


def check_source_commit():
    """RULE.md, Source: every scope file is the source commit's (read-only git)."""
    p = subprocess.run(["git", "-C", REPO, "diff", "--name-only", SOURCE_COMMIT, "--"] + SCOPE_DIRS, capture_output=True, text=True)
    if p.returncode != 0 or p.stdout.strip():
        raise SystemExit("scope files differ from the source commit (or git failed):\n" + p.stdout + p.stderr)


def param_json(p):
    return {k: v for k, v in p.items() if not k.startswith("_")}


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=HERE)
    args = ap.parse_args()
    check_source_commit()
    corpus, v1, seen = corpus_names(), v1_ids(), seen_files()
    cands, rejs, parse_errors, blocks = [], [], [], []
    unreached = []
    for pkg, d, rel, file_testish, reached in scope_files():
        path = os.path.join(REPO, d, rel)
        src = open(path, encoding="utf-8").read()
        toks = lex(src)
        out, mods = [], []
        SKIPPED.clear()
        ctx = {"testish": file_testish, "kind": "free"}
        try:
            parse_items(toks, 0, len(toks), ctx, out, mods)
        except (ValueError, IndexError) as e:
            parse_errors.append(f"{d}/{rel}: {e}")
            continue
        if not reached:
            unreached.append(f"{d}/{rel}")
        mp = module_path(rel)
        for line, why in SKIPPED:
            blocks.append((f"{d}/{rel}", line, why))
        impls = ctx.get("_impls", [])
        seen_ids = {}
        for f in out:
            f.file = f"{d}/{rel}"
            kind = f.ctx.get("kind", "free")
            if kind == "trait":
                rejs.append((dict(id=f"{pkg}::{mp + '::' if mp else ''}{f.ctx.get('self_ty')}::{f.name}", file=f.file, line=f.line), "not enumerated: a trait's own method (RULE.md 3)"))
                continue
            if kind == "trait_impl":
                owner_id = f"<{f.ctx['self_ty_id']} as {f.ctx['trait_id']}>"
            elif kind == "inherent":
                owner_id = f.ctx["self_ty_id"]
            else:
                owner_id = None
            local = f"{owner_id}::{f.name}" if owner_id else f.name
            fid = "::".join(x for x in (pkg, mp, local) if x)
            # two impls giving the same id: the later one gets `#2`, `#3`, .. (RULE.md 4)
            n = seen_ids.get(fid, 0) + 1
            seen_ids[fid] = n
            if n > 1:
                fid = f"{fid}#{n}"
            why = classify(f, pkg, rel, corpus, v1, seen, fid)
            owner = f.ctx.get("self_ty") if kind != "free" else None
            row = dict(id=fid, package=pkg, crate_dir=d, file=f.file, line=f.line, module=mp,
                       kind={"free": "fn", "inherent": "method", "trait_impl": "trait_method"}[kind], item=(owner or f.name), name=f.name)
            if why:
                rejs.append((row, why))
                continue
            if kind in ("inherent", "trait_impl"):
                others = sorted({g.name for g in out if g.ctx.get("kind") == "inherent" and g.ctx.get("self_ty") == owner and g.name != f.name})
                tmeth = sorted({g.name for g in out if g.ctx.get("kind") == "trait_impl" and g.ctx.get("self_ty") == owner and g.name != f.name})
                traits = sorted({im.get("trait") for im in impls if im.get("kind") == "trait_impl" and im.get("self_ty") == owner and im.get("trait")} - ({f.ctx.get("trait")} if kind == "trait_impl" else set()))
                row["others"] = ",".join(others)
                row["trait_methods"] = ",".join(tmeth)
                row["traits"] = ",".join(traits)
            else:
                row["others"], row["trait_methods"], row["traits"] = "", "", ""
            params = all_params(f)
            gen = {
                "params": [param_json(p) for p in params],
                "where": [param_json(w) for w in list(f.ctx.get("impl_where", [])) + list(f.where)],
                "self_ty": f.ctx.get("self_ty_full") if kind != "free" else None,
                "trait": f.ctx.get("trait_full") if kind == "trait_impl" else None,
                "fn_params": text_of(f.params),
                "n_impl_params": len(f.ctx.get("impl_gparams", [])),
                "n_fn_params": len(f.gparams),
            }
            row["generic"] = "yes" if any(p["kind"] in ("type", "const") for p in params) else "no"
            row["generics"] = json.dumps(gen, separators=(",", ":"))
            row["children"] = ",".join(m for m, _, _ in mods)
            cands.append(row)
    for c in cands:
        c["key"] = hashlib.sha256(f"{SEED}:{c['id']}".encode()).hexdigest()
    cands.sort(key=lambda c: (c["key"], c["id"]))
    cols = ["rank", "id", "package", "file", "line", "module", "kind", "item", "name", "others", "trait_methods", "traits", "children", "generic", "key", "generics"]
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "candidates.tsv"), "w") as w:
        w.write("\t".join(cols) + "\n")
        for k, c in enumerate(cands, 1):
            c["rank"] = k
            w.write("\t".join(str(c[x]) for x in cols) + "\n")
    with open(os.path.join(args.out, "rejections.tsv"), "w") as w:
        w.write("stage\tid\tfile\tline\treason\n")
        for row, why in sorted(rejs, key=lambda r: (r[0]["file"], r[0]["line"], r[0]["id"])):
            w.write(f"static\t{row['id']}\t{row['file']}\t{row['line']}\t{why}\n")
        for file, line, why in sorted(blocks):
            w.write(f"static\t-\t{file}\t{line}\t{why}\n")
        for e in parse_errors:
            w.write(f"static\t-\t{e.split(':')[0]}\t-\tfile not read (lexer): {e}\n")
    print(f"{len(cands)} candidates ({sum(c['generic'] == 'yes' for c in cands)} generic), {len(rejs)} static rejections, {len(blocks)} skipped blocks, {len(parse_errors)} unread files, {len(unreached)} files not reached from lib.rs")
    by = {}
    for row, why in rejs:
        k = "not pure: I/O or shared state" if why.startswith("not pure: names") else re.sub(r"`[^`]*`|\([^)]*\)", "", why).strip()
        by[k] = by.get(k, 0) + 1
    for k, v in sorted(by.items(), key=lambda x: -x[1]):
        print(f"  {v:5d}  {k}")
    kinds = {}
    for c in cands:
        kinds[(c["kind"], c["generic"])] = kinds.get((c["kind"], c["generic"]), 0) + 1
    print("  candidates by kind/generic:", kinds)
    for e in parse_errors:
        print("  unread:", e, file=sys.stderr)
    for u in unreached:
        print("  not reached from lib.rs (enumerated, cfg unknown):", u, file=sys.stderr)


if __name__ == "__main__":
    main()
