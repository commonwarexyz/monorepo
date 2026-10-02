#!/usr/bin/env python3
"""H2 enumeration, static filter and seeded order (RULE.md sections 1-4).

    python3 sandblaster/bench/heldout/h2/sample.py

Run from anywhere; paths resolve against the monorepo root. Writes, next to
this file:

* candidates.tsv: every candidate (RULE.md sections 1-3), in the seeded order
  of section 4;
* rejections.tsv: every function in a scope file that is not a candidate,
  with the first criterion it fails.

The probe (probe.py) takes candidates.tsv in order. Lexical only: comments are
dropped and string literals kept as single tokens, then items are read with
balanced brackets. No cargo, no rustc.
"""
import hashlib
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "../../../.."))
SEED = "6da19874a074881c6db6d18cf32b096f"

# RULE.md section 1: (package, crate dir, src-relative prefixes; empty: the whole crate)
SCOPE = [
    ("commonware-utils", "utils", []),
    ("commonware-math", "math", []),
    ("commonware-stream", "stream", []),
    ("commonware-p2p", "p2p", []),
    ("commonware-consensus", "consensus", []),
    ("commonware-storage", "storage", ["journal", "ordinal", "freezer"]),
]
ARITHMETIC_ONLY = {"commonware-consensus"}

# RULE.md section 2
TARGET_TOKENS = {"varint", "merkle", "mmr", "bmt", "qmdb", "sha256", "Sha256", "bls12381", "ed25519", "reed_solomon", "ReedSolomon"}
MATRIX_NAMES = {"parse", "shape_go", "shape", "cswap", "mul_by_014", "verify_many", "mul"}
TEST_PATH_PARTS = {"tests", "test", "mocks", "mock", "test_utils", "fuzz", "benches", "bench", "examples"}
TEST_CFG_IDENTS = {"test", "fuzzing"}
TEST_CFG_STRINGS = {"mocks", "test-utils", "fuzzing", "arbitrary", "test"}

# RULE.md section 3
IO_IDENTS = {
    "io", "fs", "net", "File", "TcpStream", "TcpListener", "UdpSocket",
    "tokio", "futures", "spawn", "thread", "Instant", "SystemTime",
    "Clock", "Spawner", "Storage", "Blob", "Network", "Sink", "Stream", "Metrics", "metrics", "Context",
    "tracing", "rand", "Rng", "RngCore", "CryptoRng", "rng",
    "Cell", "RefCell", "Mutex", "RwLock", "Arc", "Rc", "atomic",
}
IO_MACROS = {"println", "eprintln", "print", "eprint", "dbg", "trace", "debug", "info", "warn", "error"}
INT_TYPES = {"u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize"}
ARITH_TYPE_IDENTS = INT_TYPES | {"bool", "char", "Option", "Result", "mut"}


# ---------------------------------------------------------------------------
# lexer
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
    """attr: the tokens inside `#[ .. ]`."""
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


def generic_params(toks, i):
    """toks[i] is `<`: returns (end index after `>`, has a type/const parameter)."""
    depth, j, typed, start_param = 0, i, False, True
    while j < len(toks):
        t = toks[j]
        if t.kind == "punct":
            if t.text == "<":
                depth += 1
                if depth == 1:
                    start_param = True
                    j += 1
                    continue
            elif t.text == ">":
                depth -= 1
                if depth == 0:
                    return j + 1, typed
            elif t.text == ">>":
                depth -= 2
                if depth <= 0:
                    return j + 1, typed
            elif t.text == "->":
                pass
            elif t.text == "," and depth == 1:
                start_param = True
                j += 1
                continue
        if depth == 1 and start_param:
            if t.kind != "life":
                typed = True
            start_param = False
        j += 1
    return j, typed


SKIPPED = []


class Fn:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def parse_items(toks, i, end, ctx, out, mods):
    """Reads the items of toks[i:end] (a module or impl/trait body)."""
    while i < end:
        attrs, testish = [], ctx["testish"]
        # attributes
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
                i = k + 1
            else:
                break
        if i >= end:
            break
        start = i
        # visibility
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
            fn_generic = False
            if toks[j].kind == "punct" and toks[j].text == "<":
                j, fn_generic = generic_params(toks, j)
            # parameters
            if not (toks[j].kind == "punct" and toks[j].text == "("):
                raise ValueError(f"fn {name}: no parameter list at line {toks[j].line}")
            pclose = close_of(toks, j)
            params = toks[j + 1:pclose]
            k = pclose + 1
            # return type / where clause up to the body or `;`
            while k < end and not (toks[k].kind == "punct" and toks[k].text in ("{", ";")):
                if toks[k].kind == "punct" and toks[k].text in ("(", "["):
                    k = close_of(toks, k) + 1
                    continue
                k += 1
            ret = toks[pclose + 1:k]
            if toks[k].text == ";":
                body = None
                nxt = k + 1
            else:
                bclose = close_of(toks, k)
                body = toks[k + 1:bclose]
                nxt = bclose + 1
            out.append(Fn(name=name, line=toks[start].line, attrs=attrs, testish=testish, quals=quals, fn_generic=fn_generic,
                          params=params, ret=ret, body=body, sig=toks[start:k], ctx=dict(ctx)))
            i = nxt
            continue
        if kw in ("impl", "trait") or (kw == "auto" and toks[i + 1].text == "trait"):
            if kw == "auto":
                i += 1
            j = i + 1
            generic = False
            if toks[j].kind == "punct" and toks[j].text == "<":
                j, generic = generic_params(toks, j)
            hdr_start = j
            while not (toks[j].kind == "punct" and toks[j].text == "{"):
                if toks[j].kind == "punct" and toks[j].text in ("(", "["):
                    j = close_of(toks, j) + 1
                    continue
                if toks[j].kind == "punct" and toks[j].text == "<":
                    j, _ = generic_params(toks, j)
                    continue
                j += 1
            hdr = toks[hdr_start:j]
            if any(x.kind == "ident" and x.text == "where" for x in hdr):
                generic = True
            bclose = close_of(toks, j)
            sub = dict(ctx)
            sub["testish"] = testish
            if kw == "trait":
                sub["kind"] = "trait"
                sub["self_ty"] = toks[i + 1].text
            else:
                # `impl Trait for Type` at angle depth 0
                depth, is_trait, ty_toks = 0, False, []
                for x in hdr:
                    if x.kind == "punct" and x.text == "<":
                        depth += 1
                    elif x.kind == "punct" and x.text == ">":
                        depth -= 1
                    elif x.kind == "punct" and x.text == ">>":
                        depth -= 2
                    elif x.kind == "ident" and x.text == "for" and depth == 0:
                        is_trait = True
                        ty_toks = []
                        continue
                    elif x.kind == "ident" and x.text == "where" and depth == 0:
                        break
                    ty_toks.append(x)
                # the self type's name: the last path segment at depth 0
                name, depth = None, 0
                for x in ty_toks:
                    if x.kind == "punct" and x.text == "<":
                        depth += 1
                    elif x.kind == "punct" and x.text in (">", ">>"):
                        depth -= 1 if x.text == ">" else 2
                    elif x.kind == "ident" and depth == 0 and x.text not in ("dyn", "mut", "for"):
                        name = x.text
                sub["kind"] = "trait_impl" if is_trait else "inherent"
                sub["self_ty"] = name
                sub["trait"] = None
                if is_trait:
                    # the trait's last segment (before `for`)
                    d, tr = 0, None
                    for x in hdr:
                        if x.kind == "punct" and x.text == "<":
                            d += 1
                        elif x.kind == "punct" and x.text in (">", ">>"):
                            d -= 1 if x.text == ">" else 2
                        elif x.kind == "ident" and x.text == "for" and d == 0:
                            break
                        elif x.kind == "ident" and d == 0:
                            tr = x.text
                    sub["trait"] = tr
            sub["impl_generic"] = generic
            sub["impl_line"] = toks[i].line
            ctx_impls = ctx.setdefault("_impls", [])
            ctx_impls.append(sub)
            parse_items(toks, j + 1, bclose, sub, out, mods)
            i = bclose + 1
            continue
        if kw == "mod":
            name = toks[i + 1].text
            if toks[i + 2].kind == "punct" and toks[i + 2].text == ";":
                mods.append((name, testish))
                i += 3
            else:
                k = close_of(toks, i + 2)
                nfn = sum(1 for x in toks[i + 2:k] if x.kind == "ident" and x.text == "fn")
                if nfn:
                    SKIPPED.append((toks[i].line, f"not enumerated: inline module `{name}` ({nfn} fn token(s); RULE.md 3)"))
                i = k + 1  # inline module: skipped (RULE.md section 3)
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
        # a macro invocation at item level: `path! { .. }` / `path!(..);`
        j = i
        while j < end and (toks[j].kind == "ident" or (toks[j].kind == "punct" and toks[j].text == "::")):
            j += 1
        if j > i and j < end and toks[j].kind == "punct" and toks[j].text == "!" and kw not in ("struct", "enum", "union", "type", "use", "static", "const", "extern"):
            k = j + 1
            if toks[k].kind == "ident":  # macro_rules! name {..} handled above; `name! ident {..}`
                k += 1
            kc = close_of(toks, k)
            nfn = sum(1 for x in toks[k:kc] if x.kind == "ident" and x.text == "fn")
            if nfn:
                SKIPPED.append((toks[i].line, f"not enumerated: inside the macro invocation `{''.join(x.text for x in toks[i:j])}!` ({nfn} fn token(s); RULE.md 3)"))
            i = kc + 1
            if i < end and toks[i].kind == "punct" and toks[i].text == ";":
                i += 1
            continue
        # anything else (struct, enum, union, type, const, static, use, extern block)
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


def is_self_param(p):
    texts = [t.text for t in p]
    return "self" in texts and (texts[0] in ("self", "&", "mut") and (":" not in texts or texts.index("self") < texts.index(":")))


def arithmetic_type(ty):
    """RULE.md section 1, consensus: built from integers, bool, char, (),
    references, slices, arrays, tuples, Option/Result of these."""
    for k, t in enumerate(ty):
        if t.kind == "ident":
            if t.text in ARITH_TYPE_IDENTS:
                continue
            # an array length named by a constant (`[u8; SIZE]`)
            if t.text.isupper() and k > 0 and ty[k - 1].kind == "punct" and ty[k - 1].text == ";":
                continue
            return False
        if t.kind in ("life", "num"):
            continue
        if t.kind == "punct" and t.text in ("&", "&&", "[", "]", ";", "(", ")", ",", "<", ">", ">>"):
            continue
        return False
    return True


def corpus_names():
    names = set()
    text = open(os.path.join(REPO, "sandblaster/front/tests/opt_corpus/corpus.toml")).read()
    for m in re.finditer(r"^functions\s*=\s*\[(.*?)\]", text, re.M | re.S):
        for f in re.findall(r'"([^"]+)"', m.group(1)):
            names.add(f.rsplit("::", 1)[-1])
    return names


def classify(f, pkg, rel, corpus):
    """The first criterion f fails (RULE.md sections 2-3), or None."""
    sig_ids, body_ids = idents(f.sig), idents(f.body or [])
    allids = sig_ids | body_ids
    alltoks = f.sig + (f.body or [])
    parts = rel.split("/")
    if any(p in TEST_PATH_PARTS or os.path.splitext(p)[0] in TEST_PATH_PARTS for p in parts[1:]):
        return "excluded: test, mock or fuzz file (RULE.md 2.4)"
    if f.testish:
        return "excluded: under a test/mocks/fuzzing cfg (RULE.md 2.4)"
    if any(attr_is_test_fn(a) for a in f.attrs):
        return "excluded: a #[test] function (RULE.md 2.4)"
    if f.body is None:
        return "not a candidate: no body (a trait's required method)"
    hit = sorted(allids & TARGET_TOKENS)
    if hit:
        return f"excluded: names a target area ({', '.join(hit)}) (RULE.md 2.1)"
    if f.name in corpus:
        return f"excluded: named like a corpus.toml function `{f.name}` (RULE.md 2.2)"
    if f.name in MATRIX_NAMES:
        return f"excluded: named like a §15 matrix function `{f.name}` (RULE.md 2.3)"
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
    if f.fn_generic:
        return "not monomorphic: type or const parameters (RULE.md 3)"
    if f.ctx.get("impl_generic"):
        return "not monomorphic: a generic impl (RULE.md 3)"
    if "impl" in idents(f.params):
        return "not monomorphic: an `impl Trait` parameter (RULE.md 3)"
    kind = f.ctx.get("kind", "free")
    if kind == "trait_impl":
        return f"not a free function or inherent method: a method of `impl {f.ctx.get('trait')} for {f.ctx.get('self_ty')}` (RULE.md 3)"
    if kind == "trait":
        return "not a free function or inherent method: a trait's provided method (RULE.md 3)"
    if pkg in ARITHMETIC_ONLY:
        for p in split_top(f.params):
            if not p or is_self_param(p):
                continue
            ty = p[[t.text for t in p].index(":") + 1:] if any(t.text == ":" for t in p) else p
            if not arithmetic_type(ty):
                return "consensus: not arithmetic, a parameter type (RULE.md 1)"
        if f.ret:
            r = f.ret
            if r and r[0].text == "->":
                r = r[1:]
            # drop a where clause
            w = [k for k, t in enumerate(r) if t.kind == "ident" and t.text == "where"]
            if w:
                r = r[:w[0]]
            if not arithmetic_type(r):
                return "consensus: not arithmetic, the result type (RULE.md 1)"
    return None


def scope_files():
    for pkg, d, prefixes in SCOPE:
        src = os.path.join(REPO, d, "src")
        for root, dirs, files in os.walk(src):
            dirs.sort()
            for fn in sorted(files):
                if not fn.endswith(".rs"):
                    continue
                rel = os.path.relpath(os.path.join(root, fn), os.path.join(REPO, d))
                inner = rel[len("src/"):]
                if prefixes and not any(inner == p + ".rs" or inner.startswith(p + "/") for p in prefixes):
                    continue
                yield pkg, d, rel


def main():
    corpus = corpus_names()
    cands, rejs, parse_errors, blocks = [], [], [], []
    for pkg, d, rel in scope_files():
        path = os.path.join(REPO, d, rel)
        src = open(path, encoding="utf-8").read()
        toks = lex(src)
        out, mods = [], []
        SKIPPED.clear()
        ctx = {"testish": False, "kind": "free"}
        try:
            parse_items(toks, 0, len(toks), ctx, out, mods)
        except (ValueError, IndexError) as e:
            parse_errors.append(f"{d}/{rel}: {e}")
            continue
        mp = module_path(rel)
        for line, why in SKIPPED:
            blocks.append((f"{d}/{rel}", line, why))
        impls = ctx.get("_impls", [])
        for f in out:
            kind = f.ctx.get("kind", "free")
            owner = f.ctx.get("self_ty") if kind != "free" else None
            local = f"{owner}::{f.name}" if owner else f.name
            fid = "::".join(x for x in (pkg, mp, local) if x)
            why = classify(f, pkg, rel, corpus)
            row = dict(id=fid, package=pkg, crate_dir=d, file=f"{d}/{rel}", line=f.line, module=mp, kind=("method" if owner else "fn"),
                       item=(owner or f.name), name=f.name)
            if why:
                rejs.append((row, why))
                continue
            if kind == "inherent":
                # the type's other inherent methods (--skip-fns / unverified_fns) and its traits (unverified_impls)
                others = sorted({g.name for g in out if g.ctx.get("kind") == "inherent" and g.ctx.get("self_ty") == owner and g.name != f.name})
                traits = sorted({im.get("trait") for im in impls if im.get("kind") == "trait_impl" and im.get("self_ty") == owner and im.get("trait")})
                row["others"] = ",".join(others)
                row["traits"] = ",".join(traits)
            else:
                row["others"], row["traits"] = "", ""
            row["children"] = ",".join(m for m, _ in mods)
            cands.append(row)
    for c in cands:
        c["key"] = hashlib.sha256(f"{SEED}:{c['id']}".encode()).hexdigest()
    cands.sort(key=lambda c: (c["key"], c["id"]))
    cols = ["rank", "id", "package", "file", "line", "module", "kind", "item", "name", "others", "traits", "children", "key"]
    with open(os.path.join(HERE, "candidates.tsv"), "w") as w:
        w.write("\t".join(cols) + "\n")
        for k, c in enumerate(cands, 1):
            c["rank"] = k
            w.write("\t".join(str(c[x]) for x in cols) + "\n")
    with open(os.path.join(HERE, "rejections.tsv"), "w") as w:
        w.write("stage\tid\tfile\tline\treason\n")
        for row, why in sorted(rejs, key=lambda r: (r[0]["file"], r[0]["line"])):
            w.write(f"static\t{row['id']}\t{row['file']}\t{row['line']}\t{why}\n")
        for file, line, why in sorted(blocks):
            w.write(f"static\t-\t{file}\t{line}\t{why}\n")
        for e in parse_errors:
            w.write(f"static\t-\t{e.split(':')[0]}\t-\tfile not read (lexer): {e}\n")
    print(f"{len(cands)} candidates, {len(rejs)} static rejections, {len(blocks)} skipped blocks, {len(parse_errors)} unread files")
    by = {}
    for row, why in rejs:
        k = "not pure: I/O or shared state" if why.startswith("not pure: names") else why.split(":")[0] + ": " + re.sub(r"`[^`]*`|\(RULE.*", "", why.split(":", 1)[1]).split("(")[0].strip()
        by[k] = by.get(k, 0) + 1
    for k, v in sorted(by.items(), key=lambda x: -x[1]):
        print(f"  {v:5d}  {k}")
    if parse_errors:
        for e in parse_errors:
            print("  unread:", e, file=sys.stderr)


if __name__ == "__main__":
    main()
