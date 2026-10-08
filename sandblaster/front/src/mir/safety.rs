//! The memory-safety statement on a verified build's record
//! (docs/DESIGN-UNSAFE-SIMD.md §5.3; stage soundness-fixes, the review's
//! F4). UNTRUSTED: it restates, from the facts the narrow reading itself
//! read, what each function's MIR theorem already implies, so a mistake here
//! can misdescribe but never admit anything.
//!
//! Its facts, per function read from MIR, from the MIR the literal reading
//! reads: each raw-pointer formation with the window rule's verdict on it
//! (its kind, and the `&mut` parameters the base is reached through: A3,
//! A-S8), its family's base (`ptr::bases`: the base's type and kind), the
//! family's moves and its loads and stores through the admitted table
//! (`ptr::derivation`, `ptr::MEM_INTRINSICS`) with their byte counts and
//! constant offsets, the `core::arch` intrinsics the body calls with the
//! target features they need and where the body has them (its own
//! `#[target_feature]`, or the target's static features bound to the build's,
//! A-S3), the calls of `#[target_feature]` functions, and the calls of the
//! other functions read from MIR. The theorem (`L::thm::f`) excludes
//! `Stuck` on every input of the domain, so every move and access listed is
//! in bounds, every window is exclusive, and every intrinsic runs with its
//! features: the function has no undefined behaviour from them.

use std::collections::{BTreeMap, BTreeSet};

use super::ir::*;
use super::ptr::{self, Helper};

/// One load or store through a family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Access {
    /// The intrinsic's name (`vld1q_u8`).
    pub name: String,
    pub store: bool,
    pub bytes: u64,
    /// The byte offset in the base, when every move before it is a constant.
    pub off: Option<u64>,
}

/// One raw-pointer formation of a function and its family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Family {
    /// The helper's name (`as_mut_ptr`, `ptr::from_ref`) or `&raw mut`/`&raw const`.
    pub what: String,
    pub mutable: bool,
    /// The base's type and size in bytes (`None`: a slice's, its length's).
    pub base: Ty,
    pub base_bytes: Option<u64>,
    /// What it is formed from, in the source's names (`chunk`, `lut.lo[0]`).
    pub source: String,
    /// The `&mut` parameters it reaches memory through (A3, A-S8).
    pub params: Vec<String>,
    /// Its moves (`add`, `sub`, `offset`).
    pub moves: usize,
    pub accesses: Vec<Access>,
}

/// The facts of one function read from MIR.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FnFacts {
    pub name: String,
    pub families: Vec<Family>,
    /// The `core::arch` intrinsics it calls (their names) and the target
    /// features they need.
    pub intrinsics: BTreeSet<String>,
    pub needs: BTreeSet<String>,
    /// Its own `#[target_feature]` features.
    pub own_features: Vec<String>,
    /// The `#[target_feature]` functions of the crate it calls, with their
    /// features.
    pub tf_calls: BTreeMap<String, Vec<String>>,
    /// The other functions read from MIR it calls, with their call sites.
    pub calls: BTreeMap<String, usize>,
}

/// A path's last segment (`core::arch::aarch64::vld1q_u8` → `vld1q_u8`), a
/// pointer helper's short name (`std::ptr::from_ref` → `ptr::from_ref`).
fn short(path: &str) -> String {
    if path.starts_with("std::ptr::from_") || path.starts_with("core::ptr::from_") {
        return format!("ptr::{}", path.rsplit("::").next().unwrap_or(path));
    }
    path.rsplit("::").next().unwrap_or(path).to_string()
}

/// The value of an operand when it is a constant: a literal, a local
/// assigned once a literal, or the value of a checked or plain `add`,
/// `sub` or `mul` of two such (the field `0` of a checked one's result).
fn konst(f: &Fn, o: &Operand, depth: usize) -> Option<i128> {
    if depth > 8 {
        return None;
    }
    match o {
        Operand::Const(c) => match c.value() {
            Const::Int(_, v) => Some(*v),
            _ => None,
        },
        Operand::Copy(p) | Operand::Move(p) => {
            let field0 = matches!(p.proj.as_slice(), [Proj::Field(0, _)]);
            if !p.proj.is_empty() && !field0 {
                return None;
            }
            let mut found: Option<&Rvalue> = None;
            for bl in &f.blocks {
                for s in &bl.stmts {
                    if let Stmt::Assign(d, rv, _) = s
                        && d.local == p.local
                    {
                        if found.is_some() || !d.proj.is_empty() {
                            return None;
                        }
                        found = Some(rv);
                    }
                }
                if let Term::Call(_, _, d, _) = &bl.term
                    && d.local == p.local
                {
                    return None;
                }
            }
            let op = |k: &str, a: i128, b: i128| match k {
                "add" => a.checked_add(b),
                "sub" => a.checked_sub(b),
                "mul" => a.checked_mul(b),
                _ => None,
            };
            match (found?, field0) {
                (Rvalue::Use(o), false) => konst(f, o, depth + 1),
                (Rvalue::Bin(k, a, b), false) => op(k.as_str(), konst(f, a, depth + 1)?, konst(f, b, depth + 1)?),
                (Rvalue::Checked(k, a, b), true) => op(k.as_str(), konst(f, a, depth + 1)?, konst(f, b, depth + 1)?),
                _ => None,
            }
        }
        Operand::RuntimeChecks(_) => None,
    }
}

/// A place in the source's names: a local by its user name (`_n` when it
/// has none), a field by its name (a tuple's by its index), an index by
/// its constant or its local's name; a dereference of a reference is
/// implicit, as the source writes it (`lut.lo[0]`).
fn place_text(m: &Sbmir, f: &Fn, p: &Place) -> String {
    let name = |l: usize| f.debug.iter().find(|(_, x)| *x == l).map(|(n, _)| n.clone()).unwrap_or_else(|| format!("_{l}"));
    let mut s = name(p.local);
    let mut t = f.locals.get(p.local).map(|l| l.0.clone());
    for pr in &p.proj {
        let cur = t.take();
        match pr {
            Proj::Deref => {
                t = match cur {
                    Some(Ty::Ref(_, inner) | Ty::Ptr(_, inner)) => Some(*inner),
                    _ => None,
                };
            }
            Proj::Field(i, ft) => {
                let fname = match &cur {
                    Some(Ty::Adt(k)) => m.adts.get(k).and_then(|d| d.variants.first()).and_then(|v| v.fields.get(*i)).map(|fd| fd.0.clone()),
                    _ => None,
                };
                s = format!("{s}.{}", fname.unwrap_or_else(|| i.to_string()));
                t = Some(ft.clone());
            }
            Proj::Index(l) => {
                let i = konst(f, &Operand::Copy(Place { local: *l, proj: vec![] }), 0).map(|v| v.to_string()).unwrap_or_else(|| name(*l));
                s = format!("{s}[{i}]");
                t = match cur {
                    Some(Ty::Array(e, _) | Ty::Slice(e)) => Some(*e),
                    _ => None,
                };
            }
            Proj::Downcast(_) => t = cur,
            Proj::Unsupported(_) => return s,
        }
    }
    s
}

/// What the reference a formation takes points into, in the source's
/// names: the place it borrows (`&lut.lo[0]`, through an `unsize`
/// temporary), or the variable it was moved or copied from (`chunk`).
fn source_text(m: &Sbmir, f: &Fn, local: usize, depth: usize) -> String {
    if depth > 4 {
        return format!("_{local}");
    }
    if f.debug.iter().any(|(_, x)| *x == local) {
        return place_text(m, f, &Place { local, proj: vec![] });
    }
    let mut assigned: Vec<&Rvalue> = Vec::new();
    for bl in &f.blocks {
        for s in &bl.stmts {
            if let Stmt::Assign(d, rv, _) = s
                && d.local == local
                && d.proj.is_empty()
            {
                assigned.push(rv);
            }
        }
    }
    match assigned.as_slice() {
        [Rvalue::Ref(_, q) | Rvalue::AddrOf(_, q)] => place_text(m, f, q),
        [Rvalue::Use(Operand::Copy(q) | Operand::Move(q)) | Rvalue::Cast(_, Operand::Copy(q) | Operand::Move(q), _)] if q.proj.is_empty() => source_text(m, f, q.local, depth + 1),
        [Rvalue::Use(Operand::Copy(q) | Operand::Move(q))] => place_text(m, f, q),
        _ => format!("_{local}"),
    }
}

/// The facts of the function `key` of `m` (its lifted name `name`; `named`
/// gives the lifted name of another instance read from MIR).
pub fn facts(m: &Sbmir, key: &str, name: &str, named: &dyn std::ops::Fn(&str) -> Option<String>) -> Option<FnFacts> {
    let f = m.fns.get(key)?;
    let mut out = FnFacts { name: name.to_string(), own_features: f.target_features.clone(), ..FnFacts::default() };
    let bases = ptr::bases(m, f);
    let param_name = |l: usize| f.debug.iter().find(|(_, x)| *x == l).map(|(n, _)| n.clone()).unwrap_or_else(|| format!("_{l}"));
    // every derivation of the function: (point, source, destination, move:
    // the byte offset it adds, `None` when not a constant; or a cast)
    let mut derivs: Vec<(usize, usize, Option<Option<i128>>)> = Vec::new();
    for (b, bl) in f.blocks.iter().enumerate() {
        for i in 0..=bl.stmts.len() {
            let Some((s, d)) = ptr::derivation(m, f, b, i) else { continue };
            let mv = if i < bl.stmts.len() {
                match &bl.stmts[i] {
                    Stmt::Assign(_, Rvalue::Bin(k, _, o), _) if k == "offset" => {
                        let size = match &f.locals[d].0 {
                            Ty::Ptr(_, t) => ptr::size_of(t).map(|n| n as i128),
                            _ => None,
                        };
                        Some(konst(f, o, 0).zip(size).map(|(k, n)| k * n))
                    }
                    _ => None,
                }
            } else {
                match &bl.term {
                    Term::Call(Callee::Fn(k), args, _, _) => match m.fns.get(k).and_then(ptr::helper) {
                        Some(Ok((Helper::Move { neg, signed }, pointee))) => {
                            let size = ptr::size_of(&pointee).map(|n| n as i128);
                            let k = args.get(1).and_then(|a| konst(f, a, 0)).map(|k| if signed { k as u64 as i64 as i128 } else { k });
                            Some(k.zip(size).map(|(k, n)| if neg { -k * n } else { k * n }))
                        }
                        _ => None,
                    },
                    _ => None,
                }
            };
            derivs.push((s, d, mv));
        }
    }
    // the formations, in the order of the blocks, each with its verdict
    for bl in &f.blocks {
        for i in 0..=bl.stmts.len() {
            let (what, at, dest, src) = if i < bl.stmts.len() {
                match &bl.stmts[i] {
                    Stmt::Assign(d, Rvalue::AddrOf(mt, q), at) if d.proj.is_empty() => (if *mt { "&raw mut".to_string() } else { "&raw const".to_string() }, at.clone(), d.local, place_text(m, f, q)),
                    _ => continue,
                }
            } else {
                match &bl.term {
                    Term::Call(Callee::Fn(k), args, d, _) if d.proj.is_empty() => match m.fns.get(k) {
                        Some(g) if matches!(ptr::helper(g), Some(Ok((Helper::Form { .. }, _)))) => {
                            let src = match args.first() {
                                Some(Operand::Copy(q) | Operand::Move(q)) if q.proj.is_empty() => source_text(m, f, q.local, 0),
                                _ => "?".into(),
                            };
                            (g.def.clone(), bl.term_loc.clone(), d.local, src)
                        }
                        _ => continue,
                    },
                    _ => continue,
                }
            };
            let verdict = f.window.iter().flatten().find(|v| v.at == at && v.what == what);
            let params: Vec<String> = verdict.map(|v| v.params.iter().map(|l| param_name(*l)).collect()).unwrap_or_default();
            let Some(Ok(base)) = bases.get(&dest) else { continue };
            // the family: the derivations from `dest`, with each member's offset
            let mut off: BTreeMap<usize, Option<i128>> = BTreeMap::from([(dest, Some(0))]);
            let mut moves = 0;
            loop {
                let before = off.len();
                for (s, d, mv) in &derivs {
                    if let Some(o) = off.get(s).copied()
                        && !off.contains_key(d)
                    {
                        let o2 = match mv {
                            Some(Some(k)) => o.map(|o| o + k),
                            Some(None) => None,
                            None => o,
                        };
                        if mv.is_some() {
                            moves += 1;
                        }
                        off.insert(*d, o2);
                    }
                }
                if off.len() == before {
                    break;
                }
            }
            let mut accesses = Vec::new();
            for bl2 in &f.blocks {
                if let Term::Call(Callee::Arch(a), args, _, _) = &bl2.term
                    && let Some(row) = ptr::mem_intrinsic(&a.path)
                    && let Some(Operand::Copy(q) | Operand::Move(q)) = args.first()
                    && q.proj.is_empty()
                    && let Some(o) = off.get(&q.local)
                {
                    accesses.push(Access { name: short(&a.path), store: row.store, bytes: row.bytes, off: o.and_then(|o| u64::try_from(o).ok()) });
                }
            }
            out.families.push(Family { what: short(&what), mutable: base.mutable, base: base.ty.clone(), base_bytes: ptr::size_of(&base.ty), source: src, params, moves, accesses });
        }
    }
    // the intrinsics, the `#[target_feature]` functions and the other
    // functions read from MIR it calls
    for bl in &f.blocks {
        let Term::Call(c, ..) = &bl.term else { continue };
        match c {
            Callee::Arch(a) => {
                out.intrinsics.insert(short(&a.path));
                out.needs.extend(a.features.iter().cloned());
            }
            Callee::Fn(k) => {
                if let Some(n) = named(k) {
                    *out.calls.entry(n.clone()).or_default() += 1;
                    if let Some(g) = m.fns.get(k)
                        && !g.target_features.is_empty()
                        && g.target_features.iter().any(|t| !f.target_features.contains(t))
                    {
                        out.tf_calls.insert(n, g.target_features.clone());
                    }
                }
            }
            _ => {}
        }
    }
    Some(out)
}

fn ty_text(t: &Ty) -> String {
    match t {
        Ty::Int(false, 0) => "usize".into(),
        Ty::Int(s, b) => format!("{}{b}", if *s { "i" } else { "u" }),
        Ty::Array(e, n) => format!("[{}; {n}]", ty_text(e)),
        Ty::Slice(e) => format!("[{}]", ty_text(e)),
        Ty::Simd(p, _, _) => short(p),
        other => format!("{other:?}"),
    }
}

/// `0, 16, 32 and 48`.
fn list(v: &[String]) -> String {
    match v {
        [] => String::new(),
        [a] => a.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// One family's accesses, by intrinsic: `4 loads (`vld1q_u8`, 16 bytes at
/// offsets 0, 16, 32 and 48)`.
fn accesses_text(acc: &[Access]) -> String {
    let mut groups: BTreeMap<(bool, String, u64), Vec<Option<u64>>> = BTreeMap::new();
    for a in acc {
        groups.entry((a.store, a.name.clone(), a.bytes)).or_default().push(a.off);
    }
    let mut parts = Vec::new();
    for ((store, name, bytes), offs) in groups {
        let n = offs.len();
        let kind = match (store, n) {
            (false, 1) => "load",
            (false, _) => "loads",
            (true, 1) => "store",
            (true, _) => "stores",
        };
        let at: Vec<String> = offs.iter().map(|o| o.map(|o| o.to_string()).unwrap_or_else(|| "a computed offset".into())).collect();
        parts.push(format!("{n} {kind} (`{name}`, {bytes} bytes at offset{} {})", if n == 1 { "" } else { "s" }, list(&at)));
    }
    list(&parts)
}

/// The statement of one function (a sentence or a few), from its facts;
/// `statics`: the target's static features bound to the build's (A-S3).
pub fn statement(fx: &FnFacts, statics: Option<&[String]>, target: &str) -> String {
    let mut s = format!("`{}`:", fx.name);
    if fx.families.is_empty() {
        s.push_str(" no raw pointer.");
    }
    // families of the same shape, grouped (`mul_128`'s eight table rows)
    let mut groups: Vec<(Family, Vec<String>)> = Vec::new();
    for fam in &fx.families {
        let key = Family { source: String::new(), ..fam.clone() };
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, srcs)) => srcs.push(fam.source.clone()),
            None => groups.push((key, vec![fam.source.clone()])),
        }
    }
    for (fam, srcs) in &groups {
        let n = srcs.len();
        let bytes = fam.base_bytes.map(|b| format!(" of {b} bytes")).unwrap_or_default();
        let base = if fam.mutable { format!("a mutable base{bytes}, written back through its reference") } else { format!("a shared base{bytes}, read as its value when formed") };
        let srcs: Vec<String> = srcs.iter().map(|x| format!("`{x}`")).collect();
        s.push_str(&format!(
            " {} raw pointer{} formed by `{}` from {} (`{}`: {base}{});",
            n,
            if n == 1 { "" } else { "s" },
            fam.what,
            list(&srcs),
            ty_text(&fam.base),
            if fam.params.is_empty() { String::new() } else { format!(", reached through the `&mut` parameter{} {}, assumed to alias no other parameter (A3)", if fam.params.len() == 1 { "" } else { "s" }, list(&fam.params.iter().map(|p| format!("`{p}`")).collect::<Vec<_>>())) },
        ));
        let each = if n == 1 { "through it" } else { "through each" };
        let moves = match fam.moves {
            0 => String::new(),
            1 => "1 move and ".into(),
            k => format!("{k} moves and "),
        };
        s.push_str(&format!(" {each} {moves}{}, each inside the base;", if fam.accesses.is_empty() { "no access".to_string() } else { accesses_text(&fam.accesses) }));
        s.push_str(if fam.mutable { " the window rule passed: nothing else reaches the base while the pointer is in use." } else { " the window rule passed: nothing writes the base while the pointer is in use." });
    }
    for (callee, n) in &fx.calls {
        let tf = fx.tf_calls.get(callee).map(|t| format!(", a `#[target_feature(enable = \"{}\")]` function", t.join(",")));
        s.push_str(&format!(" It calls `{callee}`{} ({n} call site{}).", tf.unwrap_or_default(), if *n == 1 { "" } else { "s" }));
    }
    let mut needs: BTreeSet<String> = fx.needs.clone();
    for t in fx.tf_calls.values() {
        needs.extend(t.iter().cloned());
    }
    if fx.intrinsics.is_empty() && needs.is_empty() {
        if fx.families.is_empty() && fx.calls.is_empty() {
            s.push_str(" No intrinsic: safe code.");
        }
        return s;
    }
    let own: Vec<&String> = needs.iter().filter(|n| fx.own_features.contains(*n)).collect();
    let stat: Vec<&String> = needs.iter().filter(|n| !fx.own_features.contains(*n) && statics.is_some_and(|st| st.contains(*n))).collect();
    let none: Vec<&String> = needs.iter().filter(|n| !own.contains(n) && !stat.contains(n)).collect();
    let feats = |v: &[&String]| list(&v.iter().map(|x| format!("`{x}`")).collect::<Vec<_>>());
    let mut how = Vec::new();
    if !own.is_empty() {
        how.push(format!("{} enabled by its own `#[target_feature]`", feats(&own)));
    }
    if !stat.is_empty() {
        how.push(format!("{} enabled statically on `{target}` (the build's static target features, A-S3)", feats(&stat)));
    }
    if !none.is_empty() {
        how.push(format!("{} not established here", feats(&none)));
    }
    let intr: Vec<String> = fx.intrinsics.iter().map(|i| format!("`{i}`")).collect();
    let subject = match (intr.as_slice(), fx.tf_calls.is_empty()) {
        ([], _) => "Its calls need".to_string(),
        ([one], true) => format!("Its intrinsic {one} needs"),
        (_, true) => format!("Its intrinsics ({}) need", list(&intr)),
        (_, false) => format!("Its intrinsics ({}) and calls need", list(&intr)),
    };
    s.push_str(&format!(" {subject} {}: {}.", feats(&needs.iter().collect::<Vec<_>>()), list(&how)));
    s
}

/// The record's section: one statement per function read from MIR (`read`:
/// `(lifted name, MIR instance)`), and whether any forms a raw pointer;
/// `None` when no function forms a pointer, calls an intrinsic or calls a
/// `#[target_feature]` function (the record of safe code says nothing more).
pub fn section(loaded: &super::Loaded, read: &[(String, String)]) -> Option<(Vec<String>, bool)> {
    let by_key: BTreeMap<&str, &str> = read.iter().map(|(n, k)| (k.as_str(), n.as_str())).collect();
    let named = |k: &str| by_key.get(k).map(|n| n.to_string());
    let target = loaded.m.target.as_ref().map(|t| t.0.clone()).unwrap_or_default();
    let (mut lines, mut any, mut pointers) = (Vec::new(), false, false);
    for (n, k) in read {
        let Some(fx) = facts(&loaded.m, k, n, &named) else { continue };
        any |= !fx.families.is_empty() || !fx.intrinsics.is_empty() || !fx.tf_calls.is_empty();
        pointers |= !fx.families.is_empty();
        lines.push(statement(&fx, loaded.m.static_facts.as_deref(), &target));
    }
    any.then_some((lines, pointers))
}
