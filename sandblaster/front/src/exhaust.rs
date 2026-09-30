//! Pattern exhaustiveness (usefulness algorithm of Maranget, "Warnings for
//! pattern matching", with rustc-style constructor splitting).
//!
//! [`missing`] returns a witness value (printed as a pattern) not matched by
//! any of the given patterns, or `None` if they are exhaustive. Guarded arms
//! must be excluded by the caller (a guard may fail).
//!
//! Constructor sets per type:
//! * `bool`: `false`, `true`; `Option<T>`: `None`, `Some(_)`; enums: variants;
//! * structs, tuples, references (`Deref`) and arrays: a single constructor;
//! * unsigned integers: the value range `0..=MAX`, split into maximal
//!   intervals on which every literal/range pattern is constant; `usize`
//!   is open-ended, as in rustc (no `precise_pointer_size_matching` on
//!   stable: `0..=usize::MAX` does not cover `usize`, whose maximum depends
//!   on the target), modelled by one value past `usize::MAX` that no
//!   literal or range pattern covers — only wildcards and bindings do;
//! * slices: lengths `0..L` plus a variable-length tail constructor, where
//!   `L = max(longest fixed-length pattern + 1, longest prefix + suffix of a
//!   variable-length pattern)`;
//! * every other type (vectors, type parameters, `Int`, ...) is opaque: only
//!   wildcards and bindings cover it.

use crate::hir::{Ctor, ItemId, ItemKind, Lit, Pat, PatKind, Ty, UintTy};

/// Deconstructed constructors.
#[derive(Clone, Debug, PartialEq)]
enum Cons {
    Bool(bool),
    /// Enum variant index (`Option`: `None` = 0, `Some` = 1).
    Variant(u32),
    /// Structs, tuples, references, arrays.
    Single,
    IntRange(u128, u128),
    /// A slice of exactly this length.
    FixedLen(u64),
    /// Variable-length slice pattern with prefix and suffix lengths.
    VarLen(u64, u64),
}

#[derive(Clone, Debug)]
enum DPat {
    Wild,
    Ctor(Cons, Vec<DPat>),
    Or(Vec<DPat>),
}

/// Witness trees.
#[derive(Clone, Debug)]
enum Wit {
    Wild,
    Ctor(Cons, Vec<Wit>),
}

type Lookup<'a> = &'a dyn Fn(ItemId) -> Option<ItemKind>;
type Names<'a> = &'a dyn Fn(ItemId) -> String;

/// A witness of non-exhaustiveness (as pattern text), if any.
pub fn missing(ty: &Ty, pats: &[&Pat], lookup: Lookup, names: Names) -> Option<String> {
    let rows: Vec<Vec<DPat>> = pats.iter().map(|p| vec![lower(p)]).collect();
    let w = useful(&rows, std::slice::from_ref(ty), lookup, 0)?;
    Some(print(&w[0], ty, lookup, names))
}

fn lower(p: &Pat) -> DPat {
    match &p.kind {
        PatKind::Wild => DPat::Wild,
        PatKind::Binding { sub: None, .. } => DPat::Wild,
        PatKind::Binding { sub: Some(s), .. } => lower(s),
        PatKind::Lit(Lit::Bool(b)) => DPat::Ctor(Cons::Bool(*b), vec![]),
        PatKind::Lit(Lit::Int(v)) => DPat::Ctor(Cons::IntRange(*v, *v), vec![]),
        PatKind::Range { lo, hi } => DPat::Ctor(Cons::IntRange(*lo, *hi), vec![]),
        PatKind::Tuple(ps) => DPat::Ctor(Cons::Single, ps.iter().map(lower).collect()),
        PatKind::Ctor { ctor, fields, .. } => {
            let n = ctor_field_count(p, *ctor);
            let mut fs = vec![DPat::Wild; n];
            for (i, f) in fields {
                if (*i as usize) < n {
                    fs[*i as usize] = lower(f);
                }
            }
            let c = match ctor {
                Ctor::Struct(_) => Cons::Single,
                Ctor::Variant(_, i) => Cons::Variant(*i),
                Ctor::None => Cons::Variant(0),
                Ctor::Some => Cons::Variant(1),
            };
            DPat::Ctor(c, fs)
        }
        PatKind::Deref { pat, .. } => DPat::Ctor(Cons::Single, vec![lower(pat)]),
        PatKind::Slice { prefix, rest, suffix } => {
            let pre: Vec<DPat> = prefix.iter().map(lower).collect();
            let suf: Vec<DPat> = suffix.iter().map(lower).collect();
            match &p.ty {
                Ty::Array(_, n) => {
                    let mut fs = pre;
                    let mid = (*n as usize).saturating_sub(fs.len() + suf.len());
                    fs.extend(std::iter::repeat_n(DPat::Wild, mid));
                    fs.extend(suf);
                    DPat::Ctor(Cons::Single, fs)
                }
                _ => match rest {
                    None => DPat::Ctor(Cons::FixedLen(pre.len() as u64), pre),
                    Some(_) => {
                        let (p, s) = (pre.len() as u64, suf.len() as u64);
                        let mut fs = pre;
                        fs.extend(suf);
                        DPat::Ctor(Cons::VarLen(p, s), fs)
                    }
                },
            }
        }
        PatKind::Or(alts) => DPat::Or(alts.iter().map(lower).collect()),
    }
}

/// Number of fields of a constructor pattern (from its type arguments).
fn ctor_field_count(p: &Pat, _c: Ctor) -> usize {
    // the lowering fills written fields; the arity comes from the type at
    // specialization time, so we size by the largest index + 1 here and pad
    // later in `specialize`.
    match &p.kind {
        PatKind::Ctor { fields, .. } => fields.iter().map(|(i, _)| *i as usize + 1).max().unwrap_or(0),
        _ => 0,
    }
}

/// Field types of constructor `c` at type `ty`.
fn field_tys(ty: &Ty, c: &Cons, lookup: Lookup) -> Vec<Ty> {
    match (ty, c) {
        (Ty::Option(t), Cons::Variant(1)) => vec![(**t).clone()],
        (Ty::Option(_), Cons::Variant(_)) => vec![],
        (Ty::Adt(id, args), Cons::Variant(i)) => match lookup(*id) {
            Some(ItemKind::Enum(e)) => e.variants.get(*i as usize).map(|v| v.fields.iter().map(|f| f.ty.subst(args)).collect()).unwrap_or_default(),
            _ => vec![],
        },
        (Ty::Adt(id, args), Cons::Single) => match lookup(*id) {
            Some(ItemKind::Struct(s)) => s.fields.iter().map(|f| f.ty.subst(args)).collect(),
            _ => vec![],
        },
        (Ty::Tuple(ts), Cons::Single) => ts.clone(),
        (Ty::Ref(t), Cons::Single) => vec![(**t).clone()],
        (Ty::Array(t, n), Cons::Single) => vec![(**t).clone(); *n as usize],
        (Ty::Slice(t) | Ty::Seq(t), Cons::FixedLen(n)) => vec![(**t).clone(); *n as usize],
        (Ty::Slice(t) | Ty::Seq(t), Cons::VarLen(p, s)) => vec![(**t).clone(); (*p + *s) as usize],
        _ => vec![],
    }
}

/// The full (split) constructor list of `ty` given the head constructors
/// of the column; `None` for opaque types.
fn all_ctors(ty: &Ty, heads: &[Cons], lookup: Lookup) -> Option<Vec<Cons>> {
    match ty {
        Ty::Bool => Some(vec![Cons::Bool(false), Cons::Bool(true)]),
        Ty::Option(_) => Some(vec![Cons::Variant(0), Cons::Variant(1)]),
        Ty::Adt(id, _) => match lookup(*id) {
            Some(ItemKind::Enum(e)) => Some((0..e.variants.len() as u32).map(Cons::Variant).collect()),
            Some(ItemKind::Struct(_)) => Some(vec![Cons::Single]),
            _ => None,
        },
        Ty::Tuple(_) | Ty::Ref(_) | Ty::Array(..) => Some(vec![Cons::Single]),
        Ty::Uint(w) => {
            let max = int_ctor_max(*w);
            let mut pts: Vec<u128> = vec![0];
            for h in heads {
                if let Cons::IntRange(lo, hi) = h {
                    pts.push(*lo);
                    if *hi < max {
                        pts.push(hi + 1);
                    }
                }
            }
            pts.sort();
            pts.dedup();
            let mut out = Vec::new();
            for (i, &a) in pts.iter().enumerate() {
                let b = if i + 1 < pts.len() { pts[i + 1] - 1 } else { max };
                out.push(Cons::IntRange(a, b));
            }
            Some(out)
        }
        Ty::Slice(_) | Ty::Seq(_) => {
            let mut max_fixed: Option<u64> = None;
            let (mut max_pre, mut max_suf) = (0u64, 0u64);
            let mut any_var = false;
            for h in heads {
                match h {
                    Cons::FixedLen(n) => max_fixed = Some(max_fixed.map_or(*n, |m| m.max(*n))),
                    Cons::VarLen(p, s) => {
                        any_var = true;
                        max_pre = max_pre.max(*p);
                        max_suf = max_suf.max(*s);
                    }
                    _ => {}
                }
            }
            let l = (max_fixed.map_or(0, |m| m + 1)).max(if any_var { max_pre + max_suf } else { 0 });
            let mut out: Vec<Cons> = (0..l).map(Cons::FixedLen).collect();
            let pre = l.saturating_sub(max_suf).max(max_pre);
            out.push(Cons::VarLen(pre, l - pre.min(l)));
            Some(out)
        }
        _ => None,
    }
}

/// The largest value of the constructor range of an unsigned type: its
/// maximum, and for `usize` one more (rustc: `usize` has no fixed maximum,
/// so the values `usize::MAX + 1..` of wider targets are never covered by a
/// finite range; the error names them `usize::MAX..`).
fn int_ctor_max(w: UintTy) -> u128 {
    if w == UintTy::Usize { w.max_value() + 1 } else { w.max_value() }
}

/// Whether head constructor `h` covers (split) constructor `c`.
fn covers(h: &Cons, c: &Cons) -> bool {
    match (h, c) {
        (Cons::IntRange(a, b), Cons::IntRange(x, y)) => a <= x && y <= b,
        (Cons::FixedLen(m), Cons::FixedLen(n)) => m == n,
        (Cons::VarLen(p, s), Cons::FixedLen(n)) => p + s <= *n,
        (Cons::VarLen(..), Cons::VarLen(..)) => true,
        (Cons::FixedLen(_), Cons::VarLen(..)) => false,
        _ => h == c,
    }
}

/// Specializes a row's head pattern `h` (covering `c`) into `c`'s fields.
fn head_fields(h_cons: &Cons, h_fields: &[DPat], c: &Cons, arity: usize) -> Vec<DPat> {
    match (h_cons, c) {
        (Cons::VarLen(p, s), Cons::FixedLen(_)) | (Cons::VarLen(p, s), Cons::VarLen(..)) => {
            let (p, s) = (*p as usize, *s as usize);
            let mut out = vec![DPat::Wild; arity];
            let k = p.min(arity);
            out[..k].clone_from_slice(&h_fields[..k]);
            for j in 0..s.min(arity) {
                out[arity - s + j] = h_fields[p + j].clone();
            }
            out
        }
        _ => {
            let mut out: Vec<DPat> = h_fields.to_vec();
            out.resize(arity, DPat::Wild);
            out
        }
    }
}

fn expand_or(rows: &[Vec<DPat>]) -> Vec<Vec<DPat>> {
    let mut out = Vec::new();
    for r in rows {
        match r.first() {
            Some(DPat::Or(alts)) => {
                let expanded: Vec<Vec<DPat>> = alts
                    .iter()
                    .map(|a| {
                        let mut v = vec![a.clone()];
                        v.extend(r[1..].iter().cloned());
                        v
                    })
                    .collect();
                out.extend(expand_or(&expanded));
            }
            _ => out.push(r.clone()),
        }
    }
    out
}

/// Is the all-wildcards vector useful w.r.t. `rows`? Returns a witness.
fn useful(rows: &[Vec<DPat>], tys: &[Ty], lookup: Lookup, depth: usize) -> Option<Vec<Wit>> {
    if tys.is_empty() {
        return if rows.is_empty() { Some(vec![]) } else { None };
    }
    if depth > 200 {
        return None;
    }
    let rows = expand_or(rows);
    let ty = &tys[0];
    let heads: Vec<Cons> = rows
        .iter()
        .filter_map(|r| match &r[0] {
            DPat::Ctor(c, _) => Some(c.clone()),
            _ => None,
        })
        .collect();
    let all = all_ctors(ty, &heads, lookup);
    let complete = match &all {
        Some(all) if !all.is_empty() => all.iter().all(|c| heads.iter().any(|h| covers(h, c))),
        _ => false,
    };
    if complete {
        for c in all.unwrap() {
            let ftys = field_tys(ty, &c, lookup);
            let arity = ftys.len();
            let spec: Vec<Vec<DPat>> = rows
                .iter()
                .filter_map(|r| {
                    let mut fs = match &r[0] {
                        DPat::Wild => vec![DPat::Wild; arity],
                        DPat::Ctor(h, hf) if covers(h, &c) => head_fields(h, hf, &c, arity),
                        _ => return None,
                    };
                    fs.extend(r[1..].iter().cloned());
                    Some(fs)
                })
                .collect();
            let mut sub_tys = ftys;
            sub_tys.extend(tys[1..].iter().cloned());
            if let Some(w) = useful(&spec, &sub_tys, lookup, depth + 1) {
                let (fields, rest) = w.split_at(arity);
                let mut out = vec![Wit::Ctor(c.clone(), fields.to_vec())];
                out.extend(rest.iter().cloned());
                return Some(out);
            }
        }
        None
    } else {
        let default: Vec<Vec<DPat>> = rows.iter().filter(|r| matches!(r[0], DPat::Wild)).map(|r| r[1..].to_vec()).collect();
        let w = useful(&default, &tys[1..], lookup, depth + 1)?;
        let head = match &all {
            Some(all) => match all.iter().find(|c| !heads.iter().any(|h| covers(h, c))) {
                Some(c) if !heads.is_empty() => {
                    let n = field_tys(ty, c, lookup).len();
                    Wit::Ctor(c.clone(), vec![Wit::Wild; n])
                }
                _ => Wit::Wild,
            },
            None => Wit::Wild,
        };
        let mut out = vec![head];
        out.extend(w);
        Some(out)
    }
}

fn print(w: &Wit, ty: &Ty, lookup: Lookup, names: Names) -> String {
    match w {
        Wit::Wild => "_".into(),
        Wit::Ctor(c, fs) => {
            let ftys = field_tys(ty, c, lookup);
            let sub = |i: usize| print(&fs[i], ftys.get(i).unwrap_or(&Ty::Error), lookup, names);
            let list = |n: usize| (0..n).map(sub).collect::<Vec<_>>().join(", ");
            match (ty, c) {
                (_, Cons::Bool(b)) => b.to_string(),
                // the values past `usize::MAX` (see [`int_ctor_max`])
                (Ty::Uint(UintTy::Usize), Cons::IntRange(a, b)) if *b > UintTy::Usize.max_value() => {
                    if *a > UintTy::Usize.max_value() { "usize::MAX..".into() } else { format!("{a}..") }
                }
                (_, Cons::IntRange(a, b)) if a == b => a.to_string(),
                (_, Cons::IntRange(a, b)) => format!("{a}..={b}"),
                (Ty::Option(_), Cons::Variant(0)) => "None".into(),
                (Ty::Option(_), Cons::Variant(_)) => format!("Some({})", sub(0)),
                (Ty::Adt(id, _), Cons::Variant(i)) => {
                    let (vname, shape) = match lookup(*id) {
                        Some(ItemKind::Enum(e)) => e.variants.get(*i as usize).map(|v| (v.name.clone(), v.shape)).unwrap_or(("?".into(), crate::hir::Shape::Unit)),
                        _ => ("?".into(), crate::hir::Shape::Unit),
                    };
                    let base = format!("{}::{vname}", names(*id));
                    match shape {
                        crate::hir::Shape::Unit => base,
                        crate::hir::Shape::Tuple => format!("{base}({})", list(fs.len())),
                        crate::hir::Shape::Named => format!("{base} {{ .. }}"),
                    }
                }
                (Ty::Adt(id, _), Cons::Single) => format!("{} {{ .. }}", names(*id)),
                (Ty::Tuple(_), _) => format!("({})", list(fs.len())),
                (Ty::Ref(_), _) => format!("&{}", sub(0)),
                (Ty::Array(..), _) => format!("[{}]", list(fs.len())),
                (Ty::Slice(_) | Ty::Seq(_), Cons::FixedLen(_)) => format!("[{}]", list(fs.len())),
                (Ty::Slice(_) | Ty::Seq(_), Cons::VarLen(p, s)) => {
                    let pre: Vec<String> = (0..*p as usize).map(sub).collect();
                    let suf: Vec<String> = (*p as usize..(*p + *s) as usize).map(sub).collect();
                    let mut parts = pre;
                    parts.push("..".into());
                    parts.extend(suf);
                    format!("[{}]", parts.join(", "))
                }
                _ => "_".into(),
            }
        }
    }
}
