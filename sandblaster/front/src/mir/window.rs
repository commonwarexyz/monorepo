//! The window rule (docs/DESIGN-UNSAFE-SIMD.md §2.6 with amendments A-S1
//! and A-S8; docs/mir-lift.md §20.10). TRUSTED: a pointer formation of crate
//! code is read by the literal reading only when its family passes this
//! check; a bug here could let L give a value where Rust has undefined
//! behaviour.
//!
//! It runs on the **window extraction**, rustc's MIR at `-Zmir-opt-level=0`
//! (amendment A-S1): no pass has merged, moved or deleted an access, so the
//! MIR's accesses and reference flow are the source's (`mir::load_window`
//! checks that it is the same program as the extraction the readings read).
//! The verdict is carried to the readings' (level-1) MIR per formation, by
//! the formation's source position and what it is ([`Verdict`]); a
//! formation of the readings' MIR without exactly one verdict here is
//! refused.
//!
//! **Definitions** (a *point* is one statement or terminator):
//!
//! * a **formation** `F`: a call of an admitted formation helper
//!   (`ptr::helper`: `as_ptr`, `as_mut_ptr`, `from_ref`, `from_mut`) or a
//!   `&raw const`/`&raw mut`; its **source** `σ`: the reference it takes,
//!   looked through one `unsize` temporary, or the local whose address it
//!   takes;
//! * its **family** `Φ(F)`: the local `F` assigns, closed under the
//!   derivations (a copy or move into a local, a `PtrToPtr` cast, `Offset`,
//!   an admitted `cast`/`add`/`sub`/`offset` helper); a local reached from
//!   two formations belongs to none (both refused);
//! * its **ancestors** `A(F)`: `σ` (and the unsize temporary) and, closed
//!   flow-insensitively over the body, every local that can reach memory
//!   (its type holds a reference, a raw pointer or a lifetime; or it is the
//!   base itself) and flows into an ancestor: the root local of any place an
//!   assignment to an ancestor reads, borrows or casts (behind a dereference
//!   or not), and every reference-carrying argument of a call whose result
//!   or whose argument is an ancestor;
//! * its **uses** `U(F)`: the points that read a member; its **window**
//!   `W(F)`: the points other than `F` on a path from `F` to a use, the path
//!   not passing `F` again.
//!
//! **Rules**:
//!
//! * **W0** (one family at a time): no member is live just before `F`;
//! * **W1** (no escape): every read of a member is a derivation into a
//!   member, the pointer argument of an admitted load or store
//!   (`ptr::MEM_INTRINSICS`), or a storage marker;
//! * **W2** (mutable families): no point of the window mentions an ancestor
//!   (read, write, borrow, move, drop, call argument), except the storage
//!   marker of an ancestor that is not the base itself (a reference's
//!   storage ending touches no referent);
//! * **W3** (shared families): no point of the window assigns an ancestor,
//!   borrows one mutably (`&mut`, `&raw mut`), or uses an ancestor of `&mut`
//!   type;
//! * **W4**: a store's pointer belongs to a mutable family (L also reads a
//!   store through a shared pointer as stuck).
//!
//! **Exactness**: in a window that passes W2, every access to the base goes
//! through the family's one tag (Stacked Borrows: the raw tag above the
//! reborrow, no other tag used before the last use; Tree Borrows: no foreign
//! access to the reborrow in the window), so L's reading of the accesses as
//! reads and writes of the base through its reference code is exact; W3
//! keeps a shared family's snapshot equal to memory at every use. Two `&mut`
//! parameters are not related here: their disjointness is the caller's
//! (assumption A3), named per formation ([`Verdict::params`], A-S8).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::ir::*;
use super::ptr::{self, Helper};

/// A point: a block and the index of a statement in it (the terminator is
/// index `stmts.len()`).
type Point = (usize, usize);

/// The window rule's verdict on one pointer formation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// The formation's source position.
    pub at: Loc,
    /// What it is: the helper's definition path, `&raw mut` or `&raw const`.
    pub what: String,
    /// Passed, or the rule it breaks.
    pub result: Result<(), String>,
    /// The function's `&mut` parameters among its ancestors: the pointer
    /// reaches memory through them, so their not aliasing each other is the
    /// caller's obligation (A3; amendment A-S8).
    pub params: Vec<usize>,
}

/// What a formation of `f` at a point is: (its kind, mutable, the source
/// operand or place), or `None`.
fn formation(m: &Sbmir, f: &Fn, p: Point) -> Option<(String, bool, Place)> {
    let bl = &f.blocks[p.0];
    if p.1 < bl.stmts.len() {
        if let Stmt::Assign(d, Rvalue::AddrOf(mt, pl), _) = &bl.stmts[p.1]
            && d.proj.is_empty()
        {
            return Some((if *mt { "&raw mut".into() } else { "&raw const".into() }, *mt, pl.clone()));
        }
        return None;
    }
    if let Term::Call(Callee::Fn(k), args, _, _) = &bl.term
        && let Some(g) = m.fns.get(k)
        && let Some(Ok((Helper::Form { mutable, .. }, _))) = ptr::helper(g)
        && let Some(Operand::Copy(a) | Operand::Move(a)) = args.first()
    {
        return Some((g.def.clone(), mutable, a.clone()));
    }
    None
}

/// A formation of `f` at a point that the rule refuses outright (a helper
/// path with another signature), with why.
fn bad_formation(m: &Sbmir, f: &Fn, p: Point) -> Option<(String, String)> {
    let bl = &f.blocks[p.0];
    if p.1 == bl.stmts.len()
        && let Term::Call(Callee::Fn(k), ..) = &bl.term
        && let Some(g) = m.fns.get(k)
        && let Some(Err(e)) = ptr::helper(g)
    {
        return Some((g.def.clone(), e));
    }
    None
}

fn loc_of(f: &Fn, p: Point) -> Loc {
    let bl = &f.blocks[p.0];
    if p.1 < bl.stmts.len() {
        match &bl.stmts[p.1] {
            Stmt::Assign(_, _, l) | Stmt::Assume(_, l) => l.clone(),
            _ => None,
        }
    } else {
        bl.term_loc.clone()
    }
}

/// The points of `f`.
fn points(f: &Fn) -> Vec<Point> {
    f.blocks.iter().enumerate().flat_map(|(b, bl)| (0..=bl.stmts.len()).map(move |i| (b, i))).collect()
}

/// The points control can reach next.
fn succ(f: &Fn, p: Point) -> Vec<Point> {
    let bl = &f.blocks[p.0];
    if p.1 < bl.stmts.len() {
        return vec![(p.0, p.1 + 1)];
    }
    let ts: Vec<usize> = match &bl.term {
        Term::Goto(t) | Term::Drop(_, _, t) | Term::Assert(_, _, _, t) => vec![*t],
        Term::Switch(_, arms, o) => arms.iter().map(|a| a.1).chain([*o]).collect(),
        Term::Call(_, _, _, t) => t.iter().copied().collect(),
        Term::Return | Term::Unreachable | Term::Resume | Term::Abort | Term::Unsupported(_) => vec![],
    };
    ts.into_iter().filter(|t| *t < f.blocks.len()).map(|t| (t, 0)).collect()
}

/// The roots of the places an operand mentions (its place's local and the
/// locals of its index projections).
fn op_locals(o: &Operand, out: &mut Vec<usize>) {
    if let Operand::Copy(p) | Operand::Move(p) = o {
        place_locals(p, out);
    }
}

fn place_locals(p: &Place, out: &mut Vec<usize>) {
    out.push(p.local);
    for pr in &p.proj {
        if let Proj::Index(l) = pr {
            out.push(*l);
        }
    }
}

fn rv_locals(rv: &Rvalue, out: &mut Vec<usize>) {
    match rv {
        Rvalue::Use(o) | Rvalue::Un(_, o) | Rvalue::Cast(_, o, _) | Rvalue::Repeat(o, _) => op_locals(o, out),
        Rvalue::Bin(_, a, b) | Rvalue::Checked(_, a, b) => {
            op_locals(a, out);
            op_locals(b, out);
        }
        Rvalue::Ref(_, p) | Rvalue::Discr(p) | Rvalue::Len(p) | Rvalue::AddrOf(_, p) => place_locals(p, out),
        Rvalue::Agg(_, os) => os.iter().for_each(|o| op_locals(o, out)),
        Rvalue::Unsupported(_) => {}
    }
}

/// Every local a point mentions (read, written, borrowed, its storage
/// marked): `(local, as a storage marker)`.
fn mentions(f: &Fn, p: Point) -> Vec<(usize, bool)> {
    let bl = &f.blocks[p.0];
    let mut out = Vec::new();
    if p.1 < bl.stmts.len() {
        match &bl.stmts[p.1] {
            Stmt::Assign(d, rv, _) => {
                place_locals(d, &mut out);
                rv_locals(rv, &mut out);
            }
            Stmt::Assume(o, _) => op_locals(o, &mut out),
            Stmt::Storage(_, l) => return vec![(*l, true)],
            // (an unprinted statement: everything is mentioned)
            Stmt::Unsupported(_) => return (0..f.locals.len()).map(|l| (l, false)).collect(),
        }
    } else {
        match &bl.term {
            Term::Switch(o, ..) | Term::Assert(o, ..) => op_locals(o, &mut out),
            Term::Drop(pl, ..) => place_locals(pl, &mut out),
            Term::Call(_, args, d, _) => {
                args.iter().for_each(|a| op_locals(a, &mut out));
                place_locals(d, &mut out);
            }
            Term::Return => out.push(0),
            Term::Unsupported(_) => return (0..f.locals.len()).map(|l| (l, false)).collect(),
            Term::Goto(_) | Term::Unreachable | Term::Resume | Term::Abort => {}
        }
    }
    out.into_iter().map(|l| (l, false)).collect()
}

/// The locals a point reads (its uses, for liveness and W1): every mention
/// but a whole local assigned (a plain destination is a definition).
fn reads(f: &Fn, p: Point) -> Vec<usize> {
    let bl = &f.blocks[p.0];
    let mut out = Vec::new();
    if p.1 < bl.stmts.len() {
        match &bl.stmts[p.1] {
            Stmt::Assign(d, rv, _) => {
                if !d.proj.is_empty() {
                    place_locals(d, &mut out);
                }
                rv_locals(rv, &mut out);
            }
            Stmt::Assume(o, _) => op_locals(o, &mut out),
            Stmt::Storage(..) => {}
            Stmt::Unsupported(_) => out.extend(0..f.locals.len()),
        }
    } else {
        match &bl.term {
            Term::Switch(o, ..) | Term::Assert(o, ..) => op_locals(o, &mut out),
            Term::Drop(pl, ..) => place_locals(pl, &mut out),
            Term::Call(_, args, d, _) => {
                args.iter().for_each(|a| op_locals(a, &mut out));
                if !d.proj.is_empty() {
                    place_locals(d, &mut out);
                }
            }
            Term::Return => out.push(0),
            Term::Unsupported(_) => out.extend(0..f.locals.len()),
            Term::Goto(_) | Term::Unreachable | Term::Resume | Term::Abort => {}
        }
    }
    out
}

/// The local a point defines whole (an assignment or a call's result to a
/// plain local, a storage marker).
fn defines(f: &Fn, p: Point) -> Option<usize> {
    let bl = &f.blocks[p.0];
    if p.1 < bl.stmts.len() {
        return match &bl.stmts[p.1] {
            Stmt::Assign(d, ..) if d.proj.is_empty() => Some(d.local),
            Stmt::Storage(_, l) => Some(*l),
            _ => None,
        };
    }
    match &bl.term {
        Term::Call(_, _, d, _) if d.proj.is_empty() => Some(d.local),
        _ => None,
    }
}

/// Whether a type can reach memory: it holds a reference, a raw pointer or
/// a lifetime (`IterMut<'_, T>`, `Option<&mut T>`).
fn reaches_memory(m: &Sbmir, t: &Ty, depth: usize) -> bool {
    if depth > 8 {
        return true;
    }
    match t {
        Ty::Ref(..) | Ty::Ptr(..) => true,
        Ty::Tuple(ts) => ts.iter().any(|x| reaches_memory(m, x, depth + 1)),
        Ty::Array(e, _) | Ty::Slice(e) => reaches_memory(m, e, depth + 1),
        Ty::Closure(_, c) => reaches_memory(m, c, depth + 1),
        Ty::Adt(k) => {
            k.contains('\'') || k.contains('&') || k.contains('*') || m.adts.get(k).is_none_or(|d| d.args.iter().chain(d.variants.iter().flat_map(|v| v.fields.iter().map(|f| &f.1))).any(|x| reaches_memory(m, x, depth + 1)))
        }
        Ty::Unsupported(_) => true,
        _ => false,
    }
}

/// The admitted pointer derivation at a point (`ptr::derivation`).
fn derivation(m: &Sbmir, f: &Fn, p: Point) -> Option<(usize, usize)> {
    ptr::derivation(m, f, p.0, p.1)
}

/// The admitted load or store at a point: (whether a store, its pointer
/// argument).
fn access(f: &Fn, p: Point) -> Option<(bool, &Operand)> {
    let bl = &f.blocks[p.0];
    if p.1 != bl.stmts.len() {
        return None;
    }
    let Term::Call(Callee::Arch(a), args, _, _) = &bl.term else { return None };
    let row = ptr::mem_intrinsic(&a.path)?;
    Some((row.store, args.first()?))
}

/// The window rule's verdicts on every formation of `f` (crate code only:
/// a function of another crate has none, and the readings never read a
/// pointer there).
pub fn check(m: &Sbmir, f: &Fn) -> Vec<Verdict> {
    if !f.local || !f.has_body {
        return Vec::new();
    }
    let pts = points(f);
    let mut preds: BTreeMap<Point, Vec<Point>> = BTreeMap::new();
    for p in &pts {
        for s in succ(f, *p) {
            preds.entry(s).or_default().push(*p);
        }
    }
    // the formations, and the helpers with another signature
    let forms: Vec<(Point, String, bool, Place)> = pts.iter().filter_map(|p| formation(m, f, *p).map(|(w, mt, src)| (*p, w, mt, src))).collect();
    let mut out: Vec<Verdict> = pts.iter().filter_map(|p| bad_formation(m, f, *p).map(|(what, e)| Verdict { at: loc_of(f, *p), what, result: Err(e), params: vec![] })).collect();
    // families: the members of each formation's family (flow-insensitive);
    // a local reached from two formations belongs to none
    let derivs: Vec<(Point, usize, usize)> = pts.iter().filter_map(|p| derivation(m, f, *p).map(|(s, d)| (*p, s, d))).collect();
    let mut family: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (i, (p, ..)) in forms.iter().enumerate() {
        if let Some(r) = defines(f, *p) {
            family.entry(r).or_default().insert(i);
        }
    }
    loop {
        let mut changed = false;
        for (_, s, d) in &derivs {
            let fs = family.get(s).cloned().unwrap_or_default();
            let e = family.entry(*d).or_default();
            for x in fs {
                changed |= e.insert(x);
            }
        }
        if !changed {
            break;
        }
    }
    // liveness (backward, per point)
    let mut live_in: BTreeMap<Point, BTreeSet<usize>> = pts.iter().map(|p| (*p, BTreeSet::new())).collect();
    loop {
        let mut changed = false;
        for p in pts.iter().rev() {
            let mut l: BTreeSet<usize> = succ(f, *p).iter().flat_map(|s| live_in[s].iter().copied()).collect();
            if let Some(d) = defines(f, *p) {
                l.remove(&d);
            }
            l.extend(reads(f, *p));
            if l != live_in[p] {
                live_in.insert(*p, l);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let ptr_local = |l: usize| matches!(f.locals.get(l), Some((Ty::Ptr(..), _)));
    for (i, (fp, what, mutable, src)) in forms.iter().enumerate() {
        let verdict = (|| -> Result<Vec<usize>, String> {
            let root = defines(f, *fp).ok_or("a formation into a projection (the pointer is stored)")?;
            let members: BTreeSet<usize> = family.iter().filter(|(_, fs)| fs.contains(&i)).map(|(l, _)| *l).collect();
            for l in &members {
                if family[l].len() > 1 {
                    return Err(format!("W1: the pointer local `_{l}` is reached from two formations (a member belongs to one family only)"));
                }
            }
            if members.contains(&0) {
                return Err("W1: the pointer is returned (it escapes)".into());
            }
            // σ and the ancestors
            let mut anc: BTreeSet<usize> = BTreeSet::new();
            let mut base: Option<usize> = None;
            if what.starts_with("&raw") {
                anc.insert(src.local);
                if !src.proj.iter().any(|p| matches!(p, Proj::Deref)) {
                    base = Some(src.local);
                }
            } else {
                anc.insert(src.local);
                // looked through one `unsize` temporary
                for p in &pts {
                    if let (true, Some(Stmt::Assign(d, Rvalue::Cast(k, Operand::Copy(q) | Operand::Move(q), _), _))) = (p.1 < f.blocks[p.0].stmts.len(), f.blocks[p.0].stmts.get(p.1))
                        && d.proj.is_empty()
                        && d.local == src.local
                        && k == "unsize"
                    {
                        anc.insert(q.local);
                    }
                }
            }
            loop {
                let before = anc.len();
                for p in &pts {
                    let bl = &f.blocks[p.0];
                    let mut flow: Vec<usize> = Vec::new();
                    if p.1 < bl.stmts.len() {
                        if let Stmt::Assign(d, rv, _) = &bl.stmts[p.1]
                            && anc.contains(&d.local)
                        {
                            rv_locals(rv, &mut flow);
                        }
                    } else if let Term::Call(_, args, d, _) = &bl.term {
                        let mut ls = Vec::new();
                        args.iter().for_each(|a| op_locals(a, &mut ls));
                        if anc.contains(&d.local) || ls.iter().any(|l| anc.contains(l)) {
                            flow = ls;
                            flow.push(d.local);
                        }
                    }
                    for l in flow {
                        if f.locals.get(l).is_some_and(|(t, _)| reaches_memory(m, t, 0)) || Some(l) == base {
                            anc.insert(l);
                        }
                    }
                }
                if anc.len() == before {
                    break;
                }
            }
            // the family's own members are not its ancestors
            for l in &members {
                anc.remove(l);
            }
            // W0: no member live just before the formation
            if let Some(l) = members.iter().find(|l| **l != root && live_in[fp].contains(l)) {
                return Err(format!("W0: the pointer local `_{l}` of this family is still live at a new formation (a pointer kept across a formation)"));
            }
            if members.iter().any(|l| live_in[fp].contains(l) && reads(f, *fp).contains(l)) {
                return Err("W0: a member is read by its own formation".into());
            }
            // uses, and W1
            let mut uses: Vec<Point> = Vec::new();
            for p in &pts {
                let rs = reads(f, *p);
                let read: Vec<usize> = rs.iter().copied().filter(|l| members.contains(l)).collect();
                if read.is_empty() {
                    continue;
                }
                uses.push(*p);
                let ok = match (derivation(m, f, *p), access(f, *p)) {
                    (Some((s, d)), _) => members.contains(&s) && members.contains(&d) && rs.iter().filter(|l| members.contains(l)).count() == 1,
                    (_, Some((store, Operand::Copy(q) | Operand::Move(q)))) => q.proj.is_empty() && members.contains(&q.local) && rs.iter().filter(|l| members.contains(l)).count() == 1 && (*mutable || !store),
                    _ => false,
                };
                if !ok {
                    if let Some((true, _)) = access(f, *p)
                        && !mutable
                    {
                        return Err(format!("W4: a store through a pointer formed from a shared reference (at {:?})", loc_of(f, *p)));
                    }
                    return Err(format!("W1: the pointer `_{}` escapes: {} (a member may only be derived into a member or be the pointer of an admitted load or store)", read[0], show_point(f, *p)));
                }
            }
            // the window: after F, before a use, not through F
            let mut fwd: BTreeSet<Point> = BTreeSet::new();
            let mut q: VecDeque<Point> = succ(f, *fp).into_iter().collect();
            while let Some(p) = q.pop_front() {
                if p == *fp || !fwd.insert(p) {
                    continue;
                }
                q.extend(succ(f, p));
            }
            let mut back: BTreeSet<Point> = BTreeSet::new();
            let mut q: VecDeque<Point> = uses.iter().copied().collect();
            while let Some(p) = q.pop_front() {
                if p == *fp || !back.insert(p) {
                    continue;
                }
                q.extend(preds.get(&p).cloned().unwrap_or_default());
            }
            for p in fwd.intersection(&back) {
                for (l, storage) in mentions(f, *p) {
                    if !anc.contains(&l) || members.contains(&l) {
                        continue;
                    }
                    // a reference's storage ending touches no referent
                    if storage && Some(l) != base {
                        continue;
                    }
                    if *mutable {
                        return Err(format!("W2: `_{l}`, through which the base is reached, is used inside the pointer's window: {} (the base is reached only through the pointer while it is in use)", show_point(f, *p)));
                    }
                    // a shared family: no write to an ancestor in the window
                    let writes = match point_stmt(f, *p) {
                        PointRef::Stmt(Stmt::Assign(d, rv, _)) => d.local == l || matches!(rv, Rvalue::Ref(k, q) if k == "mut" && q.local == l) || matches!(rv, Rvalue::AddrOf(true, q) if q.local == l),
                        PointRef::Term(Term::Call(_, _, d, _)) => d.local == l,
                        _ => false,
                    };
                    let mut_ref = matches!(f.locals.get(l), Some((Ty::Ref(true, _), _)));
                    if writes || mut_ref || storage {
                        return Err(format!("W3: `_{l}`, through which the base is reached, is written or used mutably inside a shared pointer's window: {}", show_point(f, *p)));
                    }
                }
            }
            if !ptr_local(root) {
                return Err("a formation into a local that is not a pointer".into());
            }
            Ok((1..=f.argc).filter(|p| anc.contains(p) && matches!(f.locals.get(*p), Some((Ty::Ref(true, _), _)))).collect())
        })();
        let (result, params) = match verdict {
            Ok(ps) => (Ok(()), ps),
            Err(e) => (Err(e), vec![]),
        };
        out.push(Verdict { at: loc_of(f, *fp), what: what.clone(), result, params });
    }
    out
}

enum PointRef<'a> {
    Stmt(&'a Stmt),
    Term(&'a Term),
}

fn point_stmt(f: &Fn, p: Point) -> PointRef<'_> {
    let bl = &f.blocks[p.0];
    if p.1 < bl.stmts.len() { PointRef::Stmt(&bl.stmts[p.1]) } else { PointRef::Term(&bl.term) }
}

fn show_point(f: &Fn, p: Point) -> String {
    let at = loc_of(f, p).map(|(file, l, c)| format!(" at {file}:{l}:{c}")).unwrap_or_default();
    match point_stmt(f, p) {
        PointRef::Stmt(s) => format!("bb{} statement {}{at}: {}", p.0, p.1, super::cfg::show(s)),
        PointRef::Term(t) => format!("bb{} terminator{at}: {}", p.0, super::cfg::show(t)),
    }
}

/// The verdict on a formation of the readings' MIR: the one verdict of the
/// window extraction with the same source position and kind, or why the
/// formation is refused.
pub fn verdict_for(f: &Fn, at: &Loc, what: &str) -> Result<Vec<usize>, String> {
    let Some(vs) = &f.window else {
        return Err("no window extraction (`window_mir = ..`, the module's MIR at -Zmir-opt-level=0): the window rule, which checks that nothing else reaches the base while the pointer is in use, has not run".into());
    };
    let found: Vec<&Verdict> = vs.iter().filter(|v| v.at == *at && v.what == what).collect();
    match found.as_slice() {
        [v] => v.result.clone().map(|_| v.params.clone()),
        [] => Err(format!("no formation `{what}` at {at:?} in the window extraction (a formation the unoptimized MIR does not have is refused)")),
        _ => Err(format!("{} formations `{what}` at {at:?} in the window extraction: which one this is cannot be told", found.len())),
    }
}
