//! The diagnostic pass over `unsafe` in lifted functions (UNTRUSTED;
//! docs/DESIGN-UNSAFE-SIMD.md §6.3, risk 12): for a function whose source
//! has `unsafe`, every operation of its MIR outside the narrow reading of
//! existing `unsafe`, named, so the build fails with the reason. The
//! literal reading (trusted) is stuck on each of these anyway: this pass
//! only says why early, and a mistake here cannot admit anything.

use super::ir::*;

/// Why each operation of `key`'s MIR is outside the narrow reading (empty:
/// none is).
pub fn outside_reading(m: &Sbmir, key: &str) -> Vec<String> {
    let Some(f) = m.fns.get(key) else { return vec![] };
    let mut out = Vec::new();
    let ptr_local = |l: usize| matches!(f.locals.get(l), Some((Ty::Ptr(..), _)));
    let place = |p: &Place, out: &mut Vec<String>| {
        let mut t = f.locals.get(p.local).map(|l| l.0.clone());
        for pr in &p.proj {
            match (pr, t.take()) {
                (Proj::Deref, Some(Ty::Ptr(..))) => out.push(format!("the raw pointer `_{}` dereferenced as a place (`*p`)", p.local)),
                (Proj::Unsupported(s), _) => out.push(format!("the projection {s}")),
                (Proj::Deref, Some(Ty::Ref(_, i))) => t = Some(*i),
                (Proj::Field(_, ft), _) => t = Some(ft.clone()),
                (Proj::Index(_), Some(Ty::Array(e, _) | Ty::Slice(e))) => t = Some(*e),
                (Proj::Downcast(_), x) => t = x,
                _ => {}
            }
        }
    };
    let op = |o: &Operand, out: &mut Vec<String>| {
        if let Operand::Copy(p) | Operand::Move(p) = o {
            place(p, out);
        }
    };
    for (b, bl) in f.blocks.iter().enumerate() {
        for s in &bl.stmts {
            match s {
                Stmt::Assign(d, rv, at) => {
                    place(d, &mut out);
                    match rv {
                        Rvalue::Unsupported(x) => out.push(format!("bb{b}: the operation {x}")),
                        Rvalue::Cast(k, o, _) if k.starts_with('(') => {
                            out.push(format!("bb{b}: the cast {k}"));
                            op(o, &mut out);
                        }
                        Rvalue::Bin(_, x, y) if [x, y].iter().any(|o| matches!(o, Operand::Copy(p) | Operand::Move(p) if p.proj.is_empty() && ptr_local(p.local))) && !matches!(rv, Rvalue::Bin(k, ..) if k == "offset") => {
                            out.push(format!("bb{b}: an operation on raw pointers (a comparison or arithmetic other than `add`/`sub`/`offset`)"));
                        }
                        Rvalue::AddrOf(mt, p) => {
                            place(p, &mut out);
                            if let Err(e) = super::window::verdict_for(f, at, if *mt { "&raw mut" } else { "&raw const" }) {
                                out.push(format!("bb{b}: `&raw`: {e}"));
                            }
                        }
                        Rvalue::Use(o) | Rvalue::Un(_, o) | Rvalue::Cast(_, o, _) | Rvalue::Repeat(o, _) => op(o, &mut out),
                        Rvalue::Bin(_, x, y) | Rvalue::Checked(_, x, y) => {
                            op(x, &mut out);
                            op(y, &mut out);
                        }
                        Rvalue::Ref(_, p) | Rvalue::Discr(p) | Rvalue::Len(p) => place(p, &mut out),
                        Rvalue::Agg(_, os) => os.iter().for_each(|o| op(o, &mut out)),
                    }
                }
                Stmt::Assume(o, _) => op(o, &mut out),
                Stmt::Unsupported(x) => out.push(format!("bb{b}: the statement {x}")),
                Stmt::Storage(..) => {}
            }
        }
        if let Term::Call(c, args, d, _) = &bl.term {
            args.iter().for_each(|a| op(a, &mut out));
            place(d, &mut out);
            match c {
                Callee::Fn(k) => match m.fns.get(k) {
                    Some(g) => match super::ptr::helper(g) {
                        Some(Err(e)) => out.push(format!("bb{b}: {e}")),
                        Some(Ok((super::ptr::Helper::Form { .. }, _))) => {
                            if let Err(e) = super::window::verdict_for(f, &bl.term_loc, &g.def) {
                                out.push(format!("bb{b}: `{}`: {e}", g.def));
                            }
                        }
                        Some(Ok(_)) => {}
                        None if g.unsafe_fn && !g.local => out.push(format!("bb{b}: a call of the library `unsafe fn` `{}`, outside the admitted pointer operations ({})", g.def, super::ptr::helper_paths().join(", "))),
                        None => {}
                    },
                    None => {}
                },
                Callee::Arch(a) if a.pointer && super::ptr::mem_intrinsic(&a.path).is_none() => out.push(format!("bb{b}: the intrinsic `{}` takes or returns a raw pointer and is no admitted load or store (aligned, masked, broadcasting, gathering, scattering, non-temporal and interleaving forms are refused)", a.path)),
                Callee::Arch(a) if !a.safe && !a.pointer => out.push(format!("bb{b}: the `unsafe` intrinsic `{}`", a.path)),
                Callee::Unsupported(x) => out.push(format!("bb{b}: the call {x}")),
                _ => {}
            }
        }
        if let Term::Unsupported(x) = &bl.term {
            out.push(format!("bb{b}: the terminator {x}"));
        }
    }
    out.sort();
    out.dedup();
    out
}
