//! Assembled arrays (optimizer design §6.7): an array value that symbolic
//! execution produced as a literal spine, printed as the buffer it was
//! built as.
//!
//! When the driver or the straight-line executor runs a function that
//! builds a message (`let mut m = [0u8; 40]; m[0..8].copy_from_slice(
//! &n.to_be_bytes()); m[8..40].copy_from_slice(&d); hash(&m)`), the value
//! it gets is a spine of 40 elements: eight shifted bytes of `n` and 32
//! element reads of `d`. Printed as an array literal, that is 40 separate
//! byte stores (and 32 byte loads), which LLVM does not merge back. This
//! module finds the runs in such a spine and prints the array as a block
//! that fills a zeroed local with `copy_from_slice`:
//!
//! * `Copy`: consecutive element reads `b[lo], .., b[lo + n − 1]` of one
//!   array node, copied from `&b` (the whole array) or `&b[lo..lo + n]`;
//! * `Bytes`: the bytes of one integer in big- or little-endian order,
//!   copied from `x.to_be_bytes()` / `x.to_le_bytes()`;
//! * `Zero`: zero elements, which the zeroed local already holds;
//! * `Elem`: any other element, assigned `m[i] = e`.
//!
//! The block is used only when it is a clear win: at least one `Copy` run
//! of 4 or more elements, at least two pieces, and at most one statement
//! per 4 elements. Arrays made only of integer bytes (a hash's state
//! written out as bytes) and arrays that are one sub-array of another
//! (a SHA-256 block loaded as four vectors) stay literals: LLVM already
//! turns those into byte-reversal and vector loads and stores.
//!
//! An array passed to an intrinsic or a load/store helper stays a literal
//! too (the printers turn it back): its elements go to a vector register,
//! and building it in memory first would add stores and a reload that the
//! CPU cannot forward from them.
//!
//! A copy source must be an array *variable* (a parameter or a match
//! field): the kernel eta-expands array variables to their element spine
//! (DESIGN.md §5.9), so a copy from one evaluates to the same spine as the
//! literal. A copy from an array that a call returned would stay a stuck
//! `append` and fail the link, so such reads stay elements.
//!
//! Nothing here is trusted. The block elaborates to `array::copy_range`
//! applications over the zeroed array, which evaluate (with the kernel's
//! fixed-length array η) to the same spine; the residual is admitted only
//! by the kernel (conversion, or the driven residual's equality lemma),
//! and the round trip re-elaborates the printed text.

use crate::builtins::{Builtin, IntMethod};
use crate::hir::*;
use crate::span::Span;

pub(super) type NodeId = usize;

/// What one element of an array spine is, as far as assembly is
/// concerned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Shape {
    /// Element `k` of the array node `base` (a literal index).
    Read { base: NodeId, k: u64 },
    /// `(x >> shift) as u8` for the integer node `x` of width `w`.
    Byte { x: NodeId, w: UintTy, shift: u32 },
    /// The literal zero.
    Zero,
    Other,
}

/// A run of an assembled array.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub(super) enum Piece {
    /// `n` consecutive elements `base[lo..lo + n]` of an array node.
    Copy { base: NodeId, lo: u64, n: u64 },
    /// The bytes of the integer node `x` of width `w`: big-endian
    /// (`to_be_bytes`) or little-endian (`to_le_bytes`).
    Bytes { x: NodeId, w: UintTy, be: bool },
    /// One element.
    Elem(NodeId),
    /// `n` zero elements (the zeroed local already holds them).
    Zero(u64),
}

impl Piece {
    /// The number of elements the piece covers.
    pub(super) fn len(&self) -> u64 {
        match self {
            Piece::Copy { n, .. } | Piece::Zero(n) => *n,
            Piece::Bytes { w, .. } => (w.bits() / 8) as u64,
            Piece::Elem(_) => 1,
        }
    }

    /// The node the piece reads.
    pub(super) fn node(&self) -> Option<NodeId> {
        match self {
            Piece::Copy { base, .. } => Some(*base),
            Piece::Bytes { x, .. } => Some(*x),
            Piece::Elem(e) => Some(*e),
            Piece::Zero(_) => None,
        }
    }
}

/// Whether an assembled array has integer bytes (`Bytes` pieces).
pub(super) fn has_bytes(pieces: &[Piece]) -> bool {
    pieces.iter().any(|p| matches!(p, Piece::Bytes { .. }))
}

/// The runs of an array spine (`elems`, with their shapes), or `None` when
/// the spine should stay a literal (see the module docs). `uint` says
/// whether the element type is an unsigned integer (only those arrays have
/// a zero fill); `u8` whether it is `u8` (only those have integer bytes).
pub(super) fn plan(elems: &[NodeId], shapes: &[Shape], uint: bool, u8: bool) -> Option<Vec<Piece>> {
    if !uint || elems.len() < 8 || elems.len() != shapes.len() {
        return None;
    }
    let n = elems.len();
    let mut out: Vec<Piece> = Vec::new();
    let mut i = 0;
    while i < n {
        match shapes[i] {
            Shape::Read { base, k } => {
                let mut j = i + 1;
                while j < n && shapes[j] == (Shape::Read { base, k: k + (j - i) as u64 }) {
                    j += 1;
                }
                if j - i >= 2 {
                    out.push(Piece::Copy { base, lo: k, n: (j - i) as u64 });
                } else {
                    out.push(Piece::Elem(elems[i]));
                }
                i = j;
            }
            Shape::Byte { x, w, shift } if u8 && matches!(w, UintTy::U16 | UintTy::U32 | UintTy::U64) => {
                let nb = (w.bits() / 8) as usize;
                let be = i + nb <= n && (0..nb).all(|t| shapes[i + t] == Shape::Byte { x, w, shift: 8 * (nb - 1 - t) as u32 });
                let le = !be && shift == 0 && i + nb <= n && (0..nb).all(|t| shapes[i + t] == Shape::Byte { x, w, shift: 8 * t as u32 });
                if be || le {
                    out.push(Piece::Bytes { x, w, be });
                    i += nb;
                } else {
                    out.push(Piece::Elem(elems[i]));
                    i += 1;
                }
            }
            Shape::Zero => {
                let mut j = i + 1;
                while j < n && shapes[j] == Shape::Zero {
                    j += 1;
                }
                out.push(Piece::Zero((j - i) as u64));
                i = j;
            }
            _ => {
                out.push(Piece::Elem(elems[i]));
                i += 1;
            }
        }
    }
    let long_copy = out.iter().any(|p| matches!(p, Piece::Copy { n, .. } if *n >= 4));
    let stmts = out.iter().filter(|p| !matches!(p, Piece::Zero(_))).count();
    // (one copy of a whole sub-array stays a literal: LLVM loads it as one
    // vector already, e.g. the blocks of a SHA-256 compression)
    (long_copy && out.len() >= 2 && stmts * 4 <= n).then_some(out)
}

/// The source of one `copy_from_slice` of an assembled array.
pub(super) enum Src {
    /// A whole array value (its type `[T; n]`).
    Whole(Expr),
    /// `&a[lo..hi]` of an array value `a`.
    Range(Expr, u64, u64),
    /// `x.to_be_bytes()` (`true`) or `x.to_le_bytes()` of an integer value.
    Bytes(Expr, UintTy, bool),
}

/// One printed part of an assembled array, at an element offset.
pub(super) enum Part {
    Slice(Src),
    Elem(Expr),
}

fn e(kind: ExprKind, ty: Ty, span: Span) -> Expr {
    Expr::new(kind, ty, span)
}

fn usize_lit(v: u64, span: Span) -> Expr {
    e(ExprKind::Lit(Lit::Int(v as u128)), Ty::usize(), span)
}

/// `&v` where a `&[T]` is expected, for an array value `v : [T; k]`.
fn unsize(v: Expr, elem: &Ty, span: Span) -> Expr {
    // `&*r` of a reference `r` is `r`
    let r = match v.kind {
        ExprKind::Coerce(Coercion::AutoDeref, inner) if matches!(&inner.ty, Ty::Ref(t) if **t == v.ty) => *inner,
        kind => {
            let vt = v.ty.clone();
            let v = Expr::new(kind, vt.clone(), v.span);
            e(ExprKind::Ref(Box::new(v)), Ty::Ref(Box::new(vt)), span)
        }
    };
    e(ExprKind::Coerce(Coercion::Unsize, Box::new(r)), Ty::slice_ref(elem.clone()), span)
}

/// The block `{ let mut a = [0; n]; a[o..o + k].copy_from_slice(src); ..;
/// a[i] = e; ..; a }` of an assembled array with element type `elem`
/// (an unsigned integer) and length `n`; `parts` are `(offset, length,
/// part)` in order. The local is pushed to `locals`.
pub(super) fn block(span: Span, locals: &mut Vec<LocalDecl>, elem: &Ty, n: u64, parts: Vec<(u64, u64, Part)>) -> Expr {
    let aty = Ty::array(elem.clone(), n);
    let l = LocalId(locals.len() as u32);
    locals.push(LocalDecl { name: format!("m{}", l.0), ty: aty.clone(), mutable: true, ghost: false, span });
    let zero = e(ExprKind::Lit(Lit::Int(0)), elem.clone(), span);
    let init = e(ExprKind::Repeat { elem: Box::new(zero), count: n }, aty.clone(), span);
    let mut stmts = vec![Stmt { kind: StmtKind::Let { pat: Pat { kind: PatKind::Binding { local: l, mode: BindingMode::ByValue, sub: None }, ty: aty.clone(), span }, init, els: None }, span }];
    for (off, len, part) in parts {
        let kind = match part {
            Part::Slice(src) => {
                let src = match src {
                    Src::Whole(v) => unsize(v, elem, span),
                    Src::Range(v, lo, hi) => e(ExprKind::SliceRange { base: Box::new(v), lo: Some(Box::new(usize_lit(lo, span))), hi: Some(Box::new(usize_lit(hi, span))) }, Ty::slice_ref(elem.clone()), span),
                    Src::Bytes(x, w, be) => {
                        let m = if be { IntMethod::ToBeBytes } else { IntMethod::ToLeBytes };
                        let call = e(ExprKind::Call { callee: Callee::Builtin(Builtin::Int(m, w), vec![]), args: vec![x] }, Ty::array(Ty::u8(), (w.bits() / 8) as u64), span);
                        unsize(call, elem, span)
                    }
                };
                let range = if off == 0 && len == n { None } else { Some((Some(usize_lit(off, span)), Some(usize_lit(off + len, span)))) };
                StmtKind::CopyFromSlice { dst: l, range, src }
            }
            Part::Elem(v) => StmtKind::Assign { place: Place { local: l, projs: vec![Proj::Index(usize_lit(off, span))], ty: elem.clone(), span }, value: v },
        };
        stmts.push(Stmt { kind, span });
    }
    let tail = e(ExprKind::Local(l), aty.clone(), span);
    e(ExprKind::Block(Block { stmts, tail: Some(Box::new(tail)), span }), aty, span)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn byte(x: NodeId, w: UintTy, shift: u32) -> Shape {
        Shape::Byte { x, w, shift }
    }

    #[test]
    fn seal_message() {
        // be64(n) ++ d (a [u8; 32] node 100)
        let mut shapes: Vec<Shape> = (0..8).map(|t| byte(7, UintTy::U64, 56 - 8 * t)).collect();
        shapes.extend((0..32).map(|k| Shape::Read { base: 100, k }));
        let elems: Vec<NodeId> = (0..40).collect();
        let p = plan(&elems, &shapes, true, true).unwrap();
        assert_eq!(p, vec![Piece::Bytes { x: 7, w: UintTy::U64, be: true }, Piece::Copy { base: 100, lo: 0, n: 32 }]);
        assert_eq!(p.iter().map(Piece::len).sum::<u64>(), 40);
    }

    #[test]
    fn stays_literal() {
        // only integer bytes (a hash state written out): a literal
        let shapes: Vec<Shape> = (0..8).flat_map(|w| (0..4).map(move |t| byte(w, UintTy::U32, 24 - 8 * t))).collect();
        let elems: Vec<NodeId> = (0..32).collect();
        assert!(plan(&elems, &shapes, true, true).is_none());
        // one whole sub-array: a literal
        let shapes: Vec<Shape> = (16..32).map(|k| Shape::Read { base: 100, k }).collect();
        assert!(plan(&(0..16).collect::<Vec<_>>(), &shapes, true, true).is_none());
        // a short copy among many other elements: a literal
        let mut shapes: Vec<Shape> = (0..4).map(|k| Shape::Read { base: 100, k }).collect();
        shapes.extend((0..12).map(|_| Shape::Other));
        let elems: Vec<NodeId> = (0..16).collect();
        assert!(plan(&elems, &shapes, true, true).is_none());
        // not an integer element type
        let shapes: Vec<Shape> = (0..8).map(|k| Shape::Read { base: 100, k }).collect();
        assert!(plan(&(0..8).collect::<Vec<_>>(), &shapes, false, false).is_none());
    }

    #[test]
    fn zeros_little_endian_and_partial_copies() {
        // d[4..12] ++ le32(x) ++ 0 0 0 0 ++ y
        let mut shapes: Vec<Shape> = (4..12).map(|k| Shape::Read { base: 9, k }).collect();
        shapes.extend((0..4).map(|t| byte(3, UintTy::U32, 8 * t)));
        shapes.extend([Shape::Zero; 4]);
        shapes.push(Shape::Other);
        let elems: Vec<NodeId> = (0..17).collect();
        let p = plan(&elems, &shapes, true, true).unwrap();
        assert_eq!(p, vec![Piece::Copy { base: 9, lo: 4, n: 8 }, Piece::Bytes { x: 3, w: UintTy::U32, be: false }, Piece::Zero(4), Piece::Elem(16)]);
    }
}
