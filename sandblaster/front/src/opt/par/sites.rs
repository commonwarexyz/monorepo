//! Lane sites and the lane decision (plan O10; site discovery in general —
//! maps, reductions, searches, trees — is plan O11, design §14.2).
//!
//! O10's site is the simplest antichain: an exec function whose body is an
//! array literal of `N ≥ 2` calls of one user function (`[g(ā₀), …,
//! g(ā_{N−1})]`). The scan is syntactic, so programs without such a
//! function (QMDB) pay nothing: no symbolic execution, no lemma, no core
//! text is loaded for lanes.

use std::collections::HashMap;

use crate::hir::*;
use crate::opt::cost::model::SetModel;

/// A syntactic lane site: `(site, callee, lanes)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub site: ItemId,
    pub callee: ItemId,
    pub lanes: usize,
}

fn peel(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Block(b) if b.stmts.is_empty() => b.tail.as_deref().map(peel).unwrap_or(e),
        ExprKind::Coerce(_, x) => peel(x),
        _ => e,
    }
}

/// The lane sites of `krate` (source functions only, in item order).
pub fn candidates(krate: &Crate) -> Vec<Candidate> {
    let mut out = Vec::new();
    for it in &krate.items {
        if it.ghost {
            continue;
        }
        let ItemKind::Fn(f) = &it.kind else { continue };
        if f.kind != FnKind::Exec || f.implements.is_some() || !f.generics.is_empty() || f.has_requires() || !f.target_features.is_empty() || f.receiver.is_some() {
            continue;
        }
        let FnBody::Exec(b) = &f.body else { continue };
        let ExprKind::Array(xs) = &peel(b).kind else { continue };
        if xs.len() < 2 {
            continue;
        }
        let mut callee = None;
        let all = xs.iter().all(|x| match &peel(x).kind {
            ExprKind::Call { callee: Callee::Item(g, targs), .. } if targs.is_empty() && krate.fn_def(*g).is_some_and(|gf| gf.kind == FnKind::Exec) => {
                let same = callee.is_none_or(|c| c == *g);
                callee = Some(*g);
                same
            }
            _ => false,
        });
        if all && let Some(g) = callee {
            out.push(Candidate { site: it.id, callee: g, lanes: xs.len() });
        }
    }
    out
}

/// The cost of a function's source body under `m`, callees at their own
/// source cost (memoized; recursion costs nothing extra), a callee with a
/// variant in `variants` priced as that variant.
pub fn source_cost(m: &SetModel, k: &Crate, id: ItemId, variants: &HashMap<ItemId, ItemId>, memo: &mut HashMap<ItemId, u64>) -> u64 {
    let id = variants.get(&id).copied().unwrap_or(id);
    if let Some(c) = memo.get(&id) {
        return *c;
    }
    memo.insert(id, 0);
    let Some(f) = k.fn_def(id).cloned() else { return 0 };
    let cell = std::cell::RefCell::new(std::mem::take(memo));
    let callee = |c: ItemId| -> Option<u64> {
        let mut m2 = std::mem::take(&mut *cell.borrow_mut());
        let v = matches!(k.fn_def(c).map(|g| &g.body), Some(FnBody::Exec(_))).then(|| source_cost(m, k, c, variants, &mut m2));
        *cell.borrow_mut() = m2;
        v
    };
    let v = m.fn_cost(k, &f, &callee);
    *memo = cell.into_inner();
    memo.insert(id, v);
    v
}
