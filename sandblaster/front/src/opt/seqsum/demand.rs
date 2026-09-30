//! Demand splits (optimizer design §8.3).
//!
//! The segment normal form decides which piece a read or a sub-slice falls
//! in from the path's facts. When they do not decide it (whether the first
//! segment still has an element, whether the last one is empty), the
//! residual tests it: a **demand split** on a printable `usize` comparison
//! of the pieces' lengths, which the source does not have (its buffer never
//! needed it). Both arms are driven again with the comparison as a fact.
//! The proof builder splits the residual's scrutinee the same way
//! (`proof::build`, `Walk::demand_split`) and leaves the source as it is,
//! so the split is proven by construction: each arm's leaf is closed from
//! the seq lemmas under that arm's fact.
//!
//! Unread pieces never appear (the normal form takes the consumed length:
//! a zero tail past it is dropped, a `replicate` fill that is never read is
//! never materialized), and a read at a known offset is the written value
//! (forwarding) — both in [`super::segments::Norm`].

use std::rc::Rc;

use sandblaster_kernel::term::{Lvl, Tm};
use sandblaster_kernel::value::V;

use super::segments::{Ids, usize_cmp};
use crate::opt::drive::process::{Driver, Path};

/// The value of the demand split on the undecided `Int` comparison `c` (a
/// side condition of the normal form): its printable `usize` form over the
/// pieces' lengths ([`usize_cmp`], linear cancellation: `(a + 1 + b) − 1 ≤
/// a` is `b ≤ 0`). `None` when it has no printable form or the path
/// already split on it (a second split would not decide it either).
pub fn split(d: &mut Driver<'_>, path: &Path, ids: &Ids, c: &Tm) -> Option<V> {
    let cu = usize_cmp(ids, c)?;
    let cv = d.eval_tm(&path.st, &cu).ok()?;
    let depth = path.st.depth();
    for dd in &path.facts.decided {
        let mut b = sandblaster_kernel::value::Budget { steps: 1_000_000 };
        if Rc::ptr_eq(&dd.scrut, &cv) || d.env.conv(Lvl(depth), &dd.scrut, &cv, &mut b).unwrap_or(false) {
            return None;
        }
    }
    if d.trace {
        let names = path.st.names();
        eprintln!("opt: drive: seq: demand split on {} (from {})", d.env.print_term(&names, &cu), d.env.print_term(&names, c));
    }
    Some(cv)
}
