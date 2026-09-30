//! Extraction (optimizer design §10.1, §10.3; plan O8): which of the
//! rewrites the matcher found to apply, by cost.
//!
//! A rewrite's saving is the cost of the subterm it replaces minus the cost
//! of the rule's right side (the variant set's cost model). Rewrites of one
//! region never overlap (a rewritten subterm contains no other rewritten
//! one), so a set is chosen greedily by saving. The candidates, cheapest
//! first, are: the greedy set, the best single rewrite, and the greedy set
//! without its smallest saving — at most [`TOP`](crate::opt::cost::model::TOP)
//! distinct sets; the caller proves the first one and retries at most twice
//! (design §10.3 "multi-result top-3 with ≤ 2 retries").

use super::aeg::{Class, EGraph};
use super::explain::Rewrite;

/// A rewrite with its class and saving.
#[derive(Clone, Debug)]
pub struct Scored {
    pub class: Class,
    pub saving: u64,
    pub rewrite: Rewrite,
}

/// The candidate rewrite sets (see the module docs).
pub fn candidates(g: &EGraph, mut found: Vec<Scored>) -> Vec<Vec<Scored>> {
    found.retain(|s| s.saving > 0);
    // largest saving first; ties by class (deterministic)
    found.sort_by(|a, b| b.saving.cmp(&a.saving).then(a.class.cmp(&b.class)));
    let mut greedy: Vec<Scored> = Vec::new();
    for s in &found {
        if greedy.iter().all(|t| !g.below(s.class, t.class) && !g.below(t.class, s.class)) {
            greedy.push(s.clone());
        }
    }
    let mut out: Vec<Vec<Scored>> = Vec::new();
    let key = |v: &Vec<Scored>| v.iter().map(|s| (s.class, s.rewrite.rule.clone())).collect::<Vec<_>>();
    let mut push = |v: Vec<Scored>| {
        if !v.is_empty() && !out.iter().any(|o| key(o) == key(&v)) && out.len() < crate::opt::cost::model::TOP {
            out.push(v);
        }
    };
    push(greedy.clone());
    if let Some(best) = found.first() {
        push(vec![best.clone()]);
    }
    if greedy.len() > 1 {
        let mut v = greedy.clone();
        v.pop();
        push(v);
    }
    out
}
