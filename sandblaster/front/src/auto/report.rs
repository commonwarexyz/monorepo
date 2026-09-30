//! Failure reports (DESIGN.md §10.4): the normalized goal, the facts, the
//! stuck subterms (unfold / case-split candidates) and what was tried, as
//! strings for the elaborator's diagnostics. Terms are printed in core text
//! syntax (§5.12) in the goal's context.

use super::search::{Engine, truncate};
use super::state::St;
use crate::prover::{AutoFailure, Goal};

pub(crate) fn failure(e: &mut Engine<'_>, g: &Goal) -> AutoFailure {
    let st = St::new(e.env, &g.ctx, 0);
    let goal = e.show(&st, &g.target);
    let mut facts = Vec::new();
    for (l, entry) in g.ctx.entries.iter().enumerate() {
        if facts.len() >= 32 {
            facts.push("…".into());
            break;
        }
        if e.is_prop(&entry.ty, g.ctx.depth().0) && !crate::elab::fact_hidden(l as u32) {
            let origin = g.facts.iter().find(|f| f.lvl.0 == l as u32).map(|f| format!(" [{:?}]", f.origin)).unwrap_or_default();
            let names: Vec<_> = g.ctx.entries.iter().map(|x| x.name.clone()).collect();
            let ty = crate::elab::show::value(e.env, &names, &entry.ty, 300);
            facts.push(truncate(format!("{}: {ty}{origin}", entry.name), 300));
        }
    }
    if e.stuck.is_empty() {
        let mut out = Vec::new();
        e.collect_stuck(&g.target, &mut out);
        for s in out.into_iter().take(6) {
            let txt = e.show(&st, &s.val);
            if !e.stuck.contains(&txt) {
                e.stuck.push(txt);
            }
        }
    }
    AutoFailure { goal, facts, stuck: e.stuck.clone(), tried: e.tried.clone() }
}
