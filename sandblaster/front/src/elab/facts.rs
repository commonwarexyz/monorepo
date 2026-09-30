//! Method facts (DESIGN.md §3.4): lemmas about builtin calls that the
//! elaborator adds at call sites, like a callee's `ensures`. The facts come
//! from the one table [`crate::auto::lemmas::method_facts`]: its
//! [`FactShape::Always`] entries (a checked, untrusted prelude lemma
//! `Π(T..)(args..)(.req..). F[call]`) are added as an irrelevant `let` right
//! after the call is formed, so later obligations can use them; its
//! `OnSome`/`OnNone` entries need the path equation of a match on the
//! result and are used by `auto` as forward rules. A lemma that is not
//! loaded (or does not fit the call) simply adds no fact.

use sandblaster_kernel::term::{Term, Tm};
use sandblaster_kernel::util::mk;

use super::exec::K;
use super::{Elab, Val, R};
use crate::auto::lemmas::{method_facts, FactShape};
use crate::builtins::{Builtin, SliceMethod};
use crate::hir::Ty;
use crate::prover::FactOrigin;
use crate::span::Span;

impl<'a> Elab<'a> {
    /// Continues with the call value `t`, after adding its method facts.
    pub fn with_method_facts(&mut self, b: Builtin, targs: &[Ty], t: Tm, span: Span, k: &mut K<'_, 'a>) -> R<Tm> {
        let _ = targs;
        let facts = self.method_fact_terms(&b, &t);
        self.push_facts_then(facts, 0, b, Val::new(t, self.depth()), span, k)
    }

    fn push_facts_then(&mut self, facts: Vec<(Tm, Tm)>, i: usize, b: Builtin, v: Val, span: Span, k: &mut K<'_, 'a>) -> R<Tm> {
        let Some((ty, pf)) = facts.get(i).cloned() else { return k(self, v) };
        let d0 = self.depth();
        let facts2 = facts.clone();
        self.fact_in("h_fact", ty, pf, FactOrigin::MethodFact(b), span, &mut |s| {
            let facts3: Vec<(Tm, Tm)> = facts2.iter().map(|(a, c)| (sandblaster_kernel::util::shift(a, (s.depth() - d0) as i64), sandblaster_kernel::util::shift(c, (s.depth() - d0) as i64))).collect();
            s.push_facts_then(facts3, i + 1, b, v.clone(), span, k)
        })
    }

    /// The `Always` facts of a call `g T recv args..`: `(statement, proof)`
    /// at the current depth. The table's argument convention omits the
    /// literal size of `as_chunks::<N>` for its per-size lemmas; both forms
    /// are tried against the lemma's arity.
    fn method_fact_terms(&mut self, b: &Builtin, call: &Tm) -> Vec<(Tm, Tm)> {
        let (_, args) = super::items::spine(call);
        let Some((elem, rest)) = args.split_first() else { return vec![] };
        let mut forms: Vec<Vec<Tm>> = vec![rest.to_vec()];
        if let Builtin::Slice(SliceMethod::AsChunks(_)) = b
            && rest.len() == 3
        {
            forms.push(vec![rest[0].clone(), rest[2].clone()]);
        }
        let mut out = Vec::new();
        for mf in method_facts(b) {
            if !matches!(mf.shape, FactShape::Always) {
                continue;
            }
            let Some(g) = self.env.lookup_global(mf.lemma) else { continue };
            let (Some(rels), Some(ty)) = (self.env.global_param_rels(g), self.env.global_type(g)) else { continue };
            let Some(form) = forms.iter().find(|f| f.len() + 1 == rels.len()) else { continue };
            let mut all = vec![elem.clone()];
            all.extend(form.iter().cloned());
            let pf = mk::apps(mk::global(g), rels.iter().copied().zip(all.iter().cloned()));
            // the statement by substitution into the lemma's type
            let mut t = ty;
            for _ in 0..all.len() {
                let Term::Pi { cod, .. } = &*t.clone() else { break };
                t = cod.clone();
            }
            out.push((super::tm::subst_closed(&t, &all), pf));
        }
        out
    }
}
