//! The process tree of one driven function (optimizer design §5, §6).
//!
//! The tree is both the residual's decision structure and the proof log:
//!
//! * a [`Node`] carries the source-side [`Step`]s performed at that point
//!   (unfoldings, decisions from facts) and then either ends in a
//!   straight-line [`NodeKind::Leaf`] value or splits on a stuck scrutinee
//!   ([`NodeKind::Split`], a residual `match`/`if`);
//! * every value is a kernel value in the driver's context at that node:
//!   the parameters, the `requires` binders, and per enclosing split the
//!   constructor's fields followed by the path equation
//!   `e : Eq(D, scrut, Cₖ(fields))`. The proof builder (`opt::proof`)
//!   introduces exactly the same binders in the same order, so a value of
//!   the tree means the same in the proof's context (values use de Bruijn
//!   levels).
//!
//! The residual printer (`opt::residual::build_tree`) turns the tree into
//! HIR; the proof builder replays the steps on the equation
//! `Eq(R, residual x̄ h̄, f x̄ h̄)` (design §11.2).

use sandblaster_kernel::term::{GlobalId, IndId, Name, Rel};
use sandblaster_kernel::value::V;

/// A source-side step of the process graph (design §5 `Step`).
#[derive(Clone, Debug)]
pub enum Step {
    /// `Delta(def; args)`: the folded application `app` (a value whose head
    /// is `def` fully applied) is replaced by the definition's body.
    Unfold { def: GlobalId, app: V },
    /// A stuck boolean scrutinee decided by linear arithmetic from the facts
    /// in scope: `cond` is `value`.
    Prune { cond: V, value: bool },
    /// A stuck scrutinee convertible with the scrutinee of an enclosing
    /// split: the path equation at level `eq` fixes its constructor.
    /// (`flip`: a simulated fault, `DriveFault::CrossArmReuse` — the other
    /// boolean constructor was taken.)
    Reuse { scrut: V, eq: u32, flip: bool },
    /// Polyvariant specialization (design §6.5): the folded application of
    /// the recursive `def` at the head, whose arguments at the positions of
    /// `statics` are those literals, becomes a call of the helper
    /// `def__σ` (driven separately, with its own lemma
    /// `Π dyn̄. Eq(R, def__σ dyn̄, def(statics, dyn̄))`).
    Specialize { def: GlobalId, key: SpecKey },
    /// The word form (design §12.4, [`super::word`]): the folded
    /// `seq::eq U8 (==) xs ys` at the head (`app`), over two byte spines of
    /// length `8·blocks`, becomes
    /// `((W(a,0) ⊕ W(b,0)) | …) == 0` over little-endian words, by the
    /// checked lemmas `word::eq8_or` / `word::eq8_last`.
    Word { app: V, blocks: u32 },
    /// A callee summary used at its call site (design §6.4, `Apply`): the
    /// folded application `app` of the user function `def` (fully applied)
    /// is replaced by the same application of its admitted residual `res`,
    /// by the residual's equality lemma `lemma : Π x̄ h̄. Eq(R, res x̄ h̄,
    /// def x̄ h̄)` (reversed). An `Unfold` of `res` follows: the caller
    /// continues with the callee's residual body, never re-driving its
    /// source.
    Link { def: GlobalId, res: GlobalId, lemma: GlobalId, app: V },
    /// A back-edge (design §6.6, folding under the same-global rule): the
    /// folded application `app` of `def` — the function whose loop helper
    /// is being built, at the helper's own root — is the helper's
    /// recursive call; its proof is the induction hypothesis (`Rec`) of the
    /// helper's lemma. Always the last step of a leaf.
    Fold { def: GlobalId, app: V },
    /// Polyvariant call-site specialization inside a leaf (design §6.5): an
    /// application of `def` at the literals of `key` in the leaf's value
    /// (not at its head) is printed as a call of `key`'s helper; the leaf's
    /// proof rewrites the helper's calls to the applications through the
    /// helper's lemma. Always after the leaf's other steps.
    SpecializeIn { def: GlobalId, key: SpecKey },
    /// The folded application of the recursion `def` at the head is kept
    /// as a call of `def`'s fold helper (design §6.6; `summary::FoldHelper`):
    /// the helper's lemma `Π x̄ h̄. Eq(R, H x̄ h̄, def x̄ …)` rewrites it, the
    /// helper's `requires` (the source's and its bound invariant) proven at
    /// the call.
    FoldCall { def: GlobalId },
    /// A checked arithmetic call at the head of a match (`w::checked_add`,
    /// `w::checked_sub`) whose overflow condition linear arithmetic decides
    /// (`value`: no overflow, `Some`): rewritten by the lemma
    /// `w::checked_{op}_{some,none}` (optimizer design §6.3) instead of
    /// unfolding into a dependent `if` nested in the match.
    Checked { def: GlobalId, value: bool },
    /// Σ2 (optimizer design §7, `opt::loopsum`): the folded application of
    /// the loop head `def` at the head, at the static arguments of `key`,
    /// is kept as a call of the key's loop helper `H` (its body the closed
    /// form); the helper's link `Π d̄ h̄. Eq(R, H d̄ h̄, def(statics, d̄) h̄)`
    /// rewrites it, `H`'s `requires` proven at the call.
    LoopSum { def: GlobalId, key: crate::opt::loopsum::LoopKey },
    /// A guard specialization (plan O6, `opt::guardspec`): the folded
    /// application of the user function `def` at the head, in tail
    /// position, is a call of the key's guard helper `H` (the source with
    /// the early-return guards the path's facts decide removed); its lemma
    /// `Π x̄ h̄ h̄g. Eq(R, H x̄ h̄ h̄g, def x̄ h̄)` rewrites it, `h̄g` proven at
    /// the call from the facts.
    GuardSpec { def: GlobalId, key: crate::opt::guardspec::GuardKey },
    /// Σ3 (design §8, `opt::seqsum`): the leaf's value was rewritten by the
    /// segment normal form — element reads of assembled buffers forwarded,
    /// sub-slices of them resolved to sub-slices of the pieces, calls on
    /// them turned into calls of segment specializations. The proof closes
    /// the leaf from the seq lemmas (`seqsum::prove`). Always a leaf's last
    /// step.
    Seq,
    /// Σ3 demand split: the node's split is the residual's own test (the
    /// emptiness of a piece, which a read of a buffer depends on); the
    /// source has no such match, so only the residual is split.
    Demand,
}

/// The key of a specialization: the recursive function and its static
/// (literal) arguments, by kernel argument index.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpecKey {
    pub def: GlobalId,
    pub statics: Vec<(usize, sandblaster_kernel::term::BigInt)>,
}

/// One constructor field bound by a split arm.
#[derive(Clone, Debug)]
pub struct Field {
    pub name: Name,
    pub rel: Rel,
    /// The field's type (a value in the arm's context).
    pub ty: V,
    /// Its de Bruijn level in the arm's context.
    pub lvl: u32,
}

/// One arm of a split: the constructor, its fields, the level of the path
/// equation, and the subtree.
#[derive(Clone, Debug)]
pub struct Arm {
    pub ctor: u32,
    pub fields: Vec<Field>,
    pub eq_lvl: u32,
    pub body: Node,
}

#[derive(Clone, Debug)]
pub enum NodeKind {
    /// A straight-line residual value (in-place matches that need no proof
    /// split may remain: merged, select-shaped).
    Leaf(V),
    /// A residual split on `scrut : ind(params)`; the arms in constructor
    /// order. `merged`: every arm ended in the same value, independent of
    /// the arm (the **Merge** of design §6.3 for equal arms): the residual
    /// has no split here, only that value, while the proof still splits
    /// the source (each arm's steps justify its own leaf).
    Split { scrut: V, ind: IndId, params: Vec<V>, arms: Vec<Arm>, merged: Option<V> },
    /// A callee's residual inlined as a value (design §6.4, "inline through
    /// the link", a join point): `value` is the subtree of the callee's
    /// residual at its arguments (its steps: `Link`, `Unfold`), bound to a
    /// new variable at level `lvl` (`name`, of type `ty`); the caller
    /// continues in `body` over that variable instead of pushing its
    /// continuation into every leaf of the callee (case-of-case). The
    /// residual prints `let name = value; body`.
    Bind { lvl: u32, name: Name, ty: V, value: Box<Node>, body: Box<Node> },
}

#[derive(Clone, Debug)]
pub struct Node {
    /// Context depth at this node (parameters, `requires`, enclosing split
    /// binders).
    pub depth: u32,
    pub steps: Vec<Step>,
    pub kind: NodeKind,
}

impl Node {
    /// Number of process-graph nodes (steps, splits, leaves).
    pub fn size(&self) -> usize {
        self.steps.len()
            + match &self.kind {
                NodeKind::Leaf(_) => 1,
                NodeKind::Split { arms, .. } => 1 + arms.iter().map(|a| a.body.size()).sum::<usize>(),
                NodeKind::Bind { value, body, .. } => 1 + value.size() + body.size(),
            }
    }

    /// Whether the node is leaf-like for the residual: a leaf, or a split
    /// merged into one value. Returns that value.
    pub fn leaf_value(&self) -> Option<&V> {
        match &self.kind {
            NodeKind::Leaf(v) => Some(v),
            NodeKind::Split { merged: Some(v), .. } => Some(v),
            _ => None,
        }
    }

    /// Whether any step or split occurs (a tree that is a bare leaf without
    /// steps is the tier-0 case).
    pub fn is_trivial(&self) -> bool {
        self.steps.is_empty() && matches!(self.kind, NodeKind::Leaf(_))
    }

    /// The decisions among `steps`: tests pruned or reused, checked calls
    /// decided, guards specialized, leaves by the segment normal form and
    /// its demand splits (what a callee's own residual could not have done
    /// at a kept call; see [`Node::decisions`]).
    pub fn step_decisions(steps: &[Step]) -> usize {
        steps.iter().filter(|s| matches!(s, Step::Prune { .. } | Step::Reuse { .. } | Step::Checked { .. } | Step::GuardSpec { .. } | Step::Seq | Step::Demand)).count()
    }

    /// The decisions in the tree ([`Node::step_decisions`] of every node)
    /// plus its merged splits.
    pub fn decisions(&self) -> usize {
        Node::step_decisions(&self.steps)
            + match &self.kind {
                NodeKind::Leaf(_) => 0,
                NodeKind::Split { arms, merged, .. } => merged.is_some() as usize + arms.iter().map(|a| a.body.decisions()).sum::<usize>(),
                NodeKind::Bind { value, body, .. } => value.decisions() + body.decisions(),
            }
    }

    /// Counts of each step kind and of splits (for the report).
    pub fn counts(&self) -> StepCounts {
        let mut c = StepCounts::default();
        self.count_into(&mut c);
        c
    }

    fn count_into(&self, c: &mut StepCounts) {
        for s in &self.steps {
            match s {
                Step::Unfold { .. } => c.unfold += 1,
                Step::Prune { .. } => c.prune += 1,
                Step::Reuse { .. } => c.reuse += 1,
                Step::Specialize { .. } => c.specialize += 1,
                Step::Word { .. } => c.word += 1,
                Step::Link { .. } => c.link += 1,
                Step::Fold { .. } => c.fold += 1,
                Step::SpecializeIn { .. } => c.specialize += 1,
                Step::FoldCall { .. } => c.fold += 1,
                Step::Checked { .. } => c.prune += 1,
                Step::LoopSum { .. } => c.loopsum += 1,
                Step::GuardSpec { .. } => c.guard += 1,
                Step::Seq => c.seq += 1,
                Step::Demand => c.demand += 1,
            }
        }
        match &self.kind {
            NodeKind::Leaf(_) => c.leaves += 1,
            NodeKind::Split { arms, merged, .. } => {
                c.split += 1;
                if merged.is_some() {
                    c.merged += 1;
                }
                for a in arms {
                    a.body.count_into(c);
                }
            }
            NodeKind::Bind { value, body, .. } => {
                c.bind += 1;
                value.count_into(c);
                body.count_into(c);
            }
        }
    }
}

/// Step statistics of a process tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StepCounts {
    pub unfold: u32,
    pub prune: u32,
    pub reuse: u32,
    pub specialize: u32,
    pub word: u32,
    pub split: u32,
    pub leaves: u32,
    /// Callee summaries used through their link (design §6.4).
    pub link: u32,
    /// Callee residuals inlined as values (join points).
    pub bind: u32,
    /// Splits merged into one value.
    pub merged: u32,
    /// Back-edges folded into a loop helper's recursive call.
    pub fold: u32,
    /// Loop heads replaced by their Σ2 loop helpers (closed forms).
    pub loopsum: u32,
    /// Calls replaced by guard helpers (checks the facts decide).
    pub guard: u32,
    /// Leaves rewritten by the segment normal form (Σ3).
    pub seq: u32,
    /// Σ3 demand splits (the residual's own tests).
    pub demand: u32,
}

impl StepCounts {
    /// The counts for the report (`3 unfolds, 9 prunes, 31 splits (4
    /// merged: equal arms, the split and the reads below it gone), …`),
    /// the nonzero ones.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut add = |n: u32, one: &str, many: &str| {
            if n > 0 {
                parts.push(format!("{n} {}", if n == 1 { one } else { many }));
            }
        };
        add(self.unfold, "unfold", "unfolds");
        add(self.prune, "prune", "prunes");
        add(self.reuse, "reused decision", "reused decisions");
        add(self.specialize, "specialization", "specializations");
        add(self.word, "word form", "word forms");
        add(self.link, "callee instantiated through its link", "callees instantiated through their links");
        add(self.bind, "callee inlined as a value", "callees inlined as values");
        add(self.fold, "fold (a loop helper's back-edge or call)", "folds (loop helpers' back-edges or calls)");
        add(self.loopsum, "loop summarized (Σ2)", "loops summarized (Σ2)");
        add(self.guard, "call with its guards decided by facts", "calls with their guards decided by facts");
        add(self.seq, "leaf by the segment normal form", "leaves by the segment normal form");
        add(self.demand, "demand split", "demand splits");
        let mut out = parts.join(", ");
        if self.split > 0 {
            if !out.is_empty() {
                out.push_str(", ");
            }
            out.push_str(&format!("{} split{}", self.split, if self.split == 1 { "" } else { "s" }));
            if self.merged > 0 {
                out.push_str(&format!(" ({} merged: arms ending in one value, the split and what only it reads are not in the residual)", self.merged));
            }
        }
        out.push_str(&format!(", {} leaf{}", self.leaves, if self.leaves == 1 { "" } else { "s" }));
        out
    }

    /// The tree only unfolded the root and split on the source's own
    /// matches: its residual is the source up to evaluation. (A Σ2 loop
    /// summary or a Σ3 demand split changes the residual: not trivial.)
    pub fn trivial(&self) -> bool {
        self.unfold <= 1 && self.prune == 0 && self.reuse == 0 && self.specialize == 0 && self.word == 0 && self.link == 0 && self.bind == 0 && self.merged == 0 && self.fold == 0 && self.loopsum == 0 && self.guard == 0 && self.seq == 0 && self.demand == 0
    }
}

impl Node {
    /// The specialization keys requested in the tree (in tree order,
    /// without duplicates).
    /// The applications at the tree's back-edges (`Fold` leaves).
    pub fn fold_apps(&self) -> Vec<V> {
        fn go(n: &Node, out: &mut Vec<V>) {
            if let Some(Step::Fold { app, .. }) = n.steps.last() {
                out.push(app.clone());
            }
            match &n.kind {
                NodeKind::Split { arms, .. } => arms.iter().for_each(|a| go(&a.body, out)),
                NodeKind::Bind { value, body, .. } => {
                    go(value, out);
                    go(body, out);
                }
                NodeKind::Leaf(_) => {}
            }
        }
        let mut out = Vec::new();
        go(self, &mut out);
        out
    }

    /// The recursions whose fold helpers the tree calls (`FoldCall`),
    /// distinct.
    pub fn fold_calls(&self) -> Vec<GlobalId> {
        fn go(n: &Node, out: &mut Vec<GlobalId>) {
            for s in &n.steps {
                if let Step::FoldCall { def } = s
                    && !out.contains(def)
                {
                    out.push(*def);
                }
            }
            match &n.kind {
                NodeKind::Split { arms, .. } => arms.iter().for_each(|a| go(&a.body, out)),
                NodeKind::Bind { value, body, .. } => {
                    go(value, out);
                    go(body, out);
                }
                NodeKind::Leaf(_) => {}
            }
        }
        let mut out = Vec::new();
        go(self, &mut out);
        out
    }

    /// The guard specializations of the tree's `GuardSpec` steps
    /// (distinct).
    pub fn guard_keys(&self) -> Vec<crate::opt::guardspec::GuardKey> {
        fn go(n: &Node, out: &mut Vec<crate::opt::guardspec::GuardKey>) {
            for s in &n.steps {
                if let Step::GuardSpec { key, .. } = s
                    && !out.contains(key)
                {
                    out.push(key.clone());
                }
            }
            match &n.kind {
                NodeKind::Split { arms, .. } => arms.iter().for_each(|a| go(&a.body, out)),
                NodeKind::Bind { value, body, .. } => {
                    go(value, out);
                    go(body, out);
                }
                NodeKind::Leaf(_) => {}
            }
        }
        let mut out = Vec::new();
        go(self, &mut out);
        out
    }

    /// The Σ2 loop keys of the tree's `LoopSum` steps (distinct).
    pub fn loop_keys(&self) -> Vec<crate::opt::loopsum::LoopKey> {
        fn go(n: &Node, out: &mut Vec<crate::opt::loopsum::LoopKey>) {
            for s in &n.steps {
                if let Step::LoopSum { key, .. } = s
                    && !out.contains(key)
                {
                    out.push(key.clone());
                }
            }
            match &n.kind {
                NodeKind::Split { arms, .. } => arms.iter().for_each(|a| go(&a.body, out)),
                NodeKind::Bind { value, body, .. } => {
                    go(value, out);
                    go(body, out);
                }
                NodeKind::Leaf(_) => {}
            }
        }
        let mut out = Vec::new();
        go(self, &mut out);
        out
    }

    pub fn spec_keys(&self) -> Vec<SpecKey> {
        let mut out = Vec::new();
        self.spec_keys_into(&mut out);
        out
    }

    fn spec_keys_into(&self, out: &mut Vec<SpecKey>) {
        for s in &self.steps {
            if let Step::Specialize { key, .. } | Step::SpecializeIn { key, .. } = s
                && !out.contains(key)
            {
                out.push(key.clone());
            }
        }
        match &self.kind {
            NodeKind::Split { arms, .. } => {
                for a in arms {
                    a.body.spec_keys_into(out);
                }
            }
            NodeKind::Bind { value, body, .. } => {
                value.spec_keys_into(out);
                body.spec_keys_into(out);
            }
            NodeKind::Leaf(_) => {}
        }
    }

    /// Number of leaf-like ends of the tree (result positions of the
    /// residual): the cost model's estimate of how many copies a
    /// continuation pushed into it gets (case-of-case, design §6.4).
    pub fn result_leaves(&self) -> usize {
        match &self.kind {
            NodeKind::Leaf(_) | NodeKind::Split { merged: Some(_), .. } => 1,
            NodeKind::Split { arms, .. } => arms.iter().map(|a| a.body.result_leaves()).sum(),
            NodeKind::Bind { body, .. } => body.result_leaves(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StepCounts;

    /// A tree that summarizes a loop (Σ2) or splits on a piece's emptiness
    /// (Σ3 demand) changes the residual: it is not trivial, even when it
    /// only unfolds the root and splits besides (QMDB's `shape`: unfold 1,
    /// split 1, loopsum 1). A trivial tree gets a `refl` lemma attempt and
    /// its multiversioned clones keep their source.
    #[test]
    fn loop_summaries_and_demand_splits_are_not_trivial() {
        let base = StepCounts { unfold: 1, split: 1, leaves: 2, ..Default::default() };
        assert!(base.trivial());
        assert!(!StepCounts { loopsum: 1, ..base }.trivial());
        assert!(!StepCounts { demand: 1, ..base }.trivial());
    }
}
