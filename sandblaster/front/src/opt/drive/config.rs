//! Budgets of the Σ1 driver (optimizer design §17). Every budget counts
//! kernel steps or nodes, never time or memory, so the driver's decisions
//! are a pure function of its input (gate G1); exhausting one ends the
//! driven candidate (the function falls back to the next rung).

/// The driver's budgets.
#[derive(Clone, Debug)]
pub struct DriveConfig {
    /// Kernel steps of one function's driving (evaluation, linarith
    /// decisions): design §17, 5·10^7.
    pub steps: u64,
    /// Kernel steps of the equality lemma's proof (built separately, on the
    /// residual's committed definition).
    pub proof_steps: u64,
    /// Kernel steps of the proof builder's `auto` search at one leaf of the
    /// process tree whose two sides are not convertible (taken out of
    /// `proof_steps`). A leaf is normally closed by conversion; the search
    /// is a fallback for small differences, and a leaf it cannot close is a
    /// failure however long it searches (QMDB `verifier::verify`: 181 ms
    /// reading back the unfolded verifier before giving up), so it is
    /// bounded well below the proof's budget.
    pub leaf_auto_steps: u64,
    /// Process-graph nodes (unfoldings, decisions, splits) of one function.
    pub max_nodes: usize,
    /// Nested splits along one path.
    pub max_split_depth: u32,
    /// Unfoldings of recursive globals along one path (static-measure and
    /// static-structure unrolling).
    pub max_unroll: u32,
    /// Largest static measure of a user recursion that is unrolled (into
    /// per-level helpers, design §6.5, or in place); a longer one stays a
    /// call of its loop. Unrolling trades the loop for straight-line code,
    /// which the corpus measured slower on long inputs (P5, 9–10 bytes:
    /// 0.84–0.95× the loop) while faster on short ones.
    pub max_static_trips: u32,
    /// Trips of a loop unrolled inside a polyvariant call-site
    /// specialization (design §6.5; under the unroller's checkpoint).
    pub max_spec_trips: u32,
    /// Residual nodes of one driven function (the unrolled nodes of design
    /// §6.2 count here).
    pub max_residual_nodes: usize,
    /// Committed-body size (term nodes) up to which a non-recursive callee
    /// kept opaque in checking mode (a reader) is unfolded by the driver.
    pub inline_body_nodes: usize,
    /// Arms of a merged (select-shaped) residual: at most this many nodes
    /// each (design §6.3 step 3).
    pub merge_nodes: usize,
    /// Callee residuals larger than this (nodes) stay calls at their call
    /// sites (design §6.4).
    pub link_inline_nodes: usize,
    /// Case-of-case pushes a continuation into every result leaf of an
    /// instantiated callee: allowed while `leaves × continuation nodes` is
    /// at most this; beyond it the callee's residual is inlined as a value
    /// (a join point) instead.
    pub case_of_case_nodes: usize,
}

impl DriveConfig {
    /// The call-site cost thresholds (design §6.4).
    pub fn call_costs(&self) -> crate::opt::summary::CallCosts {
        crate::opt::summary::CallCosts { max_inline_nodes: self.link_inline_nodes, max_duplicated_nodes: self.case_of_case_nodes }
    }
}

impl Default for DriveConfig {
    fn default() -> DriveConfig {
        DriveConfig {
            steps: 50_000_000,
            proof_steps: 50_000_000,
            leaf_auto_steps: 100_000,
            max_nodes: 1024,
            max_split_depth: 96,
            max_unroll: 96,
            max_static_trips: 10,
            max_spec_trips: 64,
            max_residual_nodes: 4096,
            inline_body_nodes: 600,
            merge_nodes: 8,
            link_inline_nodes: 256,
            case_of_case_nodes: 4096,
        }
    }
}
