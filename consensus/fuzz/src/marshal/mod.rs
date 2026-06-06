//! Fuzz harnesses for the marshal mechanism.
//!
//! Two complementary methods, each generic over the marshal variant
//! (`StandardHarness` / `CodingHarness`), mirroring how marshal itself splits
//! into `standard` and `coding`:
//!
//! - [`single_node`]: drives one marshal actor in isolation by synthesizing
//!   every input it would receive (blocks, notarizations, finalizations,
//!   restarts) and asserting per-actor delivery invariants.
//! - [`multi_node`]: runs a live `N4F1C3` cluster (three honest nodes
//!   plus one byzantine `Disrupter`) wired to real simplex consensus, and
//!   checks marshal liveness (every honest node delivers a target number of
//!   ordered finalized blocks sampled within a single-epoch bound) plus
//!   cross-node agreement.
//!
//! # Goals, pros, and cons
//!
//! - [`single_node`] -- fuzz the core actor's state machine.
//!   - Pro: adversarial/out-of-order inputs, crash-restart recovery,
//!     durability-ack contracts, precise gap-repair; cheap and fast.
//!   - Con: single validator, so coding's peer-shard dissemination,
//!     reconstruction, and validation are unreachable.
//! - [`multi_node`] -- fuzz the live integration with one byzantine node.
//!   - Pro: real consensus plus shard dissemination/reconstruction/validation,
//!     cross-node agreement, and liveness check.
//!   - Con: heavier (fewer iterations) and only valid
//!     consensus orderings.

use arbitrary::Arbitrary;
use commonware_consensus::marshal::mocks::harness::StandardHarness;

pub mod inline;
pub mod multi_node;
pub mod single_node;
pub mod store;

pub use inline::{fuzz_marshal_inline, MarshalInlineInput};
pub use multi_node::{fuzz_marshal_liveness, MarshalLivenessInput};
pub use single_node::{fuzz_marshal, MarshalEvent, MarshalFuzzInput, VariantPublish};
pub use store::{fuzz_marshal_store, MarshalStoreInput};

#[derive(Debug, Clone)]
pub enum MarshalStandardInput {
    Actor(MarshalFuzzInput),
    Inline(MarshalInlineInput),
    Store(MarshalStoreInput),
}

impl Arbitrary<'_> for MarshalStandardInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=99)? {
            0..=69 => Self::Actor(MarshalFuzzInput::arbitrary(u)?),
            70..=89 => Self::Inline(MarshalInlineInput::arbitrary(u)?),
            _ => Self::Store(MarshalStoreInput::arbitrary(u)?),
        })
    }
}

pub fn fuzz_marshal_standard(input: MarshalStandardInput) {
    match input {
        MarshalStandardInput::Actor(input) => fuzz_marshal::<StandardHarness>(input),
        MarshalStandardInput::Inline(input) => fuzz_marshal_inline(input),
        MarshalStandardInput::Store(input) => fuzz_marshal_store(input),
    }
}
