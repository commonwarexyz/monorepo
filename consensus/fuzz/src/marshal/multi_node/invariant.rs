//! Safety and end-of-run invariants for the multi-node marshal model.
//!
//! These checks cover both the marshal/application boundary and observations
//! made while Simplex drives marshal. They panic on violation with the
//! offending state, matching the rest of the consensus fuzz crate.
//!
//! Delivery checks operate on the sink's append-only delivery log
//! ([`Application::delivered`]) -- the actual `(height, digest)` arrival
//! sequence -- rather than a by-height snapshot, so out-of-order delivery,
//! gaps, duplicates, and same-height forks are all observable (a by-height map
//! would silently overwrite them).

use crate::simplex::Simplex;
use commonware_consensus::{
    Block, CertifiableBlock,
    marshal::{
        core::Mailbox,
        mocks::{application::Application, block::Block as MockBlock, harness::TestHarness},
        standard::Standard,
    },
    simplex::types::Context as SimplexContext,
    types::{Height, Round},
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_utils::sync::Mutex;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

type SchemeOf<P> = <P as Simplex>::Scheme;
type PublicKeyOf<P> =
    <<P as Simplex>::Scheme as commonware_cryptography::certificate::Verifier>::PublicKey;
type Ctx<P> = SimplexContext<Sha256Digest, PublicKeyOf<P>>;
type B<P> = MockBlock<Sha256Digest, Ctx<P>>;
type VerifiedContexts<P> = HashMap<(Round, Sha256Digest), Vec<Ctx<P>>>;

/// Ensures a rejection scoped to one proposal header cannot poison
/// certification of the same payload under its embedded header.
pub(super) struct HeaderMismatchInvariant<P: Simplex, C: Copy> {
    verified_contexts: Arc<Mutex<VerifiedContexts<P>>>,
    app_config: C,
    rejects: fn(C, &Ctx<P>) -> bool,
}

impl<P: Simplex, C: Copy> Clone for HeaderMismatchInvariant<P, C> {
    fn clone(&self) -> Self {
        Self {
            verified_contexts: self.verified_contexts.clone(),
            app_config: self.app_config,
            rejects: self.rejects,
        }
    }
}

impl<P: Simplex, C: Copy> HeaderMismatchInvariant<P, C> {
    pub(super) fn new(app_config: C, rejects: fn(C, &Ctx<P>) -> bool) -> Self {
        Self {
            verified_contexts: Arc::new(Mutex::new(HashMap::new())),
            app_config,
            rejects,
        }
    }

    pub(super) fn record_verify(&self, context: Ctx<P>, digest: Sha256Digest) {
        self.verified_contexts
            .lock()
            .entry((context.round, digest))
            .or_default()
            .push(context);
    }

    async fn observed_mismatch(
        &self,
        mailbox: &Mailbox<SchemeOf<P>, Standard<B<P>>>,
        round: Round,
        digest: Sha256Digest,
    ) -> bool {
        let Some(block) = mailbox.get_block(&digest).await else {
            return false;
        };
        let block_context = block.context();
        let mismatch = self
            .verified_contexts
            .lock()
            .get(&(round, digest))
            .is_some_and(|contexts| contexts.iter().any(|context| context != &block_context));
        mismatch && !(self.rejects)(self.app_config, &block_context)
    }

    /// Check the certification outcome after a header-mismatching verification.
    ///
    /// `None` represents a closed certification channel.
    pub(super) async fn check_certification(
        &self,
        mailbox: &Mailbox<SchemeOf<P>, Standard<B<P>>>,
        round: Round,
        digest: Sha256Digest,
        verdict: Option<bool>,
    ) {
        let mismatch = self.observed_mismatch(mailbox, round, digest).await;
        match verdict {
            Some(value) => assert!(
                value || !mismatch,
                "marshal invariant violated: certification reused a \
                 header-scoped verification rejection"
            ),
            None => assert!(
                !mismatch,
                "marshal invariant violated: certification closed after a \
                 header-scoped verification rejection"
            ),
        }
    }
}

/// Run every liveness-model invariant.
pub fn check_all<H: TestHarness>(
    required: u64,
    honest_apps: &[(usize, Application<H::ApplicationBlock>)],
) {
    check_all_blocks(required, honest_apps);
}

/// Run every liveness-model invariant for a standard block type whose Simplex
/// context is selected by the fuzzed signing scheme.
pub fn check_all_blocks<B: Block<Digest = Sha256Digest>>(
    required: u64,
    honest_apps: &[(usize, Application<B>)],
) {
    for (idx, app) in honest_apps {
        check_in_order(*idx, required, &app.delivered());
    }
    agreement(honest_apps);
}

/// Invariant: per-node in-order, gap-free delivery.
///
/// Walks the arrival-ordered delivery log. Delivery starts either at the
/// genesis floor block (height 0, surfaced on a fresh start) or at the first
/// finalized container (height 1), then every subsequent delivery must advance
/// by exactly one. Because this is the true arrival sequence, an out-of-order
/// delivery, a gap, or a duplicate/refinalized height all fail the `+ 1` check.
/// After liveness the highest delivered height must be at least `required`.
fn check_in_order<D>(idx: usize, required: u64, delivered: &[(Height, D)]) {
    let heights: Vec<u64> = delivered.iter().map(|(h, _)| h.get()).collect();
    let first = heights.first().copied().unwrap_or(0);
    assert!(
        first <= 1,
        "node{idx} first delivery at height {first} is above the genesis floor + 1 \
         (sequence={heights:?})",
    );
    for window in heights.windows(2) {
        assert_eq!(
            window[1],
            window[0] + 1,
            "node{idx} violated in-order delivery (out-of-order, gap, or duplicate); \
             sequence={heights:?}",
        );
    }
    let max = heights.last().copied().unwrap_or(0);
    assert!(
        max >= required,
        "node{idx} delivered up to height {max}, fewer than required {required} \
         (sequence={heights:?})",
    );
}

/// Invariant: cross-node agreement (safety).
///
/// For every pair of honest nodes, the shorter finalized chain must be a prefix
/// of the longer chain. Marshal can check this stronger block-level property
/// because its application sink retains finalized `(height, digest)` entries;
/// comparing finalized heights alone would not detect conflicting blocks.
///
/// [`check_in_order`] establishes that each node's delivery log is contiguous
/// and contains no duplicate heights. Given that, requiring one digest per
/// height across all honest nodes is equivalent to pairwise prefix
/// compatibility. Heights are used instead of raw sequence indexes because a
/// fresh application may surface genesis at height 0 or begin with the first
/// finalized block at height 1.
///
/// This detects conflicting finalization, fork divergence, and recovery that
/// delivers a different block at an already observed height.
fn agreement<B: Block<Digest = Sha256Digest>>(honest_apps: &[(usize, Application<B>)]) {
    let mut seen: BTreeMap<Height, (usize, Sha256Digest)> = BTreeMap::new();
    for (idx, app) in honest_apps {
        for (height, digest) in app.delivered() {
            if let Some((first_idx, first_digest)) = seen.get(&height) {
                assert_eq!(
                    *first_digest,
                    digest,
                    "honest fork at height {}: node{first_idx} delivered {first_digest:?} \
                     but node{idx} delivered {digest:?}",
                    height.get(),
                );
            } else {
                seen.insert(height, (*idx, digest));
            }
        }
    }
}
