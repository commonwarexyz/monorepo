//! The per-producer-chain remote validator data-availability plane.
//!
//! Stage 2 of the DA-plane sharding lifts one producer chain's block store, application-validation
//! scheduling, and data-availability-vote eligibility off the single serial voter thread into a
//! per-chain runtime task (see [`super::super::actors::voter`]). This module holds the deterministic
//! state and algorithms that task drives; it performs no I/O and dispatches no application call, so
//! it is exercised directly by the core invariant harness and by focused unit tests.
//!
//! Central (the serial [`ChainState`](super::chain::ChainState) owner) keeps every durable choice:
//! it mints each observation identity, records producer ancestry and detects forks, owns the
//! one-vote-per-height DA choice, the durable cursor, and the safety-extension check. This plane
//! only *offers* the contiguous eligible run central then reserves. Its block store, in-flight
//! validations, and DA-choice read-copy are volatile and rebuildable: on restart central replays
//! its durable state, respawns a fresh plane, and re-seeds the certified anchor and chosen votes,
//! then blocks refill from re-observed gossip.

use super::{
    ArtifactId, BlockValidity, DaChoice, Observation, ValidationCompletion, ValidationId,
    ValidationJob,
};
use crate::{
    multimmit::types::{BlockRef, ChainId, SignedTransactionBlock, TransactionBlockHeader},
    types::Height,
};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use std::{collections::BTreeMap, ops::Bound, sync::Arc};

/// Where one retained block sits in the application-validation pipeline.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ValidationState {
    /// Producer-authenticated and awaiting an application-validation slot.
    Ready,
    /// Application validation is in flight under this identity.
    Pending(ValidationId),
    /// The application confirmed the payload is available and valid.
    Valid,
}

/// One producer-authenticated block retained for validation and DA-vote eligibility.
struct BlockRecord<V: Variant, D: Digest> {
    artifact: ArtifactId<D>,
    observation: Observation,
    block: Arc<SignedTransactionBlock<V, D>>,
    block_ref: BlockRef<D>,
    state: ValidationState,
}

/// One chain's contiguous eligible data-availability-vote run and how far it reaches.
///
/// `ready_through` is the greatest height the run covers, or the certified anchor when the run is
/// empty. Central mirrors it into the frontier shadow, which can only lag this plane by an in-flight
/// message and is therefore a safe lower bound.
pub(crate) struct EligibleRun<V: Variant, D: Digest> {
    pub run: Vec<Arc<SignedTransactionBlock<V, D>>>,
    pub ready_through: Height,
}

/// The remote validator data-availability plane for one producer chain.
pub(crate) struct PerChainValidator<V: Variant, D: Digest> {
    chain: ChainId,
    pipeline_depth: u64,
    /// The most in-flight application validations this chain keeps at once.
    validation_items_limit: usize,
    /// The most in-flight application-validation bytes this chain keeps at once.
    validation_bytes_limit: usize,
    /// Producer-authenticated blocks above the certified anchor, keyed by height and kept in
    /// observation order within a height so an equivocating producer resolves deterministically.
    blocks: BTreeMap<Height, Vec<BlockRecord<V, D>>>,
    /// In-flight application validations issued by this plane.
    validations: BTreeMap<ValidationId, ValidationRecord<D>>,
    validation_items: usize,
    validation_bytes: usize,
    /// The next validation identity. Identities are plane-local because their completions never
    /// leave the plane.
    next_validation: u64,
    /// The greatest DA-certified block on this chain, as central last reported it. The eligible run
    /// extends from here and every retained block sits strictly above it.
    anchor: BlockRef<D>,
    /// A read-copy of central's durable DA choices above the anchor, synced by central. Central
    /// remains the sole minter; this copy only lets eligibility skip the already-voted prefix and
    /// verify its parent linkage without a round trip. It can only lag central, never lead it.
    chosen: BTreeMap<Height, DaChoice<D>>,
    /// The contiguous height through which every height above the anchor is a local DA choice. A
    /// lower bound: an entry below the true run only lengthens a scan, never hides an eligible block.
    chosen_run: Height,
    /// The process generation this plane serves; stamped on offers so central drops stale ones.
    generation: u64,
}

/// One in-flight application validation, correlated to its retained block.
#[derive(Copy, Clone, Debug)]
struct ValidationRecord<D: Digest> {
    height: Height,
    artifact: ArtifactId<D>,
    bytes: usize,
}

/// The outcome of applying one application-validation completion.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ValidationOutcome<D: Digest> {
    /// The completion did not match any live in-flight validation.
    Stale,
    /// The payload is valid and the block is retained for eligibility.
    Retained,
    /// The payload is unavailable; the block returns to the ready state and is rescheduled.
    Deferred,
    /// The payload is invalid; the block is discarded and central blocks nothing (a validated
    /// invalid payload is the producer's own fault and never enters a DA choice).
    Invalid(ArtifactId<D>),
}

impl<V: Variant, D: Digest> PerChainValidator<V, D> {
    /// Builds a plane for one chain bound to one process generation.
    pub(crate) const fn new(
        chain: ChainId,
        pipeline_depth: u64,
        validation_items_limit: usize,
        validation_bytes_limit: usize,
        anchor: BlockRef<D>,
        generation: u64,
    ) -> Self {
        Self {
            chain,
            pipeline_depth,
            validation_items_limit,
            validation_bytes_limit,
            blocks: BTreeMap::new(),
            validations: BTreeMap::new(),
            validation_items: 0,
            validation_bytes: 0,
            next_validation: 0,
            anchor,
            chosen: BTreeMap::new(),
            chosen_run: anchor.height(),
            generation,
        }
    }

    /// Returns the process generation this plane serves.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// Admits one producer-authenticated block central routed to this chain.
    ///
    /// Central has already minted the observation identity, recorded producer ancestry, and rejected
    /// forks, so a block reaches this plane structurally valid and producer-verified. `custodied`
    /// marks the local producer's own block, which is valid without an application check. Blocks at
    /// or below the certified anchor are settled and dropped.
    pub(crate) fn observe<H: Hasher<Digest = D>>(
        &mut self,
        id: ArtifactId<D>,
        observation: Observation,
        block: Arc<SignedTransactionBlock<V, D>>,
        custodied: bool,
    ) {
        let header = block.header();
        if header.chain() != self.chain || header.height() <= self.anchor.height() {
            return;
        }
        let block_ref = header.block_ref::<H>();
        let state = if custodied {
            ValidationState::Valid
        } else {
            ValidationState::Ready
        };
        let records = self.blocks.entry(header.height()).or_default();
        if let Some(record) = records.iter().find(|record| record.artifact == id) {
            debug_assert!(
                record.block_ref == block_ref,
                "an artifact identity binds one exact block"
            );
            return;
        }
        let index = records.partition_point(|record| record.observation < observation);
        records.insert(
            index,
            BlockRecord {
                artifact: id,
                observation,
                block,
                block_ref,
                state,
            },
        );
    }

    /// Returns the next application-validation job this chain is ready to dispatch, if any, marking
    /// its block pending. The task calls this until it returns `None`.
    ///
    /// A block is dispatched only once its exact parent is certified at the anchor or is itself
    /// pending or valid here, so descendants that arrive first never occupy the slots their missing
    /// parent needs. Lower heights dispatch first.
    pub(crate) fn ready_validation(&mut self) -> Option<ValidationJob<V, D>> {
        if self.validation_items >= self.validation_items_limit {
            return None;
        }
        let candidate = self.blocks.iter().find_map(|(height, records)| {
            records
                .iter()
                .enumerate()
                .find(|(_, record)| {
                    record.state == ValidationState::Ready
                        && self.parent_available(record.block.header())
                })
                .map(|(index, record)| (*height, index, record.artifact))
        });
        let (height, index, artifact) = candidate?;
        let block = Arc::clone(&self.blocks[&height][index].block);
        let bytes = block.encode_size();
        if self
            .validation_bytes
            .checked_add(bytes)
            .is_none_or(|total| total > self.validation_bytes_limit)
        {
            return None;
        }
        let id = ValidationId::new(self.next_validation);
        self.next_validation = self.next_validation.wrapping_add(1);
        self.validation_items += 1;
        self.validation_bytes += bytes;
        self.blocks
            .get_mut(&height)
            .and_then(|records| records.get_mut(index))
            .expect("the selected block remains retained")
            .state = ValidationState::Pending(id);
        self.validations.insert(
            id,
            ValidationRecord {
                height,
                artifact,
                bytes,
            },
        );
        Some(ValidationJob::new(id, self.generation, block))
    }

    /// Whether the exact parent of `header` is certified at the anchor or retained here.
    fn parent_available(&self, header: &TransactionBlockHeader<D>) -> bool {
        let Some(parent_height) = header.height().get().checked_sub(1).map(Height::new) else {
            return false;
        };
        if parent_height == self.anchor.height() {
            return header.parent() == self.anchor.digest();
        }
        self.blocks.get(&parent_height).is_some_and(|records| {
            records.iter().any(|record| {
                matches!(
                    record.state,
                    ValidationState::Pending(_) | ValidationState::Valid
                ) && record.block_ref.digest() == header.parent()
            })
        })
    }

    /// Applies one application-validation completion of this plane's current generation.
    pub(crate) fn complete_validation(
        &mut self,
        completion: ValidationCompletion,
    ) -> ValidationOutcome<D> {
        if completion.generation() != self.generation {
            return ValidationOutcome::Stale;
        }
        let Some(job) = self.validations.remove(&completion.id()) else {
            return ValidationOutcome::Stale;
        };
        self.validation_items -= 1;
        self.validation_bytes -= job.bytes;
        let Some(records) = self.blocks.get_mut(&job.height) else {
            return ValidationOutcome::Stale;
        };
        let Some(record) = records
            .iter_mut()
            .find(|record| record.artifact == job.artifact)
        else {
            return ValidationOutcome::Stale;
        };
        if record.state != ValidationState::Pending(completion.id()) {
            return ValidationOutcome::Stale;
        }
        match completion.validity() {
            BlockValidity::Unavailable => {
                record.state = ValidationState::Ready;
                ValidationOutcome::Deferred
            }
            BlockValidity::Valid => {
                record.state = ValidationState::Valid;
                ValidationOutcome::Retained
            }
            BlockValidity::Invalid => {
                let removed = record.artifact;
                records.retain(|record| record.artifact != job.artifact);
                if records.is_empty() {
                    self.blocks.remove(&job.height);
                }
                ValidationOutcome::Invalid(removed)
            }
        }
    }

    /// Advances the certified anchor and drops every block, validation, and choice it settles.
    ///
    /// Retained blocks always sit strictly above the anchor, so a parent lookup needs only the
    /// anchor and the retained set. In-flight validations for settled blocks are released; their
    /// stale completions are dropped as no longer live.
    pub(crate) fn advance_anchor(&mut self, anchor: BlockRef<D>) -> Vec<ValidationId> {
        if anchor.height() <= self.anchor.height() {
            return Vec::new();
        }
        self.anchor = anchor;
        let settled: Vec<ValidationId> = self
            .validations
            .iter()
            .filter(|(_, record)| record.height <= anchor.height())
            .map(|(id, _)| *id)
            .collect();
        for id in &settled {
            let record = self.validations.remove(id).expect("validation was listed");
            self.validation_items -= 1;
            self.validation_bytes -= record.bytes;
        }
        self.blocks.retain(|height, _| *height > anchor.height());
        self.chosen.retain(|height, _| *height > anchor.height());
        self.chosen_run = self.chosen_run.max(anchor.height());
        settled
    }

    /// Replaces the read-copy of central's durable DA choices above the anchor.
    ///
    /// Central sends the exact retained choices whenever it mints one, so the plane skips the voted
    /// prefix and checks its parent linkage locally. The copy only ever lags central.
    pub(crate) fn note_chosen(&mut self, choices: impl IntoIterator<Item = DaChoice<D>>) {
        self.chosen.clear();
        for choice in choices {
            if choice.header().chain() == self.chain
                && choice.header().height() > self.anchor.height()
            {
                self.chosen.insert(choice.header().height(), choice);
            }
        }
        self.chosen_run = self.anchor.height();
        self.chase_chosen_run();
    }

    /// Extends the contiguous DA-choice cursor over every height it now covers.
    fn chase_chosen_run(&mut self) {
        while let Some(next) = self.chosen_run.get().checked_add(1).map(Height::new) {
            if !self.chosen.contains_key(&next) {
                break;
            }
            self.chosen_run = next;
        }
    }

    /// Rebinds the plane to a new process generation and certified anchor, dropping volatile state.
    pub(crate) fn reconfigure(&mut self, generation: u64, anchor: BlockRef<D>) {
        self.generation = generation;
        self.anchor = anchor;
        self.blocks.clear();
        self.validations.clear();
        self.validation_items = 0;
        self.validation_bytes = 0;
        self.chosen.clear();
        self.chosen_run = anchor.height();
    }

    /// Computes the contiguous eligible DA-vote run this chain now offers.
    ///
    /// The run starts at the lowest unvoted height above the anchor whose path from the anchor is
    /// fully DA-voted and validated, and extends with consecutive valid children while they stay
    /// within `pipeline_depth` of the anchor. It reproduces the inline eligibility scan exactly, off
    /// the serial thread.
    pub(crate) fn eligible_run(&self, cap: usize) -> EligibleRun<V, D> {
        let empty = EligibleRun {
            run: Vec::new(),
            ready_through: self.anchor.height(),
        };
        if cap == 0 {
            return empty;
        }
        let scanned = self.anchor.height().max(self.chosen_run);
        for (&height, records) in self
            .blocks
            .range((Bound::Excluded(scanned), Bound::Unbounded))
        {
            if self.chosen.contains_key(&height) {
                continue;
            }
            if height.get().saturating_sub(self.anchor.height().get()) > self.pipeline_depth {
                continue;
            }
            let Some(parent) = self.voted_prefix_parent(height) else {
                continue;
            };
            let Some(record) = records.iter().find(|record| {
                record.state == ValidationState::Valid && record.block.header().parent() == parent
            }) else {
                continue;
            };
            let mut run = vec![Arc::clone(&record.block)];
            let mut parent = record.block_ref;
            while run.len() < cap {
                let Some(next) = parent.height().get().checked_add(1).map(Height::new) else {
                    break;
                };
                if next.get().saturating_sub(self.anchor.height().get()) > self.pipeline_depth {
                    break;
                }
                let Some(records) = self.blocks.get(&next) else {
                    break;
                };
                let Some(record) = records.iter().find(|record| {
                    record.state == ValidationState::Valid
                        && record.block.header().parent() == parent.digest()
                }) else {
                    break;
                };
                run.push(Arc::clone(&record.block));
                parent = record.block_ref;
            }
            let ready_through = parent.height();
            return EligibleRun { run, ready_through };
        }
        empty
    }

    /// Returns the parent digest a candidate at `height` must extend when the voted prefix from the
    /// anchor is contiguous and validated, or `None` when it is not.
    fn voted_prefix_parent(&self, height: Height) -> Option<D> {
        let mut parent = self.anchor;
        let mut next = self.anchor.height().get().checked_add(1)?;
        while next < height.get() {
            let choice = self.chosen.get(&Height::new(next))?;
            if choice.header().parent() != parent.digest() || !self.has_valid_block(choice.header())
            {
                return None;
            }
            parent = choice.block_ref();
            next = next.checked_add(1)?;
        }
        Some(parent.digest())
    }

    /// Whether the exact voted header is backed by a locally valid block. Retained in eligibility
    /// (unlike the vote path) because this plane owns the block store the scan reads.
    fn has_valid_block(&self, header: &TransactionBlockHeader<D>) -> bool {
        self.blocks.get(&header.height()).is_some_and(|records| {
            records.iter().any(|record| {
                record.block.header() == header && record.state == ValidationState::Valid
            })
        })
    }

    /// Forces the DA-choice cursor down to the anchor, so a test can compare the indexed eligible
    /// run against the full scan the cursor optimizes.
    #[cfg(test)]
    pub(crate) const fn reset_chosen_run_for_test(&mut self) {
        self.chosen_run = self.anchor.height();
    }

    /// Invariant checks for the focused test harness: retained blocks stay above the anchor, the
    /// validation accounting matches the in-flight set, and the DA-choice read-copy stays above the
    /// anchor with a contiguous run cursor.
    #[cfg(test)]
    pub(crate) fn assert_invariants(&self) {
        assert!(
            self.blocks
                .keys()
                .all(|height| *height > self.anchor.height()),
            "retained blocks stay above the certified anchor"
        );
        assert!(
            self.chosen
                .keys()
                .all(|height| *height > self.anchor.height()),
            "the DA-choice read-copy stays above the certified anchor"
        );
        assert!(
            self.chosen_run >= self.anchor.height(),
            "the DA-choice cursor never dips below the anchor"
        );
        assert!(
            self.chosen_run
                .get()
                .saturating_sub(self.anchor.height().get())
                <= self.pipeline_depth
                || self.chosen.is_empty(),
            "the voted run stays within the pipeline window of the anchor"
        );
        let items = self.validations.len();
        let bytes: usize = self.validations.values().map(|record| record.bytes).sum();
        assert_eq!(
            items, self.validation_items,
            "validation item count matches"
        );
        assert_eq!(
            bytes, self.validation_bytes,
            "validation byte total matches"
        );
        assert!(
            self.validation_items <= self.validation_items_limit,
            "in-flight validations stay within the per-chain slot bound"
        );
        let pending = self
            .blocks
            .values()
            .flat_map(|records| records.iter())
            .filter(|record| matches!(record.state, ValidationState::Pending(_)))
            .count();
        assert_eq!(
            pending, self.validation_items,
            "every pending block has exactly one in-flight validation"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactId, BlockValidity, DaChoice, Observation, PerChainValidator, ValidationCompletion,
        ValidationJob, ValidationOutcome,
    };
    use crate::{
        multimmit::types::{BlockRef, ChainId, SignedTransactionBlock, TransactionBlockHeader},
        types::{Epoch, Height, Participant},
    };
    use commonware_codec::types::lazy::Lazy;
    use commonware_cryptography::{
        Hasher, Sha256,
        bls12381::primitives::variant::{MinPk, Variant},
        sha256::Digest,
    };
    use commonware_math::algebra::Additive as _;
    use commonware_utils::test_rng;
    use rand::TryRng as _;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    const EPOCH: Epoch = Epoch::new(7);
    const PIPELINE: u64 = 8;
    const ITEMS: usize = 64;
    const BYTES: usize = 1 << 20;

    /// A hasher that counts every digest it computes, to prove eligibility scans never re-hash.
    static HASH_CALLS: AtomicUsize = AtomicUsize::new(0);

    #[derive(Default)]
    struct CountingHasher(Sha256);

    impl Hasher for CountingHasher {
        type Digest = Digest;

        fn hash(parts: &[&[u8]]) -> Self::Digest {
            HASH_CALLS.fetch_add(1, Ordering::Relaxed);
            Sha256::hash(parts)
        }

        fn hash_pair(left: &[&[u8]], right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
            HASH_CALLS.fetch_add(2, Ordering::Relaxed);
            Sha256::hash_pair(left, right)
        }

        fn update(&mut self, bytes: &[u8]) -> &mut Self {
            self.0.update(bytes);
            self
        }

        fn finalize(self) -> (Self, Self::Digest) {
            let (hasher, digest) = self.0.finalize();
            (Self(hasher), digest)
        }
    }

    fn hash(bytes: &[u8]) -> Digest {
        Sha256::hash(&[bytes])
    }

    fn attestation() -> crate::multimmit::types::Attestation<MinPk> {
        crate::multimmit::types::Attestation::new(
            Participant::new(0),
            Lazy::from(<MinPk as Variant>::Signature::zero()),
        )
    }

    fn header(
        chain: u32,
        height: u64,
        parent: Digest,
        body: &[u8],
    ) -> TransactionBlockHeader<Digest> {
        TransactionBlockHeader::new(
            EPOCH,
            ChainId::new(chain),
            Height::new(height),
            parent,
            hash(body),
        )
        .unwrap()
    }

    fn block(
        header: &TransactionBlockHeader<Digest>,
    ) -> Arc<SignedTransactionBlock<MinPk, Digest>> {
        Arc::new(SignedTransactionBlock::new(header.clone(), attestation()))
    }

    fn id(header: &TransactionBlockHeader<Digest>) -> ArtifactId<Digest> {
        ArtifactId::new(header.digest::<Sha256>())
    }

    fn anchor(chain: u32) -> BlockRef<Digest> {
        BlockRef::new(ChainId::new(chain), Height::new(0), hash(b"chain genesis"))
    }

    fn validator(anchor: BlockRef<Digest>) -> PerChainValidator<MinPk, Digest> {
        PerChainValidator::new(anchor.chain(), PIPELINE, ITEMS, BYTES, anchor, 0)
    }

    fn observe(
        v: &mut PerChainValidator<MinPk, Digest>,
        order: u32,
        header: &TransactionBlockHeader<Digest>,
        custodied: bool,
    ) {
        v.observe::<Sha256>(
            id(header),
            Observation::new(1, order),
            block(header),
            custodied,
        );
    }

    fn complete(
        v: &mut PerChainValidator<MinPk, Digest>,
        job: &ValidationJob<MinPk, Digest>,
        validity: BlockValidity,
    ) -> ValidationOutcome<Digest> {
        v.complete_validation(ValidationCompletion::new(
            job.id(),
            job.generation(),
            validity,
        ))
    }

    fn choice(header: &TransactionBlockHeader<Digest>) -> DaChoice<Digest> {
        DaChoice::for_test(header.clone(), header.block_ref::<Sha256>())
    }

    /// Builds `count` consecutive headers on `chain`, rooted at `anchor`.
    fn run(
        anchor: BlockRef<Digest>,
        count: u64,
        label: &str,
    ) -> Vec<TransactionBlockHeader<Digest>> {
        let mut parent = anchor.digest();
        (1..=count)
            .map(|height| {
                let header = header(
                    anchor.chain().get(),
                    anchor.height().get() + height,
                    parent,
                    format!("{label} {height}").as_bytes(),
                );
                parent = header.block_ref::<Sha256>().digest();
                header
            })
            .collect()
    }

    fn validate_all(v: &mut PerChainValidator<MinPk, Digest>) {
        while let Some(job) = v.ready_validation() {
            complete(v, &job, BlockValidity::Valid);
        }
    }

    fn heights(headers: &[Arc<SignedTransactionBlock<MinPk, Digest>>]) -> Vec<Height> {
        headers
            .iter()
            .map(|block| block.header().height())
            .collect()
    }

    // Relocated from `invalid_block_can_be_revalidated`.
    #[test]
    fn an_invalid_block_is_discarded_and_can_be_revalidated() {
        let a = anchor(1);
        let mut v = validator(a);
        let block = header(1, 1, a.digest(), b"invalid body");
        observe(&mut v, 1, &block, false);
        let job = v
            .ready_validation()
            .expect("the anchored block enters validation");
        assert_eq!(job.block_arc().header(), &block);
        assert_eq!(
            complete(&mut v, &job, BlockValidity::Invalid),
            ValidationOutcome::Invalid(id(&block))
        );
        assert!(
            v.ready_validation().is_none(),
            "an invalid block is discarded"
        );
        assert!(v.eligible_run(4).run.is_empty());

        observe(&mut v, 2, &block, false);
        let job = v.ready_validation().expect("a revalidation is scheduled");
        assert_eq!(
            complete(&mut v, &job, BlockValidity::Valid),
            ValidationOutcome::Retained
        );
        assert_eq!(heights(&v.eligible_run(4).run), vec![Height::new(1)]);
        v.assert_invariants();
    }

    // Relocated from `a_validation_without_a_verdict_is_scheduled_again`.
    #[test]
    fn an_unavailable_verdict_reschedules_the_block() {
        let a = anchor(1);
        let mut v = validator(a);
        let block = header(1, 1, a.digest(), b"unavailable body");
        observe(&mut v, 1, &block, false);
        let first = v.ready_validation().expect("the block enters validation");
        assert_eq!(
            complete(&mut v, &first, BlockValidity::Unavailable),
            ValidationOutcome::Deferred
        );
        let retried = v.ready_validation().expect("the block is scheduled again");
        assert_ne!(retried.id(), first.id());
        assert_eq!(retried.block_arc().header(), first.block_arc().header());
        v.assert_invariants();
    }

    // Relocated from `da_fork_selection_does_not_depend_on_validation_completion_order`.
    #[test]
    fn fork_selection_ignores_validation_completion_order() {
        let a = anchor(1);
        let mut v = validator(a);
        let first = header(1, 1, a.digest(), b"first fork");
        let second = header(1, 1, a.digest(), b"second fork");
        observe(&mut v, 1, &first, false);
        observe(&mut v, 2, &second, false);
        let job_a = v.ready_validation().expect("a fork enters validation");
        let job_b = v.ready_validation().expect("its sibling enters validation");
        let (valid, invalid) = if job_a.block_arc().header() == &second {
            (job_a, job_b)
        } else {
            (job_b, job_a)
        };
        // Complete the surviving fork valid after the losing fork is rejected; the offer is the same
        // regardless of the order the verdicts arrive.
        assert_eq!(
            complete(&mut v, &valid, BlockValidity::Valid),
            ValidationOutcome::Retained
        );
        complete(&mut v, &invalid, BlockValidity::Invalid);
        assert_eq!(
            v.eligible_run(4)
                .run
                .iter()
                .map(|block| block.header().clone())
                .collect::<Vec<_>>(),
            vec![second]
        );
        v.assert_invariants();
    }

    // Relocated from `da_readiness_reuses_retained_block_references`.
    #[test]
    fn eligible_run_reuses_retained_blocks_without_rehashing() {
        let a = anchor(1);
        let mut v = validator(a);
        let headers = run(a, 3, "cached readiness");
        for (index, header) in headers.iter().enumerate() {
            v.observe::<CountingHasher>(
                id(header),
                Observation::new(1, index as u32 + 1),
                block(header),
                false,
            );
        }
        validate_all(&mut v);

        HASH_CALLS.store(0, Ordering::Relaxed);
        for _ in 0..2 {
            assert_eq!(
                heights(&v.eligible_run(4).run),
                vec![Height::new(1), Height::new(2), Height::new(3)]
            );
        }
        assert_eq!(
            HASH_CALLS.load(Ordering::Relaxed),
            0,
            "an unchanged eligibility scan must reuse retained block identities"
        );
    }

    // Relocated from `da_vote_runs_are_capped_and_single_flight_per_chain` (the run-cap; the
    // one-unacknowledged-reservation single-flight is central and covered by the engine and by
    // `da_votes_eligible_behind_one_barrier_reserve_as_one_batch`).
    #[test]
    fn eligible_run_honors_its_cap() {
        let a = anchor(1);
        let mut v = validator(a);
        let headers = run(a, 3, "run cap");
        for (index, header) in headers.iter().enumerate() {
            observe(&mut v, index as u32 + 1, header, false);
        }
        validate_all(&mut v);
        let run = v.eligible_run(2);
        assert_eq!(heights(&run.run), vec![Height::new(1), Height::new(2)]);
        assert_eq!(run.ready_through, Height::new(2));
        assert_eq!(
            heights(&v.eligible_run(3).run),
            vec![Height::new(1), Height::new(2), Height::new(3)]
        );
    }

    // Relocated from `saturated_validation_chain_does_not_block_another_producer` (the per-chain
    // slot bound; cross-producer independence is now structural, as each chain runs its own plane).
    #[test]
    fn in_flight_validations_are_bounded_and_resume_on_release() {
        let a = anchor(1);
        let mut v = PerChainValidator::<MinPk, Digest>::new(a.chain(), PIPELINE, 1, BYTES, a, 0);
        let headers = run(a, 2, "saturated");
        observe(&mut v, 1, &headers[0], false);
        observe(&mut v, 2, &headers[1], false);
        let first = v
            .ready_validation()
            .expect("the first block acquires the only slot");
        assert_eq!(first.block_arc().header().height(), Height::new(1));
        assert!(
            v.ready_validation().is_none(),
            "the per-chain slot bound holds without a fatal transition"
        );
        complete(&mut v, &first, BlockValidity::Valid);
        let second = v
            .ready_validation()
            .expect("releasing the slot resumes the next block");
        assert_eq!(second.block_arc().header().height(), Height::new(2));
        v.assert_invariants();
    }

    // Relocated from the `held_chain_is_da_voted_in_height_order` property test.
    #[test]
    fn a_held_run_is_offered_in_height_order() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let a = anchor(1);
            let mut v = validator(a);
            let count = (rng.try_next_u32().unwrap() % 4 + 1) as u64;
            let headers = run(a, count, "height order");
            let mut order = (0..headers.len()).collect::<Vec<_>>();
            for index in (1..order.len()).rev() {
                let swap = (rng.try_next_u32().unwrap() as usize) % (index + 1);
                order.swap(index, swap);
            }
            for &index in &order {
                observe(&mut v, index as u32 + 1, &headers[index], false);
            }
            validate_all(&mut v);
            assert_eq!(
                heights(&v.eligible_run(count as usize).run),
                (1..=count).map(Height::new).collect::<Vec<_>>()
            );
            v.assert_invariants();
        }
    }

    // Relocated from `da_voted_run_cursor_matches_a_full_frontier_scan` (the plane's DA-choice
    // prefix cursor; central's own `da_voted_run` cursor is exercised by the durable proptest).
    #[test]
    fn the_choice_cursor_never_hides_an_eligible_block() {
        let mut rng = test_rng();
        let a = anchor(1);
        let mut v = validator(a);
        let headers = run(a, 24, "cursor probe");
        let mut observed = 0usize;
        let mut chosen = 0u64;
        let mut anchor_height = 0u64;
        let mut nonempty = false;

        for _ in 0..400 {
            match rng.try_next_u32().unwrap() % 4 {
                // Observe the next block, then validate whatever became ready.
                0 => {
                    if observed < headers.len() && (observed as u64) < anchor_height + PIPELINE {
                        observe(&mut v, observed as u32 + 1, &headers[observed], false);
                        observed += 1;
                        validate_all(&mut v);
                    }
                }
                // Grow the voted prefix by one contiguous choice above the anchor.
                1 => {
                    let next = chosen.max(anchor_height) + 1;
                    if next as usize <= observed && next as usize <= headers.len() {
                        let prefix = (anchor_height + 1..=next)
                            .map(|height| choice(&headers[height as usize - 1]))
                            .collect::<Vec<_>>();
                        v.note_chosen(prefix);
                        chosen = next;
                    }
                }
                // Advance the certified anchor over a validated, chosen height.
                2 => {
                    if chosen > anchor_height {
                        let target = chosen.min(observed as u64);
                        if target > anchor_height {
                            v.advance_anchor(headers[target as usize - 1].block_ref::<Sha256>());
                            anchor_height = target;
                        }
                    }
                }
                // Re-seed the choice read-copy from the retained prefix, re-chasing the cursor.
                _ => {
                    let prefix = (anchor_height + 1..=chosen)
                        .map(|height| choice(&headers[height as usize - 1]))
                        .collect::<Vec<_>>();
                    v.note_chosen(prefix);
                }
            }

            let indexed = heights(&v.eligible_run(PIPELINE as usize).run);
            v.reset_chosen_run_for_test();
            let scanned = heights(&v.eligible_run(PIPELINE as usize).run);
            assert_eq!(
                indexed, scanned,
                "the choice cursor changed the eligible frontier"
            );
            nonempty |= !indexed.is_empty();
            v.assert_invariants();
        }
        assert!(
            nonempty,
            "the workload must exercise a non-empty eligible run"
        );
    }

    // New engine-adjacent coverage: the offered run's `ready_through` is the frontier shadow's safe
    // lower bound, tracking exactly the contiguous validated, unvoted prefix.
    #[test]
    fn ready_through_tracks_the_validated_prefix() {
        let a = anchor(1);
        let mut v = validator(a);
        let headers = run(a, 3, "ready through");
        for (index, header) in headers.iter().enumerate() {
            observe(&mut v, index as u32 + 1, header, false);
        }
        // Validate only the first two heights; the third stays pending.
        let first = v.ready_validation().expect("first enters validation");
        complete(&mut v, &first, BlockValidity::Valid);
        let second = v.ready_validation().expect("second enters validation");
        complete(&mut v, &second, BlockValidity::Valid);
        let run = v.eligible_run(8);
        assert_eq!(heights(&run.run), vec![Height::new(1), Height::new(2)]);
        assert_eq!(run.ready_through, Height::new(2));

        let third = v.ready_validation().expect("third enters validation");
        complete(&mut v, &third, BlockValidity::Valid);
        assert_eq!(v.eligible_run(8).ready_through, Height::new(3));
        v.assert_invariants();
    }

    // New coverage: the anchor advance settles blocks and choices below it and releases their
    // in-flight validations, holding every plane invariant.
    #[test]
    fn advancing_the_anchor_settles_and_holds_invariants() {
        let a = anchor(1);
        let mut v = validator(a);
        let headers = run(a, 4, "anchor advance");
        for (index, header) in headers.iter().enumerate() {
            observe(&mut v, index as u32 + 1, header, false);
        }
        validate_all(&mut v);
        v.note_chosen(vec![choice(&headers[0]), choice(&headers[1])]);
        v.assert_invariants();

        let settled = v.advance_anchor(headers[1].block_ref::<Sha256>());
        assert!(
            settled.is_empty(),
            "no validation was in flight over the settled prefix"
        );
        v.assert_invariants();
        // Only the heights above the new anchor remain eligible.
        assert_eq!(
            heights(&v.eligible_run(8).run),
            vec![Height::new(3), Height::new(4)]
        );
    }
}
