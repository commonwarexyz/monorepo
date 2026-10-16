//! Best-effort activity reported to the attached [`crate::Reporter`].

use crate::{
    multimmit::types::{
        BlockRef, CertificateId, ChainSet, HistoryRecord, Lqc, TransactionBlockHeader,
    },
    types::View,
};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use std::{sync::Arc, time::Duration};

/// How consensus fixed the tips of a resolved view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution<D: Digest> {
    /// `n - f` final votes of the view determine every chain's tip.
    Determined,
    /// A later leader block with `n - f` votes pins the V-QC chain through this view.
    Pinned {
        /// The view of the finalized leader block.
        view: View,
        /// The identifier of the L-QC finalizing it.
        lqc: CertificateId<D>,
    },
}

/// An agreement fact, local proposal, or admitted header reported by consensus.
///
/// Activities are idempotent, best-effort observations: losing one never stalls consensus, and a
/// restart re-reports the retained window. Consensus reports agreement only; ordering blocks,
/// holding bodies, and delivery belong to the consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activity<V: Variant, D: Digest> {
    /// A local transaction block has been signed, before its publication is persisted.
    ///
    /// This is not evidence of dissemination or finality. Retries may report the same block.
    TransactionProposed {
        /// Identity of the signed producer block.
        block: BlockRef<D>,
        /// This node's current view when the header was signed.
        view: View,
    },
    /// A producer header was accepted, by verifying its body or by adoption from `alpha`
    /// endorsers. An adopted header's body may still be missing locally.
    HeaderAccepted {
        /// The accepted header. An adopted header may have no producer-signed copy locally,
        /// only the endorsements that adopted it.
        header: TransactionBlockHeader<D>,
        /// For a header adopted without a local body verdict, the time its body may still take
        /// to arrive by relay: consensus's one-way delay estimate `delta_hat`. `None` for a
        /// header accepted in full.
        adopted: Option<Duration>,
    },
    /// Every V-QC of `view` that can be an ancestor of anything has base `base` and tips `tips`.
    ///
    /// Reported once per view, in increasing view order, with `base` equal to the previous
    /// report's `tips` and `commitment = H(TIP_HISTORY, parent_commitment, tips)`.
    ViewResolved {
        /// The resolved view.
        view: View,
        /// The tips of the previous view, one per chain.
        base: Arc<[BlockRef<D>]>,
        /// The view's tips, one per chain, each extending its base.
        tips: Arc<[BlockRef<D>]>,
        /// The tips-history commitment of the view.
        commitment: D,
        /// The tips-history commitment of the previous view.
        parent_commitment: D,
        /// How the tips were fixed.
        by: Resolution<D>,
    },
    /// Progress of the oldest unresolved view whose base is known.
    ///
    /// On each chain every block up to `finals` will be in every correct log, and a settled chain
    /// gains nothing more in this view. Successive reports for one view never retreat.
    ViewSweep {
        /// The view whose base is the latest resolved view's tips.
        view: View,
        /// Per chain, the highest block `n - f` validators endorse in the view.
        finals: Arc<[BlockRef<D>]>,
        /// Chains that can gain no further block in the view.
        settled: ChainSet,
    },
    /// A leader block reached `n - f` votes: a verifiable finalization certificate.
    LeaderFinalized {
        /// The L-QC.
        lqc: Arc<Lqc<V, D>>,
        /// The record opening the leader block's history commitment.
        opening: Arc<HistoryRecord<D>>,
    },
}
