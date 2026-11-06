//! Best-effort activity reported to the attached [`crate::Reporter`].

use crate::{
    multimmit::{
        scheme::Scheme,
        types::{
            Artifact, ArtifactId, BlockRef, CertificateId, DaCertificate, FinalityFact, FinalityId, Lqc,
            TipRecord,
        },
    },
    types::{Height, View},
};
use commonware_cryptography::Digest;
use std::sync::Arc;

/// A run of one producer chain's blocks whose positions in the canonical order became fixed: the
/// ancestors of [`Self::tip`] (the tip included) at heights above [`Self::above`] and at most
/// [`Self::height`].
///
/// The run says nothing about the blocks at or below [`Self::above`]. Those were placed before,
/// possibly on another branch: an anchor may jump to a rival branch, and the order then reads
/// the new blocks off the new tip's own path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement<D: Digest> {
    tip: BlockRef<D>,
    above: Height,
    height: Height,
}

impl<D: Digest> Placement<D> {
    /// Creates the run of `tip`'s ancestors at heights in `(above, height]`.
    ///
    /// Requires `above < height <= tip.height()`. The constructor does not check this.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const fn new(tip: BlockRef<D>, above: Height, height: Height) -> Self {
        Self { tip, above, height }
    }

    /// Returns the block whose ancestors form the run.
    pub const fn tip(&self) -> BlockRef<D> {
        self.tip
    }

    /// Returns the height of the chain's last block placed before the run.
    pub const fn above(&self) -> Height {
        self.above
    }

    /// Returns the height of the run's highest block.
    pub const fn height(&self) -> Height {
        self.height
    }
}

/// A verified L-QC, shared with the engine rather than copied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LqcProof<S: Scheme, D: Digest> {
    id: CertificateId<D>,
    artifact: Arc<Artifact<S, D>>,
}

impl<S: Scheme, D: Digest> LqcProof<S, D> {
    /// Wraps `artifact`, identified by `id`, or returns `None` when it is not an L-QC.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn new(id: CertificateId<D>, artifact: Arc<Artifact<S, D>>) -> Option<Self> {
        matches!(artifact.as_ref(), Artifact::Lqc(_)).then_some(Self { id, artifact })
    }

    /// Returns the certificate's identifier.
    pub const fn id(&self) -> CertificateId<D> {
        self.id
    }

    /// Returns the certificate.
    pub fn lqc(&self) -> &Lqc<S, D> {
        let Artifact::Lqc(certificate) = self.artifact.as_ref() else {
            unreachable!("constructed from an L-QC");
        };
        certificate
    }

    /// Returns the shared artifact holding the certificate.
    pub const fn artifact(&self) -> &Arc<Artifact<S, D>> {
        &self.artifact
    }
}

/// A local proposal, contextually admitted artifact, consensus finality observation, or durable
/// record.
///
/// Activities are idempotent, best-effort observations. They do not acknowledge delivery or
/// authorize protocol progress. Only [`Activity::CertificateRecorded`] bounds what an application
/// retains for the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Activity<S: Scheme, D: Digest> {
    /// A local transaction block has been signed, before its publication is persisted.
    ///
    /// This is not evidence of dissemination or finality. Retries may report the same block.
    TransactionProposed {
        /// Identity of the signed producer block.
        block: BlockRef<D>,
    },
    /// A leader obtained its first direct finality quorum.
    LeaderFinalized {
        /// Producer-chain tips supported by the first direct finality quorum.
        fact: FinalityFact<D>,
    },
    /// An already-finalized leader's direct finality projection advanced.
    LeaderFinalityUpdated {
        /// Producer-chain tips supported by the updated direct finality pool.
        fact: FinalityFact<D>,
    },
    /// Local finality of a leader fixed the canonical order of producer blocks to new heights.
    ///
    /// Finality of a leader fixes a prefix of the total order: the order its tip-history record
    /// carries, extended by the final sweep toward its finalized tips. Placement only advances.
    /// It precedes the ordered output of marshal, which still delivers only from portable proofs,
    /// so it never authorizes delivery.
    ///
    /// The engine names the blocks of a history opening only when it holds every opening since
    /// the one it last placed; otherwise it advances past them silently. In particular, a
    /// restarted engine names no blocks below the history of the first leader it sees finalized.
    Placed {
        /// View of the finalized leader.
        view: View,
        /// Evidence that finalized the leader.
        evidence: FinalityId<D>,
        /// Commitment of the leader's tip-history record that the placed order extends.
        history: D,
        /// The newly placed runs: one per chain each history opening advances, oldest opening
        /// first, then one per chain the final sweep advances, each group in chain order.
        placed: Vec<Placement<D>>,
    },
    /// The engine verified an L-QC: portable proof that its leader is final.
    ///
    /// Reported once for every L-QC the engine verifies, aggregated locally or received, in
    /// the drain that verifies it. A restarted engine may report a certificate again.
    Proven {
        /// The certificate.
        proof: LqcProof<S, D>,
        /// The leader finality the certificate proves on its own.
        fact: FinalityFact<D>,
        /// Records of the finalized history chain, oldest first, through the record the proof's
        /// leader commits to (`LeaderBlock::history`), that no earlier `Proven` reported.
        ///
        /// The engine reports a record once it has placed the order the record opens. Empty
        /// when the engine does not hold the leader's record or reported it already. Records
        /// need not connect to those reported before: an engine that restarted, or that dropped
        /// records while no proof arrived for a long time, reports only the suffix it holds.
        ///
        /// [`LeaderBlock::history`]: crate::multimmit::types::LeaderBlock::history
        records: Arc<[Arc<TipRecord<D>>]>,
    },
    /// An authenticated artifact entered the machine's contextually ready set.
    ProtocolAccepted {
        /// Stable identifier for the canonical artifact.
        artifact_id: ArtifactId<D>,
        /// Admitted artifact.
        artifact: Arc<Artifact<S, D>>,
    },
    /// An authenticated leader exposed its safe-tip history opening for peer seeding.
    ///
    /// The engine reports the opening of every leader block it admits or finalizes, including a
    /// leader known only from its votes or certificates, as soon as the opening is
    /// reconstructible from the leader's retained parent. Each leader is reported once per engine
    /// lifetime; a restarted engine may report it once more. A leader whose parent the engine
    /// does not retain before the leader falls out of the retained view window is not reported.
    HistoryAccepted {
        /// View of the leader that committed the opening.
        view: View,
        /// Unsigned digest of the leader block that committed the opening.
        leader: D,
        /// Commitment carried by the leader.
        commitment: D,
        /// Opening reconstructed from the retained parent state.
        record: Arc<TipRecord<D>>,
    },
    /// The engine durably recorded `certified` as the newest certified block of its chain: a DA
    /// certificate for it, or the chain's genesis tip when the engine starts without one.
    ///
    /// The engine never again depends on the application's verdict for a block of that chain at
    /// or below `released`, including after a restart; a verification it already dispatched may
    /// still arrive, and its verdict is ignored. `released` trails `certified` by the pipeline
    /// depth, because the engine keeps its DA votes for blocks just below a certificate. The
    /// engine reports this once each record is durable, and for every chain's newest record when
    /// it starts, so an application can prune what the engine no longer needs.
    CertificateRecorded {
        /// The newest block of its chain whose DA certificate is durably recorded.
        certified: BlockRef<D>,
        /// The highest height of the chain that the engine no longer verifies.
        released: Height,
    },
    /// This producer assembled a receipt for a block of its payment chain: a DA certificate
    /// counting at least `n - f` signers (see
    /// [`Parameters::payment_chain`](crate::multimmit::config::Parameters::payment_chain)).
    ///
    /// A receipt verifies with [`Generic::verify_receipt`](crate::multimmit::scheme::Generic::verify_receipt),
    /// and as an ordinary DA certificate too. The engine neither persists nor publishes it:
    /// it is reported at most once per block, after the block's `n - 2f` certificate, and a
    /// restart or a vote lost after its signer recorded the certificate can leave a block without
    /// one.
    Receipt {
        /// The receipt.
        receipt: DaCertificate<S, D>,
    },
}
