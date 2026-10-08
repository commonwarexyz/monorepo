//! Scenario addressing and the verified-handoff description.
//!
//! [`Node`] names the four validators. [`ScenarioHandoff`] is the explicit,
//! source-derived description of the state a prefix leaves for the fuzzing
//! phase: the floor the engines start from, the artifacts every honest engine
//! recovers from its seeded voter journal, the anchor the adversary attacks,
//! the reference chain (when the source has one), the resolver fetches each
//! node must have issued, the blocks each node must hold or lack, and the
//! invariant-selection hint. The scenario
//! harness ([`super::harness`]) mechanically asserts this description at
//! handoff rather than deriving the floor or attack metadata implicitly from a
//! canonical tip.

use crate::marshal::end_to_end::twins::{B, SchemeOf};
use bytes::Bytes;
use commonware_consensus::{
    marshal::resolver::handler::{Annotation, Finalized, Key},
    simplex::{Floor, types::Notarization},
    types::{Height, Round, View},
};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_cryptography::sha256::Digest as Sha256Digest;

/// The standard marshal mailbox for the mock block.
pub type Mb<P> = commonware_consensus::marshal::core::Mailbox<
    SchemeOf<P>,
    commonware_consensus::marshal::standard::Standard<B<P>>,
>;

/// A validator of the four-node cluster, addressed by its participant index.
///
/// In the adversarial mode [`Node::A`] (index 0) is the byzantine node and has
/// no marshal, so scenarios only script the honest core {B, C, D}; that keeps a
/// scenario identical in both fuzzing modes.
#[allow(dead_code)] // `A` names node 0, addressed by the adversary rather than scenarios.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Node {
    A,
    B,
    C,
    D,
}

impl Node {
    pub const fn idx(self) -> usize {
        self as usize
    }
}

/// Certificate signer set for a fabricated quorum. The source signs every
/// fabricated certificate with `schemes[0..QUORUM]`, and scenarios translate
/// source participants through one uniform permutation (source 0 -> B,
/// 1 -> C, 2 -> D, 3 -> A), so the signer set is {B, C, D}: the source
/// certificate up to the S6 node relabeling (under the mock scheme the signer
/// indices are part of the certificate identity). Every signer is an
/// always-honest, marshal-holding node in both modes; the adversary's own
/// attack messages are signed separately by the disrupters.
pub const QUORUM_SIGNERS: [Node; 3] = [Node::B, Node::C, Node::D];

/// The kind of a fabricated certificate, recorded in the ledger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateKind {
    Notarization,
    Finalization,
}

/// A ledger entry for one fabricated certificate, retained so the harness can
/// mechanically assert composition soundness (I1) at handoff.
///
/// `payload` completes the recorded certificate identity; it is surfaced through
/// the ledger for inspection rather than read by the I1 check itself. `encoded`
/// is the certificate's full wire encoding, compared exactly against the
/// recovered-journal entries for certificates above the engine floor.
#[derive(Clone, Debug)]
pub struct PrefixCertificate {
    pub kind: CertificateKind,
    pub round: Round,
    pub parent_view: View,
    #[allow(dead_code)]
    pub payload: Sha256Digest,
    pub signers: Vec<Node>,
    pub scenario: &'static str,
    pub encoded: Bytes,
}

/// The height, view, and digest the fuzz adversary attacks: the first live view
/// above the engine floor.
#[derive(Clone, Copy, Debug)]
pub struct AttackAnchor {
    pub height: Height,
    pub view: View,
    pub digest: Sha256Digest,
}

/// A backfill request the source produces, expressed precisely enough to
/// distinguish states that share a wire key (a `ByRound` fetch and a `ByHeight`
/// fetch are different source states even though both serialize as
/// [`Key::Block`]).
// `FinalizedByRound` and `FinalizedByHeight` distinguish finalized-block
// backfills that share the `Key::Block` wire key; they are part of the matcher
// surface and exercised by unit tests, reserved for finalized-fetch scenarios.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum FetchMatch {
    /// A block requested by commitment, any annotation.
    Block(Sha256Digest),
    /// A block requested for the finalized chain by finalization round.
    FinalizedByRound {
        commitment: Sha256Digest,
        round: Round,
    },
    /// A block requested for the finalized chain by known height.
    FinalizedByHeight {
        commitment: Sha256Digest,
        height: Height,
    },
    /// A block requested for a certified chain by known height.
    CertifiedHeight {
        commitment: Sha256Digest,
        height: Height,
    },
    /// A notarized proposal requested by round.
    NotarizedRound(Round),
    /// A finalization requested by height (`Key::Finalized`).
    FinalizationByHeight(Height),
}

impl FetchMatch {
    /// Whether an observed `(key, annotation)` matches this expectation.
    pub fn matches(&self, key: &Key<Sha256Digest>, annotation: &Annotation) -> bool {
        match *self {
            Self::Block(commitment) => {
                matches!(key, Key::Block(observed) if *observed == commitment)
            }
            Self::FinalizedByRound { commitment, round } => matches!(
                (key, annotation),
                (Key::Block(observed), Annotation::Finalized(Finalized::ByRound { round: annotation_round }))
                    if *observed == commitment && *annotation_round == round
            ),
            Self::FinalizedByHeight { commitment, height } => matches!(
                (key, annotation),
                (Key::Block(observed), Annotation::Finalized(Finalized::ByHeight { height: annotation_height }))
                    if *observed == commitment && *annotation_height == height
            ),
            Self::CertifiedHeight { commitment, height } => matches!(
                (key, annotation),
                (Key::Block(observed), Annotation::Certified { height: annotation_height })
                    if *observed == commitment && *annotation_height == height
            ),
            Self::NotarizedRound(round) => matches!(
                (key, annotation),
                (Key::Notarized { round: key_round }, Annotation::Notarization { round: annotation_round })
                    if *key_round == round && *annotation_round == round
            ),
            Self::FinalizationByHeight(height) => matches!(
                (key, annotation),
                (
                    Key::Finalized { height: key_height },
                    Annotation::Finalized(Finalized::ByHeight { height: annotation_height }),
                ) if *key_height == height && *annotation_height == height
            ),
        }
    }
}

/// Invariant-selection hint for the fuzzing phase, expressed in the terms of
/// the ground-truth checks in
/// `consensus/fuzz/marshal/src/marshal/end_to_end/invariants.rs`.
pub struct Expectation {
    /// The floor height every honest node started from, anchoring the
    /// ground-truth first-delivery check; `None` for genesis-started clusters
    /// (floor 0). The hint selects only among the parameters the ground-truth
    /// checks already accept; it can never weaken them.
    pub all_floor_rooted: Option<Height>,
}

impl Expectation {
    /// Genesis-rooted: every honest node delivers contiguously from genesis.
    pub const fn genesis_rooted() -> Self {
        Self {
            all_floor_rooted: None,
        }
    }
}

/// Blocks one node must hold or lack at handoff, looked up by digest through
/// the node's marshal (buffer plus local storage).
#[derive(Clone, Debug)]
pub struct NodeExpectation {
    pub node: Node,
    pub present: Vec<Sha256Digest>,
    pub absent: Vec<Sha256Digest>,
}

impl NodeExpectation {
    pub fn new(node: Node) -> Self {
        Self {
            node,
            present: Vec::new(),
            absent: Vec::new(),
        }
    }

    /// Require the node to hold the block with `digest` at handoff.
    pub fn holds(mut self, digest: Sha256Digest) -> Self {
        self.present.push(digest);
        self
    }

    /// Require the node to lack the block with `digest` at handoff.
    pub fn lacks(mut self, digest: Sha256Digest) -> Self {
        self.absent.push(digest);
        self
    }
}

/// The verified state a prefix hands the fuzzing phase.
pub struct ScenarioHandoff<P: Simplex> {
    /// The floor the engines start from: Genesis or a source-existing Finalized.
    pub engine_floor: Floor<SchemeOf<P>, Sha256Digest>,
    /// Certificates every honest engine recovers from its seeded voter journal
    /// at startup, replayed before the live loop. The runner writes each as an
    /// `Artifact::Notarization` into the engine's journal partition before
    /// `Engine::new`, and the composition proof (I1) requires every
    /// above-floor prefix certificate to match one of these entries exactly.
    pub engine_journal: Vec<Notarization<SchemeOf<P>, Sha256Digest>>,
    /// Height, view, and digest the adversary attacks: the first live view
    /// above the floor and the recovered journal state.
    pub attack_anchor: AttackAnchor,
    /// The reference chain the honest nodes deliver, when the source has one.
    pub reference_chain: Vec<B<P>>,
    /// The complete fetch history each listed node must have issued by handoff,
    /// as an exact multiset (an empty list requires the node to have issued no
    /// fetch at all). Nodes absent in the adversarial mode are skipped.
    pub node_fetches: Vec<(Node, Vec<FetchMatch>)>,
    /// The fetches that must still be active (not retained away) on each listed
    /// node at handoff, as an exact multiset.
    pub node_active_fetches: Vec<(Node, Vec<FetchMatch>)>,
    /// Block presence and absence each listed node must exhibit at handoff:
    /// the defining state names which marshal holds each candidate and which
    /// must lack it. Nodes absent in the adversarial mode are skipped.
    pub expected_nodes: Vec<NodeExpectation>,
    /// Invariant-selection hint for the fuzzing phase.
    pub expectation: Expectation,
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher as _, Sha256};

    fn round(view: u64) -> Round {
        Round::new(commonware_consensus::types::Epoch::zero(), View::new(view))
    }

    #[test]
    fn fetch_match_distinguishes_annotations_sharing_a_block_key() {
        let commitment = Sha256::hash(&[b"block"]);
        let by_round_key = Key::Block(commitment);
        let by_round = Annotation::Finalized(Finalized::ByRound { round: round(7) });
        let by_height = Annotation::Finalized(Finalized::ByHeight {
            height: Height::new(7),
        });
        let certified = Annotation::Certified {
            height: Height::new(7),
        };

        // ByRound and ByHeight serialize to the same wire key but are distinct
        // source states.
        assert!(
            FetchMatch::FinalizedByRound {
                commitment,
                round: round(7)
            }
            .matches(&by_round_key, &by_round)
        );
        assert!(
            !FetchMatch::FinalizedByRound {
                commitment,
                round: round(7)
            }
            .matches(&by_round_key, &by_height)
        );
        assert!(
            FetchMatch::FinalizedByHeight {
                commitment,
                height: Height::new(7)
            }
            .matches(&by_round_key, &by_height)
        );
        assert!(
            !FetchMatch::FinalizedByHeight {
                commitment,
                height: Height::new(7)
            }
            .matches(&by_round_key, &by_round)
        );
        assert!(
            FetchMatch::CertifiedHeight {
                commitment,
                height: Height::new(7)
            }
            .matches(&by_round_key, &certified)
        );

        // The bare Block matcher accepts any annotation for the commitment.
        assert!(FetchMatch::Block(commitment).matches(&by_round_key, &by_round));
        assert!(FetchMatch::Block(commitment).matches(&by_round_key, &by_height));

        // A notarized-round request is a different key entirely.
        let notarized_key = Key::Notarized { round: round(1) };
        let notarized = Annotation::Notarization { round: round(1) };
        assert!(FetchMatch::NotarizedRound(round(1)).matches(&notarized_key, &notarized));
        assert!(!FetchMatch::Block(commitment).matches(&notarized_key, &notarized));
    }
}
