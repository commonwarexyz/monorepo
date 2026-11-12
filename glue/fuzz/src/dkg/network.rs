//! Routing of the compromised identity's channels.
//!
//! The Simplex, marshal, and dissemination channels follow the twins rule of
//! [`crate::stateful::network`]: a message that names a view is partitioned by
//! the scenario for that view, a message that decodes but names none reaches
//! both halves, and a message that does not decode is dropped. Only the
//! classification of each channel's messages is defined here, because it
//! depends on the chain's scheme and block.
//!
//! The DKG channel carries dealings and acks, which name an epoch and no view,
//! so no scenario applies to it. It is split by the [`Mask`] instead: each
//! other identity exchanges ceremony messages with the primary half, the
//! secondary half, or both.

use super::{COMMITTEE, Digest, DkgMask, MockGroup, PublicKey, Side, stack::Endpoint};
use crate::stateful::{
    network::{
        Routing, backfill_routing, certificate_routing, forwarder, router,
        simplex_resolver_routing, vote_routing,
    },
    runner::unattributed,
};
use commonware_codec::{Decode as _, Read};
use commonware_consensus::{
    CertifiableBlock as _,
    simplex::{mocks::twins::Scenario, scheme::ed25519::Scheme},
    types::TermLength,
};
use commonware_cryptography::{bls12381::primitives::sharing::ModeVersion, certificate::Verifier};
use commonware_glue::dkg::bootstrap::Block;
use commonware_p2p::{
    Recipients,
    simulated::{Receiver, SplitForwarder, SplitOrigin, SplitRouter, SplitSender, SplitTarget},
};
use commonware_runtime::{IoBuf, deterministic};
use commonware_utils::ordered::Set;
use std::sync::Arc;

/// Codec configuration for decoding the bootstrap chain's certificates.
type CertificateCfg = <<Scheme as Verifier>::Certificate as Read>::Cfg;

/// The leader term of the bootstrap chain, whose elector rotates every view.
const TERM: TermLength = TermLength::ONE;

/// Classify a message on the bootstrap chain's dissemination channel: a bare
/// block, whose embedded consensus context names its round.
fn block_routing(message: &IoBuf, max_supported_mode: ModeVersion) -> Routing {
    Block::<MockGroup>::decode_cfg(message.clone(), &(COMMITTEE, max_supported_mode))
        .map_or(Routing::Undecodable, |block| {
            Routing::Partition(block.context().round.view())
        })
}

/// Run `forward` as harness code. A forwarder is called inside the task of the
/// half that sends, and a panic in it is the harness's, not the half's.
pub(super) fn harness(forward: impl SplitForwarder<PublicKey>) -> impl SplitForwarder<PublicKey> {
    move |origin: SplitOrigin, intended: &Recipients<PublicKey>, message: &IoBuf| {
        unattributed(|| forward(origin, intended, message))
    }
}

/// One half's end of a channel of the compromised identity.
pub(super) type Half<F> = (
    SplitSender<PublicKey, deterministic::Context, F>,
    Receiver<PublicKey>,
);

/// Split one channel of the compromised identity between its halves: what a
/// half sends passes `forward`, and `route` decides which half receives a
/// message, in a task on `context`. Returns the primary half's end of the
/// channel and the secondary half's.
pub(super) fn halve<F: SplitForwarder<PublicKey>>(
    context: deterministic::Context,
    (sender, receiver): Endpoint,
    (forward, route): (F, impl SplitRouter<PublicKey>),
) -> (Half<F>, Half<F>) {
    let (primary, secondary) = sender.split_with(forward);
    let (primary_rx, secondary_rx) = receiver.split_with(context, route);
    ((primary, primary_rx), (secondary, secondary_rx))
}

/// Both halves of a channel whose messages `classify` assigns to views, on a
/// chain whose leader rotates every view: the outbound half and the inbound
/// half of the twins split under `scenario`.
pub(super) fn split(
    participants: Arc<[PublicKey]>,
    scenario: Scenario,
    classify: impl Fn(&IoBuf) -> Routing + Send + Sync + Clone + 'static,
) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
    (
        harness(forwarder(
            participants.clone(),
            scenario.clone(),
            TERM,
            classify.clone(),
        )),
        router(participants, scenario, TERM, classify),
    )
}

/// The twins split of the bootstrap chain's view-addressable channels.
#[derive(Clone)]
pub(super) struct Twins {
    participants: Arc<[PublicKey]>,
    scenario: Scenario,
    certificates: CertificateCfg,
    max_supported_mode: ModeVersion,
}

impl Twins {
    pub(super) fn new(
        participants: Arc<[PublicKey]>,
        scenario: Scenario,
        max_supported_mode: ModeVersion,
    ) -> Self {
        // Only the bound on a certificate's size depends on the scheme
        // instance, and that depends only on the participants.
        let certificates =
            Scheme::verifier(&[], Set::from_iter_dedup(participants.iter().cloned()))
                .certificate_codec_config();
        Self {
            participants,
            scenario,
            certificates,
            max_supported_mode,
        }
    }

    /// Both halves of a channel whose messages `classify` assigns to views.
    fn split(
        &self,
        classify: impl Fn(&IoBuf) -> Routing + Send + Sync + Clone + 'static,
    ) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
        split(self.participants.clone(), self.scenario.clone(), classify)
    }

    pub(super) fn votes(&self) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
        self.split(vote_routing::<Scheme, Digest>)
    }

    pub(super) fn certificates(
        &self,
    ) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
        let codec = self.certificates;
        self.split(move |message: &IoBuf| certificate_routing::<Scheme, Digest>(message, &codec))
    }

    pub(super) fn resolver(&self) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
        let codec = self.certificates;
        self.split(move |message: &IoBuf| {
            simplex_resolver_routing::<Scheme, Digest>(message, &codec)
        })
    }

    pub(super) fn backfill(&self) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
        self.split(backfill_routing)
    }

    pub(super) fn broadcast(
        &self,
    ) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
        let max_supported_mode = self.max_supported_mode;
        self.split(move |message: &IoBuf| block_routing(message, max_supported_mode))
    }
}

/// The DKG mask: the side of every identity other than the compromised one.
#[derive(Clone)]
pub(super) struct Mask(Arc<[(PublicKey, Side)]>);

impl Mask {
    /// Assign `mask`'s sides to the identities other than `compromised`, in
    /// identity order.
    pub(super) fn new<const PEERS: usize>(
        participants: &[PublicKey],
        compromised: usize,
        mask: DkgMask<PEERS>,
    ) -> Self {
        Self(
            participants
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != compromised)
                .map(|(_, identity)| identity.clone())
                .zip(mask.0)
                .collect(),
        )
    }

    /// The side of `peer`. The compromised identity itself is on both.
    fn side(&self, peer: &PublicKey) -> Side {
        self.0
            .iter()
            .find(|(identity, _)| identity == peer)
            .map_or(Side::Both, |(_, side)| *side)
    }

    /// Whether the half `origin` exchanges ceremony messages with `peer`.
    fn admits(&self, origin: SplitOrigin, peer: &PublicKey) -> bool {
        matches!(
            (self.side(peer), origin),
            (Side::Both, _)
                | (Side::Primary, SplitOrigin::Primary)
                | (Side::Secondary, SplitOrigin::Secondary)
        )
    }

    /// The outbound half: a half's ceremony messages reach only the
    /// identities on its side.
    pub(super) fn forwarder(&self) -> impl SplitForwarder<PublicKey> {
        let mask = self.clone();
        harness(move |origin, intended: &Recipients<PublicKey>, _: &IoBuf| {
            let admitted = |peers: &mut dyn Iterator<Item = &PublicKey>| {
                Recipients::Some(
                    peers
                        .filter(|peer| mask.admits(origin, peer))
                        .cloned()
                        .collect(),
                )
            };
            Some(match intended {
                Recipients::All => admitted(&mut mask.0.iter().map(|(identity, _)| identity)),
                Recipients::Some(peers) => admitted(&mut peers.iter()),
                Recipients::One(peer) => {
                    if !mask.admits(origin, peer) {
                        return None;
                    }
                    Recipients::One(peer.clone())
                }
            })
        })
    }

    /// The inbound half: an identity's ceremony messages reach the halves on
    /// its side.
    pub(super) fn router(&self) -> impl SplitRouter<PublicKey> {
        let mask = self.clone();
        move |(sender, _): &(PublicKey, IoBuf)| match mask.side(sender) {
            Side::Primary => SplitTarget::Primary,
            Side::Secondary => SplitTarget::Secondary,
            Side::Both => SplitTarget::Both,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::fixtures::committee;

    fn recipients(recipients: Option<Recipients<PublicKey>>) -> Vec<PublicKey> {
        match recipients {
            None => Vec::new(),
            Some(Recipients::One(peer)) => vec![peer],
            Some(Recipients::Some(peers)) => peers,
            Some(Recipients::All) => panic!("the mask never broadcasts"),
        }
    }

    #[test]
    fn mask_partitions_both_directions() {
        let identities = committee();
        let mask = Mask::new(
            &identities,
            1,
            DkgMask([Side::Primary, Side::Secondary, Side::Both]),
        );
        let (forward, route) = (mask.forwarder(), mask.router());
        let message = IoBuf::default();

        // Identity 0 is on the primary side, 2 on the secondary, 3 on both.
        assert_eq!(
            recipients(forward(SplitOrigin::Primary, &Recipients::All, &message)),
            vec![identities[0].clone(), identities[3].clone()]
        );
        assert_eq!(
            recipients(forward(SplitOrigin::Secondary, &Recipients::All, &message)),
            vec![identities[2].clone(), identities[3].clone()]
        );
        assert!(
            recipients(forward(
                SplitOrigin::Secondary,
                &Recipients::One(identities[0].clone()),
                &message
            ))
            .is_empty()
        );
        assert_eq!(
            recipients(forward(
                SplitOrigin::Primary,
                &Recipients::Some(vec![identities[0].clone(), identities[2].clone()]),
                &message
            )),
            vec![identities[0].clone()]
        );
        assert_eq!(
            route(&(identities[0].clone(), message.clone())),
            SplitTarget::Primary
        );
        assert_eq!(
            route(&(identities[2].clone(), message.clone())),
            SplitTarget::Secondary
        );
        assert_eq!(route(&(identities[3].clone(), message)), SplitTarget::Both);
    }

    #[test]
    fn whole_mask_changes_nothing() {
        let identities = committee();
        let mask = Mask::new(&identities, 0, DkgMask::<3>::WHOLE);
        let forward = mask.forwarder();
        let message = IoBuf::default();
        for origin in [SplitOrigin::Primary, SplitOrigin::Secondary] {
            assert_eq!(
                recipients(forward(origin, &Recipients::All, &message)),
                identities[1..].to_vec()
            );
        }
    }
}
