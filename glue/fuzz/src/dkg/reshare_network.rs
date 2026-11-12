//! Routing of the compromised identity's channels on the reshare chain, and
//! the leaders its scenario scripts.
//!
//! The Simplex, marshal, and dissemination channels follow the twins rule of
//! [`crate::stateful::network`], as the bootstrap chain's do (see
//! [`super::network`]). Two things differ. The orchestrator multiplexes the
//! vote, certificate, and resolver channels by epoch, so each message on them
//! carries its epoch before the Simplex message; the view is read from the
//! message behind that prefix. And every epoch runs its own Simplex engine
//! from view one, so the scenario's partition applies to the first views of
//! every epoch.
//!
//! The DKG channel is multiplexed by epoch as well. Each ceremony has its own
//! [`Mask`], selected by the epoch a message carries in its channel prefix. A
//! message of an epoch past the masked ones is not masked, and a message with
//! no readable prefix is dropped.
//!
//! The probe channel carries no view and its wire format is not public, so it
//! is not split here: both halves share the identity's sender and receive
//! every inbound message.

use super::{
    Digest, DkgMask, PublicKey,
    app::{BLOCK_CFG, Block},
    network::{Mask, harness, split},
    scheme::Scheme,
};
use crate::stateful::{
    network::{
        Routing, backfill_routing, certificate_routing, simplex_resolver_routing, vote_routing,
    },
    runner::unattributed,
};
use commonware_codec::Decode as _;
use commonware_consensus::{
    CertifiableBlock as _,
    simplex::{
        elector::{self, Elector, RoundRobin, RoundRobinElector, Scheduled, Terms},
        mocks::twins::Scenario,
    },
    types::{Participant, Round},
};
use commonware_cryptography::Sha256;
use commonware_p2p::{
    Recipients,
    simulated::{SplitForwarder, SplitRouter, SplitTarget},
    utils::mux,
};
use commonware_runtime::IoBuf;
use commonware_utils::ordered::Set;
use std::sync::Arc;

/// The Simplex channels the orchestrator multiplexes by epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Simplex {
    Votes,
    Certificates,
    Resolver,
}

/// Classify a message on one of the multiplexed Simplex channels by the
/// Simplex message behind its epoch prefix. A threshold certificate has a
/// fixed size, so decoding one takes no configuration.
fn simplex_routing(channel: Simplex, message: &IoBuf) -> Routing {
    let Ok((_, message)) = mux::parse(message.clone()) else {
        return Routing::Undecodable;
    };
    match channel {
        Simplex::Votes => vote_routing::<Scheme, Digest>(&message),
        Simplex::Certificates => certificate_routing::<Scheme, Digest>(&message, &()),
        Simplex::Resolver => simplex_resolver_routing::<Scheme, Digest>(&message, &()),
    }
}

/// Classify a message on the dissemination channel: a bare block, whose
/// embedded consensus context names its round.
fn block_routing(message: &IoBuf) -> Routing {
    Block::decode_cfg(message.clone(), &BLOCK_CFG).map_or(Routing::Undecodable, |block| {
        Routing::Partition(block.context().round.view())
    })
}

/// The twins split of the reshare chain's view-addressable channels.
#[derive(Clone)]
pub(super) struct Twins {
    participants: Arc<[PublicKey]>,
    scenario: Scenario,
}

impl Twins {
    pub(super) const fn new(participants: Arc<[PublicKey]>, scenario: Scenario) -> Self {
        Self {
            participants,
            scenario,
        }
    }

    /// Both halves of one multiplexed Simplex channel. Every channel's halves
    /// have the same types, which the orchestrator requires of the three.
    pub(super) fn simplex(
        &self,
        channel: Simplex,
    ) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
        split(
            self.participants.clone(),
            self.scenario.clone(),
            move |message: &IoBuf| simplex_routing(channel, message),
        )
    }

    pub(super) fn backfill(&self) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
        split(
            self.participants.clone(),
            self.scenario.clone(),
            backfill_routing,
        )
    }

    pub(super) fn broadcast(
        &self,
    ) -> (impl SplitForwarder<PublicKey>, impl SplitRouter<PublicKey>) {
        split(
            self.participants.clone(),
            self.scenario.clone(),
            block_routing,
        )
    }
}

/// The DKG masks of a run: one per ceremony, from epoch zero on.
#[derive(Clone)]
pub(super) struct Masks(Arc<[Mask]>);

impl Masks {
    /// Assign each of `masks` to the ceremony of its epoch, among the
    /// identities other than `compromised`.
    pub(super) fn new<const PEERS: usize>(
        participants: &[PublicKey],
        compromised: usize,
        masks: &[DkgMask<PEERS>],
    ) -> Self {
        Self(
            masks
                .iter()
                .map(|mask| Mask::new(participants, compromised, *mask))
                .collect(),
        )
    }

    /// The outbound half: a half's ceremony messages reach only the
    /// identities on its side in the ceremony the message belongs to.
    pub(super) fn forwarder(&self) -> impl SplitForwarder<PublicKey> {
        let forwarders: Arc<[_]> = self.0.iter().map(Mask::forwarder).collect();
        harness(
            move |origin, intended: &Recipients<PublicKey>, message: &IoBuf| {
                let (epoch, _) = mux::parse(message.clone()).ok()?;
                match usize::try_from(epoch)
                    .ok()
                    .and_then(|epoch| forwarders.get(epoch))
                {
                    Some(forward) => forward(origin, intended, message),
                    None => Some(intended.clone()),
                }
            },
        )
    }

    /// The inbound half: an identity's ceremony messages reach the halves on
    /// its side in the ceremony the message belongs to.
    pub(super) fn router(&self) -> impl SplitRouter<PublicKey> {
        let routers: Arc<[_]> = self.0.iter().map(Mask::router).collect();
        move |message: &(PublicKey, IoBuf)| {
            let Ok((epoch, _)) = mux::parse(message.1.clone()) else {
                return SplitTarget::None;
            };
            match usize::try_from(epoch)
                .ok()
                .and_then(|epoch| routers.get(epoch))
            {
                Some(route) => route(message),
                None => SplitTarget::Both,
            }
        }
    }
}

/// Leader election that follows the scenario's scripted leaders for the first
/// views of every epoch and rotates afterwards.
///
/// The scenario names its leaders among all the identities of the run, while
/// an epoch's committee is a subset of them. A scripted leader that is in the
/// committee leads its view; a view whose scripted leader is outside the
/// committee falls back to the rotation, as every view past the script does.
#[derive(Clone, Debug)]
pub(super) struct Scripted {
    leaders: Arc<[PublicKey]>,
}

impl Scripted {
    /// The leaders `scenario` scripts among `identities`.
    pub(super) fn new(scenario: &Scenario, identities: &[PublicKey]) -> Self {
        Self {
            leaders: scenario
                .rounds()
                .iter()
                .map(|round| identities[round.leader()].clone())
                .collect(),
        }
    }
}

impl elector::Config<Scheme> for Scripted {
    type Elector = ScriptedElector;

    fn build(self, participants: &Set<PublicKey>) -> Self::Elector {
        // The elector is built and asked inside an engine's task and is the
        // harness's code, not the engine's.
        unattributed(|| ScriptedElector {
            leaders: self
                .leaders
                .iter()
                .map(|leader| participants.position(leader).map(Participant::from_usize))
                .collect(),
            fallback: elector::Config::<Scheme>::build(
                RoundRobin::<Sha256>::default(),
                participants,
            ),
        })
    }
}

/// [`Scripted`] for one epoch's committee.
#[derive(Clone, Debug)]
pub(super) struct ScriptedElector {
    /// The committee position of each scripted view's leader, if the leader
    /// is in the committee.
    leaders: Arc<[Option<Participant>]>,
    fallback: RoundRobinElector<Scheme>,
}

impl Elector<Scheme> for ScriptedElector {
    type Mode = Scheduled;

    fn terms(&self) -> Terms {
        self.fallback.terms()
    }

    fn elect(&self, round: Round, (): ()) -> Participant {
        unattributed(|| {
            // View one is the first scripted view of an epoch.
            let scripted = round
                .view()
                .term_index(self.terms().length())
                .checked_sub(1)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| self.leaders.get(index).copied().flatten());
            scripted.unwrap_or_else(|| self.fallback.elect(round, ()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::{MockGroup, RESHARE_NAMESPACE, Side, fixtures::identities},
        stateful::network::select_case,
    };
    use commonware_codec::{Encode as _, varint::UInt};
    use commonware_consensus::{
        marshal::resolver::handler::Key as BackfillKey,
        simplex::types::{Certificate, Context, Notarization, Notarize, Proposal, Vote},
        types::{Epoch, Height, TermLength, View},
    };
    use commonware_cryptography::{
        Hasher as _,
        bls12381::{dkg::feldman_desmedt::deal, primitives::sharing::Mode},
    };
    use commonware_p2p::simulated::SplitOrigin;
    use commonware_parallel::Sequential;
    use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
    use commonware_utils::{N3f1, TestRng, non_empty, sequence::U64};

    /// A DKG channel message of `epoch`: the epoch prefix and a body.
    fn muxed(epoch: u64) -> IoBuf {
        let mut message = UInt(epoch).encode().to_vec();
        message.extend_from_slice(b"body");
        IoBuf::from(message)
    }

    fn recipients(recipients: Option<Recipients<PublicKey>>) -> Vec<PublicKey> {
        match recipients {
            None => Vec::new(),
            Some(Recipients::One(peer)) => vec![peer],
            Some(Recipients::Some(peers)) => peers,
            Some(Recipients::All) => panic!("a mask never broadcasts"),
        }
    }

    #[test]
    fn mask_is_selected_by_the_epoch_prefix() {
        let identities = identities();
        let masks = Masks::new(
            &identities,
            2,
            &[
                DkgMask([Side::Primary, Side::Primary, Side::Primary, Side::Primary]),
                DkgMask([
                    Side::Secondary,
                    Side::Secondary,
                    Side::Secondary,
                    Side::Secondary,
                ]),
            ],
        );
        let (forward, route) = (masks.forwarder(), masks.router());
        let others: Vec<PublicKey> = identities
            .iter()
            .filter(|identity| **identity != identities[2])
            .cloned()
            .collect();
        let sender = identities[0].clone();

        // Epoch zero is on the primary side and epoch one on the secondary.
        assert_eq!(
            recipients(forward(SplitOrigin::Primary, &Recipients::All, &muxed(0))),
            others
        );
        assert!(
            recipients(forward(SplitOrigin::Secondary, &Recipients::All, &muxed(0))).is_empty()
        );
        assert!(recipients(forward(SplitOrigin::Primary, &Recipients::All, &muxed(1))).is_empty());
        assert_eq!(
            recipients(forward(SplitOrigin::Secondary, &Recipients::All, &muxed(1))),
            others
        );
        assert_eq!(route(&(sender.clone(), muxed(0))), SplitTarget::Primary);
        assert_eq!(route(&(sender.clone(), muxed(1))), SplitTarget::Secondary);

        // An epoch past the masked ones is not masked.
        let intended = Recipients::One(sender.clone());
        for origin in [SplitOrigin::Primary, SplitOrigin::Secondary] {
            assert_eq!(
                recipients(forward(origin, &intended, &muxed(2))),
                vec![sender.clone()]
            );
        }
        assert_eq!(route(&(sender.clone(), muxed(2))), SplitTarget::Both);

        // A message with no readable prefix is dropped.
        let unreadable = IoBuf::from(vec![0xff; 11]);
        assert!(forward(SplitOrigin::Primary, &intended, &unreadable).is_none());
        assert_eq!(route(&(sender, unreadable)), SplitTarget::None);
    }

    #[test]
    fn unreadable_simplex_traffic_is_undecodable() {
        for channel in [Simplex::Votes, Simplex::Certificates, Simplex::Resolver] {
            assert_eq!(
                simplex_routing(channel, &IoBuf::from(vec![0xff; 11])),
                Routing::Undecodable
            );
            assert_eq!(simplex_routing(channel, &muxed(0)), Routing::Undecodable);
        }
        assert_eq!(block_routing(&muxed(0)), Routing::Undecodable);
    }

    #[test]
    fn scripted_leader_leads_when_in_the_committee() {
        let identities = identities();
        let (_, scenario) = select_case(vec![7; 64], identities.len(), false, 3)
            .expect("the generator yields cases");
        let scripted = Scripted::new(&scenario, &identities);
        let rotation = |committee: &Set<PublicKey>| {
            elector::Config::<Scheme>::build(RoundRobin::<Sha256>::default(), committee)
        };

        // One committee per choice of outside identity.
        for outsider in 0..identities.len() {
            let committee = Set::from_iter_dedup(
                identities
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != outsider)
                    .map(|(_, identity)| identity.clone()),
            );
            let elector = elector::Config::<Scheme>::build(scripted.clone(), &committee);
            let fallback = rotation(&committee);
            for epoch in 0..2 {
                for (index, scripted) in scenario.rounds().iter().enumerate() {
                    let round = Round::new(Epoch::new(epoch), View::new(index as u64 + 1));
                    let leader = elector.elect(round, ());
                    if scripted.leader() == outsider {
                        assert_eq!(leader, fallback.elect(round, ()));
                    } else {
                        assert_eq!(
                            committee[usize::from(leader)],
                            identities[scripted.leader()]
                        );
                    }
                }

                // Past the script the rotation leads.
                let round = Round::new(
                    Epoch::new(epoch),
                    View::new(scenario.rounds().len() as u64 + 1),
                );
                assert_eq!(elector.elect(round, ()), fallback.elect(round, ()));
            }
        }
    }

    /// The signing schemes of a committee of the first four identities.
    fn committee() -> Vec<Scheme> {
        let participants = Set::from_iter_dedup(identities().into_iter().take(4));
        let (output, shares) =
            deal::<MockGroup, _, N3f1>(TestRng::new(1), Mode::NonZeroCounter, participants.clone())
                .expect("a trusted deal must succeed");
        participants
            .iter()
            .map(|participant| {
                let share = shares
                    .get_value(participant)
                    .expect("every participant is dealt")
                    .clone();
                Scheme::signer(
                    RESHARE_NAMESPACE,
                    participants.clone(),
                    output.public().clone(),
                    share,
                )
                .expect("a dealt share signs")
            })
            .collect()
    }

    /// `body` as the orchestrator sends it in `epoch`: behind the epoch prefix.
    fn in_epoch(epoch: u64, body: impl AsRef<[u8]>) -> IoBuf {
        let mut message = UInt(epoch).encode().to_vec();
        message.extend_from_slice(body.as_ref());
        IoBuf::from(message)
    }

    #[test]
    fn simplex_traffic_is_partitioned_by_the_view_behind_its_epoch_prefix() {
        let schemes = committee();
        let view = View::new(3);
        let proposal = Proposal::new(
            Round::new(Epoch::new(2), view),
            View::new(2),
            Sha256::hash(&[b"payload"]),
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("a signer votes"))
            .collect();
        let vote = Vote::<Scheme, Digest>::Notarize(notarizes[0].clone()).encode();
        let certificate = Certificate::<Scheme, Digest>::Notarization(
            Notarization::from_notarizes(&schemes[0], non_empty![@&notarizes], &Sequential)
                .expect("a quorum of votes certifies"),
        )
        .encode();
        let request = ResolverMessage::<U64> {
            id: 7,
            payload: ResolverPayload::Request(U64::new(view.get())),
        }
        .encode();
        let response = ResolverMessage::<U64> {
            id: 7,
            payload: ResolverPayload::Response(certificate.clone()),
        }
        .encode();
        let error = ResolverMessage::<U64> {
            id: 7,
            payload: ResolverPayload::Error,
        }
        .encode();

        // Whatever the epoch, the message's own view decides.
        for epoch in [0, 2, 200] {
            assert_eq!(
                simplex_routing(Simplex::Votes, &in_epoch(epoch, &vote)),
                Routing::Partition(view)
            );
            assert_eq!(
                simplex_routing(Simplex::Certificates, &in_epoch(epoch, &certificate)),
                Routing::Partition(view)
            );
            assert_eq!(
                simplex_routing(Simplex::Resolver, &in_epoch(epoch, &request)),
                Routing::Partition(view)
            );
            assert_eq!(
                simplex_routing(Simplex::Resolver, &in_epoch(epoch, &response)),
                Routing::Partition(view)
            );
            assert_eq!(
                simplex_routing(Simplex::Resolver, &in_epoch(epoch, &error)),
                Routing::Viewless
            );
        }

        // A message without its prefix, or on another channel, does not
        // decode.
        assert_eq!(
            simplex_routing(Simplex::Votes, &IoBuf::from(vote.to_vec())),
            Routing::Undecodable
        );
        assert_eq!(
            simplex_routing(Simplex::Votes, &in_epoch(2, &certificate)),
            Routing::Undecodable
        );
    }

    #[test]
    fn marshal_traffic_is_partitioned_by_its_view() {
        let identities = identities();
        let view = View::new(2);
        let round = Round::new(Epoch::new(1), view);
        let block = Block::new(
            Context {
                round,
                leader: identities[0].clone(),
                parent: (View::new(1), Sha256::hash(&[b"parent"])),
            },
            Sha256::hash(&[b"parent"]),
            Height::new(40),
            None,
        );
        assert_eq!(
            block_routing(&IoBuf::from(block.encode().to_vec())),
            Routing::Partition(view)
        );

        // Only a request for a notarized proposal names a round.
        let backfill = |key: BackfillKey<Digest>| {
            let request = ResolverMessage::<BackfillKey<Digest>> {
                id: 1,
                payload: ResolverPayload::Request(key),
            };
            backfill_routing(&IoBuf::from(request.encode().to_vec()))
        };
        assert_eq!(
            backfill(BackfillKey::Notarized { round }),
            Routing::Partition(view)
        );
        assert_eq!(
            backfill(BackfillKey::Block(Sha256::hash(&[b"block"]))),
            Routing::Viewless
        );
    }

    #[test]
    fn scenario_partitions_the_first_views_of_every_epoch() {
        let identities: Arc<[PublicKey]> = identities().into();
        let (compromised, scenario) = select_case(vec![3; 64], identities.len(), false, 5)
            .expect("the generator yields cases");
        let twins = Twins::new(identities.clone(), scenario.clone());
        let (forward, route) = twins.simplex(Simplex::Votes);
        let schemes = committee();
        let vote = |epoch: u64, view: u64| {
            let proposal = Proposal::new(
                Round::new(Epoch::new(epoch), View::new(view)),
                View::new(view - 1),
                Sha256::hash(&[b"payload"]),
            );
            let notarize = Notarize::sign(&schemes[0], proposal).expect("a signer votes");
            in_epoch(epoch, Vote::<Scheme, Digest>::Notarize(notarize).encode())
        };
        let sender = identities[(compromised + 1) % identities.len()].clone();

        for epoch in 0..3 {
            // A scripted view follows the scenario, in every epoch alike.
            for (index, _) in scenario.rounds().iter().enumerate() {
                let view = index as u64 + 1;
                let (primary, secondary) =
                    scenario.partitions(View::new(view), TermLength::ONE, identities.as_ref());
                assert_eq!(
                    recipients(forward(
                        SplitOrigin::Primary,
                        &Recipients::All,
                        &vote(epoch, view)
                    )),
                    primary
                );
                assert_eq!(
                    recipients(forward(
                        SplitOrigin::Secondary,
                        &Recipients::All,
                        &vote(epoch, view)
                    )),
                    secondary
                );
                assert_eq!(
                    route(&(sender.clone(), vote(epoch, view))),
                    scenario.route(
                        View::new(view),
                        TermLength::ONE,
                        &sender,
                        identities.as_ref()
                    )
                );
            }

            // Past the script both halves exchange votes with everyone.
            let view = scenario.rounds().len() as u64 + 1;
            assert_eq!(
                recipients(forward(
                    SplitOrigin::Secondary,
                    &Recipients::All,
                    &vote(epoch, view)
                )),
                identities.to_vec()
            );
            assert_eq!(
                route(&(sender.clone(), vote(epoch, view))),
                SplitTarget::Both
            );
        }
    }
}
