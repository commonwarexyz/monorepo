//! Per-channel split forwarders and routers realising the twins partition.
//!
//! The compromised identity's channels are split in two; the twins scenario
//! decides, per view, which identities each half may send to and which half
//! receives a given inbound message. The view is derived from the message
//! itself rather than from ambient state, so routing a message never depends on
//! when it is routed.
//!
//! Every channel follows one rule, applied per message:
//!
//! - A message whose protocol view can be determined is partitioned by that
//!   view: outbound it goes to the half's mask, inbound it goes to whichever
//!   halves the scenario admits its sender for. The stateful channels send it
//!   to the whole mask; [`Addressing`] lets another harness keep the
//!   recipients the engine addressed within the mask instead.
//! - A message that decodes but carries no view is delivered to both halves and
//!   sent to the recipients the engine itself addressed. Marshal backfill mixes
//!   round-addressed requests with requests addressed by block digest and by
//!   height, and this is what keeps the latter working while the former is
//!   partitioned.
//! - A message that does not decode at all is dropped in both directions,
//!   because nothing can be concluded about it.
//!
//! The database-sync channel is not split: every message on it is viewless, so
//! sharing the identity's sender and delivering to both halves already is the
//! rule. The dissemination channel is classified by the marshal variant: a
//! broadcast block names its round, while a shard names only a commitment,
//! so under the coding marshal every shard is viewless and reaches both halves.

// The mock certificate scheme's codec configuration is a unit value; the
// bindings below stay so the shape survives a scheme whose configuration is not.
#![allow(clippy::let_unit_value)]

use super::{Digest, MAX_CASES, MAX_PREFIX_ROUNDS, PublicKey, Scheme, marshal::Marshal};
use commonware_codec::{Decode, DecodeExt, Read};
use commonware_consensus::{
    Viewable,
    marshal::resolver::handler::Key as BackfillKey,
    simplex::{
        elector::{self, Input, Terms},
        mocks::twins::{self, Scenario},
        types::{Certificate, Vote},
    },
    types::{Participant, Round, TermLength, View},
};
use commonware_cryptography::{
    Digest as DigestTrait,
    certificate::{Scheme as CertificateScheme, Verifier},
};
use commonware_p2p::{
    Recipients,
    simulated::{SplitOrigin, SplitTarget},
};
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::IoBuf;
use commonware_utils::{FuzzRng, ordered::Set, sequence::U64};
use std::{iter, sync::Arc};

/// Draw the twins cases of `rounds` adversarial rounds from `entropy` and
/// select one.
///
/// Returns the compromised identity and its scenario, or `None` if the
/// generator produced no case.
pub(crate) fn select_case(
    entropy: Vec<u8>,
    participants: usize,
    rounds: usize,
    sustained: bool,
    case_selector: u16,
) -> Option<(usize, Scenario)> {
    let mut scenario_rng = FuzzRng::new(entropy);
    let cases = twins::cases(
        &mut scenario_rng,
        twins::Framework {
            participants,
            faults: 1,
            rounds,
            mode: if sustained {
                twins::Mode::Sustained
            } else {
                twins::Mode::Sampled
            },
            max_cases: MAX_CASES,
        },
    );
    if cases.is_empty() {
        return None;
    }
    let selected = usize::from(case_selector) % cases.len();
    let case = cases
        .into_iter()
        .nth(selected)
        .expect("selected twins case must exist");
    let compromised = *case
        .compromised
        .first()
        .expect("twins case must compromise one identity");
    assert!(
        compromised < participants,
        "twins case compromised an identity outside the validator set"
    );
    Some((compromised, case.scenario))
}

/// How one message is to be routed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Routing {
    /// The message belongs to this view and is partitioned by it.
    Partition(View),
    /// The message decodes but names no view.
    Viewless,
    /// The message does not decode.
    Undecodable,
}

/// Classify a message on the vote channel. Votes name the payload `D` under
/// the scheme `S`.
pub(crate) fn vote_routing<S: CertificateScheme, D: DigestTrait>(message: &IoBuf) -> Routing {
    Vote::<S, D>::decode(message.clone())
        .map_or(Routing::Undecodable, |vote| Routing::Partition(vote.view()))
}

/// Classify a message on the certificate channel.
pub(crate) fn certificate_routing<S: CertificateScheme, D: DigestTrait>(
    message: &IoBuf,
    codec: &<S::Certificate as Read>::Cfg,
) -> Routing {
    Certificate::<S, D>::decode_cfg(message.clone(), codec)
        .map_or(Routing::Undecodable, |certificate| {
            Routing::Partition(certificate.view())
        })
}

/// Classify a message on the simplex resolver channel.
///
/// A request names its view directly. A response carries a certificate, whose
/// view is the one it answers for. An error names nothing.
pub(crate) fn simplex_resolver_routing<S: CertificateScheme, D: DigestTrait>(
    message: &IoBuf,
    codec: &<S::Certificate as Read>::Cfg,
) -> Routing {
    let Ok(message) = ResolverMessage::<U64>::decode(message.clone()) else {
        return Routing::Undecodable;
    };
    match message.payload {
        ResolverPayload::Request(key) => Routing::Partition(View::new(u64::from(key))),
        ResolverPayload::Response(bytes) => Certificate::<S, D>::decode_cfg(bytes, codec)
            .map_or(Routing::Undecodable, |certificate| {
                Routing::Partition(certificate.view())
            }),
        ResolverPayload::Error => Routing::Viewless,
    }
}

/// Classify a message on the marshal backfill channel.
///
/// Only a request for a notarized proposal names a round; requests addressed by
/// block digest or by height, and every response, name no view.
pub(crate) fn backfill_routing(message: &IoBuf) -> Routing {
    let Ok(message) = ResolverMessage::<BackfillKey<Digest>>::decode(message.clone()) else {
        return Routing::Undecodable;
    };
    match message.payload {
        ResolverPayload::Request(BackfillKey::Notarized { round }) => {
            Routing::Partition(round.view())
        }
        _ => Routing::Viewless,
    }
}

/// Classify a message on the dissemination channel. The marshal variant says
/// what travels on it and whether that names a view.
fn broadcast_routing<M: Marshal>(message: &IoBuf) -> Routing {
    M::Wire::decode_cfg(message.clone(), &M::wire_cfg()).map_or(Routing::Undecodable, |wire| {
        M::wire_view(&wire).map_or(Routing::Viewless, Routing::Partition)
    })
}

/// Most rounds one generated scenario scripts. The generator counts the
/// scenarios of a length exactly, and the count of a sampled scenario much
/// longer than this overflows, so a longer script is drawn in parts.
const PART_ROUNDS: u8 = 8;

/// The twins script of a run: which leader terms the scenario partitions for
/// the compromised identity, who leads them, and how they are partitioned.
///
/// A prefix of `Some(rounds)` scripts the first `rounds` leader terms and
/// leaves every later view whole. A prefix of `None` scripts every view: the
/// longest script starts over whenever it ends. One scripted round is one
/// leader term, as in the scenario.
#[derive(Clone)]
pub(crate) struct TwinsScript {
    /// The scenarios the script is made of, in order.
    parts: Arc<[Scenario]>,
    /// Whether the script starts over after its last round.
    repeats: bool,
}

impl TwinsScript {
    /// Draw the script of `prefix` from `entropy`, among `participants`
    /// identities. A prefix outside the range the inputs draw is brought
    /// into it.
    ///
    /// Returns the compromised identity and its script, or `None` if the
    /// generator produced no case.
    pub(crate) fn select(
        entropy: Vec<u8>,
        participants: usize,
        prefix: Option<u8>,
        sustained: bool,
        case_selector: u16,
    ) -> Option<(usize, Self)> {
        let rounds = prefix.map_or(MAX_PREFIX_ROUNDS, |rounds| {
            rounds.clamp(1, MAX_PREFIX_ROUNDS)
        });
        // A sustained scenario repeats one pattern, which the generator
        // counts once whatever its length. A sampled one is drawn in parts.
        let part = if sustained { rounds } else { PART_ROUNDS };
        let mut compromised = None;
        let mut parts = Vec::new();
        for (index, start) in (0..rounds).step_by(usize::from(part)).enumerate() {
            // The first part is drawn from the entropy as it is, and each
            // later one from entropy of its own.
            let seed = if index == 0 {
                entropy.clone()
            } else {
                iter::once(index as u8)
                    .chain(entropy.iter().copied())
                    .collect()
            };
            let length = usize::from((rounds - start).min(part));
            let (identity, scenario) =
                select_case(seed, participants, length, sustained, case_selector)?;
            // The first part names the compromised identity. A later part
            // contributes its partitions and leaders only.
            compromised.get_or_insert(identity);
            parts.push(scenario);
        }
        Some((
            compromised?,
            Self {
                parts: parts.into(),
                repeats: prefix.is_none(),
            },
        ))
    }

    /// The number of rounds the script holds before it ends or starts over.
    pub(crate) fn rounds(&self) -> u64 {
        self.parts
            .iter()
            .map(|part| part.rounds().len() as u64)
            .sum()
    }

    /// The identity each scripted round names as its leader, in order.
    pub(crate) fn leaders(&self) -> impl Iterator<Item = usize> + '_ {
        self.parts
            .iter()
            .flat_map(|part| part.rounds().iter().map(|round| round.leader()))
    }

    /// The last view of the script's last round, counted from the first view
    /// and without starting over: once a run is past it, every scripted
    /// round has been played.
    pub(crate) fn scripted_through(&self, term_length: TermLength) -> View {
        View::new(self.rounds() * term_length.get())
    }

    /// The place of the round of `view` in the script, counted from zero, or
    /// none if the view is past a script that does not start over. The first
    /// leader term is the first scripted round; genesis shares its place.
    pub(crate) fn place(&self, view: View, term_length: TermLength) -> Option<u64> {
        let place = view.term_index(term_length).saturating_sub(1);
        let rounds = self.rounds();
        if self.repeats {
            Some(place % rounds)
        } else {
            (place < rounds).then_some(place)
        }
    }

    /// The scenario that scripts `view` and a view of the same round within
    /// it, or none if the script does not reach the view.
    fn part(&self, view: View, term_length: TermLength) -> Option<(&Scenario, View)> {
        let mut place = self.place(view, term_length)?;
        for part in self.parts.iter() {
            let rounds = part.rounds().len() as u64;
            if place < rounds {
                return Some((part, View::new(place * term_length.get() + 1)));
            }
            place -= rounds;
        }
        None
    }

    /// The identities the primary half and the secondary half exchange
    /// messages with at `view`: everyone, where the script does not reach.
    pub(crate) fn partitions(
        &self,
        view: View,
        term_length: TermLength,
        participants: &[PublicKey],
    ) -> (Vec<PublicKey>, Vec<PublicKey>) {
        self.part(view, term_length).map_or_else(
            || (participants.to_vec(), participants.to_vec()),
            |(scenario, view)| scenario.partitions(view, term_length, participants),
        )
    }

    /// The halves that receive what `sender` sent at `view`: both, where the
    /// script does not reach.
    pub(crate) fn route(
        &self,
        view: View,
        term_length: TermLength,
        sender: &PublicKey,
        participants: &[PublicKey],
    ) -> SplitTarget {
        self.part(view, term_length)
            .map_or(SplitTarget::Both, |(scenario, view)| {
                scenario.route(view, term_length, sender, participants)
            })
    }
}

/// Leader election that follows a script's leaders in the rounds the script
/// reaches and asks a fallback elector in every other.
#[derive(Clone)]
pub(crate) struct Scripted<C> {
    fallback: C,
    script: TwinsScript,
}

impl<C> Scripted<C> {
    /// Follow `script` and fall back to `fallback`.
    pub(crate) const fn new(fallback: C, script: TwinsScript) -> Self {
        Self { fallback, script }
    }
}

/// [`Scripted`] for one set of participants.
#[derive(Clone)]
pub(crate) struct ScriptedElector<E> {
    fallback: E,
    script: TwinsScript,
    /// The leader of each scripted round, in order.
    leaders: Arc<[Participant]>,
}

impl<S, C> elector::Config<S> for Scripted<C>
where
    S: CertificateScheme,
    C: elector::Config<S>,
{
    type Elector = ScriptedElector<C::Elector>;

    fn build(self, participants: &Set<S::PublicKey>) -> Self::Elector {
        let leaders = self
            .script
            .leaders()
            .map(|leader| {
                assert!(leader < participants.len(), "scripted leader out of bounds");
                Participant::from_usize(leader)
            })
            .collect();
        ScriptedElector {
            fallback: self.fallback.build(participants),
            script: self.script,
            leaders,
        }
    }
}

impl<S, E> elector::Elector<S> for ScriptedElector<E>
where
    S: CertificateScheme,
    E: elector::Elector<S>,
{
    // A scripted leader never reads the input, so the fallback decides
    // whether election needs the certificate.
    type Mode = E::Mode;

    fn terms(&self) -> Terms {
        self.fallback.terms()
    }

    fn elect(&self, round: Round, input: Input<'_, S, Self>) -> Participant {
        let scripted = self
            .script
            .place(round.view(), self.fallback.terms().length())
            .and_then(|place| usize::try_from(place).ok())
            .and_then(|place| self.leaders.get(place).copied());
        scripted.unwrap_or_else(|| self.fallback.elect(round, input))
    }
}

/// Where the outbound half of a split channel sends a message that is
/// partitioned by its view, given the identities the half's partition admits
/// at that view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Addressing {
    /// To the whole partition, whoever the engine addressed.
    Partition,
    /// To the recipients the engine addressed that the partition admits: a
    /// broadcast reaches the partition, a send to some identities reaches
    /// those of them it admits, and a send to one identity it does not admit
    /// reaches no one.
    // Only the DKG harness narrows.
    #[cfg_attr(not(feature = "dkg"), allow(dead_code))]
    Narrowed,
}

impl Addressing {
    /// The recipients of a message the engine addressed to `intended`, for a
    /// half whose partition admits `partition`.
    pub(crate) fn recipients(
        self,
        intended: &Recipients<PublicKey>,
        partition: Vec<PublicKey>,
    ) -> Recipients<PublicKey> {
        match (self, intended) {
            (Self::Partition, _) | (Self::Narrowed, Recipients::All) => Recipients::Some(partition),
            (Self::Narrowed, Recipients::Some(peers)) => Recipients::Some(
                peers
                    .iter()
                    .filter(|peer| partition.contains(peer))
                    .cloned()
                    .collect(),
            ),
            (Self::Narrowed, Recipients::One(peer)) if partition.contains(peer) => {
                Recipients::One(peer.clone())
            }
            (Self::Narrowed, Recipients::One(_)) => Recipients::Some(Vec::new()),
        }
    }
}

/// Build the outbound half of a split channel, which sends a message that is
/// partitioned by its view to the half's whole partition.
pub(crate) fn forwarder(
    participants: Arc<[PublicKey]>,
    scenario: TwinsScript,
    term_length: TermLength,
    classify: impl Fn(&IoBuf) -> Routing + Send + Sync + Clone + 'static,
) -> impl Fn(SplitOrigin, &Recipients<PublicKey>, &IoBuf) -> Option<Recipients<PublicKey>>
+ Send
+ Sync
+ Clone
+ 'static {
    addressed_forwarder(
        participants,
        scenario,
        term_length,
        Addressing::Partition,
        classify,
    )
}

/// Build the outbound half of a split channel, which sends a message that is
/// partitioned by its view where `addressing` says.
pub(crate) fn addressed_forwarder(
    participants: Arc<[PublicKey]>,
    scenario: TwinsScript,
    term_length: TermLength,
    addressing: Addressing,
    classify: impl Fn(&IoBuf) -> Routing + Send + Sync + Clone + 'static,
) -> impl Fn(SplitOrigin, &Recipients<PublicKey>, &IoBuf) -> Option<Recipients<PublicKey>>
+ Send
+ Sync
+ Clone
+ 'static {
    move |origin, intended, message| match classify(message) {
        Routing::Partition(view) => {
            let (primary, secondary) =
                scenario.partitions(view, term_length, participants.as_ref());
            Some(addressing.recipients(
                intended,
                match origin {
                    SplitOrigin::Primary => primary,
                    SplitOrigin::Secondary => secondary,
                },
            ))
        }
        Routing::Viewless => Some(intended.clone()),
        Routing::Undecodable => None,
    }
}

/// Build the inbound half of a split channel.
pub(crate) fn router(
    participants: Arc<[PublicKey]>,
    scenario: TwinsScript,
    term_length: TermLength,
    classify: impl Fn(&IoBuf) -> Routing + Send + Sync + 'static,
) -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    move |(sender, message)| match classify(message) {
        Routing::Partition(view) => {
            scenario.route(view, term_length, sender, participants.as_ref())
        }
        Routing::Viewless => SplitTarget::Both,
        Routing::Undecodable => SplitTarget::None,
    }
}

macro_rules! channel {
    ($forward:ident, $route:ident, $classify:expr) => {
        pub(super) fn $forward<M: Marshal>(
            participants: Arc<[PublicKey]>,
            scenario: TwinsScript,
            term_length: TermLength,
        ) -> impl Fn(SplitOrigin, &Recipients<PublicKey>, &IoBuf) -> Option<Recipients<PublicKey>>
        + Send
        + Sync
        + Clone
        + 'static {
            forwarder(participants, scenario, term_length, $classify)
        }

        pub(super) fn $route<M: Marshal>(
            participants: Arc<[PublicKey]>,
            scenario: TwinsScript,
            term_length: TermLength,
        ) -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
            router(participants, scenario, term_length, $classify)
        }
    };
}

channel!(
    vote_forwarder,
    vote_router,
    vote_routing::<Scheme, M::Payload>
);
channel!(
    broadcast_forwarder,
    broadcast_router,
    broadcast_routing::<M>
);

pub(super) fn backfill_forwarder(
    participants: Arc<[PublicKey]>,
    scenario: TwinsScript,
    term_length: TermLength,
) -> impl Fn(SplitOrigin, &Recipients<PublicKey>, &IoBuf) -> Option<Recipients<PublicKey>>
+ Send
+ Sync
+ Clone
+ 'static {
    forwarder(participants, scenario, term_length, backfill_routing)
}

pub(super) fn backfill_router(
    participants: Arc<[PublicKey]>,
    scenario: TwinsScript,
    term_length: TermLength,
) -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    router(participants, scenario, term_length, backfill_routing)
}

pub(super) fn certificate_forwarder<M: Marshal>(
    participants: Arc<[PublicKey]>,
    scenario: TwinsScript,
    term_length: TermLength,
    scheme: Scheme,
) -> impl Fn(SplitOrigin, &Recipients<PublicKey>, &IoBuf) -> Option<Recipients<PublicKey>>
+ Send
+ Sync
+ Clone
+ 'static {
    let codec = scheme.certificate_codec_config();
    forwarder(participants, scenario, term_length, move |message| {
        certificate_routing::<Scheme, M::Payload>(message, &codec)
    })
}

pub(super) fn certificate_router<M: Marshal>(
    participants: Arc<[PublicKey]>,
    scenario: TwinsScript,
    term_length: TermLength,
    scheme: Scheme,
) -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    let codec = scheme.certificate_codec_config();
    router(participants, scenario, term_length, move |message| {
        certificate_routing::<Scheme, M::Payload>(message, &codec)
    })
}

pub(super) fn resolver_forwarder<M: Marshal>(
    participants: Arc<[PublicKey]>,
    scenario: TwinsScript,
    term_length: TermLength,
    scheme: Scheme,
) -> impl Fn(SplitOrigin, &Recipients<PublicKey>, &IoBuf) -> Option<Recipients<PublicKey>>
+ Send
+ Sync
+ Clone
+ 'static {
    let codec = scheme.certificate_codec_config();
    forwarder(participants, scenario, term_length, move |message| {
        simplex_resolver_routing::<Scheme, M::Payload>(message, &codec)
    })
}

pub(super) fn resolver_router<M: Marshal>(
    participants: Arc<[PublicKey]>,
    scenario: TwinsScript,
    term_length: TermLength,
    scheme: Scheme,
) -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    let codec = scheme.certificate_codec_config();
    router(participants, scenario, term_length, move |message| {
        simplex_resolver_routing::<Scheme, M::Payload>(message, &codec)
    })
}

/// The router of a channel whose messages carry no view, such as the
/// database-sync channel: both halves receive every inbound message.
pub(crate) fn shared_router() -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static
{
    |_| SplitTarget::Both
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_consensus::{simplex::elector::RoundRobin, types::Epoch};
    use commonware_cryptography::{Sha256, Signer as _, ed25519::PrivateKey};
    use commonware_utils::NZU32;

    const ONE: TermLength = TermLength::ONE;

    fn identities(count: usize) -> Vec<PublicKey> {
        (0..count as u64)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect()
    }

    /// The script of `prefix` among `participants` identities.
    fn script(participants: usize, prefix: Option<u8>, sustained: bool) -> TwinsScript {
        TwinsScript::select(vec![7; 64], participants, prefix, sustained, 3)
            .expect("the generator yields cases")
            .1
    }

    #[test]
    fn prefix_within_one_part_is_the_generated_scenario() {
        let identities = identities(4);
        for sustained in [false, true] {
            for term in [1, 3] {
                let term = TermLength::new(NZU32!(term));
                let (compromised, scenario) =
                    select_case(vec![7; 64], identities.len(), 3, sustained, 3)
                        .expect("the generator yields cases");
                let (identity, script) =
                    TwinsScript::select(vec![7; 64], identities.len(), Some(3), sustained, 3)
                        .expect("the generator yields cases");
                assert_eq!(identity, compromised);
                assert_eq!(script.rounds(), 3);
                for view in (0..=4 * term.get()).map(View::new) {
                    assert_eq!(
                        script.partitions(view, term, &identities),
                        scenario.partitions(view, term, &identities)
                    );
                    for sender in &identities {
                        assert_eq!(
                            script.route(view, term, sender, &identities),
                            scenario.route(view, term, sender, &identities)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn every_prefix_scripts_that_many_rounds_and_no_more() {
        let term = TermLength::new(NZU32!(3));
        for participants in [4, 5] {
            for sustained in [false, true] {
                for rounds in 1..=MAX_PREFIX_ROUNDS {
                    let script = script(participants, Some(rounds), sustained);
                    let rounds = u64::from(rounds);
                    assert!(!script.repeats);
                    assert_eq!(script.rounds(), rounds);
                    assert_eq!(script.leaders().count() as u64, rounds);
                    assert_eq!(script.place(View::new(rounds), ONE), Some(rounds - 1));
                    assert_eq!(script.place(View::new(rounds + 1), ONE), None);
                    assert_eq!(script.scripted_through(ONE), View::new(rounds));
                    assert_eq!(script.place(View::new(3 * rounds), term), Some(rounds - 1));
                    assert_eq!(script.place(View::new(3 * rounds + 1), term), None);
                    assert_eq!(script.scripted_through(term), View::new(3 * rounds));
                }
            }
        }

        // Past the prefix both halves exchange messages with everyone.
        let identities = identities(4);
        let script = script(identities.len(), Some(5), false);
        let whole = (identities.clone(), identities.clone());
        for view in [6, 600] {
            assert_eq!(script.partitions(View::new(view), ONE, &identities), whole);
            assert_eq!(
                script.route(View::new(view), ONE, &identities[0], &identities),
                SplitTarget::Both
            );
        }
    }

    #[test]
    fn prefix_outside_the_drawn_range_is_brought_into_it() {
        assert_eq!(script(4, Some(0), false).rounds(), 1);
        assert_eq!(
            script(4, Some(u8::MAX), false).rounds(),
            u64::from(MAX_PREFIX_ROUNDS)
        );
    }

    #[test]
    fn script_without_a_prefix_scripts_every_round() {
        let identities = identities(4);
        let rounds = u64::from(MAX_PREFIX_ROUNDS);
        for sustained in [false, true] {
            let script = script(identities.len(), None, sustained);
            assert!(script.repeats);
            assert_eq!(script.rounds(), rounds);
            for term in [1, 2] {
                let length = TermLength::new(NZU32!(term));
                let term = u64::from(term);
                for view in 1..=3 * rounds * term {
                    assert_eq!(
                        script.place(View::new(view), length),
                        Some((view - 1) / term % rounds)
                    );
                    assert_eq!(
                        script.partitions(View::new(view), length, &identities),
                        script.partitions(View::new(view + rounds * term), length, &identities)
                    );
                }
            }
        }

        // The same script with a prefix ends where the one without starts
        // over.
        let bounded = script(identities.len(), Some(MAX_PREFIX_ROUNDS), false);
        let endless = script(identities.len(), None, false);
        for view in (1..=rounds).map(View::new) {
            assert_eq!(
                bounded.partitions(view, ONE, &identities),
                endless.partitions(view, ONE, &identities)
            );
        }
    }

    #[test]
    fn sustained_script_repeats_one_partition() {
        let identities = identities(5);
        let script = script(identities.len(), Some(MAX_PREFIX_ROUNDS), true);
        let first = script.partitions(View::new(1), ONE, &identities);
        for view in 2..=u64::from(MAX_PREFIX_ROUNDS) {
            assert_eq!(script.partitions(View::new(view), ONE, &identities), first);
        }
    }

    #[test]
    fn later_part_of_a_sampled_script_is_drawn_on_its_own() {
        let identities = identities(4);
        let script = script(identities.len(), Some(MAX_PREFIX_ROUNDS), false);
        let part = u64::from(PART_ROUNDS);
        assert!(
            (1..=part).any(|view| {
                script.partitions(View::new(view), ONE, &identities)
                    != script.partitions(View::new(view + part), ONE, &identities)
            }),
            "the second part repeats the first"
        );
    }

    /// The peers `recipients` names, and whether it names one peer.
    fn named(recipients: Option<Recipients<PublicKey>>) -> (bool, Vec<PublicKey>) {
        match recipients.expect("the message is sent") {
            Recipients::One(peer) => (true, vec![peer]),
            Recipients::Some(peers) => (false, peers),
            Recipients::All => panic!("a partitioned message is never broadcast"),
        }
    }

    /// The stateful channels send a message partitioned by its view to the
    /// half's whole partition, whoever the engine addressed; a narrowed
    /// channel keeps the engine's recipients within the partition.
    #[test]
    fn partitioned_message_goes_where_the_addressing_says() {
        let identities = identities(4);
        let partition = vec![identities[0].clone(), identities[2].clone()];
        let (inside, outside) = (identities[2].clone(), identities[1].clone());
        let intended = [
            Recipients::All,
            Recipients::Some(vec![outside.clone(), inside.clone()]),
            Recipients::One(inside.clone()),
            Recipients::One(outside.clone()),
        ];
        let whole: Vec<_> = intended
            .iter()
            .map(|intended| {
                named(Some(
                    Addressing::Partition.recipients(intended, partition.clone()),
                ))
            })
            .collect();
        assert!(whole.iter().all(|sent| *sent == (false, partition.clone())));
        let narrowed: Vec<_> = intended
            .iter()
            .map(|intended| {
                named(Some(
                    Addressing::Narrowed.recipients(intended, partition.clone()),
                ))
            })
            .collect();
        assert_eq!(
            narrowed,
            vec![
                (false, partition.clone()),
                (false, vec![inside.clone()]),
                (true, vec![inside]),
                (false, Vec::new()),
            ]
        );

        // The stateful forwarder sends a targeted message at a scripted view
        // to the whole partition of the half.
        let script = script(identities.len(), Some(1), false);
        let participants: Arc<[PublicKey]> = identities.clone().into();
        let forward = forwarder(participants, script.clone(), ONE, |_: &IoBuf| {
            Routing::Partition(View::new(1))
        });
        let (primary, secondary) = script.partitions(View::new(1), ONE, &identities);
        for (origin, partition) in [
            (SplitOrigin::Primary, primary),
            (SplitOrigin::Secondary, secondary),
        ] {
            for peer in &identities {
                let sent = forward(origin, &Recipients::One(peer.clone()), &IoBuf::default());
                assert_eq!(named(sent), (false, partition.clone()));
            }
        }
    }

    #[test]
    fn scripted_elector_follows_the_script_and_then_the_fallback() {
        let identities = identities(4);
        let participants = Set::from_iter_dedup(identities.iter().cloned());
        let fallback =
            elector::Config::<Scheme>::build(RoundRobin::<Sha256>::default(), &participants);
        let elect = |script: &TwinsScript, view: u64| {
            let elector = elector::Config::<Scheme>::build(
                Scripted::new(RoundRobin::<Sha256>::default(), script.clone()),
                &participants,
            );
            elector::Elector::elect(&elector, Round::new(Epoch::zero(), View::new(view)), ())
        };

        // A script with a prefix names the leaders of its rounds only.
        let bounded = script(identities.len(), Some(5), false);
        let leaders: Vec<usize> = bounded.leaders().collect();
        for (place, leader) in leaders.iter().enumerate() {
            assert_eq!(
                elect(&bounded, place as u64 + 1),
                Participant::from_usize(*leader)
            );
        }
        let round = Round::new(Epoch::zero(), View::new(6));
        assert_eq!(
            elect(&bounded, 6),
            elector::Elector::elect(&fallback, round, ())
        );

        // A script without one names the leader of every round.
        let endless = script(identities.len(), None, false);
        let leaders: Vec<usize> = endless.leaders().collect();
        for view in 1..=3 * leaders.len() as u64 {
            assert_eq!(
                elect(&endless, view),
                Participant::from_usize(leaders[(view as usize - 1) % leaders.len()])
            );
        }
    }
}
