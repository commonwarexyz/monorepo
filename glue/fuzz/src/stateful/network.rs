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
//!   halves the scenario admits its sender for.
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

use super::{Digest, MAX_CASES, PREFIX_ROUNDS, PublicKey, Scheme, marshal::Marshal};
use commonware_codec::{Decode, DecodeExt, Read};
use commonware_consensus::{
    Viewable,
    marshal::resolver::handler::Key as BackfillKey,
    simplex::{
        mocks::twins::{self, Scenario},
        types::{Certificate, Vote},
    },
    types::{TermLength, View},
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
use commonware_utils::{FuzzRng, sequence::U64};
use std::sync::Arc;

/// Draw the twins cases from `entropy` and select one.
///
/// Returns the compromised identity and its scenario, or `None` if the
/// generator produced no case.
pub(crate) fn select_case(
    entropy: Vec<u8>,
    participants: usize,
    sustained: bool,
    case_selector: u16,
) -> Option<(usize, Scenario)> {
    let mut scenario_rng = FuzzRng::new(entropy);
    let cases = twins::cases(
        &mut scenario_rng,
        twins::Framework {
            participants,
            faults: 1,
            rounds: PREFIX_ROUNDS,
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

/// Build the outbound half of a split channel.
pub(crate) fn forwarder(
    participants: Arc<[PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
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
            Some(match origin {
                SplitOrigin::Primary => Recipients::Some(primary),
                SplitOrigin::Secondary => Recipients::Some(secondary),
            })
        }
        Routing::Viewless => Some(intended.clone()),
        Routing::Undecodable => None,
    }
}

/// Build the inbound half of a split channel.
pub(crate) fn router(
    participants: Arc<[PublicKey]>,
    scenario: Scenario,
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
            scenario: Scenario,
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
            scenario: Scenario,
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
    scenario: Scenario,
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
    scenario: Scenario,
    term_length: TermLength,
) -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    router(participants, scenario, term_length, backfill_routing)
}

pub(super) fn certificate_forwarder<M: Marshal>(
    participants: Arc<[PublicKey]>,
    scenario: Scenario,
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
    scenario: Scenario,
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
    scenario: Scenario,
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
    scenario: Scenario,
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
