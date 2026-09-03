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
//! rule.

// The mock certificate scheme's codec configuration is a unit value; the
// bindings below stay so the shape survives a scheme whose configuration is not.
#![allow(clippy::let_unit_value)]

use super::{Digest, PublicKey, Scheme, app::Block};
use commonware_codec::{Decode, DecodeExt, Read};
use commonware_consensus::{
    Viewable,
    marshal::resolver::handler::Key as BackfillKey,
    simplex::{
        mocks::twins::Scenario,
        types::{Certificate, Vote},
    },
    types::{TermLength, View},
};
use commonware_cryptography::certificate::Verifier;
use commonware_p2p::{
    Recipients,
    simulated::{SplitOrigin, SplitTarget},
};
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::IoBuf;
use commonware_utils::sequence::U64;
use std::sync::Arc;

/// Codec configuration for decoding certificates off the wire.
type CertificateCfg = <<Scheme as Verifier>::Certificate as Read>::Cfg;

/// How one message is to be routed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Routing {
    /// The message belongs to this view and is partitioned by it.
    Partition(View),
    /// The message decodes but names no view.
    Viewless,
    /// The message does not decode.
    Undecodable,
}

/// Classify a message on the vote channel.
fn vote_routing(message: &IoBuf) -> Routing {
    Vote::<Scheme, Digest>::decode(message.clone())
        .map_or(Routing::Undecodable, |vote| Routing::Partition(vote.view()))
}

/// Classify a message on the certificate channel.
fn certificate_routing(message: &IoBuf, codec: &CertificateCfg) -> Routing {
    Certificate::<Scheme, Digest>::decode_cfg(&mut message.as_ref(), codec)
        .map_or(Routing::Undecodable, |certificate| {
            Routing::Partition(certificate.view())
        })
}

/// Classify a message on the simplex resolver channel.
///
/// A request names its view directly. A response carries a certificate, whose
/// view is the one it answers for. An error names nothing.
fn simplex_resolver_routing(message: &IoBuf, codec: &CertificateCfg) -> Routing {
    let Ok(message) = ResolverMessage::<U64>::decode(message.clone()) else {
        return Routing::Undecodable;
    };
    match message.payload {
        ResolverPayload::Request(key) => Routing::Partition(View::new(u64::from(key))),
        ResolverPayload::Response(bytes) => {
            Certificate::<Scheme, Digest>::decode_cfg(&mut bytes.as_ref(), codec)
                .map_or(Routing::Undecodable, |certificate| {
                    Routing::Partition(certificate.view())
                })
        }
        ResolverPayload::Error => Routing::Viewless,
    }
}

/// Classify a message on the marshal backfill channel.
///
/// Only a request for a notarized proposal names a round; requests addressed by
/// block digest or by height, and every response, name no view.
fn backfill_routing(message: &IoBuf) -> Routing {
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

/// Classify a message on the block broadcast channel. A broadcast payload is a
/// bare block, whose embedded consensus context names its round.
fn broadcast_routing(message: &IoBuf) -> Routing {
    Block::decode(message.clone()).map_or(Routing::Undecodable, |block| {
        Routing::Partition(block.context.round.view())
    })
}

/// Build the outbound half of a split channel.
fn forwarder(
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
fn router(
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
        pub(super) fn $forward(
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

        pub(super) fn $route(
            participants: Arc<[PublicKey]>,
            scenario: Scenario,
            term_length: TermLength,
        ) -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
            router(participants, scenario, term_length, $classify)
        }
    };
}

channel!(vote_forwarder, vote_router, vote_routing);
channel!(backfill_forwarder, backfill_router, backfill_routing);
channel!(broadcast_forwarder, broadcast_router, broadcast_routing);

pub(super) fn certificate_forwarder(
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
        certificate_routing(message, &codec)
    })
}

pub(super) fn certificate_router(
    participants: Arc<[PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
    scheme: Scheme,
) -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    let codec = scheme.certificate_codec_config();
    router(participants, scenario, term_length, move |message| {
        certificate_routing(message, &codec)
    })
}

pub(super) fn resolver_forwarder(
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
        simplex_resolver_routing(message, &codec)
    })
}

pub(super) fn resolver_router(
    participants: Arc<[PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
    scheme: Scheme,
) -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    let codec = scheme.certificate_codec_config();
    router(participants, scenario, term_length, move |message| {
        simplex_resolver_routing(message, &codec)
    })
}

/// The database-sync channel carries no view, so both halves receive every
/// inbound message.
pub(super) fn shared_router() -> impl Fn(&(PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static
{
    |_| SplitTarget::Both
}
