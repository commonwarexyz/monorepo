//! Shared Simplex Twins channel-routing helpers.
//!
//! Both the generic Simplex campaigns and marshal-backed campaigns use these
//! factories so twin halves are split and routed with identical semantics.
//! Routing is intentionally type-aware: payloads without a decodable protocol
//! view are rejected because no Twins partition can be selected for them.

use crate::simplex;
use commonware_codec::{Decode, DecodeExt, Read};
use commonware_consensus::{
    Viewable,
    simplex::{
        mocks::twins::Scenario,
        types::{Certificate, Vote},
    },
    types::{TermLength, View},
};
use commonware_cryptography::{certificate::Verifier, sha256::Digest as Sha256Digest};
use commonware_p2p::{
    Recipients,
    simulated::{SplitOrigin, SplitTarget},
};
use commonware_resolver::p2p::mocks::{Message as ResolverMessage, Payload as ResolverPayload};
use commonware_runtime::IoBuf;
use commonware_utils::sequence::U64;
use std::sync::Arc;

type PublicKey<P> = <<P as simplex::Simplex>::Scheme as Verifier>::PublicKey;
type TwinRecipients<P> = Recipients<PublicKey<P>>;
type ForwardedRecipients<P> = Option<TwinRecipients<P>>;

pub(crate) fn resolver_view<P: simplex::Simplex>(
    message: &IoBuf,
    codec: &<<P::Scheme as Verifier>::Certificate as Read>::Cfg,
) -> Option<View> {
    let message = ResolverMessage::<U64>::decode(message.clone()).ok()?;
    match message.payload {
        ResolverPayload::Request(key) => Some(View::new(u64::from(key))),
        ResolverPayload::Response(bytes) => {
            let certificate =
                Certificate::<P::Scheme, Sha256Digest>::decode_cfg(&mut bytes.as_ref(), codec)
                    .ok()?;
            Some(certificate.view())
        }
        ResolverPayload::Error => None,
    }
}

pub(crate) fn vote_forwarder<P: simplex::Simplex>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
) -> impl Fn(SplitOrigin, &TwinRecipients<P>, &IoBuf) -> ForwardedRecipients<P>
+ Send
+ Sync
+ Clone
+ 'static {
    move |origin, _, message| {
        let vote = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()).ok()?;
        let (primary, secondary) =
            scenario.partitions(vote.view(), term_length, participants.as_ref());
        match origin {
            SplitOrigin::Primary => Some(Recipients::Some(primary)),
            SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
        }
    }
}

pub(crate) fn certificate_forwarder<P: simplex::Simplex>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
    scheme: P::Scheme,
) -> impl Fn(SplitOrigin, &TwinRecipients<P>, &IoBuf) -> ForwardedRecipients<P>
+ Send
+ Sync
+ Clone
+ 'static {
    let codec = scheme.certificate_codec_config();
    move |origin, _, message| {
        let certificate =
            Certificate::<P::Scheme, Sha256Digest>::decode_cfg(&mut message.as_ref(), &codec)
                .ok()?;
        let (primary, secondary) =
            scenario.partitions(certificate.view(), term_length, participants.as_ref());
        match origin {
            SplitOrigin::Primary => Some(Recipients::Some(primary)),
            SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
        }
    }
}

pub(crate) fn vote_router<P: simplex::Simplex>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
) -> impl Fn(&(<P::Scheme as Verifier>::PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    move |(sender, message)| {
        let Ok(vote) = Vote::<P::Scheme, Sha256Digest>::decode(message.clone()) else {
            return SplitTarget::None;
        };
        scenario.route(vote.view(), term_length, sender, participants.as_ref())
    }
}

pub(crate) fn certificate_router<P: simplex::Simplex>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
    scheme: P::Scheme,
) -> impl Fn(&(<P::Scheme as Verifier>::PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    let codec = scheme.certificate_codec_config();
    move |(sender, message)| {
        let Ok(certificate) =
            Certificate::<P::Scheme, Sha256Digest>::decode_cfg(&mut message.as_ref(), &codec)
        else {
            return SplitTarget::None;
        };
        scenario.route(
            certificate.view(),
            term_length,
            sender,
            participants.as_ref(),
        )
    }
}

pub(crate) fn resolver_forwarder<P: simplex::Simplex>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
    scheme: P::Scheme,
) -> impl Fn(SplitOrigin, &TwinRecipients<P>, &IoBuf) -> ForwardedRecipients<P>
+ Send
+ Sync
+ Clone
+ 'static {
    let codec = scheme.certificate_codec_config();
    move |origin, _, message| {
        let view = resolver_view::<P>(message, &codec)?;
        let (primary, secondary) = scenario.partitions(view, term_length, participants.as_ref());
        match origin {
            SplitOrigin::Primary => Some(Recipients::Some(primary)),
            SplitOrigin::Secondary => Some(Recipients::Some(secondary)),
        }
    }
}

pub(crate) fn resolver_router<P: simplex::Simplex>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
    scheme: P::Scheme,
) -> impl Fn(&(<P::Scheme as Verifier>::PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    let codec = scheme.certificate_codec_config();
    move |(sender, message)| {
        let Some(view) = resolver_view::<P>(message, &codec) else {
            return SplitTarget::None;
        };
        scenario.route(view, term_length, sender, participants.as_ref())
    }
}
