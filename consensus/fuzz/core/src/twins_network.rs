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
use commonware_cryptography::{Digest, certificate::Verifier};
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

/// Narrows a twin half's intended recipients to the identities its mask admits:
/// a broadcast becomes the mask, a targeted send keeps the targets inside the
/// mask and reaches no one when none remain.
pub fn within_mask<P: commonware_cryptography::PublicKey>(
    intended: &Recipients<P>,
    mask: Vec<P>,
) -> Recipients<P> {
    match intended {
        Recipients::All => Recipients::Some(mask),
        Recipients::Some(peers) => Recipients::Some(
            peers
                .iter()
                .filter(|peer| mask.contains(peer))
                .cloned()
                .collect(),
        ),
        Recipients::One(peer) if mask.contains(peer) => Recipients::One(peer.clone()),
        Recipients::One(_) => Recipients::Some(Vec::new()),
    }
}

pub fn resolver_view<P: simplex::Simplex, D: Digest>(
    message: &IoBuf,
    codec: &<<P::Scheme as Verifier>::Certificate as Read>::Cfg,
) -> Option<View> {
    let message = ResolverMessage::<U64>::decode(message.clone()).ok()?;
    match message.payload {
        ResolverPayload::Request(key) => Some(View::new(u64::from(key))),
        ResolverPayload::Response(bytes) => {
            let certificate = Certificate::<P::Scheme, D>::decode_cfg(bytes, codec).ok()?;
            Some(certificate.view())
        }
        ResolverPayload::Error => None,
    }
}

pub(crate) fn vote_forwarder<P: simplex::Simplex, D: Digest>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
) -> impl Fn(SplitOrigin, &TwinRecipients<P>, &IoBuf) -> ForwardedRecipients<P>
+ Send
+ Sync
+ Clone
+ 'static {
    move |origin, intended, message| {
        let vote = Vote::<P::Scheme, D>::decode(message.clone()).ok()?;
        let (primary, secondary) =
            scenario.partitions(vote.view(), term_length, participants.as_ref());
        let mask = match origin {
            SplitOrigin::Primary => primary,
            SplitOrigin::Secondary => secondary,
        };
        Some(within_mask(intended, mask))
    }
}

pub(crate) fn certificate_forwarder<P: simplex::Simplex, D: Digest>(
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
    move |origin, intended, message| {
        let certificate = Certificate::<P::Scheme, D>::decode_cfg(message.clone(), &codec).ok()?;
        let (primary, secondary) =
            scenario.partitions(certificate.view(), term_length, participants.as_ref());
        let mask = match origin {
            SplitOrigin::Primary => primary,
            SplitOrigin::Secondary => secondary,
        };
        Some(within_mask(intended, mask))
    }
}

pub(crate) fn vote_router<P: simplex::Simplex, D: Digest>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
) -> impl Fn(&(<P::Scheme as Verifier>::PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    move |(sender, message)| {
        let Ok(vote) = Vote::<P::Scheme, D>::decode(message.clone()) else {
            return SplitTarget::None;
        };
        scenario.route(vote.view(), term_length, sender, participants.as_ref())
    }
}

pub(crate) fn certificate_router<P: simplex::Simplex, D: Digest>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
    scheme: P::Scheme,
) -> impl Fn(&(<P::Scheme as Verifier>::PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    let codec = scheme.certificate_codec_config();
    move |(sender, message)| {
        let Ok(certificate) = Certificate::<P::Scheme, D>::decode_cfg(message.clone(), &codec)
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

pub(crate) fn resolver_forwarder<P: simplex::Simplex, D: Digest>(
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
    move |origin, intended, message| {
        let view = resolver_view::<P, D>(message, &codec)?;
        let (primary, secondary) = scenario.partitions(view, term_length, participants.as_ref());
        let mask = match origin {
            SplitOrigin::Primary => primary,
            SplitOrigin::Secondary => secondary,
        };
        Some(within_mask(intended, mask))
    }
}

pub(crate) fn resolver_router<P: simplex::Simplex, D: Digest>(
    participants: Arc<[<P::Scheme as Verifier>::PublicKey]>,
    scenario: Scenario,
    term_length: TermLength,
    scheme: P::Scheme,
) -> impl Fn(&(<P::Scheme as Verifier>::PublicKey, IoBuf)) -> SplitTarget + Send + Sync + 'static {
    let codec = scheme.certificate_codec_config();
    move |(sender, message)| {
        let Some(view) = resolver_view::<P, D>(message, &codec) else {
            return SplitTarget::None;
        };
        scenario.route(view, term_length, sender, participants.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::within_mask;
    use commonware_p2p::Recipients;

    #[test]
    fn within_mask_keeps_targets_inside_the_mask() {
        let keys = crate::simplex_certificate_mock::fixture(
            &mut commonware_utils::test_rng(),
            b"twins_within_mask",
            4,
        )
        .participants;
        let mask = vec![keys[1].clone(), keys[2].clone()];
        let peers = |recipients| match recipients {
            Recipients::Some(peers) => peers,
            Recipients::One(peer) => vec![peer],
            Recipients::All => panic!("a broadcast must become the mask"),
        };

        assert_eq!(peers(within_mask(&Recipients::All, mask.clone())), mask);
        assert_eq!(
            peers(within_mask(
                &Recipients::Some(vec![keys[2].clone(), keys[0].clone(), keys[1].clone()]),
                mask.clone(),
            )),
            vec![keys[2].clone(), keys[1].clone()]
        );
        assert!(matches!(
            within_mask(&Recipients::One(keys[2].clone()), mask.clone()),
            Recipients::One(ref peer) if *peer == keys[2]
        ));
        assert!(peers(within_mask(&Recipients::One(keys[3].clone()), mask)).is_empty());
    }
}
