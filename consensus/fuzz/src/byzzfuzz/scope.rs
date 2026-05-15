//! Message-kind filters applied to *process* faults. Network faults are total
//! at their view and do not use this type.

use commonware_consensus::simplex::types::{Certificate, Vote};
use commonware_cryptography::{sha256::Digest as Sha256Digest, PublicKey};
use rand::Rng;

/// `MessageScope::Any` weight in [`sample`].
const ANY_SCOPE_WEIGHT: u32 = 50;
/// `MessageScope::Vote(_)` weight in [`sample`] (uniform over [`VOTE_KINDS`]).
const VOTE_SCOPE_WEIGHT: u32 = 45;
/// `MessageScope::Certificate(_)` weight in [`sample`] (uniform over
/// [`CERTIFICATE_KINDS`]).
const CERTIFICATE_SCOPE_WEIGHT: u32 = 5;
const TOTAL_SCOPE_WEIGHT: u32 = ANY_SCOPE_WEIGHT + VOTE_SCOPE_WEIGHT + CERTIFICATE_SCOPE_WEIGHT;

/// All [`VoteKind`] variants, sampled uniformly when [`sample`] picks the
/// `Vote(_)` bucket. Add new variants here so the sampler covers them.
const VOTE_KINDS: [VoteKind; 3] = [VoteKind::Notarize, VoteKind::Finalize, VoteKind::Nullify];

/// All [`CertificateKind`] variants, sampled uniformly when [`sample`] picks
/// the `Certificate(_)` bucket. Add new variants here so the sampler
/// covers them.
const CERTIFICATE_KINDS: [CertificateKind; 3] = [
    CertificateKind::Notarization,
    CertificateKind::Nullification,
    CertificateKind::Finalization,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteKind {
    Notarize,
    Finalize,
    Nullify,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateKind {
    Notarization,
    Nullification,
    Finalization,
}

/// Process-fault message-kind filter. `Any` adds no channel/kind restriction;
/// typed variants narrow the match to a single channel + message kind.
/// `ProcessAction` still limits which channels can execute the matched fault.
/// Resolver kinds are intentionally not yet sampled.
#[derive(Clone, Copy, Debug, Default)]
pub enum MessageScope {
    #[default]
    Any,
    Vote(VoteKind),
    Certificate(CertificateKind),
}

impl MessageScope {
    pub fn matches_vote(self, kind: VoteKind) -> bool {
        match self {
            MessageScope::Any => true,
            MessageScope::Vote(k) => k == kind,
            _ => false,
        }
    }

    pub fn matches_certificate(self, kind: CertificateKind) -> bool {
        match self {
            MessageScope::Any => true,
            MessageScope::Certificate(k) => k == kind,
            _ => false,
        }
    }

    /// Resolver currently only respects `Any` scopes.
    pub fn matches_resolver(self) -> bool {
        matches!(self, MessageScope::Any)
    }
}

/// Sample a fault scope. Buckets are weighted by [`ANY_SCOPE_WEIGHT`],
/// [`VOTE_SCOPE_WEIGHT`], [`CERTIFICATE_SCOPE_WEIGHT`]; within the
/// `Vote(_)` and `Certificate(_)` buckets the kind is drawn uniformly from
/// [`VOTE_KINDS`] / [`CERTIFICATE_KINDS`] so a new variant added to either
/// list is automatically covered.
pub fn sample(rng: &mut impl Rng) -> MessageScope {
    let bucket = rng.gen_range(0..TOTAL_SCOPE_WEIGHT);
    if bucket < ANY_SCOPE_WEIGHT {
        MessageScope::Any
    } else if bucket < ANY_SCOPE_WEIGHT + VOTE_SCOPE_WEIGHT {
        let k = VOTE_KINDS[rng.gen_range(0..VOTE_KINDS.len())];
        MessageScope::Vote(k)
    } else {
        let k = CERTIFICATE_KINDS[rng.gen_range(0..CERTIFICATE_KINDS.len())];
        MessageScope::Certificate(k)
    }
}

pub fn vote_kind<S, P>(vote: &Vote<S, Sha256Digest>) -> VoteKind
where
    S: commonware_consensus::simplex::scheme::Scheme<Sha256Digest, PublicKey = P>,
    P: PublicKey,
{
    match vote {
        Vote::Notarize(_) => VoteKind::Notarize,
        Vote::Finalize(_) => VoteKind::Finalize,
        Vote::Nullify(_) => VoteKind::Nullify,
    }
}

pub fn certificate_kind<S, P>(cert: &Certificate<S, Sha256Digest>) -> CertificateKind
where
    S: commonware_consensus::simplex::scheme::Scheme<Sha256Digest, PublicKey = P>,
    P: PublicKey,
{
    match cert {
        Certificate::Notarization(_) => CertificateKind::Notarization,
        Certificate::Nullification(_) => CertificateKind::Nullification,
        Certificate::Finalization(_) => CertificateKind::Finalization,
    }
}
