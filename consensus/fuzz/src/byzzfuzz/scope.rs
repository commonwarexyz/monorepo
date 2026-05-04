//! `FaultScope`: an optional message-kind filter applied to *process* faults
//! to narrow which intercepted byzantine messages a fault matches.
//! Network faults are total at their view and do not use this type.

use commonware_consensus::simplex::types::{Certificate, Vote};
use commonware_cryptography::{sha256::Digest as Sha256Digest, PublicKey};
use rand::Rng;

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

/// Process-fault message-kind filter. `Any` matches every byzantine
/// outgoing message when the sender's `rnd(m)` equals the fault's view;
/// the typed variants additionally narrow the match to a single
/// channel + message kind. Resolver kinds are intentionally not yet
/// sampled.
#[derive(Clone, Copy, Debug, Default)]
pub enum FaultScope {
    #[default]
    Any,
    Vote(VoteKind),
    Certificate(CertificateKind),
}

impl FaultScope {
    pub fn matches_vote(self, kind: VoteKind) -> bool {
        match self {
            FaultScope::Any => true,
            FaultScope::Vote(k) => k == kind,
            _ => false,
        }
    }

    pub fn matches_certificate(self, kind: CertificateKind) -> bool {
        match self {
            FaultScope::Any => true,
            FaultScope::Certificate(k) => k == kind,
            _ => false,
        }
    }

    /// Resolver currently only respects `Any` scopes.
    pub fn matches_resolver(self) -> bool {
        matches!(self, FaultScope::Any)
    }
}

/// Sample a fault scope. 50% `Any`, 45% specific `Vote(_)`, 5% specific
/// `Certificate(_)` (uniform within each variant).
pub fn sample(rng: &mut impl Rng) -> FaultScope {
    let bucket = rng.gen_range(0..100);
    if bucket < 50 {
        FaultScope::Any
    } else if bucket < 95 {
        let k = match rng.gen_range(0..3) {
            0 => VoteKind::Notarize,
            1 => VoteKind::Finalize,
            _ => VoteKind::Nullify,
        };
        FaultScope::Vote(k)
    } else {
        let k = match rng.gen_range(0..3) {
            0 => CertificateKind::Notarization,
            1 => CertificateKind::Nullification,
            _ => CertificateKind::Finalization,
        };
        FaultScope::Certificate(k)
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
