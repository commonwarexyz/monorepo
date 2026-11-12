//! Structural checks and known-term discharge for aggregates of unique, additive signatures.
//!
//! Both [`multisig`](super::multisig) and [`sas`](super::sas) signatures are unique per signer and
//! message, and an aggregate is their sum. A valid aggregate therefore contains exactly the known
//! signature of every term the caller already verified, and subtracting those signatures leaves an
//! aggregate over the remaining terms alone.

use crate::{
    Digest,
    bls12381::primitives::variant::Variant,
    certificate::{Aggregator, Item, distinct_terms},
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::Bytes;
use commonware_math::algebra::Additive;
use commonware_utils::Participant;

/// A signer's key and the namespaced message it signed in `period`, owned until a batch borrows
/// it.
pub(super) struct Owned<'n, K, P> {
    pub(super) period: P,
    pub(super) public: K,
    pub(super) namespace: &'n [u8],
    pub(super) message: Bytes,
}

/// The terms a claim covers.
pub(super) enum Terms<'n, K, P> {
    /// A single attestation.
    One(Owned<'n, K, P>),
    /// The terms of an aggregate left after discharge.
    Many(Vec<Owned<'n, K, P>>),
}

impl<'n, K, P> Terms<'n, K, P> {
    pub(super) fn as_slice(&self) -> &[Owned<'n, K, P>] {
        match self {
            Self::One(term) => core::slice::from_ref(term),
            Self::Many(terms) => terms,
        }
    }
}

/// An item after its structural checks and the discharge of its known terms.
pub(super) enum Prepared<'n, V: Variant, K, P> {
    /// The verdict needs no pairing.
    Settled(bool),
    /// The item is valid if `signature` is valid over every term.
    Claim {
        signature: V::Signature,
        terms: Terms<'n, K, P>,
    },
}

/// Checks the structure of `item` and subtracts the known signature of every known term from its
/// aggregate.
///
/// `aggregate` decodes an aggregate signature, and `owned` resolves a signer's term, returning
/// `None` for a signer outside the participant set.
pub(super) fn prepare<'n, 'a, S, D, V, K, P>(
    participants: usize,
    item: &Item<'_, 'a, S, D>,
    aggregate: impl FnOnce(&S::Aggregate) -> Option<V::Signature>,
    owned: impl Fn(Participant, &S::Subject<'a, D>) -> Option<Owned<'n, K, P>>,
) -> Prepared<'n, V, K, P>
where
    S: Aggregator<Signature = V::Signature>,
    D: Digest,
    V: Variant,
{
    match item {
        Item::Attestation {
            subject,
            attestation,
        } => {
            let Some(signature) = attestation.signature.get() else {
                return Prepared::Settled(false);
            };
            let Some(term) = owned(attestation.signer, subject) else {
                return Prepared::Settled(false);
            };
            Prepared::Claim {
                signature: *signature,
                terms: Terms::One(term),
            }
        }
        Item::Aggregate {
            terms,
            aggregate: signature,
        } => {
            if !distinct_terms(participants, terms) {
                return Prepared::Settled(false);
            }
            let Some(mut remainder) = aggregate(signature) else {
                return Prepared::Settled(false);
            };
            let mut remaining = Vec::with_capacity(terms.len());
            for term in terms.iter() {
                let Some(known) = term.known else {
                    let Some(owned) = owned(term.signer, &term.subject) else {
                        return Prepared::Settled(false);
                    };
                    remaining.push(owned);
                    continue;
                };
                if known.signer != term.signer {
                    return Prepared::Settled(false);
                }
                let Some(known) = known.signature.get() else {
                    return Prepared::Settled(false);
                };
                remainder -= known;
            }

            // Every term was discharged, so the aggregate must equal the known signatures.
            if remaining.is_empty() {
                return Prepared::Settled(remainder == V::Signature::zero());
            }
            Prepared::Claim {
                signature: remainder,
                terms: Terms::Many(remaining),
            }
        }
    }
}
