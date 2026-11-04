//! A suite whose roles sign through an in-memory ledger instead of real cryptography.
//!
//! [`Scheme`] runs every Multimmit role on a [`certificate::mocks`] scheme, so tests whose cost
//! is dominated by signing and verification can exercise protocol behaviour cheaply. A signature
//! or certificate is a synthetic 8-byte ID that the committee's [`Ledger`] records when it is
//! issued.
//!
//! # What it models
//!
//! - Unforgeability: a signature verifies only for the signer and subject it was issued for, and
//!   a certificate only for its subject, so corrupted, swapped, cross-role, and cross-kind
//!   signatures fail.
//! - Deterministic signing: re-signing a subject returns the same signature.
//! - Quorums: a certificate assembles only from the role's quorum of distinct signers whose
//!   recorded attestations share one subject.
//! - Aggregates: as with [`ed25519`](crate::multimmit::scheme::ed25519), V-QC and L-QC aggregates
//!   list one signature per term, and a term's known attestation stands in only for a listed
//!   signature equal to it byte for byte, so a forged or mismatched known attestation fails its
//!   item.
//!
//! # What it does not model
//!
//! - Encoded sizes: every signature and certificate encodes in 8 bytes, so sizes, codec bounds,
//!   and the limits derived from them differ from every real suite.
//! - Certificate uniqueness: as with Ed25519, certificates over one subject from different signer
//!   sets differ, unlike the threshold certificates of the BLS12-381 suites.
//! - Periods: signatures ignore [`Synchronized`](commonware_cryptography::certificate::Synchronized)
//!   periods.
//! - Keys: there are no key pairs or registration proofs, so roster checks never run.
//! - Cryptographic cost: verification is a ledger lookup, and batches verify item by item.
//! - Persistence: ledgers live in memory, so artifacts another process stored never verify.

use crate::multimmit::{
    config::Parameters,
    scheme::{Available, Binding, DaFaults, DaSubject, Error, Generic, RoleDigest},
};
use commonware_cryptography::{Hasher as _, Sha256, certificate, ed25519, sha256};
use commonware_utils::{Participant, TestRng, ordered::Set, sequence::U64, union};
use core::{fmt, hash::Hash, marker::PhantomData};
use rand_core::Rng as _;
use std::{cell::RefCell, collections::BTreeMap, sync::Arc};

/// Mock ordinary keys over [`OrdinarySubject`](crate::multimmit::scheme::OrdinarySubject)s.
pub mod ordinary {
    use crate::multimmit::scheme::{Namespace, OrdinarySubject};
    use commonware_cryptography::impl_certificate_mock;
    use commonware_utils::N5f1;

    impl_certificate_mock!(OrdinarySubject, Namespace, N5f1);
}

/// Mock data-availability certificates at the `n-2f` quorum of
/// [`DaQuorum::Available`](crate::multimmit::types::DaQuorum::Available).
pub mod da {
    use crate::multimmit::scheme::{Available, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_mock;

    impl_certificate_mock!(DaSubject, Namespace, Available);
}

/// Mock data-availability certificates at the `n-f` quorum of
/// [`DaQuorum::Binding`](crate::multimmit::types::DaQuorum::Binding).
pub mod da_binding {
    use crate::multimmit::scheme::{Binding, DaSubject, Namespace};
    use commonware_cryptography::impl_certificate_mock;

    impl_certificate_mock!(DaSubject, Namespace, Binding);
}

/// Mock nullifications at `2f+1`.
pub mod nullify {
    use crate::multimmit::scheme::{Namespace, NullifySubject};
    use commonware_cryptography::impl_certificate_mock;
    use commonware_utils::faults::N5f1Nullification;

    impl_certificate_mock!(NullifySubject, Namespace, N5f1Nullification);
}

/// The signatures and certificates one committee has issued.
///
/// Every role of every scheme built over a ledger records into and verifies against it, so a
/// committee's signers and verifiers must share one. A ledger also binds its committee into every
/// signed namespace, so its artifacts never verify under schemes built over another ledger.
#[derive(Clone)]
pub struct Ledger {
    shared: certificate::mocks::Shared,
    tag: sha256::Digest,
}

impl fmt::Debug for Ledger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ledger")
            .field("tag", &self.tag)
            .finish_non_exhaustive()
    }
}

thread_local! {
    /// The ledgers [`Ledger::dealt`] has returned on this thread, by tag.
    static DEALT: RefCell<BTreeMap<sha256::Digest, Ledger>> = const { RefCell::new(BTreeMap::new()) };
}

impl Ledger {
    /// Returns an empty ledger whose artifacts are bound to `label`.
    pub fn new(label: &[u8]) -> Self {
        Self {
            shared: certificate::mocks::Shared::default(),
            tag: Sha256::hash(&[label]),
        }
    }

    /// Returns the ledger of the committee `rng` deals to `participants`.
    ///
    /// Dealing the same committee again on the same thread returns the same ledger, so a
    /// committee rebuilt from its seed verifies the artifacts of the original, as rebuilt real
    /// keys do.
    pub(super) fn dealt(rng: &mut TestRng, participants: &Set<ed25519::PublicKey>) -> Self {
        let seed = rng.next_u64().to_be_bytes();
        let parts = core::iter::once(seed.as_slice())
            .chain(participants.iter().map(AsRef::as_ref))
            .collect::<Vec<_>>();
        let tag = Sha256::hash(&parts);
        DEALT.with_borrow_mut(|dealt| {
            dealt
                .entry(tag)
                .or_insert_with(|| Self {
                    shared: certificate::mocks::Shared::default(),
                    tag,
                })
                .clone()
        })
    }

    /// Returns the base namespace roles sign under in a deployment signing under `namespace`.
    fn namespace(&self, namespace: &[u8]) -> Vec<u8> {
        union(namespace, self.tag.as_ref())
    }
}

/// A data-availability fault model with a mock DA role.
///
/// Implemented by [`Available`] ([`da`]) and [`Binding`] ([`da_binding`]).
pub trait Quorum: DaFaults {
    /// The mock DA role at this quorum.
    type Da: for<'a> certificate::Scheme<
            PublicKey = ed25519::PublicKey,
            Faults = Self,
            Certificate = U64,
            Signature = U64,
            Subject<'a, RoleDigest> = DaSubject,
        >;

    /// Builds a DA signer, or `None` when `me` is not a participant.
    #[doc(hidden)]
    fn signer(
        namespace: &[u8],
        participants: Set<ed25519::PublicKey>,
        me: Participant,
        shared: certificate::mocks::Shared,
    ) -> Option<Self::Da>;

    /// Builds a DA verifier.
    #[doc(hidden)]
    fn verifier(
        namespace: &[u8],
        participants: Set<ed25519::PublicKey>,
        shared: certificate::mocks::Shared,
    ) -> Self::Da;
}

macro_rules! impl_quorum {
    ($faults:ty, $module:ident) => {
        impl Quorum for $faults {
            type Da = $module::Scheme<ed25519::PublicKey>;

            fn signer(
                namespace: &[u8],
                participants: Set<ed25519::PublicKey>,
                me: Participant,
                shared: certificate::mocks::Shared,
            ) -> Option<Self::Da> {
                $module::Scheme::signer(namespace, participants, me, shared)
            }

            fn verifier(
                namespace: &[u8],
                participants: Set<ed25519::PublicKey>,
                shared: certificate::mocks::Shared,
            ) -> Self::Da {
                $module::Scheme::verifier(namespace, participants, shared)
            }
        }
    };
}

impl_quorum!(Available, da);
impl_quorum!(Binding, da_binding);

/// The mock suite over Ed25519 identities, with DA certificates at the quorum `Q`.
pub struct Scheme<Q = Available>(PhantomData<fn() -> Q>);

impl<Q> Clone for Scheme<Q> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Q> Copy for Scheme<Q> {}

impl<Q> Default for Scheme<Q> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<Q> PartialEq for Scheme<Q> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<Q> Eq for Scheme<Q> {}

impl<Q> Hash for Scheme<Q> {
    fn hash<H: core::hash::Hasher>(&self, _: &mut H) {}
}

impl<Q> fmt::Debug for Scheme<Q> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mocks::suite::Scheme")
    }
}

impl<Q: Quorum> crate::multimmit::scheme::Scheme for Scheme<Q> {
    type PublicKey = ed25519::PublicKey;
    type DaFaults = Q;
    type Ordinary = ordinary::Scheme<ed25519::PublicKey>;
    type Da = Q::Da;
    type Nullify = nullify::Scheme<ed25519::PublicKey>;

    fn da_certificate_config(_: usize) {}

    fn nullification_config(_: usize) {}
}

impl<Q: Quorum> Scheme<Q> {
    /// Creates a signer for participant `me` that records into `ledger`.
    ///
    /// Fails when `me` is not one of `participants` or the participants do not match the epoch
    /// configuration.
    pub fn signer(
        parameters: &Arc<Parameters>,
        participants: Set<ed25519::PublicKey>,
        me: Participant,
        ledger: &Ledger,
    ) -> Result<Generic<Self>, Error> {
        let namespace = ledger.namespace(parameters.namespace());
        let shared = &ledger.shared;
        let ordinary =
            ordinary::Scheme::signer(&namespace, participants.clone(), me, shared.clone())
                .ok_or(Error::UnknownKey)?;
        let da = Q::signer(&namespace, participants.clone(), me, shared.clone())
            .ok_or(Error::UnknownKey)?;
        let nullify = nullify::Scheme::signer(&namespace, participants, me, shared.clone())
            .ok_or(Error::UnknownKey)?;
        Generic::new(parameters, ordinary, da, nullify)
    }

    /// Creates a verifier for `participants` that checks against `ledger`.
    pub fn verifier(
        parameters: &Arc<Parameters>,
        participants: Set<ed25519::PublicKey>,
        ledger: &Ledger,
    ) -> Result<Generic<Self>, Error> {
        let namespace = ledger.namespace(parameters.namespace());
        let shared = &ledger.shared;
        let ordinary = ordinary::Scheme::verifier(&namespace, participants.clone(), shared.clone());
        let da = Q::verifier(&namespace, participants.clone(), shared.clone());
        let nullify = nullify::Scheme::verifier(&namespace, participants, shared.clone());
        Generic::new(parameters, ordinary, da, nullify)
    }
}

#[cfg(test)]
mod tests {
    use super::{Ledger, Scheme};
    use crate::{multimmit::mocks::Committee, types::View};
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::Set, test_rng};

    #[test]
    fn rebuilt_committees_share_one_ledger_and_others_verify_nothing() {
        let committee = Committee::<Scheme>::builder(7, 6).build();
        let nullification = committee.nullification(View::new(3));
        let lqc = committee.lqc(View::new(4));

        // A committee dealt again from its seed verifies the original's artifacts.
        let rebuilt = Committee::<Scheme>::builder(7, 6).build();
        assert!(rebuilt.verifier.verify_nullification(
            &mut test_rng(),
            &nullification,
            &Sequential
        ));
        assert!(
            rebuilt
                .verifier
                .verify_lqc::<_, Sha256, _>(&mut test_rng(), &lqc, &Sequential)
                .is_some()
        );

        // The same committee over another ledger verifies none of them.
        let participants = Set::try_from(committee.identities.clone()).unwrap();
        let other = Scheme::verifier(
            committee.config.parameters(),
            participants,
            &Ledger::new(b"other"),
        )
        .unwrap();
        assert!(!other.verify_nullification(&mut test_rng(), &nullification, &Sequential));
        assert!(
            other
                .verify_lqc::<_, Sha256, _>(&mut test_rng(), &lqc, &Sequential)
                .is_none()
        );
    }
}
