//! Summaries of closes, certified by validators and posted to the ledger.

use super::{Amount, Amounts, Epoch, Error, Namespace};
use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, Encode, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{
    Digest, Hasher, PublicKey,
    certificate::{self, Verifier},
};
use commonware_parallel::Sequential;
use commonware_storage::bmt::Builder;
use core::ops::RangeInclusive;
use rand_core::CryptoRng;

/// The effects of one close, as certified by validators and posted to the ledger.
///
/// Validators certify summaries with a scheme the deployment builds from the certificate macros of
/// `commonware_cryptography`. The deployment chooses the signature scheme and its fault model. For
/// example, for Ed25519 with up to `f` Byzantine validators out of `3f + 1`:
///
/// ```
/// mod scheme {
///     use commonware_clearing::bajillion::{Namespace, Summary};
///     use commonware_cryptography::impl_certificate_ed25519;
///     use commonware_utils::N3f1;
///
///     impl_certificate_ed25519!(&'a Summary<D>, Namespace, N3f1);
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Summary<D: Digest> {
    /// Epoch the close finalizes.
    pub epoch: Epoch,
    /// Digest of the summary of the previous close.
    pub parent: D,
    /// Root of the payment matrix the close settles.
    pub matrix: D,
    /// Root of the balances after the close.
    pub balances: D,
    /// Root of the close's payouts.
    pub payouts: D,
    /// Number of queued deposits the close processes.
    pub deposits: u64,
    /// Number of queued forced withdrawals the close processes.
    pub forced_withdrawals: u64,
}

impl<D: Digest> Summary<D> {
    /// Returns the summary of the state before the first close, with balances committed by
    /// `balances`.
    pub fn genesis<H: Hasher<Digest = D>>(balances: D) -> Self {
        // An empty payment matrix and empty payouts both commit to a tree without leaves.
        let empty = Builder::<H>::new(0).build().root();
        Self {
            epoch: 0,
            parent: D::EMPTY,
            matrix: empty,
            balances,
            payouts: empty,
            deposits: 0,
            forced_withdrawals: 0,
        }
    }

    /// Returns the digest the next summary names as its parent.
    pub fn digest<H: Hasher<Digest = D>>(&self) -> D {
        H::hash(&[&self.encode()])
    }

    /// Checks that a ledger expecting the close of `epoch` after the post with digest `parent` may
    /// post this summary with `payouts` under `certificate`. `deposits` and `forced_withdrawals`
    /// each range from the queue's required count to its length.
    ///
    /// Returns WrongEpoch unless the summary is for `epoch`, WrongParent unless it names `parent`,
    /// InvalidCount unless each count is in its range, InvalidPayouts unless `payouts` has the
    /// summary's payouts root, and InvalidCertificate unless `certificate` verifies. The
    /// certificate is checked last.
    #[allow(clippy::too_many_arguments)]
    pub fn verify<H, P, A, V, R>(
        &self,
        rng: &mut R,
        verifier: &V,
        certificate: &V::Certificate,
        epoch: Epoch,
        parent: &D,
        deposits: RangeInclusive<u64>,
        forced_withdrawals: RangeInclusive<u64>,
        payouts: &Amounts<P, A>,
    ) -> Result<(), Error>
    where
        H: Hasher<Digest = D>,
        P: PublicKey,
        A: Amount,
        V: for<'a> Verifier<Subject<'a, D> = &'a Self>,
        R: CryptoRng,
    {
        if self.epoch != epoch {
            return Err(Error::WrongEpoch {
                expected: epoch,
                found: self.epoch,
            });
        }
        if self.parent != *parent {
            return Err(Error::WrongParent);
        }
        if !deposits.contains(&self.deposits)
            || !forced_withdrawals.contains(&self.forced_withdrawals)
        {
            return Err(Error::InvalidCount);
        }
        if payouts.root::<H>() != self.payouts {
            return Err(Error::InvalidPayouts);
        }
        if !verifier.verify_certificate::<_, D>(rng, self, certificate, &Sequential) {
            return Err(Error::InvalidCertificate);
        }
        Ok(())
    }
}

impl<D: Digest> Write for Summary<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.parent.write(buf);
        self.matrix.write(buf);
        self.balances.write(buf);
        self.payouts.write(buf);
        self.deposits.write(buf);
        self.forced_withdrawals.write(buf);
    }
}

impl<D: Digest> FixedSize for Summary<D> {
    const SIZE: usize = Epoch::SIZE + 4 * D::SIZE + 2 * u64::SIZE;
}

impl<D: Digest> Read for Summary<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: Epoch::read(buf)?,
            parent: D::read(buf)?,
            matrix: D::read(buf)?,
            balances: D::read(buf)?,
            payouts: D::read(buf)?,
            deposits: u64::read(buf)?,
            forced_withdrawals: u64::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Summary<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            epoch: u.arbitrary()?,
            parent: u.arbitrary()?,
            matrix: u.arbitrary()?,
            balances: u.arbitrary()?,
            payouts: u.arbitrary()?,
            deposits: u.arbitrary()?,
            forced_withdrawals: u.arbitrary()?,
        })
    }
}

impl<D: Digest> certificate::Subject for &Summary<D> {
    type Namespace = Namespace;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        &derived.summary
    }

    fn message(&self) -> Bytes {
        self.encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        Matrix,
        tests::{NAMESPACE, amounts, certify, scheme},
    };
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::{
        Digest as _, Sha256,
        ed25519::{self, PublicKey},
        sha256::Digest,
    };
    use commonware_utils::{TestRng, test_rng};

    #[test]
    fn test_genesis_and_digest() {
        let balances = Sha256::hash(&[b"balances"]);
        let genesis = Summary::<Digest>::genesis::<Sha256>(balances);
        assert_eq!(genesis.epoch, 0);
        assert_eq!(genesis.balances, balances);
        assert_eq!(
            genesis.matrix,
            Matrix::<PublicKey, Digest, u64>::empty::<Sha256>().root()
        );
        assert_eq!(
            genesis.payouts,
            Amounts::<PublicKey, u64>::empty().root::<Sha256>()
        );
        assert_eq!(Summary::decode(genesis.encode()).unwrap(), genesis);

        // Every field changes the digest.
        let other = Sha256::hash(&[b"other"]);
        let digest = genesis.digest::<Sha256>();
        for changed in [
            Summary {
                epoch: 1,
                ..genesis
            },
            Summary {
                parent: other,
                ..genesis
            },
            Summary {
                matrix: other,
                ..genesis
            },
            Summary {
                balances: other,
                ..genesis
            },
            Summary {
                payouts: other,
                ..genesis
            },
            Summary {
                deposits: 1,
                ..genesis
            },
            Summary {
                forced_withdrawals: 1,
                ..genesis
            },
        ] {
            assert_ne!(changed.digest::<Sha256>(), digest);
        }
    }

    /// The posted summary must follow the ledger's last post and process its queues within their
    /// bounds, with the payouts it commits to and a certificate over it. The certificate is checked
    /// only once everything else holds.
    #[test]
    fn test_verify_checks_every_field_before_the_certificate() {
        let fixture = ed25519::certificate::mocks::fixture(
            &mut test_rng(),
            NAMESPACE,
            4,
            scheme::Scheme::signer,
            scheme::Scheme::verifier,
        );
        let genesis = Summary::<Digest>::genesis::<Sha256>(Sha256::hash(&[b"balances"]));
        let parent = genesis.digest::<Sha256>();
        let payouts = amounts(&[(0, 3)]);
        let summary = Summary {
            epoch: 1,
            parent,
            matrix: Sha256::hash(&[b"matrix"]),
            balances: Sha256::hash(&[b"after"]),
            payouts: payouts.root::<Sha256>(),
            deposits: 2,
            forced_withdrawals: 1,
        };
        let certificate = certify(&fixture.schemes, &summary);
        let other = certify(&fixture.schemes, &genesis);
        let mut rng = test_rng();
        let mut verify = |summary: &Summary<Digest>,
                          certificate,
                          parent: &Digest,
                          deposits,
                          forced_withdrawals,
                          payouts: &Amounts<PublicKey, u64>| {
            summary.verify::<Sha256, _, _, _, TestRng>(
                &mut rng,
                &fixture.verifier,
                certificate,
                1,
                parent,
                deposits,
                forced_withdrawals,
                payouts,
            )
        };

        // Each count may lie anywhere from the queue's required count to its length.
        for (deposits, forced_withdrawals) in [(0..=2, 1..=1), (2..=5, 0..=3)] {
            verify(
                &summary,
                &certificate,
                &parent,
                deposits,
                forced_withdrawals,
                &payouts,
            )
            .unwrap();
        }

        // Every other refusal comes before the certificate's.
        for certificate in [&certificate, &other] {
            let wrong = Summary {
                epoch: 2,
                ..summary
            };
            assert!(matches!(
                verify(&wrong, certificate, &parent, 0..=2, 0..=1, &payouts),
                Err(Error::WrongEpoch {
                    expected: 1,
                    found: 2
                })
            ));
            assert!(matches!(
                verify(
                    &summary,
                    certificate,
                    &Digest::EMPTY,
                    0..=2,
                    0..=1,
                    &payouts
                ),
                Err(Error::WrongParent)
            ));
            for (deposits, forced_withdrawals) in [(3..=4, 0..=1), (0..=1, 0..=1), (0..=2, 2..=2)] {
                assert!(matches!(
                    verify(
                        &summary,
                        certificate,
                        &parent,
                        deposits,
                        forced_withdrawals,
                        &payouts
                    ),
                    Err(Error::InvalidCount)
                ));
            }
            assert!(matches!(
                verify(
                    &summary,
                    certificate,
                    &parent,
                    0..=2,
                    0..=1,
                    &amounts(&[(0, 4)])
                ),
                Err(Error::InvalidPayouts)
            ));
        }
        assert!(matches!(
            verify(&summary, &other, &parent, 0..=2, 0..=1, &payouts),
            Err(Error::InvalidCertificate)
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Summary<Digest>>,
        }
    }
}
