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

/// The requests of one ledger queue that a close processes.
///
/// A close processes the oldest `count` requests still queued. `hash` is the queue's running hash
/// after them. It extends the parent summary's hash by `H(hash || request)` for each request's
/// encoding in queue order, so it names every request the queue has processed since genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Processed<D: Digest> {
    /// Number of queued requests the close processes.
    pub count: u64,
    /// Running hash of the queue after the requests the close processes.
    pub hash: D,
}

impl<D: Digest> Processed<D> {
    /// Returns the record of a close that processes `requests` after the close recorded by `self`.
    pub(crate) fn next<H: Hasher<Digest = D>, R: Write + FixedSize>(&self, requests: &[R]) -> Self {
        let mut encoded = Vec::with_capacity(R::SIZE);
        let hash = requests.iter().fold(self.hash, |hash, request| {
            encoded.clear();
            request.write(&mut encoded);
            H::hash(&[hash.as_ref(), &encoded])
        });
        Self {
            count: requests.len() as u64,
            hash,
        }
    }
}

impl<D: Digest> Write for Processed<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.count.write(buf);
        self.hash.write(buf);
    }
}

impl<D: Digest> FixedSize for Processed<D> {
    const SIZE: usize = u64::SIZE + D::SIZE;
}

impl<D: Digest> Read for Processed<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            count: u64::read(buf)?,
            hash: D::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Processed<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            count: u.arbitrary()?,
            hash: u.arbitrary()?,
        })
    }
}

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
    /// The queued deposits the close processes.
    pub deposits: Processed<D>,
    /// The queued forced withdrawals the close processes.
    pub forced_withdrawals: Processed<D>,
}

impl<D: Digest> Summary<D> {
    /// Returns the summary of the state before the first close, with balances committed by
    /// `balances`. Both running hashes start at all zeros.
    pub fn genesis<H: Hasher<Digest = D>>(balances: D) -> Self {
        // An empty payment matrix and empty payouts both commit to a tree without leaves.
        let empty = Builder::<H>::new(0).build().root();
        let start = Processed {
            count: 0,
            hash: D::EMPTY,
        };
        Self {
            epoch: 0,
            parent: D::EMPTY,
            matrix: empty,
            balances,
            payouts: empty,
            deposits: start,
            forced_withdrawals: start,
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
    /// certificate is checked last, and it alone vouches for the matrix and balances roots and the
    /// running hashes.
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
        if !deposits.contains(&self.deposits.count)
            || !forced_withdrawals.contains(&self.forced_withdrawals.count)
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
    const SIZE: usize = Epoch::SIZE + 4 * D::SIZE + 2 * Processed::<D>::SIZE;
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
            deposits: Processed::read(buf)?,
            forced_withdrawals: Processed::read(buf)?,
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
        Deposit, ForcedWithdrawal, Matrix,
        tests::{NAMESPACE, account, amounts, certify, chain, scheme},
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

        // Every field changes the digest and decodes back unchanged.
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
                deposits: Processed {
                    count: 1,
                    ..genesis.deposits
                },
                ..genesis
            },
            Summary {
                deposits: Processed {
                    hash: other,
                    ..genesis.deposits
                },
                ..genesis
            },
            Summary {
                forced_withdrawals: Processed {
                    count: 1,
                    ..genesis.forced_withdrawals
                },
                ..genesis
            },
            Summary {
                forced_withdrawals: Processed {
                    hash: other,
                    ..genesis.forced_withdrawals
                },
                ..genesis
            },
        ] {
            assert_ne!(changed.digest::<Sha256>(), digest);
            assert_eq!(Summary::decode(changed.encode()).unwrap(), changed);
        }
    }

    /// Both running hashes start at all zeros. Each extends its parent's by `H(hash || request)`
    /// for every request processed in queue order.
    #[test]
    fn test_running_hashes_chain_processed_requests() {
        let genesis = Summary::<Digest>::genesis::<Sha256>(Sha256::hash(&[b"balances"]));
        let start = Processed {
            count: 0,
            hash: Digest::EMPTY,
        };
        assert_eq!(
            (genesis.deposits, genesis.forced_withdrawals),
            (start, start)
        );
        let deposit = |index, amount| Deposit::<_, u64> {
            account: account(index),
            amount,
        };
        let (first, second) = (deposit(0, 5), deposit(1, 7));

        // One request extends the hash by H(hash || request).
        let one = start.next::<Sha256, _>(std::slice::from_ref(&first));
        assert_eq!(one.count, 1);
        assert_eq!(
            one.hash,
            Sha256::hash(&[start.hash.as_ref(), &first.encode()])
        );
        assert_eq!(one.hash, chain(start.hash, std::slice::from_ref(&first)));
        assert_eq!(Processed::decode(one.encode()).unwrap(), one);

        // A close that processes nothing carries its parent's hash.
        let none = one.next::<Sha256, Deposit<PublicKey, u64>>(&[]);
        assert_eq!((none.count, none.hash), (0, one.hash));

        // Two closes chain to the hash of one close processing both batches.
        let both = start.next::<Sha256, _>(&[first.clone(), second.clone()]);
        let next = one.next::<Sha256, _>(std::slice::from_ref(&second));
        assert_eq!((both.count, next.count), (2, 1));
        assert_eq!(next.hash, both.hash);

        // Reordering or repeating requests changes the hash.
        let reversed = start.next::<Sha256, _>(&[second, first.clone()]);
        let repeated = start.next::<Sha256, _>(&[first.clone(), first]);
        assert_ne!(reversed.hash, both.hash);
        assert_ne!(repeated.hash, one.hash);

        // Forced withdrawals chain the same way over their own encoding.
        let forced = ForcedWithdrawal::<_, u64> {
            account: account(2),
            amount: 3,
        };
        let one = start.next::<Sha256, _>(std::slice::from_ref(&forced));
        assert_eq!(one.hash, chain(start.hash, std::slice::from_ref(&forced)));
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
            deposits: Processed {
                count: 2,
                hash: Sha256::hash(&[b"deposits"]),
            },
            forced_withdrawals: Processed {
                count: 1,
                hash: Sha256::hash(&[b"forced withdrawals"]),
            },
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
            CodecConformance<Processed<Digest>>,
            CodecConformance<Summary<Digest>>,
        }
    }
}
