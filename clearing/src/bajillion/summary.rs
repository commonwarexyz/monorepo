//! Summaries of closes, certified by validators and posted to the ledger.

use super::{Amount, Epoch, Namespace, Payout, matrix};
use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, Encode, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{
    Digest, Digestible, Hasher, PublicKey,
    certificate::{self, Verifier},
};
use commonware_parallel::Sequential;
use commonware_storage::{
    merkle::mmr,
    qmdb::{keyless, value::FixedEncoding},
};
use commonware_utils::Widen;
use core::{
    fmt::{self, Debug, Formatter},
    ops::RangeInclusive,
};
use rand_core::CryptoRng;
use thiserror::Error;

/// A ledger queue's requests that one close processes, as their count and the queue's running hash.
///
/// `hash` extends the parent summary's hash by `H(hash || request)` for each request's encoding in
/// queue order, so it covers every request the queue has processed since genesis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Processed<D: Digest> {
    /// Number of queued requests the close processes.
    pub count: u64,
    /// Running hash of the queue after the close, over every request the queue has processed.
    pub hash: D,
}

impl<D: Digest> Processed<D> {
    /// Returns the record of a close that processes `requests` after the close `self` records. Its
    /// count is the length of `requests`, and its hash extends `self`'s hash over them.
    pub(crate) fn next<H: Hasher<Digest = D>, R: Write + FixedSize>(&self, requests: &[R]) -> Self {
        let mut encoded = Vec::with_capacity(R::SIZE);
        let hash = requests.iter().fold(self.hash, |hash, request| {
            encoded.clear();
            request.write(&mut encoded);
            H::hash(&[hash.as_ref(), &encoded])
        });
        Self {
            count: Widen::widen(requests.len()),
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

/// The payout log after one close, as its size and root.
///
/// Each posted close appends its payouts to the [Payouts](super::Payouts) database in account
/// order, then a commit. `size` is the number of operations in the log after the close. It counts
/// the initial commit and the payouts and commit of every close since genesis, so the close's
/// commit sits at `size - 1`. `root` is the log's root after the close.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Log<D: Digest> {
    /// Number of operations in the payout log after the close, its initial commit included.
    pub size: u64,
    /// Root of the payout log after the close.
    pub root: D,
}

impl<D: Digest> Write for Log<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.size.write(buf);
        self.root.write(buf);
    }
}

impl<D: Digest> FixedSize for Log<D> {
    const SIZE: usize = u64::SIZE + D::SIZE;
}

impl<D: Digest> Read for Log<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            size: u64::read(buf)?,
            root: D::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Log<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            size: u.arbitrary()?,
            root: u.arbitrary()?,
        })
    }
}

/// Why the ledger refuses a post.
#[derive(Debug, Error)]
pub enum SummaryError {
    /// The summary is for another epoch.
    #[error("wrong epoch: expected {expected}, found {found}")]
    WrongEpoch {
        /// The epoch whose close the ledger expects.
        expected: Epoch,
        /// The epoch of the summary.
        found: Epoch,
    },
    /// The summary does not follow the last posted one.
    #[error("summary does not follow the last posted one")]
    WrongParent,
    /// A count is outside the range given.
    #[error("invalid number of queued requests")]
    InvalidCount,
    /// The certificate does not verify.
    #[error("invalid certificate")]
    InvalidCertificate,
}

/// The effects of one close, as certified by validators and posted to the ledger.
///
/// A summary's digest ([Digestible]) is what the next summary names as its parent, so the hasher
/// `H` is part of the type. A certificate scheme over summaries comes from the certificate macros
/// of `commonware_cryptography` and names the hasher along with the signature scheme and its fault
/// model. For example, for SHA-256 and Ed25519 with up to `f` Byzantine validators out of
/// `3f + 1`:
///
/// ```
/// mod scheme {
///     use commonware_clearing::bajillion::{Namespace, Summary};
///     use commonware_cryptography::{Sha256, impl_certificate_ed25519};
///     use commonware_utils::N3f1;
///
///     impl_certificate_ed25519!(&'a Summary<Sha256>, Namespace, N3f1);
/// }
/// ```
pub struct Summary<H: Hasher> {
    /// Epoch the close finalizes.
    pub epoch: Epoch,
    /// Digest of the summary of the previous close.
    pub parent: H::Digest,
    /// Root of the payment matrix the close settles.
    pub matrix: H::Digest,
    /// Root of the balances after the close.
    pub balances: H::Digest,
    /// The payout log after the close, as its size and root.
    pub payouts: Log<H::Digest>,
    /// The deposits the close processes, as their count and the queue's running hash.
    pub deposits: Processed<H::Digest>,
    /// The forced withdrawals the close processes, as their count and the queue's running hash.
    pub forced_withdrawals: Processed<H::Digest>,
}

impl<H: Hasher> Summary<H> {
    /// Returns the summary of the state before the first close, with balances committed by
    /// `balances`, accounts of type `P`, and amounts of type `A`. Both running hashes start at all
    /// zeros, and the payout log holds only its initial commit.
    pub fn genesis<P: PublicKey, A: Amount>(balances: H::Digest) -> Self {
        let start = Processed {
            count: 0,
            hash: H::Digest::EMPTY,
        };
        Self {
            epoch: 0,
            parent: H::Digest::EMPTY,
            matrix: matrix::root::<H, P>(core::iter::empty()),
            balances,
            payouts: Log {
                size: 1,
                root: keyless::initial_root::<mmr::Family, FixedEncoding<Payout<P, A>>, H>(),
            },
            deposits: start,
            forced_withdrawals: start,
        }
    }

    /// Checks that a ledger expecting the close of `epoch` after the post with digest `parent` may
    /// post this summary under `certificate`. `deposits` and `forced_withdrawals` each range from
    /// the queue's required count to its length.
    ///
    /// The certificate is checked last, and it alone vouches for the matrix and balances roots,
    /// the payouts size and root, and the running hashes.
    #[allow(clippy::too_many_arguments)]
    pub fn verify<V, R>(
        &self,
        rng: &mut R,
        verifier: &V,
        certificate: &V::Certificate,
        epoch: Epoch,
        parent: &H::Digest,
        deposits: RangeInclusive<u64>,
        forced_withdrawals: RangeInclusive<u64>,
    ) -> Result<(), SummaryError>
    where
        V: for<'a> Verifier<Subject<'a, H::Digest> = &'a Self>,
        R: CryptoRng,
    {
        if self.epoch != epoch {
            return Err(SummaryError::WrongEpoch {
                expected: epoch,
                found: self.epoch,
            });
        }
        if self.parent != *parent {
            return Err(SummaryError::WrongParent);
        }
        if !deposits.contains(&self.deposits.count)
            || !forced_withdrawals.contains(&self.forced_withdrawals.count)
        {
            return Err(SummaryError::InvalidCount);
        }
        if !verifier.verify_certificate::<_, H::Digest>(rng, self, certificate, &Sequential) {
            return Err(SummaryError::InvalidCertificate);
        }
        Ok(())
    }
}

// The hasher is a type parameter only, so the derived traits would bound it.
impl<H: Hasher> Clone for Summary<H> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<H: Hasher> Copy for Summary<H> {}

impl<H: Hasher> Debug for Summary<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Summary")
            .field("epoch", &self.epoch)
            .field("parent", &self.parent)
            .field("matrix", &self.matrix)
            .field("balances", &self.balances)
            .field("payouts", &self.payouts)
            .field("deposits", &self.deposits)
            .field("forced_withdrawals", &self.forced_withdrawals)
            .finish()
    }
}

impl<H: Hasher> PartialEq for Summary<H> {
    fn eq(&self, other: &Self) -> bool {
        self.epoch == other.epoch
            && self.parent == other.parent
            && self.matrix == other.matrix
            && self.balances == other.balances
            && self.payouts == other.payouts
            && self.deposits == other.deposits
            && self.forced_withdrawals == other.forced_withdrawals
    }
}

impl<H: Hasher> Eq for Summary<H> {}

impl<H: Hasher> Digestible for Summary<H> {
    type Digest = H::Digest;

    fn digest(&self) -> H::Digest {
        H::hash(&[&self.encode()])
    }
}

impl<H: Hasher> Write for Summary<H> {
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

impl<H: Hasher> FixedSize for Summary<H> {
    const SIZE: usize = Epoch::SIZE
        + 3 * H::Digest::SIZE
        + Log::<H::Digest>::SIZE
        + 2 * Processed::<H::Digest>::SIZE;
}

impl<H: Hasher> Read for Summary<H> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: Epoch::read(buf)?,
            parent: H::Digest::read(buf)?,
            matrix: H::Digest::read(buf)?,
            balances: H::Digest::read(buf)?,
            payouts: Log::read(buf)?,
            deposits: Processed::read(buf)?,
            forced_withdrawals: Processed::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<H: Hasher> arbitrary::Arbitrary<'_> for Summary<H>
where
    H::Digest: for<'a> arbitrary::Arbitrary<'a>,
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

impl<H: Hasher> certificate::Subject for &Summary<H> {
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
        tests::{NAMESPACE, account, certify, chain, scheme},
    };
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::{
        Digest as _, Sha256,
        ed25519::{self, PublicKey},
        sha256::Digest,
    };
    use commonware_utils::test_rng;

    /// Returns the summary before the first close, on top of balances with a fixed root.
    fn genesis() -> Summary<Sha256> {
        Summary::<Sha256>::genesis::<PublicKey, u64>(Sha256::hash(&[b"balances"]))
    }

    /// The genesis summary records the empty matrix and a payout log holding only its initial
    /// commit, with nothing paid out.
    #[test]
    fn test_genesis_and_digest() {
        let genesis = genesis();
        assert_eq!(genesis.epoch, 0);
        assert_eq!(genesis.parent, Digest::EMPTY);
        assert_eq!(genesis.balances, Sha256::hash(&[b"balances"]));
        assert_eq!(
            genesis.matrix,
            Matrix::<PublicKey, Sha256, u64>::empty().root()
        );
        let log =
            keyless::initial_root::<mmr::Family, FixedEncoding<Payout<PublicKey, u64>>, Sha256>();
        let expected = Log { size: 1, root: log };
        assert_eq!(genesis.payouts, expected);
        assert_eq!(Summary::decode(genesis.encode()).unwrap(), genesis);

        // Every field changes the digest and decodes back unchanged.
        let other = Sha256::hash(&[b"other"]);
        let digest = genesis.digest();
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
                payouts: Log {
                    size: 2,
                    ..genesis.payouts
                },
                ..genesis
            },
            Summary {
                payouts: Log {
                    root: other,
                    ..genesis.payouts
                },
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
            assert_ne!(changed.digest(), digest);
            assert_eq!(Summary::decode(changed.encode()).unwrap(), changed);
        }
    }

    /// Both running hashes start at all zeros. Each extends its parent's by `H(hash || request)`
    /// for every request processed in queue order.
    #[test]
    fn test_running_hashes_chain_processed_requests() {
        let genesis = genesis();
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
    /// bounds, with a certificate over it. The certificate is checked only once everything else
    /// holds, and it covers the payouts size and root.
    #[test]
    fn test_verify_checks_every_field_before_the_certificate() {
        let mut rng = test_rng();
        let fixture = ed25519::certificate::mocks::fixture(
            &mut rng,
            NAMESPACE,
            4,
            scheme::Scheme::signer,
            scheme::Scheme::verifier,
        );
        let genesis = genesis();
        let parent = genesis.digest();
        let summary = Summary {
            epoch: 1,
            parent,
            matrix: Sha256::hash(&[b"matrix"]),
            balances: Sha256::hash(&[b"after"]),
            payouts: Log {
                size: 3,
                root: Sha256::hash(&[b"payouts"]),
            },
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
        let mut verify = |summary: &Summary<Sha256>,
                          certificate,
                          parent: &Digest,
                          deposits,
                          forced_withdrawals| {
            summary.verify(
                &mut rng,
                &fixture.verifier,
                certificate,
                1,
                parent,
                deposits,
                forced_withdrawals,
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
                verify(&wrong, certificate, &parent, 0..=2, 0..=1),
                Err(SummaryError::WrongEpoch {
                    expected: 1,
                    found: 2
                })
            ));
            assert!(matches!(
                verify(&summary, certificate, &Digest::EMPTY, 0..=2, 0..=1),
                Err(SummaryError::WrongParent)
            ));
            for (deposits, forced_withdrawals) in [(3..=4, 0..=1), (0..=1, 0..=1), (0..=2, 2..=2)] {
                assert!(matches!(
                    verify(&summary, certificate, &parent, deposits, forced_withdrawals),
                    Err(SummaryError::InvalidCount)
                ));
            }
        }

        // A summary that differs in its payouts size or root is not certified.
        let changed = [
            Log {
                size: 4,
                ..summary.payouts
            },
            Log {
                root: Sha256::hash(&[b"other"]),
                ..summary.payouts
            },
        ];
        for payouts in changed {
            let changed = Summary { payouts, ..summary };
            assert!(matches!(
                verify(&changed, &certificate, &parent, 0..=2, 0..=1),
                Err(SummaryError::InvalidCertificate)
            ));
        }
        assert!(matches!(
            verify(&summary, &other, &parent, 0..=2, 0..=1),
            Err(SummaryError::InvalidCertificate)
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Processed<Digest>>,
            CodecConformance<Log<Digest>>,
            CodecConformance<Summary<Sha256>>,
        }
    }
}
