//! Summaries of closes, certified by validators and posted to the ledger.

use super::{Epoch, Namespace};
use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, Encode, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, certificate};
use commonware_storage::bmt::Builder;

/// The effects of one close, as certified by validators and posted to the ledger.
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

/// A certificate scheme that validators use to certify [Summary]s.
///
/// Deployments build one with the certificate macros of `commonware_cryptography`, choosing the
/// scheme and its fault model. For example, for Ed25519 with up to `f` Byzantine validators out
/// of `3f + 1`:
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
pub trait Scheme<D: Digest>: for<'a> certificate::Scheme<Subject<'a, D> = &'a Summary<D>> {}

impl<D: Digest, S> Scheme<D> for S where
    S: for<'a> certificate::Scheme<Subject<'a, D> = &'a Summary<D>>
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{Amounts, Matrix};
    use commonware_codec::DecodeExt as _;
    use commonware_cryptography::{Sha256, ed25519::PublicKey, sha256::Digest};

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

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Summary<Digest>>,
        }
    }
}
