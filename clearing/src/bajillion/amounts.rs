//! Amounts of funds, and nonzero amounts per account committed with a binary Merkle tree.

use super::{Error, Lookup};
use bytes::BufMut;
use commonware_codec::{
    Buf, CodecFixedShared, EncodeSize, Error as CodecError, RangeCfg, Read, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_storage::bmt::{Builder, Tree};
use core::{fmt::Debug, hash::Hash};

/// An unsigned integer amount of funds.
///
/// An implementation must be an unsigned integer type whose order is numeric order. Its codec
/// encoding must have a fixed width of at most 32 bytes and exactly one encoding per value.
pub trait Amount: Copy + Ord + Hash + Debug + CodecFixedShared + 'static {
    /// The amount zero.
    const ZERO: Self;

    /// Returns `self + other` wrapped to the type's width, and whether the sum overflowed.
    fn overflowing_add(self, other: Self) -> (Self, bool);

    /// Returns `self - other` wrapped to the type's width, and whether the difference is negative.
    fn overflowing_sub(self, other: Self) -> (Self, bool);

    /// Returns `self + other`, or `None` if the sum overflows.
    fn checked_add(self, other: Self) -> Option<Self> {
        match self.overflowing_add(other) {
            (sum, false) => Some(sum),
            (_, true) => None,
        }
    }

    /// Returns `self - other`, or `None` if the difference is negative.
    fn checked_sub(self, other: Self) -> Option<Self> {
        match self.overflowing_sub(other) {
            (difference, false) => Some(difference),
            (_, true) => None,
        }
    }
}

macro_rules! impl_amount {
    ($($type:ty),*) => {
        $(
            impl Amount for $type {
                const ZERO: Self = 0;

                fn overflowing_add(self, other: Self) -> (Self, bool) {
                    <$type>::overflowing_add(self, other)
                }

                fn overflowing_sub(self, other: Self) -> (Self, bool) {
                    <$type>::overflowing_sub(self, other)
                }
            }
        )*
    };
}

impl_amount!(u64, u128);

/// The most bytes an [Amount] may encode to.
const MAX_AMOUNT_SIZE: usize = 32;

/// Computes the leaf committing to `amount` for `account`.
pub(crate) fn leaf<H: Hasher, P: PublicKey, A: Amount>(account: &P, amount: A) -> H::Digest {
    const {
        assert!(
            A::SIZE <= MAX_AMOUNT_SIZE,
            "amounts must encode in at most 32 bytes"
        )
    };
    let mut encoded = [0u8; MAX_AMOUNT_SIZE];
    amount.write(&mut &mut encoded[..A::SIZE]);
    H::hash(&[account.as_ref(), &encoded[..A::SIZE]])
}

/// Nonzero amounts per account, sorted by account.
///
/// Payment maps, request batches, and the payouts of a close are all [Amounts]. A payment map or
/// request batch is committed by the root of a binary Merkle tree whose leaves are the `(account,
/// amount)` entries in account order. The root also binds the number of entries, so a [Lookup] of
/// two adjacent entries proves that an account between them has no amount. A close's payouts are
/// appended to the payout log ([Payout::stage](super::Payout::stage)).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Amounts<P: PublicKey, A: Amount> {
    entries: Vec<(P, A)>,
}

impl<P: PublicKey, A: Amount> Default for Amounts<P, A> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<P: PublicKey, A: Amount> Amounts<P, A> {
    /// Returns amounts with no entries.
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Collects `entries` in account order.
    ///
    /// Returns an error if an amount is zero, an account appears more than once, or there are more
    /// than `u32::MAX` entries.
    pub fn new(entries: impl IntoIterator<Item = (P, A)>) -> Result<Self, Error> {
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        Self::from_sorted(entries)
    }

    /// Wraps entries that must be strictly increasing by account with nonzero amounts.
    pub(crate) fn from_sorted(entries: Vec<(P, A)>) -> Result<Self, Error> {
        if entries.len() > u32::MAX as usize {
            return Err(Error::TooManyEntries);
        }
        if entries.iter().any(|(_, amount)| *amount == A::ZERO) {
            return Err(Error::ZeroAmount);
        }
        if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(Error::DuplicateAccount);
        }
        Ok(Self { entries })
    }

    /// Returns whether there are no entries.
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of accounts with an amount.
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the amount of `account`, or zero if it has none.
    pub fn get(&self, account: &P) -> A {
        self.position(account)
            .map_or(A::ZERO, |position| self.entries[position].1)
    }

    /// Iterates over the entries in account order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&P, A)> {
        self.entries
            .iter()
            .map(|(account, amount)| (account, *amount))
    }

    /// Returns the sum of all amounts, or `None` if it overflows.
    pub fn total(&self) -> Option<A> {
        self.entries
            .iter()
            .try_fold(A::ZERO, |total, (_, amount)| total.checked_add(*amount))
    }

    /// Returns the amounts with `other` added entry by entry.
    ///
    /// Returns an error if a sum overflows.
    pub fn combine(&self, other: &Self) -> Result<Self, Error> {
        let mut entries = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut left = self.entries.iter().peekable();
        let mut right = other.entries.iter().peekable();
        loop {
            let entry = match (left.peek(), right.peek()) {
                (None, None) => break,
                (Some(_), None) => left.next().cloned(),
                (None, Some(_)) => right.next().cloned(),
                (Some((a, x)), Some((b, y))) => match a.cmp(b) {
                    core::cmp::Ordering::Less => left.next().cloned(),
                    core::cmp::Ordering::Greater => right.next().cloned(),
                    core::cmp::Ordering::Equal => {
                        let sum = x.checked_add(*y).ok_or(Error::Overflow)?;
                        let account = a.clone();
                        left.next();
                        right.next();
                        Some((account, sum))
                    }
                },
            };
            entries.extend(entry);
        }
        Self::from_sorted(entries)
    }

    /// Returns the index of `account` in the entries.
    pub(crate) fn position(&self, account: &P) -> Option<usize> {
        self.entries
            .binary_search_by(|(candidate, _)| candidate.cmp(account))
            .ok()
    }

    /// Builds the tree committing to the entries.
    pub(crate) fn tree<H: Hasher>(&self) -> Tree<H::Digest> {
        let mut builder = Builder::<H>::new(self.entries.len());
        for (account, amount) in &self.entries {
            builder.add(&leaf::<H, P, A>(account, *amount));
        }
        builder.build()
    }

    /// Returns the commitment to the entries.
    pub fn root<H: Hasher>(&self) -> H::Digest {
        self.tree::<H>().root()
    }

    /// Opens the amount of `account` under `tree`. The tree must come from [Self::tree].
    pub(crate) fn lookup<D: Digest>(&self, tree: &Tree<D>, account: &P) -> Lookup<P, A, D> {
        Lookup::new(&self.entries, tree, account)
    }
}

impl<P: PublicKey, A: Amount> Write for Amounts<P, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.entries.write(buf);
    }
}

impl<P: PublicKey, A: Amount> EncodeSize for Amounts<P, A> {
    fn encode_size(&self) -> usize {
        self.entries.encode_size()
    }
}

impl<P: PublicKey, A: Amount> Read for Amounts<P, A> {
    /// The accepted number of entries.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        let entries = Vec::<(P, A)>::read_cfg(buf, &(*range, ((), ())))?;
        Self::from_sorted(entries).map_err(|_| {
            CodecError::Invalid(
                "clearing::bajillion::Amounts",
                "entries must be strictly increasing by account with nonzero amounts",
            )
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, A: Amount> arbitrary::Arbitrary<'_> for Amounts<P, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut entries: Vec<(P, A)> = u.arbitrary()?;
        entries.retain(|(_, amount)| *amount != A::ZERO);
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        entries.dedup_by(|(a, _), (b, _)| a == b);
        Ok(Self { entries })
    }
}

/// Draws an arbitrary nonzero amount.
#[cfg(feature = "arbitrary")]
pub(crate) fn arbitrary_nonzero<A>(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<A>
where
    A: Amount + From<u64> + for<'a> arbitrary::Arbitrary<'a>,
{
    let amount: A = u.arbitrary()?;
    Ok(if amount == A::ZERO {
        A::from(1)
    } else {
        amount
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{
        Sha256, Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };

    type TestAmounts = Amounts<PublicKey, u64>;

    /// Returns `count` public keys in increasing order.
    fn keys(count: u64) -> Vec<PublicKey> {
        let mut keys: Vec<_> = (0..count)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn test_new_sorts_entries() {
        let keys = keys(4);
        let amounts = TestAmounts::new([
            (keys[2].clone(), 3),
            (keys[0].clone(), 1),
            (keys[1].clone(), 2),
        ])
        .unwrap();
        let entries: Vec<_> = amounts
            .iter()
            .map(|(key, amount)| (key.clone(), amount))
            .collect();
        assert_eq!(
            entries,
            vec![
                (keys[0].clone(), 1),
                (keys[1].clone(), 2),
                (keys[2].clone(), 3)
            ]
        );
        assert_eq!(amounts.len(), 3);
        assert_eq!(amounts.total(), Some(6));
        assert_eq!(amounts.get(&keys[1]), 2);
        assert_eq!(amounts.get(&keys[3]), 0);
    }

    #[test]
    fn test_new_rejects_invalid_entries() {
        let keys = keys(2);
        assert!(matches!(
            TestAmounts::new([(keys[0].clone(), 0)]),
            Err(Error::ZeroAmount)
        ));
        assert!(matches!(
            TestAmounts::new([(keys[0].clone(), 1), (keys[0].clone(), 2)]),
            Err(Error::DuplicateAccount)
        ));
        assert!(TestAmounts::new([]).unwrap().is_empty());
    }

    #[test]
    fn test_combine() {
        let keys = keys(3);
        let left = TestAmounts::new([(keys[0].clone(), 1), (keys[1].clone(), 2)]).unwrap();
        let right = TestAmounts::new([(keys[1].clone(), 3), (keys[2].clone(), 4)]).unwrap();
        let combined = left.combine(&right).unwrap();
        assert_eq!(combined, right.combine(&left).unwrap());
        assert_eq!(
            combined,
            TestAmounts::new([
                (keys[0].clone(), 1),
                (keys[1].clone(), 5),
                (keys[2].clone(), 4)
            ])
            .unwrap()
        );
        assert_eq!(left.combine(&TestAmounts::empty()).unwrap(), left);

        let full = TestAmounts::new([(keys[0].clone(), u64::MAX)]).unwrap();
        let one = TestAmounts::new([(keys[0].clone(), 1)]).unwrap();
        assert!(matches!(full.combine(&one), Err(Error::Overflow)));
        let overflowing = TestAmounts::new([(keys[0].clone(), u64::MAX), (keys[1].clone(), 1)]);
        assert_eq!(overflowing.unwrap().total(), None);
    }

    #[test]
    fn test_leaf_hashes_account_and_big_endian_amount() {
        let key = &keys(1)[0];
        assert_eq!(
            leaf::<Sha256, _, u64>(key, 5),
            Sha256::hash(&[key.as_ref(), &5u64.to_be_bytes()])
        );
        assert_eq!(
            leaf::<Sha256, _, u128>(key, 5),
            Sha256::hash(&[key.as_ref(), &5u128.to_be_bytes()])
        );
    }

    #[test]
    fn test_root_commits_to_entries() {
        let keys = keys(2);
        let empty = TestAmounts::empty();
        assert_eq!(
            empty.root::<Sha256>(),
            Builder::<Sha256>::new(0).build().root()
        );

        // Every account and amount, and the number of entries, changes the root.
        let one = TestAmounts::new([(keys[0].clone(), 1)]).unwrap();
        let roots = [
            empty.root::<Sha256>(),
            one.root::<Sha256>(),
            TestAmounts::new([(keys[0].clone(), 2)])
                .unwrap()
                .root::<Sha256>(),
            TestAmounts::new([(keys[1].clone(), 1)])
                .unwrap()
                .root::<Sha256>(),
            one.combine(&TestAmounts::new([(keys[1].clone(), 1)]).unwrap())
                .unwrap()
                .root::<Sha256>(),
        ];
        for (i, a) in roots.iter().enumerate() {
            for b in &roots[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn test_lookup() {
        let keys = keys(5);
        let amounts = TestAmounts::new([(keys[1].clone(), 10), (keys[3].clone(), 30)]).unwrap();
        let root = amounts.root::<Sha256>();
        let tree = amounts.tree::<Sha256>();
        for key in &keys {
            let lookup = amounts.lookup(&tree, key);
            let value = lookup
                .verify::<Sha256>(&root, key, |key, amount| leaf::<Sha256, _, _>(key, *amount))
                .unwrap()
                .copied();
            assert_eq!(value.unwrap_or(0), amounts.get(key));
        }
    }

    #[test]
    fn test_decode_rejects_non_canonical_entries() {
        let keys = keys(2);
        let range = RangeCfg::new(..=8);
        for entries in [
            vec![(keys[1].clone(), 1u64), (keys[0].clone(), 1)],
            vec![(keys[0].clone(), 1), (keys[0].clone(), 2)],
            vec![(keys[0].clone(), 0)],
        ] {
            assert!(TestAmounts::decode_cfg(entries.encode(), &range).is_err());
        }

        let amounts = TestAmounts::new([(keys[0].clone(), 1), (keys[1].clone(), 2)]).unwrap();
        let encoded = amounts.encode();
        assert_eq!(
            TestAmounts::decode_cfg(encoded.clone(), &range).unwrap(),
            amounts
        );
        assert!(TestAmounts::decode_cfg(encoded, &RangeCfg::new(..=1)).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Amounts<PublicKey, u64>>,
        }
    }
}
