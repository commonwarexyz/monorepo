//! Amounts of funds, and nonzero amounts per account committed with a binary Merkle tree.

use super::{Amount, Lookup};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_storage::bmt::{Builder, Tree};
use commonware_utils::Widen;
use core::cmp::Ordering;
use thiserror::Error;

/// Why entries do not form amounts, or two amounts do not add up.
#[derive(Debug, Error)]
pub enum AmountsError {
    /// An amount is zero.
    #[error("amount is zero")]
    ZeroAmount,
    /// An account appears more than once.
    #[error("account appears more than once")]
    Duplicate,
    /// There are more entries than a tree can commit to.
    #[error("too many entries")]
    TooManyEntries,
    /// A sum overflows.
    #[error("arithmetic overflow")]
    Overflow,
}

/// Computes the leaf committing to `amount` for `account`.
pub(crate) fn leaf<H: Hasher, P: PublicKey, A: Amount>(account: &P, amount: A) -> H::Digest {
    H::hash(&[account.as_ref(), amount.encode().as_ref()])
}

/// Nonzero amounts per account, sorted by account.
///
/// Their root ([Amounts::root]) is that of a binary Merkle tree whose leaves are the `(account,
/// amount)` entries in account order. It also binds the number of entries, so a [Lookup] of two
/// adjacent entries proves that an account between them has no amount.
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
    pub fn new(entries: impl IntoIterator<Item = (P, A)>) -> Result<Self, AmountsError> {
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        Self::from_sorted(entries)
    }

    /// Wraps `entries` already in account order.
    pub(crate) fn from_sorted(entries: Vec<(P, A)>) -> Result<Self, AmountsError> {
        let widest: usize = Widen::widen(u32::MAX);
        if entries.len() > widest {
            return Err(AmountsError::TooManyEntries);
        }
        if entries.iter().any(|(_, amount)| *amount == A::ZERO) {
            return Err(AmountsError::ZeroAmount);
        }
        if entries.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(AmountsError::Duplicate);
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
    pub fn combine(&self, other: &Self) -> Result<Self, AmountsError> {
        let mut entries = Vec::with_capacity(self.entries.len() + other.entries.len());
        let mut left = self.entries.iter().peekable();
        let mut right = other.entries.iter().peekable();
        loop {
            let entry = match (left.peek(), right.peek()) {
                (None, None) => break,
                (Some(_), None) => left.next().cloned(),
                (None, Some(_)) => right.next().cloned(),
                (Some((a, x)), Some((b, y))) => match a.cmp(b) {
                    Ordering::Less => left.next().cloned(),
                    Ordering::Greater => right.next().cloned(),
                    Ordering::Equal => {
                        let sum = x.checked_add(*y).ok_or(AmountsError::Overflow)?;
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

/// Draws arbitrary amounts that pay at least one account.
#[cfg(feature = "arbitrary")]
pub(crate) fn arbitrary_nonempty<P, A>(
    u: &mut arbitrary::Unstructured<'_>,
) -> arbitrary::Result<Amounts<P, A>>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    A: Amount + for<'a> arbitrary::Arbitrary<'a>,
{
    let amounts = u.arbitrary::<Amounts<P, A>>()?;
    if amounts.is_empty() {
        return Err(arbitrary::Error::IncorrectFormat);
    }
    Ok(amounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::tests::accounts;
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{Sha256, ed25519::PublicKey};
    use commonware_utils::U256;

    type TestAmounts = Amounts<PublicKey, u64>;

    #[test]
    fn test_new_sorts_entries() {
        let keys = accounts(4);
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
        let keys = accounts(2);
        assert!(matches!(
            TestAmounts::new([(keys[0].clone(), 0)]),
            Err(AmountsError::ZeroAmount)
        ));
        assert!(matches!(
            TestAmounts::new([(keys[0].clone(), 1), (keys[0].clone(), 2)]),
            Err(AmountsError::Duplicate)
        ));
        assert!(TestAmounts::new([]).unwrap().is_empty());
    }

    #[test]
    fn test_combine() {
        let keys = accounts(3);
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
        assert!(matches!(full.combine(&one), Err(AmountsError::Overflow)));
        let overflowing = TestAmounts::new([(keys[0].clone(), u64::MAX), (keys[1].clone(), 1)]);
        assert_eq!(overflowing.unwrap().total(), None);
    }

    #[test]
    fn test_leaf_hashes_account_and_big_endian_amount() {
        let key = &accounts(1)[0];
        assert_eq!(
            leaf::<Sha256, _, u64>(key, 5),
            Sha256::hash(&[key.as_ref(), &5u64.to_be_bytes()])
        );
        assert_eq!(
            leaf::<Sha256, _, u128>(key, 5),
            Sha256::hash(&[key.as_ref(), &5u128.to_be_bytes()])
        );
        let mut five = [0u8; 32];
        five[31] = 5;
        assert_eq!(
            leaf::<Sha256, _, U256>(key, U256::from(5)),
            Sha256::hash(&[key.as_ref(), &five])
        );
    }

    #[test]
    fn test_root_commits_to_entries() {
        let keys = accounts(2);
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
        let keys = accounts(5);
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
        let keys = accounts(2);
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
