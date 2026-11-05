//! Nonzero amounts per account, committed with a binary Merkle tree.

use super::{Error, Lookup};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_storage::bmt::{Builder, Tree};

/// Computes the leaf committing to `amount` for `account`.
pub(crate) fn leaf<H: Hasher, P: PublicKey>(account: &P, amount: u64) -> H::Digest {
    H::hash(&[account.as_ref(), &amount.to_be_bytes()])
}

/// Nonzero amounts per account, sorted by account.
///
/// Payment maps, request batches, and the payouts of a close are all [Amounts]. They are
/// committed by the root of a binary Merkle tree whose leaves are the `(account, amount)` entries
/// in account order. The root also binds the number of entries, so two adjacent openings prove
/// that an account between them has no amount (see [Lookup]).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Amounts<P: PublicKey> {
    entries: Vec<(P, u64)>,
}

impl<P: PublicKey> Default for Amounts<P> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<P: PublicKey> Amounts<P> {
    /// Returns amounts with no entries.
    pub const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Collects `entries` in account order.
    ///
    /// Returns an error if an amount is zero, an account appears more than once, or there are
    /// more than `u32::MAX` entries.
    pub fn new(entries: impl IntoIterator<Item = (P, u64)>) -> Result<Self, Error> {
        let mut entries: Vec<_> = entries.into_iter().collect();
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        Self::from_sorted(entries)
    }

    /// Wraps entries that must be strictly increasing by account with nonzero amounts.
    pub(crate) fn from_sorted(entries: Vec<(P, u64)>) -> Result<Self, Error> {
        if entries.len() > u32::MAX as usize {
            return Err(Error::TooManyEntries);
        }
        if entries.iter().any(|(_, amount)| *amount == 0) {
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
    pub fn get(&self, account: &P) -> u64 {
        self.position(account)
            .map_or(0, |position| self.entries[position].1)
    }

    /// Iterates over the entries in account order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&P, u64)> {
        self.entries
            .iter()
            .map(|(account, amount)| (account, *amount))
    }

    /// Returns the sum of all amounts.
    pub fn total(&self) -> u128 {
        self.entries
            .iter()
            .map(|(_, amount)| u128::from(*amount))
            .sum()
    }

    /// Returns the amounts with `other` added entry by entry.
    ///
    /// Returns an error if a sum exceeds `u64::MAX`.
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
            builder.add(&leaf::<H, P>(account, *amount));
        }
        builder.build()
    }

    /// Returns the commitment to the entries.
    pub fn root<H: Hasher>(&self) -> H::Digest {
        self.tree::<H>().root()
    }

    /// Opens the amount of `account` under `tree`. The tree must come from [Self::tree].
    pub(crate) fn lookup<D: Digest>(&self, tree: &Tree<D>, account: &P) -> Lookup<P, u64, D> {
        Lookup::new(&self.entries, tree, account)
    }
}

impl<P: PublicKey> Write for Amounts<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.entries.write(buf);
    }
}

impl<P: PublicKey> EncodeSize for Amounts<P> {
    fn encode_size(&self) -> usize {
        self.entries.encode_size()
    }
}

impl<P: PublicKey> Read for Amounts<P> {
    /// The accepted number of entries.
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        let entries = Vec::<(P, u64)>::read_cfg(buf, &(*range, ((), ())))?;
        Self::from_sorted(entries).map_err(|_| {
            CodecError::Invalid(
                "clearing::bajillion::Amounts",
                "entries must be strictly increasing by account with nonzero amounts",
            )
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey> arbitrary::Arbitrary<'_> for Amounts<P>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let mut entries: Vec<(P, u64)> = u.arbitrary()?;
        entries.retain(|(_, amount)| *amount != 0);
        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        entries.dedup_by(|(a, _), (b, _)| a == b);
        Ok(Self { entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{
        Sha256, Signer as _,
        ed25519::{PrivateKey, PublicKey},
    };

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
        let amounts = Amounts::new([
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
        assert_eq!(amounts.total(), 6);
        assert_eq!(amounts.get(&keys[1]), 2);
        assert_eq!(amounts.get(&keys[3]), 0);
    }

    #[test]
    fn test_new_rejects_invalid_entries() {
        let keys = keys(2);
        assert!(matches!(
            Amounts::new([(keys[0].clone(), 0)]),
            Err(Error::ZeroAmount)
        ));
        assert!(matches!(
            Amounts::new([(keys[0].clone(), 1), (keys[0].clone(), 2)]),
            Err(Error::DuplicateAccount)
        ));
        assert!(Amounts::<PublicKey>::new([]).unwrap().is_empty());
    }

    #[test]
    fn test_combine() {
        let keys = keys(3);
        let left = Amounts::new([(keys[0].clone(), 1), (keys[1].clone(), 2)]).unwrap();
        let right = Amounts::new([(keys[1].clone(), 3), (keys[2].clone(), 4)]).unwrap();
        let combined = left.combine(&right).unwrap();
        assert_eq!(combined, right.combine(&left).unwrap());
        assert_eq!(
            combined,
            Amounts::new([
                (keys[0].clone(), 1),
                (keys[1].clone(), 5),
                (keys[2].clone(), 4)
            ])
            .unwrap()
        );
        assert_eq!(left.combine(&Amounts::empty()).unwrap(), left);

        let full = Amounts::new([(keys[0].clone(), u64::MAX)]).unwrap();
        let one = Amounts::new([(keys[0].clone(), 1)]).unwrap();
        assert!(matches!(full.combine(&one), Err(Error::Overflow)));
    }

    #[test]
    fn test_root_commits_to_entries() {
        let keys = keys(2);
        let empty = Amounts::<PublicKey>::empty();
        assert_eq!(
            empty.root::<Sha256>(),
            Builder::<Sha256>::new(0).build().root()
        );

        // Every account and amount, and the number of entries, changes the root.
        let one = Amounts::new([(keys[0].clone(), 1)]).unwrap();
        let roots = [
            empty.root::<Sha256>(),
            one.root::<Sha256>(),
            Amounts::new([(keys[0].clone(), 2)])
                .unwrap()
                .root::<Sha256>(),
            Amounts::new([(keys[1].clone(), 1)])
                .unwrap()
                .root::<Sha256>(),
            one.combine(&Amounts::new([(keys[1].clone(), 1)]).unwrap())
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
        let amounts = Amounts::new([(keys[1].clone(), 10), (keys[3].clone(), 30)]).unwrap();
        let root = amounts.root::<Sha256>();
        let tree = amounts.tree::<Sha256>();
        for key in &keys {
            let lookup = amounts.lookup(&tree, key);
            let value = lookup
                .verify::<Sha256>(key, &root, |key, amount| leaf::<Sha256, _>(key, *amount))
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
            assert!(Amounts::<PublicKey>::decode_cfg(entries.encode(), &range).is_err());
        }

        let amounts = Amounts::new([(keys[0].clone(), 1), (keys[1].clone(), 2)]).unwrap();
        let encoded = amounts.encode();
        assert_eq!(
            Amounts::<PublicKey>::decode_cfg(encoded.clone(), &range).unwrap(),
            amounts
        );
        assert!(Amounts::<PublicKey>::decode_cfg(encoded, &RangeCfg::new(..=1)).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Amounts<PublicKey>>,
        }
    }
}
