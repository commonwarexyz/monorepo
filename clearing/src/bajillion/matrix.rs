//! The payment matrix a close settles.

use super::{Amount, Amounts, InvalidOpening, Lookup, amounts};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_storage::bmt::{Builder, Tree};
use commonware_utils::Widen;
use core::fmt::{self, Debug, Formatter};
use std::sync::{Arc, OnceLock};

/// Computes the leaf committing to `sender`'s payment map with root `payments`.
fn leaf<H: Hasher, P: PublicKey>(sender: &P, payments: &H::Digest) -> H::Digest {
    H::hash(&[sender.as_ref(), payments.as_ref()])
}

/// Builds the tree over rows that are strictly increasing by sender.
fn tree<'a, H: Hasher, P: PublicKey>(
    rows: impl ExactSizeIterator<Item = (&'a P, &'a H::Digest)>,
) -> Tree<H::Digest> {
    let mut builder = Builder::<H>::new(rows.len());
    for (sender, payments) in rows {
        builder.add(&leaf::<H, P>(sender, payments));
    }
    builder.build()
}

/// Computes the root of the matrix with rows that are strictly increasing by sender.
pub(crate) fn root<'a, H: Hasher, P: PublicKey>(
    rows: impl ExactSizeIterator<Item = (&'a P, &'a H::Digest)>,
) -> H::Digest {
    tree::<H, P>(rows).root()
}

/// The payment maps a close settles, one row per sender.
///
/// The matrix commits to a binary Merkle tree of `(sender, payment map root)` leaves in sender
/// order, and opens rows with the hasher `H` that committed it. An [Opening] proves what one
/// sender paid one receiver, or that it paid nothing. Clones share the rows.
pub struct Matrix<P: PublicKey, H: Hasher, A: Amount> {
    inner: Arc<Inner<P, H, A>>,
}

struct Inner<P: PublicKey, H: Hasher, A: Amount> {
    /// Senders and the roots of their payment maps, in sender order.
    rows: Vec<(P, H::Digest)>,
    /// Payment maps aligned with `rows`.
    payments: Vec<Amounts<P, A>>,
    /// Trees over the payment maps, built the first time a row is opened.
    trees: Vec<OnceLock<Tree<H::Digest>>>,
    /// Tree over the leaves of `rows`.
    tree: Tree<H::Digest>,
}

// The hasher is a type parameter only, so the derived traits would bound it.
impl<P: PublicKey, H: Hasher, A: Amount> Clone for Matrix<P, H, A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<P: PublicKey, H: Hasher, A: Amount> Debug for Matrix<P, H, A> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Matrix")
            .field("rows", &self.inner.rows)
            .field("payments", &self.inner.payments)
            .finish()
    }
}

impl<P: PublicKey, H: Hasher, A: Amount> Matrix<P, H, A> {
    /// Returns the matrix with no rows.
    pub fn empty() -> Self {
        Self::from_sorted(Vec::new())
    }

    /// Builds a matrix from rows that are strictly increasing by sender, each with a nonempty
    /// payment map and that map's root.
    pub(crate) fn from_sorted(rows: Vec<(P, Amounts<P, A>, H::Digest)>) -> Self {
        let (rows, payments): (Vec<_>, Vec<_>) = rows
            .into_iter()
            .map(|(sender, payments, root)| ((sender, root), payments))
            .unzip();
        let tree = tree::<H, P>(rows.iter().map(|(sender, root)| (sender, root)));
        let trees = rows.iter().map(|_| OnceLock::new()).collect();
        Self {
            inner: Arc::new(Inner {
                rows,
                payments,
                trees,
                tree,
            }),
        }
    }

    /// Returns the commitment to the matrix.
    pub fn root(&self) -> H::Digest {
        self.inner.tree.root()
    }

    /// Returns the number of senders with a row.
    pub fn len(&self) -> usize {
        self.inner.rows.len()
    }

    /// Returns whether no sender has a row.
    pub fn is_empty(&self) -> bool {
        self.inner.rows.is_empty()
    }

    /// Iterates over every sender's payment map, in sender order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&P, &Amounts<P, A>)> {
        self.inner
            .rows
            .iter()
            .zip(&self.inner.payments)
            .map(|((sender, _), payments)| (sender, payments))
    }

    /// Returns every sender and the root of its payment map, in sender order.
    pub(crate) fn rows(&self) -> &[(P, H::Digest)] {
        &self.inner.rows
    }

    /// Returns the index of `sender`'s row.
    fn position(&self, sender: &P) -> Option<usize> {
        self.inner
            .rows
            .binary_search_by(|(candidate, _)| candidate.cmp(sender))
            .ok()
    }

    /// Returns `sender`'s payment map, if it has a row.
    pub fn payments(&self, sender: &P) -> Option<&Amounts<P, A>> {
        self.position(sender)
            .map(|position| &self.inner.payments[position])
    }

    /// Returns the root of `sender`'s payment map, if it has a row.
    pub fn payments_root(&self, sender: &P) -> Option<H::Digest> {
        self.position(sender)
            .map(|position| self.inner.rows[position].1)
    }

    /// Opens the amount `sender` paid `receiver`, proving that it paid nothing if it did not.
    ///
    /// An opening reveals the payment it opens or, when it proves that payment absent, the sender's
    /// payments to the receivers on either side.
    pub fn open(&self, sender: &P, receiver: &P) -> Opening<P, H::Digest, A> {
        let row = Lookup::new(&self.inner.rows, &self.inner.tree, sender);
        let entry = match &row {
            Lookup::Member { position, .. } => {
                let position: usize = Widen::widen(*position);
                let payments = &self.inner.payments[position];
                let tree = self.inner.trees[position].get_or_init(|| payments.tree::<H>());
                Some(payments.lookup(tree, receiver))
            }
            Lookup::NonMember { .. } => None,
        };
        Opening { row, entry }
    }
}

/// Opening of the amount one sender paid one receiver under a [Matrix] root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening<P: PublicKey, D: Digest, A: Amount> {
    /// Opening of the sender's row, binding the root of its payment map if it has one.
    pub row: Lookup<P, D, D>,
    /// Opening of the receiver's entry under the root of the sender's payment map, present if and
    /// only if the sender has a row.
    pub entry: Option<Lookup<P, A, D>>,
}

impl<P: PublicKey, D: Digest, A: Amount> Opening<P, D, A> {
    /// Verifies the opening of `sender`'s row under the matrix root `root`.
    ///
    /// Returns the root of `sender`'s payment map, or `None` if it has no row.
    pub fn verify_row<H: Hasher<Digest = D>>(
        &self,
        root: &D,
        sender: &P,
    ) -> Result<Option<D>, InvalidOpening> {
        let row = self
            .row
            .verify::<H>(root, sender, |sender, payments| {
                leaf::<H, P>(sender, payments)
            })?
            .copied();
        if row.is_some() != self.entry.is_some() {
            return Err(InvalidOpening);
        }
        Ok(row)
    }

    /// Verifies the opening under the matrix root `root`.
    ///
    /// Returns the amount `sender` paid `receiver`, or zero if it paid nothing.
    pub fn verify<H: Hasher<Digest = D>>(
        &self,
        root: &D,
        sender: &P,
        receiver: &P,
    ) -> Result<A, InvalidOpening> {
        let (Some(payments), Some(entry)) = (self.verify_row::<H>(root, sender)?, &self.entry)
        else {
            return Ok(A::ZERO);
        };
        let amount = entry.verify::<H>(&payments, receiver, |receiver, amount| {
            amounts::leaf::<H, P, A>(receiver, *amount)
        })?;
        Ok(amount.copied().unwrap_or(A::ZERO))
    }
}

impl<P: PublicKey, D: Digest, A: Amount> Write for Opening<P, D, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.row.write(buf);
        self.entry.write(buf);
    }
}

impl<P: PublicKey, D: Digest, A: Amount> EncodeSize for Opening<P, D, A> {
    fn encode_size(&self) -> usize {
        self.row.encode_size() + self.entry.encode_size()
    }
}

impl<P: PublicKey, D: Digest, A: Amount> Read for Opening<P, D, A> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            row: Lookup::read(buf)?,
            entry: Option::<Lookup<P, A, D>>::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, D: Digest, A: Amount> arbitrary::Arbitrary<'_> for Opening<P, D, A>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            row: u.arbitrary()?,
            entry: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::tests::accounts;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{Sha256, ed25519::PublicKey};

    /// Returns the payment map paying each `(receiver, amount)`.
    fn payments(entries: &[(&PublicKey, u64)]) -> Amounts<PublicKey, u64> {
        Amounts::new(
            entries
                .iter()
                .map(|(key, amount)| ((*key).clone(), *amount)),
        )
        .unwrap()
    }

    /// Returns the matrix of `rows`. Their senders must strictly increase.
    fn matrix(rows: &[(PublicKey, Amounts<PublicKey, u64>)]) -> Matrix<PublicKey, Sha256, u64> {
        Matrix::<_, Sha256, _>::from_sorted(
            rows.iter()
                .map(|(sender, payments)| {
                    (sender.clone(), payments.clone(), payments.root::<Sha256>())
                })
                .collect(),
        )
    }

    /// Every sender and receiver pair opens to the amount paid, or zero, and every sender to the
    /// root of its row, or to no row.
    #[test]
    fn test_opens_every_pair() {
        let keys = accounts(6);
        let rows = [
            (keys[1].clone(), payments(&[(&keys[0], 5), (&keys[4], 7)])),
            (keys[3].clone(), payments(&[(&keys[1], 1)])),
            (keys[4].clone(), payments(&[(&keys[4], 2), (&keys[5], 3)])),
        ];
        let matrix = matrix(&rows);
        let root = matrix.root();
        assert_eq!(matrix.len(), 3);
        assert!(!matrix.is_empty());

        for sender in &keys {
            let payments = rows
                .iter()
                .find(|(candidate, _)| candidate == sender)
                .map(|(_, payments)| payments);
            assert_eq!(matrix.payments(sender), payments);
            for receiver in &keys {
                let opening = matrix.open(sender, receiver);
                let expected = payments.map_or(0, |payments| payments.get(receiver));
                assert_eq!(
                    opening.verify::<Sha256>(&root, sender, receiver).unwrap(),
                    expected
                );
                assert_eq!(
                    opening.verify_row::<Sha256>(&root, sender).unwrap(),
                    payments.map(Amounts::root::<Sha256>)
                );
                assert_eq!(Opening::decode(opening.encode()).unwrap(), opening);
            }
        }

        let empty = Matrix::<PublicKey, Sha256, u64>::empty();
        assert!(empty.is_empty());
        let opening = empty.open(&keys[0], &keys[1]);
        assert_eq!(
            opening
                .verify::<Sha256>(&empty.root(), &keys[0], &keys[1])
                .unwrap(),
            0
        );
    }

    /// An opening verifies with an entry from the sender's own row exactly when the sender has a
    /// row, and an opening of a payment verifies only under its own root and for its own pair.
    #[test]
    fn test_rejects_inconsistent_openings() {
        let keys = accounts(4);
        let matrix = matrix(&[
            (keys[1].clone(), payments(&[(&keys[0], 5)])),
            (keys[3].clone(), payments(&[(&keys[0], 1)])),
        ]);
        let root = matrix.root();

        // A sender with a row must open the receiver's entry, and a sender without one must not.
        let present = matrix.open(&keys[1], &keys[0]);
        let absent = matrix.open(&keys[2], &keys[0]);
        for (sender, opening) in [
            (
                &keys[1],
                Opening {
                    row: present.row.clone(),
                    entry: None,
                },
            ),
            (
                &keys[2],
                Opening {
                    row: absent.row,
                    entry: present.entry.clone(),
                },
            ),
        ] {
            assert!(matches!(
                opening.verify::<Sha256>(&root, sender, &keys[0]),
                Err(InvalidOpening)
            ));
        }

        // A sender that pays cannot be shown to have no row by opening only the row before it.
        let forged = Opening::<_, _, u64> {
            row: Lookup::NonMember {
                position: 1,
                lower: Some(matrix.inner.rows[0].clone()),
                upper: None,
                proof: matrix.inner.tree.proof(0).unwrap(),
            },
            entry: None,
        };
        assert!(matches!(
            forged.verify::<Sha256>(&root, &keys[3], &keys[0]),
            Err(InvalidOpening)
        ));

        // The entry must open under the sender's own row.
        let other = matrix.open(&keys[3], &keys[0]);
        let swapped = Opening {
            row: present.row.clone(),
            entry: other.entry,
        };
        assert!(matches!(
            swapped.verify::<Sha256>(&root, &keys[1], &keys[0]),
            Err(InvalidOpening)
        ));

        // An opening of a payment verifies only under its own root and for its own pair.
        let other_root = Matrix::<PublicKey, Sha256, u64>::empty().root();
        assert!(
            present
                .verify::<Sha256>(&other_root, &keys[1], &keys[0])
                .is_err()
        );
        assert!(present.verify::<Sha256>(&root, &keys[3], &keys[0]).is_err());
        assert!(present.verify::<Sha256>(&root, &keys[1], &keys[2]).is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<Opening<PublicKey, Digest, u64>>,
        }
    }
}
