//! Per-payer outgoing vectors.
//!
//! A payer's epoch activity is a vector of cumulative entries ordered by canonical recipient bytes.
//! Its root authenticates the amount and payment count promised to each recipient.

use crate::bajillion::{
    commitment::{self, VectorKind, VectorRoot},
    payment::{Amount, Epoch},
};
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Sequential;
use thiserror::Error;

/// One cumulative per-recipient entry of a payer's outgoing vector.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OutEntry<P: PublicKey> {
    /// Credited recipient.
    pub recipient: P,
    /// Epoch-cumulative credit from the owning payer to this recipient.
    pub cumulative: Amount,
    /// Number of payments from the owning payer to this recipient this epoch.
    pub count: u64,
}

impl<P: PublicKey> OutEntry<P> {
    const fn validate(&self) -> Result<(), Error> {
        // Every payment moves at least one unit, so the cumulative covers the count.
        if self.cumulative == 0 || self.count == 0 || self.cumulative < self.count {
            return Err(Error::InfeasibleEntry);
        }
        Ok(())
    }
}

impl<P: PublicKey> Write for OutEntry<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.recipient.write(buf);
        self.cumulative.write(buf);
        self.count.write(buf);
    }
}

impl<P: PublicKey> FixedSize for OutEntry<P> {
    const SIZE: usize = P::SIZE + u64::SIZE * 2;
}

impl<P: PublicKey> Read for OutEntry<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            recipient: P::read(buf)?,
            cumulative: u64::read(buf)?,
            count: u64::read(buf)?,
        })
    }
}

/// Complete canonical outgoing vector for one payer and epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutVector<P: PublicKey> {
    epoch: Epoch,
    payer: P,
    entries: Vec<OutEntry<P>>,
}

impl<P: PublicKey> OutVector<P> {
    /// Creates a vector from entries with strictly increasing canonical recipient bytes.
    pub fn new(epoch: Epoch, payer: P, entries: Vec<OutEntry<P>>) -> Result<Self, Error> {
        let vector = Self {
            epoch,
            payer,
            entries,
        };
        vector.validate()?;
        Ok(vector)
    }

    /// Creates the canonical empty vector for a payer and epoch.
    #[must_use]
    pub const fn empty(epoch: Epoch, payer: P) -> Self {
        Self {
            epoch,
            payer,
            entries: Vec::new(),
        }
    }

    /// Returns the epoch this vector belongs to.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the owning payer.
    #[must_use]
    pub const fn payer(&self) -> &P {
        &self.payer
    }

    /// Returns entries ordered by canonical recipient bytes.
    #[must_use]
    pub fn entries(&self) -> &[OutEntry<P>] {
        &self.entries
    }

    fn validate(&self) -> Result<(u64, u64), Error> {
        if self.entries.len() > commitment::MAX_VECTOR_LENGTH as usize {
            return Err(Error::TooManyEntries);
        }
        if self
            .entries
            .windows(2)
            .any(|pair| pair[0].recipient.as_ref() >= pair[1].recipient.as_ref())
        {
            return Err(Error::NonCanonicalOrder);
        }
        let mut total_credit = 0_u64;
        let mut total_count = 0_u64;
        for entry in &self.entries {
            entry.validate()?;
            total_credit = total_credit
                .checked_add(entry.cumulative)
                .ok_or(Error::Arithmetic)?;
            total_count = total_count
                .checked_add(entry.count)
                .ok_or(Error::Arithmetic)?;
        }
        Ok((total_credit, total_count))
    }

    /// Returns the checked cumulative-credit and payment-count totals.
    pub fn totals(&self) -> Result<(u64, u64), Error> {
        self.validate()
    }

    fn commitment<H, D>(&self) -> Result<commitment::Tree<D>, Error>
    where
        H: Hasher<Digest = D>,
        D: Digest,
    {
        self.validate()?;
        let len = u32::try_from(self.entries.len()).map_err(|_| Error::TooManyEntries)?;
        let mut builder = commitment::Builder::<H>::new(VectorKind::OutEntry, len)?;
        builder.add_values(&self.entries, &Sequential)?;
        Ok(builder.build(&Sequential)?)
    }

    /// Computes the exact typed vector root.
    pub fn root<H, D>(&self) -> Result<VectorRoot<D>, Error>
    where
        H: Hasher<Digest = D>,
        D: Digest,
    {
        self.commitment::<H, D>().map(|tree| tree.root())
    }

    /// Produces either a membership opening or an adjacent-neighbor absence proof.
    pub fn lookup<H, D>(&self, recipient: &P) -> Result<OutTipLookup<P, D>, Error>
    where
        H: Hasher<Digest = D>,
        D: Digest,
    {
        let tree = self.commitment::<H, D>()?;
        match self
            .entries
            .binary_search_by(|entry| entry.recipient.as_ref().cmp(recipient.as_ref()))
        {
            Ok(position) => Ok(OutTipLookup::Present {
                cumulative: self.entries[position].cumulative,
                count: self.entries[position].count,
                opening: tree
                    .opening(u32::try_from(position).map_err(|_| Error::IndexOutOfRange)?)?,
            }),
            Err(position) => {
                let position = u32::try_from(position).map_err(|_| Error::IndexOutOfRange)?;
                let (predecessor, successor, opening) =
                    tree.bracket(&self.entries, position..position)?;
                Ok(OutTipLookup::Absent {
                    predecessor,
                    successor,
                    opening,
                })
            }
        }
    }
}

impl<P: PublicKey> Write for OutVector<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.payer.write(buf);
        self.entries.write(buf);
    }
}

impl<P: PublicKey> Read for OutVector<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let epoch = Epoch::read(buf)?;
        let payer = P::read(buf)?;
        let entries = Vec::<OutEntry<P>>::read_cfg(
            buf,
            &(RangeCfg::new(..=commitment::MAX_VECTOR_LENGTH as usize), ()),
        )?;
        let vector = Self {
            epoch,
            payer,
            entries,
        };
        vector
            .validate()
            .map_err(|_| CodecError::Invalid("OutVector", "outgoing vector is not canonical"))?;
        Ok(vector)
    }
}

impl<P: PublicKey> EncodeSize for OutVector<P> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.payer.encode_size() + self.entries.encode_size()
    }
}

/// Authenticated answer to an outgoing-entry lookup under one payer vector root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutTipLookup<P: PublicKey, D: Digest> {
    /// The requested recipient is present.
    Present {
        /// Authenticated cumulative credit.
        cumulative: Amount,
        /// Authenticated payment count.
        count: u64,
        /// Membership opening for the entry.
        opening: commitment::Opening<D>,
    },
    /// The requested recipient is absent, bracketed by adjacent vector neighbors.
    Absent {
        /// Immediate predecessor, or `None` at the beginning of the vector.
        predecessor: Option<OutEntry<P>>,
        /// Immediate successor, or `None` at the end of the vector.
        successor: Option<OutEntry<P>>,
        /// One shared opening for the adjacent disclosed neighbors.
        opening: commitment::RangeOpening<D>,
    },
}

impl<P: PublicKey, D: Digest> OutTipLookup<P, D> {
    /// Reconstructs the vector root this lookup authenticates and the resolved entry value.
    ///
    /// An absent recipient resolves to the canonical zero entry.
    pub fn reconstruct<H: Hasher<Digest = D>>(
        &self,
        recipient: &P,
    ) -> Result<(VectorRoot<D>, Amount, u64), Error> {
        match self {
            Self::Present {
                cumulative,
                count,
                opening,
            } => {
                let entry = OutEntry {
                    recipient: recipient.clone(),
                    cumulative: *cumulative,
                    count: *count,
                };
                entry.validate()?;
                let root =
                    opening.reconstruct::<H>(VectorKind::OutEntry, entry.encode().as_ref())?;
                Ok((root, *cumulative, *count))
            }
            Self::Absent {
                predecessor,
                successor,
                opening,
            } => {
                opening
                    .bracket(predecessor.is_some(), 0, successor.is_some())
                    .ok_or(Error::LookupOrder)?;
                if predecessor.as_ref().is_some_and(|entry| {
                    entry.recipient.as_ref() >= recipient.as_ref() || entry.validate().is_err()
                }) || successor.as_ref().is_some_and(|entry| {
                    entry.recipient.as_ref() <= recipient.as_ref() || entry.validate().is_err()
                }) {
                    return Err(Error::LookupOrder);
                }
                let encoded = predecessor
                    .iter()
                    .chain(successor.iter())
                    .map(Encode::encode)
                    .collect::<Vec<_>>();
                let root = opening.reconstruct::<H, _>(VectorKind::OutEntry, &encoded)?;
                Ok((root, 0, 0))
            }
        }
    }

    /// Verifies the lookup against a trusted vector root and resolves the entry value.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        root: &VectorRoot<D>,
        recipient: &P,
    ) -> Result<(Amount, u64), Error> {
        let (reconstructed, cumulative, count) = self.reconstruct::<H>(recipient)?;
        if reconstructed != *root {
            return Err(commitment::Error::InvalidOpening.into());
        }
        Ok((cumulative, count))
    }
}

impl<P: PublicKey, D: Digest> Write for OutTipLookup<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present {
                cumulative,
                count,
                opening,
            } => {
                1_u8.write(buf);
                cumulative.write(buf);
                count.write(buf);
                opening.write(buf);
            }
            Self::Absent {
                predecessor,
                successor,
                opening,
            } => {
                2_u8.write(buf);
                predecessor.write(buf);
                successor.write(buf);
                opening.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> Read for OutTipLookup<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::Present {
                cumulative: u64::read(buf)?,
                count: u64::read(buf)?,
                opening: commitment::Opening::read(buf)?,
            }),
            2 => Ok(Self::Absent {
                predecessor: Option::<OutEntry<P>>::read(buf)?,
                successor: Option::<OutEntry<P>>::read(buf)?,
                opening: commitment::RangeOpening::read_bounded(buf, 2, usize::MAX)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for OutTipLookup<P, D> {
    fn encode_size(&self) -> usize {
        match self {
            Self::Present { opening, .. } => u8::SIZE + u64::SIZE * 2 + opening.encode_size(),
            Self::Absent {
                predecessor,
                successor,
                opening,
            } => {
                u8::SIZE
                    + predecessor.encode_size()
                    + successor.encode_size()
                    + opening.encode_size()
            }
        }
    }
}

/// Errors returned while constructing or verifying outgoing vectors.
#[derive(Debug, Error)]
pub enum Error {
    /// The outgoing vector exceeds the protocol bound.
    #[error("outgoing vector exceeds the protocol bound")]
    TooManyEntries,
    /// Entries are not strictly recipient-sorted and unique.
    #[error("outgoing entries are not strictly recipient-sorted and unique")]
    NonCanonicalOrder,
    /// An entry endpoint cannot be reached by positive payments.
    #[error("entry endpoint has no positive-payment completion")]
    InfeasibleEntry,
    /// Summing entry endpoints overflowed.
    #[error("outgoing aggregate arithmetic overflowed")]
    Arithmetic,
    /// An opening position is outside the committed vector.
    #[error("outgoing opening position is outside the committed vector")]
    IndexOutOfRange,
    /// An absence proof does not contain the adjacent ordered neighbors.
    #[error("outgoing absence proof is not an adjacent ordered bracket")]
    LookupOrder,
    /// The generic vector commitment is invalid.
    #[error("invalid vector commitment: {0}")]
    Commitment(#[from] commitment::Error),
}

#[cfg(feature = "arbitrary")]
mod arbitrary_impls {
    use super::*;

    impl<'a, P> arbitrary::Arbitrary<'a> for OutVector<P>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let epoch = u.arbitrary()?;
            let payer = u.arbitrary()?;
            let mut recipients = Vec::new();
            for _ in 0..u.int_in_range(0..=4_usize)? {
                recipients.push(u.arbitrary::<P>()?);
            }
            recipients.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
            recipients.dedup_by(|a, b| a.as_ref() == b.as_ref());
            let entries = recipients
                .into_iter()
                .map(|recipient| {
                    let count = u.int_in_range(1..=u64::from(u16::MAX))?;
                    let cumulative = count.saturating_add(u.arbitrary::<u32>()?.into());
                    Ok(OutEntry {
                        recipient,
                        cumulative,
                        count,
                    })
                })
                .collect::<arbitrary::Result<Vec<_>>>()?;
            Ok(Self {
                epoch,
                payer,
                entries,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for OutTipLookup<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest + arbitrary::Arbitrary<'a>,
        commitment::Opening<D>: arbitrary::Arbitrary<'a>,
        commitment::RangeOpening<D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            if u.arbitrary()? {
                Ok(Self::Present {
                    cumulative: u.arbitrary()?,
                    count: u.arbitrary()?,
                    opening: u.arbitrary()?,
                })
            } else {
                Ok(Self::Absent {
                    predecessor: u.arbitrary()?,
                    successor: u.arbitrary()?,
                    opening: u.arbitrary()?,
                })
            }
        }
    }

    impl<'a, P> arbitrary::Arbitrary<'a> for OutEntry<P>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                recipient: u.arbitrary()?,
                cumulative: u.arbitrary()?,
                count: u.arbitrary()?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Sha256, Signer as _, sha256::Digest as ShaDigest};
    use commonware_cryptography_curve25519::signing::{
        SigningKey, StrictVerifyingKey as VerifyingKey,
    };

    fn account(seed: u64) -> VerifyingKey {
        SigningKey::from_seed(seed).public_key()
    }

    fn vector(entries: usize) -> OutVector<VerifyingKey> {
        let mut recipients = (0..entries as u64).map(account).collect::<Vec<_>>();
        recipients.sort_unstable();
        let entries = recipients
            .into_iter()
            .enumerate()
            .map(|(index, recipient)| OutEntry {
                recipient,
                cumulative: 10 + index as u64,
                count: 1 + index as u64,
            })
            .collect();
        OutVector::new(7, account(1_000), entries).unwrap()
    }

    #[test]
    fn lookup_membership_and_absence_resolve() {
        let vector = vector(5);
        let root = vector.root::<Sha256, ShaDigest>().unwrap();
        for entry in vector.entries() {
            let lookup = vector
                .lookup::<Sha256, ShaDigest>(&entry.recipient)
                .unwrap();
            assert_eq!(
                lookup.resolve::<Sha256>(&root, &entry.recipient).unwrap(),
                (entry.cumulative, entry.count)
            );
        }
        let missing = account(9_999);
        assert!(
            vector
                .entries()
                .binary_search_by(|entry| entry.recipient.cmp(&missing))
                .is_err()
        );
        let lookup = vector.lookup::<Sha256, ShaDigest>(&missing).unwrap();
        assert_eq!(lookup.resolve::<Sha256>(&root, &missing).unwrap(), (0, 0));
    }

    #[test]
    fn non_canonical_vectors_are_rejected() {
        let mut entries = vector(3).entries().to_vec();
        entries.reverse();
        assert!(matches!(
            OutVector::new(7, account(1_000), entries),
            Err(Error::NonCanonicalOrder)
        ));

        let infeasible = vec![OutEntry {
            recipient: account(5),
            cumulative: 2,
            count: 3,
        }];
        assert!(matches!(
            OutVector::new(7, account(1_000), infeasible),
            Err(Error::InfeasibleEntry)
        ));
    }
}
