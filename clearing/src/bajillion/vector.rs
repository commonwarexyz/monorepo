//! Per-payer outgoing vectors and the recipient-major transpose.
//!
//! A payer's epoch activity is one strictly recipient-sorted vector of cumulative entries whose
//! sum equals its epoch debit advance. The operator's lazy collation re-sorts the union of all
//! terminal vectors by (recipient, payer) into the transpose, whose per-recipient contiguous
//! range sums are each row's credit delta.

use crate::bajillion::{
    commitment::{self, VectorKind, VectorRoot},
    payment::{Amount, Epoch},
};
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
    varint::UInt,
};
use commonware_cryptography::{Digest, Hasher, PublicKey, lthash::LtHash};
use commonware_parallel::Sequential;
use thiserror::Error;

/// Domain prefix for accumulator edge keys.
const EDGE_KEY_HASH_PREFIX: &[u8] = b"_COMMONWARE_CLEARING_EDGE_KEY";

/// Folds one canonical edge key into a permutation accumulator.
pub(crate) fn accumulate_edge<P: PublicKey>(
    accumulator: &mut LtHash,
    payer: &P,
    recipient: &P,
    cumulative: u64,
    count: u64,
) {
    let mut encoded = Vec::with_capacity(EDGE_KEY_HASH_PREFIX.len() + P::SIZE * 2 + u64::SIZE * 2);
    encoded.extend_from_slice(EDGE_KEY_HASH_PREFIX);
    payer.write(&mut encoded);
    recipient.write(&mut encoded);
    cumulative.write(&mut encoded);
    count.write(&mut encoded);
    accumulator.add(&encoded);
}

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
    /// Creates a vector from strictly recipient-sorted, unique entries.
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

    /// Returns the strictly recipient-sorted entries.
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
            .any(|pair| pair[0].recipient >= pair[1].recipient)
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

    /// Folds this vector's edge keys into a fresh accumulator partial.
    ///
    /// A sender maintains this partial incrementally as its entries change, so the closer can
    /// lane-sum per-payer partials into coverage boundaries instead of re-expanding every edge.
    /// Validators never consume partials: they fold raw entries from their dealt slices.
    #[must_use]
    pub fn accumulator(&self) -> LtHash {
        let mut partial = LtHash::new();
        for entry in &self.entries {
            accumulate_edge(
                &mut partial,
                &self.payer,
                &entry.recipient,
                entry.cumulative,
                entry.count,
            );
        }
        partial
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
            .binary_search_by(|entry| entry.recipient.cmp(recipient))
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
                if predecessor
                    .as_ref()
                    .is_some_and(|entry| entry.recipient >= *recipient || entry.validate().is_err())
                    || successor.as_ref().is_some_and(|entry| {
                        entry.recipient <= *recipient || entry.validate().is_err()
                    })
                {
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

/// One recipient-major collated edge terminal.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TransposeEntry<P: PublicKey> {
    /// Credited recipient, the major sort key.
    pub recipient: P,
    /// Paying account, the minor sort key.
    pub payer: P,
    /// Epoch-cumulative credit on this edge.
    pub cumulative: Amount,
    /// Number of payments on this edge this epoch.
    pub count: u64,
}

impl<P: PublicKey> TransposeEntry<P> {
    /// Returns whether the entry endpoint admits a positive-payment completion.
    pub const fn validate(&self) -> Result<(), Error> {
        if self.cumulative == 0 || self.count == 0 || self.cumulative < self.count {
            return Err(Error::InfeasibleEntry);
        }
        Ok(())
    }
}

impl<P: PublicKey> Write for TransposeEntry<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.recipient.write(buf);
        self.payer.write(buf);
        self.cumulative.write(buf);
        self.count.write(buf);
    }
}

impl<P: PublicKey> FixedSize for TransposeEntry<P> {
    const SIZE: usize = P::SIZE * 2 + u64::SIZE * 2;
}

impl<P: PublicKey> Read for TransposeEntry<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            recipient: P::read(buf)?,
            payer: P::read(buf)?,
            cumulative: u64::read(buf)?,
            count: u64::read(buf)?,
        })
    }
}

/// Writes a transpose interval in recipient-grouped form.
///
/// The recipient-major sort makes each recipient's entries one contiguous run, so the wire
/// form carries each recipient key once per run instead of once per entry: a run count,
/// then per run the recipient, an entry count, and the per-entry (payer, cumulative, count)
/// remainders with the cumulative and count as varints. Any contiguous interval encodes this
/// way, including intervals that start or end inside a run. Ordering is not re-validated
/// here: decoded intervals flow into the existing canonical-sort validation.
pub fn write_transpose<P: PublicKey>(entries: &[TransposeEntry<P>], buf: &mut impl BufMut) {
    let mut runs = 0_usize;
    let mut index = 0;
    while index < entries.len() {
        let mut end = index + 1;
        while end < entries.len() && entries[end].recipient == entries[index].recipient {
            end += 1;
        }
        runs += 1;
        index = end;
    }
    runs.write(buf);
    let mut index = 0;
    while index < entries.len() {
        let start = index;
        while index < entries.len() && entries[index].recipient == entries[start].recipient {
            index += 1;
        }
        entries[start].recipient.write(buf);
        (index - start).write(buf);
        for entry in &entries[start..index] {
            entry.payer.write(buf);
            UInt(entry.cumulative).write(buf);
            UInt(entry.count).write(buf);
        }
    }
}

/// Reads a recipient-grouped transpose interval of at most `max` entries.
pub fn read_transpose<P: PublicKey>(
    buf: &mut impl Buf,
    max: usize,
) -> Result<Vec<TransposeEntry<P>>, CodecError> {
    let runs = usize::read_cfg(buf, &RangeCfg::new(..=max))?;
    let mut entries = Vec::new();
    for _ in 0..runs {
        let recipient = P::read(buf)?;
        let remaining = max
            .checked_sub(entries.len())
            .filter(|remaining| *remaining > 0)
            .ok_or(CodecError::Invalid("Transpose", "interval exceeds bound"))?;
        let len = usize::read_cfg(buf, &RangeCfg::new(1..=remaining))?;
        entries.reserve(len);
        for _ in 0..len {
            entries.push(TransposeEntry {
                recipient: recipient.clone(),
                payer: P::read(buf)?,
                cumulative: UInt::read(buf)?.into(),
                count: UInt::read(buf)?.into(),
            });
        }
    }
    Ok(entries)
}

/// Returns the exact recipient-grouped encoded size of a transpose interval.
pub fn transpose_encode_size<P: PublicKey>(entries: &[TransposeEntry<P>]) -> usize {
    let mut runs = 0_usize;
    let mut size = 0_usize;
    let mut index = 0;
    while index < entries.len() {
        let start = index;
        while index < entries.len() && entries[index].recipient == entries[start].recipient {
            index += 1;
        }
        runs += 1;
        size += P::SIZE
            + (index - start).encode_size()
            + entries[start..index]
                .iter()
                .map(|entry| {
                    P::SIZE + UInt(entry.cumulative).encode_size() + UInt(entry.count).encode_size()
                })
                .sum::<usize>();
    }
    runs.encode_size() + size
}

/// Errors returned while constructing or verifying outgoing vectors and transposes.
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
    use alloc::collections::BTreeSet;

    impl<'a, P> arbitrary::Arbitrary<'a> for OutVector<P>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let epoch = u.arbitrary()?;
            let payer = u.arbitrary()?;
            let mut recipients = BTreeSet::new();
            for _ in 0..u.int_in_range(0..=4_usize)? {
                recipients.insert(u.arbitrary::<P>()?);
            }
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

    impl<'a, P> arbitrary::Arbitrary<'a> for TransposeEntry<P>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                recipient: u.arbitrary()?,
                payer: u.arbitrary()?,
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
    fn transpose_codec_round_trips_and_sizes_exactly() {
        let mut recipients = (0..3u64).map(account).collect::<Vec<_>>();
        recipients.sort_unstable();
        let mut payers = (10..14u64).map(account).collect::<Vec<_>>();
        payers.sort_unstable();
        let mut entries = Vec::new();
        for (r, recipient) in recipients.iter().enumerate() {
            for (p, payer) in payers.iter().enumerate().take(r + 2) {
                entries.push(TransposeEntry {
                    recipient: recipient.clone(),
                    payer: payer.clone(),
                    cumulative: 5 + p as u64,
                    count: 1 + p as u64,
                });
            }
        }
        // Full interval and an interval that starts and ends inside runs.
        for interval in [&entries[..], &entries[1..entries.len() - 1]] {
            let mut buf = Vec::new();
            write_transpose(interval, &mut buf);
            assert_eq!(buf.len(), transpose_encode_size(interval));
            let decoded = read_transpose::<VerifyingKey>(&mut &buf[..], entries.len()).unwrap();
            assert_eq!(decoded, interval);
        }
        assert!(
            transpose_encode_size(&entries) < entries.len() * TransposeEntry::<VerifyingKey>::SIZE
        );
    }

    #[test]
    fn transpose_codec_rejects_empty_runs_and_overflow() {
        let entry = TransposeEntry {
            recipient: account(1),
            payer: account(2),
            cumulative: 3,
            count: 1,
        };
        let mut buf = Vec::new();
        write_transpose(std::slice::from_ref(&entry), &mut buf);
        assert!(read_transpose::<VerifyingKey>(&mut &buf[..], 0).is_err());

        // A run claiming zero entries is rejected by the length range.
        let mut forged = Vec::new();
        1_usize.write(&mut forged);
        entry.recipient.write(&mut forged);
        0_usize.write(&mut forged);
        assert!(read_transpose::<VerifyingKey>(&mut &forged[..], 8).is_err());
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
