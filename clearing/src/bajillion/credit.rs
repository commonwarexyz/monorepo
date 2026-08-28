//! Authenticated terminal receive-shard heads.
//!
//! A recipient's nonempty receive shards are committed in strictly increasing shard order. Each
//! compact tip exposes the terminal credit and receipt counters of its fully validated head.
//! Membership and adjacent-absence proofs use the generic BMT commitment layer.

use crate::bajillion::{
    commitment::{self, VectorKind, VectorRoot},
    payment::{Amount, Epoch, Payment, ReceiptIndex, Shard},
};
use alloc::vec::Vec;
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Sequential;
use thiserror::Error;

/// One terminal payment for a nonempty receive shard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardHead<P: PublicKey, D: Digest> {
    /// Recipient-local receive-shard identifier.
    pub shard: Shard,
    /// Last accepted payment in the shard.
    pub payment: Payment<P, D>,
}

impl<P: PublicKey, D: Digest> ShardHead<P, D> {
    /// Creates a terminal shard head.
    #[must_use]
    pub const fn new(shard: Shard, payment: Payment<P, D>) -> Self {
        Self { shard, payment }
    }

    fn validate(&self, epoch: Epoch, recipient: &P) -> Result<(), Error> {
        let receipt = self.payment.receipt().body();
        if receipt.epoch() != epoch {
            return Err(Error::EpochMismatch);
        }
        if receipt.recipient() != recipient {
            return Err(Error::RecipientMismatch);
        }
        if receipt.shard() != self.shard {
            return Err(Error::ShardMismatch);
        }
        if receipt.cumulative_shard_credit() == 0 || receipt.index() == 0 {
            return Err(Error::ZeroEndpoint);
        }
        Ok(())
    }
}

impl<P: PublicKey, D: Digest> Write for ShardHead<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.shard.write(writer);
        self.payment.write(writer);
    }
}

impl<P: PublicKey, D: Digest> Read for ShardHead<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            shard: u64::read(reader)?,
            payment: Payment::read(reader)?,
        })
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ShardHead<P, D> {
    fn encode_size(&self) -> usize {
        self.shard.encode_size() + self.payment.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ShardHead<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    Payment<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            shard: u.arbitrary()?,
            payment: u.arbitrary()?,
        })
    }
}

/// Compact terminal receive-shard projection authenticated by a changed-account leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditTip {
    /// Recipient-local receive-shard identifier.
    pub shard: Shard,
    /// Terminal cumulative credit in this shard.
    pub cumulative_credit: Amount,
    /// Terminal receipt index in this shard.
    pub index: ReceiptIndex,
}

/// Shard-relative value for a compact credit-tip membership opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreditTipValue {
    /// Terminal cumulative credit in the challenged shard.
    pub cumulative_credit: Amount,
    /// Terminal receipt index in the challenged shard.
    pub index: ReceiptIndex,
}

impl CreditTip {
    /// Projects the settlement-relevant counters from one fully validated terminal head.
    #[must_use]
    pub const fn from_head<P: PublicKey, D: Digest>(head: &ShardHead<P, D>) -> Self {
        let receipt = head.payment.receipt().body();
        Self {
            shard: head.shard,
            cumulative_credit: receipt.cumulative_shard_credit(),
            index: receipt.index(),
        }
    }

    /// Projects the value whose shard is supplied by a membership lookup target.
    #[must_use]
    pub const fn value(&self) -> CreditTipValue {
        CreditTipValue {
            cumulative_credit: self.cumulative_credit,
            index: self.index,
        }
    }

    const fn from_value(shard: Shard, value: CreditTipValue) -> Self {
        Self {
            shard,
            cumulative_credit: value.cumulative_credit,
            index: value.index,
        }
    }
}

impl Write for CreditTip {
    fn write(&self, writer: &mut impl BufMut) {
        self.shard.write(writer);
        self.cumulative_credit.write(writer);
        self.index.write(writer);
    }
}

impl FixedSize for CreditTip {
    const SIZE: usize = u64::SIZE * 3;
}

impl Read for CreditTip {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            shard: u64::read(reader)?,
            cumulative_credit: u64::read(reader)?,
            index: u64::read(reader)?,
        })
    }
}

impl Write for CreditTipValue {
    fn write(&self, writer: &mut impl BufMut) {
        self.cumulative_credit.write(writer);
        self.index.write(writer);
    }
}

impl FixedSize for CreditTipValue {
    const SIZE: usize = u64::SIZE * 2;
}

impl Read for CreditTipValue {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            cumulative_credit: u64::read(reader)?,
            index: u64::read(reader)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for CreditTip {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            shard: u.arbitrary()?,
            cumulative_credit: u.arbitrary()?,
            index: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for CreditTipValue {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            cumulative_credit: u.arbitrary()?,
            index: u.arbitrary()?,
        })
    }
}

/// Complete canonical terminal-shard vector for one recipient and epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardSet<P: PublicKey, D: Digest> {
    epoch: Epoch,
    recipient: P,
    heads: Vec<ShardHead<P, D>>,
}

impl<P: PublicKey, D: Digest> ShardSet<P, D> {
    /// Creates a set from strictly sorted, unique terminal shard heads.
    pub fn new(epoch: Epoch, recipient: P, heads: Vec<ShardHead<P, D>>) -> Result<Self, Error> {
        let set = Self {
            epoch,
            recipient,
            heads,
        };
        set.validate()?;
        Ok(set)
    }

    /// Creates the canonical empty set for a recipient and epoch.
    #[must_use]
    pub const fn empty(epoch: Epoch, recipient: P) -> Self {
        Self {
            epoch,
            recipient,
            heads: Vec::new(),
        }
    }

    /// Returns the epoch shared by every terminal receipt.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the recipient shared by every terminal receipt.
    #[must_use]
    pub const fn recipient(&self) -> &P {
        &self.recipient
    }

    /// Returns the strictly sorted terminal shard heads.
    #[must_use]
    pub fn heads(&self) -> &[ShardHead<P, D>] {
        &self.heads
    }

    fn validate(&self) -> Result<(u64, u64), Error> {
        if self.heads.len() > commitment::MAX_VECTOR_LENGTH as usize {
            return Err(Error::TooManyHeads);
        }
        if self
            .heads
            .windows(2)
            .any(|pair| pair[0].shard >= pair[1].shard)
        {
            return Err(Error::NonCanonicalOrder);
        }
        let mut total_credit = 0_u64;
        let mut total_receipts = 0_u64;
        for head in &self.heads {
            head.validate(self.epoch, &self.recipient)?;
            let receipt = head.payment.receipt().body();
            total_credit = total_credit
                .checked_add(receipt.cumulative_shard_credit())
                .ok_or(Error::Arithmetic)?;
            total_receipts = total_receipts
                .checked_add(receipt.index())
                .ok_or(Error::Arithmetic)?;
        }
        Ok((total_credit, total_receipts))
    }

    fn commitment<H: Hasher<Digest = D>>(
        &self,
    ) -> Result<(Vec<CreditTip>, commitment::Tree<D>), Error> {
        self.validate()?;
        let len = u32::try_from(self.heads.len()).map_err(|_| Error::TooManyHeads)?;
        let tips = self
            .heads
            .iter()
            .map(CreditTip::from_head)
            .collect::<Vec<_>>();
        let mut builder = commitment::Builder::<H>::new(VectorKind::CreditTip, len)?;
        builder.add_values(&tips, &Sequential)?;
        let tree = builder.build(&Sequential)?;
        Ok((tips, tree))
    }

    /// Returns the checked terminal credit and receipt totals.
    pub(crate) fn totals(&self) -> Result<(u64, u64), Error> {
        self.validate()
    }

    /// Computes the exact typed compact-tip root.
    pub fn root<H: Hasher<Digest = D>>(&self) -> Result<VectorRoot<D>, Error> {
        self.commitment::<H>().map(|(_, tree)| tree.root())
    }

    /// Recomputes and compares the complete set against `expected`.
    pub fn verify_root<H: Hasher<Digest = D>>(
        &self,
        expected: &VectorRoot<D>,
    ) -> Result<(), Error> {
        if self.root::<H>()? == *expected {
            Ok(())
        } else {
            Err(Error::RootMismatch)
        }
    }

    /// Produces either a membership opening or an adjacent-neighbor absence proof.
    pub fn lookup<H: Hasher<Digest = D>>(&self, shard: Shard) -> Result<CreditTipLookup<D>, Error> {
        let (tips, tree) = self.commitment::<H>()?;
        match self.heads.binary_search_by_key(&shard, |head| head.shard) {
            Ok(position) => Ok(CreditTipLookup::Present {
                value: tips[position].value(),
                opening: tree
                    .opening(u32::try_from(position).map_err(|_| Error::IndexOutOfRange)?)?,
            }),
            Err(position) => {
                let position = u32::try_from(position).map_err(|_| Error::IndexOutOfRange)?;
                let (predecessor, successor, opening) = tree.bracket(&tips, position..position)?;
                Ok(CreditTipLookup::Absent {
                    predecessor,
                    successor,
                    opening,
                })
            }
        }
    }
}

impl<P: PublicKey, D: Digest> Write for ShardSet<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.epoch.write(writer);
        self.recipient.write(writer);
        self.heads.write(writer);
    }
}

impl<P: PublicKey, D: Digest> Read for ShardSet<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let epoch = Epoch::read(reader)?;
        let recipient = P::read(reader)?;
        let heads = Vec::<ShardHead<P, D>>::read_cfg(
            reader,
            &(RangeCfg::new(..=commitment::MAX_VECTOR_LENGTH as usize), ()),
        )?;
        let set = Self {
            epoch,
            recipient,
            heads,
        };
        set.validate()
            .map_err(|_| CodecError::Invalid("ShardSet", "terminal shard set is not canonical"))?;
        Ok(set)
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ShardSet<P, D> {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.recipient.encode_size() + self.heads.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ShardSet<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    Payment<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let payments = u.arbitrary::<Vec<Payment<P, D>>>()?;
        let Some(first) = payments.first() else {
            return Ok(Self::empty(u.arbitrary()?, u.arbitrary()?));
        };
        let epoch = first.receipt().body().epoch();
        let recipient = first.receipt().body().recipient().clone();
        let mut heads = payments
            .into_iter()
            .filter_map(|payment| {
                let receipt = payment.receipt().body();
                let shard = receipt.shard();
                let retained = receipt.epoch() == epoch
                    && receipt.recipient() == &recipient
                    && receipt.cumulative_shard_credit() != 0
                    && receipt.index() != 0;
                retained.then(|| ShardHead::new(shard, payment))
            })
            .collect::<Vec<_>>();
        heads.sort_unstable_by_key(|head| head.shard);
        heads.dedup_by_key(|head| head.shard);
        Ok(Self {
            epoch,
            recipient,
            heads,
        })
    }
}

/// Authenticated answer to a receive-shard lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreditTipLookup<D: Digest> {
    /// The requested shard is present.
    Present {
        /// Authenticated compact terminal tip.
        value: CreditTipValue,
        /// Membership opening for the compact tip.
        opening: commitment::Opening<D>,
    },
    /// The requested shard is absent, bracketed by adjacent vector neighbors.
    Absent {
        /// Immediate predecessor, or `None` at the beginning of the vector.
        predecessor: Option<CreditTip>,
        /// Immediate successor, or `None` at the end of the vector.
        successor: Option<CreditTip>,
        /// One shared opening for the adjacent disclosed neighbors.
        opening: commitment::RangeOpening<D>,
    },
}

impl<D: Digest> CreditTipLookup<D> {
    pub(crate) fn reconstruct<H: Hasher<Digest = D>>(
        &self,
        shard: Shard,
    ) -> Result<(VectorRoot<D>, Option<CreditTip>), Error> {
        match self {
            Self::Present { value, opening } => {
                let tip = CreditTip::from_value(shard, value.clone());
                if tip.cumulative_credit == 0 || tip.index == 0 {
                    return Err(Error::ZeroEndpoint);
                }
                let root =
                    opening.reconstruct::<H>(VectorKind::CreditTip, tip.encode().as_ref())?;
                Ok((root, Some(tip)))
            }
            Self::Absent {
                predecessor,
                successor,
                opening,
            } => {
                opening
                    .bracket(predecessor.is_some(), 0, successor.is_some())
                    .ok_or(Error::LookupOrder)?;
                if predecessor.as_ref().is_some_and(|tip| {
                    tip.shard >= shard || tip.cumulative_credit == 0 || tip.index == 0
                }) || successor.as_ref().is_some_and(|tip| {
                    tip.shard <= shard || tip.cumulative_credit == 0 || tip.index == 0
                }) {
                    return Err(Error::LookupOrder);
                }
                let encoded = predecessor
                    .iter()
                    .chain(successor.iter())
                    .map(Encode::encode)
                    .collect::<Vec<_>>();
                let root = opening.reconstruct::<H, _>(VectorKind::CreditTip, &encoded)?;
                Ok((root, None))
            }
        }
    }

    /// Verifies the lookup against a trusted compact-tip root.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        root: &VectorRoot<D>,
        shard: Shard,
    ) -> Result<Option<CreditTip>, Error> {
        let (reconstructed, tip) = self.reconstruct::<H>(shard)?;
        if reconstructed != *root {
            return Err(commitment::Error::InvalidOpening.into());
        }
        Ok(tip)
    }
}

impl<D: Digest> Write for CreditTipLookup<D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Present { value, opening } => {
                1_u8.write(writer);
                value.write(writer);
                opening.write(writer);
            }
            Self::Absent {
                predecessor,
                successor,
                opening,
            } => {
                2_u8.write(writer);
                predecessor.write(writer);
                successor.write(writer);
                opening.write(writer);
            }
        }
    }
}

impl<D: Digest> Read for CreditTipLookup<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            1 => Ok(Self::Present {
                value: CreditTipValue::read(reader)?,
                opening: commitment::Opening::read(reader)?,
            }),
            2 => Ok(Self::Absent {
                predecessor: Option::<CreditTip>::read(reader)?,
                successor: Option::<CreditTip>::read(reader)?,
                opening: commitment::RangeOpening::read_bounded(reader, 2, usize::MAX)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> EncodeSize for CreditTipLookup<D> {
    fn encode_size(&self) -> usize {
        match self {
            Self::Present { value, opening } => {
                u8::SIZE + value.encode_size() + opening.encode_size()
            }
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

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for CreditTipLookup<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    CreditTipValue: for<'a> arbitrary::Arbitrary<'a>,
    CreditTip: for<'a> arbitrary::Arbitrary<'a>,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
    commitment::RangeOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Present {
                value: u.arbitrary()?,
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

/// Errors returned while constructing or verifying receive-shard commitments.
#[derive(Debug, Error)]
pub enum Error {
    /// The terminal shard vector exceeds the protocol bound.
    #[error("terminal shard vector exceeds the protocol bound")]
    TooManyHeads,
    /// Shard identifiers are not strictly sorted and unique.
    #[error("terminal shard identifiers are not strictly sorted and unique")]
    NonCanonicalOrder,
    /// A terminal receipt belongs to another epoch.
    #[error("terminal shard receipt belongs to another epoch")]
    EpochMismatch,
    /// A terminal receipt belongs to another recipient.
    #[error("terminal shard receipt belongs to another recipient")]
    RecipientMismatch,
    /// A head and its receipt name different shards.
    #[error("terminal head and receipt name different shards")]
    ShardMismatch,
    /// A terminal cumulative credit or receipt index is zero.
    #[error("terminal shard endpoint must be positive")]
    ZeroEndpoint,
    /// Summing terminal shard endpoints overflowed.
    #[error("terminal shard aggregate arithmetic overflowed")]
    Arithmetic,
    /// The recomputed complete-set root does not match the expected root.
    #[error("credit-tip root does not authenticate the supplied set")]
    RootMismatch,
    /// An opening position is outside the committed vector.
    #[error("credit-tip opening position is outside the committed vector")]
    IndexOutOfRange,
    /// An absence proof does not contain the adjacent ordered neighbors.
    #[error("credit-tip absence proof is not an adjacent ordered bracket")]
    LookupOrder,
    /// The generic vector commitment is invalid.
    #[error("invalid vector commitment: {0}")]
    Commitment(#[from] commitment::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::payment::{PaymentContext, SignedReceipt, SignedSend};
    use commonware_codec::{DecodeExt, Encode};
    use commonware_cryptography::{Sha256, Signer as _, sha256::Digest as Sha256Digest};
    use commonware_cryptography_curve25519::signing::{
        SigningKey, StrictVerifyingKey as VerifyingKey,
    };

    type TestContext = PaymentContext<VerifyingKey, Sha256Digest>;
    type TestHead = ShardHead<VerifyingKey, Sha256Digest>;
    type TestSet = ShardSet<VerifyingKey, Sha256Digest>;
    type TestLookup = CreditTipLookup<Sha256Digest>;

    fn fixture() -> (TestContext, SigningKey, SigningKey) {
        let operator = SigningKey::from_seed(1);
        let recipient = SigningKey::from_seed(2);
        (
            PaymentContext::new(
                Sha256::hash(&[b"credit-test-anchor"]),
                9,
                operator.public_key(),
            ),
            operator,
            recipient,
        )
    }

    fn head(
        context: &TestContext,
        operator: &SigningKey,
        recipient: &SigningKey,
        payer_seed: u64,
        shard: u64,
        cumulative_credit: u64,
        index: u64,
    ) -> TestHead {
        assert!(cumulative_credit > 0 && index > 0);
        let payer = SigningKey::from_seed(payer_seed);
        let send = SignedSend::sign_next(context, &payer, recipient.public_key(), 1, 0).unwrap();
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            context,
            &send,
            &recipient.public_key(),
            shard,
            cumulative_credit - 1,
            index - 1,
            operator,
        )
        .unwrap();
        ShardHead::new(
            shard,
            Payment::new::<Sha256>(context, send, receipt).unwrap(),
        )
    }

    fn three_head_set() -> (TestContext, SigningKey, SigningKey, TestSet) {
        let (context, operator, recipient) = fixture();
        let heads = vec![
            head(&context, &operator, &recipient, 10, 2, 7, 1),
            head(&context, &operator, &recipient, 11, 8, 11, 3),
            head(&context, &operator, &recipient, 12, 20, 19, 5),
        ];
        let set = ShardSet::new(context.epoch(), recipient.public_key(), heads).unwrap();
        (context, operator, recipient, set)
    }

    #[test]
    fn empty_and_singleton_sets_are_canonical() {
        let (context, operator, recipient) = fixture();
        let empty = TestSet::empty(context.epoch(), recipient.public_key());
        let root = empty.root::<Sha256>().unwrap();
        assert_eq!(
            root,
            commitment::empty_root::<Sha256>(VectorKind::CreditTip)
        );
        assert_eq!(empty.totals().unwrap(), (0, 0));
        assert!(
            empty
                .lookup::<Sha256>(7)
                .unwrap()
                .resolve::<Sha256>(&root, 7)
                .unwrap()
                .is_none()
        );

        let only = head(&context, &operator, &recipient, 3, 7, 13, 4);
        let singleton =
            ShardSet::new(context.epoch(), recipient.public_key(), vec![only.clone()]).unwrap();
        let root = singleton.root::<Sha256>().unwrap();
        assert_eq!(singleton.totals().unwrap(), (13, 4));
        let lookup = singleton.lookup::<Sha256>(7).unwrap();
        assert_eq!(
            lookup.resolve::<Sha256>(&root, 7).unwrap(),
            Some(CreditTip::from_head(&only))
        );
        assert_eq!(TestLookup::decode(lookup.encode()).unwrap(), lookup);
    }

    #[test]
    fn non_power_of_two_membership_and_adjacent_absence_verify() {
        let (_, _, _, set) = three_head_set();
        let root = set.root::<Sha256>().unwrap();
        assert_eq!(set.totals().unwrap(), (37, 9));

        for head in set.heads() {
            let lookup = set.lookup::<Sha256>(head.shard).unwrap();
            assert_eq!(
                lookup.resolve::<Sha256>(&root, head.shard).unwrap(),
                Some(CreditTip::from_head(head))
            );
            assert_eq!(TestLookup::decode(lookup.encode()).unwrap(), lookup);
        }

        for missing in [0, 10, 99] {
            let lookup = set.lookup::<Sha256>(missing).unwrap();
            assert_eq!(lookup.resolve::<Sha256>(&root, missing).unwrap(), None);
            assert_eq!(TestLookup::decode(lookup.encode()).unwrap(), lookup);
        }
        assert_eq!(TestSet::decode(set.encode()).unwrap(), set);
        assert_eq!(
            VectorRoot::<Sha256Digest>::decode(root.encode()).unwrap(),
            root
        );
    }

    #[test]
    fn shard_set_length_keeps_canonical_varint_errors() {
        let (context, _, recipient) = fixture();
        let encoded = TestSet::empty(context.epoch(), recipient.public_key()).encode();
        let length_offset = Epoch::SIZE + VerifyingKey::SIZE;
        assert_eq!(encoded[length_offset], 0);

        let mut noncanonical = encoded[..length_offset].to_vec();
        noncanonical.extend_from_slice(&[0x80, 0]);
        assert!(matches!(
            TestSet::decode(noncanonical.as_slice()),
            Err(CodecError::InvalidVarint(size)) if size == u32::SIZE
        ));

        let mut too_many = encoded[..length_offset].to_vec();
        too_many.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert!(matches!(
            TestSet::decode(too_many.as_slice()),
            Err(CodecError::InvalidLength(length)) if length == u32::MAX as usize
        ));
    }

    #[test]
    fn order_duplicates_and_mismatched_head_metadata_are_rejected() {
        let (context, operator, recipient, set) = three_head_set();
        let mut reversed = set.heads().to_vec();
        reversed.reverse();
        assert!(matches!(
            ShardSet::new(context.epoch(), recipient.public_key(), reversed),
            Err(Error::NonCanonicalOrder)
        ));

        let duplicate = vec![set.heads()[0].clone(), set.heads()[0].clone()];
        assert!(matches!(
            ShardSet::new(context.epoch(), recipient.public_key(), duplicate),
            Err(Error::NonCanonicalOrder)
        ));

        let raw = (
            context.epoch(),
            recipient.public_key(),
            vec![set.heads()[1].clone(), set.heads()[0].clone()],
        )
            .encode();
        assert!(TestSet::decode(raw).is_err());

        let mismatched_shard = ShardHead::new(3, set.heads()[0].payment.clone());
        assert!(matches!(
            ShardSet::new(
                context.epoch(),
                recipient.public_key(),
                vec![mismatched_shard],
            ),
            Err(Error::ShardMismatch)
        ));
        let other_recipient = SigningKey::from_seed(100).public_key();
        assert!(matches!(
            ShardSet::new(
                context.epoch(),
                other_recipient,
                vec![set.heads()[0].clone()],
            ),
            Err(Error::RecipientMismatch)
        ));

        let wrong_epoch = head(&context, &operator, &recipient, 30, 30, 1, 1);
        assert!(matches!(
            ShardSet::new(
                context.epoch() + 1,
                recipient.public_key(),
                vec![wrong_epoch],
            ),
            Err(Error::EpochMismatch)
        ));
    }

    #[test]
    fn totals_are_checked_bound_and_overflow_safe() {
        let (context, operator, recipient, set) = three_head_set();
        let root = set.root::<Sha256>().unwrap();
        let lookup = set.lookup::<Sha256>(8).unwrap();

        let mut wrong_root = root;
        wrong_root.digest = Sha256::hash(&[b"wrong credit-tip root"]);
        assert!(matches!(
            set.verify_root::<Sha256>(&wrong_root),
            Err(Error::RootMismatch)
        ));
        assert!(matches!(
            lookup.resolve::<Sha256>(&wrong_root, 8),
            Err(Error::Commitment(_))
        ));

        let overflowing = vec![
            head(&context, &operator, &recipient, 20, 1, u64::MAX, 1),
            head(&context, &operator, &recipient, 21, 2, 1, 1),
        ];
        let overflowing =
            ShardSet::new(context.epoch(), recipient.public_key(), overflowing).unwrap_err();
        assert!(matches!(overflowing, Error::Arithmetic));
    }

    #[test]
    fn proof_and_absence_bracket_tampering_are_rejected() {
        let (_, _, _, set) = three_head_set();
        let root = set.root::<Sha256>().unwrap();
        let mut present = set.lookup::<Sha256>(2).unwrap();
        let CreditTipLookup::Present { opening, .. } = &mut present else {
            panic!("known shard must be present");
        };
        opening.proof.siblings[0] = Sha256::hash(&[b"tampered sibling"]);
        assert!(present.resolve::<Sha256>(&root, 2).is_err());

        let lookup = set.lookup::<Sha256>(10).unwrap();
        let CreditTipLookup::Absent {
            predecessor,
            opening,
            ..
        } = lookup
        else {
            panic!("missing interior shard must be absent");
        };
        let nonadjacent = CreditTipLookup::Absent {
            predecessor,
            successor: Some(CreditTip::from_head(&set.heads()[0])),
            opening,
        };
        assert!(matches!(
            nonadjacent.resolve::<Sha256>(&root, 10),
            Err(Error::LookupOrder)
        ));
    }
}
