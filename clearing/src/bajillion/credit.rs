//! Authenticated terminal receive-shard heads.
//!
//! A recipient's nonempty receive shards are committed in strictly increasing shard order. The
//! resulting root binds the exact shard count and the checked sums of cumulative shard credit and
//! receipt counts. Membership and absence proofs use the generic BMT commitment layer.

use crate::bajillion::{
    commitment::{self, VectorKind, VectorRoot},
    payment::{Epoch, Payment},
};
use alloc::{boxed::Box, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::Sequential;
use thiserror::Error;

const CREDIT_ROOT_DOMAIN: &[u8] = b"_COMMONWARE_CLEARING_CREDIT_ROOT";

/// One terminal payment for a nonempty receive shard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardHead<P: PublicKey, D: Digest> {
    /// Recipient-local receive-shard identifier.
    pub shard: u64,
    /// Last accepted payment in the shard.
    pub payment: Payment<P, D>,
}

impl<P: PublicKey, D: Digest> ShardHead<P, D> {
    /// Creates a terminal shard head.
    #[must_use]
    pub const fn new(shard: u64, payment: Payment<P, D>) -> Self {
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

/// Fixed-size commitment to all terminal receive-shard heads for one recipient and epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CreditRoot<D: Digest> {
    /// Exact number of nonempty receive shards.
    pub len: u32,
    /// Sum of each shard's terminal cumulative credit.
    pub total_credit: u64,
    /// Sum of each shard's terminal receipt index.
    pub total_receipts: u64,
    /// Digest binding the vector root, recipient, epoch, count, and totals.
    pub digest: D,
}

impl<D: Digest> CreditRoot<D> {
    const fn validate_metadata(&self) -> Result<(), Error> {
        if self.len > commitment::MAX_VECTOR_LENGTH {
            return Err(Error::TooManyHeads);
        }
        if (self.len == 0) != (self.total_credit == 0 && self.total_receipts == 0) {
            return Err(Error::InvalidTotals);
        }
        if self.len != 0 && (self.total_credit == 0 || self.total_receipts == 0) {
            return Err(Error::InvalidTotals);
        }
        Ok(())
    }
}

impl<D: Digest> Write for CreditRoot<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.len.write(writer);
        self.total_credit.write(writer);
        self.total_receipts.write(writer);
        self.digest.write(writer);
    }
}

impl<D: Digest> Read for CreditRoot<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let root = Self {
            len: u32::read(reader)?,
            total_credit: u64::read(reader)?,
            total_receipts: u64::read(reader)?,
            digest: D::read(reader)?,
        };
        root.validate_metadata()
            .map_err(|_| CodecError::Invalid("CreditRoot", "credit count or totals are invalid"))?;
        Ok(root)
    }
}

impl<D: Digest> FixedSize for CreditRoot<D> {
    const SIZE: usize = u32::SIZE + u64::SIZE + u64::SIZE + D::SIZE;
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for CreditRoot<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0..=commitment::MAX_VECTOR_LENGTH)?;
        let (total_credit, total_receipts) = if len == 0 {
            (0, 0)
        } else {
            (u.int_in_range(1..=u64::MAX)?, u.int_in_range(1..=u64::MAX)?)
        };
        Ok(Self {
            len,
            total_credit,
            total_receipts,
            digest: u.arbitrary()?,
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
    ) -> Result<(CreditRoot<D>, commitment::Tree<D>), Error> {
        let (total_credit, total_receipts) = self.validate()?;
        let len = u32::try_from(self.heads.len()).map_err(|_| Error::TooManyHeads)?;
        let mut builder = commitment::Builder::<H>::new(VectorKind::Credit, len)?;
        for head in &self.heads {
            builder.add_encoded(head.encode().as_ref())?;
        }
        let tree = builder.build(&Sequential)?;
        let root = bind_credit_root::<H, P>(
            self.epoch,
            &self.recipient,
            tree.root(),
            len,
            total_credit,
            total_receipts,
        );
        Ok((root, tree))
    }

    /// Computes the aggregate-binding credit root.
    pub fn root<H: Hasher<Digest = D>>(&self) -> Result<CreditRoot<D>, Error> {
        self.commitment::<H>().map(|(root, _)| root)
    }

    /// Recomputes and compares the complete set against `expected`.
    pub fn verify_root<H: Hasher<Digest = D>>(
        &self,
        expected: &CreditRoot<D>,
    ) -> Result<(), Error> {
        if self.root::<H>()? == *expected {
            Ok(())
        } else {
            Err(Error::RootMismatch)
        }
    }

    /// Produces either a membership opening or an adjacent-neighbor absence proof.
    pub fn lookup<H: Hasher<Digest = D>>(&self, shard: u64) -> Result<ShardLookup<P, D>, Error> {
        let (_, tree) = self.commitment::<H>()?;
        match self.heads.binary_search_by_key(&shard, |head| head.shard) {
            Ok(position) => Ok(ShardLookup::Present {
                opening: Box::new(self.opening(&tree, position)?),
            }),
            Err(position) => Ok(ShardLookup::Absent {
                shard,
                predecessor: position
                    .checked_sub(1)
                    .map(|index| self.opening(&tree, index))
                    .transpose()?
                    .map(Box::new),
                successor: (position < self.heads.len())
                    .then(|| self.opening(&tree, position))
                    .transpose()?
                    .map(Box::new),
            }),
        }
    }

    fn opening(
        &self,
        tree: &commitment::Tree<D>,
        position: usize,
    ) -> Result<ShardOpening<P, D>, Error> {
        let value = self
            .heads
            .get(position)
            .ok_or(Error::IndexOutOfRange)?
            .clone();
        Ok(ShardOpening {
            value,
            proof: tree.opening(u32::try_from(position).map_err(|_| Error::IndexOutOfRange)?)?,
        })
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

/// A terminal shard head and its bounded vector opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardOpening<P: PublicKey, D: Digest> {
    /// Authenticated terminal head.
    pub value: ShardHead<P, D>,
    /// Position and BMT authentication path.
    pub proof: commitment::Opening<D>,
}

impl<P: PublicKey, D: Digest> Write for ShardOpening<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.value.write(writer);
        self.proof.write(writer);
    }
}

impl<P: PublicKey, D: Digest> Read for ShardOpening<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            value: ShardHead::read(reader)?,
            proof: commitment::Opening::read(reader)?,
        })
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ShardOpening<P, D> {
    fn encode_size(&self) -> usize {
        self.value.encode_size() + self.proof.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ShardOpening<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    ShardHead<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            value: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

/// Authenticated answer to a receive-shard lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShardLookup<P: PublicKey, D: Digest> {
    /// The requested shard is present.
    Present {
        /// Membership opening for the terminal head.
        opening: Box<ShardOpening<P, D>>,
    },
    /// The requested shard is absent, bracketed by adjacent vector neighbors.
    Absent {
        /// Requested absent shard identifier.
        shard: u64,
        /// Immediate predecessor, or `None` at the beginning of the vector.
        predecessor: Option<Box<ShardOpening<P, D>>>,
        /// Immediate successor, or `None` at the end of the vector.
        successor: Option<Box<ShardOpening<P, D>>>,
    },
}

impl<P: PublicKey, D: Digest> ShardLookup<P, D> {
    /// Verifies the lookup against a trusted recipient, epoch, and credit root.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        epoch: Epoch,
        recipient: &P,
        root: &CreditRoot<D>,
        shard: u64,
    ) -> Result<Option<ShardHead<P, D>>, Error> {
        root.validate_metadata()?;
        match self {
            Self::Present { opening } => {
                verify_opening::<H, P>(epoch, recipient, root, opening)?;
                if opening.value.shard != shard {
                    return Err(Error::LookupKey);
                }
                Ok(Some(opening.value.clone()))
            }
            Self::Absent {
                shard: claimed,
                predecessor,
                successor,
            } => {
                if *claimed != shard {
                    return Err(Error::LookupKey);
                }
                if root.len == 0 {
                    if predecessor.is_some()
                        || successor.is_some()
                        || *root != empty_credit_root::<H, P>(epoch, recipient)
                    {
                        return Err(Error::RootMismatch);
                    }
                    return Ok(None);
                }
                for opening in predecessor.iter().chain(successor.iter()) {
                    verify_opening::<H, P>(epoch, recipient, root, opening)?;
                }

                let insertion = successor
                    .as_ref()
                    .map_or(root.len, |opening| opening.proof.position);
                match predecessor {
                    None if insertion == 0 => {}
                    Some(opening)
                        if opening.proof.position.checked_add(1) == Some(insertion)
                            && opening.value.shard < shard => {}
                    _ => return Err(Error::LookupOrder),
                }
                match successor {
                    None if insertion == root.len => {}
                    Some(opening)
                        if opening.proof.position == insertion && opening.value.shard > shard => {}
                    _ => return Err(Error::LookupOrder),
                }
                Ok(None)
            }
        }
    }
}

fn write_optional_opening<P: PublicKey, D: Digest>(
    writer: &mut impl BufMut,
    opening: Option<&ShardOpening<P, D>>,
) {
    match opening {
        None => 0_u8.write(writer),
        Some(opening) => {
            1_u8.write(writer);
            opening.write(writer);
        }
    }
}

fn read_optional_opening<P: PublicKey, D: Digest>(
    reader: &mut impl Buf,
) -> Result<Option<Box<ShardOpening<P, D>>>, CodecError> {
    match u8::read(reader)? {
        0 => Ok(None),
        1 => Ok(Some(Box::new(ShardOpening::read(reader)?))),
        tag => Err(CodecError::InvalidEnum(tag)),
    }
}

fn optional_opening_size<P: PublicKey, D: Digest>(opening: Option<&ShardOpening<P, D>>) -> usize {
    u8::SIZE + opening.map_or(0, EncodeSize::encode_size)
}

impl<P: PublicKey, D: Digest> Write for ShardLookup<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Present { opening } => {
                1_u8.write(writer);
                opening.write(writer);
            }
            Self::Absent {
                shard,
                predecessor,
                successor,
            } => {
                2_u8.write(writer);
                shard.write(writer);
                write_optional_opening(writer, predecessor.as_deref());
                write_optional_opening(writer, successor.as_deref());
            }
        }
    }
}

impl<P: PublicKey, D: Digest> Read for ShardLookup<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            1 => Ok(Self::Present {
                opening: Box::new(ShardOpening::read(reader)?),
            }),
            2 => Ok(Self::Absent {
                shard: u64::read(reader)?,
                predecessor: read_optional_opening(reader)?,
                successor: read_optional_opening(reader)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ShardLookup<P, D> {
    fn encode_size(&self) -> usize {
        match self {
            Self::Present { opening } => u8::SIZE + opening.encode_size(),
            Self::Absent {
                predecessor,
                successor,
                ..
            } => {
                u8::SIZE
                    + u64::SIZE
                    + optional_opening_size(predecessor.as_deref())
                    + optional_opening_size(successor.as_deref())
            }
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ShardLookup<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    ShardOpening<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Present {
                opening: Box::new(u.arbitrary()?),
            })
        } else {
            Ok(Self::Absent {
                shard: u.arbitrary()?,
                predecessor: u.arbitrary::<Option<ShardOpening<P, D>>>()?.map(Box::new),
                successor: u.arbitrary::<Option<ShardOpening<P, D>>>()?.map(Box::new),
            })
        }
    }
}

/// Verifies one terminal shard opening, including its aggregate-binding root wrapper.
pub fn verify_opening<H, P>(
    epoch: Epoch,
    recipient: &P,
    root: &CreditRoot<H::Digest>,
    opening: &ShardOpening<P, H::Digest>,
) -> Result<(), Error>
where
    H: Hasher,
    P: PublicKey,
{
    root.validate_metadata()?;
    if root.len == 0 {
        return Err(Error::IndexOutOfRange);
    }
    opening.value.validate(epoch, recipient)?;
    let receipt = opening.value.payment.receipt().body();
    if receipt.cumulative_shard_credit() > root.total_credit
        || receipt.index() > root.total_receipts
    {
        return Err(Error::InvalidTotals);
    }
    let vector_root = opening
        .proof
        .reconstruct::<H>(VectorKind::Credit, opening.value.encode().as_ref())?;
    let reconstructed = bind_credit_root::<H, P>(
        epoch,
        recipient,
        vector_root,
        root.len,
        root.total_credit,
        root.total_receipts,
    );
    if reconstructed == *root {
        Ok(())
    } else {
        Err(Error::RootMismatch)
    }
}

/// Returns the canonical empty credit root for a recipient and epoch.
#[must_use]
pub fn empty_credit_root<H, P>(epoch: Epoch, recipient: &P) -> CreditRoot<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    bind_credit_root::<H, P>(
        epoch,
        recipient,
        commitment::empty_root::<H>(VectorKind::Credit),
        0,
        0,
        0,
    )
}

fn bind_credit_root<H, P>(
    epoch: Epoch,
    recipient: &P,
    vector_root: VectorRoot<H::Digest>,
    len: u32,
    total_credit: u64,
    total_receipts: u64,
) -> CreditRoot<H::Digest>
where
    H: Hasher,
    P: PublicKey,
{
    let recipient_len = u32::try_from(recipient.as_ref().len())
        .expect("a fixed-size public key length fits in u32")
        .to_be_bytes();
    CreditRoot {
        len,
        total_credit,
        total_receipts,
        digest: H::hash(&[
            CREDIT_ROOT_DOMAIN,
            &epoch.to_be_bytes(),
            &recipient_len,
            recipient.as_ref(),
            &len.to_be_bytes(),
            &total_credit.to_be_bytes(),
            &total_receipts.to_be_bytes(),
            vector_root.digest.as_ref(),
        ]),
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
    /// Root count and aggregate fields are inconsistent.
    #[error("credit root count or aggregate totals are invalid")]
    InvalidTotals,
    /// A root or opening does not authenticate the supplied value.
    #[error("credit root does not authenticate the supplied set or opening")]
    RootMismatch,
    /// An opening position is outside the committed vector.
    #[error("credit opening position is outside the committed vector")]
    IndexOutOfRange,
    /// A lookup was supplied for another shard identifier.
    #[error("credit lookup was supplied for another shard")]
    LookupKey,
    /// An absence proof does not contain the adjacent ordered neighbors.
    #[error("credit absence proof is not an adjacent ordered bracket")]
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
    type TestLookup = ShardLookup<VerifyingKey, Sha256Digest>;

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
            empty_credit_root::<Sha256, _>(context.epoch(), &recipient.public_key())
        );
        assert_eq!(root.len, 0);
        assert_eq!(root.total_credit, 0);
        assert_eq!(root.total_receipts, 0);
        assert!(
            empty
                .lookup::<Sha256>(7)
                .unwrap()
                .resolve::<Sha256>(context.epoch(), &recipient.public_key(), &root, 7)
                .unwrap()
                .is_none()
        );

        let only = head(&context, &operator, &recipient, 3, 7, 13, 4);
        let singleton =
            ShardSet::new(context.epoch(), recipient.public_key(), vec![only.clone()]).unwrap();
        let root = singleton.root::<Sha256>().unwrap();
        assert_eq!(root.len, 1);
        assert_eq!(root.total_credit, 13);
        assert_eq!(root.total_receipts, 4);
        assert_eq!(
            singleton
                .lookup::<Sha256>(7)
                .unwrap()
                .resolve::<Sha256>(context.epoch(), &recipient.public_key(), &root, 7)
                .unwrap(),
            Some(only)
        );
    }

    #[test]
    fn non_power_of_two_membership_and_adjacent_absence_verify() {
        let (context, _, recipient, set) = three_head_set();
        let root = set.root::<Sha256>().unwrap();
        assert_eq!(root.len, 3);
        assert_eq!(root.total_credit, 37);
        assert_eq!(root.total_receipts, 9);

        for head in set.heads() {
            assert_eq!(
                set.lookup::<Sha256>(head.shard)
                    .unwrap()
                    .resolve::<Sha256>(context.epoch(), &recipient.public_key(), &root, head.shard,)
                    .unwrap(),
                Some(head.clone())
            );
        }

        for missing in [0, 10, 99] {
            let lookup = set.lookup::<Sha256>(missing).unwrap();
            assert_eq!(
                lookup
                    .resolve::<Sha256>(context.epoch(), &recipient.public_key(), &root, missing,)
                    .unwrap(),
                None
            );
            assert_eq!(TestLookup::decode(lookup.encode()).unwrap(), lookup);
        }
        assert_eq!(TestSet::decode(set.encode()).unwrap(), set);
        assert_eq!(
            CreditRoot::<Sha256Digest>::decode(root.encode()).unwrap(),
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

        let mut wrong_total = root;
        wrong_total.total_credit += 1;
        assert!(matches!(
            lookup.resolve::<Sha256>(context.epoch(), &recipient.public_key(), &wrong_total, 8,),
            Err(Error::RootMismatch)
        ));

        let mut malformed_empty =
            empty_credit_root::<Sha256, _>(context.epoch(), &recipient.public_key());
        malformed_empty.total_receipts = 1;
        assert!(CreditRoot::<Sha256Digest>::decode(malformed_empty.encode()).is_err());

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
        let (context, _, recipient, set) = three_head_set();
        let root = set.root::<Sha256>().unwrap();
        let mut present = set.lookup::<Sha256>(2).unwrap();
        let ShardLookup::Present { opening } = &mut present else {
            panic!("known shard must be present");
        };
        opening.proof.proof.siblings[0] = Sha256::hash(&[b"tampered sibling"]);
        assert!(
            present
                .resolve::<Sha256>(context.epoch(), &recipient.public_key(), &root, 2)
                .is_err()
        );

        let lookup = set.lookup::<Sha256>(10).unwrap();
        let ShardLookup::Absent {
            shard, predecessor, ..
        } = lookup
        else {
            panic!("missing interior shard must be absent");
        };
        let nonadjacent_successor = match set.lookup::<Sha256>(2).unwrap() {
            ShardLookup::Present { opening } => opening,
            ShardLookup::Absent { .. } => panic!("known shard must be present"),
        };
        let nonadjacent = ShardLookup::Absent {
            shard,
            predecessor,
            successor: Some(nonadjacent_successor),
        };
        assert!(matches!(
            nonadjacent.resolve::<Sha256>(context.epoch(), &recipient.public_key(), &root, shard,),
            Err(Error::LookupOrder)
        ));
    }
}
