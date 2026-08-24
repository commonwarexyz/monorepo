//! Bounded contradictions to an admitted public close.

#[cfg(test)]
use crate::bajillion::transition::EpochContext;
use crate::bajillion::{
    commitment::{self, VectorKind, VectorRoot},
    credit::{self, CreditRoot, ShardLookup},
    payment::{Payment, PaymentError, receipt_range_is_feasible},
    state::{AccountRow, StateLeaf},
    transition::{self, BatchId, CloseContext, Header, RootBundle},
};
use alloc::boxed::Box;
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::{Sequential, Strategy};
use thiserror::Error;

/// One changed row and its opening under the change root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowOpening<P: PublicKey, D: Digest> {
    /// Authenticated changed-account row.
    pub row: AccountRow<P, D>,
    /// Position and BMT authentication path.
    pub proof: commitment::Opening<D>,
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for RowOpening<P, D>
where
    P: PublicKey,
    D: Digest,
    AccountRow<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            row: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for RowOpening<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.row.write(buf);
        self.proof.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for RowOpening<P, D> {
    fn encode_size(&self) -> usize {
        self.row.encode_size() + self.proof.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for RowOpening<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            row: AccountRow::read(buf)?,
            proof: commitment::Opening::read(buf)?,
        })
    }
}

/// One live-state leaf and its opening under a state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateOpening<P: PublicKey, D: Digest> {
    /// Authenticated live leaf.
    pub leaf: StateLeaf<P>,
    /// Position and BMT authentication path.
    pub proof: commitment::Opening<D>,
}

/// Authenticated membership or ordered nonmembership under one state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateLookup<P: PublicKey, D: Digest> {
    /// The requested account is a live state member.
    Present(Box<StateOpening<P, D>>),
    /// The requested account is absent, authenticated by its adjacent live leaves.
    ///
    /// One neighbor is absent at a state boundary, and both are absent for an empty state.
    Absent {
        /// Immediate state predecessor, if any.
        predecessor: Option<Box<StateOpening<P, D>>>,
        /// Immediate state successor, if any.
        successor: Option<Box<StateOpening<P, D>>>,
    },
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for StateLookup<P, D>
where
    P: PublicKey,
    D: Digest,
    StateOpening<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Present(Box::new(u.arbitrary()?)))
        } else {
            Ok(Self::Absent {
                predecessor: u.arbitrary::<Option<StateOpening<P, D>>>()?.map(Box::new),
                successor: u.arbitrary::<Option<StateOpening<P, D>>>()?.map(Box::new),
            })
        }
    }
}

impl<P: PublicKey, D: Digest> StateLookup<P, D> {
    /// Verifies this lookup and returns the member state, if present.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        root: &VectorRoot<D>,
        account: &P,
    ) -> Result<Option<crate::bajillion::state::AccountState>, ChallengeError> {
        match self {
            Self::Present(opening) => {
                if &opening.leaf.account != account {
                    return Err(ChallengeError::LookupKey);
                }
                opening.proof.verify::<H>(
                    VectorKind::State,
                    root,
                    opening.leaf.encode().as_ref(),
                )?;
                Ok(Some(opening.leaf.state))
            }
            Self::Absent {
                predecessor,
                successor,
            } => {
                let len = predecessor
                    .as_ref()
                    .or(successor.as_ref())
                    .map_or(0, |opening| opening.proof.proof.leaf_count);
                if len == 0 {
                    if predecessor.is_some()
                        || successor.is_some()
                        || *root != commitment::empty_root::<H>(VectorKind::State)
                    {
                        return Err(ChallengeError::LookupOrder);
                    }
                } else {
                    for opening in predecessor.iter().chain(successor.iter()) {
                        opening.proof.verify::<H>(
                            VectorKind::State,
                            root,
                            opening.leaf.encode().as_ref(),
                        )?;
                    }
                    let insertion = successor
                        .as_ref()
                        .map_or(len, |opening| opening.proof.position);
                    match predecessor {
                        None if insertion == 0 => {}
                        Some(opening)
                            if opening.proof.position.checked_add(1) == Some(insertion)
                                && opening.leaf.account < *account => {}
                        _ => return Err(ChallengeError::LookupOrder),
                    }
                    match successor {
                        None if insertion == len => {}
                        Some(opening)
                            if opening.proof.position == insertion
                                && opening.leaf.account > *account => {}
                        _ => return Err(ChallengeError::LookupOrder),
                    }
                }
                Ok(None)
            }
        }
    }
}

fn write_optional_state<P: PublicKey, D: Digest>(
    buf: &mut impl BufMut,
    value: Option<&StateOpening<P, D>>,
) {
    match value {
        None => 0_u8.write(buf),
        Some(value) => {
            1_u8.write(buf);
            value.write(buf);
        }
    }
}

fn read_optional_state<P: PublicKey, D: Digest>(
    buf: &mut impl Buf,
) -> Result<Option<Box<StateOpening<P, D>>>, CodecError> {
    match u8::read(buf)? {
        0 => Ok(None),
        1 => Ok(Some(Box::new(StateOpening::read(buf)?))),
        tag => Err(CodecError::InvalidEnum(tag)),
    }
}

fn optional_state_size<P: PublicKey, D: Digest>(value: Option<&StateOpening<P, D>>) -> usize {
    u8::SIZE + value.map_or(0, EncodeSize::encode_size)
}

impl<P: PublicKey, D: Digest> Write for StateLookup<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present(opening) => {
                1_u8.write(buf);
                opening.write(buf);
            }
            Self::Absent {
                predecessor,
                successor,
            } => {
                2_u8.write(buf);
                write_optional_state(buf, predecessor.as_deref());
                write_optional_state(buf, successor.as_deref());
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for StateLookup<P, D> {
    fn encode_size(&self) -> usize {
        match self {
            Self::Present(opening) => u8::SIZE + opening.encode_size(),
            Self::Absent {
                predecessor,
                successor,
            } => {
                u8::SIZE
                    + optional_state_size(predecessor.as_deref())
                    + optional_state_size(successor.as_deref())
            }
        }
    }
}

impl<P: PublicKey, D: Digest> Read for StateLookup<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::Present(Box::new(StateOpening::read(buf)?))),
            2 => Ok(Self::Absent {
                predecessor: read_optional_state(buf)?,
                successor: read_optional_state(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for StateOpening<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            leaf: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for StateOpening<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.leaf.write(buf);
        self.proof.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for StateOpening<P, D> {
    fn encode_size(&self) -> usize {
        self.leaf.encode_size() + self.proof.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for StateOpening<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            leaf: StateLeaf::read(buf)?,
            proof: commitment::Opening::read(buf)?,
        })
    }
}

/// Authenticated resolution of an account against the exact change vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountLookup<P: PublicKey, D: Digest> {
    /// The account changed and has one committed row.
    Present(Box<RowOpening<P, D>>),
    /// The account is absent from the change vector and therefore unchanged.
    Absent {
        /// Opening-state membership or ordered-nonmembership proof.
        state: Box<StateLookup<P, D>>,
        /// Immediate changed-row predecessor, if any.
        predecessor: Option<Box<RowOpening<P, D>>>,
        /// Immediate changed-row successor, if any.
        successor: Option<Box<RowOpening<P, D>>>,
    },
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for AccountLookup<P, D>
where
    P: PublicKey,
    D: Digest,
    RowOpening<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    StateLookup<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Present(Box::new(u.arbitrary()?)))
        } else {
            Ok(Self::Absent {
                state: Box::new(u.arbitrary()?),
                predecessor: u.arbitrary::<Option<RowOpening<P, D>>>()?.map(Box::new),
                successor: u.arbitrary::<Option<RowOpening<P, D>>>()?.map(Box::new),
            })
        }
    }
}

/// Account state and optional committed row resolved from an [`AccountLookup`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAccount<P: PublicKey, D: Digest> {
    /// State at the opening root.
    pub opening: crate::bajillion::state::AccountState,
    /// State at the closing root.
    pub closing: crate::bajillion::state::AccountState,
    /// Committed row when the account changed.
    pub row: Option<AccountRow<P, D>>,
}

impl<P: PublicKey, D: Digest> AccountLookup<P, D> {
    /// Verifies membership or ordered absence for `account`.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        opening_root: &VectorRoot<D>,
        change_root: &VectorRoot<D>,
        account: &P,
    ) -> Result<ResolvedAccount<P, D>, ChallengeError> {
        match self {
            Self::Present(opening) => {
                if &opening.row.account != account {
                    return Err(ChallengeError::LookupKey);
                }
                opening.proof.verify::<H>(
                    VectorKind::Change,
                    change_root,
                    opening.row.encode().as_ref(),
                )?;
                Ok(ResolvedAccount {
                    opening: opening.row.opening,
                    closing: opening.row.closing,
                    row: Some(opening.row.clone()),
                })
            }
            Self::Absent {
                state,
                predecessor,
                successor,
            } => {
                let state = state
                    .resolve::<H>(opening_root, account)?
                    .unwrap_or_default();

                let change_len = predecessor
                    .as_ref()
                    .or(successor.as_ref())
                    .map_or(0, |opening| opening.proof.proof.leaf_count);
                if change_len == 0 {
                    if predecessor.is_some()
                        || successor.is_some()
                        || *change_root != commitment::empty_root::<H>(VectorKind::Change)
                    {
                        return Err(ChallengeError::LookupOrder);
                    }
                } else {
                    for opening in predecessor.iter().chain(successor.iter()) {
                        opening.proof.verify::<H>(
                            VectorKind::Change,
                            change_root,
                            opening.row.encode().as_ref(),
                        )?;
                    }
                    let insertion = successor
                        .as_ref()
                        .map_or(change_len, |opening| opening.proof.position);
                    match predecessor {
                        None if insertion == 0 => {}
                        Some(opening)
                            if opening.proof.position.checked_add(1) == Some(insertion)
                                && opening.row.account < *account => {}
                        _ => return Err(ChallengeError::LookupOrder),
                    }
                    match successor {
                        None if insertion == change_len => {}
                        Some(opening)
                            if opening.proof.position == insertion
                                && opening.row.account > *account => {}
                        _ => return Err(ChallengeError::LookupOrder),
                    }
                }

                Ok(ResolvedAccount {
                    opening: state,
                    closing: state,
                    row: None,
                })
            }
        }
    }
}

fn write_optional_row<P: PublicKey, D: Digest>(
    buf: &mut impl BufMut,
    value: Option<&RowOpening<P, D>>,
) {
    match value {
        None => 0_u8.write(buf),
        Some(value) => {
            1_u8.write(buf);
            value.write(buf);
        }
    }
}

fn read_optional_row<P: PublicKey, D: Digest>(
    buf: &mut impl Buf,
) -> Result<Option<Box<RowOpening<P, D>>>, CodecError> {
    match u8::read(buf)? {
        0 => Ok(None),
        1 => Ok(Some(Box::new(RowOpening::read(buf)?))),
        tag => Err(CodecError::InvalidEnum(tag)),
    }
}

fn optional_row_size<P: PublicKey, D: Digest>(value: Option<&RowOpening<P, D>>) -> usize {
    u8::SIZE + value.map_or(0, EncodeSize::encode_size)
}

impl<P: PublicKey, D: Digest> Write for AccountLookup<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present(opening) => {
                1_u8.write(buf);
                opening.write(buf);
            }
            Self::Absent {
                state,
                predecessor,
                successor,
            } => {
                2_u8.write(buf);
                state.write(buf);
                write_optional_row(buf, predecessor.as_deref());
                write_optional_row(buf, successor.as_deref());
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for AccountLookup<P, D> {
    fn encode_size(&self) -> usize {
        match self {
            Self::Present(opening) => u8::SIZE + opening.encode_size(),
            Self::Absent {
                state,
                predecessor,
                successor,
            } => {
                u8::SIZE
                    + state.encode_size()
                    + optional_row_size(predecessor.as_deref())
                    + optional_row_size(successor.as_deref())
            }
        }
    }
}

impl<P: PublicKey, D: Digest> Read for AccountLookup<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::Present(Box::new(RowOpening::read(buf)?))),
            2 => Ok(Self::Absent {
                state: Box::new(StateLookup::read(buf)?),
                predecessor: read_optional_row(buf)?,
                successor: read_optional_row(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// Lower endpoint for an inconsistent-range challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RangeLower<P: PublicKey, D: Digest> {
    /// Canonical `(credit,index)=(0,0)` shard opening.
    ShardStart,
    /// Earlier linked payment in the same receive shard.
    Payment(Box<Payment<P, D>>),
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for RangeLower<P, D>
where
    P: PublicKey,
    D: Digest,
    Payment<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::ShardStart)
        } else {
            Ok(Self::Payment(Box::new(u.arbitrary()?)))
        }
    }
}

impl<P: PublicKey, D: Digest> Write for RangeLower<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::ShardStart => 1_u8.write(buf),
            Self::Payment(payment) => {
                2_u8.write(buf);
                payment.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for RangeLower<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::ShardStart => 0,
                Self::Payment(payment) => payment.encode_size(),
            }
    }
}

impl<P: PublicKey, D: Digest> Read for RangeLower<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::ShardStart),
            2 => Ok(Self::Payment(Box::new(Payment::read(buf)?))),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// Exactly the four private receipt-history contradiction families.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Challenge<P: PublicKey, D: Digest> {
    /// Acknowledged payer debit is above or conflicts with the public terminal debit.
    LatestAcknowledgedSend {
        /// Admitted header identifier.
        batch: BatchId<D>,
        /// Matching payer send and operator receipt.
        payment: Box<Payment<P, D>>,
        /// Payer-row membership or ordered-absence proof.
        payer: Box<AccountLookup<P, D>>,
    },
    /// Retained receipt is above the authenticated public tip of its shard.
    HigherShardTip {
        /// Admitted header identifier.
        batch: BatchId<D>,
        /// Matching payer send and operator receipt.
        payment: Box<Payment<P, D>>,
        /// Recipient-row membership or ordered-absence proof.
        recipient: Box<AccountLookup<P, D>>,
        /// Receive-shard membership or ordered-absence proof.
        shard: Box<ShardLookup<P, D>>,
    },
    /// Two strictly ordered linked endpoints cannot be joined by positive payments.
    InconsistentReceiptRange {
        /// Admitted header identifier.
        batch: BatchId<D>,
        /// Later linked endpoint.
        upper: Box<Payment<P, D>>,
        /// Earlier linked endpoint or the canonical shard start.
        lower: RangeLower<P, D>,
    },
    /// Two distinct receipt bodies fork one shard index or payer transaction.
    ReceiptFork {
        /// Admitted header identifier.
        batch: BatchId<D>,
        /// Canonically first linked payment encoding.
        left: Box<Payment<P, D>>,
        /// Canonically second linked payment encoding.
        right: Box<Payment<P, D>>,
    },
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for Challenge<P, D>
where
    P: PublicKey,
    D: Digest,
    BatchId<D>: for<'a> arbitrary::Arbitrary<'a>,
    Payment<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    AccountLookup<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    ShardLookup<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    RangeLower<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let batch = u.arbitrary()?;
        match u.int_in_range(0..=3)? {
            0 => Ok(Self::LatestAcknowledgedSend {
                batch,
                payment: Box::new(u.arbitrary()?),
                payer: Box::new(u.arbitrary()?),
            }),
            1 => Ok(Self::HigherShardTip {
                batch,
                payment: Box::new(u.arbitrary()?),
                recipient: Box::new(u.arbitrary()?),
                shard: Box::new(u.arbitrary()?),
            }),
            2 => Ok(Self::InconsistentReceiptRange {
                batch,
                upper: Box::new(u.arbitrary()?),
                lower: u.arbitrary()?,
            }),
            _ => Ok(Self::ReceiptFork {
                batch,
                left: Box::new(u.arbitrary()?),
                right: Box::new(u.arbitrary()?),
            }),
        }
    }
}

impl<P: PublicKey, D: Digest> Challenge<P, D> {
    /// Constructs a receipt fork in canonical encoded order.
    #[must_use]
    pub fn receipt_fork(batch: BatchId<D>, left: Payment<P, D>, right: Payment<P, D>) -> Self {
        if left.encode() <= right.encode() {
            Self::ReceiptFork {
                batch,
                left: Box::new(left),
                right: Box::new(right),
            }
        } else {
            Self::ReceiptFork {
                batch,
                left: Box::new(right),
                right: Box::new(left),
            }
        }
    }

    /// Admitted header identifier bound by this challenge.
    #[must_use]
    pub const fn batch(&self) -> &BatchId<D> {
        match self {
            Self::LatestAcknowledgedSend { batch, .. }
            | Self::HigherShardTip { batch, .. }
            | Self::InconsistentReceiptRange { batch, .. }
            | Self::ReceiptFork { batch, .. } => batch,
        }
    }
}

/// Successful contradiction family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeKind {
    /// [`Challenge::LatestAcknowledgedSend`].
    LatestAcknowledgedSend,
    /// [`Challenge::HigherShardTip`].
    HigherShardTip,
    /// [`Challenge::InconsistentReceiptRange`].
    InconsistentReceiptRange,
    /// [`Challenge::ReceiptFork`].
    ReceiptFork,
}

/// Result of checking well-formed participant evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Evidence proves the named contradiction.
    Proven(ChallengeKind),
    /// Evidence is valid but does not contradict the public close.
    NoContradiction,
}

/// Checks one challenge through the inclusive deadline.
pub fn adjudicate<H, P>(
    context: &CloseContext<P, H::Digest>,
    header: &Header<H::Digest>,
    roots: &RootBundle<H::Digest>,
    now: u64,
    challenge: &Challenge<P, H::Digest>,
) -> Result<Verdict, ChallengeError>
where
    H: Hasher,
    P: PublicKey,
{
    adjudicate_with_strategy::<H, P>(context, header, roots, now, challenge, &Sequential)
}

/// Checks one challenge through the inclusive deadline using the supplied execution strategy.
pub fn adjudicate_with_strategy<H, P>(
    context: &CloseContext<P, H::Digest>,
    header: &Header<H::Digest>,
    roots: &RootBundle<H::Digest>,
    now: u64,
    challenge: &Challenge<P, H::Digest>,
    strategy: &impl Strategy,
) -> Result<Verdict, ChallengeError>
where
    H: Hasher,
    P: PublicKey,
{
    if now > context.challenge_deadline() {
        return Err(ChallengeError::Expired);
    }
    if challenge.batch() != &header.batch_id::<H>() {
        return Err(ChallengeError::WrongBatch);
    }
    if transition::validate_header::<H, P, _>(context, header, roots).is_err() {
        return Err(ChallengeError::HeaderRoot);
    }
    let context = context.payment();
    let opening_root = &roots.opening;
    let change_root = &roots.change;
    match challenge {
        Challenge::LatestAcknowledgedSend { payment, payer, .. } => {
            let (_, resolved) = strategy.try_run(
                2,
                || -> Result<_, ChallengeError> {
                    payment.verify_linked_with_strategy::<H>(context, strategy)?;
                    Ok((
                        (),
                        payer.resolve::<H>(opening_root, change_root, payment.payer())?,
                    ))
                },
                || {
                    let (payment, payer) = strategy.join(
                        || payment.verify_linked_with_strategy::<H>(context, strategy),
                        || payer.resolve::<H>(opening_root, change_root, payment.payer()),
                    );
                    payment?;
                    Ok(((), payer?))
                },
            )?;
            let disclosed = payment.send().body().cumulative_debit();
            let committed = resolved.closing.cumulative_debit;
            let committed_payment = resolved.row.as_ref().and_then(|row| row.outgoing.as_ref());
            let bodies_differ = committed_payment.is_none_or(|public| {
                public.send().body() != payment.send().body()
                    || public.receipt().body() != payment.receipt().body()
            });
            Ok(
                if disclosed > committed || (disclosed == committed && bodies_differ) {
                    Verdict::Proven(ChallengeKind::LatestAcknowledgedSend)
                } else {
                    Verdict::NoContradiction
                },
            )
        }
        Challenge::HigherShardTip {
            payment,
            recipient,
            shard,
            ..
        } => {
            let receipt = payment.receipt().body();
            let (_, resolved) = strategy.try_run(
                2,
                || -> Result<_, ChallengeError> {
                    payment.verify_linked_with_strategy::<H>(context, strategy)?;
                    Ok((
                        (),
                        recipient.resolve::<H>(opening_root, change_root, receipt.recipient())?,
                    ))
                },
                || {
                    let (payment, recipient) = strategy.join(
                        || payment.verify_linked_with_strategy::<H>(context, strategy),
                        || recipient.resolve::<H>(opening_root, change_root, receipt.recipient()),
                    );
                    payment?;
                    Ok(((), recipient?))
                },
            )?;
            let root: CreditRoot<H::Digest> = resolved.row.as_ref().map_or_else(
                || credit::empty_credit_root::<H, P>(context.epoch(), receipt.recipient()),
                |row| row.credit_root,
            );
            let public =
                shard.resolve::<H>(context.epoch(), receipt.recipient(), &root, receipt.shard())?;
            let (credit, index) = public.map_or((0, 0), |head| {
                let body = head.payment.receipt().body().clone();
                (body.cumulative_shard_credit(), body.index())
            });
            Ok(
                if receipt.cumulative_shard_credit() > credit || receipt.index() > index {
                    Verdict::Proven(ChallengeKind::HigherShardTip)
                } else {
                    Verdict::NoContradiction
                },
            )
        }
        Challenge::InconsistentReceiptRange { upper, lower, .. } => {
            let (lower_credit, lower_index) = match lower {
                RangeLower::ShardStart => {
                    upper.verify_linked_with_strategy::<H>(context, strategy)?;
                    (0, 0)
                }
                RangeLower::Payment(lower) => {
                    strategy.try_run(
                        2,
                        || -> Result<_, ChallengeError> {
                            upper.verify_linked_with_strategy::<H>(context, strategy)?;
                            lower.verify_linked_with_strategy::<H>(context, strategy)?;
                            Ok(())
                        },
                        || {
                            let (upper, lower) = strategy.join(
                                || upper.verify_linked_with_strategy::<H>(context, strategy),
                                || lower.verify_linked_with_strategy::<H>(context, strategy),
                            );
                            upper?;
                            lower?;
                            Ok(())
                        },
                    )?;
                    let upper_receipt = upper.receipt().body();
                    let lower_receipt = lower.receipt().body();
                    if lower_receipt.recipient() != upper_receipt.recipient()
                        || lower_receipt.shard() != upper_receipt.shard()
                    {
                        return Err(ChallengeError::RangeScope);
                    }
                    if upper_receipt.index() <= lower_receipt.index() {
                        return Err(ChallengeError::RangeOrder);
                    }
                    (
                        lower_receipt.cumulative_shard_credit(),
                        lower_receipt.index(),
                    )
                }
            };
            let upper_receipt = upper.receipt().body();
            let contradiction = !receipt_range_is_feasible(
                lower_credit,
                lower_index,
                upper.amount(),
                upper_receipt.cumulative_shard_credit(),
                upper_receipt.index(),
            );
            Ok(if contradiction {
                Verdict::Proven(ChallengeKind::InconsistentReceiptRange)
            } else {
                Verdict::NoContradiction
            })
        }
        Challenge::ReceiptFork { left, right, .. } => {
            strategy.try_run(
                2,
                || -> Result<_, ChallengeError> {
                    left.verify_linked_with_strategy::<H>(context, strategy)?;
                    right.verify_linked_with_strategy::<H>(context, strategy)?;
                    Ok(())
                },
                || {
                    let (left, right) = strategy.join(
                        || left.verify_linked_with_strategy::<H>(context, strategy),
                        || right.verify_linked_with_strategy::<H>(context, strategy),
                    );
                    left?;
                    right?;
                    Ok(())
                },
            )?;
            if left.encode() > right.encode() {
                return Err(ChallengeError::NonCanonicalFork);
            }
            let left_receipt = left.receipt().body();
            let right_receipt = right.receipt().body();
            if left_receipt == right_receipt {
                return Ok(Verdict::NoContradiction);
            }
            let same_index = left_receipt.recipient() == right_receipt.recipient()
                && left_receipt.shard() == right_receipt.shard()
                && left_receipt.index() == right_receipt.index();
            let same_transaction = left_receipt.tx_id() == right_receipt.tx_id();
            Ok(if same_index || same_transaction {
                Verdict::Proven(ChallengeKind::ReceiptFork)
            } else {
                Verdict::NoContradiction
            })
        }
    }
}

impl<P: PublicKey, D: Digest> Write for Challenge<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::LatestAcknowledgedSend {
                batch,
                payment,
                payer,
            } => {
                1_u8.write(buf);
                batch.write(buf);
                payment.write(buf);
                payer.write(buf);
            }
            Self::HigherShardTip {
                batch,
                payment,
                recipient,
                shard,
            } => {
                2_u8.write(buf);
                batch.write(buf);
                payment.write(buf);
                recipient.write(buf);
                shard.write(buf);
            }
            Self::InconsistentReceiptRange {
                batch,
                upper,
                lower,
            } => {
                3_u8.write(buf);
                batch.write(buf);
                upper.write(buf);
                lower.write(buf);
            }
            Self::ReceiptFork { batch, left, right } => {
                4_u8.write(buf);
                batch.write(buf);
                left.write(buf);
                right.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for Challenge<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + BatchId::<D>::SIZE
            + match self {
                Self::LatestAcknowledgedSend { payment, payer, .. } => {
                    payment.encode_size() + payer.encode_size()
                }
                Self::HigherShardTip {
                    payment,
                    recipient,
                    shard,
                    ..
                } => payment.encode_size() + recipient.encode_size() + shard.encode_size(),
                Self::InconsistentReceiptRange { upper, lower, .. } => {
                    upper.encode_size() + lower.encode_size()
                }
                Self::ReceiptFork { left, right, .. } => left.encode_size() + right.encode_size(),
            }
    }
}

impl<P: PublicKey, D: Digest> Read for Challenge<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        let batch = BatchId::read(buf)?;
        match tag {
            1 => Ok(Self::LatestAcknowledgedSend {
                batch,
                payment: Box::new(Payment::read(buf)?),
                payer: Box::new(AccountLookup::read(buf)?),
            }),
            2 => Ok(Self::HigherShardTip {
                batch,
                payment: Box::new(Payment::read(buf)?),
                recipient: Box::new(AccountLookup::read(buf)?),
                shard: Box::new(ShardLookup::read(buf)?),
            }),
            3 => Ok(Self::InconsistentReceiptRange {
                batch,
                upper: Box::new(Payment::read(buf)?),
                lower: RangeLower::read(buf)?,
            }),
            4 => Ok(Self::ReceiptFork {
                batch,
                left: Box::new(Payment::read(buf)?),
                right: Box::new(Payment::read(buf)?),
            }),
            _ => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// Decodes one exact challenge after applying an outer byte bound.
pub fn decode_bounded<P: PublicKey, D: Digest>(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<Challenge<P, D>, ChallengeError> {
    if bytes.len() > maximum_bytes {
        return Err(ChallengeError::TooLarge);
    }
    Ok(Challenge::decode(bytes)?)
}

/// Malformed, unauthenticated, mistimed, or noncanonical challenge evidence.
#[derive(Debug, Error)]
pub enum ChallengeError {
    /// Encoded challenge exceeds the caller's deployment bound.
    #[error("challenge exceeds the configured byte bound")]
    TooLarge,
    /// Challenge names a different admitted header.
    #[error("challenge binds another admitted header")]
    WrongBatch,
    /// Inclusive challenge deadline has passed.
    #[error("challenge deadline has passed")]
    Expired,
    /// Supplied roots do not open the contextual header.
    #[error("challenge roots do not open the admitted header")]
    HeaderRoot,
    /// Lookup is for another account or shard.
    #[error("authenticated lookup is for another key")]
    LookupKey,
    /// Account absence proof does not use adjacent ordered rows.
    #[error("account absence proof is not an adjacent ordered bracket")]
    LookupOrder,
    /// Receipt-range endpoints name different recipients or shards.
    #[error("receipt-range endpoints do not share one recipient and shard")]
    RangeScope,
    /// Receipt-range endpoints are not strictly increasing by index.
    #[error("receipt-range endpoints are not strictly ordered")]
    RangeOrder,
    /// Receipt-fork evidence is not in canonical encoded order.
    #[error("receipt-fork evidence is not in canonical order")]
    NonCanonicalFork,
    /// Canonical decoding failed.
    #[error("invalid challenge encoding: {0}")]
    Codec(#[from] CodecError),
    /// A signature, linkage, or receipt field is invalid.
    #[error("invalid payment evidence: {0}")]
    Payment(#[from] PaymentError),
    /// A vector opening is invalid.
    #[error("invalid commitment opening: {0}")]
    Commitment(#[from] commitment::Error),
    /// A receive-shard lookup is invalid.
    #[error("invalid receive-shard lookup: {0}")]
    Credit(#[from] credit::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bajillion::{
        boundary::{DepositBatch, WithdrawalBatch},
        commitment::{Builder, Tree},
        credit::{ShardHead, ShardSet},
        payment::{PaymentContext, PaymentError, ReceiptBody, SendBody, SignedReceipt, SignedSend},
        state::{AccountState, Prefix},
        transition::{Assignment, CloseLimits, StateCache},
    };
    use alloc::vec::Vec;
    use bytes::Bytes;
    use commonware_codec::Encode;
    use commonware_cryptography::{Sha256, Signer as _, sha256::Digest as ShaDigest};
    use commonware_cryptography_curve25519::signing::{
        Signature, SigningKey, StrictVerifyingKey as VerifyingKey,
    };
    use commonware_parallel::{Rayon, Sequential};
    use core::{fmt, ops::Deref};
    use std::{
        num::NonZeroUsize,
        sync::atomic::{AtomicUsize, Ordering},
    };

    type TestPayment = Payment<VerifyingKey, ShaDigest>;
    type TestChallenge = Challenge<VerifyingKey, ShaDigest>;
    type TestLookup = AccountLookup<VerifyingKey, ShaDigest>;

    static PUBLIC_KEY_DECODE_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
    static PUBLIC_KEY_DECODE_SUCCESSES: AtomicUsize = AtomicUsize::new(0);
    static PUBLIC_KEY_WRITES: AtomicUsize = AtomicUsize::new(0);

    #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    struct CountingKey([u8; 1]);

    impl fmt::Display for CountingKey {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{}", self.0[0])
        }
    }

    impl Deref for CountingKey {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl AsRef<[u8]> for CountingKey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    impl Write for CountingKey {
        fn write(&self, buf: &mut impl BufMut) {
            PUBLIC_KEY_WRITES.fetch_add(1, Ordering::Relaxed);
            self.0.write(buf);
        }
    }

    impl FixedSize for CountingKey {
        const SIZE: usize = 1;
    }

    impl Read for CountingKey {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            PUBLIC_KEY_DECODE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            let key = Self(<[u8; 1]>::read(buf)?);
            PUBLIC_KEY_DECODE_SUCCESSES.fetch_add(1, Ordering::Relaxed);
            Ok(key)
        }
    }

    impl commonware_utils::Span for CountingKey {}
    impl commonware_utils::Array for CountingKey {}

    impl commonware_cryptography::Verifier for CountingKey {
        type Signature = Signature;

        fn verify(&self, _: &[u8], _: &[u8], _: &Self::Signature) -> bool {
            false
        }
    }

    impl commonware_cryptography::PublicKey for CountingKey {}

    struct Fixture {
        context: CloseContext<VerifyingKey, ShaDigest>,
        header: Header<ShaDigest>,
        roots: RootBundle<ShaDigest>,
        batch: BatchId<ShaDigest>,
        state_tree: Tree<ShaDigest>,
        change_tree: Tree<ShaDigest>,
        leaves: Vec<StateLeaf<VerifyingKey>>,
        rows: Vec<AccountRow<VerifyingKey, ShaDigest>>,
        shards: Vec<ShardSet<VerifyingKey, ShaDigest>>,
        operator: SigningKey,
        payer: SigningKey,
        recipient: SigningKey,
        dormant: SigningKey,
        payment: TestPayment,
    }

    fn state(balance: u64) -> AccountState {
        AccountState {
            balance,
            active: true,
            ..AccountState::default()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn payment(
        context: &PaymentContext<VerifyingKey, ShaDigest>,
        operator: &SigningKey,
        payer: &SigningKey,
        recipient: VerifyingKey,
        amount: u64,
        previous_debit: u64,
        shard: u64,
        previous_credit: u64,
        previous_index: u64,
    ) -> TestPayment {
        let send =
            SignedSend::sign_next(context, payer, recipient, amount, previous_debit).unwrap();
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            context,
            &send,
            shard,
            previous_credit,
            previous_index,
            operator,
        )
        .unwrap();
        Payment::new::<Sha256>(context, send, receipt).unwrap()
    }

    fn payment_with_endpoint(
        context: &PaymentContext<VerifyingKey, ShaDigest>,
        operator: &SigningKey,
        send: SignedSend<VerifyingKey, ShaDigest>,
        shard: u64,
        credit: u64,
        index: u64,
    ) -> TestPayment {
        let body = ReceiptBody::from_raw_unchecked(
            *context.anchor(),
            context.epoch(),
            send.body().recipient().clone(),
            shard,
            send.body().amount(),
            send.tx_id::<Sha256>(),
            credit,
            index,
        );
        let receipt = SignedReceipt::sign_body_by_authority(body, operator);
        Payment::new::<Sha256>(context, send, receipt).unwrap()
    }

    fn tree<T: Encode>(kind: VectorKind, values: &[T]) -> Tree<ShaDigest> {
        let mut builder = Builder::<Sha256>::new(kind, values.len() as u32).unwrap();
        for value in values {
            builder.add_encoded(value.encode().as_ref()).unwrap();
        }
        builder.build(&Sequential).unwrap()
    }

    fn fixture() -> Fixture {
        let operator = SigningKey::from_seed(1);
        let payer = SigningKey::from_seed(2);
        let recipient = SigningKey::from_seed(3);
        let dormant = SigningKey::from_seed(4);
        let mut leaves = vec![
            StateLeaf {
                account: payer.public_key(),
                state: state(100),
            },
            StateLeaf {
                account: recipient.public_key(),
                state: state(40),
            },
            StateLeaf {
                account: dormant.public_key(),
                state: state(25),
            },
        ];
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves.clone()).unwrap();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let context = EpochContext::new::<Sha256>(
            Sha256::hash(&[b"challenge-deployment"]),
            7,
            operator.public_key(),
            &deposits,
            &withdrawals,
            cache.liability(),
            99,
            100,
            CloseLimits::protocol_maximum(),
            Assignment::new(Sha256::hash(&[b"challenge-committee"]), 0).unwrap(),
        )
        .and_then(|epoch| epoch.bind::<Sha256>(&cache, &deposits, &withdrawals))
        .unwrap();
        let accepted = payment(
            context.payment(),
            &operator,
            &payer,
            recipient.public_key(),
            10,
            0,
            0,
            0,
            0,
        );
        let payer_shards = ShardSet::empty(context.payment().epoch(), payer.public_key());
        let recipient_shards = ShardSet::new(
            context.payment().epoch(),
            recipient.public_key(),
            vec![ShardHead::new(0, accepted.clone())],
        )
        .unwrap();
        let mut rows = vec![
            AccountRow {
                account: payer.public_key(),
                opening: state(100),
                closing: AccountState {
                    balance: 90,
                    cumulative_debit: 10,
                    ..state(100)
                },
                outgoing: Some(accepted.clone()),
                credit_root: payer_shards.root::<Sha256>().unwrap(),
                prefix: Prefix::default(),
            },
            AccountRow {
                account: recipient.public_key(),
                opening: state(40),
                closing: AccountState {
                    balance: 50,
                    cumulative_credit: 10,
                    receipt_count: 1,
                    ..state(40)
                },
                outgoing: None,
                credit_root: recipient_shards.root::<Sha256>().unwrap(),
                prefix: Prefix::default(),
            },
        ];
        rows.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let mut shards = vec![payer_shards, recipient_shards];
        shards.sort_unstable_by(|left, right| left.recipient().cmp(right.recipient()));

        let state_tree = tree(VectorKind::State, &leaves);
        let change_tree = tree(VectorKind::Change, &rows);
        let roots = RootBundle {
            opening: state_tree.root(),
            change: change_tree.root(),
            closing: state_tree.root(),
            layout: commitment::empty_root::<Sha256>(VectorKind::Layout),
        };
        let header = Header::new::<Sha256, _>(context.payment(), &roots);
        let batch = header.batch_id::<Sha256>();
        Fixture {
            context,
            header,
            roots,
            batch,
            state_tree,
            change_tree,
            leaves,
            rows,
            shards,
            operator,
            payer,
            recipient,
            dormant,
            payment: accepted,
        }
    }

    fn lookup(fixture: &Fixture, account: &VerifyingKey) -> TestLookup {
        match fixture
            .rows
            .binary_search_by(|row| row.account.cmp(account))
        {
            Ok(position) => AccountLookup::Present(Box::new(RowOpening {
                row: fixture.rows[position].clone(),
                proof: fixture.change_tree.opening(position as u32).unwrap(),
            })),
            Err(insertion) => {
                let state_position = fixture
                    .leaves
                    .binary_search_by(|leaf| leaf.account.cmp(account))
                    .unwrap();
                let row_opening = |position: usize| {
                    Box::new(RowOpening {
                        row: fixture.rows[position].clone(),
                        proof: fixture.change_tree.opening(position as u32).unwrap(),
                    })
                };
                AccountLookup::Absent {
                    state: Box::new(StateLookup::Present(Box::new(StateOpening {
                        leaf: fixture.leaves[state_position].clone(),
                        proof: fixture.state_tree.opening(state_position as u32).unwrap(),
                    }))),
                    predecessor: insertion.checked_sub(1).map(row_opening),
                    successor: (insertion < fixture.rows.len()).then(|| row_opening(insertion)),
                }
            }
        }
    }

    fn adjudicate(fixture: &Fixture, challenge: &TestChallenge) -> Result<Verdict, ChallengeError> {
        super::adjudicate::<Sha256, _>(
            &fixture.context,
            &fixture.header,
            &fixture.roots,
            100,
            challenge,
        )
    }

    fn adjudicate_strategies(
        fixture: &Fixture,
        now: u64,
        challenge: &TestChallenge,
        rayon: &Rayon,
    ) -> Result<Verdict, ChallengeError> {
        let wrapped = super::adjudicate::<Sha256, _>(
            &fixture.context,
            &fixture.header,
            &fixture.roots,
            now,
            challenge,
        );
        let sequential = super::adjudicate_with_strategy::<Sha256, _>(
            &fixture.context,
            &fixture.header,
            &fixture.roots,
            now,
            challenge,
            &Sequential,
        );
        let parallel = super::adjudicate_with_strategy::<Sha256, _>(
            &fixture.context,
            &fixture.header,
            &fixture.roots,
            now,
            challenge,
            rayon,
        );
        assert_eq!(format!("{wrapped:?}"), format!("{sequential:?}"));
        assert_eq!(format!("{wrapped:?}"), format!("{parallel:?}"));
        wrapped
    }

    fn invalid_payer_signature(payment: &TestPayment, wrong: &SigningKey) -> TestPayment {
        Payment::from_parts_unchecked(
            SignedSend::sign_body_by_authority(payment.send().body().clone(), wrong),
            payment.receipt().clone(),
        )
    }

    fn invalid_operator_signature(payment: &TestPayment, wrong: &SigningKey) -> TestPayment {
        Payment::from_parts_unchecked(
            payment.send().clone(),
            SignedReceipt::sign_body_by_authority(payment.receipt().body().clone(), wrong),
        )
    }

    fn counting_key(next_key: &mut u8) -> CountingKey {
        let key = CountingKey([*next_key]);
        *next_key = next_key.checked_add(1).unwrap();
        key
    }

    fn counting_payment(fixture: &Fixture, next_key: &mut u8) -> Payment<CountingKey, ShaDigest> {
        let send = SignedSend::from_raw_unchecked(
            SendBody::from_raw_unchecked(
                *fixture.context.payment().anchor(),
                fixture.context.payment().epoch(),
                counting_key(next_key),
                counting_key(next_key),
                1,
                1,
            ),
            fixture.payment.send().signature().clone(),
        );
        let receipt = SignedReceipt::from_raw_unchecked(
            ReceiptBody::from_raw_unchecked(
                *fixture.context.payment().anchor(),
                fixture.context.payment().epoch(),
                counting_key(next_key),
                0,
                1,
                *fixture.payment.receipt().body().tx_id(),
                1,
                1,
            ),
            fixture.payment.receipt().signature().clone(),
        );
        Payment::from_parts_unchecked(send, receipt)
    }

    #[test]
    fn higher_shard_tip_decodes_each_public_key_occurrence() {
        let fixture = fixture();
        let payer = CountingKey([1]);
        let recipient = CountingKey([2]);
        let send = SignedSend::from_raw_unchecked(
            SendBody::from_raw_unchecked(
                *fixture.context.payment().anchor(),
                fixture.context.payment().epoch(),
                payer.clone(),
                recipient.clone(),
                10,
                10,
            ),
            fixture.payment.send().signature().clone(),
        );
        let receipt = SignedReceipt::from_raw_unchecked(
            ReceiptBody::from_raw_unchecked(
                *fixture.context.payment().anchor(),
                fixture.context.payment().epoch(),
                recipient,
                0,
                10,
                *fixture.payment.receipt().body().tx_id(),
                10,
                1,
            ),
            fixture.payment.receipt().signature().clone(),
        );
        let payment = Payment::from_parts_unchecked(send, receipt);
        let row = AccountRow {
            account: payer,
            opening: state(100),
            closing: state(90),
            outgoing: Some(payment.clone()),
            credit_root: fixture.rows[0].credit_root,
            prefix: Prefix::default(),
        };
        let challenge = Challenge::HigherShardTip {
            batch: fixture.batch,
            payment: Box::new(payment.clone()),
            recipient: Box::new(AccountLookup::Present(Box::new(RowOpening {
                row,
                proof: fixture.change_tree.opening(0).unwrap(),
            }))),
            shard: Box::new(ShardLookup::Present {
                opening: Box::new(crate::bajillion::credit::ShardOpening {
                    value: ShardHead::new(0, payment),
                    proof: fixture.change_tree.opening(0).unwrap(),
                }),
            }),
        };
        PUBLIC_KEY_WRITES.store(0, Ordering::Relaxed);
        let encoded = challenge.encode();
        assert_eq!(PUBLIC_KEY_WRITES.load(Ordering::Relaxed), 10);

        PUBLIC_KEY_DECODE_ATTEMPTS.store(0, Ordering::Relaxed);
        PUBLIC_KEY_DECODE_SUCCESSES.store(0, Ordering::Relaxed);
        let decoded = Challenge::<CountingKey, ShaDigest>::decode(encoded.clone()).unwrap();

        assert_eq!(PUBLIC_KEY_DECODE_ATTEMPTS.load(Ordering::Relaxed), 10);
        assert_eq!(PUBLIC_KEY_DECODE_SUCCESSES.load(Ordering::Relaxed), 10);
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.encode_size(), encoded.len());

        Challenge::<CountingKey, ShaDigest>::decode(encoded).unwrap();
        assert_eq!(PUBLIC_KEY_DECODE_ATTEMPTS.load(Ordering::Relaxed), 20);
        assert_eq!(PUBLIC_KEY_DECODE_SUCCESSES.load(Ordering::Relaxed), 20);
    }

    #[test]
    fn maximum_challenge_shape_is_exact_across_boundaries() {
        let fixture = fixture();
        let mut next_key = 1;
        let payment = counting_payment(&fixture, &mut next_key);
        let state_key = counting_key(&mut next_key);
        let predecessor_account = counting_key(&mut next_key);
        let predecessor_payment = counting_payment(&fixture, &mut next_key);
        let successor_account = counting_key(&mut next_key);
        let successor_payment = counting_payment(&fixture, &mut next_key);
        let predecessor_shard = counting_payment(&fixture, &mut next_key);
        let successor_shard = counting_payment(&fixture, &mut next_key);
        assert_eq!(next_key, 19);

        let row = |account, outgoing| {
            Box::new(RowOpening {
                row: AccountRow {
                    account,
                    opening: state(100),
                    closing: state(90),
                    outgoing: Some(outgoing),
                    credit_root: fixture.rows[0].credit_root,
                    prefix: Prefix::default(),
                },
                proof: fixture.change_tree.opening(0).unwrap(),
            })
        };
        let shard = |payment| {
            Box::new(crate::bajillion::credit::ShardOpening {
                value: ShardHead::new(0, payment),
                proof: fixture.change_tree.opening(0).unwrap(),
            })
        };
        let challenge = Challenge::HigherShardTip {
            batch: fixture.batch,
            payment: Box::new(payment),
            recipient: Box::new(AccountLookup::Absent {
                state: Box::new(StateLookup::Present(Box::new(StateOpening {
                    leaf: StateLeaf {
                        account: state_key,
                        state: state(100),
                    },
                    proof: fixture.state_tree.opening(0).unwrap(),
                }))),
                predecessor: Some(row(predecessor_account, predecessor_payment)),
                successor: Some(row(successor_account, successor_payment)),
            }),
            shard: Box::new(ShardLookup::Absent {
                shard: 1,
                predecessor: Some(shard(predecessor_shard)),
                successor: Some(shard(successor_shard)),
            }),
        };

        PUBLIC_KEY_WRITES.store(0, Ordering::Relaxed);
        let encoded = challenge.encode();
        assert_eq!(PUBLIC_KEY_WRITES.load(Ordering::Relaxed), 18);
        assert_eq!(challenge.encode_size(), encoded.len());

        PUBLIC_KEY_DECODE_ATTEMPTS.store(0, Ordering::Relaxed);
        PUBLIC_KEY_DECODE_SUCCESSES.store(0, Ordering::Relaxed);
        assert_eq!(
            Challenge::<CountingKey, ShaDigest>::decode(encoded.clone()).unwrap(),
            challenge
        );
        assert_eq!(PUBLIC_KEY_DECODE_ATTEMPTS.load(Ordering::Relaxed), 18);
        assert_eq!(PUBLIC_KEY_DECODE_SUCCESSES.load(Ordering::Relaxed), 18);

        for split in 0..=encoded.len() {
            PUBLIC_KEY_DECODE_ATTEMPTS.store(0, Ordering::Relaxed);
            PUBLIC_KEY_DECODE_SUCCESSES.store(0, Ordering::Relaxed);
            let segmented = Bytes::copy_from_slice(&encoded[..split])
                .chain(Bytes::copy_from_slice(&encoded[split..]));
            assert_eq!(
                Challenge::<CountingKey, ShaDigest>::decode(segmented).unwrap(),
                challenge,
                "segmentation boundary {split}"
            );
            assert_eq!(PUBLIC_KEY_DECODE_ATTEMPTS.load(Ordering::Relaxed), 18);
            assert_eq!(PUBLIC_KEY_DECODE_SUCCESSES.load(Ordering::Relaxed), 18);
        }

        for length in 0..encoded.len() {
            let result = Challenge::<CountingKey, ShaDigest>::decode(encoded.slice(..length));
            assert!(
                matches!(result, Err(CodecError::EndOfBuffer)),
                "truncation at {length} returned {result:?}"
            );
        }
        for extra in 1..=4 {
            let mut trailing = encoded.to_vec();
            trailing.resize(trailing.len() + extra, 0);
            assert!(matches!(
                Challenge::<CountingKey, ShaDigest>::decode(trailing.as_slice()),
                Err(CodecError::ExtraData(remaining)) if remaining == extra
            ));
        }
    }

    #[test]
    fn every_challenge_and_lookup_wire_variant_roundtrips_exactly() {
        let fixture = fixture();
        let payer = fixture.payer.public_key();
        let recipient = fixture.recipient.public_key();
        let recipient_position = fixture
            .shards
            .binary_search_by(|set| set.recipient().cmp(&recipient))
            .unwrap();
        let present_shard = fixture.shards[recipient_position]
            .lookup::<Sha256>(0)
            .unwrap();
        let absent_shard = fixture.shards[recipient_position]
            .lookup::<Sha256>(9)
            .unwrap();
        let no_neighbor_account = AccountLookup::Absent {
            state: Box::new(StateLookup::Present(Box::new(StateOpening {
                leaf: fixture.leaves[0].clone(),
                proof: fixture.state_tree.opening(0).unwrap(),
            }))),
            predecessor: None,
            successor: None,
        };
        let no_neighbor_shard = ShardLookup::Absent {
            shard: 9,
            predecessor: None,
            successor: None,
        };
        let challenges = vec![
            Challenge::LatestAcknowledgedSend {
                batch: fixture.batch,
                payment: Box::new(fixture.payment.clone()),
                payer: Box::new(lookup(&fixture, &payer)),
            },
            Challenge::LatestAcknowledgedSend {
                batch: fixture.batch,
                payment: Box::new(fixture.payment.clone()),
                payer: Box::new(no_neighbor_account.clone()),
            },
            Challenge::HigherShardTip {
                batch: fixture.batch,
                payment: Box::new(fixture.payment.clone()),
                recipient: Box::new(lookup(&fixture, &recipient)),
                shard: Box::new(present_shard),
            },
            Challenge::HigherShardTip {
                batch: fixture.batch,
                payment: Box::new(fixture.payment.clone()),
                recipient: Box::new(lookup(&fixture, &fixture.dormant.public_key())),
                shard: Box::new(absent_shard),
            },
            Challenge::HigherShardTip {
                batch: fixture.batch,
                payment: Box::new(fixture.payment.clone()),
                recipient: Box::new(no_neighbor_account),
                shard: Box::new(no_neighbor_shard),
            },
            Challenge::InconsistentReceiptRange {
                batch: fixture.batch,
                upper: Box::new(fixture.payment.clone()),
                lower: RangeLower::ShardStart,
            },
            Challenge::InconsistentReceiptRange {
                batch: fixture.batch,
                upper: Box::new(fixture.payment.clone()),
                lower: RangeLower::Payment(Box::new(fixture.payment.clone())),
            },
            Challenge::ReceiptFork {
                batch: fixture.batch,
                left: Box::new(fixture.payment.clone()),
                right: Box::new(fixture.payment.clone()),
            },
        ];

        for challenge in challenges {
            let encoded = challenge.encode();
            assert_eq!(challenge.encode_size(), encoded.len());
            assert_eq!(TestChallenge::decode(encoded.clone()).unwrap(), challenge);
            assert_eq!(challenge.encode(), encoded);
        }
    }

    #[test]
    fn wire_errors_keep_field_and_tag_precedence() {
        let fixture = fixture();
        let challenge = Challenge::LatestAcknowledgedSend {
            batch: fixture.batch,
            payment: Box::new(fixture.payment.clone()),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        let mut invalid_tag = challenge.encode().to_vec();
        invalid_tag[0] = 99;
        let batch_end = u8::SIZE + BatchId::<ShaDigest>::SIZE;
        assert!(matches!(
            TestChallenge::decode(&invalid_tag[..batch_end - 1]),
            Err(CodecError::EndOfBuffer)
        ));
        assert!(matches!(
            TestChallenge::decode(invalid_tag.as_slice()),
            Err(CodecError::InvalidEnum(99))
        ));

        let mut row = fixture.rows[0].encode().to_vec();
        row[VerifyingKey::SIZE + AccountState::SIZE * 2] = 2;
        assert!(matches!(
            AccountRow::<VerifyingKey, ShaDigest>::decode(row.as_slice()),
            Err(CodecError::InvalidBool)
        ));

        let state = StateOpening {
            leaf: fixture.leaves[0].clone(),
            proof: fixture.state_tree.opening(0).unwrap(),
        };
        let optional_row_offset = u8::SIZE * 2 + state.encode_size();
        let mut account_lookup = AccountLookup::<VerifyingKey, ShaDigest>::Absent {
            state: Box::new(StateLookup::Present(Box::new(state))),
            predecessor: None,
            successor: None,
        }
        .encode()
        .to_vec();
        account_lookup[optional_row_offset] = 3;
        assert!(matches!(
            TestLookup::decode(account_lookup.as_slice()),
            Err(CodecError::InvalidEnum(3))
        ));

        let mut shard_lookup = ShardLookup::<VerifyingKey, ShaDigest>::Absent {
            shard: 7,
            predecessor: None,
            successor: None,
        }
        .encode()
        .to_vec();
        shard_lookup[u8::SIZE + u64::SIZE] = 4;
        assert!(matches!(
            ShardLookup::<VerifyingKey, ShaDigest>::decode(shard_lookup.as_slice()),
            Err(CodecError::InvalidEnum(4))
        ));
        assert!(matches!(
            RangeLower::<VerifyingKey, ShaDigest>::decode([9].as_slice()),
            Err(CodecError::InvalidEnum(9))
        ));
    }

    #[test]
    fn every_challenge_strategy_matches_on_valid_and_independently_malformed_evidence() {
        let fixture = fixture();
        let rayon = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();
        let recipient = fixture.recipient.public_key();
        let recipient_position = fixture
            .shards
            .binary_search_by(|set| set.recipient().cmp(&recipient))
            .unwrap();
        let shard = || {
            Box::new(
                fixture.shards[recipient_position]
                    .lookup::<Sha256>(0)
                    .unwrap(),
            )
        };

        let valid = [
            Challenge::LatestAcknowledgedSend {
                batch: fixture.batch,
                payment: Box::new(fixture.payment.clone()),
                payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
            },
            Challenge::HigherShardTip {
                batch: fixture.batch,
                payment: Box::new(fixture.payment.clone()),
                recipient: Box::new(lookup(&fixture, &recipient)),
                shard: shard(),
            },
            Challenge::InconsistentReceiptRange {
                batch: fixture.batch,
                upper: Box::new(fixture.payment.clone()),
                lower: RangeLower::ShardStart,
            },
            Challenge::receipt_fork(
                fixture.batch,
                fixture.payment.clone(),
                fixture.payment.clone(),
            ),
        ];
        for challenge in &valid {
            assert_eq!(
                adjudicate_strategies(&fixture, 100, challenge, &rayon).unwrap(),
                Verdict::NoContradiction
            );
        }

        let wrong = SigningKey::from_seed(99);
        let invalid_operator = invalid_operator_signature(&fixture.payment, &wrong);
        let invalid_payer = invalid_payer_signature(&fixture.payment, &wrong);
        let malformed = [
            Challenge::LatestAcknowledgedSend {
                batch: fixture.batch,
                payment: Box::new(invalid_operator.clone()),
                payer: Box::new(lookup(&fixture, &recipient)),
            },
            Challenge::HigherShardTip {
                batch: fixture.batch,
                payment: Box::new(invalid_operator.clone()),
                recipient: Box::new(lookup(&fixture, &fixture.payer.public_key())),
                shard: shard(),
            },
            Challenge::InconsistentReceiptRange {
                batch: fixture.batch,
                upper: Box::new(invalid_operator.clone()),
                lower: RangeLower::Payment(Box::new(invalid_payer.clone())),
            },
            Challenge::ReceiptFork {
                batch: fixture.batch,
                left: Box::new(invalid_operator),
                right: Box::new(invalid_payer),
            },
        ];
        for challenge in &malformed {
            assert!(matches!(
                adjudicate_strategies(&fixture, 100, challenge, &rayon),
                Err(ChallengeError::Payment(
                    PaymentError::InvalidOperatorSignature
                ))
            ));
        }

        let mut expired = malformed[0].clone();
        if let Challenge::LatestAcknowledgedSend { batch, .. } = &mut expired {
            *batch = BatchId::new(Sha256::hash(&[b"wrong-batch"]));
        }
        assert!(matches!(
            adjudicate_strategies(&fixture, 101, &expired, &rayon),
            Err(ChallengeError::Expired)
        ));
    }

    #[test]
    fn latest_acknowledged_send_uses_present_and_absent_accounts() {
        let fixture = fixture();
        let later = payment(
            fixture.context.payment(),
            &fixture.operator,
            &fixture.payer,
            fixture.recipient.public_key(),
            5,
            10,
            0,
            10,
            1,
        );
        let challenge = Challenge::LatestAcknowledgedSend {
            batch: fixture.batch,
            payment: Box::new(later),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::LatestAcknowledgedSend)
        );

        let omitted = payment(
            fixture.context.payment(),
            &fixture.operator,
            &fixture.dormant,
            fixture.recipient.public_key(),
            1,
            0,
            1,
            0,
            0,
        );
        let challenge = Challenge::LatestAcknowledgedSend {
            batch: fixture.batch,
            payment: Box::new(omitted),
            payer: Box::new(lookup(&fixture, &fixture.dormant.public_key())),
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::LatestAcknowledgedSend)
        );

        let represented = Challenge::LatestAcknowledgedSend {
            batch: fixture.batch,
            payment: Box::new(fixture.payment.clone()),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        assert_eq!(
            adjudicate(&fixture, &represented).unwrap(),
            Verdict::NoContradiction
        );
    }

    #[test]
    fn equal_debit_with_another_accepted_body_is_a_latest_send_fault() {
        let fixture = fixture();
        let conflict = payment(
            fixture.context.payment(),
            &fixture.operator,
            &fixture.payer,
            fixture.dormant.public_key(),
            10,
            0,
            2,
            0,
            0,
        );
        let challenge = Challenge::LatestAcknowledgedSend {
            batch: fixture.batch,
            payment: Box::new(conflict),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::LatestAcknowledgedSend)
        );
    }

    #[test]
    fn higher_shard_tip_uses_membership_and_ordered_absence() {
        let fixture = fixture();
        let later = payment(
            fixture.context.payment(),
            &fixture.operator,
            &fixture.payer,
            fixture.recipient.public_key(),
            5,
            10,
            0,
            10,
            1,
        );
        let recipient = fixture.recipient.public_key();
        let recipient_position = fixture
            .shards
            .binary_search_by(|set| set.recipient().cmp(&recipient))
            .unwrap();
        let challenge = Challenge::HigherShardTip {
            batch: fixture.batch,
            payment: Box::new(later),
            recipient: Box::new(lookup(&fixture, &recipient)),
            shard: Box::new(
                fixture.shards[recipient_position]
                    .lookup::<Sha256>(0)
                    .unwrap(),
            ),
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::HigherShardTip)
        );

        for (credit, index) in [(11, 1), (9, 2)] {
            let send = SignedSend::sign_next(
                fixture.context.payment(),
                &fixture.payer,
                recipient.clone(),
                1,
                10,
            )
            .unwrap();
            let retained = payment_with_endpoint(
                fixture.context.payment(),
                &fixture.operator,
                send,
                0,
                credit,
                index,
            );
            let challenge = Challenge::HigherShardTip {
                batch: fixture.batch,
                payment: Box::new(retained),
                recipient: Box::new(lookup(&fixture, &recipient)),
                shard: Box::new(
                    fixture.shards[recipient_position]
                        .lookup::<Sha256>(0)
                        .unwrap(),
                ),
            };
            assert_eq!(
                adjudicate(&fixture, &challenge).unwrap(),
                Verdict::Proven(ChallengeKind::HigherShardTip)
            );
        }

        let absent_shard = payment(
            fixture.context.payment(),
            &fixture.operator,
            &fixture.payer,
            recipient.clone(),
            1,
            10,
            9,
            0,
            0,
        );
        let challenge = Challenge::HigherShardTip {
            batch: fixture.batch,
            payment: Box::new(absent_shard),
            recipient: Box::new(lookup(&fixture, &recipient)),
            shard: Box::new(
                fixture.shards[recipient_position]
                    .lookup::<Sha256>(9)
                    .unwrap(),
            ),
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::HigherShardTip)
        );
    }

    #[test]
    fn inconsistent_range_checks_start_and_linked_lower_endpoint() {
        let fixture = fixture();
        let send = SignedSend::sign_next(
            fixture.context.payment(),
            &fixture.payer,
            fixture.recipient.public_key(),
            5,
            10,
        )
        .unwrap();
        let impossible =
            payment_with_endpoint(fixture.context.payment(), &fixture.operator, send, 0, 14, 2);
        let challenge = Challenge::InconsistentReceiptRange {
            batch: fixture.batch,
            upper: Box::new(impossible),
            lower: RangeLower::Payment(Box::new(fixture.payment.clone())),
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::InconsistentReceiptRange)
        );

        let impossible = payment_with_endpoint(
            fixture.context.payment(),
            &fixture.operator,
            SignedSend::sign_next(
                fixture.context.payment(),
                &fixture.dormant,
                fixture.recipient.public_key(),
                5,
                0,
            )
            .unwrap(),
            3,
            4,
            1,
        );
        let challenge = Challenge::InconsistentReceiptRange {
            batch: fixture.batch,
            upper: Box::new(impossible),
            lower: RangeLower::ShardStart,
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::InconsistentReceiptRange)
        );

        let feasible = Challenge::InconsistentReceiptRange {
            batch: fixture.batch,
            upper: Box::new(fixture.payment.clone()),
            lower: RangeLower::ShardStart,
        };
        assert_eq!(
            adjudicate(&fixture, &feasible).unwrap(),
            Verdict::NoContradiction
        );
    }

    #[test]
    fn zero_endpoint_receipt_contradicts_shard_start() {
        let fixture = fixture();
        let zero_endpoint = payment_with_endpoint(
            fixture.context.payment(),
            &fixture.operator,
            fixture.payment.send().clone(),
            0,
            0,
            0,
        );
        let challenge = Challenge::InconsistentReceiptRange {
            batch: fixture.batch,
            upper: Box::new(zero_endpoint),
            lower: RangeLower::ShardStart,
        };

        let result = adjudicate(&fixture, &challenge);
        assert!(
            matches!(
                &result,
                Ok(Verdict::Proven(ChallengeKind::InconsistentReceiptRange))
            ),
            "an operator-signed zero endpoint must contradict the shard start: {result:?}"
        );
    }

    #[test]
    fn receipt_fork_covers_same_index_and_reused_transaction() {
        let fixture = fixture();
        let other = payment(
            fixture.context.payment(),
            &fixture.operator,
            &fixture.dormant,
            fixture.recipient.public_key(),
            10,
            0,
            0,
            0,
            0,
        );
        let challenge = Challenge::receipt_fork(fixture.batch, fixture.payment.clone(), other);
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        let reused = payment_with_endpoint(
            fixture.context.payment(),
            &fixture.operator,
            fixture.payment.send().clone(),
            4,
            10,
            1,
        );
        let challenge = Challenge::receipt_fork(fixture.batch, fixture.payment.clone(), reused);
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        let duplicate = Challenge::receipt_fork(
            fixture.batch,
            fixture.payment.clone(),
            fixture.payment.clone(),
        );
        assert_eq!(
            adjudicate(&fixture, &duplicate).unwrap(),
            Verdict::NoContradiction
        );
    }

    #[test]
    fn challenges_are_batch_bound_deadline_inclusive_and_bounded() {
        let fixture = fixture();
        let challenge = Challenge::LatestAcknowledgedSend {
            batch: fixture.batch,
            payment: Box::new(fixture.payment.clone()),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        let encoded = challenge.encode();
        assert_eq!(
            decode_bounded::<VerifyingKey, ShaDigest>(&encoded, encoded.len()).unwrap(),
            challenge
        );
        assert!(matches!(
            decode_bounded::<VerifyingKey, ShaDigest>(&encoded, encoded.len() - 1),
            Err(ChallengeError::TooLarge)
        ));

        assert!(matches!(
            super::adjudicate::<Sha256, _>(
                &fixture.context,
                &fixture.header,
                &fixture.roots,
                101,
                &challenge,
            ),
            Err(ChallengeError::Expired)
        ));
        let mut other_roots = fixture.roots;
        other_roots.closing.digest = Sha256::hash(&[b"other-closing"]);
        let other_header = Header::new::<Sha256, _>(fixture.context.payment(), &other_roots);
        assert!(matches!(
            super::adjudicate::<Sha256, _>(
                &fixture.context,
                &other_header,
                &other_roots,
                100,
                &challenge,
            ),
            Err(ChallengeError::WrongBatch)
        ));

        assert!(matches!(
            super::adjudicate::<Sha256, _>(
                &fixture.context,
                &fixture.header,
                &other_roots,
                100,
                &challenge,
            ),
            Err(ChallengeError::HeaderRoot)
        ));
    }

    #[test]
    fn adjudication_rejects_batch_id_mixed_with_another_header() {
        let fixture = fixture();
        let mut roots_a = fixture.roots;
        roots_a.closing.digest = Sha256::hash(&[b"header-a-closing"]);
        let header_a = Header::new::<Sha256, _>(fixture.context.payment(), &roots_a);
        let header_b = fixture.header;
        let batch_a = header_a.batch_id::<Sha256>();
        assert_ne!(batch_a, header_b.batch_id::<Sha256>());

        let challenge = Challenge::LatestAcknowledgedSend {
            batch: batch_a,
            payment: Box::new(fixture.payment.clone()),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        let result = super::adjudicate::<Sha256, _>(
            &fixture.context,
            &header_b,
            &fixture.roots,
            fixture.context.challenge_deadline(),
            &challenge,
        );
        assert!(
            matches!(&result, Err(ChallengeError::WrongBatch)),
            "a batch ID from header A must not authorize header B inputs: {result:?}"
        );
    }

    #[test]
    fn adjudication_rejects_another_same_liability_opening_root() {
        let fixture = fixture();
        let deposits = DepositBatch::empty();
        let withdrawals = WithdrawalBatch::empty();
        let mut leaves = fixture.leaves.clone();
        let dormant = leaves
            .iter_mut()
            .find(|leaf| leaf.account == fixture.dormant.public_key())
            .unwrap();
        dormant.account = SigningKey::from_seed(99).public_key();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let cache = StateCache::new::<Sha256>(leaves).unwrap();
        let other = EpochContext::new::<Sha256>(
            Sha256::hash(&[b"challenge-deployment"]),
            7,
            fixture.operator.public_key(),
            &deposits,
            &withdrawals,
            cache.liability(),
            99,
            100,
            CloseLimits::protocol_maximum(),
            Assignment::new(Sha256::hash(&[b"challenge-committee"]), 0).unwrap(),
        )
        .and_then(|epoch| epoch.bind::<Sha256>(&cache, &deposits, &withdrawals))
        .unwrap();
        assert_eq!(other.payment(), fixture.context.payment());
        assert_ne!(other.opening_root(), fixture.context.opening_root());

        let mut roots = fixture.roots;
        roots.opening = *other.opening_root();
        let header = Header::new::<Sha256, _>(other.payment(), &roots);
        let challenge = Challenge::LatestAcknowledgedSend {
            batch: header.batch_id::<Sha256>(),
            payment: Box::new(fixture.payment.clone()),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        let result = super::adjudicate::<Sha256, _>(
            &fixture.context,
            &header,
            &roots,
            fixture.context.challenge_deadline(),
            &challenge,
        );
        assert!(
            matches!(result, Err(ChallengeError::HeaderRoot)),
            "a header from another bound opening root was accepted: {result:?}"
        );
    }

    #[test]
    fn lookup_rejects_nonadjacent_absence_brackets() {
        let fixture = fixture();
        let mut lookup = lookup(&fixture, &fixture.dormant.public_key());
        let AccountLookup::Absent {
            predecessor,
            successor,
            ..
        } = &mut lookup
        else {
            panic!("dormant account must be absent from the change vector");
        };
        if predecessor.is_some() {
            *predecessor = None;
        } else {
            *successor = None;
        }
        assert!(matches!(
            lookup.resolve::<Sha256>(
                &fixture.roots.opening,
                &fixture.roots.change,
                &fixture.dormant.public_key(),
            ),
            Err(ChallengeError::LookupOrder)
        ));
    }

    #[test]
    fn state_lookup_proves_ordered_nonmembership() {
        let fixture = fixture();
        let account = (1_000..)
            .map(|seed| SigningKey::from_seed(seed).public_key())
            .find(|account| {
                fixture
                    .leaves
                    .binary_search_by(|leaf| leaf.account.cmp(account))
                    .is_err()
            })
            .unwrap();
        let insertion = fixture
            .leaves
            .binary_search_by(|leaf| leaf.account.cmp(&account))
            .unwrap_err();
        let opening = |position: usize| {
            Box::new(StateOpening {
                leaf: fixture.leaves[position].clone(),
                proof: fixture.state_tree.opening(position as u32).unwrap(),
            })
        };
        let lookup = StateLookup::Absent {
            predecessor: insertion.checked_sub(1).map(opening),
            successor: (insertion < fixture.leaves.len()).then(|| opening(insertion)),
        };

        assert_eq!(
            lookup
                .resolve::<Sha256>(&fixture.roots.opening, &account)
                .unwrap(),
            None
        );

        let mut nonadjacent = lookup;
        match &mut nonadjacent {
            StateLookup::Absent { predecessor, .. } if predecessor.is_some() => *predecessor = None,
            StateLookup::Absent { successor, .. } if successor.is_some() => *successor = None,
            _ => panic!("a nonempty state tree has an absence guard"),
        }
        assert!(matches!(
            nonadjacent.resolve::<Sha256>(&fixture.roots.opening, &account),
            Err(ChallengeError::LookupOrder)
        ));
    }
}
