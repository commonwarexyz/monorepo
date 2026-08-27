//! Bounded contradictions to an admitted public close.

#[cfg(test)]
use crate::bajillion::transition::EpochContext;
use crate::bajillion::{
    commitment::{self, VectorKind, VectorRoot},
    credit::{self, CreditTipLookup},
    payment::{
        Entry, Payment, PaymentError, PaymentWitness, PaymentWitnessParts, read_entries,
        receipt_range_is_feasible,
    },
    state::{AccountChange, AccountState, ChangeGuard, ChangeValue, ChangeValueCore, StateLeaf},
    transition::{self, CloseContext, Header, RootBundle},
};
use alloc::{boxed::Box, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use commonware_parallel::{Sequential, Strategy};
use thiserror::Error;

/// One account-relative change value and the membership opening for its compact guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeOpening<D: Digest> {
    /// Account-relative compact changed-account value.
    pub value: ChangeValue<D>,
    /// Position and BMT authentication path.
    pub proof: commitment::Opening<D>,
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for ChangeOpening<D>
where
    D: Digest,
    ChangeValue<D>: for<'a> arbitrary::Arbitrary<'a>,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            value: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

impl<D: Digest> Write for ChangeOpening<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.value.write(buf);
        self.proof.write(buf);
    }
}

impl<D: Digest> EncodeSize for ChangeOpening<D> {
    fn encode_size(&self) -> usize {
        self.value.encode_size() + self.proof.encode_size()
    }
}

impl<D: Digest> Read for ChangeOpening<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            value: ChangeValue::read(buf)?,
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

/// Account-relative state value and its membership opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateValueOpening<D: Digest> {
    /// State for the account supplied by the lookup target.
    pub state: AccountState,
    /// Position and BMT authentication path.
    pub proof: commitment::Opening<D>,
}

/// Adjacent state leaves and one shared proof authenticating state absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateAbsence<P: PublicKey, D: Digest> {
    /// Immediate predecessor, or `None` at the beginning of the vector.
    pub predecessor: Option<StateLeaf<P>>,
    /// Immediate successor, or `None` at the end of the vector.
    pub successor: Option<StateLeaf<P>>,
    /// One shared opening for the adjacent disclosed neighbors.
    pub opening: commitment::RangeOpening<D>,
}

/// Authenticated membership or ordered nonmembership under one state root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateLookup<P: PublicKey, D: Digest> {
    /// The requested account is a live state member.
    Present(Box<StateValueOpening<D>>),
    /// The requested account is absent, authenticated by its adjacent live leaves.
    ///
    /// One neighbor is absent at a state boundary, and both are absent for an empty state.
    Absent(StateAbsence<P, D>),
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for StateLookup<P, D>
where
    P: PublicKey,
    D: Digest,
    StateValueOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
    StateAbsence<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Present(Box::new(u.arbitrary()?)))
        } else {
            Ok(Self::Absent(u.arbitrary()?))
        }
    }
}

impl<P: PublicKey, D: Digest> StateLookup<P, D> {
    /// Verifies this lookup and returns the member state, if present.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        root: &VectorRoot<D>,
        account: &P,
    ) -> Result<Option<AccountState>, ChallengeError> {
        match self {
            Self::Present(opening) => {
                let leaf = StateLeaf {
                    account: account.clone(),
                    state: opening.state,
                };
                opening
                    .proof
                    .verify::<H>(VectorKind::State, root, leaf.encode().as_ref())?;
                Ok(Some(opening.state))
            }
            Self::Absent(absence) => {
                absence.resolve::<H>(root, account)?;
                Ok(None)
            }
        }
    }
}

impl<P: PublicKey, D: Digest> StateAbsence<P, D> {
    fn resolve<H: Hasher<Digest = D>>(
        &self,
        root: &VectorRoot<D>,
        account: &P,
    ) -> Result<(), ChallengeError> {
        let len = self.opening.proof.leaf_count;
        let insertion = self
            .opening
            .start
            .checked_add(u32::from(self.predecessor.is_some()))
            .ok_or(ChallengeError::LookupOrder)?;
        if self.predecessor.is_some() != (insertion > 0)
            || self.successor.is_some() != (insertion < len)
            || self
                .predecessor
                .as_ref()
                .is_some_and(|leaf| leaf.account >= *account)
            || self
                .successor
                .as_ref()
                .is_some_and(|leaf| leaf.account <= *account)
        {
            return Err(ChallengeError::LookupOrder);
        }
        let encoded = self
            .predecessor
            .iter()
            .chain(self.successor.iter())
            .map(Encode::encode)
            .collect::<Vec<_>>();
        self.opening
            .verify::<H, _>(VectorKind::State, root, &encoded)?;
        Ok(())
    }
}

impl<D: Digest> Write for StateValueOpening<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.state.write(buf);
        self.proof.write(buf);
    }
}

impl<D: Digest> EncodeSize for StateValueOpening<D> {
    fn encode_size(&self) -> usize {
        self.state.encode_size() + self.proof.encode_size()
    }
}

impl<D: Digest> Read for StateValueOpening<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            state: AccountState::read(buf)?,
            proof: commitment::Opening::read(buf)?,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for StateAbsence<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.predecessor.write(buf);
        self.successor.write(buf);
        self.opening.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for StateAbsence<P, D> {
    fn encode_size(&self) -> usize {
        self.predecessor.encode_size() + self.successor.encode_size() + self.opening.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for StateAbsence<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            predecessor: Option::<StateLeaf<P>>::read(buf)?,
            successor: Option::<StateLeaf<P>>::read(buf)?,
            opening: commitment::RangeOpening::read_bounded(buf, 2, usize::MAX)?,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for StateLookup<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present(opening) => {
                1_u8.write(buf);
                opening.write(buf);
            }
            Self::Absent(absence) => {
                2_u8.write(buf);
                absence.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for StateLookup<P, D> {
    fn encode_size(&self) -> usize {
        match self {
            Self::Present(opening) => u8::SIZE + opening.encode_size(),
            Self::Absent(absence) => u8::SIZE + absence.encode_size(),
        }
    }
}

impl<P: PublicKey, D: Digest> Read for StateLookup<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::Present(Box::new(StateValueOpening::read(buf)?))),
            2 => Ok(Self::Absent(StateAbsence::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for StateValueOpening<D>
where
    D: Digest,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            state: u.arbitrary()?,
            proof: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for StateAbsence<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest,
    commitment::RangeOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            predecessor: u.arbitrary()?,
            successor: u.arbitrary()?,
            opening: u.arbitrary()?,
        })
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

/// Adjacent compact leaves and one shared proof authenticating change-vector absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeAbsence<P: PublicKey, D: Digest> {
    /// Immediate predecessor, or `None` at the beginning of the vector.
    pub predecessor: Option<ChangeGuard<P, D>>,
    /// Immediate successor, or `None` at the end of the vector.
    pub successor: Option<ChangeGuard<P, D>>,
    /// One contiguous proof for the disclosed adjacent leaves.
    pub opening: commitment::RangeOpening<D>,
}

impl<P: PublicKey, D: Digest> ChangeAbsence<P, D> {
    fn resolve<H: Hasher<Digest = D>>(
        &self,
        root: &VectorRoot<D>,
        account: &P,
    ) -> Result<(), ChallengeError> {
        let insertion = self
            .opening
            .start
            .checked_add(u32::from(self.predecessor.is_some()))
            .ok_or(ChallengeError::LookupOrder)?;
        if self.predecessor.is_some() != (insertion > 0)
            || self.successor.is_some() != (insertion < self.opening.proof.leaf_count)
            || self
                .predecessor
                .as_ref()
                .is_some_and(|leaf| leaf.account() >= account)
            || self
                .successor
                .as_ref()
                .is_some_and(|leaf| leaf.account() <= account)
        {
            return Err(ChallengeError::LookupOrder);
        }
        let encoded = self
            .predecessor
            .iter()
            .chain(self.successor.iter())
            .map(Encode::encode)
            .collect::<Vec<_>>();
        self.opening
            .verify::<H, _>(VectorKind::Change, root, &encoded)?;
        Ok(())
    }
}

impl<P: PublicKey, D: Digest> Write for ChangeAbsence<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.predecessor.write(buf);
        self.successor.write(buf);
        self.opening.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ChangeAbsence<P, D> {
    fn encode_size(&self) -> usize {
        self.predecessor.encode_size() + self.successor.encode_size() + self.opening.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for ChangeAbsence<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            predecessor: Option::<ChangeGuard<P, D>>::read(buf)?,
            successor: Option::<ChangeGuard<P, D>>::read(buf)?,
            opening: commitment::RangeOpening::read_bounded(buf, 2, usize::MAX)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ChangeAbsence<P, D>
where
    P: PublicKey,
    D: Digest,
    ChangeGuard<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    commitment::RangeOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            predecessor: u.arbitrary()?,
            successor: u.arbitrary()?,
            opening: u.arbitrary()?,
        })
    }
}

fn resolve_change_opening<H, P, D>(
    opening: &ChangeOpening<D>,
    root: &VectorRoot<D>,
    account: &P,
) -> Result<AccountChange<P, D>, ChallengeError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    let guard = ChangeGuard::from_value::<H>(account.clone(), &opening.value);
    opening
        .proof
        .verify::<H>(VectorKind::Change, root, guard.encode().as_ref())?;
    Ok(AccountChange::from_value(
        account.clone(),
        opening.value.clone(),
    ))
}

/// Compact changed-account membership or ordered absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangeLookup<P: PublicKey, D: Digest> {
    /// The account has one compact changed-account leaf.
    Present(Box<ChangeOpening<D>>),
    /// The account is absent from the change vector.
    Absent(ChangeAbsence<P, D>),
}

impl<P: PublicKey, D: Digest> ChangeLookup<P, D> {
    /// Verifies the lookup against the exact change root.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        root: &VectorRoot<D>,
        account: &P,
    ) -> Result<Option<AccountChange<P, D>>, ChallengeError> {
        match self {
            Self::Present(opening) => {
                resolve_change_opening::<H, P, D>(opening, root, account).map(Some)
            }
            Self::Absent(absence) => {
                absence.resolve::<H>(root, account)?;
                Ok(None)
            }
        }
    }
}

impl<P: PublicKey, D: Digest> Write for ChangeLookup<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present(opening) => {
                1_u8.write(buf);
                opening.write(buf);
            }
            Self::Absent(absence) => {
                2_u8.write(buf);
                absence.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for ChangeLookup<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Present(opening) => opening.encode_size(),
                Self::Absent(absence) => absence.encode_size(),
            }
    }
}

impl<P: PublicKey, D: Digest> Read for ChangeLookup<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::Present(Box::new(ChangeOpening::read(buf)?))),
            2 => Ok(Self::Absent(ChangeAbsence::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ChangeLookup<P, D>
where
    P: PublicKey,
    D: Digest,
    ChangeOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
    ChangeAbsence<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Present(Box::new(u.arbitrary()?)))
        } else {
            Ok(Self::Absent(u.arbitrary()?))
        }
    }
}

/// Composed recipient and receive-shard proof for a higher-tip challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HigherShardTipLookup<P: PublicKey, D: Digest> {
    /// The recipient changed, so its child proof reconstructs the omitted credit-tip root.
    Present {
        /// Change value fields preceding the reconstructed child root.
        value: ChangeValueCore<D>,
        /// Membership opening under the change root.
        proof: commitment::Opening<D>,
        /// Membership or ordered absence under the reconstructed credit-tip root.
        tip: CreditTipLookup<D>,
    },
    /// The recipient is absent from the change vector and therefore has no terminal credit tip.
    Absent(ChangeAbsence<P, D>),
}

impl<P: PublicKey, D: Digest> HigherShardTipLookup<P, D> {
    /// Verifies the composed lookup and returns the public terminal shard tip, if present.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        change_root: &VectorRoot<D>,
        recipient: &P,
        shard: u64,
    ) -> Result<Option<credit::CreditTip>, ChallengeError> {
        match self {
            Self::Present { value, proof, tip } => {
                let (credit_tip_root, tip) = tip.reconstruct::<H>(shard)?;
                let value = ChangeValue::from_core(*value, credit_tip_root);
                let guard = ChangeGuard::from_value::<H>(recipient.clone(), &value);
                proof.verify::<H>(VectorKind::Change, change_root, guard.encode().as_ref())?;
                Ok(tip)
            }
            Self::Absent(absence) => {
                absence.resolve::<H>(change_root, recipient)?;
                Ok(None)
            }
        }
    }
}

impl<P: PublicKey, D: Digest> Write for HigherShardTipLookup<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present { value, proof, tip } => {
                1_u8.write(buf);
                value.write(buf);
                proof.write(buf);
                tip.write(buf);
            }
            Self::Absent(absence) => {
                2_u8.write(buf);
                absence.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for HigherShardTipLookup<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Present { value, proof, tip } => {
                    value.encode_size() + proof.encode_size() + tip.encode_size()
                }
                Self::Absent(absence) => absence.encode_size(),
            }
    }
}

impl<P: PublicKey, D: Digest> Read for HigherShardTipLookup<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::Present {
                value: ChangeValueCore::read(buf)?,
                proof: commitment::Opening::read(buf)?,
                tip: CreditTipLookup::read(buf)?,
            }),
            2 => Ok(Self::Absent(ChangeAbsence::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for HigherShardTipLookup<P, D>
where
    P: PublicKey,
    D: Digest,
    ChangeValueCore<D>: for<'a> arbitrary::Arbitrary<'a>,
    commitment::Opening<D>: for<'a> arbitrary::Arbitrary<'a>,
    CreditTipLookup<D>: for<'a> arbitrary::Arbitrary<'a>,
    ChangeAbsence<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Present {
                value: u.arbitrary()?,
                proof: u.arbitrary()?,
                tip: u.arbitrary()?,
            })
        } else {
            Ok(Self::Absent(u.arbitrary()?))
        }
    }
}

/// Compact debit resolution, retaining predecessor state only for an unchanged account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountLookup<P: PublicKey, D: Digest> {
    /// The account changed and exposes its compact terminal debit projection.
    Present(Box<ChangeOpening<D>>),
    /// The account is unchanged and its predecessor debit remains authoritative.
    Absent {
        /// Predecessor-state membership or ordered-nonmembership proof.
        state: Box<StateLookup<P, D>>,
        /// Ordered proof that the account is absent from the change vector.
        change: ChangeAbsence<P, D>,
    },
}

/// Public debit endpoint resolved from an [`AccountLookup`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAccount<P: PublicKey, D: Digest> {
    /// Public terminal cumulative debit.
    pub terminal_debit: u64,
    /// Compact changed-account leaf, when one exists.
    pub leaf: Option<AccountChange<P, D>>,
}

impl<P: PublicKey, D: Digest> AccountLookup<P, D> {
    /// Verifies changed membership or unchanged predecessor-state resolution for `account`.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        predecessor_root: &VectorRoot<D>,
        change_root: &VectorRoot<D>,
        account: &P,
    ) -> Result<ResolvedAccount<P, D>, ChallengeError> {
        match self {
            Self::Present(opening) => {
                let leaf = resolve_change_opening::<H, P, D>(opening, change_root, account)?;
                Ok(ResolvedAccount {
                    terminal_debit: leaf.terminal_debit(),
                    leaf: Some(leaf),
                })
            }
            Self::Absent { state, change } => {
                change.resolve::<H>(change_root, account)?;
                let state = state
                    .resolve::<H>(predecessor_root, account)?
                    .unwrap_or_default();
                Ok(ResolvedAccount {
                    terminal_debit: state.cumulative_debit,
                    leaf: None,
                })
            }
        }
    }
}

impl<P: PublicKey, D: Digest> Write for AccountLookup<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present(opening) => {
                1_u8.write(buf);
                opening.write(buf);
            }
            Self::Absent { state, change } => {
                2_u8.write(buf);
                state.write(buf);
                change.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for AccountLookup<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Present(opening) => opening.encode_size(),
                Self::Absent { state, change } => state.encode_size() + change.encode_size(),
            }
    }
}

impl<P: PublicKey, D: Digest> Read for AccountLookup<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::Present(Box::new(ChangeOpening::read(buf)?))),
            2 => Ok(Self::Absent {
                state: Box::new(StateLookup::read(buf)?),
                change: ChangeAbsence::read(buf)?,
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for AccountLookup<P, D>
where
    P: PublicKey,
    D: Digest,
    ChangeOpening<D>: for<'a> arbitrary::Arbitrary<'a>,
    StateLookup<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    ChangeAbsence<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Present(Box::new(u.arbitrary()?)))
        } else {
            Ok(Self::Absent {
                state: Box::new(u.arbitrary()?),
                change: u.arbitrary()?,
            })
        }
    }
}

/// Linked payment fields whose recipient and receive shard are shared by a range endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopedPaymentWitness<P: PublicKey> {
    payer: P,
    entries: Vec<Entry<P>>,
    cumulative_debit: u64,
    payer_signature: P::Signature,
    cumulative_shard_credit: u64,
    index: u64,
    operator_signature: P::Signature,
}

impl<P: PublicKey> ScopedPaymentWitness<P> {
    /// Projects a linked payment relative to a separately encoded recipient and shard.
    #[must_use]
    pub fn from_payment<D: Digest>(payment: &Payment<P, D>) -> Self {
        Self::from_witness(&PaymentWitness::from_payment(payment))
    }

    fn from_witness(payment: &PaymentWitness<P>) -> Self {
        let parts = payment.parts();
        Self {
            payer: parts.payer,
            entries: parts.entries,
            cumulative_debit: parts.cumulative_debit,
            payer_signature: parts.payer_signature,
            cumulative_shard_credit: parts.cumulative_shard_credit,
            index: parts.index,
            operator_signature: parts.operator_signature,
        }
    }

    fn with_scope(&self, recipient: P, shard: u64) -> PaymentWitness<P> {
        PaymentWitness::from_parts(PaymentWitnessParts {
            payer: self.payer.clone(),
            entries: self.entries.clone(),
            cumulative_debit: self.cumulative_debit,
            payer_signature: self.payer_signature.clone(),
            recipient,
            shard,
            cumulative_shard_credit: self.cumulative_shard_credit,
            index: self.index,
            operator_signature: self.operator_signature.clone(),
        })
    }
}

impl<P: PublicKey> Write for ScopedPaymentWitness<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.payer.write(buf);
        self.entries.write(buf);
        self.cumulative_debit.write(buf);
        self.payer_signature.write(buf);
        self.cumulative_shard_credit.write(buf);
        self.index.write(buf);
        self.operator_signature.write(buf);
    }
}

impl<P: PublicKey> EncodeSize for ScopedPaymentWitness<P> {
    fn encode_size(&self) -> usize {
        P::SIZE + self.entries.encode_size() + u64::SIZE * 3 + P::Signature::SIZE * 2
    }
}

impl<P: PublicKey> Read for ScopedPaymentWitness<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            payer: P::read(buf)?,
            entries: read_entries(buf)?,
            cumulative_debit: u64::read(buf)?,
            payer_signature: P::Signature::read(buf)?,
            cumulative_shard_credit: u64::read(buf)?,
            index: u64::read(buf)?,
            operator_signature: P::Signature::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P> arbitrary::Arbitrary<'_> for ScopedPaymentWitness<P>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            payer: u.arbitrary()?,
            entries: u.arbitrary()?,
            cumulative_debit: u.arbitrary()?,
            payer_signature: u.arbitrary()?,
            cumulative_shard_credit: u.arbitrary()?,
            index: u.arbitrary()?,
            operator_signature: u.arbitrary()?,
        })
    }
}

/// Operator-signed receipt fields relative to one shared signed send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptWitness<P: PublicKey> {
    shard: u64,
    cumulative_shard_credit: u64,
    index: u64,
    operator_signature: P::Signature,
}

impl<P: PublicKey> ReceiptWitness<P> {
    /// Projects the receipt-specific fields from a linked payment.
    #[must_use]
    pub fn from_payment<D: Digest>(payment: &Payment<P, D>) -> Self {
        Self::from_witness(&PaymentWitness::from_payment(payment))
    }

    fn from_witness(payment: &PaymentWitness<P>) -> Self {
        let parts = payment.parts();
        Self {
            shard: parts.shard,
            cumulative_shard_credit: parts.cumulative_shard_credit,
            index: parts.index,
            operator_signature: parts.operator_signature,
        }
    }

    fn with_send(&self, send: &PaymentWitness<P>) -> PaymentWitness<P> {
        let mut parts = send.parts();
        parts.shard = self.shard;
        parts.cumulative_shard_credit = self.cumulative_shard_credit;
        parts.index = self.index;
        parts.operator_signature = self.operator_signature.clone();
        PaymentWitness::from_parts(parts)
    }
}

impl<P: PublicKey> Write for ReceiptWitness<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.shard.write(buf);
        self.cumulative_shard_credit.write(buf);
        self.index.write(buf);
        self.operator_signature.write(buf);
    }
}

impl<P: PublicKey> FixedSize for ReceiptWitness<P> {
    const SIZE: usize = u64::SIZE * 3 + P::Signature::SIZE;
}

impl<P: PublicKey> Read for ReceiptWitness<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            shard: u64::read(buf)?,
            cumulative_shard_credit: u64::read(buf)?,
            index: u64::read(buf)?,
            operator_signature: P::Signature::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P> arbitrary::Arbitrary<'_> for ReceiptWitness<P>
where
    P: PublicKey,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            shard: u.arbitrary()?,
            cumulative_shard_credit: u.arbitrary()?,
            index: u.arbitrary()?,
            operator_signature: u.arbitrary()?,
        })
    }
}

/// Linked payment fields relative to a shared recipient, shard, and receipt index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SameIndexPaymentWitness<P: PublicKey> {
    payer: P,
    entries: Vec<Entry<P>>,
    cumulative_debit: u64,
    payer_signature: P::Signature,
    cumulative_shard_credit: u64,
    operator_signature: P::Signature,
}

impl<P: PublicKey> SameIndexPaymentWitness<P> {
    /// Projects one linked payment relative to a separately encoded receipt index scope.
    #[must_use]
    pub fn from_payment<D: Digest>(payment: &Payment<P, D>) -> Self {
        Self::from_witness(&PaymentWitness::from_payment(payment))
    }

    fn from_witness(payment: &PaymentWitness<P>) -> Self {
        let parts = payment.parts();
        Self {
            payer: parts.payer,
            entries: parts.entries,
            cumulative_debit: parts.cumulative_debit,
            payer_signature: parts.payer_signature,
            cumulative_shard_credit: parts.cumulative_shard_credit,
            operator_signature: parts.operator_signature,
        }
    }

    fn with_index_scope(&self, recipient: P, shard: u64, index: u64) -> PaymentWitness<P> {
        PaymentWitness::from_parts(PaymentWitnessParts {
            payer: self.payer.clone(),
            entries: self.entries.clone(),
            cumulative_debit: self.cumulative_debit,
            payer_signature: self.payer_signature.clone(),
            recipient,
            shard,
            cumulative_shard_credit: self.cumulative_shard_credit,
            index,
            operator_signature: self.operator_signature.clone(),
        })
    }
}

impl<P: PublicKey> Write for SameIndexPaymentWitness<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.payer.write(buf);
        self.entries.write(buf);
        self.cumulative_debit.write(buf);
        self.payer_signature.write(buf);
        self.cumulative_shard_credit.write(buf);
        self.operator_signature.write(buf);
    }
}

impl<P: PublicKey> EncodeSize for SameIndexPaymentWitness<P> {
    fn encode_size(&self) -> usize {
        P::SIZE + self.entries.encode_size() + u64::SIZE * 2 + P::Signature::SIZE * 2
    }
}

impl<P: PublicKey> Read for SameIndexPaymentWitness<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            payer: P::read(buf)?,
            entries: read_entries(buf)?,
            cumulative_debit: u64::read(buf)?,
            payer_signature: P::Signature::read(buf)?,
            cumulative_shard_credit: u64::read(buf)?,
            operator_signature: P::Signature::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P> arbitrary::Arbitrary<'_> for SameIndexPaymentWitness<P>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    P::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            payer: u.arbitrary()?,
            entries: u.arbitrary()?,
            cumulative_debit: u.arbitrary()?,
            payer_signature: u.arbitrary()?,
            cumulative_shard_credit: u.arbitrary()?,
            operator_signature: u.arbitrary()?,
        })
    }
}

/// Lower endpoint for an inconsistent-range challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RangeLower<P: PublicKey> {
    /// Canonical `(credit,index)=(0,0)` shard start.
    ShardStart,
    /// Earlier linked payment in the same receive shard.
    Payment(Box<ScopedPaymentWitness<P>>),
}

impl<P: PublicKey> RangeLower<P> {
    /// Projects an earlier linked endpoint relative to the challenge's upper scope.
    #[must_use]
    pub fn from_payment<D: Digest>(payment: &Payment<P, D>) -> Self {
        Self::Payment(Box::new(ScopedPaymentWitness::from_payment(payment)))
    }
}

#[cfg(feature = "arbitrary")]
impl<P> arbitrary::Arbitrary<'_> for RangeLower<P>
where
    P: PublicKey,
    ScopedPaymentWitness<P>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::ShardStart)
        } else {
            Ok(Self::Payment(Box::new(u.arbitrary()?)))
        }
    }
}

impl<P: PublicKey> Write for RangeLower<P> {
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

impl<P: PublicKey> EncodeSize for RangeLower<P> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::ShardStart => 0,
                Self::Payment(payment) => payment.encode_size(),
            }
    }
}

impl<P: PublicKey> Read for RangeLower<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::ShardStart),
            2 => Ok(Self::Payment(Box::new(ScopedPaymentWitness::read(buf)?))),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// Canonical relation-specific evidence for a receipt fork.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptForkWitness<P: PublicKey> {
    /// Both receipts share one exact signed send and credited entry recipient.
    SameSend {
        /// Canonically first complete linked payment.
        left: Box<PaymentWitness<P>>,
        /// Receipt fields for the second payment.
        right: ReceiptWitness<P>,
    },
    /// Both receipts share one recipient-local shard index.
    SameIndex {
        /// Canonically first complete linked payment.
        left: Box<PaymentWitness<P>>,
        /// Second payment fields relative to the first receipt's index scope.
        right: SameIndexPaymentWitness<P>,
    },
    /// Lossless fallback for forks that share only a transaction digest.
    Full {
        /// Canonically first linked payment.
        left: Box<PaymentWitness<P>>,
        /// Canonically second linked payment.
        right: Box<PaymentWitness<P>>,
    },
}

impl<P: PublicKey> ReceiptForkWitness<P> {
    /// Projects two payments into their smallest canonical lossless fork relation.
    #[must_use]
    pub fn from_payments<D: Digest>(left: &Payment<P, D>, right: &Payment<P, D>) -> Self {
        Self::from_witnesses(
            PaymentWitness::from_payment(left),
            PaymentWitness::from_payment(right),
        )
    }

    fn same_send(left: &PaymentWitness<P>, right: &PaymentWitness<P>) -> bool {
        let left = left.parts();
        let right = right.parts();
        left.payer == right.payer
            && left.entries == right.entries
            && left.cumulative_debit == right.cumulative_debit
            && left.payer_signature == right.payer_signature
            && left.recipient == right.recipient
    }

    fn same_index(left: &PaymentWitness<P>, right: &PaymentWitness<P>) -> bool {
        left.recipient() == right.recipient()
            && left.shard() == right.shard()
            && left.parts().index == right.parts().index
    }

    fn from_witnesses(mut left: PaymentWitness<P>, mut right: PaymentWitness<P>) -> Self {
        if left.encode() > right.encode() {
            core::mem::swap(&mut left, &mut right);
        }
        if Self::same_send(&left, &right) {
            let right = ReceiptWitness::from_witness(&right);
            Self::SameSend {
                left: Box::new(left),
                right,
            }
        } else if Self::same_index(&left, &right) {
            let right = SameIndexPaymentWitness::from_witness(&right);
            Self::SameIndex {
                left: Box::new(left),
                right,
            }
        } else {
            Self::Full {
                left: Box::new(left),
                right: Box::new(right),
            }
        }
    }
}

impl<P: PublicKey> Write for ReceiptForkWitness<P> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::SameSend { left, right } => {
                1_u8.write(buf);
                left.write(buf);
                right.write(buf);
            }
            Self::SameIndex { left, right } => {
                2_u8.write(buf);
                left.write(buf);
                right.write(buf);
            }
            Self::Full { left, right } => {
                3_u8.write(buf);
                left.write(buf);
                right.write(buf);
            }
        }
    }
}

impl<P: PublicKey> EncodeSize for ReceiptForkWitness<P> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::SameSend { left, right } => left.encode_size() + right.encode_size(),
                Self::SameIndex { left, right } => left.encode_size() + right.encode_size(),
                Self::Full { left, right } => left.encode_size() + right.encode_size(),
            }
    }
}

impl<P: PublicKey> Read for ReceiptForkWitness<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::SameSend {
                left: Box::new(PaymentWitness::read(buf)?),
                right: ReceiptWitness::read(buf)?,
            }),
            2 => Ok(Self::SameIndex {
                left: Box::new(PaymentWitness::read(buf)?),
                right: SameIndexPaymentWitness::read(buf)?,
            }),
            3 => Ok(Self::Full {
                left: Box::new(PaymentWitness::read(buf)?),
                right: Box::new(PaymentWitness::read(buf)?),
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<P> arbitrary::Arbitrary<'_> for ReceiptForkWitness<P>
where
    P: PublicKey,
    PaymentWitness<P>: for<'a> arbitrary::Arbitrary<'a>,
    ReceiptWitness<P>: for<'a> arbitrary::Arbitrary<'a>,
    SameIndexPaymentWitness<P>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        match u.int_in_range(1..=3)? {
            1 => Ok(Self::SameSend {
                left: Box::new(u.arbitrary()?),
                right: u.arbitrary()?,
            }),
            2 => Ok(Self::SameIndex {
                left: Box::new(u.arbitrary()?),
                right: u.arbitrary()?,
            }),
            _ => Ok(Self::Full {
                left: Box::new(u.arbitrary()?),
                right: Box::new(u.arbitrary()?),
            }),
        }
    }
}

/// Exactly the four private receipt-history contradiction families.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Challenge<P: PublicKey, D: Digest> {
    /// Acknowledged payer debit is above or conflicts with the public terminal debit.
    LatestAcknowledgedSend {
        /// Matching payer send and operator receipt.
        payment: Box<PaymentWitness<P>>,
        /// Payer-row membership or ordered-absence proof.
        payer: Box<AccountLookup<P, D>>,
    },
    /// Retained receipt is above the authenticated public tip of its shard.
    HigherShardTip {
        /// Matching payer send and operator receipt.
        payment: Box<PaymentWitness<P>>,
        /// Composed recipient-row and receive-shard proof.
        recipient: Box<HigherShardTipLookup<P, D>>,
    },
    /// Two strictly ordered linked endpoints cannot be joined by positive payments.
    InconsistentReceiptRange {
        /// Later linked endpoint.
        upper: Box<PaymentWitness<P>>,
        /// Earlier linked endpoint or the canonical shard start.
        lower: RangeLower<P>,
    },
    /// Two distinct receipt bodies fork one shard index or one payer transaction entry.
    ReceiptFork {
        /// Canonical relation-specific linked payment evidence.
        fork: Box<ReceiptForkWitness<P>>,
    },
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for Challenge<P, D>
where
    P: PublicKey,
    D: Digest,
    PaymentWitness<P>: for<'a> arbitrary::Arbitrary<'a>,
    AccountLookup<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    HigherShardTipLookup<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    RangeLower<P>: for<'a> arbitrary::Arbitrary<'a>,
    ReceiptForkWitness<P>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        match u.int_in_range(0..=3)? {
            0 => Ok(Self::LatestAcknowledgedSend {
                payment: Box::new(u.arbitrary()?),
                payer: Box::new(u.arbitrary()?),
            }),
            1 => Ok(Self::HigherShardTip {
                payment: Box::new(u.arbitrary()?),
                recipient: Box::new(u.arbitrary()?),
            }),
            2 => Ok(Self::InconsistentReceiptRange {
                upper: Box::new(u.arbitrary()?),
                lower: u.arbitrary()?,
            }),
            _ => Ok(Self::ReceiptFork {
                fork: Box::new(u.arbitrary()?),
            }),
        }
    }
}

impl<P: PublicKey, D: Digest> Challenge<P, D> {
    /// Constructs a receipt fork in canonical encoded order.
    #[must_use]
    pub fn receipt_fork(left: &Payment<P, D>, right: &Payment<P, D>) -> Self {
        Self::ReceiptFork {
            fork: Box::new(ReceiptForkWitness::from_payments(left, right)),
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
    if transition::validate_header::<H, P, _>(context, header, roots).is_err() {
        return Err(ChallengeError::HeaderRoot);
    }
    let predecessor_root = context.predecessor_root();
    let context = context.payment();
    let change_root = &roots.change;
    match challenge {
        Challenge::LatestAcknowledgedSend { payment, payer } => {
            let (payment, resolved) = strategy.try_run(
                2,
                || -> Result<_, ChallengeError> {
                    let reconstructed =
                        payment.reconstruct_with_strategy::<H, H::Digest>(context, strategy)?;
                    Ok((
                        reconstructed,
                        payer.resolve::<H>(predecessor_root, change_root, payment.payer())?,
                    ))
                },
                || {
                    let (payment, payer) = strategy.join(
                        || payment.reconstruct_with_strategy::<H, H::Digest>(context, strategy),
                        || payer.resolve::<H>(predecessor_root, change_root, payment.payer()),
                    );
                    Ok((payment?, payer?))
                },
            )?;
            let disclosed = payment.send().body().cumulative_debit();
            let committed = resolved.terminal_debit;

            // Equal endpoints contradict only through the signed authorization itself. Any entry
            // receipt may accompany a committed batched send, so the receipt bytes prove nothing
            // here; a forked receipt for one entry is a receipt-fork challenge instead.
            let sends_differ = resolved
                .leaf
                .as_ref()
                .is_none_or(|leaf| !leaf.matches_outgoing::<H>(payment.send().body()));
            Ok(
                if disclosed > committed || (disclosed == committed && sends_differ) {
                    Verdict::Proven(ChallengeKind::LatestAcknowledgedSend)
                } else {
                    Verdict::NoContradiction
                },
            )
        }
        Challenge::HigherShardTip { payment, recipient } => {
            let (payment, resolved) = strategy.try_run(
                2,
                || -> Result<_, ChallengeError> {
                    let reconstructed =
                        payment.reconstruct_with_strategy::<H, H::Digest>(context, strategy)?;
                    Ok((
                        reconstructed,
                        recipient.resolve::<H>(
                            change_root,
                            payment.recipient(),
                            payment.shard(),
                        )?,
                    ))
                },
                || {
                    let (payment, recipient) = strategy.join(
                        || payment.reconstruct_with_strategy::<H, H::Digest>(context, strategy),
                        || {
                            recipient.resolve::<H>(
                                change_root,
                                payment.recipient(),
                                payment.shard(),
                            )
                        },
                    );
                    Ok((payment?, recipient?))
                },
            )?;
            let receipt = payment.receipt().body();
            let (credit, index) = resolved.map_or((0, 0), |tip| (tip.cumulative_credit, tip.index));
            Ok(
                if receipt.cumulative_shard_credit() > credit || receipt.index() > index {
                    Verdict::Proven(ChallengeKind::HigherShardTip)
                } else {
                    Verdict::NoContradiction
                },
            )
        }
        Challenge::InconsistentReceiptRange { upper, lower } => {
            let (upper, lower_credit, lower_index) = match lower {
                RangeLower::ShardStart => {
                    let upper =
                        upper.reconstruct_with_strategy::<H, H::Digest>(context, strategy)?;
                    (upper, 0, 0)
                }
                RangeLower::Payment(lower) => {
                    let lower = lower.with_scope(upper.recipient().clone(), upper.shard());
                    let (upper, lower) = strategy.try_run(
                        2,
                        || -> Result<_, ChallengeError> {
                            Ok((
                                upper
                                    .reconstruct_with_strategy::<H, H::Digest>(context, strategy)?,
                                lower
                                    .reconstruct_with_strategy::<H, H::Digest>(context, strategy)?,
                            ))
                        },
                        || -> Result<_, ChallengeError> {
                            let (upper, lower) = strategy.join(
                                || {
                                    upper.reconstruct_with_strategy::<H, H::Digest>(
                                        context, strategy,
                                    )
                                },
                                || {
                                    lower.reconstruct_with_strategy::<H, H::Digest>(
                                        context, strategy,
                                    )
                                },
                            );
                            Ok((upper?, lower?))
                        },
                    )?;
                    let upper_receipt = upper.receipt().body();
                    let lower_receipt = lower.receipt().body();
                    if upper_receipt.index() <= lower_receipt.index() {
                        return Err(ChallengeError::RangeOrder);
                    }
                    (
                        upper,
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
        Challenge::ReceiptFork { fork } => {
            let (left, right) = match fork.as_ref() {
                ReceiptForkWitness::SameSend { left, right } => {
                    (left.as_ref(), right.with_send(left))
                }
                ReceiptForkWitness::SameIndex { left, right } => {
                    let parts = left.parts();
                    (
                        left.as_ref(),
                        right.with_index_scope(parts.recipient, parts.shard, parts.index),
                    )
                }
                ReceiptForkWitness::Full { left, right } => (left.as_ref(), right.as_ref().clone()),
            };
            let (left_payment, right_payment) = strategy.try_run(
                2,
                || -> Result<_, ChallengeError> {
                    Ok((
                        left.reconstruct_with_strategy::<H, H::Digest>(context, strategy)?,
                        right.reconstruct_with_strategy::<H, H::Digest>(context, strategy)?,
                    ))
                },
                || -> Result<_, ChallengeError> {
                    let (left, right) = strategy.join(
                        || left.reconstruct_with_strategy::<H, H::Digest>(context, strategy),
                        || right.reconstruct_with_strategy::<H, H::Digest>(context, strategy),
                    );
                    Ok((left?, right?))
                },
            )?;
            if left.encode() > right.encode() {
                return Err(ChallengeError::NonCanonicalFork);
            }
            let left_receipt = left_payment.receipt().body();
            let right_receipt = right_payment.receipt().body();
            let same_recipient = left_receipt.recipient() == right_receipt.recipient();
            let same_send = left_payment.send() == right_payment.send() && same_recipient;
            let same_index = same_recipient
                && left_receipt.shard() == right_receipt.shard()
                && left_receipt.index() == right_receipt.index();
            if !match fork.as_ref() {
                ReceiptForkWitness::SameSend { .. } => same_send,
                ReceiptForkWitness::SameIndex { .. } => !same_send && same_index,
                ReceiptForkWitness::Full { .. } => !same_send && !same_index,
            } {
                return Err(ChallengeError::NonCanonicalFork);
            }
            if left_receipt == right_receipt {
                return Ok(Verdict::NoContradiction);
            }

            // Sibling receipts of one batched send legitimately share a transaction identifier,
            // so a transaction fork requires the same credited entry recipient.
            let same_entry = same_recipient && left_receipt.tx_id() == right_receipt.tx_id();
            Ok(if same_index || same_entry {
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
            Self::LatestAcknowledgedSend { payment, payer } => {
                1_u8.write(buf);
                payment.write(buf);
                payer.write(buf);
            }
            Self::HigherShardTip { payment, recipient } => {
                2_u8.write(buf);
                payment.write(buf);
                recipient.write(buf);
            }
            Self::InconsistentReceiptRange { upper, lower } => {
                3_u8.write(buf);
                upper.write(buf);
                lower.write(buf);
            }
            Self::ReceiptFork { fork } => {
                4_u8.write(buf);
                fork.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for Challenge<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::LatestAcknowledgedSend { payment, payer } => {
                    payment.encode_size() + payer.encode_size()
                }
                Self::HigherShardTip { payment, recipient } => {
                    payment.encode_size() + recipient.encode_size()
                }
                Self::InconsistentReceiptRange { upper, lower } => {
                    upper.encode_size() + lower.encode_size()
                }
                Self::ReceiptFork { fork } => fork.encode_size(),
            }
    }
}

impl<P: PublicKey, D: Digest> Read for Challenge<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            1 => Ok(Self::LatestAcknowledgedSend {
                payment: Box::new(PaymentWitness::read(buf)?),
                payer: Box::new(AccountLookup::read(buf)?),
            }),
            2 => Ok(Self::HigherShardTip {
                payment: Box::new(PaymentWitness::read(buf)?),
                recipient: Box::new(HigherShardTipLookup::read(buf)?),
            }),
            3 => Ok(Self::InconsistentReceiptRange {
                upper: Box::new(PaymentWitness::read(buf)?),
                lower: RangeLower::read(buf)?,
            }),
            4 => Ok(Self::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::read(buf)?),
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
    /// Inclusive challenge deadline has passed.
    #[error("challenge deadline has passed")]
    Expired,
    /// Supplied roots do not open the contextual header.
    #[error("challenge roots do not open the admitted header")]
    HeaderRoot,
    /// Account absence proof does not use adjacent ordered rows.
    #[error("account absence proof is not an adjacent ordered bracket")]
    LookupOrder,
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
        credit::{CreditTip, ShardHead, ShardSet},
        payment::{PaymentContext, PaymentError, ReceiptBody, SendBody, SignedReceipt, SignedSend},
        state::{AccountRow, AccountState, Prefix, SettlementOutput},
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
        state_tree: Tree<ShaDigest>,
        change_tree: Tree<ShaDigest>,
        leaves: Vec<StateLeaf<VerifyingKey>>,
        change_leaves: Vec<AccountChange<VerifyingKey, ShaDigest>>,
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
        let send = SignedSend::sign_next(context, payer, recipient.clone(), amount, previous_debit)
            .unwrap();
        let receipt = SignedReceipt::issue_next::<Sha256, _>(
            context,
            &send,
            &recipient,
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
        let entry = send.body().entries().first().unwrap();
        let body = ReceiptBody::from_raw_unchecked(
            *context.anchor(),
            context.epoch(),
            entry.recipient().clone(),
            shard,
            entry.amount(),
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
        let mut rows = [
            AccountRow {
                account: payer.public_key(),
                predecessor: state(100),
                successor: AccountState {
                    balance: 90,
                    cumulative_debit: 10,
                    ..state(100)
                },
                outgoing: Some(accepted.clone()),
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
            AccountRow {
                account: recipient.public_key(),
                predecessor: state(40),
                successor: AccountState {
                    balance: 50,
                    cumulative_credit: 10,
                    receipt_count: 1,
                    ..state(40)
                },
                outgoing: None,
                output: SettlementOutput::None,
                prefix: Prefix::default(),
            },
        ];
        rows.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        let mut shards = vec![payer_shards, recipient_shards];
        shards.sort_unstable_by(|left, right| left.recipient().cmp(right.recipient()));

        let state_tree = tree(VectorKind::State, &leaves);
        let change_leaves = rows
            .iter()
            .zip(&shards)
            .map(|(row, shards)| AccountChange::from_row::<Sha256>(row, shards).unwrap())
            .collect::<Vec<_>>();
        let change_guards = change_leaves
            .iter()
            .map(AccountChange::guard::<Sha256>)
            .collect::<Vec<_>>();
        let change_tree = tree(VectorKind::Change, &change_guards);
        let roots = RootBundle {
            change: change_tree.root(),
            withdrawal_outputs: commitment::empty_root::<Sha256>(VectorKind::WithdrawalOutput),
            successor: state_tree.root(),
            coverage: commitment::empty_root::<Sha256>(VectorKind::Coverage),
        };
        let header = Header::new::<Sha256, _>(&context, &roots);
        Fixture {
            context,
            header,
            roots,
            state_tree,
            change_tree,
            leaves,
            change_leaves,
            shards,
            operator,
            payer,
            recipient,
            dormant,
            payment: accepted,
        }
    }

    fn state_lookup(
        fixture: &Fixture,
        account: &VerifyingKey,
    ) -> StateLookup<VerifyingKey, ShaDigest> {
        match fixture
            .leaves
            .binary_search_by(|leaf| leaf.account.cmp(account))
        {
            Ok(position) => StateLookup::Present(Box::new(StateValueOpening {
                state: fixture.leaves[position].state,
                proof: fixture.state_tree.opening(position as u32).unwrap(),
            })),
            Err(insertion) => {
                let predecessor = insertion
                    .checked_sub(1)
                    .map(|position| fixture.leaves[position].clone());
                let successor = fixture.leaves.get(insertion).cloned();
                let start = insertion.saturating_sub(usize::from(predecessor.is_some()));
                let count = usize::from(predecessor.is_some()) + usize::from(successor.is_some());
                StateLookup::Absent(StateAbsence {
                    predecessor,
                    successor,
                    opening: fixture
                        .state_tree
                        .range_opening(start as u32, count as u32)
                        .unwrap(),
                })
            }
        }
    }

    fn change_absence(
        fixture: &Fixture,
        account: &VerifyingKey,
    ) -> ChangeAbsence<VerifyingKey, ShaDigest> {
        let insertion = fixture
            .change_leaves
            .binary_search_by(|leaf| leaf.account().cmp(account))
            .unwrap_err();
        let predecessor = insertion
            .checked_sub(1)
            .map(|position| fixture.change_leaves[position].guard::<Sha256>());
        let successor = fixture
            .change_leaves
            .get(insertion)
            .map(AccountChange::guard::<Sha256>);
        let start = insertion.saturating_sub(usize::from(predecessor.is_some()));
        let count = usize::from(predecessor.is_some()) + usize::from(successor.is_some());
        ChangeAbsence {
            predecessor,
            successor,
            opening: fixture
                .change_tree
                .range_opening(start as u32, count as u32)
                .unwrap(),
        }
    }

    fn higher_shard_tip_lookup(
        fixture: &Fixture,
        account: &VerifyingKey,
        shard: u64,
    ) -> HigherShardTipLookup<VerifyingKey, ShaDigest> {
        fixture
            .change_leaves
            .binary_search_by(|leaf| leaf.account().cmp(account))
            .map_or_else(
                |_| HigherShardTipLookup::Absent(change_absence(fixture, account)),
                |position| {
                    assert_eq!(fixture.shards[position].recipient(), account);
                    HigherShardTipLookup::Present {
                        value: fixture.change_leaves[position].value().core(),
                        proof: fixture.change_tree.opening(position as u32).unwrap(),
                        tip: fixture.shards[position].lookup::<Sha256>(shard).unwrap(),
                    }
                },
            )
    }

    fn lookup(fixture: &Fixture, account: &VerifyingKey) -> TestLookup {
        fixture
            .change_leaves
            .binary_search_by(|leaf| leaf.account().cmp(account))
            .map_or_else(
                |_| AccountLookup::Absent {
                    state: Box::new(state_lookup(fixture, account)),
                    change: change_absence(fixture, account),
                },
                |position| {
                    AccountLookup::Present(Box::new(ChangeOpening {
                        value: fixture.change_leaves[position].value(),
                        proof: fixture.change_tree.opening(position as u32).unwrap(),
                    }))
                },
            )
    }

    fn witness<P: PublicKey, D: Digest>(payment: &Payment<P, D>) -> Box<PaymentWitness<P>> {
        Box::new(PaymentWitness::from_payment(payment))
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

    fn assert_invalid_payer_evidence(fixture: &Fixture, challenge: &TestChallenge) {
        assert!(matches!(
            adjudicate(fixture, challenge),
            Err(ChallengeError::Payment(PaymentError::InvalidPayerSignature))
        ));
    }

    fn assert_invalid_operator_evidence(fixture: &Fixture, challenge: &TestChallenge) {
        assert!(matches!(
            adjudicate(fixture, challenge),
            Err(ChallengeError::Payment(
                PaymentError::InvalidOperatorSignature
            ))
        ));
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
                vec![Entry::from_raw_unchecked(counting_key(next_key), 1)],
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
                payer,
                vec![Entry::from_raw_unchecked(recipient.clone(), 10)],
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
        let value = fixture.change_leaves[0].value();
        let tip = fixture
            .shards
            .iter()
            .find(|set| set.recipient() == &fixture.recipient.public_key())
            .unwrap()
            .lookup::<Sha256>(0)
            .unwrap();
        let challenge = Challenge::HigherShardTip {
            payment: witness(&payment),
            recipient: Box::new(HigherShardTipLookup::Present {
                value: value.core(),
                proof: fixture.change_tree.opening(0).unwrap(),
                tip,
            }),
        };
        PUBLIC_KEY_WRITES.store(0, Ordering::Relaxed);
        let encoded = challenge.encode();
        assert_eq!(PUBLIC_KEY_WRITES.load(Ordering::Relaxed), 3);

        PUBLIC_KEY_DECODE_ATTEMPTS.store(0, Ordering::Relaxed);
        PUBLIC_KEY_DECODE_SUCCESSES.store(0, Ordering::Relaxed);
        let decoded = Challenge::<CountingKey, ShaDigest>::decode(encoded.clone()).unwrap();

        assert_eq!(PUBLIC_KEY_DECODE_ATTEMPTS.load(Ordering::Relaxed), 3);
        assert_eq!(PUBLIC_KEY_DECODE_SUCCESSES.load(Ordering::Relaxed), 3);
        assert_eq!(decoded.encode(), encoded);
        assert_eq!(decoded.encode_size(), encoded.len());

        Challenge::<CountingKey, ShaDigest>::decode(encoded).unwrap();
        assert_eq!(PUBLIC_KEY_DECODE_ATTEMPTS.load(Ordering::Relaxed), 6);
        assert_eq!(PUBLIC_KEY_DECODE_SUCCESSES.load(Ordering::Relaxed), 6);
    }

    #[test]
    fn maximum_challenge_shape_is_exact_across_boundaries() {
        let fixture = fixture();
        let mut next_key = 1;
        let payment = counting_payment(&fixture, &mut next_key);
        assert_eq!(next_key, 4);

        let tip = |shard| CreditTip {
            shard,
            cumulative_credit: 1,
            index: 1,
        };
        let tips = [tip(0), tip(2)];
        let credit_tree = tree(VectorKind::CreditTip, &tips);
        let value = fixture.change_leaves[0].value();
        let challenge = Challenge::HigherShardTip {
            payment: witness(&payment),
            recipient: Box::new(HigherShardTipLookup::Present {
                value: value.core(),
                proof: fixture.change_tree.opening(0).unwrap(),
                tip: CreditTipLookup::Absent {
                    predecessor: Some(tips[0].clone()),
                    successor: Some(tips[1].clone()),
                    opening: credit_tree.range_opening(0, 2).unwrap(),
                },
            }),
        };

        PUBLIC_KEY_WRITES.store(0, Ordering::Relaxed);
        let encoded = challenge.encode();
        assert_eq!(PUBLIC_KEY_WRITES.load(Ordering::Relaxed), 3);
        assert_eq!(challenge.encode_size(), encoded.len());

        PUBLIC_KEY_DECODE_ATTEMPTS.store(0, Ordering::Relaxed);
        PUBLIC_KEY_DECODE_SUCCESSES.store(0, Ordering::Relaxed);
        assert_eq!(
            Challenge::<CountingKey, ShaDigest>::decode(encoded.clone()).unwrap(),
            challenge
        );
        assert_eq!(PUBLIC_KEY_DECODE_ATTEMPTS.load(Ordering::Relaxed), 3);
        assert_eq!(PUBLIC_KEY_DECODE_SUCCESSES.load(Ordering::Relaxed), 3);

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
            assert_eq!(PUBLIC_KEY_DECODE_ATTEMPTS.load(Ordering::Relaxed), 3);
            assert_eq!(PUBLIC_KEY_DECODE_SUCCESSES.load(Ordering::Relaxed), 3);
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
        let empty_changes = Vec::<ChangeGuard<VerifyingKey, ShaDigest>>::new();
        let empty_change_tree = tree(VectorKind::Change, &empty_changes);
        let no_neighbor_account = AccountLookup::Absent {
            state: Box::new(state_lookup(&fixture, &fixture.dormant.public_key())),
            change: ChangeAbsence {
                predecessor: None,
                successor: None,
                opening: empty_change_tree.range_opening(0, 0).unwrap(),
            },
        };
        let no_neighbor_change = HigherShardTipLookup::Absent(ChangeAbsence {
            predecessor: None,
            successor: None,
            opening: empty_change_tree.range_opening(0, 0).unwrap(),
        });
        let challenges = vec![
            Challenge::LatestAcknowledgedSend {
                payment: witness(&fixture.payment),
                payer: Box::new(lookup(&fixture, &payer)),
            },
            Challenge::LatestAcknowledgedSend {
                payment: witness(&fixture.payment),
                payer: Box::new(no_neighbor_account),
            },
            Challenge::HigherShardTip {
                payment: witness(&fixture.payment),
                recipient: Box::new(higher_shard_tip_lookup(&fixture, &recipient, 0)),
            },
            Challenge::HigherShardTip {
                payment: witness(&fixture.payment),
                recipient: Box::new(higher_shard_tip_lookup(&fixture, &recipient, 9)),
            },
            Challenge::HigherShardTip {
                payment: witness(&fixture.payment),
                recipient: Box::new(higher_shard_tip_lookup(
                    &fixture,
                    &fixture.dormant.public_key(),
                    9,
                )),
            },
            Challenge::HigherShardTip {
                payment: witness(&fixture.payment),
                recipient: Box::new(no_neighbor_change),
            },
            Challenge::InconsistentReceiptRange {
                upper: witness(&fixture.payment),
                lower: RangeLower::ShardStart,
            },
            Challenge::InconsistentReceiptRange {
                upper: witness(&fixture.payment),
                lower: RangeLower::from_payment(&fixture.payment),
            },
            Challenge::receipt_fork(&fixture.payment, &fixture.payment),
        ];

        for challenge in challenges {
            let encoded = challenge.encode();
            assert_eq!(challenge.encode_size(), encoded.len());
            assert_eq!(TestChallenge::decode(encoded.clone()).unwrap(), challenge);
            assert_eq!(challenge.encode(), encoded);
        }
    }

    #[test]
    fn paired_witness_sizes_and_relation_tags_are_exact() {
        let fixture = fixture();
        assert_eq!(VerifyingKey::SIZE, 32);
        assert_eq!(Signature::SIZE, 64);

        let range = Challenge::InconsistentReceiptRange {
            upper: witness(&fixture.payment),
            lower: RangeLower::from_payment(&fixture.payment),
        };
        assert_eq!(range.encode_size(), 492);

        let same_send_payment = payment_with_endpoint(
            fixture.context.payment(),
            &fixture.operator,
            fixture.payment.send().clone(),
            0,
            11,
            1,
        );
        let same_send = Challenge::receipt_fork(&fixture.payment, &same_send_payment);
        assert!(matches!(
            &same_send,
            Challenge::ReceiptFork { fork }
                if matches!(fork.as_ref(), ReceiptForkWitness::SameSend { .. })
        ));
        assert_eq!(same_send.encode_size(), 355);

        let same_index_payment = payment(
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
        let same_index = Challenge::receipt_fork(&fixture.payment, &same_index_payment);
        assert!(matches!(
            &same_index,
            Challenge::ReceiptFork { fork }
                if matches!(fork.as_ref(), ReceiptForkWitness::SameIndex { .. })
        ));
        assert_eq!(same_index.encode_size(), 484);

        let full_payment = payment(
            fixture.context.payment(),
            &fixture.operator,
            &fixture.dormant,
            fixture.recipient.public_key(),
            10,
            0,
            4,
            0,
            1,
        );
        let full = Challenge::receipt_fork(&fixture.payment, &full_payment);
        assert!(matches!(
            &full,
            Challenge::ReceiptFork { fork }
                if matches!(fork.as_ref(), ReceiptForkWitness::Full { .. })
        ));

        for challenge in [&range, &same_send, &same_index, &full] {
            let encoded = challenge.encode();
            assert_eq!(challenge.encode_size(), encoded.len());
            assert_eq!(TestChallenge::decode(encoded).unwrap(), *challenge);
        }

        for (challenge, relation) in [(&same_send, 2_u8), (&same_index, 3), (&full, 2)] {
            let mut encoded = challenge.encode().to_vec();
            encoded[u8::SIZE] = relation;
            assert!(TestChallenge::decode(encoded.as_slice()).is_err());
        }

        let left = PaymentWitness::from_payment(&fixture.payment);
        let right = PaymentWitness::from_payment(&same_send_payment);
        let (left, right) = if left.encode() <= right.encode() {
            (&fixture.payment, &same_send_payment)
        } else {
            (&same_send_payment, &fixture.payment)
        };
        let noncanonical = Challenge::ReceiptFork {
            fork: Box::new(ReceiptForkWitness::SameIndex {
                left: witness(left),
                right: SameIndexPaymentWitness::from_payment(right),
            }),
        };
        assert!(matches!(
            adjudicate(&fixture, &noncanonical),
            Err(ChallengeError::NonCanonicalFork)
        ));
    }

    #[test]
    fn paired_witnesses_verify_every_retained_signature_and_canonical_relation() {
        let fixture = fixture();
        let wrong = SigningKey::from_seed(99);

        let invalid_payer = invalid_payer_signature(&fixture.payment, &wrong);
        let invalid_operator = invalid_operator_signature(&fixture.payment, &wrong);
        assert_invalid_payer_evidence(
            &fixture,
            &Challenge::InconsistentReceiptRange {
                upper: witness(&fixture.payment),
                lower: RangeLower::from_payment(&invalid_payer),
            },
        );
        assert_invalid_operator_evidence(
            &fixture,
            &Challenge::InconsistentReceiptRange {
                upper: witness(&fixture.payment),
                lower: RangeLower::from_payment(&invalid_operator),
            },
        );

        let same_send_right = payment_with_endpoint(
            fixture.context.payment(),
            &fixture.operator,
            fixture.payment.send().clone(),
            0,
            11,
            1,
        );
        assert_invalid_payer_evidence(
            &fixture,
            &Challenge::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::SameSend {
                    left: witness(&invalid_payer),
                    right: ReceiptWitness::from_payment(&same_send_right),
                }),
            },
        );
        assert_invalid_operator_evidence(
            &fixture,
            &Challenge::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::SameSend {
                    left: witness(&invalid_operator),
                    right: ReceiptWitness::from_payment(&same_send_right),
                }),
            },
        );
        let invalid_right_operator = invalid_operator_signature(&same_send_right, &wrong);
        assert_invalid_operator_evidence(
            &fixture,
            &Challenge::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::SameSend {
                    left: witness(&fixture.payment),
                    right: ReceiptWitness::from_payment(&invalid_right_operator),
                }),
            },
        );

        let same_index_right = payment(
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
        let invalid_right_payer = invalid_payer_signature(&same_index_right, &wrong);
        assert_invalid_payer_evidence(
            &fixture,
            &Challenge::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::SameIndex {
                    left: witness(&fixture.payment),
                    right: SameIndexPaymentWitness::from_payment(&invalid_right_payer),
                }),
            },
        );
        let invalid_right_operator = invalid_operator_signature(&same_index_right, &wrong);
        assert_invalid_operator_evidence(
            &fixture,
            &Challenge::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::SameIndex {
                    left: witness(&fixture.payment),
                    right: SameIndexPaymentWitness::from_payment(&invalid_right_operator),
                }),
            },
        );

        let full_right = payment(
            fixture.context.payment(),
            &fixture.operator,
            &fixture.dormant,
            fixture.recipient.public_key(),
            10,
            0,
            4,
            0,
            1,
        );
        let invalid_right_payer = invalid_payer_signature(&full_right, &wrong);
        assert_invalid_payer_evidence(
            &fixture,
            &Challenge::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::Full {
                    left: witness(&fixture.payment),
                    right: witness(&invalid_right_payer),
                }),
            },
        );
        let invalid_right_operator = invalid_operator_signature(&full_right, &wrong);
        assert_invalid_operator_evidence(
            &fixture,
            &Challenge::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::Full {
                    left: witness(&fixture.payment),
                    right: witness(&invalid_right_operator),
                }),
            },
        );

        for right in [&same_send_right, &same_index_right] {
            let mut left = PaymentWitness::from_payment(&fixture.payment);
            let mut right = PaymentWitness::from_payment(right);
            if left.encode() > right.encode() {
                core::mem::swap(&mut left, &mut right);
            }
            let noncanonical = Challenge::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::Full {
                    left: Box::new(left),
                    right: Box::new(right),
                }),
            };
            assert!(matches!(
                adjudicate(&fixture, &noncanonical),
                Err(ChallengeError::NonCanonicalFork)
            ));
        }

        let mut first = PaymentWitness::from_payment(&fixture.payment);
        let mut second = PaymentWitness::from_payment(&same_index_right);
        if first.encode() < second.encode() {
            core::mem::swap(&mut first, &mut second);
        }
        let reversed = Challenge::ReceiptFork {
            fork: Box::new(ReceiptForkWitness::SameIndex {
                left: Box::new(first),
                right: SameIndexPaymentWitness::from_witness(&second),
            }),
        };
        assert!(matches!(
            adjudicate(&fixture, &reversed),
            Err(ChallengeError::NonCanonicalFork)
        ));
    }

    #[test]
    fn higher_shard_tip_present_roundtrips_and_omits_reconstructed_root() {
        let fixture = fixture();
        let recipient = fixture.recipient.public_key();
        let position = fixture
            .change_leaves
            .binary_search_by(|leaf| leaf.account().cmp(&recipient))
            .unwrap();
        let value = fixture.change_leaves[position].value();
        let proof = fixture.change_tree.opening(position as u32).unwrap();
        let shard = fixture.shards[position].lookup::<Sha256>(0).unwrap();
        let old = ChangeLookup::<VerifyingKey, ShaDigest>::Present(Box::new(ChangeOpening {
            value: value.clone(),
            proof: proof.clone(),
        }));
        let composed = HigherShardTipLookup::Present {
            value: value.core(),
            proof,
            tip: shard.clone(),
        };

        let encoded = composed.encode();
        assert_eq!(composed.encode_size(), encoded.len());
        assert_eq!(
            HigherShardTipLookup::<VerifyingKey, ShaDigest>::decode(encoded).unwrap(),
            composed
        );
        assert_eq!(
            composed.encode_size() + ShaDigest::SIZE,
            old.encode_size() + shard.encode_size()
        );
        assert_eq!(
            composed
                .resolve::<Sha256>(&fixture.roots.change, &recipient, 0)
                .unwrap(),
            Some(CreditTip {
                shard: 0,
                cumulative_credit: 10,
                index: 1,
            })
        );
    }

    #[test]
    fn higher_shard_tip_parent_absence_omits_child_and_empty_child_stays_present() {
        let fixture = fixture();
        let dormant = fixture.dormant.public_key();
        let absence = change_absence(&fixture, &dormant);
        let old = ChangeLookup::<VerifyingKey, ShaDigest>::Absent(absence.clone());
        let absent = HigherShardTipLookup::<VerifyingKey, ShaDigest>::Absent(absence);

        assert_eq!(absent.encode(), old.encode());
        assert_eq!(
            absent
                .resolve::<Sha256>(&fixture.roots.change, &dormant, 0)
                .unwrap(),
            None
        );

        let recipient = fixture.recipient.public_key();
        let position = fixture
            .shards
            .binary_search_by(|set| set.recipient().cmp(&recipient))
            .unwrap();
        let child = fixture.shards[position].lookup::<Sha256>(0).unwrap();
        let child_encoded = child.encode();
        let mut with_child = absent.encode().to_vec();
        with_child.extend_from_slice(child_encoded.as_ref());
        assert!(matches!(
            HigherShardTipLookup::<VerifyingKey, ShaDigest>::decode(with_child.as_slice()),
            Err(CodecError::ExtraData(remaining)) if remaining == child_encoded.len()
        ));

        let payer = fixture.payer.public_key();
        let empty_child = higher_shard_tip_lookup(&fixture, &payer, 7);
        let decoded =
            HigherShardTipLookup::<VerifyingKey, ShaDigest>::decode(empty_child.encode()).unwrap();
        assert!(matches!(
            &decoded,
            HigherShardTipLookup::Present {
                tip: CreditTipLookup::Absent {
                    predecessor: None,
                    successor: None,
                    ..
                },
                ..
            }
        ));
        assert_eq!(
            decoded
                .resolve::<Sha256>(&fixture.roots.change, &payer, 7)
                .unwrap(),
            None
        );
    }

    #[test]
    fn higher_shard_tip_rejects_tampered_parent_and_child_evidence() {
        let fixture = fixture();
        let recipient = fixture.recipient.public_key();
        let position = fixture
            .change_leaves
            .binary_search_by(|leaf| leaf.account().cmp(&recipient))
            .unwrap();
        let composed = higher_shard_tip_lookup(&fixture, &recipient, 0);
        assert!(
            composed
                .resolve::<Sha256>(&fixture.roots.change, &recipient, 0)
                .is_ok()
        );

        let rejects = |lookup: &HigherShardTipLookup<VerifyingKey, ShaDigest>| {
            assert!(
                lookup
                    .resolve::<Sha256>(&fixture.roots.change, &recipient, 0)
                    .is_err()
            );
        };

        let mut child_value = composed.clone();
        let HigherShardTipLookup::Present {
            tip: CreditTipLookup::Present { value, .. },
            ..
        } = &mut child_value
        else {
            panic!("fixture shard must be present");
        };
        value.cumulative_credit = value.cumulative_credit.checked_add(1).unwrap();
        rejects(&child_value);

        let mut child_proof = composed.clone();
        let HigherShardTipLookup::Present {
            tip: CreditTipLookup::Present { opening, .. },
            ..
        } = &mut child_proof
        else {
            panic!("fixture shard must be present");
        };
        *opening = fixture.change_tree.opening(position as u32).unwrap();
        rejects(&child_proof);

        let other_position = usize::from(position == 0);
        let mut parent_value = composed.clone();
        let HigherShardTipLookup::Present { value, .. } = &mut parent_value else {
            panic!("fixture recipient must be present");
        };
        let other_value = fixture.change_leaves[other_position].value().core();
        assert_ne!(*value, other_value);
        *value = other_value;
        rejects(&parent_value);

        let mut parent_proof = composed;
        let HigherShardTipLookup::Present { proof, .. } = &mut parent_proof else {
            panic!("fixture recipient must be present");
        };
        *proof = fixture.change_tree.opening(other_position as u32).unwrap();
        rejects(&parent_proof);
    }

    #[test]
    fn wire_errors_keep_field_and_tag_precedence() {
        let fixture = fixture();
        let challenge = Challenge::LatestAcknowledgedSend {
            payment: witness(&fixture.payment),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        let mut invalid_tag = challenge.encode().to_vec();
        invalid_tag[0] = 99;
        assert!(matches!(
            TestChallenge::decode(&invalid_tag[..0]),
            Err(CodecError::EndOfBuffer)
        ));
        assert!(matches!(
            TestChallenge::decode(invalid_tag.as_slice()),
            Err(CodecError::InvalidEnum(99))
        ));

        let state = state_lookup(&fixture, &fixture.dormant.public_key());
        let optional_change_offset = u8::SIZE + state.encode_size();
        let mut account_lookup = AccountLookup::<VerifyingKey, ShaDigest>::Absent {
            state: Box::new(state),
            change: change_absence(&fixture, &fixture.dormant.public_key()),
        }
        .encode()
        .to_vec();
        account_lookup[optional_change_offset] = 3;
        assert!(matches!(
            TestLookup::decode(account_lookup.as_slice()),
            Err(CodecError::InvalidBool)
        ));

        let empty_tips = Vec::<CreditTip>::new();
        let empty_credit_tree = tree(VectorKind::CreditTip, &empty_tips);
        let mut shard_lookup = CreditTipLookup::<ShaDigest>::Absent {
            predecessor: None,
            successor: None,
            opening: empty_credit_tree.range_opening(0, 0).unwrap(),
        }
        .encode()
        .to_vec();
        shard_lookup[u8::SIZE] = 4;
        assert!(matches!(
            CreditTipLookup::<ShaDigest>::decode(shard_lookup.as_slice()),
            Err(CodecError::InvalidBool)
        ));
        assert!(matches!(
            RangeLower::<VerifyingKey>::decode([9].as_slice()),
            Err(CodecError::InvalidEnum(9))
        ));
    }

    #[test]
    fn payment_witness_decode_roundtrip_and_signature_tampering() {
        let fixture = fixture();
        let witness = PaymentWitness::from_payment(&fixture.payment);
        let encoded = witness.encode();
        assert_eq!(
            PaymentWitness::<VerifyingKey>::decode(encoded.clone()).unwrap(),
            witness
        );
        assert_eq!(encoded.len(), witness.encode_size());

        let entries =
            witness.encode_size() - (VerifyingKey::SIZE * 2 + u64::SIZE * 4 + Signature::SIZE * 2);
        let payer_signature = VerifyingKey::SIZE + entries + u64::SIZE;
        let mut tampered = encoded.to_vec();
        tampered[payer_signature] ^= 1;
        let tampered = PaymentWitness::<VerifyingKey>::decode(tampered.as_slice()).unwrap();
        assert!(matches!(
            tampered.reconstruct::<Sha256, ShaDigest>(fixture.context.payment()),
            Err(PaymentError::InvalidPayerSignature)
        ));

        let operator_signature =
            payer_signature + Signature::SIZE + VerifyingKey::SIZE + u64::SIZE * 3;
        let mut tampered = encoded.to_vec();
        tampered[operator_signature] ^= 1;
        let tampered = PaymentWitness::<VerifyingKey>::decode(tampered.as_slice()).unwrap();
        assert!(matches!(
            tampered.reconstruct::<Sha256, ShaDigest>(fixture.context.payment()),
            Err(PaymentError::InvalidOperatorSignature)
        ));
    }

    #[test]
    fn every_challenge_strategy_matches_on_valid_and_independently_malformed_evidence() {
        let fixture = fixture();
        let rayon = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();
        let recipient = fixture.recipient.public_key();

        let valid = [
            Challenge::LatestAcknowledgedSend {
                payment: witness(&fixture.payment),
                payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
            },
            Challenge::HigherShardTip {
                payment: witness(&fixture.payment),
                recipient: Box::new(higher_shard_tip_lookup(&fixture, &recipient, 0)),
            },
            Challenge::InconsistentReceiptRange {
                upper: witness(&fixture.payment),
                lower: RangeLower::ShardStart,
            },
            Challenge::receipt_fork(&fixture.payment, &fixture.payment),
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
                payment: witness(&invalid_operator),
                payer: Box::new(lookup(&fixture, &recipient)),
            },
            Challenge::HigherShardTip {
                payment: witness(&invalid_operator),
                recipient: Box::new(higher_shard_tip_lookup(&fixture, &recipient, 0)),
            },
            Challenge::InconsistentReceiptRange {
                upper: witness(&invalid_operator),
                lower: RangeLower::from_payment(&invalid_payer),
            },
            Challenge::ReceiptFork {
                fork: Box::new(ReceiptForkWitness::SameIndex {
                    left: witness(&invalid_operator),
                    right: SameIndexPaymentWitness::from_payment(&invalid_payer),
                }),
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

        assert!(matches!(
            adjudicate_strategies(&fixture, 101, &malformed[0], &rayon),
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
            payment: witness(&later),
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
            payment: witness(&omitted),
            payer: Box::new(lookup(&fixture, &fixture.dormant.public_key())),
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::LatestAcknowledgedSend)
        );

        let represented = Challenge::LatestAcknowledgedSend {
            payment: witness(&fixture.payment),
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
            payment: witness(&conflict),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::LatestAcknowledgedSend)
        );
    }

    #[test]
    fn equal_debit_with_the_committed_send_and_another_receipt_is_clean() {
        let fixture = fixture();

        // The change leaf pins only the committed terminal send, so a second receipt for it
        // contradicts nothing here. That receipt fork is a receipt-fork challenge instead.
        let other_receipt = payment_with_endpoint(
            fixture.context.payment(),
            &fixture.operator,
            fixture.payment.send().clone(),
            7,
            10,
            1,
        );
        let challenge = Challenge::LatestAcknowledgedSend {
            payment: witness(&other_receipt),
            payer: Box::new(lookup(&fixture, &fixture.payer.public_key())),
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::NoContradiction
        );
        let fork = Challenge::receipt_fork(&fixture.payment, &other_receipt);
        assert_eq!(
            adjudicate(&fixture, &fork).unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );
    }

    #[test]
    fn batched_entries_share_a_transaction_without_forking() {
        let fixture = fixture();
        let first = fixture.recipient.public_key();
        let second = fixture.dormant.public_key();
        let send = SignedSend::sign_next_batch(
            fixture.context.payment(),
            &fixture.payer,
            vec![
                Entry::new(first.clone(), 3).unwrap(),
                Entry::new(second.clone(), 4).unwrap(),
            ],
            0,
        )
        .unwrap();
        let issue = |recipient: &VerifyingKey| {
            let receipt = SignedReceipt::issue_next::<Sha256, _>(
                fixture.context.payment(),
                &send,
                recipient,
                0,
                0,
                0,
                &fixture.operator,
            )
            .unwrap();
            Payment::new::<Sha256>(fixture.context.payment(), send.clone(), receipt).unwrap()
        };

        // Distinct entries of one batch share a transaction identifier legitimately.
        let siblings = Challenge::receipt_fork(&issue(&first), &issue(&second));
        assert!(matches!(
            &siblings,
            Challenge::ReceiptFork { fork }
                if matches!(fork.as_ref(), ReceiptForkWitness::Full { .. })
        ));
        assert_eq!(
            adjudicate(&fixture, &siblings).unwrap(),
            Verdict::NoContradiction
        );

        // Two distinct receipt bodies for one entry remain a proven fork.
        let head = send.body().entries()[0].clone();
        let doubled = Challenge::receipt_fork(
            &issue(head.recipient()),
            &payment_with_endpoint(
                fixture.context.payment(),
                &fixture.operator,
                send.clone(),
                5,
                head.amount(),
                1,
            ),
        );
        assert!(matches!(
            &doubled,
            Challenge::ReceiptFork { fork }
                if matches!(fork.as_ref(), ReceiptForkWitness::SameSend { .. })
        ));
        assert_eq!(
            adjudicate(&fixture, &doubled).unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
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
        let challenge = Challenge::HigherShardTip {
            payment: witness(&later),
            recipient: Box::new(higher_shard_tip_lookup(&fixture, &recipient, 0)),
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
                payment: witness(&retained),
                recipient: Box::new(higher_shard_tip_lookup(&fixture, &recipient, 0)),
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
            payment: witness(&absent_shard),
            recipient: Box::new(higher_shard_tip_lookup(&fixture, &recipient, 9)),
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
            upper: witness(&impossible),
            lower: RangeLower::from_payment(&fixture.payment),
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
            upper: witness(&impossible),
            lower: RangeLower::ShardStart,
        };
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::InconsistentReceiptRange)
        );

        let feasible = Challenge::InconsistentReceiptRange {
            upper: witness(&fixture.payment),
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
            upper: witness(&zero_endpoint),
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
        let challenge = Challenge::receipt_fork(&fixture.payment, &other);
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
        let challenge = Challenge::receipt_fork(&fixture.payment, &reused);
        assert_eq!(
            adjudicate(&fixture, &challenge).unwrap(),
            Verdict::Proven(ChallengeKind::ReceiptFork)
        );

        let duplicate = Challenge::receipt_fork(&fixture.payment, &fixture.payment);
        assert_eq!(
            adjudicate(&fixture, &duplicate).unwrap(),
            Verdict::NoContradiction
        );
    }

    #[test]
    fn challenges_are_deadline_inclusive_bounded_and_header_bound() {
        let fixture = fixture();
        let challenge = Challenge::LatestAcknowledgedSend {
            payment: witness(&fixture.payment),
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
        other_roots.successor.digest = Sha256::hash(&[b"other-successor"]);
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
    fn adjudication_rejects_another_same_liability_predecessor_root() {
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
        assert_ne!(other.predecessor_root(), fixture.context.predecessor_root());

        let roots = fixture.roots;
        let header = Header::new::<Sha256, _>(&other, &roots);
        let challenge = Challenge::LatestAcknowledgedSend {
            payment: witness(&fixture.payment),
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
            "a header from another bound predecessor root was accepted: {result:?}"
        );
    }

    #[test]
    fn lookup_rejects_nonadjacent_absence_brackets() {
        let fixture = fixture();
        let mut lookup = lookup(&fixture, &fixture.dormant.public_key());
        let AccountLookup::Absent { change, .. } = &mut lookup else {
            panic!("dormant account must be absent from the change vector");
        };
        let ChangeAbsence {
            predecessor,
            successor,
            ..
        } = change;
        if predecessor.is_some() {
            *predecessor = None;
        } else {
            *successor = None;
        }
        assert!(matches!(
            lookup.resolve::<Sha256>(
                fixture.context.predecessor_root(),
                &fixture.roots.change,
                &fixture.dormant.public_key(),
            ),
            Err(ChallengeError::LookupOrder)
        ));
    }

    #[test]
    fn state_lookup_proves_ordered_nonmembership() {
        let fixture = fixture();
        let payer = fixture.payer.public_key();
        let present = state_lookup(&fixture, &payer);
        assert_eq!(
            present
                .resolve::<Sha256>(fixture.context.predecessor_root(), &payer)
                .unwrap(),
            Some(state(100))
        );
        assert!(
            present
                .resolve::<Sha256>(
                    fixture.context.predecessor_root(),
                    &fixture.recipient.public_key(),
                )
                .is_err()
        );

        let account = (1_000..)
            .map(|seed| SigningKey::from_seed(seed).public_key())
            .find(|account| {
                fixture
                    .leaves
                    .binary_search_by(|leaf| leaf.account.cmp(account))
                    .is_err()
            })
            .unwrap();
        let mut lookup = state_lookup(&fixture, &account);

        assert_eq!(
            lookup
                .resolve::<Sha256>(fixture.context.predecessor_root(), &account)
                .unwrap(),
            None
        );

        let StateLookup::Absent(absence) = &mut lookup else {
            panic!("the generated account is absent from the state tree");
        };
        if absence.predecessor.is_some() {
            absence.predecessor = None;
        } else {
            absence.successor = None;
        }
        assert!(matches!(
            lookup.resolve::<Sha256>(fixture.context.predecessor_root(), &account),
            Err(ChallengeError::LookupOrder)
        ));
    }
}
