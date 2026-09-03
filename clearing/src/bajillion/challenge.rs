//! One-shot contradictions against a certified close.
//!
//! Every counted value is a terminal opening under a payer-signed vector root, so challenges
//! collapse to three kinds: a retained acknowledgment above the public terminal debit, a
//! retained entry above the public terminal entry for its edge, and an operator acknowledgment
//! fork at one payer sequence number. There is no interior receipt range to reason about.

use crate::bajillion::{
    commitment::{self, RangeOpening, VectorKind, VectorRoot},
    payment::{
        AckError, VECTOR_ACK_SIGNATURE_NAMESPACE, VECTOR_SEND_SIGNATURE_NAMESPACE, VectorAck,
        VectorSendBody,
    },
    state::{AccountChange, AccountState, ChangeGuard, ChangeValue, ChangeValueCore, StateLeaf},
    transition::{
        ChallengeIndex, ChangeParts, CloseContext, Header, RootBundle, StateCache, TransitionError,
    },
    vector::{OutTipLookup, OutVector},
};
use alloc::{boxed::Box, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    DecodeExt, Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
use commonware_cryptography::{Digest, Hasher, PublicKey};
use thiserror::Error;

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
        self.opening
            .bracket(self.predecessor.is_some(), 0, self.successor.is_some())
            .ok_or(ChallengeError::LookupOrder)?;
        if self
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

/// Context-relative dual-signed acknowledgment evidence.
///
/// The anchor, epoch, and operator key are reconstructed from the trusted close context, so the
/// witness carries only the payer-variable fields and both signatures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckWitness<P: PublicKey, D: Digest> {
    /// Payer named by the acknowledged endpooint.
    pub payer: P,
    /// Epoch-local batch sequence number.
    pub seq: u64,
    /// Acknowledged lifetime cumulative debit endpoint.
    pub cumulative_debit: u64,
    /// Acknowledged per-recipient vector root.
    pub send_root: VectorRoot<D>,
    /// Payer signature over the reconstructed body.
    pub payer_signature: P::Signature,
    /// Operator countersignature over the reconstructed body.
    pub operator_signature: P::Signature,
}

impl<P: PublicKey, D: Digest> AckWitness<P, D> {
    /// Projects one full acknowledgment into its context-relative representation.
    #[must_use]
    pub fn from_ack(ack: &VectorAck<P, D>) -> Self {
        Self {
            payer: ack.body().payer().clone(),
            seq: ack.body().seq(),
            cumulative_debit: ack.body().cumulative_debit(),
            send_root: ack.body().send_root(),
            payer_signature: ack.payer_signature().clone(),
            operator_signature: ack.operator_signature().clone(),
        }
    }

    /// Reconstructs the canonical body and verifies both signatures.
    pub fn reconstruct(
        &self,
        context: &CloseContext<P, D>,
    ) -> Result<VectorSendBody<P, D>, ChallengeError> {
        let body = VectorSendBody::new(
            context.payment(),
            self.payer.clone(),
            self.seq,
            self.cumulative_debit,
            self.send_root,
        );
        let encoded = body.encode();
        if !self.payer.verify(
            VECTOR_SEND_SIGNATURE_NAMESPACE,
            &encoded,
            &self.payer_signature,
        ) {
            return Err(ChallengeError::Ack(AckError::InvalidPayerSignature));
        }
        if !context.payment().operator().verify(
            VECTOR_ACK_SIGNATURE_NAMESPACE,
            &encoded,
            &self.operator_signature,
        ) {
            return Err(ChallengeError::Ack(AckError::InvalidOperatorSignature));
        }
        Ok(body)
    }

    /// Reconstructs and verifies only the operator countersignature.
    ///
    /// An acknowledgment fork is the operator's fault regardless of whose key produced the
    /// payer half, so fork adjudication does not require valid payer signatures.
    pub fn reconstruct_operator(
        &self,
        context: &CloseContext<P, D>,
    ) -> Result<VectorSendBody<P, D>, ChallengeError> {
        let body = VectorSendBody::new(
            context.payment(),
            self.payer.clone(),
            self.seq,
            self.cumulative_debit,
            self.send_root,
        );
        let encoded = body.encode();
        if !context.payment().operator().verify(
            VECTOR_ACK_SIGNATURE_NAMESPACE,
            &encoded,
            &self.operator_signature,
        ) {
            return Err(ChallengeError::Ack(AckError::InvalidOperatorSignature));
        }
        Ok(body)
    }
}

impl<P: PublicKey, D: Digest> Write for AckWitness<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.payer.write(buf);
        self.seq.write(buf);
        self.cumulative_debit.write(buf);
        self.send_root.write(buf);
        self.payer_signature.write(buf);
        self.operator_signature.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for AckWitness<P, D> {
    const SIZE: usize = P::SIZE + u64::SIZE * 2 + VectorRoot::<D>::SIZE + P::Signature::SIZE * 2;
}

impl<P: PublicKey, D: Digest> Read for AckWitness<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            payer: P::read(buf)?,
            seq: u64::read(buf)?,
            cumulative_debit: u64::read(buf)?,
            send_root: VectorRoot::read(buf)?,
            payer_signature: P::Signature::read(buf)?,
            operator_signature: P::Signature::read(buf)?,
        })
    }
}

/// Retained per-edge evidence: an acknowledgment plus its entry opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryWitness<P: PublicKey, D: Digest> {
    /// Dual-signed acknowledgment.
    pub ack: AckWitness<P, D>,
    /// Credited recipient.
    pub recipient: P,
    /// Retained epoch-cumulative credit on the edge.
    pub cumulative: u64,
    /// Retained payment count on the edge.
    pub count: u64,
    /// Membership opening under the acknowledged vector root.
    pub opening: commitment::Opening<D>,
}

impl<P: PublicKey, D: Digest> Write for EntryWitness<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.ack.write(buf);
        self.recipient.write(buf);
        self.cumulative.write(buf);
        self.count.write(buf);
        self.opening.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for EntryWitness<P, D> {
    fn encode_size(&self) -> usize {
        AckWitness::<P, D>::SIZE + P::SIZE + u64::SIZE * 2 + self.opening.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for EntryWitness<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            ack: AckWitness::read(buf)?,
            recipient: P::read(buf)?,
            cumulative: u64::read(buf)?,
            count: u64::read(buf)?,
            opening: commitment::Opening::read(buf)?,
        })
    }
}

/// One account-relative change value and the membership opening for its compact guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeOpening<D: Digest> {
    /// Account-relative compact changed-account value.
    pub value: ChangeValue<D>,
    /// Position and BMT authentication path.
    pub proof: commitment::Opening<D>,
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

/// Adjacent compact leaves and one shared proof authenticating change-vector absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeAbsence<P: PublicKey, D: Digest> {
    /// Immediate predecessor, or `None` at the beginning of the vector.
    pub predecessor: Option<ChangeGuard<P, D>>,
    /// Immediate successor, or `None` at the end of the vector.
    pub successor: Option<ChangeGuard<P, D>>,
    /// One contiguous proof for the disclosed adjacent leaves.
    pub opening: RangeOpening<D>,
}

impl<P: PublicKey, D: Digest> ChangeAbsence<P, D> {
    fn resolve<H: Hasher<Digest = D>>(
        &self,
        root: &VectorRoot<D>,
        account: &P,
    ) -> Result<(), ChallengeError> {
        self.opening
            .bracket(self.predecessor.is_some(), 0, self.successor.is_some())
            .ok_or(ChallengeError::LookupOrder)?;
        if self
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
            opening: RangeOpening::read_bounded(buf, 2, usize::MAX)?,
        })
    }
}

/// Compact debit resolution, retaining predecessor state only for an unchanged account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountLookup<P: PublicKey, D: Digest> {
    /// The account changed and exposes its compact terminal projection.
    Present(Box<ChangeOpening<D>>),
    /// The account is unchanged and its predecessor debit remains authoritative.
    Absent {
        /// Predecessor-state membership or ordered-nonmembership proof.
        state: Box<StateLookup<P, D>>,
        /// Ordered proof that the account is absent from the change vector.
        change: ChangeAbsence<P, D>,
    },
}

impl<P: PublicKey, D: Digest> AccountLookup<P, D> {
    /// Verifies changed membership or unchanged predecessor-state resolution for `account`.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        predecessor_root: &VectorRoot<D>,
        change_root: &VectorRoot<D>,
        account: &P,
    ) -> Result<(u64, Option<AccountChange<P, D>>), ChallengeError> {
        match self {
            Self::Present(opening) => {
                let guard = ChangeGuard::from_value::<H>(account.clone(), &opening.value);
                opening.proof.verify::<H>(
                    VectorKind::Change,
                    change_root,
                    guard.encode().as_ref(),
                )?;
                let leaf = AccountChange::from_value(account.clone(), opening.value);
                Ok((leaf.terminal_debit(), Some(leaf)))
            }
            Self::Absent { state, change } => {
                change.resolve::<H>(change_root, account)?;
                let state = state
                    .resolve::<H>(predecessor_root, account)
                    .map_err(|_| ChallengeError::LookupOrder)?
                    .unwrap_or_else(AccountState::default);
                Ok((state.cumulative_debit, None))
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

/// Composed sender-row and vector-entry proof for a higher-entry challenge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HigherEntryLookup<P: PublicKey, D: Digest> {
    /// The sender changed, so its child proof reconstructs the committed vector root.
    Present {
        /// Change value fields preceding the reconstructed vector root.
        value: ChangeValueCore<D>,
        /// Membership opening under the change root.
        proof: commitment::Opening<D>,
        /// Membership or ordered absence under the reconstructed vector root.
        entry: OutTipLookup<P, D>,
    },
    /// The sender is absent from the change vector and therefore has no public entry.
    Absent(ChangeAbsence<P, D>),
}

impl<P: PublicKey, D: Digest> HigherEntryLookup<P, D> {
    /// Verifies the composed lookup and returns the public terminal entry value.
    pub fn resolve<H: Hasher<Digest = D>>(
        &self,
        change_root: &VectorRoot<D>,
        payer: &P,
        recipient: &P,
    ) -> Result<(u64, u64), ChallengeError> {
        match self {
            Self::Present {
                value,
                proof,
                entry,
            } => {
                let (send_root, cumulative, count) = entry.reconstruct::<H>(recipient)?;
                let value = ChangeValue::from_core(*value, send_root);
                let guard = ChangeGuard::from_value::<H>(payer.clone(), &value);
                proof.verify::<H>(VectorKind::Change, change_root, guard.encode().as_ref())?;
                Ok((cumulative, count))
            }
            Self::Absent(absence) => {
                absence.resolve::<H>(change_root, payer)?;
                Ok((0, 0))
            }
        }
    }
}

impl<P: PublicKey, D: Digest> Write for HigherEntryLookup<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Present {
                value,
                proof,
                entry,
            } => {
                1_u8.write(buf);
                value.write(buf);
                proof.write(buf);
                entry.write(buf);
            }
            Self::Absent(absence) => {
                2_u8.write(buf);
                absence.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for HigherEntryLookup<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::Present {
                    value,
                    proof,
                    entry,
                } => value.encode_size() + proof.encode_size() + entry.encode_size(),
                Self::Absent(absence) => absence.encode_size(),
            }
    }
}

impl<P: PublicKey, D: Digest> Read for HigherEntryLookup<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::Present {
                value: ChangeValueCore::read(buf)?,
                proof: commitment::Opening::read(buf)?,
                entry: OutTipLookup::read(buf)?,
            }),
            2 => Ok(Self::Absent(ChangeAbsence::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One bounded contradiction against a certified sender-vector close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Challenge<P: PublicKey, D: Digest> {
    /// A retained acknowledged endpoint above or inconsistent with the public terminal debit.
    HigherAckDebit {
        /// Retained dual-signed acknowledgment.
        ack: Box<AckWitness<P, D>>,
        /// Public terminal-debit resolution for the payer.
        payer: Box<AccountLookup<P, D>>,
    },
    /// A retained edge entry above the public terminal entry for the same edge.
    HigherAckEntry {
        /// Retained dual-signed acknowledgment and entry opening.
        entry: Box<EntryWitness<P, D>>,
        /// Public terminal-entry resolution under the sender row's committed root.
        sender: Box<HigherEntryLookup<P, D>>,
    },
    /// Two distinct operator-countersigned endpoints at one payer sequence number.
    AckFork {
        /// First countersigned endpoint.
        left: Box<AckWitness<P, D>>,
        /// Second countersigned endpoint.
        right: Box<AckWitness<P, D>>,
    },
}

impl<P: PublicKey, D: Digest> Write for Challenge<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::HigherAckDebit { ack, payer } => {
                1_u8.write(buf);
                ack.write(buf);
                payer.write(buf);
            }
            Self::HigherAckEntry { entry, sender } => {
                2_u8.write(buf);
                entry.write(buf);
                sender.write(buf);
            }
            Self::AckFork { left, right } => {
                3_u8.write(buf);
                left.write(buf);
                right.write(buf);
            }
        }
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for Challenge<P, D> {
    fn encode_size(&self) -> usize {
        u8::SIZE
            + match self {
                Self::HigherAckDebit { ack: _, payer } => {
                    AckWitness::<P, D>::SIZE + payer.encode_size()
                }
                Self::HigherAckEntry { entry, sender } => {
                    entry.encode_size() + sender.encode_size()
                }
                Self::AckFork { .. } => AckWitness::<P, D>::SIZE * 2,
            }
    }
}

impl<P: PublicKey, D: Digest> Read for Challenge<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            1 => Ok(Self::HigherAckDebit {
                ack: Box::new(AckWitness::read(buf)?),
                payer: Box::new(AccountLookup::read(buf)?),
            }),
            2 => Ok(Self::HigherAckEntry {
                entry: Box::new(EntryWitness::read(buf)?),
                sender: Box::new(HigherEntryLookup::read(buf)?),
            }),
            3 => Ok(Self::AckFork {
                left: Box::new(AckWitness::read(buf)?),
                right: Box::new(AckWitness::read(buf)?),
            }),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// The proven contradiction kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeKind {
    /// A retained acknowledged endpoint contradicts the public terminal debit.
    HigherAckDebit,
    /// A retained edge entry contradicts the public terminal entry.
    HigherAckEntry,
    /// The operator countersigned two endpoints at one payer sequence number.
    AckFork,
}

/// Adjudication outcome for one well-formed challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// The evidence proves the claimed contradiction.
    Proven(ChallengeKind),
    /// The evidence is authentic but does not contradict the close.
    NoContradiction,
}

/// Adjudicates one challenge against an already-certified header and root bundle.
pub fn adjudicate<H, P, D>(
    context: &CloseContext<P, D>,
    header: &Header<D>,
    roots: &RootBundle<D>,
    challenge: &Challenge<P, D>,
) -> Result<Verdict, ChallengeError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if !header.verify::<H, P>(context, roots) {
        return Err(ChallengeError::HeaderRoot);
    }
    match challenge {
        Challenge::HigherAckDebit { ack, payer } => {
            let body = ack.reconstruct(context)?;
            let (terminal_debit, leaf) =
                payer.resolve::<H>(context.predecessor_root(), &roots.change, &ack.payer)?;
            if ack.cumulative_debit > terminal_debit {
                return Ok(Verdict::Proven(ChallengeKind::HigherAckDebit));
            }
            if let Some(leaf) = leaf
                && leaf.has_outgoing::<H>()
                && !leaf.matches_outgoing::<H>(&body)
            {
                // A second countersigned body at the committed sequence is equivocation
                // against the certified terminal. The fork challenge cannot reach this case:
                // the posted corpus certifies the terminal through one aggregable
                // countersignature per slice, so no individual countersignature of the
                // committed body is extractable, and the certificate itself stands in for it.
                if ack.seq == leaf.terminal_seq() {
                    return Ok(Verdict::Proven(ChallengeKind::HigherAckDebit));
                }
                // An equal endpoint at a strictly later batch means the operator acknowledged
                // a successor the close does not carry. A retained earlier retry, or a
                // zero-advance acknowledgment against a credit-only row, is not the
                // operator's fault.
                if ack.cumulative_debit == terminal_debit && ack.seq > leaf.terminal_seq() {
                    return Ok(Verdict::Proven(ChallengeKind::HigherAckDebit));
                }
            }
            Ok(Verdict::NoContradiction)
        }
        Challenge::HigherAckEntry { entry, sender } => {
            entry.ack.reconstruct(context)?;
            if entry.cumulative == 0 || entry.count == 0 || entry.cumulative < entry.count {
                return Err(ChallengeError::Ack(AckError::InfeasibleEntry));
            }
            let retained_entry = crate::bajillion::vector::OutEntry {
                recipient: entry.recipient.clone(),
                cumulative: entry.cumulative,
                count: entry.count,
            };
            entry
                .opening
                .verify::<H>(
                    VectorKind::OutEntry,
                    &entry.ack.send_root,
                    retained_entry.encode().as_ref(),
                )
                .map_err(|_| ChallengeError::Ack(AckError::InvalidEntryOpening))?;
            let (public_cumulative, public_count) =
                sender.resolve::<H>(&roots.change, &entry.ack.payer, &entry.recipient)?;
            if entry.cumulative > public_cumulative || entry.count > public_count {
                return Ok(Verdict::Proven(ChallengeKind::HigherAckEntry));
            }
            Ok(Verdict::NoContradiction)
        }
        Challenge::AckFork { left, right } => {
            let left_body = left.reconstruct_operator(context)?;
            let right_body = right.reconstruct_operator(context)?;
            if left.payer == right.payer && left.seq == right.seq && left_body != right_body {
                return Ok(Verdict::Proven(ChallengeKind::AckFork));
            }
            Ok(Verdict::NoContradiction)
        }
    }
}

/// Builds the composed sender lookup for a higher-entry challenge.
pub fn higher_entry_lookup<H, P, D>(
    index: &ChallengeIndex<P, D>,
    payer: &P,
    out_vector: Option<&OutVector<P>>,
    recipient: &P,
) -> Result<HigherEntryLookup<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    match index.change_parts(payer)? {
        ChangeParts::Present { leaf, proof } => {
            let out_vector = out_vector.ok_or(TransitionError::VectorAlignment)?;
            if out_vector.payer() != payer {
                return Err(TransitionError::VectorAlignment);
            }
            let entry = out_vector.lookup::<H, D>(recipient)?;
            let (send_root, _, _) = entry
                .reconstruct::<H>(recipient)
                .map_err(TransitionError::Vector)?;
            if send_root != leaf.send_root() {
                return Err(TransitionError::VectorAlignment);
            }
            Ok(HigherEntryLookup::Present {
                value: leaf.value().core(),
                proof,
                entry,
            })
        }
        ChangeParts::Absent {
            predecessor,
            successor,
            opening,
        } => {
            if out_vector.is_some() {
                return Err(TransitionError::VectorAlignment);
            }
            Ok(HigherEntryLookup::Absent(ChangeAbsence {
                predecessor,
                successor,
                opening,
            }))
        }
    }
}

/// Builds the payer lookup for a higher-debit challenge.
pub fn account_lookup<H, P, D>(
    index: &ChallengeIndex<P, D>,
    cache: &StateCache<P, D>,
    account: &P,
) -> Result<AccountLookup<P, D>, TransitionError>
where
    H: Hasher<Digest = D>,
    P: PublicKey,
    D: Digest,
{
    if cache.root() != *index.predecessor_root() {
        return Err(TransitionError::PredecessorRoot);
    }
    match index.change_parts(account)? {
        ChangeParts::Present { leaf, proof } => {
            Ok(AccountLookup::Present(Box::new(ChangeOpening {
                value: leaf.value(),
                proof,
            })))
        }
        ChangeParts::Absent {
            predecessor,
            successor,
            opening,
        } => Ok(AccountLookup::Absent {
            state: Box::new(
                cache
                    .lookup(account)
                    .map_err(|_| TransitionError::PredecessorRoot)?,
            ),
            change: ChangeAbsence {
                predecessor,
                successor,
                opening,
            },
        }),
    }
}

/// Malformed, unauthenticated, mistimed, or noncanonical challenge evidence.
#[derive(Debug, Error)]
pub enum ChallengeError {
    /// The header does not commit the context and roots.
    #[error("header does not commit the context and roots")]
    HeaderRoot,
    /// The challenge deadline has passed.
    #[error("challenge deadline has passed")]
    Expired,
    /// The encoded challenge exceeds the configured byte bound.
    #[error("encoded challenge exceeds the byte bound")]
    TooLarge,
    /// The challenge bytes are not one canonical encoding.
    #[error("invalid challenge encoding: {0}")]
    Codec(#[from] CodecError),
    /// A lookup's ordered neighbors do not bracket the requested key.
    #[error("lookup neighbors do not bracket the requested key")]
    LookupOrder,
    /// An acknowledgment failed verification.
    #[error("invalid acknowledgment: {0}")]
    Ack(#[from] AckError),
    /// An edge vector proof failed verification.
    #[error("invalid edge vector: {0}")]
    Vector(#[from] crate::bajillion::vector::Error),
    /// The generic vector commitment is invalid.
    #[error("invalid vector commitment: {0}")]
    Commitment(#[from] commitment::Error),
}

#[cfg(feature = "arbitrary")]
mod arbitrary_impls {
    use super::*;

    impl<'a, P, D> arbitrary::Arbitrary<'a> for AckWitness<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                payer: u.arbitrary()?,
                seq: u.arbitrary()?,
                cumulative_debit: u.arbitrary()?,
                send_root: u.arbitrary()?,
                payer_signature: u.arbitrary()?,
                operator_signature: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for EntryWitness<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
        commitment::Opening<D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                ack: u.arbitrary()?,
                recipient: u.arbitrary()?,
                cumulative: u.arbitrary()?,
                count: u.arbitrary()?,
                opening: u.arbitrary()?,
            })
        }
    }

    impl<'a, D> arbitrary::Arbitrary<'a> for ChangeOpening<D>
    where
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
        ChangeValue<D>: arbitrary::Arbitrary<'a>,
        commitment::Opening<D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                value: u.arbitrary()?,
                proof: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for ChangeAbsence<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
        ChangeGuard<P, D>: arbitrary::Arbitrary<'a>,
        RangeOpening<D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self {
                predecessor: u.arbitrary()?,
                successor: u.arbitrary()?,
                opening: u.arbitrary()?,
            })
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for AccountLookup<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
        ChangeOpening<D>: arbitrary::Arbitrary<'a>,
        StateLookup<P, D>: arbitrary::Arbitrary<'a>,
        ChangeAbsence<P, D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
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

    impl<'a, P, D> arbitrary::Arbitrary<'a> for HigherEntryLookup<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
        ChangeValueCore<D>: arbitrary::Arbitrary<'a>,
        commitment::Opening<D>: arbitrary::Arbitrary<'a>,
        OutTipLookup<P, D>: arbitrary::Arbitrary<'a>,
        ChangeAbsence<P, D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            if u.arbitrary()? {
                Ok(Self::Present {
                    value: u.arbitrary()?,
                    proof: u.arbitrary()?,
                    entry: u.arbitrary()?,
                })
            } else {
                Ok(Self::Absent(u.arbitrary()?))
            }
        }
    }

    impl<'a, P, D> arbitrary::Arbitrary<'a> for Challenge<P, D>
    where
        P: PublicKey + arbitrary::Arbitrary<'a>,
        P::Signature: arbitrary::Arbitrary<'a>,
        D: Digest + for<'b> arbitrary::Arbitrary<'b>,
        AckWitness<P, D>: arbitrary::Arbitrary<'a>,
        AccountLookup<P, D>: arbitrary::Arbitrary<'a>,
        EntryWitness<P, D>: arbitrary::Arbitrary<'a>,
        HigherEntryLookup<P, D>: arbitrary::Arbitrary<'a>,
    {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(match u.int_in_range(0..=2)? {
                0 => Self::HigherAckDebit {
                    ack: Box::new(u.arbitrary()?),
                    payer: Box::new(u.arbitrary()?),
                },
                1 => Self::HigherAckEntry {
                    entry: Box::new(u.arbitrary()?),
                    sender: Box::new(u.arbitrary()?),
                },
                _ => Self::AckFork {
                    left: Box::new(u.arbitrary()?),
                    right: Box::new(u.arbitrary()?),
                },
            })
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
