//! Epoch activity and its compact challenge and settlement commitments.

use crate::bajillion::{
    commitment::VectorRoot,
    payment::{PaymentContext, SendAuthorization, VectorSendBody},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};

const CHANGE_VALUE_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_CHANGE_VALUE";

/// Settlement-visible output authenticated while validating one account's activity.
///
/// `Withdrawal(0)` is distinct from `None` so a compact close claim can authenticate the action
/// even when no value is released.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SettlementOutput {
    /// The activity creates no independently claimable settlement output.
    #[default]
    None,
    /// A signed withdrawal releases this amount to its requested destination.
    Withdrawal(u64),
    /// Credit to an unregistered recipient releases this amount to that recipient.
    ExternalPayout(u64),
}

impl Write for SettlementOutput {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::None => 0_u8.write(buf),
            Self::Withdrawal(amount) => {
                1_u8.write(buf);
                amount.write(buf);
            }
            Self::ExternalPayout(amount) => {
                2_u8.write(buf);
                amount.write(buf);
            }
        }
    }
}

impl EncodeSize for SettlementOutput {
    fn encode_size(&self) -> usize {
        match self {
            Self::None => u8::SIZE,
            Self::Withdrawal(_) | Self::ExternalPayout(_) => u8::SIZE + u64::SIZE,
        }
    }
}

impl Read for SettlementOutput {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::None),
            1 => Ok(Self::Withdrawal(u64::read(buf)?)),
            2 => Ok(Self::ExternalPayout(u64::read(buf)?)),
            tag => Err(CodecError::InvalidEnum(tag)),
        }
    }
}

/// One account participating in the epoch, including unchanged balances.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRow<P: PublicKey, D: Digest> {
    /// Canonical account key.
    pub account: P,
    /// Balance at the predecessor root, zero when absent.
    pub predecessor: u64,
    /// Derived successor balance, zero when absent.
    pub successor: u64,
    /// Terminal authorization for this epoch's outgoing vector.
    pub outgoing: Option<SendAuthorization<P, D>>,
    /// Derived settlement output.
    pub output: SettlementOutput,
}

/// Settlement and challenge projection derived from one fully validated activity row.
///
/// Composing the committed [`ChangeValue`] keeps this projection and the guarded compact value
/// structurally identical, so no field can exist here without being committed by the guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountChange<P: PublicKey, D: Digest> {
    account: P,
    value: ChangeValue<D>,
}

/// Account-relative value for a compact change membership opening.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangeValue<D: Digest> {
    core: ChangeValueCore,
    send_root: VectorRoot<D>,
}

/// Change value fields that precede the per-account outgoing-vector root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangeValueCore {
    output: SettlementOutput,
    terminal_debit: u64,
    terminal_seq: u64,
}

/// Ordered changed-account key and digest of its compact value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeGuard<P: PublicKey, D: Digest> {
    account: P,
    value_digest: D,
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for AccountChange<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            account: u.arbitrary()?,
            value: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for ChangeValue<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            core: u.arbitrary()?,
            send_root: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for ChangeValueCore {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            output: u.arbitrary()?,
            terminal_debit: u.arbitrary()?,
            terminal_seq: u.arbitrary()?,
        })
    }
}

impl<P: PublicKey, D: Digest> AccountChange<P, D> {
    /// Derives the compact leaf from a fully validated row and its outgoing-vector root.
    ///
    /// The row and root must describe the same account and epoch.
    pub fn from_row(row: &AccountRow<P, D>, send_root: VectorRoot<D>) -> Self {
        Self {
            account: row.account.clone(),
            value: ChangeValue {
                core: ChangeValueCore {
                    output: row.output,
                    terminal_debit: row
                        .outgoing
                        .as_ref()
                        .map_or(0, |send| send.body().cumulative_debit()),
                    terminal_seq: row.outgoing.as_ref().map_or(0, |send| send.body().seq()),
                },
                send_root,
            },
        }
    }

    /// Returns the participating account.
    pub const fn account(&self) -> &P {
        &self.account
    }

    /// Returns the committed settlement output.
    pub const fn output(&self) -> SettlementOutput {
        self.value.core.output
    }

    /// Returns this leaf's compact change value, paired elsewhere with a membership lookup target.
    #[must_use]
    pub const fn value(&self) -> ChangeValue<D> {
        self.value
    }

    /// Restores the projection from an already committed compact value.
    #[cfg(feature = "std")]
    pub(crate) const fn from_value(account: P, value: ChangeValue<D>) -> Self {
        Self { account, value }
    }

    /// Returns the public terminal epoch debit.
    pub const fn terminal_debit(&self) -> u64 {
        self.value.core.terminal_debit
    }

    /// Returns the committed terminal batch sequence number, zero when no debit advanced.
    pub const fn terminal_seq(&self) -> u64 {
        self.value.core.terminal_seq
    }

    /// Returns whether this validated activity has a terminal outgoing authorization.
    ///
    /// Every nonempty outgoing vector has positive debit; sequence zero is valid.
    pub const fn has_outgoing(&self) -> bool {
        self.terminal_debit() != 0
    }

    /// Returns the compact per-account outgoing-vector root.
    pub const fn send_root(&self) -> VectorRoot<D> {
        self.value.send_root
    }

    /// Projects the exact leaf committed by the change vector.
    pub fn guard<H: Hasher<Digest = D>>(&self) -> ChangeGuard<P, D> {
        ChangeGuard::from_value::<H>(self.account.clone(), &self.value)
    }

    /// Returns whether `body` is the terminal authorization in `context`.
    ///
    /// The caller must authenticate this activity and `context` under the same certified close.
    pub fn matches_outgoing(
        &self,
        context: &PaymentContext<P, D>,
        body: &VectorSendBody<P, D>,
    ) -> bool {
        self.has_outgoing()
            && VectorSendBody::new(
                context,
                self.account.clone(),
                self.terminal_seq(),
                self.terminal_debit(),
                self.send_root(),
            ) == *body
    }
}

impl<D: Digest> ChangeValue<D> {
    /// Returns the fields that precede the outgoing-vector root, which a child proof reconstructs.
    #[must_use]
    pub const fn core(&self) -> ChangeValueCore {
        self.core
    }

    /// Restores the exact compact value from its prefix fields and typed vector root.
    #[must_use]
    pub const fn from_core(core: ChangeValueCore, send_root: VectorRoot<D>) -> Self {
        Self { core, send_root }
    }

    /// Returns the committed outgoing-vector root.
    pub const fn send_root(&self) -> VectorRoot<D> {
        self.send_root
    }
}

impl<P: PublicKey, D: Digest> ChangeGuard<P, D> {
    pub(crate) fn from_value<H: Hasher<Digest = D>>(account: P, value: &ChangeValue<D>) -> Self {
        let encoded = value.encode();
        Self {
            account,
            value_digest: H::hash(&[CHANGE_VALUE_HASH_NAMESPACE, encoded.as_ref()]),
        }
    }

    /// Returns the ordered participating account.
    pub const fn account(&self) -> &P {
        &self.account
    }
}

impl<D: Digest> Write for ChangeValue<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.core.write(buf);
        self.send_root.write(buf);
    }
}

impl<D: Digest> EncodeSize for ChangeValue<D> {
    fn encode_size(&self) -> usize {
        self.core.encode_size() + VectorRoot::<D>::SIZE
    }
}

impl<D: Digest> Read for ChangeValue<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            core: ChangeValueCore::read(buf)?,
            send_root: VectorRoot::read(buf)?,
        })
    }
}

impl Write for ChangeValueCore {
    fn write(&self, buf: &mut impl BufMut) {
        self.output.write(buf);
        self.terminal_debit.write(buf);
        self.terminal_seq.write(buf);
    }
}

impl EncodeSize for ChangeValueCore {
    fn encode_size(&self) -> usize {
        self.output.encode_size() + u64::SIZE * 2
    }
}

impl Read for ChangeValueCore {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            output: SettlementOutput::read(buf)?,
            terminal_debit: u64::read(buf)?,
            terminal_seq: u64::read(buf)?,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for AccountChange<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.value.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for AccountChange<P, D> {
    fn encode_size(&self) -> usize {
        P::SIZE + self.value.encode_size()
    }
}

impl<P: PublicKey, D: Digest> Read for AccountChange<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            value: ChangeValue::read(buf)?,
        })
    }
}

impl<P: PublicKey, D: Digest> Write for ChangeGuard<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.value_digest.write(buf);
    }
}

impl<P: PublicKey, D: Digest> FixedSize for ChangeGuard<P, D> {
    const SIZE: usize = P::SIZE + D::SIZE;
}

impl<P: PublicKey, D: Digest> Read for ChangeGuard<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            value_digest: D::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for ChangeGuard<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            account: u.arbitrary()?,
            value_digest: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::DecodeExt;
    use commonware_cryptography::{Sha256, Signer as _, sha256::Digest as ShaDigest};
    use commonware_cryptography_curve25519::signing::{
        SigningKey, StrictVerifyingKey as VerifyingKey,
    };

    #[test]
    fn settlement_output_codec_preserves_zero_withdrawal() {
        for output in [
            SettlementOutput::None,
            SettlementOutput::Withdrawal(0),
            SettlementOutput::Withdrawal(9),
            SettlementOutput::ExternalPayout(7),
        ] {
            assert_eq!(SettlementOutput::decode(output.encode()).unwrap(), output);
        }
    }

    #[test]
    fn outgoing_projection_matches_the_complete_body_and_preserves_sequence_zero() {
        use crate::bajillion::{
            payment::PaymentContext,
            vector::{OutEntry, OutVector},
        };

        let private = SigningKey::from_seed(1);
        let account = private.public_key();
        let recipient = SigningKey::from_seed(2).public_key();
        let context = PaymentContext::new(ShaDigest::EMPTY, 7, account.clone());
        let vector = OutVector::new(
            7,
            account.clone(),
            vec![OutEntry {
                recipient: recipient.clone(),
                cumulative: 3,
                count: 1,
            }],
        )
        .unwrap();
        let root = vector.root::<Sha256, ShaDigest>().unwrap();
        let body = VectorSendBody::new(&context, account.clone(), 0, 3, root);
        let mut row = AccountRow {
            account: account.clone(),
            predecessor: 10,
            successor: 10,
            outgoing: Some(SendAuthorization::sign(body.clone(), &private)),
            output: SettlementOutput::None,
        };
        let leaf = AccountChange::from_row(&row, root);
        assert!(leaf.has_outgoing());
        assert_eq!(leaf.terminal_seq(), 0);
        assert!(leaf.matches_outgoing(&context, &body));
        let wrong_anchor =
            PaymentContext::new(Sha256::hash(&[b"other anchor"]), 7, account.clone());
        let wrong_epoch = PaymentContext::new(ShaDigest::EMPTY, 8, account.clone());
        for other in [
            VectorSendBody::new(&wrong_anchor, account.clone(), 0, 3, root),
            VectorSendBody::new(&wrong_epoch, account.clone(), 0, 3, root),
            VectorSendBody::new(&context, recipient, 0, 3, root),
            VectorSendBody::new(&context, account.clone(), 1, 3, root),
            VectorSendBody::new(&context, account.clone(), 0, 4, root),
            VectorSendBody::new(
                &context,
                account.clone(),
                0,
                3,
                OutVector::empty(7, account.clone())
                    .root::<Sha256, ShaDigest>()
                    .unwrap(),
            ),
        ] {
            assert!(!leaf.matches_outgoing(&context, &other));
        }
        assert!(!leaf.matches_outgoing(&wrong_anchor, &body));
        assert!(!leaf.matches_outgoing(&wrong_epoch, &body));
        row.outgoing = None;
        let empty = OutVector::empty(7, account.clone())
            .root::<Sha256, ShaDigest>()
            .unwrap();
        let leaf = AccountChange::from_row(&row, empty);
        assert!(!leaf.has_outgoing());
        assert!(!leaf.matches_outgoing(
            &context,
            &VectorSendBody::new(&context, account, 0, 0, empty)
        ));
    }

    #[test]
    fn change_leaf_binds_challenge_and_settlement_projection() {
        let account = SigningKey::from_seed(1).public_key();
        let send_root = crate::bajillion::commitment::empty_root::<Sha256>(
            crate::bajillion::commitment::VectorKind::OutEntry,
        );
        let row = AccountRow::<VerifyingKey, ShaDigest> {
            account: account.clone(),
            predecessor: 10,
            successor: 4,
            outgoing: None,
            output: SettlementOutput::Withdrawal(6),
        };
        let leaf = AccountChange::from_row(&row, send_root);
        assert_eq!(leaf.account(), &account);
        assert_eq!(leaf.output(), SettlementOutput::Withdrawal(6));
        assert_eq!(leaf.send_root(), send_root);
        assert_eq!(leaf.terminal_seq(), 0);
        assert!(!leaf.has_outgoing());

        let mut changed_output = row.clone();
        changed_output.output = SettlementOutput::ExternalPayout(6);
        assert_ne!(AccountChange::from_row(&changed_output, send_root), leaf);

        let mut changed_row = row;
        changed_row.successor = 5;
        assert_eq!(AccountChange::from_row(&changed_row, send_root), leaf);

        let context =
            crate::bajillion::payment::PaymentContext::new(ShaDigest::EMPTY, 0, account.clone());
        let payer = SigningKey::from_seed(1);
        let body = VectorSendBody::new(&context, account, 1, 1, send_root);
        changed_row.predecessor = 5;
        changed_row.outgoing = Some(SendAuthorization::sign(body, &payer));
        let activity = AccountChange::from_row(&changed_row, send_root);
        assert_eq!(activity.terminal_debit(), 1);
        assert_eq!(activity.terminal_seq(), 1);
        assert_ne!(activity.guard::<Sha256>(), leaf.guard::<Sha256>());
    }
}
