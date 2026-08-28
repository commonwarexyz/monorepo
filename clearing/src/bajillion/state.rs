//! Account state and canonical changed-account rows.

use crate::bajillion::{
    commitment::VectorRoot,
    credit::{self, ShardSet},
    payment::{Payment, SendBody},
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, PublicKey};

const CHANGE_OUTGOING_NONE_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_CHANGE_OUTGOING_NONE";
const CHANGE_VALUE_HASH_NAMESPACE: &[u8] = b"_COMMONWARE_CLEARING_CHANGE_VALUE";

/// Persistent state for one account row side.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AccountState {
    /// Funds currently available to the account.
    pub balance: u64,
    /// Total value the account has sent through the operator.
    pub cumulative_debit: u64,
    /// Total value the operator has promised to the account.
    pub cumulative_credit: u64,
    /// Total number of receipts contributing to `cumulative_credit`.
    pub receipt_count: u64,
    /// Whether this row side is present in the corresponding live-state vector.
    pub active: bool,
}

impl Write for AccountState {
    fn write(&self, buf: &mut impl BufMut) {
        self.balance.write(buf);
        self.cumulative_debit.write(buf);
        self.cumulative_credit.write(buf);
        self.receipt_count.write(buf);
        self.active.write(buf);
    }
}

impl FixedSize for AccountState {
    const SIZE: usize = u64::SIZE * 4 + bool::SIZE;
}

impl Read for AccountState {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            balance: u64::read(buf)?,
            cumulative_debit: u64::read(buf)?,
            cumulative_credit: u64::read(buf)?,
            receipt_count: u64::read(buf)?,
            active: bool::read(buf)?,
        })
    }
}

/// One active, positive-balance leaf in a live account-state vector.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateLeaf<P: PublicKey> {
    /// Live account occupying this vector position.
    pub account: P,
    /// Account state at this root.
    pub state: AccountState,
}

impl<P: PublicKey> Write for StateLeaf<P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.state.write(buf);
    }
}

impl<P: PublicKey> FixedSize for StateLeaf<P> {
    const SIZE: usize = P::SIZE + AccountState::SIZE;
}

impl<P: PublicKey> Read for StateLeaf<P> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            state: AccountState::read(buf)?,
        })
    }
}

/// Running totals carried by each changed-account row.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Prefix {
    /// Gross payment debit through this row.
    pub debit: u64,
    /// Gross payment credit through this row.
    pub credit: u64,
    /// Receipt value paid externally instead of entering live state.
    pub payout: u64,
    /// Deposits through this row.
    pub deposit: u64,
    /// Withdrawals through this row.
    pub withdrawal: u64,
    /// Withdrawal records through this row.
    pub withdrawal_count: u64,
    /// Terminal receive shards through this row.
    pub shard_count: u64,
}

impl Prefix {
    /// Returns the exact successor prefix, or `None` if a field overflows.
    pub fn checked_extend(self, delta: Self) -> Option<Self> {
        Some(Self {
            debit: self.debit.checked_add(delta.debit)?,
            credit: self.credit.checked_add(delta.credit)?,
            payout: self.payout.checked_add(delta.payout)?,
            deposit: self.deposit.checked_add(delta.deposit)?,
            withdrawal: self.withdrawal.checked_add(delta.withdrawal)?,
            withdrawal_count: self.withdrawal_count.checked_add(delta.withdrawal_count)?,
            shard_count: self.shard_count.checked_add(delta.shard_count)?,
        })
    }
}

impl Write for Prefix {
    fn write(&self, buf: &mut impl BufMut) {
        self.debit.write(buf);
        self.credit.write(buf);
        self.payout.write(buf);
        self.deposit.write(buf);
        self.withdrawal.write(buf);
        self.withdrawal_count.write(buf);
        self.shard_count.write(buf);
    }
}

impl FixedSize for Prefix {
    const SIZE: usize = u64::SIZE * 7;
}

impl Read for Prefix {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            debit: u64::read(buf)?,
            credit: u64::read(buf)?,
            payout: u64::read(buf)?,
            deposit: u64::read(buf)?,
            withdrawal: u64::read(buf)?,
            withdrawal_count: u64::read(buf)?,
            shard_count: u64::read(buf)?,
        })
    }
}

/// Settlement-visible output authenticated while validating one changed row.
///
/// `Withdrawal(0)` is distinct from `None` so a compact close claim can authenticate the action
/// even when no value is released.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SettlementOutput {
    /// The row creates no independently claimable settlement output.
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

/// One and only one row for an account whose authenticated state changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRow<P: PublicKey, D: Digest> {
    /// Changed account.
    pub account: P,
    /// State committed by the predecessor-state root.
    pub predecessor: AccountState,
    /// State committed by the successor-state root.
    pub successor: AccountState,
    /// Terminal accepted outgoing payment, present exactly when debit advanced.
    pub outgoing: Option<Payment<P, D>>,
    /// Claim classification validators recompute from the authenticated local effect.
    pub output: SettlementOutput,
    /// Running totals through this row.
    pub prefix: Prefix,
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for AccountRow<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    Payment<P, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            account: u.arbitrary()?,
            predecessor: u.arbitrary()?,
            successor: u.arbitrary()?,
            outgoing: u.arbitrary()?,
            output: u.arbitrary()?,
            prefix: u.arbitrary()?,
        })
    }
}

impl<P: PublicKey, D: Digest> AccountRow<P, D> {
    /// Returns the checked debit, credit, and receipt-count advances.
    pub fn checked_deltas(&self) -> Option<(u64, u64, u64)> {
        Some((
            self.successor
                .cumulative_debit
                .checked_sub(self.predecessor.cumulative_debit)?,
            self.successor
                .cumulative_credit
                .checked_sub(self.predecessor.cumulative_credit)?,
            self.successor
                .receipt_count
                .checked_sub(self.predecessor.receipt_count)?,
        ))
    }

    /// Whether this row actually changes authenticated state.
    #[must_use]
    pub fn is_changed(&self) -> bool {
        self.predecessor != self.successor
    }
}

impl<P: PublicKey, D: Digest> Write for AccountRow<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.predecessor.write(buf);
        self.successor.write(buf);
        self.outgoing.write(buf);
        self.output.write(buf);
        self.prefix.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for AccountRow<P, D> {
    fn encode_size(&self) -> usize {
        P::SIZE
            + AccountState::SIZE * 2
            + self.outgoing.encode_size()
            + self.output.encode_size()
            + Prefix::SIZE
    }
}

impl<P: PublicKey, D: Digest> Read for AccountRow<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            predecessor: AccountState::read(buf)?,
            successor: AccountState::read(buf)?,
            outgoing: Option::<Payment<P, D>>::read(buf)?,
            output: SettlementOutput::read(buf)?,
            prefix: Prefix::read(buf)?,
        })
    }
}

/// Settlement and challenge projection derived from one fully validated changed row.
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
    core: ChangeValueCore<D>,
    credit_tip_root: VectorRoot<D>,
}

/// Change value fields that precede the per-account credit-tip root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangeValueCore<D: Digest> {
    output: SettlementOutput,
    terminal_debit: u64,
    outgoing_digest: D,
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
            credit_tip_root: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D> arbitrary::Arbitrary<'_> for ChangeValueCore<D>
where
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            output: u.arbitrary()?,
            terminal_debit: u.arbitrary()?,
            outgoing_digest: u.arbitrary()?,
        })
    }
}

impl<P: PublicKey, D: Digest> AccountChange<P, D> {
    /// Derives the compact leaf from one row and its aligned full terminal-head corpus.
    pub fn from_row<H: Hasher<Digest = D>>(
        row: &AccountRow<P, D>,
        shards: &ShardSet<P, D>,
    ) -> Result<Self, credit::Error> {
        if shards.recipient() != &row.account {
            return Err(credit::Error::RecipientMismatch);
        }
        Ok(Self {
            account: row.account.clone(),
            value: ChangeValue {
                core: ChangeValueCore {
                    output: row.output,
                    terminal_debit: row.successor.cumulative_debit,
                    outgoing_digest: Self::derive_outgoing_digest::<H>(
                        row.outgoing.as_ref().map(|payment| payment.send().body()),
                    ),
                },
                credit_tip_root: shards.root::<H>()?,
            },
        })
    }

    /// Returns the changed account.
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

    /// Projects the exact leaf committed by the change vector.
    pub fn guard<H: Hasher<Digest = D>>(&self) -> ChangeGuard<P, D> {
        ChangeGuard::from_value::<H>(self.account.clone(), &self.value)
    }

    pub(crate) const fn from_value(account: P, value: ChangeValue<D>) -> Self {
        Self { account, value }
    }

    /// Returns the public terminal cumulative debit.
    pub const fn terminal_debit(&self) -> u64 {
        self.value.core.terminal_debit
    }

    /// Returns the compact per-account credit-tip root.
    pub const fn credit_tip_root(&self) -> VectorRoot<D> {
        self.value.credit_tip_root
    }

    /// Returns whether `send` is the exact committed terminal outgoing authorization.
    ///
    /// The leaf pins the unsigned terminal send body through its transaction identifier. It
    /// deliberately does not pin one acknowledging receipt: a batched send is acknowledged by
    /// one receipt per entry, and any of them may accompany the committed evidence.
    pub fn matches_outgoing<H: Hasher<Digest = D>>(&self, send: &SendBody<P, D>) -> bool {
        self.value.core.outgoing_digest == Self::derive_outgoing_digest::<H>(Some(send))
    }

    /// Returns whether this leaf commits no outgoing payment.
    pub fn has_no_outgoing<H: Hasher<Digest = D>>(&self) -> bool {
        self.value.core.outgoing_digest == Self::derive_outgoing_digest::<H>(None)
    }

    fn derive_outgoing_digest<H: Hasher<Digest = D>>(send: Option<&SendBody<P, D>>) -> D {
        send.map_or_else(
            || H::hash(&[CHANGE_OUTGOING_NONE_HASH_NAMESPACE]),
            |send| send.tx_id::<H>().into_digest(),
        )
    }

    /// Returns whether the row and terminal heads have this exact public projection.
    pub fn matches_projection<H: Hasher<Digest = D>>(
        &self,
        row: &AccountRow<P, D>,
        shards: &ShardSet<P, D>,
    ) -> bool {
        Self::from_row::<H>(row, shards).is_ok_and(|derived| self == &derived)
    }
}

impl<D: Digest> ChangeValue<D> {
    /// Returns the fields that precede the credit-tip root, which a child proof reconstructs.
    #[must_use]
    pub const fn core(&self) -> ChangeValueCore<D> {
        self.core
    }

    /// Restores the exact compact value from its prefix fields and typed credit-tip root.
    #[must_use]
    pub const fn from_core(core: ChangeValueCore<D>, credit_tip_root: VectorRoot<D>) -> Self {
        Self {
            core,
            credit_tip_root,
        }
    }

    pub(crate) const fn credit_tip_root(&self) -> VectorRoot<D> {
        self.credit_tip_root
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

    /// Returns the ordered changed account.
    pub const fn account(&self) -> &P {
        &self.account
    }
}

impl<D: Digest> Write for ChangeValue<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.core.write(buf);
        self.credit_tip_root.write(buf);
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
            credit_tip_root: VectorRoot::read(buf)?,
        })
    }
}

impl<D: Digest> Write for ChangeValueCore<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.output.write(buf);
        self.terminal_debit.write(buf);
        self.outgoing_digest.write(buf);
    }
}

impl<D: Digest> EncodeSize for ChangeValueCore<D> {
    fn encode_size(&self) -> usize {
        self.output.encode_size() + u64::SIZE + D::SIZE
    }
}

impl<D: Digest> Read for ChangeValueCore<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            output: SettlementOutput::read(buf)?,
            terminal_debit: u64::read(buf)?,
            outgoing_digest: D::read(buf)?,
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
    fn prefix_extension_is_checked_fieldwise() {
        let prefix = Prefix {
            debit: 1,
            credit: 2,
            payout: 3,
            deposit: 4,
            withdrawal: 5,
            withdrawal_count: 6,
            shard_count: 7,
        };
        assert_eq!(
            prefix.checked_extend(prefix),
            Some(Prefix {
                debit: 2,
                credit: 4,
                payout: 6,
                deposit: 8,
                withdrawal: 10,
                withdrawal_count: 12,
                shard_count: 14,
            })
        );
        assert!(
            Prefix {
                debit: u64::MAX,
                ..prefix
            }
            .checked_extend(prefix)
            .is_none()
        );
    }

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
    fn change_leaf_binds_challenge_and_settlement_projection() {
        let account = SigningKey::from_seed(1).public_key();
        let shards = ShardSet::empty(0, account.clone());
        let row = AccountRow::<VerifyingKey, ShaDigest> {
            account: account.clone(),
            predecessor: AccountState {
                balance: 10,
                active: true,
                ..AccountState::default()
            },
            successor: AccountState {
                balance: 4,
                active: true,
                ..AccountState::default()
            },
            outgoing: None,
            output: SettlementOutput::Withdrawal(6),
            prefix: Prefix {
                withdrawal: 6,
                withdrawal_count: 1,
                ..Prefix::default()
            },
        };
        let leaf = AccountChange::from_row::<Sha256>(&row, &shards).unwrap();
        assert_eq!(leaf.account(), &account);
        assert_eq!(leaf.output(), SettlementOutput::Withdrawal(6));
        assert!(leaf.matches_projection::<Sha256>(&row, &shards));

        let mut changed_output = row.clone();
        changed_output.output = SettlementOutput::ExternalPayout(6);
        assert!(!leaf.matches_projection::<Sha256>(&changed_output, &shards));

        let mut changed_row = row;
        changed_row.successor.balance = 5;
        assert!(leaf.matches_projection::<Sha256>(&changed_row, &shards));

        changed_row.successor.cumulative_debit = 1;
        assert!(!leaf.matches_projection::<Sha256>(&changed_row, &shards));
    }
}
