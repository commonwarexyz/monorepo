//! Account state and canonical changed-account rows.

use crate::bajillion::{credit::CreditRoot, payment::Payment};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_cryptography::{Digest, PublicKey};

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
    pub withdrawals: u64,
    /// Terminal receive shards through this row.
    pub shards: u64,
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
            withdrawals: self.withdrawals.checked_add(delta.withdrawals)?,
            shards: self.shards.checked_add(delta.shards)?,
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
        self.withdrawals.write(buf);
        self.shards.write(buf);
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
            withdrawals: u64::read(buf)?,
            shards: u64::read(buf)?,
        })
    }
}

/// One and only one row for an account whose authenticated state changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountRow<P: PublicKey, D: Digest> {
    /// Changed account.
    pub account: P,
    /// State committed by the opening root.
    pub opening: AccountState,
    /// State committed by the closing root.
    pub closing: AccountState,
    /// Terminal accepted outgoing payment, present exactly when debit advanced.
    pub outgoing: Option<Payment<P, D>>,
    /// Commitment to all terminal receive-shard heads for this account.
    pub credit_root: CreditRoot<D>,
    /// Running totals through this row.
    pub prefix: Prefix,
}

#[cfg(feature = "arbitrary")]
impl<P, D> arbitrary::Arbitrary<'_> for AccountRow<P, D>
where
    P: PublicKey + for<'a> arbitrary::Arbitrary<'a>,
    D: Digest + for<'a> arbitrary::Arbitrary<'a>,
    Payment<P, D>: for<'a> arbitrary::Arbitrary<'a>,
    CreditRoot<D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            account: u.arbitrary()?,
            opening: u.arbitrary()?,
            closing: u.arbitrary()?,
            outgoing: u.arbitrary()?,
            credit_root: u.arbitrary()?,
            prefix: u.arbitrary()?,
        })
    }
}

impl<P: PublicKey, D: Digest> AccountRow<P, D> {
    /// Returns the checked debit and credit advances.
    pub fn checked_deltas(&self) -> Option<(u64, u64, u64)> {
        Some((
            self.closing
                .cumulative_debit
                .checked_sub(self.opening.cumulative_debit)?,
            self.closing
                .cumulative_credit
                .checked_sub(self.opening.cumulative_credit)?,
            self.closing
                .receipt_count
                .checked_sub(self.opening.receipt_count)?,
        ))
    }

    /// Whether this row actually changes authenticated state.
    #[must_use]
    pub fn is_changed(&self) -> bool {
        self.opening != self.closing
    }
}

impl<P: PublicKey, D: Digest> Write for AccountRow<P, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.account.write(buf);
        self.opening.write(buf);
        self.closing.write(buf);
        self.outgoing.write(buf);
        self.credit_root.write(buf);
        self.prefix.write(buf);
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for AccountRow<P, D> {
    fn encode_size(&self) -> usize {
        P::SIZE
            + AccountState::SIZE * 2
            + self.outgoing.encode_size()
            + self.credit_root.encode_size()
            + Prefix::SIZE
    }
}

impl<P: PublicKey, D: Digest> Read for AccountRow<P, D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            account: P::read(buf)?,
            opening: AccountState::read(buf)?,
            closing: AccountState::read(buf)?,
            outgoing: Option::<Payment<P, D>>::read(buf)?,
            credit_root: CreditRoot::<D>::read(buf)?,
            prefix: Prefix::read(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_extension_is_checked_fieldwise() {
        let prefix = Prefix {
            debit: 1,
            credit: 2,
            payout: 3,
            deposit: 4,
            withdrawal: 5,
            withdrawals: 6,
            shards: 7,
        };
        assert_eq!(
            prefix.checked_extend(prefix),
            Some(Prefix {
                debit: 2,
                credit: 4,
                payout: 6,
                deposit: 8,
                withdrawal: 10,
                withdrawals: 12,
                shards: 14,
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
}
