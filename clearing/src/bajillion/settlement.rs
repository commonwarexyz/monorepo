//! Balances and payouts that a close settles.
//!
//! The operator and validators compute a close's effects with the same code, so an honest
//! operator always knows the balances its close will post.

use super::{Amounts, Deposit, Error, ForcedWithdrawal, Withdrawal};
use commonware_cryptography::PublicKey;
use commonware_utils::iter::zip_eq;
use std::collections::HashMap;

/// Funds moving into and out of one account in a close.
#[derive(Default)]
struct Flow {
    /// Incoming payments and processed deposits.
    credit: u128,
    /// Outgoing payments.
    debit: u128,
    /// Requested forced and soft withdrawals.
    withdraw: u128,
}

/// The effects of a close.
pub(crate) struct Settlement<P: PublicKey> {
    /// The new balance of every account whose balance changes, in account order.
    pub(crate) balances: Vec<(P, u64)>,
    /// Amount paid out to each withdrawing account.
    pub(crate) payouts: Amounts<P>,
}

/// The flows of a close, aggregated per account.
pub(crate) struct Flows<P: PublicKey> {
    /// Flow of every account the close touches, in account order.
    flows: Vec<(P, Flow)>,
}

impl<P: PublicKey> Flows<P> {
    /// Aggregates the payments, soft withdrawals, deposits, and forced withdrawals of a close.
    pub(crate) fn new<'a>(
        rows: impl IntoIterator<Item = (&'a P, &'a Amounts<P>)>,
        withdrawals: &[Withdrawal<P>],
        deposits: &[Deposit<P>],
        forced_withdrawals: &[ForcedWithdrawal<P>],
    ) -> Result<Self, Error> {
        let mut flows = HashMap::<P, Flow>::new();
        for (sender, payments) in rows {
            for (receiver, amount) in payments.iter() {
                add(
                    &mut flows,
                    receiver,
                    |flow| &mut flow.credit,
                    u128::from(amount),
                )?;
            }
            add(&mut flows, sender, |flow| &mut flow.debit, payments.total())?;
        }
        for deposit in deposits {
            let amount = u128::from(deposit.amount);
            add(
                &mut flows,
                &deposit.account,
                |flow| &mut flow.credit,
                amount,
            )?;
        }
        for withdrawal in forced_withdrawals {
            let amount = u128::from(withdrawal.amount);
            add(
                &mut flows,
                &withdrawal.account,
                |flow| &mut flow.withdraw,
                amount,
            )?;
        }
        for withdrawal in withdrawals {
            let amount = u128::from(withdrawal.amount);
            add(
                &mut flows,
                &withdrawal.account,
                |flow| &mut flow.withdraw,
                amount,
            )?;
        }
        let mut flows: Vec<_> = flows.into_iter().collect();
        flows.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        Ok(Self { flows })
    }

    /// Returns every account the close touches, in account order.
    pub(crate) fn accounts(&self) -> impl ExactSizeIterator<Item = &P> {
        self.flows.iter().map(|(account, _)| account)
    }

    /// Settles the flows on top of `balances`, the previous balance of each account in
    /// [Self::accounts] order.
    ///
    /// Each account's balance gains its credits and loses its debits, and must not go negative.
    /// The account is then paid the lesser of its balance and the amount it asked to withdraw.
    ///
    /// # Panics
    ///
    /// Panics if `balances` does not hold one balance per account.
    pub(crate) fn settle(
        self,
        balances: impl IntoIterator<Item = u64>,
    ) -> Result<Settlement<P>, Error> {
        let mut changed = Vec::new();
        let mut payouts = Vec::new();
        for ((account, flow), previous) in zip_eq(self.flows, balances) {
            let available = u128::from(previous)
                .checked_add(flow.credit)
                .ok_or(Error::Overflow)?;
            let settled = available.checked_sub(flow.debit).ok_or(Error::Overdraft)?;
            let settled = u64::try_from(settled).map_err(|_| Error::Overflow)?;
            let payout = u64::try_from(flow.withdraw.min(u128::from(settled)))
                .expect("payout must be at most the balance");
            let remaining = settled - payout;
            if remaining != previous {
                changed.push((account.clone(), remaining));
            }
            if payout > 0 {
                payouts.push((account, payout));
            }
        }
        Ok(Settlement {
            balances: changed,
            payouts: Amounts::from_sorted(payouts)?,
        })
    }
}

/// Adds `amount` to the total `field` selects in `account`'s flow.
fn add<P: PublicKey>(
    flows: &mut HashMap<P, Flow>,
    account: &P,
    field: impl FnOnce(&mut Flow) -> &mut u128,
    amount: u128,
) -> Result<(), Error> {
    let total = field(flows.entry(account.clone()).or_default());
    *total = total.checked_add(amount).ok_or(Error::Overflow)?;
    Ok(())
}
