//! Balances and payouts that a close settles.
//!
//! The operator and validators settle each account with the same rule ([Flow::settle]), so an
//! honest operator always knows the balances its close will post.

use super::{Amount, Amounts, Deposit, Epoch, Error, ForcedWithdrawal, Withdrawal};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write, varint::UInt,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_utils::iter::zip_eq;
use std::collections::HashMap;

/// An exact sum of amounts that may exceed the largest amount.
///
/// The sum is `low` plus `carries` times one more than the largest amount, so a close settles
/// whenever its final balances fit, however large its gross flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Total<A: Amount> {
    low: A,
    carries: u64,
}

impl<A: Amount> Total<A> {
    pub(crate) const ZERO: Self = Self::new(A::ZERO);

    pub(crate) const fn new(amount: A) -> Self {
        Self {
            low: amount,
            carries: 0,
        }
    }

    /// Returns the sum of `self` and `other`.
    pub(crate) fn add(self, other: Self) -> Result<Self, Error> {
        let (low, carry) = self.low.overflowing_add(other.low);
        let carries = self
            .carries
            .checked_add(other.carries)
            .and_then(|carries| carries.checked_add(u64::from(carry)))
            .ok_or(Error::Overflow)?;
        Ok(Self { low, carries })
    }

    /// Returns `self` less `other`, or `None` if the difference is negative.
    pub(crate) fn sub(self, other: Self) -> Option<Self> {
        let (low, borrow) = self.low.overflowing_sub(other.low);
        let carries = self
            .carries
            .checked_sub(other.carries)?
            .checked_sub(u64::from(borrow))?;
        Some(Self { low, carries })
    }

    /// Returns the sum as an amount, or `None` if it exceeds the largest amount.
    pub(crate) fn get(self) -> Option<A> {
        (self.carries == 0).then_some(self.low)
    }
}

impl<A: Amount> Write for Total<A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.low.write(buf);
        UInt(self.carries).write(buf);
    }
}

impl<A: Amount> EncodeSize for Total<A> {
    fn encode_size(&self) -> usize {
        A::SIZE + UInt(self.carries).encode_size()
    }
}

impl<A: Amount> Read for Total<A> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            low: A::read(buf)?,
            carries: UInt::read(buf)?.into(),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<A: Amount> arbitrary::Arbitrary<'_> for Total<A>
where
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            low: u.arbitrary()?,
            carries: u.arbitrary()?,
        })
    }
}

/// Funds moving into and out of one account in the close of an epoch, and the root of the account's
/// payment map in it.
///
/// Each part is an exact sum, so it may exceed the largest amount even when the balance the close
/// leaves fits. [Close::assemble](super::Close::assemble) computes the flow of every account a
/// close touches. The deployment routes each to the shard serving its account in the next epoch,
/// and [Operator::settle](super::Operator::settle) applies it there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow<D: Digest, A: Amount> {
    /// Epoch of the close.
    epoch: Epoch,
    /// Incoming payments and processed deposits.
    credit: Total<A>,
    /// Outgoing payments.
    debit: Total<A>,
    /// Requested forced and soft withdrawals.
    withdraw: Total<A>,
    /// Root of the account's payment map in the close, if it pays in it.
    root: Option<D>,
}

impl<D: Digest, A: Amount> Flow<D, A> {
    /// Returns a flow of the close of `epoch` that moves nothing.
    const fn zero(epoch: Epoch) -> Self {
        Self {
            epoch,
            credit: Total::ZERO,
            debit: Total::ZERO,
            withdraw: Total::ZERO,
            root: None,
        }
    }

    /// Returns the epoch of the close.
    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns whether the flow debits its account or asks to withdraw from it.
    pub(crate) fn takes(&self) -> bool {
        self.debit != Total::ZERO || self.withdraw != Total::ZERO
    }

    /// Returns the root of the account's payment map in the close, if it pays in it.
    pub(crate) const fn root(&self) -> Option<&D> {
        self.root.as_ref()
    }

    /// Settles the flow on top of the account's `previous` balance, and returns the balance left
    /// and the amount paid out.
    ///
    /// The balance gains the credits and loses the debits, and must not go negative or exceed the
    /// largest amount. The account is then paid the lesser of that balance and the amount it asked
    /// to withdraw.
    pub(crate) fn settle(&self, previous: A) -> Result<(A, A), Error> {
        let settled = Total::new(previous)
            .add(self.credit)?
            .sub(self.debit)
            .ok_or(Error::Overdraft)?
            .get()
            .ok_or(Error::Overflow)?;
        let payout = self
            .withdraw
            .get()
            .map_or(settled, |requested| requested.min(settled));
        let remaining = settled
            .checked_sub(payout)
            .expect("payout must be at most the balance");
        Ok((remaining, payout))
    }
}

impl<D: Digest, A: Amount> Write for Flow<D, A> {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.credit.write(buf);
        self.debit.write(buf);
        self.withdraw.write(buf);
        self.root.write(buf);
    }
}

impl<D: Digest, A: Amount> EncodeSize for Flow<D, A> {
    fn encode_size(&self) -> usize {
        Epoch::SIZE
            + self.credit.encode_size()
            + self.debit.encode_size()
            + self.withdraw.encode_size()
            + self.root.encode_size()
    }
}

impl<D: Digest, A: Amount> Read for Flow<D, A> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: Epoch::read(buf)?,
            credit: Total::read(buf)?,
            debit: Total::read(buf)?,
            withdraw: Total::read(buf)?,
            root: Option::<D>::read(buf)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest, A: Amount> arbitrary::Arbitrary<'_> for Flow<D, A>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    A: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            epoch: u.arbitrary()?,
            credit: u.arbitrary()?,
            debit: u.arbitrary()?,
            withdraw: u.arbitrary()?,
            root: u.arbitrary()?,
        })
    }
}

/// The effects of a close.
pub(crate) struct Settlement<P: PublicKey, A: Amount> {
    /// The new balance of every account whose balance changes, in account order.
    pub(crate) balances: Vec<(P, A)>,
    /// Amount paid out to each withdrawing account.
    pub(crate) payouts: Amounts<P, A>,
}

/// The flows of a close, aggregated per account.
pub(crate) struct Flows<P: PublicKey, D: Digest, A: Amount> {
    /// Flow of every account the close touches, in account order.
    flows: Vec<(P, Flow<D, A>)>,
}

impl<P: PublicKey, D: Digest, A: Amount> Flows<P, D, A> {
    /// Aggregates the payments, soft withdrawals, deposits, and forced withdrawals of the close of
    /// `epoch`.
    ///
    /// `rows` holds each sender's payment map with its root.
    pub(crate) fn new<'a>(
        epoch: Epoch,
        rows: impl IntoIterator<Item = (&'a P, &'a Amounts<P, A>, &'a D)>,
        withdrawals: &[Withdrawal<P, A>],
        deposits: &[Deposit<P, A>],
        forced_withdrawals: &[ForcedWithdrawal<P, A>],
    ) -> Result<Self, Error> {
        let mut flows = HashMap::<P, Flow<D, A>>::new();
        for (sender, payments, root) in rows {
            let mut paid = Total::ZERO;
            for (receiver, amount) in payments.iter() {
                let amount = Total::new(amount);
                add(&mut flows, epoch, receiver, |flow| &mut flow.credit, amount)?;
                paid = paid.add(amount)?;
            }
            add(&mut flows, epoch, sender, |flow| &mut flow.debit, paid)?;
            flows.get_mut(sender).expect("sender must have a flow").root = Some(*root);
        }
        for deposit in deposits {
            let amount = Total::new(deposit.amount);
            add(
                &mut flows,
                epoch,
                &deposit.account,
                |flow| &mut flow.credit,
                amount,
            )?;
        }
        for withdrawal in forced_withdrawals {
            let amount = Total::new(withdrawal.amount);
            add(
                &mut flows,
                epoch,
                &withdrawal.account,
                |flow| &mut flow.withdraw,
                amount,
            )?;
        }
        for withdrawal in withdrawals {
            let amount = Total::new(withdrawal.amount);
            add(
                &mut flows,
                epoch,
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

    /// Returns the flow of every account the close touches, in account order.
    pub(crate) fn into_flows(self) -> Vec<(P, Flow<D, A>)> {
        self.flows
    }

    /// Settles the flows on top of `balances`, the previous balance of each account in
    /// [Self::accounts] order.
    ///
    /// # Panics
    ///
    /// Panics if `balances` does not hold one balance per account.
    pub(crate) fn settle(
        self,
        balances: impl IntoIterator<Item = A>,
    ) -> Result<Settlement<P, A>, Error> {
        let mut changed = Vec::new();
        let mut payouts = Vec::new();
        for ((account, flow), previous) in zip_eq(self.flows, balances) {
            let (remaining, payout) = flow.settle(previous)?;
            if remaining != previous {
                changed.push((account.clone(), remaining));
            }
            if payout != A::ZERO {
                payouts.push((account, payout));
            }
        }
        Ok(Settlement {
            balances: changed,
            payouts: Amounts::from_sorted(payouts)?,
        })
    }
}

/// Adds `amount` to the total `field` selects in `account`'s flow of the close of `epoch`.
fn add<P: PublicKey, D: Digest, A: Amount>(
    flows: &mut HashMap<P, Flow<D, A>>,
    epoch: Epoch,
    account: &P,
    field: impl FnOnce(&mut Flow<D, A>) -> &mut Total<A>,
    amount: Total<A>,
) -> Result<(), Error> {
    let total = field(
        flows
            .entry(account.clone())
            .or_insert_with(|| Flow::zero(epoch)),
    );
    *total = total.add(amount)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{
        Hasher as _, Sha256, Signer as _,
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest,
    };

    #[test]
    fn test_flows_round_trip_beyond_the_largest_amount() {
        // Alice pays herself and bob the largest amount each and deposits it too, so her credits
        // and debits each exceed the largest amount while her balance does not change.
        let [alice, bob] = [0, 1].map(|seed| PrivateKey::from_seed(seed).public_key());
        let payments = Amounts::new([(alice.clone(), u64::MAX), (bob.clone(), u64::MAX)]).unwrap();
        let root = Sha256::hash(&[b"alice"]);
        let deposit = Deposit {
            account: alice.clone(),
            amount: u64::MAX,
        };
        let flows = Flows::new(2, [(&alice, &payments, &root)], &[], &[deposit], &[])
            .unwrap()
            .into_flows();
        let flow = |account: &PublicKey| {
            flows
                .iter()
                .find(|(candidate, _)| candidate == account)
                .map(|(_, flow)| *flow)
                .unwrap()
        };
        let (paying, paid) = (flow(&alice), flow(&bob));
        assert_eq!((paying.credit.carries, paying.debit.carries), (1, 1));
        assert_eq!(paying.root(), Some(&root));
        assert_eq!(paying.settle(5).unwrap(), (5, 0));
        assert_eq!(paid.root(), None);
        assert_eq!(paid.settle(0).unwrap(), (u64::MAX, 0));

        // Every flow round trips, with or without a root.
        for flow in [paying, paid] {
            assert_eq!(Flow::<Digest, u64>::decode(flow.encode()).unwrap(), flow);
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<Flow<Digest, u64>>,
        }
    }
}
