//! Verus-verified kernels for the sender-vector close.
//!
//! This file mirrors the successor-derivation and prefix arithmetic from
//! `clearing/src/bajillion` (posted.rs `derive_successor`, transition.rs `validate_row` and
//! `Prefix::checked_extend`) and proves, for all inputs:
//!
//! - **Soundness**: the forward derivation's output satisfies every successor equation row
//!   validation checks.
//! - **Uniqueness**: any successor and output satisfying those equations equal the derived
//!   ones, so the posted corpus (which omits both) admits exactly one reconstruction.
//! - **Completeness**: when derivation refuses, no satisfying successor exists at all.
//! - **Prefix conservation**: a `checked_extend` chain that completes equals the exact
//!   componentwise sum of its deltas.
//! - **Liability conservation**: summed over any sequence of valid rows, the successor
//!   balances plus withdrawals and payouts equal the predecessor balances plus deposits
//!   once gross debit and credit cancel, which is the equation
//!   `checked_successor_liability` and `validate_terminal_prefix` enforce.
//!
//! Verified out-of-band with the pinned Verus toolchain (`./verify.sh`); the exec bodies
//! here must stay line-equivalent with their crate twins, which `verify.sh` reminds
//! reviewers to diff. Single-source integration through `vstd` is the follow-up once the
//! prototype stabilizes.

use vstd::prelude::*;

verus! {

/// Mirror of `bajillion::state::AccountState`.
#[derive(Clone, Copy, PartialEq, Eq, Structural)]
pub struct AccountState {
    pub balance: u64,
    pub cumulative_debit: u64,
    pub cumulative_credit: u64,
    pub receipt_count: u64,
    pub active: bool,
}

/// Mirror of the row's withdrawal disposition: `None`, `Amount(a)`, or `Close`.
#[derive(Clone, Copy, PartialEq, Eq, Structural)]
pub enum Action {
    None,
    Amount(u64),
    Close,
}

/// Mirror of `bajillion::state::SettlementOutput`.
#[derive(Clone, Copy, PartialEq, Eq, Structural)]
pub enum Output {
    None,
    Withdrawal(u64),
    ExternalPayout(u64),
}

/// The tail available after this row's sends, as row validation computes it.
pub open spec fn spec_tail(pred: AccountState, deposit: u64, credit: u64, debit: u64) -> int {
    pred.balance + deposit + credit - debit
}

/// The withdrawal amount row validation admits for `action` over `tail`.
pub open spec fn spec_withdrawal(action: Action, tail: int) -> int {
    match action {
        Action::None => 0,
        Action::Amount(amount) => if amount <= tail { amount as int } else { 0 },
        Action::Close => tail,
    }
}

/// The external payout row validation requires for an unregistered recipient.
pub open spec fn spec_payout(pred: AccountState, deposit: u64, credit: u64) -> int {
    if pred.active || deposit != 0 { 0 } else { credit as int }
}

/// Every successor-determining equation `validate_row` checks, as one predicate.
///
/// Scope: this models the checks that pin the successor state and output (delta pins, the
/// balance equation, the withdrawal clamp, the payout rule, the active flag, the output
/// classification). Row-validity checks that do not constrain the successor (canonical
/// predecessor form, unchanged-row rejection, incoming-interval totals) live outside it.
pub open spec fn valid_successor(
    pred: AccountState,
    succ: AccountState,
    output: Output,
    debit: u64,
    credit: u64,
    receipts: u64,
    deposit: u64,
    action: Action,
) -> bool {
    let tail = spec_tail(pred, deposit, credit, debit);
    let withdrawal = spec_withdrawal(action, tail);
    let payout = spec_payout(pred, deposit, credit);
    &&& tail >= 0
    // Row validation converts the admitted withdrawal to u64, so validity requires it
    // representable (only the Close arm can exceed it).
    &&& withdrawal <= u64::MAX
    &&& succ.cumulative_debit == pred.cumulative_debit + debit
    &&& succ.cumulative_credit == pred.cumulative_credit + credit
    &&& succ.receipt_count == pred.receipt_count + receipts
    &&& succ.balance + debit + withdrawal + payout == pred.balance + credit + deposit
    &&& succ.active == (succ.balance > 0)
    &&& output == match action {
        Action::None => if payout != 0 { Output::ExternalPayout(payout as u64) } else {
            Output::None
        },
        _ => Output::Withdrawal(withdrawal as u64),
    }
}

/// Mirror of `posted::derive_successor`'s arithmetic (checked, panic-free).
pub fn derive_successor(
    pred: AccountState,
    debit: u64,
    credit: u64,
    receipts: u64,
    deposit: u64,
    action: Action,
) -> (result: Option<(AccountState, Output)>)
    ensures
        // Soundness: a derived successor satisfies every checked equation.
        result matches Some((succ, output))
            ==> valid_successor(pred, succ, output, debit, credit, receipts, deposit, action),
        // Completeness: a refusal means no satisfying successor exists.
        result is None
            ==> forall|succ: AccountState, output: Output|
                !valid_successor(pred, succ, output, debit, credit, receipts, deposit, action),
{
    let available = pred.balance as u128 + deposit as u128 + credit as u128;
    let tail = match available.checked_sub(debit as u128) {
        Some(tail) => tail,
        None => {
            return None;
        }
    };
    let withdrawal_amount: u64 = match action {
        Action::None => 0,
        Action::Amount(amount) => if amount as u128 <= tail { amount } else { 0 },
        Action::Close => {
            if tail > u64::MAX as u128 {
                return None;
            }
            tail as u64
        }
    };
    let registered = pred.active || deposit != 0;
    let payout: u64 = if registered { 0 } else { credit };
    let rest = match tail.checked_sub(withdrawal_amount as u128) {
        Some(rest) => rest,
        None => {
            return None;
        }
    };
    let rest = match rest.checked_sub(payout as u128) {
        Some(rest) => rest,
        None => {
            return None;
        }
    };
    if rest > u64::MAX as u128 {
        return None;
    }
    let balance = rest as u64;
    let cumulative_debit = match pred.cumulative_debit.checked_add(debit) {
        Some(value) => value,
        None => {
            return None;
        }
    };
    let cumulative_credit = match pred.cumulative_credit.checked_add(credit) {
        Some(value) => value,
        None => {
            return None;
        }
    };
    let receipt_count = match pred.receipt_count.checked_add(receipts) {
        Some(value) => value,
        None => {
            return None;
        }
    };
    let successor = AccountState {
        balance,
        cumulative_debit,
        cumulative_credit,
        receipt_count,
        active: balance > 0,
    };
    let output = match action {
        Action::None => if payout != 0 { Output::ExternalPayout(payout) } else { Output::None },
        _ => Output::Withdrawal(withdrawal_amount),
    };
    Some((successor, output))
}

/// Uniqueness: the equations admit at most one successor and output.
pub proof fn successor_is_unique(
    pred: AccountState,
    s1: AccountState,
    o1: Output,
    s2: AccountState,
    o2: Output,
    debit: u64,
    credit: u64,
    receipts: u64,
    deposit: u64,
    action: Action,
)
    requires
        valid_successor(pred, s1, o1, debit, credit, receipts, deposit, action),
        valid_successor(pred, s2, o2, debit, credit, receipts, deposit, action),
    ensures
        s1 == s2,
        o1 == o2,
{
}

/// Mirror of `bajillion::state::Prefix`.
#[derive(Clone, Copy, PartialEq, Eq, Structural)]
pub struct Prefix {
    pub debit: u64,
    pub credit: u64,
    pub payout: u64,
    pub deposit: u64,
    pub withdrawal: u64,
    pub withdrawal_count: u64,
    pub out_count: u64,
    pub in_count: u64,
}

impl Prefix {
    pub open spec fn spec_default() -> Prefix {
        Prefix {
            debit: 0,
            credit: 0,
            payout: 0,
            deposit: 0,
            withdrawal: 0,
            withdrawal_count: 0,
            out_count: 0,
            in_count: 0,
        }
    }

    /// Mirror of `Prefix::checked_extend`.
    pub fn checked_extend(self, delta: Prefix) -> (result: Option<Prefix>)
        ensures
            result is Some ==> {
                let sum = result->0;
                &&& sum.debit == self.debit + delta.debit
                &&& sum.credit == self.credit + delta.credit
                &&& sum.payout == self.payout + delta.payout
                &&& sum.deposit == self.deposit + delta.deposit
                &&& sum.withdrawal == self.withdrawal + delta.withdrawal
                &&& sum.withdrawal_count == self.withdrawal_count + delta.withdrawal_count
                &&& sum.out_count == self.out_count + delta.out_count
                &&& sum.in_count == self.in_count + delta.in_count
            },
    {
        if self.debit as u128 + delta.debit as u128 > u64::MAX as u128
            || self.credit as u128 + delta.credit as u128 > u64::MAX as u128
            || self.payout as u128 + delta.payout as u128 > u64::MAX as u128
            || self.deposit as u128 + delta.deposit as u128 > u64::MAX as u128
            || self.withdrawal as u128 + delta.withdrawal as u128 > u64::MAX as u128
            || self.withdrawal_count as u128 + delta.withdrawal_count as u128
                > u64::MAX as u128
            || self.out_count as u128 + delta.out_count as u128 > u64::MAX as u128
            || self.in_count as u128 + delta.in_count as u128 > u64::MAX as u128
        {
            return None;
        }
        Some(Prefix {
            debit: self.debit + delta.debit,
            credit: self.credit + delta.credit,
            payout: self.payout + delta.payout,
            deposit: self.deposit + delta.deposit,
            withdrawal: self.withdrawal + delta.withdrawal,
            withdrawal_count: self.withdrawal_count + delta.withdrawal_count,
            out_count: self.out_count + delta.out_count,
            in_count: self.in_count + delta.in_count,
        })
    }
}

/// Componentwise integer sum of a delta sequence's debit column (each column is symmetric;
/// the chain theorem below carries all eight).
pub open spec fn column_sum(deltas: Seq<Prefix>, column: spec_fn(Prefix) -> u64) -> int
    decreases deltas.len(),
{
    if deltas.len() == 0 {
        0
    } else {
        column_sum(deltas.drop_last(), column) + column(deltas.last())
    }
}

/// Conservation of the running chain: a completed `checked_extend` fold equals the exact
/// componentwise sum of its deltas. This is the fact row validation's per-row prefix
/// equality composes into, and what the terminal boundary's totals mean.
pub open spec fn sums(deltas: Seq<Prefix>, terminal: Prefix) -> bool {
    &&& terminal.debit == column_sum(deltas, |prefix: Prefix| prefix.debit)
    &&& terminal.credit == column_sum(deltas, |prefix: Prefix| prefix.credit)
    &&& terminal.payout == column_sum(deltas, |prefix: Prefix| prefix.payout)
    &&& terminal.deposit == column_sum(deltas, |prefix: Prefix| prefix.deposit)
    &&& terminal.withdrawal == column_sum(deltas, |prefix: Prefix| prefix.withdrawal)
    &&& terminal.withdrawal_count == column_sum(
        deltas,
        |prefix: Prefix| prefix.withdrawal_count,
    )
    &&& terminal.out_count == column_sum(deltas, |prefix: Prefix| prefix.out_count)
    &&& terminal.in_count == column_sum(deltas, |prefix: Prefix| prefix.in_count)
}

pub fn chain(deltas: &Vec<Prefix>) -> (result: Option<Prefix>)
    ensures
        result is Some ==> sums(deltas@, result->0),
{
    let mut prefix = Prefix {
        debit: 0,
        credit: 0,
        payout: 0,
        deposit: 0,
        withdrawal: 0,
        withdrawal_count: 0,
        out_count: 0,
        in_count: 0,
    };
    let mut index: usize = 0;
    while index < deltas.len()
        invariant
            index <= deltas.len(),
            sums(deltas@.take(index as int), prefix),
        decreases deltas.len() - index,
    {
        proof {
            assert(deltas@.take(index as int + 1).drop_last() =~= deltas@.take(index as int));
            assert(deltas@.take(index as int + 1).last() == deltas@[index as int]);
        }
        prefix = match prefix.checked_extend(deltas[index]) {
            Some(next) => next,
            None => {
                return None;
            }
        };
        index += 1;
    }
    proof {
        assert(deltas@.take(deltas@.len() as int) =~= deltas@);
    }
    Some(prefix)
}

/// One changed row's flow facts: both state sides and the classified amounts.
pub struct Row {
    pub pred: AccountState,
    pub succ: AccountState,
    pub output: Output,
    pub debit: u64,
    pub credit: u64,
    pub receipts: u64,
    pub deposit: u64,
    pub action: Action,
}

pub open spec fn row_valid(row: Row) -> bool {
    valid_successor(
        row.pred,
        row.succ,
        row.output,
        row.debit,
        row.credit,
        row.receipts,
        row.deposit,
        row.action,
    )
}

/// Integer sum of one column over a row sequence.
pub open spec fn row_sum(rows: Seq<Row>, column: spec_fn(Row) -> int) -> int
    decreases rows.len(),
{
    if rows.len() == 0 {
        0
    } else {
        row_sum(rows.drop_last(), column) + column(rows.last())
    }
}

pub open spec fn spec_row_withdrawal(row: Row) -> int {
    spec_withdrawal(row.action, spec_tail(row.pred, row.deposit, row.credit, row.debit))
}

/// Summing every valid row's balance equation: successor balances plus gross debit,
/// withdrawals, and payouts equal predecessor balances plus gross credit and deposits.
pub proof fn liability_conservation(rows: Seq<Row>)
    requires
        forall|i: int| 0 <= i < rows.len() ==> row_valid(#[trigger] rows[i]),
    ensures
        row_sum(rows, |row: Row| row.succ.balance as int) + row_sum(
            rows,
            |row: Row| row.debit as int,
        ) + row_sum(rows, |row: Row| spec_row_withdrawal(row)) + row_sum(
            rows,
            |row: Row| spec_payout(row.pred, row.deposit, row.credit),
        ) == row_sum(rows, |row: Row| row.pred.balance as int) + row_sum(
            rows,
            |row: Row| row.credit as int,
        ) + row_sum(rows, |row: Row| row.deposit as int),
    decreases rows.len(),
{
    if rows.len() > 0 {
        assert forall|i: int| 0 <= i < rows.drop_last().len() implies row_valid(
            #[trigger] rows.drop_last()[i],
        ) by {
            assert(rows.drop_last()[i] == rows[i]);
        }
        liability_conservation(rows.drop_last());
        assert(row_valid(rows[rows.len() - 1]));
    }
}

/// The settlement liability equation: with gross debit equal to gross credit (payment
/// conservation, checked at the terminal boundary), the successor liability is exactly the
/// predecessor liability plus deposits minus withdrawals and payouts.
pub proof fn successor_liability(rows: Seq<Row>)
    requires
        forall|i: int| 0 <= i < rows.len() ==> row_valid(#[trigger] rows[i]),
        row_sum(rows, |row: Row| row.debit as int) == row_sum(
            rows,
            |row: Row| row.credit as int,
        ),
    ensures
        row_sum(rows, |row: Row| row.succ.balance as int) == row_sum(
            rows,
            |row: Row| row.pred.balance as int,
        ) + row_sum(rows, |row: Row| row.deposit as int) - row_sum(
            rows,
            |row: Row| spec_row_withdrawal(row),
        ) - row_sum(rows, |row: Row| spec_payout(row.pred, row.deposit, row.credit)),
{
    liability_conservation(rows);
}

} // verus!

fn main() {}
