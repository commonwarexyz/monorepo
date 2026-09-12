//! Verus arithmetic model of the full-replica balance-only close.
//!
//! Proves successor soundness, completeness, uniqueness, and summed liability
//! conservation for epoch-local debit and credit. A zero balance denotes absence;
//! positive balances are the complete persistent account value.
//!
//! This is an out-of-band arithmetic mirror. See README.md for the production
//! correspondence and the validation obligations outside this model.

use vstd::prelude::*;

verus! {

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

/// Balance available after this epoch's outgoing debit.
pub open spec fn spec_tail(pred: u64, deposit: u64, credit: u64, debit: u64) -> int {
    pred + deposit + credit - debit
}

/// A covered Amount is released in full; an uncovered Amount releases zero.
pub open spec fn spec_withdrawal(action: Action, tail: int) -> int {
    match action {
        Action::None => 0,
        Action::Amount(amount) => if amount <= tail { amount as int } else { 0 },
        Action::Close => tail,
    }
}

/// Credit to an absent account without a deposit is paid out externally.
pub open spec fn spec_payout(pred: u64, deposit: u64, credit: u64) -> int {
    if pred != 0 || deposit != 0 { 0 } else { credit as int }
}

/// Balance and output equations for an epoch's arithmetic inputs.
///
/// Eligibility, boundary coverage, vector bounds, and signature validation belong
/// to the full-close validator. The arithmetic predicate is total over u64 inputs,
/// including zero Amount values that the production boundary type excludes.
pub open spec fn valid_successor(
    pred: u64,
    succ: u64,
    output: Output,
    debit: u64,
    credit: u64,
    deposit: u64,
    action: Action,
) -> bool {
    let tail = spec_tail(pred, deposit, credit, debit);
    let withdrawal = spec_withdrawal(action, tail);
    let payout = spec_payout(pred, deposit, credit);
    &&& tail >= 0
    &&& withdrawal <= u64::MAX
    &&& succ + debit + withdrawal + payout == pred + credit + deposit
    &&& output == match action {
        Action::None => if payout != 0 { Output::ExternalPayout(payout as u64) } else {
            Output::None
        },
        _ => Output::Withdrawal(withdrawal as u64),
    }
}

/// Checked successor arithmetic, with failure represented by None.
pub fn derive_successor(
    pred: u64,
    debit: u64,
    credit: u64,
    deposit: u64,
    action: Action,
) -> (result: Option<(u64, Output)>)
    ensures
        result matches Some((succ, output))
            ==> valid_successor(pred, succ, output, debit, credit, deposit, action),
        result is None
            ==> forall|succ: u64, output: Output|
                !valid_successor(pred, succ, output, debit, credit, deposit, action),
{
    let available = pred as u128 + deposit as u128 + credit as u128;
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
    let registered = pred != 0 || deposit != 0;
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
    let output = match action {
        Action::None => if payout != 0 { Output::ExternalPayout(payout) } else { Output::None },
        _ => Output::Withdrawal(withdrawal_amount),
    };
    Some((balance, output))
}

/// Uniqueness: the equations admit at most one successor and output.
pub proof fn successor_is_unique(
    pred: u64,
    s1: u64,
    o1: Output,
    s2: u64,
    o2: Output,
    debit: u64,
    credit: u64,
    deposit: u64,
    action: Action,
)
    requires
        valid_successor(pred, s1, o1, debit, credit, deposit, action),
        valid_successor(pred, s2, o2, debit, credit, deposit, action),
    ensures
        s1 == s2,
        o1 == o2,
{
}

/// One activity row's balances and epoch-local flows.
pub struct Row {
    pub pred: u64,
    pub succ: u64,
    pub output: Output,
    pub debit: u64,
    pub credit: u64,
    pub deposit: u64,
    pub action: Action,
}

/// A withdrawal requires a registered account, as enforced by boundary validation.
pub open spec fn row_valid(row: Row) -> bool {
    (row.action == Action::None || row.pred != 0 || row.deposit != 0)
    && valid_successor(
        row.pred,
        row.succ,
        row.output,
        row.debit,
        row.credit,
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

/// The withdrawal reserve contribution encoded by an activity output.
pub open spec fn output_withdrawal(output: Output) -> int {
    match output {
        Output::Withdrawal(amount) => amount as int,
        _ => 0,
    }
}

/// The external payout reserve contribution encoded by an activity output.
pub open spec fn output_payout(output: Output) -> int {
    match output {
        Output::ExternalPayout(amount) => amount as int,
        _ => 0,
    }
}

/// Summing every valid row's balance equation: successor balances plus gross debit,
/// withdrawals, and payouts equal predecessor balances plus gross credit and deposits.
pub proof fn liability_conservation(rows: Seq<Row>)
    requires
        forall|i: int| 0 <= i < rows.len() ==> row_valid(#[trigger] rows[i]),
    ensures
        row_sum(rows, |row: Row| row.succ as int) + row_sum(
            rows,
            |row: Row| row.debit as int,
        ) + row_sum(rows, |row: Row| output_withdrawal(row.output)) + row_sum(
            rows,
            |row: Row| output_payout(row.output),
        ) == row_sum(rows, |row: Row| row.pred as int) + row_sum(
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
/// conservation, derived from the shared vector entries), successor liability equals
/// predecessor liability plus deposits minus the two classified output totals.
pub proof fn successor_liability(rows: Seq<Row>)
    requires
        forall|i: int| 0 <= i < rows.len() ==> row_valid(#[trigger] rows[i]),
        row_sum(rows, |row: Row| row.debit as int) == row_sum(
            rows,
            |row: Row| row.credit as int,
        ),
    ensures
        row_sum(rows, |row: Row| row.succ as int) == row_sum(
            rows,
            |row: Row| row.pred as int,
        ) + row_sum(rows, |row: Row| row.deposit as int) - row_sum(
            rows,
            |row: Row| output_withdrawal(row.output),
        ) - row_sum(rows, |row: Row| output_payout(row.output)),
{
    liability_conservation(rows);
}

/// Checked settlement liability arithmetic after gross payments cancel.
pub fn checked_successor_liability(
    predecessor: u64,
    deposits: u64,
    withdrawals: u64,
    payouts: u64,
) -> (result: Option<u64>)
    ensures
        result is Some ==> result->0 + withdrawals + payouts == predecessor + deposits,
        result is None ==> {
            let successor = predecessor + deposits - withdrawals - payouts;
            successor < 0 || successor > u64::MAX
        },
{
    let available = predecessor as u128 + deposits as u128;
    let successor = match available.checked_sub(withdrawals as u128) {
        Some(remaining) => remaining,
        None => {
            return None;
        }
    };
    let successor = match successor.checked_sub(payouts as u128) {
        Some(remaining) => remaining,
        None => {
            return None;
        }
    };
    if successor > u64::MAX as u128 {
        return None;
    }
    Some(successor as u64)
}

} // verus!

fn main() {}
