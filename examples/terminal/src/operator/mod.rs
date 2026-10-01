//! The operator role: application orchestration, the SQLite ledger, and RPC dispatch.
//!
//! # Close driver
//!
//! The close driver ([`crate::service::start_close_driver`]) runs one pass per poll. Before
//! serving RPC, startup retries passes until one succeeds or its attempt budget runs out. A pass
//! runs these steps and stops after submitting a registration:
//!
//! 1. Observe: record the certified inbox entries the operator has not observed.
//! 2. Reconcile: match cut epochs with certified admission, finality, and deployment faults,
//!    then discard withdrawal authorizations whose notice window has closed.
//! 3. Register: submit the live epoch's registration while the chain has none. Once it is
//!    certified, adopt it. When [`Operator::close_due`] holds, freeze the successor's boundary
//!    and submit its registration.
//! 4. Cut: resubmit the successor's registration until it is certified, then cut the live epoch
//!    and schedule its close.
//!
//! The cut is one SQLite transaction that freezes the live epoch's payments and installs the
//! certified successor as the live epoch. Payer vectors and deferred withdrawals resolve at the
//! cut. A worker builds each scheduled close, collects the committee certificate, retains it,
//! and submits `Admit`, blocking until certified admission. Closes run one at a time in epoch
//! order.
//!
//! The driver schedules the live epoch only while it holds a receipt, deposit, withdrawal, or
//! published registration. The successor is due four blocks after the live registration's
//! inclusion height, or once the live epoch holds its maximum payments or deposit events. An
//! admission offset under eight blocks shortens this delay to the offset minus four blocks,
//! floored at zero.
//!
//! # Restart
//!
//! A restarted operator resumes its earliest unfinished close job and reuses a retained
//! certificate. With a close job pending or its live registration adopted, it accepts no
//! payments or withdrawals until it authenticates the live epoch against settlement's
//! registration sequence and an adopted live registration against its certified record. A
//! mismatch fences the operator.

mod actor;
mod qmdb;
pub(crate) mod rpc;
mod store;
mod verify;

#[cfg(test)]
pub(crate) use actor::{CloseEvent, Stage};
pub(crate) use actor::{CloseStarted, DEFAULT_AMOUNT, Operator, SendsOutcome};
pub(crate) use store::{StagedDeposit, StagedWithdrawal};
pub(crate) use verify::{MAX_VERIFICATION_BATCHES, VerifiedSends, verify_sends};
