//! Errors returned by Bajillion.

use super::Epoch;
use commonware_storage::{merkle::mmb, qmdb};
use thiserror::Error;

/// Errors returned by Bajillion.
#[derive(Debug, Error)]
pub enum Error {
    /// An amount is zero.
    #[error("amount is zero")]
    ZeroAmount,
    /// An account appears more than once.
    #[error("account appears more than once")]
    DuplicateAccount,
    /// Amounts have more entries than a tree can commit to.
    #[error("too many entries")]
    TooManyEntries,
    /// A batch or payment map pays no receiver.
    #[error("no receiver paid")]
    NoReceivers,
    /// An amount or epoch overflowed.
    #[error("arithmetic overflow")]
    Overflow,
    /// An opening does not verify.
    #[error("invalid opening")]
    InvalidOpening,
    /// An epoch is zero.
    #[error("epoch is zero")]
    ZeroEpoch,
    /// A message is for another epoch.
    #[error("wrong epoch: expected {expected}, found {found}")]
    WrongEpoch {
        /// The epoch expected.
        expected: Epoch,
        /// The epoch found.
        found: Epoch,
    },
    /// A sender already has a request pending.
    #[error("request pending")]
    Pending,
    /// A sender has no request pending.
    #[error("no request pending")]
    NotPending,
    /// A sender has already paid in a later epoch.
    #[error("already paid in a later epoch")]
    LaterEpoch,
    /// An acknowledgement does not countersign a state of the pending request.
    #[error("invalid acknowledgement")]
    InvalidAcknowledgement,
    /// A user's signature does not verify.
    #[error("invalid user signature")]
    InvalidSignature,
    /// A request exceeds the sender's live balance.
    #[error("insufficient balance")]
    InsufficientBalance,
    /// A close processes fewer queued requests than required or more than are queued.
    #[error("invalid number of queued requests")]
    InvalidCount,
    /// A receipt is for another receiver.
    #[error("receipt is for another receiver")]
    WrongReceiver,
    /// A receipt does not increase the amount received.
    #[error("receipt does not increase the amount received")]
    NotIncreasing,
    /// The close of the epoch has already posted.
    #[error("epoch already closed")]
    Closed,
    /// A receipt does not verify.
    #[error("invalid receipt")]
    InvalidReceipt,
    /// The operator's signature does not verify.
    #[error("invalid operator signature")]
    InvalidOperatorSignature,
    /// A close leaves a balance negative.
    #[error("negative balance")]
    Overdraft,
    /// A proposal does not follow the last applied close.
    #[error("proposal does not follow the last applied close")]
    StaleProposal,
    /// A checkpoint does not match its close or the stored balances.
    #[error("invalid checkpoint")]
    InvalidCheckpoint,
    /// The balances database failed.
    #[error("storage: {0}")]
    Storage(#[from] qmdb::Error<mmb::Family>),
    /// A summary does not follow the last posted one.
    #[error("summary does not follow the last posted one")]
    WrongParent,
    /// A certificate does not verify.
    #[error("invalid certificate")]
    InvalidCertificate,
    /// Payouts do not match their summary.
    #[error("payouts do not match the summary")]
    InvalidPayouts,
    /// The funds held cannot cover a payout or would exceed `u64::MAX`.
    #[error("custody exceeded")]
    Custody,
    /// No close has posted for the epoch.
    #[error("epoch not closed")]
    NotClosed,
    /// A challenge does not contradict the posted close.
    #[error("challenge does not contradict the close")]
    NoContradiction,
    /// The ledger has halted.
    #[error("ledger halted")]
    Halted,
    /// The ledger has not halted.
    #[error("ledger not halted")]
    NotHalted,
    /// An account has nothing left to refund.
    #[error("nothing to refund")]
    NothingToRefund,
    /// A balance proof does not verify.
    #[error("invalid balance proof")]
    InvalidBalanceProof,
}
