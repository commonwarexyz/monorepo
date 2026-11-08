//! Errors returned by Bajillion.

use super::Epoch;
use commonware_storage::{
    merkle::{mmb, mmr},
    qmdb,
};
use thiserror::Error;

/// Errors returned by Bajillion.
#[derive(Debug, Error)]
pub enum Error {
    /// An amount is zero.
    #[error("amount is zero")]
    ZeroAmount,
    /// An account or a soft withdrawal request appears more than once.
    #[error("account or withdrawal request appears more than once")]
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
    /// A message is for another epoch.
    #[error("wrong epoch: expected {expected}, found {found}")]
    WrongEpoch {
        /// The epoch expected.
        expected: Epoch,
        /// The epoch found.
        found: Epoch,
    },
    /// A user's signature does not verify, or covers a state the operator would not countersign.
    #[error("invalid user signature")]
    InvalidSignature,
    /// A close processes fewer queued requests than required or more than are queued.
    #[error("invalid number of queued requests")]
    InvalidCount,
    /// A receipt does not verify.
    #[error("invalid receipt")]
    InvalidReceipt,
    /// The operator's signature does not verify.
    #[error("invalid operator signature")]
    InvalidOperatorSignature,
    /// A close leaves a balance negative.
    #[error("negative balance")]
    Overdraft,
    /// A checkpoint, balances database, or proposal does not match the posted close it is used
    /// with.
    #[error("invalid checkpoint")]
    InvalidCheckpoint,
    /// The balances database failed.
    #[error("storage: {0}")]
    Storage(#[from] qmdb::Error<mmb::Family>),
    /// The payout log failed.
    #[error("payout log: {0}")]
    Log(#[from] qmdb::Error<mmr::Family>),
    /// A summary does not follow the last posted one.
    #[error("summary does not follow the last posted one")]
    WrongParent,
    /// A certificate does not verify.
    #[error("invalid certificate")]
    InvalidCertificate,
    /// A challenge does not contradict the posted close.
    #[error("challenge does not contradict the close")]
    NoContradiction,
}
