//! Clear payments between many accounts and settle each epoch's net effect at once.
//!
//! Bajillion runs between users, an operator, a committee of validators, and a ledger that holds
//! deposited funds. Users pay each other through the operator, and the operator preconfirms each
//! payment by countersigning it. To end an epoch, the operator closes it. Validators check the
//! close against the finalized balances and certify a [Summary] of its effects, and the [Ledger]
//! posts the summary once a certificate verifies over it.
//!
//! A posted close finalizes its epoch at once, with no challenge period. Balances update and
//! withdrawals pay out as soon as the close posts.
//!
//! # Payments
//!
//! For every epoch, a [Sender] keeps a payment map ([Amounts]) from each receiver to the cumulative
//! amount the operator has countersigned for it. To pay a batch of receivers, the sender adds the
//! batch to its map and signs a [State] committing to the new map and to its map of the previous
//! epoch.
//!
//! The [Operator] countersigns that same state if it is for the current epoch, extends the
//! sender's accepted maps, and fits the sender's live balance. The live balance is the sender's
//! finalized balance less everything it has paid in the current epoch. Deposits and incoming
//! payments become spendable once a close processes them.
//!
//! The sender then gives each receiver a [Receipt] holding the countersigned state and an opening
//! of the receiver's cumulative amount. A receipt preconfirms the payment. The close of its epoch
//! credits at least that amount, or the ledger halts.
//!
//! A sender keeps at most one [Request] pending. A pipelined request signs two states, one for its
//! epoch and one for the next, so a payment refused because its epoch just closed settles in the
//! next epoch without a new request. Each state commits to the sender's map of the preceding epoch,
//! so a close that settles one of the two states makes the other unsettleable.
//!
//! # Closing an epoch
//!
//! A [Close] carries every sender's latest countersigned map with the sender's signature over its
//! state, the signed [Withdrawal]s the operator honors, and how many [Deposit]s and
//! [ForcedWithdrawal]s queued on the ledger it processes. The operator signs it and opens the next
//! epoch right away, while the close is checked and posted.
//!
//! A [Validator] keeps the finalized balances in a QMDB and the payment [Matrix] of the last posted
//! close. It checks that the operator signed the close, that every map in it was signed by its
//! sender for that epoch on top of the map the last close settled for it, and that no balance goes
//! negative. Each account withdrawing is paid the lesser of its requested amount and its balance.
//!
//! The validator certifies the resulting [Summary]. A summary binds the epoch, the summary it
//! follows, the payment matrix root, the new balances root, the payouts root, and the processed
//! queue counts.
//!
//! The [Ledger] posts a close once its summary follows the last posted one and a certificate
//! verifies over it. It pays the payouts and removes the processed requests from its queues. The
//! close of an epoch must process every request queued before that epoch opened.
//!
//! # Challenges and halts
//!
//! A close can omit payments the operator preconfirmed. After a close posts, a [Receiver] opens the
//! posted matrix at its entry for every sender it holds receipts from. If the posted amount is
//! lower than a receipt, it submits a [Challenge] and the ledger halts.
//!
//! A halted ledger refunds every account its balance at the last posted close, proven against that
//! close's balances root, and its deposits no close processed. A challenge that lands after later
//! closes posted still halts the ledger, and those closes stay final.
//!
//! # Trust model
//!
//! The operator may be malicious. It cannot debit a sender beyond what the sender signed for the
//! epoch, pay out a withdrawal its account did not request, or credit the wrong account. It can
//! refuse payments and soft withdrawals, and users can still withdraw through the ledger. If it
//! omits preconfirmed payments from a close, a receiver's challenge halts the ledger.
//!
//! At most `f` validators may be Byzantine. The deployment chooses the certificate scheme and its
//! fault model, and the scheme's quorum must exceed `f` while honest validators alone must still
//! reach it. Every certificate then includes an honest validator that checked the close and keeps
//! the data needed to open its matrix and to apply it.
//!
//! # Persistence
//!
//! The types in this module are in-memory state machines, except for the balances each validator
//! keeps in QMDB. Applications persist the rest and must order it with what they release:
//!
//! - A sender persists each request before sending it. It persists each acknowledged payment map,
//!   and clears the request in the same write, before releasing receipts. It resumes with
//!   [Sender::resume].
//! - The operator persists each request and soft withdrawal it accepts before confirming it, and
//!   each close with the balances it leaves before opening the next epoch. It resumes with
//!   [Operator::resume] and replays the current epoch's requests and soft withdrawals.
//! - A receiver persists a receipt before relying on it. It resumes with [Receiver::resume].
//! - A validator persists a close before releasing its attestation and before applying it. It
//!   retains every posted close while receivers may still request openings of it, and resumes with
//!   [Validator::init].
//! - The ledger applies a posted close and transfers its payouts atomically. It is deterministic,
//!   so replaying its operations in order rebuilds it.

mod amounts;
mod close;
mod error;
mod ledger;
mod lookup;
mod matrix;
mod namespace;
mod operator;
mod payment;
mod receiver;
mod sender;
mod settlement;
mod summary;
#[cfg(test)]
mod tests;
mod validator;

pub use amounts::Amounts;
pub use close::{Close, Deposit, ForcedWithdrawal, Limits, Queue, Row, Withdrawal};
pub use error::Error;
pub use ledger::{Halt, Ledger};
pub use lookup::Lookup;
pub use matrix::{Matrix, Opening};
pub use namespace::Namespace;
pub use operator::Operator;
pub use payment::{Acknowledgement, Challenge, Receipt, Request, State};
pub use receiver::Receiver;
pub use sender::{Outcome, Sender};
pub use summary::{Scheme, Summary};
pub use validator::{BalanceProof, Checkpoint, Config, Proposal, Validator};

/// An epoch number. Epochs start at one, and epoch zero names the state before the first close.
pub type Epoch = u64;
