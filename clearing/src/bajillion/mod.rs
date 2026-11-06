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
//! Each deployment chooses the unsigned integer type of its amounts ([Amount]). This crate
//! implements it for `u64` and `u128`, and a deployment that settles EVM tokens can implement it
//! for a 256-bit integer.
//!
//! # Payments
//!
//! For every epoch, a [Sender] keeps a payment map ([Amounts]) from each receiver to the cumulative
//! amount the operator has countersigned for it. To pay a batch of receivers, the sender adds the
//! batch to its map and signs a [State] committing to the new map and to its map of the previous
//! epoch.
//!
//! ```text
//!    sender                             operator                            receiver
//!       |                                   |                                   |
//!       |--- Request(batch, signed state) ->|                                   |
//!       |                                   | fits the live balance?            |
//!       |<-- Acknowledgement or refusal ----|                                   |
//!       |                                   |                                   |
//!       |--- Receipt(state, cumulative amount, opening) ----------------------->|
//!       |                                   |                                   |
//! ```
//!
//! The [Operator] countersigns that same state if it is for the current epoch, extends the sender's
//! accepted maps, and fits the sender's live balance. The live balance is the sender's finalized
//! balance less everything it has paid in the current epoch, and less what the close still being
//! settled, if any, may take from it. Deposits and incoming payments become spendable once a close
//! processes them.
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
//! ```text
//!                               close(e) settles state(e)
//!                            +-------------------------------> paid in e, state(e+1) never settles
//!     pipelined request      |
//!     state(e), state(e+1) --+
//!                            |  close(e) leaves state(e) out
//!                            +-------------------------------> paid in e+1 by state(e+1)
//! ```
//!
//! # Closing an epoch
//!
//! A [Close] carries every sender's latest countersigned map with the sender's signature over its
//! state, the signed [Withdrawal]s the operator honors, and how many [Deposit]s and
//! [ForcedWithdrawal]s queued on the ledger it processes. The operator signs it and opens the next
//! epoch right away.
//!
//! ```text
//!   operator         validators                      ledger                 receivers
//!       |                 |                             |                       |
//!       |--- Close(e) --->|                             |                       |
//!       | opens e+1       | verify and settle           |                       |
//!       |                 |--- Summary + certificate -->|                       |
//!       |                 |                             | pays withdrawals      |
//!       |                 |<------------- posted(e) ----|--- posted(e) -------->|
//!       |                 | apply to QMDB               |                       | audit receipts
//!       |                 |                             |                       |
//!       |                 |                             |<------- Challenge ----| if underpaid
//!       |                 |                             | halts                 |
//! ```
//!
//! A [Validator] keeps the finalized balances in a QMDB and the payment [Matrix] of the last posted
//! close. It checks that the operator signed the close, that every map in it was signed by its
//! sender for that epoch on top of the map the last close settled for it, and that no balance goes
//! negative. Each account withdrawing is paid the lesser of its requested amount and its balance.
//!
//! Validators certify the resulting [Summary]. It chains to the summary before it and commits to
//! the payments, the new balances, the payouts, and how many queued requests the close processes.
//!
//! ```text
//!   Summary(e)
//!   +-------+--------+--------+----------+---------+----------+--------------------+
//!   | epoch | parent | matrix | balances | payouts | deposits | forced withdrawals |
//!   +-------+--------+--------+----------+---------+----------+--------------------+
//!               |        |          |          |        '--- how many ---'
//!               v        |          |          '--> BMT of H(account || payout)
//!         Summary(e-1)   |          '--> QMDB of balances by account
//!                        v
//!                   matrix root
//!                  /           \
//!     H(alice || a_root)     H(bob || b_root)    one leaf per sender
//!             |
//!             v
//!           a_root
//!          /      \
//!   H(bob || 5)  H(carol || 2)                   alice's payment map, one leaf per receiver
//! ```
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
//! ```text
//!        close(1)      close(2)      close(3)                   halt
//!   ---------+-------------+-------------+----------------------x---------> time
//!                          ^                                    |
//!                          '------ challenge against close(2) --'
//!
//!   validator --balance proof--> account --claim(proof)--> ledger --> balance as of close(3)
//!                                account --claim---------> ledger --> deposits no close processed
//! ```
//!
//! A challenge that lands after later closes posted still halts the ledger, and those closes stay
//! final. Epochs whose close never posted are discarded. A halted ledger accepts only claims, and
//! the operator plays no further part. Every account claims its balance at the last posted close
//! with a [BalanceProof] against that close's balances root, and claims the deposits no close
//! processed without one. Validators serve these proofs through [Validator::prove].
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
//! # Running a sharded operator
//!
//! One [Operator] can admit every account. A deployment whose traffic exceeds one machine splits
//! accounts across shards. Each shard is an [Operator] that serves the accounts the deployment
//! routes to it, such as a range of key hashes. Only the deployment's router knows which shard
//! serves an account. A shard holds no partition and processes what it is sent, so shards admit in
//! parallel without coordinating.
//!
//! Each shard countersigns the requests it admits as they arrive, so every shard holds the
//! operator's signing key.
//!
//! Each shard admits within its own [Limits], while validators decode the close with theirs. A
//! deployment therefore gives each shard limits whose senders and soft withdrawals sum to at most
//! the validators', with the same receivers per sender. When shards outnumber the senders a close
//! may hold, as with one shard per account, the deployment's router keeps each epoch's senders and
//! soft withdrawals within the validators' limits.
//!
//! An epoch ends in three steps. Each shard cuts the epoch with [Operator::cut], given the forced
//! withdrawals the close processes for its accounts. The cut freezes what the shard admitted into a
//! [Cut], and the shard opens the next epoch at once. A builder assembles the shards' cuts into the
//! [Close] with [Close::assemble], on any thread or machine, and sums the [Flow] of every account
//! the close touches. The deployment routes each flow to the shard serving its account in the next
//! epoch, and each shard settles its flows with [Operator::settle].
//!
//! A deployment with one operator does all three with [Operator::close].
//!
//! ```text
//!             epoch e       cut(e)   e+1, against the floor     settle(e)   e+1, exact
//!   shard 1   accept .....>   x  ----> accept ...............>      s  ----> accept ...
//!   shard 2   accept .....>   x  ----> accept ...............>      s  ----> accept ...
//!                             |                                     ^
//!                             | cuts                                | flows, by shard in e+1
//!                             v                                     |
//!   builder              assemble(e) -------------------------------'
//!                             |  merge rows, matrix root, sign, sum flows
//!                             v
//!                          Close(e) ----> validators
//! ```
//!
//! Until a shard settles an epoch, it does not know what the epoch left in each balance, because
//! credits from other shards are summed only at assembly. Meanwhile it admits the next epoch
//! against a floor. At the cut, it deducts from each account active in the epoch everything the
//! close may take from it. That is what the account paid in the epoch and the withdrawals it asked
//! for, soft and forced.
//!
//! The floor is the account's balance as of the last epoch settled (B below) less these deductions.
//! Credits only add and payouts never exceed the requests, so the close leaves at least the floor.
//! It leaves exactly the floor plus the account's credits whenever the floor is above zero.
//!
//! ```text
//!                 0                        floor                             B
//!   at cut(e)     |===========|============|---------------------------------|
//!                  paid in e+1  live        deductions of e
//!                                          |
//!   at settle(e)  |========================|++++++++++|
//!                                           credits
//!                 |<------- balance after e -------->|
//! ```
//!
//! A shard settles each epoch before it cuts the next. The builder has the flows as soon as it
//! assembles the close, while the ledger reports the queues of the next close only once it posts
//! this one, so the next cut never waits on a settle.
//!
//! ```text
//!             cut(e)                         settle(e)                 cut(e+1)
//!   shard  ----x--------------------------------s-------------------------x------> time
//!              |  e+1 against the floor         ^  e+1 against the        ^
//!              v                                |  exact balance          |
//!   builder  assemble(e) ------- flows ---------'                         |
//!              |                                                          |
//!              v                                                          |
//!   ledger   Close(e) ---> certified ---> posted(e) --- queues of e+1 ----'
//! ```
//!
//! Each flow names its epoch, and a shard refuses flows of another. It also refuses, with
//! [Error::MissingFlow], flows that leave out an account it deducted from. Lifting that deduction
//! without applying what the close took would let the account spend it twice. A missing flow that
//! only credits its account goes unnoticed. It leaves the account's stored balance below the
//! validators', and that only holds the account back.
//!
//! ## Shards that skip epochs
//!
//! A shard takes part in an epoch only when it has something to do in it, so a deployment may run
//! as many shards as it has accounts. A shard cuts an epoch if it admitted payments or soft
//! withdrawals in it, or serves an account whose forced withdrawal the close processes. It settles
//! the epoch if it cut it or a flow reaches it. Every other shard skips the epoch, and the close of
//! an epoch no shard cuts only processes the ledger's queues.
//!
//! A shard admits an epoch until it is cut, so before assembling epoch `e`, no shard may still
//! admit `e`. With several routers, or clients that reach shards directly, the deployment cuts
//! every shard whose current epoch is `e`. A single router that handles every account can instead
//! stop forwarding requests of `e`, drain those in flight, and cut every shard it forwarded one to.
//! A payment admitted by a shard left out would be missing from the close, and its receiver's
//! challenge would halt the ledger.
//!
//! A shard that skipped an epoch settles the flows that reach it without a cut, as long as they
//! only credit its accounts. Before a shard that skipped epochs takes part again, it catches up by
//! settling the epoch before, with no flows. It does so only once that epoch's flows reached it, so
//! a shard behind the current epoch admits a request of it only after the flows of the epoch
//! before. Either settle records its epoch in the store and opens the epoch after it, so one call
//! skips any number of epochs. The deployment chooses the epoch, never a request.
//!
//! ```text
//!               epoch 5                 epoch 6                    epoch 7
//!   shard a   pay ...> x ---> s       .   .   .   .   .   .      s(6) --> pay ...> x ---> s
//!   shard b   .   .   .   .   .       s <--- credit              .   .   .   .   .   .   .
//!   shard c   .   .   .   .   .       s(5) --> x ---> s          .   .   .   .   .   .   .
//!                                              ^
//!                                              forced withdrawal of c's account
//!
//!   x  cut      s  settle      s(e)  catch-up settle of epoch e, with no flows
//! ```
//!
//! A catch-up settle records its epoch, so the deployment delivers an epoch's flows to the shard of
//! every account they touch before it lets any shard catch up past that epoch. Delivering the flows
//! right after assembly, before announcing the next epoch, does that.
//!
//! A shard ignores a repeated settle of the latest epoch its store includes, and refuses a settle
//! of an older one with [Error::Late]. A credit that arrives after its shard caught up past the
//! epoch is therefore lost, and the account's stored balance stays below the validators'. That
//! holds the account back but never lets it overspend. A flow that takes from its account and
//! arrives that late returns [Error::MissingCut], because the shard did not cut the epoch.
//!
//! ## Balance stores
//!
//! Each shard keeps its finalized balances in a [Balances] store. The store may hold every account
//! of a large deployment, while the shard holds in memory only what the current epoch and its last
//! cut involve. It reads a balance from the store when an account first pays or settles, and caches
//! it while either involves the account.
//!
//! ```text
//!   operator memory, bounded by activity              store, every finalized balance
//!   +------------------------------------+           +------------------------------+
//!   | payment maps of the current epoch  |   get     | balance of each account      |
//!   | roots of the previous maps         | <-------- |                              |
//!   | floor deductions of the last cut   |           | epoch of the last close      |
//!   | cached balances of active accounts | --------> | this shard wrote             |
//!   +------------------------------------+   put     +------------------------------+
//! ```
//!
//! Settling reads the previous balance of every account in the shard's flows, applies the rule
//! validators apply, and writes the new balances to the store with the epoch. The epoch's
//! deductions drop only once that write completes. A shard that fails or restarts before then still
//! holds them, and one that restarts after starts from balances that include the epoch.
//!
//! ```text
//!              get            apply the rule          put(e)          drop deductions of e
//!   shard  -----x-------------------x---------------------x------------------x--------> time
//!               ^                                         |
//!               | balances after e-1                      v  balances after e, epoch e
//!   store  -----'-----------------------------------------x-----------------------------> time
//!          |<---- a restart here holds the deductions --->|<-- a restart here starts at e ->
//! ```
//!
//! Only the shard's own settles write the epoch its store records. The shard reads that epoch when
//! it starts, and passes the epoch it last read or wrote with each put. The store checks it in the
//! same transaction as its writes, so if another writer or a stale process has moved the store's
//! epoch, the shard's put fails without writing and leaves the shard failed.
//!
//! ## Moving accounts between shards
//!
//! Each account is served by one shard in each epoch. The deployment routes the account's requests,
//! soft withdrawals, and processed forced withdrawals of an epoch to the shard serving it in that
//! epoch, and the account's flow of the epoch to the shard serving it in the next. The two differ
//! only for an account that moves at the epoch's cut.
//!
//! An account moves to another shard only at a cut, and only if it was idle in the epoch being cut,
//! with no payments, soft withdrawals, or processed forced withdrawals. No shard then holds a
//! deduction for it, and its payment map in the epoch is empty. Its new shard reads its stored
//! balance and admits it at once, and its next states commit to an empty previous map, as
//! validators expect. Its flow of the epoch can only credit it, so admitting it before the new
//! shard settles that flow only holds it back.
//!
//! The stored balance must include every flow the old shard settles for the account. The last of
//! these is of the epoch before the move. A shard settles each epoch before it cuts the next, so
//! this holds whenever the old shard cut the epoch of the move. Otherwise, if the old shard cut the
//! epoch before or received flows of it, the deployment waits for that settle before it routes the
//! account to the new shard. With a store per shard, it then copies the account's balance to the
//! new shard's store.
//!
//! ```text
//!                   epoch e      cut(e)      epoch e+1       cut(e+1)     epoch e+2
//!   shard 1   B pays ............> x --- s --- B held ------------------------------------> time
//!   shard 2   .   .   .   .   .   .  A pays at once ..........> x --- B pays at once -----> time
//!                                  ^                            ^
//!                                  A moves, idle in e           B moves, idle in e+1
//!
//!   x  cut      s  settle of e
//! ```
//!
//! A new shard cannot know an active account's deductions or its payment map in the epoch. Only the
//! old shard's cut holds the deductions, and the account's next states commit to the map. To move
//! an active account, the deployment holds its requests for one epoch, so the account is idle in
//! it, and moves it at that epoch's cut. If the close of that epoch processes a forced withdrawal
//! of the account, the account is active in it and waits another epoch.
//!
//! Moving an active account early comes to light at its old shard. That shard's cut deducted from
//! the account, and the account's flow goes to the new shard, so the old shard's settle returns
//! [Error::MissingFlow]. The new shard may by then have admitted the account against a balance that
//! misses what the epoch took.
//!
//! # Persistence
//!
//! The types in this module are in-memory state machines, except for the balances each validator
//! keeps in QMDB and each operator keeps in its [Balances] store. Applications persist the rest and
//! must order it with what they release:
//!
//! - A sender persists each request before sending it. It persists each acknowledged payment map,
//!   and clears the request in the same write, before releasing receipts. It resumes with
//!   [Sender::resume].
//! - The operator, or each shard of it, persists each request and soft withdrawal before
//!   acknowledging it, and each cut before acknowledging a request of the next epoch.
//!   [Operator::settle] writes the balances an epoch leaves to the store before it drops the
//!   epoch's deductions, and a failed write leaves the operator failed. The operator restarts with
//!   [Operator::init] from its store and its last cut, reading the store's epoch to tell whether
//!   that cut settled. [Operator::close] returns no cut, so an operator that closes with it passes
//!   the rows of the matrix of the last close the store includes. It then replays the current
//!   epoch's requests and soft withdrawals.
//! - The builder persists each close and its flows before releasing the close or routing a flow.
//!   After the ledger posts the close, it holds none of the requests the close processed, so the
//!   close and its flows cannot be rebuilt from it.
//! - A receiver persists a receipt before relying on it. It resumes with [Receiver::resume].
//! - A validator persists a close before releasing its attestation and before applying it. It
//!   retains every posted close while receivers may still request openings of it, and resumes with
//!   [Validator::init].
//! - The ledger applies a posted close and transfers its payouts atomically. It is deterministic,
//!   so replaying its operations in order rebuilds it.
//!
//! Messages between the shards, the builder, and the stores can fail, so every step of a sharded
//! operator can be retried. A shard answers a repeated cut request from the cut it persisted.
//! Assembly is deterministic, and the builder persists the close and its flows before releasing
//! them, so resent flows are the same. A repeated settle of the latest epoch the shard settled
//! returns without effect, and accepting a request or collecting a soft withdrawal again has no
//! effect either.
//!
//! A sharded deployment also keeps contracts the crate cannot check:
//!
//! - The close of an epoch holds the cut of every shard that admitted payments or soft withdrawals,
//!   or serves an account whose forced withdrawal it processes. A close missing a shard's cut omits
//!   payments that shard preconfirmed, so a receiver's challenge halts the ledger. That shard's
//!   settle also returns [Error::MissingFlow] when an account it deducted from has no flow.
//! - The shards' limits on senders and soft withdrawals sum to at most the validators', with the
//!   same limit on receivers per sender, or the router keeps each epoch's senders and soft
//!   withdrawals within the validators' limits.
//! - Before assembling an epoch, no shard may still admit it. The deployment cuts every shard whose
//!   current epoch it is, or, with a single router, stops forwarding the epoch's requests, drains
//!   those in flight, and cuts every shard it forwarded one to.
//! - Each account is served by one shard in each epoch. That shard receives the account's requests,
//!   soft withdrawals, and processed forced withdrawals of the epoch, and its flow of the epoch
//!   before. Each shard's cut is given exactly the processed forced withdrawals of its accounts.
//!   Assembly refuses an account that pays or withdraws in two cuts, but cannot check the rest.
//! - An account moves to another shard only at a cut, only if it was idle in the epoch being cut,
//!   and only once its stored balance includes every flow its old shard settles for it.
//! - The deployment delivers an epoch's flows before any shard catches up past that epoch. A shard
//!   receives its flows of an epoch in one settle, and a retry carries the same flows, because the
//!   first settle of an epoch is final.

mod amounts;
mod balances;
mod close;
mod cut;
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

pub use amounts::{Amount, Amounts};
pub use balances::{Balances, MemoryBalances};
pub use close::{Close, Deposit, ForcedWithdrawal, Limits, Queue, Row, Withdrawal};
pub use cut::Cut;
pub use error::Error;
pub use ledger::{Halt, Ledger};
pub use lookup::Lookup;
pub use matrix::{Matrix, Opening};
pub use namespace::Namespace;
pub use operator::Operator;
pub use payment::{Acknowledgement, Challenge, Receipt, Request, State};
pub use receiver::Receiver;
pub use sender::{Outcome, Sender};
pub use settlement::Flow;
pub use summary::{Scheme, Summary};
pub use validator::{BalanceProof, Checkpoint, Config, Proposal, Validator};

/// An epoch number. Epochs start at one, and epoch zero names the state before the first close.
pub type Epoch = u64;
