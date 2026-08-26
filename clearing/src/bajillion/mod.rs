//! Clear many-to-many payments with compact, challengeable settlement.
//!
//! This module implements the runtime-agnostic protocol objects, verification rules, and bounded
//! in-memory settlement transitions described by [Bajillion](https://commonware.xyz/blogs/clearing).
//! Operators, persistence, networking, clocks, and atomic asset-adapter integration are
//! deliberately left to applications.
//!
//! # Fault model
//!
//! The operator may halt, censor, equivocate, withhold messages, and propose arbitrary closes. It
//! cannot forge an account's signature. Hashes and signatures are assumed secure, validator
//! proofs of possession are authenticated before committee construction, and callers of
//! randomized batch verification must supply fresh cryptographic randomness.
//!
//! ## Certified public relation
//!
//! A validator does more than compare aggregate debit and credit. Before voting, it authenticates
//! its exact assigned [`transition::ProofSlice`] values: their layout and state ranges, every
//! changed row, terminal outgoing payment, terminal receive-shard head, boundary contribution,
//! prefix transition, state update, and signature. The terminal prefix then binds the exact vector
//! lengths, boundary totals, payment conservation, and closing liability.
//!
//! A committee has exactly `n = 3f + 1` validators, every slice has exactly `q = 2f + 1` holders,
//! and an admission certificate has exactly `q` signers. Assuming at most `f` Byzantine validators
//! and that each honest signer makes its [`admission::RetainedAssignment`] durable before releasing
//! its vote, quorum intersection leaves at least one honest certificate signer retaining every
//! slice. The honest signer can differ by slice. This proves the selected public corpus satisfies
//! the encoded relation; it does not prove that the operator never signed another private receipt.
//!
//! ## Payer sequencing and private evidence
//!
//! Each payer account is one linear cumulative-debit sequence. The base safety guarantee assumes a
//! wallet has at most one unacknowledged send for that account: it stages one exact
//! [`payment::SignedSend`], retries the same bytes after response loss, verifies and durably commits
//! the linked [`payment::Payment`], advances its locally owned debit, and only then signs the next
//! endpoint. This serializes one payer account, not independent payers or a recipient's receive
//! shards.
//!
//! A later cumulative endpoint authorizes the entire debit delta up to that endpoint, while a
//! public account row carries only its terminal outgoing payment. If a wallet signs later endpoints
//! before obtaining earlier receipts, an earlier receipt can be neither held privately nor selected
//! as the public terminal endpoint. That intentionally pipelined exposure is outside the base safety
//! guarantee.
//!
//! A send alone is not an accepted payment. The transferable evidence is the linked payer send and
//! operator receipt. Challenge submission has no caller identity requirement, so neither payer nor
//! recipient must remain continuously online. The actual assumption is per private receipt: at
//! least one honest holder must obtain and retain the required payment pair or pairs and get a
//! challenge included by the inclusive deadline. A recipient that wants an independently
//! enforceable preconfirmation must obtain that pair before relying on it; the protocol cannot
//! reconstruct a receipt that no independent holder received or retained.
//!
//! ## Availability and settlement
//!
//! Honest validators retain their assigned public slices through the challenge deadline, while the
//! embedding makes the root bundle, public corpus, and required Merkle openings retrievable. Users
//! must also retain or obtain later withdrawal, external-payout, and frozen-state claim openings;
//! the crate does not provide a data-availability network.
//!
//! Deposits do not depend on private receipt availability. Settlement records their refund account,
//! amount, and inclusion deadline; an expired unadmitted deposit permanently faults the operator
//! and is directly refundable without an operator or state opening.
//!
//! A clean close finalizes only after its inclusive challenge window, and a withdrawal becomes
//! claimable only after the close carrying it reaches the FIFO front and finalizes. A withdrawal's
//! absolute deadline is a permanent-fault trigger, not a payout timestamp. Safety additionally
//! assumes a correct and live settlement chain, one authenticated monotonic clock, immutable
//! deployment policy, and atomic, idempotent persistence of each state mutation with its custody
//! effect. Hard-fault recovery removes operator cooperation but not these evidence and settlement
//! assumptions.
//!
//! # State machine
//!
//! Bajillion has two coupled state machines. The off-chain machine constructs and authenticates a
//! close. The settlement machine registers its custody boundary, admits the certified commitment,
//! and either finalizes it or enters permanent hard-fault recovery. Certification alone never
//! changes settlement state or releases custody.
//!
//! ## Construct and certify a close
//!
//! ```text
//! +-----------------------+
//! | EpochContext          |  root-independent payment anchor and sealed
//! |                       |  deposit/withdrawal boundary roots
//! +-----------+-----------+
//!             | bind the exact opening StateCache root and liability
//!             v
//! +-----------------------+
//! | CloseContext          |
//! +-----------+-----------+
//!             | exact DepositBatch, WithdrawalBatch, opening StateCache,
//!             | and canonical rows/shard tips from accepted Payment pairs
//!             | prepare_close_with_strategy
//!             v
//! +-----------------------+
//! | PreparedClose         | ----> TerminalProof and later claim openings
//! | Header + RootBundle   | ----> validate if the corpus was not assembled
//! | retained Merkle trees |       from already accepted local payments
//! +-----------+-----------+
//!             | assemble_slices ("deal" every deterministic interval)
//!             v
//! +-----------------------+
//! | all ProofSlices       |
//! +-----------+-----------+
//!             | deterministic fan-out: every slice has exactly 2f+1 holders
//!             v
//! +-----------------------+
//! | validator dealing     |  exact canonical subset for one validator
//! +-----------+-----------+
//!             | seal
//!             | - authenticate every assigned slice
//!             | - batch-verify every distinct send/receipt signature
//!             v
//! +-----------------------+
//! | Vote                  |  publish only after durably retaining the
//! | RetainedAssignment    |  complete dealing through the challenge deadline
//! +-----------+-----------+
//!             | collect exactly 2f+1 distinct votes over the same Header
//!             v
//! +-----------------------+
//! | Certificate           |  aggregate signature plus signer bitmap
//! +-----------+-----------+
//!             | settlement admit also checks the registered context,
//!             | RootBundle, terminal proof, and certificate
//!             v
//!        [Pending close]
//!
//!   retained accepted Payment pair(s) + bounded authenticated openings
//!                             |
//!                             v
//!                  [Challenge against Pending]
//!                             |
//!                             +--> Proven(kind) ------> settlement hard fault
//!                             |
//!                             +--> NoContradiction or malformed evidence
//!                                  (no batch-status change)
//! ```
//!
//! [`transition::EpochContext`] deliberately excludes the opening state root so a projected
//! successor can serve while its predecessor closes. [`transition::EpochContext::bind`] creates
//! the canonical [`transition::CloseContext`] once the exact opening root is known. A
//! [`payment::Payment`] is a linked payer send and operator receipt; a bare send is not accepted
//! payment evidence. [`transition::prepare_close_with_strategy`] constructs the roots but does not
//! make untrusted rows valid. Call [`transition::PreparedClose::validate`] when the corpus was not
//! assembled from payments already checked by the application.
//!
//! "Deal" produces every [`transition::ProofSlice`]. Each slice is replicated to an exact quorum;
//! a validator's "dealing" is its complete assigned subset. [`admission::seal`] rejects any other
//! subset, authenticates its slices, and returns one [`admission::Vote`] plus the owned
//! [`admission::RetainedAssignment`]. The assignment must be durable before the vote is released.
//! The exact-quorum certificate authenticates the shared [`transition::Header`]; the separate
//! [`transition::TerminalProof`] authenticates terminal counts and totals but does not re-establish
//! certification or full-corpus validity.
//!
//! ## Settle pipelined closes
//!
//! `OPEN` below means that the single registration slot is empty. It does not mean that the
//! admitted pipeline is empty. Consequently, epoch `e + 1` can register and become admitted while
//! epoch `e` remains challengeable.
//!
//! ```text
//! +------------------------------- OPERATING ---------------------------------+
//! |                                                                           |
//! |  registration slot:                                                       |
//! |                                                                           |
//! |  +------+   register / register_epoch   +------------+                    |
//! |  | OPEN | ----------------------------> | REGISTERED |                    |
//! |  +--+---+                               +------+-----+                    |
//! |     ^                                          |                          |
//! |     | expire_unadmitted after                  | admit certified close    |
//! |     | the inclusive admission deadline        | and append at tail        |
//! |     +------------------------------------------+                          |
//! |                                                                           |
//! |  admitted FIFO pipeline (bounded by max_pending_epochs):                  |
//! |                                                                           |
//! |  finalized root -> [Pending e] -> [Pending e+1] -> ... -> [tail]          |
//! |                       |                                                   |
//! |                       +-- front and now > challenge deadline --> finalize |
//! |                           advance root/liability; create claim reserves   |
//! |                                                                           |
//! |  record_deposit and queue_withdrawal are accepted only while OPEN.        |
//! +---------------------------------------------------------------------------+
//!          |                                        |
//!          | proven challenge to any Pending        | an outstanding deposit or
//!          | (target -> Challenged; every later     | withdrawal reaches its
//!          |  close -> Invalidated)                 | inclusive deadline
//!          +----------------------+-----------------+
//!                                 v
//! +---------------------- HARD FAULT / PREFIX DRAIN --------------------------+
//! | New intake, registration, and admission are permanently fenced.           |
//! | The unadmitted registration is discarded; its boundary remains staged.    |
//! | Any earlier Pending prefix may still be challenged or finalized FIFO.     |
//! | A Challenged/Invalidated suffix never finalizes.                          |
//! | Staged deposits are directly refundable by account without a state proof. |
//! +--------------------------------+------------------------------------------+
//!                                  | begin_hard_fault_settlement once the
//!                                  | pipeline front is absent or non-Pending
//!                                  v
//! +------------------------- HARD FAULT / CLAIMING ---------------------------+
//! | Freeze the last finalized StateRoot and its liability.                    |
//! | Recover staged and invalid-suffix deposits/withdrawals from bounded state.|
//! | begin_hard_fault_settlement is idempotent while CLAIMING.                 |
//! | Zero remaining totals make begin transition directly to SETTLED.          |
//! |                                                                           |
//! | claim_hard_fault(StateOpening)                                            |
//! |   - consume each frozen state position once                               |
//! |   - route Amount or Close to its signed destination                       |
//! |   - return any residual frozen balance to the account                     |
//! |                                                                           |
//! | claim_pending_deposit(account)                                            |
//! |   - refund fixed account without operator cooperation or a state proof    |
//! +--------------------------------+------------------------------------------+
//!                                  | remaining frozen-state liability == 0
//!                                  | and remaining terminal deposits == 0
//!                                  v
//! +-------------------------- HARD FAULT / SETTLED ---------------------------+
//! | Active state and active custody are empty. The fault remains permanent.   |
//! | Claim reserves created by earlier clean finalizations remain independent. |
//! +---------------------------------------------------------------------------+
//! ```
//!
//! A challenge is accepted through its batch's inclusive challenge deadline; FIFO finalization
//! requires `now` to be strictly later. The four proof-to-fault edges are
//! [`challenge::Challenge::LatestAcknowledgedSend`],
//! [`challenge::Challenge::HigherShardTip`],
//! [`challenge::Challenge::InconsistentReceiptRange`], and
//! [`challenge::Challenge::ReceiptFork`]. [`challenge::Verdict::NoContradiction`] and malformed
//! evidence do not challenge a batch. An expired queued or admitted-but-unfinalized withdrawal,
//! an expired unadmitted deposit, or a proven challenge permanently fences the deployment. The
//! first fault reason is retained, although a later proof against an earlier pending prefix may
//! shorten the valid prefix.
//!
//! [`settlement::SettlementConfig`] fixes the admission-delay bound, challenge-duration range,
//! deposit inclusion timeout, and withdrawal notice range before the deployment accepts funds.
//! Registration deadlines must remain monotonic and inside that immutable policy.
//!
//! Every [`settlement::SettlementChain`] mutation that accepts `now` observes expired intake
//! obligations before performing its requested operation. The observation may therefore be the
//! method's only mutation even when it returns an error. The embedding must use one authenticated
//! monotonic clock and persist mutation-on-error results.
//!
//! ## Accounts, custody, and claims
//!
//! ```text
//!                         canonical transition row
//!                 +------------------------------------+
//!                 | opening state + deposit            |
//!                 | + accepted debit/credit endpoints  |
//!                 | + queued Amount or Close           |
//!                 +-----------------+------------------+
//!                                   |
//!                                   v
//!         +-------------------------+--------------------------+
//!         |                                                    |
//!         | absent + no deposit + credit -> external payout    |
//!         | absent + deposit              -> may create LIVE   |
//!         | LIVE + positive non-close tail -> remains LIVE     |
//!         | zero tail or Close             -> becomes ABSENT   |
//!         |                                                    |
//!         +-------------------------+--------------------------+
//!                                   |
//!                                   v
//!              exact-length closing StateRoot + ChangeRoot
//! ```
//!
//! State roots contain only sorted, active, positive-balance leaves; zero balances are omitted,
//! not retained as tombstones. An [`boundary::WithdrawalAction::Amount`] authorizes one exact
//! positive amount. [`boundary::WithdrawalAction::Close`] carries no amount, permits payment
//! activity through the epoch, then sweeps the authenticated epoch-tail balance and removes the
//! account. Credit to an absent account without a deposit remains outside live state and becomes
//! an external payout.
//!
//! Clean [`settlement::SettlementChain::finalize`] advances the finalized state and moves only the
//! aggregate withdrawal and external-payout totals from active custody into independent claim
//! reserves. [`settlement::SettlementChain::claim_withdrawal`] and
//! [`settlement::SettlementChain::claim_external_payout`] consume their authenticated positions
//! once and may run in any order without blocking later epochs. These reserves survive a later
//! hard fault. Hard-fault survivor claims and pending-deposit refunds instead drain active custody.
//! The embedding must atomically and idempotently persist every returned payout together with its
//! state-machine mutation.

pub mod admission;
pub mod boundary;
pub mod challenge;
pub mod commitment;
pub mod credit;
pub mod payment;
pub mod settlement;
pub mod state;
pub mod transition;
