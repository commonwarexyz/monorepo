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
//! its exact assigned [`transition::ProofSlice`] values: their coverage and state ranges, every
//! changed row, terminal payer-signed vector endpoint, outgoing vector, transpose interval,
//! accumulator transition, boundary contribution, prefix transition, state update, the slice's
//! combined operator countersignature, and every payer signature. The terminal boundary then
//! binds the exact vector lengths, boundary totals, payment conservation, the multiset equality
//! between the two edge orderings, and successor liability.
//!
//! A committee has exactly `n = 3f + 1` validators, every slice has exactly `q = 2f + 1` holders,
//! and an admission certificate has exactly `q` signers. Assuming at most `f` Byzantine validators
//! and that each honest signer makes its [`admission::SealedDealing`] durable before releasing
//! its vote, quorum intersection leaves at least one honest certificate signer retaining every
//! slice. The honest signer can differ by slice. This proves the selected public corpus satisfies
//! the encoded relation. It does not prove that the operator never signed another private receipt.
//!
//! ## Payer sequencing and private evidence
//!
//! Each payer account is one linear cumulative-debit sequence over one strictly
//! recipient-sorted, epoch-cumulative outgoing vector ([`vector::OutVector`]). A batch adds
//! delta entries to that vector, and the payer authorizes it by signing one
//! [`payment::VectorSendBody`]: the epoch-local batch sequence number, the lifetime cumulative
//! debit endpoint, and the vector root ([`payment::SendAuthorization`]). The batch is accepted
//! or rejected as a whole and advances the sequence by exactly its total. The operator accepts
//! by countersigning the identical body, once for the dual-signed receipt
//! ([`payment::VectorAck`]) and once, aggregably, for the close's per-slice countersignatures.
//!
//! The base safety guarantee assumes a wallet has at most one unacknowledged batch for that
//! account: it stages one exact [`payment::SendAuthorization`], retries the same bytes after
//! response loss, verifies and durably commits its acknowledgment and per-entry openings,
//! advances its locally owned debit, and only then signs the next endpoint. This serializes one
//! payer account, not independent payers or recipients.
//!
//! A later cumulative endpoint authorizes the entire debit delta up to that endpoint, while a
//! public account row carries only its terminal endpoint. An authorization alone is not an
//! accepted payment. The transferable per-edge evidence is one [`payment::EntryReceipt`]: the
//! dual-signed acknowledgment plus one membership opening of the credited recipient's
//! cumulative entry under the acknowledged vector root. Challenge submission has no caller
//! identity requirement, so neither payer nor recipient must remain continuously online. The
//! actual assumption is per private receipt: at least one honest holder must obtain and retain
//! the required evidence and get a challenge included by the inclusive deadline. A recipient
//! that wants an independently enforceable preconfirmation must obtain its entry receipt before
//! relying on it. The protocol cannot reconstruct a receipt that no independent holder received
//! or retained.
//!
//! ## Availability and settlement
//!
//! Honest validators retain their assigned public slices through the challenge deadline, while the
//! embedding makes the root bundle, public corpus, and required Merkle openings retrievable. Users
//! must also retain or obtain later withdrawal, external-payout, and frozen-state claim openings.
//! The crate does not provide a data-availability network.
//!
//! Deposits do not depend on private receipt availability. Settlement records their refund account,
//! amount, and inclusion deadline. An expired unadmitted deposit permanently faults the operator
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
//! Bajillion has three coupled state machines: a registered epoch collects payments and constructs
//! one close, validators certify that close, and settlement admits or rejects its custody
//! transition. Finalized withdrawal and external-payout reserves form a separate claim ledger.
//! Certification alone never changes settlement state or releases custody.
//!
//! [`transition::CloseContext`] owns the predecessor state root. [`transition::RootBundle`] holds
//! the change, withdrawal-output, successor-state, coverage, and transpose roots plus the exact
//! transpose leaf count, and [`transition::Header`] binds all of those contextual roles. The
//! posted corpus ships movers and edges only ([`posted`]): readers hold the previous certified
//! state as a [`posted::Replica`], live accounts ride as rank gaps, and the transpose,
//! predecessor states, successor states, and prefixes are all derived rather than shipped.
//! Dealt slices travel without their unchanged state ([`retained`]): every slice assignee
//! retains its key interval across closes and hydrates each dealing against it.
//!
//! Arrows below are successful transitions. Ordinary validation failure leaves the requested state
//! unchanged. A call carrying `now` is the exception: it first observes every liveness deadline,
//! so it can record a permanent fault and then return an error for the requested operation.
//!
//! ## Register, construct, certify, and admit
//!
//! ```text
//! SETTLEMENT                                  EPOCH / CERTIFICATION
//! ----------                                  ---------------------
//! +-------------------------+
//! | OPEN registration slot  |  no registration heartbeat
//! | finalized head (R,L,e)  |
//! | staged deposits D       |
//! | staged withdrawals W    |
//! +------------+------------+
//!              | EpochContext E commits the payment anchor, D/W roots,
//!              | predecessor liability L, deadlines, limits, and assignment.
//!              | register_epoch binds R; register_close accepts an already-bound C.
//!              v
//! +-------------------------+                 +-----------------------------+
//! | REGISTERED              |---------------->| CloseContext C = E + R      |
//! | exact C; derived D;     |                 | PaymentContext: anchor,e,op |
//! | W superset; deadline A  |                 +--------------+--------------+
//! +------+------------------+                                |
//!        |                                                   | only now may the
//!        |                                                   | operator release
//!        |                                                   | accepted Payment
//!        |                                                   | pairs
//!        |                                                   v
//!        |                                    +-----------------------------+
//!        |                                    | C + predecessor StateCache  |
//!        |                                    | + exact D/W + rows/vectors  |
//!        |                                    | prepare_close_with_strategy |
//!        |                                    v                             |
//!        |                                    | PreparedClose               |
//!        |                                    | Header + RootBundle         |
//!        |                                    | five retained Merkle trees  |
//!        |                                    +--------------+--------------+
//!        |                                                   |
//!        |                                    assemble_slices | + StateCache
//!        |                                                   v
//!        |                                    +-----------------------------+
//!        |                                    | every ProofSlice            |
//!        |                                    +--------------+--------------+
//!        |                                                   |
//!        |                                    exact deterministic dealing
//!        |                                    for each validator
//!        |                                                   v
//!        |                                    +-----------------------------+
//!        |                                    | seal                        |
//!        |                                    | - authenticate every slice  |
//!        |                                    |   and its combined operator |
//!        |                                    |   countersignature          |
//!        |                                    | - one randomized batch for  |
//!        |                                    |   every distinct payer      |
//!        |                                    |   authorization signature   |
//!        |                                    +------+----------------------+
//!        |                                           |
//!        |                              +------------+------------+
//!        |                              v                         v
//!        |                    SealedDealing                     Vote
//!        |                    durable through the                 |
//!        |                    challenge deadline                  | publish only
//!        |                                                        | after retention
//!        |                                                        v
//!        |                                             exactly 2f+1 votes
//!        |                                             over one Header
//!        |                                                        |
//!        |                                                        v
//!        |                                             +-------------------+
//!        |                                             | Certificate       |
//!        |                                             +---------+---------+
//!        |                                                       |
//!        |<----- Header + RootBundle + TerminalProof + Certificate
//!        |
//!        | admit while now <= A; consume registration and included boundary
//!        v
//! +-------------------------+
//! | OPEN + Pending(e) tail  |
//! +-------------------------+
//!
//! REGISTERED -- first time observation with now > A --> PERMANENT HARD FAULT
//! ```
//!
//! [`transition::EpochContext`] is predecessor-state-root-independent, not liability-independent.
//! This lets the same payment anchor serve while its predecessor closes. [`transition::CloseContext`]
//! adds the exact root and verifies the already-committed liability. The embedding must release no
//! operator-signed acknowledgment until that exact context has registered successfully. A
//! [`payment::EntryReceipt`] is the dual-signed acknowledgment plus one entry opening. A bare
//! authorization is not accepted payment evidence.
//!
//! Registration activates an immutable, one-shot payment context. `max_admission_delay` bounds
//! that context's publication window. It is not a periodic heartbeat while the slot is `OPEN`.
//! Failed construction, certification, or admission can retry against the same registration through
//! its inclusive deadline. Afterward the context cannot be rebased because its deadline is part of
//! the payment anchor, so observing the missed deadline permanently faults the deployment and
//! retains that exact anchor in the fault reason. Payments from a close that was never admitted do
//! not enter state. Terminal recovery freezes and settles against the last root reached by the
//! valid finalized prefix.
//!
//! [`transition::prepare_close_with_strategy`] constructs the five trees but does not make arbitrary
//! untrusted rows valid. Call [`transition::PreparedClose::validate`] when the application did not
//! assemble the corpus from inputs it already validated. Prepared state retains the change,
//! withdrawal-output, successor-state, coverage, and transpose trees. Dealing still borrows the
//! predecessor [`transition::StateCache`]. Settlement admission sees the registered context, typed
//! roots, terminal proof, and certificate, not the full corpus or every slice.
//!
//! "Deal" produces every [`transition::ProofSlice`]. Each slice is replicated to an exact
//! quorum. A validator's "dealing" is its complete assigned subset. [`admission::seal`] rejects any other
//! subset, authenticates its slices, and returns one [`admission::Vote`] plus the owned
//! [`admission::SealedDealing`]. The dealing must be durable before the vote is released.
//! The exact-quorum certificate authenticates the shared [`transition::Header`]. The separate
//! [`transition::TerminalProof`] authenticates terminal counts and totals but does not re-establish
//! certification or full-corpus validity.
//!
//! ## Authenticate gap-free proof slices
//!
//! For `S` slices, the coverage tree has exactly `S + 1` boundary leaves. Boundary `B[i]`
//! authenticates positions in the predecessor-state, change, and successor-state vectors together
//! with a cumulative prefix. Each slice opens the same boundary used by its neighbor, making local
//! interval checks compose into one global relation.
//!
//! ```text
//! CoverageRoot
//!     |
//!     +-- B[0] ---- B[1] ---- B[2] ---- ... ---- B[S]
//!         default     ^          ^                   terminal lengths,
//!                     |          |                   totals, liability
//!                     +----------+
//!                     shared authenticated boundary
//!
//! slice i opens B[i] and B[i+1], then authenticates exactly:
//!
//!   predecessor StateRoot  [B[i].predecessor .. B[i+1].predecessor)
//!   ChangeRoot             [B[i].change   .. B[i+1].change)
//!   successor StateRoot    [B[i].successor   .. B[i+1].successor)
//!   WithdrawalOutputRoot   [prefix[i].withdrawal_count .. prefix[i+1].withdrawal_count)
//!
//! Ordered guards prove both sides of each disclosed state/change range.
//! Typed openings bind root role, vector length, position, and hash domain.
//! B[i+1] is literally the next slice's B[i], so no certified gap can be hidden.
//! ```
//!
//! The [`transition::CoverageRange`] openings establish adjacency, while the three content roots
//! and the withdrawal-output root authenticate the interval contents. `B[0]` pins the empty
//! prefix. `B[S]` pins every vector length, boundary total, conservation total, and successor
//! liability. This is why local ordered range guards cannot replace the `CoverageRoot`.
//!
//! ## Settle pipelined closes
//!
//! `OPEN` below means that the single registration slot is empty. It does not mean that the
//! admitted pipeline is empty. Consequently, epoch `e + 1` can register and become admitted while
//! epoch `e` remains challengeable. Registration must always name the exact successor of the
//! pipeline tail (or the finalized head when the pipeline is empty), and finalization consumes the
//! FIFO front, so neither path can skip an epoch.
//!
//! ```text
//! +------------------------------- OPERATING ---------------------------------+
//! |                                                                           |
//! |  +------+ register_close / register_epoch +----------+                    |
//! |  | OPEN | ----------------------------> | REGISTERED |                    |
//! |  +--+---+                               +------+-----+                    |
//! |     ^                                          |                          |
//! |     | admit certified close, now <= deadline   |                          |
//! |     | consume registration, append Pending     |                          |
//! |     +------------------------------------------+                          |
//! |                                                |                          |
//! |                         observed now > deadline|                          |
//! |                                                +-------> HARD FAULT       |
//! |                                                                           |
//! |  admitted FIFO pipeline (bounded by max_pending_epochs):                  |
//! |                                                                           |
//! |  finalized root -> [Pending e] -> [Pending e+1] -> ... -> [tail]          |
//! |                       |                         |                         |
//! |                       | front and now >         | challenge explicit      |
//! |                       | challenge deadline      | BatchId, now <= target  |
//! |                       v                         | deadline                |
//! |                    finalize                     v                         |
//! |                    advance head;       Proven: target Challenged,         |
//! |                    create reserves     descendants Invalidated            |
//! |                                        NoContradiction: no status change  |
//! |                                                                           |
//! |  OPEN has no heartbeat. record_deposit and queue_withdrawal are accepted  |
//! |  only while OPEN; each accepted request owns its separate deadline.       |
//! +---------------------------------------------------------------------------+
//!          |                            |                            |
//!          | proven challenge           | deposit now >= deadline    |
//!          | to any Pending             | withdrawal now >= deadline |
//!          +----------------------------+----------------------------+
//!                                       v
//! +---------------------- HARD FAULT / PREFIX DRAIN --------------------------+
//! | New intake, registration, and admission are permanently fenced.           |
//! | The registration is discarded; its exact deposits/withdrawals stay owned. |
//! | The exact first reason and admission fence remain immutable.              |
//! | Only a proven challenge sets invalid_from and invalidates a suffix.       |
//! | Any earlier Pending prefix may still be challenged or finalized FIFO.     |
//! | A Challenged/Invalidated suffix never finalizes.                          |
//! | Staged deposits may already be refunded by account without a state proof. |
//! +--------------------------------+------------------------------------------+
//!                                  | begin_hard_fault_settlement once the
//!                                  | pipeline front is absent or non-Pending
//!                                  v
//! +------------------------- HARD FAULT / CLAIMING ---------------------------+
//! | Freeze the last finalized StateRoot and its liability.                    |
//! | Drain the remaining suffix; gather staged/suffix deposits and withdrawals.|
//! | begin_hard_fault_settlement is idempotent while CLAIMING.                 |
//! | Zero remaining totals make begin transition directly to SETTLED.          |
//! |                                                                           |
//! | claim_hard_fault(StateOpening)                                            |
//! |   - consume each frozen state position once                               |
//! |   - route Amount or Close to its signed destination                       |
//! |   - return any residual frozen balance to the account                     |
//! |                                                                           |
//! | claim_pending_deposit(account)                                            |
//! |   - refund the fixed account without operator cooperation or state proof  |
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
//! A challenge is accepted through its batch's inclusive challenge deadline. FIFO finalization
//! requires `now` to be strictly later. The three proof-to-fault edges are
//! [`challenge::Challenge::HigherAckDebit`],
//! [`challenge::Challenge::HigherAckEntry`], and
//! [`challenge::Challenge::AckFork`]. There is no interior receipt range to reason about:
//! every counted value is a terminal opening under a payer-signed vector root.
//! [`challenge::Verdict::NoContradiction`] and malformed
//! evidence do not change batch status. A missed registered admission, an expired staged deposit,
//! an expired queued or admitted-but-unfinalized withdrawal, or a proven challenge permanently
//! fences the deployment. The first fault reason and admission fence are retained. A later proof
//! against an earlier Pending prefix may separately move `invalid_from` earlier and shorten the
//! finalizable prefix. Fault attribution chooses the earliest first-fault instant. Registration
//! wins a tie with intake so its active payment anchor remains in the permanent reason. Among
//! intake obligations, a withdrawal wins a tie with a deposit. All tied monetary obligations
//! remain recoverable regardless of which reason names the fault.
//!
//! [`settlement::SettlementConfig`] fixes the admission-delay bound, challenge-duration range,
//! deposit inclusion timeout, and withdrawal notice range before the deployment accepts funds.
//! Registration deadlines must remain monotonic and inside that immutable policy.
//!
//! Every [`settlement::SettlementChain`] mutation that accepts `now` observes expired registration,
//! deposit, and withdrawal obligations before performing its requested operation. Time does not
//! advance the in-memory object by itself: an embedding presents the authenticated monotonic time,
//! then atomically persists the observation even if the requested operation returns an error.
//!
//! ## User-visible money paths
//!
//! The diagrams below follow value rather than internal objects. Every edge labeled `HARD FAULT`
//! is permanent: the operator cannot resume, re-register, or admit another epoch afterward.
//!
//! ```text
//! DEPOSIT
//! -------
//! user records (deposit id, account, amount, inclusion deadline)
//!        |
//!        +-- included by an admitted close --> Pending
//!        |                                        |
//!        |                                        v
//!        |                              clean FIFO finalization
//!        |                                        |
//!        |                                        v
//!        |                              authenticated epoch tail
//!        |                                 |                 |
//!        |                  positive and no Close            +--> zero or Close:
//!        |                                 |                      account absent;
//!        |                                 v                      positive withdrawal
//!        |                             live state                 output, if any,
//!        |                                                        enters its reserve
//!        |
//!        +-- still pending at its deadline --> HARD FAULT --> exact aggregate account refund
//!                                                          (no state opening needed)
//!
//! ACCEPTED PAYMENT
//! ----------------
//! payer signs one cumulative vector endpoint (one or more entries)
//!        |
//!        v
//! operator verifies and atomically records the debit and every entry credit
//!        |
//!        v
//! operator countersigns the exact body (receipt and aggregable halves)
//!        |
//!        +-- selected in a clean close --> FIFO finalization
//!        |                                  |              |
//!        |                                  |              +--> absent predecessor
//!        |                                  |                   with no deposit:
//!        |                                  |                   external-payout reserve
//!        |                                  +--> active predecessor or deposit:
//!        |                                       canonical row determines successor
//!        |                                       state and any withdrawal output
//!        |
//!        +-- omitted or contradicted --> holder submits both signatures
//!                                           + typed Merkle evidence
//!                                                   |
//!                                                   v
//!                                             target Challenged
//!                                             descendants Invalidated
//!                                                   |
//!                                                   v
//!                                        drain only the earlier clean FIFO prefix
//!                                                   |
//!                                                   v
//!                                        freeze the last finalized StateRoot
//!                                                   |
//!                                                   v
//!                                 frozen payer balance is released exactly once
//!                                 (to the payer or its signed withdrawal route)
//!
//! SIGNED WITHDRAWAL
//! -----------------
//! account signs destination + Amount(n) or amountless Close + absolute deadline
//!        |
//!        +-- admitted and finalized in the clean FIFO prefix
//!        |         |
//!        |         v
//!        |   withdrawal-output reserve
//!        |         |
//!        |         v
//!        |   claim (BatchId, position) once with one typed opening
//!        |
//!        +-- still outstanding at deadline --> HARD FAULT
//!                                                   |
//!                         +-------------------------+-------------------------+
//!                         |                                                   |
//!              an earlier clean close finalizes it                 it remains in frozen state
//!                         |                                                   |
//!                         v                                                   v
//!                 ordinary output claim                       Amount(n): n to destination,
//!                                                             residual to account
//!                                                             Close: entire tail to destination
//! ```
//!
//! A missed registered admission window takes the same permanent-fault path. The unadmitted close
//! contributes no debit, credit, withdrawal reserve, or payout reserve. Recovery therefore starts
//! from the last root finalized by the clean FIFO prefix. Finalized reserves are outside active
//! state custody, so each remains independently claimable even if a later epoch faults. These
//! disjoint buckets ensure that a sender's value is either represented by a finalized transition,
//! a finalized claim reserve, the frozen survivor state, or a direct pending-deposit refund, never
//! silently discarded by an operator fault.
//!
//! ## Accounts, custody, and claims
//!
//! ```text
//!                         canonical transition row
//!                 +------------------------------------+
//!                 | predecessor state + deposit        |
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
//!          successor-state projection + compact ChangeRoot entry
//!              ChangeGuard = account + digest(ChangeValue)
//! ```
//!
//! State roots contain only sorted, active, positive-balance leaves. Zero balances are omitted,
//! not retained as tombstones. An [`boundary::WithdrawalAction::Amount`] authorizes one exact
//! positive amount and releases it exactly or not at all: an amount the epoch tail can no longer
//! cover settles with a zero release, so a payer spending after authorizing a withdrawal cannot
//! leave the operator without a buildable close. [`boundary::WithdrawalAction::Close`] carries no
//! amount, permits payment activity through the epoch, then sweeps the authenticated epoch-tail
//! balance and removes the account. Credit to an absent account without a deposit remains outside
//! live state and becomes an external payout. Validators derive each compact change value and
//! withdrawal output while checking the full row and exact signed request. Amount and Close
//! claims have the same shape: the certified destination and amount plus one withdrawal-output
//! opening. An external payout
//! instead uses one compact change opening and never opens a neighboring row.
//!
//! ```text
//! finalize(now) chooses the clean FIFO front
//!          |
//!          +--> ClaimableBatch
//!                 | withdrawal: (BatchId, output position) + output opening
//!                 | payout:     (BatchId, change position) + change opening
//!                 v
//!              consume each typed position once
//!
//! active custody ---------------------> hard-fault survivor/refund claims
//! finalized claim reserves ----------> clean withdrawal/payout claims
//!                 (independent buckets; either may remain after a hard fault)
//! ```
//!
//! Clean [`settlement::SettlementChain::finalize`] advances the finalized state and moves only the
//! aggregate withdrawal and external-payout totals from active custody into independent claim
//! reserves. [`settlement::SettlementChain::claim_withdrawal`] and
//! [`settlement::SettlementChain::claim_external_payout`] consume positions atomically under the
//! replay keys shown above and may run in any order without blocking later epochs. A challenged or
//! invalidated close never creates these reserves. An acknowledged send in an unadmitted or
//! invalidated close therefore never debits the frozen finalized state: the payer recovers that
//! finalized balance exactly once. Hard-fault survivor claims and deposit refunds instead drain
//! active custody. The embedding must atomically and idempotently persist every returned payout
//! together with its state-machine mutation.
//!
//! The crate's executable Stateright model checks finite proof-profile/certification, challenge,
//! claim-ledger, and settlement machines to completion. Deterministic traces cover the accepted and
//! rejected user flows shown above, including malicious-operator recovery, exact deadline
//! boundaries, strict epoch order, and independent finalized reserves. Bounded refinement tests
//! run every settlement action class through real signed production objects and compare private
//! state after each step. The exhaustive model still uses ideal cryptography and representative
//! proof classes. Arbitrary-cardinality and crash-consistency obligations remain with the Rust
//! tests, fuzz targets, and embedding.

pub mod admission;
pub mod boundary;
pub mod challenge;
pub mod commitment;
pub mod payment;
pub mod posted;
pub mod retained;
pub mod settlement;
pub mod state;
pub mod transition;
pub mod vector;

#[cfg(test)]
mod model;
#[cfg(test)]
mod tests;
