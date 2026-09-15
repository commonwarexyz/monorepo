//! Clear many-to-many payments with compact, challengeable settlement.
//!
//! Bajillion separates payment acceptance from settlement. Payers sign cumulative payment
//! vectors, an operator acknowledges them, and validators certify the resulting account activity.
//! Each validator retains the operator's complete account state in QMDB Current Ordered with MMB.
//! The operator distributes one identical dealing that every validator checks against that state.
//!
//! Payment, boundary, vector, and BMT types support `no_std`. QMDB state, complete-close
//! validation, challenges, and settlement require `std` and use Commonware runtime traits.
//! Applications own networking, clocks, operator acceptance, and atomic persistence of protocol
//! state with votes and asset transfers. The terminal example supplies an application integration.
//!
//! # Fault model
//!
//! The operator may halt, censor, equivocate, withhold data, or propose arbitrary closes. It cannot
//! forge account signatures. Hashes and signatures are assumed secure; committee proofs of
//! possession must be authenticated at registration. Randomized signature verification requires
//! fresh cryptographic randomness from its caller.
//!
//! A committee has `n = 3f + 1` validators and tolerates at most `f` Byzantine members. Every honest
//! signer checks the complete dealing and durably retains the native state and original proof
//! sources before publishing a vote. An exact `q = 2f + 1` certificate therefore includes at least
//! `f + 1` honest holders of those sources.
//! Certification proves the disclosed public relation. It cannot prove that the operator never
//! signed an additional private receipt.
//!
//! # Payments and private evidence
//!
//! Each payer maintains one strictly recipient-sorted [`vector::OutVector`] for an immutable
//! registered epoch. An entry records the cumulative amount and payment count for that recipient.
//! A [`payment::SendAuthorization`] signs the payer's epoch-local sequence, cumulative debit, and
//! vector root. Debit starts at zero for each epoch and equals the terminal vector's total.
//! Each accepted batch advances debit by a positive amount and preserves every earlier entry's
//! amount and count. Different payers can advance independently, including payments to the same
//! recipient.
//!
//! The operator countersigns the exact body in two distinct roles: the private receipt uses
//! [`payment::VectorAck`], and a separate aggregable acceptance signature authenticates the
//! terminal bodies in the close. The committee certificate signs the close commitment. These
//! signatures bind different messages and use separate domains.
//!
//! A wallet keeps at most one unacknowledged batch for an account. It stages the exact signed
//! request, retries those bytes after response loss, verifies the acknowledgment and entry
//! openings, and durably saves them before signing its next endpoint. A zero spendable balance
//! does not reset the epoch's accepted sequence, debit, vector, or retry state. Moving to another
//! epoch does not resolve an ambiguous payment: the wallet must authenticate the old outcome
//! before authorizing a replacement.
//!
//! A [`payment::EntryReceipt`] combines the dual-signed acknowledgment with one opening under
//! the payer's vector root. The recipient obtains it before relying on the payment. Any holder
//! can later submit evidence; neither payer nor recipient must remain continuously online. Each
//! receipt relied upon needs an honest holder that retains it, obtains the public openings, and
//! gets a challenge included by the inclusive deadline. Validators cannot reconstruct a private
//! receipt nobody saved.
//!
//! # State and account activity
//!
//! QMDB maps each canonical 32-byte account key to a positive eight-byte balance. Absence means
//! zero. Payments and deposits create positive balances; a zero successor balance removes them.
//! The public key retains authority when its balance is absent, so later credit recreates the
//! same owner's account. A key absent from the predecessor without a sealed deposit can receive
//! but cannot originate payments until the successor epoch. A withdrawal accepted into the
//! settlement queue earlier still executes against the carrying epoch's tail.
//! Eligible accounts can reuse incoming credit within the epoch.
//! Payment counters belong to their epoch's evidence and are not stored in the balance record.
//!
//! Each dealing identifies its activity accounts once, with payer authorizations, cumulative
//! payment entries, and one combined operator acceptance. Every validator derives incoming credit
//! from the signed payer vectors, applies the registered deposits and withdrawals, and computes
//! the resulting balances. It checks per-account limits, overflow, spendability, and the exact
//! boundary/output rules before preparing one canonical QMDB batch. Equal old and new balances
//! produce no database write. The batch boundary is part of the authenticated history even when
//! no balances change.
//!
//! A cumulative native keyless MMR contains every disclosed sender, recipient, and boundary
//! participant. Each epoch starts with a contiguous full-row prefix sorted by canonical account
//! bytes; its certified count separates it from the flat outgoing-entry suffix. Every row commits
//! the account, terminal debit, sequence, and outgoing vector root even when the balance is
//! unchanged. Entries for positive-debit rows follow in row order, and their positive amounts
//! uniquely delimit each vector. Payer-vector BMT proofs are reconstructed only when requested.
//! A second keyless MMR appends every withdrawal output in request order, including zero releases.
//! Payout identities are native Append locations. All three public stores use empty Commit
//! metadata; native Commit leaves terminate batches outside their account and output intervals.
//!
//! `transition::Header` binds the exact registered context and predecessors, all three successor
//! roots and native counts, canonical log floors, independent ProposalId, and withdrawal total.
//! Every validator derives the append extension from its retained predecessor. Settlement checks
//! the exact quorum certificate and derives successor liability from its registered deposits and
//! certified outflow. The operator identifies its proposal without constructing the native trees.
//! Registration captures log floors from one finalized snapshot; later finalizations cannot
//! change the inputs used by signers processing that same proposal.
//!
//! `transition::prepare_dealing` encodes accepted activity without reading account state.
//! `admission::seal` decodes and validates the complete dealing against the exact predecessor and
//! registered committee, returning the vote and owned native candidate. Before publishing the
//! vote, the application durably commits all three candidate stores, then records its private
//! checkpoint and signing decision. It keeps the canonical parent until settlement selects the
//! successor. QMDB mutation failures consume the affected database owner; an embedding must not
//! continue using it.
//!
//! Canonical history and proof material protect the predecessor, every pending close, and the
//! latest finalized recovery state. A pending close may outlive its own challenge deadline while
//! an earlier FIFO entry waits. Native Current historical views reconstruct current-value proofs
//! from retained operation history and pinned nodes. Operation inclusion alone does not prove an
//! old balance was current. The private checkpoint names all three accepted native boundaries.
//! Recovery opens each store at its durable head and reconciles those heads with that decision.
//! Before discarding an unadmitted candidate, the application selects its durable parent
//! checkpoint before truncating any store. Pruning preserves every protected activity, payout,
//! and Current historical boundary.
//!
//! # Registration and settlement
//!
//! One registration fixes the deployment, operator, epoch, deposits, signed withdrawals, opening
//! liability, deadlines, limits, and committee. The payment anchor and the separately bound exact
//! predecessor root must match the registered close context before an acknowledgment is released.
//! An empty registration slot has no heartbeat. Once registered, its inclusive admission deadline
//! is a one-shot obligation; the context cannot be rebased after it expires.
//!
//! The acknowledged set freezes before dealing. A retry under that registration redistributes the
//! same corpus and resubmits the same certified header. A genuine certificate may be admitted by
//! any holder, so releasing two different closes for the same registration can make an honest
//! operator's later acknowledgments contradict its earlier certified close.
//!
//! ```text
//! registered context + terminal payment vectors
//!                  |
//!                  v
//!          operator prepares one shared dealing
//!                  |
//!                  v
//!       every signer derives the close using its QMDB state
//!                  |
//!       retain state/evidence, then publish votes
//!                  |
//!                  v
//!             exact 2f+1 certificate
//!                  |
//!                  v
//!       admit into the ordered pending queue
//!                  |
//!       challenge window ends and earlier closes finalize
//!                  |
//!                  v
//!       advance finalized state and reserve withdrawals
//! ```
//!
//! A successor epoch can register against the admitted queue tail while earlier closes remain
//! challengeable. Registration and admission cannot skip ancestry. Finalization consumes only the
//! FIFO front and requires time strictly later than its challenge deadline. Certification alone
//! never changes custody or finalizes payments.
//!
//! A receipt challenge proves an understated terminal debit, an understated recipient amount or
//! count, or conflicting operator acknowledgments. An activity-absent payer has public epoch debit
//! zero, so that absence is enough to challenge an omitted accepted payment. Public activity and
//! payer-vector openings keep challenges to one onchain call. Malformed evidence and a valid
//! `NoContradiction` verdict do not change batch status.
//!
//! A proven challenge marks its target challenged and invalidates its pending descendants. A
//! missed admission, deposit, or withdrawal deadline also permanently faults the deployment.
//! New work stops, but an earlier clean pending prefix can still be challenged or finalized.
//! The first fault reason and admission fence remain immutable; a later successful challenge can
//! shorten the surviving prefix. Registration wins a tied fault instant over intake, and a tied
//! withdrawal wins over a deposit. All monetary obligations remain recoverable.
//!
//! Calls taking `now` first observe every expired obligation. The embedding supplies authenticated
//! monotonic time and persists that observation even when the requested operation subsequently
//! fails. Time alone does not advance this in-memory settlement state machine.
//!
//! # Withdrawals, custody, and recovery
//!
//! An exact [`boundary::WithdrawalAction::Amount`] releases its authorized amount when the epoch
//! tail covers it and otherwise releases zero. An amountless [`boundary::WithdrawalAction::Close`]
//! drains the final balance and removes the balance record. Every payment credits its recipient
//! virtually and creates no settlement output. Validators derive withdrawals from the account
//! equation and signed authorizations; `Withdrawal(0)` remains distinct from no withdrawal action.
//!
//! A censored withdrawal can be queued onchain against one finalized balance opening, including
//! during an active epoch. It leaves that epoch's registered boundary unchanged and must appear
//! in the next registration. Fresh operator-carried requests instead prove their balance against
//! the registered predecessor and boundary deposits. Intervening payments can change either
//! request's final release; recovery always uses the surviving finalized balance.
//!
//! Clean FIFO finalization updates one approved cumulative payout root/count and issues only its
//! new nonempty interval of Append locations. The external ledger stores disjoint unclaimed
//! `(deployment, start) -> end` ranges. A claim supplies the containing start, proves its output at
//! the latest approved head, and atomically replaces that interval with up to two fragments while
//! releasing its amount. Zero releases also consume their locations. No finalized epoch root or
//! spent-position set is retained in this ledger; its size is bounded by outstanding outputs.
//! Claims have no expiry and remain available through faults without another Bajillion vote.
//!
//! Replicas that retain longer native history serve old outputs and refreshed proofs as the
//! approved head advances. This availability duty is separate from validator challenge history:
//! an old unclaimed output does not pin hot validator pruning. A stale path alone does not provide
//! a current-root claim witness, and a missing source is an error rather than evidence of absence.
//!
//! Public native Commit operations carry no metadata. Retained activity operations preserve the
//! bounded originals needed to reconstruct requested payer-vector proofs, while the independently
//! certified close descriptor and registered context authenticate the epoch and range. Native
//! originals are proof material, not a second source of context or provenance. Old payout claims
//! authenticate directly under the current finalized payout head, allowing retirement of old epoch
//! roots and anchors after their live obligations end. Onchain challenges against a pending
//! admitted root use native activity and payer-vector openings authenticated by that descriptor.
//!
//! Once the surviving clean prefix drains, hard-fault recovery freezes the last finalized QMDB
//! root and liability. Each live account proves its positive balance at that root and is consumed
//! once by account identity. Recovery routes a covered Amount or full Close to its signed
//! destination and returns any residual to the account. Unadmitted deposits are refunded separately
//! by account without requiring an operator or state proof. A never-admitted or invalidated close
//! never debits this frozen state or creates a withdrawal reserve.
//!
//! Active custody, finalized claim reserves, and pending-deposit refunds are disjoint accounting
//! buckets. Every returned asset transfer must be persisted atomically and idempotently with its
//! claim consumption. Completion assumes a correct, live settlement chain, available proof
//! material, and eventual submission of claims.
//!
//! The Stateright model exhausts finite certification, challenge, claim, and settlement instances.
//! Production refinement exercises real signed objects and verifies the settlement effects after
//! each action. These checks complement byte-level tests and fuzzing; they are not proofs for
//! arbitrary cardinalities or substitutes for the embedding's durable crash tests.

#[cfg(feature = "std")]
pub mod admission;
/// Shared signed workloads for production durability benchmarks.
#[cfg(feature = "bench")]
#[doc(hidden)]
#[path = "benches/workload.rs"]
pub mod benchmark_workload;
pub mod boundary;
#[cfg(feature = "std")]
pub mod challenge;
pub mod commitment;
#[cfg(feature = "std")]
pub mod custody;
#[cfg(feature = "std")]
pub mod logs;
pub mod payment;
#[cfg(feature = "std")]
pub mod posted;
#[cfg(feature = "std")]
pub mod qmdb;
#[cfg(feature = "std")]
pub mod replica;
#[cfg(feature = "std")]
pub mod settlement;
pub mod state;
#[cfg(feature = "std")]
pub mod transition;
pub mod vector;

#[cfg(all(test, feature = "std"))]
mod model;
#[cfg(all(test, feature = "std"))]
mod tests;
