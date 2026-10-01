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
//! sources before publishing a vote. A certificate with at least `q = f + 1` signatures therefore
//! includes at least one honest validator that checked and retained the complete close. Distinct
//! valid certificates may coexist; certification does not select a canonical close. Ordered
//! admission owns that selection. Canonical state advancement and finality follow the admitted
//! close, while speculative work may continue on other candidates.
//! Certification proves the disclosed public relation. It cannot prove that the operator never
//! signed an additional private receipt.
//!
//! # Payments and private evidence
//!
//! Each payer maintains one strictly recipient-sorted [`vector::OutVector`] for an immutable
//! registered epoch. An entry records the cumulative amount and payment count for that recipient.
//! A [`payment::SendAuthorization`] signs the payer's epoch-local sequence, cumulative debit,
//! vector root, and predecessor. Debit starts at zero for each epoch and equals the terminal
//! vector's total. Each accepted batch advances debit by a positive amount and preserves every
//! earlier entry's amount and count. Different payers can advance independently, including
//! payments to the same recipient.
//!
//! The operator countersigns each accepted message for the private [`payment::VectorAck`] receipt.
//! At close, the same key signs the registered epoch context and the canonical ordered batch of
//! complete terminal messages, including their predecessor roots. This signature authenticates
//! the selected endpoints, including an empty batch, without attesting to private receipt delivery.
//! The committee's aggregate certificate signs the derived close commitment. Private receipts,
//! terminal batches, and committee votes use separate signature domains.
//!
//! A wallet keeps at most one unacknowledged batch for an account. It stages the exact signed
//! request, retries those bytes after response loss, verifies the acknowledgment and entry
//! openings, and durably saves them before signing its next endpoint. A zero spendable balance
//! does not reset the epoch's accepted sequence, debit, vector, or retry state.
//!
//! Every body also signs the root of the payer's terminal vector in the preceding epoch.
//! Validators check an epoch only after its predecessor is admitted, so a close carries a body
//! only when the preceding close ended where the payer said. A wallet may re-sign an ambiguous
//! payment in the next epoch against a root that excludes it, and at most one copy can settle.
//! The binding reaches back one epoch. A wallet signs a payment again only after every earlier
//! epoch in which it signed that payment, other than the immediately preceding one, is decided:
//! admitted, or dead because its own preceding epoch was admitted at another root.
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
//! payment entries, and one operator batch signature. Every validator derives incoming credit
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
//! a certificate with at least the minimum quorum and derives successor liability from its
//! registered deposits and certified outflow. The operator identifies its proposal without
//! constructing the native trees.
//! Registration captures log floors from one finalized snapshot, and they stay fixed while the
//! epoch waits in the queue. Later finalizations cannot change the inputs used by signers
//! processing that same proposal.
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
//! One registration fixes the deployment, operator, epoch, deposits, signed withdrawals, limits,
//! and committee. The payment anchor commits nothing about the predecessor close or timing, so an
//! epoch can register, and its payments can be acknowledged, while its predecessor's close is
//! still built, certified, and admitted. The embedding must not release an acknowledgment before
//! settlement has registered the exact anchor.
//!
//! Registered epochs wait in FIFO order. Registration requires only that the previous epoch is
//! registered, and neither registration nor admission can skip ancestry. The earliest registered
//! epoch is the admission frontier. An epoch becomes the frontier at its registration when no
//! earlier epoch awaits admission, and otherwise at its predecessor's admission. Settlement then
//! binds it to the exact state root, log heads, account rows, and liability of its own admitted
//! head and derives both deadlines from the deployment policy. The operator states none of these values. Only the
//! frontier has deadlines, so only the frontier can expire. Its inclusive admission deadline is a
//! one-shot obligation, and its context cannot be rebased after it expires. An empty queue has no
//! heartbeat.
//!
//! Deposits and chain-queued withdrawals enter one ordered inbox, and each receives the next inbox
//! index when settlement records it. No epoch is assigned then. A registration names the exclusive
//! end of the prefix it pulls, starting at the first unpulled index, and commits exactly the
//! deposits recorded there. Intake recorded later, including earlier in the same block, cannot
//! change it. A registered boundary therefore never changes, and admitting an epoch removes
//! exactly its own deposits. A deposit's inclusion deadline applies until a registration pulls it.
//! Deposits share one timeout, so the oldest unpulled deposit expires first. Afterward the deposit
//! follows its epoch: that epoch's admission carries it into the admitted close, and a hard fault
//! before that admission makes it refundable. A registration must carry every uncarried
//! chain-queued withdrawal in its prefix verbatim. It may carry a request recorded past its prefix
//! early, or supersede that request with a fresh extra signed for the same account. No later
//! registration can carry a carried or superseded request.
//!
//! The embedding stores each deposit under `(deployment, index)` and supplies the per-account
//! aggregate of the pulled prefix at registration. Settlement authenticates that aggregate only
//! against the registered deposit root, so the embedding must read it from its own records.
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
//!           at least f+1 signatures
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
//! Admitted closes remain challengeable while later epochs register and admit. Finalization
//! consumes only the FIFO front and requires time strictly later than its challenge deadline.
//! Certification alone never changes custody or finalizes payments.
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
//! A fault drops the frontier and every queued registration. Their deposits and chain-queued
//! withdrawals stay with their owners.
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
//! while epochs are registered. It leaves every registered boundary unchanged and must appear in
//! the registration that pulls its inbox index. Fresh operator-carried requests carry no balance
//! proof. Every authorization enters settlement only while its deadline lies within the notice
//! window of the accepting block, and its replay id stays consumed until the deadline. The
//! carrying epoch's tail resolves the release: the requested amount when the tail covers it, and
//! zero otherwise. Intervening payments can change either request's final release. A fresh request
//! supersedes a different request its account queued after the registration's pull ended, since
//! the signer authorized both, so intake that races a published boundary cannot fail its
//! registration. Recovery always uses the surviving finalized balance.
//!
//! Clean FIFO finalization updates one approved cumulative payout root/count and marks its trailing
//! native Commit location as consumed. The external ledger stores disjoint claimed
//! `(deployment, start) -> end` ranges. The embedding reads the immediate neighbors and verifies
//! the output at the latest approved head. It atomically merges the location into those ranges
//! while releasing the amount. Zero releases also consume their locations. Adjacent claims and the
//! structurally unclaimable inter-close Commit locations collapse settled history; arbitrary claim
//! order can still fragment the ledger. If `U` Append outputs remain unpaid, every maximal claimed
//! range except possibly the last must be separated from the next by a distinct unpaid output, so
//! the ledger contains at most `U + 1` ranges. The genesis Commit at location zero is excluded;
//! membership in a claimed range does not by itself prove that the location contained a payout.
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
//! by account without requiring an operator or state proof, and one refund returns every
//! unadmitted deposit of the account, pulled or not. A never-admitted or invalidated close never
//! debits this
//! frozen state or creates a withdrawal reserve.
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
