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
//! signer checks the complete dealing and retains its evidence before publishing a vote. An exact
//! `q = 2f + 1` certificate therefore includes at least `f + 1` honest holders of the entire close.
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
//! the account is not live. Deposits can create accounts; a zero successor balance removes them.
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
//! The activity BMT includes every disclosed sender, recipient, and boundary/output participant.
//! Activity that nets to zero still needs terminal evidence, even though it needs no balance
//! mutation. A compact activity value commits the terminal epoch debit and sequence, outgoing
//! vector root and settlement output. A separate BMT indexes withdrawal outputs in request order. Payer-vector BMTs remain nested under their signed endpoints.
//!
//! `transition::Header` binds the exact registered context and predecessor state, the activity,
//! withdrawal-output, and successor QMDB roots, and the actual withdrawal and external-payout
//! totals. Settlement derives successor liability from its registered deposits, predecessor
//! liability, and these certified outflows. The dealing carries inputs from which validators
//! reconstruct this header. External settlement additionally receives the roots and outflow totals.
//!
//! `transition::prepare_close_with_strategy` constructs a candidate without installing it.
//! `admission::seal` decodes and validates the complete dealing against the exact predecessor and
//! registered committee, returning the vote and owned candidate/evidence. The application durably
//! retains the evidence and its predecessor state before publishing the vote. Validators advance
//! their canonical replica to the close selected by settlement. QMDB mutation failures consume
//! the affected database owner; an embedding must not continue using it.
//!
//! Canonical QMDB history and proof material must remain available for predecessor and pending
//! roots and the last finalized recovery root. Pending roots may outlive their own challenge
//! deadlines while earlier FIFO entries wait. Historical Current proofs require the activity
//! bitmap as well as the operation history. The state service retains canonical batches and uses
//! QMDB replay/rewind for historical proof construction; operation inclusion alone does not prove
//! that an old balance was current. Retention and seek costs belong to the state owner.
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
//! registered context + predecessor QMDB state + terminal payment vectors
//!                  |
//!                  v
//!          prepare one shared dealing
//!                  |
//!                  v
//!       every signer validates the complete close
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
//!       advance finalized state and reserve payouts
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
//! sweeps the final balance and removes the account. Credit to an absent account without a deposit
//! becomes an external payout. Validators derive these outputs from the account equation and
//! signed authorizations; `Withdrawal(0)` remains distinct from no withdrawal action.
//!
//! A censored withdrawal can be queued onchain while registration is open. Its balance openings
//! cover the finalized state and every pending successor root selected by settlement. Operator-
//! carried requests are checked against the registered predecessor and boundary deposits. These
//! checks keep a withdrawal recoverable across each possible surviving finalized prefix.
//!
//! Clean finalization moves aggregate withdrawal and external-payout amounts into independent
//! reserves. A withdrawal claim opens its certified destination and amount in the output BMT;
//! an external payout opens the compact activity value. Each consumes its typed `(batch, position)`
//! once. These reserves remain independently claimable through later faults.
//!
//! Once the surviving clean prefix drains, hard-fault recovery freezes the last finalized QMDB
//! root and liability. Each live account proves its positive balance at that root and is consumed
//! once by account identity. Recovery routes a covered Amount or full Close to its signed
//! destination and returns any residual to the account. Unadmitted deposits are refunded separately
//! by account without requiring an operator or state proof. A never-admitted or invalidated close
//! never debits this frozen state or creates a payout reserve.
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
pub mod boundary;
#[cfg(feature = "std")]
pub mod challenge;
pub mod commitment;
pub mod payment;
#[cfg(feature = "std")]
pub mod posted;
#[cfg(feature = "std")]
pub mod qmdb;
#[cfg(feature = "std")]
pub mod serve;
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
