//! Settlement chain built on `glue::stateful`, and its client surface.
//!
//! Block height is the clock, every deadline is an absolute block height
//! chosen when its obligation is created, every read is certified against
//! the canonical current-database root, and the settlement transition logic
//! runs as deterministic block execution (see [`state`]). [`tx`] defines the
//! settlement transactions and their request codecs, [`native`] the native
//! genesis and deployment registry entries, and [`registry`] the certified
//! operator membership that authorizes peers. [`ingress`] carries
//! transactions from peers and local RPC into proposals, [`query`] serves
//! certified reads and accepts submissions, [`light`] verifies certified
//! reads client-side, [`client`] packages the settlement operations the
//! wallet and operator roles consume, [`da`] carries dealing dissemination
//! and votes for distributed certification, [`node`] runs the operator as a
//! non-signing p2p secondary, [`harness`] runs an in-process
//! single-validator chain for the scripted walkthrough and tests, and
//! [`validator`] with [`setup`] assemble a runnable committee.
//!
//! # Embedding
//!
//! Each registered deployment runs one clearing [`SettlementChain`] in chain
//! state.
//!
//! Settlement has two signing layers. The clearing committee signs each close
//! header with BLS votes, and `Admit` carries the certificate. The terminal
//! requires 3 of its 4 validators, and the primitive permits `f + 1`. Simplex
//! threshold consensus finalizes the settlement blocks. The same four machines
//! run both layers under separate keys (see [`setup`]). The primitive allows a
//! separate settlement chain or committee.
//!
//! A block first advances every registered deployment: it observes expired
//! deadlines, then finalizes at most one admitted close past its challenge
//! window. The block's transactions then execute in order. The [`tx`] table
//! lists each transaction's checks.
//!
//! [`tx::SettlementTx`] is the input surface. The output surface is the
//! certified [`state::Record`] values that [`query::Lookup`] reads. Every
//! block rewrites each deployment's [`state::StatusRecord`]. Deposit and
//! withdrawal effects ([`state::DepositEffect`], [`state::WithdrawalEffect`]),
//! inbox entries ([`state::Intake`]), registrations
//! ([`state::RegistrationRecord`]), carried withdrawals
//! ([`state::CarriedRecord`]), admitted closes
//! ([`state::AdmittedRootsResponse`]), and faults ([`state::FaultRecord`])
//! track the obligation lifecycle.
//!
//! An obligation enters the inbox at the next index through `Deposit` or
//! `QueueWithdrawal`. A `RegisterEpoch` pulls it, `Admit` lands the pulling
//! epoch's certified close, and a later block finalizes that close. Expiry
//! faults the deployment instead when a deposit remains unpulled at its
//! inclusion deadline, the admission frontier passes its admission deadline,
//! or a chain-queued or admitted withdrawal remains unfinalized at its signed
//! deadline.
//!
//! ## Exit paths
//!
//! Each exit path completes through settlement transactions and certified
//! records without the operator. Fee funding instead keeps the operator
//! registering epochs. [Getting your money
//! out](../../README.md#getting-your-money-out) describes these paths from the
//! wallet.
//!
//! - Escalated withdrawal: `QueueWithdrawal` carries a [`SignedWithdrawal`]
//!   and a state opening at the finalized root. Settlement accepts it only
//!   while the signed deadline lies within the notice window, which the genesis
//!   timing sets to 1,201 through 1,301 blocks after the accepting block, and
//!   while the account has no other unfinalized withdrawal. The opening must
//!   verify against the current finalized root for the signing account. Its
//!   balance must cover an `Amount` and must be positive for a `Close`.
//!   Execution writes a [`state::WithdrawalEffect`] and an inbox
//!   [`state::Intake`] entry. The registration that pulls the entry, or an
//!   earlier one, must carry the request (`MissingQueuedWithdrawal`), which
//!   writes a [`state::CarriedRecord`]. The carrying close's finalization
//!   appends a payout output under the finalized payout head. A `Close` takes
//!   the account's balance at the end of that epoch. An `Amount` takes its full
//!   amount when that balance covers it. Otherwise its output carries zero and
//!   the balance stays with the account.
//! - Payout claim: `ClaimWithdrawal` opens the output against the current
//!   finalized payout head and inserts its position into the claimed ranges.
//!   It has no deadline and remains valid after a fault.
//! - Hard fault: an unpulled deposit at its inclusion deadline
//!   (`ExpiredDeposit`), an admission frontier past its admission deadline
//!   (`ExpiredRegistration`), a chain-queued or admitted withdrawal unfinalized
//!   at its signed deadline (`ExpiredWithdrawal`), or a proven `Challenge`
//!   (`ProvenChallenge`) writes [`state::FaultRecord::Faulted`] and drops every
//!   unadmitted registration. Admitted closes that no challenge invalidated
//!   keep finalizing.
//! - Omission challenge: `Challenge` with `HigherAckEntry` from a recipient
//!   receipt, `HigherAckDebit` from a payer receipt, or `AckFork` from two
//!   distinct countersigned messages at one payer sequence, landed through the
//!   close's challenge deadline, invalidates that close and every later
//!   admitted close and faults the deployment. The wallet submits the first
//!   two kinds.
//! - Terminal settlement: `BeginHardFaultSettlement` freezes the last
//!   finalized state root and writes [`state::FaultRecord::Settling`]. It
//!   fails with `PreFaultBatchPending` while an admitted close that no
//!   challenge invalidated awaits finalization. `ClaimHardFault` opens one
//!   account at the frozen root, routes its chain-queued withdrawal or the
//!   withdrawal an invalidated close carried when the balance covers it, pays
//!   the rest to the account, and writes a [`state::HardFaultReleaseRecord`].
//! - Deposit refund: `ClaimPendingDeposit` with `terminal` false refunds the
//!   account's unadmitted deposits, pulled or not, after any fault. With
//!   `terminal` true it refunds the terminal table, which also holds the
//!   deposits of invalidated closes. Each phase writes its own refund record.
//! - Idle deployment: with no epoch awaiting admission, no admission deadline
//!   runs. A `QueueWithdrawal` or `Deposit` creates a deadline that faults the
//!   deployment when it expires.
//! - Fee funding: a `NativeTransfer` to the operator's account funds the epoch
//!   fee each `RegisterEpoch` pays, so an operator short of the fee can resume
//!   registering.
//!
//! [`SettlementChain`]: commonware_clearing::bajillion::settlement::SettlementChain
//! [`SignedWithdrawal`]: commonware_clearing::bajillion::boundary::SignedWithdrawal

pub(crate) mod app;
pub(crate) mod client;
pub(crate) mod da;
pub(crate) mod harness;
pub(crate) mod ingress;
pub(crate) mod light;
pub(crate) mod native;
pub(crate) mod node;
pub(crate) mod query;
pub(crate) mod registry;
pub(crate) mod setup;
pub(crate) mod state;
pub(crate) mod tx;
pub(crate) mod types;
pub(crate) mod validator;

#[cfg(test)]
mod tests;
