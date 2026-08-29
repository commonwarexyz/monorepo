//! SQLite ownership boundary for one agent wallet.
//!
//! Receipts remain durable because this example has no authenticated signal that their challenge
//! windows closed. An embedding may prune them only after obtaining that signal.
//!
//! The provider's held incoming pairs follow the same discipline. Each is a self-verified
//! (send, receipt) pair credited to this wallet, durably retained so a provider can enforce its
//! preconfirmation. They are irreplaceable once the operator is gone, so like the recovery
//! openings they are counterparty-death-surviving evidence, never an overwritable cache.

use crate::{
    operator::rpc as operator_rpc,
    protocol::{
        Acceptance, DepositEvent, Key, MAX_ACCEPTANCE_BYTES, MAX_ACCOUNTS, MAX_PAYMENT_BYTES,
        Payment,
    },
    settlement::rpc as settlement_rpc,
    store::CommitUnknown,
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    challenge::StateOpening,
    commitment::{VectorKind, VectorRoot},
    payment::{PaymentContext, SignedSend},
    state::AccountState,
};
use commonware_codec::{DecodeExt as _, Encode as _, FixedSize};
use commonware_cryptography::{Sha256, sha256::Digest};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use std::path::Path;

const SCHEMA_VERSION: i64 = 11;
const MAX_PENDING_CLAIM_BYTES: usize = 16 * 1024;
const MIN_STATE_OPENING_BYTES: usize = Key::SIZE + AccountState::SIZE + u32::SIZE * 2 + 1;
const MAX_STATE_OPENING_BYTES: usize =
    Key::SIZE + AccountState::SIZE + u32::SIZE * 2 + 1 + Digest::SIZE * u32::BITS as usize;
const DEPOSIT_EVENT_BYTES: usize = Digest::SIZE + Key::SIZE + u64::SIZE;

#[derive(Clone)]
pub(crate) struct PendingPayment {
    pub(crate) send: SignedSend<Key, Digest>,
    pub(crate) recovery_root: VectorRoot<Digest>,
}

/// One open claim intent: the claim kind and this wallet's identity, an overwritable
/// cache of self-verified evidence, and a recorded settlement release that pins the exact
/// evidence it paid until the operator acknowledgement completes the claim.
///
/// The intent deliberately carries no epoch: no counterparty-supplied provenance is
/// verifiable at open time, so the claim binds to its finalized batch only when fetched
/// evidence verifies locally against that batch's own claim roots.
#[derive(Clone)]
pub(crate) struct PendingClaim<E, R> {
    pub(crate) evidence: Option<E>,
    pub(crate) result: Option<R>,
}

pub(crate) type PendingWithdrawalClaim =
    PendingClaim<operator_rpc::WithdrawalEvidenceResponse, settlement_rpc::WithdrawalResponse>;
pub(crate) type PendingPayoutClaim = PendingClaim<
    operator_rpc::ExternalPayoutEvidenceResponse,
    settlement_rpc::ExternalPayoutResponse,
>;

pub(crate) struct State {
    pub(crate) cumulative_debit: u64,
    pub(crate) pending_payment: Option<PendingPayment>,
    pub(crate) pending_deposit: Option<DepositEvent>,
    pub(crate) pending_withdrawal_claim: Option<PendingWithdrawalClaim>,
    pub(crate) pending_payout_claim: Option<PendingPayoutClaim>,
    pub(crate) receipt_count: u64,
    /// Provider intake state: the durable fetch cursor and the verified-credit ledger summary.
    pub(crate) incoming: IncomingSummary,
    /// Highest epoch whose held credits were reconciled against the committed close.
    pub(crate) last_reconciled_epoch: Option<u64>,
}

/// The provider's verified incoming ledger summary: total credited value, count of held
/// pairs, and the durable fetch cursor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct IncomingSummary {
    pub(crate) total: u64,
    pub(crate) count: u64,
    pub(crate) cursor: u64,
}

/// One verified incoming pair ready to persist: its acceptance cursor, credited metadata,
/// and the canonical [`Payment`] bytes.
pub(crate) struct IncomingRecord {
    pub(crate) tx_id: Digest,
    pub(crate) payer: Key,
    pub(crate) epoch: u64,
    pub(crate) anchor: Digest,
    pub(crate) shard: u64,
    pub(crate) cumulative_shard_credit: u64,
    pub(crate) receipt_index: u64,
    pub(crate) amount: u64,
    pub(crate) cursor: u64,
    pub(crate) pair: Payment,
}

/// The wallet's highest held receipt in one receive shard of one epoch.
pub(crate) struct HeldReceipt {
    pub(crate) shard: u64,
    pub(crate) cumulative_shard_credit: u64,
    pub(crate) receipt_index: u64,
    pub(crate) pair: Payment,
}

/// One held credit answering a provider's service-accounting query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IncomingCredit {
    pub(crate) epoch: u64,
    pub(crate) shard: u64,
    pub(crate) amount: u64,
}

/// The durable outcome of reconciling one epoch's held credits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub(crate) enum ReconcileOutcome {
    /// The committed close's credit tip covered every held receipt.
    Reconciled = 1,
    /// A held receipt exceeded the committed tip and a proven challenge was submitted.
    Challenged = 2,
    /// An enforcement dead end: a finalized close understated a held receipt past the
    /// challenge window, or a registered epoch's close never admitted and settlement faulted.
    Unenforceable = 3,
}

#[derive(Clone, Copy)]
#[repr(i64)]
enum ClaimKind {
    Withdrawal = 1,
    ExternalPayout = 2,
}

/// Durable payment lifecycle. The outstanding slot holds `Staged` or `Submitted`, and the
/// ledger records every concluded payment as `Accepted` (operator receipts held),
/// `Finalized` (endpoint observed in a finalized settlement root), or `Abandoned`.
#[derive(Clone, Copy)]
#[repr(i64)]
enum PaymentState {
    Staged = 1,
    Submitted = 2,
    Accepted = 3,
    Finalized = 4,
    Abandoned = 5,
}

/// Bound parameters selecting the endpoint-advancing ledger states.
const SETTLED_STATES: [i64; 2] = [
    PaymentState::Accepted as i64,
    PaymentState::Finalized as i64,
];

struct Binding {
    account: Key,
    deployment: Digest,
    operator: Key,
}

pub(crate) struct Store {
    connection: Connection,
    account: Key,
    operator: Key,
    poisoned: bool,
    /// Highest endpoint already recorded as finalized, so repeated observations of an
    /// unchanged finalized head skip their redundant write.
    finalized_watermark: u64,
}

impl Store {
    pub(crate) fn open(
        path: &Path,
        account: &Key,
        deployment: &Digest,
        operator: &Key,
    ) -> Result<(Self, State)> {
        let connection = Connection::open(path)
            .with_context(|| format!("open SQLite agent at {}", path.display()))?;
        Self::from_connection(connection, false, account, deployment, operator)
    }

    pub(crate) fn in_memory(
        account: &Key,
        deployment: &Digest,
        operator: &Key,
    ) -> Result<(Self, State)> {
        Self::from_connection(
            Connection::open_in_memory().context("open in-memory SQLite agent")?,
            true,
            account,
            deployment,
            operator,
        )
    }

    fn from_connection(
        mut connection: Connection,
        in_memory: bool,
        account: &Key,
        deployment: &Digest,
        operator: &Key,
    ) -> Result<(Self, State)> {
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA busy_timeout = 5000;",
        )?;

        configure_durability(&connection, in_memory)?;
        let schema = schema_presence(&connection)?;
        match schema {
            SchemaPresence::Empty => {
                initialize_schema(&mut connection, account, deployment, operator)?;
            }
            SchemaPresence::Complete => {}
        }

        let binding = read_binding(&connection)?;
        ensure!(
            binding.account == *account,
            "agent database belongs to another account"
        );
        ensure!(
            binding.deployment == *deployment,
            "agent database belongs to another deployment"
        );
        ensure!(
            binding.operator == *operator,
            "agent database belongs to another operator"
        );
        let state = read_state(&connection, account, operator)?;
        let finalized_watermark = latest_finalized(&connection)?;

        Ok((
            Self {
                connection,
                account: account.clone(),
                operator: operator.clone(),
                poisoned: false,
                finalized_watermark,
            },
            state,
        ))
    }

    pub(crate) fn retain_recovery_opening(
        &mut self,
        root: &VectorRoot<Digest>,
        opening: &StateOpening<Key, Digest>,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_recovery_opening(root, opening, &self.account)?;
        let encoded_root = root.encode();
        let encoded_opening = opening.encode();
        ensure!(
            encoded_root.len() == VectorRoot::<Digest>::SIZE,
            "state root encoding has an unexpected length"
        );
        ensure!(
            encoded_opening.len() <= MAX_STATE_OPENING_BYTES,
            "state opening encoding exceeds its bound"
        );

        let result = retain_recovery_opening_transaction(
            &mut self.connection,
            &self.account,
            root,
            encoded_root.as_ref(),
            opening,
            encoded_opening.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn recovery_opening(
        &self,
        root: &VectorRoot<Digest>,
    ) -> Result<Option<StateOpening<Key, Digest>>> {
        self.ensure_usable()?;
        read_recovery_opening(&self.connection, root, &self.account)
    }

    /// Opens the withdrawal-claim intent. Opening is idempotent.
    pub(crate) fn open_withdrawal_claim(&mut self) -> Result<()> {
        self.ensure_usable()?;
        let result = open_claim_transaction(&mut self.connection, ClaimKind::Withdrawal);
        self.finish_mutation(result)
    }

    /// Opens the external-payout-claim intent. Opening is idempotent.
    pub(crate) fn open_payout_claim(&mut self) -> Result<()> {
        self.ensure_usable()?;
        let result = open_claim_transaction(&mut self.connection, ClaimKind::ExternalPayout);
        self.finish_mutation(result)
    }

    /// Overwrites the open withdrawal-claim intent's evidence cache.
    ///
    /// Evidence is counterparty-reproducible, so any self-verified copy may replace the
    /// cache. The one exception is evidence with a recorded settlement release, which
    /// stays immutable until the operator acknowledgement completes the claim.
    pub(crate) fn cache_withdrawal_claim(
        &mut self,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_withdrawal_evidence(evidence, &self.account)?;
        let encoded = evidence.encode();
        ensure_claim_bound(encoded.as_ref(), "withdrawal evidence")?;
        let result = cache_claim_transaction(
            &mut self.connection,
            ClaimKind::Withdrawal,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn record_withdrawal_result(
        &mut self,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
        result: &settlement_rpc::WithdrawalResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_withdrawal_evidence(evidence, &self.account)?;
        validate_withdrawal_result(evidence, result)?;
        let evidence = evidence.encode();
        let result = result.encode();
        ensure_claim_bound(evidence.as_ref(), "withdrawal evidence")?;
        ensure_claim_bound(result.as_ref(), "withdrawal result")?;
        let result = record_claim_result_transaction(
            &mut self.connection,
            ClaimKind::Withdrawal,
            evidence.as_ref(),
            result.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn complete_withdrawal_claim(
        &mut self,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
        result: &settlement_rpc::WithdrawalResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_withdrawal_evidence(evidence, &self.account)?;
        validate_withdrawal_result(evidence, result)?;
        let evidence = evidence.encode();
        let result = result.encode();
        ensure_claim_bound(evidence.as_ref(), "withdrawal evidence")?;
        ensure_claim_bound(result.as_ref(), "withdrawal result")?;
        let result = complete_claim_transaction(
            &mut self.connection,
            ClaimKind::Withdrawal,
            evidence.as_ref(),
            result.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Drops the exact cached withdrawal evidence after a definitive settlement
    /// rejection, keeping the claim intent open for a fresh cache.
    pub(crate) fn drop_withdrawal_claim_evidence(
        &mut self,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        let encoded = evidence.encode();
        let result = drop_claim_evidence_transaction(
            &mut self.connection,
            ClaimKind::Withdrawal,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Overwrites the open external-payout-claim intent's evidence cache, under the same
    /// immutability rule as [`Self::cache_withdrawal_claim`].
    pub(crate) fn cache_payout_claim(
        &mut self,
        evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_payout_evidence(evidence, &self.account)?;
        let encoded = evidence.encode();
        ensure_claim_bound(encoded.as_ref(), "external-payout evidence")?;
        let result = cache_claim_transaction(
            &mut self.connection,
            ClaimKind::ExternalPayout,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn record_payout_result(
        &mut self,
        evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
        payout: &settlement_rpc::ExternalPayoutResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_payout_evidence(evidence, &self.account)?;
        validate_payout_result(payout, &self.account)?;
        let evidence = evidence.encode();
        let payout = payout.encode();
        ensure_claim_bound(evidence.as_ref(), "external-payout evidence")?;
        ensure_claim_bound(payout.as_ref(), "external payout")?;
        let result = record_claim_result_transaction(
            &mut self.connection,
            ClaimKind::ExternalPayout,
            evidence.as_ref(),
            payout.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn complete_payout_claim(
        &mut self,
        evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
        payout: &settlement_rpc::ExternalPayoutResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_payout_evidence(evidence, &self.account)?;
        validate_payout_result(payout, &self.account)?;
        let evidence = evidence.encode();
        let payout = payout.encode();
        ensure_claim_bound(evidence.as_ref(), "external-payout evidence")?;
        ensure_claim_bound(payout.as_ref(), "external payout")?;
        let result = complete_claim_transaction(
            &mut self.connection,
            ClaimKind::ExternalPayout,
            evidence.as_ref(),
            payout.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Drops the exact cached external-payout evidence after a definitive settlement
    /// rejection, keeping the claim intent open for a fresh cache.
    pub(crate) fn drop_payout_claim_evidence(
        &mut self,
        evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        let encoded = evidence.encode();
        let result = drop_claim_evidence_transaction(
            &mut self.connection,
            ClaimKind::ExternalPayout,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    pub(crate) fn ensure_usable(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "agent database is unusable after a failed mutation"
        );
        Ok(())
    }

    const fn finish_mutation<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn stage_payment(
        &mut self,
        send: &SignedSend<Key, Digest>,
        recovery_root: &VectorRoot<Digest>,
        previous_debit: u64,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_send(send, &self.account, &self.operator, previous_debit)?;
        sql_u64(send.body().cumulative_debit(), "pending cumulative debit")?;
        let encoded = send.encode();
        ensure!(
            encoded.len() <= MAX_PAYMENT_BYTES,
            "signed send encoding exceeds its bound"
        );

        let encoded_root = recovery_root.encode();
        let result = stage_payment_transaction(
            &mut self.connection,
            &self.account,
            recovery_root,
            previous_debit,
            encoded_root.as_ref(),
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Marks the outstanding send submitted before its bytes go on the wire, so the ledger
    /// never claims less than what may have reached the operator.
    pub(crate) fn mark_payment_submitted(&mut self, send: &SignedSend<Key, Digest>) -> Result<()> {
        self.ensure_usable()?;
        let encoded = send.encode();
        let result = mark_payment_submitted_transaction(&mut self.connection, encoded.as_ref());
        self.finish_mutation(result)
    }

    /// Records a staged send proven never to have committed and frees the outstanding slot.
    ///
    /// The caller must hold settlement's proof of non-commitment: a verified finalized-root
    /// opening whose endpoint excludes the send. The abandoned row stays in the ledger so
    /// the wallet's own history is complete, and the retained recovery opening is
    /// deliberately left in place. It is keyed by full root, can be shared with an already
    /// committed sibling payment quoted at the same finalized head, and stays load-bearing
    /// for frozen-root recovery.
    pub(crate) fn abandon_payment(&mut self, send: &SignedSend<Key, Digest>) -> Result<()> {
        self.ensure_usable()?;
        let endpoint = sql_u64(send.body().cumulative_debit(), "abandoned cumulative debit")?;
        let tx_id = send.tx_id::<Sha256>().into_digest();
        let encoded = send.encode();
        let result = abandon_payment_transaction(
            &mut self.connection,
            tx_id.as_ref(),
            endpoint,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Durably commits a send proven finalized whose operator receipts are not held, and
    /// advances the endpoint.
    ///
    /// The caller must hold settlement's proof of commitment: a verified finalized-root
    /// opening whose endpoint equals the send's successor endpoint. The pipelined-exposure
    /// carve-out lets the next send proceed without the receipts.
    pub(crate) fn finalize_payment_unheld(
        &mut self,
        send: &SignedSend<Key, Digest>,
        previous_debit: u64,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_send(send, &self.account, &self.operator, previous_debit)?;
        let endpoint = sql_u64(send.body().cumulative_debit(), "finalized cumulative debit")?;
        let tx_id = send.tx_id::<Sha256>().into_digest();
        let encoded = send.encode();
        let result = finalize_payment_unheld_transaction(
            &mut self.connection,
            previous_debit,
            tx_id.as_ref(),
            endpoint,
            encoded.as_ref(),
        );
        self.finish_mutation(result)
    }

    /// Records every accepted payment at or below a finalized endpoint as finalized.
    ///
    /// This is an opportunistic observation during ordinary quote flows: the caller passes
    /// the endpoint of a Merkle-verified opening against a finalized settlement root, and
    /// an endpoint at or below the watermark skips its redundant write.
    pub(crate) fn observe_finalized(&mut self, endpoint: u64) -> Result<()> {
        self.ensure_usable()?;
        if endpoint <= self.finalized_watermark {
            return Ok(());
        }
        let endpoint_sql = sql_u64(endpoint, "observed finalized endpoint")?;
        let result = observe_finalized_transaction(&mut self.connection, endpoint_sql);
        self.finish_mutation(result)?;
        self.finalized_watermark = endpoint;
        Ok(())
    }

    /// Durably commits one accepted send's receipts and advances the endpoint.
    pub(crate) fn commit_payment(
        &mut self,
        acceptance: &Acceptance,
        previous_debit: u64,
        receipt_count: u64,
    ) -> Result<u64> {
        self.ensure_usable()?;
        validate_acceptance(acceptance, &self.account, &self.operator)?;
        let send = &acceptance.send;

        // The acceptance verification above already authenticated this exact send, so only
        // the debit-chain step remains: the endpoint must be the exact successor of the
        // caller's previous debit.
        ensure!(
            send.body().is_next(previous_debit),
            "accepted debit is not the exact successor"
        );
        let endpoint = sql_u64(send.body().cumulative_debit(), "accepted cumulative debit")?;
        let receipts =
            u64::try_from(acceptance.receipts.len()).context("agent receipt count overflow")?;
        let next_receipt_count = receipt_count
            .checked_add(receipts)
            .context("agent receipt count overflow")?;
        sql_u64(next_receipt_count, "agent receipt count")?;
        let tx_id = send.tx_id::<Sha256>().into_digest();
        let encoded_send = send.encode();
        let encoded = acceptance.encode();
        ensure!(
            encoded.len() <= MAX_ACCEPTANCE_BYTES,
            "acceptance encoding exceeds its bound"
        );

        let result = commit_payment_transaction(
            &mut self.connection,
            previous_debit,
            tx_id.as_ref(),
            endpoint,
            receipts,
            encoded_send.as_ref(),
            encoded.as_ref(),
        );
        self.finish_mutation(result).map(|()| next_receipt_count)
    }

    /// Durably stages one deposit event before custody moves at settlement.
    ///
    /// The event's identifier derives from a volatile nonce and only that exact identifier
    /// can be retried against recorded custody. Staging first means a crash between the
    /// settlement record and the operator credit cannot orphan the deposit: a restarted
    /// wallet retries the same event, which both custody surfaces deduplicate.
    pub(crate) fn stage_deposit(&mut self, event: &DepositEvent) -> Result<()> {
        self.ensure_usable()?;
        validate_deposit(event, &self.account)?;
        let encoded = event.encode();
        ensure!(
            encoded.len() == DEPOSIT_EVENT_BYTES,
            "deposit event encoding has an unexpected length"
        );
        let result = stage_deposit_transaction(&mut self.connection, encoded.as_ref());
        self.finish_mutation(result)
    }

    /// Removes the staged deposit after the operator acknowledged the exact event.
    pub(crate) fn complete_deposit(&mut self, event: &DepositEvent) -> Result<()> {
        self.ensure_usable()?;
        let encoded = event.encode();
        let result = remove_deposit_transaction(
            &mut self.connection,
            encoded.as_ref(),
            "pending deposit completion",
        );
        self.finish_mutation(result)
    }

    /// Discards the staged deposit after settlement confirmed the exact id was never
    /// recorded.
    ///
    /// The caller must hold that confirmation: it proves no custody moved, so abandoning
    /// the event cannot orphan a recorded deposit and a fresh event may be staged.
    pub(crate) fn discard_deposit(&mut self, event: &DepositEvent) -> Result<()> {
        self.ensure_usable()?;
        let encoded = event.encode();
        let result = remove_deposit_transaction(
            &mut self.connection,
            encoded.as_ref(),
            "pending deposit discard",
        );
        self.finish_mutation(result)
    }

    /// Durably records one verified intake page: the accepted pairs and the advanced cursor.
    ///
    /// The pairs and the cursor commit together, so a provider that observes the cursor
    /// advance is guaranteed to hold every credit up to it. Insertion is idempotent per
    /// transaction id, so a crash before this commit leaves the cursor unchanged and the
    /// exact page refetches and reinserts without duplication. Only self-verified pairs
    /// reach here: an invalid pair is never stored, yet the cursor still advances past it.
    pub(crate) fn record_incoming(
        &mut self,
        records: &[IncomingRecord],
        next_cursor: u64,
    ) -> Result<IncomingSummary> {
        self.ensure_usable()?;
        for record in records {
            let encoded = record.pair.encode();
            ensure!(
                !encoded.is_empty() && encoded.len() <= MAX_PAYMENT_BYTES,
                "incoming pair encoding exceeds its bound"
            );
            sql_u64(record.cursor, "incoming cursor")?;
        }
        let result = record_incoming_transaction(&mut self.connection, records, next_cursor);
        self.finish_mutation(result)?;
        read_incoming_summary(&self.connection)
    }

    /// Answers the provider's service-accounting question: has `payer` paid this account under
    /// transaction `tx_id`, and for how much? The payer chooses the transaction id by signing
    /// its send, so it is the natural invoice reference.
    pub(crate) fn paid(&self, payer: &Key, tx_id: &Digest) -> Result<Option<IncomingCredit>> {
        self.ensure_usable()?;
        self.connection
            .query_row(
                "SELECT epoch, shard, amount FROM agent_incoming
                 WHERE payer = ?1 AND tx_id = ?2",
                params![payer.as_ref(), tx_id.as_ref()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .map(|(epoch, shard, amount)| {
                Ok(IncomingCredit {
                    epoch: from_sql_u64(epoch, "incoming epoch")?,
                    shard: from_sql_u64(shard, "incoming shard")?,
                    amount: from_sql_u64(amount, "incoming amount")?,
                })
            })
            .transpose()
    }

    /// Returns the epochs holding incoming credits that reconciliation has not yet decided.
    pub(crate) fn unreconciled_incoming_epochs(&self) -> Result<Vec<u64>> {
        self.ensure_usable()?;
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT epoch FROM agent_incoming
             WHERE epoch NOT IN (SELECT epoch FROM agent_reconciled)
             ORDER BY epoch",
        )?;
        let epochs = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .map(|value| from_sql_u64(value.map_err(anyhow::Error::from)?, "unreconciled epoch"))
            .collect::<Result<Vec<_>>>()?;
        Ok(epochs)
    }

    /// Returns the wallet's highest held receipt in each receive shard of one epoch.
    pub(crate) fn held_receipts(&self, epoch: u64, operator: &Key) -> Result<Vec<HeldReceipt>> {
        self.ensure_usable()?;

        // SQLite resolves the bare columns from the row selected by the single max() aggregate,
        // so each group yields the terminal receipt of its shard.
        let mut statement = self.connection.prepare(
            "SELECT shard, MAX(cumulative_shard_credit), receipt_index, length(pair), pair
             FROM agent_incoming WHERE epoch = ?1 GROUP BY shard ORDER BY shard",
        )?;
        let held = statement
            .query_map([sql_u64(epoch, "epoch")?], |row| {
                let shard = from_sql_u64(row.get(0)?, "held shard").map_err(to_sqlite_error)?;
                let cumulative_shard_credit =
                    from_sql_u64(row.get(1)?, "held credit").map_err(to_sqlite_error)?;
                let receipt_index =
                    from_sql_u64(row.get(2)?, "held index").map_err(to_sqlite_error)?;
                let encoded = read_bounded_blob(row, 3, 4, MAX_PAYMENT_BYTES, "held pair")?;
                let pair = Payment::decode(encoded.as_slice()).map_err(|error| {
                    to_sqlite_error(anyhow::anyhow!("decode held pair: {error}"))
                })?;
                Ok(HeldReceipt {
                    shard,
                    cumulative_shard_credit,
                    receipt_index,
                    pair,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        // Re-verify each terminal pair against its own context before it can back a challenge.
        for receipt in &held {
            let context = context_for_send(receipt.pair.send(), operator);
            receipt
                .pair
                .verify_linked::<Sha256>(&context)
                .context("verify held incoming pair")?;
            ensure!(
                receipt.pair.recipient() == &self.account,
                "held incoming pair credits another account"
            );
        }
        Ok(held)
    }

    /// Durably records that an epoch's held credits reconciled cleanly with the committed close.
    pub(crate) fn mark_reconciled(&mut self, epoch: u64) -> Result<()> {
        self.record_outcome(epoch, ReconcileOutcome::Reconciled)
    }

    /// Durably records that a proven challenge was submitted for an understated epoch.
    pub(crate) fn record_challenge(&mut self, epoch: u64) -> Result<()> {
        self.record_outcome(epoch, ReconcileOutcome::Challenged)
    }

    /// Durably records an epoch whose held credit can no longer be enforced: a finalized close
    /// understated it past the window, or its close never admitted and settlement faulted.
    pub(crate) fn record_unenforceable(&mut self, epoch: u64) -> Result<()> {
        self.record_outcome(epoch, ReconcileOutcome::Unenforceable)
    }

    fn record_outcome(&mut self, epoch: u64, outcome: ReconcileOutcome) -> Result<()> {
        self.ensure_usable()?;
        let result = record_reconcile_transaction(
            &mut self.connection,
            sql_u64(epoch, "reconciled epoch")?,
            outcome as i64,
        );
        self.finish_mutation(result)
    }
}

/// Verifies one acceptance owned by `account`: every entry pair is linked and in entry order.
fn validate_acceptance(acceptance: &Acceptance, account: &Key, operator: &Key) -> Result<()> {
    ensure!(
        acceptance.send.body().payer() == account,
        "accepted payment belongs to another payer"
    );
    acceptance.verify(&context_for_send(&acceptance.send, operator))
}

enum SchemaPresence {
    Empty,
    Complete,
}

fn schema_presence(connection: &Connection) -> Result<SchemaPresence> {
    let has_meta = table_exists(connection, "agent_meta")?;
    let has_openings = table_exists(connection, "agent_state_openings")?;
    let has_pending = table_exists(connection, "agent_pending_payment")?;
    let has_pending_deposit = table_exists(connection, "agent_pending_deposit")?;
    let has_pending_claims = table_exists(connection, "agent_pending_claims")?;
    let has_payments = table_exists(connection, "agent_payments")?;
    let has_incoming_cursor = table_exists(connection, "agent_incoming_cursor")?;
    let has_incoming = table_exists(connection, "agent_incoming")?;
    let has_reconciled = table_exists(connection, "agent_reconciled")?;
    let has_unexpected: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema
             WHERE (type = 'table'
                    AND name NOT LIKE 'sqlite_%'
                    AND name NOT IN (
                        'agent_meta', 'agent_state_openings',
                        'agent_pending_payment', 'agent_pending_deposit',
                        'agent_pending_claims', 'agent_payments',
                        'agent_incoming_cursor', 'agent_incoming', 'agent_reconciled'
                    ))
                OR type IN ('trigger', 'view')
                OR (type = 'index'
                    AND name NOT LIKE 'sqlite_autoindex_%'
                    AND name NOT IN (
                        'agent_payments_settled',
                        'agent_incoming_payer_tx', 'agent_incoming_epoch_shard'
                    ))
             LIMIT 1
         )",
        [],
        |row| row.get(0),
    )?;

    if !has_meta
        && !has_openings
        && !has_pending
        && !has_pending_deposit
        && !has_pending_claims
        && !has_payments
        && !has_incoming_cursor
        && !has_incoming
        && !has_reconciled
        && !has_unexpected
    {
        return Ok(SchemaPresence::Empty);
    }
    ensure!(
        has_meta
            && has_openings
            && has_pending
            && has_pending_deposit
            && has_pending_claims
            && has_payments
            && has_incoming_cursor
            && has_incoming
            && has_reconciled
            && !has_unexpected,
        "incompatible agent database schema"
    );
    Ok(SchemaPresence::Complete)
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1 LIMIT 1
         )",
        [table],
        |row| row.get(0),
    )?)
}

fn configure_durability(connection: &Connection, in_memory: bool) -> Result<()> {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .context("enable SQLite agent WAL")?;
    ensure!(
        (in_memory && journal_mode.eq_ignore_ascii_case("memory"))
            || journal_mode.eq_ignore_ascii_case("wal"),
        "SQLite agent database did not enter WAL mode"
    );
    connection
        .execute_batch("PRAGMA synchronous = FULL;")
        .context("configure SQLite agent durability")?;
    let locking_mode: String = connection
        .query_row("PRAGMA locking_mode = EXCLUSIVE", [], |row| row.get(0))
        .context("reserve SQLite agent ownership")?;
    ensure!(
        locking_mode.eq_ignore_ascii_case("exclusive"),
        "SQLite agent database did not enter exclusive locking mode"
    );
    connection
        .execute_batch("BEGIN EXCLUSIVE; COMMIT;")
        .context("acquire SQLite agent ownership")?;
    Ok(())
}

fn initialize_schema(
    connection: &mut Connection,
    account: &Key,
    deployment: &Digest,
    operator: &Key,
) -> Result<()> {
    let schema = format!(
        "CREATE TABLE agent_meta (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             schema_version INTEGER NOT NULL,
             account BLOB NOT NULL CHECK (length(account) = {key_size}),
             deployment BLOB NOT NULL CHECK (length(deployment) = {digest_size}),
             operator BLOB NOT NULL CHECK (length(operator) = {key_size})
         );

         CREATE TABLE agent_state_openings (
             root BLOB NOT NULL PRIMARY KEY CHECK (length(root) = {root_size}),
             opening BLOB NOT NULL CHECK (
                 length(opening) BETWEEN {min_opening_size} AND {max_opening_size}
             )
         );

         CREATE TABLE agent_pending_payment (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             recovery_root BLOB NOT NULL CHECK (length(recovery_root) = {root_size}),
             send BLOB NOT NULL CHECK (
                 length(send) BETWEEN 1 AND {max_send_size}
             ),
             state INTEGER NOT NULL CHECK (state IN (1, 2)),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE,
             FOREIGN KEY (recovery_root) REFERENCES agent_state_openings(root)
         );

         CREATE TABLE agent_pending_deposit (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             event BLOB NOT NULL CHECK (length(event) = {deposit_event_size}),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE
         );

         CREATE TABLE agent_pending_claims (
             kind INTEGER PRIMARY KEY CHECK (kind IN (1, 2)),
             evidence BLOB CHECK (
                 evidence IS NULL OR length(evidence) BETWEEN 1 AND {max_claim_size}
             ),
             result BLOB CHECK (
                 result IS NULL OR (
                     evidence IS NOT NULL
                     AND length(result) BETWEEN 1 AND {max_claim_size}
                 )
             )
         );

         CREATE TABLE agent_payments (
             tx_id BLOB PRIMARY KEY CHECK (length(tx_id) = {digest_size}),
             cumulative_debit INTEGER NOT NULL CHECK (cumulative_debit > 0),
             recovery_root BLOB NOT NULL CHECK (length(recovery_root) = {root_size}),
             send BLOB NOT NULL CHECK (
                 length(send) BETWEEN 1 AND {max_send_size}
             ),
             state INTEGER NOT NULL CHECK (state IN (3, 4, 5)),
             receipts INTEGER CHECK (receipts IS NULL OR receipts > 0),
             acceptance BLOB CHECK (
                 acceptance IS NULL OR length(acceptance) BETWEEN 1 AND {max_acceptance_size}
             ),
             CHECK ((receipts IS NULL) = (acceptance IS NULL)),
             CHECK (state != 3 OR acceptance IS NOT NULL),
             CHECK (state != 5 OR acceptance IS NULL),
             FOREIGN KEY (recovery_root) REFERENCES agent_state_openings(root)
         );

         CREATE INDEX agent_payments_settled
             ON agent_payments (state, cumulative_debit);

         CREATE TABLE agent_incoming_cursor (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             cursor INTEGER NOT NULL CHECK (cursor >= 0)
         );

         CREATE TABLE agent_incoming (
             tx_id BLOB PRIMARY KEY CHECK (length(tx_id) = {digest_size}),
             payer BLOB NOT NULL CHECK (length(payer) = {key_size}),
             epoch INTEGER NOT NULL CHECK (epoch >= 0),
             anchor BLOB NOT NULL CHECK (length(anchor) = {digest_size}),
             shard INTEGER NOT NULL CHECK (shard >= 0),
             cumulative_shard_credit INTEGER NOT NULL CHECK (cumulative_shard_credit >= 0),
             receipt_index INTEGER NOT NULL CHECK (receipt_index >= 0),
             amount INTEGER NOT NULL CHECK (amount >= 0),
             cursor INTEGER NOT NULL CHECK (cursor > 0),
             pair BLOB NOT NULL CHECK (length(pair) BETWEEN 1 AND {max_pair_size})
         );
         CREATE INDEX agent_incoming_payer_tx ON agent_incoming (payer, tx_id);
         CREATE INDEX agent_incoming_epoch_shard ON agent_incoming (epoch, shard);

         CREATE TABLE agent_reconciled (
             epoch INTEGER PRIMARY KEY CHECK (epoch >= 0),
             status INTEGER NOT NULL CHECK (status IN (1, 2, 3))
         );",
        key_size = Key::SIZE,
        digest_size = Digest::SIZE,
        root_size = VectorRoot::<Digest>::SIZE,
        max_send_size = MAX_PAYMENT_BYTES,
        max_acceptance_size = MAX_ACCEPTANCE_BYTES,
        min_opening_size = MIN_STATE_OPENING_BYTES,
        max_opening_size = MAX_STATE_OPENING_BYTES,
        max_claim_size = MAX_PENDING_CLAIM_BYTES,
        max_pair_size = MAX_PAYMENT_BYTES,
        deposit_event_size = DEPOSIT_EVENT_BYTES,
    );
    let encoded_account = account.encode();
    let encoded_deployment = deployment.encode();
    let encoded_operator = operator.encode();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin SQLite agent initialization")?;
    transaction
        .execute_batch(&schema)
        .context("create SQLite agent schema")?;
    transaction.execute(
        "INSERT INTO agent_meta (
             singleton, schema_version, account, deployment, operator
         ) VALUES (1, ?1, ?2, ?3, ?4)",
        params![
            SCHEMA_VERSION,
            encoded_account.as_ref(),
            encoded_deployment.as_ref(),
            encoded_operator.as_ref(),
        ],
    )?;
    transaction.execute(
        "INSERT INTO agent_incoming_cursor (singleton, cursor) VALUES (1, 0)",
        [],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("agent initialization", source))?;
    Ok(())
}

fn read_binding(connection: &Connection) -> Result<Binding> {
    let mut statement = connection.prepare(
        "SELECT singleton, schema_version,
                length(account), account,
                length(deployment), deployment,
                length(operator), operator
         FROM agent_meta
         ORDER BY singleton
         LIMIT 2",
    )?;
    let mut rows = statement.query([])?;
    let row = rows.next()?.context("agent database metadata is missing")?;
    ensure!(
        row.get::<_, i64>(0)? == 1,
        "agent database metadata singleton is not canonical"
    );
    let schema_version: i64 = row.get(1)?;
    let encoded_account = read_fixed_blob(row, 2, 3, Key::SIZE, "agent account")?;
    let encoded_deployment = read_fixed_blob(row, 4, 5, Digest::SIZE, "agent deployment")?;
    let encoded_operator = read_fixed_blob(row, 6, 7, Key::SIZE, "agent operator")?;
    ensure!(
        rows.next()?.is_none(),
        "agent database has extra metadata rows"
    );
    ensure!(
        schema_version == SCHEMA_VERSION,
        "unsupported agent database schema version {schema_version}"
    );

    Ok(Binding {
        account: Key::decode(encoded_account.as_slice()).context("decode agent account")?,
        deployment: Digest::decode(encoded_deployment.as_slice())
            .context("decode agent deployment")?,
        operator: Key::decode(encoded_operator.as_slice()).context("decode agent operator")?,
    })
}

fn read_state(connection: &Connection, account: &Key, operator: &Key) -> Result<State> {
    let (cumulative_debit, receipt_count) = read_receipt_state(connection, account, operator)?;
    let pending_payment = read_pending_payment(connection, account)?;
    let pending_deposit = read_pending_deposit(connection, account)?;
    let (pending_withdrawal_claim, pending_payout_claim) =
        read_pending_claims(connection, account)?;
    if let Some(pending) = &pending_payment {
        validate_send(&pending.send, account, operator, cumulative_debit)?;
        sql_u64(
            pending.send.body().cumulative_debit(),
            "pending cumulative debit",
        )?;
    }

    let incoming = read_incoming_summary(connection)?;
    let last_reconciled_epoch = read_last_reconciled(connection)?;

    Ok(State {
        cumulative_debit,
        pending_payment,
        pending_deposit,
        pending_withdrawal_claim,
        pending_payout_claim,
        receipt_count,
        incoming,
        last_reconciled_epoch,
    })
}

fn read_incoming_summary(connection: &Connection) -> Result<IncomingSummary> {
    let cursor = from_sql_u64(
        connection.query_row(
            "SELECT cursor FROM agent_incoming_cursor WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?,
        "incoming cursor",
    )?;
    let (total, count) = connection.query_row(
        "SELECT COALESCE(SUM(amount), 0), COUNT(*) FROM agent_incoming",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok(IncomingSummary {
        total: from_sql_u64(total, "incoming total")?,
        count: from_sql_u64(count, "incoming count")?,
        cursor,
    })
}

fn read_last_reconciled(connection: &Connection) -> Result<Option<u64>> {
    connection
        .query_row(
            "SELECT MAX(epoch) FROM agent_reconciled WHERE status = ?1",
            [ReconcileOutcome::Reconciled as i64],
            |row| row.get::<_, Option<i64>>(0),
        )?
        .map(|epoch| from_sql_u64(epoch, "reconciled epoch"))
        .transpose()
}

fn read_receipt_state(
    connection: &Connection,
    account: &Key,
    operator: &Key,
) -> Result<(u64, u64)> {
    let receipt_count = from_sql_u64(
        connection.query_row(
            "SELECT COALESCE(SUM(receipts), 0) FROM agent_payments WHERE state IN (?1, ?2)",
            SETTLED_STATES,
            |row| row.get(0),
        )?,
        "agent receipt count",
    )?;

    // The endpoint is carried by the latest committed row: an acceptance when receipts are
    // held, or a bare finalized send when the finalized root proved commitment without them.
    let stored = connection
        .query_row(
            "SELECT cumulative_debit, receipts,
                    length(recovery_root), recovery_root,
                    length(send), send,
                    length(acceptance), acceptance
             FROM agent_payments
             WHERE state IN (?1, ?2)
             ORDER BY cumulative_debit DESC
             LIMIT 1",
            SETTLED_STATES,
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    read_fixed_blob(row, 2, 3, VectorRoot::<Digest>::SIZE, "recovery root")?,
                    read_bounded_blob(row, 4, 5, MAX_PAYMENT_BYTES, "retained send")?,
                    read_optional_bounded_blob(
                        row,
                        6,
                        7,
                        MAX_ACCEPTANCE_BYTES,
                        "retained acceptance",
                    )?,
                ))
            },
        )
        .optional()?;
    let Some((stored_endpoint, stored_receipts, encoded_root, encoded_send, encoded)) = stored
    else {
        ensure!(receipt_count == 0, "agent receipt count is inconsistent");
        return Ok((0, 0));
    };
    let stored_endpoint = from_sql_u64(stored_endpoint, "retained cumulative debit")?;
    let recovery_root =
        VectorRoot::decode(encoded_root.as_slice()).context("decode receipt recovery root")?;
    read_recovery_opening(connection, &recovery_root, account)?
        .context("receipt recovery opening is missing")?;
    match (encoded, stored_receipts) {
        (Some(encoded), Some(stored_receipts)) => {
            let stored_receipts = from_sql_u64(stored_receipts, "retained receipt count")?;
            let acceptance =
                Acceptance::decode(encoded.as_slice()).context("decode retained acceptance")?;
            validate_acceptance(&acceptance, account, operator)
                .context("verify retained acceptance")?;
            ensure!(
                acceptance.send.encode().as_ref() == encoded_send.as_slice(),
                "retained acceptance does not carry its ledger send"
            );
            ensure!(
                u64::try_from(acceptance.receipts.len()).ok() == Some(stored_receipts),
                "retained acceptance receipt count is inconsistent"
            );
            ensure!(
                acceptance.send.body().cumulative_debit() == stored_endpoint,
                "retained acceptance has another debit endpoint"
            );
        }
        (None, None) => {
            let send = SignedSend::decode(encoded_send.as_slice())
                .context("decode retained finalized send")?;
            ensure!(
                send.body().payer() == account,
                "retained finalized send belongs to another payer"
            );
            send.verify(&context_for_send(&send, operator))
                .context("verify retained finalized send")?;
            ensure!(
                send.body().cumulative_debit() == stored_endpoint,
                "retained finalized send has another debit endpoint"
            );
        }
        _ => anyhow::bail!("retained receipt count and acceptance disagree"),
    }
    Ok((stored_endpoint, receipt_count))
}

fn read_pending_payment(connection: &Connection, account: &Key) -> Result<Option<PendingPayment>> {
    let mut statement = connection.prepare(
        "SELECT singleton,
                length(recovery_root), recovery_root,
                length(send), send,
                state
         FROM agent_pending_payment
         ORDER BY singleton
         LIMIT 2",
    )?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    ensure!(
        row.get::<_, i64>(0)? == 1,
        "agent database pending payment singleton is not canonical"
    );
    let encoded_root = read_fixed_blob(
        row,
        1,
        2,
        VectorRoot::<Digest>::SIZE,
        "pending recovery root",
    )?;
    let encoded_send = read_bounded_blob(row, 3, 4, MAX_PAYMENT_BYTES, "pending signed send")?;
    let state = row.get::<_, i64>(5)?;
    ensure!(
        state == PaymentState::Staged as i64 || state == PaymentState::Submitted as i64,
        "pending payment state is not canonical"
    );
    ensure!(
        rows.next()?.is_none(),
        "agent database has multiple pending payments"
    );
    let recovery_root =
        VectorRoot::decode(encoded_root.as_slice()).context("decode pending recovery root")?;
    read_recovery_opening(connection, &recovery_root, account)?
        .context("pending recovery opening is missing")?;
    Ok(Some(PendingPayment {
        send: SignedSend::decode(encoded_send.as_slice()).context("decode pending signed send")?,
        recovery_root,
    }))
}

fn read_pending_deposit(connection: &Connection, account: &Key) -> Result<Option<DepositEvent>> {
    let mut statement = connection.prepare(
        "SELECT singleton, length(event), event
         FROM agent_pending_deposit
         ORDER BY singleton
         LIMIT 2",
    )?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    ensure!(
        row.get::<_, i64>(0)? == 1,
        "agent database pending deposit singleton is not canonical"
    );
    let encoded = read_fixed_blob(row, 1, 2, DEPOSIT_EVENT_BYTES, "pending deposit event")?;
    ensure!(
        rows.next()?.is_none(),
        "agent database has multiple pending deposits"
    );
    let event = DepositEvent::decode(encoded.as_slice()).context("decode pending deposit event")?;
    validate_deposit(&event, account)?;
    Ok(Some(event))
}

fn read_pending_claims(
    connection: &Connection,
    account: &Key,
) -> Result<(Option<PendingWithdrawalClaim>, Option<PendingPayoutClaim>)> {
    let mut statement = connection.prepare(
        "SELECT kind, length(evidence), evidence, length(result), result
         FROM agent_pending_claims
         ORDER BY kind
         LIMIT 3",
    )?;
    let mut rows = statement.query([])?;
    let mut withdrawal = None;
    let mut payout = None;
    while let Some(row) = rows.next()? {
        let kind = row.get::<_, i64>(0)?;
        let evidence = read_optional_bounded_blob(
            row,
            1,
            2,
            MAX_PENDING_CLAIM_BYTES,
            "pending claim evidence",
        )?;
        let result =
            read_optional_bounded_blob(row, 3, 4, MAX_PENDING_CLAIM_BYTES, "pending claim result")?;
        ensure!(
            result.is_none() || evidence.is_some(),
            "recorded claim result has no pinned evidence"
        );
        match kind {
            value if value == ClaimKind::Withdrawal as i64 => {
                ensure!(
                    withdrawal.is_none(),
                    "multiple withdrawal claims are pending"
                );
                let evidence = evidence
                    .map(|encoded| {
                        operator_rpc::WithdrawalEvidenceResponse::decode(encoded.as_slice())
                            .context("decode pending withdrawal evidence")
                    })
                    .transpose()?;
                let result = result
                    .map(|encoded| {
                        settlement_rpc::WithdrawalResponse::decode(encoded.as_slice())
                            .context("decode pending withdrawal result")
                    })
                    .transpose()?;
                if let Some(evidence) = &evidence {
                    validate_withdrawal_evidence(evidence, account)?;
                    if let Some(result) = &result {
                        validate_withdrawal_result(evidence, result)?;
                    }
                }
                withdrawal = Some(PendingWithdrawalClaim { evidence, result });
            }
            value if value == ClaimKind::ExternalPayout as i64 => {
                ensure!(payout.is_none(), "multiple external payouts are pending");
                let evidence = evidence
                    .map(|encoded| {
                        operator_rpc::ExternalPayoutEvidenceResponse::decode(encoded.as_slice())
                            .context("decode pending external-payout evidence")
                    })
                    .transpose()?;
                let result = result
                    .map(|encoded| {
                        settlement_rpc::ExternalPayoutResponse::decode(encoded.as_slice())
                            .context("decode pending external payout")
                    })
                    .transpose()?;
                if let Some(evidence) = &evidence {
                    validate_payout_evidence(evidence, account)?;
                }
                if let Some(result) = &result {
                    validate_payout_result(result, account)?;
                }
                payout = Some(PendingPayoutClaim { evidence, result });
            }
            _ => anyhow::bail!("pending claim kind is not canonical"),
        }
    }
    Ok((withdrawal, payout))
}

fn validate_recovery_opening(
    root: &VectorRoot<Digest>,
    opening: &StateOpening<Key, Digest>,
    account: &Key,
) -> Result<()> {
    ensure!(
        opening.leaf.account == *account,
        "state opening belongs to another account"
    );
    ensure!(
        opening.leaf.state.active && opening.leaf.state.balance > 0,
        "state opening does not contain a live payer"
    );
    ensure!(
        opening.proof.proof.leaf_count <= MAX_ACCOUNTS as u32,
        "state opening exceeds the terminal account bound"
    );
    opening
        .proof
        .verify::<Sha256>(VectorKind::State, root, opening.leaf.encode().as_ref())
        .context("verify payer state opening")
}

fn validate_deposit(event: &DepositEvent, account: &Key) -> Result<()> {
    ensure!(
        &event.account == account,
        "pending deposit belongs to another account"
    );
    ensure!(event.amount > 0, "pending deposit has no value");
    Ok(())
}

fn validate_withdrawal_evidence(
    evidence: &operator_rpc::WithdrawalEvidenceResponse,
    account: &Key,
) -> Result<()> {
    ensure!(
        &evidence.account == account,
        "pending withdrawal evidence belongs to another account"
    );
    Ok(())
}

fn validate_withdrawal_result(
    evidence: &operator_rpc::WithdrawalEvidenceResponse,
    result: &settlement_rpc::WithdrawalResponse,
) -> Result<()> {
    ensure!(
        result.destination == *evidence.claim.output().destination()
            && result.amount == evidence.claim.output().amount(),
        "pending withdrawal result differs from its evidence"
    );
    Ok(())
}

fn validate_payout_evidence(
    evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
    account: &Key,
) -> Result<()> {
    ensure!(
        evidence.claim.recipient() == account,
        "pending external-payout evidence belongs to another account"
    );
    Ok(())
}

fn validate_payout_result(
    result: &settlement_rpc::ExternalPayoutResponse,
    account: &Key,
) -> Result<()> {
    ensure!(
        &result.recipient == account,
        "pending external payout belongs to another account"
    );
    Ok(())
}

fn ensure_claim_bound(encoded: &[u8], field: &str) -> Result<()> {
    ensure!(
        !encoded.is_empty() && encoded.len() <= MAX_PENDING_CLAIM_BYTES,
        "{field} exceeds its persistence bound"
    );
    Ok(())
}

fn read_recovery_opening(
    connection: &Connection,
    root: &VectorRoot<Digest>,
    account: &Key,
) -> Result<Option<StateOpening<Key, Digest>>> {
    let encoded_root = root.encode();
    let encoded = connection
        .query_row(
            "SELECT length(opening), opening
             FROM agent_state_openings WHERE root = ?1",
            [encoded_root.as_ref()],
            |row| read_bounded_blob(row, 0, 1, MAX_STATE_OPENING_BYTES, "state opening"),
        )
        .optional()?;
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let opening = StateOpening::decode(encoded.as_slice()).context("decode state opening")?;
    validate_recovery_opening(root, &opening, account)?;
    Ok(Some(opening))
}

fn validate_send(
    send: &SignedSend<Key, Digest>,
    account: &Key,
    operator: &Key,
    previous_debit: u64,
) -> Result<()> {
    ensure!(
        send.body().payer() == account,
        "pending payment belongs to another payer"
    );
    send.verify_next(&context_for_send(send, operator), previous_debit)
        .context("verify pending debit successor")
}

fn context_for_send(send: &SignedSend<Key, Digest>, operator: &Key) -> PaymentContext<Key, Digest> {
    PaymentContext::new(*send.body().anchor(), send.body().epoch(), operator.clone())
}

fn retain_recovery_opening_transaction(
    connection: &mut Connection,
    account: &Key,
    root: &VectorRoot<Digest>,
    encoded_root: &[u8],
    opening: &StateOpening<Key, Digest>,
    encoded_opening: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin recovery opening retention")?;
    transaction.execute(
        "INSERT INTO agent_state_openings (root, opening) VALUES (?1, ?2)
         ON CONFLICT(root) DO NOTHING",
        params![encoded_root, encoded_opening],
    )?;
    let retained = read_recovery_opening(&transaction, root, account)?
        .context("retained recovery opening is missing")?;
    ensure!(
        retained == *opening,
        "state root is bound to another recovery opening"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("recovery opening retention", source))?;
    Ok(())
}

fn stage_payment_transaction(
    connection: &mut Connection,
    account: &Key,
    recovery_root: &VectorRoot<Digest>,
    previous_debit: u64,
    encoded_root: &[u8],
    encoded_send: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending payment stage")?;
    ensure!(
        latest_debit(&transaction)? == previous_debit,
        "agent debit changed before payment staging"
    );
    read_recovery_opening(&transaction, recovery_root, account)?
        .context("payment recovery opening is missing")?;
    let pending_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_pending_payment LIMIT 1)",
        [],
        |row| row.get(0),
    )?;
    ensure!(!pending_exists, "another payment is already staged");
    transaction.execute(
        "INSERT INTO agent_pending_payment (singleton, recovery_root, send, state)
         VALUES (1, ?1, ?2, ?3)",
        params![encoded_root, encoded_send, PaymentState::Staged as i64],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending payment stage", source))?;
    Ok(())
}

fn mark_payment_submitted_transaction(
    connection: &mut Connection,
    encoded_send: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin payment submission mark")?;
    let marked = transaction.execute(
        "UPDATE agent_pending_payment SET state = ?1 WHERE singleton = 1 AND send = ?2",
        params![PaymentState::Submitted as i64, encoded_send],
    )?;
    ensure!(marked == 1, "no staged payment matched the submission mark");
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("payment submission mark", source))?;
    Ok(())
}

/// Moves the outstanding slot's exact send into the ledger and clears the slot.
///
/// An endpoint-advancing conclusion supplies the caller's committed debit, which must
/// still be the ledger's latest endpoint inside this same transaction.
#[allow(
    clippy::too_many_arguments,
    reason = "one durable conclusion, three call sites"
)]
fn conclude_payment_transaction(
    connection: &mut Connection,
    operation: &'static str,
    previous_debit: Option<u64>,
    tx_id: &[u8],
    endpoint: i64,
    state: PaymentState,
    receipts: Option<i64>,
    encoded_send: &[u8],
    encoded_acceptance: Option<&[u8]>,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .with_context(|| format!("begin {operation}"))?;
    if let Some(previous_debit) = previous_debit {
        ensure!(
            latest_debit(&transaction)? == previous_debit,
            "agent debit changed before {operation}"
        );
    }
    ensure!(
        transaction.execute(
            "INSERT INTO agent_payments (
                 tx_id, cumulative_debit, recovery_root, send, state, receipts, acceptance
             )
             SELECT ?1, ?2, recovery_root, send, ?3, ?4, ?5
             FROM agent_pending_payment WHERE singleton = 1 AND send = ?6",
            params![
                tx_id,
                endpoint,
                state as i64,
                receipts,
                encoded_acceptance,
                encoded_send,
            ],
        )? == 1,
        "pending payment changed before {operation}"
    );
    ensure!(
        transaction.execute(
            "DELETE FROM agent_pending_payment WHERE singleton = 1 AND send = ?1",
            [encoded_send],
        )? == 1,
        "pending payment changed before {operation}"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new(operation, source))?;
    Ok(())
}

fn abandon_payment_transaction(
    connection: &mut Connection,
    tx_id: &[u8],
    endpoint: i64,
    encoded_send: &[u8],
) -> Result<()> {
    conclude_payment_transaction(
        connection,
        "payment abandonment",
        None,
        tx_id,
        endpoint,
        PaymentState::Abandoned,
        None,
        encoded_send,
        None,
    )
}

fn finalize_payment_unheld_transaction(
    connection: &mut Connection,
    previous_debit: u64,
    tx_id: &[u8],
    endpoint: i64,
    encoded_send: &[u8],
) -> Result<()> {
    conclude_payment_transaction(
        connection,
        "finalized payment commit",
        Some(previous_debit),
        tx_id,
        endpoint,
        PaymentState::Finalized,
        None,
        encoded_send,
        None,
    )
}

fn observe_finalized_transaction(connection: &mut Connection, endpoint: i64) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin finalized observation")?;
    transaction.execute(
        "UPDATE agent_payments SET state = ?1
         WHERE state = ?2 AND cumulative_debit <= ?3",
        params![
            PaymentState::Finalized as i64,
            PaymentState::Accepted as i64,
            endpoint,
        ],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("finalized observation", source))?;
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "one durable commit, one call site"
)]
fn commit_payment_transaction(
    connection: &mut Connection,
    previous_debit: u64,
    tx_id: &[u8],
    endpoint: i64,
    receipts: u64,
    encoded_send: &[u8],
    encoded_acceptance: &[u8],
) -> Result<()> {
    conclude_payment_transaction(
        connection,
        "accepted payment",
        Some(previous_debit),
        tx_id,
        endpoint,
        PaymentState::Accepted,
        Some(sql_u64(receipts, "retained receipt count")?),
        encoded_send,
        Some(encoded_acceptance),
    )
}

fn stage_deposit_transaction(connection: &mut Connection, encoded_event: &[u8]) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending deposit stage")?;
    transaction.execute(
        "INSERT INTO agent_pending_deposit (singleton, event) VALUES (1, ?1)
         ON CONFLICT(singleton) DO NOTHING",
        [encoded_event],
    )?;
    let stored = transaction
        .query_row(
            "SELECT event FROM agent_pending_deposit WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .context("staged deposit event is missing")?;
    ensure!(stored == encoded_event, "another deposit is already staged");
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending deposit stage", source))?;
    Ok(())
}

fn remove_deposit_transaction(
    connection: &mut Connection,
    encoded_event: &[u8],
    operation: &'static str,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .with_context(|| format!("begin {operation}"))?;
    ensure!(
        transaction.execute(
            "DELETE FROM agent_pending_deposit WHERE singleton = 1 AND event = ?1",
            [encoded_event],
        )? == 1,
        "{operation} does not match durable staging"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new(operation, source))?;
    Ok(())
}

fn record_incoming_transaction(
    connection: &mut Connection,
    records: &[IncomingRecord],
    next_cursor: u64,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin incoming intake record")?;
    let current = from_sql_u64(
        transaction.query_row(
            "SELECT cursor FROM agent_incoming_cursor WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?,
        "incoming cursor",
    )?;
    {
        let mut insert = transaction.prepare_cached(
            "INSERT INTO agent_incoming (
                 tx_id, payer, epoch, anchor, shard,
                 cumulative_shard_credit, receipt_index, amount, cursor, pair
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(tx_id) DO NOTHING",
        )?;
        for record in records {
            let encoded = record.pair.encode();
            insert.execute(params![
                record.tx_id.as_ref(),
                record.payer.as_ref(),
                sql_u64(record.epoch, "incoming epoch")?,
                record.anchor.as_ref(),
                sql_u64(record.shard, "incoming shard")?,
                sql_u64(record.cumulative_shard_credit, "incoming credit")?,
                sql_u64(record.receipt_index, "incoming index")?,
                sql_u64(record.amount, "incoming amount")?,
                sql_u64(record.cursor, "incoming cursor")?,
                encoded.as_ref(),
            ])?;
        }
    }

    // The cursor never rewinds, so an out-of-order or duplicate page cannot lose ground.
    let advanced = current.max(next_cursor);
    transaction.execute(
        "UPDATE agent_incoming_cursor SET cursor = ?1 WHERE singleton = 1",
        [sql_u64(advanced, "incoming cursor")?],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("incoming intake record", source))?;
    Ok(())
}

fn record_reconcile_transaction(
    connection: &mut Connection,
    epoch: i64,
    status: i64,
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin reconcile outcome record")?;

    // The first recorded outcome for an epoch is durable: reconcile never reopens a decided
    // epoch, so an idempotent re-run leaves it unchanged.
    transaction.execute(
        "INSERT INTO agent_reconciled (epoch, status) VALUES (?1, ?2)
         ON CONFLICT(epoch) DO NOTHING",
        params![epoch, status],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("reconcile outcome record", source))?;
    Ok(())
}

fn open_claim_transaction(connection: &mut Connection, kind: ClaimKind) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin claim intent open")?;
    transaction.execute(
        "INSERT INTO agent_pending_claims (kind, evidence, result)
         VALUES (?1, NULL, NULL)
         ON CONFLICT(kind) DO NOTHING",
        [kind as i64],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("claim intent open", source))?;
    Ok(())
}

fn cache_claim_transaction(
    connection: &mut Connection,
    kind: ClaimKind,
    evidence: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin claim evidence cache")?;
    let result_recorded: Option<bool> = transaction
        .query_row(
            "SELECT result IS NOT NULL FROM agent_pending_claims WHERE kind = ?1",
            [kind as i64],
            |row| row.get(0),
        )
        .optional()?;
    let result_recorded = result_recorded.context("no claim intent is open")?;
    ensure!(
        !result_recorded,
        "claim evidence with a recorded result is immutable"
    );
    transaction.execute(
        "UPDATE agent_pending_claims SET evidence = ?1 WHERE kind = ?2",
        params![evidence, kind as i64],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("claim evidence cache", source))?;
    Ok(())
}

fn record_claim_result_transaction(
    connection: &mut Connection,
    kind: ClaimKind,
    evidence: &[u8],
    result: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending claim result")?;
    let (stored_evidence, stored_result) = transaction
        .query_row(
            "SELECT evidence, result FROM agent_pending_claims WHERE kind = ?1",
            [kind as i64],
            |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                ))
            },
        )
        .context("pending claim evidence is missing")?;
    ensure!(
        stored_evidence.as_deref() == Some(evidence),
        "another claim of this kind is pending"
    );
    if let Some(stored_result) = stored_result {
        ensure!(stored_result == result, "pending claim has another result");
    } else {
        ensure!(
            transaction.execute(
                "UPDATE agent_pending_claims SET result = ?1
                 WHERE kind = ?2 AND evidence = ?3 AND result IS NULL",
                params![result, kind as i64, evidence],
            )? == 1,
            "pending claim changed before its result was recorded"
        );
    }
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending claim result", source))?;
    Ok(())
}

fn drop_claim_evidence_transaction(
    connection: &mut Connection,
    kind: ClaimKind,
    evidence: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin claim evidence drop")?;
    let dropped = transaction.execute(
        "UPDATE agent_pending_claims SET evidence = NULL
         WHERE kind = ?1 AND evidence = ?2 AND result IS NULL",
        params![kind as i64, evidence],
    )?;
    ensure!(dropped == 1, "no cached claim evidence matched the drop");
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("claim evidence drop", source))?;
    Ok(())
}

fn complete_claim_transaction(
    connection: &mut Connection,
    kind: ClaimKind,
    evidence: &[u8],
    result: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending claim completion")?;
    ensure!(
        transaction.execute(
            "DELETE FROM agent_pending_claims
             WHERE kind = ?1 AND evidence = ?2 AND result = ?3",
            params![kind as i64, evidence, result],
        )? == 1,
        "pending claim completion does not match durable evidence"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending claim completion", source))?;
    Ok(())
}

fn latest_debit(connection: &Connection) -> Result<u64> {
    let endpoint = connection
        .query_row(
            "SELECT cumulative_debit
             FROM agent_payments
             WHERE state IN (?1, ?2)
             ORDER BY cumulative_debit DESC
             LIMIT 1",
            SETTLED_STATES,
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    endpoint.map_or(Ok(0), |value| {
        from_sql_u64(value, "retained cumulative debit")
    })
}

fn latest_finalized(connection: &Connection) -> Result<u64> {
    let endpoint = connection
        .query_row(
            "SELECT cumulative_debit
             FROM agent_payments
             WHERE state = ?1
             ORDER BY cumulative_debit DESC
             LIMIT 1",
            [PaymentState::Finalized as i64],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    endpoint.map_or(Ok(0), |value| {
        from_sql_u64(value, "finalized cumulative debit")
    })
}

fn read_fixed_blob(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    expected: usize,
    field: &str,
) -> rusqlite::Result<Vec<u8>> {
    let length = usize::try_from(row.get::<_, i64>(length_column)?)
        .map_err(|_| to_sqlite_error(anyhow::anyhow!("invalid {field} length")))?;
    if length != expected {
        return Err(to_sqlite_error(anyhow::anyhow!(
            "invalid {field} length {length}, expected {expected}"
        )));
    }
    row.get(value_column)
}

fn read_bounded_blob(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    maximum: usize,
    field: &str,
) -> rusqlite::Result<Vec<u8>> {
    let length = usize::try_from(row.get::<_, i64>(length_column)?)
        .map_err(|_| to_sqlite_error(anyhow::anyhow!("invalid {field} length")))?;
    if length == 0 || length > maximum {
        return Err(to_sqlite_error(anyhow::anyhow!(
            "invalid {field} length {length}, maximum {maximum}"
        )));
    }
    row.get(value_column)
}

fn read_optional_bounded_blob(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    maximum: usize,
    field: &str,
) -> rusqlite::Result<Option<Vec<u8>>> {
    let length = row.get::<_, Option<i64>>(length_column)?;
    let value = row.get::<_, Option<Vec<u8>>>(value_column)?;
    match (length, value) {
        (None, None) => Ok(None),
        (Some(length), Some(value)) => {
            let length = usize::try_from(length)
                .map_err(|_| to_sqlite_error(anyhow::anyhow!("invalid {field} length")))?;
            if length == 0 || length > maximum || value.len() != length {
                return Err(to_sqlite_error(anyhow::anyhow!(
                    "invalid {field} length {length}, maximum {maximum}"
                )));
            }
            Ok(Some(value))
        }
        _ => Err(to_sqlite_error(anyhow::anyhow!(
            "{field} length and value disagree"
        ))),
    }
}

fn sql_u64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{field} exceeds SQLite INTEGER range"))
}

fn from_sql_u64(value: i64, field: &str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("{field} is negative"))
}

fn to_sqlite_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, error.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Wallet, deployment, identities, operator_key, wallets};
    use commonware_clearing::bajillion::{state::StateLeaf, transition::StateCache};
    use commonware_cryptography::Hasher as _;
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDatabase {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TempDatabase {
        fn new() -> Self {
            let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "commonware-terminal-agent-store-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("agent.sqlite");
            Self { directory, path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn open_error(path: &Path, account: &Key, deployment: &Digest, operator: &Key) -> String {
        match Store::open(path, account, deployment, operator) {
            Ok(_) => panic!("incompatible agent database was accepted"),
            Err(error) => format!("{error:#}"),
        }
    }

    fn open_store(path: &Path, account: &Key) -> (Store, State) {
        Store::open(path, account, &deployment(), &operator_key()).unwrap()
    }

    fn recovery_evidence(
        account: &Key,
        balance: u64,
    ) -> (VectorRoot<Digest>, StateOpening<Key, Digest>) {
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.clone(),
            state: AccountState {
                balance,
                active: true,
                ..AccountState::default()
            },
        }])
        .unwrap();
        (cache.root(), cache.opening(account).unwrap())
    }

    fn signed_send(wallet: &Wallet, anchor: &[u8]) -> SignedSend<Key, Digest> {
        let context = PaymentContext::new(Sha256::hash(&[anchor]), 1, operator_key());
        SignedSend::sign_next(&context, wallet.signer(), identities().remove(1).key, 1, 0).unwrap()
    }

    #[test]
    fn recovery_opening_retention_is_exact_and_idempotent() {
        let database = TempDatabase::new();
        let account = identities().remove(0).key;
        let (root, opening) = recovery_evidence(&account, 100);
        let (mut store, _) = open_store(database.path(), &account);

        store.retain_recovery_opening(&root, &opening).unwrap();
        store.retain_recovery_opening(&root, &opening).unwrap();

        assert_eq!(store.recovery_opening(&root).unwrap(), Some(opening));
        let retained_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM agent_state_openings", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(retained_count, 1);
    }

    #[test]
    fn recovery_opening_history_is_keyed_by_full_root() {
        let database = TempDatabase::new();
        let account = identities().remove(0).key;
        let (first_root, first_opening) = recovery_evidence(&account, 100);
        let (second_root, second_opening) = recovery_evidence(&account, 200);
        assert_ne!(first_root, second_root);
        let (mut store, _) = open_store(database.path(), &account);
        store
            .retain_recovery_opening(&first_root, &first_opening)
            .unwrap();
        store
            .retain_recovery_opening(&second_root, &second_opening)
            .unwrap();
        drop(store);

        let (store, _) = open_store(database.path(), &account);
        assert_eq!(
            store.recovery_opening(&first_root).unwrap(),
            Some(first_opening)
        );
        assert_eq!(
            store.recovery_opening(&second_root).unwrap(),
            Some(second_opening)
        );
    }

    #[test]
    fn stage_payment_requires_retained_recovery_opening() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let send = signed_send(&wallet, b"missing-recovery-opening");
        let (root, _) = recovery_evidence(&account, 100);
        let (mut store, _) = open_store(database.path(), &account);

        let error = store.stage_payment(&send, &root, 0).unwrap_err();
        assert!(format!("{error:#}").contains("payment recovery opening is missing"));
        assert!(store.poisoned);
        drop(store);

        let (store, state) = open_store(database.path(), &account);
        assert!(state.pending_payment.is_none());
        let pending_count: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM agent_pending_payment", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending_count, 0);
    }

    #[test]
    fn pending_payment_reopens_with_its_original_recovery_root() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let send = signed_send(&wallet, b"pending-original-recovery-root");
        let (original_root, original_opening) = recovery_evidence(&account, 100);
        let (later_root, later_opening) = recovery_evidence(&account, 200);
        assert_ne!(original_root, later_root);
        let (mut store, _) = open_store(database.path(), &account);
        store
            .retain_recovery_opening(&original_root, &original_opening)
            .unwrap();
        store
            .retain_recovery_opening(&later_root, &later_opening)
            .unwrap();
        store.stage_payment(&send, &original_root, 0).unwrap();
        drop(store);

        let (store, state) = open_store(database.path(), &account);
        let pending = state.pending_payment.unwrap();
        assert_eq!(pending.send, send);
        assert_eq!(pending.recovery_root, original_root);
        assert_eq!(
            store.recovery_opening(&pending.recovery_root).unwrap(),
            Some(original_opening)
        );
    }

    #[test]
    fn oversized_recovery_opening_is_rejected_boundedly_on_reopen() {
        let database = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let send = signed_send(&wallet, b"oversized-recovery-opening");
        let (root, opening) = recovery_evidence(&account, 100);
        let (mut store, _) = open_store(database.path(), &account);
        store.retain_recovery_opening(&root, &opening).unwrap();
        store.stage_payment(&send, &root, 0).unwrap();
        drop(store);

        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        connection
            .execute(
                "UPDATE agent_state_openings SET opening = zeroblob(?1) WHERE root = ?2",
                params![
                    i64::try_from(MAX_STATE_OPENING_BYTES + 1).unwrap(),
                    root.encode().as_ref()
                ],
            )
            .unwrap();
        drop(connection);

        let error = open_error(database.path(), &account, &deployment(), &operator_key());
        assert!(error.contains("invalid state opening length"));
        assert!(error.contains(&format!("maximum {MAX_STATE_OPENING_BYTES}")));
    }

    #[test]
    fn stored_recovery_opening_for_another_account_is_rejected() {
        let database = TempDatabase::new();
        let identities = identities();
        let account = identities[0].key.clone();
        let foreign_account = identities[1].key.clone();
        let (foreign_root, foreign_opening) = recovery_evidence(&foreign_account, 100);
        let (store, _) = open_store(database.path(), &account);
        drop(store);

        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute(
                "INSERT INTO agent_state_openings (root, opening) VALUES (?1, ?2)",
                params![
                    foreign_root.encode().as_ref(),
                    foreign_opening.encode().as_ref()
                ],
            )
            .unwrap();
        drop(connection);

        let (store, _) = open_store(database.path(), &account);
        let error = store.recovery_opening(&foreign_root).unwrap_err();
        assert!(format!("{error:#}").contains("state opening belongs to another account"));
    }

    #[test]
    fn database_binding_rejects_another_identity() {
        let database = TempDatabase::new();
        let identities = identities();
        let (store, _) = Store::open(
            database.path(),
            &identities[0].key,
            &deployment(),
            &operator_key(),
        )
        .unwrap();
        drop(store);

        let error = open_error(
            database.path(),
            &identities[1].key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("another account"));
    }

    #[test]
    fn malformed_or_incompatible_database_is_rejected() {
        let incompatible = TempDatabase::new();
        let connection = Connection::open(incompatible.path()).unwrap();
        connection
            .execute("CREATE TABLE unrelated (value BLOB)", [])
            .unwrap();
        drop(connection);
        let identity = identities().remove(0);
        let error = open_error(
            incompatible.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("incompatible agent database schema"));

        let malformed = TempDatabase::new();
        let (store, _) = Store::open(
            malformed.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        )
        .unwrap();
        drop(store);
        let connection = Connection::open(malformed.path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE agent_meta SET account = zeroblob(1048576) WHERE singleton = 1;",
            )
            .unwrap();
        drop(connection);
        let error = open_error(
            malformed.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("invalid agent account length"));
    }

    #[test]
    fn database_rejects_unexpected_trigger() {
        let database = TempDatabase::new();
        let identity = identities().remove(0);
        let (store, _) = Store::open(
            database.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        )
        .unwrap();
        drop(store);
        let connection = Connection::open(database.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER discard_pending
                 AFTER INSERT ON agent_pending_payment
                 BEGIN
                     DELETE FROM agent_pending_payment;
                 END;",
            )
            .unwrap();
        drop(connection);
        let error = open_error(
            database.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("incompatible agent database schema"));
    }

    #[test]
    fn database_rejects_noncanonical_singletons() {
        let identity = identities().remove(0);

        let metadata = TempDatabase::new();
        let (store, _) = Store::open(
            metadata.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        )
        .unwrap();
        drop(store);
        let connection = Connection::open(metadata.path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 UPDATE agent_meta SET singleton = 2 WHERE singleton = 1;",
            )
            .unwrap();
        drop(connection);
        let error = open_error(
            metadata.path(),
            &identity.key,
            &deployment(),
            &operator_key(),
        );
        assert!(error.contains("metadata singleton"));

        let pending = TempDatabase::new();
        let wallet = wallets().remove(0);
        let account = wallet.public_key();
        let (mut store, _) =
            Store::open(pending.path(), &account, &deployment(), &operator_key()).unwrap();
        let context = PaymentContext::new(
            Sha256::hash(&[b"noncanonical-pending-singleton"]),
            1,
            operator_key(),
        );
        let send =
            SignedSend::sign_next(&context, wallet.signer(), identities().remove(1).key, 1, 0)
                .unwrap();
        let cache = StateCache::new::<Sha256>(vec![StateLeaf {
            account: account.clone(),
            state: AccountState {
                balance: 100,
                active: true,
                ..AccountState::default()
            },
        }])
        .unwrap();
        let root = cache.root();
        let opening = cache.opening(&account).unwrap();
        store.retain_recovery_opening(&root, &opening).unwrap();
        store.stage_payment(&send, &root, 0).unwrap();
        drop(store);
        let connection = Connection::open(pending.path()).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 PRAGMA ignore_check_constraints = ON;
                 UPDATE agent_pending_payment SET singleton = 2 WHERE singleton = 1;",
            )
            .unwrap();
        drop(connection);
        let error = open_error(pending.path(), &account, &deployment(), &operator_key());
        assert!(error.contains("pending payment singleton"));
    }

    #[test]
    fn sqlite_integer_domain_is_bounded() {
        assert_eq!(sql_u64(i64::MAX as u64, "test value").unwrap(), i64::MAX);
        assert!(sql_u64(i64::MAX as u64 + 1, "test value").is_err());
        assert_eq!(
            from_sql_u64(i64::MAX, "test value").unwrap(),
            i64::MAX as u64
        );
        assert!(from_sql_u64(-1, "test value").is_err());
    }
}
