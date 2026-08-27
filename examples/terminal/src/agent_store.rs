//! SQLite ownership boundary for one agent wallet.
//!
//! Receipts remain durable because this example has no authenticated signal that their challenge
//! windows closed. An embedding may prune them only after obtaining that signal.

use crate::{
    operator_rpc,
    protocol::{Key, MAX_ACCOUNTS, Payment},
    settlement_rpc,
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
use thiserror::Error;

const SCHEMA_VERSION: i64 = 3;
const MAX_PENDING_CLAIM_BYTES: usize = 16 * 1024;
const MIN_STATE_OPENING_BYTES: usize = Key::SIZE + AccountState::SIZE + u32::SIZE * 2 + 1;
const MAX_STATE_OPENING_BYTES: usize =
    Key::SIZE + AccountState::SIZE + u32::SIZE * 2 + 1 + Digest::SIZE * u32::BITS as usize;

#[derive(Clone)]
pub(crate) struct PendingPayment {
    pub(crate) send: SignedSend<Key, Digest>,
    pub(crate) recovery_root: VectorRoot<Digest>,
}

#[derive(Clone)]
pub(crate) struct PendingWithdrawalClaim {
    pub(crate) evidence: operator_rpc::WithdrawalEvidenceResponse,
    pub(crate) result: Option<settlement_rpc::WithdrawalResponse>,
}

#[derive(Clone)]
pub(crate) struct PendingPayoutClaim {
    pub(crate) evidence: operator_rpc::ExternalPayoutEvidenceResponse,
    pub(crate) result: Option<settlement_rpc::ExternalPayoutResponse>,
}

pub(crate) struct AgentState {
    pub(crate) cumulative_debit: u64,
    pub(crate) pending_payment: Option<PendingPayment>,
    pub(crate) pending_withdrawal_claim: Option<PendingWithdrawalClaim>,
    pub(crate) pending_payout_claim: Option<PendingPayoutClaim>,
    pub(crate) receipt_count: u64,
}

#[derive(Clone, Copy)]
#[repr(i64)]
enum ClaimKind {
    Withdrawal = 1,
    ExternalPayout = 2,
}

struct Binding {
    account: Key,
    deployment: Digest,
    operator: Key,
}

#[derive(Debug, Error)]
#[error("{operation} commit outcome is unknown")]
struct CommitUnknown {
    operation: &'static str,
    #[source]
    source: rusqlite::Error,
}

impl CommitUnknown {
    const fn new(operation: &'static str, source: rusqlite::Error) -> Self {
        Self { operation, source }
    }
}

pub(crate) struct AgentStore {
    connection: Connection,
    account: Key,
    operator: Key,
    poisoned: bool,
}

impl AgentStore {
    pub(crate) fn open(
        path: &Path,
        account: &Key,
        deployment: &Digest,
        operator: &Key,
    ) -> Result<(Self, AgentState)> {
        let connection = Connection::open(path)
            .with_context(|| format!("open SQLite agent at {}", path.display()))?;
        Self::from_connection(connection, false, account, deployment, operator)
    }

    pub(crate) fn in_memory(
        account: &Key,
        deployment: &Digest,
        operator: &Key,
    ) -> Result<(Self, AgentState)> {
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
    ) -> Result<(Self, AgentState)> {
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

        Ok((
            Self {
                connection,
                account: account.clone(),
                operator: operator.clone(),
                poisoned: false,
            },
            state,
        ))
    }

    pub(crate) fn retain_recovery_opening(
        &mut self,
        root: &VectorRoot<Digest>,
        opening: &StateOpening<Key, Digest>,
    ) -> Result<()> {
        ensure!(
            !self.poisoned,
            "agent database is unusable after a failed mutation"
        );
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
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn recovery_opening(
        &self,
        root: &VectorRoot<Digest>,
    ) -> Result<Option<StateOpening<Key, Digest>>> {
        ensure!(
            !self.poisoned,
            "agent database is unusable after a failed mutation"
        );
        read_recovery_opening(&self.connection, root, &self.account)
    }

    pub(crate) fn stage_withdrawal_claim(
        &mut self,
        evidence: &operator_rpc::WithdrawalEvidenceResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_withdrawal_claim(evidence, None, &self.account)?;
        let encoded = evidence.encode();
        ensure_claim_bound(encoded.as_ref(), "withdrawal evidence")?;
        let result = stage_claim_transaction(
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
        validate_withdrawal_claim(evidence, Some(result), &self.account)?;
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
        validate_withdrawal_claim(evidence, Some(result), &self.account)?;
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

    pub(crate) fn stage_payout_claim(
        &mut self,
        evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
    ) -> Result<()> {
        self.ensure_usable()?;
        validate_external_payout(evidence, None, &self.account)?;
        let encoded = evidence.encode();
        ensure_claim_bound(encoded.as_ref(), "external-payout evidence")?;
        let result = stage_claim_transaction(
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
        validate_external_payout(evidence, Some(payout), &self.account)?;
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
        validate_external_payout(evidence, Some(payout), &self.account)?;
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

    fn ensure_usable(&self) -> Result<()> {
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
        ensure!(
            !self.poisoned,
            "agent database is unusable after a failed mutation"
        );
        validate_send(send, &self.account, &self.operator, previous_debit)?;
        sql_u64(send.body().cumulative_debit(), "pending cumulative debit")?;
        let encoded = send.encode();
        ensure!(
            encoded.len() == SignedSend::<Key, Digest>::SIZE,
            "signed send encoding has an unexpected length"
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
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn commit_payment(
        &mut self,
        payment: &Payment,
        previous_debit: u64,
        receipt_count: u64,
    ) -> Result<u64> {
        ensure!(
            !self.poisoned,
            "agent database is unusable after a failed mutation"
        );
        let context = context_for_send(payment.send(), &self.operator);
        ensure!(
            payment.payer() == &self.account,
            "accepted payment belongs to another payer"
        );
        payment
            .verify_linked::<Sha256>(&context)
            .context("verify payment before persistence")?;
        payment
            .send()
            .verify_next(&context, previous_debit)
            .context("verify persisted debit successor")?;
        let endpoint = sql_u64(
            payment.send().body().cumulative_debit(),
            "accepted cumulative debit",
        )?;
        let next_receipt_count = receipt_count
            .checked_add(1)
            .context("agent receipt count overflow")?;
        sql_u64(next_receipt_count, "agent receipt count")?;
        let encoded_send = payment.send().encode();
        let encoded_payment = payment.encode();
        ensure!(
            encoded_send.len() == SignedSend::<Key, Digest>::SIZE,
            "signed send encoding has an unexpected length"
        );
        ensure!(
            encoded_payment.len() == Payment::SIZE,
            "payment encoding has an unexpected length"
        );

        let result = commit_payment_transaction(
            &mut self.connection,
            &self.account,
            previous_debit,
            endpoint,
            encoded_send.as_ref(),
            encoded_payment.as_ref(),
        );
        if result.is_err() {
            self.poisoned = true;
        }
        result.map(|()| next_receipt_count)
    }
}

enum SchemaPresence {
    Empty,
    Complete,
}

fn schema_presence(connection: &Connection) -> Result<SchemaPresence> {
    let has_meta = table_exists(connection, "agent_meta")?;
    let has_openings = table_exists(connection, "agent_state_openings")?;
    let has_pending = table_exists(connection, "agent_pending_payment")?;
    let has_pending_claims = table_exists(connection, "agent_pending_claims")?;
    let has_receipts = table_exists(connection, "agent_receipts")?;
    let has_unexpected: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema
             WHERE (type = 'table'
                    AND name NOT LIKE 'sqlite_%'
                    AND name NOT IN (
                        'agent_meta', 'agent_state_openings',
                        'agent_pending_payment', 'agent_pending_claims',
                        'agent_receipts'
                    ))
                OR type IN ('trigger', 'view')
                OR (type = 'index' AND name NOT LIKE 'sqlite_autoindex_%')
             LIMIT 1
         )",
        [],
        |row| row.get(0),
    )?;

    if !has_meta
        && !has_openings
        && !has_pending
        && !has_pending_claims
        && !has_receipts
        && !has_unexpected
    {
        return Ok(SchemaPresence::Empty);
    }
    ensure!(
        has_meta
            && has_openings
            && has_pending
            && has_pending_claims
            && has_receipts
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
             send BLOB NOT NULL CHECK (length(send) = {send_size}),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE,
             FOREIGN KEY (recovery_root) REFERENCES agent_state_openings(root)
         );

         CREATE TABLE agent_pending_claims (
             kind INTEGER PRIMARY KEY CHECK (kind IN (1, 2)),
             evidence BLOB NOT NULL CHECK (
                 length(evidence) BETWEEN 1 AND {max_claim_size}
             ),
             result BLOB CHECK (
                 result IS NULL OR length(result) BETWEEN 1 AND {max_claim_size}
             )
         );

         CREATE TABLE agent_receipts (
             cumulative_debit INTEGER PRIMARY KEY CHECK (cumulative_debit > 0),
             recovery_root BLOB NOT NULL CHECK (length(recovery_root) = {root_size}),
             payment BLOB NOT NULL CHECK (length(payment) = {payment_size}),
             FOREIGN KEY (recovery_root) REFERENCES agent_state_openings(root)
         );",
        key_size = Key::SIZE,
        digest_size = Digest::SIZE,
        root_size = VectorRoot::<Digest>::SIZE,
        send_size = SignedSend::<Key, Digest>::SIZE,
        payment_size = Payment::SIZE,
        min_opening_size = MIN_STATE_OPENING_BYTES,
        max_opening_size = MAX_STATE_OPENING_BYTES,
        max_claim_size = MAX_PENDING_CLAIM_BYTES,
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

fn read_state(connection: &Connection, account: &Key, operator: &Key) -> Result<AgentState> {
    let (cumulative_debit, receipt_count) = read_receipt_state(connection, account, operator)?;
    let pending_payment = read_pending_payment(connection, account)?;
    let (pending_withdrawal_claim, pending_payout_claim) =
        read_pending_claims(connection, account)?;
    if let Some(pending) = &pending_payment {
        validate_send(&pending.send, account, operator, cumulative_debit)?;
        sql_u64(
            pending.send.body().cumulative_debit(),
            "pending cumulative debit",
        )?;
    }

    Ok(AgentState {
        cumulative_debit,
        pending_payment,
        pending_withdrawal_claim,
        pending_payout_claim,
        receipt_count,
    })
}

fn read_receipt_state(
    connection: &Connection,
    account: &Key,
    operator: &Key,
) -> Result<(u64, u64)> {
    let receipt_count = from_sql_u64(
        connection.query_row("SELECT COUNT(*) FROM agent_receipts", [], |row| row.get(0))?,
        "agent receipt count",
    )?;
    let stored = connection
        .query_row(
            "SELECT cumulative_debit,
                    length(recovery_root), recovery_root,
                    length(payment), payment
             FROM agent_receipts
             ORDER BY cumulative_debit DESC
             LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    read_fixed_blob(row, 1, 2, VectorRoot::<Digest>::SIZE, "recovery root")?,
                    read_fixed_blob(row, 3, 4, Payment::SIZE, "agent receipt")?,
                ))
            },
        )
        .optional()?;
    let Some((stored_endpoint, encoded_root, encoded)) = stored else {
        ensure!(receipt_count == 0, "agent receipt count is inconsistent");
        return Ok((0, 0));
    };
    ensure!(receipt_count > 0, "agent receipt count is inconsistent");
    let stored_endpoint = from_sql_u64(stored_endpoint, "retained cumulative debit")?;
    let recovery_root =
        VectorRoot::decode(encoded_root.as_slice()).context("decode receipt recovery root")?;
    read_recovery_opening(connection, &recovery_root, account)?
        .context("receipt recovery opening is missing")?;
    let payment = Payment::decode(encoded.as_slice()).context("decode retained payment")?;
    let context = context_for_send(payment.send(), operator);
    ensure!(
        payment.payer() == account,
        "retained payment belongs to another payer"
    );
    payment
        .verify_linked::<Sha256>(&context)
        .context("verify retained payment")?;
    ensure!(
        payment.send().body().cumulative_debit() == stored_endpoint,
        "retained payment has another debit endpoint"
    );
    Ok((stored_endpoint, receipt_count))
}

fn read_pending_payment(connection: &Connection, account: &Key) -> Result<Option<PendingPayment>> {
    let mut statement = connection.prepare(
        "SELECT singleton,
                length(recovery_root), recovery_root,
                length(send), send
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
    let encoded_send = read_fixed_blob(
        row,
        3,
        4,
        SignedSend::<Key, Digest>::SIZE,
        "pending signed send",
    )?;
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
        let evidence =
            read_bounded_blob(row, 1, 2, MAX_PENDING_CLAIM_BYTES, "pending claim evidence")?;
        let result =
            read_optional_bounded_blob(row, 3, 4, MAX_PENDING_CLAIM_BYTES, "pending claim result")?;
        match kind {
            value if value == ClaimKind::Withdrawal as i64 => {
                ensure!(
                    withdrawal.is_none(),
                    "multiple withdrawal claims are pending"
                );
                let evidence =
                    operator_rpc::WithdrawalEvidenceResponse::decode(evidence.as_slice())
                        .context("decode pending withdrawal evidence")?;
                let result = result
                    .map(|encoded| {
                        settlement_rpc::WithdrawalResponse::decode(encoded.as_slice())
                            .context("decode pending withdrawal result")
                    })
                    .transpose()?;
                validate_withdrawal_claim(&evidence, result.as_ref(), account)?;
                withdrawal = Some(PendingWithdrawalClaim { evidence, result });
            }
            value if value == ClaimKind::ExternalPayout as i64 => {
                ensure!(payout.is_none(), "multiple external payouts are pending");
                let evidence =
                    operator_rpc::ExternalPayoutEvidenceResponse::decode(evidence.as_slice())
                        .context("decode pending external-payout evidence")?;
                let result = result
                    .map(|encoded| {
                        settlement_rpc::ExternalPayoutResponse::decode(encoded.as_slice())
                            .context("decode pending external payout")
                    })
                    .transpose()?;
                validate_external_payout(&evidence, result.as_ref(), account)?;
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

fn validate_withdrawal_claim(
    evidence: &operator_rpc::WithdrawalEvidenceResponse,
    result: Option<&settlement_rpc::WithdrawalResponse>,
    account: &Key,
) -> Result<()> {
    ensure!(
        &evidence.account == account,
        "pending withdrawal evidence belongs to another account"
    );
    if let Some(result) = result {
        ensure!(
            result.destination == *evidence.claim.output().destination()
                && result.amount == evidence.claim.output().amount(),
            "pending withdrawal result differs from its evidence"
        );
    }
    Ok(())
}

fn validate_external_payout(
    evidence: &operator_rpc::ExternalPayoutEvidenceResponse,
    result: Option<&settlement_rpc::ExternalPayoutResponse>,
    account: &Key,
) -> Result<()> {
    ensure!(
        evidence.claim.recipient() == account,
        "pending external-payout evidence belongs to another account"
    );
    if let Some(result) = result {
        ensure!(
            &result.recipient == account,
            "pending external payout belongs to another account"
        );
    }
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
        "INSERT INTO agent_pending_payment (singleton, recovery_root, send)
         VALUES (1, ?1, ?2)",
        params![encoded_root, encoded_send],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending payment stage", source))?;
    Ok(())
}

fn commit_payment_transaction(
    connection: &mut Connection,
    account: &Key,
    previous_debit: u64,
    endpoint: i64,
    encoded_send: &[u8],
    encoded_payment: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin accepted payment commit")?;
    ensure!(
        latest_debit(&transaction)? == previous_debit,
        "agent debit changed before receipt commit"
    );
    let pending =
        read_pending_payment(&transaction, account)?.context("pending payment is missing")?;
    ensure!(
        pending.send.encode().as_ref() == encoded_send,
        "another payment is pending"
    );
    ensure!(
        transaction.execute(
            "INSERT INTO agent_receipts (cumulative_debit, recovery_root, payment)
             SELECT ?1, recovery_root, ?2
             FROM agent_pending_payment WHERE singleton = 1 AND send = ?3",
            params![endpoint, encoded_payment, encoded_send],
        )? == 1,
        "pending payment changed before receipt commit"
    );
    ensure!(
        transaction.execute(
            "DELETE FROM agent_pending_payment WHERE singleton = 1 AND send = ?1",
            [encoded_send],
        )? == 1,
        "pending payment changed before receipt commit"
    );
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("accepted payment", source))?;
    Ok(())
}

fn stage_claim_transaction(
    connection: &mut Connection,
    kind: ClaimKind,
    evidence: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending claim stage")?;
    transaction.execute(
        "INSERT INTO agent_pending_claims (kind, evidence, result)
         VALUES (?1, ?2, NULL)
         ON CONFLICT(kind) DO NOTHING",
        params![kind as i64, evidence],
    )?;
    let stored = transaction
        .query_row(
            "SELECT evidence FROM agent_pending_claims WHERE kind = ?1",
            [kind as i64],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .context("staged claim evidence is missing")?;
    ensure!(stored == evidence, "another claim of this kind is pending");
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending claim stage", source))?;
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
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .context("pending claim evidence is missing")?;
    ensure!(
        stored_evidence == evidence,
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
             FROM agent_receipts
             ORDER BY cumulative_debit DESC
             LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    endpoint.map_or(Ok(0), |value| {
        from_sql_u64(value, "retained cumulative debit")
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
        match AgentStore::open(path, account, deployment, operator) {
            Ok(_) => panic!("incompatible agent database was accepted"),
            Err(error) => format!("{error:#}"),
        }
    }

    fn open_store(path: &Path, account: &Key) -> (AgentStore, AgentState) {
        AgentStore::open(path, account, &deployment(), &operator_key()).unwrap()
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
        let (store, _) = AgentStore::open(
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
        let (store, _) = AgentStore::open(
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
        let (store, _) = AgentStore::open(
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
        let (store, _) = AgentStore::open(
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
            AgentStore::open(pending.path(), &account, &deployment(), &operator_key()).unwrap();
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
