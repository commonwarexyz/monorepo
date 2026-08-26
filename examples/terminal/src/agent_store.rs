//! SQLite ownership boundary for one agent wallet.
//!
//! Receipts remain durable because this example has no authenticated signal that their challenge
//! windows closed. An embedding may prune them only after obtaining that signal.

use crate::protocol::{Key, Payment};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::payment::{PaymentContext, SignedSend};
use commonware_codec::{DecodeExt as _, Encode as _, FixedSize};
use commonware_cryptography::{Sha256, sha256::Digest};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use std::path::Path;
use thiserror::Error;

const SCHEMA_VERSION: i64 = 1;

pub(crate) struct AgentState {
    pub(crate) cumulative_debit: u64,
    pub(crate) pending_send: Option<SignedSend<Key, Digest>>,
    pub(crate) receipt_count: u64,
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

    pub(crate) fn stage_payment(
        &mut self,
        send: &SignedSend<Key, Digest>,
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

        let result =
            stage_payment_transaction(&mut self.connection, previous_debit, encoded.as_ref());
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
    let has_pending = table_exists(connection, "agent_pending_payment")?;
    let has_receipts = table_exists(connection, "agent_receipts")?;
    let has_unexpected: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema
             WHERE (type = 'table'
                    AND name NOT LIKE 'sqlite_%'
                    AND name NOT IN ('agent_meta', 'agent_pending_payment', 'agent_receipts'))
                OR type IN ('trigger', 'view')
                OR (type = 'index' AND name NOT LIKE 'sqlite_autoindex_%')
             LIMIT 1
         )",
        [],
        |row| row.get(0),
    )?;

    if !has_meta && !has_pending && !has_receipts && !has_unexpected {
        return Ok(SchemaPresence::Empty);
    }
    ensure!(
        has_meta && has_pending && has_receipts && !has_unexpected,
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

         CREATE TABLE agent_pending_payment (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             send BLOB NOT NULL CHECK (length(send) = {send_size}),
             FOREIGN KEY (singleton) REFERENCES agent_meta(singleton) ON DELETE CASCADE
         );

         CREATE TABLE agent_receipts (
             cumulative_debit INTEGER PRIMARY KEY CHECK (cumulative_debit > 0),
             payment BLOB NOT NULL CHECK (length(payment) = {payment_size})
         );",
        key_size = Key::SIZE,
        digest_size = Digest::SIZE,
        send_size = SignedSend::<Key, Digest>::SIZE,
        payment_size = Payment::SIZE,
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
    let pending_send = read_pending_send(connection)?;
    if let Some(send) = &pending_send {
        validate_send(send, account, operator, cumulative_debit)?;
        sql_u64(send.body().cumulative_debit(), "pending cumulative debit")?;
    }

    Ok(AgentState {
        cumulative_debit,
        pending_send,
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
            "SELECT cumulative_debit, length(payment), payment
             FROM agent_receipts
             ORDER BY cumulative_debit DESC
             LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    read_fixed_blob(row, 1, 2, Payment::SIZE, "agent receipt")?,
                ))
            },
        )
        .optional()?;
    let Some((stored_endpoint, encoded)) = stored else {
        ensure!(receipt_count == 0, "agent receipt count is inconsistent");
        return Ok((0, 0));
    };
    ensure!(receipt_count > 0, "agent receipt count is inconsistent");
    let stored_endpoint = from_sql_u64(stored_endpoint, "retained cumulative debit")?;
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

fn read_pending_send(connection: &Connection) -> Result<Option<SignedSend<Key, Digest>>> {
    let mut statement = connection.prepare(
        "SELECT singleton, length(send), send
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
    let encoded = read_fixed_blob(
        row,
        1,
        2,
        SignedSend::<Key, Digest>::SIZE,
        "pending signed send",
    )?;
    ensure!(
        rows.next()?.is_none(),
        "agent database has multiple pending payments"
    );
    Ok(Some(
        SignedSend::decode(encoded.as_slice()).context("decode pending signed send")?,
    ))
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

fn stage_payment_transaction(
    connection: &mut Connection,
    previous_debit: u64,
    encoded_send: &[u8],
) -> Result<()> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin pending payment stage")?;
    ensure!(
        latest_debit(&transaction)? == previous_debit,
        "agent debit changed before payment staging"
    );
    let pending_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM agent_pending_payment LIMIT 1)",
        [],
        |row| row.get(0),
    )?;
    ensure!(!pending_exists, "another payment is already staged");
    transaction.execute(
        "INSERT INTO agent_pending_payment (singleton, send) VALUES (1, ?1)",
        [encoded_send],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("pending payment stage", source))?;
    Ok(())
}

fn commit_payment_transaction(
    connection: &mut Connection,
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
    let pending = read_pending_send(&transaction)?.context("pending payment is missing")?;
    ensure!(
        pending.encode().as_ref() == encoded_send,
        "another payment is pending"
    );
    transaction.execute(
        "INSERT INTO agent_receipts (cumulative_debit, payment) VALUES (?1, ?2)",
        params![endpoint, encoded_payment],
    )?;
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
    use crate::protocol::{deployment, identities, operator_key, wallets};
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
        store.stage_payment(&send, 0).unwrap();
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
