//! SQLite ownership boundary for the operator.

#[cfg(test)]
use crate::protocol::INITIAL_BALANCE;
use crate::{
    protocol::{
        Acceptance, AcceptedEntry, Account, AccountIdentity, Ack, DepositEvent, Entry, Key,
        MAX_ACCEPTED_PAYMENTS, MAX_DEPOSIT_EVENTS, MAX_DESTINATION_BYTES, MAX_ENTRIES,
        MAX_WITHDRAWALS, Protocol, Receipt, SQLITE_U64_MAX, SettlementResult, encoded_artifacts,
    },
    store::CommitUnknown,
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, SignedWithdrawal, WithdrawalAction},
    commitment::Opening,
    payment::{PaymentContext, SendAuthorization, VECTOR_ACK_SIGNATURE_NAMESPACE},
    qmdb::StateRoot,
    transition::{EpochContext, Header, RootBundle},
    vector::{OutEntry, OutTipLookup, OutVector},
};
use commonware_codec::{Copying, Decode, DecodeExt, Encode, FixedSize, RangeCfg};
use commonware_cryptography::{Sha256, sha256::Digest};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use thiserror::Error;

const SCHEMA_VERSION: i64 = 18;
/// Bounds one page of incoming receipts served to a receiver. Each served row reassembles
/// one [`Receipt`] from a fixed-size acknowledgment and a bounded entry opening, so this
/// page stays well under the RPC body limit.
pub(crate) const MAX_INCOMING_PAGE: usize = 128;
/// Bounds one stored entry opening: a position and a BMT path over at most
/// [`MAX_ACCEPTED_PAYMENTS`] vector leaves.
const MAX_OPENING_BYTES: usize = 1_024;
const MAX_CLAIM_BYTES: usize = 16 * 1024;
const MAX_CLOSE_ERROR_BYTES: usize = 4 * 1024;
const MAX_WITHDRAWAL_BYTES: usize = 512;
const MAX_RESULT_BYTES: usize =
    crate::rpc::MAX_BODY_SIZE + MAX_WITHDRAWALS * (MAX_CLAIM_BYTES + MAX_WITHDRAWAL_BYTES) + 4096;
const EFFECTIVE_ACCOUNT_SQL: &str = "SELECT state.epoch, identity.name,
            length(state.public_key), state.public_key,
            state.predecessor_balance, state.current_balance
     FROM account_states AS state
     JOIN account_identities AS identity USING(public_key)
     WHERE state.public_key = ?1 AND state.epoch <= ?2
     ORDER BY state.epoch DESC LIMIT 1";

// Starting from the identity catalog performs one indexed history probe per account. `CROSS JOIN`
// fixes that loop order instead of scanning every version accumulated across epochs.
const EPOCH_ACCOUNTS_SQL: &str = "SELECT identity.name,
                    length(state.public_key), state.public_key,
                    CASE WHEN state.epoch = ?1
                         THEN state.predecessor_balance ELSE state.current_balance END,
                    state.current_balance
             FROM account_identities AS identity
             CROSS JOIN account_states AS state
             WHERE state.rowid = (
                 SELECT candidate.rowid
                 FROM account_states AS candidate
                 WHERE candidate.public_key = identity.public_key
                   AND candidate.epoch <= ?1
                 ORDER BY candidate.epoch DESC
                 LIMIT 1
             )
               AND (state.epoch = ?1 OR state.current_balance > 0)
             ORDER BY state.public_key";
static NEXT_EPHEMERAL_DATABASE: AtomicU64 = AtomicU64::new(0);

type EpochPaymentContext = PaymentContext<Key, Digest>;

#[derive(Debug, Error)]
#[error("{operation} storage mutation failed")]
pub(crate) struct MutationFailed {
    operation: &'static str,
    #[source]
    source: anyhow::Error,
}

#[derive(Debug, Error)]
#[error("{0}")]
pub(crate) struct CloseRejected(&'static str);

impl MutationFailed {
    fn new(operation: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self {
            operation,
            source: source.into(),
        }
    }
}

fn mutate<T>(
    connection: &mut Connection,
    operation: &'static str,
    body: impl FnOnce(&Transaction<'_>) -> Result<T>,
) -> Result<T> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|source| MutationFailed::new(operation, source))?;
    match body(&transaction) {
        Ok(value) => {
            transaction
                .commit()
                .map_err(|source| CommitUnknown::new(operation, source))?;
            Ok(value)
        }
        Err(error) => {
            let storage_failure = error
                .chain()
                .any(|source| source.downcast_ref::<rusqlite::Error>().is_some());
            if let Err(source) = transaction.rollback() {
                return Err(MutationFailed::new(
                    operation,
                    anyhow::Error::new(source).context(format!(
                        "rollback failed after the operation returned: {error:#}"
                    )),
                )
                .into());
            }
            if storage_failure {
                Err(MutationFailed::new(operation, error).into())
            } else {
                Err(error)
            }
        }
    }
}

pub(crate) struct StoredAccount {
    pub(crate) name: String,
    pub(crate) key: Key,
    pub(crate) predecessor: u64,
    pub(crate) current: u64,
}

/// One credited entry of an accepted batch, with its stable acceptance-order cursor and
/// the membership opening computed under that batch's acknowledged vector root.
pub(crate) struct StoredEntry {
    pub(crate) sequence: u64,
    pub(crate) payer: Key,
    pub(crate) seq: u64,
    pub(crate) recipient: Key,
    pub(crate) amount: u64,
    pub(crate) cumulative: u64,
    pub(crate) count: u64,
    pub(crate) opening: Opening<Digest>,
}

/// One live cumulative out-vector edge of the epoch.
pub(crate) struct StoredEdge {
    pub(crate) payer: Key,
    pub(crate) entry: OutEntry<Key>,
}

/// One accepted entry receipt crediting a receiver, with its stable acceptance-order cursor.
///
/// The cursor is the serving log's autoincrement id, so a receiver can fetch new credits
/// incrementally by passing the highest cursor it already holds.
pub(crate) struct IncomingPayment {
    pub(crate) sequence: u64,
    pub(crate) receipt: Receipt,
}

/// One payer's accepted endpoint in the live epoch: its epoch cumulative debit, its
/// epoch-local batch sequence (zero when none), and its cumulative out vector.
pub(crate) struct Endpoint {
    pub(crate) cumulative_debit: u64,
    pub(crate) seq: u64,
    pub(crate) entries: Vec<OutEntry<Key>>,
}

pub(crate) struct EpochData {
    pub(crate) epoch: u64,
    pub(crate) accounts: Vec<StoredAccount>,
    /// Accepted batch acknowledgments in (payer, seq) order.
    pub(crate) acks: Vec<Ack>,
    /// The credited-entry serving log in acceptance order.
    pub(crate) entries: Vec<StoredEntry>,
    /// The live cumulative out vectors in (payer, recipient) order.
    pub(crate) edges: Vec<StoredEdge>,
    pub(crate) deposits: Vec<DepositEvent>,
    pub(crate) withdrawals: Vec<StoredWithdrawal>,
    /// Chain-assigned deadlines, once adopted from the epoch's certified
    /// registration record. Durable because recovery must rebuild the exact
    /// registered context offline to validate the epoch's payment log.
    pub(crate) deadlines: Option<(u64, u64)>,
    pub(crate) floors: Option<commonware_clearing::bajillion::logs::Floors>,
}

pub(crate) struct StoredWithdrawal {
    pub(crate) request: SignedWithdrawal<Key, Digest>,
    /// `None` defers the output amount until cutover resolves the epoch tail.
    pub(crate) applied_amount: Option<u64>,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct AccountView {
    pub(crate) name: String,
    pub(crate) balance: u64,
    pub(crate) present: bool,
}

#[cfg(test)]
pub(crate) struct StoreSnapshot {
    pub(crate) epoch: u64,
    pub(crate) accounts: Vec<AccountView>,
    pub(crate) payments: Vec<StoredEntry>,
}

pub(crate) struct StoreStatus {
    pub(crate) epoch: u64,
    pub(crate) accounts: u64,
    pub(crate) present_accounts: u64,
    pub(crate) recent_payments: u64,
}

pub(crate) struct StoredCloseFinished {
    pub(crate) header: Header<Digest>,
    pub(crate) rows: usize,
    pub(crate) dealing_bytes: usize,
    pub(crate) withdrawal_total: u64,
    pub(crate) header_bytes: usize,
    pub(crate) certificate_bytes: usize,
    pub(crate) prepare_micros: u128,
    pub(crate) deal_micros: u128,
    pub(crate) seal_micros: u128,
}

pub(crate) enum StoredCloseOutcome {
    Pending,
    Finished(StoredCloseFinished),
    Failed(String),
}

/// One accepted batch: its epoch, its payer-local sequence, its delta total, and the
/// acceptance the wire returns.
#[derive(Clone)]
pub(crate) struct AcceptedBatch {
    pub(crate) epoch: u64,
    pub(crate) sequence: u64,
    pub(crate) total: u64,
    pub(crate) acceptance: Acceptance,
}

/// The store's verdict on one submitted batch.
pub(crate) enum SendVerdict {
    /// The batch, or its exact replay, is committed with its acceptance.
    Accepted(Box<AcceptedBatch>),
    /// Corrective rejection: the signed endpoint does not extend the payer's accepted
    /// state, so the payer must adopt this endpoint, re-sign, and retry.
    Stale(Endpoint),
}

/// Fully validated admission of one new batch, or its corrective rejection.
enum Admission {
    Stale(Endpoint),
    Admit(Box<Plan>),
}

struct Plan {
    epoch: u64,
    total: u64,
    payer: StoredAccount,
    /// The payer's merged cumulative out vector after this batch.
    vector: OutVector<Key>,
    credits: Vec<Credit>,
}

struct Credit {
    amount: u64,
    receiver: StoredAccount,
}

pub(crate) struct StagedDeposit {
    /// Epoch whose boundary includes the event, the successor when the aggregate defers.
    pub(crate) epoch: u64,
    pub(crate) id: Digest,
    pub(crate) account: Key,
    pub(crate) amount: u64,
}

/// One chain-confirmed deposit event awaiting staging, with its display identity and boundary context.
pub(crate) struct Staging {
    pub(crate) identity: AccountIdentity,
    pub(crate) event: DepositEvent,
    pub(crate) replacement: EpochPaymentContext,
}

pub(crate) struct StagedWithdrawal {
    pub(crate) epoch: u64,
    pub(crate) account: Key,
    pub(crate) action: WithdrawalAction,
}

struct StoreLocation {
    path: PathBuf,
    ephemeral: bool,
    failure: OnceLock<String>,
    _lock: fs::File,
}

impl Drop for StoreLocation {
    fn drop(&mut self) {
        if !self.ephemeral {
            return;
        }

        // Normal shutdown drops the final shared source after its foreground or worker connection.
        let mut proof_path = OsString::from(self.path.as_os_str());
        proof_path.push(".qmdb");
        let _ = fs::remove_dir_all(PathBuf::from(proof_path));
        for suffix in ["", "-wal", "-shm", ".lock"] {
            let mut path = OsString::from(self.path.as_os_str());
            path.push(suffix);
            let _ = fs::remove_file(PathBuf::from(path));
        }
    }
}

#[derive(Clone)]
struct StoreSource(Arc<StoreLocation>);

impl StoreSource {
    fn new(path: &Path) -> Result<Self> {
        let ephemeral = path == Path::new(":memory:");
        let path = if ephemeral {
            // SQLite cannot use WAL for an in-memory database. Reserve a process-local temporary
            // file so background close readers never block successor writes through shared-cache
            // table locks.
            loop {
                let id = NEXT_EPHEMERAL_DATABASE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("commonware-terminal-{}-{id}.sqlite", process::id()));
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(file) => {
                        drop(file);
                        break path;
                    }
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(error).context("reserve ephemeral SQLite operator path");
                    }
                }
            }
        } else {
            path.to_owned()
        };
        let mut lock_path = OsString::from(path.as_os_str());
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(PathBuf::from(lock_path))?;
        lock.try_lock()
            .context("another operator owns this store")?;
        Ok(Self(Arc::new(StoreLocation {
            path,
            ephemeral,
            failure: OnceLock::new(),
            _lock: lock,
        })))
    }

    fn connect(&self) -> Result<Connection> {
        if let Some(failure) = self.0.failure.get() {
            anyhow::bail!("the SQLite store is unusable: {failure}");
        }
        Connection::open(&self.0.path)
            .with_context(|| format!("open SQLite operator at {}", self.0.path.display()))
    }
}

#[derive(Clone)]
pub(crate) struct EpochReader {
    source: StoreSource,
}

impl EpochReader {
    /// A mutable storage failure fences every connection sharing this operator store.
    pub(super) fn fence_storage_failure(&self, error: &anyhow::Error) {
        if error.chain().any(|cause| {
            cause.downcast_ref::<MutationFailed>().is_some()
                || cause.downcast_ref::<CommitUnknown>().is_some()
                || matches!(
                    cause.downcast_ref::<rusqlite::Error>(),
                    Some(rusqlite::Error::SqliteFailure(..))
                )
        }) {
            let _ = self
                .source
                .0
                .failure
                .set(format!("{error:#}; restart the operator"));
        }
    }

    pub(super) fn proof_connection(&self) -> Result<Connection> {
        let connection = self.source.connect()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;",
        )?;
        Ok(connection)
    }

    /// Retains reconstruction inputs until native commit and certified finality both cover them.
    pub(super) fn prune_proof_inputs(&self, applied_checkpoint: u64) -> Result<()> {
        let Some(epoch) = applied_checkpoint.checked_sub(1) else {
            return Ok(());
        };
        let mut connection = self.proof_connection()?;
        let result = mutate(
            &mut connection,
            "retire proof reconstruction inputs",
            |transaction| {
                let finalized: Option<i64> = transaction.query_row(
                    "SELECT MAX(epoch) FROM close_jobs WHERE status = 'finalized' AND epoch <= ?1",
                    [sql_u64(epoch, "proof checkpoint epoch")?],
                    |row| row.get(0),
                )?;
                let Some(finalized) = finalized else {
                    return Ok(());
                };
                transaction.execute(
                    "DELETE FROM account_states AS old
                 WHERE old.epoch <= ?1 AND (
                     EXISTS(SELECT 1 FROM account_states AS newer
                            WHERE newer.public_key = old.public_key
                              AND newer.epoch > old.epoch AND newer.epoch <= ?1)
                     OR old.current_balance = 0)",
                    [finalized],
                )?;
                transaction.execute("DELETE FROM out_entries WHERE epoch <= ?1", [finalized])?;
                Ok(())
            },
        );
        if let Err(error) = &result {
            self.fence_storage_failure(error);
        }
        result
    }

    pub(crate) fn stored_result(&self, epoch: u64) -> Result<Option<SettlementResult>> {
        stored_result(&self.source.connect()?, epoch)
    }

    /// Commits the certified result before its admission can have an uncertain outcome.
    pub(crate) fn record_result(
        &self,
        result: &SettlementResult,
        genesis_root: StateRoot<Digest>,
    ) -> Result<()> {
        let mut connection = self.source.connect()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;",
        )?;
        let result = record_result(&mut connection, result, genesis_root);
        if let Err(error) = &result {
            self.fence_storage_failure(error);
        }
        result
    }

    /// Loads a current or still-closing epoch.
    pub(crate) fn load(&self, epoch: u64) -> Result<EpochData> {
        let connection = self.source.connect()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        Store::load_epoch(&connection, epoch)
    }
}

pub(crate) struct Store {
    connection: Connection,
    source: StoreSource,
    #[cfg(test)]
    fail_payment_commit: bool,
    #[cfg(test)]
    fail_payment_write: bool,
    #[cfg(test)]
    fail_deposit_commit: bool,
    #[cfg(test)]
    fail_cutover_commit: bool,
}

impl Store {
    pub(crate) fn storage_fault(&self) -> Option<&str> {
        self.source.0.failure.get().map(String::as_str)
    }

    #[cfg(test)]
    pub(crate) fn open(path: &Path, identities: &[AccountIdentity]) -> Result<Self> {
        let accounts = identities
            .iter()
            .map(|identity| Account {
                key: identity.key.clone(),
                balance: INITIAL_BALANCE,
            })
            .collect::<Vec<_>>();
        Self::open_configured(path, identities, &accounts)
    }

    pub(crate) fn open_configured(
        path: &Path,
        identities: &[AccountIdentity],
        accounts: &[Account],
    ) -> Result<Self> {
        ensure!(
            identities.len() == accounts.len()
                && identities
                    .iter()
                    .zip(accounts)
                    .all(|(identity, account)| identity.key == account.key),
            "configured account identities differ from the deployment"
        );
        let source = StoreSource::new(path)?;
        let connection = source.connect()?;
        Self::from_connection(connection, source, identities, accounts)
    }

    #[cfg(test)]
    pub(crate) fn in_memory(identities: &[AccountIdentity]) -> Result<Self> {
        Self::open(Path::new(":memory:"), identities)
    }

    fn from_connection(
        connection: Connection,
        source: StoreSource,
        identities: &[AccountIdentity],
        accounts: &[Account],
    ) -> Result<Self> {
        let schema = format!(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;

             CREATE TABLE IF NOT EXISTS operator_meta (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 schema_version INTEGER NOT NULL,
                 genesis_accounts BLOB NOT NULL,
                 genesis_root BLOB,
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 live_liability BLOB NOT NULL CHECK (length(live_liability) = 8),
                 deposit_events INTEGER NOT NULL CHECK (
                     deposit_events BETWEEN 0 AND {max_deposit_events}
                 ),
                 payment_context BLOB CHECK (
                     payment_context IS NULL OR length(payment_context) = {context_size}
                 )
             );

             CREATE TABLE IF NOT EXISTS account_identities (
                 public_key BLOB PRIMARY KEY CHECK (length(public_key) = 32),
                 name TEXT NOT NULL
             );

             CREATE TABLE IF NOT EXISTS account_states (
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 public_key BLOB NOT NULL CHECK (length(public_key) = 32),
                 predecessor_balance INTEGER NOT NULL CHECK (predecessor_balance >= 0),
                 current_balance INTEGER NOT NULL CHECK (current_balance >= 0),
                 PRIMARY KEY(epoch, public_key),
                 FOREIGN KEY(public_key) REFERENCES account_identities(public_key)
             );
             CREATE INDEX IF NOT EXISTS account_states_key_epoch
                 ON account_states(public_key, epoch DESC);

             CREATE TABLE IF NOT EXISTS acks (
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 payer BLOB NOT NULL CHECK (length(payer) = 32),
                 seq INTEGER NOT NULL CHECK (seq >= 1),
                 cumulative_debit INTEGER NOT NULL CHECK (cumulative_debit >= 0),
                 ack BLOB NOT NULL CHECK (length(ack) = {ack_size}),
                 PRIMARY KEY(epoch, payer, seq)
             );

             CREATE TABLE IF NOT EXISTS out_entries (
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 payer BLOB NOT NULL CHECK (length(payer) = 32),
                 recipient BLOB NOT NULL CHECK (length(recipient) = 32),
                 cumulative INTEGER NOT NULL CHECK (cumulative > 0),
                 count INTEGER NOT NULL CHECK (count > 0),
                 PRIMARY KEY(epoch, payer, recipient)
             );

             CREATE TABLE IF NOT EXISTS accepted_entries (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 payer BLOB NOT NULL CHECK (length(payer) = 32),
                 seq INTEGER NOT NULL CHECK (seq >= 1),
                 recipient BLOB NOT NULL CHECK (length(recipient) = 32),
                 amount INTEGER NOT NULL CHECK (amount > 0),
                 cumulative INTEGER NOT NULL CHECK (cumulative > 0),
                 count INTEGER NOT NULL CHECK (count > 0),
                 opening BLOB NOT NULL CHECK (
                     length(opening) > 0 AND length(opening) <= {max_opening_bytes}
                 )
             );
             CREATE INDEX IF NOT EXISTS accepted_entries_epoch_id
                 ON accepted_entries(epoch, id);
             CREATE INDEX IF NOT EXISTS accepted_entries_recipient_id
                 ON accepted_entries(recipient, id);

             CREATE TABLE IF NOT EXISTS deposits (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 32),
                 account BLOB NOT NULL CHECK (length(account) = 32),
                 amount INTEGER NOT NULL CHECK (amount > 0)
             );
             CREATE INDEX IF NOT EXISTS deposits_epoch_sequence
                 ON deposits(epoch, sequence);

             CREATE TABLE IF NOT EXISTS withdrawals (
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 account BLOB NOT NULL CHECK (length(account) = 32),
                 request_id BLOB NOT NULL UNIQUE CHECK (length(request_id) = 32),
                 applied_amount INTEGER CHECK (
                     applied_amount IS NULL OR applied_amount >= 0
                 ),
                 encoded BLOB NOT NULL CHECK (
                     length(encoded) > 0 AND length(encoded) <= {max_withdrawal_bytes}
                 ),
                 PRIMARY KEY(epoch, account)
             );
             CREATE INDEX IF NOT EXISTS withdrawals_pending_close_epoch
                 ON withdrawals(epoch, account) WHERE applied_amount IS NULL;

             CREATE TABLE IF NOT EXISTS registrations (
                 epoch INTEGER PRIMARY KEY CHECK (epoch >= 0),
                 floors BLOB CHECK(floors IS NULL OR length(floors) = 16),
                 admission_deadline INTEGER CHECK (admission_deadline >= 0),
                 challenge_deadline INTEGER CHECK (
                     challenge_deadline > admission_deadline
                 ),
                 CHECK ((admission_deadline IS NULL) = (challenge_deadline IS NULL))
             );

             CREATE TABLE IF NOT EXISTS close_jobs (
                 epoch INTEGER PRIMARY KEY CHECK (epoch >= 0),
                 status TEXT NOT NULL CHECK (status IN ('closing', 'finalized', 'failed')),
                 payment_context BLOB NOT NULL CHECK (length(payment_context) = {context_size}),
                 result BLOB CHECK (result IS NULL OR length(result) <= {max_result_bytes}),
                 error TEXT CHECK (
                     error IS NULL OR length(CAST(error AS BLOB)) <= {max_close_error_bytes}
                 )
             );
             CREATE INDEX IF NOT EXISTS close_jobs_status_epoch
                 ON close_jobs(status, epoch);

             CREATE TABLE IF NOT EXISTS settlements (
                 epoch INTEGER PRIMARY KEY CHECK (epoch >= 0),
                 batch_id BLOB NOT NULL UNIQUE CHECK (length(batch_id) = 32),
                 header BLOB NOT NULL CHECK (length(header) = 32),
                 roots BLOB NOT NULL,
                 certificate BLOB NOT NULL,
                 rows INTEGER NOT NULL CHECK (rows >= 0),
                 dealing_bytes INTEGER NOT NULL CHECK (dealing_bytes >= 0),
                 withdrawal_total INTEGER NOT NULL CHECK (withdrawal_total >= 0),
                 prepare_micros INTEGER NOT NULL CHECK (prepare_micros >= 0),
                 deal_micros INTEGER NOT NULL CHECK (deal_micros >= 0),
                 seal_micros INTEGER NOT NULL CHECK (seal_micros >= 0)
             );",
            max_result_bytes = MAX_RESULT_BYTES,
            ack_size = Ack::SIZE,
            max_opening_bytes = MAX_OPENING_BYTES,
            context_size = EpochPaymentContext::SIZE,
            max_deposit_events = MAX_DEPOSIT_EVENTS,
            max_close_error_bytes = MAX_CLOSE_ERROR_BYTES,
            max_withdrawal_bytes = MAX_WITHDRAWAL_BYTES,
        );
        connection.execute_batch(&schema)?;

        // The accept path alone reuses more distinct statements than rusqlite's default
        // cache of 16 holds, so give prepared statements headroom against eviction.
        connection.set_prepared_statement_cache_capacity(32);
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        ensure!(
            journal_mode.eq_ignore_ascii_case("wal"),
            "SQLite operator requires WAL, but the selected source uses {journal_mode}"
        );

        let metadata = connection
            .query_row(
                "SELECT schema_version, epoch FROM operator_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let mut genesis_accounts = accounts
            .iter()
            .map(|account| (account.key.clone(), account.balance))
            .collect::<Vec<_>>();
        genesis_accounts.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let genesis_accounts = genesis_accounts.encode();
        match metadata {
            Some((version, _)) => {
                ensure!(
                    version == SCHEMA_VERSION,
                    "unsupported clearing operator schema version {version}"
                );
                let matches: bool = connection.query_row(
                    "SELECT genesis_accounts = ?1 FROM operator_meta WHERE singleton = 1",
                    [genesis_accounts.as_ref()],
                    |row| row.get(0),
                )?;
                ensure!(matches, "operator store has the wrong genesis allocations");
            }
            None => {
                let transaction = connection.unchecked_transaction()?;
                let initial_liability = accounts.iter().try_fold(0_u64, |total, account| {
                    sql_u64(account.balance, "initial balance")?;
                    total
                        .checked_add(account.balance)
                        .context("initial liability overflow")
                })?;
                transaction.execute(
                    "INSERT INTO operator_meta(
                         singleton, schema_version, genesis_accounts, epoch, live_liability, deposit_events
                     ) VALUES(1, ?1, ?2, 0, ?3, 0)",
                    params![SCHEMA_VERSION, genesis_accounts.as_ref(), initial_liability.to_be_bytes().as_slice()],
                )?;
                for (identity, account) in identities.iter().zip(accounts) {
                    let key = identity.key.clone();
                    let balance = sql_u64(account.balance, "initial balance")?;
                    transaction.execute(
                        "INSERT INTO account_identities(public_key, name) VALUES(?1, ?2)",
                        params![key.as_ref(), identity.name],
                    )?;
                    if balance > 0 {
                        transaction.execute(
                            "INSERT INTO account_states(
                                 epoch, public_key, predecessor_balance, current_balance
                             ) VALUES(0, ?1, ?2, ?2)",
                            params![key.as_ref(), balance],
                        )?;
                    }
                }
                transaction.commit()?;
            }
        }
        Ok(Self {
            connection,
            source,
            #[cfg(test)]
            fail_payment_commit: false,
            #[cfg(test)]
            fail_payment_write: false,
            #[cfg(test)]
            fail_deposit_commit: false,
            #[cfg(test)]
            fail_cutover_commit: false,
        })
    }

    pub(crate) fn epoch(&self) -> Result<u64> {
        metadata_epoch(&self.connection)
    }

    pub(crate) fn bind_genesis(&mut self, root: StateRoot<Digest>) -> Result<()> {
        mutate(&mut self.connection, "genesis binding", |transaction| {
            let matches: Option<bool> = transaction.query_row(
                "SELECT genesis_root = ?1 FROM operator_meta WHERE singleton = 1",
                [root.encode().as_ref()],
                |row| row.get(0),
            )?;
            ensure!(
                matches != Some(false),
                "operator store has the wrong genesis root"
            );
            transaction.execute(
                "UPDATE operator_meta SET genesis_root = ?1 WHERE singleton = 1 AND genesis_root IS NULL",
                [root.encode().as_ref()],
            )?;
            Ok(())
        })
    }

    pub(crate) fn stored_result(&self, epoch: u64) -> Result<Option<SettlementResult>> {
        stored_result(&self.connection, epoch)
    }

    #[cfg(test)]
    pub(crate) fn record_result(
        &mut self,
        result: &SettlementResult,
        genesis_root: StateRoot<Digest>,
    ) -> Result<()> {
        record_result(&mut self.connection, result, genesis_root)
    }

    /// Returns the cached liability of the current account state.
    pub(crate) fn current_liability(&self) -> Result<u64> {
        metadata_live_liability(&self.connection)
    }

    /// Projects successor liability after resolving deferred withdrawal outputs.
    pub(crate) fn successor_liability(&self) -> Result<u64> {
        let epoch = self.epoch()?;
        let pending_total = pending_withdrawals(&self.connection, epoch)?
            .into_iter()
            .try_fold(0_u64, |total, (_, amount)| {
                total
                    .checked_add(amount)
                    .context("pending withdrawal total overflow")
            })?;
        self.current_liability()?
            .checked_sub(pending_total)
            .context("pending withdrawals exceed live liability")
    }

    pub(crate) fn current_deposit_events(&self) -> Result<usize> {
        metadata_deposit_events(&self.connection)
    }

    pub(crate) fn staged_deposit(&self, id: &Digest) -> Result<Option<StagedDeposit>> {
        self.connection
            .query_row(
                "SELECT epoch, length(account), account, amount
                 FROM deposits WHERE event_id = ?1",
                [id.as_ref()],
                |row| {
                    let account = read_fixed_blob(row, 1, 2, Key::SIZE, "deposit account")?;
                    Ok((row.get::<_, i64>(0)?, account, row.get::<_, i64>(3)?))
                },
            )
            .optional()?
            .map(|(epoch, account, amount)| {
                Ok(StagedDeposit {
                    epoch: from_sql_u64(epoch, "deposit epoch")?,
                    id: *id,
                    account: Key::decode(account).context("decode staged deposit account")?,
                    amount: from_sql_u64(amount, "deposit amount")?,
                })
            })
            .transpose()
    }

    pub(crate) fn staged_withdrawal(
        &self,
        account: &Key,
    ) -> Result<Option<(SignedWithdrawal<Key, Digest>, StagedWithdrawal)>> {
        self.connection
            .query_row(
                "SELECT epoch, applied_amount, length(encoded), encoded
                 FROM withdrawals WHERE epoch = ?1 AND account = ?2",
                params![sql_u64(self.epoch()?, "epoch")?, account.as_ref()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        read_bounded_blob(row, 2, 3, MAX_WITHDRAWAL_BYTES, "encoded withdrawal")?,
                    ))
                },
            )
            .optional()?
            .map(|(epoch, applied_amount, encoded)| {
                let request = SignedWithdrawal::<Key, Digest>::decode_cfg(
                    encoded,
                    &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                )
                .context("decode staged withdrawal")?;
                validate_applied_withdrawal(&request, applied_amount)?;
                Ok((
                    request.clone(),
                    StagedWithdrawal {
                        epoch: from_sql_u64(epoch, "withdrawal epoch")?,
                        account: account.clone(),
                        action: *request.body().action(),
                    },
                ))
            })
            .transpose()
    }

    pub(crate) fn staged_withdrawal_request(
        &self,
        request: &SignedWithdrawal<Key, Digest>,
    ) -> Result<Option<StagedWithdrawal>> {
        let request_id = request.id::<Sha256>();
        self.connection
            .query_row(
                "SELECT epoch, applied_amount, length(encoded), encoded
                 FROM withdrawals WHERE request_id = ?1",
                [request_id.digest().as_ref()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        read_bounded_blob(row, 2, 3, MAX_WITHDRAWAL_BYTES, "encoded withdrawal")?,
                    ))
                },
            )
            .optional()?
            .map(|(epoch, applied_amount, encoded)| {
                let stored = SignedWithdrawal::<Key, Digest>::decode_cfg(
                    encoded,
                    &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                )
                .context("decode staged withdrawal")?;
                ensure!(
                    stored == *request,
                    "withdrawal id is bound to another authorization"
                );
                validate_applied_withdrawal(&stored, applied_amount)?;
                Ok(StagedWithdrawal {
                    epoch: from_sql_u64(epoch, "withdrawal epoch")?,
                    account: request.account().clone(),
                    action: *request.body().action(),
                })
            })
            .transpose()
    }

    pub(crate) fn epoch_reader(&self) -> EpochReader {
        EpochReader {
            source: self.source.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn outgoing_entry_count(&self, epoch: u64) -> Result<i64> {
        Ok(self.connection.query_row(
            "SELECT count(*) FROM out_entries WHERE epoch = ?1",
            [sql_u64(epoch, "epoch")?],
            |row| row.get(0),
        )?)
    }

    #[cfg(test)]
    pub(crate) fn account_version_count(&self) -> Result<u64> {
        let rows = self
            .connection
            .query_row("SELECT count(*) FROM account_states", [], |row| {
                row.get::<_, i64>(0)
            })?;
        from_sql_u64(rows, "account storage row count")
    }

    #[cfg(test)]
    pub(crate) fn close_job_status_query_plan(&self) -> Result<Vec<String>> {
        let mut statement = self.connection.prepare(
            "EXPLAIN QUERY PLAN
             SELECT epoch FROM close_jobs
             WHERE status = 'closing' ORDER BY epoch LIMIT 1",
        )?;
        Ok(statement
            .query_map([], |row| row.get::<_, String>(3))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }

    #[cfg(test)]
    pub(crate) fn total_changes(&self) -> u64 {
        self.connection.total_changes()
    }

    #[cfg(test)]
    pub(crate) fn account_lookup_plan(&self, account: &Key) -> Result<Vec<String>> {
        let sql = format!("EXPLAIN QUERY PLAN {EFFECTIVE_ACCOUNT_SQL}");
        let mut statement = self.connection.prepare(&sql)?;
        statement
            .query_map(
                params![account.as_ref(), sql_u64(self.epoch()?, "epoch")?],
                |row| row.get(3),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    #[cfg(test)]
    pub(crate) fn epoch_account_plan(&self, epoch: u64) -> Result<Vec<String>> {
        let sql = format!("EXPLAIN QUERY PLAN {EPOCH_ACCOUNTS_SQL}");
        let mut statement = self.connection.prepare(&sql)?;
        statement
            .query_map([sql_u64(epoch, "epoch")?], |row| row.get(3))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    #[cfg(test)]
    pub(crate) fn journal_mode(&self) -> Result<String> {
        self.connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .map_err(Into::into)
    }

    pub(crate) fn database_path(&self) -> PathBuf {
        self.source.0.path.clone()
    }

    pub(crate) fn ensure_current_context(&mut self, expected: &EpochPaymentContext) -> Result<()> {
        mutate(&mut self.connection, "payment context", |transaction| {
            ensure!(
                metadata_epoch(transaction)? == expected.epoch(),
                "stored epoch does not match its payment context"
            );
            match metadata_payment_context(transaction)? {
                Some(stored) => ensure!(
                    stored == *expected,
                    "stored payment context differs from the reconstructed epoch"
                ),
                None => {
                    let accepted: i64 = transaction.query_row(
                        "SELECT count(*) FROM acks WHERE epoch = ?1",
                        [sql_u64(expected.epoch(), "epoch")?],
                        |row| row.get(0),
                    )?;
                    ensure!(
                        accepted == 0,
                        "an active payment epoch is missing its durable context"
                    );
                    transaction.execute(
                        "UPDATE operator_meta SET payment_context = ?1 WHERE singleton = 1",
                        [expected.encode().as_ref()],
                    )?;
                }
            }
            Ok(())
        })
    }

    /// Records the boundary's publication before signed registration bytes can escape.
    pub(crate) fn begin_registration(&mut self, expected: &EpochPaymentContext) -> Result<()> {
        mutate(
            &mut self.connection,
            "prepare registration",
            |transaction| {
                let epoch = metadata_epoch(transaction)?;
                ensure!(epoch == expected.epoch(), "registration context is stale");
                ensure!(
                    metadata_payment_context(transaction)?.as_ref() == Some(expected),
                    "registration anchor is stale"
                );
                transaction.execute(
                    "INSERT OR IGNORE INTO registrations(epoch) VALUES(?1)",
                    [sql_u64(epoch, "epoch")?],
                )?;
                Ok(())
            },
        )
    }

    /// Returns the chain-assigned deadlines, excluding unadopted publications.
    pub(crate) fn chain_deadlines(&self, epoch: u64) -> Result<Option<(u64, u64)>> {
        let deadlines = self
            .connection
            .query_row(
                "SELECT admission_deadline, challenge_deadline
                 FROM registrations WHERE epoch = ?1 AND admission_deadline IS NOT NULL",
                [sql_u64(epoch, "epoch")?],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        Ok(match deadlines {
            Some((admission, challenge)) => Some((
                from_sql_u64(admission, "admission deadline")?,
                from_sql_u64(challenge, "challenge deadline")?,
            )),
            None => None,
        })
    }

    /// Adopts the chain-assigned deadlines for the live epoch, moving the
    /// stored payment context from `expected` to `replacement` in the same
    /// transaction. Deadlines may only move before the epoch's first receipt:
    /// every accepted send binds the registered context, and the anchor
    /// commits the deadlines.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn adopt_deadlines(
        &mut self,
        epoch: u64,
        expected: &EpochPaymentContext,
        replacement: &EpochPaymentContext,
        admission_deadline: u64,
        challenge_deadline: u64,
        floors: commonware_clearing::bajillion::logs::Floors,
    ) -> Result<()> {
        mutate(&mut self.connection, "chain registration", |transaction| {
            ensure!(
                metadata_epoch(transaction)? == epoch,
                "chain deadlines target another epoch"
            );
            if let Some(stored) = metadata_payment_context(transaction)? {
                ensure!(
                    stored == *expected,
                    "stored payment context differs from the live registration"
                );
            }
            let epoch_sql = sql_u64(epoch, "epoch")?;
            let accepted: i64 = transaction.query_row(
                "SELECT count(*) FROM acks WHERE epoch = ?1",
                [epoch_sql],
                |row| row.get(0),
            )?;
            ensure!(
                accepted == 0,
                "chain deadlines cannot move under an epoch with receipts"
            );
            transaction.execute(
                "INSERT INTO registrations(epoch, admission_deadline, challenge_deadline, floors)
                 VALUES(?1, ?2, ?3, ?4)
                 ON CONFLICT(epoch) DO UPDATE
                 SET admission_deadline = ?2, challenge_deadline = ?3, floors = ?4",
                params![
                    epoch_sql,
                    sql_u64(admission_deadline, "admission deadline")?,
                    sql_u64(challenge_deadline, "challenge deadline")?,
                    floors.encode().as_ref(),
                ],
            )?;
            transaction.execute(
                "UPDATE operator_meta SET payment_context = ?1 WHERE singleton = 1",
                [replacement.encode().as_ref()],
            )?;
            Ok(())
        })
    }

    pub(crate) fn closing_context(&self, epoch: u64) -> Result<EpochPaymentContext> {
        let epoch = sql_u64(epoch, "epoch")?;
        let encoded: Vec<u8> = self.connection.query_row(
            "SELECT length(payment_context), payment_context
             FROM close_jobs WHERE epoch = ?1",
            [epoch],
            |row| read_fixed_blob(row, 0, 1, EpochPaymentContext::SIZE, "payment context"),
        )?;
        decode_payment_context(&encoded)
    }

    pub(crate) fn load_current(&self) -> Result<EpochData> {
        Self::load_epoch(&self.connection, self.epoch()?)
    }

    pub(crate) fn ensure_payer_eligible(&self, account: &Key, first_unadmitted: u64) -> Result<()> {
        let epoch = self.epoch()?;
        eligible_account(&self.connection, epoch, account)?;
        let pending_creation: bool = self.connection.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM account_states AS state
             WHERE state.public_key = ?1 AND state.epoch >= ?2 AND state.epoch < ?3
               AND state.predecessor_balance = 0
               AND NOT EXISTS(SELECT 1 FROM deposits
                              WHERE deposits.epoch = state.epoch AND deposits.account = state.public_key))"
        )?.query_row(params![account.as_ref(), sql_u64(first_unadmitted, "first unadmitted epoch")?, sql_u64(epoch, "epoch")?], |row| row.get(0))?;
        ensure!(
            !pending_creation,
            "recipient's first positive close is not admitted"
        );
        Ok(())
    }

    pub(crate) fn current_account(&self, account: &Key) -> Result<Option<StoredAccount>> {
        effective_account(&self.connection, self.epoch()?, account)
    }

    pub(crate) fn has_current_work(&self) -> Result<bool> {
        epoch_has_work(&self.connection, self.epoch()?)
    }

    fn load_epoch(connection: &Connection, epoch: u64) -> Result<EpochData> {
        // Account state is copy-on-write by epoch. A target-local zero version remains visible to
        // that close, while a zero inherited from an older epoch denotes an account already
        // removed at the intervening boundary.
        let epoch_sql = sql_u64(epoch, "epoch")?;
        let mut statement = connection.prepare(EPOCH_ACCOUNTS_SQL)?;
        let account_rows = statement.query_map([epoch_sql], read_account)?;
        let accounts = account_rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .with_context(|| format!("read epoch {epoch} account state"))?;

        let entry_count = epoch_entry_count(connection, epoch_sql)?;
        ensure!(
            entry_count <= MAX_ACCEPTED_PAYMENTS,
            "epoch payment count exceeds its configured bound"
        );
        let mut statement = connection.prepare(
            "SELECT length(ack), ack, seq, cumulative_debit, length(payer), payer
             FROM acks WHERE epoch = ?1 ORDER BY payer, seq",
        )?;
        let acks = statement
            .query_map([epoch_sql], |row| {
                Ok((
                    read_fixed_blob(row, 0, 1, Ack::SIZE, "acknowledgment")?,
                    from_sql_u64(row.get(2)?, "ack sequence").map_err(to_sqlite_error)?,
                    from_sql_u64(row.get(3)?, "ack debit").map_err(to_sqlite_error)?,
                    read_fixed_blob(row, 4, 5, Key::SIZE, "acknowledgment payer")?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(
            acks.len() <= MAX_ACCEPTED_PAYMENTS,
            "epoch batch count exceeds its configured bound"
        );
        let acks = acks
            .into_iter()
            .map(|(ack, seq, debit, payer)| {
                let ack = Ack::decode(ack).context("decode stored acknowledgment")?;
                ensure!(
                    ack.body().epoch() == epoch
                        && ack.body().seq() == seq
                        && ack.body().cumulative_debit() == debit
                        && ack.body().payer().as_ref() == payer.as_slice(),
                    "stored acknowledgment metadata differs from its signed body"
                );
                Ok(ack)
            })
            .collect::<Result<Vec<_>>>()?;

        let mut statement = connection.prepare(
            "SELECT id, length(payer), payer, seq, length(recipient), recipient,
                    amount, cumulative, count, length(opening), opening
             FROM accepted_entries WHERE epoch = ?1 ORDER BY id",
        )?;
        let entries = statement
            .query_map([epoch_sql], |row| {
                let payer = read_fixed_blob(row, 1, 2, Key::SIZE, "entry payer")?;
                let recipient = read_fixed_blob(row, 4, 5, Key::SIZE, "entry recipient")?;

                // Check SQLite's scalar length before asking rusqlite to materialize the blob.
                let opening = read_bounded_blob(row, 9, 10, MAX_OPENING_BYTES, "entry opening")?;
                Ok(StoredEntry {
                    sequence: from_sql_u64(row.get(0)?, "entry cursor").map_err(to_sqlite_error)?,
                    payer: Key::decode(payer).map_err(|error| {
                        to_sqlite_error(anyhow::anyhow!("decode entry payer: {error}"))
                    })?,
                    seq: from_sql_u64(row.get(3)?, "batch sequence").map_err(to_sqlite_error)?,
                    recipient: Key::decode(recipient).map_err(|error| {
                        to_sqlite_error(anyhow::anyhow!("decode entry recipient: {error}"))
                    })?,
                    amount: from_sql_u64(row.get(6)?, "entry amount").map_err(to_sqlite_error)?,
                    cumulative: from_sql_u64(row.get(7)?, "entry cumulative")
                        .map_err(to_sqlite_error)?,
                    count: from_sql_u64(row.get(8)?, "entry count").map_err(to_sqlite_error)?,
                    opening: Opening::decode(opening).map_err(|error| {
                        to_sqlite_error(anyhow::anyhow!("decode entry opening: {error}"))
                    })?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut statement = connection.prepare(
            "SELECT length(payer), payer, length(recipient), recipient, cumulative, count
             FROM out_entries WHERE epoch = ?1 ORDER BY payer, recipient",
        )?;
        let edges = statement
            .query_map([epoch_sql], |row| {
                let payer = read_fixed_blob(row, 0, 1, Key::SIZE, "edge payer")?;
                let recipient = read_fixed_blob(row, 2, 3, Key::SIZE, "edge recipient")?;
                Ok(StoredEdge {
                    payer: Key::decode(payer).map_err(|error| {
                        to_sqlite_error(anyhow::anyhow!("decode edge payer: {error}"))
                    })?,
                    entry: OutEntry {
                        recipient: Key::decode(recipient).map_err(|error| {
                            to_sqlite_error(anyhow::anyhow!("decode edge recipient: {error}"))
                        })?,
                        cumulative: from_sql_u64(row.get(4)?, "edge cumulative")
                            .map_err(to_sqlite_error)?,
                        count: from_sql_u64(row.get(5)?, "edge count").map_err(to_sqlite_error)?,
                    },
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let deposits = {
            let count = connection.query_row(
                "SELECT count(*) FROM deposits WHERE epoch = ?1",
                [epoch_sql],
                |row| row.get::<_, i64>(0),
            )?;
            let count = usize::try_from(count).context("invalid deposit event count")?;
            ensure!(
                count <= MAX_DEPOSIT_EVENTS,
                "epoch deposit event count exceeds its configured bound"
            );
            let mut statement = connection.prepare(
                "SELECT length(event_id), event_id, length(account), account, amount
                 FROM deposits WHERE epoch = ?1 ORDER BY sequence",
            )?;
            statement
                .query_map([epoch_sql], |row| {
                    let event_id = read_fixed_blob(row, 0, 1, Digest::SIZE, "deposit id")?;
                    let account = read_fixed_blob(row, 2, 3, Key::SIZE, "deposit account")?;
                    Ok(DepositEvent {
                        id: Digest::decode(event_id).map_err(|error| {
                            to_sqlite_error(anyhow::anyhow!("decode deposit id: {error}"))
                        })?,
                        account: Key::decode(account).map_err(|error| {
                            to_sqlite_error(anyhow::anyhow!("decode deposit account: {error}"))
                        })?,
                        amount: from_sql_u64(row.get(4)?, "deposit amount")
                            .map_err(to_sqlite_error)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let withdrawal_count = connection.query_row(
            "SELECT count(*) FROM withdrawals WHERE epoch = ?1",
            [epoch_sql],
            |row| row.get::<_, i64>(0),
        )?;
        let withdrawal_count =
            usize::try_from(withdrawal_count).context("invalid withdrawal count")?;
        ensure!(
            withdrawal_count <= MAX_WITHDRAWALS,
            "epoch withdrawal count exceeds its configured bound"
        );
        let mut statement = connection.prepare(
            "SELECT applied_amount, length(encoded), encoded
             FROM withdrawals WHERE epoch = ?1 ORDER BY account",
        )?;
        let withdrawals = statement
            .query_map([epoch_sql], |row| {
                let applied_amount = row.get::<_, Option<i64>>(0)?;
                let encoded =
                    read_bounded_blob(row, 1, 2, MAX_WITHDRAWAL_BYTES, "encoded withdrawal")?;
                let request = SignedWithdrawal::<Key, Digest>::decode_cfg(
                    encoded,
                    &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                )
                .map_err(|error| {
                    to_sqlite_error(anyhow::anyhow!("decode stored withdrawal: {error}"))
                })?;
                let applied_amount = validate_applied_withdrawal(&request, applied_amount)
                    .map_err(to_sqlite_error)?;
                Ok(StoredWithdrawal {
                    request,
                    applied_amount,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let deadlines = connection
            .query_row(
                "SELECT admission_deadline, challenge_deadline
                 FROM registrations WHERE epoch = ?1 AND admission_deadline IS NOT NULL",
                [epoch_sql],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let deadlines = match deadlines {
            Some((admission, challenge)) => Some((
                from_sql_u64(admission, "admission deadline")?,
                from_sql_u64(challenge, "challenge deadline")?,
            )),
            None => None,
        };
        let floors = connection
            .query_row(
                "SELECT floors FROM registrations WHERE epoch = ?1",
                [epoch_sql],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .map(commonware_clearing::bajillion::logs::Floors::decode)
            .transpose()?;
        Ok(EpochData {
            epoch,
            accounts,
            acks,
            entries,
            edges,
            deposits,
            withdrawals,
            deadlines,
            floors,
        })
    }

    pub(crate) fn accept_send(
        &mut self,
        context: &EpochPaymentContext,
        protocol: &Protocol,
        authorization: SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<SendVerdict> {
        #[cfg(test)]
        let fail_commit = std::mem::take(&mut self.fail_payment_commit);
        #[cfg(test)]
        let fail_write = std::mem::take(&mut self.fail_payment_write);
        let verdict = mutate(&mut self.connection, "payment", |transaction| {
            if let Some(accepted) = find_accepted_batch(transaction, &authorization, entries)? {
                return Ok(SendVerdict::Accepted(Box::new(accepted)));
            }
            let plan = match validate_new_batch(transaction, context, &authorization, entries)? {
                Admission::Stale(endpoint) => return Ok(SendVerdict::Stale(endpoint)),
                Admission::Admit(plan) => plan,
            };
            let epoch = plan.epoch;
            let epoch_sql = sql_u64(epoch, "epoch")?;
            let seq = authorization.body().seq();
            let seq_sql = sql_u64(seq, "batch sequence")?;

            upsert_account_state(transaction, epoch, &plan.payer)?;
            let body = authorization.body().clone();
            let encoded_body = body.encode();
            let operator_signature = protocol
                .operator()
                .sign(VECTOR_ACK_SIGNATURE_NAMESPACE, encoded_body.as_ref());
            let ack = Ack::from_raw_unchecked(
                body,
                authorization.payer_signature().clone(),
                operator_signature,
            );
            transaction
                .prepare_cached(
                    "INSERT INTO acks(epoch, payer, seq, cumulative_debit, ack)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                )?
                .execute(params![
                    epoch_sql,
                    plan.payer.key.as_ref(),
                    seq_sql,
                    sql_u64(ack.body().cumulative_debit(), "cumulative debit")?,
                    ack.encode().as_ref(),
                ])?;

            // Every credited entry lands in this one transaction: the payer debit, each
            // receiver credit, each cumulative edge advance, and each serving-log row
            // commit or roll back together. Each entry's opening is computed once here,
            // under this batch's acknowledged root, and served verbatim thereafter.
            let mut advance_edge = transaction.prepare_cached(
                "INSERT INTO out_entries(epoch, payer, recipient, cumulative, count)
                 VALUES(?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(epoch, payer, recipient) DO UPDATE SET
                     cumulative = excluded.cumulative,
                     count = excluded.count",
            )?;
            let mut insert_entry = transaction.prepare_cached(
                "INSERT INTO accepted_entries(
                     epoch, payer, seq, recipient, amount, cumulative, count, opening
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            let mut accepted = Vec::with_capacity(plan.credits.len());
            for credit in &plan.credits {
                upsert_account_state(transaction, epoch, &credit.receiver)?;
                let lookup = plan
                    .vector
                    .lookup::<Sha256, Digest>(&credit.receiver.key)
                    .context("open accepted entry")?;
                let OutTipLookup::Present {
                    cumulative,
                    count,
                    opening,
                } = lookup
                else {
                    unreachable!("every credited recipient is in the merged vector");
                };
                advance_edge.execute(params![
                    epoch_sql,
                    plan.payer.key.as_ref(),
                    credit.receiver.key.as_ref(),
                    sql_u64(cumulative, "edge cumulative credit")?,
                    sql_u64(count, "edge payment count")?,
                ])?;
                let encoded = opening.encode();
                ensure!(
                    encoded.len() <= MAX_OPENING_BYTES,
                    "entry opening exceeds the operator bound"
                );
                insert_entry.execute(params![
                    epoch_sql,
                    plan.payer.key.as_ref(),
                    seq_sql,
                    credit.receiver.key.as_ref(),
                    sql_u64(credit.amount, "entry amount")?,
                    sql_u64(cumulative, "entry cumulative")?,
                    sql_u64(count, "entry count")?,
                    encoded.as_ref(),
                ])?;
                accepted.push(AcceptedEntry {
                    recipient: credit.receiver.key.clone(),
                    cumulative,
                    count,
                    opening,
                });
            }
            #[cfg(test)]
            if fail_write {
                return Err(rusqlite::Error::ExecuteReturnedResults.into());
            }
            Ok(SendVerdict::Accepted(Box::new(AcceptedBatch {
                epoch,
                sequence: seq,
                total: plan.total,
                acceptance: Acceptance {
                    ack,
                    entries: accepted,
                },
            })))
        })?;
        #[cfg(test)]
        if fail_commit {
            return Err(
                CommitUnknown::new("payment", rusqlite::Error::ExecuteReturnedResults).into(),
            );
        }
        Ok(verdict)
    }

    pub(crate) fn payment_requires_epoch_registration(
        &self,
        context: &EpochPaymentContext,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<bool> {
        if find_accepted_batch(&self.connection, authorization, entries)?.is_some() {
            return Ok(false);
        }
        match validate_new_batch(&self.connection, context, authorization, entries)? {
            // A corrective rejection admits nothing, so it triggers no registration.
            Admission::Stale(_) => Ok(false),
            Admission::Admit(_) => Ok(true),
        }
    }

    /// Reads any committed batch for one authorization across every epoch.
    ///
    /// This is a durable, side-effect-free read of committed acknowledgment rows. It
    /// authoritatively answers whether a specific signed endpoint committed, which is exactly
    /// what resolves a client's commitment uncertainty independent of whether the operator is
    /// fenced from admitting new state.
    pub(crate) fn accepted_batch(
        &self,
        authorization: &SendAuthorization<Key, Digest>,
        entries: &[Entry],
    ) -> Result<Option<AcceptedBatch>> {
        find_accepted_batch(&self.connection, authorization, entries)
    }

    /// Reads one payer's accepted endpoint in the live epoch, for the corrective rejection.
    pub(crate) fn payer_endpoint(&self, payer: &Key) -> Result<Endpoint> {
        let epoch = self.epoch()?;
        let epoch_sql = sql_u64(epoch, "epoch")?;
        eligible_account(&self.connection, epoch, payer)?;
        let (seq, cumulative_debit) = payer_endpoint(&self.connection, epoch_sql, payer)?;
        Ok(Endpoint {
            cumulative_debit,
            seq,
            entries: out_entries_for(&self.connection, epoch_sql, payer)?,
        })
    }

    /// Serves accepted entry receipts crediting `receiver` in acceptance order after `after`.
    ///
    /// Each receipt uses its batch's stored acknowledgment and entry opening. This immutable
    /// log remains available across finalization and operational cache pruning.
    pub(crate) fn incoming_payments(
        &self,
        receiver: &Key,
        after: u64,
        limit: usize,
    ) -> Result<Vec<IncomingPayment>> {
        let limit = i64::try_from(limit.min(MAX_INCOMING_PAGE)).context("incoming page")?;
        let mut statement = self.connection.prepare_cached(
            "SELECT entry.id, entry.cumulative, entry.count,
                    length(entry.opening), entry.opening, length(ack.ack), ack.ack
             FROM accepted_entries AS entry
             JOIN acks AS ack
               ON ack.epoch = entry.epoch AND ack.payer = entry.payer AND ack.seq = entry.seq
             WHERE entry.recipient = ?1 AND entry.id > ?2
             ORDER BY entry.id
             LIMIT ?3",
        )?;
        let rows = statement
            .query_map(
                params![receiver.as_ref(), sql_u64(after, "incoming cursor")?, limit],
                |row| {
                    Ok((
                        from_sql_u64(row.get(0)?, "entry cursor").map_err(to_sqlite_error)?,
                        from_sql_u64(row.get(1)?, "entry cumulative").map_err(to_sqlite_error)?,
                        from_sql_u64(row.get(2)?, "entry count").map_err(to_sqlite_error)?,
                        read_bounded_blob(row, 3, 4, MAX_OPENING_BYTES, "entry opening")?,
                        read_fixed_blob(row, 5, 6, Ack::SIZE, "acknowledgment")?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(sequence, cumulative, count, opening, ack)| {
                Ok(IncomingPayment {
                    sequence,
                    receipt: Receipt {
                        ack: Ack::decode(ack).context("decode stored acknowledgment")?,
                        recipient: receiver.clone(),
                        cumulative,
                        count,
                        opening: Opening::decode(opening).context("decode stored entry opening")?,
                    },
                })
            })
            .collect()
    }

    /// Stages one finalized block's chain-confirmed deposit events in one
    /// immediate transaction: either every credit lands together with the
    /// boundary context it chains to, or none do and the block is
    /// re-observed. `expected` is the live context the first staging moves
    /// from, and each event's replacement is the next event's expectation.
    pub(crate) fn stage_deposits(
        &mut self,
        expected: &EpochPaymentContext,
        batch: &[Staging],
    ) -> Result<Vec<StagedDeposit>> {
        #[cfg(test)]
        let fail_commit = std::mem::take(&mut self.fail_deposit_commit);
        let mut context = expected;
        for staging in batch {
            ensure!(staging.event.amount > 0, "deposit amount must be positive");
            ensure!(
                staging.event.account == staging.identity.key,
                "deposit account does not match its identity"
            );
            ensure!(
                context.epoch() == staging.replacement.epoch()
                    && context.operator() == staging.replacement.operator(),
                "deposit context changed immutable epoch identity"
            );
            context = &staging.replacement;
        }
        let staged = mutate(&mut self.connection, "deposit", |transaction| {
            let mut context = expected;
            let mut staged = Vec::with_capacity(batch.len());
            for staging in batch {
                staged.push(stage_event(transaction, staging, context)?);
                context = &staging.replacement;
            }
            Ok(staged)
        })?;
        #[cfg(test)]
        if fail_commit {
            return Err(
                CommitUnknown::new("deposit", rusqlite::Error::ExecuteReturnedResults).into(),
            );
        }
        Ok(staged)
    }

    pub(crate) fn discard_unregistered_withdrawals(
        &mut self,
        expected: &EpochPaymentContext,
        replacement: &EpochPaymentContext,
        discarded: &[SignedWithdrawal<Key, Digest>],
    ) -> Result<()> {
        mutate(
            &mut self.connection,
            "unregistered withdrawal",
            |transaction| {
                let epoch = metadata_epoch(transaction)?;
                ensure!(
                    epoch == expected.epoch()
                        && epoch == replacement.epoch()
                        && expected.operator() == replacement.operator()
                        && metadata_payment_context(transaction)?.as_ref() == Some(expected),
                    "unregistered withdrawal context changed"
                );
                let epoch_sql = sql_u64(epoch, "epoch")?;
                let adopted: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM registrations WHERE epoch = ?1 AND admission_deadline IS NOT NULL)
                 OR EXISTS(SELECT 1 FROM acks WHERE epoch = ?1)
                 OR EXISTS(SELECT 1 FROM close_jobs WHERE epoch = ?1)",
                [epoch_sql], |row| row.get(0))?;
                ensure!(
                    !adopted,
                    "an adopted withdrawal boundary cannot be discarded"
                );
                let mut liability = metadata_live_liability(transaction)?;
                for request in discarded {
                    let (amount, encoded) = transaction.query_row(
                    "SELECT applied_amount, length(encoded), encoded FROM withdrawals WHERE epoch = ?1 AND account = ?2",
                    params![epoch_sql, request.account().as_ref()], |row| Ok((row.get::<_, Option<i64>>(0)?,
                        read_bounded_blob(row, 1, 2, MAX_WITHDRAWAL_BYTES, "unregistered withdrawal")?)))?;
                    ensure!(
                        encoded.as_slice() == request.encode().as_ref(),
                        "unregistered withdrawal request changed"
                    );
                    validate_applied_withdrawal(request, amount)?;
                    if let Some(amount) = amount {
                        let amount = from_sql_u64(amount, "withdrawal amount")?;
                        let mut account = effective_account(transaction, epoch, request.account())?
                            .context("withdrawal account is absent")?;
                        account.current =
                            checked_sql_add(account.current, amount, "restored balance")?;
                        upsert_account_state(transaction, epoch, &account)?;
                        liability = liability
                            .checked_add(amount)
                            .context("restored liability overflow")?;
                    }
                    transaction.execute(
                        "DELETE FROM withdrawals WHERE epoch = ?1 AND account = ?2",
                        params![epoch_sql, request.account().as_ref()],
                    )?;
                }
                transaction.execute("DELETE FROM registrations WHERE epoch = ?1", [epoch_sql])?;
                transaction.execute("UPDATE operator_meta SET payment_context = ?1, live_liability = ?2 WHERE singleton = 1",
                params![replacement.encode().as_ref(), liability.to_be_bytes().as_slice()])?;
                Ok(())
            },
        )
    }

    pub(crate) fn withdrawals_frozen(&self) -> Result<bool> {
        withdrawals_frozen(&self.connection, self.epoch()?)
    }

    pub(crate) fn stage_withdrawal(
        &mut self,
        request: &SignedWithdrawal<Key, Digest>,
        expected: &EpochPaymentContext,
        replacement: &EpochPaymentContext,
        queued: bool,
    ) -> Result<StagedWithdrawal> {
        ensure!(
            expected.epoch() == replacement.epoch()
                && expected.operator() == replacement.operator(),
            "withdrawal context changed immutable epoch identity"
        );
        request
            .verify_signature()
            .context("verify withdrawal authorization")?;
        ensure!(
            request.body().destination().len() <= MAX_DESTINATION_BYTES,
            "withdrawal destination exceeds the operator bound"
        );
        let encoded = request.encode();
        ensure!(
            encoded.len() <= MAX_WITHDRAWAL_BYTES,
            "withdrawal authorization exceeds the operator bound"
        );

        mutate(&mut self.connection, "withdrawal", |transaction| {
            let epoch = metadata_epoch(transaction)?;
            ensure!(epoch == expected.epoch(), "withdrawal context is stale");
            ensure!(
                metadata_payment_context(transaction)?.as_ref() == Some(expected),
                "withdrawal anchor is stale"
            );

            // A registration may reach settlement before its read-back or first receipt.
            // Published withdrawal boundaries remain fixed across those crash cuts.
            ensure!(
                !withdrawals_frozen(transaction, epoch)?,
                "withdrawals are frozen once registration publication begins"
            );

            let mut account = if queued {
                match effective_account(transaction, epoch, request.account())? {
                    Some(account) => account,
                    None => StoredAccount {
                        name: account_name(transaction, request.account())?,
                        key: request.account().clone(),
                        predecessor: 0,
                        current: 0,
                    },
                }
            } else {
                let account = eligible_account(transaction, epoch, request.account())?;
                ensure!(
                    account.predecessor > 0,
                    "withdrawal account is absent from the epoch predecessor"
                );
                account
            };
            let applied_amount = match request.body().action() {
                WithdrawalAction::Amount(amount) if account.current >= amount.get() => {
                    account.current -= amount.get();
                    Some(amount.get())
                }
                WithdrawalAction::Amount(_) => {
                    ensure!(queued, "withdrawal exceeds the live balance");
                    None
                }
                WithdrawalAction::Close => None,
            };

            // A queued authorization for an absent account still belongs to this epoch's boundary.
            upsert_account_state(transaction, epoch, &account)?;
            transaction.execute(
                "INSERT INTO withdrawals(epoch, account, request_id, applied_amount, encoded)
             VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    sql_u64(epoch, "epoch")?,
                    request.account().as_ref(),
                    request.id::<Sha256>().digest().as_ref(),
                    applied_amount
                        .map(|amount| sql_u64(amount, "withdrawal amount"))
                        .transpose()?,
                    encoded.as_ref(),
                ],
            )?;
            match applied_amount {
                Some(amount) => {
                    let live_liability = metadata_live_liability(transaction)?
                        .checked_sub(amount)
                        .context("withdrawal exceeds live liability")?;
                    transaction.execute(
                        "UPDATE operator_meta
                     SET payment_context = ?1, live_liability = ?2
                     WHERE singleton = 1",
                        params![
                            replacement.encode().as_ref(),
                            live_liability.to_be_bytes().as_slice(),
                        ],
                    )?;
                }
                None => {
                    transaction.execute(
                        "UPDATE operator_meta SET payment_context = ?1 WHERE singleton = 1",
                        [replacement.encode().as_ref()],
                    )?;
                }
            }
            Ok(StagedWithdrawal {
                epoch,
                account: request.account().clone(),
                action: *request.body().action(),
            })
        })
    }

    #[cfg(test)]
    pub(crate) const fn fail_next_payment_commit(&mut self) {
        self.fail_payment_commit = true;
    }

    #[cfg(test)]
    pub(crate) const fn fail_next_payment_write(&mut self) {
        self.fail_payment_write = true;
    }

    #[cfg(test)]
    pub(crate) const fn fail_next_deposit_commit(&mut self) {
        self.fail_deposit_commit = true;
    }

    #[cfg(test)]
    pub(crate) const fn fail_next_cutover_commit(&mut self) {
        self.fail_cutover_commit = true;
    }

    pub(crate) fn rotate_epoch(
        &mut self,
        epoch: u64,
        expected: &EpochPaymentContext,
        successor: &EpochContext<Key, Digest>,
    ) -> Result<()> {
        #[cfg(test)]
        let fail_commit = std::mem::take(&mut self.fail_cutover_commit);
        mutate(&mut self.connection, "epoch cutover", |transaction| {
            ensure!(
                metadata_epoch(transaction)? == epoch,
                "epoch changed during cutover"
            );
            ensure!(
                expected.epoch() == epoch,
                "closing context has the wrong epoch"
            );
            ensure!(
                metadata_payment_context(transaction)?.as_ref() == Some(expected),
                "closing payment anchor is stale"
            );
            let next_epoch = epoch.checked_add(1).context("epoch overflow")?;
            ensure!(
                successor.payment().epoch() == next_epoch
                    && successor.payment().operator() == expected.operator(),
                "successor context does not extend the closing epoch"
            );
            let epoch_sql = sql_u64(epoch, "epoch")?;
            ensure!(
                epoch_has_work(transaction, epoch)?,
                "there is nothing to close"
            );

            let pending = pending_withdrawals(transaction, epoch)?;
            let pending_total = pending.iter().try_fold(0_u64, |total, (_, amount)| {
                total
                    .checked_add(*amount)
                    .context("pending withdrawal total overflow")
            })?;
            let successor_liability = metadata_live_liability(transaction)?
                .checked_sub(pending_total)
                .context("pending withdrawals exceed live liability")?;
            ensure!(
                successor_liability == successor.predecessor_liability(),
                "successor context has the wrong predecessor liability"
            );

            let mut apply_withdrawal = transaction.prepare_cached(
                "UPDATE withdrawals SET applied_amount = ?1
                 WHERE epoch = ?2 AND account = ?3 AND applied_amount IS NULL",
            )?;
            for (mut account, amount) in pending {
                account.current -= amount;
                upsert_account_state(transaction, epoch, &account)?;
                let updated = apply_withdrawal.execute(params![
                    sql_u64(amount, "withdrawal output")?,
                    epoch_sql,
                    account.key.as_ref(),
                ])?;
                ensure!(
                    updated == 1,
                    "pending withdrawal disappeared during cutover"
                );
            }

            ensure!(
                successor.deposit_root() == &DepositBatch::<Key>::empty().root::<Sha256>()?,
                "successor context must start without deposits"
            );

            // Withdrawal outputs and epoch rotation share one commit. Other accounts
            // retain their existing copy-on-write rows.
            transaction.execute(
                "INSERT INTO close_jobs(epoch, status, payment_context)
             VALUES(?1, 'closing', ?2)",
                params![epoch_sql, expected.encode().as_ref()],
            )?;
            transaction.execute(
                "UPDATE operator_meta
             SET epoch = ?1, live_liability = ?2, payment_context = ?3, deposit_events = 0
             WHERE singleton = 1",
                params![
                    sql_u64(next_epoch, "epoch")?,
                    successor_liability.to_be_bytes().as_slice(),
                    successor.payment().encode().as_ref(),
                ],
            )?;
            Ok(())
        })?;
        #[cfg(test)]
        if fail_commit {
            return Err(CommitUnknown::new(
                "epoch cutover",
                rusqlite::Error::ExecuteReturnedResults,
            )
            .into());
        }
        Ok(())
    }

    pub(crate) fn finish_close(
        &mut self,
        result: &SettlementResult,
        genesis_root: StateRoot<Digest>,
    ) -> Result<()> {
        ensure!(
            result.withdrawal_claims.len() == result.withdrawals.requests().len(),
            "finalized withdrawals do not have exact claim evidence"
        );
        let mut withdrawal_total = 0_u64;
        for (position, (request, claim)) in result
            .withdrawals
            .requests()
            .iter()
            .zip(&result.withdrawal_claims)
            .enumerate()
        {
            let position = result
                .context
                .predecessor_logs()
                .payouts
                .operations
                .checked_add(u64::try_from(position)?)
                .context("withdrawal position overflow")?;
            ensure!(
                claim.position() == position,
                "withdrawal claim has the wrong request position"
            );
            let output = claim
                .verify::<Sha256>(&result.roots.withdrawal_outputs)
                .context("verify withdrawal claim")?;
            ensure!(
                output.destination() == request.body().destination(),
                "withdrawal claim has the wrong request destination"
            );
            if let WithdrawalAction::Amount(amount) = request.body().action() {
                ensure!(
                    output.amount() == 0 || output.amount() == amount.get(),
                    "withdrawal claim has the wrong requested amount"
                );
            }
            withdrawal_total = withdrawal_total
                .checked_add(output.amount())
                .context("withdrawal claim total overflow")?;
        }
        ensure!(
            withdrawal_total == result.withdrawal_total,
            "withdrawal claims do not exhaust the finalized reserve"
        );
        mutate(&mut self.connection, "close finalization", |transaction| {
            let epoch = sql_u64(result.context.payment().epoch(), "epoch")?;
            let status: Option<String> = transaction
                .query_row(
                    "SELECT status FROM close_jobs WHERE epoch = ?1",
                    [epoch],
                    |row| row.get(0),
                )
                .optional()?;
            ensure!(
                status.as_deref() == Some("closing"),
                "close job is not pending"
            );
            if close_payment_context(transaction, epoch)? != *result.context.payment() {
                return Err(CloseRejected("close result has the wrong payment context").into());
            }
            if result.context.payment().epoch() == 0 {
                if *result.context.predecessor_root() != genesis_root {
                    return Err(CloseRejected(
                        "genesis close does not extend the configured predecessor root",
                    )
                    .into());
                }
            } else {
                let predecessor =
                    sql_u64(result.context.payment().epoch() - 1, "predecessor epoch")?;
                let roots_len: Option<i64> = transaction
                    .query_row(
                        "SELECT length(roots) FROM settlements WHERE epoch = ?1",
                        [predecessor],
                        |row| row.get(0),
                    )
                    .optional()?;
                let roots_len = roots_len.ok_or(CloseRejected(
                    "predecessor settlement roots are unavailable",
                ))?;
                if roots_len != RootBundle::<Digest>::SIZE as i64 {
                    return Err(CloseRejected("predecessor settlement roots are malformed").into());
                }
                let roots: Vec<u8> = transaction.query_row(
                    "SELECT roots FROM settlements WHERE epoch = ?1",
                    [predecessor],
                    |row| row.get(0),
                )?;
                let roots = RootBundle::<Digest>::decode(roots)
                    .map_err(|_| CloseRejected("predecessor settlement roots are malformed"))?;
                if roots.successor != *result.context.predecessor_root() {
                    return Err(CloseRejected(
                        "close result does not extend its predecessor state root",
                    )
                    .into());
                }
            }
            let (header, roots, certificate) = encoded_artifacts(result);
            transaction.execute(
                "INSERT INTO settlements(
                 epoch, batch_id, header, roots, certificate, rows, dealing_bytes,
                 withdrawal_total, prepare_micros, deal_micros, seal_micros
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    epoch,
                    result.header.batch_id::<Sha256>().digest().as_ref(),
                    header,
                    roots,
                    certificate,
                    sql_usize(result.rows, "row count")?,
                    sql_usize(result.dealing_bytes, "dealing bytes")?,
                    sql_u64(result.withdrawal_total, "withdrawal total")?,
                    sql_u128(result.prepare_micros, "prepare duration")?,
                    sql_u128(result.deal_micros, "deal duration")?,
                    sql_u128(result.seal_micros, "seal duration")?,
                ],
            )?;
            transaction.execute(
                "UPDATE close_jobs
             SET status = 'finalized', error = NULL
             WHERE epoch = ?1",
                [epoch],
            )?;

            Ok(())
        })
    }

    pub(crate) fn fail_close(&mut self, epoch: u64, error: &str) -> Result<()> {
        let mut end = error.len().min(MAX_CLOSE_ERROR_BYTES);
        while !error.is_char_boundary(end) {
            end -= 1;
        }
        let bounded = &error[..end];

        mutate(&mut self.connection, "close fence", |transaction| {
            // A failed close invalidates every pending descendant while preserving finalized ancestors.
            let updated = transaction.execute(
                "UPDATE close_jobs SET status = 'failed', error = ?2
                 WHERE epoch >= ?1 AND status = 'closing'",
                params![sql_u64(epoch, "epoch")?, bounded],
            )?;
            ensure!(updated > 0, "pending close job disappeared while fencing");
            Ok(())
        })
    }

    pub(crate) fn first_failed_epoch(&self) -> Result<Option<u64>> {
        self.connection
            .query_row(
                "SELECT epoch FROM close_jobs WHERE status = 'failed' ORDER BY epoch LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|value| from_sql_u64(value, "failed epoch"))
            .transpose()
    }

    pub(crate) fn latest_finalized_root(&self) -> Result<Option<(u64, StateRoot<Digest>)>> {
        let stored = self
            .connection
            .query_row(
                "SELECT epoch, length(roots), roots
                 FROM settlements ORDER BY epoch DESC LIMIT 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        read_fixed_blob(row, 1, 2, RootBundle::<Digest>::SIZE, "settlement roots")?,
                    ))
                },
            )
            .optional()?;
        let Some((epoch, encoded)) = stored else {
            return Ok(None);
        };
        let roots =
            RootBundle::<Digest>::decode(encoded).context("decode latest settlement roots")?;
        Ok(Some((
            from_sql_u64(epoch, "settlement epoch")?,
            roots.successor,
        )))
    }

    pub(crate) fn closing_epoch_from(&self, first: u64) -> Result<Option<u64>> {
        self.connection
            .query_row(
                "SELECT epoch FROM close_jobs WHERE status = 'closing' AND epoch >= ?1 ORDER BY epoch LIMIT 1",
                [sql_u64(first, "first closing epoch")?],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|value| from_sql_u64(value, "closing epoch"))
            .transpose()
    }

    pub(crate) fn pending_epochs(&self) -> Result<Vec<u64>> {
        let mut query = self.connection.prepare_cached(
            "SELECT epoch FROM close_jobs WHERE status = 'closing' ORDER BY epoch",
        )?;
        query
            .query_map([], |row| row.get::<_, i64>(0))?
            .map(|epoch| from_sql_u64(epoch?, "closing epoch"))
            .collect()
    }

    pub(crate) fn current_entry_count(&self) -> Result<usize> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM accepted_entries WHERE epoch = ?1",
            [sql_u64(self.epoch()?, "epoch")?],
            |row| row.get(0),
        )?;
        usize::try_from(count).context("entry count does not fit usize")
    }

    /// Returns whether the exact epoch already has a durable close job.
    pub(crate) fn has_close_job(&self, epoch: u64) -> Result<bool> {
        self.connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM close_jobs WHERE epoch = ?1)",
                [sql_u64(epoch, "epoch")?],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub(crate) fn close_outcome(&self, epoch: u64) -> Result<StoredCloseOutcome> {
        let epoch = sql_u64(epoch, "epoch")?;
        let status = self
            .connection
            .query_row(
                "SELECT status FROM close_jobs WHERE epoch = ?1",
                [epoch],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .context("close epoch is unknown")?;
        match status.as_str() {
            "closing" => Ok(StoredCloseOutcome::Pending),
            "failed" => {
                let error = self.connection.query_row(
                    "SELECT coalesce(length(CAST(error AS BLOB)), 0), error
                     FROM close_jobs WHERE epoch = ?1",
                    [epoch],
                    |row| {
                        let length = usize::try_from(row.get::<_, i64>(0)?).map_err(|_| {
                            to_sqlite_error(anyhow::anyhow!("invalid close error length"))
                        })?;
                        if length > MAX_CLOSE_ERROR_BYTES {
                            return Err(to_sqlite_error(anyhow::anyhow!(
                                "close error exceeds its persisted byte bound"
                            )));
                        }
                        row.get::<_, String>(1)
                    },
                )?;
                Ok(StoredCloseOutcome::Failed(error))
            }
            "finalized" => {
                let stored = self.connection.query_row(
                    "SELECT length(header), header, rows, dealing_bytes, withdrawal_total,
                            length(certificate), prepare_micros, deal_micros, seal_micros
                     FROM settlements WHERE epoch = ?1",
                    [epoch],
                    |row| {
                        Ok((
                            read_fixed_blob(row, 0, 1, Header::<Digest>::SIZE, "header")?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, i64>(7)?,
                            row.get::<_, i64>(8)?,
                        ))
                    },
                )?;
                let header =
                    Header::<Digest>::decode(stored.0).context("decode finalized close header")?;
                Ok(StoredCloseOutcome::Finished(StoredCloseFinished {
                    header,
                    rows: usize::try_from(from_sql_u64(stored.1, "close row count")?)
                        .context("close row count does not fit usize")?,
                    dealing_bytes: usize::try_from(from_sql_u64(stored.2, "close dealing bytes")?)
                        .context("close dealing bytes does not fit usize")?,
                    withdrawal_total: from_sql_u64(stored.3, "close withdrawal total")?,
                    header_bytes: Header::<Digest>::SIZE,
                    certificate_bytes: usize::try_from(from_sql_u64(
                        stored.4,
                        "certificate byte count",
                    )?)
                    .context("certificate byte count does not fit usize")?,
                    prepare_micros: u128::from(from_sql_u64(stored.5, "prepare duration")?),
                    deal_micros: u128::from(from_sql_u64(stored.6, "deal duration")?),
                    seal_micros: u128::from(from_sql_u64(stored.7, "seal duration")?),
                }))
            }
            _ => anyhow::bail!("close job has an invalid status"),
        }
    }

    pub(crate) fn failed_close(&self) -> Result<Option<String>> {
        let failed = self
            .connection
            .query_row(
                "SELECT epoch, coalesce(length(CAST(error AS BLOB)), 0), error
                 FROM close_jobs WHERE status = 'failed' ORDER BY epoch LIMIT 1",
                [],
                |row| {
                    let length = usize::try_from(row.get::<_, i64>(1)?).map_err(|_| {
                        to_sqlite_error(anyhow::anyhow!("invalid close error length"))
                    })?;
                    if length > MAX_CLOSE_ERROR_BYTES {
                        return Err(to_sqlite_error(anyhow::anyhow!(
                            "close error exceeds its persisted byte bound"
                        )));
                    }
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(2)?))
                },
            )
            .optional()?;
        let Some((epoch, error)) = failed else {
            return Ok(None);
        };
        Ok(Some(format!(
            "epoch {}: {}",
            from_sql_u64(epoch, "failed epoch")?,
            error.as_deref().unwrap_or("unknown close failure")
        )))
    }

    pub(crate) fn status(&self) -> Result<StoreStatus> {
        let epoch = self.epoch()?;
        let epoch_sql = sql_u64(epoch, "epoch")?;
        let (accounts, present_accounts, recent_payments) = self.connection.query_row(
            "SELECT
                     (SELECT count(*) FROM account_identities),
                     (SELECT count(*) FROM account_identities AS identity
                      WHERE (SELECT state.current_balance
                             FROM account_states AS state
                             WHERE state.public_key = identity.public_key
                               AND state.epoch <= ?1
                             ORDER BY state.epoch DESC LIMIT 1) > 0),
                     min((SELECT count(*) FROM accepted_entries WHERE epoch = ?1), 12)",
            [epoch_sql],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        Ok(StoreStatus {
            epoch,
            accounts: from_sql_u64(accounts, "account count")?,
            present_accounts: from_sql_u64(present_accounts, "present account count")?,
            recent_payments: from_sql_u64(recent_payments, "recent payment count")?,
        })
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Result<StoreSnapshot> {
        let epoch = self.epoch()?;
        let current = self.load_current()?;
        let accounts = current
            .accounts
            .into_iter()
            .map(|account| AccountView {
                name: account.name,
                balance: account.current,
                present: account.current > 0,
            })
            .collect();
        let payments = current.entries.into_iter().rev().take(12).collect();
        Ok(StoreSnapshot {
            epoch,
            accounts,
            payments,
        })
    }
}

fn validate_new_batch(
    connection: &Connection,
    context: &EpochPaymentContext,
    authorization: &SendAuthorization<Key, Digest>,
    entries: &[Entry],
) -> Result<Admission> {
    let epoch = metadata_epoch(connection)?;
    ensure!(epoch == context.epoch(), "payment context is stale");
    ensure!(
        metadata_payment_context(connection)?.as_ref() == Some(context),
        "payment anchor is stale"
    );
    let epoch_sql = sql_u64(epoch, "epoch")?;
    let accepted = epoch_entry_count(connection, epoch_sql)?;
    ensure!(
        entries.len() <= MAX_ACCEPTED_PAYMENTS - accepted.min(MAX_ACCEPTED_PAYMENTS),
        "epoch payment capacity is exhausted"
    );

    authorization
        .verify(context)
        .context("verify payer authorization")?;
    let body = authorization.body();
    let payer_key = body.payer().clone();
    let mut payer = eligible_account(connection, epoch, &payer_key)?;

    // The wire carries per-batch deltas: strictly recipient-sorted, unique, positive, and
    // never self-crediting.
    ensure!(!entries.is_empty(), "batched send credits no entries");
    ensure!(
        entries
            .windows(2)
            .all(|pair| pair[0].recipient < pair[1].recipient),
        "batch entries are not strictly recipient-sorted"
    );
    let mut total = 0_u64;
    for entry in entries {
        ensure!(
            entry.recipient != payer_key,
            "self-payments are omitted from this operator"
        );
        ensure!(entry.amount > 0, "batch entry amount must be positive");
        total = checked_sql_add(total, entry.amount, "batch total")?;
    }
    let gross = connection
        .prepare_cached("SELECT COALESCE(SUM(amount), 0) FROM accepted_entries WHERE epoch = ?1")?
        .query_row([epoch_sql], |row| row.get::<_, i64>(0))?;
    checked_sql_add(
        from_sql_u64(gross, "epoch gross payment")?,
        total,
        "epoch gross payment",
    )?;

    // Endpoint discipline: the signed body must extend the payer's accepted state by
    // exactly this batch. The replay probe already ran, so a re-signed accepted sequence
    // is wallet equivocation and fails closed, while a skipped or mismatched endpoint
    // earns the corrective rejection carrying the operator's current view.
    let (prior_seq, prior_debit) = payer_endpoint(connection, epoch_sql, &payer_key)?;
    ensure!(
        body.seq() > prior_seq,
        "batch sequence is already bound to another accepted endpoint"
    );
    let expected_seq = prior_seq
        .checked_add(1)
        .context("batch sequence overflow")?;
    let expected_debit = checked_sql_add(prior_debit, total, "payer cumulative debit")?;
    let current = out_entries_for(connection, epoch_sql, &payer_key)?;
    if body.seq() != expected_seq || body.cumulative_debit() != expected_debit {
        return Ok(Admission::Stale(Endpoint {
            cumulative_debit: prior_debit,
            seq: prior_seq,
            entries: current,
        }));
    }
    ensure!(
        payer.current >= total,
        "payer has insufficient available balance"
    );

    // Merge the deltas into the payer's cumulative vector and require the signed root to
    // commit exactly the merged result. A mismatch means the payer merged from another
    // view of its own vector, which the corrective rejection repairs.
    let mut merged = current.clone();
    for entry in entries {
        match merged.binary_search_by(|edge| edge.recipient.cmp(&entry.recipient)) {
            Ok(position) => {
                merged[position].cumulative = checked_sql_add(
                    merged[position].cumulative,
                    entry.amount,
                    "edge cumulative credit",
                )?;
                merged[position].count =
                    checked_sql_add(merged[position].count, 1, "edge payment count")?;
            }
            Err(position) => merged.insert(
                position,
                OutEntry {
                    recipient: entry.recipient.clone(),
                    cumulative: entry.amount,
                    count: 1,
                },
            ),
        }
    }
    ensure!(
        merged.len() <= MAX_ENTRIES,
        "payer vector capacity is exhausted"
    );
    let vector = OutVector::new(epoch, payer_key, merged).context("assemble merged out vector")?;
    let send_root = vector
        .root::<Sha256, Digest>()
        .context("commit merged out vector")?;
    if send_root != body.send_root() {
        return Ok(Admission::Stale(Endpoint {
            cumulative_debit: prior_debit,
            seq: prior_seq,
            entries: current,
        }));
    }
    payer.current -= total;

    let mut credits = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut receiver = match effective_account(connection, epoch, &entry.recipient)? {
            Some(receiver) => receiver,
            None => StoredAccount {
                name: account_name(connection, &entry.recipient)?,
                key: entry.recipient.clone(),
                predecessor: 0,
                current: 0,
            },
        };
        receiver.current =
            checked_sql_add(receiver.current, entry.amount, "receiver account balance")?;
        credits.push(Credit {
            amount: entry.amount,
            receiver,
        });
    }
    Ok(Admission::Admit(Box::new(Plan {
        epoch,
        total,
        payer,
        vector,
        credits,
    })))
}

fn find_accepted_batch(
    connection: &Connection,
    authorization: &SendAuthorization<Key, Digest>,
    entries: &[Entry],
) -> Result<Option<AcceptedBatch>> {
    // The signed epoch selects one immutable accepted row; body equality also binds its anchor.
    let body = authorization.body();
    let mut statement = connection.prepare_cached(
        "SELECT epoch, length(ack), ack
         FROM acks WHERE payer = ?1 AND seq = ?2 AND epoch = ?3",
    )?;
    let stored_ack = statement
        .query_row(
            params![
                body.payer().as_ref(),
                sql_u64(body.seq(), "batch sequence")?,
                sql_u64(body.epoch(), "batch epoch")?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    read_fixed_blob(row, 1, 2, Ack::SIZE, "acknowledgment")?,
                ))
            },
        )
        .optional()?;
    let Some((epoch, encoded)) = stored_ack else {
        return Ok(None);
    };
    let ack = Ack::decode(encoded).context("decode stored acknowledgment")?;
    if ack.body() != body {
        return Ok(None);
    }
    ensure!(
        ack.payer_signature() == authorization.payer_signature(),
        "retry does not match the accepted payer signature"
    );
    let epoch = from_sql_u64(epoch, "acknowledgment epoch")?;
    let stored = batch_entries(connection, epoch, body.payer(), body.seq())?;

    // An exact replay carries the accepted deltas: the signed root determines them
    // from the payer's prior vector, so a divergent claim is not this batch.
    ensure!(
        stored.len() == entries.len(),
        "authorization is bound to another accepted batch"
    );
    let mut total = 0_u64;
    let mut accepted = Vec::with_capacity(stored.len());
    for (row, entry) in stored.into_iter().zip(entries) {
        ensure!(
            row.recipient == entry.recipient && row.amount == entry.amount,
            "authorization is bound to another accepted batch"
        );
        total = checked_sql_add(total, row.amount, "accepted batch total")?;
        accepted.push(AcceptedEntry {
            recipient: row.recipient,
            cumulative: row.cumulative,
            count: row.count,
            opening: row.opening,
        });
    }
    Ok(Some(AcceptedBatch {
        epoch,
        sequence: body.seq(),
        total,
        acceptance: Acceptance {
            ack,
            entries: accepted,
        },
    }))
}

/// Reads one accepted batch's serving-log rows in acceptance order.
fn batch_entries(
    connection: &Connection,
    epoch: u64,
    payer: &Key,
    seq: u64,
) -> Result<Vec<StoredEntry>> {
    let mut statement = connection.prepare_cached(
        "SELECT id, length(recipient), recipient, amount, cumulative, count,
                length(opening), opening
         FROM accepted_entries
         WHERE epoch = ?1 AND payer = ?2 AND seq = ?3
         ORDER BY id",
    )?;
    let rows = statement
        .query_map(
            params![
                sql_u64(epoch, "epoch")?,
                payer.as_ref(),
                sql_u64(seq, "batch sequence")?
            ],
            |row| {
                let recipient = read_fixed_blob(row, 1, 2, Key::SIZE, "entry recipient")?;
                let opening = read_bounded_blob(row, 6, 7, MAX_OPENING_BYTES, "entry opening")?;
                Ok(StoredEntry {
                    sequence: from_sql_u64(row.get(0)?, "entry cursor").map_err(to_sqlite_error)?,
                    payer: payer.clone(),
                    seq,
                    recipient: Key::decode(recipient).map_err(|error| {
                        to_sqlite_error(anyhow::anyhow!("decode entry recipient: {error}"))
                    })?,
                    amount: from_sql_u64(row.get(3)?, "entry amount").map_err(to_sqlite_error)?,
                    cumulative: from_sql_u64(row.get(4)?, "entry cumulative")
                        .map_err(to_sqlite_error)?,
                    count: from_sql_u64(row.get(5)?, "entry count").map_err(to_sqlite_error)?,
                    opening: Opening::decode(opening).map_err(|error| {
                        to_sqlite_error(anyhow::anyhow!("decode entry opening: {error}"))
                    })?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Reads the last accepted sequence and debit in this epoch, or the empty endpoint.
fn payer_endpoint(connection: &Connection, epoch: i64, payer: &Key) -> Result<(u64, u64)> {
    let endpoint = connection
        .prepare_cached(
            "SELECT seq, cumulative_debit FROM acks
                         WHERE epoch = ?1 AND payer = ?2 ORDER BY seq DESC LIMIT 1",
        )?
        .query_row(params![epoch, payer.as_ref()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    endpoint.map_or(Ok((0, 0)), |(seq, debit)| {
        Ok((
            from_sql_u64(seq, "batch sequence")?,
            from_sql_u64(debit, "epoch debit")?,
        ))
    })
}

/// Reads one payer's live cumulative out vector in canonical recipient order.
fn out_entries_for(connection: &Connection, epoch: i64, payer: &Key) -> Result<Vec<OutEntry<Key>>> {
    let mut statement = connection.prepare_cached(
        "SELECT length(recipient), recipient, cumulative, count
         FROM out_entries WHERE epoch = ?1 AND payer = ?2 ORDER BY recipient",
    )?;
    let rows = statement
        .query_map(params![epoch, payer.as_ref()], |row| {
            let recipient = read_fixed_blob(row, 0, 1, Key::SIZE, "edge recipient")?;
            Ok(OutEntry {
                recipient: Key::decode(recipient).map_err(|error| {
                    to_sqlite_error(anyhow::anyhow!("decode edge recipient: {error}"))
                })?,
                cumulative: from_sql_u64(row.get(2)?, "edge cumulative")
                    .map_err(to_sqlite_error)?,
                count: from_sql_u64(row.get(3)?, "edge count").map_err(to_sqlite_error)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn read_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAccount> {
    let key = read_fixed_blob(row, 1, 2, Key::SIZE, "account key")?;
    Ok(StoredAccount {
        name: row.get(0)?,
        key: Key::decode(key)
            .map_err(|error| to_sqlite_error(anyhow::anyhow!("decode account key: {error}")))?,
        predecessor: from_sql_u64(row.get(3)?, "predecessor balance").map_err(to_sqlite_error)?,
        current: from_sql_u64(row.get(4)?, "current balance").map_err(to_sqlite_error)?,
    })
}

fn account_name(connection: &Connection, account: &Key) -> Result<String> {
    Ok(connection
        .prepare_cached("SELECT name FROM account_identities WHERE public_key = ?1")?
        .query_row([account.as_ref()], |row| row.get(0))
        .optional()?
        .unwrap_or_else(|| "Account".to_string()))
}

fn eligible_account(connection: &Connection, epoch: u64, key: &Key) -> Result<StoredAccount> {
    let account =
        effective_account(connection, epoch, key)?.context("payer is absent in this epoch")?;
    if account.predecessor == 0 {
        let deposit: bool = connection
            .prepare_cached(
                "SELECT EXISTS(SELECT 1 FROM deposits WHERE epoch = ?1 AND account = ?2)",
            )?
            .query_row(params![sql_u64(epoch, "epoch")?, key.as_ref()], |row| {
                row.get(0)
            })?;
        ensure!(deposit, "payer is absent at the epoch boundary");
    }
    Ok(account)
}

fn effective_account(
    connection: &Connection,
    epoch: u64,
    account: &Key,
) -> Result<Option<StoredAccount>> {
    let epoch_sql = sql_u64(epoch, "epoch")?;
    let version = connection
        .prepare_cached(EFFECTIVE_ACCOUNT_SQL)?
        .query_row(params![account.as_ref(), epoch_sql], |row| {
            let key = read_fixed_blob(row, 2, 3, Key::SIZE, "account key")?;
            let predecessor =
                from_sql_u64(row.get(4)?, "predecessor balance").map_err(to_sqlite_error)?;
            let balance = from_sql_u64(row.get(5)?, "current balance").map_err(to_sqlite_error)?;
            Ok((
                from_sql_u64(row.get(0)?, "account state epoch").map_err(to_sqlite_error)?,
                StoredAccount {
                    name: row.get(1)?,
                    key: Key::decode(key).map_err(|error| {
                        to_sqlite_error(anyhow::anyhow!("decode account key: {error}"))
                    })?,
                    predecessor,
                    current: balance,
                },
            ))
        })
        .optional()?;
    let Some((version_epoch, mut account)) = version else {
        return Ok(None);
    };
    if version_epoch < epoch {
        // A zero tail remains visible to its own epoch, then denotes absence at later boundaries.
        if account.current == 0 {
            return Ok(None);
        }
        account.predecessor = account.current;
    }
    Ok(Some(account))
}

fn upsert_account_state(
    transaction: &Transaction<'_>,
    epoch: u64,
    account: &StoredAccount,
) -> Result<()> {
    transaction
        .prepare_cached(
            "INSERT INTO account_identities(public_key, name) VALUES(?1, ?2)
         ON CONFLICT(public_key) DO NOTHING",
        )?
        .execute(params![account.key.as_ref(), account.name])?;
    let name: String = transaction
        .prepare_cached("SELECT name FROM account_identities WHERE public_key = ?1")?
        .query_row([account.key.as_ref()], |row| row.get(0))?;
    ensure!(name == account.name, "account label does not match its key");
    transaction
        .prepare_cached(
            "INSERT INTO account_states(epoch, public_key, predecessor_balance, current_balance)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(epoch, public_key) DO UPDATE SET
                 current_balance = excluded.current_balance",
        )?
        .execute(params![
            sql_u64(epoch, "epoch")?,
            account.key.as_ref(),
            sql_u64(account.predecessor, "predecessor balance")?,
            sql_u64(account.current, "current balance")?,
        ])?;
    Ok(())
}

fn pending_withdrawals(connection: &Connection, epoch: u64) -> Result<Vec<(StoredAccount, u64)>> {
    let epoch_sql = sql_u64(epoch, "epoch")?;
    let encoded = {
        let mut statement = connection.prepare(
            "SELECT length(encoded), encoded
             FROM withdrawals
             WHERE epoch = ?1 AND applied_amount IS NULL
             ORDER BY account",
        )?;
        statement
            .query_map([epoch_sql], |row| {
                let length = usize::try_from(row.get::<_, i64>(0)?).map_err(|_| {
                    to_sqlite_error(anyhow::anyhow!("invalid encoded withdrawal length"))
                })?;
                if length == 0 || length > MAX_WITHDRAWAL_BYTES {
                    return Err(to_sqlite_error(anyhow::anyhow!(
                        "invalid encoded withdrawal length"
                    )));
                }
                row.get::<_, Vec<u8>>(1)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };

    encoded
        .into_iter()
        .map(|encoded| {
            let request = SignedWithdrawal::<Key, Digest>::decode_cfg(
                encoded,
                &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
            )
            .context("decode pending withdrawal")?;
            request
                .verify_signature()
                .context("verify pending withdrawal authorization")?;
            let account = effective_account(connection, epoch, request.account())?
                .context("pending withdrawal account is not represented in its epoch")?;
            let amount = withdrawal_amount(request.body().action(), account.current);
            Ok((account, amount))
        })
        .collect()
}

/// Stages one chain-confirmed deposit event inside an open transaction: the
/// per-event step of [`Store::stage_deposits`].
fn stage_event(
    transaction: &Transaction<'_>,
    staging: &Staging,
    expected: &EpochPaymentContext,
) -> Result<StagedDeposit> {
    let event = &staging.event;
    let amount = event.amount;
    let amount_sql = sql_u64(amount, "deposit amount")?;
    let epoch = metadata_epoch(transaction)?;
    ensure!(epoch == expected.epoch(), "deposit context is stale");
    ensure!(
        metadata_payment_context(transaction)?.as_ref() == Some(expected),
        "deposit anchor is stale"
    );
    let deposit_events = metadata_deposit_events(transaction)?;
    ensure!(
        deposit_events < MAX_DEPOSIT_EVENTS,
        "deposit event capacity is exhausted"
    );

    // Settlement rejects deposits during an active registration. A confirmed event
    // therefore precedes any registration of this boundary and invalidates a pending
    // request with an older deposit root. It remains stageable before read-back.
    let accepted: i64 = transaction.query_row(
        "SELECT count(*) FROM acks WHERE epoch = ?1",
        [sql_u64(epoch, "epoch")?],
        |row| row.get(0),
    )?;
    ensure!(
        accepted == 0,
        "deposits are frozen once the first payment registers the epoch boundary"
    );
    let key = staging.identity.key.clone();
    let account = if let Some(mut account) = effective_account(transaction, epoch, &key)? {
        account.current = checked_sql_add(account.current, amount, "deposit account balance")?;
        account
    } else {
        StoredAccount {
            name: staging.identity.name.to_string(),
            key: key.clone(),
            predecessor: 0,
            current: amount,
        }
    };
    let live_liability = checked_sql_add(
        metadata_live_liability(transaction)?,
        amount,
        "live liability",
    )?;
    let deposit_events = deposit_events + 1;
    transaction.execute(
        "INSERT INTO deposits(epoch, event_id, account, amount)
     VALUES(?1, ?2, ?3, ?4)",
        params![
            sql_u64(epoch, "epoch")?,
            event.id.as_ref(),
            key.as_ref(),
            amount_sql,
        ],
    )?;
    upsert_account_state(transaction, epoch, &account)?;
    transaction.execute(
        "UPDATE operator_meta
     SET payment_context = ?1, live_liability = ?2, deposit_events = ?3
     WHERE singleton = 1",
        params![
            staging.replacement.encode().as_ref(),
            live_liability.to_be_bytes().as_slice(),
            sql_usize(deposit_events, "deposit event count")?,
        ],
    )?;
    Ok(StagedDeposit {
        epoch,
        id: event.id,
        account: event.account.clone(),
        amount,
    })
}

fn withdrawals_frozen(connection: &Connection, epoch: u64) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM registrations WHERE epoch = ?1)
             OR EXISTS(SELECT 1 FROM acks WHERE epoch = ?1)",
            [sql_u64(epoch, "epoch")?],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

/// Resolves a withdrawal against its available epoch tail.
pub(super) const fn withdrawal_amount(action: &WithdrawalAction, tail: u64) -> u64 {
    match action {
        WithdrawalAction::Amount(amount) if amount.get() <= tail => amount.get(),
        WithdrawalAction::Amount(_) => 0,
        WithdrawalAction::Close => tail,
    }
}

fn validate_applied_withdrawal(
    request: &SignedWithdrawal<Key, Digest>,
    applied_amount: Option<i64>,
) -> Result<Option<u64>> {
    let applied_amount = applied_amount
        .map(|amount| from_sql_u64(amount, "applied withdrawal amount"))
        .transpose()?;
    match request.body().action() {
        WithdrawalAction::Amount(amount) => ensure!(
            applied_amount.is_none_or(|applied| applied == 0 || applied == amount.get()),
            "withdrawal has an inconsistent applied amount"
        ),
        WithdrawalAction::Close => {}
    }
    Ok(applied_amount)
}

// A published registration must close even if no receipt followed its preparation.
fn epoch_has_work(connection: &Connection, epoch: u64) -> Result<bool> {
    connection
        .query_row(
            "SELECT
             EXISTS(SELECT 1 FROM acks WHERE epoch = ?1)
             OR EXISTS(SELECT 1 FROM deposits WHERE epoch = ?1)
             OR EXISTS(SELECT 1 FROM withdrawals WHERE epoch = ?1)
             OR EXISTS(SELECT 1 FROM registrations WHERE epoch = ?1)",
            [sql_u64(epoch, "epoch")?],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn metadata_epoch(connection: &Connection) -> Result<u64> {
    let value = connection
        .prepare_cached("SELECT epoch FROM operator_meta WHERE singleton = 1")?
        .query_row([], |row| row.get::<_, i64>(0))?;
    from_sql_u64(value, "epoch")
}

fn metadata_live_liability(connection: &Connection) -> Result<u64> {
    let encoded: Vec<u8> = connection
        .prepare_cached(
            "SELECT length(live_liability), live_liability
         FROM operator_meta WHERE singleton = 1",
        )?
        .query_row([], |row| read_fixed_blob(row, 0, 1, 8, "live liability"))?;
    decode_live_liability(&encoded)
}

fn metadata_deposit_events(connection: &Connection) -> Result<usize> {
    let count = connection
        .prepare_cached("SELECT deposit_events FROM operator_meta WHERE singleton = 1")?
        .query_row([], |row| row.get::<_, i64>(0))?;
    usize::try_from(count).context("deposit event count does not fit usize")
}

fn epoch_entry_count(connection: &Connection, epoch: i64) -> Result<usize> {
    let count = connection
        .prepare_cached("SELECT count(*) FROM accepted_entries WHERE epoch = ?1")?
        .query_row([epoch], |row| row.get::<_, i64>(0))?;
    usize::try_from(count).context("entry count does not fit usize")
}

// SQLite exposes a blob's length without copying its contents. Materialize only after the declared
// fixed-width persistence contract has been checked.
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

fn decode_live_liability(encoded: &[u8]) -> Result<u64> {
    let encoded: [u8; 8] = encoded
        .try_into()
        .context("live liability must contain exactly 8 bytes")?;
    Ok(u64::from_be_bytes(encoded))
}

fn metadata_payment_context(connection: &Connection) -> Result<Option<EpochPaymentContext>> {
    let encoded = connection
        .prepare_cached(
            "SELECT length(payment_context), payment_context
         FROM operator_meta WHERE singleton = 1",
        )?
        .query_row([], |row| {
            if row.get::<_, Option<i64>>(0)?.is_none() {
                return Ok(None);
            }
            read_fixed_blob(row, 0, 1, EpochPaymentContext::SIZE, "payment context").map(Some)
        })?;
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    decode_payment_context(&encoded).map(Some)
}

fn close_payment_context(transaction: &Transaction<'_>, epoch: i64) -> Result<EpochPaymentContext> {
    let encoded: Vec<u8> = transaction.query_row(
        "SELECT length(payment_context), payment_context
         FROM close_jobs WHERE epoch = ?1",
        [epoch],
        |row| read_fixed_blob(row, 0, 1, EpochPaymentContext::SIZE, "payment context"),
    )?;
    decode_payment_context(&encoded)
}

fn stored_result(connection: &Connection, epoch: u64) -> Result<Option<SettlementResult>> {
    let encoded = connection
        .query_row(
            "SELECT length(result), result FROM close_jobs WHERE epoch = ?1 AND result IS NOT NULL",
            [sql_u64(epoch, "close epoch")?],
            |row| read_bounded_blob(row, 0, 1, MAX_RESULT_BYTES, "retained close result"),
        )
        .optional()?;
    encoded
        .map(|bytes| SettlementResult::decode(bytes).context("decode retained close result"))
        .transpose()
}

fn record_result(
    connection: &mut Connection,
    result: &SettlementResult,
    genesis_root: StateRoot<Digest>,
) -> Result<()> {
    let encoded = result.encode();
    ensure!(
        encoded.len() <= MAX_RESULT_BYTES,
        "certified close result exceeds its bound"
    );
    mutate(connection, "certified close retention", |transaction| {
        let epoch = result.context.payment().epoch();
        if let Some(stored) = stored_result(transaction, epoch)? {
            ensure!(
                stored.encode() == encoded,
                "certified close result conflicts with retained result"
            );
            return Ok(());
        }
        let status: String = transaction.query_row(
            "SELECT status FROM close_jobs WHERE epoch = ?1",
            [sql_u64(epoch, "close epoch")?],
            |row| row.get(0),
        )?;
        ensure!(status == "closing", "certified close job is not pending");
        ensure!(
            close_payment_context(transaction, sql_u64(epoch, "close epoch")?)?
                == *result.context.payment(),
            "certified close has the wrong payment context"
        );
        let predecessor = match epoch.checked_sub(1) {
            Some(epoch) => {
                stored_result(transaction, epoch)?
                    .context("certified predecessor result is unavailable")?
                    .roots
                    .successor
            }
            None => genesis_root,
        };
        ensure!(
            result.context.predecessor_root() == &predecessor,
            "certified close does not extend the retained predecessor"
        );
        transaction.execute(
            "UPDATE close_jobs SET result = ?1 WHERE epoch = ?2",
            params![encoded.as_ref(), sql_u64(epoch, "close epoch")?],
        )?;
        Ok(())
    })
}

fn decode_payment_context(encoded: &[u8]) -> Result<EpochPaymentContext> {
    EpochPaymentContext::decode(Copying(encoded)).context("decode stored payment context")
}

fn checked_sql_add(left: u64, right: u64, field: &str) -> Result<u64> {
    let value = left
        .checked_add(right)
        .with_context(|| format!("{field} overflow"))?;
    ensure!(
        value <= SQLITE_U64_MAX,
        "{field} exceeds SQLite-safe u64 domain"
    );
    Ok(value)
}

fn sql_u64(value: u64, field: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{field} exceeds SQLite INTEGER range"))
}

fn sql_u128(value: u128, field: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{field} exceeds SQLite INTEGER range"))
}

fn sql_usize(value: usize, field: &str) -> Result<i64> {
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
    use crate::protocol::{deployment, epoch_context, identities};
    use bytes::Bytes;
    use commonware_clearing::bajillion::{
        boundary::{DepositBatch, DepositRecord, WithdrawalAction, WithdrawalBatch},
        payment::VectorSendBody,
    };
    use commonware_cryptography::{Hasher as _, Signer as _};
    use commonware_cryptography_curve25519::signing::SigningKey;
    use std::num::{NonZeroU64, NonZeroUsize};

    #[test]
    fn non_wal_sqlite_sources_are_rejected() {
        let source = StoreSource::new(Path::new(":memory:")).unwrap();
        let path = source.0.path.clone();
        let mut lock_path = OsString::from(path.as_os_str());
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        assert!(path.exists());
        assert!(lock_path.exists());
        let error = Store::from_connection(
            Connection::open_in_memory().unwrap(),
            source,
            &identities(),
            &crate::protocol::accounts(),
        )
        .err()
        .expect("non-WAL database was accepted");
        assert!(format!("{error:#}").contains("WAL"));
        assert!(!path.exists());
        assert!(!lock_path.exists());
    }

    #[test]
    fn mutation_helper_reports_rollback_failure() {
        let mut connection = Connection::open_in_memory().unwrap();
        let result: Result<()> = mutate(&mut connection, "test mutation", |transaction| {
            transaction.execute_batch("ROLLBACK")?;
            anyhow::bail!("semantic rejection");
        });

        let error = result.unwrap_err();
        assert!(error.downcast_ref::<MutationFailed>().is_some());
        assert!(format!("{error:#}").contains("rollback failed"));
    }

    #[test]
    fn mutation_helper_reports_real_commit_failure() {
        let mut connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE parent(id INTEGER PRIMARY KEY);
                 CREATE TABLE child(
                     parent INTEGER,
                     FOREIGN KEY(parent) REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED
                 );",
            )
            .unwrap();
        let result: Result<()> = mutate(&mut connection, "test mutation", |transaction| {
            transaction.execute("INSERT INTO child(parent) VALUES(1)", [])?;
            Ok(())
        });

        let error = result.unwrap_err();
        assert!(error.downcast_ref::<CommitUnknown>().is_some());
    }

    struct PaymentFixture {
        store: Store,
        context: EpochPaymentContext,
        protocol: Protocol,
        payer: SigningKey,
        receiver: SigningKey,
    }

    impl PaymentFixture {
        fn new() -> Self {
            let identities = identities();
            let mut store = Store::in_memory(&identities).unwrap();
            let context = payment_context(
                u64::try_from(identities.len()).unwrap() * INITIAL_BALANCE,
                DepositBatch::empty(),
            );
            store.ensure_current_context(&context).unwrap();
            Self {
                store,
                context,
                protocol: Protocol::new(NonZeroUsize::MIN).unwrap(),
                payer: SigningKey::from_seed(101),
                receiver: SigningKey::from_seed(102),
            }
        }

        fn reopen(self) -> Self {
            let Self {
                store,
                context,
                protocol,
                payer,
                receiver,
            } = self;
            let source = store.source.clone();
            drop(store);
            let store = Store::from_connection(
                source.connect().unwrap(),
                source,
                &identities(),
                &crate::protocol::accounts(),
            )
            .unwrap();
            Self {
                store,
                context,
                protocol,
                payer,
                receiver,
            }
        }

        /// Signs the `seq`-th unit send to the fixture receiver: the cumulative vector is
        /// one edge whose endpoint equals the sequence.
        fn send(&self, seq: u64) -> (SendAuthorization<Key, Digest>, Vec<Entry>) {
            let recipient = self.receiver.public_key();
            let vector = OutVector::new(
                self.context.epoch(),
                self.payer.public_key(),
                vec![OutEntry {
                    recipient: recipient.clone(),
                    cumulative: seq,
                    count: seq,
                }],
            )
            .unwrap();
            let body = VectorSendBody::new(
                &self.context,
                self.payer.public_key(),
                seq,
                seq,
                vector.root::<Sha256, Digest>().unwrap(),
            );
            (
                SendAuthorization::sign(body, &self.payer),
                vec![Entry {
                    recipient,
                    amount: 1,
                }],
            )
        }
    }

    fn payment_context(
        predecessor_liability: u64,
        deposits: DepositBatch<Key>,
    ) -> EpochPaymentContext {
        epoch_context(
            0,
            &deposits,
            &WithdrawalBatch::empty(),
            predecessor_liability,
        )
        .unwrap()
        .payment()
        .clone()
    }

    fn deposit_context(
        account: Key,
        amount: u64,
        predecessor_liability: u64,
    ) -> EpochPaymentContext {
        let deposits =
            DepositBatch::new(vec![DepositRecord::new(account, amount).unwrap()]).unwrap();
        payment_context(predecessor_liability, deposits)
    }

    fn accepted(result: Result<SendVerdict>) -> AcceptedBatch {
        match result.unwrap() {
            SendVerdict::Accepted(accepted) => *accepted,
            SendVerdict::Stale(_) => panic!("the send earned a corrective rejection"),
        }
    }

    fn rejected_payment(result: Result<SendVerdict>) -> anyhow::Error {
        match result {
            Ok(SendVerdict::Accepted(_)) => panic!("payment was accepted"),
            Ok(SendVerdict::Stale(_)) => panic!("payment earned a corrective rejection"),
            Err(error) => error,
        }
    }

    fn rejected_deposit(result: Result<Vec<StagedDeposit>>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("deposit was staged"),
            Err(error) => error,
        }
    }

    fn assert_payment_domain_rejected(configure: impl FnOnce(&mut PaymentFixture), expected: &str) {
        let mut fixture = PaymentFixture::new();
        configure(&mut fixture);
        let (send, entries) = fixture.send(1);
        let changes = fixture.store.total_changes();

        let error = fixture
            .store
            .payment_requires_epoch_registration(&fixture.context, &send, &entries)
            .unwrap_err();
        assert!(format!("{error:#}").contains(expected));

        let error = rejected_payment(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            send,
            &entries,
        ));
        assert!(format!("{error:#}").contains(expected));
        assert_eq!(fixture.store.total_changes(), changes);
        assert!(fixture.store.load_current().unwrap().entries.is_empty());
    }

    #[test]
    fn epoch_endpoint_resets_at_cutover_and_preserves_old_retry() {
        let mut fixture = PaymentFixture::new();
        let (send, entries) = fixture.send(1);
        let first = accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            send.clone(),
            &entries,
        ));
        let successor = epoch_context(
            1,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            fixture.store.successor_liability().unwrap(),
        )
        .unwrap();
        fixture
            .store
            .rotate_epoch(0, &fixture.context, &successor)
            .unwrap();
        fixture = fixture.reopen();
        let endpoint = fixture
            .store
            .payer_endpoint(&fixture.payer.public_key())
            .unwrap();
        assert_eq!((endpoint.seq, endpoint.cumulative_debit), (0, 0));
        assert!(endpoint.entries.is_empty());
        fixture.context = successor.payment().clone();
        let retry = accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            send,
            &entries,
        ));
        assert_eq!(retry.acceptance, first.acceptance);
        let (send, entries) = fixture.send(1);
        let next = accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            send,
            &entries,
        ));
        assert_eq!(next.epoch, 1);
        assert_eq!(next.acceptance.ack.body().cumulative_debit(), 1);
    }

    #[test]
    fn zero_balance_keeps_epoch_endpoint_for_retry_and_recredit() {
        let mut fixture = PaymentFixture::new();
        let payer = fixture.payer.public_key();
        let receiver = fixture.receiver.public_key();
        let vector = OutVector::new(
            0,
            payer.clone(),
            vec![OutEntry {
                recipient: receiver.clone(),
                cumulative: INITIAL_BALANCE,
                count: 1,
            }],
        )
        .unwrap();
        let send = SendAuthorization::sign(
            VectorSendBody::new(
                &fixture.context,
                payer.clone(),
                1,
                INITIAL_BALANCE,
                vector.root::<Sha256, Digest>().unwrap(),
            ),
            &fixture.payer,
        );
        let entries = vec![Entry {
            recipient: receiver.clone(),
            amount: INITIAL_BALANCE,
        }];
        let first = accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            send.clone(),
            &entries,
        ));
        fixture = fixture.reopen();
        let endpoint = fixture.store.payer_endpoint(&payer).unwrap();
        assert_eq!(
            (endpoint.seq, endpoint.cumulative_debit),
            (1, INITIAL_BALANCE)
        );
        let retry = accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            send,
            &entries,
        ));
        assert_eq!(retry.acceptance, first.acceptance);
        let credit = OutVector::new(
            0,
            receiver.clone(),
            vec![OutEntry {
                recipient: payer.clone(),
                cumulative: 7,
                count: 1,
            }],
        )
        .unwrap();
        let send = SendAuthorization::sign(
            VectorSendBody::new(
                &fixture.context,
                receiver,
                1,
                7,
                credit.root::<Sha256, Digest>().unwrap(),
            ),
            &fixture.receiver,
        );
        accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            send,
            &[Entry {
                recipient: payer.clone(),
                amount: 7,
            }],
        ));
        let vector = OutVector::new(
            0,
            payer.clone(),
            vec![OutEntry {
                recipient: fixture.receiver.public_key(),
                cumulative: INITIAL_BALANCE + 7,
                count: 2,
            }],
        )
        .unwrap();
        let send = SendAuthorization::sign(
            VectorSendBody::new(
                &fixture.context,
                payer.clone(),
                2,
                INITIAL_BALANCE + 7,
                vector.root::<Sha256, Digest>().unwrap(),
            ),
            &fixture.payer,
        );
        accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            send,
            &[Entry {
                recipient: fixture.receiver.public_key(),
                amount: 7,
            }],
        ));
        assert_eq!(fixture.store.payer_endpoint(&payer).unwrap().seq, 2);
        assert_eq!(
            effective_account(&fixture.store.connection, 0, &payer)
                .unwrap()
                .unwrap()
                .current,
            0
        );
    }

    #[test]
    fn invalid_payer_signature_cannot_change_balances_or_endpoints() {
        let mut fixture = PaymentFixture::new();
        let (valid, entries) = fixture.send(1);
        let invalid = SendAuthorization::sign(valid.body().clone(), &fixture.receiver);
        let changes = fixture.store.total_changes();
        assert!(
            fixture
                .store
                .payment_requires_epoch_registration(&fixture.context, &invalid, &entries,)
                .is_err()
        );
        let error = rejected_payment(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            invalid,
            &entries,
        ));
        assert!(format!("{error:#}").contains("verify payer authorization"));
        assert_eq!(fixture.store.total_changes(), changes);
        fixture = fixture.reopen();
        assert_eq!(
            fixture
                .store
                .payer_endpoint(&fixture.payer.public_key())
                .unwrap()
                .seq,
            0
        );
        assert!(fixture.store.load_current().unwrap().acks.is_empty());
        assert_eq!(
            fixture
                .store
                .current_account(&fixture.payer.public_key())
                .unwrap()
                .unwrap()
                .current,
            INITIAL_BALANCE
        );
        let invalid = SendAuthorization::sign(valid.body().clone(), &fixture.receiver);
        accepted(
            fixture
                .store
                .accept_send(&fixture.context, &fixture.protocol, valid, &entries),
        );
        let changes = fixture.store.total_changes();
        let error = rejected_payment(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            invalid,
            &entries,
        ));
        assert!(format!("{error:#}").contains("accepted payer signature"));
        assert_eq!(fixture.store.total_changes(), changes);
    }

    #[test]
    fn payment_capacity_rejects_new_sends_without_breaking_retries() {
        let mut fixture = PaymentFixture::new();
        let (initial_send, initial_entries) = fixture.send(1);
        let initial = accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            initial_send,
            &initial_entries,
        ));
        let opening = initial.acceptance.entries[0].opening.encode();
        let payer = fixture.payer.public_key();
        let receiver = fixture.receiver.public_key();
        let transaction = fixture.store.connection.transaction().unwrap();
        for index in 1..(MAX_ACCEPTED_PAYMENTS - 1) {
            let seq = i64::try_from(index).unwrap() + 1_000;
            transaction
                .execute(
                    "INSERT INTO accepted_entries(
                         epoch, payer, seq, recipient, amount, cumulative, count, opening
                     ) VALUES(0, ?1, ?2, ?3, 1, 1, 1, ?4)",
                    params![payer.as_ref(), seq, receiver.as_ref(), opening.as_ref()],
                )
                .unwrap();
        }
        transaction.commit().unwrap();

        let (retry_send, retry_entries) = fixture.send(2);
        assert!(
            fixture
                .store
                .payment_requires_epoch_registration(&fixture.context, &retry_send, &retry_entries)
                .unwrap()
        );
        let first = accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            retry_send.clone(),
            &retry_entries,
        ));
        let changes = fixture.store.total_changes();
        assert!(
            !fixture
                .store
                .payment_requires_epoch_registration(&fixture.context, &retry_send, &retry_entries)
                .unwrap()
        );
        let replay = accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            retry_send,
            &retry_entries,
        ));
        assert_eq!(replay.sequence, first.sequence);
        assert_eq!(replay.acceptance, first.acceptance);
        assert_eq!(fixture.store.total_changes(), changes);

        let (new_send, new_entries) = fixture.send(3);
        let error = fixture
            .store
            .payment_requires_epoch_registration(&fixture.context, &new_send, &new_entries)
            .unwrap_err();
        assert!(format!("{error:#}").contains("payment capacity"));
        let error = rejected_payment(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            new_send,
            &new_entries,
        ));
        assert!(format!("{error:#}").contains("payment capacity"));
        assert_eq!(fixture.store.total_changes(), changes);
        assert_eq!(
            fixture.store.load_current().unwrap().entries.len(),
            MAX_ACCEPTED_PAYMENTS
        );
    }

    #[test]
    fn stored_rows_reassemble_the_served_receipts() {
        let mut fixture = PaymentFixture::new();
        let third = SigningKey::from_seed(103).public_key();
        let mut edges = vec![
            OutEntry {
                recipient: fixture.receiver.public_key(),
                cumulative: 1,
                count: 1,
            },
            OutEntry {
                recipient: third,
                cumulative: 2,
                count: 1,
            },
        ];
        edges.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
        let mut entries = edges
            .iter()
            .map(|edge| Entry {
                recipient: edge.recipient.clone(),
                amount: edge.cumulative,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by(|left, right| left.recipient.cmp(&right.recipient));
        let vector =
            OutVector::new(fixture.context.epoch(), fixture.payer.public_key(), edges).unwrap();
        let body = VectorSendBody::new(
            &fixture.context,
            fixture.payer.public_key(),
            1,
            3,
            vector.root::<Sha256, Digest>().unwrap(),
        );
        let send = SendAuthorization::sign(body, &fixture.payer);
        let batch = accepted(fixture.store.accept_send(
            &fixture.context,
            &fixture.protocol,
            send,
            &entries,
        ));
        assert_eq!(batch.acceptance.entries.len(), 2);
        batch.acceptance.verify(&fixture.context).unwrap();

        // Each served incoming row must reassemble the exact receipt the acceptance
        // issued, because receivers persist and rely on the served evidence.
        let expected = batch.acceptance.receipts().collect::<Vec<_>>();
        for receipt in &expected {
            let served = fixture
                .store
                .incoming_payments(&receipt.recipient, 0, 10)
                .unwrap();
            assert_eq!(served.len(), 1);
            assert_eq!(&served[0].receipt, receipt);
            served[0]
                .receipt
                .verify::<Sha256>(&fixture.context)
                .unwrap();
        }
    }

    #[test]
    fn payment_validation_rejects_sql_domain_overflow_before_epoch_registration() {
        assert_payment_domain_rejected(
            |fixture| {
                let receiver = fixture.receiver.public_key();
                fixture
                    .store
                    .connection
                    .execute(
                        "UPDATE account_states SET current_balance = ?1 WHERE public_key = ?2",
                        params![i64::MAX, receiver.as_ref()],
                    )
                    .unwrap();
            },
            "receiver account balance",
        );
        assert_payment_domain_rejected(
            |fixture| {
                let payer = fixture.payer.public_key();
                let receiver = fixture.receiver.public_key();
                fixture
                    .store
                    .connection
                    .execute(
                        "INSERT INTO out_entries(
                             epoch, payer, recipient, cumulative, count
                         ) VALUES(0, ?1, ?2, ?3, 1)",
                        params![payer.as_ref(), receiver.as_ref(), i64::MAX],
                    )
                    .unwrap();
            },
            "edge cumulative credit",
        );
    }

    #[test]
    fn deposit_balance_domain_is_checked_before_mutation() {
        let identities = identities();
        let identity = &identities[0];
        let predecessor_liability = u64::try_from(identities.len()).unwrap() * INITIAL_BALANCE;
        let expected = payment_context(predecessor_liability, DepositBatch::empty());
        let replacement = deposit_context(identity.key.clone(), 1, predecessor_liability);
        let mut store = Store::in_memory(&identities).unwrap();
        store.ensure_current_context(&expected).unwrap();
        store
            .connection
            .execute(
                "UPDATE account_states SET current_balance = ?1 WHERE public_key = ?2",
                params![i64::MAX, identity.key.as_ref()],
            )
            .unwrap();
        let event = DepositEvent {
            id: Sha256::hash(&[b"deposit-balance-domain"]),
            account: identity.key.clone(),
            amount: 1,
        };
        let changes = store.total_changes();

        let error = rejected_deposit(store.stage_deposits(
            &expected,
            &[Staging {
                identity: identity.clone(),
                event: event.clone(),
                replacement,
            }],
        ));
        assert!(format!("{error:#}").contains("deposit account balance"));
        assert_eq!(store.total_changes(), changes);
        assert!(store.staged_deposit(&event.id).unwrap().is_none());
        assert_eq!(
            store
                .current_account(&identity.key)
                .unwrap()
                .unwrap()
                .current,
            SQLITE_U64_MAX
        );
    }

    #[test]
    fn deposit_liability_domain_is_checked_before_mutation() {
        let identities = identities();
        let identity = &identities[0];
        let expected = payment_context(SQLITE_U64_MAX, DepositBatch::empty());
        let replacement = deposit_context(identity.key.clone(), 1, SQLITE_U64_MAX);
        let mut store = Store::in_memory(&identities).unwrap();
        store.ensure_current_context(&expected).unwrap();
        let encoded = SQLITE_U64_MAX.to_be_bytes();
        store
            .connection
            .execute(
                "UPDATE operator_meta SET live_liability = ?1 WHERE singleton = 1",
                [encoded.as_slice()],
            )
            .unwrap();
        let event = DepositEvent {
            id: Sha256::hash(&[b"deposit-liability-domain"]),
            account: identity.key.clone(),
            amount: 1,
        };
        let changes = store.total_changes();

        let error = rejected_deposit(store.stage_deposits(
            &expected,
            &[Staging {
                identity: identity.clone(),
                event: event.clone(),
                replacement,
            }],
        ));
        assert!(format!("{error:#}").contains("live liability"));
        assert_eq!(store.total_changes(), changes);
        assert!(store.staged_deposit(&event.id).unwrap().is_none());
        assert_eq!(store.current_liability().unwrap(), SQLITE_U64_MAX);
    }

    #[test]
    fn offset_boundaries_survive_unknown_cutover() {
        let mut fixture = PaymentFixture::new();
        let identity = identities()[0].clone();
        let liability = fixture.store.current_liability().unwrap();
        let request = SignedWithdrawal::sign(
            deployment(),
            Sha256::hash(&[b"carried-credit-root"]),
            Bytes::from_static(b"destination"),
            WithdrawalAction::Amount(NonZeroU64::new(INITIAL_BALANCE).unwrap()),
            100,
            &fixture.payer,
        );
        let withdrawals = WithdrawalBatch::new(vec![request.clone()]).unwrap();
        let registered = fixture
            .protocol
            .registration(0, DepositBatch::empty(), withdrawals.clone(), liability)
            .unwrap();
        fixture
            .store
            .stage_withdrawal(
                &request,
                &fixture.context,
                registered.context.payment(),
                false,
            )
            .unwrap();
        fixture.context = registered.context.payment().clone();
        let event = DepositEvent {
            id: Sha256::hash(&[b"carried-credit-event"]),
            account: identity.key.clone(),
            amount: INITIAL_BALANCE,
        };
        let registered = fixture
            .protocol
            .registration(
                0,
                DepositBatch::new(vec![
                    DepositRecord::new(event.account.clone(), event.amount).unwrap(),
                ])
                .unwrap(),
                withdrawals,
                liability,
            )
            .unwrap();
        fixture
            .store
            .stage_deposits(
                &fixture.context,
                &[Staging {
                    identity,
                    event,
                    replacement: registered.context.payment().clone(),
                }],
            )
            .unwrap();
        fixture.context = registered.context.payment().clone();
        assert_eq!(
            registered.deposits.amount_for(&fixture.payer.public_key()),
            INITIAL_BALANCE
        );
        let successor = fixture
            .protocol
            .registration(
                1,
                DepositBatch::empty(),
                WithdrawalBatch::empty(),
                liability,
            )
            .unwrap();
        let invalid = fixture
            .protocol
            .registration(1, registered.deposits, WithdrawalBatch::empty(), liability)
            .unwrap();
        assert!(
            fixture
                .store
                .rotate_epoch(0, &fixture.context, &invalid.context)
                .is_err()
        );
        assert_eq!(fixture.store.epoch().unwrap(), 0);
        assert_eq!(
            fixture
                .store
                .current_account(&fixture.payer.public_key())
                .unwrap()
                .unwrap()
                .current,
            INITIAL_BALANCE
        );
        fixture.store.fail_next_cutover_commit();
        let error = fixture
            .store
            .rotate_epoch(0, &fixture.context, &successor.context)
            .unwrap_err();
        assert!(error.downcast_ref::<CommitUnknown>().is_some());
        fixture = fixture.reopen();
        assert_eq!(fixture.store.epoch().unwrap(), 1);
        assert_eq!(fixture.store.current_liability().unwrap(), liability);
        assert_eq!(
            fixture
                .store
                .current_account(&fixture.payer.public_key())
                .unwrap()
                .unwrap()
                .current,
            INITIAL_BALANCE
        );
        assert!(
            fixture
                .store
                .rotate_epoch(0, &fixture.context, &successor.context)
                .is_err()
        );
        fixture = fixture.reopen();
        assert_eq!(
            fixture
                .store
                .current_account(&fixture.payer.public_key())
                .unwrap()
                .unwrap()
                .current,
            INITIAL_BALANCE
        );
        let endpoint = fixture
            .store
            .payer_endpoint(&fixture.payer.public_key())
            .unwrap();
        assert_eq!((endpoint.seq, endpoint.cumulative_debit), (0, 0));
    }

    #[test]
    fn queued_amount_resolves_after_credit_without_deducting_reserved_amounts_twice() {
        for (requested, reserved, output) in [
            (INITIAL_BALANCE + 1, None, INITIAL_BALANCE + 1),
            (INITIAL_BALANCE + 2, None, 0),
            (
                INITIAL_BALANCE / 2,
                Some(INITIAL_BALANCE / 2),
                INITIAL_BALANCE / 2,
            ),
        ] {
            let mut fixture = PaymentFixture::new();
            let liability = fixture.store.current_liability().unwrap();
            let account = fixture.receiver.public_key();
            let request = SignedWithdrawal::sign(
                deployment(),
                Sha256::hash(&[b"queued-amount-root"]),
                Bytes::from_static(b"destination"),
                WithdrawalAction::Amount(NonZeroU64::new(requested).unwrap()),
                100,
                &fixture.receiver,
            );
            let registration = fixture
                .protocol
                .registration(
                    0,
                    DepositBatch::empty(),
                    WithdrawalBatch::new(vec![request.clone()]).unwrap(),
                    liability,
                )
                .unwrap();
            fixture
                .store
                .stage_withdrawal(
                    &request,
                    &fixture.context,
                    registration.context.payment(),
                    true,
                )
                .unwrap();
            fixture.context = registration.context.payment().clone();
            fixture = fixture.reopen();
            assert_eq!(
                fixture.store.load_current().unwrap().withdrawals[0].applied_amount,
                reserved
            );
            assert_eq!(
                fixture.store.current_liability().unwrap(),
                liability - reserved.unwrap_or(0)
            );

            let (send, entries) = fixture.send(1);
            accepted(fixture.store.accept_send(
                &fixture.context,
                &fixture.protocol,
                send,
                &entries,
            ));
            assert_eq!(
                fixture.store.load_current().unwrap().withdrawals[0].applied_amount,
                reserved
            );
            assert_eq!(
                fixture.store.successor_liability().unwrap(),
                liability - output
            );
            let successor = epoch_context(
                1,
                &DepositBatch::empty(),
                &WithdrawalBatch::empty(),
                liability - output,
            )
            .unwrap();
            fixture
                .store
                .rotate_epoch(0, &fixture.context, &successor)
                .unwrap();
            fixture = fixture.reopen();
            assert_eq!(
                fixture.store.current_liability().unwrap(),
                liability - output
            );
            let frozen = fixture.store.epoch_reader().load(0).unwrap();
            assert_eq!(frozen.withdrawals[0].applied_amount, Some(output));
            assert_eq!(
                frozen
                    .accounts
                    .iter()
                    .find(|stored| stored.key == account)
                    .unwrap()
                    .current,
                INITIAL_BALANCE + 1 - output,
            );
        }
    }

    #[test]
    fn queued_absent_withdrawal_materializes_zero_without_payer_eligibility() {
        for action in [
            WithdrawalAction::Amount(NonZeroU64::MIN),
            WithdrawalAction::Close,
        ] {
            let mut fixture = PaymentFixture::new();
            let signer = SigningKey::from_seed(999);
            let account = signer.public_key();
            let liability = fixture.store.current_liability().unwrap();
            assert!(fixture.store.current_account(&account).unwrap().is_none());
            let request = SignedWithdrawal::sign(
                deployment(),
                Sha256::hash(&[b"queued-absent-root"]),
                Bytes::from_static(b"destination"),
                action,
                100,
                &signer,
            );
            let registration = fixture
                .protocol
                .registration(
                    0,
                    DepositBatch::empty(),
                    WithdrawalBatch::new(vec![request.clone()]).unwrap(),
                    liability,
                )
                .unwrap();
            fixture
                .store
                .stage_withdrawal(
                    &request,
                    &fixture.context,
                    registration.context.payment(),
                    true,
                )
                .unwrap();
            fixture.context = registration.context.payment().clone();
            fixture = fixture.reopen();
            let data = fixture.store.load_current().unwrap();
            let stored = data
                .accounts
                .iter()
                .find(|stored| stored.key == account)
                .unwrap();
            assert_eq!((stored.predecessor, stored.current), (0, 0));
            assert_eq!(data.withdrawals[0].applied_amount, None);
            assert!(eligible_account(&fixture.store.connection, 0, &account).is_err());
            assert_eq!(fixture.store.successor_liability().unwrap(), liability);
            let successor = epoch_context(
                1,
                &DepositBatch::empty(),
                &WithdrawalBatch::empty(),
                liability,
            )
            .unwrap();
            fixture
                .store
                .rotate_epoch(0, &fixture.context, &successor)
                .unwrap();
            assert_eq!(
                fixture.store.epoch_reader().load(0).unwrap().withdrawals[0].applied_amount,
                Some(0)
            );
            assert!(fixture.store.current_account(&account).unwrap().is_none());
            assert_eq!(fixture.store.current_liability().unwrap(), liability);
        }
    }

    #[test]
    fn fresh_amount_still_requires_live_affordability() {
        let mut fixture = PaymentFixture::new();
        let request = SignedWithdrawal::sign(
            deployment(),
            Sha256::hash(&[b"fresh-amount-root"]),
            Bytes::from_static(b"destination"),
            WithdrawalAction::Amount(NonZeroU64::new(INITIAL_BALANCE + 1).unwrap()),
            100,
            &fixture.receiver,
        );
        let registration = fixture
            .protocol
            .registration(
                0,
                DepositBatch::empty(),
                WithdrawalBatch::new(vec![request.clone()]).unwrap(),
                fixture.store.current_liability().unwrap(),
            )
            .unwrap();
        let error = fixture
            .store
            .stage_withdrawal(
                &request,
                &fixture.context,
                registration.context.payment(),
                false,
            )
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("withdrawal exceeds the live balance"));
    }

    #[test]
    fn amount_outputs_accept_only_deferred_zero_or_the_requested_amount() {
        let signer = SigningKey::from_seed(101);
        let request = SignedWithdrawal::sign(
            deployment(),
            Sha256::hash(&[b"amount-output-root"]),
            Bytes::from_static(b"destination"),
            WithdrawalAction::Amount(NonZeroU64::new(10).unwrap()),
            100,
            &signer,
        );
        for amount in [None, Some(0), Some(10)] {
            assert_eq!(
                validate_applied_withdrawal(&request, amount).unwrap(),
                amount.map(|amount| amount as u64)
            );
        }
        for amount in [-1, 1, 9, 11] {
            assert!(validate_applied_withdrawal(&request, Some(amount)).is_err());
        }
    }

    #[test]
    fn close_staging_is_deferred_and_cutover_persists_the_derived_tail() {
        let identities = identities();
        let account = identities[0].key.clone();
        let signer = SigningKey::from_seed(101);
        assert_eq!(signer.public_key(), account);
        let predecessor_liability = u64::try_from(identities.len()).unwrap() * INITIAL_BALANCE;
        let request = SignedWithdrawal::sign(
            deployment(),
            Sha256::hash(&[b"store-close-safety-root"]),
            Bytes::from_static(b"destination"),
            WithdrawalAction::Close,
            100,
            &signer,
        );
        let expected = epoch_context(
            0,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            predecessor_liability,
        )
        .unwrap();
        let withdrawals = WithdrawalBatch::new(vec![request.clone()]).unwrap();
        let replacement = epoch_context(
            0,
            &DepositBatch::empty(),
            &withdrawals,
            predecessor_liability,
        )
        .unwrap();
        let mut store = Store::in_memory(&identities).unwrap();
        store.ensure_current_context(expected.payment()).unwrap();

        let staged = store
            .stage_withdrawal(&request, expected.payment(), replacement.payment(), false)
            .unwrap();
        assert_eq!(staged.action, WithdrawalAction::Close);
        assert_eq!(store.current_liability().unwrap(), predecessor_liability);
        assert_eq!(
            store.current_account(&account).unwrap().unwrap().current,
            INITIAL_BALANCE
        );
        assert_eq!(
            store.load_current().unwrap().withdrawals[0].applied_amount,
            None
        );
        let mut statement = store
            .connection
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT length(encoded), encoded FROM withdrawals
                 WHERE epoch = 0 AND applied_amount IS NULL ORDER BY account",
            )
            .unwrap();
        let plan = statement
            .query_map([], |row| row.get::<_, String>(3))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|step| step.contains("withdrawals_pending_close_epoch")),
            "{plan:?}"
        );
        drop(statement);

        let successor_liability = predecessor_liability - INITIAL_BALANCE;
        assert_eq!(store.successor_liability().unwrap(), successor_liability);
        let successor = epoch_context(
            1,
            &DepositBatch::empty(),
            &WithdrawalBatch::empty(),
            successor_liability,
        )
        .unwrap();
        store
            .rotate_epoch(0, replacement.payment(), &successor)
            .unwrap();

        assert_eq!(store.epoch().unwrap(), 1);
        assert_eq!(store.current_liability().unwrap(), successor_liability);
        assert!(store.current_account(&account).unwrap().is_none());
        let frozen = store.epoch_reader().load(0).unwrap();
        let account = frozen
            .accounts
            .iter()
            .find(|stored| stored.key == account)
            .unwrap();
        assert_eq!(account.current, 0);
        assert_eq!(frozen.withdrawals[0].applied_amount, Some(INITIAL_BALANCE));
    }
}
