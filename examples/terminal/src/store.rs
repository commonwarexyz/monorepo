//! SQLite ownership boundary for the operator.

use crate::protocol::{
    Acceptance, AccountIdentity, DepositEvent, INITIAL_BALANCE, Key, MAX_ACCEPTED_PAYMENTS,
    MAX_DEPOSIT_EVENTS, MAX_PAYMENT_BYTES, MAX_WITHDRAWALS, Payment, SQLITE_U64_MAX,
    SettlementResult, encoded_artifacts,
};
use anyhow::{Context, Result, ensure};
use commonware_clearing::bajillion::{
    boundary::{DepositBatch, DepositRecord, SignedWithdrawal, WithdrawalAction},
    commitment::VectorRoot,
    payment::{PaymentContext, SignedReceipt, SignedSend},
    settlement::SettlementChain,
    state::AccountState,
    transition::{BatchId, EpochContext, ExternalPayoutClaim, Header, RootBundle, WithdrawalClaim},
};
use commonware_codec::{Decode, DecodeExt, Encode, FixedSize, RangeCfg};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_cryptography_curve25519::signing::SigningKey;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::ErrorKind,
    path::{Path, PathBuf},
    process,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use thiserror::Error;

const SCHEMA_VERSION: i64 = 6;
const MAX_CLAIM_BYTES: usize = 16 * 1024;
const MAX_CLOSE_ERROR_BYTES: usize = 4 * 1024;
pub(crate) const MAX_DESTINATION_BYTES: usize = 256;
const MAX_WITHDRAWAL_BYTES: usize = 512;
const EFFECTIVE_ACCOUNT_SQL: &str = "SELECT state.epoch, identity.name,
            length(state.public_key), state.public_key,
            state.predecessor_balance, state.predecessor_debit, state.predecessor_credit,
            state.predecessor_receipts, state.predecessor_active,
            state.current_balance, state.current_debit,
            state.current_credit, state.current_receipts
     FROM account_states AS state
     JOIN account_identities AS identity USING(public_key)
     WHERE state.public_key = ?1 AND state.epoch <= ?2
     ORDER BY state.epoch DESC LIMIT 1";

// Starting from the identity catalog performs one indexed history probe per account. `CROSS JOIN`
// keeps SQLite from reversing that loop and walking every version accumulated across epochs.
const EPOCH_ACCOUNTS_SQL: &str = "SELECT identity.name,
                    length(state.public_key), state.public_key,
                    CASE WHEN state.epoch = ?1
                         THEN state.predecessor_balance ELSE state.current_balance END,
                    CASE WHEN state.epoch = ?1
                         THEN state.predecessor_debit ELSE state.current_debit END,
                    CASE WHEN state.epoch = ?1
                         THEN state.predecessor_credit ELSE state.current_credit END,
                    CASE WHEN state.epoch = ?1
                         THEN state.predecessor_receipts ELSE state.current_receipts END,
                    CASE WHEN state.epoch = ?1 THEN state.predecessor_active ELSE 1 END,
                    state.current_balance, state.current_debit,
                    state.current_credit, state.current_receipts
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
const PRUNE_FINALIZED_ACCOUNT_STATES_SQL: &str = "DELETE FROM account_states
    WHERE rowid IN (
        SELECT old.rowid
        FROM account_states AS finalized
        JOIN account_states AS old
          ON old.public_key = finalized.public_key
         AND old.epoch < finalized.epoch
        WHERE finalized.epoch = ?1
        UNION ALL
        SELECT finalized.rowid
        FROM account_states AS finalized
        WHERE finalized.epoch = ?1 AND finalized.current_balance = 0
    )";
static NEXT_EPHEMERAL_DATABASE: AtomicU64 = AtomicU64::new(0);

type EpochPaymentContext = PaymentContext<Key, Digest>;

#[derive(Debug, Error)]
#[error("{operation} commit outcome is unknown")]
pub(crate) struct CommitUnknown {
    operation: &'static str,
    #[source]
    source: rusqlite::Error,
}

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

impl CommitUnknown {
    pub(crate) const fn new(operation: &'static str, source: rusqlite::Error) -> Self {
        Self { operation, source }
    }
}

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
    pub(crate) predecessor: AccountState,
    pub(crate) current: AccountState,
}

pub(crate) struct StoredPayment {
    pub(crate) sequence: u64,
    pub(crate) payer_name: String,
    pub(crate) recipient_name: String,
    pub(crate) external: bool,
    pub(crate) tx_id: Digest,
    pub(crate) payment: Payment,
}

pub(crate) struct StoredShardEndpoint {
    pub(crate) recipient: Key,
    pub(crate) shard: u64,
    pub(crate) cumulative_credit: u64,
    pub(crate) receipt_index: u64,
}

pub(crate) struct EpochData {
    pub(crate) epoch: u64,
    pub(crate) accounts: Vec<StoredAccount>,
    pub(crate) payments: Vec<StoredPayment>,
    pub(crate) receive_shards: Vec<StoredShardEndpoint>,
    pub(crate) deposits: Vec<DepositEvent>,
    /// Deposit events parked past this epoch: their aggregates are exactly offset by this
    /// epoch's withdrawals, so the chain defers them whole and this epoch's account state
    /// never credits them. A `carried_from` marks the epoch a row was first staged in,
    /// and repeated exact offsets chain the park forward one epoch at a time, so a row
    /// belongs to the staged set of every epoch from its origin through its landing.
    pub(crate) carried: Vec<DepositEvent>,
    pub(crate) withdrawals: Vec<StoredWithdrawal>,
}

pub(crate) struct StoredWithdrawal {
    pub(crate) request: SignedWithdrawal<Key, Digest>,
    /// `None` keeps a Close tail live before cutover. Cutover atomically records its derived tail.
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
#[derive(Clone)]
pub(crate) struct PaymentView {
    pub(crate) external: bool,
}

#[cfg(test)]
pub(crate) struct StoreSnapshot {
    pub(crate) epoch: u64,
    pub(crate) accounts: Vec<AccountView>,
    pub(crate) payments: Vec<PaymentView>,
    pub(crate) reserved_payout_value: u64,
}

pub(crate) struct StoreStatus {
    pub(crate) epoch: u64,
    pub(crate) accounts: u64,
    pub(crate) present_accounts: u64,
    pub(crate) recent_payments: u64,
    pub(crate) reserved_payout_value: u64,
}

pub(crate) struct StoredCloseFinished {
    pub(crate) header: Header<Digest>,
    pub(crate) rows: usize,
    pub(crate) slices: usize,
    pub(crate) payout_total: u64,
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

/// One accepted send and its position in the payment log.
#[derive(Clone)]
pub(crate) struct AcceptedBatch {
    pub(crate) epoch: u64,
    pub(crate) sequence: u64,
    pub(crate) total: u64,
    pub(crate) acceptance: Acceptance,
}

struct NewPaymentPlan {
    epoch: u64,
    payer: StoredAccount,
    live_liability: Option<u64>,
    total: u64,
    entries: Vec<EntryPlan>,
}

struct EntryPlan {
    recipient_key: Key,
    recipient: Option<StoredAccount>,
    recipient_name: String,
    external: bool,
    previous_credit: u64,
    previous_index: u64,
}

pub(crate) struct StagedDeposit {
    /// Epoch whose boundary includes the event, the successor when the aggregate defers.
    pub(crate) epoch: u64,
    pub(crate) id: Digest,
    pub(crate) account: Key,
    pub(crate) amount: u64,
}

pub(crate) struct StagedWithdrawal {
    pub(crate) epoch: u64,
    pub(crate) account: Key,
    pub(crate) action: WithdrawalAction,
}

pub(crate) struct WithdrawalEvidence {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) account: Key,
    pub(crate) claim: WithdrawalClaim<Digest>,
}

pub(crate) struct ExternalPayoutEvidence {
    pub(crate) batch_id: BatchId<Digest>,
    pub(crate) claim: ExternalPayoutClaim<Key, Digest>,
}

struct StoreLocation {
    path: PathBuf,
    ephemeral: bool,
}

impl Drop for StoreLocation {
    fn drop(&mut self) {
        if !self.ephemeral {
            return;
        }

        // Normal shutdown drops the final shared source after its foreground or worker connection.
        for suffix in ["", "-wal", "-shm"] {
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
        if path == Path::new(":memory:") {
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
                        return Ok(Self(Arc::new(StoreLocation {
                            path,
                            ephemeral: true,
                        })));
                    }
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(error).context("reserve ephemeral SQLite operator path");
                    }
                }
            }
        }
        Ok(Self(Arc::new(StoreLocation {
            path: path.to_owned(),
            ephemeral: false,
        })))
    }

    fn connect(&self) -> Result<Connection> {
        Connection::open(&self.0.path)
            .with_context(|| format!("open SQLite operator at {}", self.0.path.display()))
    }
}

#[derive(Clone)]
pub(crate) struct EpochReader {
    source: StoreSource,
}

impl EpochReader {
    /// Loads a current or still-closing epoch.
    ///
    /// Finalized historical epochs may have had their balance versions pruned.
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
    pub(crate) fn open(path: &Path, identities: &[AccountIdentity]) -> Result<Self> {
        let source = StoreSource::new(path)?;
        let connection = source.connect()?;
        Self::from_connection(connection, source, identities)
    }

    #[cfg(test)]
    pub(crate) fn in_memory(identities: &[AccountIdentity]) -> Result<Self> {
        Self::open(Path::new(":memory:"), identities)
    }

    fn from_connection(
        connection: Connection,
        source: StoreSource,
        identities: &[AccountIdentity],
    ) -> Result<Self> {
        let schema = format!(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA busy_timeout = 5000;

             CREATE TABLE IF NOT EXISTS operator_meta (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 schema_version INTEGER NOT NULL,
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
                 name TEXT NOT NULL UNIQUE
             );

             CREATE TABLE IF NOT EXISTS account_states (
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 public_key BLOB NOT NULL CHECK (length(public_key) = 32),
                 predecessor_balance INTEGER NOT NULL CHECK (predecessor_balance >= 0),
                 predecessor_debit INTEGER NOT NULL CHECK (predecessor_debit >= 0),
                 predecessor_credit INTEGER NOT NULL CHECK (predecessor_credit >= 0),
                 predecessor_receipts INTEGER NOT NULL CHECK (predecessor_receipts >= 0),
                 predecessor_active INTEGER NOT NULL CHECK (predecessor_active IN (0, 1)),
                 current_balance INTEGER NOT NULL CHECK (current_balance >= 0),
                 current_debit INTEGER NOT NULL CHECK (current_debit >= 0),
                 current_credit INTEGER NOT NULL CHECK (current_credit >= 0),
                 current_receipts INTEGER NOT NULL CHECK (current_receipts >= 0),
                 PRIMARY KEY(epoch, public_key),
                 FOREIGN KEY(public_key) REFERENCES account_identities(public_key)
             );
             CREATE INDEX IF NOT EXISTS account_states_key_epoch
                 ON account_states(public_key, epoch DESC);

             CREATE TABLE IF NOT EXISTS payments (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 payer_name TEXT NOT NULL,
                 recipient BLOB NOT NULL CHECK (length(recipient) = 32),
                 recipient_name TEXT NOT NULL,
                 external INTEGER NOT NULL CHECK (external IN (0, 1)),
                 tx_id BLOB NOT NULL CHECK (length(tx_id) = 32),
                 encoded BLOB NOT NULL CHECK (
                     length(encoded) > 0 AND length(encoded) <= {max_payment_bytes}
                 ),
                 UNIQUE(tx_id, recipient)
             );
             CREATE INDEX IF NOT EXISTS payments_epoch_sequence
                 ON payments(epoch, sequence);

             CREATE TABLE IF NOT EXISTS receive_shards (
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 recipient BLOB NOT NULL CHECK (length(recipient) = 32),
                 shard INTEGER NOT NULL CHECK (shard >= 0),
                 cumulative_credit INTEGER NOT NULL CHECK (cumulative_credit >= 0),
                 receipt_index INTEGER NOT NULL CHECK (receipt_index >= 0),
                 PRIMARY KEY(epoch, recipient, shard)
             );

             CREATE TABLE IF NOT EXISTS deposits (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 event_id BLOB NOT NULL UNIQUE CHECK (length(event_id) = 32),
                 account BLOB NOT NULL CHECK (length(account) = 32),
                 amount INTEGER NOT NULL CHECK (amount > 0),
                 carried_from INTEGER CHECK (
                     carried_from IS NULL
                     OR (carried_from >= 0 AND carried_from < epoch)
                 )
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

             CREATE TABLE IF NOT EXISTS close_jobs (
                 epoch INTEGER PRIMARY KEY CHECK (epoch >= 0),
                 status TEXT NOT NULL CHECK (status IN ('closing', 'finalized', 'failed')),
                 payment_context BLOB NOT NULL CHECK (length(payment_context) = {context_size}),
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
                 slices INTEGER NOT NULL CHECK (slices >= 0),
                 dealing_slices INTEGER NOT NULL CHECK (dealing_slices >= 0),
                 withdrawal_total INTEGER NOT NULL CHECK (withdrawal_total >= 0),
                 payout_total INTEGER NOT NULL CHECK (payout_total >= 0),
                 prepare_micros INTEGER NOT NULL CHECK (prepare_micros >= 0),
                 deal_micros INTEGER NOT NULL CHECK (deal_micros >= 0),
                 seal_micros INTEGER NOT NULL CHECK (seal_micros >= 0)
             );

             CREATE TABLE IF NOT EXISTS payout_claims (
                 epoch INTEGER NOT NULL CHECK (epoch >= 0),
                 position INTEGER NOT NULL CHECK (position >= 0),
                 recipient BLOB NOT NULL CHECK (length(recipient) = 32),
                 amount INTEGER NOT NULL CHECK (amount > 0),
                 proof BLOB NOT NULL,
                 claimed INTEGER NOT NULL DEFAULT 0 CHECK (claimed IN (0, 1)),
                 PRIMARY KEY(epoch, position)
             );

             CREATE TABLE IF NOT EXISTS withdrawal_claims (
                 batch_id BLOB NOT NULL CHECK (length(batch_id) = 32),
                 position INTEGER NOT NULL CHECK (
                     position BETWEEN 0 AND 4294967295
                 ),
                 account BLOB NOT NULL CHECK (length(account) = 32),
                 proof BLOB NOT NULL CHECK (
                     length(proof) > 0 AND length(proof) <= {max_claim_bytes}
                 ),
                 claimed INTEGER NOT NULL DEFAULT 0 CHECK (claimed IN (0, 1)),
                 PRIMARY KEY(batch_id, position),
                 FOREIGN KEY(batch_id) REFERENCES settlements(batch_id)
             );
             CREATE INDEX IF NOT EXISTS withdrawal_claims_account_unclaimed
                 ON withdrawal_claims(account) WHERE claimed = 0;",
            max_payment_bytes = MAX_PAYMENT_BYTES,
            context_size = EpochPaymentContext::SIZE,
            max_deposit_events = MAX_DEPOSIT_EVENTS,
            max_close_error_bytes = MAX_CLOSE_ERROR_BYTES,
            max_withdrawal_bytes = MAX_WITHDRAWAL_BYTES,
            max_claim_bytes = MAX_CLAIM_BYTES,
        );
        connection.execute_batch(&schema)?;
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
        match metadata {
            Some((version, _)) => ensure!(
                version == SCHEMA_VERSION,
                "unsupported clearing operator schema version {version}"
            ),
            None => {
                let transaction = connection.unchecked_transaction()?;
                let initial_liability = u64::try_from(identities.len())
                    .context("wallet count does not fit u64")?
                    .checked_mul(INITIAL_BALANCE)
                    .context("initial liability overflow")?;
                transaction.execute(
                    "INSERT INTO operator_meta(
                         singleton, schema_version, epoch, live_liability, deposit_events
                     ) VALUES(1, ?1, 0, ?2, 0)",
                    params![SCHEMA_VERSION, initial_liability.to_be_bytes().as_slice()],
                )?;
                for identity in identities {
                    let key = identity.key.clone();
                    let balance = sql_u64(INITIAL_BALANCE, "initial balance")?;
                    transaction.execute(
                        "INSERT INTO account_identities(public_key, name) VALUES(?1, ?2)",
                        params![key.as_ref(), identity.name],
                    )?;
                    transaction.execute(
                        "INSERT INTO account_states(
                             epoch, public_key,
                             predecessor_balance, predecessor_debit, predecessor_credit,
                             predecessor_receipts, predecessor_active,
                             current_balance, current_debit, current_credit, current_receipts
                         ) VALUES(0, ?1, ?2, 0, 0, 0, 1, ?2, 0, 0, 0)",
                        params![key.as_ref(), balance],
                    )?;
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

    /// Returns the cached liability of the current account state without constructing its BMT.
    pub(crate) fn current_liability(&self) -> Result<u64> {
        metadata_live_liability(&self.connection)
    }

    /// Projects the successor liability by sweeping only accounts with a pending Close.
    pub(crate) fn successor_liability(&self) -> Result<u64> {
        let epoch = self.epoch()?;
        let close_total = pending_close_accounts(&self.connection, epoch)?
            .into_iter()
            .try_fold(0_u64, |total, (_, account)| {
                total
                    .checked_add(account.current.balance)
                    .context("Close tail total overflow")
            })?;
        self.current_liability()?
            .checked_sub(close_total)
            .context("Close tails exceed live liability")
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
                    account: Key::decode(account.as_slice())
                        .context("decode staged deposit account")?,
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
                    encoded.as_slice(),
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
                    encoded.as_slice(),
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

    #[cfg(test)]
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
                    let payment_count: i64 = transaction.query_row(
                        "SELECT count(*) FROM payments WHERE epoch = ?1",
                        [sql_u64(expected.epoch(), "epoch")?],
                        |row| row.get(0),
                    )?;
                    ensure!(
                        payment_count == 0,
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

    #[cfg(test)]
    pub(crate) fn current_account(&self, account: &Key) -> Result<Option<StoredAccount>> {
        effective_account(&self.connection, self.epoch()?, account)
    }

    pub(crate) fn has_current_work(&self) -> Result<bool> {
        let epoch = sql_u64(self.epoch()?, "epoch")?;
        self.connection
            .query_row(
                "SELECT
                     EXISTS(SELECT 1 FROM payments WHERE epoch = ?1)
                     OR EXISTS(SELECT 1 FROM deposits WHERE epoch = ?1)
                     OR EXISTS(SELECT 1 FROM withdrawals WHERE epoch = ?1)",
                [epoch],
                |row| row.get::<_, bool>(0),
            )
            .map_err(Into::into)
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

        let payment_count = epoch_payment_count(connection, epoch_sql)?;
        ensure!(
            payment_count <= MAX_ACCEPTED_PAYMENTS,
            "epoch payment count exceeds its configured bound"
        );
        let mut statement = connection.prepare(
            "SELECT sequence, payer_name, recipient_name, external,
                    length(tx_id), tx_id, length(encoded), encoded
             FROM payments WHERE epoch = ?1 ORDER BY sequence",
        )?;
        let payments = statement
            .query_map([epoch_sql], |row| {
                let sequence =
                    from_sql_u64(row.get(0)?, "payment sequence").map_err(to_sqlite_error)?;
                let tx_id = read_fixed_blob(row, 4, 5, Digest::SIZE, "transaction id")?;
                let tx_id = Digest::decode(tx_id.as_slice()).map_err(|error| {
                    to_sqlite_error(anyhow::anyhow!("decode stored transaction id: {error}"))
                })?;

                // Check SQLite's scalar length before asking rusqlite to materialize the blob.
                let encoded = read_bounded_blob(row, 6, 7, MAX_PAYMENT_BYTES, "encoded payment")?;
                let payment = Payment::decode(encoded.as_slice()).map_err(|error| {
                    to_sqlite_error(anyhow::anyhow!("decode stored payment: {error}"))
                })?;
                Ok(StoredPayment {
                    sequence,
                    payer_name: row.get(1)?,
                    recipient_name: row.get(2)?,
                    external: row.get::<_, i64>(3)? != 0,
                    tx_id,
                    payment,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut statement = connection.prepare(
            "SELECT length(recipient), recipient, shard, cumulative_credit, receipt_index
             FROM receive_shards WHERE epoch = ?1 ORDER BY recipient, shard",
        )?;
        let receive_shards = statement
            .query_map([epoch_sql], |row| {
                let recipient = read_fixed_blob(row, 0, 1, Key::SIZE, "shard recipient")?;
                Ok(StoredShardEndpoint {
                    recipient: Key::decode(recipient.as_slice()).map_err(|error| {
                        to_sqlite_error(anyhow::anyhow!("decode receive-shard recipient: {error}"))
                    })?,
                    shard: from_sql_u64(row.get(2)?, "receive shard").map_err(to_sqlite_error)?,
                    cumulative_credit: from_sql_u64(row.get(3)?, "shard credit")
                        .map_err(to_sqlite_error)?,
                    receipt_index: from_sql_u64(row.get(4)?, "receipt index")
                        .map_err(to_sqlite_error)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let read_deposits = |filter: &str| -> Result<Vec<DepositEvent>> {
            let count = connection.query_row(
                &format!("SELECT count(*) FROM deposits WHERE {filter}"),
                [epoch_sql],
                |row| row.get::<_, i64>(0),
            )?;
            let count = usize::try_from(count).context("invalid deposit event count")?;
            ensure!(
                count <= MAX_DEPOSIT_EVENTS,
                "epoch deposit event count exceeds its configured bound"
            );
            let mut statement = connection.prepare(&format!(
                "SELECT length(event_id), event_id, length(account), account, amount
                 FROM deposits WHERE {filter} ORDER BY sequence"
            ))?;
            let deposits = statement
                .query_map([epoch_sql], |row| {
                    let event_id = read_fixed_blob(row, 0, 1, Digest::SIZE, "deposit id")?;
                    let account = read_fixed_blob(row, 2, 3, Key::SIZE, "deposit account")?;
                    Ok(DepositEvent {
                        id: Digest::decode(event_id.as_slice()).map_err(|error| {
                            to_sqlite_error(anyhow::anyhow!("decode deposit id: {error}"))
                        })?,
                        account: Key::decode(account.as_slice()).map_err(|error| {
                            to_sqlite_error(anyhow::anyhow!("decode deposit account: {error}"))
                        })?,
                        amount: from_sql_u64(row.get(4)?, "deposit amount")
                            .map_err(to_sqlite_error)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(deposits)
        };
        let deposits = read_deposits("epoch = ?1")?;

        // A parked row's staged history is the contiguous epochs from its origin through
        // its landing, so this epoch's parked set stays addressable after cutover credits
        // it onward, and even after a later epoch parks it again.
        let carried = read_deposits("carried_from <= ?1 AND epoch > ?1")?;
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
                    encoded.as_slice(),
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
        Ok(EpochData {
            epoch,
            accounts,
            payments,
            receive_shards,
            deposits,
            carried,
            withdrawals,
        })
    }

    pub(crate) fn accept_send(
        &mut self,
        context: &EpochPaymentContext,
        operator: &SigningKey,
        send: SignedSend<Key, Digest>,
        shard: u64,
    ) -> Result<AcceptedBatch> {
        #[cfg(test)]
        let fail_commit = std::mem::take(&mut self.fail_payment_commit);
        #[cfg(test)]
        let fail_write = std::mem::take(&mut self.fail_payment_write);
        let accepted = mutate(&mut self.connection, "payment", |transaction| {
            if let Some(accepted) = find_accepted_batch(transaction, &send)? {
                return Ok(accepted);
            }
            let plan = validate_new_payment(transaction, context, &send, shard)?;
            let epoch = plan.epoch;
            let epoch_sql = sql_u64(epoch, "epoch")?;
            let tx_id = send.tx_id::<Sha256>();
            let shard_sql = sql_u64(shard, "receive shard")?;

            upsert_account_state(transaction, epoch, &plan.payer)?;
            if let Some(live_liability) = plan.live_liability {
                let updated = transaction.execute(
                    "UPDATE operator_meta SET live_liability = ?1 WHERE singleton = 1",
                    [live_liability.to_be_bytes().as_slice()],
                )?;
                ensure!(updated == 1, "operator metadata disappeared during payment");
            }

            // One batch acknowledgment issues every receipt against one verified send: the
            // plan verified the payer authorization above, and the operator signs its own
            // receipts here, so no per-entry send verification remains.
            let starts = plan
                .entries
                .iter()
                .map(|entry| (shard, entry.previous_credit, entry.previous_index))
                .collect::<Vec<_>>();
            let issued =
                SignedReceipt::issue_next_batch::<Sha256, _>(context, &send, &starts, operator)
                    .context("issue operator receipts")?;

            // Every entry lands in this one transaction: the payer debit, each recipient credit,
            // each shard advance, and each linked payment row commit or roll back together.
            let mut sequence = None;
            let mut receipts = Vec::with_capacity(plan.entries.len());
            for (entry, receipt) in plan.entries.iter().zip(issued) {
                // The operator issued this receipt for this exact send, so the pair links
                // by construction.
                let payment = Payment::from_parts_unchecked(send.clone(), receipt);
                if let Some(recipient) = entry.recipient.as_ref() {
                    upsert_account_state(transaction, epoch, recipient)?;
                }
                transaction.execute(
                    "INSERT INTO receive_shards(
                     epoch, recipient, shard, cumulative_credit, receipt_index
                 ) VALUES(?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(epoch, recipient, shard) DO UPDATE SET
                     cumulative_credit = excluded.cumulative_credit,
                     receipt_index = excluded.receipt_index",
                    params![
                        epoch_sql,
                        entry.recipient_key.as_ref(),
                        shard_sql,
                        sql_u64(
                            payment.receipt().body().cumulative_shard_credit(),
                            "shard credit",
                        )?,
                        sql_u64(payment.receipt().body().index(), "receipt index")?,
                    ],
                )?;
                transaction.execute(
                    "INSERT INTO payments(
                     epoch, payer_name, recipient, recipient_name, external, tx_id, encoded
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        epoch_sql,
                        plan.payer.name,
                        entry.recipient_key.as_ref(),
                        entry.recipient_name,
                        i64::from(entry.external),
                        tx_id.digest().as_ref(),
                        payment.encode().as_ref(),
                    ],
                )?;
                if sequence.is_none() {
                    sequence = Some(from_sql_u64(
                        transaction.last_insert_rowid(),
                        "payment sequence",
                    )?);
                }
                receipts.push(payment.into_parts().1);
            }
            #[cfg(test)]
            if fail_write {
                return Err(rusqlite::Error::ExecuteReturnedResults.into());
            }
            Ok(AcceptedBatch {
                epoch,
                sequence: sequence.context("accepted batch has no entries")?,
                total: plan.total,
                acceptance: Acceptance { send, receipts },
            })
        })?;
        #[cfg(test)]
        if fail_commit {
            return Err(
                CommitUnknown::new("payment", rusqlite::Error::ExecuteReturnedResults).into(),
            );
        }
        Ok(accepted)
    }

    pub(crate) fn payment_requires_epoch_registration(
        &self,
        context: &EpochPaymentContext,
        send: &SignedSend<Key, Digest>,
        shard: u64,
    ) -> Result<bool> {
        if find_accepted_batch(&self.connection, send)?.is_some() {
            return Ok(false);
        }
        validate_new_payment(&self.connection, context, send, shard)?;
        Ok(true)
    }

    /// Reads any committed batch for one send by transaction id across every epoch.
    ///
    /// This is a durable, side-effect-free read of committed payment rows. It authoritatively
    /// answers whether a specific send committed, which is exactly what resolves a client's
    /// commitment uncertainty independent of whether the operator is fenced from admitting new
    /// state.
    pub(crate) fn accepted_batch(
        &self,
        send: &SignedSend<Key, Digest>,
    ) -> Result<Option<AcceptedBatch>> {
        find_accepted_batch(&self.connection, send)
    }

    pub(crate) fn stage_deposit(
        &mut self,
        identity: &AccountIdentity,
        event: &DepositEvent,
        expected: &EpochPaymentContext,
        replacement: &EpochPaymentContext,
    ) -> Result<StagedDeposit> {
        #[cfg(test)]
        let fail_commit = std::mem::take(&mut self.fail_deposit_commit);
        ensure!(event.amount > 0, "deposit amount must be positive");
        ensure!(
            event.account == identity.key,
            "deposit account does not match its identity"
        );
        ensure!(
            expected.epoch() == replacement.epoch()
                && expected.operator() == replacement.operator(),
            "deposit context changed immutable epoch identity"
        );
        let amount = event.amount;
        let amount_sql = sql_u64(amount, "deposit amount")?;
        let staged = mutate(&mut self.connection, "deposit", |transaction| {
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
            let payment_count: i64 = transaction.query_row(
                "SELECT count(*) FROM payments WHERE epoch = ?1",
                [sql_u64(epoch, "epoch")?],
                |row| row.get(0),
            )?;
            ensure!(
                payment_count == 0,
                "deposits are frozen after the first payment in an epoch"
            );
            let key = identity.key.clone();
            let staged = staged_account_deposits(transaction, epoch, &key)?;
            let aggregate = checked_sql_add(
                checked_sql_add(
                    staged.included_total,
                    staged.parked_total,
                    "account deposit total",
                )?,
                amount,
                "account deposit total",
            )?;

            // The chain's boundary rule decides where this event lands: an aggregate
            // exactly offset by the account's staged withdrawal defers whole to the
            // successor epoch, and a grown aggregate that no longer offsets returns.
            // Storage stays normalized so an epoch's rows and account state carry exactly
            // its boundary-included deposits.
            let defers = deposit_defers(transaction, epoch, &key, aggregate)?;
            let successor = epoch.checked_add(1).context("epoch overflow")?;
            let account = effective_account(transaction, epoch, &key)?;
            let (landing_epoch, account, live_liability, deposit_events) = if defers {
                // Parking preserves a row's origin so every epoch of its staged history
                // stays addressable, and a carried-in row parks onward like a fresh one.
                let parked = transaction.execute(
                    "UPDATE deposits
                     SET epoch = ?1, carried_from = COALESCE(carried_from, ?2)
                     WHERE account = ?3 AND epoch = ?2",
                    params![
                        sql_u64(successor, "epoch")?,
                        sql_u64(epoch, "epoch")?,
                        key.as_ref(),
                    ],
                )?;
                ensure!(
                    parked == staged.included_events,
                    "staged deposit rows changed during deferral"
                );
                let mut account = account.context("deferring account is not in the live state")?;
                account.current.balance = account
                    .current
                    .balance
                    .checked_sub(staged.included_total)
                    .context("deferred aggregate exceeds the live balance")?;
                let live_liability = metadata_live_liability(transaction)?
                    .checked_sub(staged.included_total)
                    .context("deferred aggregate exceeds live liability")?;
                let deposit_events = deposit_events
                    .checked_sub(staged.included_events)
                    .context("deferred deposit event count underflow")?;
                (successor, account, live_liability, deposit_events)
            } else {
                let returned = if staged.parked_total > 0 {
                    // The grown aggregate no longer offsets the withdrawal exactly, so
                    // the parked rows return to this epoch's boundary with their credit.
                    // A row this epoch first staged loses its mark, and a carried-in row
                    // keeps its origin.
                    let unparked = transaction.execute(
                        "UPDATE deposits
                         SET epoch = ?1,
                             carried_from = CASE
                                 WHEN carried_from = ?1 THEN NULL ELSE carried_from
                             END
                         WHERE account = ?2 AND carried_from <= ?1 AND epoch > ?1",
                        params![sql_u64(epoch, "epoch")?, key.as_ref()],
                    )?;
                    ensure!(
                        unparked == staged.parked_events,
                        "parked deposit rows changed during return"
                    );
                    staged.parked_total
                } else {
                    0
                };
                let credit = checked_sql_add(returned, amount, "deposit credit")?;
                let account = if let Some(mut account) = account {
                    account.current.balance = checked_sql_add(
                        account.current.balance,
                        credit,
                        "deposit account balance",
                    )?;
                    account
                } else {
                    StoredAccount {
                        name: identity.name.to_string(),
                        key: key.clone(),
                        predecessor: AccountState::default(),
                        current: AccountState {
                            balance: credit,
                            active: true,
                            ..AccountState::default()
                        },
                    }
                };
                let live_liability = checked_sql_add(
                    metadata_live_liability(transaction)?,
                    credit,
                    "live liability",
                )?;
                let deposit_events = deposit_events
                    .checked_add(staged.parked_events)
                    .and_then(|count| count.checked_add(1))
                    .context("deposit event count overflow")?;
                ensure!(
                    deposit_events <= MAX_DEPOSIT_EVENTS,
                    "deposit event capacity is exhausted"
                );
                (epoch, account, live_liability, deposit_events)
            };
            transaction.execute(
                "INSERT INTO deposits(epoch, event_id, account, amount, carried_from)
             VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    sql_u64(landing_epoch, "epoch")?,
                    event.id.as_ref(),
                    key.as_ref(),
                    amount_sql,
                    defers.then(|| sql_u64(epoch, "epoch")).transpose()?,
                ],
            )?;
            upsert_account_state(transaction, epoch, &account)?;
            transaction.execute(
                "UPDATE operator_meta
             SET payment_context = ?1, live_liability = ?2, deposit_events = ?3
             WHERE singleton = 1",
                params![
                    replacement.encode().as_ref(),
                    live_liability.to_be_bytes().as_slice(),
                    sql_usize(deposit_events, "deposit event count")?,
                ],
            )?;
            Ok(StagedDeposit {
                epoch: landing_epoch,
                id: event.id,
                account: event.account.clone(),
                amount,
            })
        })?;
        #[cfg(test)]
        if fail_commit {
            return Err(
                CommitUnknown::new("deposit", rusqlite::Error::ExecuteReturnedResults).into(),
            );
        }
        Ok(staged)
    }

    pub(crate) fn stage_withdrawal(
        &mut self,
        request: &SignedWithdrawal<Key, Digest>,
        expected: &EpochPaymentContext,
        replacement: &EpochPaymentContext,
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
            let payment_count: i64 = transaction.query_row(
                "SELECT count(*) FROM payments WHERE epoch = ?1",
                [sql_u64(epoch, "epoch")?],
                |row| row.get(0),
            )?;
            ensure!(
                payment_count == 0,
                "withdrawals are frozen after the first payment in an epoch"
            );

            let mut account = effective_account(transaction, epoch, request.account())?
                .context("withdrawing account is not in the live state")?;
            let mut deferred_total = 0_u64;
            let mut deferred_events = 0_usize;
            let applied_amount = match request.body().action() {
                WithdrawalAction::Amount(amount) => {
                    let amount = amount.get();
                    let staged = staged_account_deposits(transaction, epoch, request.account())?;

                    // The operator may never refuse or fail to represent any shape a
                    // permissionless settlement path can force into the registration: the
                    // chain's queue accepts an exact offset of a carried-in aggregate and
                    // defers it again, so intake must park it again, not refuse it.
                    if SettlementChain::<Sha256, Key>::withdrawal_defers_deposit(
                        request,
                        staged.included_total,
                    ) {
                        // The exact offset defers now: park the aggregate for the
                        // successor epoch and remove its credit, mirroring the chain's
                        // boundary rule. Parking preserves a row's origin so every epoch
                        // of its staged history stays addressable.
                        let successor = epoch.checked_add(1).context("epoch overflow")?;
                        let parked = transaction.execute(
                            "UPDATE deposits
                             SET epoch = ?1, carried_from = COALESCE(carried_from, ?2)
                             WHERE account = ?3 AND epoch = ?2",
                            params![
                                sql_u64(successor, "epoch")?,
                                sql_u64(epoch, "epoch")?,
                                request.account().as_ref(),
                            ],
                        )?;
                        ensure!(
                            parked == staged.included_events,
                            "staged deposit rows changed during deferral"
                        );
                        account.current.balance = account
                            .current
                            .balance
                            .checked_sub(staged.included_total)
                            .context("deferred aggregate exceeds the live balance")?;
                        deferred_total = staged.included_total;
                        deferred_events = staged.included_events;
                    } else if amount > staged.included_total {
                        // A later deposit can complete the exact offset, deferring the
                        // whole aggregate, so the amount must stay coverable without it.
                        let uncovered = account
                            .current
                            .balance
                            .checked_sub(staged.included_total)
                            .context("staged deposits exceed the live balance")?;
                        ensure!(
                            uncovered >= amount,
                            "withdrawal exceeds the balance available without its deposit aggregate"
                        );
                    }
                    ensure!(
                        account.current.balance >= amount,
                        "withdrawal exceeds the live balance"
                    );
                    account.current.balance -= amount;
                    account.current.active = account.current.balance > 0;
                    upsert_account_state(transaction, epoch, &account)?;
                    Some(amount)
                }
                WithdrawalAction::Close => None,
            };
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
                        .context("withdrawal exceeds live liability")?
                        .checked_sub(deferred_total)
                        .context("deferred aggregate exceeds live liability")?;
                    let deposit_events = metadata_deposit_events(transaction)?
                        .checked_sub(deferred_events)
                        .context("deferred deposit event count underflow")?;
                    transaction.execute(
                        "UPDATE operator_meta
                     SET payment_context = ?1, live_liability = ?2, deposit_events = ?3
                     WHERE singleton = 1",
                        params![
                            replacement.encode().as_ref(),
                            live_liability.to_be_bytes().as_slice(),
                            sql_usize(deposit_events, "deposit event count")?,
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
            let work: i64 = transaction.query_row(
                "SELECT
                 EXISTS(SELECT 1 FROM payments WHERE epoch = ?1)
                 OR EXISTS(SELECT 1 FROM deposits WHERE epoch = ?1)
                 OR EXISTS(SELECT 1 FROM withdrawals WHERE epoch = ?1)",
                [epoch_sql],
                |row| row.get(0),
            )?;
            ensure!(
                work != 0,
                "there are no payments, deposits, or withdrawals to close"
            );

            let closing_accounts = pending_close_accounts(transaction, epoch)?;
            let close_total = closing_accounts
                .iter()
                .try_fold(0_u64, |total, (_, account)| {
                    total
                        .checked_add(account.current.balance)
                        .context("Close tail total overflow")
                })?;
            let successor_liability = metadata_live_liability(transaction)?
                .checked_sub(close_total)
                .context("Close tails exceed live liability")?;
            ensure!(
                successor_liability == successor.predecessor_liability(),
                "successor context has the wrong predecessor liability"
            );

            for (request, mut account) in closing_accounts {
                let tail = account.current.balance;
                account.current.balance = 0;
                account.current.active = false;
                upsert_account_state(transaction, epoch, &account)?;
                let updated = transaction.execute(
                    "UPDATE withdrawals SET applied_amount = ?1
                 WHERE epoch = ?2 AND account = ?3 AND applied_amount IS NULL",
                    params![
                        sql_u64(tail, "Close tail")?,
                        epoch_sql,
                        request.account().as_ref(),
                    ],
                )?;
                ensure!(updated == 1, "pending Close disappeared during cutover");
            }

            // Deferred aggregates were parked as the successor's rows at intake, whatever
            // epoch first staged them. Credit them now so the successor opens with those
            // deposits staged, exactly as the chain carries an exactly offset deposit
            // into its next boundary.
            let carried = {
                let mut statement = transaction.prepare(
                    "SELECT length(account), account, sum(amount), count(*)
                     FROM deposits WHERE carried_from <= ?1 AND epoch > ?1
                     GROUP BY account ORDER BY account",
                )?;
                statement
                    .query_map([epoch_sql], |row| {
                        let account =
                            read_fixed_blob(row, 0, 1, Key::SIZE, "carried deposit account")?;
                        Ok((account, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?
            };
            let mut carried_records = Vec::with_capacity(carried.len());
            let mut carried_total = 0_u64;
            let mut carried_events = 0_usize;
            for (encoded_account, amount, count) in carried {
                let key = Key::decode(encoded_account.as_slice())
                    .context("decode carried deposit account")?;
                let amount = from_sql_u64(amount, "carried deposit amount")?;
                let count = usize::try_from(count).context("invalid carried deposit count")?;
                let account = match effective_account(transaction, next_epoch, &key)? {
                    Some(mut account) => {
                        account.current.balance = checked_sql_add(
                            account.current.balance,
                            amount,
                            "carried deposit balance",
                        )?;
                        account
                    }
                    None => {
                        let name: String = transaction.query_row(
                            "SELECT name FROM account_identities WHERE public_key = ?1",
                            [key.as_ref()],
                            |row| row.get(0),
                        )?;
                        StoredAccount {
                            name,
                            key: key.clone(),
                            predecessor: AccountState::default(),
                            current: AccountState {
                                balance: amount,
                                active: true,
                                ..AccountState::default()
                            },
                        }
                    }
                };
                upsert_account_state(transaction, next_epoch, &account)?;
                carried_records
                    .push(DepositRecord::new(key, amount).context("carried deposit record")?);
                carried_total = checked_sql_add(carried_total, amount, "carried deposit total")?;
                carried_events = carried_events
                    .checked_add(count)
                    .context("carried deposit count overflow")?;
            }
            ensure!(
                carried_events <= MAX_DEPOSIT_EVENTS,
                "carried deposit events exceed the epoch bound"
            );
            let carried_root = DepositBatch::new(carried_records)
                .context("aggregate carried deposits")?
                .root::<Sha256>()
                .context("commit carried deposit boundary")?;
            ensure!(
                successor.deposit_root() == &carried_root,
                "successor context does not stage the carried deposits"
            );
            let live_liability = checked_sql_add(
                successor_liability,
                carried_total,
                "successor live liability",
            )?;

            // Close projections and the epoch transition share one commit. Unchanged accounts remain
            // copy-on-write, so cutover work is proportional to the number of Close authorizations
            // and carried deposits.
            transaction.execute(
                "INSERT INTO close_jobs(epoch, status, payment_context)
             VALUES(?1, 'closing', ?2)",
                params![epoch_sql, expected.encode().as_ref()],
            )?;
            transaction.execute(
                "UPDATE operator_meta
             SET epoch = ?1, live_liability = ?2, payment_context = ?3, deposit_events = ?4
             WHERE singleton = 1",
                params![
                    sql_u64(next_epoch, "epoch")?,
                    live_liability.to_be_bytes().as_slice(),
                    successor.payment().encode().as_ref(),
                    sql_usize(carried_events, "carried deposit count")?,
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
        genesis_root: VectorRoot<Digest>,
    ) -> Result<()> {
        let mut external_total = 0_u64;
        let external_claims = result
            .external_claims
            .iter()
            .map(|claim| {
                let payout = claim
                    .verify::<Sha256>(&result.roots.change)
                    .context("verify external payout claim")?;
                external_total = external_total
                    .checked_add(payout.amount)
                    .context("external payout total overflow")?;
                let encoded = claim.encode();
                ensure!(
                    encoded.len() <= MAX_CLAIM_BYTES,
                    "external payout claim exceeds the operator bound"
                );
                Ok((claim.position(), payout, encoded))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            external_total == result.finalized.payout_total,
            "external claims do not exhaust the finalized payout reserve"
        );

        ensure!(
            result.withdrawal_claims.len() == result.withdrawals.requests().len(),
            "finalized withdrawals do not have exact claim evidence"
        );
        let mut withdrawal_total = 0_u64;
        let withdrawal_claims = result
            .withdrawals
            .requests()
            .iter()
            .zip(&result.withdrawal_claims)
            .enumerate()
            .map(|(position, (request, claim))| {
                let position = u32::try_from(position).context("withdrawal position overflow")?;
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
                        output.amount() == amount.get(),
                        "withdrawal claim has the wrong requested amount"
                    );
                }
                withdrawal_total = withdrawal_total
                    .checked_add(output.amount())
                    .context("withdrawal claim total overflow")?;
                let proof = claim.encode();
                ensure!(
                    proof.len() <= MAX_CLAIM_BYTES,
                    "withdrawal claim exceeds the operator bound"
                );
                Ok((request.account().clone(), position, output, proof))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            withdrawal_total == result.finalized.withdrawal_total,
            "withdrawal claims do not exhaust the finalized reserve"
        );
        mutate(&mut self.connection, "close finalization", |transaction| {
            let epoch = sql_u64(result.epoch, "epoch")?;
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
            if close_payment_context(transaction, epoch)? != result.payment_context {
                return Err(CloseRejected("close result has the wrong payment context").into());
            }
            if result.epoch == 0 {
                if result.predecessor_root != genesis_root {
                    return Err(CloseRejected(
                        "genesis close does not extend the configured predecessor root",
                    )
                    .into());
                }
            } else {
                let predecessor = sql_u64(result.epoch - 1, "predecessor epoch")?;
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
                let roots = RootBundle::<Digest>::decode(roots.as_slice())
                    .map_err(|_| CloseRejected("predecessor settlement roots are malformed"))?;
                if roots.successor != result.predecessor_root {
                    return Err(CloseRejected(
                        "close result does not extend its predecessor state root",
                    )
                    .into());
                }
            }
            let (header, roots, certificate) = encoded_artifacts(result);
            transaction.execute(
                "INSERT INTO settlements(
                 epoch, batch_id, header, roots, certificate, rows, slices, dealing_slices,
                 withdrawal_total, payout_total, prepare_micros, deal_micros, seal_micros
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    epoch,
                    result.finalized.batch_id.digest().as_ref(),
                    header,
                    roots,
                    certificate,
                    sql_usize(result.rows, "row count")?,
                    sql_usize(result.slices, "slice count")?,
                    sql_usize(result.dealing_slices, "dealing slice count")?,
                    sql_u64(result.finalized.withdrawal_total, "withdrawal total")?,
                    sql_u64(result.finalized.payout_total, "payout total")?,
                    sql_u128(result.prepare_micros, "prepare duration")?,
                    sql_u128(result.deal_micros, "deal duration")?,
                    sql_u128(result.seal_micros, "seal duration")?,
                ],
            )?;
            for (account, position, output, proof) in withdrawal_claims {
                if output.amount() == 0 {
                    continue;
                }
                transaction.execute(
                    "INSERT INTO withdrawal_claims(batch_id, position, account, proof)
                 VALUES(?1, ?2, ?3, ?4)",
                    params![
                        result.finalized.batch_id.digest().as_ref(),
                        i64::from(position),
                        account.as_ref(),
                        proof.as_ref(),
                    ],
                )?;
            }
            for (position, payout, proof) in external_claims {
                transaction.execute(
                    "INSERT INTO payout_claims(epoch, position, recipient, amount, proof)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![
                        epoch,
                        i64::from(position),
                        payout.recipient.as_ref(),
                        sql_u64(payout.amount, "payout amount")?,
                        proof.as_ref(),
                    ],
                )?;
            }
            transaction.execute(
                "UPDATE close_jobs
             SET status = 'finalized', error = NULL
             WHERE epoch = ?1",
                [epoch],
            )?;

            // Only finalized history authorizes deletion. Retire versions shadowed by this epoch and
            // remove its finalized zero-balance account versions without relying on a successor.
            transaction.execute(PRUNE_FINALIZED_ACCOUNT_STATES_SQL, [epoch])?;
            Ok(())
        })
    }

    pub(crate) fn withdrawal_evidence(&self, account: &Key) -> Result<WithdrawalEvidence> {
        let encoded = self
            .connection
            .query_row(
                "SELECT length(settlements.header), settlements.header,
                        withdrawal_claims.position,
                        length(withdrawal_claims.proof), withdrawal_claims.proof
                 FROM withdrawal_claims
                 JOIN settlements USING(batch_id)
                 WHERE withdrawal_claims.account = ?1 AND withdrawal_claims.claimed = 0
                 ORDER BY settlements.epoch
                 LIMIT 1",
                [account.as_ref()],
                |row| {
                    let header = read_fixed_blob(row, 0, 1, Header::<Digest>::SIZE, "header")?;
                    let position = u32::try_from(row.get::<_, i64>(2)?).map_err(|_| {
                        to_sqlite_error(anyhow::anyhow!("invalid withdrawal claim position"))
                    })?;
                    let proof_len = usize::try_from(row.get::<_, i64>(3)?).map_err(|_| {
                        to_sqlite_error(anyhow::anyhow!("invalid withdrawal claim length"))
                    })?;
                    if proof_len == 0 || proof_len > MAX_CLAIM_BYTES {
                        return Err(to_sqlite_error(anyhow::anyhow!(
                            "invalid withdrawal claim length"
                        )));
                    }
                    Ok((header, position, row.get::<_, Vec<u8>>(4)?))
                },
            )
            .optional()?
            .context("there is no finalized withdrawal claim for this account")?;
        let header = Header::<Digest>::decode(encoded.0.as_slice())
            .context("decode withdrawal settlement header")?;
        let claim = WithdrawalClaim::<Digest>::decode_cfg(
            encoded.2.as_slice(),
            &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
        )
        .context("decode withdrawal claim")?;
        ensure!(
            claim.position() == encoded.1,
            "stored withdrawal claim has the wrong position"
        );
        Ok(WithdrawalEvidence {
            batch_id: header.batch_id::<Sha256>(),
            account: account.clone(),
            claim,
        })
    }

    pub(crate) fn acknowledge_withdrawal_claim(
        &mut self,
        batch_id: BatchId<Digest>,
        account: &Key,
        claim: &WithdrawalClaim<Digest>,
    ) -> Result<()> {
        let proof = claim.encode();
        ensure!(
            proof.len() <= MAX_CLAIM_BYTES,
            "withdrawal claim exceeds the operator bound"
        );
        mutate(
            &mut self.connection,
            "withdrawal claim acknowledgement",
            |transaction| {
                let claimed = transaction
                    .query_row(
                        "SELECT withdrawal_claims.claimed
                 FROM withdrawal_claims
                 WHERE withdrawal_claims.batch_id = ?1
                   AND withdrawal_claims.position = ?2
                   AND withdrawal_claims.account = ?3
                   AND withdrawal_claims.proof = ?4",
                        params![
                            batch_id.digest().as_ref(),
                            i64::from(claim.position()),
                            account.as_ref(),
                            proof.as_ref(),
                        ],
                        |row| row.get::<_, bool>(0),
                    )
                    .optional()?
                    .context("withdrawal acknowledgement does not match stored evidence")?;
                if !claimed {
                    let updated = transaction.execute(
                        "UPDATE withdrawal_claims
                 SET claimed = 1
                 WHERE batch_id = ?1
                   AND position = ?2
                   AND account = ?3
                   AND proof = ?4
                   AND claimed = 0",
                        params![
                            batch_id.digest().as_ref(),
                            i64::from(claim.position()),
                            account.as_ref(),
                            proof.as_ref(),
                        ],
                    )?;
                    ensure!(
                        updated == 1,
                        "withdrawal acknowledgement changed concurrently"
                    );
                }
                Ok(())
            },
        )
    }

    pub(crate) fn external_payout_evidence(
        &self,
        recipient: &Key,
    ) -> Result<ExternalPayoutEvidence> {
        let stored = self
            .connection
            .query_row(
                "SELECT claims.position, length(claims.proof), claims.proof,
                        length(settlements.roots), settlements.roots,
                        length(claims.recipient), claims.recipient, claims.amount,
                        length(settlements.header), settlements.header
                 FROM payout_claims AS claims
                 JOIN settlements USING(epoch)
                 WHERE claims.claimed = 0 AND claims.recipient = ?1
                 ORDER BY claims.epoch, claims.position
                 LIMIT 1",
                [recipient.as_ref()],
                |row| {
                    let proof_len = row.get::<_, i64>(1)?;
                    if proof_len <= 0
                        || usize::try_from(proof_len).map_or(true, |len| len > MAX_CLAIM_BYTES)
                    {
                        return Err(to_sqlite_error(anyhow::anyhow!(
                            "invalid external claim length"
                        )));
                    }
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(2)?,
                        read_fixed_blob(row, 3, 4, RootBundle::<Digest>::SIZE, "settlement roots")?,
                        read_fixed_blob(row, 5, 6, Key::SIZE, "claim recipient")?,
                        row.get::<_, i64>(7)?,
                        read_fixed_blob(row, 8, 9, Header::<Digest>::SIZE, "header")?,
                    ))
                },
            )
            .optional()?
            .context("there is no unclaimed external payout for this recipient")?;
        let position = u32::try_from(stored.0).context("claim position does not fit u32")?;
        let claim = ExternalPayoutClaim::<Key, Digest>::decode(stored.1.as_slice())
            .context("decode external payout claim")?;
        ensure!(
            claim.position() == position,
            "stored claim position differs from its proof"
        );
        let roots = RootBundle::<Digest>::decode(stored.2.as_slice())
            .context("decode settlement roots for claim")?;
        let payout = claim
            .verify::<Sha256>(&roots.change)
            .context("verify external payout claim")?;
        ensure!(
            payout.recipient.as_ref() == stored.3.as_slice(),
            "stored claim recipient differs from its proof"
        );
        ensure!(
            payout.amount == from_sql_u64(stored.4, "claim amount")?,
            "stored claim amount differs from its proof"
        );
        let header = Header::<Digest>::decode(stored.5.as_slice())
            .context("decode external payout settlement header")?;
        Ok(ExternalPayoutEvidence {
            batch_id: header.batch_id::<Sha256>(),
            claim,
        })
    }

    pub(crate) fn acknowledge_external_payout_claim(
        &mut self,
        batch_id: BatchId<Digest>,
        claim: &ExternalPayoutClaim<Key, Digest>,
    ) -> Result<()> {
        let proof = claim.encode();
        ensure!(
            !proof.is_empty() && proof.len() <= MAX_CLAIM_BYTES,
            "external payout claim exceeds the operator bound"
        );
        mutate(
            &mut self.connection,
            "external payout acknowledgement",
            |transaction| {
                let claimed = transaction
                    .query_row(
                        "SELECT payout_claims.claimed
                 FROM payout_claims
                 JOIN settlements USING(epoch)
                 WHERE settlements.batch_id = ?1
                   AND payout_claims.position = ?2
                   AND payout_claims.proof = ?3",
                        params![
                            batch_id.digest().as_ref(),
                            i64::from(claim.position()),
                            proof.as_ref(),
                        ],
                        |row| row.get::<_, bool>(0),
                    )
                    .optional()?
                    .context("external payout acknowledgement does not match stored evidence")?;
                if !claimed {
                    let updated = transaction.execute(
                        "UPDATE payout_claims
                 SET claimed = 1
                 WHERE epoch = (SELECT epoch FROM settlements WHERE batch_id = ?1)
                   AND position = ?2
                   AND proof = ?3
                   AND claimed = 0",
                        params![
                            batch_id.digest().as_ref(),
                            i64::from(claim.position()),
                            proof.as_ref(),
                        ],
                    )?;
                    ensure!(
                        updated == 1,
                        "external payout acknowledgement changed concurrently"
                    );
                }
                Ok(())
            },
        )
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

    pub(crate) fn latest_finalized_root(&self) -> Result<Option<(u64, VectorRoot<Digest>)>> {
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
        let roots = RootBundle::<Digest>::decode(encoded.as_slice())
            .context("decode latest settlement roots")?;
        Ok(Some((
            from_sql_u64(epoch, "settlement epoch")?,
            roots.successor,
        )))
    }

    #[cfg(test)]
    pub(crate) fn settlement_roots(&self, epoch: u64) -> Result<RootBundle<Digest>> {
        let encoded: Vec<u8> = self.connection.query_row(
            "SELECT length(roots), roots FROM settlements WHERE epoch = ?1",
            [sql_u64(epoch, "epoch")?],
            |row| read_fixed_blob(row, 0, 1, RootBundle::<Digest>::SIZE, "settlement roots"),
        )?;
        RootBundle::decode(encoded.as_slice()).context("decode settlement roots")
    }

    pub(crate) fn next_closing_epoch(&self) -> Result<Option<u64>> {
        self.connection
            .query_row(
                "SELECT epoch FROM close_jobs WHERE status = 'closing' ORDER BY epoch LIMIT 1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .map(|value| from_sql_u64(value, "closing epoch"))
            .transpose()
    }

    pub(crate) fn pending_close_count(&self) -> Result<usize> {
        let count = self.connection.query_row(
            "SELECT count(*) FROM close_jobs WHERE status = 'closing'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        usize::try_from(count).context("pending close count does not fit usize")
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
                    "SELECT length(header), header, rows, slices, payout_total,
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
                let header = Header::<Digest>::decode(stored.0.as_slice())
                    .context("decode finalized close header")?;
                Ok(StoredCloseOutcome::Finished(StoredCloseFinished {
                    header,
                    rows: usize::try_from(from_sql_u64(stored.1, "close row count")?)
                        .context("close row count does not fit usize")?,
                    slices: usize::try_from(from_sql_u64(stored.2, "close slice count")?)
                        .context("close slice count does not fit usize")?,
                    payout_total: from_sql_u64(stored.3, "close payout total")?,
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
        let (accounts, present_accounts, recent_payments, reserved_payout_value) =
            self.connection.query_row(
                "SELECT
                     (SELECT count(*) FROM account_identities),
                     (SELECT count(*) FROM account_identities AS identity
                      WHERE (SELECT state.current_balance
                             FROM account_states AS state
                             WHERE state.public_key = identity.public_key
                               AND state.epoch <= ?1
                             ORDER BY state.epoch DESC LIMIT 1) > 0),
                     min((SELECT count(*) FROM payments WHERE epoch = ?1), 12),
                     (SELECT coalesce(sum(amount), 0)
                      FROM payout_claims WHERE claimed = 0)",
                [epoch_sql],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )?;
        Ok(StoreStatus {
            epoch,
            accounts: from_sql_u64(accounts, "account count")?,
            present_accounts: from_sql_u64(present_accounts, "present account count")?,
            recent_payments: from_sql_u64(recent_payments, "recent payment count")?,
            reserved_payout_value: from_sql_u64(reserved_payout_value, "reserved payout value")?,
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
                balance: account.current.balance,
                present: account.current.balance > 0,
            })
            .collect();
        let payments = current
            .payments
            .into_iter()
            .rev()
            .take(12)
            .map(|payment| PaymentView {
                external: payment.external,
            })
            .collect();
        let reserved_payout_value = from_sql_u64(
            self.connection.query_row(
                "SELECT coalesce(sum(amount), 0) FROM payout_claims WHERE claimed = 0",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            "reserved payout value",
        )?;
        Ok(StoreSnapshot {
            epoch,
            accounts,
            payments,
            reserved_payout_value,
        })
    }
}

fn validate_new_payment(
    connection: &Connection,
    context: &EpochPaymentContext,
    send: &SignedSend<Key, Digest>,
    shard: u64,
) -> Result<NewPaymentPlan> {
    let epoch = metadata_epoch(connection)?;
    ensure!(epoch == context.epoch(), "payment context is stale");
    ensure!(
        metadata_payment_context(connection)?.as_ref() == Some(context),
        "payment anchor is stale"
    );
    let epoch_sql = sql_u64(epoch, "epoch")?;
    let accepted = epoch_payment_count(connection, epoch_sql)?;
    ensure!(
        send.body().entries().len() <= MAX_ACCEPTED_PAYMENTS - accepted.min(MAX_ACCEPTED_PAYMENTS),
        "epoch payment capacity is exhausted"
    );

    let payer_key = send.body().payer().clone();
    let mut payer = effective_account(connection, epoch, &payer_key)?
        .context("payer is not a live registered account")?;
    send.verify_next(context, payer.current.cumulative_debit)
        .context("verify payer authorization")?;
    let total = send
        .body()
        .total()
        .context("verified send total is checked")?;
    ensure!(
        payer.current.balance >= total,
        "payer has insufficient available balance"
    );
    payer.current.cumulative_debit = checked_sql_add(
        payer.current.cumulative_debit,
        total,
        "payer cumulative debit",
    )?;
    payer.current.balance -= total;

    let shard_sql = sql_u64(shard, "receive shard")?;
    let mut external_total = 0_u64;
    let mut entries = Vec::with_capacity(send.body().entries().len());
    for entry in send.body().entries() {
        let recipient_key = entry.recipient().clone();
        ensure!(
            recipient_key != payer_key,
            "self-payments are omitted from this operator"
        );
        let amount = entry.amount();
        let mut recipient = effective_account(connection, epoch, &recipient_key)?;
        let external = recipient.is_none();
        let recipient_name = recipient.as_ref().map_or_else(
            || "external".to_string(),
            |recipient| recipient.name.clone(),
        );
        if let Some(recipient) = recipient.as_mut() {
            recipient.current.balance = checked_sql_add(
                recipient.current.balance,
                amount,
                "recipient account balance",
            )?;
            recipient.current.cumulative_credit = checked_sql_add(
                recipient.current.cumulative_credit,
                amount,
                "recipient cumulative credit",
            )?;
            recipient.current.receipt_count = checked_sql_add(
                recipient.current.receipt_count,
                1,
                "recipient receipt count",
            )?;
        } else {
            external_total = checked_sql_add(external_total, amount, "external payment total")?;
        }
        let endpoint = connection
            .query_row(
                "SELECT cumulative_credit, receipt_index FROM receive_shards
                 WHERE epoch = ?1 AND recipient = ?2 AND shard = ?3",
                params![epoch_sql, recipient_key.as_ref(), shard_sql],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .unwrap_or((0, 0));
        let previous_credit = from_sql_u64(endpoint.0, "shard credit")?;
        checked_sql_add(previous_credit, amount, "receive-shard cumulative credit")?;
        entries.push(EntryPlan {
            recipient_key,
            recipient,
            recipient_name,
            external,
            previous_credit,
            previous_index: from_sql_u64(endpoint.1, "receipt index")?,
        });
    }
    let live_liability = if external_total > 0 {
        Some(
            metadata_live_liability(connection)?
                .checked_sub(external_total)
                .context("external payment exceeds live liability")?,
        )
    } else {
        None
    };
    Ok(NewPaymentPlan {
        epoch,
        payer,
        live_liability,
        total,
        entries,
    })
}

fn find_accepted_batch(
    connection: &Connection,
    send: &SignedSend<Key, Digest>,
) -> Result<Option<AcceptedBatch>> {
    let tx_id = send.tx_id::<Sha256>();
    let mut statement = connection.prepare(
        "SELECT epoch, sequence, length(encoded), encoded
         FROM payments WHERE tx_id = ?1 ORDER BY sequence",
    )?;
    let rows = statement
        .query_map([tx_id.digest().as_ref()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                read_bounded_blob(row, 2, 3, MAX_PAYMENT_BYTES, "encoded payment")?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let Some((epoch, sequence, _)) = rows.first() else {
        return Ok(None);
    };
    let epoch = from_sql_u64(*epoch, "payment epoch")?;
    let sequence = from_sql_u64(*sequence, "payment sequence")?;
    ensure!(
        rows.len() == send.body().entries().len(),
        "transaction id is bound to another payment request"
    );
    let mut total = 0_u64;
    let mut receipts = Vec::with_capacity(rows.len());
    for (_, _, encoded) in &rows {
        let payment = Payment::decode(encoded.as_slice()).context("decode accepted payment")?;
        ensure!(
            payment.send() == send,
            "transaction id is bound to another payment request"
        );
        total = checked_sql_add(total, payment.amount(), "accepted batch total")?;
        receipts.push(payment.into_parts().1);
    }
    Ok(Some(AcceptedBatch {
        epoch,
        sequence,
        total,
        acceptance: Acceptance {
            send: send.clone(),
            receipts,
        },
    }))
}

fn read_account(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredAccount> {
    let key = read_fixed_blob(row, 1, 2, Key::SIZE, "account key")?;
    Ok(StoredAccount {
        name: row.get(0)?,
        key: Key::decode(key.as_slice())
            .map_err(|error| to_sqlite_error(anyhow::anyhow!("decode account key: {error}")))?,
        predecessor: AccountState {
            balance: from_sql_u64(row.get(3)?, "predecessor balance").map_err(to_sqlite_error)?,
            cumulative_debit: from_sql_u64(row.get(4)?, "predecessor debit")
                .map_err(to_sqlite_error)?,
            cumulative_credit: from_sql_u64(row.get(5)?, "predecessor credit")
                .map_err(to_sqlite_error)?,
            receipt_count: from_sql_u64(row.get(6)?, "predecessor receipts")
                .map_err(to_sqlite_error)?,
            active: row.get::<_, i64>(7)? != 0,
        },
        current: AccountState {
            balance: from_sql_u64(row.get(8)?, "current balance").map_err(to_sqlite_error)?,
            cumulative_debit: from_sql_u64(row.get(9)?, "current debit")
                .map_err(to_sqlite_error)?,
            cumulative_credit: from_sql_u64(row.get(10)?, "current credit")
                .map_err(to_sqlite_error)?,
            receipt_count: from_sql_u64(row.get(11)?, "current receipts")
                .map_err(to_sqlite_error)?,
            active: from_sql_u64(row.get(8)?, "current balance").map_err(to_sqlite_error)? > 0,
        },
    })
}

fn effective_account(
    connection: &Connection,
    epoch: u64,
    account: &Key,
) -> Result<Option<StoredAccount>> {
    let epoch_sql = sql_u64(epoch, "epoch")?;
    let version = connection
        .query_row(
            EFFECTIVE_ACCOUNT_SQL,
            params![account.as_ref(), epoch_sql],
            |row| {
                let key = read_fixed_blob(row, 2, 3, Key::SIZE, "account key")?;
                let predecessor = AccountState {
                    balance: from_sql_u64(row.get(4)?, "predecessor balance")
                        .map_err(to_sqlite_error)?,
                    cumulative_debit: from_sql_u64(row.get(5)?, "predecessor debit")
                        .map_err(to_sqlite_error)?,
                    cumulative_credit: from_sql_u64(row.get(6)?, "predecessor credit")
                        .map_err(to_sqlite_error)?,
                    receipt_count: from_sql_u64(row.get(7)?, "predecessor receipts")
                        .map_err(to_sqlite_error)?,
                    active: row.get::<_, i64>(8)? != 0,
                };
                let balance =
                    from_sql_u64(row.get(9)?, "current balance").map_err(to_sqlite_error)?;
                Ok((
                    from_sql_u64(row.get(0)?, "account state epoch").map_err(to_sqlite_error)?,
                    StoredAccount {
                        name: row.get(1)?,
                        key: Key::decode(key.as_slice()).map_err(|error| {
                            to_sqlite_error(anyhow::anyhow!("decode account key: {error}"))
                        })?,
                        predecessor,
                        current: AccountState {
                            balance,
                            cumulative_debit: from_sql_u64(row.get(10)?, "current debit")
                                .map_err(to_sqlite_error)?,
                            cumulative_credit: from_sql_u64(row.get(11)?, "current credit")
                                .map_err(to_sqlite_error)?,
                            receipt_count: from_sql_u64(row.get(12)?, "current receipts")
                                .map_err(to_sqlite_error)?,
                            active: balance > 0,
                        },
                    },
                ))
            },
        )
        .optional()?;
    let Some((version_epoch, mut account)) = version else {
        return Ok(None);
    };
    if version_epoch < epoch {
        // Zero-balance accounts remain registered through the epoch that drained them, then
        // disappear unless a later deposit creates a fresh version.
        if account.current.balance == 0 {
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
    transaction.execute(
        "INSERT INTO account_identities(public_key, name) VALUES(?1, ?2)
         ON CONFLICT(public_key) DO NOTHING",
        params![account.key.as_ref(), account.name],
    )?;
    let name: String = transaction.query_row(
        "SELECT name FROM account_identities WHERE public_key = ?1",
        [account.key.as_ref()],
        |row| row.get(0),
    )?;
    ensure!(name == account.name, "account label does not match its key");
    transaction.execute(
        "INSERT INTO account_states(
             epoch, public_key,
             predecessor_balance, predecessor_debit, predecessor_credit,
             predecessor_receipts, predecessor_active,
             current_balance, current_debit, current_credit, current_receipts
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(epoch, public_key) DO UPDATE SET
             current_balance = excluded.current_balance,
             current_debit = excluded.current_debit,
             current_credit = excluded.current_credit,
             current_receipts = excluded.current_receipts",
        params![
            sql_u64(epoch, "epoch")?,
            account.key.as_ref(),
            sql_u64(account.predecessor.balance, "predecessor balance")?,
            sql_u64(account.predecessor.cumulative_debit, "predecessor debit")?,
            sql_u64(account.predecessor.cumulative_credit, "predecessor credit")?,
            sql_u64(account.predecessor.receipt_count, "predecessor receipts")?,
            i64::from(account.predecessor.active),
            sql_u64(account.current.balance, "current balance")?,
            sql_u64(account.current.cumulative_debit, "current debit")?,
            sql_u64(account.current.cumulative_credit, "current credit")?,
            sql_u64(account.current.receipt_count, "current receipts")?,
        ],
    )?;
    Ok(())
}

fn pending_close_accounts(
    connection: &Connection,
    epoch: u64,
) -> Result<Vec<(SignedWithdrawal<Key, Digest>, StoredAccount)>> {
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
                    to_sqlite_error(anyhow::anyhow!("invalid encoded Close length"))
                })?;
                if length == 0 || length > MAX_WITHDRAWAL_BYTES {
                    return Err(to_sqlite_error(anyhow::anyhow!(
                        "invalid encoded Close length"
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
                encoded.as_slice(),
                &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
            )
            .context("decode pending Close")?;
            ensure!(
                matches!(request.body().action(), WithdrawalAction::Close),
                "only Close may have a pending applied amount"
            );
            request
                .verify_signature()
                .context("verify pending Close authorization")?;
            let account = effective_account(connection, epoch, request.account())?
                .context("pending Close account is not represented in its epoch")?;
            Ok((request, account))
        })
        .collect()
}

/// One account's staged deposit shape for the current epoch.
struct StagedAccountDeposits {
    /// Aggregate of rows the current epoch's boundary includes.
    included_total: u64,
    /// Number of included rows.
    included_events: usize,
    /// Aggregate of rows parked for the successor epoch.
    parked_total: u64,
    /// Number of parked rows.
    parked_events: usize,
}

fn staged_account_deposits(
    connection: &Connection,
    epoch: u64,
    account: &Key,
) -> Result<StagedAccountDeposits> {
    let epoch_sql = sql_u64(epoch, "epoch")?;
    let mut statement = connection.prepare(
        "SELECT amount, epoch FROM deposits
         WHERE account = ?1 AND (epoch = ?2 OR (carried_from <= ?2 AND epoch > ?2))",
    )?;
    let rows = statement
        .query_map(params![account.as_ref(), epoch_sql], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut staged = StagedAccountDeposits {
        included_total: 0,
        included_events: 0,
        parked_total: 0,
        parked_events: 0,
    };
    for (amount, row_epoch) in rows {
        let amount = from_sql_u64(amount, "deposit amount")?;
        if row_epoch == epoch_sql {
            staged.included_total =
                checked_sql_add(staged.included_total, amount, "staged deposit aggregate")?;
            staged.included_events += 1;
        } else {
            staged.parked_total =
                checked_sql_add(staged.parked_total, amount, "parked deposit aggregate")?;
            staged.parked_events += 1;
        }
    }
    Ok(staged)
}

fn epoch_withdrawal(
    connection: &Connection,
    epoch: u64,
    account: &Key,
) -> Result<Option<SignedWithdrawal<Key, Digest>>> {
    connection
        .query_row(
            "SELECT length(encoded), encoded
             FROM withdrawals WHERE epoch = ?1 AND account = ?2",
            params![sql_u64(epoch, "epoch")?, account.as_ref()],
            |row| read_bounded_blob(row, 0, 1, MAX_WITHDRAWAL_BYTES, "encoded withdrawal"),
        )
        .optional()?
        .map(|encoded| {
            SignedWithdrawal::<Key, Digest>::decode_cfg(
                encoded.as_slice(),
                &RangeCfg::new(0..=MAX_DESTINATION_BYTES),
            )
            .context("decode staged withdrawal")
        })
        .transpose()
}

/// Whether an aggregate exactly offset by the account's staged withdrawal defers whole to
/// the successor epoch, the chain's boundary rule.
fn deposit_defers(
    connection: &Connection,
    epoch: u64,
    account: &Key,
    aggregate: u64,
) -> Result<bool> {
    Ok(
        epoch_withdrawal(connection, epoch, account)?.is_some_and(|request| {
            SettlementChain::<Sha256, Key>::withdrawal_defers_deposit(&request, aggregate)
        }),
    )
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
            applied_amount == Some(amount.get()),
            "ordinary withdrawal has an inconsistent applied amount"
        ),
        WithdrawalAction::Close => {}
    }
    Ok(applied_amount)
}

fn metadata_epoch(connection: &Connection) -> Result<u64> {
    let value = connection.query_row(
        "SELECT epoch FROM operator_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    from_sql_u64(value, "epoch")
}

fn metadata_live_liability(connection: &Connection) -> Result<u64> {
    let encoded: Vec<u8> = connection.query_row(
        "SELECT length(live_liability), live_liability
         FROM operator_meta WHERE singleton = 1",
        [],
        |row| read_fixed_blob(row, 0, 1, 8, "live liability"),
    )?;
    decode_live_liability(&encoded)
}

fn metadata_deposit_events(connection: &Connection) -> Result<usize> {
    let count = connection.query_row(
        "SELECT deposit_events FROM operator_meta WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    usize::try_from(count).context("deposit event count does not fit usize")
}

fn epoch_payment_count(connection: &Connection, epoch: i64) -> Result<usize> {
    let count = connection.query_row(
        "SELECT count(*) FROM payments WHERE epoch = ?1",
        [epoch],
        |row| row.get::<_, i64>(0),
    )?;
    usize::try_from(count).context("payment count does not fit usize")
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
    let encoded = connection.query_row(
        "SELECT length(payment_context), payment_context
         FROM operator_meta WHERE singleton = 1",
        [],
        |row| {
            if row.get::<_, Option<i64>>(0)?.is_none() {
                return Ok(None);
            }
            read_fixed_blob(row, 0, 1, EpochPaymentContext::SIZE, "payment context").map(Some)
        },
    )?;
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

fn decode_payment_context(encoded: &[u8]) -> Result<EpochPaymentContext> {
    EpochPaymentContext::decode(encoded).context("decode stored payment context")
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
    use commonware_clearing::bajillion::boundary::{
        DepositBatch, DepositRecord, WithdrawalAction, WithdrawalBatch,
    };
    use commonware_cryptography::{Hasher as _, Signer as _};

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
        operator: SigningKey,
        payer: SigningKey,
        recipient: SigningKey,
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
                operator: SigningKey::from_seed(1),
                payer: SigningKey::from_seed(101),
                recipient: SigningKey::from_seed(102),
            }
        }

        fn send(&self, previous_debit: u64) -> SignedSend<Key, Digest> {
            SignedSend::sign_next(
                &self.context,
                &self.payer,
                self.recipient.public_key(),
                1,
                previous_debit,
            )
            .unwrap()
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

    fn rejected_payment(result: Result<AcceptedBatch>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("payment was accepted"),
            Err(error) => error,
        }
    }

    fn rejected_deposit(result: Result<StagedDeposit>) -> anyhow::Error {
        match result {
            Ok(_) => panic!("deposit was staged"),
            Err(error) => error,
        }
    }

    fn assert_payment_domain_rejected(
        configure: impl FnOnce(&mut PaymentFixture),
        previous_debit: u64,
        expected: &str,
    ) {
        let mut fixture = PaymentFixture::new();
        configure(&mut fixture);
        let send = fixture.send(previous_debit);
        let changes = fixture.store.total_changes();

        let error = fixture
            .store
            .payment_requires_epoch_registration(&fixture.context, &send, 0)
            .unwrap_err();
        assert!(format!("{error:#}").contains(expected));

        let error = rejected_payment(fixture.store.accept_send(
            &fixture.context,
            &fixture.operator,
            send,
            0,
        ));
        assert!(format!("{error:#}").contains(expected));
        assert_eq!(fixture.store.total_changes(), changes);
        assert!(fixture.store.load_current().unwrap().payments.is_empty());
    }

    #[test]
    fn payment_capacity_rejects_new_sends_without_breaking_retries() {
        let mut fixture = PaymentFixture::new();
        let initial_send = fixture.send(0);
        let initial = fixture
            .store
            .accept_send(&fixture.context, &fixture.operator, initial_send, 0)
            .unwrap();
        let payment = initial
            .acceptance
            .payments()
            .next()
            .expect("accepted batch has one entry");
        let recipient = payment.recipient().clone();
        let encoded = payment.encode();
        let transaction = fixture.store.connection.transaction().unwrap();
        for index in 1..(MAX_ACCEPTED_PAYMENTS - 1) {
            let index = u64::try_from(index).unwrap();
            let index_bytes = index.to_be_bytes();
            let tx_id = Sha256::hash(&[b"payment-capacity-fixture", &index_bytes]);
            transaction
                .execute(
                    "INSERT INTO payments(
                         epoch, payer_name, recipient, recipient_name, external, tx_id, encoded
                     ) VALUES(0, 'fixture payer', ?1, 'fixture recipient', 0, ?2, ?3)",
                    params![recipient.as_ref(), tx_id.as_ref(), encoded.as_ref()],
                )
                .unwrap();
        }
        transaction.commit().unwrap();

        let retry_send = fixture.send(1);
        assert!(
            fixture
                .store
                .payment_requires_epoch_registration(&fixture.context, &retry_send, 0)
                .unwrap()
        );
        let first = fixture
            .store
            .accept_send(&fixture.context, &fixture.operator, retry_send.clone(), 0)
            .unwrap();
        let changes = fixture.store.total_changes();
        assert!(
            !fixture
                .store
                .payment_requires_epoch_registration(&fixture.context, &retry_send, 0)
                .unwrap()
        );
        let replay = fixture
            .store
            .accept_send(&fixture.context, &fixture.operator, retry_send, 0)
            .unwrap();
        assert_eq!(replay.sequence, first.sequence);
        assert_eq!(replay.acceptance, first.acceptance);
        assert_eq!(fixture.store.total_changes(), changes);

        let new_send = fixture.send(2);
        let error = fixture
            .store
            .payment_requires_epoch_registration(&fixture.context, &new_send, 0)
            .unwrap_err();
        assert!(format!("{error:#}").contains("payment capacity"));
        let error = rejected_payment(fixture.store.accept_send(
            &fixture.context,
            &fixture.operator,
            new_send,
            0,
        ));
        assert!(format!("{error:#}").contains("payment capacity"));
        assert_eq!(fixture.store.total_changes(), changes);
        assert_eq!(
            fixture.store.load_current().unwrap().payments.len(),
            MAX_ACCEPTED_PAYMENTS
        );
    }

    #[test]
    fn payment_validation_rejects_sql_domain_overflow_before_epoch_registration() {
        assert_payment_domain_rejected(
            |fixture| {
                let payer = fixture.payer.public_key();
                fixture
                    .store
                    .connection
                    .execute(
                        "UPDATE account_states SET current_debit = ?1 WHERE public_key = ?2",
                        params![i64::MAX, payer.as_ref()],
                    )
                    .unwrap();
            },
            SQLITE_U64_MAX,
            "payer cumulative debit",
        );
        assert_payment_domain_rejected(
            |fixture| {
                let recipient = fixture.recipient.public_key();
                fixture
                    .store
                    .connection
                    .execute(
                        "UPDATE account_states SET current_balance = ?1 WHERE public_key = ?2",
                        params![i64::MAX, recipient.as_ref()],
                    )
                    .unwrap();
            },
            0,
            "recipient account balance",
        );
        assert_payment_domain_rejected(
            |fixture| {
                let recipient = fixture.recipient.public_key();
                fixture
                    .store
                    .connection
                    .execute(
                        "UPDATE account_states SET current_credit = ?1 WHERE public_key = ?2",
                        params![i64::MAX, recipient.as_ref()],
                    )
                    .unwrap();
            },
            0,
            "recipient cumulative credit",
        );
        assert_payment_domain_rejected(
            |fixture| {
                let recipient = fixture.recipient.public_key();
                fixture
                    .store
                    .connection
                    .execute(
                        "UPDATE account_states SET current_receipts = ?1 WHERE public_key = ?2",
                        params![i64::MAX, recipient.as_ref()],
                    )
                    .unwrap();
            },
            0,
            "recipient receipt count",
        );
        assert_payment_domain_rejected(
            |fixture| {
                let recipient = fixture.recipient.public_key();
                fixture
                    .store
                    .connection
                    .execute(
                        "INSERT INTO receive_shards(
                             epoch, recipient, shard, cumulative_credit, receipt_index
                         ) VALUES(0, ?1, 0, ?2, 0)",
                        params![recipient.as_ref(), i64::MAX],
                    )
                    .unwrap();
            },
            0,
            "receive-shard cumulative credit",
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

        let error =
            rejected_deposit(store.stage_deposit(identity, &event, &expected, &replacement));
        assert!(format!("{error:#}").contains("deposit account balance"));
        assert_eq!(store.total_changes(), changes);
        assert!(store.staged_deposit(&event.id).unwrap().is_none());
        assert_eq!(
            store
                .current_account(&identity.key)
                .unwrap()
                .unwrap()
                .current
                .balance,
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

        let error =
            rejected_deposit(store.stage_deposit(identity, &event, &expected, &replacement));
        assert!(format!("{error:#}").contains("live liability"));
        assert_eq!(store.total_changes(), changes);
        assert!(store.staged_deposit(&event.id).unwrap().is_none());
        assert_eq!(store.current_liability().unwrap(), SQLITE_U64_MAX);
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
            .stage_withdrawal(&request, expected.payment(), replacement.payment())
            .unwrap();
        assert_eq!(staged.action, WithdrawalAction::Close);
        assert_eq!(store.current_liability().unwrap(), predecessor_liability);
        assert_eq!(
            store
                .current_account(&account)
                .unwrap()
                .unwrap()
                .current
                .balance,
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
        assert_eq!(account.current.balance, 0);
        assert_eq!(frozen.withdrawals[0].applied_amount, Some(INITIAL_BALANCE));
    }
}
