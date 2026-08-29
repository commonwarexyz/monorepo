//! SQLite ownership boundary for the settlement role.
//!
//! The clearing crate leaves persistence to embeddings and assumes atomic, idempotent
//! persistence of each state mutation with its custody effect. This store meets that
//! obligation with an event-sourced input log: every state-bearing input is applied in
//! memory, appended in one committed transaction, and only then answered. Startup
//! replays the log through the live dispatch path, so all derived settlement state
//! (chain custody, the registered slot, claim-root and replay records, fault state,
//! and the logical clock) is rebuilt rather than persisted.

use crate::{
    protocol::deployment, rpc, settlement::Settlement, settlement_rpc, store::CommitUnknown,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use commonware_codec::{DecodeExt as _, Encode as _, FixedSize};
use commonware_cryptography::sha256::Digest;
use rusqlite::{Connection, TransactionBehavior, params};
use std::path::Path;

const SCHEMA_VERSION: i64 = 1;

/// One logged settlement input: a dispatched method with the body bytes as received and
/// the logical time the call observed.
struct Input {
    method: u8,
    body: Bytes,
    now: u64,
}

pub(crate) struct Store {
    settlement: Settlement,
    connection: Connection,
    poisoned: bool,
}

impl Store {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let in_memory = path == Path::new(":memory:");
        let mut connection = if in_memory {
            Connection::open_in_memory().context("open in-memory SQLite settlement")?
        } else {
            Connection::open(path)
                .with_context(|| format!("open SQLite settlement at {}", path.display()))?
        };
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA busy_timeout = 5000;",
        )?;

        configure_durability(&connection, in_memory)?;
        match schema_presence(&connection)? {
            SchemaPresence::Empty => initialize_schema(&mut connection)?,
            SchemaPresence::Complete => {}
        }
        read_binding(&connection)?;

        // Startup replay re-dispatches every logged input through the same path live
        // requests take, so the rebuilt state is the live state bit for bit. Only
        // response transmission is suppressed. A logged input may have been rejected
        // live (a time-advancing call that tripped a fault, for example), so replayed
        // outcomes are discarded like the lost responses they stand in for.
        let mut settlement = Settlement::new()?;
        for input in read_log(&connection)? {
            let _ = settlement_rpc::dispatch(
                &mut settlement,
                input.now,
                rpc::Request {
                    method: input.method,
                    body: input.body,
                },
            );
        }
        settlement.resume();

        Ok(Self {
            settlement,
            connection,
            poisoned: false,
        })
    }

    pub(crate) fn handle(&mut self, request: rpc::Request) -> rpc::Response {
        match self.apply(request) {
            Ok(body) => rpc::Response::Success { body },
            Err(error) => rpc::error_response(format!("{error:#}")),
        }
    }

    fn apply(&mut self, request: rpc::Request) -> Result<Bytes> {
        let now = self.settlement.observe_now();
        self.apply_at(now, request)
    }

    fn apply_at(&mut self, now: u64, request: rpc::Request) -> Result<Bytes> {
        self.ensure_usable()?;
        let method = request.method;
        let body = request.body.clone();
        let advances = now > self.settlement.now();
        let result = settlement_rpc::dispatch(&mut self.settlement, now, request);

        // Log every call that advances observed time, with its now and regardless of
        // outcome, plus every mutating method that succeeded. A time advance can
        // permanently record a liveness fault even on a rejected call, while a rejected
        // call that advanced nothing mutates nothing, so this exact set replays into
        // the identical state. The append commits before the response leaves, which
        // keeps every answered mutation durable.
        if advances || (settlement_rpc::mutates(method) && result.is_ok()) {
            let appended = self.append(method, body.as_ref(), now);
            self.finish_mutation(appended)?;
        }
        result
    }

    /// Appends one observed input. The log grows without bound because the demo takes
    /// no snapshots. That is acceptable here: records are small, terminal runs are
    /// short-lived, and replaying from genesis keeps recovery obviously correct.
    fn append(&mut self, method: u8, body: &[u8], now: u64) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("begin settlement input append")?;
        transaction.execute(
            "INSERT INTO settlement_log(method, body, now) VALUES(?1, ?2, ?3)",
            params![i64::from(method), body, now.to_be_bytes().as_slice()],
        )?;
        transaction
            .commit()
            .map_err(|source| CommitUnknown::new("settlement input append", source))?;
        Ok(())
    }

    fn ensure_usable(&self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "settlement database is unusable after a failed mutation"
        );
        Ok(())
    }

    const fn finish_mutation<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Advances the logical clock by dispatching one logged status observation, so the
    /// advance replays like any other input. Ticks are relative to the observed now
    /// because reopening re-anchors the liveness clock.
    #[cfg(test)]
    pub(crate) fn advance_logical_time(&mut self, ticks: u64) -> Result<()> {
        let Some(now) = self.settlement.tick_target(ticks) else {
            return Ok(());
        };
        self.apply_at(
            now,
            rpc::Request {
                method: settlement_rpc::METHOD_STATUS,
                body: Bytes::new(),
            },
        )
        .map(|_| ())
    }
}

enum SchemaPresence {
    Empty,
    Complete,
}

fn schema_presence(connection: &Connection) -> Result<SchemaPresence> {
    let has_meta = table_exists(connection, "settlement_meta")?;
    let has_log = table_exists(connection, "settlement_log")?;
    let has_unexpected: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema
             WHERE (type = 'table'
                    AND name NOT LIKE 'sqlite_%'
                    AND name NOT IN ('settlement_meta', 'settlement_log'))
                OR type IN ('trigger', 'view')
                OR (type = 'index' AND name NOT LIKE 'sqlite_autoindex_%')
             LIMIT 1
         )",
        [],
        |row| row.get(0),
    )?;

    if !has_meta && !has_log && !has_unexpected {
        return Ok(SchemaPresence::Empty);
    }
    ensure!(
        has_meta && has_log && !has_unexpected,
        "incompatible settlement database schema"
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
        .context("enable SQLite settlement WAL")?;
    ensure!(
        (in_memory && journal_mode.eq_ignore_ascii_case("memory"))
            || journal_mode.eq_ignore_ascii_case("wal"),
        "SQLite settlement database did not enter WAL mode"
    );
    connection
        .execute_batch("PRAGMA synchronous = FULL;")
        .context("configure SQLite settlement durability")?;
    let locking_mode: String = connection
        .query_row("PRAGMA locking_mode = EXCLUSIVE", [], |row| row.get(0))
        .context("reserve SQLite settlement ownership")?;
    ensure!(
        locking_mode.eq_ignore_ascii_case("exclusive"),
        "SQLite settlement database did not enter exclusive locking mode"
    );
    connection
        .execute_batch("BEGIN EXCLUSIVE; COMMIT;")
        .context("acquire SQLite settlement ownership")?;
    Ok(())
}

fn initialize_schema(connection: &mut Connection) -> Result<()> {
    let schema = format!(
        "CREATE TABLE settlement_meta (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             schema_version INTEGER NOT NULL,
             deployment BLOB NOT NULL CHECK (length(deployment) = {digest_size})
         );

         CREATE TABLE settlement_log (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             method INTEGER NOT NULL CHECK (method BETWEEN 0 AND 255),
             body BLOB NOT NULL CHECK (length(body) <= {max_body_size}),
             now BLOB NOT NULL CHECK (length(now) = 8)
         );",
        digest_size = Digest::SIZE,
        max_body_size = rpc::MAX_BODY_SIZE,
    );
    let encoded_deployment = deployment().encode();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .context("begin SQLite settlement initialization")?;
    transaction
        .execute_batch(&schema)
        .context("create SQLite settlement schema")?;
    transaction.execute(
        "INSERT INTO settlement_meta(singleton, schema_version, deployment)
         VALUES(1, ?1, ?2)",
        params![SCHEMA_VERSION, encoded_deployment.as_ref()],
    )?;
    transaction
        .commit()
        .map_err(|source| CommitUnknown::new("settlement initialization", source))?;
    Ok(())
}

fn read_binding(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT singleton, schema_version, deployment
         FROM settlement_meta
         ORDER BY singleton
         LIMIT 2",
    )?;
    let mut rows = statement.query([])?;
    let row = rows
        .next()?
        .context("settlement database metadata is missing")?;
    ensure!(
        row.get::<_, i64>(0)? == 1,
        "settlement database metadata singleton is not canonical"
    );
    let schema_version: i64 = row.get(1)?;
    let encoded_deployment: Vec<u8> = row.get(2)?;
    ensure!(
        rows.next()?.is_none(),
        "settlement database has extra metadata rows"
    );

    // A log written by another schema version is refused outright. Replay depends on
    // byte-identical dispatch, so there is no migration path at ALPHA.
    ensure!(
        schema_version == SCHEMA_VERSION,
        "unsupported settlement database schema version {schema_version}"
    );
    let recorded =
        Digest::decode(encoded_deployment.as_slice()).context("decode settlement deployment")?;
    ensure!(
        recorded == deployment(),
        "settlement database belongs to another deployment"
    );
    Ok(())
}

fn read_log(connection: &Connection) -> Result<Vec<Input>> {
    let mut statement =
        connection.prepare("SELECT method, body, now FROM settlement_log ORDER BY sequence")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut inputs = Vec::new();
    for row in rows {
        let (method, body, now) = row?;
        let method = u8::try_from(method).context("settlement log method is out of range")?;
        let now = u64::from_be_bytes(
            now.as_slice()
                .try_into()
                .context("settlement log time has an unexpected length")?,
        );
        inputs.push(Input {
            method,
            body: Bytes::from(body),
            now,
        });
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        protocol::{
            DepositEvent, INITIAL_BALANCE, Key, Protocol, SettlementResult, identities,
            settlement_config,
        },
        settlement::SettlementSubmission,
        settlement_rpc::{
            AdmitRequest, AdmitResponse, BeginHardFaultSettlementRequest,
            BeginHardFaultSettlementResponse, ClaimHardFaultRequest, ClaimHardFaultResponse,
            ClaimPendingDepositRequest, ClaimPendingDepositResponse, ClaimRootsRequest,
            ClaimRootsResponse, HardFaultReasonResponse, METHOD_ADMIT,
            METHOD_BEGIN_HARD_FAULT_SETTLEMENT, METHOD_CLAIM_HARD_FAULT,
            METHOD_CLAIM_PENDING_DEPOSIT, METHOD_CLAIM_ROOTS, METHOD_CONFIRM_DEPOSIT,
            METHOD_DEPOSIT, METHOD_REGISTER_EPOCH, METHOD_STATUS, RegisterEpochRequest,
            StatusResponse,
        },
    };
    use commonware_clearing::bajillion::{
        boundary::{DepositBatch, DepositRecord, WithdrawalBatch},
        credit::ShardSet,
        state::{AccountRow, AccountState, Prefix, SettlementOutput, StateLeaf},
        transition::StateCache,
    };
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_utils::TestRng;
    use std::{
        fs,
        num::NonZeroUsize,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEMP_DATABASE_ID: AtomicU64 = AtomicU64::new(0);

    struct TempDatabase {
        directory: PathBuf,
        database: PathBuf,
    }

    impl TempDatabase {
        fn new() -> Self {
            let id = TEMP_DATABASE_ID.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "commonware-terminal-settlement-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let database = directory.join("settlement.sqlite");
            Self {
                directory,
                database,
            }
        }

        fn path(&self) -> &Path {
            &self.database
        }
    }

    impl Drop for TempDatabase {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn request(method: u8, body: impl Into<Bytes>) -> rpc::Request {
        rpc::Request {
            method,
            body: body.into(),
        }
    }

    fn success_body(response: rpc::Response) -> Bytes {
        match response {
            rpc::Response::Success { body } => body,
            rpc::Response::Error { error } => {
                panic!("unexpected RPC error: {}", String::from_utf8_lossy(&error))
            }
        }
    }

    fn status(store: &mut Store) -> StatusResponse {
        StatusResponse::decode(success_body(
            store.handle(request(METHOD_STATUS, Bytes::new())),
        ))
        .unwrap()
    }

    fn genesis_leaves() -> Vec<StateLeaf<Key>> {
        let mut leaves = identities()
            .into_iter()
            .map(|identity| StateLeaf {
                account: identity.key,
                state: AccountState {
                    balance: INITIAL_BALANCE,
                    active: true,
                    ..AccountState::default()
                },
            })
            .collect::<Vec<_>>();
        leaves.sort_unstable_by(|left, right| left.account.cmp(&right.account));
        leaves
    }

    /// One certified close over a single deposit: the deposit event, its signed epoch
    /// registration, the admit request, and the protocol result the close derives from.
    fn close_fixture() -> (
        DepositEvent,
        RegisterEpochRequest,
        AdmitRequest,
        SettlementResult,
    ) {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let predecessor = genesis_leaves();
        let state = StateCache::new::<Sha256>(predecessor.clone()).unwrap();
        let account = predecessor[0].account.clone();
        let deposit = DepositEvent {
            id: Sha256::hash(&[b"settlement-store-deposit"]),
            account: account.clone(),
            amount: 1,
        };
        let deposits =
            DepositBatch::new(vec![DepositRecord::new(account.clone(), 1).unwrap()]).unwrap();
        let deposits_root = deposits.root::<Sha256>().unwrap();
        let withdrawals = WithdrawalBatch::empty();
        let signature =
            protocol.sign_registration(0, 400, &deposits_root, &deposits_root, &withdrawals);
        let registration_request = RegisterEpochRequest {
            epoch: 0,
            predecessor_liability: 400,
            deposits_root,
            staged_root: deposits_root,
            withdrawals: withdrawals.clone(),
            openings: Vec::new(),
            signature,
        };

        let predecessor_state = predecessor[0].state;
        let successor_state = AccountState {
            balance: predecessor_state.balance + 1,
            ..predecessor_state
        };
        let row = AccountRow {
            account: account.clone(),
            predecessor: predecessor_state,
            successor: successor_state,
            outgoing: None,
            output: SettlementOutput::None,
            prefix: Prefix {
                deposit: 1,
                ..Prefix::default()
            },
        };
        let mut successor = predecessor;
        successor[0].state = successor_state;
        let registration = protocol
            .registration(0, deposits, withdrawals, 400)
            .unwrap();
        let prepared = protocol
            .prepare(
                registration,
                vec![deposit.clone()],
                state.leaves().to_vec(),
                vec![row],
                vec![ShardSet::empty(0, account)],
                successor,
            )
            .unwrap();
        let result = protocol.complete(prepared, &mut TestRng::new(91)).unwrap();
        let admit = AdmitRequest::from(&SettlementSubmission::from(&result));
        (deposit, registration_request, admit, result)
    }

    enum Step {
        Call(u8, Bytes),
        Advance(u64),
    }

    fn apply_step(store: &mut Store, step: &Step) -> Option<rpc::Response> {
        match step {
            Step::Call(method, body) => Some(store.handle(request(*method, body.clone()))),
            Step::Advance(ticks) => {
                store.advance_logical_time(*ticks).unwrap();
                None
            }
        }
    }

    #[test]
    fn reopen_after_every_input_tracks_an_uninterrupted_run() {
        let control_database = TempDatabase::new();
        let interrupted_database = TempDatabase::new();
        let (deposit, registration, admit, result) = close_fixture();
        let lookup = ClaimRootsRequest {
            batch_id: result.finalized.batch_id,
        };
        let steps = [
            Step::Call(METHOD_DEPOSIT, deposit.encode()),
            Step::Call(METHOD_REGISTER_EPOCH, registration.encode()),
            Step::Call(METHOD_ADMIT, admit.encode()),
            Step::Advance(1),
            Step::Call(METHOD_ADMIT, admit.encode()),
            Step::Call(METHOD_CLAIM_ROOTS, lookup.encode()),
            Step::Call(METHOD_CONFIRM_DEPOSIT, deposit.encode()),
        ];

        let mut control = Store::open(control_database.path()).unwrap();
        let mut interrupted = Store::open(interrupted_database.path()).unwrap();
        for step in &steps {
            let expected = apply_step(&mut control, step);
            let answered = apply_step(&mut interrupted, step);
            assert_eq!(answered, expected);

            // Simulate a crash after the answer left. The reopened process must serve
            // the identical state the uninterrupted control run holds.
            drop(interrupted);
            interrupted = Store::open(interrupted_database.path()).unwrap();
            assert_eq!(status(&mut interrupted), status(&mut control));
        }

        let recovered = status(&mut interrupted);
        assert_eq!(recovered.last_finalized, Some(0));
        assert!(!recovered.hard_faulted);
        assert_eq!(recovered.state_root, result.finalized.successor_root);
        let roots = Option::<ClaimRootsResponse>::decode(success_body(
            interrupted.handle(request(METHOD_CLAIM_ROOTS, lookup.encode())),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(roots.withdrawal_outputs, result.roots.withdrawal_outputs);
        assert_eq!(roots.change, result.roots.change);
    }

    #[test]
    fn commit_without_response_replays_the_idempotent_answer() {
        let database = TempDatabase::new();
        let (deposit, registration, admit, result) = close_fixture();
        let challenge_deadline = result.epoch_context.challenge_deadline();

        // Deposit: custody committed but the response was lost.
        let mut store = Store::open(database.path()).unwrap();
        assert!(success_body(store.handle(request(METHOD_DEPOSIT, deposit.encode()))).is_empty());
        drop(store);
        let mut store = Store::open(database.path()).unwrap();
        assert!(success_body(store.handle(request(METHOD_DEPOSIT, deposit.encode()))).is_empty());
        assert_eq!(status(&mut store).custody_balance, 401);

        // Registration: the slot committed but the response was lost.
        assert!(
            success_body(store.handle(request(METHOD_REGISTER_EPOCH, registration.encode())))
                .is_empty()
        );
        drop(store);
        let mut store = Store::open(database.path()).unwrap();
        assert!(
            success_body(store.handle(request(METHOD_REGISTER_EPOCH, registration.encode())))
                .is_empty()
        );

        // Admission: the certified close committed but the response was lost.
        let first = store.handle(request(METHOD_ADMIT, admit.encode()));
        assert_eq!(
            AdmitResponse::decode(success_body(first.clone())).unwrap(),
            AdmitResponse::Pending
        );
        drop(store);
        let mut store = Store::open(database.path()).unwrap();
        let retry = store.handle(request(METHOD_ADMIT, admit.encode()));
        assert_eq!(retry, first);
        let admitted = status(&mut store);
        assert_eq!(admitted.now, challenge_deadline);
        assert_eq!(admitted.custody_balance, 401);
        assert_eq!(admitted.last_finalized, None);
    }

    #[test]
    fn hard_fault_and_released_claims_replay_into_the_identical_state() {
        let database = TempDatabase::new();
        let cache = StateCache::new::<Sha256>(genesis_leaves()).unwrap();
        let account = identities()[0].key.clone();
        let deposit = DepositEvent {
            id: Sha256::hash(&[b"settlement-store-fault-deposit"]),
            account: account.clone(),
            amount: 7,
        };
        let deadline = settlement_config().deposit_inclusion_timeout.get();

        let mut store = Store::open(database.path()).unwrap();
        success_body(store.handle(request(METHOD_DEPOSIT, deposit.encode())));
        store.advance_logical_time(deadline).unwrap();

        let begin_request = BeginHardFaultSettlementRequest.encode();
        let begin = BeginHardFaultSettlementResponse::decode(success_body(store.handle(request(
            METHOD_BEGIN_HARD_FAULT_SETTLEMENT,
            begin_request.clone(),
        ))))
        .unwrap();
        assert_eq!(
            begin.reason,
            HardFaultReasonResponse::ExpiredDeposit {
                account: account.clone(),
                expired_at: deadline,
            }
        );
        let claim_request = ClaimHardFaultRequest {
            opening: cache.opening(&account).unwrap(),
        };
        let claim = ClaimHardFaultResponse::decode(success_body(
            store.handle(request(METHOD_CLAIM_HARD_FAULT, claim_request.encode())),
        ))
        .unwrap();
        assert_eq!(claim.released_custody, INITIAL_BALANCE);
        let refund_request = ClaimPendingDepositRequest { account };
        let refund = ClaimPendingDepositResponse::decode(success_body(store.handle(request(
            METHOD_CLAIM_PENDING_DEPOSIT,
            refund_request.encode(),
        ))))
        .unwrap();
        assert_eq!(refund.amount, 7);
        let live = status(&mut store);
        assert!(live.hard_faulted);
        assert_eq!(live.now, deadline);
        assert_eq!(live.state_root, begin.frozen_state_root);
        assert_eq!(live.custody_balance, 300);

        // The replayed log lands in the identical hard-fault state, and every recorded
        // release answers its retry unchanged.
        drop(store);
        let mut store = Store::open(database.path()).unwrap();
        assert_eq!(status(&mut store), live);
        assert_eq!(
            BeginHardFaultSettlementResponse::decode(success_body(
                store.handle(request(METHOD_BEGIN_HARD_FAULT_SETTLEMENT, begin_request)),
            ))
            .unwrap(),
            begin
        );
        assert_eq!(
            ClaimHardFaultResponse::decode(success_body(
                store.handle(request(METHOD_CLAIM_HARD_FAULT, claim_request.encode())),
            ))
            .unwrap(),
            claim
        );
        assert_eq!(
            ClaimPendingDepositResponse::decode(success_body(store.handle(request(
                METHOD_CLAIM_PENDING_DEPOSIT,
                refund_request.encode(),
            ))))
            .unwrap(),
            refund
        );
    }

    #[test]
    fn rejected_time_advancing_call_replays_its_fault() {
        let database = TempDatabase::new();
        let account = identities()[0].key.clone();
        let staged = DepositEvent {
            id: Sha256::hash(&[b"settlement-store-staged-deposit"]),
            account: account.clone(),
            amount: 7,
        };
        let late = DepositEvent {
            id: Sha256::hash(&[b"settlement-store-late-deposit"]),
            account: account.clone(),
            amount: 9,
        };
        let deadline = settlement_config().deposit_inclusion_timeout.get();

        let mut store = Store::open(database.path()).unwrap();
        success_body(store.handle(request(METHOD_DEPOSIT, staged.encode())));

        // The late deposit arrives after the staged deposit's inclusion deadline
        // lapsed. Observing that time records the permanent fault before the intake is
        // rejected, and the rejected call is logged because it advanced time.
        let error = store
            .apply_at(deadline, request(METHOD_DEPOSIT, late.encode()))
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("record custody deposit"),
            "unexpected error: {error:#}"
        );
        let live = status(&mut store);
        assert!(live.hard_faulted);
        assert_eq!(live.now, deadline);
        assert_eq!(live.custody_balance, 407);

        drop(store);
        let mut store = Store::open(database.path()).unwrap();
        assert_eq!(status(&mut store), live);
        let begin = BeginHardFaultSettlementResponse::decode(success_body(store.handle(request(
            METHOD_BEGIN_HARD_FAULT_SETTLEMENT,
            BeginHardFaultSettlementRequest.encode(),
        ))))
        .unwrap();
        assert_eq!(
            begin.reason,
            HardFaultReasonResponse::ExpiredDeposit {
                account,
                expired_at: deadline,
            }
        );
        assert_eq!(begin.unfinalized_deposit_total, 7);
    }

    #[test]
    fn ephemeral_store_serves_without_a_file() {
        let mut store = Store::open(Path::new(":memory:")).unwrap();
        assert_eq!(status(&mut store).custody_balance, 400);
    }

    #[test]
    fn another_schema_version_is_refused() {
        let database = TempDatabase::new();
        drop(Store::open(database.path()).unwrap());
        {
            let connection = rusqlite::Connection::open(database.path()).unwrap();
            connection
                .execute(
                    "UPDATE settlement_meta SET schema_version = ?1",
                    [SCHEMA_VERSION + 1],
                )
                .unwrap();
        }

        let error = match Store::open(database.path()) {
            Ok(_) => panic!("another schema version was accepted"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("unsupported settlement database schema version"),
            "unexpected error: {error:#}"
        );
    }
}
