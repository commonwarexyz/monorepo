//! Serial ownership of the operator's native balance proofs.

use super::{
    actor::{registration_for, replica_terminals},
    store::EpochReader,
};
use crate::protocol::{Account, Key, Protocol, state_config};
use anyhow::{Context as _, Result, ensure};
use commonware_clearing::bajillion::{
    qmdb::{Config, Mutations, PreparedState, State, StateOpening, StateRoot, account_key},
    settlement::Genesis,
    transition::prepare_close_with_strategy,
};
use commonware_codec::{DecodeExt as _, Encode};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Rayon;
use commonware_runtime::{Runner as _, Spawner, tokio};
use commonware_storage::Context;
use rusqlite::{Connection, params};
use std::{
    num::NonZeroU64,
    path::{Path, PathBuf},
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender, SyncSender},
    },
    thread::{self, JoinHandle},
};

type Reply<T> = SyncSender<Result<T>>;

#[derive(Debug, thiserror::Error)]
#[error("balance storage is unavailable; restart the operator: {0:#}")]
pub(crate) struct Unavailable(anyhow::Error);

fn unavailable(error: impl Into<anyhow::Error>) -> anyhow::Error {
    Unavailable(error.into()).into()
}

pub(super) fn classify(error: anyhow::Error) -> anyhow::Error {
    if error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(..))
        ) || matches!(
            cause.downcast_ref::<commonware_clearing::bajillion::qmdb::Error>(),
            Some(commonware_clearing::bajillion::qmdb::Error::Storage(_))
        )
    }) {
        unavailable(error)
    } else {
        error
    }
}

enum Request {
    Root(u64, Reply<StateRoot<Digest>>),
    Opening(u64, Key, Reply<StateOpening<Key, Digest>>),
    CatchUp(Option<Reply<()>>),
    #[cfg(test)]
    PauseNext(Reply<(Receiver<()>, SyncSender<()>)>),
    #[cfg(test)]
    StartupWork(Reply<(Vec<u64>, Vec<u64>)>),
}

struct Owner {
    // The SQL source owns ephemeral paths and outlives the joined balance worker.
    _source: EpochReader,
    sender: Option<Sender<Request>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Clone)]
pub(crate) struct Handle(Arc<Owner>);

impl Handle {
    pub(crate) fn open(
        path: &Path,
        accounts: &[Account],
        protocol: Arc<Protocol>,
        source: EpochReader,
        configured: Option<Genesis<Digest>>,
    ) -> Result<Self> {
        let mut directory = path.as_os_str().to_owned();
        directory.push(".qmdb");
        let directory = PathBuf::from(directory);
        std::fs::create_dir_all(&directory)?;
        let connection = source.proof_connection()?;
        let mut allocations = accounts
            .iter()
            .map(|account| (account.key.clone(), account.balance))
            .collect::<Vec<_>>();
        allocations.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let matches: bool = connection.query_row(
            "SELECT genesis_accounts = ?1 FROM operator_meta WHERE singleton = 1",
            [allocations.encode().as_ref()],
            |row| row.get(0),
        )?;
        ensure!(matches, "balance history has the wrong genesis allocations");
        let mut genesis = accounts
            .iter()
            .filter_map(|account| {
                NonZeroU64::new(account.balance).map(|balance| (account, balance))
            })
            .map(|(account, balance)| Ok((account_key(&account.key)?, Some(balance))))
            .collect::<Result<Mutations>>()?;
        genesis.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let (sender, receiver) = mpsc::channel();
        let (ready, started) = mpsc::sync_channel(1);
        let worker_source = source.clone();
        let thread = thread::Builder::new()
            .name("terminal-balances".into())
            .spawn(move || {
                let runner =
                    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory));
                runner.start(|context| {
                    run(
                        context,
                        protocol,
                        worker_source,
                        connection,
                        genesis,
                        configured,
                        receiver,
                        ready,
                    )
                });
            })?;
        if let Err(error) = started
            .recv()
            .context("balance worker stopped during initialization")
            .and_then(|result| result)
        {
            let _ = thread.join();
            return Err(error);
        }
        Ok(Self(Arc::new(Owner {
            _source: source,
            sender: Some(sender),
            thread: Some(thread),
        })))
    }

    fn request<T>(&self, request: impl FnOnce(Reply<T>) -> Request) -> Result<T> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.0
            .sender
            .as_ref()
            .unwrap()
            .send(request(reply))
            .map_err(|_| unavailable(anyhow::anyhow!("balance worker stopped")))?;
        receiver
            .recv()
            .map_err(|error| unavailable(anyhow::anyhow!(error)))?
            .map_err(classify)
    }

    pub(crate) fn root(&self, epoch: u64) -> Result<StateRoot<Digest>> {
        self.request(|reply| Request::Root(epoch, reply))
    }

    pub(crate) fn opening(&self, epoch: u64, key: &Key) -> Result<StateOpening<Key, Digest>> {
        self.request(|reply| Request::Opening(epoch, key.clone(), reply))
    }

    #[cfg(test)]
    pub(crate) fn catch_up(&self) -> Result<()> {
        self.request(|reply| Request::CatchUp(Some(reply)))
    }

    pub(crate) fn notify(&self) {
        let _ = self.0.sender.as_ref().unwrap().send(Request::CatchUp(None));
    }

    #[cfg(test)]
    pub(crate) fn pause_next_catch_up(&self) -> Result<(Receiver<()>, SyncSender<()>)> {
        self.request(Request::PauseNext)
    }

    #[cfg(test)]
    pub(crate) fn startup_work(&self) -> Result<(Vec<u64>, Vec<u64>)> {
        self.request(Request::StartupWork)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    context: tokio::Context,
    protocol: Arc<Protocol>,
    source: EpochReader,
    connection: Connection,
    genesis: Mutations,
    configured: Option<Genesis<Digest>>,
    receiver: Receiver<Request>,
    ready: Reply<()>,
) {
    #[cfg(test)]
    let mut recovery = Recovery::default();
    let initialized: Result<_> = async {
        initialize_checkpoints(&connection)?;
        let config = state_config("operator-balances", &context, protocol.strategy().clone());
        let state = recover(
            context,
            config,
            &connection,
            genesis,
            configured,
            #[cfg(test)]
            &mut recovery,
        )
        .await?;
        catch_up(
            state,
            &protocol,
            &source,
            &connection,
            #[cfg(test)]
            &mut recovery,
        )
        .await
    }
    .await;
    let mut state = match initialized {
        Ok(state) => {
            let _ = ready.send(Ok(()));
            state
        }
        Err(error) => {
            source.fence_storage_failure(&error);
            let _ = ready.send(Err(unavailable(error)));
            return;
        }
    };
    #[cfg(test)]
    let startup_work = (recovery.prepared.clone(), recovery.applied.clone());
    while let Ok(request) = receiver.recv() {
        #[cfg(test)]
        match &request {
            Request::StartupWork(reply) => {
                let _ = reply.send(Ok(startup_work.clone()));
                continue;
            }
            Request::PauseNext(reply) => {
                let (started, waiting) = mpsc::sync_channel(1);
                let (release, resume) = mpsc::sync_channel(1);
                recovery.gate = Some((started, resume));
                let _ = reply.send(Ok((waiting, release)));
                continue;
            }
            _ => {}
        }
        state = match async {
            let advance = match &request {
                Request::Root(epoch, _) | Request::Opening(epoch, _, _) => {
                    *epoch > sequence(&connection, &state)?
                }
                _ => true,
            };
            if advance {
                catch_up(
                    state,
                    &protocol,
                    &source,
                    &connection,
                    #[cfg(test)]
                    &mut recovery,
                )
                .await
            } else {
                Ok(state)
            }
        }
        .await
        {
            Ok(state) => state,
            Err(error) => {
                source.fence_storage_failure(&error);
                match request {
                    Request::Root(_, reply) => {
                        let _ = reply.send(Err(unavailable(error)));
                    }
                    Request::Opening(_, _, reply) => {
                        let _ = reply.send(Err(unavailable(error)));
                    }
                    Request::CatchUp(Some(reply)) => {
                        let _ = reply.send(Err(unavailable(error)));
                    }
                    _ => {}
                }
                return;
            }
        };
        match request {
            Request::Root(epoch, reply) => {
                let _ = reply.send(checkpoint(&connection, epoch).map(|(root, _)| root));
            }
            Request::Opening(epoch, key, reply) => {
                let result = match checkpoint(&connection, epoch) {
                    Ok((root, operations)) => state
                        .opening_at(root, operations, key)
                        .await
                        .map_err(Into::into),
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Request::CatchUp(Some(reply)) => {
                let _ = reply.send(Ok(()));
            }
            Request::CatchUp(None) => {}
            #[cfg(test)]
            _ => unreachable!(),
        }
    }
}

fn initialize_checkpoints(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS proof_checkpoints (
             sequence INTEGER PRIMARY KEY CHECK(sequence >= 0),
             root BLOB NOT NULL CHECK(length(root) = 32),
             operations INTEGER NOT NULL CHECK(operations > 0)
         );
         CREATE UNIQUE INDEX IF NOT EXISTS proof_checkpoint_head
             ON proof_checkpoints(root, operations);",
    )?;
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryCut {
    Checkpoint,
    Applied,
    Committed,
}

#[cfg(test)]
#[derive(Default)]
struct Recovery {
    prepared: Vec<u64>,
    applied: Vec<u64>,
    cut: Option<RecoveryCut>,
    gate: Option<(SyncSender<()>, Receiver<()>)>,
}

#[cfg(test)]
impl Recovery {
    fn stop(&self, cut: RecoveryCut) -> Result<()> {
        ensure!(self.cut != Some(cut), "injected recovery cut: {cut:?}");
        Ok(())
    }
}

async fn recover<E: Context + Spawner>(
    context: E,
    config: Config<Rayon>,
    connection: &Connection,
    genesis: Mutations,
    configured: Option<Genesis<Digest>>,
    #[cfg(test)] recovery: &mut Recovery,
) -> Result<State<E, Sha256, Rayon>> {
    if let Some(configured) = configured {
        let liability = genesis.iter().try_fold(0u64, |total, (_, balance)| {
            total
                .checked_add(balance.map_or(0, NonZeroU64::get))
                .context("genesis liability overflow")
        })?;
        ensure!(
            liability == configured.liability(),
            "configured genesis liability mismatch"
        );
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM proof_checkpoints WHERE sequence = 0)",
            [],
            |row| row.get(0),
        )?;
        if exists {
            ensure!(
                checkpoint(connection, 0)? == (configured.root(), configured.operations()),
                "configured genesis commitment mismatch"
            );
        }
    }
    let state = State::open(context, config).await?;
    if state.is_bootstrap() {
        #[cfg(test)]
        recovery.prepared.push(0);
        let candidate = state.prepare(state.head(), genesis).await?;
        if let Some(configured) = configured {
            ensure!(
                candidate.root() == configured.root()
                    && candidate.head().operations() == configured.operations(),
                "configured genesis commitment mismatch"
            );
        }
        return apply_checkpoint(
            connection,
            0,
            state,
            candidate,
            #[cfg(test)]
            recovery,
        )
        .await;
    }
    // Recovery may find a complete apply that survived without its caller's commit.
    // Sync that exact prefix before its SQL reconstruction inputs can be retired.
    sequence(connection, &state)?;
    Ok(state.commit().await?)
}

async fn catch_up<E: Context + Spawner>(
    mut state: State<E, Sha256, Rayon>,
    protocol: &Protocol,
    source: &EpochReader,
    connection: &Connection,
    #[cfg(test)] recovery: &mut Recovery,
) -> Result<State<E, Sha256, Rayon>> {
    let mut applied = sequence(connection, &state)?;
    let latest: Option<i64> = connection.query_row(
        "SELECT MAX(epoch) FROM close_jobs WHERE result IS NOT NULL",
        [],
        |row| row.get(0),
    )?;
    let latest = latest.map(u64::try_from).transpose()?;
    source.prune_proof_inputs(applied)?;
    while latest.is_some_and(|latest| applied <= latest) {
        let result = source
            .stored_result(applied)?
            .context("certified balance result prefix has a gap")?;
        #[cfg(test)]
        if let Some((started, release)) = recovery.gate.take() {
            let _ = started.send(());
            release.recv().context("proof catch-up gate dropped")?;
        }
        let data = source.load(applied)?;
        let registration = registration_for(protocol, &data)?;
        let terminals = replica_terminals(protocol, &data)?;
        let context = registration.context.bind::<Sha256, _, _>(
            &state,
            &registration.deposits,
            &registration.withdrawals,
        )?;
        ensure!(
            context == result.context,
            "certified close context mismatch"
        );
        #[cfg(test)]
        recovery.prepared.push(applied + 1);
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &state,
            &context,
            &registration.deposits,
            &registration.withdrawals,
            terminals,
            protocol.strategy(),
        )
        .await?;
        let (close, candidate) = prepared.into_parts();
        ensure!(
            close.header == result.header
                && close.roots == result.roots
                && close.withdrawal_total == result.withdrawal_total
                && candidate.root() == result.roots.successor,
            "certified close differs from locally derived native state"
        );
        applied = applied.checked_add(1).context("epoch overflow")?;
        state = apply_checkpoint(
            connection,
            applied,
            state,
            candidate,
            #[cfg(test)]
            recovery,
        )
        .await?;
        source.prune_proof_inputs(applied)?;
    }
    let ahead: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM proof_checkpoints WHERE sequence > ?1)",
        [i64::try_from(applied)?],
        |row| row.get(0),
    )?;
    ensure!(!ahead, "balance checkpoint has no certified result");
    Ok(state)
}

fn sequence<E: Context + Spawner>(
    connection: &Connection,
    state: &State<E, Sha256, Rayon>,
) -> Result<u64> {
    let sequence: i64 = connection
        .query_row(
            "SELECT sequence FROM proof_checkpoints WHERE root = ?1 AND operations = ?2",
            params![
                state.root().encode().as_ref(),
                i64::try_from(state.head().operations())?
            ],
            |row| row.get(0),
        )
        .context("native balance head has no accepted checkpoint")?;
    u64::try_from(sequence).context("negative balance checkpoint sequence")
}

fn checkpoint(connection: &Connection, epoch: u64) -> Result<(StateRoot<Digest>, u64)> {
    let (bytes, operations): (Vec<u8>, i64) = connection
        .query_row(
            "SELECT root, operations FROM proof_checkpoints WHERE sequence = ?1",
            [i64::try_from(epoch).context("epoch exceeds SQLite range")?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("the predecessor balance root is not available yet")?;
    Ok((
        StateRoot::decode(bytes).context("decode retained balance root")?,
        u64::try_from(operations).context("negative balance checkpoint operation count")?,
    ))
}

fn record(
    connection: &Connection,
    sequence: u64,
    candidate: &PreparedState<Digest, Rayon>,
) -> Result<()> {
    connection.execute(
        "INSERT INTO proof_checkpoints(sequence, root, operations) VALUES(?1, ?2, ?3)
         ON CONFLICT(sequence) DO NOTHING",
        params![
            i64::try_from(sequence)?,
            candidate.root().encode().as_ref(),
            i64::try_from(candidate.head().operations())?,
        ],
    )?;
    ensure!(
        checkpoint(connection, sequence)? == (candidate.root(), candidate.head().operations()),
        "retained balance checkpoint mismatch"
    );
    Ok(())
}

async fn apply_checkpoint<E: Context + Spawner>(
    connection: &Connection,
    sequence: u64,
    state: State<E, Sha256, Rayon>,
    candidate: PreparedState<Digest, Rayon>,
    #[cfg(test)] recovery: &mut Recovery,
) -> Result<State<E, Sha256, Rayon>> {
    // The identity is durable before native writes; the owning close result and retained SQL
    // activity reconstruct this candidate if those writes do not survive a crash.
    record(connection, sequence, &candidate)?;
    #[cfg(test)]
    recovery.stop(RecoveryCut::Checkpoint)?;
    #[cfg(test)]
    recovery.applied.push(sequence);
    let state = state.apply(candidate).await?;
    #[cfg(test)]
    recovery.stop(RecoveryCut::Applied)?;
    let state = state.commit().await?;
    #[cfg(test)]
    recovery.stop(RecoveryCut::Committed)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        operator::store::Store,
        protocol::{Ack, INITIAL_BALANCE, SettlementResult, identities, wallets},
    };
    use bytes::Bytes;
    use commonware_clearing::bajillion::{
        boundary::{DepositBatch, WithdrawalBatch},
        qmdb::AccountKey,
    };
    use commonware_codec::FixedSize as _;
    use commonware_runtime::{Supervisor as _, deterministic};
    use std::num::NonZeroUsize;

    fn genesis() -> Mutations {
        vec![(AccountKey::new([1; 32]), NonZeroU64::new(100))]
    }

    fn checkpoints() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        initialize_checkpoints(&connection).unwrap();
        connection
    }

    #[test]
    fn genesis_checkpoint_precedes_apply_and_surviving_apply_is_not_repeated() {
        for cut in [
            RecoveryCut::Checkpoint,
            RecoveryCut::Applied,
            RecoveryCut::Committed,
        ] {
            deterministic::Runner::default().start(|context| async move {
                let mut config = state_config(
                    "bootstrap-cut",
                    &context,
                    Rayon::new(NonZeroUsize::MIN).unwrap(),
                );
                if cut == RecoveryCut::Applied {
                    config.journal_config.items_per_blob = NonZeroU64::MIN;
                    config.merkle_config.items_per_blob = NonZeroU64::MIN;
                }
                let connection = checkpoints();
                let mut trace = Recovery {
                    cut: Some(cut),
                    ..Recovery::default()
                };
                let error = recover(
                    context.child("cut"),
                    config.clone(),
                    &connection,
                    genesis(),
                    None,
                    &mut trace,
                )
                .await
                .err()
                .unwrap();
                assert!(format!("{error:#}").contains("injected recovery cut"));
                assert_eq!(trace.prepared, [0]);
                let expected = checkpoint(&connection, 0).unwrap();
                let native =
                    State::<_, Sha256, Rayon>::open(context.child("inspect"), config.clone())
                        .await
                        .unwrap();
                let missing = native.is_bootstrap();
                assert_eq!(missing, cut == RecoveryCut::Checkpoint);
                drop(native);
                let mut trace = Recovery::default();
                let state = recover(
                    context.child("recovered"),
                    config,
                    &connection,
                    genesis(),
                    None,
                    &mut trace,
                )
                .await
                .unwrap();
                let work = if missing { vec![0] } else { vec![] };
                assert_eq!(trace.prepared, work);
                assert_eq!(trace.applied, work);
                assert_eq!((state.root(), state.head().operations()), expected);
                assert_eq!(state.liability(), 100);
                assert_eq!(state.live_accounts(), 1);
                assert_eq!(
                    connection
                        .query_row("SELECT count(*) FROM proof_checkpoints", [], |row| row
                            .get::<_, i64>(0))
                        .unwrap(),
                    1
                );
            });
        }
    }

    fn retain(connection: &Connection, result: &SettlementResult) {
        connection
            .execute(
                "INSERT INTO close_jobs(epoch, status, payment_context, result)
                 VALUES(?1, 'closing', ?2, ?3)",
                params![
                    i64::try_from(result.context.payment().epoch()).unwrap(),
                    result.context.payment().encode().as_ref(),
                    result.encode().as_ref(),
                ],
            )
            .unwrap();
    }

    #[test]
    fn restart_derives_only_missing_result_suffix_from_sql_activity() {
        let protocol = Protocol::new(NonZeroUsize::MIN).unwrap();
        let identities = identities();
        let accounts = identities
            .iter()
            .map(|identity| Account {
                key: identity.key.clone(),
                balance: INITIAL_BALANCE,
            })
            .collect::<Vec<_>>();
        let mut genesis = accounts
            .iter()
            .map(|account| {
                (
                    account_key(&account.key).unwrap(),
                    NonZeroU64::new(account.balance),
                )
            })
            .collect::<Mutations>();
        genesis.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let configured = protocol.fixture_genesis(&accounts).unwrap();
        let mut results = Vec::new();
        for epoch in 0..2 {
            let registration = protocol
                .registration(
                    epoch,
                    DepositBatch::empty(),
                    WithdrawalBatch::empty(),
                    configured.liability(),
                )
                .unwrap();
            let prepared = protocol.prepare(registration, Vec::new()).unwrap();
            results.push(
                protocol
                    .fixture_complete(&accounts, &results, prepared, epoch)
                    .unwrap(),
            );
        }
        for cut in [
            RecoveryCut::Checkpoint,
            RecoveryCut::Applied,
            RecoveryCut::Committed,
        ] {
            let store = Store::in_memory(&identities).unwrap();
            let source = store.epoch_reader();
            let connection = source.proof_connection().unwrap();
            initialize_checkpoints(&connection).unwrap();
            let protocol = protocol.clone();
            let accounts = accounts.clone();
            let genesis = genesis.clone();
            let results = results.clone();
            deterministic::Runner::default().start(|context| async move {
                let mut config = state_config("suffix", &context, protocol.strategy().clone());
                if cut == RecoveryCut::Applied {
                    config.journal_config.items_per_blob = NonZeroU64::MIN;
                    config.merkle_config.items_per_blob = NonZeroU64::MIN;
                }
                let state = recover(
                    context.child("genesis"),
                    config.clone(),
                    &connection,
                    genesis.clone(),
                    Some(configured),
                    &mut Recovery::default(),
                )
                .await
                .unwrap();
                let mut result = results[0].clone();
                result.evidence = Bytes::from_static(b"untrusted evidence metadata");
                retain(&connection, &result);
                let mut trace = Recovery {
                    cut: Some(cut),
                    ..Recovery::default()
                };
                let error = catch_up(state, &protocol, &source, &connection, &mut trace)
                    .await
                    .err()
                    .unwrap();
                assert!(format!("{error:#}").contains("injected recovery cut"));
                assert_eq!(trace.prepared, [1]);
                let native =
                    State::<_, Sha256, Rayon>::open(context.child("inspect"), config.clone())
                        .await
                        .unwrap();
                let survived = sequence(&connection, &native).unwrap() == 1;
                assert_eq!(survived, cut != RecoveryCut::Checkpoint);
                drop(native);
                if survived {
                    // Applied activity is deliberately undecodable, so replaying its epoch fails.
                    connection
                        .execute(
                            "INSERT INTO acks(epoch,payer,seq,cumulative_debit,ack)
                         VALUES(0,?1,1,1,zeroblob(?2))",
                            params![
                                accounts[0].key.encode().as_ref(),
                                i64::try_from(Ack::SIZE).unwrap()
                            ],
                        )
                        .unwrap();
                    assert!(source.load(0).is_err());
                }
                retain(&connection, &results[1]);
                let mut trace = Recovery::default();
                let state = recover(
                    context.child("recover"),
                    config.clone(),
                    &connection,
                    genesis.clone(),
                    Some(configured),
                    &mut trace,
                )
                .await
                .unwrap();
                let state = catch_up(state, &protocol, &source, &connection, &mut trace)
                    .await
                    .unwrap();
                let expected = if survived { vec![2] } else { vec![1, 2] };
                assert_eq!(trace.prepared, expected);
                assert_eq!(trace.applied, expected);
                assert_eq!(state.root(), results[1].roots.successor);
                assert_eq!(sequence(&connection, &state).unwrap(), 2);
                drop(state);
                // Applied result blobs are deliberately undecodable; checkpoint identities own restart.
                connection
                    .execute("UPDATE close_jobs SET result = x'ff' WHERE epoch < 2", [])
                    .unwrap();
                let mut trace = Recovery::default();
                let state = recover(
                    context.child("current"),
                    config,
                    &connection,
                    genesis.clone(),
                    Some(configured),
                    &mut trace,
                )
                .await
                .unwrap();
                let state = catch_up(state, &protocol, &source, &connection, &mut trace)
                    .await
                    .unwrap();
                assert!(trace.prepared.is_empty());
                assert!(trace.applied.is_empty());
                let (root, operations) = checkpoint(&connection, 0).unwrap();
                let opening = state
                    .opening_at(root, operations, accounts[0].key.clone())
                    .await
                    .unwrap();
                assert_eq!(
                    opening.verify::<Sha256>(&root).unwrap().get(),
                    INITIAL_BALANCE
                );
            });
        }
    }

    #[test]
    fn configured_genesis_mismatch_cannot_publish_or_reopen_native_state() {
        for changed in 0..3 {
            deterministic::Runner::default().start(|context| async move {
                let config = state_config(
                    "configured",
                    &context,
                    Rayon::new(NonZeroUsize::MIN).unwrap(),
                );
                let state =
                    State::<_, Sha256, Rayon>::open(context.child("derive"), config.clone())
                        .await
                        .unwrap();
                let candidate = state.prepare(state.head(), genesis()).await.unwrap();
                let expected = Genesis::from(candidate.head());
                let wrong = Genesis::new(
                    if changed == 0 {
                        state.root()
                    } else {
                        expected.root()
                    },
                    expected.operations() + u64::from(changed == 1),
                    &[(
                        AccountKey::new([1; 32]),
                        NonZeroU64::new(100 + u64::from(changed == 2)).unwrap(),
                    )],
                )
                .unwrap();
                drop(candidate);
                drop(state);
                let connection = checkpoints();
                for (configured, succeeds) in [(wrong, false), (expected, true), (wrong, false)] {
                    let mut trace = Recovery::default();
                    let result = recover(
                        context.child("attempt"),
                        config.clone(),
                        &connection,
                        genesis(),
                        Some(configured),
                        &mut trace,
                    )
                    .await;
                    if succeeds {
                        assert_eq!(result.unwrap().root(), expected.root());
                    } else {
                        let error = result.err().unwrap();
                        assert!(format!("{error:#}").contains("configured genesis"));
                        assert!(trace.applied.is_empty());
                    }
                }
            });
        }
    }

    #[test]
    fn historical_openings_survive_later_bitmap_chunks_and_native_restart() {
        deterministic::Runner::default().start(|context| async move {
            let config = state_config(
                "historical",
                &context,
                Rayon::new(NonZeroUsize::MIN).unwrap(),
            );
            let account = wallets().remove(0).public_key();
            let key = account_key(&account).unwrap();
            let genesis = vec![(key.clone(), NonZeroU64::new(100))];
            let connection = checkpoints();
            let mut state = recover(
                context.child("genesis"),
                config.clone(),
                &connection,
                genesis.clone(),
                None,
                &mut Recovery::default(),
            )
            .await
            .unwrap();
            for sequence in 1..=160 {
                let candidate = state
                    .prepare(
                        state.head(),
                        vec![(key.clone(), NonZeroU64::new(100 + sequence))],
                    )
                    .await
                    .unwrap();
                state = apply_checkpoint(
                    &connection,
                    sequence,
                    state,
                    candidate,
                    &mut Recovery::default(),
                )
                .await
                .unwrap();
            }
            drop(state);
            let mut trace = Recovery::default();
            let state = recover(
                context.child("recovered"),
                config,
                &connection,
                genesis,
                None,
                &mut trace,
            )
            .await
            .unwrap();
            assert!(trace.prepared.is_empty());
            assert!(trace.applied.is_empty());
            assert!(state.head().operations() > 256);
            for sequence in [0, 1, 31, 32, 127, 128, 159, 160] {
                let (root, operations) = checkpoint(&connection, sequence).unwrap();
                let opening = state
                    .opening_at(root, operations, account.clone())
                    .await
                    .unwrap();
                assert_eq!(
                    opening.verify::<Sha256>(&root).unwrap().get(),
                    100 + sequence
                );
            }
            assert_eq!(state.liability(), 260);
        });
    }
}
