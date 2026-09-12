//! Serial ownership of the operator's durable balance database.

use super::store::{EpochData, EpochReader};
use crate::protocol::{
    AccountIdentity, EpochRegistration, INITIAL_BALANCE, Key, MAX_ACCOUNTS, PreparedEpoch,
    Protocol, SettlementResult, state_config,
};
use anyhow::{Context as _, Result, ensure};
use commonware_clearing::bajillion::{
    qmdb::{Config, Mutations, PreparedState, State, StateOpening, StateRoot, account_key},
    settlement::Genesis,
    transition::{Close, CloseContext},
};
use commonware_codec::{Decode as _, DecodeExt as _, Encode, RangeCfg};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Rayon;
use commonware_runtime::{Runner as _, Spawner, tokio};
use commonware_storage::Context;
use rusqlite::{Connection, OptionalExtension as _, params};
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
type Database = State<tokio::Context, Sha256, Rayon>;

#[derive(Debug, thiserror::Error)]
#[error("balance storage is unavailable; restart the operator: {0:#}")]
pub(crate) struct Unavailable(anyhow::Error);

fn unavailable(error: impl Into<anyhow::Error>) -> anyhow::Error {
    Unavailable(error.into()).into()
}

pub(super) fn classify(error: anyhow::Error) -> anyhow::Error {
    let storage_failure = error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<rusqlite::Error>(),
            Some(rusqlite::Error::SqliteFailure(..))
        ) || matches!(
            cause.downcast_ref::<commonware_clearing::bajillion::qmdb::Error>(),
            Some(commonware_clearing::bajillion::qmdb::Error::Storage(_))
        )
    });
    if storage_failure {
        unavailable(error)
    } else {
        error
    }
}

enum Request {
    Root(u64, Reply<StateRoot<Digest>>),
    Opening(u64, Key, Reply<StateOpening<Key, Digest>>),
    Prepare(Box<(EpochData, EpochRegistration)>, Reply<PreparedEpoch>),
    Complete(Box<PreparedEpoch>, u64, Reply<SettlementResult>),
    Apply(
        Box<(SettlementResult, PreparedState<Digest, Rayon>)>,
        Reply<SettlementResult>,
    ),
    Result(u64, Reply<Option<SettlementResult>>),
    Evidence(u64, Reply<(CloseContext<Key, Digest>, Close<Key, Digest>)>),
    Check(u64, Vec<(Key, u64)>, Reply<()>),
    #[cfg(test)]
    FailAfterJournal(Reply<()>),
    #[cfg(test)]
    FailRead(Reply<()>),
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
        identities: &[AccountIdentity],
        protocol: Arc<Protocol>,
        source: EpochReader,
        configured: Option<Genesis<Digest>>,
    ) -> Result<Self> {
        let directory = path.with_extension("qmdb");
        std::fs::create_dir_all(&directory)?;
        let journal_path = directory.join("history.sqlite");
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("owner.lock"))?;
        lock.try_lock()
            .context("another operator owns this balance database")?;
        let mut genesis = identities
            .iter()
            .map(|identity| {
                Ok((
                    account_key(&identity.key)?,
                    NonZeroU64::new(INITIAL_BALANCE).unwrap(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        genesis.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        let (sender, receiver) = mpsc::channel();
        let (ready, started) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("terminal-balances".into())
            .spawn(move || {
                let _lock = lock;
                let runner =
                    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory));
                runner.start(|context| {
                    run(
                        context,
                        protocol,
                        journal_path,
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

    #[cfg(test)]
    pub(crate) fn fail_after_journal(&self) -> Result<()> {
        self.request(Request::FailAfterJournal)
    }

    #[cfg(test)]
    pub(crate) fn fail_read(&self) -> Result<()> {
        self.request(Request::FailRead)
    }

    #[cfg(test)]
    pub(crate) fn startup_work(&self) -> Result<(Vec<u64>, Vec<u64>)> {
        self.request(Request::StartupWork)
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
    pub(crate) fn prepare(
        &self,
        data: EpochData,
        registration: EpochRegistration,
    ) -> Result<PreparedEpoch> {
        self.request(|reply| Request::Prepare(Box::new((data, registration)), reply))
    }
    pub(crate) fn complete(&self, prepared: PreparedEpoch, seed: u64) -> Result<SettlementResult> {
        self.request(|reply| Request::Complete(Box::new(prepared), seed, reply))
    }
    pub(crate) fn apply(
        &self,
        result: SettlementResult,
        state: PreparedState<Digest, Rayon>,
    ) -> Result<SettlementResult> {
        self.request(|reply| Request::Apply(Box::new((result, state)), reply))
    }
    pub(crate) fn stored_result(&self, epoch: u64) -> Result<Option<SettlementResult>> {
        self.request(|reply| Request::Result(epoch, reply))
    }
    pub(crate) fn evidence(
        &self,
        epoch: u64,
    ) -> Result<(CloseContext<Key, Digest>, Close<Key, Digest>)> {
        self.request(|reply| Request::Evidence(epoch, reply))
    }
    pub(crate) fn check(&self, epoch: u64, accounts: Vec<(Key, u64)>) -> Result<()> {
        self.request(|reply| Request::Check(epoch, accounts, reply))
    }
}

async fn run(
    context: tokio::Context,
    protocol: Arc<Protocol>,
    journal_path: PathBuf,
    genesis: Vec<(commonware_clearing::bajillion::qmdb::AccountKey, NonZeroU64)>,
    configured: Option<Genesis<Digest>>,
    receiver: Receiver<Request>,
    ready: Reply<()>,
) {
    #[cfg(test)]
    let mut recovery = Recovery::default();
    let initialized: Result<_> = async {
        let mut journal = open_journal(&journal_path)?;
        let config = state_config("operator-balances", &context, protocol.strategy().clone());
        let genesis = genesis
            .into_iter()
            .map(|(key, balance)| (key, Some(balance)))
            .collect();
        let state = recover(
            context,
            config,
            &mut journal,
            genesis,
            configured,
            #[cfg(test)]
            &mut recovery,
        )
        .await?;
        Ok((journal, state))
    }
    .await;
    let (journal, mut state) = match initialized {
        Ok(value) => {
            let _ = ready.send(Ok(()));
            value
        }
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    #[cfg(test)]
    let mut fail_after_journal = false;
    #[cfg(test)]
    let mut fail_read = false;
    while let Ok(request) = receiver.recv() {
        match request {
            #[cfg(test)]
            Request::StartupWork(reply) => {
                let _ = reply.send(Ok((recovery.prepared.clone(), recovery.applied.clone())));
            }
            #[cfg(test)]
            Request::FailRead(reply) => {
                fail_read = true;
                let _ = reply.send(Ok(()));
            }
            #[cfg(test)]
            Request::FailAfterJournal(reply) => {
                fail_after_journal = true;
                let _ = reply.send(Ok(()));
            }
            Request::Root(epoch, reply) => {
                let _ = reply.send(checkpoint(&journal, epoch).map(|(root, _)| root));
            }
            Request::Opening(epoch, key, reply) => {
                let result = match checkpoint(&journal, epoch) {
                    Ok((root, operations)) => state
                        .opening_at(root, operations, key)
                        .await
                        .map_err(Into::into),
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Request::Prepare(input, reply) => {
                let (data, registration) = *input;
                let result = async {
                    check(
                        &journal,
                        &state,
                        data.epoch,
                        &data
                            .accounts
                            .iter()
                            .map(|account| (account.key.clone(), account.predecessor))
                            .collect::<Vec<_>>(),
                    )
                    .await?;
                    let assembled = super::actor::assemble_epoch(&protocol, &data, &registration)?;
                    let mut events = data.deposits;
                    events.extend(data.carried);
                    protocol
                        .prepare(registration, events, &state, assembled.terminals)
                        .await
                }
                .await;
                let _ = reply.send(result);
            }
            Request::Complete(prepared, seed, reply) => {
                #[cfg(test)]
                let mut rng = commonware_utils::TestRng::new(seed);
                #[cfg(not(test))]
                let mut rng = {
                    let _ = seed;
                    rand::rng()
                };
                let result = protocol.complete(*prepared, &state, &mut rng).await;
                match result {
                    Ok((result, candidate)) => {
                        #[cfg(test)]
                        let persisted =
                            persist(&journal, state, result, candidate, fail_after_journal).await;
                        #[cfg(not(test))]
                        let persisted = persist(&journal, state, result, candidate).await;
                        match persisted {
                            Ok((next, result)) => {
                                state = next;
                                let _ = reply.send(Ok(result));
                            }
                            Err(error) => {
                                let _ = reply.send(Err(unavailable(error)));
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            Request::Apply(input, reply) => {
                let (result, candidate) = *input;
                #[cfg(test)]
                let persisted =
                    persist(&journal, state, result, candidate, fail_after_journal).await;
                #[cfg(not(test))]
                let persisted = persist(&journal, state, result, candidate).await;
                match persisted {
                    Ok((next, result)) => {
                        state = next;
                        let _ = reply.send(Ok(result));
                    }
                    Err(error) => {
                        let _ = reply.send(Err(unavailable(error)));
                        return;
                    }
                }
            }
            Request::Result(epoch, reply) => {
                #[cfg(test)]
                if std::mem::take(&mut fail_read) {
                    let error = rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                        Some("injected result read failure".into()),
                    );
                    let _ = reply.send(Err(error.into()));
                    continue;
                }
                let _ = reply.send(stored_result(&journal, epoch));
            }
            Request::Evidence(epoch, reply) => {
                let result = stored_result(&journal, epoch).and_then(|result| {
                    let result = result.context("close evidence is not available")?;
                    let context = result.context.clone();
                    let close = Close::decode_evidence::<Sha256>(
                        result.evidence,
                        &context,
                        &result.header,
                    )?;
                    Ok((context, close))
                });
                let _ = reply.send(result);
            }
            Request::Check(epoch, accounts, reply) => {
                let result = check(&journal, &state, epoch, &accounts).await;
                let _ = reply.send(result);
            }
        }
    }
}

fn open_journal(path: &Path) -> Result<Connection> {
    let journal = Connection::open(path)?;
    journal.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS batches (
            sequence INTEGER PRIMARY KEY CHECK(sequence >= 0),
            root BLOB NOT NULL CHECK(length(root) = 32),
            operations INTEGER NOT NULL CHECK(operations > 0),
            mutations BLOB NOT NULL,
            result BLOB
        );
        CREATE UNIQUE INDEX IF NOT EXISTS batches_root ON batches(root);",
    )?;
    Ok(journal)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryCut {
    Journal,
    Applied,
    Committed,
}

#[cfg(test)]
#[derive(Default)]
struct Recovery {
    prepared: Vec<u64>,
    applied: Vec<u64>,
    cut: Option<RecoveryCut>,
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
    journal: &mut Connection,
    genesis: Mutations,
    configured: Option<Genesis<Digest>>,
    #[cfg(test)] recovery: &mut Recovery,
) -> Result<State<E, Sha256, Rayon>> {
    // The immutable genesis encoding binds this journal to its configured accounts.
    let matches: Option<bool> = journal
        .query_row(
            "SELECT mutations = ?1 FROM batches WHERE sequence = 0",
            [genesis.encode().as_ref()],
            |row| row.get(0),
        )
        .optional()?;
    ensure!(
        matches != Some(false),
        "balance history has the wrong genesis"
    );
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
        if matches.is_some() {
            ensure!(
                checkpoint(journal, 0)? == (configured.root(), configured.operations()),
                "configured genesis commitment mismatch"
            );
        }
    }
    let mut state = State::open(context, config).await?;
    if matches.is_none() {
        ensure!(
            state.is_bootstrap(),
            "native balance head has no accepted checkpoint"
        );
        let empty: bool =
            journal.query_row("SELECT NOT EXISTS(SELECT 1 FROM batches)", [], |row| {
                row.get(0)
            })?;
        ensure!(empty, "balance history has no genesis");
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
        record(journal, 0, &candidate, None)?;
        #[cfg(test)]
        recovery.stop(RecoveryCut::Journal)?;
        #[cfg(test)]
        recovery.applied.push(0);
        state = state.apply(candidate).await?;
        #[cfg(test)]
        recovery.stop(RecoveryCut::Applied)?;
        state = state.commit().await?;
        #[cfg(test)]
        recovery.stop(RecoveryCut::Committed)?;
    }
    let mut applied = if state.is_bootstrap() {
        None
    } else {
        Some(sequence(journal, &state)?)
    };
    loop {
        let next = applied.map_or(Ok(0), |sequence| {
            sequence.checked_add(1).context("epoch overflow")
        })?;
        let row = journal
            .query_row(
                "SELECT sequence, root, operations, mutations FROM batches WHERE sequence >= ?1 ORDER BY sequence LIMIT 1",
                [i64::try_from(next)?],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?)),
            )
            .optional()?;
        let Some((sequence, root, operations, bytes)) = row else {
            break;
        };
        let sequence = u64::try_from(sequence)?;
        let operations = u64::try_from(operations)?;
        ensure!(sequence == next, "balance history has a gap");
        let root = StateRoot::decode(root.as_slice()).context("decode accepted balance root")?;
        let mutations = Mutations::decode_cfg(
            bytes.as_slice(),
            &(RangeCfg::new(0..=MAX_ACCOUNTS), ((), ())),
        )
        .context("decode missing balance checkpoint")?;
        #[cfg(test)]
        recovery.prepared.push(sequence);
        let candidate = state.prepare(state.head(), mutations).await?;
        ensure!(
            candidate.root() == root && candidate.head().operations() == operations,
            "accepted balance checkpoint mismatch"
        );
        #[cfg(test)]
        recovery.applied.push(sequence);
        state = state.apply(candidate).await?.commit().await?;
        applied = Some(sequence);
    }
    Ok(state)
}

fn sequence<E: Context + Spawner>(
    journal: &Connection,
    state: &State<E, Sha256, Rayon>,
) -> Result<u64> {
    let sequence: i64 = journal
        .query_row(
            "SELECT sequence FROM batches WHERE root = ?1 AND operations = ?2",
            params![
                state.root().encode().as_ref(),
                i64::try_from(state.head().operations())?
            ],
            |row| row.get(0),
        )
        .context("native balance head has no accepted checkpoint")?;
    u64::try_from(sequence).context("negative balance checkpoint sequence")
}

fn checkpoint(journal: &Connection, epoch: u64) -> Result<(StateRoot<Digest>, u64)> {
    let (bytes, operations): (Vec<u8>, i64) = journal
        .query_row(
            "SELECT root, operations FROM batches WHERE sequence = ?1",
            [i64::try_from(epoch).context("epoch exceeds SQLite range")?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("the predecessor balance root is not available yet")?;
    Ok((
        StateRoot::decode(bytes.as_slice()).context("decode retained balance root")?,
        u64::try_from(operations).context("negative balance checkpoint operation count")?,
    ))
}

fn record(
    journal: &Connection,
    sequence: u64,
    candidate: &PreparedState<Digest, Rayon>,
    result: Option<&SettlementResult>,
) -> Result<()> {
    journal.execute(
        "INSERT INTO batches(sequence, root, operations, mutations, result) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![
            i64::try_from(sequence)?,
            candidate.root().encode().as_ref(),
            i64::try_from(candidate.head().operations())?,
            candidate.mutations().encode().as_ref(),
            result.map(Encode::encode).as_deref(),
        ],
    )?;
    Ok(())
}

fn stored_result(journal: &Connection, epoch: u64) -> Result<Option<SettlementResult>> {
    let bytes: Option<Vec<u8>> = journal
        .query_row(
            "SELECT result FROM batches WHERE sequence = ?1",
            [i64::try_from(epoch)
                .context("epoch exceeds SQLite range")?
                .checked_add(1)
                .context("epoch overflow")?],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            SettlementResult::decode(bytes.as_slice()).context("decode retained close result")
        })
        .transpose()
}

async fn persist(
    journal: &Connection,
    state: Database,
    result: SettlementResult,
    candidate: PreparedState<Digest, Rayon>,
    #[cfg(test)] fail_after_journal: bool,
) -> Result<(Database, SettlementResult)> {
    ensure!(
        result.epoch == sequence(journal, &state)? && candidate.predecessor() == state.head(),
        "close does not extend the balance state"
    );
    ensure!(
        candidate.root() == result.roots.successor,
        "close balance root mismatch"
    );

    // Canonical history and all settlement evidence become durable before QMDB can advance.
    record(
        journal,
        result.epoch.checked_add(1).context("epoch overflow")?,
        &candidate,
        Some(&result),
    )?;
    #[cfg(test)]
    if fail_after_journal {
        anyhow::bail!("injected crash after balance history commit");
    }
    let state = state.apply(candidate).await?.commit().await?;
    Ok((state, result))
}

async fn check(
    journal: &Connection,
    state: &Database,
    epoch: u64,
    accounts: &[(Key, u64)],
) -> Result<()> {
    ensure!(
        epoch == sequence(journal, state)?,
        "balance state is not at the current epoch"
    );
    let mut liability = 0u64;
    let mut count = 0u64;
    for (key, balance) in accounts {
        let actual = state
            .get(&account_key(key)?)
            .await?
            .map_or(0, NonZeroU64::get);
        ensure!(
            actual == *balance,
            "SQL predecessor root does not authenticate its balances"
        );
        liability = liability
            .checked_add(*balance)
            .context("balance liability overflow")?;
        count += u64::from(*balance > 0);
    }
    ensure!(
        liability == state.liability() && count == state.live_accounts(),
        "SQL predecessor does not cover QMDB state"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_clearing::bajillion::qmdb::AccountKey;
    use commonware_runtime::{Supervisor as _, deterministic};
    use std::num::NonZeroUsize;

    fn genesis() -> Mutations {
        vec![(AccountKey::new([1; 32]), NonZeroU64::new(100))]
    }

    #[test]
    fn genesis_journal_precedes_apply_and_surviving_apply_is_not_repeated() {
        for cut in [
            RecoveryCut::Journal,
            RecoveryCut::Applied,
            RecoveryCut::Committed,
        ] {
            deterministic::Runner::default().start(|context| async move {
                let strategy = Rayon::new(NonZeroUsize::MIN).unwrap();
                let mut config = state_config("bootstrap-cut", &context, strategy);
                if cut == RecoveryCut::Applied {
                    config.journal_config.items_per_blob = NonZeroU64::MIN;
                    config.merkle_config.items_per_blob = NonZeroU64::MIN;
                }
                let mut journal = open_journal(Path::new(":memory:")).unwrap();
                let mut trace = Recovery {
                    cut: Some(cut),
                    ..Recovery::default()
                };
                let result = recover(
                    context.child("cut"),
                    config.clone(),
                    &mut journal,
                    genesis(),
                    None,
                    &mut trace,
                )
                .await;
                assert!(format!("{:#}", result.err().unwrap()).contains("injected recovery cut"));
                assert_eq!(trace.prepared, [0]);
                let expected = checkpoint(&journal, 0).unwrap();
                assert_eq!(
                    journal
                        .query_row("SELECT count(*) FROM batches", [], |row| row
                            .get::<_, i64>(0))
                        .unwrap(),
                    1
                );

                let native =
                    State::<_, Sha256, Rayon>::open(context.child("native"), config.clone())
                        .await
                        .unwrap();
                let missing = native.is_bootstrap();
                if cut == RecoveryCut::Journal {
                    assert!(missing);
                }
                if matches!(cut, RecoveryCut::Applied | RecoveryCut::Committed) {
                    assert!(!missing, "a complete flushed apply must survive restart");
                }
                drop(native);
                let mut trace = Recovery::default();
                let state = recover(
                    context.child("recovered"),
                    config,
                    &mut journal,
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
            });
        }
    }

    #[test]
    fn restart_decodes_and_applies_only_missing_accepted_suffix() {
        deterministic::Runner::default().start(|context| async move {
            let config = state_config("suffix", &context, Rayon::new(NonZeroUsize::MIN).unwrap());
            let mut journal = open_journal(Path::new(":memory:")).unwrap();
            let state = recover(
                context.child("genesis"),
                config.clone(),
                &mut journal,
                genesis(),
                None,
                &mut Recovery::default(),
            )
            .await
            .unwrap();
            let candidate = state
                .prepare(
                    state.head(),
                    vec![(AccountKey::new([1; 32]), NonZeroU64::new(90))],
                )
                .await
                .unwrap();
            record(&journal, 1, &candidate, None).unwrap();
            let state = state
                .apply(candidate)
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
            // A sentinel in an already applied non-genesis blob detects accidental historical decoding.
            journal
                .execute(
                    "UPDATE batches SET mutations = x'ff' WHERE sequence = 1",
                    [],
                )
                .unwrap();
            let candidate = state
                .prepare(
                    state.head(),
                    vec![(AccountKey::new([1; 32]), NonZeroU64::new(80))],
                )
                .await
                .unwrap();
            let expected = *candidate.head();
            record(&journal, 2, &candidate, None).unwrap();
            drop(candidate);
            drop(state);

            let mut trace = Recovery::default();
            let state = recover(
                context.child("suffix"),
                config.clone(),
                &mut journal,
                genesis(),
                None,
                &mut trace,
            )
            .await
            .unwrap();
            assert_eq!(trace.prepared, [2]);
            assert_eq!(trace.applied, [2]);
            assert_eq!(*state.head(), expected);
            drop(state);
            let mut trace = Recovery::default();
            let state = recover(
                context.child("current"),
                config,
                &mut journal,
                genesis(),
                None,
                &mut trace,
            )
            .await
            .unwrap();
            assert!(trace.prepared.is_empty());
            assert!(trace.applied.is_empty());
            assert_eq!(*state.head(), expected);
        });
    }

    #[test]
    fn configured_genesis_mismatch_cannot_publish_or_reopen_a_balance_owner() {
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
                let bad_root = if changed == 0 {
                    state.root()
                } else {
                    expected.root()
                };
                let bad_operations = expected.operations() + u64::from(changed == 1);
                let accounts = [(
                    AccountKey::new([1; 32]),
                    NonZeroU64::new(100 + u64::from(changed == 2)).unwrap(),
                )];
                let wrong = Genesis::new(bad_root, bad_operations, &accounts).unwrap();
                drop(candidate);
                drop(state);
                let mut journal = open_journal(Path::new(":memory:")).unwrap();
                let mut trace = Recovery::default();
                let error = recover(
                    context.child("wrong_fresh"),
                    config.clone(),
                    &mut journal,
                    genesis(),
                    Some(wrong),
                    &mut trace,
                )
                .await
                .err()
                .unwrap();
                assert!(format!("{error:#}").contains("configured genesis"));
                assert!(trace.applied.is_empty());
                assert_eq!(
                    journal
                        .query_row("SELECT count(*) FROM batches", [], |row| row
                            .get::<_, i64>(0))
                        .unwrap(),
                    0
                );
                let native =
                    State::<_, Sha256, Rayon>::open(context.child("inspect"), config.clone())
                        .await
                        .unwrap();
                assert!(native.is_bootstrap());
                drop(native);
                let state = recover(
                    context.child("valid"),
                    config.clone(),
                    &mut journal,
                    genesis(),
                    Some(expected),
                    &mut Recovery::default(),
                )
                .await
                .unwrap();
                assert_eq!(state.root(), expected.root());
                drop(state);
                let mut trace = Recovery::default();
                let error = recover(
                    context.child("wrong_restart"),
                    config,
                    &mut journal,
                    genesis(),
                    Some(wrong),
                    &mut trace,
                )
                .await
                .err()
                .unwrap();
                assert!(format!("{error:#}").contains("configured genesis"));
                assert!(trace.prepared.is_empty());
                assert!(trace.applied.is_empty());
            });
        }
    }

    #[test]
    fn restart_rejects_genesis_and_native_checkpoint_mismatches_without_replay() {
        deterministic::Runner::default().start(|context| async move {
            let config = state_config("mismatch", &context, Rayon::new(NonZeroUsize::MIN).unwrap());
            let mut journal = open_journal(Path::new(":memory:")).unwrap();
            let state = recover(
                context.child("genesis"),
                config.clone(),
                &mut journal,
                genesis(),
                None,
                &mut Recovery::default(),
            )
            .await
            .unwrap();
            drop(state);
            let mut trace = Recovery::default();
            let wrong_genesis = vec![(AccountKey::new([2; 32]), NonZeroU64::new(100))];
            let error = recover(
                context.child("wrong_genesis"),
                config.clone(),
                &mut journal,
                wrong_genesis,
                None,
                &mut trace,
            )
            .await
            .err()
            .unwrap();
            assert!(format!("{error:#}").contains("wrong genesis"));
            assert!(trace.prepared.is_empty());
            assert!(trace.applied.is_empty());
            journal
                .execute(
                    "UPDATE batches SET operations = operations + 1 WHERE sequence = 0",
                    [],
                )
                .unwrap();
            let error = recover(
                context.child("wrong_checkpoint"),
                config,
                &mut journal,
                genesis(),
                None,
                &mut trace,
            )
            .await
            .err()
            .unwrap();
            assert!(
                format!("{error:#}").contains("native balance head has no accepted checkpoint")
            );
            assert!(trace.prepared.is_empty());
            assert!(trace.applied.is_empty());
        });
    }
}
