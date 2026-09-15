//! Serial ownership of the operator's optional native proof replica.

use super::{
    actor::{registration_for, replica_terminals},
    store::EpochReader,
};
use crate::{
    chain::da::replica_config,
    protocol::{Account, Key, Protocol},
};
use anyhow::{Context as _, Result, ensure};
use commonware_clearing::bajillion::{
    challenge::HigherEntryLookup,
    custody::Epoch,
    logs::{Heads, LogHead},
    qmdb::{Mutations, StateOpening, StateRoot, account_key},
    replica::{Config, PreparedReplica, Replica, ReplicaHead},
    settlement::Genesis,
    transition::{WithdrawalClaim, prepare_close_with_strategy},
};
use commonware_codec::{DecodeExt as _, Encode, FixedSize as _};
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
type OperatorReplica<E> = Replica<E, Sha256, Key, Rayon>;

#[derive(Debug, thiserror::Error)]
#[error("proof replica storage is unavailable; restart the operator: {0:#}")]
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
        ) || matches!(
            cause.downcast_ref::<commonware_clearing::bajillion::logs::Error>(),
            Some(commonware_clearing::bajillion::logs::Error::Storage(_))
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
    CommittedEntry(u64, Key, Key, Reply<HigherEntryLookup<Key, Digest>>),
    PayoutProof(LogHead<Digest>, u64, Reply<WithdrawalClaim<Digest>>),
    CatchUp(Option<Reply<()>>),
    #[cfg(test)]
    PauseNext(Reply<(Receiver<()>, SyncSender<()>)>),
    #[cfg(test)]
    StartupWork(Reply<(Vec<u64>, Vec<u64>)>),
}

struct Owner {
    // The SQL source owns ephemeral paths and outlives the joined replica worker.
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
            .name("terminal-proof-replica".into())
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
            .context("proof replica worker stopped during initialization")
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
            .map_err(|_| unavailable(anyhow::anyhow!("proof replica worker stopped")))?;
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

    pub(crate) fn committed_entry(
        &self,
        epoch: u64,
        payer: &Key,
        recipient: &Key,
    ) -> Result<HigherEntryLookup<Key, Digest>> {
        self.request(|reply| {
            Request::CommittedEntry(epoch, payer.clone(), recipient.clone(), reply)
        })
    }

    pub(crate) fn payout_proof(
        &self,
        head: LogHead<Digest>,
        index: u64,
    ) -> Result<WithdrawalClaim<Digest>> {
        self.request(|reply| Request::PayoutProof(head, index, reply))
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
    let initialized: Result<_> = Box::pin(async {
        initialize_checkpoints(&connection)?;
        let config = replica_config("operator-proof", &context, protocol.strategy().clone());
        let state = Box::pin(recover(
            context,
            config,
            &connection,
            genesis,
            configured,
            #[cfg(test)]
            &mut recovery,
        ))
        .await?;
        Box::pin(catch_up(
            state,
            &protocol,
            &source,
            &connection,
            #[cfg(test)]
            &mut recovery,
        ))
        .await
    })
    .await;
    let mut replica = match initialized {
        Ok(replica) => {
            let _ = ready.send(Ok(()));
            replica
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
        replica = match Box::pin(async {
            let advance = match &request {
                Request::Root(epoch, _) | Request::Opening(epoch, _, _) => {
                    *epoch > sequence(&connection, &replica)?
                }
                Request::CommittedEntry(epoch, _, _, _) => {
                    *epoch >= sequence(&connection, &replica)?
                }
                Request::PayoutProof(head, _, _) => {
                    head.operations > replica.head().logs.payouts.operations
                }
                _ => true,
            };
            if advance {
                Box::pin(catch_up(
                    replica,
                    &protocol,
                    &source,
                    &connection,
                    #[cfg(test)]
                    &mut recovery,
                ))
                .await
            } else {
                Ok(replica)
            }
        })
        .await
        {
            Ok(replica) => replica,
            Err(error) => {
                source.fence_storage_failure(&error);
                match request {
                    Request::Root(_, reply) => {
                        let _ = reply.send(Err(unavailable(error)));
                    }
                    Request::Opening(_, _, reply) => {
                        let _ = reply.send(Err(unavailable(error)));
                    }
                    Request::CommittedEntry(_, _, _, reply) => {
                        let _ = reply.send(Err(unavailable(error)));
                    }
                    Request::PayoutProof(_, _, reply) => {
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
                let _ = reply.send(checkpoint(&connection, epoch).map(|head| head.state.root()));
            }
            Request::Opening(epoch, key, reply) => {
                let result = match checkpoint(&connection, epoch) {
                    Ok(head) => replica
                        .state()
                        .opening_at(head.state.root(), head.state.operations(), key)
                        .await
                        .map_err(Into::into),
                    Err(error) => Err(error),
                };
                let _ = reply.send(result);
            }
            Request::CommittedEntry(epoch, payer, recipient, reply) => {
                let result = committed_entry(&replica, &source, epoch, &payer, &recipient).await;
                let _ = reply.send(result);
            }
            Request::PayoutProof(head, index, reply) => {
                let result = payout_claim(&replica, &head, index).await;
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

async fn committed_entry<E: Context + Spawner>(
    replica: &OperatorReplica<E>,
    source: &EpochReader,
    epoch: u64,
    payer: &Key,
    recipient: &Key,
) -> Result<HigherEntryLookup<Key, Digest>> {
    let result = source
        .stored_result(epoch)?
        .context("certified close is not retained")?;
    ensure!(
        result.header.verify::<Sha256, Key>(
            &result.context,
            &result.roots,
            result.withdrawal_total
        ),
        "retained certified descriptor does not match its header"
    );
    let range = result.roots.activity_range(&result.context)?;
    let retained = Epoch::at(replica.logs(), epoch, range).await?;
    let lookup = retained
        .higher_entry_lookup(replica.logs(), payer, recipient)
        .await?;
    Ok(lookup)
}

async fn payout_claim<E: Context + Spawner>(
    replica: &OperatorReplica<E>,
    head: &LogHead<Digest>,
    index: u64,
) -> Result<WithdrawalClaim<Digest>> {
    let (opening, operations) = replica
        .logs()
        .payout_opening(head, index, NonZeroU64::MIN)
        .await?;
    let [commonware_storage::qmdb::keyless::Operation::Append(output)] = operations.as_slice()
    else {
        anyhow::bail!("the requested payout location is not an output");
    };
    let claim = WithdrawalClaim::new(output.clone(), opening);
    ensure!(
        claim.position() == index,
        "generated payout claim has the wrong location"
    );
    claim
        .verify::<Sha256>(head)
        .context("verify generated payout claim")?;
    Ok(claim)
}

fn initialize_checkpoints(connection: &Connection) -> Result<()> {
    connection.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS proof_replica_checkpoints (
             sequence INTEGER PRIMARY KEY CHECK(sequence >= 0),
             head BLOB NOT NULL CHECK(length(head) = {}),
             complete INTEGER NOT NULL CHECK(complete IN (0, 1))
         );
         CREATE UNIQUE INDEX IF NOT EXISTS proof_replica_checkpoint_head
             ON proof_replica_checkpoints(head);",
        ReplicaHead::<Digest>::SIZE,
    ))?;
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryCut {
    Checkpoint,
    Applied,
    StateCommitted,
    Committed,
    Completed,
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
) -> Result<OperatorReplica<E>> {
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
            "SELECT EXISTS(SELECT 1 FROM proof_replica_checkpoints WHERE sequence = 0)",
            [],
            |row| row.get(0),
        )?;
        if exists {
            let checkpoint = checkpoint(connection, 0)?;
            ensure!(
                checkpoint.state.root() == configured.root()
                    && checkpoint.state.operations() == configured.operations(),
                "configured genesis commitment mismatch"
            );
        }
    }
    let mut replica = Replica::open(context, config).await?;

    // The latest completed SQL head is the only mutable recovery anchor. Components may be at
    // different later accepted heads when a prior native commit was interrupted.
    if let Some((sequence, complete)) = latest_complete(connection)? {
        replica = align(connection, replica, sequence, &complete).await?;
        return Ok(replica);
    }

    // Genesis has no earlier application checkpoint. An exact durable candidate can be completed;
    // otherwise the bootstrap owner deterministically reapplies the configured allocations.
    let accepted = checkpoint_optional(connection, 0)?;
    if accepted == Some(replica.head()) {
        let replica = replica.commit().await?;
        complete(connection, 0, &replica.head())?;
        #[cfg(test)]
        recovery.stop(RecoveryCut::Completed)?;
        return Ok(replica);
    }
    ensure!(
        replica.state().is_bootstrap() && replica.logs().head() == &Heads::empty::<Key, Sha256>(),
        "native replica head has no completed checkpoint"
    );
    {
        #[cfg(test)]
        recovery.prepared.push(0);
        let candidate = replica
            .state()
            .prepare(replica.state().head(), genesis)
            .await?;
        if let Some(configured) = configured {
            ensure!(
                candidate.root() == configured.root()
                    && candidate.head().operations() == configured.operations(),
                "configured genesis commitment mismatch"
            );
        }
        let head = ReplicaHead {
            state: *candidate.head(),
            logs: replica.head().logs,
        };
        if let Some(accepted) = accepted {
            ensure!(accepted == head, "retained genesis checkpoint mismatch");
        }
        record(connection, 0, &head)?;
        #[cfg(test)]
        recovery.stop(RecoveryCut::Checkpoint)?;
        #[cfg(test)]
        recovery.applied.push(0);
        let (state, logs) = replica.into_parts();
        let state = state.apply(candidate).await?;
        replica = Replica::from_parts(state, logs);
        #[cfg(test)]
        recovery.stop(RecoveryCut::Applied)?;
        replica = replica.commit().await?;
        #[cfg(test)]
        recovery.stop(RecoveryCut::Committed)?;
        complete(connection, 0, &replica.head())?;
        #[cfg(test)]
        recovery.stop(RecoveryCut::Completed)?;
    }
    Ok(replica)
}

async fn catch_up<E: Context + Spawner>(
    mut replica: OperatorReplica<E>,
    protocol: &Protocol,
    source: &EpochReader,
    connection: &Connection,
    #[cfg(test)] recovery: &mut Recovery,
) -> Result<OperatorReplica<E>> {
    let mut applied = sequence(connection, &replica)?;
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
            .context("certified result prefix has a gap")?;
        #[cfg(test)]
        if let Some((started, release)) = recovery.gate.take() {
            let _ = started.send(());
            release.recv().context("proof catch-up gate dropped")?;
        }

        // Replay derives all three native batches from retained SQL activity using the
        // immutable floors in the certified result.
        let data = source.load(applied)?;
        let registration = registration_for(protocol, &data)?;
        let terminals = replica_terminals(protocol, &data)?;
        let context = registration.context.bind::<Sha256, _, _>(
            &replica,
            &registration.deposits,
            &registration.withdrawals,
            result.context.floors(),
        )?;
        ensure!(
            context == result.context,
            "certified close context mismatch"
        );
        #[cfg(test)]
        recovery.prepared.push(applied + 1);
        let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
            &replica,
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
                && candidate.head().state.root() == result.roots.successor
                && candidate.head().state.operations() == result.roots.successor_operations
                && candidate.head().state.sync_boundary() == result.roots.successor_sync_boundary
                && candidate.head().logs == result.roots.logs(),
            "certified close differs from locally derived native state"
        );
        applied = applied.checked_add(1).context("epoch overflow")?;
        replica = apply_checkpoint(
            connection,
            applied,
            replica,
            candidate,
            #[cfg(test)]
            recovery,
        )
        .await?;
        source.prune_proof_inputs(applied)?;
    }
    let ahead: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM proof_replica_checkpoints WHERE sequence > ?1)",
        [i64::try_from(applied)?],
        |row| row.get(0),
    )?;
    ensure!(!ahead, "replica checkpoint has no certified result");
    Ok(replica)
}

fn sequence<E: Context + Spawner>(
    connection: &Connection,
    replica: &OperatorReplica<E>,
) -> Result<u64> {
    let sequence: i64 = connection
        .query_row(
            "SELECT sequence FROM proof_replica_checkpoints WHERE head = ?1 AND complete = 1",
            [replica.head().encode().as_ref()],
            |row| row.get(0),
        )
        .context("native replica head has no completed checkpoint")?;
    u64::try_from(sequence).context("negative replica checkpoint sequence")
}

fn checkpoint(connection: &Connection, epoch: u64) -> Result<ReplicaHead<Digest>> {
    let bytes: Vec<u8> = connection
        .query_row(
            "SELECT head FROM proof_replica_checkpoints WHERE sequence = ?1",
            [i64::try_from(epoch).context("epoch exceeds SQLite range")?],
            |row| row.get(0),
        )
        .context("the predecessor replica head is not available yet")?;
    ReplicaHead::decode(bytes).context("decode retained replica head")
}

fn checkpoint_optional(
    connection: &Connection,
    sequence: u64,
) -> Result<Option<ReplicaHead<Digest>>> {
    let bytes = connection
        .query_row(
            "SELECT head FROM proof_replica_checkpoints WHERE sequence = ?1",
            [i64::try_from(sequence).context("sequence exceeds SQLite range")?],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    bytes
        .map(|bytes| ReplicaHead::decode(bytes).context("decode retained replica head"))
        .transpose()
}

fn latest_complete(connection: &Connection) -> Result<Option<(u64, ReplicaHead<Digest>)>> {
    let row = connection
        .query_row(
            "SELECT sequence, head FROM proof_replica_checkpoints
             WHERE complete = 1 ORDER BY sequence DESC LIMIT 1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    row.map(|(sequence, bytes)| {
        Ok((
            u64::try_from(sequence).context("negative replica checkpoint sequence")?,
            ReplicaHead::decode(bytes).context("decode completed replica head")?,
        ))
    })
    .transpose()
}

fn accepted_heads(connection: &Connection, sequence: u64) -> Result<Vec<ReplicaHead<Digest>>> {
    let mut statement = connection.prepare_cached(
        "SELECT head FROM proof_replica_checkpoints WHERE sequence >= ?1 ORDER BY sequence",
    )?;
    let rows = statement
        .query_map(
            [i64::try_from(sequence).context("sequence exceeds SQLite range")?],
            |row| row.get::<_, Vec<u8>>(0),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|bytes| ReplicaHead::decode(bytes).context("decode accepted replica head"))
        .collect()
}

async fn align<E: Context + Spawner>(
    connection: &Connection,
    replica: OperatorReplica<E>,
    sequence: u64,
    target: &ReplicaHead<Digest>,
) -> Result<OperatorReplica<E>> {
    if replica.head() == *target {
        return Ok(replica);
    }
    let recovered = replica.head();
    ensure!(
        recovered.state.operations() >= target.state.operations()
            && recovered.logs.activity.operations >= target.logs.activity.operations
            && recovered.logs.payouts.operations >= target.logs.payouts.operations,
        "native replica is behind its completed checkpoint"
    );
    let accepted = accepted_heads(connection, sequence)?;
    ensure!(
        accepted.iter().any(|head| head.state == recovered.state)
            && accepted
                .iter()
                .any(|head| head.logs.activity == recovered.logs.activity)
            && accepted
                .iter()
                .any(|head| head.logs.payouts == recovered.logs.payouts),
        "native replica contains an unauthorized checkpoint component"
    );
    let replica = replica.rewind(target).await?;
    ensure!(
        replica.head() == *target,
        "native rewind did not restore the completed checkpoint"
    );
    Ok(replica)
}

fn complete(connection: &Connection, sequence: u64, head: &ReplicaHead<Digest>) -> Result<()> {
    ensure!(
        checkpoint(connection, sequence)? == *head,
        "completed native replica differs from its accepted checkpoint"
    );
    let changed = connection.execute(
        "UPDATE proof_replica_checkpoints SET complete = 1 WHERE sequence = ?1 AND head = ?2",
        params![i64::try_from(sequence)?, head.encode().as_ref()],
    )?;
    ensure!(
        changed == 1,
        "replica checkpoint completion was not recorded"
    );
    Ok(())
}

fn record(connection: &Connection, sequence: u64, head: &ReplicaHead<Digest>) -> Result<()> {
    connection.execute(
        "INSERT INTO proof_replica_checkpoints(sequence, head, complete) VALUES(?1, ?2, 0)
         ON CONFLICT(sequence) DO NOTHING",
        params![i64::try_from(sequence)?, head.encode().as_ref()],
    )?;
    ensure!(
        checkpoint(connection, sequence)? == *head,
        "retained replica checkpoint mismatch"
    );
    Ok(())
}

#[commonware_macros::boxed]
async fn apply_checkpoint<E: Context + Spawner>(
    connection: &Connection,
    sequence: u64,
    replica: OperatorReplica<E>,
    candidate: PreparedReplica<Key, Digest, Rayon>,
    #[cfg(test)] recovery: &mut Recovery,
) -> Result<OperatorReplica<E>> {
    // The accepted native head is durable before native writes. The owning close result and
    // retained SQL activity reconstruct this candidate if those writes do not survive a crash.
    record(connection, sequence, &candidate.head())?;
    #[cfg(test)]
    recovery.stop(RecoveryCut::Checkpoint)?;
    #[cfg(test)]
    recovery.applied.push(sequence);
    #[cfg(test)]
    if recovery.cut == Some(RecoveryCut::StateCommitted) {
        let (state, _logs) = replica.into_parts();
        let (state_candidate, _logs_candidate) = candidate.into_parts();
        let _state = state.apply(state_candidate).await?.commit().await?;
        recovery.stop(RecoveryCut::StateCommitted)?;
        unreachable!("the matching recovery cut always stops")
    }
    let replica = replica.apply(candidate).await?;
    #[cfg(test)]
    recovery.stop(RecoveryCut::Applied)?;
    let replica = replica.commit().await?;
    #[cfg(test)]
    recovery.stop(RecoveryCut::Committed)?;

    // Completion becomes visible only after every native operation journal is durable.
    complete(connection, sequence, &replica.head())?;
    #[cfg(test)]
    recovery.stop(RecoveryCut::Completed)?;
    Ok(replica)
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
        logs::ActivityInput,
        qmdb::AccountKey,
        transition::WithdrawalOutput,
    };
    use commonware_codec::{Decode as _, RangeCfg, Write as _};
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
            RecoveryCut::Completed,
        ] {
            deterministic::Runner::default().start(|context| async move {
                let mut config = replica_config(
                    "bootstrap-cut",
                    &context,
                    Rayon::new(NonZeroUsize::MIN).unwrap(),
                );
                if cut == RecoveryCut::Applied {
                    config.state.journal_config.items_per_blob = NonZeroU64::MIN;
                    config.state.merkle_config.items_per_blob = NonZeroU64::MIN;
                }
                let connection = checkpoints();
                let mut trace = Recovery {
                    cut: Some(cut),
                    ..Recovery::default()
                };
                let error = Box::pin(recover(
                    context.child("cut"),
                    config.clone(),
                    &connection,
                    genesis(),
                    None,
                    &mut trace,
                ))
                .await
                .err()
                .unwrap();
                assert!(format!("{error:#}").contains("injected recovery cut"));
                assert_eq!(trace.prepared, [0]);
                let expected = checkpoint(&connection, 0).unwrap();
                let native = OperatorReplica::open(context.child("inspect"), config.clone())
                    .await
                    .unwrap();
                let missing = native.state().is_bootstrap();
                assert_eq!(missing, cut == RecoveryCut::Checkpoint);
                drop(native);
                let mut trace = Recovery::default();
                let state = Box::pin(recover(
                    context.child("recovered"),
                    config,
                    &connection,
                    genesis(),
                    None,
                    &mut trace,
                ))
                .await
                .unwrap();
                let work = if cut == RecoveryCut::Checkpoint {
                    vec![0]
                } else {
                    vec![]
                };
                assert_eq!(trace.prepared, work);
                assert_eq!(trace.applied, work);
                assert_eq!(state.head(), expected);
                assert_eq!(state.state().live_accounts(), 1);
                assert_eq!(
                    connection
                        .query_row(
                            "SELECT count(*) FROM proof_replica_checkpoints",
                            [],
                            |row| row.get::<_, i64>(0)
                        )
                        .unwrap(),
                    1
                );
            });
        }
    }

    #[test]
    fn recovery_rejects_a_native_head_outside_the_certified_journal() {
        deterministic::Runner::default().start(|context| async move {
            let config = replica_config(
                "unauthorized-head",
                &context,
                Rayon::new(NonZeroUsize::MIN).unwrap(),
            );
            let connection = checkpoints();
            let replica = Box::pin(recover(
                context.child("genesis"),
                config.clone(),
                &connection,
                genesis(),
                None,
                &mut Recovery::default(),
            ))
            .await
            .unwrap();

            // A locally durable but unjournaled state transition cannot become replay authority.
            let (state, logs) = replica.into_parts();
            let candidate = state
                .prepare(
                    state.head(),
                    vec![(AccountKey::new([1; 32]), NonZeroU64::new(101))],
                )
                .await
                .unwrap();
            let state = state
                .apply(candidate)
                .await
                .unwrap()
                .commit()
                .await
                .unwrap();
            drop(state);
            drop(logs);

            let error = Box::pin(recover(
                context.child("recover"),
                config,
                &connection,
                genesis(),
                None,
                &mut Recovery::default(),
            ))
            .await
            .err()
            .unwrap();
            assert!(format!("{error:#}").contains("unauthorized checkpoint component"));
        });
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
    fn restart_aligns_mixed_native_commits_and_replays_only_incomplete_certified_suffix() {
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
            RecoveryCut::StateCommitted,
            RecoveryCut::Committed,
            RecoveryCut::Completed,
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
                let mut config = replica_config("suffix", &context, protocol.strategy().clone());
                if cut == RecoveryCut::Applied {
                    config.state.journal_config.items_per_blob = NonZeroU64::MIN;
                    config.state.merkle_config.items_per_blob = NonZeroU64::MIN;
                }
                let state = Box::pin(recover(
                    context.child("genesis"),
                    config.clone(),
                    &connection,
                    genesis.clone(),
                    Some(configured),
                    &mut Recovery::default(),
                ))
                .await
                .unwrap();
                retain(&connection, &results[0]);
                let mut trace = Recovery {
                    cut: Some(cut),
                    ..Recovery::default()
                };
                let error = Box::pin(catch_up(state, &protocol, &source, &connection, &mut trace))
                    .await
                    .err()
                    .unwrap();
                assert!(format!("{error:#}").contains("injected recovery cut"));
                assert_eq!(trace.prepared, [1]);
                let native = OperatorReplica::open(context.child("inspect"), config.clone())
                    .await
                    .unwrap();
                let genesis_head = checkpoint(&connection, 0).unwrap();
                let candidate_head = checkpoint(&connection, 1).unwrap();
                if cut == RecoveryCut::StateCommitted {
                    assert_eq!(native.head().state, candidate_head.state);
                    assert_eq!(native.head().logs, genesis_head.logs);
                }
                let survived = native.head() == candidate_head;
                if cut == RecoveryCut::Checkpoint {
                    assert!(!survived);
                }
                if matches!(cut, RecoveryCut::Committed | RecoveryCut::Completed) {
                    assert!(survived);
                }
                drop(native);
                let completed = cut == RecoveryCut::Completed;
                if completed {
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
                let state = Box::pin(recover(
                    context.child("recover"),
                    config.clone(),
                    &connection,
                    genesis.clone(),
                    Some(configured),
                    &mut trace,
                ))
                .await
                .unwrap();
                let state = Box::pin(catch_up(state, &protocol, &source, &connection, &mut trace))
                    .await
                    .unwrap();
                let expected = if completed { vec![2] } else { vec![1, 2] };
                assert_eq!(trace.prepared, expected);
                assert_eq!(trace.applied, expected);
                assert_eq!(state.state().root(), results[1].roots.successor);
                assert_eq!(sequence(&connection, &state).unwrap(), 2);
                let entry = committed_entry(&state, &source, 0, &accounts[0].key, &accounts[1].key)
                    .await
                    .unwrap();
                assert_eq!(
                    entry
                        .resolve::<Sha256>(
                            &results[0]
                                .roots
                                .activity_range(&results[0].context)
                                .unwrap(),
                            &accounts[0].key,
                            &accounts[1].key,
                        )
                        .unwrap(),
                    (0, 0)
                );
                drop(state);
                // Applied result blobs are deliberately undecodable; checkpoint identities own restart.
                connection
                    .execute("UPDATE close_jobs SET result = x'ff' WHERE epoch < 2", [])
                    .unwrap();
                let mut trace = Recovery::default();
                let state = Box::pin(recover(
                    context.child("current"),
                    config,
                    &connection,
                    genesis.clone(),
                    Some(configured),
                    &mut trace,
                ))
                .await
                .unwrap();
                let state = Box::pin(catch_up(state, &protocol, &source, &connection, &mut trace))
                    .await
                    .unwrap();
                assert!(trace.prepared.is_empty());
                assert!(trace.applied.is_empty());
                let checkpoint = checkpoint(&connection, 0).unwrap();
                let opening = state
                    .state()
                    .opening_at(
                        checkpoint.state.root(),
                        checkpoint.state.operations(),
                        accounts[0].key.clone(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    opening
                        .verify::<Sha256>(&checkpoint.state.root())
                        .unwrap()
                        .get(),
                    INITIAL_BALANCE
                );
            });
        }
    }

    #[test]
    fn configured_genesis_mismatch_cannot_publish_or_reopen_native_state() {
        for changed in 0..3 {
            deterministic::Runner::default().start(|context| async move {
                let config = replica_config(
                    "configured",
                    &context,
                    Rayon::new(NonZeroUsize::MIN).unwrap(),
                );
                let state = OperatorReplica::open(context.child("derive"), config.clone())
                    .await
                    .unwrap();
                let candidate = state
                    .state()
                    .prepare(state.state().head(), genesis())
                    .await
                    .unwrap();
                let expected = Genesis::new(
                    candidate.head().root(),
                    candidate.head().operations(),
                    &[(AccountKey::new([1; 32]), NonZeroU64::new(100).unwrap())],
                )
                .unwrap();
                let wrong = Genesis::new(
                    if changed == 0 {
                        state.state().root()
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
                    let result = Box::pin(recover(
                        context.child("attempt"),
                        config.clone(),
                        &connection,
                        genesis(),
                        Some(configured),
                        &mut trace,
                    ))
                    .await;
                    if succeeds {
                        assert_eq!(result.unwrap().state().root(), expected.root());
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
            let config = replica_config(
                "historical",
                &context,
                Rayon::new(NonZeroUsize::MIN).unwrap(),
            );
            let account = wallets().remove(0).public_key();
            let key = account_key(&account).unwrap();
            let genesis = vec![(key.clone(), NonZeroU64::new(100))];
            let connection = checkpoints();
            let mut state = Box::pin(recover(
                context.child("genesis"),
                config.clone(),
                &connection,
                genesis.clone(),
                None,
                &mut Recovery::default(),
            ))
            .await
            .unwrap();
            for sequence in 1..=160 {
                let predecessor = state.head();
                let candidate = state
                    .prepare(
                        &predecessor,
                        vec![(key.clone(), NonZeroU64::new(100 + sequence))],
                        ActivityInput::new(Vec::new(), Vec::new()),
                        Vec::new(),
                        commonware_clearing::bajillion::logs::Floors {
                            activity: predecessor.logs.activity.operations - 1,
                            payouts: predecessor.logs.payouts.operations - 1,
                        },
                    )
                    .await
                    .unwrap();
                state = Box::pin(apply_checkpoint(
                    &connection,
                    sequence,
                    state,
                    candidate,
                    &mut Recovery::default(),
                ))
                .await
                .unwrap();
            }
            drop(state);
            let mut trace = Recovery::default();
            let state = Box::pin(recover(
                context.child("recovered"),
                config,
                &connection,
                genesis,
                None,
                &mut trace,
            ))
            .await
            .unwrap();
            assert!(trace.prepared.is_empty());
            assert!(trace.applied.is_empty());
            assert!(state.state().head().operations() > 256);
            for sequence in [0, 1, 31, 32, 127, 128, 159, 160] {
                let checkpoint = checkpoint(&connection, sequence).unwrap();
                let opening = state
                    .state()
                    .opening_at(
                        checkpoint.state.root(),
                        checkpoint.state.operations(),
                        account.clone(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    opening
                        .verify::<Sha256>(&checkpoint.state.root())
                        .unwrap()
                        .get(),
                    100 + sequence
                );
            }
        });
    }

    #[test]
    fn payout_proofs_are_generated_at_requested_retained_heads() {
        deterministic::Runner::default().start(|context| async move {
            let config = replica_config(
                "payout-proofs",
                &context,
                Rayon::new(NonZeroUsize::MIN).unwrap(),
            );
            let mut replica = OperatorReplica::open(context.child("replica"), config)
                .await
                .unwrap();
            let destination = Bytes::from_static(b"destination");
            let mut encoded = Vec::new();
            destination.write(&mut encoded);
            17_u64.write(&mut encoded);
            let output = WithdrawalOutput::decode_cfg(
                encoded,
                &RangeCfg::new(0..=crate::protocol::MAX_DESTINATION_BYTES),
            )
            .unwrap();

            // The first accepted range places its output at the predecessor operation count.
            let predecessor = replica.head();
            let index = predecessor.logs.payouts.operations;
            let prepared = replica
                .prepare(
                    &predecessor,
                    Vec::new(),
                    ActivityInput::new(Vec::new(), Vec::new()),
                    vec![output.clone()],
                    commonware_clearing::bajillion::logs::Floors {
                        activity: 0,
                        payouts: 0,
                    },
                )
                .await
                .unwrap();
            let first = prepared.head();
            replica = replica.apply(prepared).await.unwrap();
            replica = Box::pin(replica.sync()).await.unwrap();
            let claim = payout_claim(&replica, &first.logs.payouts, index)
                .await
                .unwrap();
            assert_eq!(claim.verify::<Sha256>(&first.logs.payouts).unwrap(), output);
            assert!(
                payout_claim(
                    &replica,
                    &first.logs.payouts,
                    first.logs.payouts.operations - 1,
                )
                .await
                .is_err()
            );

            // A later empty range advances the root and supports a refreshed proof for the ID.
            let predecessor = replica.head();
            let prepared = replica
                .prepare(
                    &predecessor,
                    Vec::new(),
                    ActivityInput::new(Vec::new(), Vec::new()),
                    Vec::new(),
                    commonware_clearing::bajillion::logs::Floors {
                        activity: predecessor.logs.activity.operations - 1,
                        payouts: predecessor.logs.payouts.operations - 1,
                    },
                )
                .await
                .unwrap();
            let second = prepared.head();
            replica = replica.apply(prepared).await.unwrap();
            replica = Box::pin(replica.sync()).await.unwrap();
            let historical = payout_claim(&replica, &first.logs.payouts, index)
                .await
                .unwrap();
            assert_eq!(
                historical.verify::<Sha256>(&first.logs.payouts).unwrap(),
                output
            );
            let refreshed = payout_claim(&replica, &second.logs.payouts, index)
                .await
                .unwrap();
            assert_eq!(refreshed.position(), index);
            assert_eq!(
                refreshed.verify::<Sha256>(&second.logs.payouts).unwrap(),
                output
            );
            assert!(
                payout_claim(
                    &replica,
                    &second.logs.payouts,
                    second.logs.payouts.operations - 1,
                )
                .await
                .is_err()
            );
        });
    }
}
