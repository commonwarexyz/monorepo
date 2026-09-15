//! Authenticated native operation transfer for one shared replica checkpoint.

#[cfg(test)]
pub(crate) mod tests;

use super::{
    Lane, NativeReplica,
    checkpoint::{Checkpoint, Retention},
};
use crate::{
    chain::{
        state::{AdmittedRootsResponse, Record, admitted_key, status_key},
        types::Database,
    },
    protocol::{Deployment, Key, MAX_DESTINATION_BYTES},
    rpc,
};
use anyhow::{Context as _, Result, ensure};
use bytes::{BufMut, Bytes};
use commonware_clearing::bajillion::{logs, qmdb, replica::Replica};
use commonware_codec::{
    Buf, Decode as _, DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read,
    ReadExt as _, Write,
};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_macros::select;
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, Network, Spawner};
use commonware_storage::{
    Context as StorageContext,
    merkle::{Location, mmb, mmr},
    qmdb::{
        current::proof::OpsRootWitness,
        sync::{self, Request, Source},
    },
};
use std::{marker::PhantomData, net::SocketAddr, time::Duration};

pub(super) struct Imported<E: StorageContext + Spawner> {
    pub(super) replica: NativeReplica<E>,
    pub(super) transfer: Transfer,
}

/// A single local chain snapshot authenticates the entire target selection.
pub(super) struct Authorities {
    pub(super) first: u64,
    pub(super) finalized: Option<u64>,
    pub(super) entries: Vec<AdmittedRootsResponse>,
}
impl Authorities {
    pub(super) const fn next(&self) -> u64 {
        self.first + self.entries.len() as u64
    }
    pub(super) fn get(&self, epoch: u64) -> Option<&AdmittedRootsResponse> {
        self.entries
            .get(usize::try_from(epoch.checked_sub(self.first)?).ok()?)
    }
    pub(super) fn retention(
        &self,
        target: &Checkpoint,
        source: &commonware_clearing::bajillion::custody::Source<Key, Digest>,
    ) -> Result<Retention> {
        let first = self.entries.first().context("empty admitted suffix")?;
        ensure!(
            source.context().deployment() == &target.deployment
                && source.context().payment().epoch() == self.first
                && source.heads() == first.roots.logs(),
            "protected source does not match finalized authority"
        );
        let predecessor = source.context().predecessor_logs();
        Ok(Retention {
            epoch: self.first,
            state: if self.finalized.is_some() {
                first.roots.successor_sync_boundary
            } else {
                0
            },
            activity: predecessor
                .activity
                .operations
                .min(target.head.logs.activity.floor),
            payouts: predecessor
                .payouts
                .operations
                .min(target.head.logs.payouts.floor),
        })
    }
}
pub(super) async fn capture<E: StorageContext + Spawner>(
    db: &Database<E>,
    deployment: &Digest,
) -> Result<Authorities> {
    let db = db.read().await;
    let finalized = match db.get(&status_key(deployment)).await? {
        Some(Record::Status(status)) => status.last_finalized,
        _ => None,
    };
    let first = finalized.unwrap_or(0);
    let mut epoch = first;
    let mut entries = Vec::new();
    while let Some(Record::Admitted(admitted)) = db.get(&admitted_key(deployment, epoch)).await? {
        entries.push(admitted);
        epoch = epoch.checked_add(1).context("admission epoch overflow")?;
    }
    Ok(Authorities {
        first,
        finalized,
        entries,
    })
}

/// Download a certified coherent checkpoint into an isolated native generation.
#[allow(clippy::too_many_arguments)]
pub(super) async fn download<E: StorageContext + Spawner + Network>(
    context: E,
    authority: Authorities,
    deployment: Deployment,
    config: commonware_clearing::bajillion::replica::Config<Sequential>,
    base: Checkpoint,
    generation: u64,
    retain_history: bool,
    address: SocketAddr,
    timeout: Duration,
) -> Result<Option<Imported<E>>> {
    if authority.next() <= base.next {
        return Ok(None);
    }
    let response = call(
        &context,
        address,
        timeout,
        NativeRequest {
            deployment: *deployment.digest(),
            query: Query::Checkpoint {
                max_next: authority.next(),
            },
        },
    )
    .await?;
    let NativeResponse::Checkpoint(transfer) = response else {
        return Ok(None);
    };
    transfer.check(&deployment)?;
    if transfer.checkpoint.next <= base.next {
        return Ok(None);
    }
    let Some(admitted) = authority.get(transfer.checkpoint.next - 1) else {
        return Ok(None);
    };
    transfer.check_admitted(admitted)?;
    let retained = if retain_history {
        Retention::default()
    } else {
        let first = authority.entries.first().context("empty admitted suffix")?;
        let commit = first
            .roots
            .change
            .operations
            .checked_sub(1)
            .context("empty finalized activity")?;
        let remote = Remote::<_, Activity>::new(
            context.child("retention_source"),
            address,
            timeout,
            *deployment.digest(),
        );
        let (response, _) = remote
            .serve(Request::Operations {
                size: Location::new(first.roots.change.operations),
                start: Location::new(commit),
                max_ops: std::num::NonZeroU64::MIN,
            })
            .await?;
        let sync::Response::Operations { proof, operations } = response else {
            anyhow::bail!("source did not return the finalized Commit");
        };
        let [logs::ActivityOperation::Commit(Some(logs::ActivityRecord::Metadata(metadata)), _)] =
            operations.as_slice()
        else {
            anyhow::bail!("finalized activity boundary is not source metadata");
        };
        let proof = commonware_clearing::bajillion::custody::SourceProof {
            metadata: metadata.clone(),
            opening: logs::Opening {
                start: commit,
                proof,
            },
        };
        let source = proof.verify::<Sha256, Key>(&first.roots.logs())?;
        authority.retention(&transfer.checkpoint, &source)?
    };
    let replica = Box::pin(import(
        context,
        config,
        &deployment,
        &transfer,
        retained,
        address,
        timeout,
    ))
    .await?;
    let mut transfer = *transfer;
    transfer.checkpoint.generation = generation;
    transfer.checkpoint.retained = retained;
    Ok(Some(Imported { replica, transfer }))
}

pub(crate) const METHOD_NATIVE: u8 = 4;
const FETCH_OPERATIONS: usize = 128;

#[derive(Clone, Debug)]
pub(crate) enum Query {
    Checkpoint { max_next: u64 },
    State(Request<mmb::Family>),
    Activity(Request<mmr::Family>),
    Payouts(Request<mmr::Family>),
}

#[derive(Clone, Debug)]
pub(crate) struct NativeRequest {
    pub(crate) deployment: Digest,
    pub(crate) query: Query,
}

impl Write for NativeRequest {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        match &self.query {
            Query::Checkpoint { max_next } => {
                0u8.write(buf);
                max_next.write(buf);
            }
            Query::State(value) => {
                2u8.write(buf);
                value.write(buf);
            }
            Query::Activity(value) => {
                3u8.write(buf);
                value.write(buf);
            }
            Query::Payouts(value) => {
                4u8.write(buf);
                value.write(buf);
            }
        }
    }
}
impl EncodeSize for NativeRequest {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size()
            + 1
            + match &self.query {
                Query::Checkpoint { .. } => 8,
                Query::State(value) => value.encode_size(),
                Query::Activity(value) | Query::Payouts(value) => value.encode_size(),
            }
    }
}
impl Read for NativeRequest {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let deployment = Digest::read(buf)?;
        let query = match u8::read(buf)? {
            0 => Query::Checkpoint {
                max_next: u64::read(buf)?,
            },
            2 => Query::State(Request::read(buf)?),
            3 => Query::Activity(Request::read(buf)?),
            4 => Query::Payouts(Request::read(buf)?),
            tag => return Err(CodecError::InvalidEnum(tag)),
        };
        let count = match &query {
            Query::State(request) => request.max_ops().get(),
            Query::Activity(request) | Query::Payouts(request) => request.max_ops().get(),
            _ => 1,
        };
        if count > FETCH_OPERATIONS as u64 {
            return Err(CodecError::Invalid(
                "NativeRequest",
                "operation batch exceeds limit",
            ));
        }
        Ok(Self { deployment, query })
    }
}

/// The canonical Current root authenticates its separate operations-tree transfer root.
#[derive(Clone, Debug)]
pub(crate) struct Transfer {
    pub(crate) checkpoint: Checkpoint,
    pub(crate) ops_root: Digest,
    pub(crate) witness: OpsRootWitness<mmb::Family, Digest>,
}

impl Transfer {
    pub(super) async fn capture<E: StorageContext + Spawner>(
        replica: &NativeReplica<E>,
        checkpoint: Checkpoint,
    ) -> Result<Self> {
        ensure!(
            replica.head() == checkpoint.head,
            "checkpoint differs from native owner"
        );
        let target = replica
            .state()
            .sync_target(checkpoint.retained.state)
            .await?;
        Ok(Self {
            checkpoint,
            ops_root: target.operations_root,
            witness: target.witness,
        })
    }
    pub(super) fn check_admitted(
        &self,
        admitted: &crate::chain::state::AdmittedRootsResponse,
    ) -> Result<()> {
        ensure!(
            Some(admitted.batch_id.into_digest()) == self.checkpoint.batch
                && admitted.roots.successor == self.checkpoint.head.state.root()
                && admitted.roots.successor_operations == self.checkpoint.head.state.operations()
                && admitted.roots.successor_sync_boundary
                    == self.checkpoint.head.state.sync_boundary()
                && admitted.roots.logs() == self.checkpoint.head.logs,
            "native checkpoint is not the admitted triplet"
        );
        Ok(())
    }
    pub(crate) fn check(&self, deployment: &Deployment) -> Result<()> {
        self.checkpoint.check(deployment)?;
        ensure!(
            self.witness
                .verify::<Sha256>(&self.ops_root, &self.checkpoint.head.state.root().digest),
            "Current operations root is not bound to the certified root"
        );
        Ok(())
    }
}
impl Write for Transfer {
    fn write(&self, buf: &mut impl BufMut) {
        self.checkpoint.write(buf);
        self.ops_root.write(buf);
        self.witness.write(buf);
    }
}
impl EncodeSize for Transfer {
    fn encode_size(&self) -> usize {
        self.checkpoint.encode_size() + self.ops_root.encode_size() + self.witness.encode_size()
    }
}
impl Read for Transfer {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            checkpoint: Checkpoint::read(buf)?,
            ops_root: Digest::read(buf)?,
            witness: OpsRootWitness::read(buf)?,
        })
    }
}

pub(crate) enum NativeResponse {
    Unavailable,
    Checkpoint(Box<Transfer>),
    Data(Bytes),
}
impl Write for NativeResponse {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Unavailable => 0u8.write(buf),
            Self::Checkpoint(value) => {
                1u8.write(buf);
                value.write(buf);
            }
            Self::Data(value) => {
                3u8.write(buf);
                value.write(buf);
            }
        }
    }
}
impl EncodeSize for NativeResponse {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Unavailable => 0,
            Self::Checkpoint(value) => value.encode_size(),
            Self::Data(value) => value.encode_size(),
        }
    }
}
impl Read for NativeResponse {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(match u8::read(buf)? {
            0 => Self::Unavailable,
            1 => Self::Checkpoint(Box::new(Transfer::read(buf)?)),
            3 => Self::Data(Bytes::read_cfg(
                buf,
                &RangeCfg::new(0..=rpc::MAX_BODY_SIZE),
            )?),
            tag => return Err(CodecError::InvalidEnum(tag)),
        })
    }
}

pub(super) async fn serve<E: StorageContext + Spawner>(
    lanes: &[Lane<E>],
    request: NativeRequest,
) -> Result<NativeResponse> {
    let Some(lane) = lanes
        .iter()
        .find(|lane| lane.deployment.digest() == &request.deployment)
    else {
        return Ok(NativeResponse::Unavailable);
    };
    let replica = lane.state.as_ref().context("replica is being replaced")?;
    let manifest = lane
        .checkpoint
        .as_ref()
        .and_then(|store| store.get())
        .context("missing shared checkpoint")?;
    ensure!(
        replica.head() == manifest.complete().checkpoint.head,
        "native transfer requires a complete shared checkpoint"
    );
    let response = match request.query {
        Query::Checkpoint { max_next } => {
            let offer = manifest
                .candidate
                .as_ref()
                .filter(|target| target.checkpoint.next <= max_next)
                .or_else(|| {
                    (manifest.canonical.checkpoint.next <= max_next).then_some(&manifest.canonical)
                });
            offer.map_or(NativeResponse::Unavailable, |target| {
                NativeResponse::Checkpoint(Box::new(target.clone()))
            })
        }
        Query::State(request) => match replica.state().source().serve(request).await {
            Ok((response, _)) => NativeResponse::Data(response.encode()),
            Err(_) => NativeResponse::Unavailable,
        },
        Query::Activity(request) => match replica.logs().activity_source().serve(request).await {
            Ok((response, _)) => NativeResponse::Data(response.encode()),
            Err(_) => NativeResponse::Unavailable,
        },
        Query::Payouts(request) => match replica.logs().payout_source().serve(request).await {
            Ok((response, _)) => NativeResponse::Data(response.encode()),
            Err(_) => NativeResponse::Unavailable,
        },
    };
    Ok(response)
}

pub(super) async fn call<E: Network + Clock>(
    context: &E,
    address: SocketAddr,
    timeout: Duration,
    request: NativeRequest,
) -> Result<NativeResponse> {
    let request = rpc::Request {
        method: METHOD_NATIVE,
        body: request.encode(),
    };
    let response = select! {
        response = rpc::call(context, address, &request) => response?,
        _ = context.sleep(timeout) => anyhow::bail!("native source timed out"),
    };
    let rpc::Response::Success { body } = response else {
        anyhow::bail!("native source rejected request")
    };
    Ok(NativeResponse::decode(body)?)
}

pub(super) struct Remote<E, R> {
    context: E,
    address: SocketAddr,
    timeout: Duration,
    deployment: Digest,
    role: PhantomData<R>,
}
impl<E, R> Remote<E, R> {
    pub(super) const fn new(
        context: E,
        address: SocketAddr,
        timeout: Duration,
        deployment: Digest,
    ) -> Self {
        Self {
            context,
            address,
            timeout,
            deployment,
            role: PhantomData,
        }
    }
}
pub(super) struct Balances;
pub(super) struct Activity;
pub(super) struct Payouts;

#[derive(Debug, thiserror::Error)]
#[error("native source unavailable: {0}")]
pub(super) struct SourceError(String);

macro_rules! source {
    ($role:ident, $family:ty, $op:ty, $variant:ident, $cfg:expr) => {
        impl<E: Network + Clock> Source for Remote<E, $role> {
            type Family = $family;
            type Digest = Digest;
            type Op = $op;
            type Error = SourceError;
            async fn serve(
                &self,
                request: Request<Self::Family>,
            ) -> Result<
                (
                    sync::Response<Self::Family, Self::Op, Digest>,
                    sync::FeedbackTx,
                ),
                SourceError,
            > {
                let result = async {
                    let response = call(
                        &self.context,
                        self.address,
                        self.timeout,
                        NativeRequest {
                            deployment: self.deployment,
                            query: Query::$variant(request),
                        },
                    )
                    .await?;
                    let NativeResponse::Data(bytes) = response else {
                        anyhow::bail!("requested native range is not retained")
                    };
                    let response = sync::Response::decode_cfg(
                        bytes,
                        &(usize::try_from(request.max_ops().get())?, $cfg),
                    )?;
                    Ok((response, None))
                }
                .await;
                result.map_err(|error: anyhow::Error| SourceError(error.to_string()))
            }
        }
    };
}
source!(Balances, mmb::Family, qmdb::StateOperation, State, ());
source!(Activity, mmr::Family, logs::ActivityOperation<Key, Digest>, Activity, RangeCfg::new(0..=rpc::MAX_BODY_SIZE));
source!(
    Payouts,
    mmr::Family,
    logs::PayoutOperation,
    Payouts,
    RangeCfg::new(0..=MAX_DESTINATION_BYTES)
);

/// Each native engine verifies operation and boundary proofs before rebuilding its database.
async fn database<DB, S>(
    context: DB::Context,
    db_config: DB::Config,
    target: sync::Target<DB::Family, DB::Digest>,
    source: S,
) -> Result<DB>
where
    DB: sync::Database,
    DB::Op: commonware_codec::Encode,
    S: sync::SourceFor<DB>,
{
    sync::sync(sync::engine::Config {
        context,
        source,
        target,
        max_outstanding_requests: 4,
        fetch_batch_size: commonware_utils::NZU64!(128),
        apply_batch_size: commonware_utils::NZU64!(128),
        db_config,
        update_rx: None,
        finish_rx: None,
        reached_target_tx: None,
        max_retained_roots: 0,
    })
    .await
    .map_err(|error| anyhow::anyhow!("native checkpoint import: {error}"))
}

/// Import one certified triplet into a fresh local partition generation.
///
/// The caller publishes the shared checkpoint only after all three native engines finish.
#[allow(clippy::too_many_arguments)]
pub(super) async fn import<E>(
    context: E,
    config: commonware_clearing::bajillion::replica::Config<Sequential>,
    deployment: &Deployment,
    transfer: &Transfer,
    retained: Retention,
    address: SocketAddr,
    timeout: Duration,
) -> Result<NativeReplica<E>>
where
    E: StorageContext + Spawner + Network,
{
    transfer.check(deployment)?;
    let mut expected = transfer.checkpoint.clone();
    expected.retained = retained;
    expected.check(deployment)?;
    let current = qmdb::StateTarget {
        head: expected.head.state,
        operations_root: transfer.ops_root,
        witness: transfer.witness.clone(),
        start: retained.state,
    };
    let native = database::<qmdb::StateDb<E, Sha256, Sequential>, _>(
        context.child("state_sync"),
        config.state,
        current.native::<Sha256>()?,
        Remote::<_, Balances>::new(
            context.child("source"),
            address,
            timeout,
            *deployment.digest(),
        ),
    )
    .await?;
    ensure!(
        native.root() == expected.head.state.root().digest,
        "imported Current root mismatch"
    );
    let state = qmdb::State::<_, Sha256>::from_db(native, &expected.head.state).await?;
    let target =
        |head: logs::LogHead<Digest>, start: u64| -> Result<sync::Target<mmr::Family, Digest>> {
            Ok(sync::Target::new(
                head.root,
                commonware_utils::range::NonEmptyRange::try_from(
                    Location::new(start)..Location::new(head.operations),
                )?,
            ))
        };
    let activity_cfg = config.logs.activity.log.codec_config;
    let payout_cfg = config.logs.payouts.log.codec_config;
    let activity = database::<logs::ActivityDb<E, Sha256, Key, Sequential>, _>(
        context.child("activity_sync"),
        config.logs.activity,
        target(expected.head.logs.activity, retained.activity)?,
        Remote::<_, Activity>::new(
            context.child("source"),
            address,
            timeout,
            *deployment.digest(),
        ),
    )
    .await?;
    let payouts = database::<logs::PayoutDb<E, Sha256, Sequential>, _>(
        context.child("payout_sync"),
        config.logs.payouts,
        target(expected.head.logs.payouts, retained.payouts)?,
        Remote::<_, Payouts>::new(context, address, timeout, *deployment.digest()),
    )
    .await?;
    let replica = Replica::from_parts(
        state,
        logs::Logs::from_parts(activity, payouts, activity_cfg, payout_cfg),
    );
    ensure!(
        replica.head() == expected.head,
        "native import mixed checkpoint heads"
    );
    replica.sync().await.map_err(Into::into)
}
