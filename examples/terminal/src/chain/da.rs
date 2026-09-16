//! Native close certification, checkpoint recovery, and proof serving.
//!
//! A vote becomes visible only after all three public stores and the private candidate
//! checkpoint are durable. Recovery rewinds the public stores to the selected common checkpoint.
//! Independent replicas may retain older native history for proof availability.

#[cfg(feature = "bench")]
pub(crate) mod benches;
mod checkpoint;
mod config;
#[cfg(test)]
mod durability;
mod proofs;
pub(crate) mod sync;
#[cfg(test)]
pub(crate) mod tests;

use crate::{
    chain::{
        query::{EvidenceRequest, EvidenceResponse},
        registry::RegistryView,
        setup::ValidatorEntry,
        state::{Machine, Record, machine_key, status_key},
        types::Database,
        validator::MAILBOX_SIZE,
    },
    protocol::{Deployment, Key, genesis_balances},
    rpc,
};
use anyhow::{Context as _, Result, ensure};
use bytes::{BufMut, Bytes};
use commonware_actor::mailbox::{self, UnreliablePolicy, UnreliableReceiver, UnreliableSender};
use commonware_clearing::bajillion::{
    admission::{Vote, bls12381, seal},
    logs::{Floors, Heads},
    replica::{PreparedReplica, Replica},
    transition::{CloseContext, EpochContext, Header, RootBundle},
};
use commonware_codec::{
    Buf, DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read,
    ReadExt as _, Write,
};
use commonware_cryptography::{Sha256, ed25519, sha256::Digest};
use commonware_cryptography_curve25519::signing::BatchVerifier as PaymentBatchVerifier;
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_parallel::Rayon;
use commonware_runtime::{
    ContextCell, Handle, IoBuf, Metrics, Network, Spawner, buffer::paged::CacheRef, spawn_cell,
};
use commonware_storage::Context as StorageContext;
use commonware_utils::channel::{fallible::OneshotExt as _, oneshot};
pub(crate) use config::replica_config;
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::FuturesUnordered};
use rand_core::CryptoRng;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tracing::{debug, error, warn};

pub(crate) type NativeReplica<E> = Replica<E, Sha256, Key, Rayon>;

/// One immutable complete dealing, shared by every validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Dealing {
    pub(crate) deployment: Digest,
    pub(crate) epoch: u64,
    pub(crate) context: EpochContext<Key, Digest>,
    pub(crate) bytes: Bytes,
}
impl Dealing {
    pub(crate) fn id(&self) -> Digest {
        *commonware_clearing::bajillion::transition::ProposalId::for_dealing::<Sha256, _>(
            &self.context,
            &self.bytes,
        )
        .digest()
    }
}
impl Write for Dealing {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.epoch.write(buf);
        self.context.write(buf);
        self.bytes.write(buf);
    }
}
impl EncodeSize for Dealing {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size()
            + self.epoch.encode_size()
            + self.context.encode_size()
            + self.bytes.encode_size()
    }
}
impl Read for Dealing {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            epoch: u64::read(buf)?,
            context: EpochContext::read(buf)?,
            bytes: Bytes::read_cfg(buf, &RangeCfg::new(0..=rpc::MAX_BODY_SIZE))?,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Ballot {
    pub(crate) deployment: Digest,
    pub(crate) epoch: u64,
    pub(crate) proposal: Digest,
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) withdrawal_total: u64,
    pub(crate) vote: Vote,
}
impl Write for Ballot {
    fn write(&self, buf: &mut impl BufMut) {
        self.deployment.write(buf);
        self.epoch.write(buf);
        self.proposal.write(buf);
        self.context.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.withdrawal_total.write(buf);
        self.vote.write(buf);
    }
}
impl EncodeSize for Ballot {
    fn encode_size(&self) -> usize {
        self.deployment.encode_size()
            + self.epoch.encode_size()
            + self.proposal.encode_size()
            + self.context.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.withdrawal_total.encode_size()
            + self.vote.encode_size()
    }
}
impl Read for Ballot {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            deployment: Digest::read(buf)?,
            epoch: u64::read(buf)?,
            proposal: Digest::read(buf)?,
            context: CloseContext::read(buf)?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            withdrawal_total: u64::read(buf)?,
            vote: Vote::read(buf)?,
        })
    }
}
pub(crate) enum Message {
    Dealing(Box<Dealing>),
    Vote(Box<Ballot>),
}
impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Dealing(v) => {
                0u8.write(buf);
                v.write(buf)
            }
            Self::Vote(v) => {
                1u8.write(buf);
                v.write(buf)
            }
        }
    }
}
impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Dealing(v) => v.encode_size(),
            Self::Vote(v) => v.encode_size(),
        }
    }
}
impl Read for Message {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        match u8::read(buf)? {
            0 => Ok(Self::Dealing(Box::new(Dealing::read(buf)?))),
            1 => Ok(Self::Vote(Box::new(Ballot::read(buf)?))),
            v => Err(CodecError::InvalidEnum(v)),
        }
    }
}

impl Ballot {
    fn check(&self) -> Result<()> {
        ensure!(
            self.deployment == *self.context.deployment()
                && self.epoch == self.context.payment().epoch()
                && self.proposal == *self.roots.proposal.digest()
                && self.header
                    == Header::new::<Sha256, _>(&self.context, &self.roots, self.withdrawal_total),
            "voting decision context mismatch"
        );
        Ok(())
    }
}

/// Every backwards transition selects its durable target before truncating native stores.
#[commonware_macros::boxed]
async fn recover<E: StorageContext + Spawner>(
    mut replica: NativeReplica<E>,
    deployment: &Deployment,
    mut checkpoints: checkpoint::Store<E>,
) -> Result<(NativeReplica<E>, checkpoint::Store<E>)> {
    if checkpoints.get().is_none() {
        let (mut state, logs) = replica.into_parts();
        if state.is_bootstrap() {
            let candidate = state
                .prepare(
                    state.head(),
                    genesis_balances(deployment)?
                        .into_iter()
                        .map(|(key, balance)| (key, Some(balance)))
                        .collect(),
                )
                .await?;
            ensure!(
                (candidate.root(), candidate.head().operations())
                    == (
                        deployment.genesis().root(),
                        deployment.genesis().operations()
                    ),
                "configured genesis mismatch"
            );
            state = state.apply(candidate).await?.sync().await?;
        }
        replica = Replica::from_parts(state, logs).sync().await?;
        ensure!(
            (replica.state().root(), replica.state().head().operations())
                == (
                    deployment.genesis().root(),
                    deployment.genesis().operations()
                )
                && *replica.logs().head() == Heads::empty::<Key, Sha256>(),
            "native replica has no completed checkpoint"
        );
        let canonical = sync::Transfer::capture(
            &replica,
            checkpoint::Checkpoint::genesis(deployment, &replica),
        )
        .await?;
        checkpoints = checkpoints
            .put(checkpoint::Manifest {
                canonical,
                candidate: None,
                decision: None,
                garbage: None,
            })
            .await?;
    }
    let manifest = checkpoints.get().unwrap();
    manifest.check(deployment)?;
    let complete = &manifest.complete().checkpoint;
    replica = replica.rewind(&complete.head).await?;
    if manifest.candidate.is_none() {
        let retained = complete.retained;
        replica = replica
            .prune(
                &complete.head,
                retained.state,
                Floors {
                    activity: retained.activity,
                    payouts: retained.payouts,
                },
            )
            .await?;
    }
    Ok((replica, checkpoints))
}

/// The native triplet is durable before its candidate and voting decision are published.
#[commonware_macros::boxed]
async fn persist_candidate<E: StorageContext + Spawner>(
    lane: &mut Lane<E>,
    prepared: PreparedReplica<Key, Digest, Rayon>,
    ballot: Ballot,
) -> Result<()> {
    let mut manifest = lane.manifest().as_ref().clone();
    ensure!(
        manifest.candidate.is_none() && manifest.decision.is_none(),
        "registration already has a voting decision"
    );
    let replica = lane
        .state
        .take()
        .expect("replica owner")
        .apply(prepared)
        .await?
        .commit()
        .await?;
    let mut checkpoint = manifest.canonical.checkpoint.clone();
    checkpoint.next = checkpoint.next.checked_add(1).context("epoch overflow")?;
    checkpoint.batch = Some(ballot.header.batch_id::<Sha256>().into_digest());
    checkpoint.head = replica.head();
    manifest.candidate = Some(sync::Transfer::capture(&replica, checkpoint).await?);
    manifest.decision = Some(ballot);
    manifest.check(&lane.deployment)?;
    lane.state = Some(replica);
    lane.checkpoint = Some(lane.checkpoint.take().unwrap().put(manifest).await?);
    Ok(())
}

/// Select the durable parent before any native candidate data is truncated.
async fn discard<E: StorageContext + Spawner>(lane: &mut Lane<E>) -> Result<()> {
    let mut manifest = lane.manifest().as_ref().clone();
    if manifest.candidate.take().is_none() {
        return Ok(());
    }
    let target = manifest.canonical.checkpoint.head;
    lane.checkpoint = Some(lane.checkpoint.take().unwrap().put(manifest).await?);
    lane.state = Some(lane.state.take().unwrap().rewind(&target).await?);
    Ok(())
}

pub(crate) struct Config<E: Spawner + StorageContext> {
    pub(crate) strategy: Rayon,
    pub(crate) page_cache: CacheRef,
    pub(crate) scheme: bls12381::Scheme,
    pub(crate) registry: RegistryView,
    pub(crate) db: Database<E>,
    pub(crate) partition: String,
    pub(crate) validators: Vec<ValidatorEntry>,
    pub(crate) fetch_timeout: Duration,
    pub(crate) retain_history: bool,
}
struct Lane<E: StorageContext + Spawner> {
    deployment: Deployment,
    pending: Option<Dealing>,
    state: Option<NativeReplica<E>>,
    checkpoint: Option<checkpoint::Store<E>>,
}
impl<E: StorageContext + Spawner> Lane<E> {
    fn manifest(&self) -> Arc<checkpoint::Manifest> {
        self.checkpoint
            .as_ref()
            .and_then(|store| store.get())
            .expect("initialized checkpoint")
    }
    fn next(&self) -> u64 {
        self.manifest().canonical.checkpoint.next
    }
}
type ImportCompletion<E> = (usize, usize, Result<Option<sync::Imported<E>>>);
type Imports<E> = FuturesUnordered<BoxFuture<'static, ImportCompletion<E>>>;
pub(crate) struct Serve {
    request: EvidenceRequest,
    response: oneshot::Sender<EvidenceResponse>,
}
enum Work {
    Evidence(Box<Serve>),
    Native {
        request: sync::NativeRequest,
        response: oneshot::Sender<sync::NativeResponse>,
    },
}
impl UnreliablePolicy for Work {
    type Overflow = VecDeque<Self>;
    fn handle(_: &mut VecDeque<Self>, _: Self) -> bool {
        false
    }
}
#[derive(Clone)]
pub(crate) struct Mailbox {
    sender: UnreliableSender<Work>,
}
impl Mailbox {
    pub(crate) async fn serve(&self, request: EvidenceRequest) -> Result<EvidenceResponse> {
        let (response, rx) = oneshot::channel();
        ensure!(
            !self
                .sender
                .enqueue(Work::Evidence(Box::new(Serve { request, response })))
                .is_rejected(),
            "sealer mailbox full"
        );
        rx.await.context("sealer stopped")
    }
    pub(crate) async fn native(
        &self,
        request: sync::NativeRequest,
    ) -> Result<sync::NativeResponse> {
        let (response, rx) = oneshot::channel();
        ensure!(
            !self
                .sender
                .enqueue(Work::Native { request, response })
                .is_rejected(),
            "sealer mailbox full"
        );
        rx.await.context("sealer stopped")
    }
}
pub(crate) struct Sealer<E: Spawner + Metrics + Network + StorageContext + CryptoRng> {
    context: ContextCell<E>,
    strategy: Rayon,
    page_cache: CacheRef,
    scheme: bls12381::Scheme,
    registry: RegistryView,
    db: Database<E>,
    partition: String,
    validators: Vec<ValidatorEntry>,
    fetch_timeout: Duration,
    retain_history: bool,
    mailbox: UnreliableReceiver<Work>,
}
impl<E: Spawner + Metrics + Network + StorageContext + CryptoRng> Sealer<E> {
    pub(crate) fn new(context: E, config: Config<E>) -> (Self, Mailbox) {
        assert!(config.scheme.me().is_some());
        let (sender, mailbox) = mailbox::new_unreliable(context.child("mailbox"), MAILBOX_SIZE);
        (
            Self {
                context: ContextCell::new(context),
                strategy: config.strategy,
                page_cache: config.page_cache,
                scheme: config.scheme,
                registry: config.registry,
                db: config.db,
                partition: config.partition,
                validators: config.validators,
                fetch_timeout: config.fetch_timeout,
                retain_history: config.retain_history,
                mailbox,
            },
            Mailbox { sender },
        )
    }
    pub(crate) fn start<Se, Re>(mut self, channel: (Se, Re)) -> Handle<()>
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        spawn_cell!(self.context, self.run(channel))
    }
    async fn run<Se, Re>(mut self, (mut sender, mut receiver): (Se, Re))
    where
        Se: Sender<PublicKey = ed25519::PublicKey>,
        Re: Receiver<PublicKey = ed25519::PublicKey>,
    {
        let result: Result<()> = async {
            let mut lanes = Vec::new();
            let mut imports = Imports::new();
            for entry in self.registry.entries() { self.lane(&mut lanes, &entry.deployment).await?; }
            let interval = Duration::from_millis(100);
            let mut tick = self.context.sleep(interval).boxed();
            loop {
                // Every ready source gets a turn, including a persistent maintenance deadline.
                let mut progressed = false;
                if tick.as_mut().now_or_never().is_some() {
                    for position in 0..lanes.len() { self.reconcile(&mut lanes, &mut imports, position).await?; }
                    tick = self.context.sleep(interval).boxed();
                    progressed = true;
                }
                if let Some(Some(completion)) = imports.next().now_or_never() {
                    self.imported(&mut lanes, &mut imports, completion, &mut sender).await?;
                    progressed = true;
                }
                if let Some(message) = self.mailbox.recv().now_or_never() {
                    let Some(message) = message else { return Ok(()); };
                    self.request_work(&mut lanes, &mut imports, message).await?;
                    progressed = true;
                }
                if let Some(incoming) = receiver.recv().now_or_never() {
                    let Ok((peer, bytes)) = incoming else { return Ok(()); };
                    self.incoming(&mut lanes, &mut imports, peer, bytes, &mut sender).await?;
                    progressed = true;
                }
                if progressed { commonware_runtime::reschedule().await; continue; }
                select! {
                    _ = &mut tick => {
                        for position in 0..lanes.len() { self.reconcile(&mut lanes, &mut imports, position).await?; }
                        tick = self.context.sleep(interval).boxed();
                    },
                    completion = async { if imports.is_empty() { std::future::pending().await } else { imports.next().await } } => {
                        self.imported(&mut lanes, &mut imports, completion.expect("nonempty import set"), &mut sender).await?;
                    },
                    message = self.mailbox.recv() => {
                        let Some(message) = message else { return Ok(()); };
                        self.request_work(&mut lanes, &mut imports, message).await?;
                    },
                    incoming = receiver.recv() => {
                        let Ok((peer, bytes)) = incoming else { return Ok(()); };
                        self.incoming(&mut lanes, &mut imports, peer, bytes, &mut sender).await?;
                    },
                }
            }
        }.await;
        if let Err(error) = result {
            error!(?error, "validator replica owner stopped");
        }
    }
    #[commonware_macros::boxed]
    async fn lane(&self, lanes: &mut Vec<Lane<E>>, deployment: &Deployment) -> Result<usize> {
        if let Some(position) = lanes
            .iter()
            .position(|lane| lane.deployment.digest() == deployment.digest())
        {
            return Ok(position);
        }
        let mut checkpoints = checkpoint::Store::open(
            self.context.child("checkpoint"),
            &self.partition,
            deployment.digest(),
            self.page_cache.clone(),
        )
        .await?;
        if let Some(generation) = checkpoints.get().and_then(|manifest| manifest.garbage) {
            config::remove_generation(
                self.context.as_present(),
                self.config(deployment.digest(), generation),
            )
            .await?;
            checkpoints = checkpoints.retired().await?;
        }
        let generation = checkpoints
            .get()
            .map_or(0, |manifest| manifest.canonical.checkpoint.generation);
        let replica = NativeReplica::open(
            self.context.child("replica"),
            self.config(deployment.digest(), generation),
        )
        .await?;
        let (replica, checkpoints) = recover(replica, deployment, checkpoints).await?;
        if self.retain_history {
            ensure!(
                checkpoints.get().unwrap().canonical.checkpoint.retained
                    == checkpoint::Retention::default(),
                "pruned native history cannot be restored by changing retention policy"
            );
        }
        let position = lanes.len();
        lanes.push(Lane {
            deployment: deployment.clone(),
            pending: None,
            state: Some(replica),
            checkpoint: Some(checkpoints),
        });
        Ok(position)
    }
    fn config(
        &self,
        deployment: &Digest,
        generation: u64,
    ) -> commonware_clearing::bajillion::replica::Config<Rayon> {
        replica_config(
            &format!("{}-replica-{deployment}-{generation}", self.partition),
            self.page_cache.clone(),
            self.strategy.clone(),
        )
    }
    async fn incoming<Se: Sender<PublicKey = ed25519::PublicKey>>(
        &mut self,
        lanes: &mut Vec<Lane<E>>,
        imports: &mut Imports<E>,
        peer: ed25519::PublicKey,
        bytes: IoBuf,
        sender: &mut Se,
    ) -> Result<()> {
        let mut prefix = bytes.clone();
        let Ok(0) = u8::read(&mut prefix) else {
            return Ok(());
        };
        let Ok(deployment) = Digest::read(&mut prefix) else {
            return Ok(());
        };
        let Some(entry) = self.registry.get(&deployment) else {
            return Ok(());
        };
        if entry.network_key != peer || bytes.len() > entry.max_dealing_bytes as usize {
            return Ok(());
        }
        let Ok(Message::Dealing(dealing)) = Message::decode(bytes) else {
            return Ok(());
        };
        let position = self.lane(lanes, &entry.deployment).await?;
        self.deal(lanes, imports, position, *dealing, sender).await
    }
    async fn request_work(
        &mut self,
        lanes: &mut Vec<Lane<E>>,
        imports: &mut Imports<E>,
        work: Work,
    ) -> Result<()> {
        let deployment = match &work {
            Work::Evidence(request) => request.request.deployment,
            Work::Native { request, .. } => request.deployment,
        };
        if let Some(entry) = self.registry.get(&deployment) {
            let position = self.lane(lanes, &entry.deployment).await?;
            self.reconcile(lanes, imports, position).await?;
        }
        match work {
            Work::Evidence(request) => {
                let served = proofs::serve(lanes, request.request)
                    .await
                    .unwrap_or_else(|error| {
                        debug!(?error, "requested native proof is unavailable");
                        EvidenceResponse::Unsealed
                    });
                request.response.send_lossy(served);
            }
            Work::Native { request, response } => {
                let served = sync::serve(lanes, request).await.unwrap_or_else(|error| {
                    debug!(?error, "requested native range is unavailable");
                    sync::NativeResponse::Unavailable
                });
                response.send_lossy(served);
            }
        }
        Ok(())
    }
    #[commonware_macros::boxed]
    async fn deal<Se: Sender<PublicKey = ed25519::PublicKey>>(
        &mut self,
        lanes: &mut [Lane<E>],
        imports: &mut Imports<E>,
        position: usize,
        dealing: Dealing,
        sender: &mut Se,
    ) -> Result<()> {
        let deployment = *lanes[position].deployment.digest();
        if dealing.deployment != deployment
            || dealing.context.deployment() != &deployment
            || dealing.context.payment().epoch() != dealing.epoch
        {
            return Ok(());
        }
        self.reconcile(lanes, imports, position).await?;
        let (machine, height) = {
            let db = self.db.read().await;
            let Some(Record::Machine(bytes)) = db.get(&machine_key(&deployment)).await? else {
                return Ok(());
            };
            let height = match db.get(&status_key(&deployment)).await? {
                Some(Record::Status(status)) if !status.hard_faulted => status.height,
                _ => return Ok(()),
            };
            (Machine::decode(bytes)?, height)
        };
        let Some(registered) = machine.registered() else {
            return Ok(());
        };
        if registered.context.epoch_context() != &dealing.context
            || height > registered.context.admission_deadline()
        {
            return Ok(());
        }
        let peer = self
            .registry
            .get(&deployment)
            .expect("authorized deployment")
            .network_key
            .clone();
        let lane = &mut lanes[position];
        if let Some(decision) = &lane.manifest().decision {
            if lane.manifest().candidate.is_some()
                && decision.epoch == dealing.epoch
                && decision.proposal == dealing.id()
                && decision.context == *registered.context
            {
                Self::vote(sender, &peer, decision.clone());
            }
            return Ok(());
        }
        let importing = lane.manifest().garbage.is_some();
        if lane.next() != dealing.epoch
            || importing
            || lane.state.as_ref().unwrap().state().root() != *registered.context.predecessor_root()
        {
            if importing {
                lane.pending = Some(dealing);
            }
            return Ok(());
        }
        let result = seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
            &self.scheme,
            lane.state.as_ref().unwrap(),
            registered.context,
            &lane.deployment.operator_ack,
            registered.deposits,
            registered.withdrawals,
            dealing.bytes.clone(),
            self.context.as_mut(),
            &self.strategy,
        )
        .await;
        let Ok((vote, prepared)) = result else {
            warn!(epoch = dealing.epoch, "complete dealing validation failed");
            return Ok(());
        };
        let close = prepared.close();
        let ballot = Ballot {
            deployment,
            epoch: dealing.epoch,
            proposal: dealing.id(),
            context: registered.context.clone(),
            header: close.header,
            roots: close.roots,
            withdrawal_total: close.withdrawal_total,
            vote,
        };
        ballot.check()?;
        persist_candidate(lane, prepared.into_parts().1, ballot.clone()).await?;
        let active = {
            let db = self.db.read().await;
            matches!(db.get(&status_key(&deployment)).await?, Some(Record::Status(status)) if !status.hard_faulted && status.height <= ballot.context.admission_deadline())
        };
        if active {
            Self::vote(sender, &peer, ballot);
        }
        Ok(())
    }
    async fn reconcile(
        &self,
        lanes: &mut [Lane<E>],
        imports: &mut Imports<E>,
        position: usize,
    ) -> Result<()> {
        let lane = &mut lanes[position];
        let authority = sync::capture(&self.db, lane.deployment.digest()).await?;
        if let Some(candidate) = lane.manifest().candidate.as_ref() {
            let epoch = candidate.checkpoint.next - 1;
            if authority
                .get(epoch)
                .is_some_and(|admitted| candidate.check_admitted(admitted).is_ok())
            {
                let mut manifest = lane.manifest().as_ref().clone();
                manifest.canonical = manifest.candidate.take().unwrap();
                manifest.decision = None;
                lane.checkpoint = Some(lane.checkpoint.take().unwrap().put(manifest).await?);
            } else {
                let expired = {
                    let db = self.db.read().await;
                    match db.get(&status_key(lane.deployment.digest())).await? {
                        Some(Record::Status(status)) => {
                            status.hard_faulted
                                || status.height
                                    > lane
                                        .manifest()
                                        .decision
                                        .as_ref()
                                        .unwrap()
                                        .context
                                        .admission_deadline()
                        }
                        _ => false,
                    }
                };
                if expired && authority.get(epoch).is_none() {
                    discard(lane).await?;
                }
            }
        }
        if lane.manifest().garbage.is_none() && authority.next() > lane.next() {
            self.begin_import(lanes, imports, position, 0).await?;
        }
        if !self.retain_history && lanes[position].manifest().candidate.is_none() {
            self.maybe_prune(&mut lanes[position], &authority).await?;
        }
        Ok(())
    }
    async fn maybe_prune(&self, lane: &mut Lane<E>, authority: &sync::Authorities) -> Result<()> {
        let Some(epoch) = authority.finalized else {
            return Ok(());
        };
        let complete = &lane.manifest().canonical.checkpoint;
        if epoch <= complete.retained.epoch || epoch >= complete.next {
            return Ok(());
        }
        let replica = lane.state.as_ref().unwrap();
        let first = authority
            .entries
            .first()
            .context("empty finalized suffix")?;
        let payout_commit = sync::payout_predecessor(
            replica.logs().payout_source(),
            &first.roots.withdrawal_outputs,
            complete.retained.payouts,
        )
        .await?;
        let retained = authority.retention(complete, payout_commit)?;
        Self::prune(lane, retained).await
    }
    async fn prune(lane: &mut Lane<E>, retained: checkpoint::Retention) -> Result<()> {
        let mut manifest = lane.manifest().as_ref().clone();
        ensure!(manifest.candidate.is_none(), "candidate cannot be pruned");
        let complete = &mut manifest.canonical.checkpoint;
        ensure!(
            retained.state >= complete.retained.state
                && retained.activity >= complete.retained.activity
                && retained.payouts >= complete.retained.payouts,
            "retention regressed"
        );
        complete.retained = retained;
        complete.check(&lane.deployment)?;
        let target = complete.head;
        lane.checkpoint = Some(lane.checkpoint.take().unwrap().put(manifest).await?);
        lane.state = Some(
            lane.state
                .take()
                .unwrap()
                .prune(
                    &target,
                    retained.state,
                    Floors {
                        activity: retained.activity,
                        payouts: retained.payouts,
                    },
                )
                .await?,
        );
        Ok(())
    }
    async fn begin_import(
        &self,
        lanes: &mut [Lane<E>],
        imports: &mut Imports<E>,
        position: usize,
        holder: usize,
    ) -> Result<()> {
        if holder == self.validators.len() {
            return Ok(());
        }
        let lane = &mut lanes[position];
        if lane.manifest().garbage.is_some() {
            return Ok(());
        }
        let authority = sync::capture(&self.db, lane.deployment.digest()).await?;
        if authority.next() <= lane.next() {
            return Ok(());
        }
        let base = lane.manifest().canonical.checkpoint.clone();
        let generation = base
            .generation
            .checked_add(1)
            .context("replica generation overflow")?;
        lane.checkpoint = Some(lane.checkpoint.take().unwrap().stage(generation).await?);
        let context = self.context.child("checkpoint_import");
        let deployment = lane.deployment.clone();
        let config = self.config(deployment.digest(), generation);
        let address = self.validators[holder].query;
        let timeout = self.fetch_timeout;
        let retain_history = self.retain_history;
        imports.push(
            async move {
                (
                    position,
                    holder,
                    sync::download(
                        context,
                        authority,
                        deployment,
                        config,
                        base,
                        generation,
                        retain_history,
                        address,
                        timeout,
                    )
                    .await,
                )
            }
            .boxed(),
        );
        Ok(())
    }
    async fn imported<Se: Sender<PublicKey = ed25519::PublicKey>>(
        &mut self,
        lanes: &mut [Lane<E>],
        imports: &mut Imports<E>,
        (position, holder, result): ImportCompletion<E>,
        sender: &mut Se,
    ) -> Result<()> {
        let lane = &mut lanes[position];
        let mut progressed = false;
        let retired = match result {
            Ok(Some(sync::Imported { replica, transfer }))
                if transfer.checkpoint.next > lane.next() =>
            {
                let mut manifest = lane.manifest().as_ref().clone();
                ensure!(
                    manifest.garbage == Some(transfer.checkpoint.generation),
                    "unreserved import generation"
                );
                manifest.garbage = Some(manifest.canonical.checkpoint.generation);
                manifest.canonical = transfer;
                manifest.candidate = None;
                if manifest
                    .decision
                    .as_ref()
                    .is_some_and(|decision| decision.epoch < manifest.canonical.checkpoint.next)
                {
                    manifest.decision = None;
                }
                manifest.check(&lane.deployment)?;
                lane.checkpoint = Some(lane.checkpoint.take().unwrap().put(manifest).await?);
                let retired = lane.state.replace(replica);
                progressed = true;
                retired
            }
            Ok(Some(imported)) => Some(imported.replica),
            Ok(None) => None,
            Err(error) => {
                debug!(?error, holder, "native source unavailable");
                None
            }
        };
        if let Some(retired) = retired {
            retired.destroy().await?;
        } else {
            let generation = lane.manifest().garbage.expect("staged generation");
            config::remove_generation(
                self.context.as_present(),
                self.config(lane.deployment.digest(), generation),
            )
            .await?;
        }
        lane.checkpoint = Some(lane.checkpoint.take().unwrap().retired().await?);
        if progressed {
            self.reconcile(lanes, imports, position).await?;
            if let Some(dealing) = lanes[position].pending.take() {
                self.deal(lanes, imports, position, dealing, sender).await?;
            }
        } else {
            self.begin_import(lanes, imports, position, holder + 1)
                .await?;
        }
        Ok(())
    }
    fn vote<Se: Sender<PublicKey = ed25519::PublicKey>>(
        sender: &mut Se,
        operator: &ed25519::PublicKey,
        ballot: Ballot,
    ) {
        let epoch = ballot.epoch;
        if sender
            .send(
                Recipients::One(operator.clone()),
                Message::Vote(Box::new(ballot)).encode(),
                true,
            )
            .is_empty()
        {
            debug!(epoch, "operator will retry lost vote");
        }
    }
}

async fn payout<E: StorageContext + Spawner>(
    replica: &NativeReplica<E>,
    head: &commonware_clearing::bajillion::logs::LogHead<Digest>,
    index: u64,
) -> Result<commonware_clearing::bajillion::transition::WithdrawalClaim<Digest>> {
    let (opening, operations) = replica
        .logs()
        .payout_opening(head, index, std::num::NonZeroU64::MIN)
        .await?;
    let [commonware_storage::qmdb::keyless::Operation::Append(output)] = operations.as_slice()
    else {
        anyhow::bail!("payout index is not an Append");
    };
    let claim =
        commonware_clearing::bajillion::transition::WithdrawalClaim::new(output.clone(), opening);
    claim.verify::<Sha256>(head)?;
    Ok(claim)
}
