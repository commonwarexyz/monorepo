//! Full-close certification and retained balance proof service.
//!
//! Each validator validates the complete dealing against its own balance replica and the
//! chain's registered context. Candidate mutations and evidence become durable before voting.
//! Consensus selects the canonical history; its records precede state application and commit.
//! A restart replays that history without treating an unselected vote as branch authority.

use crate::{
    chain::{
        query::{
            Evidence, EvidenceBody, EvidenceLookup, EvidenceRequest, EvidenceResponse,
            METHOD_EVIDENCE,
        },
        setup::ValidatorEntry,
        state::{Machine, Record, admitted_key, machine_key, status_key},
        types::Database,
        validator::{IO_BUFFER_SIZE, MAILBOX_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE},
    },
    protocol::{
        Deployment, Key, MAX_ACCOUNTS, MAX_DESTINATION_BYTES, MAX_WITHDRAWALS, genesis_balances,
        state_config,
    },
    rpc,
};
use anyhow::{Context as _, Result, ensure};
use bytes::{Buf, BufMut, Bytes};
use commonware_actor::mailbox::{self, UnreliablePolicy, UnreliableReceiver, UnreliableSender};
use commonware_clearing::bajillion::{
    admission::{Vote, bls12381, seal},
    boundary::{DepositBatch, WithdrawalBatch},
    qmdb::{Mutations, State, StateLookup, StateOpening, account_key},
    serve::{Index, ServeError},
    transition::{
        Close, CloseAmounts, CloseContext, Header, PreparedClose, RootBundle, TransitionError,
    },
};
use commonware_codec::{
    DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _,
    Write,
};
use commonware_cryptography::{Sha256, ed25519, sha256::Digest};
use commonware_cryptography_curve25519::signing::BatchVerifier as PaymentBatchVerifier;
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    ContextCell, Handle, Metrics, Network, Spawner, buffer::paged::CacheRef, spawn_cell,
};
use commonware_storage::{
    Context as StorageContext,
    archive::{Archive as _, Identifier, prunable},
    translator::TwoCap,
};
use commonware_utils::{
    NZU64,
    channel::{fallible::OneshotExt as _, oneshot},
};
use rand_core::CryptoRng;
use std::{collections::VecDeque, pin::pin, time::Duration};
use tracing::{debug, error, warn};

/// One immutable complete dealing, shared by every validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Dealing {
    pub(crate) epoch: u64,
    pub(crate) header: Header<Digest>,
    pub(crate) bytes: Bytes,
}
impl Write for Dealing {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.header.write(buf);
        self.bytes.write(buf);
    }
}
impl EncodeSize for Dealing {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.header.encode_size() + self.bytes.encode_size()
    }
}
impl Read for Dealing {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            header: Header::read(buf)?,
            bytes: Bytes::read_cfg(buf, &RangeCfg::new(0..=rpc::MAX_BODY_SIZE))?,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Ballot {
    pub(crate) epoch: u64,
    pub(crate) header: Header<Digest>,
    pub(crate) vote: Vote,
}
impl Write for Ballot {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.header.write(buf);
        self.vote.write(buf);
    }
}
impl EncodeSize for Ballot {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.header.encode_size() + self.vote.encode_size()
    }
}
impl Read for Ballot {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            epoch: u64::read(buf)?,
            header: Header::read(buf)?,
            vote: Vote::read(buf)?,
        })
    }
}
pub(crate) enum Message {
    Dealing(Dealing),
    Vote(Ballot),
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
            0 => Ok(Self::Dealing(Dealing::read(buf)?)),
            1 => Ok(Self::Vote(Ballot::read(buf)?)),
            v => Err(CodecError::InvalidEnum(v)),
        }
    }
}

/// The durable inputs and outputs of one fully validated state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Sealed {
    pub(crate) context: CloseContext<Key, Digest>,
    pub(crate) header: Header<Digest>,
    pub(crate) roots: RootBundle<Digest>,
    pub(crate) amounts: CloseAmounts,
    pub(crate) deposits: DepositBatch<Key>,
    pub(crate) withdrawals: WithdrawalBatch<Key, Digest>,
    pub(crate) dealing: Bytes,
    pub(crate) evidence: Bytes,
    pub(crate) mutations: Mutations,
    pub(crate) operations: u64,
    pub(crate) predecessor_operations: u64,
}
impl Write for Sealed {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.header.write(buf);
        self.roots.write(buf);
        self.amounts.write(buf);
        self.deposits.write(buf);
        self.withdrawals.write(buf);
        self.dealing.write(buf);
        self.evidence.write(buf);
        self.mutations.write(buf);
        self.operations.write(buf);
        self.predecessor_operations.write(buf);
    }
}
impl EncodeSize for Sealed {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.header.encode_size()
            + self.roots.encode_size()
            + self.amounts.encode_size()
            + self.deposits.encode_size()
            + self.withdrawals.encode_size()
            + self.dealing.encode_size()
            + self.evidence.encode_size()
            + self.mutations.encode_size()
            + self.operations.encode_size()
            + self.predecessor_operations.encode_size()
    }
}
impl Read for Sealed {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            context: CloseContext::read(buf)?,
            header: Header::read(buf)?,
            roots: RootBundle::read(buf)?,
            amounts: CloseAmounts::read(buf)?,
            deposits: DepositBatch::read_cfg(buf, &RangeCfg::new(0..=MAX_ACCOUNTS))?,
            withdrawals: WithdrawalBatch::read_cfg(
                buf,
                &(
                    RangeCfg::new(0..=MAX_WITHDRAWALS),
                    RangeCfg::new(0..=MAX_DESTINATION_BYTES),
                ),
            )?,
            dealing: Bytes::read_cfg(buf, &RangeCfg::new(0..=rpc::MAX_BODY_SIZE))?,
            evidence: Bytes::read_cfg(buf, &RangeCfg::new(0..=rpc::MAX_BODY_SIZE))?,
            mutations: Vec::read_cfg(buf, &(RangeCfg::new(0..=MAX_ACCOUNTS), ((), ())))?,
            operations: u64::read(buf)?,
            predecessor_operations: u64::read(buf)?,
        })
    }
}
impl Sealed {
    fn close(&self) -> Result<Close<Key, Digest>> {
        ensure!(
            self.header
                .verify::<Sha256, Key>(&self.context, &self.roots, &self.amounts),
            "retained header mismatch"
        );
        let close =
            Close::decode_evidence::<Sha256>(self.evidence.clone(), &self.context, &self.header)?;
        ensure!(
            close.header == self.header
                && close.roots == self.roots
                && close.amounts == self.amounts,
            "retained evidence mismatch"
        );
        Ok(close)
    }
}
pub(crate) type Store<E> = prunable::Archive<TwoCap, E, Digest, Sealed>;
pub(crate) async fn store<E: StorageContext>(
    context: E,
    partition: &str,
    deployment: &Digest,
) -> Store<E> {
    let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
    let prefix = format!("{partition}-{deployment}");
    Store::init(
        context,
        prunable::Config {
            translator: TwoCap,
            key_partition: format!("{prefix}-key"),
            key_page_cache: cache,
            value_partition: format!("{prefix}-value"),
            compression: None,
            codec_config: (),
            items_per_section: NZU64!(1024),
            key_write_buffer: IO_BUFFER_SIZE,
            value_write_buffer: IO_BUFFER_SIZE,
            replay_buffer: IO_BUFFER_SIZE,
        },
    )
    .await
    .expect("open durable close archive")
}

/// Per-close activity proofs are independent of historical balance proofs.
pub(crate) fn answer(
    close: &Close<Key, Digest>,
    lookup: &EvidenceLookup,
) -> Result<EvidenceResponse> {
    let index = Index::new(close);
    let body = match lookup {
        EvidenceLookup::Change { account, .. } => index
            .change_opening::<Sha256>(account)
            .map(EvidenceBody::Change),
        EvidenceLookup::Account { account, .. } => index
            .account_lookup::<Sha256>(account)
            .map(EvidenceBody::Account),
        EvidenceLookup::CommittedEntry {
            payer, recipient, ..
        } => index
            .higher_entry_lookup::<Sha256>(payer, recipient)
            .map(EvidenceBody::CommittedEntry),
        EvidenceLookup::WithdrawalOutput { account, .. } => index
            .withdrawal_claim::<Sha256>(account)
            .map(EvidenceBody::WithdrawalOutput),
        EvidenceLookup::ExternalPayout { account, .. } => index
            .external_payout_claim::<Sha256>(account)
            .map(EvidenceBody::ExternalPayout),
        _ => anyhow::bail!("balance or history lookup passed to activity service"),
    };
    Ok(match body {
        Ok(body) => EvidenceResponse::Served(Evidence::Close {
            header: close.header,
            roots: close.roots,
            body,
        }),
        Err(
            ServeError::Absent
            | ServeError::Transition(TransitionError::WithdrawalClaim | TransitionError::PayoutClaim),
        ) => EvidenceResponse::Absent,
        Err(error) => return Err(error.into()),
    })
}

/// The serial canonical journal can be ahead of the native account head by one close.
/// Older records were committed before the next canonical record could be accepted.
async fn recover<E: StorageContext + Spawner>(
    mut state: State<E, Sha256>,
    deployment: &Deployment,
    archive: &Store<E>,
) -> Result<(State<E, Sha256>, u64)> {
    let genesis = deployment.genesis();
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
            (
                candidate.root(),
                candidate.head().operations(),
                candidate.head().liability()
            ) == (genesis.root(), genesis.operations(), genesis.liability()),
            "configured genesis mismatch"
        );
        state = state.apply(candidate).await?.commit().await?;
    }
    let Some(last) = archive.last_index() else {
        ensure!(
            (state.root(), state.head().operations(), state.liability())
                == (genesis.root(), genesis.operations(), genesis.liability()),
            "unaccepted account head"
        );
        return Ok((state, 0));
    };
    let first = archive
        .get(Identifier::Index(0))
        .await?
        .context("missing canonical genesis anchor")?;
    ensure!(
        first.context.deployment() == deployment.digest()
            && first.context.payment().epoch() == 0
            && first.context.predecessor_root() == &genesis.root()
            && first.predecessor_operations == genesis.operations()
            && first.context.predecessor_liability() == genesis.liability(),
        "canonical genesis mismatch"
    );
    let tail = if last == 0 {
        first
    } else {
        archive
            .get(Identifier::Index(last))
            .await?
            .context("missing canonical tail")?
    };
    ensure!(
        tail.context.deployment() == deployment.digest() && tail.context.payment().epoch() == last,
        "canonical tail context mismatch"
    );
    let next = last.checked_add(1).context("epoch overflow")?;
    if (state.root(), state.head().operations()) == (tail.roots.successor, tail.operations) {
        return Ok((state, next));
    }
    ensure!(
        (state.root(), state.head().operations())
            == (
                *tail.context.predecessor_root(),
                tail.predecessor_operations
            ),
        "unaccepted account head"
    );
    let candidate = state.prepare(state.head(), tail.mutations).await?;
    ensure!(
        (candidate.root(), candidate.head().operations())
            == (tail.roots.successor, tail.operations),
        "canonical successor mismatch"
    );
    state = state.apply(candidate).await?.commit().await?;
    Ok((state, next))
}

pub(crate) struct Config<E: Spawner + StorageContext> {
    pub(crate) scheme: bls12381::Scheme,
    pub(crate) operators: Vec<(ed25519::PublicKey, Deployment)>,
    pub(crate) db: Database<E>,
    pub(crate) partition: String,
    pub(crate) validators: Vec<ValidatorEntry>,
    pub(crate) fetch_timeout: Duration,
}
struct Lane<E: StorageContext + Spawner> {
    peer: ed25519::PublicKey,
    deployment: Deployment,
    store: Option<Store<E>>,
    votes: Option<Store<E>>,
    state: Option<State<E, Sha256>>,
    next: u64,
}
pub(crate) struct Serve {
    request: EvidenceRequest,
    response: oneshot::Sender<EvidenceResponse>,
}
impl UnreliablePolicy for Serve {
    type Overflow = VecDeque<Self>;
    fn handle(_: &mut VecDeque<Self>, _: Self) -> bool {
        false
    }
}
#[derive(Clone)]
pub(crate) struct Mailbox {
    sender: UnreliableSender<Serve>,
}
impl Mailbox {
    pub(crate) async fn serve(&self, request: EvidenceRequest) -> Result<EvidenceResponse> {
        let (response, rx) = oneshot::channel();
        ensure!(
            !self
                .sender
                .enqueue(Serve { request, response })
                .is_rejected(),
            "sealer mailbox full"
        );
        rx.await.context("sealer stopped")
    }
}
pub(crate) struct Sealer<E: Spawner + Metrics + Network + StorageContext + CryptoRng> {
    context: ContextCell<E>,
    scheme: bls12381::Scheme,
    operators: Vec<(ed25519::PublicKey, Deployment)>,
    db: Database<E>,
    partition: String,
    validators: Vec<ValidatorEntry>,
    fetch_timeout: Duration,
    mailbox: UnreliableReceiver<Serve>,
}
impl<E: Spawner + Metrics + Network + StorageContext + CryptoRng> Sealer<E> {
    pub(crate) fn new(context: E, config: Config<E>) -> (Self, Mailbox) {
        assert!(config.scheme.me().is_some());
        let (sender, mailbox) = mailbox::new_unreliable(context.child("mailbox"), MAILBOX_SIZE);
        (
            Self {
                context: ContextCell::new(context),
                scheme: config.scheme,
                operators: config.operators,
                db: config.db,
                partition: config.partition,
                validators: config.validators,
                fetch_timeout: config.fetch_timeout,
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
            for (peer, deployment) in &self.operators {
                let archive = store(
                    self.context.child("archive"),
                    &format!("{}-canonical", self.partition),
                    deployment.digest(),
                )
                .await;
                let votes = store(
                    self.context.child("votes"),
                    &format!("{}-votes", self.partition),
                    deployment.digest(),
                )
                .await;
                let config = state_config(
                    &format!("{}-balances-{}", self.partition, deployment.digest()),
                    self.context.as_present(),
                    Sequential,
                );
                let state =
                    State::<_, Sha256>::open(self.context.child("balances"), config).await?;
                let (state, next) = recover(state, deployment, &archive).await?;
                lanes.push(Lane {
                    peer: peer.clone(),
                    deployment: deployment.clone(),
                    store: Some(archive),
                    votes: Some(votes),
                    state: Some(state),
                    next,
                });
            }
            loop {
                select! {
                    incoming = receiver.recv() => {
                        let Ok((peer, bytes)) = incoming else {
                            return Ok(());
                        };
                        let Some(position) = lanes.iter().position(|lane| lane.peer == peer) else {
                            continue;
                        };
                        let Ok(Message::Dealing(dealing)) = Message::decode(bytes) else {
                            continue;
                        };
                        let batch = dealing.header.batch_id::<Sha256>().into_digest();
                        if let Some(saved) = lanes[position]
                            .votes
                            .as_ref()
                            .unwrap()
                            .get(Identifier::Key(&batch))
                            .await?
                        {
                            if saved.dealing == dealing.bytes
                                && saved.context.payment().epoch() == dealing.epoch
                            {
                                self.vote(&mut sender, &peer, dealing.epoch, saved.header);
                            }
                            continue;
                        }
                        let deployment = *lanes[position].deployment.digest();
                        let (machine, height) = {
                            let db = self.db.read().await;
                            let Some(Record::Machine(bytes)) =
                                db.get(&machine_key(&deployment)).await?
                            else {
                                continue;
                            };
                            let machine = Machine::decode(bytes)?;
                            let height = match db.get(&status_key(&deployment)).await? {
                                Some(Record::Status(v)) => v.height,
                                _ => 0,
                            };
                            (machine, height)
                        };
                        let Some(registered) = machine.registered() else {
                            continue;
                        };
                        if registered.context.payment().epoch() != dealing.epoch
                            || height > registered.context.admission_deadline()
                        {
                            continue;
                        }
                        self.reconcile(&mut lanes, position).await?;
                        let lane = &mut lanes[position];
                        if lane.next != dealing.epoch
                            || lane.state.as_ref().unwrap().root()
                                != *registered.context.predecessor_root()
                        {
                            continue;
                        }
                        let checked = seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                            &self.scheme,
                            lane.state.as_ref().unwrap(),
                            registered.context,
                            machine.operator_ack(),
                            registered.deposits,
                            registered.withdrawals,
                            dealing.bytes,
                            self.context.as_mut(),
                            &Sequential,
                        )
                        .await;
                        let Ok((_, prepared)) = checked else {
                            warn!(epoch = dealing.epoch, "complete dealing validation failed");
                            continue;
                        };
                        if prepared.close().header != dealing.header {
                            continue;
                        }
                        if lane
                            .votes
                            .as_ref()
                            .unwrap()
                            .get(Identifier::Index(dealing.epoch))
                            .await?
                            .is_some()
                        {
                            continue;
                        }
                        let record = Self::record(
                            registered.context.clone(),
                            registered.deposits.clone(),
                            registered.withdrawals.clone(),
                            &prepared,
                        );
                        let archive = lane.votes.take().expect("vote archive owner");
                        let archive = archive.put_sync(dealing.epoch, batch, record).await?;
                        ensure!(
                            archive.has(Identifier::Key(&batch)).await?,
                            "vote evidence was not retained"
                        );
                        lane.votes = Some(archive);
                        self.vote(&mut sender, &peer, dealing.epoch, dealing.header);
                    },
                    message = self.mailbox.recv() => {
                        let Some(Serve { request, response }) = message else {
                            return Ok(());
                        };
                        if let Some(position) = lanes
                            .iter()
                            .position(|lane| lane.deployment.digest() == &request.deployment)
                        {
                            self.reconcile(&mut lanes, position).await?;
                        }
                        response.send_lossy(self.serve(&lanes, request).await?);
                    },
                }
            }
        }
        .await;
        if let Err(error) = result {
            error!(?error, "validator balance owner stopped");
        }
    }
    fn record(
        context: CloseContext<Key, Digest>,
        deposits: DepositBatch<Key>,
        withdrawals: WithdrawalBatch<Key, Digest>,
        prepared: &PreparedClose<Key, Digest>,
    ) -> Sealed {
        let close = prepared.close();
        Sealed {
            context,
            header: close.header,
            roots: close.roots,
            amounts: close.amounts,
            deposits,
            withdrawals,
            dealing: close.encoded().clone(),
            evidence: close.encode_evidence(),
            mutations: prepared.state().mutations().to_vec(),
            operations: prepared.state().head().operations(),
            predecessor_operations: prepared.state().predecessor().operations(),
        }
    }

    /// Advance only the branch that consensus admitted; a local vote is not branch authority.
    async fn reconcile(&mut self, lanes: &mut [Lane<E>], position: usize) -> Result<()> {
        loop {
            let deployment = *lanes[position].deployment.digest();
            let epoch = lanes[position].next;
            let certified = {
                let db = self.db.read().await;
                match db.get(&admitted_key(&deployment, epoch)).await? {
                    Some(Record::Admitted(v)) => v,
                    _ => return Ok(()),
                }
            };
            let local = lanes[position]
                .votes
                .as_ref()
                .unwrap()
                .get(Identifier::Key(&certified.batch_id.into_digest()))
                .await?;
            let prepared = if let Some(saved) = local {
                seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                    &self.scheme,
                    lanes[position].state.as_ref().unwrap(),
                    &saved.context,
                    &lanes[position].deployment.operator_ack,
                    &saved.deposits,
                    &saved.withdrawals,
                    saved.dealing.clone(),
                    self.context.as_mut(),
                    &Sequential,
                )
                .await
                .map(|(_, prepared)| (saved, prepared))
                .ok()
            } else {
                None
            };
            let selected = match prepared {
                Some(v) => Some(v),
                None => self.fetch_serving(lanes, position, &certified).await?,
            };
            let Some((saved, prepared)) = selected else {
                return Ok(());
            };
            ensure!(
                prepared.close().header.batch_id::<Sha256>() == certified.batch_id
                    && prepared.close().roots == certified.roots,
                "certified close mismatch"
            );
            let lane = &mut lanes[position];
            let record = Self::record(saved.context, saved.deposits, saved.withdrawals, &prepared);
            let batch = record.header.batch_id::<Sha256>().into_digest();
            let archive = lane.store.take().expect("canonical archive owner");
            ensure!(
                archive.get(Identifier::Index(epoch)).await?.is_none(),
                "conflicting canonical epoch"
            );
            let archive = archive.put_sync(epoch, batch, record).await?;
            ensure!(
                archive.has(Identifier::Key(&batch)).await?,
                "canonical evidence was not retained"
            );
            lane.store = Some(archive);
            let state = lane.state.take().expect("balance owner");
            lane.state = Some(state.apply(prepared.into_parts().1).await?.commit().await?);
            lane.next = epoch.checked_add(1).context("epoch overflow")?;
        }
    }
    async fn serve(&self, lanes: &[Lane<E>], request: EvidenceRequest) -> Result<EvidenceResponse> {
        let Some(lane) = lanes
            .iter()
            .find(|lane| lane.deployment.digest() == &request.deployment)
        else {
            return Ok(EvidenceResponse::Unknown);
        };
        if let EvidenceLookup::GenesisState { account } = &request.lookup {
            return Ok(
                match lane
                    .state
                    .as_ref()
                    .unwrap()
                    .lookup_at(
                        lane.deployment.genesis().root(),
                        lane.deployment.genesis().operations(),
                        &account_key(account)?,
                    )
                    .await?
                {
                    StateLookup::Present(value) => {
                        EvidenceResponse::Served(Evidence::Genesis(StateOpening {
                            account: account.clone(),
                            balance: value.balance,
                            proof: value.proof,
                        }))
                    }
                    StateLookup::Absent(proof) => {
                        EvidenceResponse::Served(Evidence::GenesisAbsent(proof))
                    }
                },
            );
        }
        if let EvidenceLookup::Dealing { epoch } = &request.lookup {
            return Ok(lane
                .store
                .as_ref()
                .unwrap()
                .get(Identifier::Index(*epoch))
                .await?
                .or(lane
                    .votes
                    .as_ref()
                    .unwrap()
                    .get(Identifier::Index(*epoch))
                    .await?)
                .map_or(EvidenceResponse::Unsealed, |record| {
                    EvidenceResponse::Served(Evidence::Dealing(Box::new(record)))
                }));
        }
        let batch = request.lookup.batch().expect("close lookup");
        let Some(record) = lane
            .store
            .as_ref()
            .unwrap()
            .get(Identifier::Key(batch))
            .await?
        else {
            return Ok(EvidenceResponse::Unsealed);
        };
        let target = match &request.lookup {
            EvidenceLookup::PredecessorState { .. } => Some((
                *record.context.predecessor_root(),
                record.predecessor_operations,
            )),
            EvidenceLookup::SuccessorState { .. } => {
                Some((record.roots.successor, record.operations))
            }
            _ => None,
        };
        if let Some((root, operations)) = target {
            let account = request.lookup.account().unwrap().clone();
            let body = match lane
                .state
                .as_ref()
                .unwrap()
                .lookup_at(root, operations, &account_key(&account)?)
                .await?
            {
                StateLookup::Present(value) => EvidenceBody::State(StateOpening {
                    account,
                    balance: value.balance,
                    proof: value.proof,
                }),
                StateLookup::Absent(proof) => EvidenceBody::StateAbsent(proof),
            };
            return Ok(EvidenceResponse::Served(Evidence::Close {
                header: record.header,
                roots: record.roots,
                body,
            }));
        }
        answer(&record.close()?, &request.lookup)
    }
    async fn fetch_serving(
        &mut self,
        lanes: &[Lane<E>],
        position: usize,
        certified: &super::state::AdmittedRootsResponse,
    ) -> Result<Option<(Sealed, PreparedClose<Key, Digest>)>> {
        let deployment = *lanes[position].deployment.digest();
        let epoch = lanes[position].next;
        let context = self.context.as_present();
        let request = rpc::Request {
            method: METHOD_EVIDENCE,
            body: EvidenceRequest::new(deployment, EvidenceLookup::Dealing { epoch }).encode(),
        };
        for validator in self.validators.clone() {
            let timeout = self.fetch_timeout;
            let fetch = async {
                select! {
                    v = rpc::call(context, validator.query, &request) => v,
                    _ = context.sleep(timeout) => anyhow::bail!("history fetch timeout"),
                }
            };
            let mut fetch = pin!(fetch);
            let response = loop {
                select! {
                    result = &mut fetch => break result,
                    message = self.mailbox.recv() => {
                        let Some(Serve { request, response }) = message else {
                            return Ok(None);
                        };
                        response.send_lossy(self.serve(lanes, request).await?);
                    },
                }
            };
            let Ok(rpc::Response::Success { body }) = response else {
                continue;
            };
            let Ok(EvidenceResponse::Served(Evidence::Dealing(saved))) =
                EvidenceResponse::decode(body)
            else {
                continue;
            };
            if saved.context.deployment() != &deployment
                || saved.context.payment().epoch() != epoch
                || saved.header.batch_id::<Sha256>() != certified.batch_id
                || saved.roots != certified.roots
            {
                continue;
            }
            let mut rng = self.context.child("history_validation");
            let checked = seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                &self.scheme,
                lanes[position].state.as_ref().unwrap(),
                &saved.context,
                &lanes[position].deployment.operator_ack,
                &saved.deposits,
                &saved.withdrawals,
                saved.dealing.clone(),
                &mut rng,
                &Sequential,
            )
            .await;
            let Ok((_, prepared)) = checked else { continue };
            if prepared.close().header != saved.header || prepared.close().roots != certified.roots
            {
                continue;
            }
            return Ok(Some((*saved, prepared)));
        }
        Ok(None)
    }
    fn vote<Se: Sender<PublicKey = ed25519::PublicKey>>(
        &self,
        sender: &mut Se,
        operator: &ed25519::PublicKey,
        epoch: u64,
        header: Header<Digest>,
    ) {
        let vote = self.scheme.sign(&header).expect("clearing signer");
        let sent = sender.send(
            Recipients::One(operator.clone()),
            Message::Vote(Ballot {
                epoch,
                header,
                vote,
            })
            .encode(),
            true,
        );
        if sent.is_empty() {
            debug!(epoch, "operator will retry lost vote");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chain::{
            tx::{AdmitRequest, RegisterEpochRequest, SettlementTx},
            validator::db_config,
        },
        protocol::{Protocol, clearing_private, committee, deployments, wallets},
    };
    use commonware_clearing::bajillion::{
        payment::{SendAuthorization, VectorSendBody},
        transition::{Terminal, prepare_close_with_strategy},
        vector::{OutEntry, OutVector},
    };
    use commonware_consensus::types::Height;
    use commonware_cryptography::Signer as _;
    use commonware_glue::stateful::db::DatabaseSet;
    use commonware_p2p::simulated::{Config as NetConfig, Link, Network};
    use commonware_runtime::{
        Clock as _, Listener as _, Network as _, Runner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{NZUsize, TestRng, probability};
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    /// One two-peer simulated network: the operator's DA channel endpoints
    /// and the validator's, with links per `to_validator`/`to_operator`.
    async fn network(
        context: &deterministic::Context,
        operator: &ed25519::PublicKey,
        validator: &ed25519::PublicKey,
        to_validator: bool,
        to_operator: bool,
    ) -> (
        (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
        (
            impl Sender<PublicKey = ed25519::PublicKey>,
            impl Receiver<PublicKey = ed25519::PublicKey>,
        ),
    ) {
        let (net, oracle) = Network::new_with_peers(
            context.child("network"),
            NetConfig {
                max_size: 4 * 1024 * 1024,
                max_peers_per_set: NZUsize!(2),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            [operator.clone(), validator.clone()],
        )
        .await;
        net.start();
        let quota = commonware_runtime::Quota::per_second(commonware_utils::NZU32!(128));
        let operator_chan = oracle
            .control(operator.clone())
            .register(0, quota)
            .await
            .unwrap();
        let validator_chan = oracle
            .control(validator.clone())
            .register(0, quota)
            .await
            .unwrap();
        let link = Link {
            latency: Duration::from_millis(1),
            jitter: Duration::from_millis(0),
            success_rate: probability!(1.0),
        };
        if to_validator {
            oracle
                .add_link(operator.clone(), validator.clone(), link.clone())
                .await
                .unwrap();
        }
        if to_operator {
            oracle
                .add_link(validator.clone(), operator.clone(), link)
                .await
                .unwrap();
        }
        (operator_chan, validator_chan)
    }

    async fn history_server(
        context: deterministic::Context,
        address: SocketAddr,
        record: Sealed,
    ) -> Arc<AtomicUsize> {
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        let mut listener = context.bind(address).await.unwrap();
        context.spawn(move |_| async move {
            while let Ok((_, mut sink, mut stream)) = listener.accept().await {
                if rpc::recv_request(&mut stream).await.is_err() {
                    continue;
                }
                counted.fetch_add(1, Ordering::SeqCst);
                let response = rpc::Response::Success {
                    body: EvidenceResponse::Served(Evidence::Dealing(Box::new(record.clone())))
                        .encode(),
                };
                let _ = rpc::send_response(&mut sink, &response).await;
            }
        });
        hits
    }

    #[test]
    fn vote_survives_restart_without_advancing_unadmitted_state() {
        deterministic::Runner::default().start(|context| async move {
            let mut deployment = deployments().remove(0);
            deployment.generate(context.child("genesis")).await.unwrap();
            let protocol = Protocol::new(NZUsize!(1)).unwrap();
            let state = State::<_, Sha256>::init(
                context.child("operator_balances"),
                state_config("vote-operator", &context, Sequential),
                genesis_balances(&deployment).unwrap(),
            )
            .await
            .unwrap();
            let deposits = DepositBatch::empty();
            let withdrawals = WithdrawalBatch::empty();
            let root = deposits.root::<Sha256>().unwrap();
            let registration = crate::chain::tx::SettlementTx::RegisterEpoch(
                crate::chain::tx::RegisterEpochRequest {
                    deployment: *deployment.digest(),
                    epoch: 0,
                    predecessor_liability: 400,
                    deposits_root: root,
                    staged_root: root,
                    withdrawals: withdrawals.clone(),
                    openings: Vec::new(),
                    signature: protocol.sign_chain_registration(0, 400, &root, &root, &withdrawals),
                },
            );
            let db = <Database<deterministic::Context> as DatabaseSet<_>>::init(
                context.child("settlement"),
                db_config(
                    "vote-settlement",
                    CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                ),
            )
            .await;
            let batch = crate::chain::state::execute(
                db.new_batches().await,
                Height::new(1),
                1,
                &crate::protocol::Timing::DEFAULT,
                std::slice::from_ref(&deployment),
                &[registration],
            )
            .await
            .unwrap();
            db.apply(batch).await;
            let epoch = protocol
                .registration_at(0, deposits.clone(), withdrawals.clone(), 400, 11, 12)
                .unwrap()
                .context;
            let close_context = epoch
                .bind::<Sha256, _, _>(&state, &deposits, &withdrawals)
                .await
                .unwrap();
            let prepared = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &state,
                &close_context,
                &deposits,
                &withdrawals,
                Vec::new(),
                &Sequential,
            )
            .await
            .unwrap();
            let header = prepared.close().header;
            let wire = Message::Dealing(Dealing {
                epoch: 0,
                header,
                bytes: prepared.encoded().clone(),
            })
            .encode();
            assert_eq!(Message::decode(wire.clone()).unwrap().encode(), wire);
            let operator = ed25519::PrivateKey::from_seed(90).public_key();
            let validator = ed25519::PrivateKey::from_seed(91).public_key();
            for restart in 0..2 {
                let run = context.child(if restart == 0 { "first_run" } else { "restart" });
                let ((mut send, mut receive), validator_channel) =
                    network(&run, &operator, &validator, true, true).await;
                let scheme =
                    bls12381::Scheme::signer(committee().unwrap(), clearing_private(0).unwrap())
                        .unwrap();
                let (sealer, mailbox) = Sealer::new(
                    run.child("sealer"),
                    Config {
                        scheme,
                        operators: vec![(operator.clone(), deployment.clone())],
                        db: db.clone(),
                        partition: "vote-durable".into(),
                        validators: Vec::new(),
                        fetch_timeout: Duration::from_millis(100),
                    },
                );
                let handle = sealer.start(validator_channel);
                let bad = Message::Dealing(Dealing {
                    epoch: 0,
                    header,
                    bytes: Bytes::from_static(&[0]),
                })
                .encode();
                assert!(
                    !send
                        .send(Recipients::One(validator.clone()), bad, true)
                        .is_empty()
                );
                assert!(
                    !send
                        .send(Recipients::One(validator.clone()), wire.clone(), true)
                        .is_empty()
                );
                let (_, voted) = receive.recv().await.unwrap();
                let Message::Vote(ballot) = Message::decode(voted).unwrap() else {
                    panic!("expected vote")
                };
                assert_eq!(ballot.header, header);
                let EvidenceResponse::Served(Evidence::Dealing(saved)) = mailbox
                    .serve(EvidenceRequest::new(
                        *deployment.digest(),
                        EvidenceLookup::Dealing { epoch: 0 },
                    ))
                    .await
                    .unwrap()
                else {
                    panic!("durable vote evidence")
                };
                assert_eq!(saved.dealing, prepared.encoded().clone());
                assert_eq!(saved.close().unwrap().header, header);
                assert_eq!(
                    mailbox
                        .serve(EvidenceRequest::new(
                            *deployment.digest(),
                            EvidenceLookup::SuccessorState {
                                batch: header.batch_id::<Sha256>().into_digest(),
                                account: wallets()[0].public_key()
                            }
                        ))
                        .await
                        .unwrap(),
                    EvidenceResponse::Unsealed
                );
                handle.abort();
                let _ = handle.await;
                let archive = store(
                    run.child("inspect_votes"),
                    "vote-durable-votes",
                    deployment.digest(),
                )
                .await;
                assert!(
                    archive
                        .has(Identifier::Key(&header.batch_id::<Sha256>().into_digest()))
                        .await
                        .unwrap()
                );
            }
        });
    }

    #[test]
    fn canonical_replay_ignores_unselected_vote_and_invalid_first_holder() {
        deterministic::Runner::default().start(|context| async move {
            let mut deployment = deployments().remove(0);
            deployment
                .generate(context.child("genesis"))
                .await
                .unwrap();
            let protocol = Protocol::new(NZUsize!(1)).unwrap();
            let config = state_config(
                &format!("branch-balances-{}", deployment.digest()),
                &context,
                Sequential,
            );
            let genesis = genesis_balances(&deployment).unwrap();
            let mut state = State::<_, Sha256>::init(
                context.child("balances"),
                config.clone(),
                genesis.clone(),
            )
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
            let deposits = DepositBatch::empty();
            let withdrawals = WithdrawalBatch::empty();
            let epoch = protocol
                .registration_at(0, deposits.clone(), withdrawals.clone(), 400, 11, 12)
                .unwrap()
                .context;
            let close_context = epoch
                .bind::<Sha256, _, _>(&state, &deposits, &withdrawals)
                .await
                .unwrap();
            let a = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &state,
                &close_context,
                &deposits,
                &withdrawals,
                Vec::new(),
                &Sequential,
            )
            .await
            .unwrap();
            let wallets = wallets();
            let payer = &wallets[0];
            let recipient = wallets[1].public_key();
            let vector = OutVector::new(
                0,
                payer.public_key(),
                vec![OutEntry {
                    recipient: recipient.clone(),
                    cumulative: 1,
                    count: 1,
                }],
            )
            .unwrap();
            let body = VectorSendBody::new(
                close_context.payment(),
                payer.public_key(),
                1,
                1,
                vector.root::<Sha256, Digest>().unwrap(),
            );
            let terminal = Terminal {
                operator_signature: protocol.sign_ack_aggregate(&body),
                authorization: SendAuthorization::sign(body, payer.signer()),
                vector,
            };
            let b = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &state,
                &close_context,
                &deposits,
                &withdrawals,
                vec![terminal],
                &Sequential,
            )
            .await
            .unwrap();
            let record_a = Sealer::<deterministic::Context>::record(
                close_context.clone(),
                deposits.clone(),
                withdrawals.clone(),
                &a,
            );
            let record_b = Sealer::<deterministic::Context>::record(
                close_context.clone(),
                deposits.clone(),
                withdrawals.clone(),
                &b,
            );
            assert_ne!(record_a.header, record_b.header);
            assert_ne!(record_a.roots.successor, record_b.roots.successor);
            let encoded = record_b.encode();
            assert_eq!(Sealed::decode(encoded.clone()).unwrap(), record_b);
            assert!(Sealed::decode(encoded.slice(..encoded.len() - 1)).is_err());
            let evidence = b.close().encode_evidence();
            assert!(
                Close::<Key, Digest>::decode_evidence::<Sha256>(
                    evidence.clone(),
                    &close_context,
                    &record_a.header
                )
                .is_err()
            );
            assert!(
                Close::<Key, Digest>::decode_evidence::<Sha256>(
                    evidence.slice(..evidence.len() - 1),
                    &close_context,
                    &record_b.header
                )
                .is_err()
            );
            let opening = state.opening(payer.public_key()).await.unwrap();
            assert_eq!(opening.balance.get(), 100);
            let old_root = state.root();
            let invalid = SocketAddr::from(([127, 0, 0, 1], 20100));
            let honest = SocketAddr::from(([127, 0, 0, 1], 20101));
            // The signed anchor authenticates the deadline even when every outer commitment matches.
            let mut invalid_record = record_b.clone();
            let mut encoded_context = close_context.encode().to_vec();
            let admission_offset = close_context.payment().encode_size()
                + close_context.deployment().encode_size()
                + close_context.deposit_root().encode_size()
                + close_context.withdrawal_root().encode_size()
                + close_context.predecessor_liability().encode_size();
            let changed_deadline = (close_context.admission_deadline() - 1).encode();
            encoded_context[admission_offset..admission_offset + changed_deadline.len()]
                .copy_from_slice(&changed_deadline);
            invalid_record.context = CloseContext::decode(Bytes::from(encoded_context)).unwrap();
            assert_eq!(invalid_record.header, record_b.header);
            assert_eq!(invalid_record.roots, record_b.roots);
            assert!(
                !invalid_record
                    .context
                    .epoch_context()
                    .verify_anchor::<Sha256>()
            );
            let invalid_hits =
                history_server(context.child("invalid_peer"), invalid, invalid_record).await;
            let mut peer_record = record_b.clone();
            peer_record.operations = u64::MAX;
            peer_record.predecessor_operations = u64::MAX;
            let honest_hits =
                history_server(context.child("honest_peer"), honest, peer_record).await;
            let cache = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let db = <Database<deterministic::Context> as DatabaseSet<_>>::init(
                context.child("settlement"),
                db_config("branch-settlement", cache),
            )
            .await;
            let registration = |epoch| {
                let root = deposits.root::<Sha256>().unwrap();
                SettlementTx::RegisterEpoch(RegisterEpochRequest {
                    deployment: *deployment.digest(),
                    epoch,
                    predecessor_liability: 400,
                    deposits_root: root,
                    staged_root: root,
                    withdrawals: withdrawals.clone(),
                    openings: Vec::new(),
                    signature: protocol.sign_chain_registration(
                        epoch, 400, &root, &root, &withdrawals,
                    ),
                })
            };

            // The other three validators certify B while this replica retains its vote for A.
            let scheme =
                bls12381::Scheme::signer(committee().unwrap(), clearing_private(0).unwrap())
                    .unwrap();
            let certificate = scheme
                .assemble_exact((1..=scheme.committee().quorum()).map(|index| {
                    bls12381::Scheme::signer(
                        committee().unwrap(),
                        clearing_private(index).unwrap(),
                    )
                    .unwrap()
                    .sign(&record_b.header)
                    .unwrap()
                }))
                .unwrap();
            let batch = crate::chain::state::execute(
                db.new_batches().await,
                Height::new(1),
                1,
                &crate::protocol::Timing::DEFAULT,
                std::slice::from_ref(&deployment),
                &[
                    registration(0),
                    SettlementTx::Admit(AdmitRequest {
                        deployment: *deployment.digest(),
                        epoch: 0,
                        predecessor_liability: 400,
                        deposits: deposits.clone(),
                        withdrawals: withdrawals.clone(),
                        header: record_b.header,
                        roots: record_b.roots,
                        amounts: record_b.amounts,
                        certificate,
                    }),
                ],
            )
            .await
            .unwrap();
            db.apply(batch).await;
            let validators = vec![
                ValidatorEntry {
                    clearing: scheme.committee().members()[0],
                    query: invalid,
                },
                ValidatorEntry {
                    clearing: scheme.committee().members()[1],
                    query: honest,
                },
            ];
            let peer = ed25519::PrivateKey::from_seed(88).public_key();
            let (mut sealer, _mailbox) = Sealer::new(
                context.child("sealer"),
                Config {
                    scheme,
                    operators: vec![(peer.clone(), deployment.clone())],
                    db: db.clone(),
                    partition: "branch".into(),
                    validators,
                    fetch_timeout: Duration::from_secs(1),
                },
            );
            let votes = store(context.child("votes"), "branch-votes", deployment.digest())
                .await
                .put_sync(
                    0,
                    record_a.header.batch_id::<Sha256>().into_digest(),
                    record_a.clone(),
                )
                .await
                .unwrap();
            let canonical = store(
                context.child("canonical"),
                "branch-canonical",
                deployment.digest(),
            )
            .await;
            let mut lanes = vec![Lane {
                peer: peer.clone(),
                deployment: deployment.clone(),
                votes: Some(votes),
                store: Some(canonical),
                state: Some(state),
                next: 0,
            }];
            let honest_holder = sealer.validators.pop().unwrap();
            Box::pin(sealer.reconcile(&mut lanes, 0)).await.unwrap();
            assert_eq!(lanes[0].next, 0);
            assert_eq!(lanes[0].state.as_ref().unwrap().root(), old_root);
            sealer.validators.push(honest_holder);
            Box::pin(sealer.reconcile(&mut lanes, 0)).await.unwrap();
            assert_eq!(
                lanes[0].state.as_ref().unwrap().root(),
                record_b.roots.successor
            );
            assert_eq!(lanes[0].next, 1);
            assert_eq!(lanes[0].store.as_ref().unwrap().get(Identifier::Index(0)).await.unwrap().unwrap().operations, record_b.operations);
            assert_eq!(
                lanes[0].store.as_ref().unwrap().get(Identifier::Index(0)).await.unwrap().unwrap().predecessor_operations,
                record_b.predecessor_operations,
            );
            assert!(invalid_hits.load(Ordering::SeqCst) > 0);
            assert!(honest_hits.load(Ordering::SeqCst) > 0);
            assert!(
                lanes[0]
                    .votes
                    .as_ref()
                    .unwrap()
                    .has(Identifier::Key(
                        &record_a.header.batch_id::<Sha256>().into_digest()
                    ))
                    .await
                    .unwrap()
            );
            for (lookup, root, expected) in [
                (
                    EvidenceLookup::PredecessorState {
                        batch: record_b.header.batch_id::<Sha256>().into_digest(),
                        account: payer.public_key(),
                    },
                    old_root,
                    100,
                ),
                (
                    EvidenceLookup::SuccessorState {
                        batch: record_b.header.batch_id::<Sha256>().into_digest(),
                        account: payer.public_key(),
                    },
                    record_b.roots.successor,
                    99,
                ),
            ] {
                let EvidenceResponse::Served(Evidence::Close {
                    body: EvidenceBody::State(opening),
                    ..
                }) = sealer
                    .serve(
                        &lanes,
                        EvidenceRequest::new(*deployment.digest(), lookup),
                    )
                    .await
                    .unwrap()
                else {
                    panic!("retained balance")
                };
                assert_eq!(opening.verify::<Sha256>(&root).unwrap().get(), expected);
            }
            // A canonical record owns replay even when the process stops before applying it.
            let crash_config = state_config("archive-ahead-balances", &context, Sequential);
            let crash_state = State::<_, Sha256>::init(
                context.child("archive_ahead_balances"),
                crash_config.clone(),
                genesis.clone(),
            )
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
            let crash_archive = store(
                context.child("archive_ahead"),
                "archive-ahead",
                deployment.digest(),
            )
            .await
            .put_sync(
                0,
                record_b.header.batch_id::<Sha256>().into_digest(),
                record_b.clone(),
            )
            .await
            .unwrap();
            drop(crash_archive);
            drop(crash_state);
            let reopened_archive = store(
                context.child("archive_ahead_reopened"),
                "archive-ahead",
                deployment.digest(),
            )
            .await;
            let recovered_record = reopened_archive
                .get(Identifier::Index(0))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(recovered_record, record_b);
            let recovered = State::<_, Sha256>::open(context.child("archive_ahead_replay"), crash_config)
                .await
                .unwrap();
            assert!(
                context
                    .encode()
                    .contains("archive_ahead_replay_balances_apply_batch_calls_total 0")
            );
            let (recovered, recovered_next) = recover(recovered, &deployment, &reopened_archive)
                .await
                .unwrap();
            assert_eq!(recovered_next, 1);
            assert!(
                context
                    .encode()
                    .contains("archive_ahead_replay_balances_apply_batch_calls_total 1")
            );
            assert_eq!(recovered.root(), record_b.roots.successor);
            assert_eq!(
                recovered
                    .opening(payer.public_key())
                    .await
                    .unwrap()
                    .balance
                    .get(),
                99
            );

            // Applied history remains proof material but is not input to restart catch-up.
            drop(lanes[0].state.take());
            state = State::<_, Sha256>::open(context.child("reopened"), config.clone())
                .await
                .unwrap();
            let mut already_applied = record_b.clone();
            already_applied.mutations = vec![
                (account_key(&payer.public_key()).unwrap(), None),
                (account_key(&payer.public_key()).unwrap(), None),
            ];
            let applied_archive = store(
                context.child("applied_archive"),
                "applied-only",
                deployment.digest(),
            )
            .await
            .put_sync(
                0,
                record_b.header.batch_id::<Sha256>().into_digest(),
                already_applied,
            )
            .await
            .unwrap();
            let (resumed, resumed_next) = recover(state, &deployment, &applied_archive).await.unwrap();
            state = resumed;
            assert_eq!(resumed_next, 1);
            assert!(
                context
                    .encode()
                    .contains("reopened_balances_apply_batch_calls_total 0")
            );
            let mut wrong_size = record_b.clone();
            wrong_size.operations += 1;
            let wrong_size_archive = store(
                context.child("wrong_size_archive"),
                "wrong-size",
                deployment.digest(),
            )
            .await
            .put_sync(
                0,
                wrong_size.header.batch_id::<Sha256>().into_digest(),
                wrong_size,
            )
            .await
            .unwrap();
            assert!(
                recover(state, &deployment, &wrong_size_archive)
                    .await
                    .is_err()
            );
            state = State::<_, Sha256>::open(context.child("after_wrong_size"), config.clone())
                .await
                .unwrap();
            let wrong_genesis_operations = Deployment::configured(
                deployment.operator.clone(),
                deployment.operator_ack,
                deployment.accounts.clone(),
                deployment.genesis().root(),
                deployment.genesis().operations() + 1,
            )
            .unwrap();
            assert!(
                recover(state, &wrong_genesis_operations, &reopened_archive)
                    .await
                    .is_err()
            );
            state = State::<_, Sha256>::open(
                context.child("after_wrong_genesis_operations"),
                config.clone(),
            )
            .await
            .unwrap();
            let wrong_genesis = Deployment::configured(
                deployment.operator.clone(),
                deployment.operator_ack,
                deployment.accounts.clone(),
                record_b.roots.successor,
                record_b.operations,
            )
            .unwrap();
            assert!(
                recover(state, &wrong_genesis, &reopened_archive)
                    .await
                    .is_err()
            );
            state = State::<_, Sha256>::open(context.child("after_wrong_genesis"), config.clone())
                .await
                .unwrap();
            let fresh = State::<_, Sha256>::open(
                context.child("wrong_genesis_bootstrap"),
                state_config("wrong-genesis-bootstrap", &context, Sequential),
            )
            .await
            .unwrap();
            let empty_archive = store(
                context.child("empty_archive"),
                "empty-canonical",
                deployment.digest(),
            )
            .await;
            assert!(
                recover(fresh, &wrong_genesis, &empty_archive)
                    .await
                    .is_err()
            );
            let untouched = State::<_, Sha256>::open(
                context.child("wrong_genesis_reopened"),
                state_config("wrong-genesis-bootstrap", &context, Sequential),
            )
            .await
            .unwrap();
            assert!(untouched.is_bootstrap());
            assert!(
                context
                    .encode()
                    .contains("wrong_genesis_reopened_balances_apply_batch_calls_total 0")
            );
            assert!(
                state
                    .lookup_at(old_root, 0, &account_key(&payer.public_key()).unwrap())
                    .await
                    .is_err()
            );
            assert!(
                state
                    .lookup_at(
                        old_root,
                        record_b.operations,
                        &account_key(&payer.public_key()).unwrap()
                    )
                    .await
                    .is_err()
            );
            assert_eq!(state.root(), record_b.roots.successor);
            assert_eq!(
                state
                    .opening_at(
                        old_root,
                        deployment.genesis().operations(),
                        payer.public_key()
                    )
                    .await
                    .unwrap()
                    .balance
                    .get(),
                100
            );
            assert!(
                seal::<Sha256, _, _, _, _, PaymentBatchVerifier, _>(
                    &sealer.scheme,
                    &state,
                    &close_context,
                    protocol.operator_ack_key(),
                    &deposits,
                    &withdrawals,
                    record_b.dealing.clone(),
                    &mut TestRng::new(7),
                    &Sequential
                )
                .await
                .is_err()
            );
            let batch = crate::chain::state::execute(
                db.new_batches().await,
                Height::new(2),
                2,
                &crate::protocol::Timing::DEFAULT,
                std::slice::from_ref(&deployment),
                &[registration(1)],
            )
            .await
            .unwrap();
            db.apply(batch).await;
            let next_context = {
                let guard = db.read().await;
                let Some(Record::Machine(bytes)) = guard
                    .get(&machine_key(deployment.digest()))
                    .await
                    .unwrap()
                else {
                    panic!("registered settlement machine");
                };
                let machine = Machine::decode(bytes).unwrap();
                machine.registered().unwrap().context.clone()
            };
            assert_eq!(next_context.payment().epoch(), 1);
            assert_eq!(*next_context.predecessor_root(), record_b.roots.successor);
            assert_ne!(*next_context.predecessor_root(), record_a.roots.successor);
            let next = prepare_close_with_strategy::<Sha256, _, _, _, _>(
                &state,
                &next_context,
                &deposits,
                &withdrawals,
                Vec::new(),
                &Sequential,
            )
            .await
            .unwrap();
            let next_header = next.close().header;
            let next_wire = Message::Dealing(Dealing {
                epoch: 1,
                header: next_header,
                bytes: next.encoded().clone(),
            })
            .encode();
            drop(state);
            drop(lanes);
            drop(sealer);
            let validator = ed25519::PrivateKey::from_seed(89).public_key();
            let restart_network = context.child("restart_network");
            let ((mut send, mut receive), channel) = network(
                &restart_network,
                &peer,
                &validator,
                true,
                true,
            )
            .await;
            let verifier =
                bls12381::Scheme::signer(committee().unwrap(), clearing_private(0).unwrap())
                    .unwrap();
            let (restarted, _mailbox) = Sealer::new(
                context.child("restarted_sealer"),
                Config {
                    scheme: verifier.clone(),
                    operators: vec![(peer, deployment.clone())],
                    db,
                    partition: "branch".into(),
                    validators: Vec::new(),
                    fetch_timeout: Duration::from_millis(100),
                },
            );
            let handle = restarted.start(channel);
            assert!(
                !send
                    .send(Recipients::One(validator.clone()), next_wire, true)
                    .is_empty()
            );
            let (sender, wire) = select! {
                result = receive.recv() => result.unwrap(),
                _ = context.sleep(Duration::from_secs(1)) => panic!("restarted validator did not vote on the selected branch"),
            };
            let Message::Vote(ballot) = Message::decode(wire).unwrap() else {
                panic!("successor vote")
            };
            assert_eq!(sender, validator);
            assert_eq!(ballot.epoch, 1);
            assert_eq!(ballot.header, next_header);
            assert_eq!(ballot.vote.signer, verifier.me().unwrap());
            assert!(verifier.verify_vote(&next_header, &ballot.vote));
            handle.abort();
            let _ = handle.await;
            let votes = store(
                context.child("reopened_votes"),
                "branch-votes",
                deployment.digest(),
            )
            .await;
            assert_eq!(
                votes.get(Identifier::Index(0)).await.unwrap().unwrap(),
                record_a
            );
            let next_vote = votes.get(Identifier::Index(1)).await.unwrap().unwrap();
            assert_eq!(next_vote.header, next_header);
            assert_eq!(*next_vote.context.predecessor_root(), record_b.roots.successor);
        });
    }
}
