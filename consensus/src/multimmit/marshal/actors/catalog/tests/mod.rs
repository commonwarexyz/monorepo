//! Catalog actor tests: shared fixtures here, one module per concern.

use super::{
    Error, Fatal, Mailbox,
    mailbox::{AdmissionReply, Command, Message, Read, Traced},
    materializer::BODY_READER_RESIDENCY,
};
use crate::{
    Epochable as _, Reporter, Viewable as _,
    multimmit::{
        marshal::{
            MarshalProgress,
            actors::delivery::{self, DeliveryOutput, DurableBatch, HotOutput},
            bodies::Bodies,
            config::{ArchiveConfig, ArchiveMode, Config, Retention, Start},
            open::{Opened, storage as open_storage},
            storage::{
                Error as StorageError,
                catalog::{Admission, InstallRequest, StoredRef},
                catalog_state::{CatalogState, Checkpoint, CheckpointParts, PendingFloors},
                commit::{Commit, CustodyRef, HistoryOpening, OutputRow, SelectedLqc},
                pending::BODY_READ_CONCURRENCY,
                record::blob_size,
            },
            types::{OutputIndex, Update},
        },
        mocks::Committee,
        testing::{TestBody, metric_total},
        types::{
            BlockRef, Body, CertificateId, ChainId, Lqc, PathLimits, TipRecord, TransactionBlock,
            TransactionBlockHeader, genesis_history,
        },
    },
    types::{Height, Participant, View},
};
use commonware_actor::Feedback;
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{
    Digestible as _, Hasher, Sha256,
    bls12381::primitives::variant::{MinPk, Variant},
    sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Metrics as RuntimeMetrics, Runner as _, Spawner, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, Context as DeterministicContext},
    mocks::{
        DelayedOpenContext, DelayedReadContext, DelayedSyncContext, Gated, Gates, PendingSyncs,
        drive_pending_syncs, release_next_pending_syncs,
    },
    telemetry::metrics::metric_sum,
};
use commonware_storage::{Context, translator::TwoCap};
use commonware_utils::{
    Acknowledgement as _, NZU16, NZU64, NZUsize, acknowledgement::Exact, channel::oneshot,
    sync::Mutex,
};
use futures::{FutureExt as _, future::try_join_all};
use std::{
    collections::VecDeque,
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
use tracing::{Instrument as _, Span, info_span};
use tracing_subscriber::{Layer, layer::Context as LayerContext, prelude::*, registry::LookupSpan};

mod admission;
mod commit;
mod install;
mod reads;
mod recovery;
mod spans;

#[derive(Clone, Default)]
struct SpanPaths(Arc<Mutex<Vec<Vec<&'static str>>>>);

impl<S: tracing::Subscriber + for<'a> LookupSpan<'a>> Layer<S> for SpanPaths {
    fn on_new_span(
        &self,
        _: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        context: LayerContext<'_, S>,
    ) {
        let span = context.span(id).unwrap();
        self.0
            .lock()
            .push(span.scope().map(|span| span.metadata().name()).collect());
    }
}

async fn wait_for_checkpoint_sync(
    context: &DeterministicContext,
    syncs: &PendingSyncs,
    paths: &SpanPaths,
    publication: &mut (impl Future<Output = Result<(), Error>> + Unpin),
) {
    let checkpoint_started = || {
        paths
            .0
            .lock()
            .iter()
            .any(|path| path.first() == Some(&"multimmit.marshal.catalog.publish_checkpoint"))
    };
    for _ in 0..100 {
        if checkpoint_started() {
            break;
        }
        let pending = syncs.lock().len();
        release_next_pending_syncs(syncs, pending);
        commonware_macros::select! {
            result = &mut *publication => panic!("commit published before its checkpoint cut: {result:?}"),
            _ = context.sleep(std::time::Duration::from_millis(1)) => {},
        }
    }
    assert!(
        checkpoint_started(),
        "checkpoint cut did not start after finalized archives became durable"
    );
    assert!(
        !syncs.lock().is_empty(),
        "checkpoint durability remains blocked"
    );
}

type Client = Mailbox<Sha256, MinPk, TestBody>;

type DeliveryReceiver = delivery::Receiver<Sha256, TestBody>;

#[derive(Clone, Default)]
struct TestReporter {
    pending: Arc<Mutex<VecDeque<(OutputIndex, Exact)>>>,
}

impl TestReporter {
    fn contains(&self, index: OutputIndex) -> bool {
        self.pending
            .lock()
            .iter()
            .any(|(pending_index, _)| *pending_index == index)
    }

    fn acknowledge(&self, index: OutputIndex) -> bool {
        let mut pending = self.pending.lock();
        let Some(position) = pending
            .iter()
            .position(|(pending_index, _)| *pending_index == index)
        else {
            return false;
        };
        let (_, acknowledgement) = pending
            .remove(position)
            .expect("the located acknowledgement exists");
        drop(pending);
        acknowledgement.acknowledge();
        true
    }
}

async fn wait_for_report(
    context: &DeterministicContext,
    reporter: &TestReporter,
    index: OutputIndex,
) {
    for _ in 0..100 {
        if reporter.contains(index) {
            return;
        }
        context.sleep(std::time::Duration::from_millis(1)).await;
    }
    panic!("delivery did not report output {index}");
}

impl Reporter for TestReporter {
    type Activity = Update<TransactionBlock<Sha256, TestBody>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update {
            index,
            acknowledgement,
            ..
        } = activity;
        self.pending.lock().push_back((index, acknowledgement));
        Feedback::Ok
    }
}

/// Couples the mailbox, admission-cut, and pending-segment capacities, mirroring the
/// pre-split single knob these tests shape storage geometry with.
fn set_capacity(config: &mut Config<TwoCap, MinPk, TestBody>, capacity: usize) {
    config.capacities.catalog_mailbox_size =
        NonZeroUsize::new(capacity).expect("capacity is non-zero");
    config.capacities.admission_cut_capacity = config.capacities.catalog_mailbox_size;
    config.capacities.pending_segment_items =
        NonZeroU64::new(capacity as u64).expect("capacity is non-zero");
}

pub(super) fn config(
    context: &DeterministicContext,
    committee: &Committee<MinPk>,
) -> Config<TwoCap, MinPk, TestBody> {
    let mut archive = ArchiveConfig::new(
        TwoCap,
        CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
    );
    archive.items_per_section = NZU64!(1);
    let mut config = Config::new(
        Start::Genesis(committee.config.genesis().clone()),
        "catalog_integration".into(),
        committee.codec(),
        (),
        archive,
    );
    set_capacity(&mut config, 16);
    config.capacities.max_commit_outputs = NZUsize!(1);
    config.retention.lqc = ArchiveMode::Prunable;
    config.retention.history = ArchiveMode::Immutable;
    config.retention.blocks = ArchiveMode::Prunable;
    config
}

/// Returns the next committed batch sent to delivery.
async fn next_batch(receiver: &mut DeliveryReceiver) -> DurableBatch<Sha256, TestBody> {
    while let Some(message) = receiver.recv().await {
        if let delivery::Message::Committed(batch) = message {
            return batch;
        }
    }
    panic!("delivery mailbox closed before commit");
}

/// Returns the next reset sent to delivery.
async fn next_reset(receiver: &mut DeliveryReceiver) -> delivery::Message<Sha256, TestBody> {
    while let Some(message) = receiver.recv().await {
        if let delivery::Message::Reset { .. } = message {
            return message;
        }
    }
    panic!("delivery mailbox closed before reset");
}

async fn spawn_catalog<E>(
    config: Config<TwoCap, MinPk, TestBody>,
    context: E,
) -> (Client, Handle<Result<(), Fatal>>, DeliveryReceiver)
where
    E: Context + Spawner + RuntimeMetrics,
{
    let (delivery, receiver) = delivery::channel(context.child("delivery_mailbox"));
    let Opened {
        catalog: client,
        catalog_handle: handle,
        promoter: _,
        delivery_store: _,
    } = open_storage::<_, _, Sha256, _, _>(
        context,
        &config,
        &config.actor_bounds().unwrap(),
        delivery,
    )
    .await
    .unwrap();
    (client, handle, receiver)
}

/// Spawn a catalog like [spawn_catalog], also returning the promoter task, which owns the
/// immutable finalized archives and must stop before a test reopens their storage.
async fn spawn_catalog_with_promoter<E>(
    config: Config<TwoCap, MinPk, TestBody>,
    context: E,
) -> (
    Client,
    Handle<Result<(), Fatal>>,
    Option<Handle<impl Send + 'static>>,
    DeliveryReceiver,
)
where
    E: Context + Spawner + RuntimeMetrics,
{
    let (delivery, receiver) = delivery::channel(context.child("delivery_mailbox"));
    let Opened {
        catalog: client,
        catalog_handle: handle,
        promoter,
        delivery_store: _,
    } = open_storage::<_, _, Sha256, _, _>(
        context,
        &config,
        &config.actor_bounds().unwrap(),
        delivery,
    )
    .await
    .unwrap();
    (
        client,
        handle,
        promoter.map(|promoter| promoter.handle),
        receiver,
    )
}

async fn spawn_catalog_delivery<E>(
    config: Config<TwoCap, MinPk, TestBody>,
    context: &E,
    delivery_client: delivery::Mailbox<Sha256, TestBody>,
    delivery_commands: DeliveryReceiver,
) -> (
    Client,
    Handle<Result<(), Fatal>>,
    TestReporter,
    Handle<Result<(), delivery::Error>>,
)
where
    E: Context + Spawner,
{
    let delivery_bounds = delivery::Bounds {
        pending_acks: config.capacities.max_pending_acks,
        delivery_bytes: config.limits.max_delivery_bytes,
        hot_block_bytes: config.limits.max_hot_block_bytes,
    };
    let Opened {
        catalog: client,
        catalog_handle,
        promoter,
        delivery_store,
    } = open_storage::<_, _, Sha256, _, _>(
        context.child("catalog"),
        &config,
        &config.actor_bounds().unwrap(),
        delivery_client,
    )
    .await
    .unwrap();
    assert!(promoter.is_none());
    let reporter = TestReporter::default();
    let delivery_handle = delivery::Actor::new(delivery::Config {
        context: context.child("delivery"),
        store: delivery_store,
        catalog: client.clone(),
        bodies: Bodies::new(client.clone(), None),
        application: reporter.clone(),
        mailbox: delivery_commands,
        bounds: delivery_bounds,
    })
    .start();
    (client, catalog_handle, reporter, delivery_handle)
}

async fn open(
    context: &DeterministicContext,
    label: &'static str,
    committee: &Committee<MinPk>,
) -> (Client, Handle<Result<(), Fatal>>, DeliveryReceiver) {
    spawn_catalog(config(context, committee), context.child(label)).await
}

/// Wraps a request as the mailbox would, without an enqueue time.
fn traced<M>(message: M) -> Traced<M> {
    Traced {
        message,
        span: Span::current(),
        enqueued: None,
    }
}

impl<H, V, B> Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Admits a history opening and waits until it is durable.
    pub(crate) async fn admit_history(
        &self,
        view: View,
        commitment: H::Digest,
        record: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        self.request(|reply| Message::Admit {
            admissions: vec![Admission::History(view, commitment, record)],
            reply: AdmissionReply::Durable(reply),
        })
        .await
    }

    /// Commits one batch and waits for its publication.
    pub(crate) async fn commit(&self, batch: Commit<H, V>) -> Result<(), Error> {
        self.start_commit(batch, Vec::new()).await?.wait().await
    }

    /// Admits an L-QC with its leader's history opening and waits until both are durable.
    async fn admit_finality(
        &self,
        view: View,
        id: CertificateId<H::Digest>,
        proof: Arc<Lqc<V, H::Digest>>,
        history: Arc<TipRecord<H::Digest>>,
    ) -> Result<(), Error> {
        let expected_history = proof.leader().history();
        self.request(|reply| Message::Admit {
            admissions: vec![
                Admission::Lqc(view, id, proof),
                Admission::History(view, expected_history, history),
            ],
            reply: AdmissionReply::Durable(reply),
        })
        .await
    }
}

pub(super) fn producer_block(
    committee: &Committee<MinPk>,
    chain: u32,
    timestamp: u64,
) -> Arc<TransactionBlock<Sha256, TestBody>> {
    let body = TestBody::new(
        Sha256::hash(&[b"application parent"]),
        Height::new(9),
        timestamp,
    );
    let header = committee.transaction_header(ChainId::new(chain), body.digest());
    Arc::new(TransactionBlock::new(header, body).unwrap())
}

pub(super) fn output_row(
    index: OutputIndex,
    block: &Arc<TransactionBlock<Sha256, TestBody>>,
) -> OutputRow<Sha256Digest> {
    OutputRow::new(index, CustodyRef::for_test(block))
}

/// Hands off `block` as the body of output `index`, committed by `floor_generation`.
fn hot_output(
    index: OutputIndex,
    block: &Arc<TransactionBlock<Sha256, TestBody>>,
    floor_generation: u64,
) -> HotOutput<Sha256, TestBody> {
    HotOutput {
        stored: StoredRef::new(&output_row(index, block), floor_generation),
        block: Arc::clone(block),
    }
}

/// Builds an output-only commit extending the supplied accepted checkpoint.
fn output_commit<'a>(
    current: &Checkpoint<Sha256Digest>,
    blocks: impl IntoIterator<Item = &'a Arc<TransactionBlock<Sha256, TestBody>>>,
) -> Commit<Sha256, MinPk> {
    let mut emitted = current.emitted().to_vec();
    let mut committed = current.committed();
    let outputs = blocks
        .into_iter()
        .map(|block| {
            emitted[block.reference().chain().get() as usize] = block.reference();
            let index = committed.map_or(OutputIndex::ZERO, |index| index.next().unwrap());
            committed = Some(index);
            output_row(index, block)
        })
        .collect();
    let checkpoint = Checkpoint::try_from(CheckpointParts {
        epoch: current.epoch(),
        floor_generation: current.floor_generation(),
        archive_layout: current.archive_layout(),
        floor: current.floor(),
        history: current.history(),
        history_index: current.history_index(),
        ordered: current.ordered().to_vec(),
        emitted,
        committed,
    })
    .unwrap();
    Commit {
        selected: Vec::new(),
        history: Vec::new(),
        outputs,
        checkpoint,
    }
}

fn lqc(
    committee: &Committee<MinPk>,
    view: u64,
    signers: impl IntoIterator<Item = usize>,
) -> Arc<Lqc<MinPk, Sha256Digest>> {
    let leader = committee.leader_block(View::new(view));
    let votes = signers
        .into_iter()
        .map(|signer| committee.vote(Participant::from_usize(signer), &leader))
        .collect::<Vec<_>>();
    Arc::new(
        committee
            .verifier
            .assemble_lqc::<Sha256, _>(leader.block().clone(), &votes, &Sequential)
            .unwrap(),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn checkpoint(
    committee: &Committee<MinPk>,
    floor_generation: u64,
    floor: CertificateId<Sha256Digest>,
    history: Sha256Digest,
    history_index: u64,
    emitted: Vec<BlockRef<Sha256Digest>>,
    committed: Option<OutputIndex>,
) -> Checkpoint<Sha256Digest> {
    Checkpoint::try_from(CheckpointParts {
        epoch: committee.config.epoch(),
        floor_generation,
        archive_layout: Retention {
            lqc: ArchiveMode::Prunable,
            history: ArchiveMode::Immutable,
            blocks: ArchiveMode::Prunable,
        },
        floor,
        history,
        history_index: Some(history_index),
        ordered: committee.config.genesis().tips().to_vec(),
        emitted,
        committed,
    })
    .unwrap()
}

fn selected_commit(
    proof: Arc<Lqc<MinPk, Sha256Digest>>,
    checkpoint: Checkpoint<Sha256Digest>,
) -> Commit<Sha256, MinPk> {
    Commit {
        selected: vec![SelectedLqc {
            view: proof.view(),
            id: proof.id::<Sha256>(),
            proof,
        }],
        history: Vec::new(),
        outputs: Vec::new(),
        checkpoint,
    }
}

fn install_floors(view: View) -> PendingFloors {
    PendingFloors {
        lqc: View::new(view.get() + 1),
        history: View::new(view.get() + 1),
        blocks: vec![Height::new(2); 4],
    }
}

/// Artifacts for tests that walk one catalog through commits, reopens, and a floor install.
struct Lifecycle {
    committee: Committee<MinPk>,
    /// The genesis history opening.
    record: Arc<TipRecord<Sha256Digest>>,
    history: Sha256Digest,
    /// The L-QC the finalizing commit selects.
    proof: Arc<Lqc<MinPk, Sha256Digest>>,
    /// A same-view L-QC from another committee that stays pending.
    alternate: Arc<Lqc<MinPk, Sha256Digest>>,
    /// The block the intermediate commit outputs.
    block: Arc<TransactionBlock<Sha256, TestBody>>,
    /// A competing block of the same chain and height that never commits.
    conflicting: Arc<TransactionBlock<Sha256, TestBody>>,
    /// A block of another chain that never commits.
    other_chain: Arc<TransactionBlock<Sha256, TestBody>>,
}

impl Lifecycle {
    fn new() -> Self {
        let limits = PathLimits::new(2, 2).unwrap();
        let producers = (0..4).map(Participant::new).collect::<Vec<_>>();
        let committee = Committee::<MinPk>::builder(7, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG")
            .producers(producers.clone())
            .limits(limits)
            .build();
        let alternate = Committee::<MinPk>::builder(7, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_ALTERNATE")
            .producers(producers)
            .limits(limits)
            .build();
        let genesis = committee.config.genesis();
        let record = Arc::new(
            TipRecord::at_tips(genesis_history::<Sha256>(genesis), genesis.tips().to_vec())
                .unwrap(),
        );
        let proof = Arc::new(committee.lqc(View::new(3)));
        let alternate = Arc::new(alternate.lqc(View::new(3)));
        assert_ne!(proof.id::<Sha256>(), alternate.id::<Sha256>());
        Self {
            history: record.commitment::<Sha256>(),
            record,
            proof,
            alternate,
            block: producer_block(&committee, 0, 10),
            conflicting: producer_block(&committee, 0, 11),
            other_chain: producer_block(&committee, 1, 12),
            committee,
        }
    }

    /// Admits every artifact concurrently and waits until each is durable.
    async fn admit_all(&self, client: &Client) {
        let admissions = futures::join!(
            client.admit_finality(
                self.proof.view(),
                self.proof.id::<Sha256>(),
                self.proof.clone(),
                self.record.clone(),
            ),
            client.admit_lqc(
                self.alternate.view(),
                self.alternate.id::<Sha256>(),
                self.alternate.clone(),
            ),
            client.admit_block(self.block.reference(), self.block.clone()),
            client.admit_block(self.conflicting.reference(), self.conflicting.clone()),
            client.admit_block(self.other_chain.reference(), self.other_chain.clone()),
        );
        for result in [
            admissions.0,
            admissions.1,
            admissions.2,
            admissions.3,
            admissions.4,
        ] {
            result.unwrap();
        }
    }

    /// Returns the emitted frontier once `block` commits.
    fn emitted(&self) -> Vec<BlockRef<Sha256Digest>> {
        let mut emitted = self.committee.config.genesis().tips().to_vec();
        emitted[0] = self.block.reference();
        emitted
    }

    /// Commits `block` with the genesis history opening under the genesis floor.
    fn intermediate(&self) -> Commit<Sha256, MinPk> {
        Commit {
            selected: Vec::new(),
            history: vec![HistoryOpening {
                commitment: self.history,
                record: self.record.clone(),
            }],
            outputs: vec![output_row(OutputIndex::ZERO, &self.block)],
            checkpoint: checkpoint(
                &self.committee,
                0,
                self.committee.config.genesis().lqc(),
                self.history,
                0,
                self.emitted(),
                Some(OutputIndex::ZERO),
            ),
        }
    }

    /// Moves the floor to `proof` without new outputs.
    fn finalizing(&self) -> Commit<Sha256, MinPk> {
        selected_commit(
            self.proof.clone(),
            checkpoint(
                &self.committee,
                0,
                self.proof.id::<Sha256>(),
                self.history,
                0,
                self.emitted(),
                Some(OutputIndex::ZERO),
            ),
        )
    }

    /// Commits both batches, durably acknowledges output zero, and stops the catalog.
    async fn acknowledged(&self, context: &DeterministicContext, label: &'static str) {
        let child = context.child(label);
        let (delivery_client, _delivery) = delivery::channel(child.child("delivery_mailbox"));
        let config = config(context, &self.committee);
        let Opened {
            catalog: client,
            catalog_handle: handle,
            promoter: _,
            mut delivery_store,
        } = open_storage::<_, _, Sha256, _, _>(
            child,
            &config,
            &config.actor_bounds().unwrap(),
            delivery_client,
        )
        .await
        .unwrap();
        self.admit_all(&client).await;
        client.commit(self.intermediate()).await.unwrap();
        client.commit(self.finalizing()).await.unwrap();
        delivery_store
            .start_acknowledgement(0, OutputIndex::ZERO)
            .await
            .unwrap()
            .await
            .unwrap();
        assert_eq!(
            client.delivery_cursor(0, Some(OutputIndex::ZERO)),
            Feedback::Ok
        );
        while client.progress().await.unwrap().acknowledged != Some(OutputIndex::ZERO) {
            context.sleep(std::time::Duration::from_millis(1)).await;
        }
        drop(delivery_store);
        drop(client);
        assert!(handle.await.is_ok());
    }
}
