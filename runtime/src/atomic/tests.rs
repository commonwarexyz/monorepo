use super::*;
#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
use crate::storage::tokio as tokio_storage;
use crate::{
    BatchOperation, BufferPool, BufferPoolConfig, Handle, IoBufMut, Runner as _, deterministic,
    deterministic::{FaultConfig, PartialWriteMode},
    mocks::{DelayedSyncBlob, PendingSyncs, next_pending_sync},
    storage::{memory, metered},
    telemetry::metrics::Registry,
};
use commonware_utils::sync::Mutex as SyncMutex;
use futures::FutureExt as _;
use std::sync::atomic::{AtomicUsize, Ordering};

impl PayloadBudget {
    fn total(&self) -> u128 {
        self.state.lock().total
    }
}

fn payload_checksum(mut payload: impl Buf) -> PayloadDigest {
    let mut hasher = Sha256::default();
    hasher.update(PAYLOAD_DOMAIN);
    update_payload_checksum(&mut hasher, &mut payload);
    hasher.finalize().1.as_ref().try_into().unwrap()
}

fn encode_root(
    state: RootState,
    generation: u64,
    logical_len: u64,
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
) -> [u8; ROOT_LEN] {
    encode_root_value(
        state,
        Root {
            generation,
            logical_len,
            integrity_start: 0,
            integrity_checksum: 0,
            integrity_scheme: IntegrityScheme::Unbound,
            tag,
        },
    )
}

fn rejection_plan(
    backing_len: u64,
    encoded: &[RootSlot; ROOT_OFFSETS.len()],
) -> io::Result<Option<RejectionPlan>> {
    rejection_plan_for(backing_len, encoded, None)
}

impl State {
    fn recover(
        backing_len: u64,
        encoded: &[RootSlot; ROOT_OFFSETS.len()],
    ) -> io::Result<(Self, Option<u64>)> {
        Self::recover_for(backing_len, encoded, None, [0; INCARNATION_LEN])
    }

    fn prepare_append(&mut self, data_len: usize) -> Result<(u64, u64, u64), Error> {
        let start = self.logical_len;
        let prepared = self.prepare_integrity_append(
            IoBufs::from(vec![0; data_len]),
            IntegrityBoundary::Continue,
        )?;
        Ok(prepared.map_or((start, 0, start), |prepared| {
            (
                prepared.result_offset,
                raw_len(prepared.logical_start).expect("prepared offsets were preflighted"),
                prepared.logical_end,
            )
        }))
    }

    fn rewind(&mut self, len: u64) -> Result<(), Error> {
        if self.rewind_integrity_source(len, None)?.is_some() {
            return Err(invalid_input(
                "atomic batch rewind requires a proven integrity-unit boundary",
            ));
        }
        self.apply_rewind(len, None)
    }
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
fn pause_next_admitted_operation(
    lineage: &Arc<RwLock<()>>,
) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered_sender, entered_receiver) = oneshot::channel();
    let (resume_sender, resume_receiver) = oneshot::channel();
    let target = Arc::downgrade(lineage);
    let mut pauses = ADMISSION_PAUSES.lock();
    assert!(
        !pauses
            .iter()
            .any(|pause| Weak::ptr_eq(&pause.lineage, &target)),
        "only one operation per lineage may be paused at a time"
    );
    pauses.push(AdmissionPause {
        lineage: Arc::downgrade(lineage),
        entered: entered_sender,
        resume: resume_receiver,
    });
    (entered_receiver, resume_sender)
}

fn test_pool() -> BufferPool {
    let mut registry = Registry::default();
    BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
}

fn test_resources() -> AtomicResources {
    AtomicResources {
        driver: Driver::inline(),
        exclusion: Arc::new(RwLock::new(())),
        namespace: Arc::new(Mutex::new(())),
        payload_budget: Arc::new(PayloadBudget::default()),
    }
}

#[derive(Clone, Default)]
struct FinalRootGate {
    waiter: Arc<SyncMutex<Option<FinalRootWaiter>>>,
}

struct FinalRootWaiter {
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

impl FinalRootGate {
    fn arm(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered_sender, entered_receiver) = oneshot::channel();
        let (release_sender, release_receiver) = oneshot::channel();
        let mut waiter = self.waiter.lock();
        assert!(waiter.is_none(), "only one final-root write can be gated");
        *waiter = Some(FinalRootWaiter {
            entered: entered_sender,
            release: release_receiver,
        });
        (entered_receiver, release_sender)
    }
}

#[derive(Clone)]
struct FinalRootGateBlob<B> {
    inner: B,
    gate: FinalRootGate,
}

impl<B: BackingBlob> BackingBlob for FinalRootGateBlob<B> {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.inner.read_at(offset, len).await
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let waiter = if ROOT_OFFSETS.contains(&offset) && bufs.len() == ROOT_LEN {
            self.gate.waiter.lock().take()
        } else {
            None
        };
        if let Some(waiter) = waiter {
            let _ = waiter.entered.send(());
            waiter.release.await.map_err(|_| Error::Closed)?;
        }
        self.inner.write_at(offset, bufs, options).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.inner.sync().await
    }

    async fn start_sync(&self) -> Handle<()> {
        self.inner.start_sync().await
    }
}

#[derive(Clone)]
struct FinalRootGateStorage {
    inner: memory::Storage,
    gate: FinalRootGate,
    identifiers: Arc<AtomicUsize>,
}

impl FinalRootGateStorage {
    fn new(inner: memory::Storage, gate: FinalRootGate) -> Self {
        Self {
            inner,
            gate,
            identifiers: Arc::new(AtomicUsize::new(1)),
        }
    }
}

impl Storage for FinalRootGateStorage {
    type Blob = FinalRootGateBlob<memory::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        let (inner, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        Ok((
            FinalRootGateBlob {
                inner,
                gate: self.gate.clone(),
            },
            len,
            version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

impl Backend for FinalRootGateStorage {
    type Worker = Self;

    fn atomic_worker(&self) -> Self {
        Self {
            inner: Backend::atomic_worker(&self.inner),
            gate: self.gate.clone(),
            identifiers: self.identifiers.clone(),
        }
    }

    fn atomic_resources(&self) -> AtomicResources {
        Backend::atomic_resources(&self.inner)
    }

    fn new_atomic_identifier(&self) -> [u8; INCARNATION_LEN] {
        let ordinal = self.identifiers.fetch_add(1, Ordering::Relaxed) as u64;
        let mut identifier = [0; INCARNATION_LEN];
        identifier[INCARNATION_LEN - size_of::<u64>()..].copy_from_slice(&ordinal.to_be_bytes());
        identifier
    }

    async fn migrate_atomic_backing(
        &self,
        blob: Self::Blob,
        incarnation: [u8; INCARNATION_LEN],
    ) -> Result<(), Error> {
        Backend::migrate_atomic_backing(&self.inner, blob.inner, incarnation).await
    }

    async fn open_atomic_existing(
        &self,
        partition: &str,
        name: &[u8],
    ) -> Result<Option<(Self::Blob, u64)>, Error> {
        Ok(Backend::open_atomic_existing(&self.inner, partition, name)
            .await?
            .map(|(inner, len)| {
                (
                    FinalRootGateBlob {
                        inner,
                        gate: self.gate.clone(),
                    },
                    len,
                )
            }))
    }
}

#[cfg(feature = "arbitrary")]
mod conformance {
    use super::*;
    use commonware_conformance::Conformance;

    /// Canonical identity, root-state, witness, and slot-placement bytes.
    struct AtomicFormat;

    impl Conformance for AtomicFormat {
        async fn commit(_: u64) -> Vec<u8> {
            let migration = migration_prefix(
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                0x0102_0304_0506_0708,
                0x1122_3344,
            );
            let prepared = batch::prepare_with_group_id(
                vec![
                    batch::Participant {
                        partition: "fixture".into(),
                        name: b"removed".to_vec(),
                        incarnation: [0x11; INCARNATION_LEN],
                        candidate: batch::Candidate::with_payload(
                            Root {
                                generation: 1,
                                logical_len: 5,
                                integrity_start: 5,
                                integrity_checksum: 0,
                                integrity_scheme: IntegrityScheme::Variable,
                                tag: [0x33; ATOMIC_BLOB_TAG_LEN],
                            },
                            batch::PayloadDescriptor::empty(5),
                        )
                        .unwrap(),
                        removed: true,
                    },
                    batch::Participant {
                        partition: "fixture".into(),
                        name: b"present".to_vec(),
                        incarnation: [0x22; INCARNATION_LEN],
                        candidate: batch::Candidate::with_payload(
                            Root {
                                generation: 2,
                                logical_len: 19,
                                integrity_start: 12,
                                integrity_checksum: 0x5566_7788,
                                integrity_scheme: IntegrityScheme::Chunked(
                                    std::num::NonZeroU32::new(8).unwrap(),
                                ),
                                tag: [0x44; ATOMIC_BLOB_TAG_LEN],
                            },
                            batch::PayloadDescriptor {
                                start: 5,
                                checksum: [0x66; 32],
                            },
                        )
                        .unwrap(),
                        removed: false,
                    },
                ],
                [0x77; batch::GROUP_ID_LEN],
            )
            .unwrap();
            let root_region_len = (DATA_OFFSET - IDENTITY_PAGE_LEN) as usize;
            let mut prepared_roots = vec![0; root_region_len];
            let mut finalized_roots = vec![0; root_region_len];
            for (participant, slot) in prepared.participants.iter().zip(&prepared.slots) {
                let offset =
                    (participant.candidate.root_offset().unwrap() - IDENTITY_PAGE_LEN) as usize;
                prepared_roots[offset..offset + ROOT_SLOT_SIZE].copy_from_slice(slot);
                finalized_roots[offset..offset + ROOT_SLOT_SIZE].copy_from_slice(slot);
                finalized_roots[offset..offset + ROOT_LEN]
                    .copy_from_slice(&participant.candidate.final_root().unwrap());
            }

            let mut commitment = Vec::with_capacity(DATA_OFFSET as usize + 2 * root_region_len);
            commitment.extend_from_slice(&migration);
            commitment.extend_from_slice(&prepared_roots);
            commitment.extend_from_slice(&finalized_roots);
            commitment
        }
    }

    commonware_conformance::conformance_tests! {
        AtomicFormat => 1
    }
}

type WriteRetention = (PartialWriteMode, f64);

const FULL_RETENTION: WriteRetention = (PartialWriteMode::Prefix, 1.0);
const SUBSET_RETENTION: WriteRetention = (PartialWriteMode::Subset, 0.5);

fn write_retention_config(retention: Option<WriteRetention>) -> FaultConfig {
    FaultConfig {
        write_retention: retention,
        ..FaultConfig::default()
    }
}

async fn initialize_test_backing<B: BackingBlob>(
    backing: &B,
    backing_len: u64,
) -> ([u8; INCARNATION_LEN], u64) {
    let incarnation = Blob::<B>::initialize_identity(backing, backing_len, test_incarnation)
        .await
        .unwrap();
    (incarnation, DATA_OFFSET)
}

#[cfg(not(target_arch = "wasm32"))]
fn saturate_background_driver(driver: &Driver) -> (Arc<tokio::sync::Semaphore>, Vec<Handle<()>>) {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (started_sender, started_receiver) = std::sync::mpsc::channel();
    let mut handles = Vec::with_capacity(DRIVER_ADMISSION_CAPACITY);
    for _ in 0..DRIVER_ADMISSION_CAPACITY {
        let gate = gate.clone();
        let started_sender = started_sender.clone();
        let permit = futures::executor::block_on(driver.reserve()).unwrap();
        handles.push(permit.drive(async move {
            started_sender.send(()).unwrap();
            drop(gate.acquire().await.unwrap());
            Ok::<_, Error>(())
        }));
    }
    for _ in 0..DRIVER_ADMISSION_CAPACITY {
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("an admitted driver task did not start");
    }
    (gate, handles)
}

#[test]
fn inline_foreground_reservation_drives_work() {
    let driver = Driver::inline();
    let permit = futures::executor::block_on(driver.reserve()).unwrap();
    let handle = permit.drive(futures::future::ready(Ok::<_, Error>(7)));
    assert_eq!(futures::executor::block_on(handle).unwrap(), 7);
}

#[test]
fn detached_inline_work_completes_before_returning() {
    let driver = Driver::inline();
    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task_completed = completed.clone();
    futures::executor::block_on(driver.drive_detached(async move {
        task_completed.store(true, std::sync::atomic::Ordering::Relaxed);
    }));
    assert!(completed.load(std::sync::atomic::Ordering::Relaxed));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn background_driver_completes_and_reports_closed() {
    let driver = Driver::background();
    let permit = futures::executor::block_on(driver.reserve()).unwrap();
    let result =
        futures::executor::block_on(permit.drive(futures::future::ready(Ok::<_, Error>(()))));
    assert!(result.is_ok());

    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    drop(receiver);
    let background = Arc::new(BackgroundDriver::new());
    background.sender.set(sender).ok().unwrap();
    let driver = Driver::Background(background);

    let permit = futures::executor::block_on(driver.reserve()).unwrap();
    let result =
        futures::executor::block_on(permit.drive(futures::future::ready(Ok::<_, Error>(()))));
    assert_eq!(
        std::mem::discriminant(&result.unwrap_err()),
        std::mem::discriminant(&Error::Closed)
    );

    let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let task_completed = completed.clone();
    futures::executor::block_on(driver.drive_detached(async move {
        task_completed.store(true, std::sync::atomic::Ordering::Relaxed);
    }));
    assert!(completed.load(std::sync::atomic::Ordering::Relaxed));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn background_driver_bounds_foreground_admission_until_completion() {
    let driver = Driver::background();
    let (gate, handles) = saturate_background_driver(&driver);
    let (started_sender, started_receiver) = std::sync::mpsc::channel();

    let gate_for_overflow = gate.clone();
    let overflow_sender = started_sender;
    let overflow_task = async move {
        overflow_sender.send(()).unwrap();
        drop(gate_for_overflow.acquire().await.unwrap());
        Ok::<_, Error>(())
    };
    let mut overflow = Box::pin(driver.reserve());
    assert!(overflow.as_mut().now_or_never().is_none());
    let overflow_started = started_receiver
        .recv_timeout(std::time::Duration::from_millis(100))
        .is_ok();

    gate.add_permits(DRIVER_ADMISSION_CAPACITY + 1);
    futures::executor::block_on(async {
        for handle in handles {
            handle.await.unwrap();
        }
        overflow.await.unwrap().drive(overflow_task).await.unwrap();
    });
    assert!(!overflow_started, "the driver exceeded its admission bound");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn canceling_waiting_foreground_reservation_does_not_leak() {
    let driver = Driver::background();
    let (gate, handles) = saturate_background_driver(&driver);
    let mut waiting = Box::pin(driver.reserve());
    assert!(waiting.as_mut().now_or_never().is_none());
    drop(waiting);

    gate.add_permits(DRIVER_ADMISSION_CAPACITY);
    futures::executor::block_on(async {
        for handle in handles {
            handle.await.unwrap();
        }
    });
    let permit = futures::executor::block_on(driver.reserve()).unwrap();
    futures::executor::block_on(permit.drive(futures::future::ready(Ok::<_, Error>(())))).unwrap();
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn saturated_background_driver_can_handoff_detached_preflushes() {
    let driver = Driver::background();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let (started_sender, started_receiver) = std::sync::mpsc::channel();
    let (completed_sender, completed_receiver) = std::sync::mpsc::channel();
    let mut handles = Vec::with_capacity(DRIVER_ADMISSION_CAPACITY);

    for _ in 0..DRIVER_ADMISSION_CAPACITY {
        let child_driver = driver.clone();
        let gate = gate.clone();
        let started_sender = started_sender.clone();
        let completed_sender = completed_sender.clone();
        let permit = futures::executor::block_on(driver.reserve()).unwrap();
        handles.push(permit.drive(async move {
            child_driver
                .drive_detached(async move {
                    started_sender.send(()).unwrap();
                    drop(gate.acquire().await.unwrap());
                    completed_sender.send(()).unwrap();
                })
                .await;
            Ok::<_, Error>(())
        }));
    }
    futures::executor::block_on(async {
        for handle in handles {
            handle.await.unwrap();
        }
    });
    for _ in 0..DRIVER_ADMISSION_CAPACITY {
        started_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("a detached preflush did not start");
    }

    let overflow_gate = gate.clone();
    let overflow_started = started_sender;
    let overflow_completed = completed_sender;
    let mut overflow = Box::pin(driver.drive_detached(async move {
        overflow_started.send(()).unwrap();
        drop(overflow_gate.acquire().await.unwrap());
        overflow_completed.send(()).unwrap();
    }));
    assert!(overflow.as_mut().now_or_never().is_none());
    assert!(
        started_receiver
            .recv_timeout(std::time::Duration::from_millis(100))
            .is_err(),
        "the detached driver exceeded its admission bound"
    );

    gate.add_permits(DRIVER_ADMISSION_CAPACITY + 1);
    futures::executor::block_on(overflow);
    for _ in 0..=DRIVER_ADMISSION_CAPACITY {
        completed_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("a detached preflush did not complete");
    }
}

async fn delayed_preflush_blob(
    partition: &str,
    driver: Driver,
) -> (
    Blob<DelayedSyncBlob<memory::Blob>>,
    PendingSyncs,
    Arc<PayloadBudget>,
) {
    let storage = memory::Storage::new(test_pool());
    let (backing, backing_len) = storage.open(partition, b"blob").await.unwrap();
    let (incarnation, backing_len) = initialize_test_backing(&backing, backing_len).await;

    let (backing, pending) = DelayedSyncBlob::new(backing);
    let budget = Arc::new(PayloadBudget::default());
    let (blob, _) = Blob::open_named(
        backing,
        partition,
        b"blob",
        backing_len,
        incarnation,
        test_token_epoch(),
        AtomicResources {
            driver,
            exclusion: Arc::new(RwLock::new(())),
            namespace: Arc::new(Mutex::new(())),
            payload_budget: budget.clone(),
        },
    )
    .await
    .unwrap();
    (blob, pending, budget)
}

#[cfg(not(target_arch = "wasm32"))]
async fn disjoint_delayed_blobs() -> (Vec<Blob<DelayedSyncBlob<memory::Blob>>>, Vec<PendingSyncs>) {
    let storage = memory::Storage::new(test_pool());
    let shared_exclusion = Arc::new(RwLock::new(()));
    let shared_namespace = Arc::new(Mutex::new(()));
    let shared_budget = Arc::new(PayloadBudget::default());
    let mut blobs = Vec::new();
    let mut pending = Vec::new();

    for name in [b"a".as_slice(), b"b"] {
        let (backing, backing_len) = storage.open("disjoint_publications", name).await.unwrap();
        let (incarnation, backing_len) = initialize_test_backing(&backing, backing_len).await;

        let (backing, syncs) = DelayedSyncBlob::new(backing);
        let (blob, _) = Blob::open_named(
            backing,
            "disjoint_publications",
            name,
            backing_len,
            incarnation,
            test_token_epoch(),
            AtomicResources {
                driver: Driver::inline(),
                exclusion: shared_exclusion.clone(),
                namespace: shared_namespace.clone(),
                payload_budget: shared_budget.clone(),
            },
        )
        .await
        .unwrap();
        blob.append(name).await.unwrap();
        blobs.push(blob);
        pending.push(syncs);
    }

    (blobs, pending)
}

#[cfg(not(target_arch = "wasm32"))]
async fn install_test_carried_group(
    blobs: &[Blob<DelayedSyncBlob<memory::Blob>>],
    group_id: [u8; batch::GROUP_ID_LEN],
) -> Arc<CarriedGroup<DelayedSyncBlob<memory::Blob>>> {
    let carried = Arc::new(CarriedGroup {
        group_id,
        members: blobs
            .iter()
            .map(|blob| CarriedMember {
                partition: blob.partition.clone(),
                name: blob.name.clone(),
                incarnation: blob.incarnation,
                backing: blob.backing.clone(),
                sync_gate: blob.preflush.sync_gate.clone(),
                slot: Arc::downgrade(&blob.carried),
            })
            .collect(),
        payment: blobs[0].payload.budget.register_carried(group_id),
        coordination: Mutex::new(()),
    });
    for blob in blobs {
        *blob.carried.lock().await = Some(carried.clone());
    }
    carried
}

#[cfg(not(target_arch = "wasm32"))]
async fn begin_blocked_large_preflush(
    blob: &Blob<DelayedSyncBlob<memory::Blob>>,
    pending: &PendingSyncs,
) -> (u64, oneshot::Sender<Result<(), Error>>) {
    pending.arm();
    let deferred = next_pending_sync(pending);
    let release = deferred.release;
    let len = MAX_UNSYNCED_PAYLOAD_LEN + 1;
    let mut append = Box::pin(blob.append(vec![7; len as usize]));
    let mut append_result = append.as_mut().now_or_never();
    deferred.blocked.await.unwrap();
    if append_result.is_none() {
        append_result = append.as_mut().now_or_never();
    }
    assert!(
        append_result.is_some(),
        "append must return while its invisible payload preflush remains in flight"
    );
    append_result.unwrap().unwrap();
    (len, release)
}

struct ParticipantIoProbe {
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
    started: bool,
}

struct PendingOnce {
    result: Option<Result<(), Error>>,
    pending: bool,
}

struct FailingParticipantIoProbe {
    started: Arc<AtomicUsize>,
    completed: Arc<AtomicUsize>,
    pending: bool,
    fail: bool,
}

impl Future for PendingOnce {
    type Output = Result<(), Error>;

    fn poll(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if self.pending {
            self.pending = false;
            context.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        std::task::Poll::Ready(self.result.take().expect("a test future resolves once"))
    }
}

impl Future for ParticipantIoProbe {
    type Output = Result<(), Error>;

    fn poll(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if !self.started {
            self.started = true;
            let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
            self.maximum.fetch_max(active, Ordering::Relaxed);
            context.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        self.active.fetch_sub(1, Ordering::Relaxed);
        std::task::Poll::Ready(Ok(()))
    }
}

impl Future for FailingParticipantIoProbe {
    type Output = Result<(), Error>;

    fn poll(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if self.pending {
            self.pending = false;
            self.started.fetch_add(1, Ordering::Relaxed);
            context.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        self.completed.fetch_add(1, Ordering::Relaxed);
        std::task::Poll::Ready(if self.fail {
            Err(Error::Timeout)
        } else {
            Ok(())
        })
    }
}

#[test]
fn participant_io_starts_the_complete_set_concurrently() {
    deterministic::Runner::default().start(|_| async move {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let participant_count = 65;
        let operations = (0..participant_count).map(|_| ParticipantIoProbe {
            active: active.clone(),
            maximum: maximum.clone(),
            started: false,
        });

        join_participant_io(operations.collect()).await.unwrap();
        assert_eq!(active.load(Ordering::Relaxed), 0);
        assert_eq!(maximum.load(Ordering::Relaxed), participant_count);
    });
}

#[test]
fn participant_io_error_drains_the_complete_set() {
    deterministic::Runner::default().start(|_| async move {
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let participant_count = 65;
        let operations = (0..participant_count)
            .map(|index| FailingParticipantIoProbe {
                started: started.clone(),
                completed: completed.clone(),
                pending: true,
                fail: index == 0,
            })
            .collect();

        assert!(join_participant_io(operations).await.is_err());
        assert_eq!(started.load(Ordering::Relaxed), participant_count);
        assert_eq!(completed.load(Ordering::Relaxed), participant_count);
    });
}

#[test]
fn start_apply_distinguishes_decision_from_task_completion() {
    deterministic::Runner::default().start(|_| async move {
        let (sender, receiver) = oneshot::channel();
        sender.send(()).unwrap();
        let completion = Handle::from_future(futures::future::pending());
        let detached = await_batch_decision(completion, receiver).await.unwrap();
        drop(detached);

        for (completion_result, expected) in [
            (Ok(()), Error::Closed),
            (Err(Error::Timeout), Error::Timeout),
        ] {
            let (sender, receiver) = oneshot::channel();
            drop(sender);
            let completion = Handle::from_future(PendingOnce {
                result: Some(completion_result),
                pending: true,
            });
            let result = await_batch_decision(completion, receiver).await;
            assert!(result.is_err());
            let error = result.err().unwrap();
            assert_eq!(error.to_string(), expected.to_string());
        }
    });
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
async fn observe_tokio_recovery(
    storage: tokio_storage::Storage,
    partition: &'static str,
    name: &'static [u8],
    scan: bool,
) -> Result<(), Error> {
    if scan {
        storage.scan_atomic(partition).await.map(|_| ())
    } else {
        storage.open_atomic(partition, name).await.map(|_| ())
    }
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
struct ResumeWriteOnDrop(Option<std::sync::mpsc::SyncSender<()>>);

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
impl ResumeWriteOnDrop {
    const fn new(sender: std::sync::mpsc::SyncSender<()>) -> Self {
        Self(Some(sender))
    }

    fn release(mut self) {
        self.0.take().unwrap().send(()).unwrap();
    }
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
impl Drop for ResumeWriteOnDrop {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[test]
fn paused_write_is_resumed_while_a_failing_test_unwinds() {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    drop(ResumeWriteOnDrop::new(sender));
    receiver.recv().unwrap();
}

fn test_incarnation() -> [u8; INCARNATION_LEN] {
    [3; INCARNATION_LEN]
}

fn test_token_epoch() -> [u8; INCARNATION_LEN] {
    [4; INCARNATION_LEN]
}

fn io_kind(error: &Error) -> Option<io::ErrorKind> {
    match error {
        Error::Io(error) => Some(error.kind()),
        _ => None,
    }
}

fn is_blob_corrupt(error: &Error) -> bool {
    matches!(error, Error::BlobCorrupt(_, _, _))
}

fn is_offset_overflow(error: &Error) -> bool {
    matches!(error, Error::OffsetOverflow)
}

#[test]
fn batch_publishes_three_blobs_as_one_group() {
    deterministic::Runner::default().start(|context| async move {
        let (a, _) = context.open_atomic("atomic_batch", b"a").await.unwrap();
        let (b, _) = context.open_atomic("atomic_batch", b"b").await.unwrap();
        let (c, _) = context.open_atomic("atomic_batch", b"c").await.unwrap();
        a.append(b"old-a").await.unwrap();
        b.append(b"old-b").await.unwrap();
        c.append(b"old-c").await.unwrap();
        context
            .apply(vec![
                BatchOperation::Publish(a.clone()),
                BatchOperation::Publish(b.clone()),
                BatchOperation::Publish(c.clone()),
            ])
            .await
            .unwrap();

        a.append(b"-new").await.unwrap();
        b.append(b"-new").await.unwrap();
        c.append(b"-new").await.unwrap();
        context
            .apply(vec![
                BatchOperation::Publish(a),
                BatchOperation::Publish(b),
                BatchOperation::Publish(c),
            ])
            .await
            .unwrap();

        for (name, expected) in [
            (b"a".as_slice(), b"old-a-new".as_slice()),
            (b"b".as_slice(), b"old-b-new".as_slice()),
            (b"c".as_slice(), b"old-c-new".as_slice()),
        ] {
            let (blob, len) = context.open_atomic("atomic_batch", name).await.unwrap();
            assert_eq!(len, expected.len() as u64);
            assert_eq!(
                blob.read_at(0, expected.len()).await.unwrap().coalesce(),
                expected
            );
        }
    });
}

#[test]
fn cross_partition_ring_recovers_publish_and_remove() {
    let (_, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let locations = [
                ("cross_partition_a", b"a".as_slice(), false),
                ("cross_partition_b", b"b".as_slice(), true),
            ];
            let mut participants = Vec::new();
            let mut backings = BTreeMap::new();
            for (ordinal, (partition, name, removed)) in locations.into_iter().enumerate() {
                let (blob, _) = context.open_atomic(partition, name).await.unwrap();
                blob.append_tagged(b"old", [0x10 + ordinal as u8; ATOMIC_BLOB_TAG_LEN])
                    .await
                    .unwrap();
                blob.sync().await.unwrap();
                blob.append_tagged(b"-new", [0x20 + ordinal as u8; ATOMIC_BLOB_TAG_LEN])
                    .await
                    .unwrap();
                blob.backing.sync().await.unwrap();
                participants.push(batch::Participant {
                    partition: partition.to_string(),
                    name: name.to_vec(),
                    incarnation: blob.incarnation,
                    candidate: batch::Candidate::with_payload(
                        Root::unbound(2, 7, [0x20 + ordinal as u8; ATOMIC_BLOB_TAG_LEN]),
                        if removed {
                            batch::PayloadDescriptor::empty(7)
                        } else {
                            batch::PayloadDescriptor {
                                start: 3,
                                checksum: payload_checksum(IoBufs::from(b"-new".to_vec())),
                            }
                        },
                    )
                    .unwrap(),
                    removed,
                });
                backings.insert((partition.to_string(), name.to_vec()), blob.backing.clone());
            }

            let prepared = batch::prepare(participants).unwrap();
            for (participant, slot) in prepared.participants.iter().zip(&prepared.slots) {
                backings[&(participant.partition.clone(), participant.name.clone())]
                    .write_at(
                        participant.candidate.root_offset().unwrap(),
                        slot.to_vec(),
                        WriteOptions::SYNC,
                    )
                    .await
                    .unwrap();
            }
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let (retained, len) = context
            .open_atomic("cross_partition_a", b"a")
            .await
            .unwrap();
        assert_eq!(len, 7);
        assert_eq!(retained.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
        assert_eq!(
            context.scan("cross_partition_a").await.unwrap(),
            vec![b"a".to_vec()]
        );
        assert!(context.scan("cross_partition_b").await.unwrap().is_empty());
    });
}

#[test]
fn persisted_atomic_identifiers_follow_the_deterministic_runtime_rng() {
    fn run() -> String {
        deterministic::Runner::seeded(0x08a7_01c5).start(|context| async move {
            let (a, _) = context
                .open_atomic("deterministic_ids", b"a")
                .await
                .unwrap();
            let (b, _) = context
                .open_atomic("deterministic_ids", b"b")
                .await
                .unwrap();
            a.append(b"a").await.unwrap();
            b.append(b"b").await.unwrap();
            context
                .apply(vec![BatchOperation::Publish(a), BatchOperation::Publish(b)])
                .await
                .unwrap();
            context.auditor().state()
        })
    }

    assert_eq!(run(), run());
}

#[derive(Clone, Copy)]
enum StagedPayload {
    Durable,
    Prefix(usize),
}

async fn stage_batch_with_payload<S>(
    storage: &S,
    partition: &str,
    names: &[&[u8]],
    removals: &[bool],
    slot_mask: u64,
    payload: StagedPayload,
) -> batch::PreparedGroup
where
    S: Storage + AtomicStorage<AtomicBlob = Blob<<S as Storage>::Blob>>,
{
    assert_eq!(names.len(), removals.len());
    assert!(names.len() <= 64);
    let mut participants = Vec::with_capacity(names.len());
    let mut backings = BTreeMap::new();
    for (ordinal, (&name, &removed)) in names.iter().zip(removals).enumerate() {
        let old_tag = [0x10 + ordinal as u8; ATOMIC_BLOB_TAG_LEN];
        let new_tag = [0x20 + ordinal as u8; ATOMIC_BLOB_TAG_LEN];
        let (blob, _) = storage.open_atomic(partition, name).await.unwrap();
        blob.append_tagged(b"old", old_tag).await.unwrap();
        blob.sync().await.unwrap();
        blob.append_tagged(b"-new", new_tag).await.unwrap();
        let backing = blob.backing.clone();
        match payload {
            StagedPayload::Durable => backing.sync().await.unwrap(),
            StagedPayload::Prefix(len) => {
                assert!(len < b"-new".len());
                backing
                    .write_at(DATA_OFFSET + 3, b"-new"[..len].to_vec(), WriteOptions::SYNC)
                    .await
                    .unwrap();
            }
        }
        let identity = backing
            .read_at(0, IDENTITY_PAGE_LEN as usize)
            .await
            .unwrap()
            .coalesce();
        let incarnation = decode_identity(identity.as_ref().try_into().unwrap()).unwrap();
        participants.push(batch::Participant {
            partition: partition.to_string(),
            name: name.to_vec(),
            incarnation,
            candidate: batch::Candidate::with_payload(
                Root::unbound(2, 7, new_tag),
                if removed {
                    batch::PayloadDescriptor::empty(7)
                } else {
                    batch::PayloadDescriptor {
                        start: 3,
                        checksum: payload_checksum(IoBufs::from(b"-new".to_vec())),
                    }
                },
            )
            .unwrap(),
            removed,
        });
        backings.insert(name.to_vec(), backing);
    }

    let prepared = batch::prepare(participants).unwrap();
    for (ordinal, (participant, slot)) in prepared
        .participants
        .iter()
        .zip(&prepared.slots)
        .enumerate()
    {
        if slot_mask & (1 << ordinal) == 0 {
            continue;
        }
        let backing = &backings[&participant.name];
        backing
            .write_at(
                participant.candidate.root_offset().unwrap(),
                slot.to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
    }
    prepared
}

async fn stage_batch<S>(
    storage: &S,
    partition: &str,
    names: &[&[u8]],
    removals: &[bool],
    slot_mask: u64,
) -> batch::PreparedGroup
where
    S: Storage + AtomicStorage<AtomicBlob = Blob<<S as Storage>::Blob>>,
{
    stage_batch_with_payload(
        storage,
        partition,
        names,
        removals,
        slot_mask,
        StagedPayload::Durable,
    )
    .await
}

async fn stage_singleton_successor<S: Storage>(
    storage: &S,
    predecessor: &batch::Participant,
    root: Root,
    payload: batch::PayloadDescriptor,
    removed: bool,
    group_id: u8,
) {
    let participant = batch::Participant {
        partition: predecessor.partition.clone(),
        name: predecessor.name.clone(),
        incarnation: predecessor.incarnation,
        candidate: batch::Candidate::with_payload(root, payload).unwrap(),
        removed,
    };
    let prepared =
        batch::prepare_with_group_id(vec![participant.clone()], [group_id; batch::GROUP_ID_LEN])
            .unwrap();
    let (backing, _) = storage
        .open(&participant.partition, &participant.name)
        .await
        .unwrap();
    backing
        .write_at(
            participant.candidate.root_offset().unwrap(),
            prepared.slots[0].to_vec(),
            WriteOptions::SYNC,
        )
        .await
        .unwrap();
}

async fn stage_identity_corruption<S: Storage>(storage: &S, partition: &str, name: &[u8]) {
    let (backing, _) = storage.open(partition, name).await.unwrap();
    let mut prefix = vec![0; IDENTITY_PAGE_LEN as usize + 1];
    prefix[0] = b'x';
    prefix[IDENTITY_PAGE_LEN as usize] = 1;
    backing
        .write_at(0, prefix, WriteOptions::SYNC)
        .await
        .unwrap();
}

async fn stage_group_corruption<S>(storage: &S, partition: &str, name: &[u8])
where
    S: Storage + AtomicStorage<AtomicBlob = Blob<<S as Storage>::Blob>>,
{
    let (blob, _) = storage.open_atomic(partition, name).await.unwrap();
    let participant = batch::Participant {
        partition: partition.into(),
        name: name.to_vec(),
        incarnation: blob.incarnation,
        candidate: batch::Candidate::new(Root::unbound(1, u64::MAX, [1; ATOMIC_BLOB_TAG_LEN]))
            .unwrap(),
        removed: false,
    };
    let prepared = batch::prepare(vec![participant.clone()]).unwrap();
    blob.backing
        .write_at(
            participant.candidate.root_offset().unwrap(),
            prepared.slots[0].to_vec(),
            WriteOptions::SYNC,
        )
        .await
        .unwrap();
}

async fn stage_root_corruption<S>(storage: &S, partition: &str, name: &[u8])
where
    S: Storage + AtomicStorage<AtomicBlob = Blob<<S as Storage>::Blob>>,
{
    let (blob, _) = storage.open_atomic(partition, name).await.unwrap();
    blob.backing
        .write_at(ROOT_OFFSETS[0], vec![1; ROOT_SLOT_SIZE], WriteOptions::SYNC)
        .await
        .unwrap();
}

async fn assert_open_maps_recovery_corruption<S>(storage: &S, partition: &str)
where
    S: Storage + AtomicStorage<AtomicBlob = Blob<<S as Storage>::Blob>>,
{
    stage_identity_corruption(storage, partition, b"identity").await;
    let error = storage
        .open_atomic(partition, b"identity")
        .await
        .err()
        .unwrap();
    assert!(is_blob_corrupt(&error));

    let (blob, _) = storage
        .open_atomic(partition, b"guarded_identity")
        .await
        .unwrap();
    let backing = blob.backing.clone();
    drop(blob);
    let old = backing.read_at(8, 1).await.unwrap().coalesce();
    let old = old.as_ref()[0];
    backing
        .write_at(8, vec![old ^ 1], WriteOptions::SYNC)
        .await
        .unwrap();
    backing
        .write_at(IDENTITY_PAGE_LEN, vec![1], WriteOptions::SYNC)
        .await
        .unwrap();
    drop(backing);
    let error = storage
        .open_atomic(partition, b"guarded_identity")
        .await
        .err()
        .unwrap();
    assert!(is_blob_corrupt(&error));

    let (backing, _) = storage.open(partition, b"identity_root").await.unwrap();
    backing.resize(IDENTITY_PAGE_LEN + 1).await.unwrap();
    backing
        .write_at(IDENTITY_PAGE_LEN, vec![1], WriteOptions::SYNC)
        .await
        .unwrap();
    let error = storage
        .open_atomic(partition, b"identity_root")
        .await
        .err()
        .unwrap();
    assert!(is_blob_corrupt(&error));

    stage_group_corruption(storage, partition, b"group").await;
    let error = storage
        .open_atomic(partition, b"group")
        .await
        .err()
        .unwrap();
    assert!(is_blob_corrupt(&error));

    stage_root_corruption(storage, partition, b"roots").await;
    let error = storage
        .open_atomic(partition, b"roots")
        .await
        .err()
        .unwrap();
    assert!(is_blob_corrupt(&error));
}

#[test]
fn every_three_member_slot_subset_is_atomic_with_delayed_opens() {
    deterministic::Runner::default().start(|context| async move {
        for slot_mask in 0..8 {
            let partition = format!("batch_slot_mask_{slot_mask}");
            stage_batch(
                &context,
                &partition,
                &[b"a", b"b", b"c"],
                &[false; 3],
                slot_mask,
            )
            .await;
            let decided = slot_mask == 0b111;
            if decided {
                let existing = open_existing(&context, &partition, b"a")
                    .await
                    .unwrap()
                    .unwrap();
                let link = existing
                    .slots
                    .iter()
                    .find_map(|slot| batch::link(slot, &partition, b"a"))
                    .unwrap();
                let members = traverse_group(
                    &context,
                    GroupMember {
                        link,
                        backing: existing.backing,
                        backing_len: existing.backing_len,
                        slots: existing.slots,
                    },
                    false,
                )
                .await
                .unwrap()
                .expect("all three prepared slots form a closed ring");
                for member in &members {
                    assert!(
                        candidate_status(&member.link, member.backing_len, &member.slots, false,)
                            .unwrap()
                            .is_some()
                    );
                }
            }

            // Recover A first and advance it before either peer opens. C must still resolve
            // its original three-member witness without treating A as a singleton or vote.
            let (a, a_len) = context.open_atomic(&partition, b"a").await.unwrap();
            assert_eq!(a_len, if decided { 7 } else { 3 });
            a.append(b"!").await.unwrap();
            a.sync().await.unwrap();
            drop(a);

            for name in [b"c".as_slice(), b"b".as_slice()] {
                let (blob, len) = context.open_atomic(&partition, name).await.unwrap();
                assert_eq!(len, if decided { 7 } else { 3 }, "mask {slot_mask:#05b}");
                let expected = if decided {
                    b"old-new".as_slice()
                } else {
                    b"old".as_slice()
                };
                assert_eq!(
                    blob.read_at(0, expected.len()).await.unwrap().coalesce(),
                    expected,
                    "mask {slot_mask:#05b}",
                );
            }
        }
    });
}

#[test]
fn disconnected_retained_finals_survive_peer_unlinks_and_later_advancement() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "batch_disconnected_finals";
        stage_batch(
            &context,
            partition,
            &[b"a", b"b", b"c", b"d"],
            &[false, true, false, true],
            0b1111,
        )
        .await;

        // Opening A decides and independently finalizes all four participants before B and D
        // are unlinked. The remaining M roots no longer need a traversable ring.
        let (a, len) = context.open_atomic(partition, b"a").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(a.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
        assert_eq!(
            context.scan(partition).await.unwrap(),
            vec![b"a".to_vec(), b"c".to_vec()]
        );

        // A same-name replacement has a new incarnation and must not be consumed by C's old
        // witness or by deferred cleanup for the removed participant.
        let (replacement, _) = context.open_atomic(partition, b"b").await.unwrap();
        replacement.append(b"replacement").await.unwrap();
        replacement.sync().await.unwrap();
        drop(replacement);

        a.append(b"!").await.unwrap();
        a.sync().await.unwrap();
        drop(a);

        let (c, len) = context.open_atomic(partition, b"c").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(c.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
        drop(c);
        let (replacement, len) = context.open_atomic(partition, b"b").await.unwrap();
        assert_eq!(len, b"replacement".len() as u64);
        assert_eq!(
            replacement
                .read_at(0, b"replacement".len())
                .await
                .unwrap()
                .coalesce(),
            b"replacement",
        );
        assert_eq!(
            context.scan(partition).await.unwrap(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        );
    });
}

#[test]
fn mixed_publish_rewind_remove_batch_updates_the_complete_vector() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "batch_mixed_operations";
        let (published, _) = context.open_atomic(partition, b"published").await.unwrap();
        let (rewound, _) = context.open_atomic(partition, b"rewound").await.unwrap();
        let (removed, _) = context.open_atomic(partition, b"removed").await.unwrap();
        published.append(b"old").await.unwrap();
        rewound.append(b"abcdef").await.unwrap();
        removed.append(b"victim").await.unwrap();
        context
            .apply(vec![
                BatchOperation::Publish(published.clone()),
                BatchOperation::Publish(rewound.clone()),
                BatchOperation::Publish(removed.clone()),
            ])
            .await
            .unwrap();

        published
            .append_tagged(b"-new", [1; ATOMIC_BLOB_TAG_LEN])
            .await
            .unwrap();
        rewound.set_tag([2; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
        let removed_reader = removed.clone();
        let completion = context
            .start_apply(vec![
                BatchOperation::Remove(removed),
                BatchOperation::Rewind {
                    blob: rewound,
                    len: 3,
                },
                BatchOperation::Publish(published),
            ])
            .await
            .unwrap();
        completion.await.unwrap();

        assert_eq!(
            removed_reader.read_at(0, 6).await.unwrap().coalesce(),
            b"victim"
        );
        assert!(removed_reader.append(b"!").await.is_err());
        assert!(removed_reader.rewind(0).await.is_err());
        assert!(
            removed_reader
                .set_tag([3; ATOMIC_BLOB_TAG_LEN])
                .await
                .is_err()
        );
        let removed_slots = Blob::read_roots(&removed_reader.backing).await.unwrap();
        assert!(
            context
                .apply(vec![BatchOperation::Publish(removed_reader.clone())])
                .await
                .is_err()
        );
        assert!(
            context
                .apply(vec![BatchOperation::Rewind {
                    blob: removed_reader.clone(),
                    len: 6,
                }])
                .await
                .is_err()
        );
        assert!(
            context
                .apply(vec![BatchOperation::Remove(removed_reader.clone())])
                .await
                .is_err()
        );
        assert_eq!(
            Blob::read_roots(&removed_reader.backing).await.unwrap(),
            removed_slots
        );

        let (published, len) = context.open_atomic(partition, b"published").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(
            published.read_at(0, 7).await.unwrap().coalesce(),
            b"old-new"
        );
        assert_eq!(published.tag().await.unwrap(), [1; ATOMIC_BLOB_TAG_LEN]);

        let (rewound, len) = context.open_atomic(partition, b"rewound").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(rewound.read_at(0, 3).await.unwrap().coalesce(), b"abc");
        assert_eq!(rewound.tag().await.unwrap(), [2; ATOMIC_BLOB_TAG_LEN]);

        assert_eq!(
            context.scan(partition).await.unwrap(),
            vec![b"published".to_vec(), b"rewound".to_vec()],
        );
        let (replacement, len) = context.open_atomic(partition, b"removed").await.unwrap();
        assert_eq!(len, 0);
        replacement.append(b"replacement").await.unwrap();
        replacement.sync().await.unwrap();
    });
}

#[test]
fn every_batch_operation_combination_recovers_as_one_world() {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Kind {
        Publish,
        Rewind,
        Remove,
    }

    #[derive(Clone, Copy, Debug)]
    enum FaultCase {
        PartialWrite(PartialWriteMode),
        FailedSync(Option<WriteRetention>),
    }

    const PARTITION: &str = "batch_operation_matrix";
    const NAMES: [&[u8]; 3] = [b"a", b"b", b"c"];
    const OLD: [&[u8]; 3] = [b"abcdef", b"ghijkl", b"mnopqr"];
    const SUFFIX: &[u8] = b"-new";
    const FAULTS: [FaultCase; 4] = [
        FaultCase::PartialWrite(PartialWriteMode::Prefix),
        FaultCase::PartialWrite(PartialWriteMode::Subset),
        FaultCase::FailedSync(None),
        FaultCase::FailedSync(Some(FULL_RETENTION)),
    ];

    for combination in 0..3u64.pow(NAMES.len() as u32) {
        let mut encoded = combination;
        let kinds: [Kind; NAMES.len()] = std::array::from_fn(|_| {
            let kind = match encoded % 3 {
                0 => Kind::Publish,
                1 => Kind::Rewind,
                2 => Kind::Remove,
                _ => unreachable!(),
            };
            encoded /= 3;
            kind
        });

        for (fault_index, fault) in FAULTS.into_iter().enumerate() {
            let seed = combination * FAULTS.len() as u64 + fault_index as u64;
            let (_, checkpoint) =
                deterministic::Runner::seeded(seed).start_and_recover(|context| async move {
                    let mut blobs = Vec::with_capacity(NAMES.len());
                    for (index, name) in NAMES.into_iter().enumerate() {
                        let (blob, _) = context.open_atomic(PARTITION, name).await.unwrap();
                        blob.append_tagged(OLD[index], [index as u8 + 1; ATOMIC_BLOB_TAG_LEN])
                            .await
                            .unwrap();
                        blobs.push(blob);
                    }
                    context
                        .apply(blobs.into_iter().map(BatchOperation::Publish).collect())
                        .await
                        .unwrap();
                });

            let (_, checkpoint) =
                deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
                    let mut blobs = Vec::with_capacity(NAMES.len());
                    for name in NAMES {
                        blobs.push(context.open_atomic(PARTITION, name).await.unwrap().0);
                    }

                    // Keep every speculative payload byte eligible to survive so this matrix
                    // can exercise either candidate selection or predecessor rollback.
                    *context.storage_fault_config().write() =
                        write_retention_config(Some(FULL_RETENTION));
                    for (index, kind) in kinds.into_iter().enumerate() {
                        let tag = [0x80 + index as u8; ATOMIC_BLOB_TAG_LEN];
                        match kind {
                            Kind::Publish => {
                                blobs[index].append_tagged(SUFFIX, tag).await.unwrap();
                            }
                            Kind::Rewind => blobs[index].set_tag(tag).await.unwrap(),
                            Kind::Remove => {}
                        }
                    }

                    let mut operations = Vec::with_capacity(NAMES.len());
                    // A caller may place removals first. Physical unlink ordering is owned by
                    // finalization, not by the input order of the batch.
                    for ordered_kind in [Kind::Remove, Kind::Rewind, Kind::Publish] {
                        for (index, kind) in kinds.into_iter().enumerate() {
                            if kind != ordered_kind {
                                continue;
                            }
                            operations.push(match kind {
                                Kind::Publish => BatchOperation::Publish(blobs[index].clone()),
                                Kind::Rewind => BatchOperation::Rewind {
                                    blob: blobs[index].clone(),
                                    len: 3,
                                },
                                Kind::Remove => BatchOperation::Remove(blobs[index].clone()),
                            });
                        }
                    }

                    *context.storage_fault_config().write() = match fault {
                        FaultCase::PartialWrite(mode) => {
                            write_retention_config(Some(FULL_RETENTION))
                                .write(1.0)
                                .write_retention(mode, 0.5)
                        }
                        FaultCase::FailedSync(retention) => {
                            write_retention_config(retention).sync(1.0)
                        }
                    };
                    assert!(context.apply(operations).await.is_err());
                });

            deterministic::Runner::from(checkpoint).start(|context| async move {
                *context.storage_fault_config().write() = FaultConfig::default();
                let scanned = context.scan_atomic(PARTITION).await.unwrap();
                let mut actual = Vec::with_capacity(NAMES.len());
                for name in NAMES {
                    if scanned.iter().any(|value| value.as_slice() == name) {
                        let (blob, len) = context.open_atomic(PARTITION, name).await.unwrap();
                        let data = blob
                            .read_at(0, len as usize)
                            .await
                            .unwrap()
                            .coalesce()
                            .as_ref()
                            .to_vec();
                        actual.push(Some((data, blob.tag().await.unwrap())));
                    } else {
                        actual.push(None);
                    }
                }

                let mut matches_predecessor = true;
                let mut matches_candidate = true;
                for (index, kind) in kinds.into_iter().enumerate() {
                    matches_predecessor &= actual[index].as_ref().is_some_and(|(data, tag)| {
                        data == OLD[index] && *tag == [index as u8 + 1; ATOMIC_BLOB_TAG_LEN]
                    });
                    matches_candidate &= match kind {
                        Kind::Publish => {
                            let mut expected = OLD[index].to_vec();
                            expected.extend_from_slice(SUFFIX);
                            actual[index].as_ref().is_some_and(|(data, tag)| {
                                data == &expected
                                    && *tag == [0x80 + index as u8; ATOMIC_BLOB_TAG_LEN]
                            })
                        }
                        Kind::Rewind => actual[index].as_ref().is_some_and(|(data, tag)| {
                            data == &OLD[index][..3]
                                && *tag == [0x80 + index as u8; ATOMIC_BLOB_TAG_LEN]
                        }),
                        Kind::Remove => actual[index].is_none(),
                    };
                }

                assert!(
                    matches_predecessor || matches_candidate,
                    "mixed recovery for combination {combination} after {fault:?}: {actual:?}"
                );
                match fault {
                    FaultCase::FailedSync(None) => assert!(matches_predecessor),
                    FaultCase::FailedSync(Some(retention)) if retention == FULL_RETENTION => {
                        assert!(matches_candidate);
                    }
                    FaultCase::PartialWrite(_) | FaultCase::FailedSync(Some(_)) => {}
                }
            });
        }
    }
}

#[test]
fn batch_rewind_to_the_durable_length_discards_only_pending_appends() {
    deterministic::Runner::default().start(|context| async move {
        let (blob, _) = context
            .open_atomic("batch_pending_rewind", b"blob")
            .await
            .unwrap();
        blob.append(b"old").await.unwrap();
        blob.sync().await.unwrap();
        blob.append(b"-pending").await.unwrap();

        context
            .apply(vec![BatchOperation::Rewind {
                blob: blob.clone(),
                len: 3,
            }])
            .await
            .unwrap();
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"old");
        blob.append(b"!").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, len) = context
            .open_atomic("batch_pending_rewind", b"blob")
            .await
            .unwrap();
        assert_eq!(len, 4);
        assert_eq!(blob.read_at(0, 4).await.unwrap().coalesce(), b"old!");
    });
}

#[test]
fn batch_append_does_not_depend_on_resize() {
    deterministic::Runner::default().start(|context| async move {
        let (blob, _) = context
            .open_atomic("batch_append_no_resize", b"blob")
            .await
            .unwrap();
        blob.append(b"x").await.unwrap();

        *context.storage_fault_config().write() = FaultConfig::default().resize(1.0);
        context
            .apply(vec![BatchOperation::Publish(blob.clone())])
            .await
            .unwrap();

        assert_eq!(blob.read_at(0, 1).await.unwrap().coalesce(), b"x");
    });
}

#[test]
fn batch_tag_only_publication_preserves_payload_lengths() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "batch_tag_only";
        let (a, _) = context.open_atomic(partition, b"a").await.unwrap();
        let (b, _) = context.open_atomic(partition, b"b").await.unwrap();
        a.append(b"alpha").await.unwrap();
        b.append(b"bravo").await.unwrap();
        a.sync().await.unwrap();
        b.sync().await.unwrap();

        a.set_tag([1; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
        b.set_tag([2; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
        context
            .apply(vec![
                BatchOperation::Publish(a.clone()),
                BatchOperation::Publish(b.clone()),
            ])
            .await
            .unwrap();

        assert_eq!(a.tag().await.unwrap(), [1; ATOMIC_BLOB_TAG_LEN]);
        assert_eq!(b.tag().await.unwrap(), [2; ATOMIC_BLOB_TAG_LEN]);
        assert_eq!(a.read_at(0, 5).await.unwrap().coalesce(), b"alpha");
        assert_eq!(b.read_at(0, 5).await.unwrap().coalesce(), b"bravo");
    });
}

#[test]
fn identical_batch_operations_are_collapsed() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "identical_batch_operations";

        let (published, _) = context.open_atomic(partition, b"published").await.unwrap();
        published.append(b"value").await.unwrap();
        context
            .apply(vec![
                BatchOperation::Publish(published.clone()),
                BatchOperation::Publish(published.clone()),
            ])
            .await
            .unwrap();
        assert_eq!(published.read_at(0, 5).await.unwrap().coalesce(), b"value");

        let (rewound, _) = context.open_atomic(partition, b"rewound").await.unwrap();
        rewound.append(b"value").await.unwrap();
        rewound.sync().await.unwrap();
        assert!(
            context
                .apply(vec![
                    BatchOperation::Rewind {
                        blob: rewound.clone(),
                        len: 2,
                    },
                    BatchOperation::Rewind {
                        blob: rewound.clone(),
                        len: 3,
                    },
                ])
                .await
                .is_err()
        );
        context
            .apply(vec![
                BatchOperation::Rewind {
                    blob: rewound.clone(),
                    len: 3,
                },
                BatchOperation::Rewind {
                    blob: rewound.clone(),
                    len: 3,
                },
            ])
            .await
            .unwrap();
        assert_eq!(rewound.read_at(0, 3).await.unwrap().coalesce(), b"val");
        assert!(rewound.read_at(3, 1).await.is_err());

        let (removed, _) = context.open_atomic(partition, b"removed").await.unwrap();
        context
            .apply(vec![
                BatchOperation::Remove(removed.clone()),
                BatchOperation::Remove(removed.clone()),
            ])
            .await
            .unwrap();
    });
}

#[test]
fn batch_validation_is_read_only_and_rejects_stale_or_aliased_handles() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "batch_validation";
        context.apply(Vec::new()).await.unwrap();

        let (blob, _) = context.open_atomic(partition, b"blob").await.unwrap();
        context
            .apply(vec![
                BatchOperation::Publish(blob.clone()),
                BatchOperation::Publish(blob.clone()),
            ])
            .await
            .unwrap();
        blob.append(b"value").await.unwrap();
        assert!(
            context
                .apply(vec![
                    BatchOperation::Publish(blob.clone()),
                    BatchOperation::Remove(blob.clone()),
                ])
                .await
                .is_err()
        );
        assert_eq!(blob.read_at(0, 5).await.unwrap().coalesce(), b"value");
        assert!(
            context
                .apply(vec![BatchOperation::Rewind {
                    blob: blob.clone(),
                    len: 6,
                }])
                .await
                .is_err()
        );
        context
            .apply(vec![
                BatchOperation::Publish(blob.clone()),
                BatchOperation::Publish(blob.clone()),
            ])
            .await
            .unwrap();

        let (independent, _) = context.open_atomic(partition, b"blob").await.unwrap();
        assert!(
            context
                .apply(vec![
                    BatchOperation::Publish(blob.clone()),
                    BatchOperation::Publish(independent),
                ])
                .await
                .is_err()
        );

        let (missing, _) = context.open_atomic(partition, b"missing").await.unwrap();
        context.remove(partition, Some(b"missing")).await.unwrap();
        assert!(matches!(
            context.apply(vec![BatchOperation::Remove(missing)]).await,
            Err(Error::BlobMissing(_, _))
        ));

        let (replaced, _) = context.open_atomic(partition, b"replaced").await.unwrap();
        context.remove(partition, Some(b"replaced")).await.unwrap();
        let (replacement, _) = context.open_atomic(partition, b"replaced").await.unwrap();
        assert!(matches!(
            context.apply(vec![BatchOperation::Remove(replaced)]).await,
            Err(Error::BlobMissing(_, _))
        ));
        replacement.append(b"replacement").await.unwrap();
        replacement.sync().await.unwrap();

        let (stale, _) = context.open_atomic(partition, b"stale").await.unwrap();
        let (advancing, _) = context.open_atomic(partition, b"stale").await.unwrap();
        advancing.append(b"new").await.unwrap();
        advancing.sync().await.unwrap();
        stale.append(b"stale").await.unwrap();
        assert!(
            context
                .apply(vec![BatchOperation::Publish(stale)])
                .await
                .is_err()
        );

        let (left, _) = context.open_atomic(partition, b"left").await.unwrap();
        let (right, _) = context.open_atomic(partition, b"right").await.unwrap();
        right
            .backing
            .write_at(
                0,
                encode_identity(left.incarnation).to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
        let alias = Blob {
            backing: right.backing,
            partition: right.partition,
            name: right.name,
            incarnation: left.incarnation,
            state: right.state,
            payload: right.payload,
            preflush: right.preflush,
            carried: right.carried,
            driver: right.driver,
            exclusion: right.exclusion,
            operation: right.operation,
        };
        left.append(b"left").await.unwrap();
        alias.append(b"right").await.unwrap();
        assert!(
            context
                .apply(vec![
                    BatchOperation::Publish(left.clone()),
                    BatchOperation::Publish(alias.clone()),
                ])
                .await
                .is_err()
        );
        assert_eq!(left.read_at(0, 4).await.unwrap().coalesce(), b"left");
        assert_eq!(alias.read_at(0, 5).await.unwrap().coalesce(), b"right");
    });
}

#[test]
fn crash_subsets_across_payload_and_prepare_writes_recover_the_old_vector() {
    for randomize_prepare in [false, true] {
        for seed in 0..16 {
            let (_, checkpoint) =
                deterministic::Runner::seeded(seed).start_and_recover(|context| async move {
                    let mut blobs = Vec::new();
                    for name in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
                        let (blob, _) = context
                            .open_atomic("batch_subset_round", name)
                            .await
                            .unwrap();
                        blob.append(b"old").await.unwrap();
                        blobs.push(blob);
                    }
                    context
                        .apply(blobs.into_iter().map(BatchOperation::Publish).collect())
                        .await
                        .unwrap();
                });

            let (_, checkpoint) =
                deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
                    let mut blobs = Vec::new();
                    for name in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
                        let (blob, _) = context
                            .open_atomic("batch_subset_round", name)
                            .await
                            .unwrap();
                        *context.storage_fault_config().write() = FaultConfig::default()
                            .write_retention(SUBSET_RETENTION.0, SUBSET_RETENTION.1);
                        blob.append(b"-candidate").await.unwrap();
                        blobs.push(blob);
                    }
                    let prepare_retention = if randomize_prepare {
                        SUBSET_RETENTION
                    } else {
                        FULL_RETENTION
                    };
                    *context.storage_fault_config().write() = FaultConfig::default()
                        .write_retention(prepare_retention.0, prepare_retention.1)
                        .sync(1.0);
                    assert!(
                        context
                            .apply(blobs.iter().cloned().map(BatchOperation::Publish).collect())
                            .await
                            .is_err()
                    );
                    for blob in blobs {
                        assert!(blob.tag().await.is_err());
                    }
                });

            deterministic::Runner::from(checkpoint).start(|context| async move {
                *context.storage_fault_config().write() = FaultConfig::default();
                let mut retained = 0;
                let mut omitted = 0;
                let mut retained_prepare = false;
                let mut incomplete_prepare = false;
                for name in [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()] {
                    let (backing, backing_len) =
                        context.open("batch_subset_round", name).await.unwrap();
                    let mut candidate_complete = false;
                    let mut candidate_slot_nonzero = false;
                    for root_offset in ROOT_OFFSETS {
                        let slot = backing
                            .read_at(root_offset, ROOT_SLOT_SIZE)
                            .await
                            .unwrap()
                            .coalesce();
                        let link = batch::link(slot.as_ref(), "batch_subset_round", name).is_some();
                        if root_offset == ROOT_OFFSETS[0] {
                            candidate_complete = link;
                            candidate_slot_nonzero = slot.as_ref().iter().any(|byte| *byte != 0);
                        }
                    }
                    if randomize_prepare {
                        retained_prepare |= candidate_slot_nonzero;
                        incomplete_prepare |= !candidate_complete;
                    } else {
                        assert!(candidate_complete, "seed {seed} name {name:?}");
                    }

                    let candidate = b"-candidate";
                    let available = backing_len
                        .saturating_sub(DATA_OFFSET + 3)
                        .min(candidate.len() as u64) as usize;
                    let mut crash_bytes = vec![0; candidate.len()];
                    if available != 0 {
                        crash_bytes[..available].copy_from_slice(
                            backing
                                .read_at(DATA_OFFSET + 3, available)
                                .await
                                .unwrap()
                                .coalesce()
                                .as_ref(),
                        );
                    }
                    for (actual, expected) in crash_bytes.into_iter().zip(candidate) {
                        if actual == *expected {
                            retained += 1;
                        } else {
                            omitted += 1;
                        }
                    }
                }
                assert!(retained != 0, "seed {seed} retained no payload bytes");
                assert!(omitted != 0, "seed {seed} retained the complete payload");
                if randomize_prepare {
                    assert!(retained_prepare, "seed {seed} retained no prepare bytes");
                    assert!(incomplete_prepare, "seed {seed} retained every prepare");
                }

                let order: [&[u8]; 3] = if seed % 2 == 0 {
                    [b"a", b"c", b"b"]
                } else {
                    [b"c", b"a", b"b"]
                };
                for name in order {
                    let (blob, len) = context
                        .open_atomic("batch_subset_round", name)
                        .await
                        .unwrap();
                    assert_eq!(len, 3);
                    assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"old");
                }
            });
        }
    }
}

#[test]
fn batch_crash_boundaries_require_the_complete_ring_and_payload_vector() {
    const PARTITION: &str = "batch_subset_boundaries";
    const NAMES: [&[u8]; 3] = [b"a", b"b", b"c"];
    const OLD: &[u8] = b"old";
    const SUFFIX: &[u8] = b"-candidate";

    for payload_retention in [None, Some(FULL_RETENTION)] {
        for prepare_retention in [None, Some(FULL_RETENTION)] {
            let (_, checkpoint) =
                deterministic::Runner::default().start_and_recover(|context| async move {
                    let mut blobs = Vec::new();
                    for name in NAMES {
                        let (blob, _) = context.open_atomic(PARTITION, name).await.unwrap();
                        blob.append(OLD).await.unwrap();
                        blobs.push(blob);
                    }
                    context
                        .apply(blobs.into_iter().map(BatchOperation::Publish).collect())
                        .await
                        .unwrap();
                });

            let (_, checkpoint) =
                deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
                    let mut blobs = Vec::new();
                    for name in NAMES {
                        let (blob, _) = context.open_atomic(PARTITION, name).await.unwrap();
                        blobs.push(blob);
                    }
                    *context.storage_fault_config().write() =
                        write_retention_config(payload_retention);
                    for blob in &blobs {
                        blob.append(SUFFIX).await.unwrap();
                    }
                    *context.storage_fault_config().write() =
                        write_retention_config(prepare_retention).sync(1.0);
                    assert!(
                        context
                            .apply(blobs.into_iter().map(BatchOperation::Publish).collect())
                            .await
                            .is_err()
                    );
                });

            deterministic::Runner::from(checkpoint).start(|context| async move {
                *context.storage_fault_config().write() = FaultConfig::default();
                for name in NAMES {
                    let (backing, backing_len) = context.open(PARTITION, name).await.unwrap();
                    let slot = backing
                        .read_at(ROOT_OFFSETS[0], ROOT_SLOT_SIZE)
                        .await
                        .unwrap()
                        .coalesce();
                    assert_eq!(
                        batch::link(slot.as_ref(), PARTITION, name).is_some(),
                        prepare_retention == Some(FULL_RETENTION)
                    );

                    let available = backing_len
                        .saturating_sub(DATA_OFFSET + OLD.len() as u64)
                        .min(SUFFIX.len() as u64) as usize;
                    let mut retained = vec![0; SUFFIX.len()];
                    if available != 0 {
                        retained[..available].copy_from_slice(
                            backing
                                .read_at(DATA_OFFSET + OLD.len() as u64, available)
                                .await
                                .unwrap()
                                .coalesce()
                                .as_ref(),
                        );
                    }
                    assert_eq!(
                        retained.as_slice() == SUFFIX,
                        payload_retention == Some(FULL_RETENTION)
                    );
                }

                let publish = payload_retention == Some(FULL_RETENTION)
                    && prepare_retention == Some(FULL_RETENTION);
                let expected = if publish {
                    b"old-candidate".as_slice()
                } else {
                    OLD
                };
                for name in [b"c".as_slice(), b"a".as_slice(), b"b".as_slice()] {
                    let (blob, len) = context.open_atomic(PARTITION, name).await.unwrap();
                    assert_eq!(len, expected.len() as u64);
                    assert_eq!(
                        blob.read_at(0, expected.len()).await.unwrap().coalesce(),
                        expected
                    );
                }
            });
        }
    }
}

#[test]
fn direct_crash_subsets_publish_only_a_complete_singleton_ring_and_payload() {
    const PARTITION: &str = "direct_subset_round";
    const NAME: &[u8] = b"blob";
    const OLD: &[u8] = b"old";
    const SUFFIX: &[u8] = b"-candidate";

    let modes = [None, Some(FULL_RETENTION), Some(SUBSET_RETENTION)];
    let mut random_payload_retained = false;
    let mut random_payload_omitted = false;
    let mut random_prepare_retained = false;
    let mut random_prepare_incomplete = false;

    for payload_mode in modes {
        for prepare_mode in modes {
            for seed in 0..8 {
                let (_, checkpoint) =
                    deterministic::Runner::seeded(seed).start_and_recover(|context| async move {
                        let (blob, _) = context.open_atomic(PARTITION, NAME).await.unwrap();
                        blob.append(OLD).await.unwrap();
                        blob.sync().await.unwrap();
                    });

                let (_, checkpoint) = deterministic::Runner::from(checkpoint).start_and_recover(
                    |context| async move {
                        let (blob, _) = context.open_atomic(PARTITION, NAME).await.unwrap();
                        *context.storage_fault_config().write() =
                            write_retention_config(payload_mode);
                        blob.append(SUFFIX).await.unwrap();
                        *context.storage_fault_config().write() =
                            write_retention_config(prepare_mode).sync(1.0);
                        assert!(blob.sync().await.is_err());
                    },
                );

                let (payload_retained, payload_omitted, prepare_nonzero, prepare_complete) =
                    deterministic::Runner::from(checkpoint).start(|context| async move {
                        *context.storage_fault_config().write() = FaultConfig::default();
                        let (backing, backing_len) = context.open(PARTITION, NAME).await.unwrap();
                        let slot = backing
                            .read_at(ROOT_OFFSETS[0], ROOT_SLOT_SIZE)
                            .await
                            .unwrap()
                            .coalesce();
                        let prepare_nonzero = slot.as_ref().iter().any(|&byte| byte != 0);
                        let prepare_complete =
                            batch::link(slot.as_ref(), PARTITION, NAME).is_some();

                        let available = backing_len
                            .saturating_sub(DATA_OFFSET + OLD.len() as u64)
                            .min(SUFFIX.len() as u64)
                            as usize;
                        let mut retained = vec![0; SUFFIX.len()];
                        if available != 0 {
                            retained[..available].copy_from_slice(
                                backing
                                    .read_at(DATA_OFFSET + OLD.len() as u64, available)
                                    .await
                                    .unwrap()
                                    .coalesce()
                                    .as_ref(),
                            );
                        }
                        let payload_retained = retained
                            .iter()
                            .zip(SUFFIX)
                            .any(|(&actual, &expected)| actual == expected);
                        let payload_omitted = retained
                            .iter()
                            .zip(SUFFIX)
                            .any(|(&actual, &expected)| actual != expected);
                        let payload_complete = !payload_omitted;
                        drop(backing);

                        let (blob, len) = context.open_atomic(PARTITION, NAME).await.unwrap();
                        if prepare_complete && payload_complete {
                            assert_eq!(len, (OLD.len() + SUFFIX.len()) as u64);
                            assert_eq!(
                                blob.read_at(0, OLD.len() + SUFFIX.len())
                                    .await
                                    .unwrap()
                                    .coalesce(),
                                b"old-candidate"
                            );
                        } else {
                            assert_eq!(len, OLD.len() as u64);
                            assert_eq!(blob.read_at(0, OLD.len()).await.unwrap().coalesce(), OLD);
                        }
                        (
                            payload_retained,
                            payload_omitted,
                            prepare_nonzero,
                            prepare_complete,
                        )
                    });

                if payload_mode == Some(SUBSET_RETENTION) {
                    random_payload_retained |= payload_retained;
                    random_payload_omitted |= payload_omitted;
                }
                if prepare_mode == Some(SUBSET_RETENTION) {
                    random_prepare_retained |= prepare_nonzero;
                    random_prepare_incomplete |= !prepare_complete;
                }
            }
        }
    }

    assert!(random_payload_retained && random_payload_omitted);
    assert!(random_prepare_retained && random_prepare_incomplete);
}

#[test]
fn complete_prepared_ring_rejects_an_incomplete_payload_suffix() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "batch_incomplete_payload";
        stage_batch_with_payload(
            &context,
            partition,
            &[b"a", b"b", b"c"],
            &[false; 3],
            0b111,
            StagedPayload::Prefix(1),
        )
        .await;

        // The complete prepared slot may survive even when one byte of the earlier unsynced
        // append does not. The bound suffix descriptor must prevent that ring from deciding.
        for name in [b"b".as_slice(), b"a".as_slice(), b"c".as_slice()] {
            let (blob, len) = context.open_atomic(partition, name).await.unwrap();
            assert_eq!(len, 3);
            assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"old");
        }
    });
}

#[test]
fn direct_self_link_rejects_an_incomplete_payload_suffix() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "direct_incomplete_payload";
        stage_batch_with_payload(
            &context,
            partition,
            &[b"blob"],
            &[false],
            1,
            StagedPayload::Prefix(1),
        )
        .await;

        let (blob, len) = context.open_atomic(partition, b"blob").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"old");
    });
}

#[test]
fn later_publications_pay_carried_peer_materialization_debt() {
    let partition = "carried_materialization_debt";
    let (_, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let (a, _) = context.open_atomic(partition, b"a").await.unwrap();
            let (b, _) = context.open_atomic(partition, b"b").await.unwrap();
            a.append(b"a").await.unwrap();
            b.append(b"b").await.unwrap();
            context
                .apply(vec![
                    BatchOperation::Publish(a.clone()),
                    BatchOperation::Publish(b.clone()),
                ])
                .await
                .unwrap();

            a.append(b"-direct").await.unwrap();
            a.sync().await.unwrap();

            let (c, _) = context.open_atomic(partition, b"c").await.unwrap();
            let (d, _) = context.open_atomic(partition, b"d").await.unwrap();
            let (e, _) = context.open_atomic(partition, b"e").await.unwrap();
            c.append(b"c").await.unwrap();
            d.append(b"d").await.unwrap();
            context
                .apply(vec![
                    BatchOperation::Publish(c.clone()),
                    BatchOperation::Publish(d.clone()),
                ])
                .await
                .unwrap();

            c.append(b"-batch").await.unwrap();
            e.append(b"e").await.unwrap();
            context
                .apply(vec![BatchOperation::Publish(c), BatchOperation::Publish(e)])
                .await
                .unwrap();
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        for (name, expected) in [(b"b".as_slice(), b"b".as_slice()), (b"d", b"d")] {
            let (blob, len) = context.open_atomic(partition, name).await.unwrap();
            assert_eq!(len, expected.len() as u64);
            assert_eq!(
                blob.read_at(0, expected.len()).await.unwrap().coalesce(),
                expected
            );
        }
    });
}

#[test]
fn singleton_publications_do_not_register_carried_groups() {
    let (_, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let partition = "singleton_without_carried_group";
            let (blob, _) = context.open_atomic(partition, b"blob").await.unwrap();
            let budget = blob.payload.budget.clone();

            blob.append(b"direct").await.unwrap();
            blob.sync().await.unwrap();
            assert!(blob.carried.lock().await.is_none());
            assert!(budget.state.lock().carried_payments.is_empty());

            blob.append(b"-batch").await.unwrap();
            context
                .apply(vec![BatchOperation::Publish(blob.clone())])
                .await
                .unwrap();
            assert!(blob.carried.lock().await.is_none());
            assert!(budget.state.lock().carried_payments.is_empty());

            blob.append(b"-batch").await.unwrap();
            context
                .apply(vec![BatchOperation::Publish(blob.clone())])
                .await
                .unwrap();
            assert!(blob.carried.lock().await.is_none());
            assert!(budget.state.lock().carried_payments.is_empty());

            blob.append(b"-direct").await.unwrap();
            blob.sync().await.unwrap();
            assert!(blob.carried.lock().await.is_none());
            assert!(budget.state.lock().carried_payments.is_empty());
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let expected = b"direct-batch-batch-direct";
        let (reopened, len) = context
            .open_atomic("singleton_without_carried_group", b"blob")
            .await
            .unwrap();
        assert_eq!(len, expected.len() as u64);
        assert_eq!(
            reopened
                .read_at(0, expected.len())
                .await
                .unwrap()
                .coalesce(),
            expected
        );
    });
}

#[test]
fn advancing_a_surviving_member_skips_a_dropped_peer_backlink() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "carried_group_dropped_peer";
        let (a, _) = context.open_atomic(partition, b"a").await.unwrap();
        let (b, _) = context.open_atomic(partition, b"b").await.unwrap();
        let dropped_slot = Arc::downgrade(&b.carried);
        a.append(b"a").await.unwrap();
        b.append(b"b").await.unwrap();
        context
            .apply(vec![
                BatchOperation::Publish(a.clone()),
                BatchOperation::Publish(b.clone()),
            ])
            .await
            .unwrap();

        drop(b);
        assert!(dropped_slot.upgrade().is_none());
        a.append(b"-later").await.unwrap();
        a.sync().await.unwrap();

        assert_eq!(a.read_at(0, 7).await.unwrap().coalesce(), b"a-later");
        let (b, len) = context.open_atomic(partition, b"b").await.unwrap();
        assert_eq!(len, 1);
        assert_eq!(b.read_at(0, 1).await.unwrap().coalesce(), b"b");
    });
}

#[test]
fn recovery_retires_a_live_carried_group() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "recovery_retires_live_group";
        let (a, _) = context.open_atomic(partition, b"a").await.unwrap();
        let (b, _) = context.open_atomic(partition, b"b").await.unwrap();
        let (c, _) = context.open_atomic(partition, b"c").await.unwrap();
        a.append(b"a").await.unwrap();
        c.append(b"c").await.unwrap();
        context
            .apply(vec![
                BatchOperation::Publish(a.clone()),
                BatchOperation::Remove(b),
                BatchOperation::Publish(c.clone()),
            ])
            .await
            .unwrap();

        drop(a);
        let (a, len) = context.open_atomic(partition, b"a").await.unwrap();
        assert_eq!(len, 1);
        a.append(b"-new").await.unwrap();
        a.sync().await.unwrap();

        c.append(b"-new").await.unwrap();
        c.sync().await.unwrap();
        assert_eq!(c.read_at(0, 5).await.unwrap().coalesce(), b"c-new");

        drop(a);
        let (a, len) = context.open_atomic(partition, b"a").await.unwrap();
        assert_eq!(len, 5);
        assert_eq!(a.read_at(0, 5).await.unwrap().coalesce(), b"a-new");
    });
}

#[test]
fn partial_carried_debt_barrier_keeps_the_prior_group_authoritative() {
    fn run_case(removed: bool) {
        let mut exercised = false;
        for seed in 0..128 {
            let partition = format!("partial_carried_debt_{removed}_{seed}");
            let ((failed, prior_incarnation), checkpoint) = deterministic::Runner::seeded(seed)
                .start_and_recover(|context| {
                    let partition = partition.clone();
                    async move {
                        let (a, _) = context.open_atomic(&partition, b"a").await.unwrap();
                        let (b, _) = context.open_atomic(&partition, b"b").await.unwrap();
                        let prior_incarnation = b.incarnation;
                        a.append(b"a").await.unwrap();
                        b.append(b"b").await.unwrap();
                        context
                            .apply(vec![
                                BatchOperation::Publish(a.clone()),
                                if removed {
                                    BatchOperation::Remove(b)
                                } else {
                                    BatchOperation::Publish(b)
                                },
                            ])
                            .await
                            .unwrap();

                        a.append(b"-later").await.unwrap();
                        *context.storage_fault_config().write() = FaultConfig::default().sync(0.5);
                        (a.sync().await.is_err(), prior_incarnation)
                    }
                });
            if !failed {
                continue;
            }

            let (partial_barrier, _) =
                deterministic::Runner::from(checkpoint).start_and_recover(|context| {
                    let partition = partition.clone();
                    async move {
                        *context.storage_fault_config().write() = FaultConfig::default();
                        let (a_backing, _) = context.open(&partition, b"a").await.unwrap();
                        let (b_backing, _) = context.open(&partition, b"b").await.unwrap();
                        let a_slots = Blob::read_roots(&a_backing).await.unwrap();
                        let b_slots = Blob::read_roots(&b_backing).await.unwrap();
                        let a_prior = a_slots.iter().find_map(|slot| {
                            batch::link(slot, &partition, b"a").filter(|link| {
                                link.participant
                                    .candidate
                                    .root()
                                    .is_some_and(|root| root.generation == 1)
                            })
                        });
                        let a_later = a_slots.iter().any(|slot| {
                            batch::link(slot, &partition, b"a")
                                .and_then(|link| link.participant.candidate.root())
                                .is_some_and(|root| root.generation == 2)
                        });
                        let b_prior = b_slots.iter().find_map(|slot| {
                            batch::link(slot, &partition, b"b").filter(|link| {
                                link.participant
                                    .candidate
                                    .root()
                                    .is_some_and(|root| root.generation == 1)
                            })
                        });
                        let partial_barrier =
                            a_prior.as_ref().is_some_and(|link| {
                                exact_final(link, &a_slots)
                                    && b_prior.as_ref().is_some_and(|peer| {
                                        peer.group_id == link.group_id
                                            && !exact_final(peer, &b_slots)
                                            && root_index(
                                                peer.participant.candidate.root_offset().unwrap(),
                                            )
                                            .is_some_and(|index| {
                                                b_slots[index][..ROOT_LEN]
                                                    == peer.participant.candidate.prepared_root
                                            })
                                    })
                            }) && a_later;
                        drop(a_backing);
                        drop(b_backing);
                        if !partial_barrier {
                            return false;
                        }

                        let (recovered, len) = context.open_atomic(&partition, b"b").await.unwrap();
                        if removed {
                            assert_eq!(len, 0);
                            assert_ne!(recovered.incarnation, prior_incarnation);
                        } else {
                            assert_eq!(len, 1);
                            assert_eq!(recovered.read_at(0, 1).await.unwrap().coalesce(), b"b");
                        }
                        true
                    }
                });
            if partial_barrier {
                exercised = true;
                break;
            }
        }
        assert!(exercised, "no partial carried-debt barrier was generated");
    }

    run_case(false);
    run_case(true);
}

#[test]
fn removal_recovery_closes_carried_predecessor_before_unlink() {
    fn run_case(removal_first: bool) {
        let partition = format!("removal_closes_predecessor_{removal_first}");
        let (failed, checkpoint) = deterministic::Runner::seeded(1).start_and_recover({
            let partition = partition.clone();
            move |context| async move {
                let (a, _) = context.open_atomic(&partition, b"a").await.unwrap();
                let (b, _) = context.open_atomic(&partition, b"b").await.unwrap();
                a.append(b"a").await.unwrap();
                b.append(b"b").await.unwrap();
                context
                    .apply(vec![
                        BatchOperation::Publish(a.clone()),
                        BatchOperation::Publish(b),
                    ])
                    .await
                    .unwrap();

                *context.storage_fault_config().write() = FaultConfig::default().sync(0.5);
                context
                    .apply(vec![BatchOperation::Remove(a)])
                    .await
                    .is_err()
            }
        });
        assert!(failed, "the carried predecessor barrier did not fail");

        deterministic::Runner::from(checkpoint).start({
            move |context| async move {
                *context.storage_fault_config().write() = FaultConfig::default();
                let (a_backing, _) = context.open(&partition, b"a").await.unwrap();
                let (b_backing, _) = context.open(&partition, b"b").await.unwrap();
                let a_slots = Blob::read_roots(&a_backing).await.unwrap();
                let b_slots = Blob::read_roots(&b_backing).await.unwrap();
                let a_prior = a_slots
                    .iter()
                    .find_map(|slot| {
                        batch::link(slot, &partition, b"a").filter(|link| {
                            link.participant
                                .candidate
                                .root()
                                .is_some_and(|root| root.generation == 1)
                        })
                    })
                    .expect("A retained its predecessor witness");
                let a_removal = a_slots
                    .iter()
                    .find_map(|slot| {
                        batch::link(slot, &partition, b"a").filter(|link| {
                            link.participant.removed
                                && link
                                    .participant
                                    .candidate
                                    .root()
                                    .is_some_and(|root| root.generation == 2)
                        })
                    })
                    .expect("A retained its later removal witness");
                let b_prior = b_slots
                    .iter()
                    .find_map(|slot| {
                        batch::link(slot, &partition, b"b").filter(|link| {
                            link.participant
                                .candidate
                                .root()
                                .is_some_and(|root| root.generation == 1)
                        })
                    })
                    .expect("B retained its predecessor witness");
                assert!(exact_final(&a_prior, &a_slots));
                assert!(!exact_final(&a_removal, &a_slots));
                assert!(!exact_final(&b_prior, &b_slots));
                let b_index =
                    root_index(b_prior.participant.candidate.root_offset().unwrap()).unwrap();
                assert_eq!(
                    b_slots[b_index][..ROOT_LEN],
                    b_prior.participant.candidate.prepared_root
                );
                drop(a_backing);
                drop(b_backing);

                let b = if removal_first {
                    drop(context.open_atomic(&partition, b"a").await.unwrap());
                    context.open_atomic(&partition, b"b").await.unwrap().0
                } else {
                    let b = context.open_atomic(&partition, b"b").await.unwrap().0;
                    drop(context.open_atomic(&partition, b"a").await.unwrap());
                    b
                };
                assert_eq!(b.read_at(0, 1).await.unwrap().coalesce(), b"b");
            }
        });
    }

    run_case(true);
    run_case(false);
}

#[test]
fn peer_only_incomplete_successor_does_not_hide_a_committed_ring() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "peer_only_incomplete_successor";
        let prior = stage_batch(
            &context,
            partition,
            &[b"a".as_slice(), b"b"],
            &[false, false],
            0b11,
        )
        .await;
        let a = prior
            .participants
            .iter()
            .find(|participant| participant.name == b"a")
            .unwrap();
        let prior_root = a.candidate.root().unwrap();
        let lost = b"lost";
        stage_singleton_successor(
            &context,
            a,
            Root::unbound(
                prior_root.generation + 1,
                prior_root.logical_len + lost.len() as u64,
                [0x31; ATOMIC_BLOB_TAG_LEN],
            ),
            batch::PayloadDescriptor {
                start: prior_root.logical_len,
                checksum: payload_checksum(IoBufs::from(lost.to_vec())),
            },
            false,
            0x31,
        )
        .await;

        let (b, len) = context.open_atomic(partition, b"b").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(
            b.read_at(0, len as usize).await.unwrap().coalesce(),
            b"old-new"
        );
        drop(b);

        let (a, len) = context.open_atomic(partition, b"a").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(
            a.read_at(0, len as usize).await.unwrap().coalesce(),
            b"old-new"
        );
    });
}

#[test]
fn accepted_successor_closes_a_prepared_predecessor() {
    fn run_case(removed: bool) {
        deterministic::Runner::default().start(move |context| async move {
            let partition = if removed {
                "remove_closes_prepared_predecessor"
            } else {
                "publish_closes_prepared_predecessor"
            };
            let prior = stage_batch(
                &context,
                partition,
                &[b"a".as_slice(), b"b"],
                &[false, false],
                0b11,
            )
            .await;
            let a = prior
                .participants
                .iter()
                .find(|participant| participant.name == b"a")
                .unwrap();
            let prior_root = a.candidate.root().unwrap();
            stage_singleton_successor(
                &context,
                a,
                Root::unbound(
                    prior_root.generation + 1,
                    prior_root.logical_len,
                    [0x32; ATOMIC_BLOB_TAG_LEN],
                ),
                batch::PayloadDescriptor::empty(prior_root.logical_len),
                removed,
                0x32,
            )
            .await;

            let (a, len) = context.open_atomic(partition, b"a").await.unwrap();
            if removed {
                assert_eq!(len, 0);
            } else {
                assert_eq!(len, 7);
                assert_eq!(a.tag().await.unwrap(), [0x32; ATOMIC_BLOB_TAG_LEN]);
            }
            drop(a);

            let (b, len) = context.open_atomic(partition, b"b").await.unwrap();
            assert_eq!(len, 7);
            assert_eq!(
                b.read_at(0, len as usize).await.unwrap().coalesce(),
                b"old-new"
            );
        });
    }

    run_case(false);
    run_case(true);
}

#[test]
fn overlapping_predecessor_recovery_preserves_the_newer_final() {
    let partition = "overlapping_predecessor_recovery";
    let (_, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let (a, _) = context.open_atomic(partition, b"a").await.unwrap();
            let (b, _) = context.open_atomic(partition, b"b").await.unwrap();
            a.append_tagged(b"a", [0x11; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            b.append_tagged(b"old", [0x11; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            context
                .apply(vec![
                    BatchOperation::Publish(a.clone()),
                    BatchOperation::Publish(b.clone()),
                ])
                .await
                .unwrap();

            let (c, _) = context.open_atomic(partition, b"c").await.unwrap();
            b.append_tagged(b"-new", [0x22; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            c.append_tagged(b"c", [0x22; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            context
                .apply(vec![
                    BatchOperation::Publish(b),
                    BatchOperation::Publish(c.clone()),
                ])
                .await
                .unwrap();

            a.set_tag([0x33; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
            *context.storage_fault_config().write() = FaultConfig::default()
                .write_retention(FULL_RETENTION.0, FULL_RETENTION.1)
                .sync(1.0);
            assert!(
                context
                    .apply(vec![BatchOperation::Remove(c), BatchOperation::Publish(a),])
                    .await
                    .is_err()
            );
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        *context.storage_fault_config().write() = FaultConfig::default();
        let (c, len) = context.open_atomic(partition, b"c").await.unwrap();
        assert_eq!(len, 0);
        drop(c);

        let (b, len) = context.open_atomic(partition, b"b").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(
            b.read_at(0, len as usize).await.unwrap().coalesce(),
            b"old-new"
        );
        assert_eq!(b.tag().await.unwrap(), [0x22; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[test]
fn stale_final_checksum_byte_does_not_bypass_payload_validation() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "batch_stale_final_byte";
        let mut blobs = Vec::new();
        let mut participants = Vec::new();
        for (ordinal, name) in [b"a".as_slice(), b"b", b"c"].into_iter().enumerate() {
            let (blob, _) = context.open_atomic(partition, name).await.unwrap();
            participants.push(batch::Participant {
                partition: partition.to_string(),
                name: name.to_vec(),
                incarnation: blob.incarnation,
                candidate: batch::Candidate::with_payload(
                    Root::unbound(3, 7, [0x30 + ordinal as u8; ATOMIC_BLOB_TAG_LEN]),
                    batch::PayloadDescriptor {
                        start: 3,
                        checksum: payload_checksum(IoBufs::from(b"-new".to_vec())),
                    },
                )
                .unwrap(),
                removed: false,
            });
            blobs.push(blob);
        }
        let prepared = batch::prepare(participants).unwrap();

        let a = &prepared.participants[0];
        let final_root = a.candidate.final_root().unwrap();
        let (old_tag, stale_index) = (0u32..)
            .find_map(|counter| {
                let mut tag = [0u8; ATOMIC_BLOB_TAG_LEN];
                tag[..4].copy_from_slice(&counter.to_be_bytes());
                let old = encode_root(RootState::Committed, 1, 3, tag);
                (ROOT_BODY_LEN..ROOT_LEN)
                    .find(|&index| {
                        old[index] == final_root[index]
                            && a.candidate.prepared_root[index] != final_root[index]
                    })
                    .map(|index| (tag, index))
            })
            .expect("some old checksum byte matches a final-root checksum byte");

        for (ordinal, blob) in blobs.iter().enumerate() {
            let old_tag = if ordinal == 0 {
                old_tag
            } else {
                [0x10 + ordinal as u8; ATOMIC_BLOB_TAG_LEN]
            };
            blob.append_tagged(b"old", old_tag).await.unwrap();
            blob.sync().await.unwrap();
            blob.set_tag([0x20 + ordinal as u8; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            blob.sync().await.unwrap();
            blob.append_tagged(b"-new", [0x30 + ordinal as u8; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            // The hand-built generation-three candidate assumes its generation-two
            // predecessor is independently durable. A normal next publication folds this
            // materialization debt into its one barrier; establish the same precondition here.
            blob.backing.sync().await.unwrap();

            let participant = &prepared.participants[ordinal];
            let mut slot = prepared.slots[ordinal];
            if ordinal == 0 {
                // Before this group's final write is issued, the same-parity generation-one
                // root may leave a checksum byte that happens to equal the final target. That
                // coincidence is not proof that preparation (including payload) was durable.
                slot[stale_index] = final_root[stale_index];
                let link = batch::link_at(
                    &slot,
                    partition,
                    &participant.name,
                    participant.candidate.root_offset().unwrap(),
                )
                .unwrap();
                let installed = slot[..ROOT_LEN].try_into().unwrap();
                assert_eq!(
                    link.participant.candidate.status(installed),
                    Some(batch::CandidateStatus::Transition)
                );
            }
            blob.backing
                .write_at(
                    participant.candidate.root_offset().unwrap(),
                    slot.to_vec(),
                    WriteOptions::SYNC,
                )
                .await
                .unwrap();
            let installed = Blob::read_roots(&blob.backing).await.unwrap();
            let slot_index = root_index(participant.candidate.root_offset().unwrap()).unwrap();
            assert_eq!(installed[slot_index], slot);
            assert!(batch::link(&installed[slot_index], partition, &participant.name).is_some());
        }
        blobs[0]
            .backing
            .write_at(DATA_OFFSET + 3, vec![0], WriteOptions::SYNC)
            .await
            .unwrap();
        drop(blobs);

        let existing = open_existing(&context, partition, b"b")
            .await
            .unwrap()
            .unwrap();
        let b_index =
            root_index(prepared.participants[1].candidate.root_offset().unwrap()).unwrap();
        assert_eq!(existing.slots[b_index], prepared.slots[1]);
        let link = existing
            .slots
            .iter()
            .filter_map(|slot| batch::link(slot, partition, b"b"))
            .find(|link| {
                link.participant
                    .candidate
                    .root()
                    .is_some_and(|root| root.generation == 3)
            })
            .unwrap();
        let members = traverse_group(
            &context,
            GroupMember {
                link,
                backing: existing.backing,
                backing_len: existing.backing_len,
                slots: existing.slots,
            },
            false,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(members.len(), 3);
        let a = members
            .iter()
            .find(|member| member.link.participant.name == b"a")
            .unwrap();
        assert_eq!(
            candidate_status(&a.link, a.backing_len, &a.slots, false).unwrap(),
            Some(batch::CandidateStatus::Transition)
        );
        assert!(!candidate_payload_valid(a).await.unwrap());

        for name in [b"b".as_slice(), b"a", b"c"] {
            let (blob, len) = context.open_atomic(partition, name).await.unwrap();
            assert_eq!(len, 3);
            assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"old");
        }
    });
}

#[test]
fn same_parity_torn_prepare_cannot_synthesize_final_authority() {
    deterministic::Runner::default().start(|_| async move {
        let partition = "p";
        let name = b"n";
        let incarnation = [0x11; INCARNATION_LEN];
        let mut predecessor_tag = [0; ATOMIC_BLOB_TAG_LEN];
        predecessor_tag[..4].copy_from_slice(&0x0000_9496u32.to_be_bytes());
        let mut candidate_tag = [0xA7; ATOMIC_BLOB_TAG_LEN];
        candidate_tag[..4].copy_from_slice(&0x0001_D7E5u32.to_be_bytes());

        let storage = memory::Storage::new(test_pool());
        let (backing, backing_len) = storage.open(partition, name).await.unwrap();
        assert_eq!(backing_len, 0);
        assert_eq!(
            Blob::<_>::initialize_identity(&backing, backing_len, || incarnation)
                .await
                .unwrap(),
            incarnation
        );
        let (blob, len) = Blob::open_named(
            backing,
            partition,
            name,
            DATA_OFFSET,
            incarnation,
            test_token_epoch(),
            storage.atomic_resources(),
        )
        .await
        .unwrap();
        assert_eq!(len, 0);
        blob.set_tag([1; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
        blob.sync().await.unwrap();
        blob.set_tag(predecessor_tag).await.unwrap();
        blob.sync().await.unwrap();
        blob.set_tag([3; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
        blob.sync().await.unwrap();
        // The unsynchronized generation-three final may survive completely before the next
        // publication, without making any later payload or prepared-root byte durable.
        blob.backing.sync().await.unwrap();

        let predecessor_slots = Blob::read_roots(&blob.backing).await.unwrap();
        let candidate = batch::prepare_with_group_id(
            vec![batch::Participant {
                partition: partition.to_string(),
                name: name.to_vec(),
                incarnation,
                candidate: batch::Candidate::with_payload(
                    Root {
                        generation: 4,
                        logical_len: 2,
                        integrity_start: 0,
                        integrity_checksum: Crc32::checksum(b"XY"),
                        integrity_scheme: IntegrityScheme::Unbound,
                        tag: candidate_tag,
                    },
                    batch::PayloadDescriptor {
                        start: 0,
                        checksum: payload_checksum(IoBufs::from(b"XY".to_vec())),
                    },
                )
                .unwrap(),
                removed: false,
            }],
            direct_group_id(partition, name, &incarnation, 4),
        )
        .unwrap();
        let participant = &candidate.participants[0];
        let candidate_index = root_index(participant.candidate.root_offset().unwrap()).unwrap();
        let predecessor = predecessor_slots[candidate_index];
        let prepared = candidate.slots[0];
        let mut finalized = prepared;
        finalized[..ROOT_LEN].copy_from_slice(&participant.candidate.final_root().unwrap());

        // Build the closest final image available from the durable same-slot predecessor and
        // issued prepared write. The final must remain unavailable until it is actually
        // issued.
        let mut retained = predecessor;
        for (index, (&prepared, &finalized)) in prepared.iter().zip(&finalized).enumerate() {
            if prepared == finalized {
                retained[index] = prepared;
            }
        }
        assert_ne!(retained, finalized);

        // Model a crash that retained only the final payload byte and the slot mosaic.
        blob.backing
            .write_at(DATA_OFFSET, vec![0, b'Y'], WriteOptions::SYNC)
            .await
            .unwrap();
        blob.backing
            .write_at(
                participant.candidate.root_offset().unwrap(),
                retained.to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
        drop(blob);

        let (reopened, len) = storage.open_atomic(partition, name).await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(reopened.tag().await.unwrap(), [3; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[test]
fn batch_preflushes_payload_during_append_to_preserve_the_group_wide_bound() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "batch_payload_bound";
        let suffix_len = MAX_UNSYNCED_PAYLOAD_LEN / 2 + 1;
        let mut blobs = Vec::new();
        for name in [b"a".as_slice(), b"b"] {
            let (blob, _) = context.open_atomic(partition, name).await.unwrap();
            blob.append(vec![name[0]; suffix_len as usize])
                .await
                .unwrap();
            blobs.push(blob);
        }

        assert_eq!(blobs[0].state.lock().await.durable_len, 0);
        assert_eq!(blobs[1].state.lock().await.durable_len, suffix_len);

        context
            .apply(blobs.iter().cloned().map(BatchOperation::Publish).collect())
            .await
            .unwrap();

        let mut total = 0u64;
        for blob in blobs {
            let slots = Blob::read_roots(&blob.backing).await.unwrap();
            let link = slots
                .iter()
                .find_map(|slot| batch::link(slot, partition, &blob.name))
                .unwrap();
            total = total
                .checked_add(link.participant.candidate.payload_len().unwrap())
                .unwrap();
        }
        assert!(total <= MAX_UNSYNCED_PAYLOAD_LEN);
    });
}

#[test]
fn large_append_preflushes_its_invisible_payload() {
    deterministic::Runner::default().start(|context| async move {
        let (blob, _) = context
            .open_atomic("large_append_preflush", b"blob")
            .await
            .unwrap();
        let len = MAX_UNSYNCED_PAYLOAD_LEN + 1;
        blob.append(vec![7; len as usize]).await.unwrap();

        let state = blob.state.lock().await;
        assert_eq!(state.logical_len, len);
        assert_eq!(state.durable_len, len);
        assert_eq!(state.committed.logical_len, 0);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn payload_preflush_runs_behind_append_and_publication_drains_it() {
    futures::executor::block_on(async move {
        let (blob, pending, _) =
            delayed_preflush_blob("background_preflush", Driver::background()).await;

        let (len, release) = begin_blocked_large_preflush(&blob, &pending).await;
        blob.append(b"x").await.unwrap();
        assert_eq!(blob.state.lock().await.durable_len, 0);

        let _ = release.send(Ok(()));
        blob.drain_payload_preflush().await.unwrap();
        assert_eq!(blob.state.lock().await.durable_len, len + 1);
        blob.sync().await.unwrap();
        let state = blob.state.lock().await;
        assert_eq!(state.logical_len, len + 1);
        assert_eq!(state.durable_len, len + 1);
        assert_eq!(state.committed.logical_len, len + 1);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn rewind_waits_for_payload_preflush_before_reusing_the_tail() {
    futures::executor::block_on(async move {
        let (blob, pending, budget) =
            delayed_preflush_blob("preflush_rewind", Driver::background()).await;
        let (_, release) = begin_blocked_large_preflush(&blob, &pending).await;

        let mut rewind = Box::pin(blob.rewind(0));
        assert!(
            rewind.as_mut().now_or_never().is_none(),
            "rewind must not reclaim bytes while their payload preflush is running"
        );
        let _ = release.send(Ok(()));
        rewind.await.unwrap();

        let state = blob.state.lock().await;
        assert_eq!(state.logical_len, 0);
        assert_eq!(state.durable_len, 0);
        assert_eq!(budget.total(), 0);
    });
}

#[test]
fn payload_preflush_failure_poisons_the_blob_and_releases_its_budget() {
    futures::executor::block_on(async move {
        let (blob, pending, budget) =
            delayed_preflush_blob("preflush_failure", Driver::inline()).await;
        pending.arm();
        pending.arm_fail();
        pending.unblock();

        let len = MAX_UNSYNCED_PAYLOAD_LEN + 1;
        assert!(blob.append(vec![7; len as usize]).await.is_err());
        assert!(blob.state.lock().await.poisoned);
        assert_eq!(budget.total(), 0);
        assert!(blob.sync().await.is_err());
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn canceling_inline_preflush_poisons_without_stranding_a_round() {
    futures::executor::block_on(async move {
        let (blob, pending, budget) =
            delayed_preflush_blob("cancel_inline_preflush", Driver::inline()).await;
        let clone = blob.clone();

        pending.arm();
        let deferred = next_pending_sync(&pending);
        let len = MAX_UNSYNCED_PAYLOAD_LEN + 1;
        let mut append = Box::pin(blob.append(vec![7; len as usize]));
        assert!(append.as_mut().now_or_never().is_none());
        deferred.blocked.await.unwrap();
        drop(append);

        assert!(clone.state.lock().await.poisoned);
        assert!(clone.preflush.state.lock().current.is_none());
        assert!(budget.state.lock().rounds.is_empty());
        budget.drain().await.unwrap();
        assert!(clone.sync().await.is_err());
        assert!(deferred.release.send(Ok(())).is_err());
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn publication_reports_the_exact_detached_payload_preflush_failure() {
    futures::executor::block_on(async move {
        let (mut blob, pending, budget) =
            delayed_preflush_blob("detached_preflush_failure", Driver::background()).await;
        blob.append(b"x").await.unwrap();

        pending.arm();
        let deferred = next_pending_sync(&pending);
        let release = deferred.release;
        blob.request_payload_preflush(1).await.unwrap();
        deferred.blocked.await.unwrap();
        blob.driver = Driver::inline();

        let mut publication = Box::pin(blob.sync());
        assert!(
            publication.as_mut().now_or_never().is_none(),
            "publication must wait on the live detached preflush round"
        );
        let _ = release.send(Err(Error::Io(
            std::io::Error::other("detached preflush failed").into(),
        )));

        match publication.await.unwrap_err() {
            Error::Io(error) => assert_eq!(error.to_string(), "detached preflush failed"),
            error => panic!("expected the detached I/O failure, got {error}"),
        }
        assert!(blob.state.lock().await.poisoned);
        assert_eq!(budget.total(), 0);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn failed_detached_preflush_survives_last_handle_drop() {
    futures::executor::block_on(async move {
        let (blob, pending, budget) =
            delayed_preflush_blob("dropped_preflush_failure", Driver::background()).await;
        blob.append(b"x").await.unwrap();

        pending.arm();
        let deferred = next_pending_sync(&pending);
        blob.request_payload_preflush(1).await.unwrap();
        deferred.blocked.await.unwrap();

        let mut drain = Box::pin(budget.drain());
        assert!(drain.as_mut().now_or_never().is_none());
        drop(blob);
        deferred.release.send(Err(Error::Closed)).unwrap();

        assert!(matches!(drain.await.unwrap_err(), Error::Closed));
        assert!(matches!(budget.drain().await.unwrap_err(), Error::Closed));
        assert_eq!(budget.state.lock().rounds.len(), 1);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn disjoint_publication_does_not_wait_for_another_blobs_preflush() {
    futures::executor::block_on(async move {
        let (mut blobs, pending) = disjoint_delayed_blobs().await;
        blobs[0].driver = Driver::background();

        pending[0].arm();
        let first_preflush = next_pending_sync(&pending[0]);
        blobs[0].request_payload_preflush(1).await.unwrap();
        first_preflush
            .blocked
            .await
            .expect("first blob's payload preflush never reached its backing barrier");

        pending[1].arm();
        let second_sync = next_pending_sync(&pending[1]);
        let mut second_blocked = Box::pin(second_sync.blocked);
        let mut second = Box::pin(blobs[1].sync());
        assert!(second.as_mut().now_or_never().is_none());
        assert!(
            second_blocked.as_mut().now_or_never().is_some(),
            "a disjoint publication waited for another blob's payload preflush"
        );

        first_preflush.release.send(Ok(())).unwrap();
        second_sync.release.send(Ok(())).unwrap();
        blobs[0].drain_payload_preflush().await.unwrap();
        second.await.unwrap();
    });
}

#[test]
fn payload_budget_drain_fails_closed_when_a_round_loses_its_driver() {
    futures::executor::block_on(async move {
        let budget = PayloadBudget::default();
        let (signaler, completion) = Signaler::new();
        budget.register(completion);
        drop(signaler);

        assert!(matches!(budget.drain().await.unwrap_err(), Error::Closed));
        assert!(matches!(budget.drain().await.unwrap_err(), Error::Closed));
        assert_eq!(budget.state.lock().rounds.len(), 1);
    });
}

#[test]
fn payload_accounts_replace_and_release_their_aggregate_contribution() {
    let budget = Arc::new(PayloadBudget::default());
    let first = PayloadAccount::new(budget.clone());
    let second = PayloadAccount::new(budget.clone());

    assert_eq!(first.set(7), 7);
    assert_eq!(second.set(11), 18);
    assert_eq!(first.set(3), 14);
    drop(second);
    assert_eq!(budget.total(), 3);
    drop(first);
    assert_eq!(budget.total(), 0);
}

#[test]
fn recovered_ring_rejects_an_over_budget_payload_vector() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "recovered_payload_bound";
        let suffix_len = MAX_UNSYNCED_PAYLOAD_LEN / 2 + 1;
        let mut participants = Vec::new();
        let mut backings = Vec::new();
        for (ordinal, name) in [b"a".as_slice(), b"b"].into_iter().enumerate() {
            let (blob, _) = context.open_atomic(partition, name).await.unwrap();
            participants.push(batch::Participant {
                partition: partition.to_string(),
                name: name.to_vec(),
                incarnation: blob.incarnation,
                candidate: batch::Candidate::with_payload(
                    Root::unbound(1, suffix_len, [ordinal as u8; ATOMIC_BLOB_TAG_LEN]),
                    batch::PayloadDescriptor {
                        start: 0,
                        checksum: [ordinal as u8; 32],
                    },
                )
                .unwrap(),
                removed: false,
            });
            backings.push(blob.backing.clone());
        }
        let prepared = batch::prepare(participants).unwrap();
        for (backing, slot) in backings.iter().zip(&prepared.slots) {
            backing
                .write_at(ROOT_OFFSETS[1], slot.to_vec(), WriteOptions::SYNC)
                .await
                .unwrap();
        }
        drop(backings);

        for name in [b"a".as_slice(), b"b"] {
            let (blob, len) = context.open_atomic(partition, name).await.unwrap();
            assert_eq!(len, 0);
            assert_eq!(blob.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);
        }
    });
}

#[test]
fn every_batch_finalization_subset_recovers_the_candidate_vector() {
    deterministic::Runner::default().start(|context| async move {
        for removed in [false, true] {
            let probe =
                batch::Candidate::new(Root::unbound(2, 7, [0x20; ATOMIC_BLOB_TAG_LEN])).unwrap();
            let final_root = probe.final_root().unwrap();
            let changed = probe
                .prepared_root
                .iter()
                .zip(final_root)
                .enumerate()
                .filter_map(|(index, (prepared, final_byte))| {
                    (*prepared != final_byte).then_some(index)
                })
                .collect::<Vec<_>>();
            assert!(changed.len() < usize::BITS as usize);

            for mask in 0..(1usize << changed.len()) {
                let partition = format!("batch_final_subset_{removed}_{mask}");
                let prepared =
                    stage_batch(&context, &partition, &[b"a", b"b"], &[removed, false], 0b11).await;
                let participant = &prepared.participants[0];
                let final_root = participant.candidate.final_root().unwrap();
                let (backing, _) = context
                    .open(&participant.partition, &participant.name)
                    .await
                    .unwrap();
                for (bit, index) in changed.iter().copied().enumerate() {
                    if mask & (1 << bit) != 0 {
                        backing
                            .write_at(
                                participant.candidate.root_offset().unwrap() + index as u64,
                                vec![final_root[index]],
                                WriteOptions::SYNC,
                            )
                            .await
                            .unwrap();
                    }
                }
                drop(backing);

                let (b, len) = context.open_atomic(&partition, b"b").await.unwrap();
                assert_eq!(len, 7);
                assert_eq!(b.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
                let names = context.scan(&partition).await.unwrap();
                assert_eq!(names.contains(&b"a".to_vec()), !removed);
            }
        }
    });
}

#[test]
fn recovery_resyncs_readable_exact_finals_before_unlink() {
    let (_, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let partition = "recovery_resyncs_exact_final";
            let prepared =
                stage_batch(&context, partition, &[b"a", b"b"], &[false, true], 0b11).await;
            let retained = &prepared.participants[0];
            let (backing, backing_len) = context.open(partition, b"a").await.unwrap();
            backing
                .write_at(
                    retained.candidate.root_offset().unwrap(),
                    retained.candidate.final_root().unwrap().to_vec(),
                    WriteOptions::default(),
                )
                .await
                .unwrap();
            let local = Existing {
                backing: backing.clone(),
                backing_len,
                incarnation: retained.incarnation,
                slots: Blob::read_roots(&backing).await.unwrap(),
            };

            assert_eq!(
                Box::pin(recover_groups(&context, partition, b"a", &local, None))
                    .await
                    .unwrap(),
                GroupRecovery::Present
            );
            assert_eq!(context.scan(partition).await.unwrap(), vec![b"a".to_vec()]);
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        let (retained, len) = context
            .open_atomic("recovery_resyncs_exact_final", b"a")
            .await
            .unwrap();
        assert_eq!(len, 7);
        assert_eq!(retained.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
        assert_eq!(
            context.scan("recovery_resyncs_exact_final").await.unwrap(),
            vec![b"a".to_vec()]
        );
    });
}

#[test]
fn failed_one_barrier_materialization_preserves_the_complete_group() {
    let cases = [
        (
            "prefix",
            FaultConfig::default()
                .write(1.0)
                .write_retention(PartialWriteMode::Prefix, 0.5),
        ),
        (
            "subset",
            FaultConfig::default()
                .write(1.0)
                .write_retention(PartialWriteMode::Subset, 0.5),
        ),
        (
            "random_sync",
            FaultConfig::default()
                .write_retention(SUBSET_RETENTION.0, SUBSET_RETENTION.1)
                .sync(1.0),
        ),
    ];

    for (case, faults) in cases {
        let partition = format!("failed_one_barrier_materialization_{case}");
        let (_, checkpoint) = deterministic::Runner::seeded(17).start_and_recover(|context| {
            let partition = partition.clone();
            async move {
                let prepared =
                    stage_batch(&context, &partition, &[b"a", b"b"], &[false, true], 0b11).await;
                let retained = &prepared.participants[0];
                let (backing, backing_len) = context.open(&partition, b"a").await.unwrap();
                backing
                    .write_at(
                        retained.candidate.root_offset().unwrap(),
                        retained.candidate.final_root().unwrap().to_vec(),
                        WriteOptions::default(),
                    )
                    .await
                    .unwrap();
                let local = Existing {
                    backing: backing.clone(),
                    backing_len,
                    incarnation: retained.incarnation,
                    slots: Blob::read_roots(&backing).await.unwrap(),
                };

                *context.storage_fault_config().write() = faults;
                assert!(
                    Box::pin(recover_groups(&context, &partition, b"a", &local, None))
                        .await
                        .is_err()
                );
            }
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            *context.storage_fault_config().write() = FaultConfig::default();
            assert_eq!(
                context.scan(&partition).await.unwrap(),
                vec![b"a".to_vec(), b"b".to_vec()]
            );

            let (a, len) = context.open_atomic(&partition, b"a").await.unwrap();
            assert_eq!(len, 7);
            assert_eq!(a.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
            assert_eq!(context.scan(&partition).await.unwrap(), vec![b"a".to_vec()]);
        });
    }
}

#[test]
fn identity_creation_requires_fresh_backing_and_one_barrier() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());

        let (nonempty, _) = storage.open("identity", b"nonempty").await.unwrap();
        nonempty.resize(1).await.unwrap();
        nonempty.sync().await.unwrap();
        assert!(
            Blob::<memory::Blob>::initialize_identity(&nonempty, 1, test_incarnation)
                .await
                .is_err()
        );

        let (fresh, _) = storage.open("identity", b"fresh").await.unwrap();
        let fresh_events = Arc::new(SyncMutex::new(Vec::new()));
        let fresh = CountingBlob {
            inner: fresh,
            read_bytes: Arc::new(AtomicUsize::new(0)),
            events: fresh_events.clone(),
        };
        let incarnation =
            Blob::<CountingBlob<memory::Blob>>::initialize_identity(&fresh, 0, test_incarnation)
                .await
                .unwrap();
        assert_eq!(
            *fresh_events.lock(),
            [
                Event::Resize(DATA_OFFSET),
                Event::Write {
                    offset: 0,
                    len: IDENTITY_PAGE_LEN as usize,
                    options: WriteOptions::default(),
                },
                Event::Sync,
            ]
        );
        let installed = fresh
            .read_at(0, IDENTITY_PAGE_LEN as usize)
            .await
            .unwrap()
            .coalesce();
        assert_eq!(
            decode_identity(installed.as_ref().try_into().unwrap()),
            Some(incarnation)
        );
    });
}

#[test]
fn impossible_torn_identity_is_rejected_without_mutation() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "impossible_torn_identity";
        for (name, offset) in [
            (b"magic".as_slice(), 0),
            (b"padding".as_slice(), IDENTITY_LEN as u64),
        ] {
            let (backing, _) = context.open(partition, name).await.unwrap();
            backing.resize(DATA_OFFSET).await.unwrap();
            backing.sync().await.unwrap();
            backing
                .write_at(offset, vec![0xff], WriteOptions::SYNC)
                .await
                .unwrap();
            drop(backing);

            let error = context.open_atomic(partition, name).await.err().unwrap();
            assert!(is_blob_corrupt(&error));

            let (backing, backing_len) = context.open(partition, name).await.unwrap();
            assert_eq!(backing_len, DATA_OFFSET);
            assert_eq!(
                backing
                    .read_at(offset, 1)
                    .await
                    .unwrap()
                    .coalesce()
                    .as_ref(),
                &[0xff]
            );
        }
    });
}

#[test]
fn atomic_open_and_scan_complete_an_identity_only_backing() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "identity_only";
        let open_incarnation = [0x11; INCARNATION_LEN];
        let scan_incarnation = [0x22; INCARNATION_LEN];
        for (name, incarnation) in [
            (b"open".as_slice(), open_incarnation),
            (b"scan".as_slice(), scan_incarnation),
        ] {
            let (backing, _) = context.open(partition, name).await.unwrap();
            backing.resize(IDENTITY_PAGE_LEN).await.unwrap();
            backing
                .write_at(
                    0,
                    encode_identity(incarnation).to_vec(),
                    WriteOptions::default(),
                )
                .await
                .unwrap();
            backing.sync().await.unwrap();
        }

        let (opened, len) = context.open_atomic(partition, b"open").await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(opened.incarnation, open_incarnation);
        drop(opened);

        assert_eq!(
            context.scan_atomic(partition).await.unwrap(),
            [b"open".to_vec(), b"scan".to_vec()]
        );
        let (scanned, len) = context.open_atomic(partition, b"scan").await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(scanned.incarnation, scan_incarnation);

        for name in [b"open".as_slice(), b"scan".as_slice()] {
            let (_, backing_len) = context.open(partition, name).await.unwrap();
            assert_eq!(backing_len, DATA_OFFSET);
        }
    });
}

#[test]
fn subset_faults_during_identity_creation_require_a_complete_identity() {
    let mut saw_invalid_partial_page = false;
    for seed in 0..256 {
        let outcome = deterministic::Runner::seeded(seed).start(|context| async move {
            *context.storage_fault_config().write() = FaultConfig::default()
                .write(0.5)
                .write_retention(PartialWriteMode::Subset, 0.5);
            if context
                .open_atomic("subset_identity", b"blob")
                .await
                .is_ok()
            {
                return None;
            }

            *context.storage_fault_config().write() = FaultConfig::default();
            let (backing, backing_len) = context.open("subset_identity", b"blob").await.unwrap();
            assert!(backing_len > 0 && backing_len <= IDENTITY_PAGE_LEN);
            let encoded = backing
                .read_at(0, backing_len as usize)
                .await
                .unwrap()
                .coalesce();
            let incarnation = (backing_len == IDENTITY_PAGE_LEN)
                .then(|| decode_identity(encoded.as_ref().try_into().unwrap()))
                .flatten();
            drop(backing);

            match incarnation {
                Some(incarnation) => {
                    let (blob, len) = context
                        .open_atomic("subset_identity", b"blob")
                        .await
                        .unwrap();
                    assert_eq!(len, 0);
                    assert_eq!(blob.incarnation, incarnation);
                }
                None => {
                    let error = context
                        .open_atomic("subset_identity", b"blob")
                        .await
                        .err()
                        .expect("an incomplete pre-existing identity must be rejected");
                    assert!(is_blob_corrupt(&error));
                    let (backing, len) = context.open("subset_identity", b"blob").await.unwrap();
                    assert_eq!(len, backing_len);
                    assert_eq!(
                        backing
                            .read_at(0, backing_len as usize)
                            .await
                            .unwrap()
                            .coalesce()
                            .as_ref(),
                        encoded.as_ref()
                    );
                }
            }
            Some(incarnation.is_none())
        });
        saw_invalid_partial_page |= outcome.unwrap_or(false);
        if saw_invalid_partial_page {
            break;
        }
    }
    assert!(saw_invalid_partial_page);
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[tokio::test]
async fn tokio_backing_recovers_complete_rings() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    let directory = std::env::temp_dir().join(format!(
        "commonware_runtime_atomic_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let storage = tokio_storage::Storage::new(
        tokio_storage::Config::new(directory.clone(), 2 * 1024 * 1024),
        test_pool(),
    );

    stage_batch(&storage, "tokio_atomic", &[b"rejected"], &[false], 0).await;
    let (_, len) = storage
        .open_atomic("tokio_atomic", b"rejected")
        .await
        .unwrap();
    assert_eq!(len, 3);

    stage_batch(&storage, "tokio_atomic", &[b"a", b"b"], &[false; 2], 0b11).await;
    let (a, len) = storage.open_atomic("tokio_atomic", b"a").await.unwrap();
    assert_eq!(len, 7);
    assert_eq!(a.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
    let (b, len) = storage.open_atomic("tokio_atomic", b"b").await.unwrap();
    assert_eq!(len, 7);
    assert_eq!(b.read_at(0, 7).await.unwrap().coalesce(), b"old-new");

    assert_open_maps_recovery_corruption(&storage, "tokio_corruption").await;

    drop((a, b, storage));
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[tokio::test]
async fn foreign_lineage_batch_handles_are_rejected() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    let directory = std::env::temp_dir().join(format!(
        "commonware_runtime_atomic_foreign_lineage_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let seed_directory = directory.join("seed");
    let left_directory = directory.join("left");
    let right_directory = directory.join("right");
    let partition = "foreign_lineage";
    let seed = tokio_storage::Storage::new(
        tokio_storage::Config::new(seed_directory.clone(), 2 * 1024 * 1024),
        test_pool(),
    );
    let (seed_a, _) = seed.open_atomic(partition, b"a").await.unwrap();
    let (seed_b, _) = seed.open_atomic(partition, b"b").await.unwrap();
    seed_a.sync().await.unwrap();
    seed_b.sync().await.unwrap();
    drop((seed_a, seed_b, seed));

    for destination in [&left_directory, &right_directory] {
        std::fs::create_dir_all(destination.join(partition)).unwrap();
        for name in [b"a".as_slice(), b"b".as_slice()] {
            let encoded_name = commonware_formatting::hex(name);
            std::fs::copy(
                seed_directory.join(partition).join(&encoded_name),
                destination.join(partition).join(encoded_name),
            )
            .unwrap();
        }
    }

    let left = tokio_storage::Storage::new(
        tokio_storage::Config::new(left_directory, 2 * 1024 * 1024),
        test_pool(),
    );
    let right = tokio_storage::Storage::new(
        tokio_storage::Config::new(right_directory, 2 * 1024 * 1024),
        test_pool(),
    );
    let (left_a, _) = left.open_atomic(partition, b"a").await.unwrap();
    let (right_b, _) = right.open_atomic(partition, b"b").await.unwrap();
    left_a.set_tag([1; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
    right_b.set_tag([2; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
    let result = left
        .apply(vec![
            BatchOperation::Publish(left_a.clone()),
            BatchOperation::Publish(right_b.clone()),
        ])
        .await;
    let error_kind = result.as_ref().err().and_then(io_kind);
    drop((left_a, right_b));

    let mut durable_tags = Vec::new();
    for storage in [&left, &right] {
        for name in [b"a".as_slice(), b"b".as_slice()] {
            let (blob, len) = storage.open_atomic(partition, name).await.unwrap();
            assert_eq!(len, 0);
            durable_tags.push(blob.tag().await.unwrap());
            drop(blob);
        }
    }
    drop((left, right));
    std::fs::remove_dir_all(directory).unwrap();

    assert_eq!(error_kind, Some(io::ErrorKind::InvalidInput));
    assert_eq!(durable_tags, vec![[0; ATOMIC_BLOB_TAG_LEN]; 4]);
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
async fn run_tokio_rewind_predecessor_case(label: &str, direct: bool, rewind_peer: bool) {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    let directory = std::env::temp_dir().join(format!(
        "commonware_runtime_atomic_{label}_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let storage = tokio_storage::Storage::new(
        tokio_storage::Config::new(directory.clone(), 2 * 1024 * 1024),
        test_pool(),
    );

    let partition = label;
    let (a, _) = storage.open_atomic(partition, b"a").await.unwrap();
    let (b, _) = storage.open_atomic(partition, b"b").await.unwrap();
    a.append(b"abcdef").await.unwrap();
    b.append(b"peer").await.unwrap();
    storage
        .apply(vec![
            BatchOperation::Publish(a.clone()),
            BatchOperation::Publish(b.clone()),
        ])
        .await
        .unwrap();

    if direct {
        a.rewind(3).await.unwrap();
        a.sync().await.unwrap();
    } else {
        storage
            .apply(vec![BatchOperation::Rewind {
                blob: a.clone(),
                len: 3,
            }])
            .await
            .unwrap();
    }
    if rewind_peer {
        storage
            .apply(vec![BatchOperation::Rewind {
                blob: b.clone(),
                len: 2,
            }])
            .await
            .unwrap();
    }
    drop((a, b));

    // The physical shrink follows the barrier that made the predecessor's finals independent.
    // Its retained witness can outlive the payload extent without becoming recovery authority.
    let (a, len) = storage.open_atomic(partition, b"a").await.unwrap();
    assert_eq!(len, 3);
    assert_eq!(a.read_at(0, 3).await.unwrap().coalesce(), b"abc");
    drop(a);
    let (b, len) = storage.open_atomic(partition, b"b").await.unwrap();
    let expected = if rewind_peer {
        b"pe".as_slice()
    } else {
        b"peer"
    };
    assert_eq!(len, expected.len() as u64);
    assert_eq!(
        b.read_at(0, expected.len()).await.unwrap().coalesce(),
        expected
    );
    drop(b);

    drop(storage);
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[tokio::test]
async fn tokio_rewind_recovery_accepts_a_truncated_predecessor_extent() {
    run_tokio_rewind_predecessor_case("tokio_rewind_predecessor_batch", false, false).await;
    run_tokio_rewind_predecessor_case("tokio_rewind_predecessor_direct", true, false).await;
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[tokio::test]
async fn tokio_rewind_recovery_accepts_independently_truncated_predecessor_peers() {
    run_tokio_rewind_predecessor_case("tokio_rewind_predecessor_peers", false, true).await;
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[tokio::test]
async fn canceled_open_and_scan_peer_recovery_retain_group_exclusion() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    for scan in [false, true] {
        let directory = std::env::temp_dir().join(format!(
            "commonware_runtime_atomic_cancel_recovery_{}_{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let storage = tokio_storage::Storage::new(
            tokio_storage::Config::new(directory.clone(), 2 * 1024 * 1024),
            test_pool(),
        );
        stage_batch(
            &storage,
            "cancel_peer_recovery",
            &[b"a", b"b"],
            &[false, false],
            0b11,
        )
        .await;

        let (entered, resume, completed) = tokio_storage::pause_write("cancel_peer_recovery", b"b");
        let recovering = tokio::spawn(observe_tokio_recovery(
            storage.clone(),
            "cancel_peer_recovery",
            b"a",
            scan,
        ));
        entered.await.unwrap();
        recovering.abort();
        let _ = recovering.await;

        let reopening = {
            let storage = storage.clone();
            tokio::spawn(async move { storage.open_atomic("cancel_peer_recovery", b"b").await })
        };
        let same_operation = tokio::spawn(observe_tokio_recovery(
            storage.clone(),
            "cancel_peer_recovery",
            b"a",
            scan,
        ));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !reopening.is_finished() && !same_operation.is_finished(),
            "canceling the observer released atomic work while admitted recovery was running"
        );

        resume.send(()).unwrap();
        completed.await.unwrap();
        let (b, len) = reopening.await.unwrap().unwrap();
        same_operation.await.unwrap().unwrap();
        assert_eq!(len, 7);
        assert_eq!(b.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
        drop((b, storage));
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[test]
fn runtime_shutdown_retains_atomic_exclusion_until_physical_io_quiesces() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    let directory = std::env::temp_dir().join(format!(
        "commonware_runtime_atomic_shutdown_recovery_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let storage = tokio_storage::Storage::new(
        tokio_storage::Config::new(directory.clone(), 2 * 1024 * 1024),
        test_pool(),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(stage_batch(
        &storage,
        "shutdown_peer_recovery",
        &[b"a", b"b"],
        &[false, false],
        0b11,
    ));

    let (entered, resume, completed) = tokio_storage::pause_write("shutdown_peer_recovery", b"b");
    let recovering_storage = storage.clone();
    drop(runtime.spawn(observe_tokio_recovery(
        recovering_storage,
        "shutdown_peer_recovery",
        b"a",
        false,
    )));
    runtime.block_on(entered).unwrap();
    runtime.shutdown_timeout(std::time::Duration::from_millis(10));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let reopening_storage = storage.clone();
    let mut reopening = runtime.spawn(async move {
        reopening_storage
            .open_atomic("shutdown_peer_recovery", b"b")
            .await
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    let resume = ResumeWriteOnDrop::new(resume);
    assert!(
        !reopening.is_finished(),
        "runtime shutdown released group exclusion while admitted physical I/O remained"
    );

    resume.release();
    runtime.block_on(completed).unwrap();
    let (blob, len) = runtime.block_on(&mut reopening).unwrap().unwrap();
    assert_eq!(len, 7);
    assert_eq!(
        runtime.block_on(blob.read_at(0, 7)).unwrap().coalesce(),
        b"old-new"
    );

    drop((blob, storage, runtime));
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[test]
fn runtime_shutdown_retains_direct_publication_until_physical_io_quiesces() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    let directory = std::env::temp_dir().join(format!(
        "commonware_runtime_atomic_shutdown_publish_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let storage = tokio_storage::Storage::new(
        tokio_storage::Config::new(directory.clone(), 2 * 1024 * 1024),
        test_pool(),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let blob = runtime.block_on(async {
        let (blob, _) = storage
            .open_atomic("shutdown_direct_publish", b"blob")
            .await
            .unwrap();
        blob.append(b"old").await.unwrap();
        blob.sync().await.unwrap();
        blob.append(b"-new").await.unwrap();
        blob
    });

    let (entered, resume, completed) =
        tokio_storage::pause_write("shutdown_direct_publish", b"blob");
    drop(runtime.spawn(async move { blob.sync().await }));
    runtime.block_on(entered).unwrap();
    runtime.shutdown_timeout(std::time::Duration::from_millis(10));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let reopening_storage = storage.clone();
    let mut reopening = runtime.spawn(async move {
        reopening_storage
            .open_atomic("shutdown_direct_publish", b"blob")
            .await
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    let resume = ResumeWriteOnDrop::new(resume);
    assert!(
        !reopening.is_finished(),
        "runtime shutdown released direct-publication authority while admitted physical I/O \
         remained"
    );

    resume.release();
    runtime.block_on(completed).unwrap();
    let (blob, len) = runtime.block_on(&mut reopening).unwrap().unwrap();
    assert_eq!(len, 7);
    assert_eq!(
        runtime.block_on(blob.read_at(0, 7)).unwrap().coalesce(),
        b"old-new"
    );

    drop((blob, storage, runtime));
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[test]
fn runtime_shutdown_retains_direct_append_until_physical_io_quiesces() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    let directory = std::env::temp_dir().join(format!(
        "commonware_runtime_atomic_shutdown_append_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let storage = tokio_storage::Storage::new(
        tokio_storage::Config::new(directory.clone(), 2 * 1024 * 1024),
        test_pool(),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let blob = runtime.block_on(async {
        let (blob, _) = storage
            .open_atomic("shutdown_direct_append", b"blob")
            .await
            .unwrap();
        blob.append(b"old").await.unwrap();
        blob.sync().await.unwrap();
        blob
    });

    let (entered, resume, completed) =
        tokio_storage::pause_write("shutdown_direct_append", b"blob");
    drop(runtime.spawn(async move { blob.append(b"stale").await }));
    runtime.block_on(entered).unwrap();
    runtime.shutdown_timeout(std::time::Duration::from_millis(10));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let reopening_storage = storage.clone();
    let mut reopening = runtime.spawn(async move {
        reopening_storage
            .open_atomic("shutdown_direct_append", b"blob")
            .await
    });
    std::thread::sleep(std::time::Duration::from_millis(100));
    let resume = ResumeWriteOnDrop::new(resume);
    assert!(
        !reopening.is_finished(),
        "runtime shutdown released direct-append authority while admitted physical I/O \
         remained"
    );

    resume.release();
    runtime.block_on(completed).unwrap();
    let (blob, len) = runtime.block_on(&mut reopening).unwrap().unwrap();
    assert_eq!(len, 3);
    runtime.block_on(async {
        blob.append(b"fresh").await.unwrap();
        blob.sync().await.unwrap();
    });
    assert_eq!(
        runtime.block_on(blob.read_at(0, 8)).unwrap().coalesce(),
        b"oldfresh"
    );

    drop((blob, storage, runtime));
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[test]
fn detached_context_atomic_work_does_not_drop_the_runner_runtime() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
    static PANIC_HOOK: SyncMutex<()> = SyncMutex::new(());

    let _panic_hook = PANIC_HOOK.lock();
    let previous_hook = Arc::new(std::panic::take_hook());
    let hook_previous = previous_hook.clone();
    let (panic_sender, panic_receiver) = std::sync::mpsc::channel();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|message| (*message).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        if message.contains("Cannot drop a runtime") {
            let _ = panic_sender.send(message);
        } else {
            hook_previous(info);
        }
    }));

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let directory = std::env::temp_dir().join(format!(
            "commonware_runtime_atomic_context_shutdown_{}_{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&directory);
        let (entered, resume, completed) = tokio_storage::pause_write("context_shutdown", b"blob");
        let resume = ResumeWriteOnDrop::new(resume);

        crate::tokio::Runner::new(
            crate::tokio::Config::new().with_storage_directory(directory.clone()),
        )
        .start(|context| async move {
            let mut opening = Box::pin(context.open_atomic("context_shutdown", b"blob"));
            assert!(opening.as_mut().now_or_never().is_none());
            entered.await.unwrap();
            drop(opening);
        });

        resume.release();
        futures::executor::block_on(completed).unwrap();
        if let Ok(message) = panic_receiver.recv_timeout(std::time::Duration::from_secs(2)) {
            panic!("detached atomic work dropped the runner runtime: {message}");
        }
        let _ = std::fs::remove_dir_all(directory);
    }));

    drop(std::panic::take_hook());
    let previous_hook = Arc::try_unwrap(previous_hook)
        .unwrap_or_else(|_| panic!("the temporary panic hook retained its predecessor"));
    std::panic::set_hook(previous_hook);
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

#[test]
fn identity_decoder_and_root_classifier_cover_corrupt_and_terminal_images() {
    let incarnation = [9; INCARNATION_LEN];
    let valid = encode_identity(incarnation);
    assert_eq!(decode_identity(&valid), Some(incarnation));

    let mut bad_magic = valid;
    bad_magic[0] ^= 1;
    assert_eq!(decode_identity(&bad_magic), None);
    let mut bad_guard = valid;
    bad_guard[IDENTITY_GUARD_OFFSET] = 0;
    assert_eq!(decode_identity(&bad_guard), None);
    let mut bad_checksum = valid;
    bad_checksum[24] ^= 1;
    assert_eq!(decode_identity(&bad_checksum), None);
    let mut bad_suffix = valid;
    bad_suffix[IDENTITY_LEN] = 1;
    assert_eq!(decode_identity(&bad_suffix), None);

    let raw = [[1; ROOT_SLOT_SIZE]; ROOT_OFFSETS.len()];
    assert!(rejection_plan(DATA_OFFSET, &raw).is_err());
    let prepared = batch::prepare(vec![batch::Participant {
        partition: "terminal".into(),
        name: b"blob".to_vec(),
        incarnation: [1; INCARNATION_LEN],
        candidate: batch::Candidate::new(Root::unbound(2, 0, [0; ATOMIC_BLOB_TAG_LEN])).unwrap(),
        removed: true,
    }])
    .unwrap();
    let mut tombstone = [
        prepared.slots[0],
        root_slot(encode_root(
            RootState::Committed,
            1,
            0,
            [0; ATOMIC_BLOB_TAG_LEN],
        )),
    ];
    tombstone[0][..ROOT_LEN]
        .copy_from_slice(&prepared.participants[0].candidate.final_root().unwrap());
    assert!(rejection_plan(DATA_OFFSET, &tombstone).unwrap().is_none());
}

#[test]
fn older_tombstone_does_not_unlink_a_newer_independent_root() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "newer_root_blocks_tombstone";
        let name = b"blob";
        let (blob, _) = context.open_atomic(partition, name).await.unwrap();
        let incarnation = blob.incarnation;
        let prepared = batch::prepare(vec![batch::Participant {
            partition: partition.into(),
            name: name.to_vec(),
            incarnation,
            candidate: batch::Candidate::new(Root::unbound(2, 0, [0; ATOMIC_BLOB_TAG_LEN]))
                .unwrap(),
            removed: true,
        }])
        .unwrap();
        let participant = &prepared.participants[0];
        let mut tombstone = prepared.slots[0];
        tombstone[..ROOT_LEN].copy_from_slice(&participant.candidate.final_root().unwrap());
        blob.backing
            .write_at(ROOT_OFFSETS[0], tombstone.to_vec(), WriteOptions::SYNC)
            .await
            .unwrap();
        blob.backing
            .write_at(
                ROOT_OFFSETS[1],
                finalized_slot_for(Root::unbound(3, 0, [0; ATOMIC_BLOB_TAG_LEN]), incarnation)
                    .to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
        drop(blob);

        let error = context
            .open_atomic(partition, name)
            .await
            .err()
            .expect("contradictory removal authority must be rejected");
        assert!(is_blob_corrupt(&error));
        let existing = open_existing(&context, partition, name)
            .await
            .unwrap()
            .expect("rejected removal must not unlink the incarnation");
        assert_eq!(existing.incarnation, incarnation);
    });
}

#[test]
fn peer_recovery_does_not_unlink_a_newer_independent_root() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "peer_newer_root_blocks_tombstone";
        let prepared = stage_batch(&context, partition, &[b"a", b"b"], &[false, true], 0b11).await;
        for participant in &prepared.participants {
            let (backing, _) = context
                .open(&participant.partition, &participant.name)
                .await
                .unwrap();
            backing
                .write_at(
                    participant.candidate.root_offset().unwrap(),
                    participant.candidate.final_root().unwrap().to_vec(),
                    WriteOptions::SYNC,
                )
                .await
                .unwrap();
            if participant.removed {
                backing
                    .write_at(
                        ROOT_OFFSETS[1],
                        finalized_slot_for_group(
                            Root::unbound(3, 7, [0x21; ATOMIC_BLOB_TAG_LEN]),
                            participant.incarnation,
                            [0x6b; batch::GROUP_ID_LEN],
                        )
                        .to_vec(),
                        WriteOptions::SYNC,
                    )
                    .await
                    .unwrap();
            }
        }
        let removed = prepared
            .participants
            .iter()
            .find(|participant| participant.removed)
            .unwrap();

        let error = context
            .open_atomic(partition, b"a")
            .await
            .err()
            .expect("peer recovery must reject contradictory removal authority");
        assert!(is_blob_corrupt(&error));
        let existing = open_existing(&context, partition, &removed.name)
            .await
            .unwrap()
            .expect("peer recovery must not unlink the newer authority");
        assert_eq!(existing.incarnation, removed.incarnation);
    });
}

#[test]
fn tombstone_does_not_authorize_a_prepared_successor() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "tombstone_prepared_successor";
        let name = b"blob";
        let (blob, _) = context.open_atomic(partition, name).await.unwrap();
        let incarnation = blob.incarnation;

        let terminal = batch::prepare_with_group_id(
            vec![batch::Participant {
                partition: partition.into(),
                name: name.to_vec(),
                incarnation,
                candidate: batch::Candidate::new(Root::unbound(2, 0, [0; ATOMIC_BLOB_TAG_LEN]))
                    .unwrap(),
                removed: true,
            }],
            [0x6a; 16],
        )
        .unwrap();
        let mut tombstone = terminal.slots[0];
        tombstone[..ROOT_LEN]
            .copy_from_slice(&terminal.participants[0].candidate.final_root().unwrap());
        let successor = batch::prepare_with_group_id(
            vec![batch::Participant {
                partition: partition.into(),
                name: name.to_vec(),
                incarnation,
                candidate: batch::Candidate::new(Root::unbound(3, 0, [0; ATOMIC_BLOB_TAG_LEN]))
                    .unwrap(),
                removed: false,
            }],
            [0x7b; 16],
        )
        .unwrap();
        blob.backing
            .write_at(ROOT_OFFSETS[0], tombstone.to_vec(), WriteOptions::SYNC)
            .await
            .unwrap();
        blob.backing
            .write_at(
                ROOT_OFFSETS[1],
                successor.slots[0].to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
        drop(blob);

        let error = context
            .open_atomic(partition, name)
            .await
            .err()
            .expect("a terminal tombstone must reject a prepared successor");
        assert!(is_blob_corrupt(&error));
        let existing = open_existing(&context, partition, name)
            .await
            .unwrap()
            .expect("terminal-state corruption must not unlink the incarnation");
        assert_eq!(existing.incarnation, incarnation);
    });
}

#[test]
fn tombstone_does_not_authorize_a_later_exact_final() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "tombstone_later_exact_final";
        let name = b"blob";
        let (blob, _) = context.open_atomic(partition, name).await.unwrap();
        let incarnation = blob.incarnation;

        let terminal = batch::prepare_with_group_id(
            vec![batch::Participant {
                partition: partition.into(),
                name: name.to_vec(),
                incarnation,
                candidate: batch::Candidate::new(Root::unbound(2, 0, [0; ATOMIC_BLOB_TAG_LEN]))
                    .unwrap(),
                removed: true,
            }],
            [0x6a; 16],
        )
        .unwrap();
        let mut tombstone = terminal.slots[0];
        tombstone[..ROOT_LEN]
            .copy_from_slice(&terminal.participants[0].candidate.final_root().unwrap());

        let successor = batch::prepare_with_group_id(
            vec![batch::Participant {
                partition: partition.into(),
                name: name.to_vec(),
                incarnation,
                candidate: batch::Candidate::new(Root::unbound(5, 0, [0; ATOMIC_BLOB_TAG_LEN]))
                    .unwrap(),
                removed: false,
            }],
            [0x7b; 16],
        )
        .unwrap();
        let mut finalized = successor.slots[0];
        finalized[..ROOT_LEN]
            .copy_from_slice(&successor.participants[0].candidate.final_root().unwrap());
        blob.backing
            .write_at(ROOT_OFFSETS[0], tombstone.to_vec(), WriteOptions::SYNC)
            .await
            .unwrap();
        blob.backing
            .write_at(ROOT_OFFSETS[1], finalized.to_vec(), WriteOptions::SYNC)
            .await
            .unwrap();
        drop(blob);

        let error = context
            .open_atomic(partition, name)
            .await
            .err()
            .expect("a terminal tombstone must reject every later exact final");
        assert!(is_blob_corrupt(&error));
        let existing = open_existing(&context, partition, name)
            .await
            .unwrap()
            .expect("terminal-state corruption must not recreate the incarnation");
        assert_eq!(existing.incarnation, incarnation);
    });
}

#[test]
fn peer_tombstone_does_not_authorize_a_prepared_successor() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "peer_tombstone_prepared_successor";
        let mut incarnations = BTreeMap::new();
        let mut backings = BTreeMap::new();
        for name in [b"a".as_slice(), b"b".as_slice()] {
            let (blob, _) = context.open_atomic(partition, name).await.unwrap();
            incarnations.insert(name.to_vec(), blob.incarnation);
            backings.insert(name.to_vec(), blob.backing.clone());
        }

        let removed_name = b"b";
        let removed_incarnation = incarnations[removed_name.as_slice()];
        let terminal = batch::prepare_with_group_id(
            vec![batch::Participant {
                partition: partition.into(),
                name: removed_name.to_vec(),
                incarnation: removed_incarnation,
                candidate: batch::Candidate::new(Root::unbound(2, 0, [0; ATOMIC_BLOB_TAG_LEN]))
                    .unwrap(),
                removed: true,
            }],
            [0x6a; 16],
        )
        .unwrap();
        let mut tombstone = terminal.slots[0];
        tombstone[..ROOT_LEN]
            .copy_from_slice(&terminal.participants[0].candidate.final_root().unwrap());

        let successor = batch::prepare_with_group_id(
            [b"a".as_slice(), b"b".as_slice()]
                .into_iter()
                .map(|name| batch::Participant {
                    partition: partition.into(),
                    name: name.to_vec(),
                    incarnation: incarnations[name],
                    candidate: batch::Candidate::new(Root::unbound(3, 0, [0; ATOMIC_BLOB_TAG_LEN]))
                        .unwrap(),
                    removed: false,
                })
                .collect(),
            [0x7b; 16],
        )
        .unwrap();
        for (participant, slot) in successor.participants.iter().zip(&successor.slots) {
            let backing = &backings[&participant.name];
            let predecessor = if participant.name == removed_name {
                tombstone
            } else {
                finalized_slot_for(
                    Root::unbound(2, 0, [0; ATOMIC_BLOB_TAG_LEN]),
                    participant.incarnation,
                )
            };
            backing
                .write_at(ROOT_OFFSETS[0], predecessor.to_vec(), WriteOptions::SYNC)
                .await
                .unwrap();
            backing
                .write_at(ROOT_OFFSETS[1], slot.to_vec(), WriteOptions::SYNC)
                .await
                .unwrap();
        }
        drop(backings);

        let error = context
            .open_atomic(partition, b"a")
            .await
            .err()
            .expect("peer recovery must reject a prepared successor of a tombstone");
        assert!(is_blob_corrupt(&error));
        let existing = open_existing(&context, partition, removed_name)
            .await
            .unwrap()
            .expect("peer recovery must preserve terminal-state corruption");
        assert_eq!(existing.incarnation, removed_incarnation);
    });
}

#[test]
fn existing_only_lookup_never_creates_and_requires_a_complete_identity() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        assert!(
            open_existing(&storage, "existing_only", b"missing")
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            storage.scan("existing_only").await,
            Err(Error::PartitionMissing(_))
        ));

        let (incomplete, len) = storage.open("existing_only", b"incomplete").await.unwrap();
        assert_eq!(len, 0);
        drop(incomplete);
        assert!(
            open_existing(&storage, "existing_only", b"incomplete")
                .await
                .unwrap()
                .is_none()
        );

        let (missing_identity, _) = storage
            .open("existing_only", b"missing_identity")
            .await
            .unwrap();
        missing_identity.resize(DATA_OFFSET).await.unwrap();
        missing_identity.sync().await.unwrap();
        drop(missing_identity);
        assert!(
            open_existing(&storage, "existing_only", b"missing_identity")
                .await
                .unwrap()
                .is_none()
        );

        let (short, _) = storage.open("existing_only", b"short").await.unwrap();
        short.resize(1).await.unwrap();
        short.sync().await.unwrap();
        assert!(
            open_existing(&storage, "existing_only", b"short")
                .await
                .unwrap()
                .is_none()
        );

        let (invalid, _) = storage.open("existing_only", b"invalid").await.unwrap();
        invalid.resize(DATA_OFFSET).await.unwrap();
        invalid.sync().await.unwrap();
        invalid
            .write_at(0, vec![1], WriteOptions::SYNC)
            .await
            .unwrap();
        assert!(
            open_existing(&storage, "existing_only", b"invalid")
                .await
                .unwrap()
                .is_none()
        );

        let (valid, _) = storage
            .open_atomic("existing_only", b"valid")
            .await
            .unwrap();
        drop(valid);
        assert!(
            open_existing(&storage, "existing_only", b"valid")
                .await
                .unwrap()
                .is_some()
        );
    });
}

fn group_member(
    participant: batch::Participant,
    link: batch::Link,
    slot: RootSlot,
    backing_len: u64,
) -> GroupMember<()> {
    let mut slots = [[0; ROOT_SLOT_SIZE]; ROOT_OFFSETS.len()];
    let index = root_index(participant.candidate.root_offset().unwrap()).unwrap();
    slots[index] = slot;
    GroupMember {
        link,
        backing: (),
        backing_len,
        slots,
    }
}

fn linked_member<B: Clone>(existing: &Existing<B>, partition: &str, name: &[u8]) -> GroupMember<B> {
    let link = existing
        .slots
        .iter()
        .find_map(|slot| batch::link(slot, partition, name))
        .unwrap();
    GroupMember {
        link,
        backing: existing.backing.clone(),
        backing_len: existing.backing_len,
        slots: existing.slots,
    }
}

#[test]
fn payload_validation_rejects_every_invalid_internal_boundary() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "payload_validation_boundaries";
        stage_batch(&context, partition, &[b"member"], &[false], 1).await;
        let existing = open_existing(&context, partition, b"member")
            .await
            .unwrap()
            .unwrap();
        let mut member = linked_member(&existing, partition, b"member");
        let candidate = member.link.participant.candidate.clone();

        member.link.participant.candidate = batch::Candidate {
            prepared_root: encode_root_value(
                RootState::BatchPrepared,
                Root::unbound(2, MAX_UNSYNCED_PAYLOAD_LEN + 1, [0; ATOMIC_BLOB_TAG_LEN]),
            ),
            payload: batch::PayloadDescriptor {
                start: 0,
                checksum: [0; 32],
            },
        };
        assert!(!candidate_payload_valid(&member).await.unwrap());

        member.link.participant.candidate = candidate.clone();
        member.link.participant.candidate.payload.start = u64::MAX;
        assert!(!candidate_payload_valid(&member).await.unwrap());

        member.link.participant.candidate = candidate.clone();
        member.link.participant.candidate.prepared_root[ROOT_BODY_LEN] ^= 1;
        assert!(!candidate_payload_valid(&member).await.unwrap());

        member.link.participant.candidate = batch::Candidate::with_payload(
            Root::unbound(2, u64::MAX, [0; ATOMIC_BLOB_TAG_LEN]),
            batch::PayloadDescriptor {
                start: u64::MAX - 1,
                checksum: [0; 32],
            },
        )
        .unwrap();
        assert!(!candidate_payload_valid(&member).await.unwrap());

        member.link.participant.candidate = candidate;
        member.backing_len = DATA_OFFSET + 6;
        assert!(!candidate_payload_valid(&member).await.unwrap());
    });
}

#[test]
fn payload_proof_distinguishes_a_known_crc32c_collision() {
    // These two payloads collide under CRC32C when prefixed by PAYLOAD_DOMAIN. Publication
    // evidence must still distinguish the complete issued write from this retained subset.
    let complete = [0xf1, 0x76, 0xec, 0x05, 0x01, 0x42];
    let retained_subset = [0, 0, 0, 0, 0, 0x42];
    assert_ne!(
        payload_checksum(IoBufs::from(complete.to_vec())),
        payload_checksum(IoBufs::from(retained_subset.to_vec())),
    );
}

#[test]
fn group_candidate_and_ring_validation_rejects_every_structural_mismatch() {
    let prepared = batch::prepare(vec![
        batch::Participant {
            partition: "ring".into(),
            name: b"b".to_vec(),
            incarnation: [2; INCARNATION_LEN],
            candidate: batch::Candidate::new(Root::unbound(2, 2, [2; ATOMIC_BLOB_TAG_LEN]))
                .unwrap(),
            removed: false,
        },
        batch::Participant {
            partition: "ring".into(),
            name: b"a".to_vec(),
            incarnation: [1; INCARNATION_LEN],
            candidate: batch::Candidate::new(Root::unbound(2, 2, [1; ATOMIC_BLOB_TAG_LEN]))
                .unwrap(),
            removed: false,
        },
    ])
    .unwrap();
    let mut members = prepared
        .participants
        .iter()
        .cloned()
        .zip(prepared.slots.iter().copied())
        .map(|(participant, slot)| {
            let link = batch::link(&slot, &participant.partition, &participant.name).unwrap();
            group_member(participant, link, slot, DATA_OFFSET + 2)
        })
        .collect::<Vec<_>>();
    let links = members
        .iter()
        .map(|member| &member.link)
        .collect::<Vec<_>>();
    assert!(canonical_ring(&links));

    members[1].link.next.name = b"b".to_vec();
    let links = members
        .iter()
        .map(|member| &member.link)
        .collect::<Vec<_>>();
    assert!(!canonical_ring(&links));
    members[1].link.next.name = b"a".to_vec();
    members[1].link.participant.name = b"a".to_vec();
    let links = members
        .iter()
        .map(|member| &member.link)
        .collect::<Vec<_>>();
    assert!(!canonical_ring(&links));
    members[1].link.participant.name = b"b".to_vec();
    members[1].link.participant.incarnation = [1; INCARNATION_LEN];
    let links = members
        .iter()
        .map(|member| &member.link)
        .collect::<Vec<_>>();
    assert!(!canonical_ring(&links));
    members[1].link.participant.incarnation = [2; INCARNATION_LEN];
    let links = members
        .iter()
        .map(|member| &member.link)
        .collect::<Vec<_>>();
    assert!(canonical_ring(&links));

    let member = &mut members[0];
    let candidate_index =
        root_index(member.link.participant.candidate.root_offset().unwrap()).unwrap();
    let other = 1 - candidate_index;
    member.slots[other] = root_slot(encode_root(
        RootState::Committed,
        1,
        2,
        [0; ATOMIC_BLOB_TAG_LEN],
    ));
    assert_eq!(
        candidate_status(&member.link, member.backing_len, &member.slots, false,).unwrap(),
        Some(batch::CandidateStatus::Prepared)
    );
    member.backing_len = DATA_OFFSET + 1;
    assert_eq!(
        candidate_status(&member.link, member.backing_len, &member.slots, false,).unwrap(),
        None
    );
    member.backing_len = DATA_OFFSET + 2;

    let removed = batch::Participant {
        partition: "removed_short".into(),
        name: b"blob".to_vec(),
        incarnation: [8; INCARNATION_LEN],
        candidate: batch::Candidate::new(Root::unbound(1, 2, [0; ATOMIC_BLOB_TAG_LEN])).unwrap(),
        removed: true,
    };
    let removed_prepared = batch::prepare(vec![removed.clone()]).unwrap();
    let removed_link = batch::link(
        &removed_prepared.slots[0],
        &removed.partition,
        &removed.name,
    )
    .unwrap();
    let mut removed_slots = [[0; ROOT_SLOT_SIZE]; ROOT_OFFSETS.len()];
    let removed_index =
        root_index(removed_link.participant.candidate.root_offset().unwrap()).unwrap();
    removed_slots[removed_index] = removed_prepared.slots[0];
    assert_eq!(
        candidate_status(&removed_link, DATA_OFFSET, &removed_slots, false).unwrap(),
        Some(batch::CandidateStatus::Prepared)
    );

    member.slots[candidate_index][0] ^= 1;
    assert_eq!(
        candidate_status(&member.link, member.backing_len, &member.slots, false,).unwrap(),
        None
    );
    member.slots[candidate_index] = prepared.slots[0];

    member.slots[other] = finalized_slot_for(
        Root::unbound(3, 0, [0; ATOMIC_BLOB_TAG_LEN]),
        member.link.participant.incarnation,
    );
    assert_eq!(
        candidate_status(&member.link, member.backing_len, &member.slots, false,).unwrap(),
        None
    );
    member.slots[other] = [0; ROOT_SLOT_SIZE];

    let mut malformed = member.link.clone();
    malformed.participant.candidate.prepared_root[0] ^= 1;
    let malformed = GroupMember {
        link: malformed,
        backing: (),
        backing_len: DATA_OFFSET + 2,
        slots: member.slots,
    };
    assert!(
        candidate_status(
            &malformed.link,
            malformed.backing_len,
            &malformed.slots,
            false,
        )
        .is_err()
    );

    let mut overflowing = member.link.clone();
    overflowing.participant.candidate =
        batch::Candidate::new(Root::unbound(2, u64::MAX, [0; ATOMIC_BLOB_TAG_LEN])).unwrap();
    let overflowing = GroupMember {
        link: overflowing,
        backing: (),
        backing_len: u64::MAX,
        slots: member.slots,
    };
    assert!(
        candidate_status(
            &overflowing.link,
            overflowing.backing_len,
            &overflowing.slots,
            false,
        )
        .is_err()
    );

    let participant = batch::Participant {
        partition: "invalid_geometry".into(),
        name: b"blob".to_vec(),
        incarnation: [9; INCARNATION_LEN],
        candidate: batch::Candidate::new(Root {
            generation: 1,
            logical_len: 0,
            integrity_start: 1,
            integrity_checksum: 0,
            integrity_scheme: IntegrityScheme::Unbound,
            tag: [0; ATOMIC_BLOB_TAG_LEN],
        })
        .unwrap(),
        removed: true,
    };
    let prepared = batch::prepare(vec![participant.clone()]).unwrap();
    let link = batch::link(
        &prepared.slots[0],
        &participant.partition,
        &participant.name,
    )
    .unwrap();
    let mut slots = [[0; ROOT_SLOT_SIZE]; ROOT_OFFSETS.len()];
    let invalid_index = root_index(link.participant.candidate.root_offset().unwrap()).unwrap();
    slots[invalid_index] = prepared.slots[0];
    assert!(candidate_status(&link, DATA_OFFSET, &slots, false).is_err());

    let final_root = member.link.participant.candidate.final_root().unwrap();
    member.slots[candidate_index][..ROOT_LEN].copy_from_slice(&final_root);
    assert!(exact_final(&member.link, &member.slots));
    member.link.participant.candidate.prepared_root[0] ^= 1;
    assert!(!exact_final(&member.link, &member.slots));
}

#[test]
fn older_batch_candidate_is_suppressed_by_every_newer_frontier() {
    let participant = batch::Participant {
        partition: "newest_first".into(),
        name: b"blob".to_vec(),
        incarnation: [1; INCARNATION_LEN],
        candidate: batch::Candidate::new(Root::unbound(2, 2, [2; ATOMIC_BLOB_TAG_LEN])).unwrap(),
        removed: false,
    };
    let prepared = batch::prepare(vec![participant.clone()]).unwrap();
    let link = batch::link(
        &prepared.slots[0],
        &participant.partition,
        &participant.name,
    )
    .unwrap();
    let mut slots = [[0; ROOT_SLOT_SIZE]; ROOT_OFFSETS.len()];
    slots[0] = prepared.slots[0];

    slots[0] = finalized_slot(Root::unbound(4, 4, [4; ATOMIC_BLOB_TAG_LEN]));
    assert_eq!(
        candidate_status(&link, DATA_OFFSET + 4, &slots, false).unwrap(),
        None
    );
    slots[0] = prepared.slots[0];

    slots[1] = root_slot(encode_root(
        RootState::BatchPrepared,
        3,
        3,
        [3; ATOMIC_BLOB_TAG_LEN],
    ));
    assert_eq!(
        candidate_status(&link, DATA_OFFSET + 3, &slots, false).unwrap(),
        None
    );

    let newer = batch::prepare(vec![batch::Participant {
        candidate: batch::Candidate::new(Root::unbound(3, 3, [3; ATOMIC_BLOB_TAG_LEN])).unwrap(),
        ..participant
    }])
    .unwrap();
    slots[1] = newer.slots[0];
    assert_eq!(
        candidate_status(&link, DATA_OFFSET + 3, &slots, false).unwrap(),
        None
    );

    slots[1] = [0; ROOT_SLOT_SIZE];
    slots[1][0] = 1;
    assert_eq!(
        candidate_status(&link, DATA_OFFSET + 3, &slots, false).unwrap(),
        None
    );

    let mut malformed = link;
    malformed.participant.candidate.prepared_root[0] ^= 1;
    assert!(!candidate_frontier_is_current(&malformed, &slots, false));
}

#[test]
fn ring_traversal_rejects_gaps_and_wrong_successors() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "ring_traversal";
        stage_batch(&context, partition, &[b"a", b"b", b"c"], &[false; 3], 0b111).await;
        let a = open_existing(&context, partition, b"a")
            .await
            .unwrap()
            .unwrap();
        assert!(
            traverse_group(&context, linked_member(&a, partition, b"a"), false,)
                .await
                .unwrap()
                .is_some()
        );

        let mut stale_start = linked_member(&a, partition, b"a");
        let candidate_index = root_index(
            stale_start
                .link
                .participant
                .candidate
                .root_offset()
                .unwrap(),
        )
        .unwrap();
        let newer_generation = stale_start
            .link
            .participant
            .candidate
            .root()
            .unwrap()
            .generation
            + 1;
        stale_start.slots[1 - candidate_index] = root_slot(encode_root(
            RootState::BatchPrepared,
            newer_generation,
            7,
            [0x71; ATOMIC_BLOB_TAG_LEN],
        ));
        assert!(
            traverse_group(&context, stale_start, false)
                .await
                .unwrap()
                .is_none()
        );

        let mut missing = linked_member(&a, partition, b"a");
        missing.link.next.name = b"missing".to_vec();
        assert!(
            traverse_group(&context, missing, false)
                .await
                .unwrap()
                .is_none()
        );

        let mut wrong_incarnation = linked_member(&a, partition, b"a");
        wrong_incarnation.link.next.incarnation[0] ^= 1;
        assert!(
            traverse_group(&context, wrong_incarnation, false)
                .await
                .unwrap()
                .is_none()
        );

        let mut wrong_group = linked_member(&a, partition, b"a");
        wrong_group.link.group_id[0] ^= 1;
        assert!(
            traverse_group(&context, wrong_group, false)
                .await
                .unwrap()
                .is_none()
        );

        let peer = open_existing(&context, partition, b"b")
            .await
            .unwrap()
            .unwrap();
        let peer_member = linked_member(&peer, partition, b"b");
        let candidate_index = root_index(
            peer_member
                .link
                .participant
                .candidate
                .root_offset()
                .unwrap(),
        )
        .unwrap();
        let newer_generation = peer_member
            .link
            .participant
            .candidate
            .root()
            .unwrap()
            .generation
            + 1;
        peer.backing
            .write_at(
                ROOT_OFFSETS[1 - candidate_index],
                root_slot(encode_root(
                    RootState::BatchPrepared,
                    newer_generation,
                    7,
                    [0x72; ATOMIC_BLOB_TAG_LEN],
                ))
                .to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
        assert!(
            traverse_group(&context, linked_member(&a, partition, b"a"), false,)
                .await
                .unwrap()
                .is_none()
        );
    });
}

#[test]
fn partial_final_propagates_peer_io_and_retries_group_wide() {
    deterministic::Runner::default().start(|context| async move {
        for removed in [false, true] {
            for (fault, config) in [
                ("open", FaultConfig::default().open(1.0)),
                ("read", FaultConfig::default().read(1.0)),
            ] {
                let partition = format!("local_final_io_{removed}_{fault}");
                let prepared =
                    stage_batch(&context, &partition, &[b"a", b"b"], &[removed, false], 0b11).await;
                let participant = &prepared.participants[0];
                let (backing, _) = context
                    .open(&participant.partition, &participant.name)
                    .await
                    .unwrap();
                backing
                    .write_at(
                        participant.candidate.root_offset().unwrap(),
                        participant.candidate.final_root().unwrap().to_vec(),
                        WriteOptions::SYNC,
                    )
                    .await
                    .unwrap();
                drop(backing);
                let local = open_existing(&context, &partition, b"a")
                    .await
                    .unwrap()
                    .unwrap();

                *context.storage_fault_config().write() = config;
                assert!(
                    Box::pin(recover_groups(&context, &partition, b"a", &local, None))
                        .await
                        .is_err(),
                    "a local final cannot hide a transient peer-{fault} failure"
                );
                *context.storage_fault_config().write() = FaultConfig::default();

                let recovered = Box::pin(recover_groups(&context, &partition, b"a", &local, None))
                    .await
                    .unwrap();
                assert_eq!(
                    recovered,
                    if removed {
                        GroupRecovery::Removed
                    } else {
                        GroupRecovery::Present
                    }
                );
                let peer = open_existing(&context, &partition, b"b")
                    .await
                    .unwrap()
                    .unwrap();
                let peer_link = batch::link(&prepared.slots[1], &partition, b"b").unwrap();
                assert!(exact_final(&peer_link, &peer.slots));
            }
        }
    });
}

#[test]
fn opening_a_complete_removed_participant_creates_a_new_incarnation() {
    deterministic::Runner::default().start(|context| async move {
        let complete = "open_complete_tombstone";
        stage_batch(&context, complete, &[b"a", b"b"], &[true, false], 0b11).await;
        let (replacement, len) = context.open_atomic(complete, b"a").await.unwrap();
        assert_eq!(len, 0);
        replacement.append(b"replacement").await.unwrap();
        replacement.sync().await.unwrap();
        let (b, len) = context.open_atomic(complete, b"b").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(b.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
    });
}

#[test]
fn payload_short_removed_participant_is_finalized_before_recreation() {
    const PARTITION: &str = "open_payload_short_tombstone";
    const NAME: &[u8] = b"blob";

    let (old_incarnation, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let (blob, _) = context.open_atomic(PARTITION, NAME).await.unwrap();
            let old_incarnation = blob.incarnation;
            blob.append(b"discarded").await.unwrap();

            *context.storage_fault_config().write() = FaultConfig::default()
                .write_retention(FULL_RETENTION.0, FULL_RETENTION.1)
                .sync(1.0);
            assert!(
                context
                    .apply(vec![BatchOperation::Remove(blob)])
                    .await
                    .is_err()
            );
            old_incarnation
        });

    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            *context.storage_fault_config().write() = FaultConfig::default().remove(1.0);
            assert!(context.open_atomic(PARTITION, NAME).await.is_err());
        });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        *context.storage_fault_config().write() = FaultConfig::default();
        let (replacement, len) = context.open_atomic(PARTITION, NAME).await.unwrap();
        assert_eq!(len, 0);
        assert_ne!(replacement.incarnation, old_incarnation);
        replacement.append(b"replacement").await.unwrap();
        replacement.sync().await.unwrap();
        drop(replacement);
        assert_eq!(context.scan(PARTITION).await.unwrap(), vec![NAME.to_vec()]);
    });
}

#[test]
fn exact_tombstone_missing_peer_rejects_invalid_geometry() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "invalid_disconnected_tombstone";
        let (a, _) = context.open_atomic(partition, b"a").await.unwrap();
        let (b, _) = context.open_atomic(partition, b"b").await.unwrap();
        a.append(b"old").await.unwrap();
        b.append(b"old").await.unwrap();
        a.sync().await.unwrap();
        b.sync().await.unwrap();

        let prepared = batch::prepare(vec![
            batch::Participant {
                partition: partition.into(),
                name: b"a".to_vec(),
                incarnation: a.incarnation,
                candidate: batch::Candidate::new(Root {
                    integrity_start: 4,
                    ..Root::unbound(2, 3, [0; ATOMIC_BLOB_TAG_LEN])
                })
                .unwrap(),
                removed: true,
            },
            batch::Participant {
                partition: partition.into(),
                name: b"b".to_vec(),
                incarnation: b.incarnation,
                candidate: batch::Candidate::new(Root::unbound(2, 3, [0; ATOMIC_BLOB_TAG_LEN]))
                    .unwrap(),
                removed: true,
            },
        ])
        .unwrap();
        for (participant, slot) in prepared.participants.iter().zip(&prepared.slots) {
            let backing = match participant.name.as_slice() {
                b"a" => &a.backing,
                b"b" => &b.backing,
                _ => unreachable!(),
            };
            backing
                .write_at(
                    participant.candidate.root_offset().unwrap(),
                    slot.to_vec(),
                    WriteOptions::SYNC,
                )
                .await
                .unwrap();
            backing
                .write_at(
                    participant.candidate.root_offset().unwrap(),
                    participant.candidate.final_root().unwrap().to_vec(),
                    WriteOptions::SYNC,
                )
                .await
                .unwrap();
        }
        drop((a, b));
        context.remove(partition, Some(b"b")).await.unwrap();

        let error = context
            .open_atomic(partition, b"a")
            .await
            .err()
            .expect("a noncanonical exact tombstone must not authorize removal");
        assert!(is_blob_corrupt(&error));
        assert_eq!(context.scan(partition).await.unwrap(), vec![b"a".to_vec()]);
    });
}

#[test]
fn atomic_scan_recovers_each_completed_group_once() {
    deterministic::Runner::default().start(|_| async move {
        const PARTICIPANTS: usize = 4;

        let mut registry = Registry::default();
        let storage = metered::Storage::new(memory::Storage::new(test_pool()), &mut registry);
        let mut operations = Vec::with_capacity(PARTICIPANTS);
        for name in [b"a".as_slice(), b"b", b"c", b"d"] {
            let (blob, _) = storage.open_atomic("scan_group_once", name).await.unwrap();
            blob.append(name).await.unwrap();
            operations.push(BatchOperation::Publish(blob));
        }
        storage.apply(operations).await.unwrap();

        // The first recovery materializes and synchronizes final roots that live publication
        // deliberately leaves as cleanup debt. Measure an already-finalized ring so the only
        // required scan work is one all-member confirmation barrier.
        storage.scan_atomic("scan_group_once").await.unwrap();

        let syncs_before = storage.storage_syncs();
        assert_eq!(
            storage.scan_atomic("scan_group_once").await.unwrap(),
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()]
        );
        assert_eq!(
            storage.storage_syncs() - syncs_before,
            PARTICIPANTS as u64,
            "one serialized scan should pay a completed group's durability debt once"
        );
    });
}

#[test]
fn atomic_scan_omits_and_reclaims_a_stranded_tombstone() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "scan_stranded_tombstone";
        let prepared = stage_batch(&context, partition, &[b"a", b"b"], &[true, false], 0b11).await;
        for participant in &prepared.participants {
            let (backing, _) = context
                .open(&participant.partition, &participant.name)
                .await
                .unwrap();
            backing
                .write_at(
                    participant.candidate.root_offset().unwrap(),
                    participant.candidate.final_root().unwrap().to_vec(),
                    WriteOptions::SYNC,
                )
                .await
                .unwrap();
        }

        assert_eq!(
            context.scan_atomic(partition).await.unwrap(),
            vec![b"b".to_vec()]
        );
        assert_eq!(context.scan(partition).await.unwrap(), vec![b"b".to_vec()]);
    });
}

#[test]
fn atomic_scan_recovers_every_post_final_unlink_subset() {
    deterministic::Runner::default().start(|context| async move {
        const NAMES: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
        for removal_mask in 1u8..1 << NAMES.len() {
            for unlink_mask in 0u8..1 << NAMES.len() {
                if unlink_mask & !removal_mask != 0 {
                    continue;
                }
                let partition = format!("scan_final_{removal_mask:04b}_{unlink_mask:04b}");
                let removals =
                    std::array::from_fn::<_, 4, _>(|ordinal| removal_mask & (1 << ordinal) != 0);
                let prepared = stage_batch(
                    &context,
                    &partition,
                    &NAMES,
                    &removals,
                    (1 << NAMES.len()) - 1,
                )
                .await;
                for participant in &prepared.participants {
                    let (backing, _) = context
                        .open(&participant.partition, &participant.name)
                        .await
                        .unwrap();
                    backing
                        .write_at(
                            participant.candidate.root_offset().unwrap(),
                            participant.candidate.final_root().unwrap().to_vec(),
                            WriteOptions::SYNC,
                        )
                        .await
                        .unwrap();
                }
                for (ordinal, name) in NAMES.iter().enumerate() {
                    if unlink_mask & (1 << ordinal) != 0 {
                        context.remove(&partition, Some(name)).await.unwrap();
                    }
                }

                let expected = NAMES
                    .iter()
                    .enumerate()
                    .filter(|(ordinal, _)| removal_mask & (1 << ordinal) == 0)
                    .map(|(_, name)| name.to_vec())
                    .collect::<Vec<_>>();
                assert_eq!(
                    context.scan_atomic(&partition).await.unwrap(),
                    expected,
                    "removals {removal_mask:04b}, unlinks {unlink_mask:04b}"
                );
                assert_eq!(context.scan(&partition).await.unwrap(), expected);
            }
        }
    });
}

#[test]
fn atomic_scan_rejects_an_incomplete_pre_existing_identity() {
    deterministic::Runner::default().start(|context| async move {
        let (atomic, len) = context.open_atomic("scan_zero", b"blob").await.unwrap();
        assert_eq!(len, 0);
        atomic.backing.resize(0).await.unwrap();
        atomic.backing.sync().await.unwrap();
        drop(atomic);

        let error = context.scan_atomic("scan_zero").await.unwrap_err();
        assert!(is_blob_corrupt(&error));
        let (_, backing_len) = context.open("scan_zero", b"blob").await.unwrap();
        assert_eq!(backing_len, 0);
    });
}

#[test]
fn atomic_scan_maps_identity_group_and_root_corruption() {
    deterministic::Runner::default().start(|context| async move {
        stage_identity_corruption(&context, "scan_bad_identity", b"blob").await;
        assert!(is_blob_corrupt(
            &context.scan_atomic("scan_bad_identity").await.unwrap_err()
        ));

        stage_group_corruption(&context, "scan_bad_group", b"blob").await;
        assert!(is_blob_corrupt(
            &context.scan_atomic("scan_bad_group").await.unwrap_err()
        ));
        let error = context
            .open_atomic("scan_bad_group", b"blob")
            .await
            .err()
            .unwrap();
        assert!(is_blob_corrupt(&error));

        stage_root_corruption(&context, "scan_bad_roots", b"blob").await;
        assert!(is_blob_corrupt(
            &context.scan_atomic("scan_bad_roots").await.unwrap_err()
        ));

        assert_open_maps_recovery_corruption(&context, "context_corruption").await;
    });
}

#[test]
fn batch_validation_rejects_a_corrupt_durable_predecessor() {
    deterministic::Runner::default().start(|context| async move {
        let (blob, _) = context
            .open_atomic("batch_corrupt_predecessor", b"blob")
            .await
            .unwrap();
        blob.append(b"pending").await.unwrap();
        blob.backing
            .write_at(ROOT_OFFSETS[0], vec![1; ROOT_SLOT_SIZE], WriteOptions::SYNC)
            .await
            .unwrap();

        assert!(
            context
                .apply(vec![BatchOperation::Publish(blob)])
                .await
                .is_err()
        );
    });
}

#[test]
fn finalization_rejects_an_invalid_in_memory_candidate() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "invalid_final_candidate";
        stage_batch(&context, partition, &[b"a"], &[false], 1).await;
        let existing = open_existing(&context, partition, b"a")
            .await
            .unwrap()
            .unwrap();
        let mut member = linked_member(&existing, partition, b"a");
        member.link.participant.candidate.prepared_root[0] ^= 1;
        assert!(finish_group(&context, &[member]).await.is_err());
    });
}

#[test]
fn recovery_repeats_batch_truncation_after_the_group_decision() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "batch_recovery_truncate";
        stage_batch(&context, partition, &[b"a", b"b"], &[false; 2], 0b11).await;
        let (backing, _) = context.open(partition, b"a").await.unwrap();
        backing.resize(DATA_OFFSET + 100).await.unwrap();
        backing.sync().await.unwrap();
        drop(backing);

        let (b, len) = context.open_atomic(partition, b"b").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(b.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
        let (a, len) = context.open_atomic(partition, b"a").await.unwrap();
        assert_eq!(len, 7);
        assert!(a.backing.read_at(DATA_OFFSET + 7, 1).await.is_err());
    });
}

#[test]
fn newer_incomplete_generation_is_resolved_before_older_ring_traversal() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "batch_staggered_generations";
        let prepared = stage_batch(&context, partition, &[b"a", b"b"], &[false; 2], 0b11).await;
        for participant in &prepared.participants {
            let (backing, _) = context
                .open(&participant.partition, &participant.name)
                .await
                .unwrap();
            backing
                .write_at(
                    participant.candidate.root_offset().unwrap(),
                    participant.candidate.final_root().unwrap().to_vec(),
                    WriteOptions::SYNC,
                )
                .await
                .unwrap();
        }
        let (backing, _) = context.open(partition, b"a").await.unwrap();
        backing
            .write_at(DATA_OFFSET + 7, b"!", WriteOptions::default())
            .await
            .unwrap();
        let later = root_slot(encode_root(
            RootState::BatchPrepared,
            3,
            8,
            [0x33; ATOMIC_BLOB_TAG_LEN],
        ));
        backing
            .write_at(ROOT_OFFSETS[1], later.to_vec(), WriteOptions::SYNC)
            .await
            .unwrap();
        drop(backing);

        let (b, len) = context.open_atomic(partition, b"b").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(b.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
        drop(b);

        let (backing, backing_len) = context.open(partition, b"a").await.unwrap();
        assert_eq!(backing_len, DATA_OFFSET + 7);
        let slot = backing
            .read_at(ROOT_OFFSETS[1], ROOT_SLOT_SIZE)
            .await
            .unwrap()
            .coalesce();
        assert_eq!(slot.as_ref(), later);
        drop(backing);

        let (a, len) = context.open_atomic(partition, b"a").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(a.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
        assert_eq!(a.tag().await.unwrap(), [0x20; ATOMIC_BLOB_TAG_LEN]);
        assert!(a.backing.read_at(DATA_OFFSET + 7, 1).await.is_err());
        drop(a);

        let (backing, _) = context.open(partition, b"a").await.unwrap();
        let slot = backing
            .read_at(ROOT_OFFSETS[1], ROOT_SLOT_SIZE)
            .await
            .unwrap()
            .coalesce();
        assert!(slot.as_ref().iter().all(|byte| *byte == 0));
    });
}

#[test]
fn atomic_blob_round_trip_and_unsynced_rollback() {
    deterministic::Runner::default().start(|context| async move {
        let tag = [0xA5; ATOMIC_BLOB_TAG_LEN];
        let (blob, len) = context.open_atomic("atomic", b"round_trip").await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(blob.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);

        assert_eq!(blob.append_tagged(b"durable", tag).await.unwrap(), 0);
        assert_eq!(blob.read_at(0, 7).await.unwrap().coalesce(), b"durable");
        blob.sync().await.unwrap();
        drop(blob);

        let (backing, backing_len) = context.open("atomic", b"round_trip").await.unwrap();
        assert_eq!(backing_len, DATA_OFFSET + 7);
        assert_eq!(
            backing.read_at(DATA_OFFSET, 7).await.unwrap().coalesce(),
            b"durable"
        );
        drop(backing);

        let (blob, len) = context.open_atomic("atomic", b"round_trip").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(blob.tag().await.unwrap(), tag);
        blob.append_tagged(b"-discarded", [0x5A; ATOMIC_BLOB_TAG_LEN])
            .await
            .unwrap();
        drop(blob);

        let (blob, len) = context.open_atomic("atomic", b"round_trip").await.unwrap();
        assert_eq!(len, 7);
        assert_eq!(blob.tag().await.unwrap(), tag);
        assert_eq!(blob.read_at(0, 7).await.unwrap().coalesce(), b"durable");
    });
}

#[test]
fn clones_share_visible_state_and_rewind_cannot_extend() {
    deterministic::Runner::default().start(|context| async move {
        let (blob, _) = context.open_atomic("atomic", b"clones").await.unwrap();
        let clone = blob.clone();

        let error = clone.rewind(1).await.unwrap_err();
        assert_eq!(io_kind(&error), Some(io::ErrorKind::InvalidInput));
        assert_eq!(io_kind(&Error::OffsetOverflow), None);

        blob.append_tagged(b"shared", [7; ATOMIC_BLOB_TAG_LEN])
            .await
            .unwrap();
        assert_eq!(clone.read_at(0, 6).await.unwrap().coalesce(), b"shared");
        assert_eq!(clone.tag().await.unwrap(), [7; ATOMIC_BLOB_TAG_LEN]);
        clone.sync().await.unwrap();
    });
}

#[test]
fn rewind_of_committed_bytes_fences_appends_until_sync() {
    deterministic::Runner::default().start(|context| async move {
        let (blob, _) = context.open_atomic("atomic", b"rewind").await.unwrap();
        blob.append(b"abcdef").await.unwrap();
        blob.sync().await.unwrap();

        blob.rewind_tagged(3, [3; ATOMIC_BLOB_TAG_LEN])
            .await
            .unwrap();
        assert_eq!(blob.append(Vec::<u8>::new()).await.unwrap(), 3);
        assert_eq!(blob.tag().await.unwrap(), [3; ATOMIC_BLOB_TAG_LEN]);
        assert_eq!(
            blob.append_tagged(Vec::<u8>::new(), [4; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap(),
            3
        );
        let error = blob.append(b"blocked").await.unwrap_err();
        assert_eq!(io_kind(&error), Some(io::ErrorKind::InvalidInput));
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"abc");
        assert_eq!(
            io_kind(&blob.read_at(3, 1).await.unwrap_err()),
            Some(io::ErrorKind::UnexpectedEof)
        );

        blob.sync().await.unwrap();
        assert_eq!(blob.append(b"d").await.unwrap(), 3);
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, len) = context.open_atomic("atomic", b"rewind").await.unwrap();
        assert_eq!(len, 4);
        assert_eq!(blob.read_at(0, 4).await.unwrap().coalesce(), b"abcd");
        assert_eq!(blob.tag().await.unwrap(), [4; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[test]
fn unpublished_rewind_reuses_the_physical_tail() {
    deterministic::Runner::default().start(|context| async move {
        let (blob, _) = context.open_atomic("atomic", b"reuse_tail").await.unwrap();
        blob.append(b"base").await.unwrap();
        blob.sync().await.unwrap();

        blob.append(b"abcdef").await.unwrap();
        blob.rewind(7).await.unwrap();
        assert_eq!(blob.append(b"XYZ").await.unwrap(), 7);
        assert_eq!(blob.read_at(0, 10).await.unwrap().coalesce(), b"baseabcXYZ");
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, len) = context.open_atomic("atomic", b"reuse_tail").await.unwrap();
        assert_eq!(len, 10);
        assert_eq!(blob.read_at(0, 10).await.unwrap().coalesce(), b"baseabcXYZ");
    });
}

#[test]
fn tag_only_publication_and_no_op_mutations_are_stable() {
    deterministic::Runner::default().start(|context| async move {
        let tag = std::array::from_fn(|index| index as u8);
        let (blob, _) = context.open_atomic("atomic", b"tag_only").await.unwrap();
        assert_eq!(blob.append(Vec::<u8>::new()).await.unwrap(), 0);
        blob.rewind(0).await.unwrap();
        blob.set_tag(tag).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (blob, len) = context.open_atomic("atomic", b"tag_only").await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(blob.tag().await.unwrap(), tag);
        blob.set_tag(tag).await.unwrap();
        blob.sync().await.unwrap();
    });
}

#[test]
fn recovery_repeats_a_committed_rewind_truncate() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (backing, _) = storage.open("atomic", b"lost_truncate").await.unwrap();
        let mut image = vec![0u8; (DATA_OFFSET + 6) as usize];
        image[..IDENTITY_PAGE_LEN as usize].copy_from_slice(&encode_identity(test_incarnation()));
        let old = encode_root(RootState::Committed, 1, 6, [1; ATOMIC_BLOB_TAG_LEN]);
        let new = finalized_slot_for(
            Root::unbound(2, 3, [2; ATOMIC_BLOB_TAG_LEN]),
            test_incarnation(),
        );
        image[ROOT_OFFSETS[1] as usize..ROOT_OFFSETS[1] as usize + ROOT_LEN].copy_from_slice(&old);
        image[ROOT_OFFSETS[0] as usize..ROOT_OFFSETS[0] as usize + ROOT_SLOT_SIZE]
            .copy_from_slice(&new);
        image[DATA_OFFSET as usize..].copy_from_slice(b"abcdef");
        backing
            .write_at(0, image, WriteOptions::SYNC)
            .await
            .unwrap();
        drop(backing);

        let (blob, len) = storage
            .open_atomic("atomic", b"lost_truncate")
            .await
            .unwrap();
        assert_eq!(len, 3);
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"abc");
        assert_eq!(blob.tag().await.unwrap(), [2; ATOMIC_BLOB_TAG_LEN]);
        assert_eq!(blob.append(b"XYZ").await.unwrap(), 3);
        blob.sync().await.unwrap();
        drop(blob);

        let (_, backing_len) = storage.open("atomic", b"lost_truncate").await.unwrap();
        assert_eq!(backing_len, DATA_OFFSET + 6);
    });
}

#[test]
fn payload_beyond_the_root_region_is_not_converted() {
    deterministic::Runner::default().start(|context| async move {
        let (ordinary, _) = context.open("ordinary", b"zero_prefix").await.unwrap();
        ordinary.resize(DATA_OFFSET + 1).await.unwrap();
        ordinary
            .write_at(DATA_OFFSET, b"x", WriteOptions::SYNC)
            .await
            .unwrap();
        drop(ordinary);

        let error = context
            .open_atomic("ordinary", b"zero_prefix")
            .await
            .err()
            .expect("data beyond a zero atomic prefix must be rejected");
        assert!(is_blob_corrupt(&error));
        let (ordinary, len) = context.open("ordinary", b"zero_prefix").await.unwrap();
        assert_eq!(len, DATA_OFFSET + 1);
        assert_eq!(
            ordinary.read_at(DATA_OFFSET, 1).await.unwrap().coalesce(),
            b"x"
        );
    });
}

#[test]
fn ordinary_zero_payload_requires_explicit_migration() {
    deterministic::Runner::default().start(|context| async move {
        for (partition, name) in [
            ("ordinary_zero_open", b"open".as_slice()),
            ("ordinary_zero_scan", b"scan".as_slice()),
        ] {
            let (ordinary, _) = context.open(partition, name).await.unwrap();
            ordinary
                .write_at(0, b"\0", WriteOptions::SYNC)
                .await
                .unwrap();
            drop(ordinary);
        }

        let error = context
            .open_atomic("ordinary_zero_open", b"open")
            .await
            .err()
            .expect("an existing ordinary blob must not be converted implicitly");
        assert!(is_blob_corrupt(&error));
        assert!(context.scan_atomic("ordinary_zero_scan").await.is_err());

        for (partition, name) in [
            ("ordinary_zero_open", b"open".as_slice()),
            ("ordinary_zero_scan", b"scan".as_slice()),
        ] {
            let (ordinary, len) = context.open(partition, name).await.unwrap();
            assert_eq!(len, 1);
            assert_eq!(ordinary.read_at(0, 1).await.unwrap().coalesce(), b"\0");
        }

        let (ordinary, _) = context.open("ordinary_zero_open", b"open").await.unwrap();
        context.migrate_atomic(ordinary).await.unwrap();
        let (atomic, len) = context
            .open_atomic("ordinary_zero_open", b"open")
            .await
            .unwrap();
        assert_eq!(len, 1);
        assert_eq!(atomic.read_at(0, 1).await.unwrap().coalesce(), b"\0");
    });
}

#[test]
fn native_backing_with_payload_but_no_identity_is_corrupt() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (backing, _) = storage.open("missing_identity", b"blob").await.unwrap();
        backing.resize(DATA_OFFSET + 1).await.unwrap();
        backing.sync().await.unwrap();
        drop(backing);

        assert!(
            storage
                .open_atomic("missing_identity", b"blob")
                .await
                .is_err()
        );
    });
}

#[test]
fn corrupt_full_root_region_is_not_reinitialized() {
    deterministic::Runner::default().start(|context| async move {
        let (ordinary, _) = context.open("ordinary", b"full_root").await.unwrap();
        ordinary.resize(DATA_OFFSET).await.unwrap();
        ordinary
            .write_at(IDENTITY_PAGE_LEN, &[0xFF], WriteOptions::SYNC)
            .await
            .unwrap();
        drop(ordinary);

        let error = context
            .open_atomic("ordinary", b"full_root")
            .await
            .err()
            .expect("corrupt roots must be rejected");
        assert!(is_blob_corrupt(&error));
        assert!(!is_offset_overflow(&error));

        let (ordinary, _) = context.open("ordinary", b"surplus_root").await.unwrap();
        ordinary.resize(DATA_OFFSET + 1).await.unwrap();
        ordinary
            .write_at(IDENTITY_PAGE_LEN, &[0xFF], WriteOptions::SYNC)
            .await
            .unwrap();
        drop(ordinary);
        let error = context
            .open_atomic("ordinary", b"surplus_root")
            .await
            .err()
            .expect("corrupt roots with a physical surplus must be rejected");
        assert!(is_blob_corrupt(&error));
    });
}

#[test]
fn atomic_open_reclaims_a_tombstone_before_recreating_the_name() {
    deterministic::Runner::default().start(|context| async move {
        let partition = "atomic_tombstone_open";
        let (ordinary, _, version) = context
            .open_versioned(partition, b"blob", 7..=7)
            .await
            .unwrap();
        assert_eq!(version, 7);
        context.migrate_atomic(ordinary).await.unwrap();
        let (removed, _) = context.open_atomic(partition, b"blob").await.unwrap();
        let removed_incarnation = removed.incarnation;
        removed.append(b"old").await.unwrap();
        removed.sync().await.unwrap();
        let participant = batch::Participant {
            partition: partition.into(),
            name: b"blob".to_vec(),
            incarnation: removed.incarnation,
            candidate: batch::Candidate::new(Root::unbound(3, 3, [0; ATOMIC_BLOB_TAG_LEN]))
                .unwrap(),
            removed: true,
        };
        let prepared = batch::prepare(vec![participant.clone()]).unwrap();
        let prepared_participant = &prepared.participants[0];
        removed
            .backing
            .write_at(
                prepared_participant.candidate.root_offset().unwrap(),
                prepared.slots[0].to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
        removed
            .backing
            .write_at(
                prepared_participant.candidate.root_offset().unwrap(),
                prepared_participant
                    .candidate
                    .final_root()
                    .unwrap()
                    .to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
        drop(removed);

        let (replacement, len) = context.open_atomic(partition, b"blob").await.unwrap();
        assert_eq!(len, 0);
        assert_ne!(replacement.incarnation, removed_incarnation);
    });
}

#[test]
fn fresh_blob_uses_the_canonical_zero_predecessor() {
    deterministic::Runner::default().start(|context| async move {
        let (blob, len) = context
            .open_atomic("atomic", b"zero_predecessor")
            .await
            .unwrap();
        assert_eq!(len, 0);
        drop(blob);

        let (backing, backing_len) = context.open("atomic", b"zero_predecessor").await.unwrap();
        assert_eq!(backing_len, DATA_OFFSET);
        let identity = backing
            .read_at(0, IDENTITY_PAGE_LEN as usize)
            .await
            .unwrap()
            .coalesce();
        assert!(decode_identity(identity.as_ref().try_into().unwrap()).is_some());
        assert!(
            backing
                .read_at(
                    IDENTITY_PAGE_LEN,
                    (DATA_OFFSET - IDENTITY_PAGE_LEN) as usize,
                )
                .await
                .unwrap()
                .coalesce()
                .as_ref()
                .iter()
                .all(|byte| *byte == 0)
        );
        drop(backing);

        let (blob, _) = context
            .open_atomic("atomic", b"zero_predecessor")
            .await
            .unwrap();
        blob.append_tagged(b"first", [1; ATOMIC_BLOB_TAG_LEN])
            .await
            .unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (backing, _) = context.open("atomic", b"zero_predecessor").await.unwrap();
        let slot = backing
            .read_at(ROOT_OFFSETS[1], ROOT_SLOT_SIZE)
            .await
            .unwrap()
            .coalesce();
        let link = batch::link(slot.as_ref(), "atomic", b"zero_predecessor").unwrap();
        let candidate = link.participant.candidate.root().unwrap();
        assert_eq!(link.participant.candidate.base_generation().unwrap(), 0);
        assert_eq!(candidate.generation, 1);
        assert_eq!(candidate.logical_len, 5);
        assert_eq!(link.next.partition, "atomic");
        assert_eq!(link.next.name, b"zero_predecessor");
        assert_eq!(link.next.incarnation, link.participant.incarnation);
    });
}

#[test]
fn open_error_mapping_covers_truncated_and_unrelated_failures() {
    let truncated = map_open_error(
        "partition",
        b"blob",
        io::Error::new(io::ErrorKind::UnexpectedEof, "truncated roots").into(),
    );
    assert!(is_blob_corrupt(&truncated));

    let denied = map_open_error(
        "partition",
        b"blob",
        io::Error::new(io::ErrorKind::PermissionDenied, "denied").into(),
    );
    assert_eq!(io_kind(&denied), Some(io::ErrorKind::PermissionDenied));

    let overflow = map_open_error("partition", b"blob", Error::OffsetOverflow);
    assert!(is_offset_overflow(&overflow));
}

#[test]
fn partial_initial_resize_is_not_reclassified_as_atomic() {
    let (_, checkpoint) =
        deterministic::Runner::seeded(7).start_and_recover(|context| async move {
            *context.storage_fault_config().write() =
                FaultConfig::default().resize(1.0).partial_resize(1.0);
            assert!(context.open_atomic("atomic_init", b"blob").await.is_err());
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        *context.storage_fault_config().write() = FaultConfig::default();
        let (backing, before_len) = context.open("atomic_init", b"blob").await.unwrap();
        let before = backing
            .read_at(0, before_len as usize)
            .await
            .unwrap()
            .coalesce();
        drop(backing);

        let error = context
            .open_atomic("atomic_init", b"blob")
            .await
            .err()
            .expect("a partial pre-existing identity must be rejected");
        assert!(is_blob_corrupt(&error));
        let (backing, after_len) = context.open("atomic_init", b"blob").await.unwrap();
        assert_eq!(after_len, before_len);
        let after = backing
            .read_at(0, after_len as usize)
            .await
            .unwrap()
            .coalesce();
        assert_eq!(after.as_ref(), before.as_ref());
    });
}

#[test]
fn full_length_nonprefix_first_candidate_is_consumed() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (initialized, _) = storage
            .open_atomic("atomic_init", b"nonprefix")
            .await
            .unwrap();
        drop(initialized);
        let (backing, _) = storage.open("atomic_init", b"nonprefix").await.unwrap();

        let initial = root_slot(encode_root(
            RootState::Committed,
            1,
            0,
            [0; ATOMIC_BLOB_TAG_LEN],
        ));
        for (index, byte) in initial.iter().copied().enumerate() {
            if byte != 0 && index % 2 == 0 {
                backing
                    .write_at(
                        ROOT_OFFSETS[1] + index as u64,
                        [byte].to_vec(),
                        WriteOptions::default(),
                    )
                    .await
                    .unwrap();
            }
        }
        backing.sync().await.unwrap();
        drop(backing);

        let (blob, len) = storage
            .open_atomic("atomic_init", b"nonprefix")
            .await
            .unwrap();
        assert_eq!(len, 0);
        blob.append(b"ready").await.unwrap();
        let state = blob.state.lock().await;
        let prepared = state.prepare_commit().unwrap().unwrap();
        assert_eq!(prepared.generation, 1);
        assert_eq!(prepared.root_offset, ROOT_OFFSETS[1]);
    });
}

#[test]
fn failed_publication_poisons_the_handle_and_recovers_the_old_root() {
    let (_, checkpoint) =
        deterministic::Runner::default().start_and_recover(|context| async move {
            let (blob, _) = context.open_atomic("atomic_fault", b"blob").await.unwrap();
            blob.append_tagged(b"old", [1; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            blob.sync().await.unwrap();
        });

    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            let (blob, _) = context.open_atomic("atomic_fault", b"blob").await.unwrap();
            blob.append_tagged(b"-new", [2; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            let clone = blob.clone();

            *context.storage_fault_config().write() = FaultConfig {
                sync_rate: Some(1.0),
                ..FaultConfig::default()
            };
            assert!(blob.sync().await.is_err());
            assert!(blob.append(b"poisoned").await.is_err());
            assert!(clone.read_at(0, 0).await.is_err());
            assert!(clone.tag().await.is_err());
            assert!(clone.append(b"poisoned clone").await.is_err());
            assert!(clone.rewind(0).await.is_err());
            assert!(clone.sync().await.is_err());
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        *context.storage_fault_config().write() = FaultConfig::default();
        let (blob, len) = context.open_atomic("atomic_fault", b"blob").await.unwrap();
        assert_eq!(len, 3);
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert_eq!(blob.tag().await.unwrap(), [1; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[test]
fn canceling_an_admitted_publication_poisons_every_clone() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (initialized, _) = storage.open_atomic("atomic_cancel", b"blob").await.unwrap();
        let incarnation = initialized.incarnation;
        drop(initialized);
        let (backing, backing_len) = storage.open("atomic_cancel", b"blob").await.unwrap();
        let (backing, pending) = DelayedSyncBlob::new(backing);
        let (blob, _) = Blob::open_named(
            backing,
            "atomic_cancel",
            b"blob",
            backing_len,
            incarnation,
            test_token_epoch(),
            test_resources(),
        )
        .await
        .unwrap();
        blob.append(b"candidate").await.unwrap();
        let clone = blob.clone();

        pending.arm();
        let deferred = next_pending_sync(&pending);
        let mut publish = Box::pin(blob.sync());
        assert!(
            publish.as_mut().now_or_never().is_none(),
            "publication must reach the gated whole-blob barrier"
        );
        deferred
            .blocked
            .await
            .expect("publication never entered the backing barrier");
        drop(publish);

        assert!(clone.read_at(0, 0).await.is_err());
        assert!(clone.tag().await.is_err());
        assert!(clone.append(b"x").await.is_err());
        assert!(clone.rewind(0).await.is_err());
        assert!(clone.sync().await.is_err());
        assert!(deferred.release.send(Ok(())).is_err());

        // The canceled wrapper still contains volatile readable bytes. A real reopen obtains
        // a fresh handle from durable storage, where neither the candidate payload nor its
        // bound slot survived the canceled barrier.
        drop(clone);
        drop(blob);
        let (recovered, len) = storage.open_atomic("atomic_cancel", b"blob").await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(recovered.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn publications_with_shared_carried_debt_serialize() {
    futures::executor::block_on(async move {
        let (blobs, pending) = disjoint_delayed_blobs().await;
        let _carried = install_test_carried_group(&blobs, [7; batch::GROUP_ID_LEN]).await;

        pending[0].arm();
        pending[1].arm();
        let first_a = next_pending_sync(&pending[0]);
        let first_b = next_pending_sync(&pending[1]);
        let mut first = Box::pin(blobs[0].sync());
        assert!(first.as_mut().now_or_never().is_none());
        first_a
            .blocked
            .await
            .expect("publication never reached its own backing barrier");
        first_b
            .blocked
            .await
            .expect("publication never reached its carried peer's barrier");

        let mut second = Box::pin(blobs[1].sync());
        assert!(second.as_mut().now_or_never().is_none());
        assert_eq!(pending[0].calls(), 1);
        assert_eq!(pending[1].calls(), 1);

        first_a.release.send(Ok(())).unwrap();
        first_b.release.send(Ok(())).unwrap();
        first.await.unwrap();

        second
            .as_mut()
            .now_or_never()
            .expect("publication did not resume after shared debt was discharged")
            .unwrap();
        assert_eq!(pending[0].calls(), 1);
        assert_eq!(pending[1].calls(), 2);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn carried_peer_preflush_does_not_overlap_cleanup_barrier() {
    futures::executor::block_on(async move {
        let (mut blobs, pending) = disjoint_delayed_blobs().await;
        let _carried = install_test_carried_group(&blobs, [8; batch::GROUP_ID_LEN]).await;
        blobs[1].driver = Driver::background();

        pending[1].arm();
        let preflush = next_pending_sync(&pending[1]);
        blobs[1].request_payload_preflush(1).await.unwrap();
        preflush.blocked.await.unwrap();

        let mut publication = Box::pin(blobs[0].sync());
        assert!(publication.as_mut().now_or_never().is_none());
        assert_eq!(pending[1].calls(), 1);

        preflush.release.send(Ok(())).unwrap();
        publication.await.unwrap();
        blobs[1].drain_payload_preflush().await.unwrap();
        assert_eq!(pending[1].calls(), 2);
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn disjoint_direct_publications_reach_their_barriers_concurrently() {
    futures::executor::block_on(async move {
        let (blobs, pending) = disjoint_delayed_blobs().await;

        pending[0].arm();
        let first_sync = next_pending_sync(&pending[0]);
        let mut first = Box::pin(blobs[0].sync());
        assert!(first.as_mut().now_or_never().is_none());
        first_sync
            .blocked
            .await
            .expect("first publication never reached its backing barrier");

        pending[1].arm();
        let second_sync = next_pending_sync(&pending[1]);
        let mut second_blocked = Box::pin(second_sync.blocked);
        let mut second = Box::pin(blobs[1].sync());
        assert!(second.as_mut().now_or_never().is_none());
        assert!(
            second_blocked.as_mut().now_or_never().is_some(),
            "a disjoint publication was blocked behind another path's barrier"
        );

        first_sync.release.send(Ok(())).unwrap();
        second_sync.release.send(Ok(())).unwrap();
        first.await.unwrap();
        second.await.unwrap();
    });
}

#[cfg(not(target_arch = "wasm32"))]
#[tokio::test]
async fn background_start_sync_waits_for_the_publication_linearization_point() {
    let storage = memory::Storage::new(test_pool());
    let (mut blob, _) = storage
        .open_atomic("start_sync_admission", b"blob")
        .await
        .unwrap();
    blob.append(b"candidate").await.unwrap();
    blob.driver = Driver::background();

    let publication_guard = blob.operation.clone().lock_owned().await;
    let mut start = Box::pin(blob.start_sync());
    assert!(
        start.as_mut().now_or_never().is_none(),
        "start_sync must not return while publication is blocked before its state snapshot"
    );

    drop(publication_guard);
    let completion = start.await;
    blob.set_tag([9; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
    completion.await.unwrap();
    drop(blob);

    let (reopened, len) = storage
        .open_atomic("start_sync_admission", b"blob")
        .await
        .unwrap();
    assert_eq!(len, 9);
    assert_eq!(reopened.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);
}

#[test]
fn inline_start_sync_waits_for_carried_coordination() {
    futures::executor::block_on(async move {
        let storage = memory::Storage::new(test_pool());
        let (first, _) = storage
            .open_atomic("inline_start_sync", b"first")
            .await
            .unwrap();
        let (second, _) = storage
            .open_atomic("inline_start_sync", b"second")
            .await
            .unwrap();
        first.append(b"first").await.unwrap();
        second.append(b"second").await.unwrap();
        storage
            .apply(vec![
                BatchOperation::Publish(first.clone()),
                BatchOperation::Publish(second.clone()),
            ])
            .await
            .unwrap();

        second.append(b"-next").await.unwrap();
        let carried = second
            .carried
            .lock()
            .await
            .clone()
            .expect("a multi-blob publication installs shared cleanup debt");
        let coordination = carried.coordination.lock().await;
        let mut start = Box::pin(second.start_sync());
        assert!(start.as_mut().now_or_never().is_none());
        assert!(
            start.as_mut().now_or_never().is_none(),
            "inline start_sync returned an observer that still owned publication work"
        );

        drop(coordination);
        start.await.await.unwrap();
        assert_eq!(second.state.lock().await.committed.logical_len, 11);
    });
}

#[test]
fn inline_start_apply_finishes_before_returning_completion_observer() {
    futures::executor::block_on(async move {
        let gate = FinalRootGate::default();
        let storage = FinalRootGateStorage::new(memory::Storage::new(test_pool()), gate.clone());
        let (blob, _) = storage
            .open_atomic("inline_start_apply", b"blob")
            .await
            .unwrap();
        blob.append(b"candidate").await.unwrap();

        let (entered, release) = gate.arm();
        let mut start = Box::pin(storage.start_apply(vec![BatchOperation::Publish(blob.clone())]));
        assert!(start.as_mut().now_or_never().is_none());
        entered.await.unwrap();
        assert!(
            start.as_mut().now_or_never().is_none(),
            "inline start_apply returned an observer that still owned finalization"
        );

        release.send(()).unwrap();
        let completion = start.await.unwrap();
        drop(completion);
        blob.set_tag([9; ATOMIC_BLOB_TAG_LEN]).await.unwrap();
        assert_eq!(blob.tag().await.unwrap(), [9; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[tokio::test]
async fn canceled_admitted_batch_fences_reopen() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    let directory = std::env::temp_dir().join(format!(
        "commonware_runtime_atomic_cancel_batch_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let storage = tokio_storage::Storage::new(
        tokio_storage::Config::new(directory.clone(), 2 * 1024 * 1024),
        test_pool(),
    );

    let (blob, _) = storage
        .open_atomic("canceled_batch_open", b"blob")
        .await
        .unwrap();
    blob.append(b"old").await.unwrap();
    blob.sync().await.unwrap();
    blob.set_tag([1; ATOMIC_BLOB_TAG_LEN]).await.unwrap();

    let resources = Backend::atomic_resources(&storage);
    let (entered, resume) = pause_next_admitted_operation(&resources.exclusion);
    let batch_storage = storage.clone();
    let start = tokio::spawn(async move {
        batch_storage
            .start_apply(vec![BatchOperation::Publish(blob)])
            .await
    });
    entered.await.unwrap();
    start.abort();
    let _ = start.await;
    assert!(
        resources.exclusion.clone().try_write_owned().is_err(),
        "admitted batch did not transfer its lineage guard before cancellation"
    );

    resume.send(()).unwrap();
    let (reopened, len) = storage
        .open_atomic("canceled_batch_open", b"blob")
        .await
        .unwrap();
    assert_eq!(len, 3);
    assert_eq!(reopened.tag().await.unwrap(), [1; ATOMIC_BLOB_TAG_LEN]);

    drop((reopened, storage));
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[tokio::test]
async fn canceled_admitted_migration_fences_ordinary_retry_open() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    let directory = std::env::temp_dir().join(format!(
        "commonware_runtime_atomic_cancel_migration_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let storage = tokio_storage::Storage::new(
        tokio_storage::Config::new(directory.clone(), 2 * 1024 * 1024),
        test_pool(),
    );
    let (ordinary, _) = storage
        .open("canceled_migration_open", b"blob")
        .await
        .unwrap();
    ordinary
        .write_at(0, b"old", WriteOptions::SYNC)
        .await
        .unwrap();

    let resources = Backend::atomic_resources(&storage);
    let (entered, resume) = pause_next_admitted_operation(&resources.exclusion);
    let migration_storage = storage.clone();
    let migration = tokio::spawn(async move { migration_storage.migrate_atomic(ordinary).await });
    entered.await.unwrap();
    migration.abort();
    let _ = migration.await;
    assert!(
        resources.exclusion.clone().try_write_owned().is_err(),
        "admitted migration did not retain its atomic lineage guard"
    );

    let namespace_was_fenced = resources.namespace.try_lock().is_err();
    let retry_storage = storage.clone();
    let retry = tokio::spawn(async move {
        let (blob, len) = retry_storage
            .open("canceled_migration_open", b"blob")
            .await
            .unwrap();
        (blob, len)
    });
    tokio::task::yield_now().await;
    let retry_was_blocked = !retry.is_finished();

    resume.send(()).unwrap();
    let (retry_blob, retry_len) = retry.await.unwrap();
    let retry_result = storage.migrate_atomic(retry_blob).await;
    let (atomic, len) = storage
        .open_atomic("canceled_migration_open", b"blob")
        .await
        .unwrap();
    assert_eq!(len, 3);
    assert_eq!(atomic.read_at(0, 3).await.unwrap().coalesce(), b"old");
    drop((atomic, storage));
    std::fs::remove_dir_all(&directory).unwrap();

    assert!(
        namespace_was_fenced,
        "admitted migration did not own the ordinary namespace before observer cancellation"
    );
    assert!(
        retry_was_blocked,
        "an ordinary retry open overtook an admitted migration"
    );
    assert_eq!(retry_len, DATA_OFFSET + 3);
    retry_result.unwrap();
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage")))]
#[tokio::test]
async fn foreground_capacity_precedes_lineage_ownership() {
    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    let directory = std::env::temp_dir().join(format!(
        "commonware_runtime_atomic_admission_order_{}_{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&directory);
    let storage = tokio_storage::Storage::new(
        tokio_storage::Config::new(directory.clone(), 2 * 1024 * 1024),
        test_pool(),
    );
    let resources = Backend::atomic_resources(&storage);
    let lineage = resources.exclusion.clone();
    let blocker = lineage.clone().read_owned().await;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let mut admitted = Vec::with_capacity(DRIVER_ADMISSION_CAPACITY);
    for _ in 0..DRIVER_ADMISSION_CAPACITY {
        let lineage = lineage.clone();
        let gate = gate.clone();
        let permit = resources.driver.reserve().await.unwrap();
        admitted.push(permit.drive(async move {
            drop(gate.acquire().await.unwrap());
            drop(lineage.write_owned().await);
            Ok::<_, Error>(())
        }));
    }

    let mut batch = Box::pin(storage.start_apply(Vec::new()));
    assert!(futures::poll!(batch.as_mut()).is_pending());
    gate.add_permits(DRIVER_ADMISSION_CAPACITY);
    drop(blocker);

    let completion = tokio::time::timeout(std::time::Duration::from_secs(5), batch)
        .await
        .expect("foreground admission deadlocked with lineage ownership")
        .unwrap();
    completion.await.unwrap();
    for handle in admitted {
        handle.await.unwrap();
    }

    drop(storage);
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn atomic_locations_are_rejected_before_creation_or_migration() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let partition = "p";
        let max_name_len = batch::MAX_LOCATION_LEN - partition.len();
        let max = vec![b'a'; max_name_len];
        let oversized = vec![b'b'; max_name_len + 1];

        let (blob, _) = storage.open_atomic(partition, &max).await.unwrap();
        blob.append(b"x").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let error = match storage.open_atomic(partition, &oversized).await {
            Err(error) => error,
            Ok(_) => panic!("oversized atomic location was created"),
        };
        assert_eq!(io_kind(&error), Some(io::ErrorKind::InvalidInput));
        assert!(!storage.scan(partition).await.unwrap().contains(&oversized));

        let migrated_max = vec![b'c'; max_name_len];
        let (ordinary, _) = storage.open(partition, &migrated_max).await.unwrap();
        ordinary
            .write_at(0, b"ordinary", WriteOptions::SYNC)
            .await
            .unwrap();
        storage.migrate_atomic(ordinary).await.unwrap();
        let (blob, _) = storage.open_atomic(partition, &migrated_max).await.unwrap();
        blob.append(b"!").await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (ordinary, _) = storage.open(partition, &oversized).await.unwrap();
        ordinary
            .write_at(0, b"ordinary", WriteOptions::SYNC)
            .await
            .unwrap();
        let error = storage.migrate_atomic(ordinary).await.unwrap_err();
        assert_eq!(io_kind(&error), Some(io::ErrorKind::InvalidInput));
        let (ordinary, len) = storage.open(partition, &oversized).await.unwrap();
        assert_eq!(len, 8);
        assert_eq!(
            ordinary.read_at(0, 8).await.unwrap().coalesce(),
            b"ordinary"
        );
    });
}

#[test]
fn subset_payload_write_fault_recovers_the_published_prefix() {
    let (_, checkpoint) =
        deterministic::Runner::seeded(17).start_and_recover(|context| async move {
            let (blob, _) = context
                .open_atomic("atomic_subset", b"payload")
                .await
                .unwrap();
            blob.append_tagged(b"old", [1; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            blob.sync().await.unwrap();
        });

    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            let (blob, _) = context
                .open_atomic("atomic_subset", b"payload")
                .await
                .unwrap();
            *context.storage_fault_config().write() = FaultConfig::default()
                .write(1.0)
                .write_retention(PartialWriteMode::Subset, 0.5);

            assert!(blob.append(b"-discarded").await.is_err());
            assert!(blob.tag().await.is_err());
            assert!(blob.read_at(0, 0).await.is_err());
            assert!(blob.set_tag([3; ATOMIC_BLOB_TAG_LEN]).await.is_err());
            assert!(blob.rewind(3).await.is_err());
            assert!(blob.sync().await.is_err());
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        *context.storage_fault_config().write() = FaultConfig::default();
        let (blob, len) = context
            .open_atomic("atomic_subset", b"payload")
            .await
            .unwrap();
        assert_eq!(len, 3);
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert_eq!(blob.tag().await.unwrap(), [1; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[test]
fn subset_payload_write_after_rewind_recovers_the_rewound_root() {
    let (_, checkpoint) = deterministic::Runner::seeded(11856441296640707210).start_and_recover(
        |context| async move {
            context
                .open_atomic("atomic_subset_rewind", b"payload")
                .await
                .unwrap();
        },
    );

    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            let (blob, _) = context
                .open_atomic("atomic_subset_rewind", b"payload")
                .await
                .unwrap();
            blob.append(b"older").await.unwrap();
            blob.sync().await.unwrap();
            blob.rewind_tagged(0, [7; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            blob.sync().await.unwrap();

            *context.storage_fault_config().write() = FaultConfig::default()
                .write(1.0)
                .write_retention(PartialWriteMode::Subset, 0.5);
            assert!(
                blob.append_tagged(b"yy", [9; ATOMIC_BLOB_TAG_LEN])
                    .await
                    .is_err()
            );
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        *context.storage_fault_config().write() = FaultConfig::default();
        assert_eq!(
            context.scan_atomic("atomic_subset_rewind").await.unwrap(),
            [b"payload".to_vec()]
        );
        let (blob, len) = context
            .open_atomic("atomic_subset_rewind", b"payload")
            .await
            .unwrap();
        assert_eq!(len, 0);
        assert_eq!(blob.tag().await.unwrap(), [7; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[test]
fn subset_prepare_and_clear_faults_are_retryable() {
    let (_, checkpoint) =
        deterministic::Runner::seeded(29).start_and_recover(|context| async move {
            let (blob, _) = context
                .open_atomic("atomic_subset", b"repair")
                .await
                .unwrap();
            blob.append_tagged(b"old", [1; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            blob.sync().await.unwrap();
        });

    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            let (blob, _) = context
                .open_atomic("atomic_subset", b"repair")
                .await
                .unwrap();
            blob.append_tagged(b"-candidate", [2; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            *context.storage_fault_config().write() = FaultConfig::default()
                .write(1.0)
                .write_retention(PartialWriteMode::Subset, 0.5);
            assert!(blob.sync().await.is_err());
        });

    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            *context.storage_fault_config().write() = FaultConfig::default()
                .write(1.0)
                .write_retention(PartialWriteMode::Subset, 0.5);
            assert!(
                context
                    .open_atomic("atomic_subset", b"repair")
                    .await
                    .is_err()
            );
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        *context.storage_fault_config().write() = FaultConfig::default();
        let (blob, len) = context
            .open_atomic("atomic_subset", b"repair")
            .await
            .unwrap();
        assert_eq!(len, 3);
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"old");
        assert_eq!(blob.tag().await.unwrap(), [1; ATOMIC_BLOB_TAG_LEN]);

        blob.append_tagged(b"-next", [3; ATOMIC_BLOB_TAG_LEN])
            .await
            .unwrap();
        blob.sync().await.unwrap();
    });
}

#[test]
fn committed_rewind_survives_a_failed_post_root_resize() {
    let (_, checkpoint) =
        deterministic::Runner::seeded(31).start_and_recover(|context| async move {
            let (blob, _) = context
                .open_atomic("atomic_fault", b"resize")
                .await
                .unwrap();
            blob.append(b"abcdef").await.unwrap();
            blob.sync().await.unwrap();
        });

    let (_, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|context| async move {
            let (blob, _) = context
                .open_atomic("atomic_fault", b"resize")
                .await
                .unwrap();
            blob.rewind_tagged(3, [3; ATOMIC_BLOB_TAG_LEN])
                .await
                .unwrap();
            *context.storage_fault_config().write() = FaultConfig::default().resize(1.0);
            assert!(blob.sync().await.is_err());
            assert!(blob.read_at(0, 1).await.is_err());
        });

    deterministic::Runner::from(checkpoint).start(|context| async move {
        *context.storage_fault_config().write() = FaultConfig::default();
        let (blob, len) = context
            .open_atomic("atomic_fault", b"resize")
            .await
            .unwrap();
        assert_eq!(len, 3);
        assert_eq!(blob.read_at(0, 3).await.unwrap().coalesce(), b"abc");
        assert_eq!(blob.tag().await.unwrap(), [3; ATOMIC_BLOB_TAG_LEN]);

        assert_eq!(blob.append(b"XYZ").await.unwrap(), 3);
        blob.sync().await.unwrap();
        assert_eq!(blob.read_at(0, 6).await.unwrap().coalesce(), b"abcXYZ");
    });
}

fn root_slot(header: [u8; ROOT_LEN]) -> RootSlot {
    let mut slot = [0u8; ROOT_SLOT_SIZE];
    slot[..ROOT_LEN].copy_from_slice(&header);
    slot
}

fn finalized_slot(root: Root) -> RootSlot {
    finalized_slot_for(root, [0xA5; INCARNATION_LEN])
}

fn finalized_slot_for(root: Root, incarnation: [u8; INCARNATION_LEN]) -> RootSlot {
    finalized_slot_for_group(root, incarnation, [0xA5; batch::GROUP_ID_LEN])
}

fn finalized_slot_for_group(
    root: Root,
    incarnation: [u8; INCARNATION_LEN],
    group_id: [u8; batch::GROUP_ID_LEN],
) -> RootSlot {
    let prepared = batch::prepare_with_group_id(
        vec![batch::Participant {
            partition: "finalized_slot".into(),
            name: b"blob".to_vec(),
            incarnation,
            candidate: batch::Candidate::new(root).unwrap(),
            removed: false,
        }],
        group_id,
    )
    .unwrap();
    let mut slot = prepared.slots[0];
    slot[..ROOT_LEN].copy_from_slice(&prepared.participants[0].candidate.final_root().unwrap());
    slot
}

fn apply_recovery(backing_len: u64, mut slots: [RootSlot; ROOT_OFFSETS.len()]) -> State {
    if let Some(plan) = rejection_plan(backing_len, &slots).unwrap() {
        let index = ROOT_OFFSETS
            .iter()
            .position(|offset| *offset == plan.root_offset)
            .unwrap();
        slots[index].fill(0);
    }
    State::recover(backing_len, &slots).unwrap().0
}

fn representative_masks(len: usize) -> Vec<Vec<bool>> {
    let mut masks = (0..=len)
        .map(|prefix| (0..len).map(|index| index < prefix).collect())
        .collect::<Vec<_>>();
    for index in 0..len {
        masks.push((0..len).map(|candidate| candidate == index).collect());
        masks.push((0..len).map(|candidate| candidate != index).collect());
    }
    masks.push((0..len).map(|index| index % 2 == 0).collect());
    masks.push((0..len).map(|index| index % 3 == 1).collect());
    masks.push((0..len).map(|index| index.count_ones() % 2 == 0).collect());
    masks
}

#[test]
fn incomplete_batch_candidate_subsets_never_publish() {
    let old_tag = [1; ATOMIC_BLOB_TAG_LEN];
    let new_tag = [2; ATOMIC_BLOB_TAG_LEN];
    let old = encode_root(RootState::Committed, 1, 3, old_tag);
    let prepared = encode_root(RootState::BatchPrepared, 2, 7, new_tag);

    for (case, mask) in representative_masks(ROOT_LEN).iter().enumerate() {
        let mut torn = [0u8; ROOT_LEN];
        for (index, retained) in mask.iter().copied().enumerate() {
            if retained {
                torn[index] = prepared[index];
            }
        }
        let state = apply_recovery(DATA_OFFSET + 7, [root_slot(torn), root_slot(old)]);
        assert_eq!(state.logical_len, 3, "fresh target case {case}");
        assert_eq!(state.tag, old_tag, "fresh target case {case}");
    }

    // Repeat against a slot that still contains its generation h-2 image. The root checksum
    // and distinct prepared spelling must reject retained mosaics when a parity slot is reused.
    let authority = finalized_slot(Root::unbound(2, 4, old_tag));
    let stale = encode_root(RootState::Committed, 1, 4, old_tag);
    let prepared = encode_root(RootState::BatchPrepared, 3, 8, new_tag);
    for (case, mask) in representative_masks(ROOT_LEN).iter().enumerate() {
        let mut torn = stale;
        for (index, retained) in mask.iter().copied().enumerate() {
            if retained {
                torn[index] = prepared[index];
            }
        }
        let state = apply_recovery(DATA_OFFSET + 8, [authority, root_slot(torn)]);
        assert_eq!(state.logical_len, 4, "reused target case {case}");
        assert_eq!(state.tag, old_tag, "reused target case {case}");
    }
}

#[test]
fn partial_zero_clear_never_creates_new_authority() {
    let old_tag = [1; ATOMIC_BLOB_TAG_LEN];
    let incarnation = [7; INCARNATION_LEN];
    let authority = finalized_slot_for(Root::unbound(2, 4, old_tag), incarnation);
    let prepared = batch::prepare(vec![batch::Participant {
        partition: "partial_clear".into(),
        name: b"blob".to_vec(),
        incarnation,
        candidate: batch::Candidate::new(Root::unbound(3, 8, [2; ATOMIC_BLOB_TAG_LEN])).unwrap(),
        removed: false,
    }])
    .unwrap()
    .slots[0];

    for (case, mask) in representative_masks(ROOT_SLOT_SIZE).iter().enumerate() {
        let mut partially_cleared = prepared;
        for (index, cleared) in mask.iter().copied().enumerate() {
            if cleared {
                partially_cleared[index] = 0;
            }
        }
        let slots = [authority, partially_cleared];
        let plan = rejection_plan_for(DATA_OFFSET + 8, &slots, Some(&incarnation)).unwrap();
        if partially_cleared.iter().all(|byte| *byte == 0) {
            assert!(plan.is_none(), "case {case}");
        } else {
            assert_eq!(
                plan.expect("a partial clear remains non-authoritative")
                    .root_offset,
                ROOT_OFFSETS[1],
                "case {case}"
            );
        }
        let state = State::recover_for(
            DATA_OFFSET + 8,
            &slots,
            Some(&incarnation),
            test_token_epoch(),
        )
        .unwrap()
        .0;
        assert_eq!(state.committed.generation, 2, "case {case}");
        assert_eq!(state.logical_len, 4, "case {case}");
        assert_eq!(state.tag, old_tag, "case {case}");
    }
}

#[test]
fn old_final_header_with_a_new_batch_witness_is_consumed() {
    let incarnation = [7; INCARNATION_LEN];
    let participant = |generation| batch::Participant {
        partition: "foreign_witness".into(),
        name: b"blob".to_vec(),
        incarnation,
        candidate: batch::Candidate::new(Root::unbound(
            generation,
            generation,
            [generation as u8; ATOMIC_BLOB_TAG_LEN],
        ))
        .unwrap(),
        removed: false,
    };
    let old = batch::prepare(vec![participant(2)]).unwrap();
    let new = batch::prepare(vec![participant(4)]).unwrap();

    // The generation-4 prepared write may retain its complete wrapper while the same-parity
    // generation-2 Finalized header survives. The resulting slot is not the complete old
    // source and must be consumed before generation 4 can be admitted again.
    let mut mixed = new.slots[0];
    mixed[..ROOT_LEN].copy_from_slice(&old.participants[0].candidate.final_root().unwrap());
    let replacement_incarnation = [8; INCARNATION_LEN];
    let slots = [
        mixed,
        finalized_slot_for(
            Root::unbound(3, 3, [3; ATOMIC_BLOB_TAG_LEN]),
            replacement_incarnation,
        ),
    ];

    let plan = rejection_plan(DATA_OFFSET + 4, &slots)
        .unwrap()
        .expect("a foreign witness makes the old final spelling non-quiescent");
    assert_eq!(plan.root_offset, ROOT_OFFSETS[0]);

    let mut exact_old = old.slots[0];
    exact_old[..ROOT_LEN].copy_from_slice(&old.participants[0].candidate.final_root().unwrap());
    let slots = [exact_old, slots[1]];
    assert!(rejection_plan(DATA_OFFSET + 3, &slots).unwrap().is_none());
    assert!(
        rejection_plan_for(DATA_OFFSET + 3, &slots, Some(&replacement_incarnation))
            .unwrap()
            .is_some(),
        "a final witness from another incarnation is not a quiescent predecessor"
    );
}

#[test]
fn interrupted_batch_candidate_is_consumed_before_slot_reuse() {
    let old_tag = [1; ATOMIC_BLOB_TAG_LEN];
    let new_tag = [2; ATOMIC_BLOB_TAG_LEN];
    let old = encode_root(RootState::Committed, 1, 3, old_tag);
    let prepared = encode_root(RootState::BatchPrepared, 2, 7, new_tag);

    for prefix in 1..=ROOT_LEN {
        let mut torn = [0u8; ROOT_LEN];
        torn[..prefix].copy_from_slice(&prepared[..prefix]);
        let mut state = apply_recovery(DATA_OFFSET + 7, [root_slot(torn), root_slot(old)]);
        assert_eq!(state.logical_len, 3, "prefix {prefix}");
        assert_eq!(state.tag, old_tag, "prefix {prefix}");
        assert_eq!(state.committed.generation, 1, "prefix {prefix}");
        state.set_tag([3; ATOMIC_BLOB_TAG_LEN]).unwrap();
        let next = state.prepare_commit().unwrap().unwrap();
        assert_eq!(next.generation, 2);
        assert_eq!(next.root_offset, ROOT_OFFSETS[0]);
    }
}

#[test]
fn root_guards_distinguish_states_and_slot_reuse() {
    let guards = [
        RootState::BatchPrepared.guard(1),
        RootState::Committed.guard(1),
        RootState::Finalized.guard(1),
    ];
    assert_eq!(guards, [1, 2, 3]);
    assert_eq!(
        [1, 2, 3, 4].map(|generation| RootState::Finalized.guard(generation)),
        [3, 4, 4, 3],
    );
    for generation in 3..=8 {
        assert_ne!(
            RootState::Finalized.guard(generation),
            RootState::Finalized.guard(generation - 2),
        );
    }

    let mut wrong_state = encode_root(RootState::Committed, 1, 0, [0; ATOMIC_BLOB_TAG_LEN]);
    wrong_state[ROOT_GUARD_OFFSET] = RootState::Finalized.guard(1);
    let checksum = checksum(&[ROOT_DOMAIN, &wrong_state[..ROOT_BODY_LEN]]);
    wrong_state[ROOT_BODY_LEN..].copy_from_slice(&checksum.to_be_bytes());
    assert!(decode_root(&wrong_state, RootState::Committed).is_none());
}

#[test]
fn root_encoding_matches_the_r15_batch_grammar() {
    let tag = [0xA5; ATOMIC_BLOB_TAG_LEN];
    let prepared = encode_root(RootState::BatchPrepared, 1, 7, tag);
    let committed = encode_root(RootState::Committed, 1, 7, tag);
    let finalized = encode_root(RootState::Finalized, 1, 7, tag);

    assert_eq!(&prepared[..7], b"CWUNO15");
    assert_eq!(prepared[ROOT_GUARD_OFFSET], 1);
    assert_eq!(committed[ROOT_GUARD_OFFSET], 2);
    assert_eq!(finalized[ROOT_GUARD_OFFSET], 3);
    assert_eq!(&prepared[24..ROOT_PREFIX_LEN], &[0; ROOT_PREFIX_LEN - 24]);
    assert_eq!(&prepared[ROOT_PREFIX_LEN..ROOT_BODY_LEN], &tag);
    assert_eq!(
        u32::from_be_bytes(prepared[ROOT_BODY_LEN..ROOT_LEN].try_into().unwrap()),
        checksum(&[ROOT_DOMAIN, &prepared[..ROOT_BODY_LEN]])
    );
    assert_eq!(ROOT_LEN, 132);
}

#[test]
fn first_generation_batch_candidate_is_consumed_from_zero() {
    let prepared = root_slot(encode_root(
        RootState::BatchPrepared,
        1,
        0,
        [0; ATOMIC_BLOB_TAG_LEN],
    ));
    let slots = [[0; ROOT_SLOT_SIZE], prepared];

    let plan = rejection_plan(DATA_OFFSET, &slots)
        .unwrap()
        .expect("a first-generation batch candidate must be consumed");
    assert_eq!(plan.root_offset, ROOT_OFFSETS[1]);
}

#[test]
fn incomplete_slot_clear_preserves_the_predecessor() {
    let old_tag = [1; ATOMIC_BLOB_TAG_LEN];
    let old = root_slot(encode_root(RootState::Committed, 1, 3, old_tag));
    let mut slots = [[0u8; ROOT_SLOT_SIZE], old];
    slots[0][0] = 0x5A;
    let plan = rejection_plan(DATA_OFFSET + 3, &slots).unwrap().unwrap();
    assert_eq!(plan.root_offset, ROOT_OFFSETS[0]);

    slots[0][0] = 0;
    let selected = State::recover(DATA_OFFSET + 3, &slots).unwrap().0;
    assert_eq!(selected.committed.generation, 1);
    assert_eq!(selected.logical_len, 3);
    assert_eq!(selected.tag, old_tag);
    assert!(rejection_plan(DATA_OFFSET + 3, &slots).unwrap().is_none());
}

#[test]
fn rejected_suffix_over_an_exact_old_root_is_consumed() {
    let tag = [1; ATOMIC_BLOB_TAG_LEN];
    let mut stale = root_slot(encode_root(RootState::Committed, 1, 0, tag));
    stale[ROOT_LEN] = 0x5A;
    let authority = finalized_slot(Root::unbound(2, 0, tag));
    let slots = [authority, stale];

    let plan = rejection_plan(DATA_OFFSET, &slots)
        .unwrap()
        .expect("a partially replaced stale slot must be consumed");
    assert_eq!(plan.root_offset, ROOT_OFFSETS[1]);
}

#[test]
fn generation_exhaustion_is_read_only() {
    assert!(next_generation(u64::MAX).is_err());

    let tag = [7; ATOMIC_BLOB_TAG_LEN];
    let slots = [
        finalized_slot(Root::unbound(u64::MAX - 1, 1, tag)),
        finalized_slot(Root::unbound(u64::MAX, 1, tag)),
    ];
    assert!(rejection_plan(DATA_OFFSET + 1, &slots).unwrap().is_none());
    let mut state = State::recover(DATA_OFFSET + 1, &slots).unwrap().0;

    assert!(state.prepare_append(1).is_err());
    assert!(state.rewind(0).is_err());
    assert!(state.set_tag([8; ATOMIC_BLOB_TAG_LEN]).is_err());
    assert!(state.prepare_commit().unwrap().is_none());

    assert_eq!(state.prepare_append(0).unwrap().0, 1);
    state.rewind(1).unwrap();
    state.set_tag(tag).unwrap();

    state.tag = [8; ATOMIC_BLOB_TAG_LEN];
    assert!(state.prepare_commit().is_err());
}

#[test]
fn append_preflights_the_complete_translated_range() {
    let mut ordinary = State::default();
    assert_eq!(ordinary.prepare_append(1).unwrap(), (0, DATA_OFFSET, 1));

    let mut state = State {
        logical_len: u64::MAX - DATA_OFFSET,
        durable_len: u64::MAX - DATA_OFFSET,
        committed: Root::unbound(1, u64::MAX - DATA_OFFSET, [0; ATOMIC_BLOB_TAG_LEN]),
        tag: [0; ATOMIC_BLOB_TAG_LEN],
        poisoned: false,
        removed: false,
        ..State::default()
    };

    assert_eq!(raw_len(state.logical_len).unwrap(), u64::MAX);
    let error = state.prepare_append(1).unwrap_err();
    assert!(is_offset_overflow(&error));
    assert!(!is_blob_corrupt(&error));
    assert!(!state.is_dirty());

    state.logical_len = u64::MAX;
    state.committed.logical_len = u64::MAX;
    assert!(is_offset_overflow(&state.prepare_append(1).unwrap_err()));

    state.logical_len = u64::MAX - DATA_OFFSET + 1;
    state.committed.logical_len = state.logical_len;
    assert!(is_offset_overflow(&state.prepare_append(1).unwrap_err()));
}

#[test]
fn public_bounds_and_generation_errors_precede_backing_io() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (backing, _) = storage.open("bounds", b"blob").await.unwrap();
        let state = State {
            logical_len: u64::MAX,
            durable_len: u64::MAX,
            committed: Root::unbound(u64::MAX, u64::MAX, [1; ATOMIC_BLOB_TAG_LEN]),
            tag: [1; ATOMIC_BLOB_TAG_LEN],
            poisoned: false,
            removed: false,
            ..State::default()
        };
        let blob = Blob {
            backing: backing.clone(),
            partition: Arc::from("bounds"),
            name: Arc::from(b"blob".as_slice()),
            incarnation: [1; INCARNATION_LEN],
            state: Arc::new(Mutex::new(state)),
            payload: PayloadAccount::new(Arc::new(PayloadBudget::default())),
            preflush: Arc::new(PayloadPreflush::default()),
            carried: Arc::new(Mutex::new(None)),
            driver: Driver::inline(),
            exclusion: Arc::new(RwLock::new(())),
            operation: Arc::new(Mutex::new(())),
        };

        assert!(is_offset_overflow(
            &blob.read_at(u64::MAX, 1).await.unwrap_err()
        ));
        assert!(is_offset_overflow(
            &blob.read_at(u64::MAX, 0).await.unwrap_err()
        ));
        assert!(blob.set_tag([2; ATOMIC_BLOB_TAG_LEN]).await.is_err());
        assert!(
            blob.append_tagged(Vec::<u8>::new(), [2; ATOMIC_BLOB_TAG_LEN])
                .await
                .is_err()
        );
        assert!(
            blob.rewind_tagged(u64::MAX, [2; ATOMIC_BLOB_TAG_LEN])
                .await
                .is_err()
        );
        assert_eq!(blob.tag().await.unwrap(), [1; ATOMIC_BLOB_TAG_LEN]);

        let dirty = Blob {
            backing,
            partition: Arc::from("bounds"),
            name: Arc::from(b"blob".as_slice()),
            incarnation: [1; INCARNATION_LEN],
            state: Arc::new(Mutex::new(State {
                logical_len: u64::MAX,
                durable_len: u64::MAX,
                committed: Root::unbound(u64::MAX, u64::MAX, [0; ATOMIC_BLOB_TAG_LEN]),
                tag: [1; ATOMIC_BLOB_TAG_LEN],
                poisoned: false,
                removed: false,
                ..State::default()
            })),
            payload: PayloadAccount::new(Arc::new(PayloadBudget::default())),
            preflush: Arc::new(PayloadPreflush::default()),
            carried: Arc::new(Mutex::new(None)),
            driver: Driver::inline(),
            exclusion: Arc::new(RwLock::new(())),
            operation: Arc::new(Mutex::new(())),
        };
        assert!(dirty.sync().await.is_err());
        assert_eq!(dirty.tag().await.unwrap(), [1; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[test]
fn rewind_dirty_state_accounts_for_a_pending_tag() {
    let mut integrity = State {
        logical_len: 5,
        integrity_scheme: IntegrityScheme::Variable,
        ..State::default()
    };
    assert!(integrity.rewind(3).is_err());

    let mut changed_tag = State {
        logical_len: 5,
        durable_len: 3,
        committed: Root::unbound(1, 3, [0; ATOMIC_BLOB_TAG_LEN]),
        tag: [1; ATOMIC_BLOB_TAG_LEN],
        poisoned: false,
        removed: false,
        ..State::default()
    };
    changed_tag.rewind(3).unwrap();
    assert!(changed_tag.is_dirty());

    let mut unchanged_tag = State {
        tag: [0; ATOMIC_BLOB_TAG_LEN],
        ..changed_tag
    };
    unchanged_tag.logical_len = 5;
    unchanged_tag.rewind(3).unwrap();
    assert!(!unchanged_tag.is_dirty());
}

#[test]
fn recovery_rejects_malformed_roots_and_consumes_noncanonical_candidates() {
    let old_tag = [1; ATOMIC_BLOB_TAG_LEN];
    let old = root_slot(encode_root(RootState::Committed, 1, 0, old_tag));
    let mut noncanonical = root_slot(encode_root(
        RootState::BatchPrepared,
        2,
        0,
        [2; ATOMIC_BLOB_TAG_LEN],
    ));
    noncanonical[ROOT_LEN] = 1;
    let mut slots = [noncanonical, old];
    let plan = rejection_plan(DATA_OFFSET, &slots).unwrap().unwrap();
    assert_eq!(plan.root_offset, ROOT_OFFSETS[0]);
    slots[0].fill(0);
    let state = State::recover(DATA_OFFSET, &slots).unwrap().0;
    assert_eq!(state.committed.generation, 1);
    assert_eq!(state.tag, old_tag);

    let wrong_slot = [
        root_slot(encode_root(RootState::Committed, 1, 0, old_tag)),
        [0; ROOT_SLOT_SIZE],
    ];
    assert!(rejection_plan(DATA_OFFSET, &wrong_slot).is_err());

    let too_long = [
        [0; ROOT_SLOT_SIZE],
        root_slot(encode_root(RootState::Committed, 1, 1, old_tag)),
    ];
    assert!(rejection_plan(DATA_OFFSET, &too_long).is_err());

    let mut raw = [0u8; ROOT_SLOT_SIZE];
    raw[0] = 1;
    let exhausted = [raw, finalized_slot(Root::unbound(u64::MAX, 0, old_tag))];
    assert!(rejection_plan(DATA_OFFSET, &exhausted).is_err());
}

#[test]
fn recovery_rejects_invalid_lineage_and_missing_authority() {
    let tag = [1; ATOMIC_BLOB_TAG_LEN];
    let zeros = [[0; ROOT_SLOT_SIZE]; ROOT_OFFSETS.len()];
    assert!(rejection_plan(DATA_OFFSET - 1, &zeros).is_err());

    let root = Root::unbound(1, 0, tag);
    assert!(validate_root(root, ROOT_OFFSETS[0], DATA_OFFSET).is_err());

    let nonconsecutive = [
        finalized_slot(Root::unbound(4, 0, tag)),
        root_slot(encode_root(RootState::Committed, 1, 0, tag)),
    ];
    let plan = rejection_plan(DATA_OFFSET, &nonconsecutive)
        .unwrap()
        .expect("an older nonconsecutive spelling is a consumable target image");
    assert_eq!(plan.root_offset, ROOT_OFFSETS[1]);

    let unresolved_invalid_authority = [
        finalized_slot(Root::unbound(2, 1, tag)),
        root_slot(encode_root(RootState::Committed, 1, 0, tag)),
    ];
    assert!(rejection_plan(DATA_OFFSET, &unresolved_invalid_authority).is_err());

    let skipped = batch::prepare(vec![batch::Participant {
        partition: "skipped".into(),
        name: b"blob".to_vec(),
        incarnation: [1; INCARNATION_LEN],
        candidate: batch::Candidate::new(Root::unbound(4, 0, tag)).unwrap(),
        removed: false,
    }])
    .unwrap();
    let skipped_candidate = [
        skipped.slots[0],
        root_slot(encode_root(RootState::Committed, 1, 0, tag)),
    ];
    assert!(rejection_plan(DATA_OFFSET, &skipped_candidate).is_err());

    let prepared_then_committed = [
        root_slot(encode_root(
            RootState::BatchPrepared,
            2,
            0,
            [2; ATOMIC_BLOB_TAG_LEN],
        )),
        root_slot(encode_root(RootState::Committed, 1, 0, tag)),
    ];
    let state = State::recover(DATA_OFFSET, &prepared_then_committed)
        .unwrap()
        .0;
    assert_eq!(state.committed.generation, 1);

    let zero = State::recover(DATA_OFFSET, &zeros).unwrap().0;
    assert_eq!(zero.committed.generation, 0);
    assert_eq!(zero.logical_len, 0);
    assert_eq!(zero.tag, [0; ATOMIC_BLOB_TAG_LEN]);
    let mut raw_without_authority = zeros;
    raw_without_authority[0][0] = 1;
    assert!(State::recover(DATA_OFFSET, &raw_without_authority).is_err());
    let only_invalid_authority = [
        finalized_slot(Root::unbound(2, 1, tag)),
        [0; ROOT_SLOT_SIZE],
    ];
    assert!(State::recover(DATA_OFFSET, &only_invalid_authority).is_err());
}

#[test]
fn invalid_older_root_is_consumed_before_slot_reuse() {
    let tag = [1; ATOMIC_BLOB_TAG_LEN];
    let slots = [
        finalized_slot(Root::unbound(2, 0, tag)),
        root_slot(encode_root(RootState::Committed, 1, 1, tag)),
    ];
    let plan = rejection_plan(DATA_OFFSET, &slots)
        .unwrap()
        .expect("an out-of-bounds predecessor image is not quiescent");
    assert_eq!(plan.root_offset, ROOT_OFFSETS[1]);
}

#[test]
fn root_decoder_rejects_corrupt_and_unknown_spellings() {
    let valid = encode_root(RootState::Committed, 1, 0, [0; ATOMIC_BLOB_TAG_LEN]);

    let mut bad_magic = valid;
    bad_magic[0] ^= 1;
    assert!(decode_any_root(&bad_magic).is_none());

    let mut bad_checksum = valid;
    bad_checksum[ROOT_BODY_LEN] ^= 1;
    assert!(decode_any_root(&bad_checksum).is_none());

    let generation_zero = encode_root(RootState::Committed, 0, 0, [0; ATOMIC_BLOB_TAG_LEN]);
    assert!(decode_any_root(&generation_zero).is_none());
    let later_committed = encode_root(RootState::Committed, 2, 0, [0; ATOMIC_BLOB_TAG_LEN]);
    assert!(decode_any_root(&later_committed).is_none());

    let mut unknown_guard = valid;
    unknown_guard[ROOT_GUARD_OFFSET] = 0xFF;
    let unknown_checksum = checksum(&[ROOT_DOMAIN, &unknown_guard[..ROOT_BODY_LEN]]);
    unknown_guard[ROOT_BODY_LEN..].copy_from_slice(&unknown_checksum.to_be_bytes());
    assert!(decode_any_root(&unknown_guard).is_none());

    let mut bound_committed = valid;
    bound_committed[ROOT_BINDING_OFFSET] = 1;
    let bound_checksum = checksum(&[ROOT_DOMAIN, &bound_committed[..ROOT_BODY_LEN]]);
    bound_committed[ROOT_BODY_LEN..].copy_from_slice(&bound_checksum.to_be_bytes());
    assert!(decode_any_root(&bound_committed).is_none());

    let overflowing = Root::unbound(1, u64::MAX, [0; ATOMIC_BLOB_TAG_LEN]);
    assert!(validate_root(overflowing, ROOT_OFFSETS[1], u64::MAX).is_err());
}

#[derive(Clone)]
struct CountingBlob<B> {
    inner: B,
    read_bytes: Arc<AtomicUsize>,
    events: Arc<SyncMutex<Vec<Event>>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Event {
    Write {
        offset: u64,
        len: usize,
        options: WriteOptions,
    },
    Resize(u64),
    Sync,
}

impl<B: BackingBlob> BackingBlob for CountingBlob<B> {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.read_bytes.fetch_add(len, Ordering::Relaxed);
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.read_bytes.fetch_add(len, Ordering::Relaxed);
        self.inner.read_at(offset, len).await
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        self.events.lock().push(Event::Write {
            offset,
            len: bufs.len(),
            options,
        });
        self.inner.write_at(offset, bufs, options).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.events.lock().push(Event::Resize(len));
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.events.lock().push(Event::Sync);
        self.inner.sync().await
    }

    async fn start_sync(&self) -> Handle<()> {
        self.inner.start_sync().await
    }
}

#[test]
fn accepted_successor_does_not_rehash_predecessor_payloads() {
    deterministic::Runner::default().start(|_| async move {
        let mut registry = Registry::default();
        let storage = metered::Storage::new(memory::Storage::new(test_pool()), &mut registry);
        let partition = "predecessor_payload_proof";
        let names = [b"a".as_slice(), b"b".as_slice()];
        let mut blobs = BTreeMap::new();
        let mut successors = Vec::new();

        for (ordinal, name) in names.into_iter().enumerate() {
            let (blob, _) = storage.open_atomic(partition, name).await.unwrap();
            blob.append(vec![ordinal as u8 + 1; 1024]).await.unwrap();
            blob.sync().await.unwrap();

            let slots = Blob::read_roots(&blob.backing).await.unwrap();
            let predecessor = slots
                .iter()
                .zip(ROOT_OFFSETS)
                .find_map(|(slot, offset)| batch::link_at(slot, partition, name, offset))
                .unwrap();
            let predecessor_root = predecessor.participant.candidate.root().unwrap();
            successors.push(batch::Participant {
                partition: partition.into(),
                name: name.to_vec(),
                incarnation: blob.incarnation,
                candidate: batch::Candidate::with_payload(
                    Root {
                        generation: predecessor_root.generation + 1,
                        tag: [0x80 + ordinal as u8; ATOMIC_BLOB_TAG_LEN],
                        ..predecessor_root
                    },
                    batch::PayloadDescriptor::empty(predecessor_root.logical_len),
                )
                .unwrap(),
                removed: false,
            });
            blobs.insert(name.to_vec(), blob);
        }

        let group_id = [0x4d; batch::GROUP_ID_LEN];
        let prepared = batch::prepare_with_group_id(successors, group_id).unwrap();
        let mut members = Vec::new();
        for (participant, slot) in prepared.participants.iter().zip(&prepared.slots) {
            let blob = &blobs[&participant.name];
            blob.backing
                .write_at(
                    participant.candidate.root_offset().unwrap(),
                    slot.to_vec(),
                    WriteOptions::default(),
                )
                .await
                .unwrap();
            let slots = Blob::read_roots(&blob.backing).await.unwrap();
            let link = slots
                .iter()
                .zip(ROOT_OFFSETS)
                .find_map(|(slot, offset)| {
                    batch::link_at(slot, partition, &participant.name, offset)
                        .filter(|link| link.group_id == group_id)
                })
                .unwrap();
            members.push(GroupMember {
                link,
                backing: blob.backing.clone(),
                backing_len: raw_len(participant.candidate.root().unwrap().logical_len).unwrap(),
                slots,
            });
        }
        join_participant_io(blobs.values().map(|blob| blob.backing.sync()).collect())
            .await
            .unwrap();

        let read_bytes_before = storage.storage_read_bytes();
        let predecessors = predecessor_groups(&storage, &members).await.unwrap();
        assert_eq!(predecessors.len(), names.len());
        assert_eq!(storage.storage_read_bytes() - read_bytes_before, 0);
    });
}

#[test]
fn counting_backing_forwards_buffered_reads_and_background_sync() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (inner, _) = storage.open("counting", b"forward").await.unwrap();
        inner
            .write_at(0, b"x", WriteOptions::default())
            .await
            .unwrap();

        let read_bytes = Arc::new(AtomicUsize::new(0));
        let backing = CountingBlob {
            inner,
            read_bytes: read_bytes.clone(),
            events: Arc::new(SyncMutex::new(Vec::new())),
        };
        let read = backing
            .read_at_buf(0, 1, IoBufMut::with_capacity(1))
            .await
            .unwrap();
        assert_eq!(read.coalesce(), b"x");
        assert_eq!(read_bytes.load(Ordering::Relaxed), 1);
        backing.start_sync().await.await.unwrap();
    });
}

#[test]
fn raw_memory_storage_repairs_and_maps_recovery_errors() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (blob, _) = storage.open_atomic("raw", b"repair").await.unwrap();
        drop(blob);

        let (backing, backing_len) = storage.open("raw", b"repair").await.unwrap();
        let prepared = root_slot(encode_root(
            RootState::BatchPrepared,
            1,
            0,
            [9; ATOMIC_BLOB_TAG_LEN],
        ));
        backing
            .write_at(ROOT_OFFSETS[1], prepared.to_vec(), WriteOptions::SYNC)
            .await
            .unwrap();
        drop(backing);

        let (blob, len) = storage.open_atomic("raw", b"repair").await.unwrap();
        assert_eq!(len, 0);
        assert_eq!(blob.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);
        drop(blob);

        let (corrupt, _) = storage.open("raw", b"corrupt").await.unwrap();
        corrupt.resize(DATA_OFFSET).await.unwrap();
        corrupt
            .write_at(IDENTITY_PAGE_LEN, &[0xFF], WriteOptions::SYNC)
            .await
            .unwrap();
        drop(corrupt);

        let error = storage
            .open_atomic("raw", b"corrupt")
            .await
            .err()
            .expect("corrupt roots must be rejected");
        assert!(is_blob_corrupt(&error));
        assert_eq!(backing_len, DATA_OFFSET);

        assert_open_maps_recovery_corruption(&storage, "raw_corruption").await;
    });
}

#[test]
fn raw_memory_backing_recovers_a_complete_ring() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        stage_batch(
            &storage,
            "raw_memory_ring",
            &[b"a", b"b"],
            &[false; 2],
            0b11,
        )
        .await;

        for name in [b"a".as_slice(), b"b".as_slice()] {
            let (blob, len) = storage.open_atomic("raw_memory_ring", name).await.unwrap();
            assert_eq!(len, 7);
            assert_eq!(blob.read_at(0, 7).await.unwrap().coalesce(), b"old-new");
        }
    });
}

#[test]
fn recovery_materializes_finals_with_one_barrier() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let partition = "mixed_recovery_barrier";
        let prepared = stage_batch(
            &storage,
            partition,
            &[b"exact", b"missing"],
            &[false, true],
            0b11,
        )
        .await;

        let exact = &prepared.participants[0];
        let (exact_backing, exact_len) = storage.open(partition, &exact.name).await.unwrap();
        exact_backing
            .write_at(
                exact.candidate.root_offset().unwrap(),
                exact.candidate.final_root().unwrap().to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();
        let exact_events = Arc::new(SyncMutex::new(Vec::new()));
        let exact_backing = CountingBlob {
            inner: exact_backing,
            read_bytes: Arc::new(AtomicUsize::new(0)),
            events: exact_events.clone(),
        };
        let exact_slots = Blob::<CountingBlob<memory::Blob>>::read_roots(&exact_backing)
            .await
            .unwrap();
        let exact_link = exact_slots
            .iter()
            .find_map(|slot| batch::link(slot, partition, &exact.name))
            .unwrap();

        let missing = &prepared.participants[1];
        let (missing_backing, missing_len) = storage.open(partition, &missing.name).await.unwrap();
        let missing_events = Arc::new(SyncMutex::new(Vec::new()));
        let missing_backing = CountingBlob {
            inner: missing_backing,
            read_bytes: Arc::new(AtomicUsize::new(0)),
            events: missing_events.clone(),
        };
        let missing_slots = Blob::<CountingBlob<memory::Blob>>::read_roots(&missing_backing)
            .await
            .unwrap();
        let missing_link = missing_slots
            .iter()
            .find_map(|slot| batch::link(slot, partition, &missing.name))
            .unwrap();

        materialize_group_roots(&[
            GroupMember {
                link: exact_link,
                backing: exact_backing,
                backing_len: exact_len,
                slots: exact_slots,
            },
            GroupMember {
                link: missing_link,
                backing: missing_backing,
                backing_len: missing_len,
                slots: missing_slots,
            },
        ])
        .await
        .unwrap();

        assert_eq!(*exact_events.lock(), [Event::Sync]);
        assert_eq!(
            *missing_events.lock(),
            [
                Event::Write {
                    offset: missing.candidate.root_offset().unwrap(),
                    len: ROOT_LEN,
                    options: WriteOptions::default(),
                },
                Event::Sync,
            ]
        );
    });
}

#[test]
fn predecessor_debt_probe_defers_live_payload_validation() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let partition = "predecessor_debt_probe";
        let name = b"blob";
        let prepared = stage_batch(&storage, partition, &[name], &[false], 0b1).await;
        let participant = &prepared.participants[0];
        let (backing, backing_len) = storage.open(partition, name).await.unwrap();
        backing
            .write_at(
                participant.candidate.root_offset().unwrap(),
                participant.candidate.final_root().unwrap().to_vec(),
                WriteOptions::SYNC,
            )
            .await
            .unwrap();

        let read_bytes = Arc::new(AtomicUsize::new(0));
        let backing = CountingBlob {
            inner: backing,
            read_bytes: read_bytes.clone(),
            events: Arc::new(SyncMutex::new(Vec::new())),
        };
        let slots = Blob::<CountingBlob<memory::Blob>>::read_roots(&backing)
            .await
            .unwrap();
        let link = slots
            .iter()
            .find_map(|slot| batch::link(slot, partition, name))
            .unwrap();
        let member = GroupMember {
            link,
            backing,
            backing_len,
            slots,
        };
        read_bytes.store(0, Ordering::Relaxed);

        assert!(
            !predecessor_debt_is_paid(
                std::slice::from_ref(&member),
                std::slice::from_ref(&member),
            )
            .unwrap()
        );
        assert_eq!(read_bytes.load(Ordering::Relaxed), 0);
    });
}

#[test]
fn reopen_reads_only_roots_and_the_bounded_publication_suffix() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let partition = "bounded";
        let name = b"blob";
        let (blob, _) = storage.open_atomic(partition, name).await.unwrap();
        let incarnation = blob.incarnation;
        blob.append(vec![0x5A; 2 * 1024 * 1024]).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);

        let (backing, backing_len) = storage.open(partition, name).await.unwrap();
        let read_bytes = Arc::new(AtomicUsize::new(0));
        let events = Arc::new(SyncMutex::new(Vec::new()));
        let backing = CountingBlob {
            inner: backing,
            read_bytes: read_bytes.clone(),
            events: events.clone(),
        };
        let slots = Blob::<CountingBlob<memory::Blob>>::read_roots(&backing)
            .await
            .unwrap();
        let link = slots
            .iter()
            .find_map(|slot| batch::link(slot, partition, name))
            .unwrap();
        let member = GroupMember {
            link,
            backing: backing.clone(),
            backing_len,
            slots,
        };
        assert!(
            recovery_group_complete(std::slice::from_ref(&member), false)
                .await
                .unwrap()
        );
        materialize_group_roots(std::slice::from_ref(&member))
            .await
            .unwrap();
        let (_, len) = Blob::open_named(
            backing,
            partition,
            name,
            backing_len,
            incarnation,
            test_token_epoch(),
            test_resources(),
        )
        .await
        .unwrap();
        assert_eq!(len, 2 * 1024 * 1024);
        assert_eq!(
            read_bytes.load(Ordering::Relaxed),
            2 * ROOT_OFFSETS.len() * ROOT_SLOT_SIZE + 2 * 1024 * 1024
        );
        assert_eq!(
            *events.lock(),
            [
                Event::Write {
                    offset: ROOT_OFFSETS[1],
                    len: ROOT_LEN,
                    options: WriteOptions::default(),
                },
                Event::Sync,
            ]
        );
    });
}

#[test]
fn recovery_durably_clears_a_rejected_slot_in_one_write() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (blob, _) = storage.open_atomic("ordered_clear", b"blob").await.unwrap();
        let incarnation = blob.incarnation;
        drop(blob);

        let (backing, backing_len) = storage.open("ordered_clear", b"blob").await.unwrap();
        let prepared = root_slot(encode_root(
            RootState::BatchPrepared,
            1,
            0,
            [9; ATOMIC_BLOB_TAG_LEN],
        ));
        backing
            .write_at(ROOT_OFFSETS[1], prepared.to_vec(), WriteOptions::SYNC)
            .await
            .unwrap();

        let events = Arc::new(SyncMutex::new(Vec::new()));
        let backing = CountingBlob {
            inner: backing,
            read_bytes: Arc::new(AtomicUsize::new(0)),
            events: events.clone(),
        };
        let (blob, len) = Blob::open_named(
            backing,
            "ordered_clear",
            b"blob",
            backing_len,
            incarnation,
            test_token_epoch(),
            test_resources(),
        )
        .await
        .unwrap();
        assert_eq!(len, 0);
        assert_eq!(blob.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);
        assert_eq!(
            *events.lock(),
            [Event::Write {
                offset: ROOT_OFFSETS[1],
                len: ROOT_SLOT_SIZE,
                options: WriteOptions::SYNC,
            }]
        );
    });
}

#[test]
fn publication_orders_payload_prepare_barrier_and_decision() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (initialized, _) = storage.open_atomic("ordered", b"blob").await.unwrap();
        let incarnation = initialized.incarnation;
        drop(initialized);
        let (backing, backing_len) = storage.open("ordered", b"blob").await.unwrap();
        let events = Arc::new(SyncMutex::new(Vec::new()));
        let backing = CountingBlob {
            inner: backing,
            read_bytes: Arc::new(AtomicUsize::new(0)),
            events: events.clone(),
        };
        let (blob, _) = Blob::open_named(
            backing,
            "ordered",
            b"blob",
            backing_len,
            incarnation,
            test_token_epoch(),
            test_resources(),
        )
        .await
        .unwrap();
        events.lock().clear();

        blob.append(b"payload").await.unwrap();
        blob.sync().await.unwrap();
        assert_eq!(
            *events.lock(),
            [
                Event::Write {
                    offset: DATA_OFFSET,
                    len: 7,
                    options: WriteOptions::default(),
                },
                Event::Write {
                    offset: ROOT_OFFSETS[1],
                    len: ROOT_SLOT_SIZE,
                    options: WriteOptions::default(),
                },
                Event::Sync,
                Event::Write {
                    offset: ROOT_OFFSETS[1],
                    len: ROOT_LEN,
                    options: WriteOptions::default(),
                },
            ]
        );

        events.lock().clear();
        blob.rewind(3).await.unwrap();
        blob.sync().await.unwrap();
        assert_eq!(
            *events.lock(),
            [
                Event::Write {
                    offset: ROOT_OFFSETS[0],
                    len: ROOT_SLOT_SIZE,
                    options: WriteOptions::default(),
                },
                Event::Sync,
                Event::Write {
                    offset: ROOT_OFFSETS[0],
                    len: ROOT_LEN,
                    options: WriteOptions::default(),
                },
                Event::Resize(DATA_OFFSET + 3),
            ]
        );
    });
}

#[test]
fn integrity_tokens_reject_other_blobs_and_stale_reopened_state() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (first, _) = storage.open_atomic("tokens", b"first").await.unwrap();
        let (second, _) = storage.open_atomic("tokens", b"second").await.unwrap();
        let first_token = first.integrity_snapshot().await.unwrap().token;
        let second_token = second.integrity_snapshot().await.unwrap().token;
        assert_ne!(first_token, second_token);

        first
            .append_integrity(first_token, b"payload", IntegrityBoundary::Continue, None)
            .await
            .unwrap();
        first.sync().await.unwrap();
        drop(first);

        let (reopened, _) = storage.open_atomic("tokens", b"first").await.unwrap();
        assert_eq!(
            io_kind(
                &reopened
                    .append_integrity(first_token, b"stale", IntegrityBoundary::Continue, None,)
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );
    });
}

#[test]
fn integrity_tokens_reject_rolled_back_revision_after_reopen() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (blob, _) = storage.open_atomic("tokens", b"rolled_back").await.unwrap();
        let initial = blob.integrity_snapshot().await.unwrap().token;
        let retired = blob
            .append_integrity(initial, b"old", IntegrityBoundary::Complete, None)
            .await
            .unwrap()
            .token;
        drop(blob);

        let (reopened, len) = storage.open_atomic("tokens", b"rolled_back").await.unwrap();
        assert_eq!(len, 0);
        let replacement = reopened.integrity_snapshot().await.unwrap().token;
        reopened
            .append_integrity(replacement, b"new", IntegrityBoundary::Complete, None)
            .await
            .unwrap();

        assert_eq!(
            io_kind(
                &reopened
                    .compare_set_tag(retired, [1; ATOMIC_BLOB_TAG_LEN])
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );
        assert_eq!(reopened.tag().await.unwrap(), [0; ATOMIC_BLOB_TAG_LEN]);
    });
}

#[test]
fn backend_identifier_contract_retires_tokens_on_reopen() {
    deterministic::Runner::default().start(|_| async move {
        let storage =
            crate::storage::tests::RecordingAtomicBackend::new(memory::Storage::new(test_pool()));
        let (blob, _) = storage
            .open_atomic("tokens", b"backend_identifier")
            .await
            .unwrap();
        let retired = blob.integrity_snapshot().await.unwrap().token;
        drop(blob);

        let (reopened, _) = storage
            .open_atomic("tokens", b"backend_identifier")
            .await
            .unwrap();
        assert_eq!(
            io_kind(
                &reopened
                    .compare_set_tag(retired, [1; ATOMIC_BLOB_TAG_LEN])
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );
    });
}

#[test]
fn variable_integrity_units_round_trip_rewind_and_detect_corruption() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (blob, len) = storage.open_atomic("integrity", b"variable").await.unwrap();
        assert_eq!(len, 0);

        let initial = blob.integrity_snapshot().await.unwrap();
        assert_eq!(initial.scheme, IntegrityScheme::Unbound);
        assert!(initial.tail.is_none());
        assert_eq!(
            io_kind(
                &blob
                    .read_integrity(IntegrityUnit { offset: 0, len: 1 })
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );

        let first = blob
            .append_integrity(
                initial.token,
                b"ab",
                IntegrityBoundary::Continue,
                Some([1; ATOMIC_BLOB_TAG_LEN]),
            )
            .await
            .unwrap();
        assert_eq!(first.offset, 0);
        assert_eq!(blob.tag().await.unwrap(), [1; ATOMIC_BLOB_TAG_LEN]);
        assert_eq!(
            io_kind(
                &blob
                    .append_integrity(initial.token, b"stale", IntegrityBoundary::Continue, None,)
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );

        let open = blob.integrity_snapshot().await.unwrap();
        assert_eq!(open.encoded_len, 2);
        assert_eq!(open.scheme, IntegrityScheme::Unbound);
        let (tail, data) = open.tail.unwrap();
        assert_eq!(tail, IntegrityUnit { offset: 0, len: 2 });
        assert_eq!(data.coalesce(), b"ab");

        let complete = blob
            .append_integrity(first.token, b"cd", IntegrityBoundary::Complete, None)
            .await
            .unwrap();
        assert_eq!(complete.offset, 2);
        let closed = blob.integrity_snapshot().await.unwrap();
        assert_eq!(closed.encoded_len, 8);
        assert_eq!(closed.scheme, IntegrityScheme::Variable);
        assert!(closed.tail.is_none());
        let unit = IntegrityUnit { offset: 0, len: 4 };
        assert_eq!(
            io_kind(
                &blob
                    .read_integrity(IntegrityUnit { offset: 0, len: 0 })
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );
        assert_eq!(blob.read_integrity(unit).await.unwrap().coalesce(), b"abcd");

        assert_eq!(
            io_kind(
                &blob
                    .compare_set_tag(first.token, [2; ATOMIC_BLOB_TAG_LEN])
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );
        let tagged = blob
            .compare_set_tag(complete.token, [2; ATOMIC_BLOB_TAG_LEN])
            .await
            .unwrap();
        blob.start_sync().await.await.unwrap();
        drop(blob);

        let (blob, len) = storage.open_atomic("integrity", b"variable").await.unwrap();
        assert_eq!(len, 8);
        assert_eq!(
            blob.integrity_scheme().await.unwrap(),
            IntegrityScheme::Variable
        );
        assert_eq!(blob.tag().await.unwrap(), [2; ATOMIC_BLOB_TAG_LEN]);
        assert_eq!(blob.read_integrity(unit).await.unwrap().coalesce(), b"abcd");

        let reopened_token = blob.integrity_snapshot().await.unwrap().token;
        assert_ne!(reopened_token, tagged);
        let rewound = blob
            .rewind_integrity(reopened_token, 2, Some(unit), None)
            .await
            .unwrap();
        let snapshot = blob.integrity_snapshot().await.unwrap();
        assert_eq!(snapshot.encoded_len, 2);
        let (tail, data) = snapshot.tail.unwrap();
        assert_eq!(tail, IntegrityUnit { offset: 0, len: 2 });
        assert_eq!(data.coalesce(), b"ab");
        assert_eq!(
            io_kind(
                &blob
                    .append_integrity(rewound, b"cd", IntegrityBoundary::Complete, None)
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );
        blob.start_sync().await.await.unwrap();
        let restored = blob
            .append_integrity(
                blob.integrity_snapshot().await.unwrap().token,
                b"cd",
                IntegrityBoundary::Complete,
                None,
            )
            .await
            .unwrap();
        assert_eq!(restored.offset, 2);
        assert_eq!(blob.read_integrity(unit).await.unwrap().coalesce(), b"abcd");

        blob.backing
            .write_at(
                raw_len(4).unwrap(),
                vec![0; INTEGRITY_CHECKSUM_LEN],
                WriteOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            io_kind(&blob.read_integrity(unit).await.unwrap_err()),
            Some(io::ErrorKind::InvalidData)
        );
    });
}

#[test]
fn read_integrity_reuses_pooled_read_buffer() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let (blob, _) = storage
            .open_atomic("integrity", b"pooled_read")
            .await
            .unwrap();
        let payload = vec![0xA5; crate::iobuf::page_size()];
        let token = blob.integrity_snapshot().await.unwrap().token;
        blob.append_integrity(token, payload.clone(), IntegrityBoundary::Complete, None)
            .await
            .unwrap();

        let unit = IntegrityUnit {
            offset: 0,
            len: payload.len() as u64,
        };
        let result = blob
            .read_integrity(unit)
            .await
            .unwrap()
            .try_into_single()
            .unwrap();
        assert_eq!(result.as_ref(), payload);
        assert!(result.is_pooled());
    });
}

#[test]
fn chunked_integrity_spans_appends_and_empty_append_closes_a_full_tail() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let width = std::num::NonZeroU32::new(3).unwrap();
        let (blob, _) = storage.open_atomic("integrity", b"chunked").await.unwrap();
        let token = blob.integrity_snapshot().await.unwrap().token;
        let append = blob
            .append_integrity(token, b"abcdefgh", IntegrityBoundary::Chunked(width), None)
            .await
            .unwrap();
        assert_eq!(append.offset, 0);
        assert_eq!(
            blob.read_integrity(IntegrityUnit { offset: 0, len: 3 })
                .await
                .unwrap()
                .coalesce(),
            b"abc"
        );
        assert_eq!(
            blob.read_integrity(IntegrityUnit { offset: 7, len: 3 })
                .await
                .unwrap()
                .coalesce(),
            b"def"
        );
        let snapshot = blob.integrity_snapshot().await.unwrap();
        assert_eq!(snapshot.encoded_len, 16);
        assert_eq!(snapshot.scheme, IntegrityScheme::Chunked(width));
        let (tail, data) = snapshot.tail.unwrap();
        assert_eq!(tail, IntegrityUnit { offset: 14, len: 2 });
        assert_eq!(data.coalesce(), b"gh");
        let closed = blob
            .append_integrity(append.token, b"i", IntegrityBoundary::Chunked(width), None)
            .await
            .unwrap();
        assert_eq!(closed.offset, 16);
        assert_eq!(blob.integrity_snapshot().await.unwrap().encoded_len, 21);
        assert_eq!(
            blob.read_integrity(IntegrityUnit { offset: 14, len: 3 })
                .await
                .unwrap()
                .coalesce(),
            b"ghi"
        );
        assert_eq!(
            io_kind(
                &blob
                    .read_integrity(IntegrityUnit { offset: 1, len: 3 })
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );
        assert_eq!(
            io_kind(
                &blob
                    .read_integrity(IntegrityUnit { offset: 21, len: 3 })
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );
        blob.sync().await.unwrap();
        drop(blob);
        let (blob, len) = storage.open_atomic("integrity", b"chunked").await.unwrap();
        assert_eq!(len, 21);
        assert_eq!(
            blob.integrity_scheme().await.unwrap(),
            IntegrityScheme::Chunked(width)
        );
        let token = blob.integrity_snapshot().await.unwrap().token;
        assert_eq!(
            io_kind(
                &blob
                    .append_integrity(token, b"x", IntegrityBoundary::Complete, None,)
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );

        let (full_tail, _) = storage
            .open_atomic("integrity", b"full_tail")
            .await
            .unwrap();
        full_tail.append(b"abc").await.unwrap();
        let token = full_tail.integrity_snapshot().await.unwrap().token;
        let closed = full_tail
            .append_integrity(
                token,
                Vec::<u8>::new(),
                IntegrityBoundary::Chunked(width),
                None,
            )
            .await
            .unwrap();
        assert_eq!(closed.offset, 3);
        assert_eq!(full_tail.integrity_snapshot().await.unwrap().encoded_len, 7);
        assert_eq!(
            full_tail
                .read_integrity(IntegrityUnit { offset: 0, len: 3 })
                .await
                .unwrap()
                .coalesce(),
            b"abc"
        );

        let token = full_tail.integrity_snapshot().await.unwrap().token;
        assert_eq!(
            io_kind(
                &full_tail
                    .rewind_integrity(token, 3, Some(IntegrityUnit { offset: 0, len: 3 }), None,)
                    .await
                    .unwrap_err()
            ),
            Some(io::ErrorKind::InvalidInput)
        );
        full_tail.sync().await.unwrap();
        drop(full_tail);
        let (_, len) = storage
            .open_atomic("integrity", b"full_tail")
            .await
            .unwrap();
        assert_eq!(len, 7);
    });
}

#[test]
fn raw_appends_continue_chunked_integrity_with_footer_interleaving() {
    deterministic::Runner::default().start(|_| async move {
        let storage = memory::Storage::new(test_pool());
        let width = std::num::NonZeroU32::new(3).unwrap();
        for (name, tag) in [
            (b"append".as_slice(), None),
            (b"append_tagged".as_slice(), Some([7; ATOMIC_BLOB_TAG_LEN])),
        ] {
            let (blob, _) = storage.open_atomic("integrity", name).await.unwrap();
            let token = blob.integrity_snapshot().await.unwrap().token;
            blob.append_integrity(token, b"ab", IntegrityBoundary::Chunked(width), None)
                .await
                .unwrap();

            let offset = match tag {
                Some(tag) => blob.append_tagged(b"cdef", tag).await.unwrap(),
                None => blob.append(b"cdef").await.unwrap(),
            };
            assert_eq!(offset, 2);
            assert_eq!(blob.integrity_snapshot().await.unwrap().encoded_len, 14);
            assert_eq!(
                blob.read_integrity(IntegrityUnit { offset: 0, len: 3 })
                    .await
                    .unwrap()
                    .coalesce(),
                b"abc"
            );
            assert_eq!(
                blob.read_integrity(IntegrityUnit { offset: 7, len: 3 })
                    .await
                    .unwrap()
                    .coalesce(),
                b"def"
            );
            let encoded = blob.read_at(offset, 5).await.unwrap().coalesce();
            assert_eq!(encoded.as_ref()[0], b'c');
            assert_eq!(
                &encoded.as_ref()[1..],
                Crc32::checksum(b"abc").to_be_bytes().as_slice()
            );
            if let Some(tag) = tag {
                assert_eq!(blob.tag().await.unwrap(), tag);
            }
        }
    });
}

#[test]
fn chunked_one_bounds_prepared_fragments() {
    let width = std::num::NonZeroU32::new(1).unwrap();
    let data = (0..513).map(|index| index as u8).collect::<Vec<_>>();
    let mut state = State::default();
    let prepared = state
        .prepare_integrity_append(
            IoBufs::from(data.clone()),
            IntegrityBoundary::Chunked(width),
        )
        .unwrap()
        .unwrap();

    let mut expected = Vec::with_capacity(data.len() * (1 + INTEGRITY_CHECKSUM_LEN));
    for byte in data {
        expected.push(byte);
        expected.extend_from_slice(&Crc32::checksum(&[byte]).to_be_bytes());
    }
    assert_eq!(prepared.logical_end, expected.len() as u64);
    assert_eq!(prepared.encoded.clone().coalesce().as_ref(), expected);
    assert!(
        prepared.encoded.chunk_count() <= expected.len().div_ceil(INTEGRITY_ENCODING_BLOCK_LEN)
    );
}

#[test]
fn integrity_state_rejects_every_noncanonical_boundary() {
    let width = std::num::NonZeroU32::new(3).unwrap();
    let valid = Root {
        generation: 1,
        logical_len: 9,
        integrity_start: 7,
        integrity_checksum: 1,
        integrity_scheme: IntegrityScheme::Chunked(width),
        tag: [1; ATOMIC_BLOB_TAG_LEN],
    };
    let encoded = encode_root_value(RootState::Finalized, valid);
    assert_eq!(decode_root(&encoded, RootState::Finalized).unwrap(), valid);

    let mut zero_chunk = encoded;
    zero_chunk[ROOT_INTEGRITY_CHUNK_OFFSET..ROOT_BINDING_OFFSET].fill(0);
    assert!(decode_root_fields(&zero_chunk).is_none());
    let mut unknown_scheme = encoded;
    unknown_scheme[ROOT_INTEGRITY_SCHEME_OFFSET..ROOT_INTEGRITY_CHUNK_OFFSET]
        .copy_from_slice(&3u32.to_be_bytes());
    assert!(decode_root_fields(&unknown_scheme).is_none());

    for invalid in [
        Root {
            integrity_start: 10,
            ..valid
        },
        Root {
            logical_len: 7,
            integrity_start: 7,
            integrity_checksum: 1,
            ..valid
        },
        Root {
            integrity_start: 1,
            integrity_scheme: IntegrityScheme::Unbound,
            ..valid
        },
        Root {
            integrity_start: 1,
            ..valid
        },
        Root {
            logical_len: 10,
            ..valid
        },
    ] {
        assert!(validate_root(invalid, ROOT_OFFSETS[1], DATA_OFFSET + 16).is_err());
    }

    let closed = State::default();
    closed.validate_integrity_tail(&[]).unwrap();
    assert!(closed.validate_integrity_tail(b"x").is_err());
    let mut open = State {
        logical_len: 2,
        ..State::default()
    };
    open.integrity_checksum = Crc32::checksum(b"ab");
    assert!(open.validate_integrity_tail(b"a").is_err());

    let mut empty = State::default();
    assert!(
        empty
            .prepare_integrity_append(IoBufs::default(), IntegrityBoundary::Chunked(width))
            .unwrap()
            .is_none()
    );
    assert_eq!(empty.integrity_scheme, IntegrityScheme::Chunked(width));

    let mut oversized = State {
        logical_len: 4,
        ..State::default()
    };
    oversized.integrity_checksum = Crc32::checksum(b"abcd");
    assert!(
        oversized
            .prepare_integrity_append(
                IoBufs::from(b"x".as_slice()),
                IntegrityBoundary::Chunked(width)
            )
            .is_err()
    );

    let variable = IntegrityScheme::Variable;
    assert!(
        variable
            .validate_completed_unit(IntegrityUnit { offset: 0, len: 0 })
            .is_err()
    );
    assert!(
        IntegrityScheme::Unbound
            .validate_completed_unit(IntegrityUnit { offset: 0, len: 1 })
            .is_err()
    );
    assert!(
        IntegrityScheme::Chunked(width)
            .validate_completed_unit(IntegrityUnit { offset: 1, len: 3 })
            .is_err()
    );

    let state = State {
        logical_len: 10,
        integrity_start: 8,
        integrity_scheme: variable,
        ..State::default()
    };
    assert!(state.rewind_integrity_source(0, None).unwrap().is_none());
    assert!(state.rewind_integrity_source(7, None).is_err());
    assert!(
        state
            .rewind_integrity_source(8, Some(IntegrityUnit { offset: 8, len: 2 }))
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .rewind_integrity_source(9, Some(IntegrityUnit { offset: 8, len: 4 }))
            .is_err()
    );
    assert!(
        state
            .rewind_integrity_source(6, Some(IntegrityUnit { offset: 0, len: 4 }))
            .is_err()
    );

    let chunked = State {
        logical_len: 15,
        integrity_start: 14,
        integrity_scheme: IntegrityScheme::Chunked(width),
        ..State::default()
    };
    assert!(chunked.rewind_integrity_source(7, None).unwrap().is_none());

    let mut invalid_source = state.clone();
    assert!(
        invalid_source
            .apply_rewind(9, Some((IntegrityUnit { offset: 8, len: 2 }, b"x")))
            .is_err()
    );
    let mut boundary = state;
    boundary.apply_rewind(8, None).unwrap();
    assert_eq!(boundary.integrity_start, 8);
    assert_eq!(boundary.integrity_checksum, 0);
}
