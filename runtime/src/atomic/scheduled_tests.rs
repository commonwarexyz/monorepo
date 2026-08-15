//! Deterministic post-identity crash schedules for atomic publication and recovery.
//!
//! The schedules cover canonical program-issued writes, resizes, full and range syncs, and
//! removals against the in-memory backend. Container creation, migration replacement, task
//! cancellation, and filesystem durability are outside this gate. Migration crash behavior has a
//! dedicated fuzz target.

use super::*;
use crate::{
    BufferPool, BufferPoolConfig, Handle, IoBufs, IoBufsMut, Runner as _, WriteOptions,
    deterministic, storage::memory, telemetry::metrics::Registry,
};
use commonware_utils::sync::Mutex as SyncMutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    ops::RangeInclusive,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

const PARTITION: &str = "atomic_scheduled";
const DIRECT_NAMES: [&[u8]; 1] = [b"a"];
const PAIR_NAMES: [&[u8]; 2] = [b"a", b"b"];
const TRIPLE_NAMES: [&[u8]; 3] = [b"a", b"b", b"c"];
const SUFFIX: &[u8] = b"-new";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Location {
    partition: String,
    name: Vec<u8>,
}

impl Location {
    fn new(partition: &str, name: &[u8]) -> Self {
        Self {
            partition: partition.to_string(),
            name: name.to_vec(),
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum EventKind {
    Write { offset: u64, len: usize, sync: bool },
    Sync,
    Resize { len: u64 },
    Remove,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CallIdentity {
    location: Location,
    ordinal: u64,
    kind: EventKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PrimitiveEvent {
    issue: u64,
    call: CallIdentity,
    failed: bool,
}

enum PendingMutation {
    Write {
        issue: u64,
        event_len: usize,
        source_start: usize,
        location: Location,
        blob: memory::Blob,
        offset: u64,
        bytes: Vec<u8>,
        durable: bool,
    },
    Resize {
        issue: u64,
        location: Location,
        blob: memory::Blob,
        len: u64,
    },
}

impl PendingMutation {
    fn location(&self) -> &Location {
        match self {
            Self::Write { location, .. } | Self::Resize { location, .. } => location,
        }
    }
}

#[derive(Default)]
struct ScheduleState {
    events: Vec<PrimitiveEvent>,
    failures: BTreeSet<CallIdentity>,
    remove_then_errors: BTreeSet<CallIdentity>,
    ordinals: BTreeMap<Location, u64>,
    next_issue: u64,
    pending: Vec<PendingMutation>,
}

impl ScheduleState {
    fn record(&mut self, location: Location, kind: EventKind) -> (u64, bool) {
        let ordinal = self.ordinals.entry(location.clone()).or_default();
        let call = CallIdentity {
            location,
            ordinal: *ordinal,
            kind,
        };
        *ordinal = ordinal
            .checked_add(1)
            .expect("one location cannot exhaust call ordinals");
        let issue = self.next_issue;
        self.next_issue = self
            .next_issue
            .checked_add(1)
            .expect("one storage cannot exhaust issue identifiers");
        let failed = self.failures.remove(&call);
        self.events.push(PrimitiveEvent {
            issue,
            call,
            failed,
        });
        (issue, failed)
    }
}

#[derive(Default)]
struct CrashPlan {
    writes: BTreeMap<u64, Vec<bool>>,
    resizes: BTreeMap<u64, bool>,
}

#[derive(Clone, Copy, Debug)]
enum Retention {
    Discard,
    Keep,
    Stripe,
}

impl Retention {
    fn mask(self, issue: u64, len: usize) -> Vec<bool> {
        match self {
            Self::Discard => vec![false; len],
            Self::Keep => vec![true; len],
            Self::Stripe => (0..len)
                .map(|index| (issue + index as u64).is_multiple_of(2))
                .collect(),
        }
    }

    fn retain_resize(self, issue: u64) -> bool {
        match self {
            Self::Discard => false,
            Self::Keep => true,
            Self::Stripe => issue.is_multiple_of(2),
        }
    }
}

#[derive(Clone)]
struct ScheduledStorage {
    inner: memory::Storage,
    state: Arc<SyncMutex<ScheduleState>>,
    identifiers: Arc<AtomicU64>,
}

impl ScheduledStorage {
    fn new(pool: BufferPool) -> Self {
        Self {
            inner: memory::Storage::new(pool),
            state: Arc::new(SyncMutex::new(ScheduleState::default())),
            identifiers: Arc::new(AtomicU64::new(0)),
        }
    }

    fn wrap(&self, partition: &str, name: &[u8], inner: memory::Blob) -> ScheduledBlob {
        ScheduledBlob {
            inner,
            location: Location::new(partition, name),
            state: self.state.clone(),
        }
    }

    fn arm(&self, failures: impl IntoIterator<Item = CallIdentity>) {
        self.arm_with_mode(failures, false);
    }

    fn arm_clean(&self, failures: impl IntoIterator<Item = CallIdentity>) {
        self.arm_with_mode(failures, true);
    }

    fn arm_clean_remove_then_error(&self, failure: CallIdentity) {
        self.arm_with_mode([], true);
        self.state.lock().remove_then_errors.insert(failure);
    }

    fn arm_with_mode(&self, failures: impl IntoIterator<Item = CallIdentity>, require_clean: bool) {
        let mut state = self.state.lock();
        assert!(
            state.failures.is_empty() && state.remove_then_errors.is_empty(),
            "the previous schedule did not consume every fault"
        );
        if require_clean {
            assert!(
                state.pending.is_empty(),
                "a clean schedule began with mutation debt"
            );
        }
        state.events.clear();
        state.ordinals.clear();
        state.failures = failures.into_iter().collect();
    }

    fn events(&self) -> Vec<PrimitiveEvent> {
        self.state.lock().events.clone()
    }

    fn pending_issues(&self) -> BTreeSet<u64> {
        self.state
            .lock()
            .pending
            .iter()
            .map(|mutation| match mutation {
                PendingMutation::Write { issue, .. } | PendingMutation::Resize { issue, .. } => {
                    *issue
                }
            })
            .collect()
    }

    fn assert_unsynchronized_finals(&self, names: &[&[u8]]) {
        let state = self.state.lock();
        for name in names {
            let location = Location::new(PARTITION, name);
            assert!(
                state.pending.iter().any(|mutation| matches!(
                    mutation,
                    PendingMutation::Write {
                        location: candidate,
                        offset,
                        bytes,
                        durable: false,
                        ..
                    } if candidate == &location
                        && ROOT_OFFSETS.contains(offset)
                        && bytes.len() == ROOT_LEN
                )),
                "the first publication did not leave final-root debt for {location:?}"
            );
        }
    }

    fn assert_failures_consumed(&self) {
        let state = self.state.lock();
        assert!(
            state.failures.is_empty() && state.remove_then_errors.is_empty(),
            "the scheduled primitive call was not reached"
        );
    }

    fn crash_plan(&self, retention: Retention) -> CrashPlan {
        let state = self.state.lock();
        let mut plan = CrashPlan::default();
        for mutation in &state.pending {
            match mutation {
                PendingMutation::Write {
                    issue,
                    event_len,
                    durable,
                    ..
                } => {
                    let mask = if *durable {
                        vec![true; *event_len]
                    } else {
                        retention.mask(*issue, *event_len)
                    };
                    if let Some(existing) = plan.writes.insert(*issue, mask.clone()) {
                        assert_eq!(existing, mask, "one write issue has one exact byte mask");
                    }
                }
                PendingMutation::Resize { issue, .. } => {
                    plan.resizes.insert(*issue, retention.retain_resize(*issue));
                }
            }
        }
        plan
    }

    fn crash(&self, plan: CrashPlan) -> Result<(), Error> {
        let pending = {
            let mut state = self.state.lock();
            state.failures.clear();
            state.remove_then_errors.clear();
            std::mem::take(&mut state.pending)
        };

        for mutation in pending {
            match mutation {
                PendingMutation::Write {
                    issue,
                    event_len,
                    source_start,
                    blob,
                    offset,
                    bytes,
                    ..
                } => {
                    let mask = plan
                        .writes
                        .get(&issue)
                        .unwrap_or_else(|| panic!("missing byte mask for write issue {issue}"));
                    assert_eq!(mask.len(), event_len, "write masks have exact widths");
                    let mut retained = mask[source_start..source_start + bytes.len()]
                        .iter()
                        .copied();
                    blob.retain_crash_write(offset, IoBufs::from(bytes), || {
                        retained.next().expect("one decision exists for every byte")
                    })?;
                    assert!(retained.next().is_none());
                }
                PendingMutation::Resize {
                    issue, blob, len, ..
                } => {
                    let retain = plan
                        .resizes
                        .get(&issue)
                        .unwrap_or_else(|| panic!("missing outcome for resize issue {issue}"));
                    if *retain {
                        blob.retain_crash_resize(len)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn clear_pending(&self, location: &Location) {
        self.state
            .lock()
            .pending
            .retain(|mutation| mutation.location() != location);
    }

    fn clear_removed(&self, partition: &str, name: Option<&[u8]>) {
        self.state.lock().pending.retain(|mutation| {
            let location = mutation.location();
            location.partition != partition
                || name.is_some_and(|name| location.name.as_slice() != name)
        });
    }
}

#[derive(Clone)]
struct ScheduledBlob {
    inner: memory::Blob,
    location: Location,
    state: Arc<SyncMutex<ScheduleState>>,
}

impl ScheduledBlob {
    fn record(&self, kind: EventKind) -> (u64, bool) {
        self.state.lock().record(self.location.clone(), kind)
    }

    fn record_pending_write(&self, issue: u64, offset: u64, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let event_len = bytes.len();
        self.state.lock().pending.push(PendingMutation::Write {
            issue,
            event_len,
            source_start: 0,
            location: self.location.clone(),
            blob: self.inner.clone(),
            offset,
            bytes,
            durable: false,
        });
    }

    fn retire_range(&self, issue: u64, offset: u64, bytes: &[u8]) {
        let len = bytes.len();
        let end = offset
            .checked_add(len as u64)
            .expect("the submitted write range was validated");
        let mut state = self.state.lock();
        let mutations = std::mem::take(&mut state.pending);
        let mut retained = Vec::with_capacity(mutations.len() + 1);
        let mut follows_resize = false;
        for mutation in mutations {
            let PendingMutation::Write {
                issue: pending_issue,
                event_len,
                source_start,
                location,
                blob,
                offset: write_offset,
                bytes,
                durable,
            } = mutation
            else {
                if matches!(
                    &mutation,
                    PendingMutation::Resize { location, .. } if location == &self.location
                ) {
                    follows_resize = true;
                }
                retained.push(mutation);
                continue;
            };
            if location != self.location {
                retained.push(PendingMutation::Write {
                    issue: pending_issue,
                    event_len,
                    source_start,
                    location,
                    blob,
                    offset: write_offset,
                    bytes,
                    durable,
                });
                continue;
            }
            let write_end = write_offset + bytes.len() as u64;
            let overlap_start = write_offset.max(offset);
            let overlap_end = write_end.min(end);
            if overlap_start >= overlap_end {
                retained.push(PendingMutation::Write {
                    issue: pending_issue,
                    event_len,
                    source_start,
                    location,
                    blob,
                    offset: write_offset,
                    bytes,
                    durable,
                });
                continue;
            }

            let prefix_len = usize::try_from(overlap_start - write_offset).unwrap();
            let suffix_start = usize::try_from(overlap_end - write_offset).unwrap();
            if prefix_len != 0 {
                retained.push(PendingMutation::Write {
                    issue: pending_issue,
                    event_len,
                    source_start,
                    location: location.clone(),
                    blob: blob.clone(),
                    offset: write_offset,
                    bytes: bytes[..prefix_len].to_vec(),
                    durable,
                });
            }
            if suffix_start != bytes.len() {
                retained.push(PendingMutation::Write {
                    issue: pending_issue,
                    event_len,
                    source_start: source_start + suffix_start,
                    location,
                    blob,
                    offset: overlap_end,
                    bytes: bytes[suffix_start..].to_vec(),
                    durable,
                });
            }
        }
        if follows_resize && !bytes.is_empty() {
            retained.push(PendingMutation::Write {
                issue,
                event_len: bytes.len(),
                source_start: 0,
                location: self.location.clone(),
                blob: self.inner.clone(),
                offset,
                bytes: bytes.to_vec(),
                durable: true,
            });
        }
        state.pending = retained;
    }

    async fn sync_inner(&self) -> Result<(), Error> {
        let (_, failed) = self.record(EventKind::Sync);
        if failed {
            return Err(injected_error());
        }
        self.inner.sync().await?;
        self.state
            .lock()
            .pending
            .retain(|mutation| mutation.location() != &self.location);
        Ok(())
    }
}

fn injected_error() -> Error {
    io::Error::other("scheduled storage fault").into()
}

impl crate::Blob for ScheduledBlob {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.inner.read_at(offset, len).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        let bufs = bufs.into();
        let bytes = bufs.clone().coalesce().as_ref().to_vec();
        let sync = options.contains(WriteOptions::SYNC);
        let (issue, failed) = self.record(EventKind::Write {
            offset,
            len: bytes.len(),
            sync,
        });

        if failed {
            self.inner
                .write_at(offset, bufs, options.without(WriteOptions::SYNC))
                .await?;
            self.record_pending_write(issue, offset, bytes);
            return Err(injected_error());
        }

        self.inner.write_at(offset, bufs, options).await?;
        if sync {
            self.retire_range(issue, offset, &bytes);
        } else {
            self.record_pending_write(issue, offset, bytes);
        }
        Ok(())
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let (issue, failed) = self.record(EventKind::Resize { len });
        self.inner.resize(len).await?;
        self.state.lock().pending.push(PendingMutation::Resize {
            issue,
            location: self.location.clone(),
            blob: self.inner.clone(),
            len,
        });
        if failed {
            Err(injected_error())
        } else {
            Ok(())
        }
    }

    async fn sync(&self) -> Result<(), Error> {
        self.sync_inner().await
    }

    async fn start_sync(&self) -> Handle<()> {
        Handle::ready(self.sync_inner().await)
    }
}

impl crate::Storage for ScheduledStorage {
    type Blob = ScheduledBlob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(Self::Blob, u64, u16), Error> {
        let (blob, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        Ok((self.wrap(partition, name, blob), len, version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        let location = Location::new(partition, name.unwrap_or_default());
        let (failed, remove_then_error, call) = {
            let mut state = self.state.lock();
            let (_, failed) = state.record(location, EventKind::Remove);
            let call = state.events.last().unwrap().call.clone();
            let remove_then_error = state.remove_then_errors.contains(&call);
            if remove_then_error {
                state.events.last_mut().unwrap().failed = true;
            }
            (failed, remove_then_error, call)
        };
        if failed {
            return Err(injected_error());
        }
        self.inner.remove(partition, name).await?;
        self.clear_removed(partition, name);
        if remove_then_error {
            assert!(self.state.lock().remove_then_errors.remove(&call));
            Err(injected_error())
        } else {
            Ok(())
        }
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

impl Backend for ScheduledStorage {
    type Worker = Self;

    fn atomic_worker(&self) -> Self::Worker {
        self.clone()
    }

    fn atomic_resources(&self) -> AtomicResources {
        <memory::Storage as Backend>::atomic_resources(&self.inner)
    }

    fn new_atomic_identifier(&self) -> [u8; INCARNATION_LEN] {
        let ordinal = self.identifiers.fetch_add(1, Ordering::Relaxed);
        let mut identifier = [0x5c; INCARNATION_LEN];
        identifier[INCARNATION_LEN - std::mem::size_of::<u64>()..]
            .copy_from_slice(&ordinal.to_be_bytes());
        identifier
    }

    async fn migrate_atomic_backing(
        &self,
        blob: Self::Blob,
        incarnation: [u8; INCARNATION_LEN],
    ) -> Result<(), Error> {
        let location = blob.location.clone();
        <memory::Storage as Backend>::migrate_atomic_backing(&self.inner, blob.inner, incarnation)
            .await?;
        self.clear_pending(&location);
        Ok(())
    }

    async fn open_atomic_existing(
        &self,
        partition: &str,
        name: &[u8],
    ) -> Result<Option<(Self::Blob, u64)>, Error> {
        Ok(
            <memory::Storage as Backend>::open_atomic_existing(&self.inner, partition, name)
                .await?
                .map(|(blob, len)| (self.wrap(partition, name, blob), len)),
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum Scenario {
    Direct,
    Pair,
    Triple,
}

impl Scenario {
    fn names(self) -> &'static [&'static [u8]] {
        match self {
            Self::Direct => &DIRECT_NAMES,
            Self::Pair => &PAIR_NAMES,
            Self::Triple => &TRIPLE_NAMES,
        }
    }

    fn initial(self, index: usize) -> &'static [u8] {
        match (self, index) {
            (Self::Direct, 0) => b"old",
            (_, 0) => b"old-a",
            (_, 1) => b"abcdef",
            (Self::Triple, 2) => b"victim",
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Value {
    data: Vec<u8>,
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct World(Vec<Option<Value>>);

#[derive(Clone, Copy)]
enum RecoveryEntry {
    Open(usize),
    Scan,
}

fn old_tag(index: usize) -> [u8; ATOMIC_BLOB_TAG_LEN] {
    [0x10 + index as u8; ATOMIC_BLOB_TAG_LEN]
}

fn new_tag(index: usize) -> [u8; ATOMIC_BLOB_TAG_LEN] {
    [0x20 + index as u8; ATOMIC_BLOB_TAG_LEN]
}

fn successor_tag() -> [u8; ATOMIC_BLOB_TAG_LEN] {
    [0x30; ATOMIC_BLOB_TAG_LEN]
}

fn test_pool() -> BufferPool {
    let mut registry = Registry::default();
    BufferPool::new(BufferPoolConfig::for_storage(), &mut registry)
}

fn expected_worlds(scenario: Scenario) -> (World, World) {
    let predecessor = World(
        scenario
            .names()
            .iter()
            .enumerate()
            .map(|(index, _)| {
                Some(Value {
                    data: scenario.initial(index).to_vec(),
                    tag: old_tag(index),
                })
            })
            .collect(),
    );
    let candidate = match scenario {
        Scenario::Direct => World(vec![Some(Value {
            data: b"old-new".to_vec(),
            tag: new_tag(0),
        })]),
        Scenario::Pair => World(vec![
            Some(Value {
                data: b"old-a-new".to_vec(),
                tag: new_tag(0),
            }),
            Some(Value {
                data: b"abc".to_vec(),
                tag: new_tag(1),
            }),
        ]),
        Scenario::Triple => World(vec![
            Some(Value {
                data: b"old-a-new".to_vec(),
                tag: new_tag(0),
            }),
            Some(Value {
                data: b"abc".to_vec(),
                tag: new_tag(1),
            }),
            None,
        ]),
    };
    (predecessor, candidate)
}

async fn initialize(scenario: Scenario) -> (ScheduledStorage, Vec<Blob<ScheduledBlob>>) {
    let storage = ScheduledStorage::new(test_pool());
    let mut blobs = Vec::new();
    for (index, name) in scenario.names().iter().enumerate() {
        let (blob, _) = storage.open_atomic(PARTITION, name).await.unwrap();
        blob.append_tagged(scenario.initial(index), old_tag(index))
            .await
            .unwrap();
        blob.sync().await.unwrap();
        blob.backing.sync().await.unwrap();
        blobs.push(blob);
    }
    storage.arm_clean([]);
    (storage, blobs)
}

async fn publish(
    scenario: Scenario,
    storage: &ScheduledStorage,
    blobs: &[Blob<ScheduledBlob>],
) -> Result<(), Error> {
    blobs[0].append_tagged(SUFFIX, new_tag(0)).await?;
    if matches!(scenario, Scenario::Direct) {
        return blobs[0].sync().await;
    }

    blobs[1].set_tag(new_tag(1)).await?;
    let mut operations = vec![
        BatchOperation::Publish(blobs[0].clone()),
        BatchOperation::Rewind {
            blob: blobs[1].clone(),
            len: 3,
        },
    ];
    if matches!(scenario, Scenario::Triple) {
        operations.insert(0, BatchOperation::Remove(blobs[2].clone()));
    }
    storage.apply(operations).await
}

async fn read_value(storage: &ScheduledStorage, name: &[u8]) -> Result<Value, Error> {
    let (blob, len) = storage.open_atomic(PARTITION, name).await?;
    let data = blob
        .read_at(0, len as usize)
        .await?
        .coalesce()
        .as_ref()
        .to_vec();
    Ok(Value {
        data,
        tag: blob.tag().await?,
    })
}

async fn observe_names(
    storage: &ScheduledStorage,
    scenario: Scenario,
    names: &[Vec<u8>],
) -> Result<World, Error> {
    let mut world = Vec::new();
    for name in scenario.names() {
        if !names.iter().any(|candidate| candidate.as_slice() == *name) {
            world.push(None);
            continue;
        }
        world.push(Some(read_value(storage, name).await?));
    }
    Ok(World(world))
}

async fn observe(storage: &ScheduledStorage, scenario: Scenario) -> Result<World, Error> {
    let names = storage.scan_atomic(PARTITION).await?;
    observe_names(storage, scenario, &names).await
}

async fn recover_via(
    storage: &ScheduledStorage,
    scenario: Scenario,
    expected: &World,
    entry: RecoveryEntry,
) -> Result<Vec<PrimitiveEvent>, Error> {
    match entry {
        RecoveryEntry::Open(index) => {
            let value = read_value(storage, scenario.names()[index]).await?;
            assert_eq!(Some(&value), expected.0[index].as_ref());
            let trace = storage.events();
            assert_eq!(observe(storage, scenario).await?, *expected);
            Ok(trace)
        }
        RecoveryEntry::Scan => {
            let names = storage.scan_atomic(PARTITION).await?;
            let trace = storage.events();
            let world = observe_names(storage, scenario, &names).await?;
            assert_eq!(world, *expected);
            Ok(trace)
        }
    }
}

async fn observe_in_order(
    storage: &ScheduledStorage,
    scenario: Scenario,
    order: &[usize],
) -> Result<World, Error> {
    assert_eq!(order.len(), scenario.names().len());
    let mut world = vec![None; order.len()];
    for &index in order {
        world[index] = Some(read_value(storage, scenario.names()[index]).await?);
    }
    Ok(World(world))
}

fn prepared_write_index(events: &[PrimitiveEvent], location: &Location) -> Option<usize> {
    events.iter().position(|event| {
        event.call.location == *location
            && matches!(
                event.call.kind,
                EventKind::Write {
                    offset,
                    len: ROOT_SLOT_SIZE,
                    sync: false,
                } if ROOT_OFFSETS.contains(&offset)
            )
    })
}

fn participant_barriers_completed(scenario: Scenario, events: &[PrimitiveEvent]) -> bool {
    scenario.names().iter().all(|name| {
        let location = Location::new(PARTITION, name);
        let Some(prepared) = prepared_write_index(events, &location) else {
            return false;
        };
        events[prepared + 1..].iter().any(|event| {
            event.call.location == location
                && matches!(event.call.kind, EventKind::Sync)
                && !event.failed
        })
    })
}

fn complete_prepared_publication_retained(
    scenario: Scenario,
    events: &[PrimitiveEvent],
    plan: &CrashPlan,
) -> bool {
    scenario.names().iter().all(|name| {
        let location = Location::new(PARTITION, name);
        let Some(prepared) = prepared_write_index(events, &location) else {
            return false;
        };
        if events[prepared + 1..].iter().any(|event| {
            event.call.location == location
                && matches!(event.call.kind, EventKind::Sync)
                && !event.failed
        }) {
            return true;
        }

        events[..=prepared]
            .iter()
            .filter(|event| {
                event.call.location == location
                    && matches!(event.call.kind, EventKind::Write { .. })
            })
            .all(|event| {
                plan.writes
                    .get(&event.issue)
                    .is_some_and(|mask| mask.iter().all(|retained| *retained))
            })
    })
}

fn publication_candidate_authoritative(
    scenario: Scenario,
    events: &[PrimitiveEvent],
    plan: &CrashPlan,
) -> bool {
    participant_barriers_completed(scenario, events)
        || complete_prepared_publication_retained(scenario, events, plan)
}

fn assert_complete_world(actual: &World, predecessor: &World, candidate: &World) {
    assert!(
        actual == predecessor || actual == candidate,
        "recovery selected a mixed world: {actual:?}"
    );
}

async fn assert_idempotent_and_usable(
    storage: &ScheduledStorage,
    scenario: Scenario,
    recovered: &World,
) {
    let plan = storage.crash_plan(Retention::Discard);
    storage.crash(plan).unwrap();
    storage.arm_clean([]);
    let repeated = observe(storage, scenario).await.unwrap();
    assert_eq!(&repeated, recovered);

    let plan = storage.crash_plan(Retention::Discard);
    storage.crash(plan).unwrap();
    storage.arm_clean([]);
    let original = recovered.0[0].as_ref().unwrap();
    let (blob, len) = storage.open_atomic(PARTITION, b"a").await.unwrap();
    assert_eq!(len as usize, original.data.len());
    blob.append_tagged(b"!", [0x70; ATOMIC_BLOB_TAG_LEN])
        .await
        .unwrap();
    blob.sync().await.unwrap();
    drop(blob);
    let plan = storage.crash_plan(Retention::Discard);
    storage.crash(plan).unwrap();
    storage.arm_clean([]);
    let (blob, len) = storage.open_atomic(PARTITION, b"a").await.unwrap();
    let mut expected = original.data.clone();
    expected.push(b'!');
    assert_eq!(len as usize, expected.len());
    assert_eq!(
        blob.read_at(0, expected.len())
            .await
            .unwrap()
            .coalesce()
            .as_ref(),
        expected
    );
    assert_eq!(blob.tag().await.unwrap(), [0x70; ATOMIC_BLOB_TAG_LEN]);
}

async fn publication_trace(scenario: Scenario) -> Vec<PrimitiveEvent> {
    let (storage, blobs) = initialize(scenario).await;
    publish(scenario, &storage, &blobs).await.unwrap();
    storage.events()
}

fn overlap_worlds() -> (World, World) {
    let first = expected_worlds(Scenario::Pair).1;
    let mut successor = first.clone();
    let value = successor.0[0].as_mut().unwrap();
    value.data.extend_from_slice(b"-next");
    value.tag = successor_tag();
    (first, successor)
}

async fn initialize_overlap() -> (ScheduledStorage, Vec<Blob<ScheduledBlob>>, BTreeSet<u64>) {
    let (storage, blobs) = initialize(Scenario::Pair).await;
    publish(Scenario::Pair, &storage, &blobs).await.unwrap();
    storage.assert_unsynchronized_finals(Scenario::Pair.names());
    let prior_debt = storage.pending_issues();
    assert!(!prior_debt.is_empty());
    storage.arm([]);
    (storage, blobs, prior_debt)
}

async fn publish_overlap_successor(blobs: &[Blob<ScheduledBlob>]) -> Result<(), Error> {
    blobs[0].append_tagged(b"-next", successor_tag()).await?;
    blobs[0].sync().await
}

async fn overlap_sync_trace() -> Vec<PrimitiveEvent> {
    let (storage, blobs, prior_debt) = initialize_overlap().await;
    publish_overlap_successor(&blobs).await.unwrap();
    let events = storage.events();
    let last_prior_issue = prior_debt.last().copied().unwrap();
    assert!(events.iter().all(|event| event.issue > last_prior_issue));
    events
        .into_iter()
        .filter(|event| matches!(event.call.kind, EventKind::Sync))
        .collect()
}

fn reincarnation_worlds() -> (World, World) {
    let predecessor = World(vec![
        Some(Value {
            data: b"old-a-kept".to_vec(),
            tag: [0x41; ATOMIC_BLOB_TAG_LEN],
        }),
        Some(Value {
            data: b"new-b".to_vec(),
            tag: [0x42; ATOMIC_BLOB_TAG_LEN],
        }),
    ]);
    let mut candidate = predecessor.clone();
    for (index, value) in candidate.0.iter_mut().enumerate() {
        let value = value.as_mut().unwrap();
        value.data.extend_from_slice(b"-later");
        value.tag = [0x51 + index as u8; ATOMIC_BLOB_TAG_LEN];
    }
    (predecessor, candidate)
}

async fn initialize_reincarnation_history() -> (
    ScheduledStorage,
    Blob<ScheduledBlob>,
    Blob<ScheduledBlob>,
    [u8; INCARNATION_LEN],
) {
    let (storage, blobs) = initialize(Scenario::Pair).await;
    let old_incarnation = blobs[1].incarnation;
    blobs[0]
        .append_tagged(b"-kept", [0x41; ATOMIC_BLOB_TAG_LEN])
        .await
        .unwrap();
    storage
        .apply(vec![
            BatchOperation::Remove(blobs[1].clone()),
            BatchOperation::Publish(blobs[0].clone()),
        ])
        .await
        .unwrap();
    drop(blobs);

    let plan = storage.crash_plan(Retention::Discard);
    storage.crash(plan).unwrap();
    storage.arm_clean([]);
    let (replacement, len) = storage.open_atomic(PARTITION, b"b").await.unwrap();
    assert_eq!(len, 0);
    let new_incarnation = replacement.incarnation;
    assert_ne!(new_incarnation, old_incarnation);
    replacement
        .append_tagged(b"new-b", [0x42; ATOMIC_BLOB_TAG_LEN])
        .await
        .unwrap();
    replacement.sync().await.unwrap();
    replacement.backing.sync().await.unwrap();

    let (survivor, len) = storage.open_atomic(PARTITION, b"a").await.unwrap();
    assert_eq!(len, b"old-a-kept".len() as u64);
    storage.arm_clean([]);
    (storage, survivor, replacement, new_incarnation)
}

async fn publish_reincarnation_successor(
    storage: &ScheduledStorage,
    survivor: &Blob<ScheduledBlob>,
    replacement: &Blob<ScheduledBlob>,
) -> Result<(), Error> {
    survivor
        .append_tagged(b"-later", [0x51; ATOMIC_BLOB_TAG_LEN])
        .await?;
    replacement
        .append_tagged(b"-later", [0x52; ATOMIC_BLOB_TAG_LEN])
        .await?;
    storage
        .apply(vec![
            BatchOperation::Publish(survivor.clone()),
            BatchOperation::Publish(replacement.clone()),
        ])
        .await
}

async fn reincarnation_successor_trace() -> Vec<PrimitiveEvent> {
    let (storage, survivor, replacement, _) = initialize_reincarnation_history().await;
    publish_reincarnation_successor(&storage, &survivor, &replacement)
        .await
        .unwrap();
    storage.events()
}

fn call_identity(name: &[u8], ordinal: u64, kind: EventKind) -> CallIdentity {
    CallIdentity {
        location: Location::new(PARTITION, name),
        ordinal,
        kind,
    }
}

async fn initialize_raw(name: &[u8], bytes: &[u8]) -> (ScheduledStorage, ScheduledBlob) {
    let storage = ScheduledStorage::new(test_pool());
    let (blob, _) = storage.open(PARTITION, name).await.unwrap();
    blob.write_at(0, bytes.to_vec(), WriteOptions::SYNC)
        .await
        .unwrap();
    storage.arm_clean([]);
    (storage, blob)
}

async fn raw_image(storage: &ScheduledStorage, name: &[u8]) -> Vec<u8> {
    let (blob, len) = storage.open(PARTITION, name).await.unwrap();
    blob.read_at(0, len as usize)
        .await
        .unwrap()
        .coalesce()
        .as_ref()
        .to_vec()
}

async fn publication_fault_case(
    scenario: Scenario,
    failed_call: CallIdentity,
    retention: Retention,
) {
    let (storage, blobs) = initialize(scenario).await;
    storage.arm_clean([failed_call]);
    assert!(publish(scenario, &storage, &blobs).await.is_err());
    storage.assert_failures_consumed();
    drop(blobs);

    let plan = storage.crash_plan(retention);
    let events = storage.events();
    let candidate_authoritative = publication_candidate_authoritative(scenario, &events, &plan);
    storage.crash(plan).unwrap();
    storage.arm_clean([]);
    let actual = observe(&storage, scenario).await.unwrap();
    let (predecessor, candidate) = expected_worlds(scenario);
    assert_complete_world(&actual, &predecessor, &candidate);
    let expected = if candidate_authoritative {
        &candidate
    } else {
        &predecessor
    };
    assert_eq!(&actual, expected);
    assert_idempotent_and_usable(&storage, scenario, &actual).await;
}

#[test]
fn exact_publication_faults_never_mix_worlds() {
    deterministic::Runner::seeded(0x5c4e_d001).start(|_| async move {
        for scenario in [Scenario::Direct, Scenario::Pair, Scenario::Triple] {
            let trace = publication_trace(scenario).await;
            assert!(!trace.is_empty());
            for event in trace {
                for retention in [Retention::Discard, Retention::Keep, Retention::Stripe] {
                    publication_fault_case(scenario, event.call.clone(), retention).await;
                }
            }
        }
    });
}

#[test]
fn participant_sync_outcomes_have_exact_oracles() {
    deterministic::Runner::seeded(0x5c4e_d002).start(|_| async move {
        for scenario in [Scenario::Direct, Scenario::Pair, Scenario::Triple] {
            let trace = publication_trace(scenario).await;
            let syncs = trace
                .iter()
                .filter(|event| matches!(event.call.kind, EventKind::Sync))
                .map(|event| event.call.clone())
                .collect::<Vec<_>>();
            assert_eq!(syncs.len(), scenario.names().len());

            for failed in 0..1usize << syncs.len() {
                for retention in [Retention::Discard, Retention::Keep] {
                    let (storage, blobs) = initialize(scenario).await;
                    let failures = syncs
                        .iter()
                        .enumerate()
                        .filter_map(|(index, call)| {
                            (failed & (1 << index) != 0).then_some(call.clone())
                        })
                        .collect::<Vec<_>>();
                    storage.arm_clean(failures);
                    let result = publish(scenario, &storage, &blobs).await;
                    assert_eq!(result.is_err(), failed != 0);
                    storage.assert_failures_consumed();
                    drop(blobs);
                    let plan = storage.crash_plan(retention);
                    let events = storage.events();
                    let candidate_authoritative =
                        publication_candidate_authoritative(scenario, &events, &plan);
                    storage.crash(plan).unwrap();
                    storage.arm_clean([]);
                    let actual = observe(&storage, scenario).await.unwrap();
                    let (predecessor, candidate) = expected_worlds(scenario);
                    let expected = if candidate_authoritative {
                        &candidate
                    } else {
                        &predecessor
                    };
                    assert_eq!(&actual, expected);
                }
            }
        }
    });
}

#[test]
fn overlapping_publications_pay_hidden_debt_exactly() {
    deterministic::Runner::seeded(0x5c4e_d004).start(|_| async move {
        let syncs = overlap_sync_trace().await;
        assert_eq!(syncs.len(), 2);
        assert_eq!(
            syncs
                .iter()
                .map(|event| event.call.location.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                Location::new(PARTITION, b"a"),
                Location::new(PARTITION, b"b"),
            ])
        );

        for failed in 0..1usize << syncs.len() {
            for retention in [Retention::Discard, Retention::Keep] {
                for order in [[0, 1], [1, 0]] {
                    let (storage, blobs, prior_debt) = initialize_overlap().await;
                    let failures = syncs.iter().enumerate().filter_map(|(index, event)| {
                        (failed & (1 << index) != 0).then_some(event.call.clone())
                    });
                    storage.arm(failures);
                    let result = publish_overlap_successor(&blobs).await;
                    assert_eq!(result.is_err(), failed != 0);
                    storage.assert_failures_consumed();
                    let events = storage.events();
                    let last_prior_issue = prior_debt.last().copied().unwrap();
                    assert!(events.iter().all(|event| event.issue > last_prior_issue));
                    drop(blobs);

                    let plan = storage.crash_plan(retention);
                    // The first ring is already durable. The strict-subset successor is selected
                    // exactly when A's complete self-linked preparation is durable; recovery
                    // independently closes any retained first-ring debt on B.
                    let successor_authoritative =
                        publication_candidate_authoritative(Scenario::Direct, &events, &plan);
                    storage.crash(plan).unwrap();
                    storage.arm_clean([]);

                    let actual = observe_in_order(&storage, Scenario::Pair, &order)
                        .await
                        .unwrap();
                    let (first, successor) = overlap_worlds();
                    assert_complete_world(&actual, &first, &successor);
                    let expected = if successor_authoritative {
                        &successor
                    } else {
                        &first
                    };
                    assert_eq!(&actual, expected);
                    assert_idempotent_and_usable(&storage, Scenario::Pair, &actual).await;
                }
            }
        }
    });
}

#[test]
fn recreated_participant_joins_a_later_ring_exactly() {
    deterministic::Runner::seeded(0x5c4e_d009).start(|_| async move {
        let failed_sync = reincarnation_successor_trace()
            .await
            .into_iter()
            .find(|event| {
                event.call.location == Location::new(PARTITION, b"b")
                    && matches!(event.call.kind, EventKind::Sync)
            })
            .expect("the replacement participates in the group durability barrier")
            .call;

        for retention in [Retention::Discard, Retention::Keep] {
            let (storage, survivor, replacement, new_incarnation) =
                initialize_reincarnation_history().await;
            storage.arm_clean([failed_sync.clone()]);
            assert!(
                publish_reincarnation_successor(&storage, &survivor, &replacement)
                    .await
                    .is_err()
            );
            storage.assert_failures_consumed();
            drop(survivor);
            drop(replacement);

            let plan = storage.crash_plan(retention);
            let events = storage.events();
            let candidate_authoritative =
                publication_candidate_authoritative(Scenario::Pair, &events, &plan);
            assert_eq!(
                candidate_authoritative,
                matches!(retention, Retention::Keep)
            );
            storage.crash(plan).unwrap();
            storage.arm_clean([]);

            let (predecessor, candidate) = reincarnation_worlds();
            let expected = if matches!(retention, Retention::Keep) {
                &candidate
            } else {
                &predecessor
            };
            let actual = observe_in_order(&storage, Scenario::Pair, &[0, 1])
                .await
                .unwrap();
            assert_eq!(&actual, expected);
            let (opened, _) = storage.open_atomic(PARTITION, b"b").await.unwrap();
            assert_eq!(opened.incarnation, new_incarnation);
            drop(opened);
            assert_idempotent_and_usable(&storage, Scenario::Pair, &actual).await;
        }
    });
}

#[test]
fn backend_explicit_masks_replay_overlapping_writes_in_issue_order() {
    deterministic::Runner::seeded(0x5c4e_d005).start(|_| async move {
        let name = b"mechanics-overlap";
        let (storage, blob) = initialize_raw(name, b"........").await;
        blob.write_at(0, b"ABCDEFGH".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(2, b"wxyz".to_vec(), WriteOptions::default())
            .await
            .unwrap();

        let events = storage.events();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0].call,
            call_identity(
                name,
                0,
                EventKind::Write {
                    offset: 0,
                    len: 8,
                    sync: false,
                },
            )
        );
        assert_eq!(
            events[1].call,
            call_identity(
                name,
                1,
                EventKind::Write {
                    offset: 2,
                    len: 4,
                    sync: false,
                },
            )
        );
        let mut plan = storage.crash_plan(Retention::Discard);
        plan.writes.insert(
            events[0].issue,
            vec![true, false, true, false, true, false, true, false],
        );
        plan.writes
            .insert(events[1].issue, vec![false, true, true, false]);
        drop(blob);
        storage.crash(plan).unwrap();
        storage.arm_clean([]);

        assert_eq!(raw_image(&storage, name).await, b"A.Cxy.G.");
    });
}

#[test]
fn backend_range_sync_replays_after_retained_resize() {
    deterministic::Runner::seeded(0x5c4e_d006).start(|_| async move {
        let name = b"mechanics-range";
        let (storage, blob) = initialize_raw(name, b"abcdefghij").await;
        blob.write_at(0, b"ABCDEFGHIJ".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.resize(3).await.unwrap();
        blob.write_at(6, b"WXYZ".to_vec(), WriteOptions::SYNC)
            .await
            .unwrap();

        let events = storage.events();
        assert_eq!(events.len(), 3);
        let write_issue = events
            .iter()
            .find(|event| {
                event.call.kind
                    == (EventKind::Write {
                        offset: 0,
                        len: 10,
                        sync: false,
                    })
            })
            .unwrap()
            .issue;
        let resize_issue = events
            .iter()
            .find(|event| event.call.kind == EventKind::Resize { len: 3 })
            .unwrap()
            .issue;
        assert!(events.iter().any(|event| {
            event.call.kind
                == (EventKind::Write {
                    offset: 6,
                    len: 4,
                    sync: true,
                })
        }));

        let mut plan = storage.crash_plan(Retention::Discard);
        plan.writes.insert(write_issue, vec![true; 10]);
        plan.resizes.insert(resize_issue, true);
        drop(blob);
        storage.crash(plan).unwrap();
        storage.arm_clean([]);

        assert_eq!(raw_image(&storage, name).await, b"ABC\0\0\0WXYZ".to_vec());
    });
}

#[test]
fn backend_range_sync_retires_overlap_and_preserves_mask_alignment() {
    deterministic::Runner::seeded(0x5c4e_d007).start(|_| async move {
        let name = b"mechanics-range-overlap";
        let (storage, blob) = initialize_raw(name, b"........").await;
        blob.write_at(0, b"ABCDEFGH".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(3, b"xy".to_vec(), WriteOptions::SYNC)
            .await
            .unwrap();

        let events = storage.events();
        assert_eq!(events.len(), 2);
        let write_issue = events
            .iter()
            .find(|event| {
                event.call.kind
                    == (EventKind::Write {
                        offset: 0,
                        len: 8,
                        sync: false,
                    })
            })
            .unwrap()
            .issue;
        assert!(events.iter().any(|event| {
            event.call.kind
                == (EventKind::Write {
                    offset: 3,
                    len: 2,
                    sync: true,
                })
        }));

        let mut plan = storage.crash_plan(Retention::Discard);
        plan.writes.insert(
            write_issue,
            vec![true, false, false, true, true, false, true, true],
        );
        drop(blob);
        storage.crash(plan).unwrap();
        storage.arm_clean([]);

        assert_eq!(raw_image(&storage, name).await, b"A..xy.GH");
    });
}

#[test]
fn backend_failed_full_sync_leaves_mutation_debt() {
    deterministic::Runner::seeded(0x5c4e_d008).start(|_| async move {
        let name = b"mechanics-full-sync";
        let (storage, blob) = initialize_raw(name, b"........").await;
        let failed_sync = call_identity(name, 1, EventKind::Sync);
        storage.arm_clean([failed_sync.clone()]);
        blob.write_at(0, b"ABCDEFGH".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        assert!(blob.sync().await.is_err());
        storage.assert_failures_consumed();

        let events = storage.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].call, failed_sync);
        assert!(events[1].failed);
        let mut plan = storage.crash_plan(Retention::Discard);
        plan.writes.insert(
            events[0].issue,
            vec![false, true, false, false, true, false, false, true],
        );
        drop(blob);
        storage.crash(plan).unwrap();
        storage.arm_clean([]);

        assert_eq!(raw_image(&storage, name).await, b".B..E..H");
    });
}

#[derive(Clone, Copy)]
enum RecoveryFixture {
    CandidateGroup,
    RejectedSlot,
    ShortIdentity,
}

impl RecoveryFixture {
    fn scenario(self) -> Scenario {
        match self {
            Self::CandidateGroup => Scenario::Triple,
            Self::RejectedSlot | Self::ShortIdentity => Scenario::Direct,
        }
    }

    fn expected(self) -> World {
        match self {
            Self::CandidateGroup => expected_worlds(Scenario::Triple).1,
            Self::RejectedSlot => expected_worlds(Scenario::Direct).0,
            Self::ShortIdentity => World(vec![Some(Value {
                data: Vec::new(),
                tag: [0; ATOMIC_BLOB_TAG_LEN],
            })]),
        }
    }
}

async fn recovery_image(
    fixture: RecoveryFixture,
    rejected_write: &CallIdentity,
) -> ScheduledStorage {
    match fixture {
        RecoveryFixture::CandidateGroup => {
            let scenario = fixture.scenario();
            let (storage, blobs) = initialize(scenario).await;
            publish(scenario, &storage, &blobs).await.unwrap();
            drop(blobs);
            let plan = storage.crash_plan(Retention::Discard);
            storage.crash(plan).unwrap();
            storage.arm_clean([]);
            storage
        }
        RecoveryFixture::RejectedSlot => {
            let scenario = fixture.scenario();
            let (storage, blobs) = initialize(scenario).await;
            storage.arm_clean([rejected_write.clone()]);
            assert!(publish(scenario, &storage, &blobs).await.is_err());
            storage.assert_failures_consumed();
            drop(blobs);
            let plan = storage.crash_plan(Retention::Stripe);
            storage.crash(plan).unwrap();
            storage.arm_clean([]);
            storage
        }
        RecoveryFixture::ShortIdentity => {
            let (storage, blob) = initialize_raw(b"a", &encode_identity([0x3C; 16])).await;
            drop(blob);
            storage
        }
    }
}

async fn retry_recovery_after_fault(
    storage: &ScheduledStorage,
    scenario: Scenario,
    expected: &World,
    entry: RecoveryEntry,
    retention: Retention,
) {
    storage.assert_failures_consumed();
    let plan = storage.crash_plan(retention);
    storage.crash(plan).unwrap();
    storage.arm_clean([]);
    recover_via(storage, scenario, expected, entry)
        .await
        .unwrap();
    assert_idempotent_and_usable(storage, scenario, expected).await;
}

#[test]
fn recovery_primitive_failures_are_retryable() {
    deterministic::Runner::seeded(0x5c4e_d003).start(|_| async move {
        let rejected_write = publication_trace(Scenario::Direct)
            .await
            .into_iter()
            .find(|event| {
                matches!(
                    event.call.kind,
                    EventKind::Write {
                        len: ROOT_SLOT_SIZE,
                        sync: false,
                        ..
                    }
                )
            })
            .unwrap()
            .call;

        for (fixture, entry) in [
            (RecoveryFixture::CandidateGroup, RecoveryEntry::Open(1)),
            (RecoveryFixture::CandidateGroup, RecoveryEntry::Scan),
            (RecoveryFixture::RejectedSlot, RecoveryEntry::Open(0)),
            (RecoveryFixture::ShortIdentity, RecoveryEntry::Open(0)),
        ] {
            let scenario = fixture.scenario();
            let expected = fixture.expected();
            let storage = recovery_image(fixture, &rejected_write).await;
            let recovery_trace = recover_via(&storage, scenario, &expected, entry)
                .await
                .unwrap();
            match fixture {
                RecoveryFixture::CandidateGroup => assert!(
                    recovery_trace
                        .iter()
                        .any(|event| matches!(event.call.kind, EventKind::Remove))
                ),
                RecoveryFixture::RejectedSlot => assert!(recovery_trace.iter().any(|event| {
                    matches!(
                        event.call.kind,
                        EventKind::Write {
                            len: ROOT_SLOT_SIZE,
                            sync: true,
                            ..
                        }
                    )
                })),
                RecoveryFixture::ShortIdentity => {
                    assert!(recovery_trace.iter().any(|event| {
                        event.call.kind == (EventKind::Resize { len: DATA_OFFSET })
                    }));
                    assert!(
                        recovery_trace
                            .iter()
                            .any(|event| matches!(event.call.kind, EventKind::Sync))
                    );
                }
            }

            for event in &recovery_trace {
                for retention in [Retention::Discard, Retention::Keep] {
                    let storage = recovery_image(fixture, &rejected_write).await;
                    storage.arm_clean([event.call.clone()]);
                    assert!(
                        recover_via(&storage, scenario, &expected, entry)
                            .await
                            .is_err()
                    );
                    retry_recovery_after_fault(&storage, scenario, &expected, entry, retention)
                        .await;
                }
            }

            let Some(remove_call) = recovery_trace
                .iter()
                .find(|event| matches!(event.call.kind, EventKind::Remove))
                .map(|event| event.call.clone())
            else {
                continue;
            };
            // The injected error follows the unlink, after earlier recovery writes are
            // durable, so there is no remaining mutation whose retention can vary.
            let storage = recovery_image(fixture, &rejected_write).await;
            storage.arm_clean_remove_then_error(remove_call);
            assert!(
                recover_via(&storage, scenario, &expected, entry)
                    .await
                    .is_err()
            );
            retry_recovery_after_fault(&storage, scenario, &expected, entry, Retention::Discard)
                .await;
        }
    });
}
