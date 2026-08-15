//! Model-based fuzzing for atomic blob crash recovery.
//!
//! One input drives a fixed namespace through multiple operation cycles. A `Crash` ends the
//! current cycle, `start_and_recover` applies the existing faulty-memory crash semantics, and the
//! next cycle first recovers from a name present in at least one allowed world before scanning the
//! namespace.
//!
//! The model keeps immediately visible state separate from durable state. A failed publication
//! may recover either its complete predecessor world or its complete candidate world, but never a
//! per-blob mixture. Faults are selected per mutating operation so a trace can build state without
//! faults and then target a later payload, root, barrier, resize, or removal.

#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(dead_code))]

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{
    ATOMIC_BLOB_TAG_LEN, AtomicBlob as _, AtomicStorage, BatchOperation, Error, IntegrityBoundary,
    IntegrityScheme, IntegrityToken, IntegrityUnit, Runner as _,
    deterministic::{self, FaultConfig, PartialWriteMode},
};
#[cfg(not(test))]
use libfuzzer_sys::fuzz_target;
use std::{mem::size_of, num::NonZeroU32};

const PARTITION: &str = "atomic-fuzz";
const NAMES: [&[u8]; 3] = [b"a", b"b", b"c"];
const MAX_OPERATIONS: usize = 48;
const MAX_CRASHES: usize = 8;
const MAX_APPEND_LEN: usize = 16;
const MAX_BLOB_LEN: usize = 128;

type AtomicBlob = <deterministic::Context as AtomicStorage>::AtomicBlob;
type Handles = [Option<AtomicBlob>; NAMES.len()];

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Failure {
    None,
    Read,
    Write,
    PartialWritePrefix,
    PartialWriteSubset,
    Sync,
    Resize,
    PartialResize,
    Remove,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Retention {
    None,
    Full,
    Random,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
struct Faults {
    failure: Failure,
    retention: Retention,
    resize_retention: Retention,
}

impl Faults {
    fn config(self) -> FaultConfig {
        let write_retention = match self.failure {
            Failure::PartialWritePrefix => Some((PartialWriteMode::Prefix, 0.5)),
            Failure::PartialWriteSubset => Some((PartialWriteMode::Subset, 0.5)),
            _ => match self.retention {
                Retention::None => None,
                Retention::Full => Some((PartialWriteMode::Prefix, 1.0)),
                Retention::Random => Some((PartialWriteMode::Subset, 0.5)),
            },
        };
        let mut config = match self.failure {
            Failure::None => FaultConfig::default(),
            Failure::Read => FaultConfig::default().read(1.0),
            Failure::Write => FaultConfig::default().write(1.0),
            Failure::PartialWritePrefix | Failure::PartialWriteSubset => {
                FaultConfig::default().write(1.0)
            }
            Failure::Sync => FaultConfig::default().sync(1.0),
            Failure::Resize => FaultConfig::default().resize(1.0),
            Failure::PartialResize => FaultConfig::default().resize(1.0).partial_resize(1.0),
            Failure::Remove => FaultConfig::default().remove(1.0),
        };
        config.write_retention = write_retention;
        config.crash_resize_rate = match self.resize_retention {
            Retention::None => None,
            Retention::Full => Some(1.0),
            Retention::Random => Some(0.5),
        };
        config
    }
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum IntegrityBoundaryInput {
    Continue,
    Complete,
    Chunked { width: u8 },
}

#[derive(Arbitrary, Clone, Debug)]
enum BatchKind {
    Publish,
    Rewind { len: u16 },
    Remove,
}

#[derive(Arbitrary, Clone, Debug)]
struct BatchMember {
    blob: u8,
    kind: BatchKind,
}

#[derive(Clone, Debug)]
enum Operation {
    Append {
        blob: u8,
        data: Vec<u8>,
        faults: Faults,
    },
    AppendTagged {
        blob: u8,
        data: Vec<u8>,
        tag: u8,
        faults: Faults,
    },
    SetTag {
        blob: u8,
        tag: u8,
    },
    CompareSetTag {
        blob: u8,
        tag: u8,
        stale: bool,
    },
    AppendIntegrity {
        blob: u8,
        data: Vec<u8>,
        boundary: IntegrityBoundaryInput,
        tagged: bool,
        tag: u8,
        faults: Faults,
    },
    Rewind {
        blob: u8,
        len: u16,
    },
    RewindTagged {
        blob: u8,
        len: u16,
        tag: u8,
    },
    RewindIntegrity {
        blob: u8,
        unit: u8,
        retain: u8,
        tagged: bool,
        tag: u8,
        faults: Faults,
    },
    Sync {
        blob: u8,
        faults: Faults,
    },
    Batch {
        members: Vec<BatchMember>,
        faults: Faults,
        drop_completion: bool,
    },
    Read {
        blob: u8,
        offset: u16,
        len: u8,
    },
    ReadIntegrity {
        blob: u8,
        unit: u8,
        faults: Faults,
    },
    Recreate {
        blob: u8,
    },
    Crash,
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let operation = match u.int_in_range(0..=13u8)? {
            0 => Self::Append {
                blob: u.arbitrary()?,
                data: bounded_data(u)?,
                faults: u.arbitrary()?,
            },
            1 => Self::AppendTagged {
                blob: u.arbitrary()?,
                data: bounded_data(u)?,
                tag: u.arbitrary()?,
                faults: u.arbitrary()?,
            },
            2 => Self::SetTag {
                blob: u.arbitrary()?,
                tag: u.arbitrary()?,
            },
            3 => Self::CompareSetTag {
                blob: u.arbitrary()?,
                tag: u.arbitrary()?,
                stale: u.arbitrary()?,
            },
            4 => Self::AppendIntegrity {
                blob: u.arbitrary()?,
                data: bounded_data(u)?,
                boundary: u.arbitrary()?,
                tagged: u.arbitrary()?,
                tag: u.arbitrary()?,
                faults: u.arbitrary()?,
            },
            5 => Self::Rewind {
                blob: u.arbitrary()?,
                len: u.arbitrary()?,
            },
            6 => Self::RewindTagged {
                blob: u.arbitrary()?,
                len: u.arbitrary()?,
                tag: u.arbitrary()?,
            },
            7 => Self::RewindIntegrity {
                blob: u.arbitrary()?,
                unit: u.arbitrary()?,
                retain: u.arbitrary()?,
                tagged: u.arbitrary()?,
                tag: u.arbitrary()?,
                faults: u.arbitrary()?,
            },
            8 => Self::Sync {
                blob: u.arbitrary()?,
                faults: u.arbitrary()?,
            },
            9 => {
                let member_count = u.int_in_range(0..=NAMES.len())?;
                let members = (0..member_count)
                    .map(|_| u.arbitrary())
                    .collect::<Result<Vec<_>, _>>()?;
                Self::Batch {
                    members,
                    faults: u.arbitrary()?,
                    drop_completion: u.arbitrary()?,
                }
            }
            10 => Self::Read {
                blob: u.arbitrary()?,
                offset: u.arbitrary()?,
                len: u.arbitrary()?,
            },
            11 => Self::ReadIntegrity {
                blob: u.arbitrary()?,
                unit: u.arbitrary()?,
                faults: u.arbitrary()?,
            },
            12 => Self::Recreate {
                blob: u.arbitrary()?,
            },
            13 => Self::Crash,
            _ => unreachable!(),
        };
        Ok(operation)
    }
}

#[derive(Debug)]
struct FuzzInput {
    seed: u64,
    recovery_entry: u8,
    operations: Vec<Operation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.arbitrary()?;
        let recovery_entry = u.arbitrary()?;
        let operation_count = u.int_in_range(0..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(operation_count);
        let mut crashes = 0;
        for _ in 0..operation_count {
            let operation = Operation::arbitrary(u)?;
            if matches!(operation, Operation::Crash) {
                if crashes == MAX_CRASHES {
                    continue;
                }
                crashes += 1;
            }
            operations.push(operation);
        }
        Ok(Self {
            seed,
            recovery_entry,
            operations,
        })
    }
}

fn bounded_data(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(0..=MAX_APPEND_LEN)?;
    Ok(u.bytes(len)?.to_vec())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntegrityUnitState {
    unit: IntegrityUnit,
    data: Vec<u8>,
}

impl IntegrityUnitState {
    fn encoded_end(&self) -> u64 {
        self.unit
            .offset
            .checked_add(self.unit.len)
            .and_then(|end| end.checked_add(size_of::<u32>() as u64))
            .expect("bounded integrity units cannot overflow")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlobState {
    data: Vec<u8>,
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
    scheme: IntegrityScheme,
    tail: Option<IntegrityUnitState>,
    completed: Vec<IntegrityUnitState>,
}

impl Default for BlobState {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            tag: [0; ATOMIC_BLOB_TAG_LEN],
            scheme: IntegrityScheme::Unbound,
            tail: None,
            completed: Vec::new(),
        }
    }
}

impl BlobState {
    fn observable_eq(&self, other: &Self) -> bool {
        self.data == other.data
            && self.tag == other.tag
            && self.scheme == other.scheme
            && self.tail == other.tail
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct World(
    [Option<BlobState>; NAMES.len()],
    [Option<commonware_runtime::IntegrityToken>; NAMES.len()],
);

impl World {
    fn absent() -> Self {
        Self(std::array::from_fn(|_| None), std::array::from_fn(|_| None))
    }

    fn initialized() -> Self {
        Self(
            std::array::from_fn(|_| Some(BlobState::default())),
            std::array::from_fn(|_| None),
        )
    }

    fn observable_eq(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(&other.0)
            .all(|(left, right)| match (left, right) {
                (Some(left), Some(right)) => left.observable_eq(right),
                (None, None) => true,
                _ => false,
            })
    }
}

#[derive(Clone, Debug)]
struct Expected(Vec<World>);

impl Expected {
    fn exact(world: World) -> Self {
        Self(vec![world])
    }

    fn either(predecessor: World, candidate: World) -> Self {
        if predecessor == candidate {
            Self::exact(predecessor)
        } else {
            Self(vec![predecessor, candidate])
        }
    }

    async fn resolve(&self, actual: World, handles: &Handles) -> World {
        let expected = self
            .0
            .iter()
            .find(|expected| expected.observable_eq(&actual))
            .unwrap_or_else(|| {
                panic!(
                    "recovered a partial or otherwise unexpected world: actual={actual:?}, allowed={:?}",
                    self.0
                )
            });

        for (index, state) in expected.0.iter().enumerate() {
            let Some(state) = state else {
                continue;
            };
            let blob = handles[index]
                .as_ref()
                .expect("present modeled blobs have open handles");
            for completed in &state.completed {
                let data = blob
                    .read_integrity(completed.unit)
                    .await
                    .expect("modeled completed integrity unit remains valid")
                    .coalesce();
                assert_eq!(data.as_ref(), completed.data);
            }
        }

        let mut resolved = actual;
        for (actual, expected) in resolved.0.iter_mut().zip(&expected.0) {
            if let (Some(actual), Some(expected)) = (actual, expected) {
                actual.completed.clone_from(&expected.completed);
            }
        }
        resolved.1 = expected.1;
        resolved
    }
}

fn failed_publication(faults: Faults, predecessor: World, candidate: World) -> Expected {
    match faults.failure {
        Failure::Read | Failure::Write => Expected::exact(predecessor),
        Failure::PartialWritePrefix | Failure::PartialWriteSubset => {
            Expected::either(predecessor, candidate)
        }
        // A failed durability operation establishes no cut. Without crash-write retention, none
        // of the newly issued prepared-root bytes can authorize the candidate after restart.
        Failure::Sync if matches!(faults.retention, Retention::None) => {
            Expected::exact(predecessor)
        }
        Failure::Sync => Expected::either(predecessor, candidate),
        Failure::Resize | Failure::PartialResize => Expected::exact(candidate),
        Failure::None | Failure::Remove => {
            panic!("publication failed outside its injected I/O phase: {faults:?}")
        }
    }
}

#[derive(Clone, Debug)]
enum AppliedBatch {
    Publish(usize),
    Rewind { blob: usize, state: BlobState },
    Remove(usize),
}

fn blob_index(blob: u8) -> usize {
    usize::from(blob) % NAMES.len()
}

fn tag(value: u8) -> [u8; ATOMIC_BLOB_TAG_LEN] {
    [value; ATOMIC_BLOB_TAG_LEN]
}

fn install_faults(context: &deterministic::Context, faults: Faults) {
    *context.storage_fault_config().write() = faults.config();
}

fn disable_faults(context: &deterministic::Context) {
    *context.storage_fault_config().write() = FaultConfig::default();
}

async fn capture_blob_state(blob: &AtomicBlob, completed: Vec<IntegrityUnitState>) -> BlobState {
    let snapshot = blob
        .integrity_snapshot()
        .await
        .expect("capturing a fault-free integrity snapshot");
    let encoded_len =
        usize::try_from(snapshot.encoded_len).expect("bounded atomic payload lengths fit in usize");
    assert!(
        encoded_len <= MAX_BLOB_LEN,
        "recovered blob exceeded modeled bound: {encoded_len}"
    );
    let data = if encoded_len == 0 {
        Vec::new()
    } else {
        blob.read_at(0, encoded_len)
            .await
            .expect("reading a fault-free atomic snapshot")
            .coalesce()
            .as_ref()
            .to_vec()
    };
    let tail = snapshot.tail.map(|(unit, data)| IntegrityUnitState {
        unit,
        data: data.coalesce().as_ref().to_vec(),
    });
    assert_eq!(blob.tag().await.expect("captured tag"), snapshot.tag);
    assert_eq!(
        blob.integrity_scheme().await.expect("captured scheme"),
        snapshot.scheme
    );
    BlobState {
        data,
        tag: snapshot.tag,
        scheme: snapshot.scheme,
        tail,
        completed,
    }
}

#[derive(Debug)]
struct AppendReference {
    offset: u64,
    encoded_len: usize,
    tag: [u8; ATOMIC_BLOB_TAG_LEN],
    scheme: IntegrityScheme,
    tail: Option<IntegrityUnitState>,
    completed: Vec<IntegrityUnitState>,
}

fn resolve_integrity_boundary(
    input: IntegrityBoundaryInput,
    state: &BlobState,
) -> IntegrityBoundary {
    match (state.scheme, input) {
        (_, IntegrityBoundaryInput::Continue) => IntegrityBoundary::Continue,
        (
            IntegrityScheme::Unbound | IntegrityScheme::Variable,
            IntegrityBoundaryInput::Complete,
        ) => IntegrityBoundary::Complete,
        (IntegrityScheme::Chunked(width), IntegrityBoundaryInput::Complete) => {
            IntegrityBoundary::Chunked(width)
        }
        (IntegrityScheme::Chunked(width), IntegrityBoundaryInput::Chunked { .. }) => {
            IntegrityBoundary::Chunked(width)
        }
        (IntegrityScheme::Variable, IntegrityBoundaryInput::Chunked { .. }) => {
            IntegrityBoundary::Complete
        }
        (IntegrityScheme::Unbound, IntegrityBoundaryInput::Chunked { width }) => {
            let requested = u32::from(width % 16) + 1;
            let tail_len = state
                .tail
                .as_ref()
                .map_or(0, |tail| u32::try_from(tail.unit.len).unwrap());
            IntegrityBoundary::Chunked(NonZeroU32::new(requested.max(tail_len)).unwrap())
        }
    }
}

fn seal_tail(
    tail: &mut Option<IntegrityUnitState>,
    completed: &mut Vec<IntegrityUnitState>,
    cursor: &mut usize,
) {
    let unit = tail
        .take()
        .expect("only nonempty integrity tails are sealed");
    assert!(!unit.data.is_empty());
    completed.push(unit);
    *cursor = cursor
        .checked_add(size_of::<u32>())
        .expect("bounded integrity encoding cannot overflow");
}

fn append_reference(
    state: &BlobState,
    data: &[u8],
    boundary: IntegrityBoundary,
    next_tag: Option<[u8; ATOMIC_BLOB_TAG_LEN]>,
) -> Option<AppendReference> {
    let scheme = match (state.scheme, boundary) {
        (scheme, IntegrityBoundary::Continue) => scheme,
        (IntegrityScheme::Unbound | IntegrityScheme::Variable, IntegrityBoundary::Complete) => {
            IntegrityScheme::Variable
        }
        (IntegrityScheme::Unbound, IntegrityBoundary::Chunked(width)) => {
            IntegrityScheme::Chunked(width)
        }
        (IntegrityScheme::Chunked(current), IntegrityBoundary::Chunked(requested))
            if current == requested =>
        {
            state.scheme
        }
        _ => return None,
    };

    let mut cursor = state.data.len();
    let mut completed = state.completed.clone();
    let mut tail = state.tail.clone();
    let mut result_offset = None;

    if let IntegrityScheme::Chunked(width) = scheme {
        let width = usize::try_from(width.get()).unwrap();
        if tail.as_ref().is_some_and(|tail| tail.data.len() > width) {
            return None;
        }
        if tail.as_ref().is_some_and(|tail| tail.data.len() == width) {
            seal_tail(&mut tail, &mut completed, &mut cursor);
        }

        let mut remaining = data;
        while !remaining.is_empty() {
            let tail_len = tail.as_ref().map_or(0, |tail| tail.data.len());
            let take = remaining.len().min(width - tail_len);
            result_offset.get_or_insert(cursor as u64);
            let current = tail.get_or_insert_with(|| IntegrityUnitState {
                unit: IntegrityUnit {
                    offset: cursor as u64,
                    len: 0,
                },
                data: Vec::new(),
            });
            current.data.extend_from_slice(&remaining[..take]);
            current.unit.len = current.data.len() as u64;
            cursor += take;
            remaining = &remaining[take..];
            if current.data.len() == width {
                seal_tail(&mut tail, &mut completed, &mut cursor);
            }
        }
    } else {
        if !data.is_empty() {
            result_offset = Some(cursor as u64);
            let current = tail.get_or_insert_with(|| IntegrityUnitState {
                unit: IntegrityUnit {
                    offset: cursor as u64,
                    len: 0,
                },
                data: Vec::new(),
            });
            current.data.extend_from_slice(data);
            current.unit.len = current.data.len() as u64;
            cursor += data.len();
        }
        if matches!(boundary, IntegrityBoundary::Complete) && tail.is_some() {
            seal_tail(&mut tail, &mut completed, &mut cursor);
        }
    }

    Some(AppendReference {
        offset: result_offset.unwrap_or(state.data.len() as u64),
        encoded_len: cursor,
        tag: next_tag.unwrap_or(state.tag),
        scheme,
        tail,
        completed,
    })
}

fn bounded_append_reference(
    state: &BlobState,
    data: &[u8],
    boundary: IntegrityBoundary,
    next_tag: Option<[u8; ATOMIC_BLOB_TAG_LEN]>,
) -> Option<(Vec<u8>, AppendReference)> {
    for len in (0..=data.len()).rev() {
        let reference = append_reference(state, &data[..len], boundary, next_tag)?;
        if reference.encoded_len <= MAX_BLOB_LEN {
            return Some((data[..len].to_vec(), reference));
        }
    }
    None
}

fn assert_append_reference(actual: &BlobState, expected: &AppendReference) {
    assert_eq!(actual.data.len(), expected.encoded_len);
    assert_eq!(actual.tag, expected.tag);
    assert_eq!(actual.scheme, expected.scheme);
    assert_eq!(actual.tail, expected.tail);
    assert_eq!(actual.completed, expected.completed);
}

async fn initialize(context: &deterministic::Context) {
    disable_faults(context);
    for name in NAMES {
        let (blob, len) = context
            .open_atomic(PARTITION, name)
            .await
            .expect("fault-free atomic initialization");
        assert_eq!(len, 0);
        assert_eq!(blob.tag().await.expect("initial tag"), tag(0));
        assert_eq!(
            blob.integrity_scheme().await.expect("initial scheme"),
            IntegrityScheme::Unbound
        );
    }
}

async fn observe_world(context: &deterministic::Context) -> (World, Handles) {
    let names = context
        .scan_atomic(PARTITION)
        .await
        .expect("fault-free atomic scan");
    let mut world = World::absent();
    let mut handles: Handles = std::array::from_fn(|_| None);
    let mut seen = [false; NAMES.len()];

    for name in names {
        let blob_index = NAMES
            .iter()
            .position(|candidate| *candidate == name.as_slice())
            .unwrap_or_else(|| panic!("scan returned unknown atomic name {name:?}"));
        assert!(!seen[blob_index], "scan returned a duplicate atomic name");
        seen[blob_index] = true;

        let (blob, len) = context
            .open_atomic(PARTITION, &name)
            .await
            .expect("opening a scanned atomic blob");
        let state = capture_blob_state(&blob, Vec::new()).await;
        assert_eq!(len, state.data.len() as u64);
        world.0[blob_index] = Some(state);
        handles[blob_index] = Some(blob);
    }

    (world, handles)
}

async fn integrity_token_is_current(blob: &AtomicBlob, token: IntegrityToken) -> bool {
    let tag = blob.tag().await.expect("integrity-token probe tag");
    match blob.compare_set_tag(token, tag).await {
        Ok(_) => true,
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput => false,
        Err(error) => panic!("integrity-token probe failed unexpectedly: {error}"),
    }
}

async fn assert_retired_tokens_stale(world: &World, handles: &Handles) {
    for (retired, blob) in world.1.iter().zip(handles) {
        if let (Some(retired), Some(blob)) = (retired, blob) {
            assert!(
                !integrity_token_is_current(blob, *retired).await,
                "recreated blob accepted its retired integrity token"
            );
        }
    }
}

async fn recover_from_entry(
    context: &deterministic::Context,
    mut expected: Expected,
    selector: u8,
) -> Expected {
    let present = (0..NAMES.len())
        .filter(|index| expected.0.iter().any(|world| world.0[*index].is_some()))
        .collect::<Vec<_>>();
    let Some(index) = present.get(usize::from(selector) % present.len().max(1)) else {
        return expected;
    };
    let (blob, _) = context
        .open_atomic(PARTITION, NAMES[*index])
        .await
        .expect("recovering from a modeled atomic blob");

    // Presence can differ only when the candidate removed this name. Every open has a fresh token
    // epoch, so the pre-recovery token must be stale for either outcome. Normalize only the absent
    // branch and drop its candidate-only token once recovery exposes a replacement.
    let retired = expected
        .0
        .iter()
        .find(|world| world.0[*index].is_none())
        .map(|world| {
            world.1[*index].expect("an absent recovery-entry world carries its retired token")
        });
    if let Some(retired) = retired {
        assert!(
            !integrity_token_is_current(&blob, retired).await,
            "reopened blob accepted its retired integrity token"
        );
        for world in &mut expected.0 {
            if world.0[*index].is_none() {
                world.0[*index] = Some(BlobState::default());
                world.1[*index] = None;
            }
        }
    }
    drop(blob);
    expected
}

fn published(durable: &World, visible: &World, blob: usize) -> World {
    let mut candidate = durable.clone();
    candidate.0[blob] = visible.0[blob].clone();
    candidate
}

fn rewind_boundaries(state: &BlobState, durable: &BlobState) -> Vec<u64> {
    let current_len = state.data.len() as u64;
    let mut targets = vec![0, current_len];
    if durable.data.len() as u64 <= current_len {
        targets.push(durable.data.len() as u64);
    }
    if matches!(state.scheme, IntegrityScheme::Chunked(_)) {
        targets.extend(state.completed.iter().map(IntegrityUnitState::encoded_end));
    }
    if let Some(tail) = &state.tail {
        targets.push(tail.unit.offset);
    }
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn direct_rewind_target(state: &BlobState, durable: &BlobState, selector: u16) -> u64 {
    let mut targets = rewind_boundaries(state, durable);
    if let Some(tail) = &state.tail {
        let retain = u64::from(selector) % (tail.unit.len + 1);
        targets.push(tail.unit.offset + retain);
    }
    targets[usize::from(selector) % targets.len()]
}

fn rewind_reference(
    state: &BlobState,
    durable: &BlobState,
    len: u64,
    source: Option<&IntegrityUnitState>,
    next_tag: Option<[u8; ATOMIC_BLOB_TAG_LEN]>,
) -> BlobState {
    assert!(len <= state.data.len() as u64);
    let mut rewound = if len == state.data.len() as u64 {
        state.clone()
    } else if len == durable.data.len() as u64 {
        assert_eq!(&state.data[..len as usize], durable.data);
        let mut committed = durable.clone();
        committed.tag = state.tag;
        committed
    } else {
        let mut rewound = state.clone();
        rewound.data.truncate(len as usize);
        rewound.completed.retain(|unit| unit.encoded_end() <= len);
        let containing = source.or_else(|| {
            state
                .tail
                .as_ref()
                .filter(|tail| tail.unit.offset < len && len <= tail.unit.offset + tail.unit.len)
        });
        rewound.tail = containing.and_then(|unit| {
            let retained = usize::try_from(len - unit.unit.offset).unwrap();
            (retained != 0).then(|| IntegrityUnitState {
                unit: IntegrityUnit {
                    offset: unit.unit.offset,
                    len: retained as u64,
                },
                data: unit.data[..retained].to_vec(),
            })
        });
        rewound
    };
    if let Some(tag) = next_tag {
        rewound.tag = tag;
    }
    rewound
}

fn integrity_rewind_choice(
    state: &BlobState,
    unit_selector: u8,
    retain_selector: u8,
) -> Option<(IntegrityUnitState, u64)> {
    let mut units = state.completed.clone();
    units.extend(state.tail.clone());
    let unit = units
        .get(usize::from(unit_selector) % units.len().max(1))?
        .clone();
    let current = state.tail.as_ref() == Some(&unit);
    let max_retain = match (current, state.scheme) {
        (true, _) => unit.unit.len.saturating_sub(1),
        (false, IntegrityScheme::Variable) => unit.unit.len,
        (false, IntegrityScheme::Chunked(_)) => unit.unit.len.saturating_sub(1),
        (false, IntegrityScheme::Unbound) => 0,
    };
    let retain = u64::from(retain_selector) % (max_retain + 1);
    let len = unit.unit.offset + retain;
    Some((unit, len))
}

async fn run_operations(
    context: &deterministic::Context,
    mut durable: World,
    mut visible: World,
    mut handles: Handles,
    operations: &[Operation],
) -> Expected {
    for operation in operations {
        assert_retired_tokens_stale(&visible, &handles).await;
        match operation {
            Operation::Append { blob, data, faults } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                let state = visible.0[blob_index].as_ref().unwrap();
                let Some((data, reference)) =
                    bounded_append_reference(state, data, IntegrityBoundary::Continue, None)
                else {
                    continue;
                };
                let should_fail = !data.is_empty()
                    && (state.data.len() < durable.0[blob_index].as_ref().unwrap().data.len()
                        || matches!(
                            faults.failure,
                            Failure::Write
                                | Failure::PartialWritePrefix
                                | Failure::PartialWriteSubset
                        ));
                install_faults(context, *faults);
                match blob.append(data.clone()).await {
                    Ok(_) if should_fail => {
                        panic!("append unexpectedly succeeded despite a modeled rejection")
                    }
                    Ok(offset) => {
                        assert_eq!(offset, reference.offset);
                        disable_faults(context);
                        let actual = capture_blob_state(&blob, reference.completed.clone()).await;
                        assert_append_reference(&actual, &reference);
                        visible.0[blob_index] = Some(actual);
                    }
                    Err(_) if should_fail => return Expected::exact(durable),
                    Err(error) => panic!("bounded append was unexpectedly rejected: {error}"),
                }
            }
            Operation::AppendTagged {
                blob,
                data,
                tag: value,
                faults,
            } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                let state = visible.0[blob_index].as_ref().unwrap();
                let Some((data, reference)) = bounded_append_reference(
                    state,
                    data,
                    IntegrityBoundary::Continue,
                    Some(tag(*value)),
                ) else {
                    continue;
                };
                let should_fail = !data.is_empty()
                    && (state.data.len() < durable.0[blob_index].as_ref().unwrap().data.len()
                        || matches!(
                            faults.failure,
                            Failure::Write
                                | Failure::PartialWritePrefix
                                | Failure::PartialWriteSubset
                        ));
                install_faults(context, *faults);
                match blob.append_tagged(data.clone(), tag(*value)).await {
                    Ok(_) if should_fail => {
                        panic!("tagged append unexpectedly succeeded despite a modeled rejection")
                    }
                    Ok(offset) => {
                        assert_eq!(offset, reference.offset);
                        disable_faults(context);
                        let actual = capture_blob_state(&blob, reference.completed.clone()).await;
                        assert_append_reference(&actual, &reference);
                        visible.0[blob_index] = Some(actual);
                    }
                    Err(_) if should_fail => return Expected::exact(durable),
                    Err(error) => {
                        panic!("bounded tagged append was unexpectedly rejected: {error}")
                    }
                }
            }
            Operation::SetTag { blob, tag: value } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                disable_faults(context);
                blob.set_tag(tag(*value))
                    .await
                    .expect("fault-free tag update");
                visible.0[blob_index].as_mut().unwrap().tag = tag(*value);
            }
            Operation::CompareSetTag {
                blob,
                tag: value,
                stale,
            } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                disable_faults(context);
                let token = blob
                    .integrity_snapshot()
                    .await
                    .expect("fault-free compare-tag snapshot")
                    .token;
                if *stale {
                    let mut intermediate = visible.0[blob_index].as_ref().unwrap().tag;
                    intermediate[0] = intermediate[0].wrapping_add(1);
                    blob.set_tag(intermediate)
                        .await
                        .expect("fault-free token invalidation");
                    visible.0[blob_index].as_mut().unwrap().tag = intermediate;
                    assert!(blob.compare_set_tag(token, tag(*value)).await.is_err());
                } else {
                    blob.compare_set_tag(token, tag(*value))
                        .await
                        .expect("fault-free fresh-token tag update");
                    visible.0[blob_index].as_mut().unwrap().tag = tag(*value);
                }
            }
            Operation::AppendIntegrity {
                blob,
                data,
                boundary,
                tagged,
                tag: value,
                faults,
            } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                disable_faults(context);
                let snapshot = blob
                    .integrity_snapshot()
                    .await
                    .expect("fault-free integrity append snapshot");
                let state = visible.0[blob_index].as_ref().unwrap();
                let boundary = resolve_integrity_boundary(*boundary, state);
                let next_tag = tagged.then(|| tag(*value));
                let Some((data, reference)) =
                    bounded_append_reference(state, data, boundary, next_tag)
                else {
                    continue;
                };
                let pending_rewind =
                    state.data.len() < durable.0[blob_index].as_ref().unwrap().data.len();
                let fence_checked =
                    !(data.is_empty() && matches!(boundary, IntegrityBoundary::Continue));
                let writes_payload = reference.encoded_len > state.data.len();
                let write_failure = matches!(
                    faults.failure,
                    Failure::Write | Failure::PartialWritePrefix | Failure::PartialWriteSubset
                );
                let should_fail =
                    pending_rewind && fence_checked || writes_payload && write_failure;
                install_faults(context, *faults);
                match blob
                    .append_integrity(snapshot.token, data.clone(), boundary, next_tag)
                    .await
                {
                    Ok(_) if should_fail => panic!(
                        "integrity append unexpectedly succeeded despite a modeled rejection"
                    ),
                    Ok(appended) => {
                        assert_eq!(appended.offset, reference.offset);
                        disable_faults(context);
                        let actual = capture_blob_state(&blob, reference.completed.clone()).await;
                        assert_append_reference(&actual, &reference);
                        visible.0[blob_index] = Some(actual);
                    }
                    Err(_) if should_fail => return Expected::exact(durable),
                    Err(error) => {
                        panic!("bounded integrity append was unexpectedly rejected: {error}")
                    }
                }
            }
            Operation::Rewind { blob, len } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                let state = visible.0[blob_index].as_ref().unwrap();
                let committed = durable.0[blob_index].as_ref().unwrap();
                let len = direct_rewind_target(state, committed, *len);
                let expected = rewind_reference(state, committed, len, None, None);
                disable_faults(context);
                blob.rewind(len).await.expect("fault-free rewind");
                let actual = capture_blob_state(&blob, expected.completed.clone()).await;
                assert_eq!(actual, expected);
                visible.0[blob_index] = Some(actual);
            }
            Operation::RewindTagged {
                blob,
                len,
                tag: value,
            } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                let state = visible.0[blob_index].as_ref().unwrap();
                let committed = durable.0[blob_index].as_ref().unwrap();
                let len = direct_rewind_target(state, committed, *len);
                let expected = rewind_reference(state, committed, len, None, Some(tag(*value)));
                disable_faults(context);
                blob.rewind_tagged(len, tag(*value))
                    .await
                    .expect("fault-free tagged rewind");
                let actual = capture_blob_state(&blob, expected.completed.clone()).await;
                assert_eq!(actual, expected);
                visible.0[blob_index] = Some(actual);
            }
            Operation::RewindIntegrity {
                blob,
                unit,
                retain,
                tagged,
                tag: value,
                faults,
            } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                let state = visible.0[blob_index].as_ref().unwrap();
                let Some((unit, len)) = integrity_rewind_choice(state, *unit, *retain) else {
                    continue;
                };
                let read_required = len != state.data.len() as u64
                    && len != durable.0[blob_index].as_ref().unwrap().data.len() as u64
                    && !(state.tail.as_ref() == Some(&unit) && len == unit.unit.offset);
                let should_fail = read_required && matches!(faults.failure, Failure::Read);
                let next_tag = tagged.then(|| tag(*value));
                let expected = rewind_reference(
                    state,
                    durable.0[blob_index].as_ref().unwrap(),
                    len,
                    Some(&unit),
                    next_tag,
                );
                disable_faults(context);
                let token = blob
                    .integrity_snapshot()
                    .await
                    .expect("fault-free integrity rewind snapshot")
                    .token;
                install_faults(context, *faults);
                match blob
                    .rewind_integrity(token, len, Some(unit.unit), next_tag)
                    .await
                {
                    Ok(_) if should_fail => panic!(
                        "integrity rewind unexpectedly succeeded despite an injected read failure"
                    ),
                    Ok(_) => {
                        disable_faults(context);
                        let actual = capture_blob_state(&blob, expected.completed.clone()).await;
                        assert_eq!(actual, expected);
                        visible.0[blob_index] = Some(actual);
                    }
                    Err(_) if should_fail => return Expected::exact(durable),
                    Err(error) => {
                        panic!("bounded integrity rewind was unexpectedly rejected: {error}")
                    }
                }
            }
            Operation::Sync { blob, faults } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                let candidate = published(&durable, &visible, blob_index);
                install_faults(context, *faults);
                if blob.start_sync().await.await.is_err() {
                    return failed_publication(*faults, durable, candidate);
                }
                durable = candidate;
            }
            Operation::Batch {
                members,
                faults,
                drop_completion,
            } => {
                disable_faults(context);
                let mut seen = [false; NAMES.len()];
                let mut batch = Vec::with_capacity(members.len());
                let mut applied = Vec::with_capacity(members.len());
                let mut candidate = durable.clone();

                for member in members {
                    let blob_index = blob_index(member.blob);
                    if seen[blob_index] {
                        continue;
                    }
                    let Some(blob) = handles[blob_index].clone() else {
                        continue;
                    };
                    seen[blob_index] = true;
                    match member.kind {
                        BatchKind::Publish => {
                            candidate.0[blob_index] = visible.0[blob_index].clone();
                            batch.push(BatchOperation::Publish(blob));
                            applied.push(AppliedBatch::Publish(blob_index));
                        }
                        BatchKind::Rewind { len } => {
                            let current = visible.0[blob_index].as_ref().unwrap();
                            let targets =
                                rewind_boundaries(current, durable.0[blob_index].as_ref().unwrap());
                            let len = targets[usize::from(len) % targets.len()];
                            let state = rewind_reference(
                                current,
                                durable.0[blob_index].as_ref().unwrap(),
                                len,
                                None,
                                None,
                            );
                            candidate.0[blob_index] = Some(state.clone());
                            batch.push(BatchOperation::Rewind { blob, len });
                            applied.push(AppliedBatch::Rewind {
                                blob: blob_index,
                                state,
                            });
                        }
                        BatchKind::Remove => {
                            candidate.1[blob_index] = Some(
                                blob.integrity_snapshot()
                                    .await
                                    .expect("fault-free pre-remove snapshot")
                                    .token,
                            );
                            candidate.0[blob_index] = None;
                            batch.push(BatchOperation::Remove(blob));
                            applied.push(AppliedBatch::Remove(blob_index));
                        }
                    }
                }

                install_faults(context, *faults);
                let completion = match context.start_apply(batch).await {
                    Ok(completion) => completion,
                    Err(_) => return failed_publication(*faults, durable, candidate),
                };
                durable = candidate.clone();
                if *drop_completion {
                    drop(completion);
                    return Expected::exact(candidate);
                }
                if completion.await.is_err() {
                    return Expected::exact(candidate);
                }
                let has_remove = applied
                    .iter()
                    .any(|operation| matches!(operation, AppliedBatch::Remove(_)));
                for operation in applied {
                    match operation {
                        AppliedBatch::Publish(blob) => {
                            debug_assert!(visible.0[blob].is_some());
                        }
                        AppliedBatch::Rewind { blob, state } => {
                            visible.0[blob] = Some(state);
                        }
                        AppliedBatch::Remove(blob) => {
                            visible.0[blob] = None;
                            visible.1[blob] = candidate.1[blob];
                            handles[blob] = None;
                        }
                    }
                }
                if has_remove && matches!(faults.failure, Failure::Remove) {
                    handles.fill(None);
                    assert!(context.scan_atomic(PARTITION).await.is_err());
                    return Expected::exact(candidate);
                }
            }
            Operation::Read { blob, offset, len } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                disable_faults(context);
                let expected = &visible.0[blob_index].as_ref().unwrap().data;
                let offset = usize::from(*offset) % (expected.len() + 1);
                let len = usize::from(*len) % (expected.len() - offset + 1);
                let actual = blob
                    .read_at(offset as u64, len)
                    .await
                    .expect("in-bounds live read")
                    .coalesce();
                assert_eq!(actual.as_ref(), &expected[offset..offset + len]);
            }
            Operation::ReadIntegrity { blob, unit, faults } => {
                let blob_index = blob_index(*blob);
                let Some(blob) = handles[blob_index].clone() else {
                    continue;
                };
                let completed = &visible.0[blob_index].as_ref().unwrap().completed;
                let Some(expected) = completed.get(usize::from(*unit) % completed.len().max(1))
                else {
                    continue;
                };
                install_faults(context, *faults);
                match blob.read_integrity(expected.unit).await {
                    Ok(data) => assert_eq!(data.coalesce().as_ref(), expected.data),
                    Err(_) if matches!(faults.failure, Failure::Read) => {}
                    Err(error) => panic!("valid completed integrity unit was rejected: {error}"),
                }
                disable_faults(context);
            }
            Operation::Recreate { blob } => {
                let blob_index = blob_index(*blob);
                if handles[blob_index].is_some() {
                    continue;
                }
                // A failed first identity write is intentionally not recoverable. Recreate names
                // fault-free so this target can keep exercising later incarnations.
                disable_faults(context);
                let (blob, len) = context
                    .open_atomic(PARTITION, NAMES[blob_index])
                    .await
                    .expect("fault-free atomic recreation");
                assert_eq!(len, 0);
                assert_eq!(blob.tag().await.expect("recreated tag"), tag(0));
                if let Some(retired) = durable.1[blob_index] {
                    assert!(
                        !integrity_token_is_current(&blob, retired).await,
                        "recreated blob accepted its retired integrity token"
                    );
                }
                let state = BlobState::default();
                durable.0[blob_index] = Some(state.clone());
                visible.0[blob_index] = Some(state);
                handles[blob_index] = Some(blob);
            }
            Operation::Crash => unreachable!("crash markers are removed before execution"),
        }
    }

    assert_retired_tokens_stale(&visible, &handles).await;
    Expected::exact(durable)
}

fn split_into_cycles(operations: &[Operation]) -> Vec<Vec<Operation>> {
    let mut cycles = Vec::new();
    let mut current = Vec::new();
    for operation in operations {
        if matches!(operation, Operation::Crash) {
            cycles.push(std::mem::take(&mut current));
        } else {
            current.push(operation.clone());
        }
    }
    cycles.push(current);
    cycles
}

fn run_cycle(
    runner: deterministic::Runner,
    expected: Expected,
    operations: Vec<Operation>,
    recovery_entry: u8,
) -> (Expected, deterministic::Checkpoint) {
    runner.start_and_recover(move |context| async move {
        disable_faults(&context);
        let expected = recover_from_entry(&context, expected, recovery_entry).await;
        let (observed, handles) = observe_world(&context).await;
        let actual = expected.resolve(observed, &handles).await;
        run_operations(&context, actual.clone(), actual, handles, &operations).await
    })
}

async fn recreate_for_final_mutation(
    context: &deterministic::Context,
    actual: &mut World,
    handles: &mut Handles,
    blob_index: usize,
) {
    if handles[blob_index].is_some() {
        return;
    }

    let (blob, len) = context
        .open_atomic(PARTITION, NAMES[blob_index])
        .await
        .expect("final fault-free recreation");
    assert_eq!(len, 0);
    if let Some(retired) = actual.1[blob_index]
        && integrity_token_is_current(&blob, retired).await
    {
        panic!("recreated blob accepted its retired integrity token");
    }
    handles[blob_index] = Some(blob);
    actual.0[blob_index] = Some(BlobState::default());
}

async fn publish_final_mutation(
    context: &deterministic::Context,
    mut actual: World,
    mut handles: Handles,
) -> World {
    let blob_index = actual.0.iter().position(Option::is_some).unwrap_or(0);
    recreate_for_final_mutation(context, &mut actual, &mut handles, blob_index).await;

    let blob = handles[blob_index].as_ref().unwrap();
    let state = actual.0[blob_index].as_ref().unwrap().clone();
    let mut next_tag = state.tag;
    next_tag[0] = next_tag[0].wrapping_add(1);
    let token = blob
        .integrity_snapshot()
        .await
        .expect("final integrity snapshot")
        .token;
    blob.compare_set_tag(token, next_tag)
        .await
        .expect("final tag mutation");
    assert_retired_tokens_stale(&actual, &handles).await;
    let completed = state.completed.clone();
    let updated = capture_blob_state(blob, completed).await;
    assert_eq!(updated.data, state.data);
    assert_eq!(updated.scheme, state.scheme);
    assert_eq!(updated.tail, state.tail);
    assert_eq!(updated.tag, next_tag);
    actual.0[blob_index] = Some(updated);
    blob.sync().await.expect("final sync");
    actual
}

fn run(input: FuzzInput) {
    let (_, mut checkpoint) =
        deterministic::Runner::seeded(input.seed).start_and_recover(|context| async move {
            initialize(&context).await;
        });
    let mut expected = Expected::exact(World::initialized());

    for operations in split_into_cycles(&input.operations) {
        (expected, checkpoint) = run_cycle(
            deterministic::Runner::from(checkpoint),
            expected,
            operations,
            input.recovery_entry,
        );
    }

    // Publish one final fault-free mutation so recovery is also proven usable as the start of the
    // next generation, rather than only readable at the end of the fuzz trace.
    let (final_world, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(move |context| async move {
            disable_faults(&context);
            let expected = recover_from_entry(&context, expected, input.recovery_entry).await;
            let (observed, handles) = observe_world(&context).await;
            let actual = expected.resolve(observed, &handles).await;
            publish_final_mutation(&context, actual, handles).await
        });

    deterministic::Runner::from(checkpoint).start(move |context| async move {
        disable_faults(&context);
        let expected =
            recover_from_entry(&context, Expected::exact(final_world), input.recovery_entry).await;
        let (observed, handles) = observe_world(&context).await;
        expected.resolve(observed, &handles).await;
    });
}

#[cfg(not(test))]
fuzz_target!(|input: FuzzInput| {
    run(input);
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_entry_normalizes_a_removed_candidate_with_stale_tokens() {
        fn run_case(removed: bool) {
            let (modeled, checkpoint) =
                deterministic::Runner::default().start_and_recover(move |context| async move {
                    initialize(&context).await;
                    let predecessor = World::initialized();
                    let (blob, _) = context.open_atomic(PARTITION, NAMES[0]).await.unwrap();
                    let retired = blob.integrity_snapshot().await.unwrap().token;
                    if removed {
                        context
                            .apply(vec![BatchOperation::Remove(blob)])
                            .await
                            .unwrap();
                    } else {
                        drop(blob);
                    }

                    let mut candidate = predecessor.clone();
                    candidate.0[0] = None;
                    candidate.1[0] = Some(retired);
                    (Expected::either(predecessor, candidate), retired)
                });

            deterministic::Runner::from(checkpoint).start(move |context| async move {
                let (expected, retired) = modeled;
                let expected = recover_from_entry(&context, expected, 0).await;
                let (observed, handles) = observe_world(&context).await;
                assert_eq!(expected.0.len(), 2);
                assert!(
                    expected
                        .0
                        .iter()
                        .all(|world| { world.0[0].is_some() && world.1[0].is_none() })
                );
                assert!(
                    handles[0]
                        .as_ref()
                        .unwrap()
                        .compare_set_tag(retired, tag(1))
                        .await
                        .is_err()
                );
                expected.resolve(observed, &handles).await;
            });
        }

        run_case(false);
        run_case(true);
    }

    #[test]
    fn forced_final_recreation_rejects_a_retired_token() {
        deterministic::Runner::default().start(|context| async move {
            initialize(&context).await;
            let (blob, _) = context.open_atomic(PARTITION, NAMES[0]).await.unwrap();
            let token = blob.integrity_snapshot().await.unwrap().token;
            drop(blob);

            let mut actual = World::absent();
            actual.1[0] = Some(token);
            let mut handles = std::array::from_fn(|_| None);
            recreate_for_final_mutation(&context, &mut actual, &mut handles, 0).await;
        });
    }

    #[test]
    fn forced_final_recreation_accepts_a_new_incarnation() {
        run(FuzzInput {
            seed: 0,
            recovery_entry: 0,
            operations: vec![Operation::Batch {
                members: (0..NAMES.len())
                    .map(|blob| BatchMember {
                        blob: blob as u8,
                        kind: BatchKind::Remove,
                    })
                    .collect(),
                faults: Faults {
                    failure: Failure::None,
                    retention: Retention::None,
                    resize_retention: Retention::None,
                },
                drop_completion: false,
            }],
        });
    }

    #[test]
    fn forced_final_recreation_rejects_delayed_token_reuse() {
        let (retired, checkpoint) =
            deterministic::Runner::default().start_and_recover(|context| async move {
                initialize(&context).await;
                let (blob, _) = context.open_atomic(PARTITION, NAMES[0]).await.unwrap();
                blob.set_tag(tag(1)).await.unwrap();
                blob.integrity_snapshot().await.unwrap().token
            });

        deterministic::Runner::from(checkpoint).start(move |context| async move {
            let mut actual = World::absent();
            actual.1[0] = Some(retired);
            let handles = std::array::from_fn(|_| None);
            publish_final_mutation(&context, actual, handles).await;
        });
    }
}
