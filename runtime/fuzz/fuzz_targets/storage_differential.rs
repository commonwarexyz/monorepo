//! Differential fuzzing of the deterministic and tokio storage backends.
//!
//! One sequence of [Storage] and [Blob] operations runs on the deterministic runtime (memory
//! storage) and on the tokio runtime (filesystem storage). The sequence is split into sessions at
//! its `Restart` operations: each session is one deterministic runner start, recovered from the
//! previous session's checkpoint, and one tokio runner start on the same directory.
//!
//! Each backend is judged against its own contract model, and the two traces are compared with
//! each other wherever both models agree on the state an operation depends on. Failures are
//! collected during the run and reported after it, with the operation trace and both
//! observations of every operation, so a crash is triageable from its log.
//!
//! See `runtime/fuzz/SPEC.md` for the design.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use bytes::Buf as _;
use commonware_runtime::{
    Blob, BlobLayout, BlobVersion, DEFAULT_BLOB_LAYOUT, Error, IoBuf, IoBufMut, IoBufs, IoBufsMut,
    ReadOptions, Runner as _, Storage, WriteOptions, deterministic, tokio,
};
use commonware_runtime_fuzz::decode;
use commonware_utils::{Entropy, FuzzRng, rng::mix64};
use futures::StreamExt as _;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write as _},
    io::IoSlice,
    ops::RangeInclusive,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_OPS: usize = 64;
const SLOTS: usize = 4;
const MAX_CHUNKS: usize = 4;
const MAX_RANGES: usize = 8;

/// Memory storage allocates up to `offset + len` on writes and resizes and `len` on every read,
/// so offsets and lengths stay small enough that no allocation aborts.
const MAX_OFFSET: u64 = 1 << 20;
const MAX_LEN: usize = 1 << 16;

/// Overflow-edge read offsets, read with at most [MAX_EDGE_LEN] bytes.
const EDGE_OFFSETS: [u64; 4] = [
    u64::MAX,
    i64::MAX as u64,
    i64::MAX as u64 - 4096,
    i64::MAX as u64 - 8,
];
const MAX_EDGE_LEN: usize = 16;

/// Largest logical size the operations can produce, used to reject absurd reported sizes before
/// the model allocates them.
const MAX_SIZE: u64 = MAX_OFFSET + MAX_LEN as u64;

/// Base directory for tokio storage, defaulting to the system temporary directory.
const DIR_ENV: &str = "COMMONWARE_RUNTIME_FUZZ_DIR";

/// Model byte flags: the value is known, and the byte is durable.
const KNOWN: u8 = 1 << 0;
const STABLE: u8 = 1 << 1;

#[derive(Clone, Copy, Debug)]
enum PartitionName {
    P0,
    P1,
    Empty,
    Slash,
    Long255,
    Long256,
}

impl PartitionName {
    fn get(self) -> String {
        match self {
            Self::P0 => "p0".into(),
            Self::P1 => "p1".into(),
            Self::Empty => String::new(),
            Self::Slash => "a/b".into(),
            Self::Long255 => "p".repeat(255),
            Self::Long256 => "p".repeat(256),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum BlobName {
    A,
    B,
    Empty,
    Long127,
    Long128,
    NonUtf8,
}

impl BlobName {
    fn get(self) -> Vec<u8> {
        match self {
            Self::A => b"a".to_vec(),
            Self::B => b"b".to_vec(),
            Self::Empty => Vec::new(),
            Self::Long127 => vec![b'n'; 127],
            Self::Long128 => vec![b'n'; 128],
            Self::NonUtf8 => vec![0xff, 0x00],
        }
    }
}

/// An offset, either absolute or relative to the slot's size in the executing backend's model.
#[derive(Clone, Copy, Debug)]
enum Offset {
    At(u64),
    End(i8),
}

impl Offset {
    fn resolve(self, size: u64, cap: u64) -> u64 {
        match self {
            Self::At(offset) => offset,
            Self::End(delta) => size.saturating_add_signed(i64::from(delta)).min(cap),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Layouts {
    V0,
    V1,
    Both,
}

impl Layouts {
    #[allow(deprecated)]
    const fn range(self) -> RangeInclusive<BlobLayout> {
        match self {
            Self::V0 => BlobLayout::V0..=BlobLayout::V0,
            Self::V1 => BlobLayout::V1..=BlobLayout::V1,
            Self::Both => BlobLayout::V0..=BlobLayout::V1,
        }
    }
}

#[derive(Clone, Debug)]
enum Op {
    Open {
        slot: usize,
        partition: PartitionName,
        name: BlobName,
        versions: (u16, u16),
    },
    Write {
        slot: usize,
        offset: Offset,
        chunks: Vec<usize>,
        sync: bool,
        dont_cache: bool,
    },
    ReadAt {
        slot: usize,
        offset: Offset,
        len: usize,
        dont_cache: bool,
    },
    ReadAtBuf {
        slot: usize,
        offset: Offset,
        len: usize,
        /// Capacities of the destination chunks, summing to at least `len`.
        chunks: Vec<usize>,
        dont_cache: bool,
    },
    ReadMany {
        slot: usize,
        ranges: Vec<(Offset, usize)>,
        dont_cache: bool,
    },
    StartReadMany {
        slot: usize,
        ranges: Vec<(Offset, usize)>,
        dont_cache: bool,
        wait: bool,
    },
    Resize {
        slot: usize,
        len: Offset,
    },
    Sync {
        slot: usize,
    },
    StartSync {
        slot: usize,
        wait: bool,
    },
    Remove {
        partition: PartitionName,
        name: Option<BlobName>,
    },
    Scan {
        partition: PartitionName,
    },
    Drop {
        slot: usize,
    },
    Restart {
        layouts: Layouts,
    },
}

fn slot(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(0..=SLOTS - 1)
}

/// Most partitions come from the plain pool so that operations collide on the same blobs.
fn partition(u: &mut Unstructured<'_>) -> arbitrary::Result<PartitionName> {
    Ok(match u.int_in_range(0..=31)? {
        0 => match u.int_in_range(0..=3)? {
            0 => PartitionName::Empty,
            1 => PartitionName::Slash,
            2 => PartitionName::Long255,
            _ => PartitionName::Long256,
        },
        1..=16 => PartitionName::P0,
        _ => PartitionName::P1,
    })
}

/// Most names come from the plain pool so that operations collide on the same blobs.
fn blob_name(u: &mut Unstructured<'_>) -> arbitrary::Result<BlobName> {
    Ok(match u.int_in_range(0..=31)? {
        0 => match u.int_in_range(0..=3)? {
            0 => BlobName::Empty,
            1 => BlobName::Long127,
            2 => BlobName::Long128,
            _ => BlobName::NonUtf8,
        },
        1..=16 => BlobName::A,
        _ => BlobName::B,
    })
}

fn versions(u: &mut Unstructured<'_>) -> arbitrary::Result<(u16, u16)> {
    let a = u.int_in_range(0..=2)?;
    let b = u.int_in_range(0..=2)?;
    Ok((a.min(b), a.max(b)))
}

/// Write and resize offsets, biased toward page edges and the slot's current size.
fn offset(u: &mut Unstructured<'_>) -> arbitrary::Result<Offset> {
    Ok(match u.int_in_range(0..=9)? {
        0 | 1 => Offset::At(0),
        2 => Offset::At(4095),
        3 => Offset::At(4096),
        4 => Offset::At(4097),
        5 | 6 => Offset::End(u.int_in_range(-4..=4)?),
        7 => Offset::At(u.int_in_range(0..=64)?),
        8 => Offset::At(u.int_in_range(0..=3 * 4096)?),
        _ => Offset::At(u.int_in_range(0..=MAX_OFFSET)?),
    })
}

/// Lengths, biased toward empty, single-byte and page-edge lengths.
fn length(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    Ok(match u.int_in_range(0..=9)? {
        0 => 0,
        1 => 1,
        2 => 4095,
        3 => 4096,
        4 => 4097,
        5..=7 => u.int_in_range(1..=64)?,
        8 => u.int_in_range(1..=3 * 4096)?,
        _ => u.int_in_range(0..=MAX_LEN)?,
    })
}

/// A read range, occasionally at an overflow-edge offset with a short length.
fn read_range(u: &mut Unstructured<'_>) -> arbitrary::Result<(Offset, usize)> {
    if u.ratio(1u8, 16u8)? {
        let edge = EDGE_OFFSETS[u.int_in_range(0..=EDGE_OFFSETS.len() - 1)?];
        return Ok((Offset::At(edge), u.int_in_range(0..=MAX_EDGE_LEN)?));
    }
    Ok((offset(u)?, length(u)?))
}

fn read_ranges(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<(Offset, usize)>> {
    (0..u.int_in_range(0..=MAX_RANGES)?)
        .map(|_| read_range(u))
        .collect()
}

/// Chunk lengths of a write, at most [MAX_LEN] bytes in total.
fn write_chunks(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<usize>> {
    let mut budget = MAX_LEN;
    (0..u.int_in_range(1..=MAX_CHUNKS)?)
        .map(|_| {
            let len = length(u)?.min(budget);
            budget -= len;
            Ok(len)
        })
        .collect()
}

/// Destination chunk capacities of a `read_at_buf`, summing to `len` plus some spare capacity.
fn buf_chunks(u: &mut Unstructured<'_>, len: usize) -> arbitrary::Result<Vec<usize>> {
    let extra = match u.int_in_range(0..=3)? {
        0 | 1 => 0,
        2 => u.int_in_range(1..=16)?,
        _ => u.int_in_range(1..=4096)?,
    };
    let capacity = len + extra;
    let mut cuts = (1..u.int_in_range(1..=MAX_CHUNKS)?)
        .map(|_| u.int_in_range(0..=capacity))
        .collect::<arbitrary::Result<Vec<_>>>()?;
    cuts.push(0);
    cuts.push(capacity);
    cuts.sort_unstable();
    Ok(cuts.windows(2).map(|w| w[1] - w[0]).collect())
}

impl<'a> Arbitrary<'a> for Op {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=31)? {
            0..=5 | 31 => Self::Open {
                slot: slot(u)?,
                partition: partition(u)?,
                name: blob_name(u)?,
                versions: versions(u)?,
            },
            6..=11 => Self::Write {
                slot: slot(u)?,
                offset: offset(u)?,
                chunks: write_chunks(u)?,
                sync: u.arbitrary()?,
                dont_cache: u.arbitrary()?,
            },
            12..=15 => {
                let slot = slot(u)?;
                let (offset, len) = read_range(u)?;
                Self::ReadAt {
                    slot,
                    offset,
                    len,
                    dont_cache: u.arbitrary()?,
                }
            }
            16 | 17 => {
                let slot = slot(u)?;
                let (offset, len) = read_range(u)?;
                Self::ReadAtBuf {
                    slot,
                    offset,
                    len,
                    chunks: buf_chunks(u, len)?,
                    dont_cache: u.arbitrary()?,
                }
            }
            18 | 19 => Self::ReadMany {
                slot: slot(u)?,
                ranges: read_ranges(u)?,
                dont_cache: u.arbitrary()?,
            },
            20 => Self::StartReadMany {
                slot: slot(u)?,
                ranges: read_ranges(u)?,
                dont_cache: u.arbitrary()?,
                wait: u.arbitrary()?,
            },
            21 | 22 => Self::Resize {
                slot: slot(u)?,
                len: offset(u)?,
            },
            23 | 24 => Self::Sync { slot: slot(u)? },
            25 => Self::StartSync {
                slot: slot(u)?,
                wait: u.arbitrary()?,
            },
            26 => Self::Remove {
                partition: partition(u)?,
                name: if u.ratio(1u8, 4u8)? {
                    None
                } else {
                    Some(blob_name(u)?)
                },
            },
            27 => Self::Scan {
                partition: partition(u)?,
            },
            28 | 29 => Self::Drop { slot: slot(u)? },
            _ => Self::Restart {
                layouts: match u.int_in_range(0..=2)? {
                    0 => Layouts::V0,
                    1 => Layouts::V1,
                    _ => Layouts::Both,
                },
            },
        })
    }
}

#[derive(Debug)]
struct FuzzInput {
    ops: Vec<Op>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let (session, entropy) = decode(u)?;
        let u = &mut Unstructured::new(&session);

        let ops = (0..u.int_in_range(1..=MAX_OPS)?)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self { ops, entropy })
    }
}

/// The never-zero byte that operation `index` writes at blob offset `position`.
fn value(index: usize, position: u64) -> u8 {
    (mix64(((index as u64) << 48) ^ position) % 255) as u8 + 1
}

/// A divergence the maintainer confirmed, tracked upstream and recorded in
/// `runtime/fuzz/FINDINGS.md`. From its trigger onward, the harness models the confirmed
/// behaviour of the affected backend.
struct Allowed {
    name: &'static str,
    issue: u32,
    op: &'static str,
    trigger: &'static str,
    behaviour: &'static str,
}

impl Allowed {
    /// Name the entry in a violation that may mean it no longer holds.
    fn note(&self) -> String {
        format!(
            "allowlist entry {} (#{}: {} when {}; modeled as: {})",
            self.name, self.issue, self.op, self.trigger, self.behaviour
        )
    }

    /// Report a backend that no longer shows the confirmed divergence.
    fn stale(&self, observed: &str) -> String {
        format!(
            "{observed}, which contradicts {}; remove the entry if #{} is fixed",
            self.note(),
            self.issue
        )
    }
}

const RF1: usize = 0;
const RF2: usize = 1;
const RF3: usize = 2;

/// Divergences the maintainer approved, indexed by [RF1], [RF2] and [RF3].
const ALLOWLIST: [Allowed; 3] = [
    Allowed {
        name: "RF-1",
        issue: 5752,
        op: "ReadAt, ReadAtBuf, ReadMany or StartReadMany",
        trigger: "a zero-length range starts past the end of the blob",
        behaviour: "tokio Ok against memory Err(BlobInsufficientLength) is accepted, and neither \
                    model judges the range",
    },
    Allowed {
        name: "RF-2",
        issue: 5752,
        op: "Write",
        trigger: "an empty write without SYNC starts past the end of the blob",
        behaviour: "the deterministic model grows the blob to the offset with known zeros",
    },
    Allowed {
        name: "RF-3",
        issue: 5752,
        op: "Open",
        trigger: "the partition is over 255 characters, or the name is empty or over 127 bytes",
        behaviour: "the tokio model expects PartitionCreationFailed or BlobOpenFailed and records \
                    the partition a name over 127 bytes creates",
    },
];

/// The error tokio returns for a name past its limits (RF-3), and whether the failed open
/// leaves its partition directory behind. A partition over 255 characters fails to be created
/// unless the name is empty, in which case the path is the partition itself.
fn tokio_rf3(partition: &str, name: &[u8]) -> Option<(Rf3Error, bool)> {
    if name.is_empty() {
        Some((Rf3Error::BlobOpen, false))
    } else if partition.len() > 255 {
        Some((Rf3Error::PartitionCreation, false))
    } else if name.len() > 127 {
        Some((Rf3Error::BlobOpen, true))
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug)]
enum Rf3Error {
    PartitionCreation,
    BlobOpen,
}

impl Rf3Error {
    const fn matches(self, error: &Error) -> bool {
        match self {
            Self::PartitionCreation => matches!(error, Error::PartitionCreationFailed(_)),
            Self::BlobOpen => matches!(error, Error::BlobOpenFailed(..)),
        }
    }
}

/// Tokio stores a blob at `<partition>/<hex(name)>`, so a partition over 255 characters or a name
/// over 127 bytes exceeds the filesystem's 255-byte component limit, and the empty name names the
/// partition directory itself. Memory storage accepts all of them.
fn exceeds_tokio_limits(partition: &str, name: &[u8]) -> bool {
    partition.len() > 255 || name.is_empty() || name.len() > 127
}

fn valid_partition(partition: &str) -> bool {
    !partition.is_empty()
        && partition
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Abbreviate long names so that reports stay readable.
fn display_partition(partition: &str) -> String {
    if partition.len() > 16 {
        format!("<{} chars>", partition.len())
    } else {
        format!("{partition:?}")
    }
}

fn display_name(name: &[u8]) -> String {
    if name.len() > 8 {
        format!("<{} bytes>", name.len())
    } else {
        format!("{name:02x?}")
    }
}

/// An error variant the trait docs name for a condition the model predicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Documented {
    AlreadyOpen,
    VersionMismatch,
    LayoutMismatch,
    PartitionInvalid,
}

impl Documented {
    const ALL: [Self; 4] = [
        Self::AlreadyOpen,
        Self::VersionMismatch,
        Self::LayoutMismatch,
        Self::PartitionInvalid,
    ];

    const fn matches(self, error: &Error) -> bool {
        match self {
            Self::AlreadyOpen => matches!(error, Error::BlobAlreadyOpen(..)),
            Self::VersionMismatch => matches!(error, Error::BlobVersionMismatch { .. }),
            Self::LayoutMismatch => matches!(error, Error::BlobLayoutMismatch { .. }),
            Self::PartitionInvalid => matches!(error, Error::PartitionNameInvalid(_)),
        }
    }
}

/// What the model requires of an operation's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    Ok,
    Err,
    Any,
}

/// A read of `len` bytes at `offset` must succeed inside the blob and fail past its end. A
/// zero-length read past the end has no specified outcome.
fn read_expect(size: u64, offset: u64, len: usize) -> Expect {
    match offset.checked_add(len as u64) {
        Some(end) if end <= size => Expect::Ok,
        _ if len == 0 => Expect::Any,
        _ => Expect::Err,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Deterministic,
    Tokio,
}

/// Model of one blob identity: a partition, a name and the generation that a removal ends.
struct BlobModel {
    partition: String,
    name: Vec<u8>,
    generation: u64,
    version: u16,
    /// `None` when the blob was adopted from a name whose earlier creation failed, which may
    /// have left a blob of any layout behind.
    layout: Option<BlobLayout>,
    /// Logical contents, exact in length while a handle is open.
    data: Vec<u8>,
    /// [KNOWN] and [STABLE] flags of each byte of `data`.
    flags: Vec<u8>,
    /// The size made durable by the last completed sync, while no size change followed it.
    synced_len: Option<u64>,
    /// Smallest and largest size held since the last completed sync, that size included.
    sizes: (u64, u64),
    open: bool,
    removed: bool,
    /// Set once the contract no longer determines this blob's state, such as after a mutation
    /// of a removed blob or a failed mutation. Results through it are not asserted.
    unchecked: bool,
    /// Set once the deterministic model grew the blob under [RF2].
    rf2: bool,
}

impl BlobModel {
    fn new(
        partition: String,
        name: Vec<u8>,
        generation: u64,
        version: u16,
        layout: Option<BlobLayout>,
    ) -> Self {
        Self {
            partition,
            name,
            generation,
            version,
            layout,
            data: Vec::new(),
            flags: Vec::new(),
            synced_len: Some(0),
            sizes: (0, 0),
            open: true,
            removed: false,
            unchecked: false,
            rf2: false,
        }
    }

    const fn len(&self) -> u64 {
        self.data.len() as u64
    }

    fn size_changed(&mut self) {
        let len = self.len();
        self.synced_len = None;
        self.sizes = (self.sizes.0.min(len), self.sizes.1.max(len));
    }

    /// A completed write: the range becomes known, durable only if the write was `SYNC`. Growth
    /// zero-fills any gap before the range.
    fn write(&mut self, offset: u64, bytes: &[u8], sync: bool) {
        let start = offset as usize;
        let end = start + bytes.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
            self.flags.resize(end, KNOWN);
            self.size_changed();
        }
        self.data[start..end].copy_from_slice(bytes);
        self.flags[start..end].fill(if sync { KNOWN | STABLE } else { KNOWN });
    }

    /// A completed resize: shrinking drops bytes, growing appends known zeros.
    fn resize(&mut self, len: u64) {
        let len = len as usize;
        self.data.resize(len, 0);
        self.flags.resize(len, KNOWN);
        self.size_changed();
    }

    /// A completed sync: every byte and the size become durable.
    fn sync(&mut self) {
        for flag in &mut self.flags {
            *flag |= STABLE;
        }
        let len = self.len();
        self.synced_len = Some(len);
        self.sizes = (len, len);
    }

    /// Sizes a reopen may observe.
    const fn allowed_sizes(&self) -> (u64, u64) {
        match self.synced_len {
            Some(len) => (len, len),
            None => self.sizes,
        }
    }

    /// Adopt the size observed by a reopen. Only durable bytes below it stay known. Everything
    /// readable when an open returns is durable (`Storage` durability), so the reopen acts as a
    /// completed sync.
    fn reopen(&mut self, size: u64) {
        if size > MAX_SIZE {
            self.unchecked = true;
            self.data.clear();
            self.flags.clear();
            return;
        }
        for flag in &mut self.flags {
            if *flag & STABLE == 0 {
                *flag = 0;
            }
        }
        self.data.resize(size as usize, 0);
        self.flags.resize(size as usize, 0);
        self.sync();
    }

    /// The model's known value of each byte of a range, `None` where unknown or past the end.
    fn expected(&self, offset: u64, len: usize) -> Vec<Option<u8>> {
        (0..len as u64)
            .map(|i| {
                let position = usize::try_from(offset.checked_add(i)?).ok()?;
                (*self.flags.get(position)? & KNOWN != 0).then(|| self.data[position])
            })
            .collect()
    }

    fn summary(&self) -> String {
        format!(
            "blob {}/{} gen={} version={} layout={:?} len={} synced_len={:?} sizes={:?} open={} removed={} unchecked={} known={} stable={}",
            display_partition(&self.partition),
            display_name(&self.name),
            self.generation,
            self.version,
            self.layout,
            self.len(),
            self.synced_len,
            self.sizes,
            self.open,
            self.removed,
            self.unchecked,
            runs(&self.flags, KNOWN),
            runs(&self.flags, STABLE),
        ) + if self.rf2 {
            " allowlist=RF-2 (#5752)"
        } else {
            ""
        }
    }

    /// A note for violations on a blob [RF2] grew: if memory stopped growing on empty writes, the
    /// model's size is too large.
    fn rf2_note(&self) -> String {
        if self.rf2 {
            format!("; this blob is affected by {}", ALLOWLIST[RF2].note())
        } else {
            String::new()
        }
    }
}

/// The byte ranges whose flags contain `flag`, abbreviated after a few.
fn runs(flags: &[u8], flag: u8) -> String {
    let mut out = Vec::new();
    let mut start = None;
    for (i, f) in flags.iter().chain(std::iter::once(&0)).enumerate() {
        match (start, f & flag != 0) {
            (None, true) => start = Some(i),
            (Some(s), false) => {
                out.push(format!("{s}..{i}"));
                start = None;
            }
            _ => {}
        }
    }
    if out.len() > 6 {
        let more = out.len() - 6;
        out.truncate(6);
        out.push(format!("+{more} more"));
    }
    format!("[{}]", out.join(", "))
}

/// Model of one backend's storage.
struct Model {
    kind: Kind,
    /// Layouts the backend accepts in the current session.
    layouts: RangeInclusive<BlobLayout>,
    next_generation: u64,
    /// Existing partitions and the live generation of each name in them.
    partitions: BTreeMap<String, BTreeMap<Vec<u8>, u64>>,
    /// Every live generation and every removed one a handle still refers to.
    blobs: BTreeMap<u64, BlobModel>,
    /// The generation each slot's handle refers to.
    slots: [Option<u64>; SLOTS],
    /// Names whose creation failed with an undocumented error, which may have left a partial
    /// blob behind, so the model does not know whether they exist or what they hold.
    uncertain: BTreeSet<(String, Vec<u8>)>,
}

impl Model {
    const fn new(kind: Kind) -> Self {
        Self {
            kind,
            layouts: BlobLayout::ALL,
            next_generation: 0,
            partitions: BTreeMap::new(),
            blobs: BTreeMap::new(),
            slots: [None; SLOTS],
            uncertain: BTreeSet::new(),
        }
    }

    fn current(&self, partition: &str, name: &[u8]) -> Option<u64> {
        self.partitions.get(partition)?.get(name).copied()
    }

    fn names(&self, partition: &str) -> Option<BTreeSet<Vec<u8>>> {
        Some(self.partitions.get(partition)?.keys().cloned().collect())
    }

    /// Names of a partition whose failed creation may have left a blob behind.
    fn uncertain_names(&self, partition: &str) -> BTreeSet<Vec<u8>> {
        self.uncertain
            .iter()
            .filter(|(p, _)| p == partition)
            .map(|(_, name)| name.clone())
            .collect()
    }

    /// Memory storage creates every blob with the default layout. Tokio creates it with the
    /// latest layout of its configured range.
    fn create_layout(&self) -> BlobLayout {
        match self.kind {
            Kind::Deterministic => DEFAULT_BLOB_LAYOUT,
            Kind::Tokio => *self.layouts.end(),
        }
    }

    fn create(
        &mut self,
        partition: String,
        name: Vec<u8>,
        version: u16,
        layout: Option<BlobLayout>,
    ) -> u64 {
        let generation = self.next_generation;
        self.next_generation += 1;
        self.partitions
            .entry(partition.clone())
            .or_default()
            .insert(name.clone(), generation);
        self.blobs.insert(
            generation,
            BlobModel::new(partition, name, generation, version, layout),
        );
        generation
    }

    fn close(&mut self, generation: u64) {
        let Some(blob) = self.blobs.get_mut(&generation) else {
            return;
        };
        blob.open = false;
        if blob.removed {
            self.blobs.remove(&generation);
        }
    }

    fn close_slot(&mut self, slot: usize) {
        if let Some(generation) = self.slots[slot].take() {
            self.close(generation);
        }
    }

    /// Unlink a blob, or every blob of a partition along with the partition. Handles keep
    /// referring to the removed generations.
    fn unlink(&mut self, partition: &str, name: Option<&[u8]>) {
        self.uncertain
            .retain(|(p, n)| p != partition || name.is_some_and(|name| n != name));
        let removed: Vec<u64> = match name {
            // A blob was removed from the partition, so the partition exists even when a
            // failed creation, not the model, put the blob there.
            Some(name) => self
                .partitions
                .entry(partition.to_string())
                .or_default()
                .remove(name)
                .into_iter()
                .collect(),
            None => self
                .partitions
                .remove(partition)
                .map(|names| names.into_values().collect())
                .unwrap_or_default(),
        };
        for generation in removed {
            let blob = self
                .blobs
                .get_mut(&generation)
                .expect("live blob is modeled");
            blob.removed = true;
            if !blob.open {
                self.blobs.remove(&generation);
            }
        }
    }

    fn partition_summary(&self, partition: &str) -> String {
        match self.partitions.get(partition) {
            None => format!("partition {} missing", display_partition(partition)),
            Some(names) => format!(
                "partition {} names [{}]",
                display_partition(partition),
                names
                    .keys()
                    .map(|name| display_name(name))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    }
}

#[derive(Debug)]
enum Value {
    Unit,
    Opened { size: u64, version: u16 },
    Bytes(Vec<Vec<u8>>),
    Names(Vec<Vec<u8>>),
}

#[derive(Debug)]
enum Outcome {
    Skipped,
    Dropped,
    Ok(Value),
    Err(String),
}

impl Outcome {
    fn err(error: &Error) -> Self {
        Self::Err(format!("{error:?}"))
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Skipped => write!(f, "skipped (slot empty)"),
            Self::Dropped => write!(f, "handle dropped"),
            Self::Ok(Value::Unit) => write!(f, "Ok"),
            Self::Ok(Value::Opened { size, version }) => {
                write!(f, "Ok(size={size}, version={version})")
            }
            Self::Ok(Value::Bytes(bufs)) => {
                write!(f, "Ok([")?;
                for (i, buf) in bufs.iter().enumerate() {
                    let head = &buf[..buf.len().min(8)];
                    let sep = if i == 0 { "" } else { ", " };
                    write!(f, "{sep}len={} {head:02x?}", buf.len())?;
                }
                write!(f, "])")
            }
            Self::Ok(Value::Names(names)) => write!(
                f,
                "Ok([{}])",
                names
                    .iter()
                    .map(|name| display_name(name))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Err(error) => write!(f, "Err({error})"),
        }
    }
}

/// Generate the failure classes, each with a stable tag and its own cold panic function, so
/// that the top frame of a crash and the start of its message name the class.
macro_rules! classes {
    ($($(#[$doc:meta])* $variant:ident => $name:ident,)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Class {
            $($(#[$doc])* $variant,)*
        }

        impl Class {
            fn fail(self, report: &str) -> ! {
                match self {
                    $(Self::$variant => $name(report),)*
                }
            }
        }

        $(
            #[cold]
            #[inline(never)]
            fn $name(report: &str) -> ! {
                panic!("[{}] {report}", stringify!($name))
            }
        )*
    };
}

classes! {
    /// An open's Ok/Err differs across backends.
    CrossOpen => cross_backend_open,
    /// A remove's Ok/Err differs across backends.
    CrossRemove => cross_backend_remove,
    /// A scan's Ok/Err differs across backends.
    CrossScan => cross_backend_scan,
    /// A read's Ok/Err or known bytes differ across backends.
    CrossRead => cross_backend_read,
    /// A write, resize or sync's Ok/Err differs across backends.
    CrossMutation => cross_backend_mutation,
    /// A read returned bytes that differ from known model bytes.
    ReadBytes => model_read_bytes,
    /// A read succeeded past the size, failed inside it, or returned the wrong length.
    ReadLen => model_read_len,
    /// `read_many` or `start_read_many` yielded ranges other than each exactly once.
    ReadMany => model_read_many,
    /// `read_at_buf` did not return the caller's buffers with their layout.
    Layout => model_layout,
    /// An open failed or succeeded against the model's prediction.
    OpenError => model_open_error,
    /// A reopen returned a size or version the model rules out.
    Reopen => model_reopen,
    /// A creation returned a size or version other than a new blob's.
    Create => model_create,
    /// A scan disagreed with the model.
    Scan => model_scan,
    /// A remove disagreed with the model.
    Remove => model_remove,
    /// A mutation through a live, checked handle failed.
    MutationFailed => model_mutation_failed,
    /// A backend no longer shows a divergence the allowlist names.
    AllowlistStale => allowlist_stale,
}

/// The cross-backend class of an operation.
const fn cross_class(op: &Op) -> Class {
    match op {
        Op::Open { .. } => Class::CrossOpen,
        Op::Remove { .. } => Class::CrossRemove,
        Op::Scan { .. } => Class::CrossScan,
        Op::Write { .. } | Op::Resize { .. } | Op::Sync { .. } | Op::StartSync { .. } => {
            Class::CrossMutation
        }
        Op::ReadAt { .. }
        | Op::ReadAtBuf { .. }
        | Op::ReadMany { .. }
        | Op::StartReadMany { .. } => Class::CrossRead,
        // Never compared, so never classed.
        Op::Drop { .. } | Op::Restart { .. } => Class::CrossRead,
    }
}

/// Model state an operation's outcome depends on, compared across backends.
#[derive(Debug, PartialEq, Eq)]
enum Compare {
    /// Never compared.
    None,
    /// An operation through a checked handle: the blob's size before the operation, and the
    /// model's known value of every byte each range returns.
    Blob {
        len: u64,
        expected: Vec<Vec<Option<u8>>>,
        /// Whether a zero-length range starts past the end ([RF1]).
        rf1: bool,
    },
    /// A namespace operation and the model state it depends on.
    State(State),
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    Open { existing: Option<(u16, bool)> },
    Remove { partition: bool, blob: Option<bool> },
    Scan { names: Option<BTreeSet<Vec<u8>>> },
}

struct Record {
    outcome: Outcome,
    /// Parameters resolved against the backend's model, such as size-relative offsets.
    resolved: String,
    /// Model state before the operation.
    state: String,
    compare: Compare,
}

impl Record {
    fn skipped() -> Self {
        Self {
            outcome: Outcome::Skipped,
            resolved: String::new(),
            state: String::new(),
            compare: Compare::None,
        }
    }
}

/// One backend's model, trace and model violations.
struct Backend {
    model: Model,
    records: Vec<Record>,
    violations: Vec<(usize, Class, String)>,
}

impl Backend {
    const fn new(kind: Kind) -> Self {
        Self {
            model: Model::new(kind),
            records: Vec::new(),
            violations: Vec::new(),
        }
    }

    fn violation(&mut self, index: usize, class: Class, message: String) {
        self.violations.push((index, class, message));
    }

    /// Within the size caps, a mutation through a live, checked handle has no reason to fail. A
    /// failure is reported, and the blob is unchecked from then on either way.
    fn mutated(
        &mut self,
        index: usize,
        generation: u64,
        compare: &Compare,
        result: &Result<(), Error>,
    ) {
        let Err(e) = result else {
            return;
        };
        if matches!(compare, Compare::Blob { .. }) {
            let note = self.model.blobs[&generation].rf2_note();
            self.violation(
                index,
                Class::MutationFailed,
                format!("mutation through a live handle failed with {e:?}{note}"),
            );
        }
        self.model.blobs.get_mut(&generation).unwrap().unchecked = true;
    }

    /// Run one session's operations. Every handle is dropped before this returns, so none
    /// outlives its runner.
    async fn run<S: Storage>(&mut self, storage: &S, base: usize, ops: &[Op]) {
        let mut slots: [Option<S::Blob>; SLOTS] = Default::default();
        for (i, op) in ops.iter().enumerate() {
            let record = self.step(storage, &mut slots, base + i, op).await;
            self.records.push(record);
        }
        drop(slots);
        for slot in 0..SLOTS {
            self.model.close_slot(slot);
        }
    }

    async fn step<S: Storage>(
        &mut self,
        storage: &S,
        slots: &mut [Option<S::Blob>; SLOTS],
        index: usize,
        op: &Op,
    ) -> Record {
        match op {
            Op::Open {
                slot,
                partition,
                name,
                versions,
            } => {
                self.open(storage, slots, index, *slot, *partition, *name, *versions)
                    .await
            }
            Op::Write {
                slot,
                offset,
                chunks,
                sync,
                dont_cache,
            } => {
                let Some(blob) = slots[*slot].as_ref() else {
                    return Record::skipped();
                };
                let generation = self.model.slots[*slot].expect("open slot is modeled");
                let model = &self.model.blobs[&generation];
                let state = model.summary();
                let offset = offset.resolve(model.len(), MAX_OFFSET);
                let compare = self.mutation_compare(generation);
                let total: usize = chunks.iter().sum();
                let data: Vec<u8> = (0..total as u64)
                    .map(|i| value(index, offset + i))
                    .collect();
                let mut bufs = Vec::with_capacity(chunks.len());
                let mut start = 0;
                for len in chunks {
                    bufs.push(IoBuf::from(data[start..start + len].to_vec()));
                    start += len;
                }
                let mut options = WriteOptions::default();
                if *sync {
                    options |= WriteOptions::SYNC;
                }
                if *dont_cache {
                    options |= WriteOptions::DONT_CACHE;
                }
                let result = blob.write_at(offset, IoBufs::from(bufs), options).await;
                self.mutated(index, generation, &compare, &result);
                let kind = self.model.kind;
                let model = self.model.blobs.get_mut(&generation).unwrap();
                if model.removed || result.is_err() {
                    model.unchecked = true;
                } else if total > 0 {
                    model.write(offset, &data, *sync);
                } else if kind == Kind::Deterministic && !*sync && offset > model.len() {
                    // RF-2: memory resizes its contents to the write's end, zero-filling.
                    model.resize(offset);
                    model.rf2 = true;
                }
                Record {
                    outcome: result
                        .map_or_else(|e| Outcome::err(&e), |()| Outcome::Ok(Value::Unit)),
                    resolved: format!("offset={offset} len={total}"),
                    state,
                    compare,
                }
            }
            Op::ReadAt {
                slot,
                offset,
                len,
                dont_cache,
            } => {
                let Some(blob) = slots[*slot].as_ref() else {
                    return Record::skipped();
                };
                let generation = self.model.slots[*slot].expect("open slot is modeled");
                let size = self.model.blobs[&generation].len();
                let range = (offset.resolve(size, u64::MAX), *len);
                let result = blob
                    .read_at(range.0, range.1, read_options(*dont_cache))
                    .await
                    .map(|buf| vec![buf.coalesce().as_ref().to_vec()]);
                self.judge_reads(index, generation, &[range], result)
            }
            Op::ReadAtBuf {
                slot,
                offset,
                len,
                chunks,
                dont_cache,
            } => {
                let Some(blob) = slots[*slot].as_ref() else {
                    return Record::skipped();
                };
                let generation = self.model.slots[*slot].expect("open slot is modeled");
                let size = self.model.blobs[&generation].len();
                let range = (offset.resolve(size, u64::MAX), *len);
                let bufs: Vec<IoBufMut> =
                    chunks.iter().map(|c| IoBufMut::with_capacity(*c)).collect();
                // Construction keeps only the chunks with capacity.
                let starts: Vec<*const u8> = bufs
                    .iter()
                    .filter(|buf| buf.capacity() > 0)
                    .map(|buf| buf.as_ref().as_ptr())
                    .collect();
                let result = blob
                    .read_at_buf(
                        range.0,
                        range.1,
                        IoBufsMut::from(bufs),
                        read_options(*dont_cache),
                    )
                    .await;
                if let Ok(buf) = &result
                    && let Some(message) = buf_layout(buf, chunks, &starts, range.1)
                {
                    self.violation(index, Class::Layout, message);
                }
                let result = result.map(|buf| vec![buf.coalesce().as_ref().to_vec()]);
                self.judge_reads(index, generation, &[range], result)
            }
            Op::ReadMany {
                slot,
                ranges,
                dont_cache,
            } => {
                let Some(blob) = slots[*slot].as_ref() else {
                    return Record::skipped();
                };
                let generation = self.model.slots[*slot].expect("open slot is modeled");
                let ranges = self.resolve_ranges(generation, ranges);
                let stream = blob.read_many(&ranges, read_options(*dont_cache));
                let mut stream = std::pin::pin!(stream);
                let mut bufs: Vec<Option<Vec<u8>>> = vec![None; ranges.len()];
                let mut error = None;
                while let Some(item) = stream.next().await {
                    match item {
                        Ok((i, buf)) => match bufs.get_mut(i) {
                            Some(entry @ None) => *entry = Some(buf.coalesce().as_ref().to_vec()),
                            Some(Some(_)) => {
                                self.violation(
                                    index,
                                    Class::ReadMany,
                                    format!("read_many yielded range {i} twice"),
                                );
                            }
                            None => {
                                self.violation(
                                    index,
                                    Class::ReadMany,
                                    format!("read_many yielded range {i} of {}", ranges.len()),
                                );
                            }
                        },
                        Err(e) => {
                            error = Some(e);
                            break;
                        }
                    }
                }
                let result = match error {
                    Some(e) => Err(e),
                    None => {
                        let missing: Vec<usize> =
                            (0..bufs.len()).filter(|i| bufs[*i].is_none()).collect();
                        if !missing.is_empty() {
                            self.violation(
                                index,
                                Class::ReadMany,
                                format!("read_many ended without an error or ranges {missing:?}"),
                            );
                        }
                        Ok(bufs.into_iter().map(Option::unwrap_or_default).collect())
                    }
                };
                self.judge_reads(index, generation, &ranges, result)
            }
            Op::StartReadMany {
                slot,
                ranges,
                dont_cache,
                wait,
            } => {
                let Some(blob) = slots[*slot].as_ref() else {
                    return Record::skipped();
                };
                let generation = self.model.slots[*slot].expect("open slot is modeled");
                let ranges = self.resolve_ranges(generation, ranges);
                let handle = blob
                    .start_read_many(&ranges, read_options(*dont_cache))
                    .await;
                if !*wait {
                    drop(handle);
                    return Record {
                        outcome: Outcome::Dropped,
                        resolved: format!("ranges={ranges:?}"),
                        state: self.model.blobs[&generation].summary(),
                        compare: Compare::None,
                    };
                }
                let result = handle.await.map(|bufs| {
                    bufs.into_iter()
                        .map(|buf| buf.coalesce().as_ref().to_vec())
                        .collect::<Vec<_>>()
                });
                if let Ok(bufs) = &result
                    && bufs.len() != ranges.len()
                {
                    self.violation(
                        index,
                        Class::ReadMany,
                        format!(
                            "start_read_many returned {} buffers for {} ranges",
                            bufs.len(),
                            ranges.len()
                        ),
                    );
                }
                self.judge_reads(index, generation, &ranges, result)
            }
            Op::Resize { slot, len } => {
                let Some(blob) = slots[*slot].as_ref() else {
                    return Record::skipped();
                };
                let generation = self.model.slots[*slot].expect("open slot is modeled");
                let model = &self.model.blobs[&generation];
                let state = model.summary();
                let len = len.resolve(model.len(), MAX_OFFSET);
                let compare = self.mutation_compare(generation);
                let result = blob.resize(len).await;
                self.mutated(index, generation, &compare, &result);
                let model = self.model.blobs.get_mut(&generation).unwrap();
                if model.removed || result.is_err() {
                    model.unchecked = true;
                } else {
                    model.resize(len);
                }
                Record {
                    outcome: result
                        .map_or_else(|e| Outcome::err(&e), |()| Outcome::Ok(Value::Unit)),
                    resolved: format!("len={len}"),
                    state,
                    compare,
                }
            }
            Op::Sync { slot } => {
                let Some(blob) = slots[*slot].as_ref() else {
                    return Record::skipped();
                };
                let generation = self.model.slots[*slot].expect("open slot is modeled");
                let state = self.model.blobs[&generation].summary();
                let compare = self.mutation_compare(generation);
                let result = blob.sync().await;
                self.mutated(index, generation, &compare, &result);
                self.synced(generation, result.is_ok());
                Record {
                    outcome: result
                        .map_or_else(|e| Outcome::err(&e), |()| Outcome::Ok(Value::Unit)),
                    resolved: String::new(),
                    state,
                    compare,
                }
            }
            Op::StartSync { slot, wait } => {
                let Some(blob) = slots[*slot].as_ref() else {
                    return Record::skipped();
                };
                let generation = self.model.slots[*slot].expect("open slot is modeled");
                let state = self.model.blobs[&generation].summary();
                let compare = self.mutation_compare(generation);
                let handle = blob.start_sync().await;
                if !*wait {
                    // A dropped handle's sync may or may not complete, so the model is unchanged.
                    drop(handle);
                    let model = self.model.blobs.get_mut(&generation).unwrap();
                    if model.removed {
                        model.unchecked = true;
                    }
                    return Record {
                        outcome: Outcome::Dropped,
                        resolved: String::new(),
                        state,
                        compare: Compare::None,
                    };
                }
                let result = handle.await;
                self.mutated(index, generation, &compare, &result);
                self.synced(generation, result.is_ok());
                Record {
                    outcome: result
                        .map_or_else(|e| Outcome::err(&e), |()| Outcome::Ok(Value::Unit)),
                    resolved: String::new(),
                    state,
                    compare,
                }
            }
            Op::Remove { partition, name } => {
                let partition = partition.get();
                let name = name.map(BlobName::get);
                let state = self.model.partition_summary(&partition);
                // Removing a name, or a partition holding a name, that a failed creation may
                // have left behind has no outcome the model can predict.
                let uncertain = self.model.uncertain_names(&partition);
                let compare = if name
                    .as_ref()
                    .map_or(!uncertain.is_empty(), |name| uncertain.contains(name))
                {
                    Compare::None
                } else {
                    Compare::State(State::Remove {
                        partition: self.model.partitions.contains_key(&partition),
                        blob: name
                            .as_ref()
                            .map(|name| self.model.current(&partition, name).is_some()),
                    })
                };
                // Removing a blob or partition the model holds has no reason to fail, unless a
                // failed creation left the partition's contents uncertain.
                let held = name.as_ref().map_or_else(
                    || self.model.partitions.contains_key(&partition),
                    |name| self.model.current(&partition, name).is_some(),
                );
                let result = storage.remove(&partition, name.as_deref()).await;
                let valid = valid_partition(&partition);
                match &result {
                    Ok(()) if !valid => {
                        self.violation(
                            index,
                            Class::Remove,
                            "remove of an invalid partition succeeded".into(),
                        );
                    }
                    Ok(()) => self.model.unlink(&partition, name.as_deref()),
                    Err(e) if !valid && !Documented::PartitionInvalid.matches(e) => {
                        self.violation(
                            index,
                            Class::Remove,
                            format!("remove of an invalid partition failed with {e:?}"),
                        );
                    }
                    Err(e) if valid && held && uncertain.is_empty() => {
                        self.violation(
                            index,
                            Class::Remove,
                            format!("remove of a held target failed with {e:?}"),
                        );
                    }
                    Err(_) => {}
                }
                Record {
                    outcome: result
                        .map_or_else(|e| Outcome::err(&e), |()| Outcome::Ok(Value::Unit)),
                    resolved: String::new(),
                    state,
                    compare,
                }
            }
            Op::Scan { partition } => {
                let partition = partition.get();
                let state = self.model.partition_summary(&partition);
                let names = self.model.names(&partition);
                // A failed creation may have left its name, and its partition, behind.
                let uncertain = self.model.uncertain_names(&partition);
                let result = storage.scan(&partition).await;
                let valid = valid_partition(&partition);
                match &result {
                    Ok(_) if !valid => {
                        self.violation(
                            index,
                            Class::Scan,
                            "scan of an invalid partition succeeded".into(),
                        );
                    }
                    Ok(got) => {
                        let got: BTreeSet<Vec<u8>> = got.iter().cloned().collect();
                        let expected = names.clone().unwrap_or_default();
                        if !expected.is_subset(&got)
                            || got
                                .iter()
                                .any(|n| !expected.contains(n) && !uncertain.contains(n))
                        {
                            self.violation(
                                index,
                                Class::Scan,
                                format!(
                                    "scan returned {:?}, model holds {:?} and may hold {:?}",
                                    got.iter().map(|n| display_name(n)).collect::<Vec<_>>(),
                                    expected.iter().map(|n| display_name(n)).collect::<Vec<_>>(),
                                    uncertain
                                        .iter()
                                        .map(|n| display_name(n))
                                        .collect::<Vec<_>>(),
                                ),
                            );
                        }
                    }
                    Err(e) if !valid => {
                        if !Documented::PartitionInvalid.matches(e) {
                            self.violation(
                                index,
                                Class::Scan,
                                format!("scan of an invalid partition failed with {e:?}"),
                            );
                        }
                    }
                    Err(e) if names.is_some() => {
                        self.violation(
                            index,
                            Class::Scan,
                            format!("scan of an existing partition failed with {e:?}"),
                        );
                    }
                    Err(_) => {}
                }
                Record {
                    outcome: match result {
                        Ok(names) => Outcome::Ok(Value::Names(names)),
                        Err(e) => Outcome::err(&e),
                    },
                    resolved: String::new(),
                    state,
                    compare: if uncertain.is_empty() {
                        Compare::State(State::Scan { names })
                    } else {
                        Compare::None
                    },
                }
            }
            Op::Drop { slot } => {
                let Some(blob) = slots[*slot].take() else {
                    return Record::skipped();
                };
                drop(blob);
                let generation = self.model.slots[*slot].expect("open slot is modeled");
                let state = self.model.blobs[&generation].summary();
                self.model.close_slot(*slot);
                Record {
                    outcome: Outcome::Ok(Value::Unit),
                    resolved: String::new(),
                    state,
                    compare: Compare::None,
                }
            }
            Op::Restart { .. } => unreachable!("sessions end at restarts"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn open<S: Storage>(
        &mut self,
        storage: &S,
        slots: &mut [Option<S::Blob>; SLOTS],
        index: usize,
        slot: usize,
        partition: PartitionName,
        name: BlobName,
        (lo, hi): (u16, u16),
    ) -> Record {
        // Opening into an occupied slot first drops its handle.
        drop(slots[slot].take());
        self.model.close_slot(slot);

        let partition = partition.get();
        let name = name.get();
        let existing = self.model.current(&partition, &name);
        let state = existing.map_or_else(
            || self.model.partition_summary(&partition),
            |generation| self.model.blobs[&generation].summary(),
        );

        // Documented errors the model predicts. Several may apply at once, and any of them is
        // accepted then.
        let mut documented = Vec::new();
        if !valid_partition(&partition) {
            documented.push(Documented::PartitionInvalid);
        } else if let Some(generation) = existing {
            let blob = &self.model.blobs[&generation];
            if !(lo..=hi).contains(&blob.version) {
                documented.push(Documented::VersionMismatch);
            }
            match blob.layout {
                Some(layout) if self.model.kind == Kind::Tokio => {
                    if !self.model.layouts.contains(&layout) {
                        documented.push(Documented::LayoutMismatch);
                    }
                }
                // An unknown layout may mismatch on tokio, so the error is accepted whenever
                // another one is predicted.
                None if self.model.kind == Kind::Tokio && !documented.is_empty() => {
                    documented.push(Documented::LayoutMismatch);
                }
                _ => {}
            }
            if blob.open {
                documented.push(Documented::AlreadyOpen);
            }
        }
        let layout_unknown = self.model.kind == Kind::Tokio
            && existing.is_some_and(|generation| self.model.blobs[&generation].layout.is_none());

        // Documented errors whose precondition the model rules out. A reopen after a removal is
        // a new blob, and a removed generation's handle does not count as open. The version and
        // layout of a name whose creation failed, or of an unchecked blob, are not certain.
        let uncertain = self
            .model
            .uncertain
            .contains(&(partition.clone(), name.clone()));
        let mut excluded = Vec::new();
        if self.model.kind == Kind::Deterministic {
            excluded.push(Documented::LayoutMismatch);
        }
        if valid_partition(&partition) {
            excluded.push(Documented::PartitionInvalid);
            match existing.map(|generation| &self.model.blobs[&generation]) {
                None => {
                    excluded.push(Documented::AlreadyOpen);
                    if !uncertain {
                        excluded.push(Documented::VersionMismatch);
                        excluded.push(Documented::LayoutMismatch);
                    }
                }
                Some(blob) => {
                    if !blob.open {
                        excluded.push(Documented::AlreadyOpen);
                    }
                    if !blob.unchecked {
                        if (lo..=hi).contains(&blob.version) {
                            excluded.push(Documented::VersionMismatch);
                        }
                        if blob
                            .layout
                            .is_some_and(|layout| self.model.layouts.contains(&layout))
                        {
                            excluded.push(Documented::LayoutMismatch);
                        }
                    }
                }
            }
        }

        // RF-3: tokio fails to open a valid name past its limits, which it never holds.
        let rf3 =
            (self.model.kind == Kind::Tokio && valid_partition(&partition) && existing.is_none())
                .then(|| tokio_rf3(&partition, &name))
                .flatten();

        // Memory reads every layout by design, so a mismatch predicted or possible on tokio is not
        // compared. Nor is a name whose creation failed, which may hold state of a different shape
        // on each backend, or an RF-3 open.
        let compare = if uncertain
            || layout_unknown
            || rf3.is_some()
            || documented.contains(&Documented::LayoutMismatch)
        {
            Compare::None
        } else {
            Compare::State(State::Open {
                existing: existing.map(|generation| {
                    let blob = &self.model.blobs[&generation];
                    (blob.version, blob.open)
                }),
            })
        };

        let result = storage
            .open_versioned(
                &partition,
                &name,
                BlobVersion::new(lo)..=BlobVersion::new(hi),
            )
            .await;
        let outcome = match &result {
            Ok((_, size, version)) => Outcome::Ok(Value::Opened {
                size: *size,
                version: version.get(),
            }),
            Err(e) => Outcome::err(e),
        };
        match result {
            Err(e) if rf3.is_some_and(|(error, _)| error.matches(&e)) => {
                if rf3.is_some_and(|(_, creates)| creates) {
                    self.model.partitions.entry(partition).or_default();
                }
            }
            Err(e) if rf3.is_some() => {
                let (error, _) = rf3.unwrap();
                self.violation(
                    index,
                    Class::AllowlistStale,
                    ALLOWLIST[RF3].stale(&format!("tokio's open failed with {e:?}, not {error:?}")),
                );
                self.model.uncertain.insert((partition, name));
            }
            Err(e) => {
                if let Some(rule) = excluded.iter().find(|d| d.matches(&e)) {
                    self.violation(
                        index,
                        Class::OpenError,
                        format!("open failed with {e:?}, which the model rules out ({rule:?})"),
                    );
                } else if !documented.is_empty() && !documented.iter().any(|d| d.matches(&e)) {
                    self.violation(
                        index,
                        Class::OpenError,
                        format!("open failed with {e:?}, expected one of {documented:?}"),
                    );
                } else if documented.is_empty() {
                    // Any open the model expects to succeed must, except a name whose creation
                    // already failed, an unchecked blob, and names past tokio's limits.
                    let expected = valid_partition(&partition)
                        && !uncertain
                        && existing
                            .is_none_or(|generation| !self.model.blobs[&generation].unchecked)
                        && (self.model.kind == Kind::Deterministic
                            || !exceeds_tokio_limits(&partition, &name));
                    if expected && !Documented::ALL.iter().any(|d| d.matches(&e)) {
                        // Memory accepting names past tokio's limits is what RF-3 relies on.
                        if exceeds_tokio_limits(&partition, &name) {
                            self.violation(
                                index,
                                Class::AllowlistStale,
                                ALLOWLIST[RF3].stale(&format!(
                                    "memory failed to open a name past tokio's limits with {e:?}"
                                )),
                            );
                        } else {
                            self.violation(
                                index,
                                Class::OpenError,
                                format!("open the model expects to succeed failed with {e:?}"),
                            );
                        }
                    }
                    if existing.is_none() {
                        self.model.uncertain.insert((partition, name));
                    }
                }
            }
            Ok((blob, _, _)) if !documented.is_empty() => {
                drop(blob);
                self.violation(
                    index,
                    Class::OpenError,
                    format!("open succeeded, expected one of {documented:?}"),
                );
            }
            Ok((blob, size, version)) => {
                if let Some((error, _)) = rf3 {
                    self.violation(
                        index,
                        Class::AllowlistStale,
                        ALLOWLIST[RF3].stale(&format!("tokio's open succeeded, not {error:?}")),
                    );
                }
                let generation = match existing {
                    Some(generation) => {
                        let model = &self.model.blobs[&generation];
                        let recorded = model.version;
                        let (min, max) = model.allowed_sizes();
                        let unchecked = model.unchecked;
                        let note = model.rf2_note();
                        if version.get() != recorded {
                            self.violation(
                                index,
                                Class::Reopen,
                                format!(
                                    "reopen returned version {}, blob holds {recorded}",
                                    version.get(),
                                ),
                            );
                        }
                        if !unchecked && !(min..=max).contains(&size) {
                            self.violation(
                                index,
                                Class::Reopen,
                                format!("reopen returned size {size}, allowed {min}..={max}{note}"),
                            );
                        }
                        generation
                    }
                    None => {
                        // Creation with the range's highest version is implementation behaviour
                        // (`Header::create` uses `versions.end()`), not a documented guarantee.
                        if !uncertain && (size != 0 || version.get() != hi) {
                            self.violation(
                                index, Class::Create,
                                format!(
                                    "creation returned size {size} and version {}, expected size 0 and version {hi}",
                                    version.get()
                                ),
                            );
                        }
                        self.model
                            .uncertain
                            .remove(&(partition.clone(), name.clone()));
                        // A name whose earlier creation failed may hold a blob that this open
                        // adopted, so its returned version is recorded and its layout is unknown.
                        if uncertain {
                            let version = version.get();
                            self.model.create(partition, name, version, None)
                        } else {
                            let layout = self.model.create_layout();
                            self.model.create(partition, name, hi, Some(layout))
                        }
                    }
                };
                let model = self.model.blobs.get_mut(&generation).unwrap();
                model.reopen(size);
                model.open = true;
                slots[slot] = Some(blob);
                self.model.slots[slot] = Some(generation);
            }
        }
        Record {
            outcome,
            resolved: String::new(),
            state,
            compare,
        }
    }

    /// Mutations through a removed or unchecked handle have no specified outcome, so they are
    /// not compared. A mutation through a removed handle makes it unchecked.
    fn mutation_compare(&mut self, generation: u64) -> Compare {
        let model = self.model.blobs.get_mut(&generation).unwrap();
        if model.removed {
            model.unchecked = true;
        }
        if model.unchecked {
            return Compare::None;
        }
        Compare::Blob {
            len: model.len(),
            expected: Vec::new(),
            rf1: false,
        }
    }

    fn synced(&mut self, generation: u64, ok: bool) {
        let model = self.model.blobs.get_mut(&generation).unwrap();
        if ok && !model.unchecked {
            model.sync();
        }
    }

    fn resolve_ranges(&self, generation: u64, ranges: &[(Offset, usize)]) -> Vec<(u64, usize)> {
        let size = self.model.blobs[&generation].len();
        ranges
            .iter()
            .map(|(offset, len)| (offset.resolve(size, u64::MAX), *len))
            .collect()
    }

    /// Judge the result of reading `ranges` against the model and record it.
    fn judge_reads(
        &mut self,
        index: usize,
        generation: u64,
        ranges: &[(u64, usize)],
        result: Result<Vec<Vec<u8>>, Error>,
    ) -> Record {
        let model = &self.model.blobs[&generation];
        let state = model.summary();
        let resolved = format!("ranges={ranges:?}");
        let checked = !model.unchecked;
        let size = model.len();
        let rf1 = ranges
            .iter()
            .any(|(offset, len)| *len == 0 && *offset > size);
        let note = model.rf2_note();
        let expected: Vec<Vec<Option<u8>>> = ranges
            .iter()
            .map(|(offset, len)| model.expected(*offset, *len))
            .collect();

        let mut violations = Vec::new();
        if let Ok(bufs) = &result {
            for (i, (buf, (_, len))) in bufs.iter().zip(ranges).enumerate() {
                if buf.len() != *len {
                    violations.push((
                        Class::ReadLen,
                        format!("range {i} returned {} bytes, requested {len}", buf.len()),
                    ));
                }
            }
        }
        if checked {
            let expect = ranges
                .iter()
                .map(|(offset, len)| read_expect(size, *offset, *len))
                .fold(Expect::Ok, |acc, e| match (acc, e) {
                    (Expect::Err, _) | (_, Expect::Err) => Expect::Err,
                    (Expect::Any, _) | (_, Expect::Any) => Expect::Any,
                    _ => Expect::Ok,
                });
            match (&result, expect) {
                (Ok(_), Expect::Err) => {
                    violations.push((
                        Class::ReadLen,
                        format!("read past len {size} succeeded{note}"),
                    ));
                }
                (Err(e), Expect::Ok) => {
                    violations.push((
                        Class::ReadLen,
                        format!("read inside len {size} failed with {e:?}{note}"),
                    ));
                }
                // Memory fails every zero-length read past the end, so its success means RF-1
                // changed.
                (Ok(_), _) if rf1 && self.model.kind == Kind::Deterministic => {
                    violations.push((
                        Class::AllowlistStale,
                        ALLOWLIST[RF1].stale("memory succeeded on a zero-length read past the end"),
                    ));
                }
                _ => {}
            }
            if let Ok(bufs) = &result {
                for (i, (buf, known)) in bufs.iter().zip(&expected).enumerate() {
                    let mismatches: Vec<usize> = buf
                        .iter()
                        .zip(known)
                        .enumerate()
                        .filter(|(_, (got, want))| want.is_some_and(|want| want != **got))
                        .map(|(j, _)| j)
                        .collect();
                    if let Some(&first) = mismatches.first() {
                        let offset = ranges[i].0 + first as u64;
                        violations.push((Class::ReadBytes, format!(
                            "range {i} differs from known model bytes at {} positions, first at blob offset {offset}: got {:#04x}, model {:#04x} (flags {:#04b}){note}",
                            mismatches.len(),
                            buf[first],
                            known[first].unwrap(),
                            model.flags[offset as usize],
                        )));
                    }
                }
            }
        }
        for (class, message) in violations {
            self.violation(index, class, message);
        }

        // A byte whose only flag is STABLE was readable at the last reopen, which makes it
        // durable (`Storage` durability), and no mutation has touched it since, so every later
        // read must return the value observed now. Removed handles and blobs adopted from a
        // failed creation are left alone.
        let model = self.model.blobs.get_mut(&generation).unwrap();
        if checked
            && !model.removed
            && model.layout.is_some()
            && let Ok(bufs) = &result
        {
            for (buf, (offset, len)) in bufs.iter().zip(ranges) {
                if buf.len() != *len {
                    continue;
                }
                for (j, value) in buf.iter().enumerate() {
                    let Some(position) = offset
                        .checked_add(j as u64)
                        .and_then(|position| usize::try_from(position).ok())
                    else {
                        break;
                    };
                    if let Some(flag) = model.flags.get_mut(position)
                        && *flag == STABLE
                    {
                        *flag = KNOWN | STABLE;
                        model.data[position] = *value;
                    }
                }
            }
        }

        Record {
            outcome: match result {
                Ok(bufs) => Outcome::Ok(Value::Bytes(bufs)),
                Err(e) => Outcome::err(&e),
            },
            resolved,
            state,
            compare: if checked {
                Compare::Blob {
                    len: size,
                    expected,
                    rf1,
                }
            } else {
                Compare::None
            },
        }
    }
}

/// Check that `read_at_buf` returned the caller's buffers with their chunk layout preserved
/// (`Blob::read_at_buf`): the same total capacity and the same single-chunk shape, given that
/// construction keeps only the chunks with capacity. The readable length of each chunk is also
/// checked against filling `len` bytes into the chunks in order. That is implementation behaviour
/// (every backend fills the buffers through `IoBufsMut::set_len`), not a documented guarantee.
/// Each readable chunk must start at the caller's chunk in the same position, so the buffers
/// returned are the ones passed in. Chunks left without readable bytes expose no address and are
/// not checked.
fn buf_layout(
    buf: &IoBufsMut,
    chunks: &[usize],
    starts: &[*const u8],
    len: usize,
) -> Option<String> {
    let capacities: Vec<usize> = chunks.iter().copied().filter(|c| *c > 0).collect();
    let capacity: usize = capacities.iter().sum();
    let single = capacities.len() <= 1;
    let mut remaining = len;
    let expected: Vec<usize> = capacities
        .iter()
        .map(|c| {
            let filled = remaining.min(*c);
            remaining -= filled;
            filled
        })
        .filter(|filled| *filled > 0)
        .collect();
    let mut slices = [IoSlice::new(&[]); MAX_CHUNKS + 1];
    let count = buf.chunks_vectored(&mut slices);
    let readable: Vec<usize> = slices[..count].iter().map(|s| s.len()).collect();
    let moved: Vec<usize> = slices[..count]
        .iter()
        .zip(starts)
        .enumerate()
        .filter(|(_, (slice, start))| slice.as_ptr() != **start)
        .map(|(i, _)| i)
        .collect();
    (buf.capacity() != capacity
        || buf.is_single() != single
        || readable != expected
        || !moved.is_empty())
    .then(|| {
        format!(
            "read_at_buf changed the chunk layout of capacities {capacities:?}: returned capacity {} (expected {capacity}), single {} (expected {single}), readable chunks {readable:?} (expected {expected:?}), chunks {moved:?} are not the caller's buffers",
            buf.capacity(),
            buf.is_single(),
        )
    })
}

fn read_options(dont_cache: bool) -> ReadOptions {
    if dont_cache {
        ReadOptions::DONT_CACHE
    } else {
        ReadOptions::default()
    }
}

/// Compare one operation, `det` on the deterministic backend and `tok` on tokio. Ok/Err must agree
/// when both models hold the same state, and returned bytes must agree wherever both models know
/// the same value. [RF1] accepts tokio Ok against memory `Err(BlobInsufficientLength)`.
fn compare(det: &Record, tok: &Record) -> Option<String> {
    let (a, b) = (det, tok);
    if let (Compare::Blob { rf1: true, .. }, Compare::Blob { rf1: true, .. }) =
        (&a.compare, &b.compare)
        && let (Outcome::Err(error), Outcome::Ok(_)) = (&a.outcome, &b.outcome)
        && error.starts_with("BlobInsufficientLength")
    {
        return None;
    }
    let comparable = match (&a.compare, &b.compare) {
        (Compare::Blob { len: la, .. }, Compare::Blob { len: lb, .. }) => la == lb,
        (Compare::State(sa), Compare::State(sb)) => sa == sb,
        _ => false,
    };
    if !comparable {
        return None;
    }
    match (&a.outcome, &b.outcome) {
        (Outcome::Ok(Value::Bytes(ba)), Outcome::Ok(Value::Bytes(bb))) => {
            let (Compare::Blob { expected: ea, .. }, Compare::Blob { expected: eb, .. }) =
                (&a.compare, &b.compare)
            else {
                return None;
            };
            for (i, (((xa, xb), ka), kb)) in ba.iter().zip(bb).zip(ea).zip(eb).enumerate() {
                for (j, (((va, vb), ka), kb)) in xa.iter().zip(xb).zip(ka).zip(kb).enumerate() {
                    if ka.is_some() && ka == kb && va != vb {
                        return Some(format!(
                            "range {i} byte {j} differs where both models know {:#04x}: {va:#04x} against {vb:#04x}",
                            ka.unwrap()
                        ));
                    }
                }
            }
            None
        }
        (Outcome::Ok(_), Outcome::Err(_)) | (Outcome::Err(_), Outcome::Ok(_)) => {
            Some("one backend succeeded and the other failed".into())
        }
        _ => None,
    }
}

/// Panic with the earliest failure, both observations of it, the model state, and the trace.
fn report(ops: &[Op], det: &Backend, tok: &Backend) {
    // Each op's failures in a fixed priority: deterministic model violations, tokio model
    // violations, then the cross-backend mismatch, each in recorded order. The first one classes
    // the crash.
    let mut failures: BTreeMap<usize, Vec<(Class, String)>> = BTreeMap::new();
    for (index, class, message) in &det.violations {
        failures
            .entry(*index)
            .or_default()
            .push((*class, format!("deterministic model violation: {message}")));
    }
    for (index, class, message) in &tok.violations {
        failures
            .entry(*index)
            .or_default()
            .push((*class, format!("tokio model violation: {message}")));
    }
    for (index, (a, b)) in det.records.iter().zip(&tok.records).enumerate() {
        if let Some(message) = compare(a, b) {
            failures.entry(index).or_default().push((
                cross_class(&ops[index]),
                format!("cross-backend mismatch: {message}"),
            ));
        }
    }
    let Some((&index, reasons)) = failures.iter().next() else {
        return;
    };

    let mut out = String::new();
    let _ = writeln!(
        out,
        "storage_differential failure at op {index}: {:?}",
        ops[index]
    );
    for (_, reason) in reasons {
        let _ = writeln!(out, "  {reason}");
    }
    for (name, backend) in [("deterministic", det), ("tokio", tok)] {
        let record = &backend.records[index];
        let _ = writeln!(out, "  {name}: {} {}", record.outcome, record.resolved);
        let _ = writeln!(out, "    before: {}", record.state);
    }
    let _ = writeln!(out, "trace:");
    for (i, op) in ops.iter().enumerate().take(index + 1) {
        let _ = writeln!(out, "  #{i} {op:?}");
        for (name, backend) in [("det", det), ("tok", tok)] {
            let record = &backend.records[i];
            let _ = writeln!(out, "      {name}: {} {}", record.outcome, record.resolved);
        }
    }
    reasons[0].0.fail(&out);
}

/// A fresh tokio storage directory for one input.
fn tokio_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let base = std::env::var_os(DIR_ENV).map_or_else(std::env::temp_dir, PathBuf::from);
    let dir = base.join(format!(
        "commonware_runtime_fuzz_{}_{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn fuzz(input: FuzzInput) {
    // Split the operations into sessions at their restarts. A restart carries the layouts the
    // next tokio session accepts. The first session accepts every layout.
    let mut sessions = Vec::new();
    let mut start = 0;
    let mut layouts = BlobLayout::ALL;
    for (i, op) in input.ops.iter().enumerate() {
        if let Op::Restart { layouts: next } = op {
            sessions.push((start, &input.ops[start..i], layouts, true));
            start = i + 1;
            layouts = next.range();
        }
    }
    sessions.push((start, &input.ops[start..], layouts, false));

    let dir = tokio_dir();
    let mut det = Backend::new(Kind::Deterministic);
    let mut tok = Backend::new(Kind::Tokio);
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(input.entropy));
    let mut runner = deterministic::Runner::new(cfg);
    for (base, ops, layouts, restart) in sessions {
        let (det_ref, tok_ref, dir_ref) = (&mut det, &mut tok, &dir);
        let ((), checkpoint) = runner.start_and_recover(|context| async move {
            det_ref.run(&context, base, ops).await;
            drop(context);

            let cfg = tokio::Config::new()
                .with_storage_directory(dir_ref.clone())
                .with_storage_blob_layouts(layouts.clone())
                .with_worker_threads(1)
                .with_catch_panics(false);
            tok_ref.model.layouts = layouts;
            tokio::Runner::new(cfg).start(|context| async move {
                tok_ref.run(&context, base, ops).await;
            });
        });
        runner = deterministic::Runner::from(checkpoint);
        if restart {
            for backend in [&mut det, &mut tok] {
                backend.records.push(Record {
                    outcome: Outcome::Ok(Value::Unit),
                    resolved: String::new(),
                    state: String::new(),
                    compare: Compare::None,
                });
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(det.records.len(), input.ops.len());
    assert_eq!(tok.records.len(), input.ops.len());
    report(&input.ops, &det, &tok);
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
