//! Operation vocabulary and backend-neutral contract model of the `storage_differential` target.
//!
//! The operations, their decoding and the model of the public [commonware_runtime::Storage] and
//! [commonware_runtime::Blob] contract live here so that other targets can drive the same model.
//! `storage_faults` uses [Model] with [Kind::Deterministic] for its namespace and views. See
//! `runtime/fuzz/SPEC.md`.

use crate::decode;
use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{BlobLayout, DEFAULT_BLOB_LAYOUT, Error};
use commonware_utils::{Entropy, rng::mix64};
use core::ops::RangeInclusive;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_OPS: usize = 64;
pub const SLOTS: usize = 4;
pub const MAX_CHUNKS: usize = 4;
pub const MAX_RANGES: usize = 8;

/// Memory storage allocates up to `offset + len` on writes and resizes and `len` on every read,
/// so offsets and lengths stay small enough that no allocation aborts.
pub const MAX_OFFSET: u64 = 1 << 20;
pub const MAX_LEN: usize = 1 << 16;

/// Overflow-edge read offsets, read with at most [MAX_EDGE_LEN] bytes.
pub const EDGE_OFFSETS: [u64; 4] = [
    u64::MAX,
    i64::MAX as u64,
    i64::MAX as u64 - 4096,
    i64::MAX as u64 - 8,
];
pub const MAX_EDGE_LEN: usize = 16;

/// Largest logical size the operations can produce, used to reject absurd reported sizes before
/// the model allocates them.
pub const MAX_SIZE: u64 = MAX_OFFSET + MAX_LEN as u64;

/// Model byte flags: the value is known, and the byte is durable.
pub const KNOWN: u8 = 1 << 0;
pub const STABLE: u8 = 1 << 1;

#[derive(Clone, Copy, Debug)]
pub enum PartitionName {
    P0,
    P1,
    Empty,
    Slash,
    Long255,
    Long256,
}

impl PartitionName {
    pub fn get(self) -> String {
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
pub enum BlobName {
    A,
    B,
    Empty,
    Long127,
    Long128,
    NonUtf8,
}

impl BlobName {
    pub fn get(self) -> Vec<u8> {
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
pub enum Offset {
    At(u64),
    End(i8),
}

impl Offset {
    pub fn resolve(self, size: u64, cap: u64) -> u64 {
        match self {
            Self::At(offset) => offset,
            Self::End(delta) => size.saturating_add_signed(i64::from(delta)).min(cap),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Layouts {
    V0,
    V1,
    Both,
}

impl Layouts {
    #[allow(deprecated)]
    pub const fn range(self) -> RangeInclusive<BlobLayout> {
        match self {
            Self::V0 => BlobLayout::V0..=BlobLayout::V0,
            Self::V1 => BlobLayout::V1..=BlobLayout::V1,
            Self::Both => BlobLayout::V0..=BlobLayout::V1,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Op {
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

pub fn slot(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(0..=SLOTS - 1)
}

/// Most partitions come from the plain pool so that operations collide on the same blobs.
pub fn partition(u: &mut Unstructured<'_>) -> arbitrary::Result<PartitionName> {
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
pub fn blob_name(u: &mut Unstructured<'_>) -> arbitrary::Result<BlobName> {
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

pub fn versions(u: &mut Unstructured<'_>) -> arbitrary::Result<(u16, u16)> {
    let a = u.int_in_range(0..=2)?;
    let b = u.int_in_range(0..=2)?;
    Ok((a.min(b), a.max(b)))
}

/// Write and resize offsets, biased toward page edges and the slot's current size.
pub fn offset(u: &mut Unstructured<'_>) -> arbitrary::Result<Offset> {
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
pub fn length(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
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
pub fn read_range(u: &mut Unstructured<'_>) -> arbitrary::Result<(Offset, usize)> {
    if u.ratio(1u8, 16u8)? {
        let edge = EDGE_OFFSETS[u.int_in_range(0..=EDGE_OFFSETS.len() - 1)?];
        return Ok((Offset::At(edge), u.int_in_range(0..=MAX_EDGE_LEN)?));
    }
    Ok((offset(u)?, length(u)?))
}

pub fn read_ranges(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<(Offset, usize)>> {
    (0..u.int_in_range(0..=MAX_RANGES)?)
        .map(|_| read_range(u))
        .collect()
}

/// Chunk lengths of a write, at most [MAX_LEN] bytes in total.
pub fn write_chunks(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<usize>> {
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
pub fn buf_chunks(u: &mut Unstructured<'_>, len: usize) -> arbitrary::Result<Vec<usize>> {
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
pub struct FuzzInput {
    pub ops: Vec<Op>,
    pub entropy: Entropy,
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
pub fn value(index: usize, position: u64) -> u8 {
    (mix64(((index as u64) << 48) ^ position) % 255) as u8 + 1
}

pub fn valid_partition(partition: &str) -> bool {
    !partition.is_empty()
        && partition
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Abbreviate long names so that reports stay readable.
pub fn display_partition(partition: &str) -> String {
    if partition.len() > 16 {
        format!("<{} chars>", partition.len())
    } else {
        format!("{partition:?}")
    }
}

pub fn display_name(name: &[u8]) -> String {
    if name.len() > 8 {
        format!("<{} bytes>", name.len())
    } else {
        format!("{name:02x?}")
    }
}

/// An error variant the trait docs name for a condition the model predicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Documented {
    AlreadyOpen,
    VersionMismatch,
    LayoutMismatch,
    PartitionInvalid,
}

impl Documented {
    pub const ALL: [Self; 4] = [
        Self::AlreadyOpen,
        Self::VersionMismatch,
        Self::LayoutMismatch,
        Self::PartitionInvalid,
    ];

    pub const fn matches(self, error: &Error) -> bool {
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
pub enum Expect {
    Ok,
    Err,
    Any,
}

/// A read of `len` bytes at `offset` must succeed inside the blob and fail past its end. A
/// zero-length read past the end has no specified outcome.
pub fn read_expect(size: u64, offset: u64, len: usize) -> Expect {
    match offset.checked_add(len as u64) {
        Some(end) if end <= size => Expect::Ok,
        _ if len == 0 => Expect::Any,
        _ => Expect::Err,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Deterministic,
    Tokio,
}

/// Model of one blob identity: a partition, a name and the generation that a removal ends.
pub struct BlobModel {
    pub partition: String,
    pub name: Vec<u8>,
    pub generation: u64,
    pub version: u16,
    /// `None` when the blob was adopted from a name whose earlier creation failed, which may
    /// have left a blob of any layout behind.
    pub layout: Option<BlobLayout>,
    /// Logical contents, exact in length while a handle is open.
    pub data: Vec<u8>,
    /// [KNOWN] and [STABLE] flags of each byte of `data`.
    pub flags: Vec<u8>,
    /// The size made durable by the last completed sync, while no size change followed it.
    pub synced_len: Option<u64>,
    /// Smallest and largest size held since the last completed sync, that size included.
    pub sizes: (u64, u64),
    pub open: bool,
    pub removed: bool,
    /// Set once the contract no longer determines this blob's state, such as after a mutation
    /// of a removed blob or a failed mutation. Results through it are not asserted.
    pub unchecked: bool,
    /// Set once the deterministic model grew the blob under the RF-2 allowlist entry.
    pub rf2: bool,
}

impl BlobModel {
    pub fn new(
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

    pub const fn len(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn size_changed(&mut self) {
        let len = self.len();
        self.synced_len = None;
        self.sizes = (self.sizes.0.min(len), self.sizes.1.max(len));
    }

    /// A completed write: the range becomes known, durable only if the write was `SYNC`. Growth
    /// zero-fills any gap before the range.
    pub fn write(&mut self, offset: u64, bytes: &[u8], sync: bool) {
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
    pub fn resize(&mut self, len: u64) {
        let len = len as usize;
        self.data.resize(len, 0);
        self.flags.resize(len, KNOWN);
        self.size_changed();
    }

    /// A completed sync: every byte and the size become durable.
    pub fn sync(&mut self) {
        for flag in &mut self.flags {
            *flag |= STABLE;
        }
        let len = self.len();
        self.synced_len = Some(len);
        self.sizes = (len, len);
    }

    /// Sizes a reopen may observe.
    pub const fn allowed_sizes(&self) -> (u64, u64) {
        match self.synced_len {
            Some(len) => (len, len),
            None => self.sizes,
        }
    }

    /// Adopt the size observed by a reopen. Only durable bytes below it stay known. Everything
    /// readable when an open returns is durable (`Storage` durability), so the reopen acts as a
    /// completed sync.
    pub fn reopen(&mut self, size: u64) {
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
    pub fn expected(&self, offset: u64, len: usize) -> Vec<Option<u8>> {
        (0..len as u64)
            .map(|i| {
                let position = usize::try_from(offset.checked_add(i)?).ok()?;
                (*self.flags.get(position)? & KNOWN != 0).then(|| self.data[position])
            })
            .collect()
    }

    pub fn summary(&self) -> String {
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

    /// A note for violations on a blob the RF-2 allowlist entry grew: if memory stopped growing on
    /// empty writes, the model's size is too large. The caller passes the entry's description.
    pub fn rf2_note(&self, entry: &str) -> String {
        if self.rf2 {
            format!("; this blob is affected by {entry}")
        } else {
            String::new()
        }
    }
}

/// The byte ranges whose flags contain `flag`, abbreviated after a few.
pub fn runs(flags: &[u8], flag: u8) -> String {
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
pub struct Model {
    pub kind: Kind,
    /// Layouts the backend accepts in the current session.
    pub layouts: RangeInclusive<BlobLayout>,
    pub next_generation: u64,
    /// Existing partitions and the live generation of each name in them.
    pub partitions: BTreeMap<String, BTreeMap<Vec<u8>, u64>>,
    /// Every live generation and every removed one a handle still refers to.
    pub blobs: BTreeMap<u64, BlobModel>,
    /// The generation each slot's handle refers to.
    pub slots: [Option<u64>; SLOTS],
    /// Names whose creation failed with an undocumented error, which may have left a partial
    /// blob behind, so the model does not know whether they exist or what they hold.
    pub uncertain: BTreeSet<(String, Vec<u8>)>,
}

impl Model {
    pub const fn new(kind: Kind) -> Self {
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

    pub fn current(&self, partition: &str, name: &[u8]) -> Option<u64> {
        self.partitions.get(partition)?.get(name).copied()
    }

    pub fn names(&self, partition: &str) -> Option<BTreeSet<Vec<u8>>> {
        Some(self.partitions.get(partition)?.keys().cloned().collect())
    }

    /// Names of a partition whose failed creation may have left a blob behind.
    pub fn uncertain_names(&self, partition: &str) -> BTreeSet<Vec<u8>> {
        self.uncertain
            .iter()
            .filter(|(p, _)| p == partition)
            .map(|(_, name)| name.clone())
            .collect()
    }

    /// Memory storage creates every blob with the default layout. Tokio creates it with the
    /// latest layout of its configured range.
    pub fn create_layout(&self) -> BlobLayout {
        match self.kind {
            Kind::Deterministic => DEFAULT_BLOB_LAYOUT,
            Kind::Tokio => *self.layouts.end(),
        }
    }

    pub fn create(
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

    pub fn close(&mut self, generation: u64) {
        let Some(blob) = self.blobs.get_mut(&generation) else {
            return;
        };
        blob.open = false;
        if blob.removed {
            self.blobs.remove(&generation);
        }
    }

    pub fn close_slot(&mut self, slot: usize) {
        if let Some(generation) = self.slots[slot].take() {
            self.close(generation);
        }
    }

    /// Unlink a blob, or every blob of a partition along with the partition. Handles keep
    /// referring to the removed generations.
    pub fn unlink(&mut self, partition: &str, name: Option<&[u8]>) {
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

    pub fn partition_summary(&self, partition: &str) -> String {
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
