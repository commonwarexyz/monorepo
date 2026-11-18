//! The runtime's own storage contract under injected failures and simulated crashes.
//!
//! One run drives the public [Storage] and [Blob] API of the deterministic runtime: four baseline
//! operations, the operations decoded from the input, and a crash after the last of them. Some
//! input operations carry a fault, which is written into the fault configuration of the runtime
//! for exactly that call. `Crash` operations and the mandatory crash end a session; the next one
//! starts from the checkpoint and verifies what survived.
//!
//! Every result is judged against a model of the contract: the namespace and the view of every
//! handle come from [crate::storage_model], and this module adds, per blob generation, the image
//! at the last durability cut (the base) and the mutations issued since (the log). After a crash
//! every blob must hold an image that replaying the log over the base can give ([reachable]).
//!
//! [fuzz] is the fuzz entry. [run] is the same run with a seam around the storage and no panic
//! on a violation, so tests can plant faults and read the result. See `runtime/fuzz/SPEC.md`,
//! target `storage_faults`, for the requirements (SF-R) and invariants (SF-I) named below.

use crate::{
    decode,
    storage_model::{
        self, KNOWN, Kind, Model, Offset, display_name, display_partition, valid_partition, value,
    },
};
use arbitrary::{Arbitrary, Unstructured};
use bytes::Buf as _;
use commonware_runtime::{
    Blob, BlobVersion, DEFAULT_BLOB_LAYOUT, Error, IoBuf, IoBufMut, IoBufs, IoBufsMut, ReadOptions,
    Storage, WriteOptions,
    deterministic::{self, FaultConfig, PartialWriteMode, ResizeConfig, WriteConfig},
};
use commonware_utils::{Entropy, FuzzRng, Probability, sync::RwLock};
use futures::StreamExt as _;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    io::IoSlice,
    sync::Arc,
};

/// Input operations per non-empty input.
pub const MAX_OPS: usize = 48;
/// `Crash` operations that take effect, on top of the mandatory crash.
pub const MAX_EXTRA_CRASHES: usize = 3;
/// Open handles.
pub const SLOTS: usize = 4;
/// Largest offset of a `Write`.
pub const MAX_OFFSET: u64 = 2048;
/// Largest total length of a `Write`.
pub const MAX_WRITE: usize = 256;
/// Largest length of a `Resize`, and so of every blob.
pub const MAX_SIZE: u64 = MAX_OFFSET + MAX_WRITE as u64;
/// Largest length of a read or of one range.
pub const MAX_READ: usize = 512;
/// Largest number of ranges of `ReadMany` and `StartReadMany`.
pub const MAX_RANGES: usize = 4;
/// Bytes of the baseline write.
pub const BASELINE_LEN: usize = 64;
/// Baseline operations at the start of every run.
pub const BASELINE_OPS: usize = 4;

/// Largest number of chunks of a write or of a `read_at_buf` destination.
const MAX_CHUNKS: usize = 4;
/// Largest spare capacity of a `read_at_buf` destination.
const MAX_EXTRA_CAPACITY: usize = 16;
/// Read offsets past the largest blob, so reads past the end are common.
const MAX_READ_OFFSET: u64 = MAX_SIZE + 8;
/// Overflow-edge read offsets, read with 1 to [MAX_EDGE_LEN] bytes.
const EDGE_OFFSETS: [u64; 3] = [u64::MAX, i64::MAX as u64, i64::MAX as u64 - 8];
const MAX_EDGE_LEN: usize = 16;
/// Retention rates a write fault may carry, in percent.
const RETENTION_PERCENTS: [u8; 5] = [0, 25, 50, 75, 100];
/// Partial rates a resize fault may carry, in percent.
const PARTIAL_PERCENTS: [u8; 3] = [0, 50, 100];
/// Probe reads the length search may use: enough to bisect `0..=MAX_SIZE`.
const MAX_SEARCH_READS: usize = 12;
/// Versions every recovery open accepts.
const RECOVERY_VERSIONS: (u16, u16) = (0, 2);
/// Trace records printed in a failure report.
const REPORT_RECORDS: usize = 40;

const _: () = assert!(SLOTS == storage_model::SLOTS);
const _: () = assert!(1u64 << MAX_SEARCH_READS > MAX_SIZE);

/// A partition name. `Empty` and `Slash` are invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionName {
    P0,
    P1,
    Empty,
    Slash,
}

impl PartitionName {
    pub fn get(self) -> String {
        match self {
            Self::P0 => "p0".into(),
            Self::P1 => "p1".into(),
            Self::Empty => String::new(),
            Self::Slash => "a/b".into(),
        }
    }
}

/// A blob name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobName {
    A,
    B,
    C,
}

impl BlobName {
    pub fn get(self) -> Vec<u8> {
        match self {
            Self::A => b"a".to_vec(),
            Self::B => b"b".to_vec(),
            Self::C => b"c".to_vec(),
        }
    }
}

/// A write fault: `write_rate` with `failure_rate` 0 or 1, a retention rate and a mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteFault {
    /// `failure_rate` 1 when set, else 0 (the crash policy of a write that succeeds, SF-R7).
    pub fails: bool,
    /// One of [RETENTION_PERCENTS].
    pub retention_percent: u8,
    pub mode: PartialWriteMode,
}

/// A resize fault: `resize_rate` with `failure_rate` 50 or 100 percent and `partial_rate` 0, 50
/// or 100 percent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResizeFault {
    pub failure_percent: u8,
    pub partial_percent: u8,
}

/// The fault written into the configuration for one call. The default is no fault.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fault {
    pub open: bool,
    pub read: bool,
    pub sync: bool,
    pub remove: bool,
    pub scan: bool,
    pub write: Option<WriteFault>,
    pub resize: Option<ResizeFault>,
}

fn percent(value: u8) -> Probability {
    Probability::new(u64::from(value), 100).expect("percent is at most 100")
}

impl Fault {
    /// Whether any rate is set.
    pub fn armed(&self) -> bool {
        *self != Self::default()
    }

    /// The fault configuration that carries this fault.
    pub fn config(&self) -> FaultConfig {
        let one = percent(100);
        let mut config = FaultConfig::default();
        if self.open {
            config = config.open(one);
        }
        if self.read {
            config = config.read(one);
        }
        if self.sync {
            config = config.sync(one);
        }
        if self.remove {
            config = config.remove(one);
        }
        if self.scan {
            config = config.scan(one);
        }
        if let Some(write) = self.write {
            config = config.write(WriteConfig {
                failure_rate: percent(if write.fails { 100 } else { 0 }),
                retention_rate: percent(write.retention_percent),
                mode: write.mode,
            });
        }
        if let Some(resize) = self.resize {
            config = config.resize(ResizeConfig {
                failure_rate: percent(resize.failure_percent),
                partial_rate: percent(resize.partial_percent),
            });
        }
        config
    }
}

/// An input operation. A `bool` named `fault` arms the operation with the one fault it may carry
/// (SF-R6).
#[derive(Clone, Debug)]
pub enum Op {
    Open {
        slot: usize,
        partition: PartitionName,
        name: BlobName,
        versions: (u16, u16),
        fault: bool,
    },
    OpenDefault {
        slot: usize,
        partition: PartitionName,
        name: BlobName,
        fault: bool,
    },
    Write {
        slot: usize,
        offset: Offset,
        /// Chunk lengths, 1 to 4 chunks with a total of at most [MAX_WRITE].
        chunks: Vec<usize>,
        sync: bool,
        dont_cache: bool,
        write_fault: Option<WriteFault>,
        /// A sync fault, only with `sync`.
        sync_fault: bool,
    },
    ReadAt {
        slot: usize,
        offset: Offset,
        len: usize,
        dont_cache: bool,
        fault: bool,
    },
    ReadAtBuf {
        slot: usize,
        offset: Offset,
        len: usize,
        /// Capacities of the destination chunks, summing to at least `len`.
        chunks: Vec<usize>,
        dont_cache: bool,
        fault: bool,
    },
    ReadMany {
        slot: usize,
        ranges: Vec<(Offset, usize)>,
        dont_cache: bool,
        fault: bool,
    },
    StartReadMany {
        slot: usize,
        ranges: Vec<(Offset, usize)>,
        dont_cache: bool,
        wait: bool,
        fault: bool,
    },
    Resize {
        slot: usize,
        len: Offset,
        fault: Option<ResizeFault>,
    },
    Sync {
        slot: usize,
        fault: bool,
    },
    StartSync {
        slot: usize,
        wait: bool,
        fault: bool,
    },
    Remove {
        partition: PartitionName,
        name: Option<BlobName>,
        fault: bool,
    },
    Scan {
        partition: PartitionName,
        fault: bool,
    },
    Drop {
        slot: usize,
    },
    Crash,
}

impl Op {
    /// The fault this operation writes into the configuration for its call.
    pub fn fault(&self) -> Fault {
        let mut fault = Fault::default();
        match self {
            Self::Open { fault: f, .. } | Self::OpenDefault { fault: f, .. } => fault.open = *f,
            Self::ReadAt { fault: f, .. }
            | Self::ReadAtBuf { fault: f, .. }
            | Self::ReadMany { fault: f, .. }
            | Self::StartReadMany { fault: f, .. } => fault.read = *f,
            Self::Write {
                write_fault,
                sync_fault,
                ..
            } => {
                fault.write = *write_fault;
                fault.sync = *sync_fault;
            }
            Self::Resize { fault: f, .. } => fault.resize = *f,
            Self::Sync { fault: f, .. } | Self::StartSync { fault: f, .. } => fault.sync = *f,
            Self::Remove { fault: f, .. } => fault.remove = *f,
            Self::Scan { fault: f, .. } => fault.scan = *f,
            Self::Drop { .. } | Self::Crash => {}
        }
        fault
    }
}

/// Whether an operation that may carry a fault carries one: true in 1 draw of 4 (SF-R8).
pub fn sample_armed(u: &mut Unstructured<'_>) -> arbitrary::Result<bool> {
    Ok(u.int_in_range(0..=3u8)? == 3)
}

/// Whether a write fault has `failure_rate` 1: true in 1 draw of 2 (SF-R8).
pub fn sample_write_fails(u: &mut Unstructured<'_>) -> arbitrary::Result<bool> {
    Ok(u.int_in_range(0..=1u8)? == 1)
}

fn slot(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    u.int_in_range(0..=SLOTS - 1)
}

fn partition(u: &mut Unstructured<'_>) -> arbitrary::Result<PartitionName> {
    Ok(if u.ratio(1u8, 16u8)? {
        if u.arbitrary()? {
            PartitionName::Empty
        } else {
            PartitionName::Slash
        }
    } else if u.arbitrary()? {
        PartitionName::P1
    } else {
        PartitionName::P0
    })
}

fn blob_name(u: &mut Unstructured<'_>) -> arbitrary::Result<BlobName> {
    Ok(match u.int_in_range(0..=2u8)? {
        0 => BlobName::A,
        1 => BlobName::B,
        _ => BlobName::C,
    })
}

fn versions(u: &mut Unstructured<'_>) -> arbitrary::Result<(u16, u16)> {
    let a = u.int_in_range(0..=2)?;
    let b = u.int_in_range(0..=2)?;
    Ok((a.min(b), a.max(b)))
}

/// Offsets and lengths up to `bound`, biased toward 0, 1, the bound and the view length.
fn bounded(u: &mut Unstructured<'_>, bound: u64) -> arbitrary::Result<Offset> {
    Ok(match u.int_in_range(0..=7u8)? {
        0 | 1 => Offset::At(0),
        2 => Offset::At(1),
        3 => Offset::At(bound),
        4 | 5 => Offset::End(u.int_in_range(-4..=4)?),
        6 => Offset::At(u.int_in_range(0..=64)?),
        _ => Offset::At(u.int_in_range(0..=bound)?),
    })
}

fn length(u: &mut Unstructured<'_>, bound: usize) -> arbitrary::Result<usize> {
    Ok(match u.int_in_range(0..=7u8)? {
        0 => 0,
        1 => 1,
        2 => bound,
        3..=5 => u.int_in_range(1..=16)?,
        _ => u.int_in_range(1..=bound)?,
    })
}

fn read_range(u: &mut Unstructured<'_>) -> arbitrary::Result<(Offset, usize)> {
    if u.ratio(1u8, 16u8)? {
        let edge = EDGE_OFFSETS[u.int_in_range(0..=EDGE_OFFSETS.len() - 1)?];
        return Ok((Offset::At(edge), u.int_in_range(1..=MAX_EDGE_LEN)?));
    }
    Ok((bounded(u, MAX_READ_OFFSET)?, length(u, MAX_READ)?))
}

fn read_ranges(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<(Offset, usize)>> {
    (0..u.int_in_range(1..=MAX_RANGES)?)
        .map(|_| read_range(u))
        .collect()
}

/// Cut `total` into 1 to [MAX_CHUNKS] chunks, some possibly empty.
fn cuts(u: &mut Unstructured<'_>, total: usize) -> arbitrary::Result<Vec<usize>> {
    let mut cuts = (1..u.int_in_range(1..=MAX_CHUNKS)?)
        .map(|_| u.int_in_range(0..=total))
        .collect::<arbitrary::Result<Vec<_>>>()?;
    cuts.push(0);
    cuts.push(total);
    cuts.sort_unstable();
    Ok(cuts.windows(2).map(|w| w[1] - w[0]).collect())
}

fn write_fault(u: &mut Unstructured<'_>) -> arbitrary::Result<WriteFault> {
    Ok(WriteFault {
        fails: sample_write_fails(u)?,
        retention_percent: RETENTION_PERCENTS[u.int_in_range(0..=RETENTION_PERCENTS.len() - 1)?],
        mode: if u.arbitrary()? {
            PartialWriteMode::Subset
        } else {
            PartialWriteMode::Prefix
        },
    })
}

fn resize_fault(u: &mut Unstructured<'_>) -> arbitrary::Result<ResizeFault> {
    Ok(ResizeFault {
        failure_percent: if u.arbitrary()? { 100 } else { 50 },
        partial_percent: PARTIAL_PERCENTS[u.int_in_range(0..=PARTIAL_PERCENTS.len() - 1)?],
    })
}

impl<'a> Arbitrary<'a> for Op {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=31u8)? {
            0..=3 => Self::Open {
                slot: slot(u)?,
                partition: partition(u)?,
                name: blob_name(u)?,
                versions: versions(u)?,
                fault: sample_armed(u)?,
            },
            4 => Self::OpenDefault {
                slot: slot(u)?,
                partition: partition(u)?,
                name: blob_name(u)?,
                fault: sample_armed(u)?,
            },
            5..=11 => {
                let slot = slot(u)?;
                let offset = bounded(u, MAX_OFFSET)?;
                let total = length(u, MAX_WRITE)?;
                let chunks = cuts(u, total)?;
                let sync = u.arbitrary()?;
                let dont_cache = u.arbitrary()?;
                let (write_fault, sync_fault) = if !sample_armed(u)? {
                    (None, false)
                } else if sync {
                    match u.int_in_range(0..=2u8)? {
                        0 => (Some(write_fault(u)?), false),
                        1 => (None, true),
                        _ => (Some(write_fault(u)?), true),
                    }
                } else {
                    (Some(write_fault(u)?), false)
                };
                Self::Write {
                    slot,
                    offset,
                    chunks,
                    sync,
                    dont_cache,
                    write_fault,
                    sync_fault,
                }
            }
            12..=14 => {
                let slot = slot(u)?;
                let (offset, len) = read_range(u)?;
                Self::ReadAt {
                    slot,
                    offset,
                    len,
                    dont_cache: u.arbitrary()?,
                    fault: sample_armed(u)?,
                }
            }
            15 | 16 => {
                let slot = slot(u)?;
                let (offset, len) = read_range(u)?;
                let extra = if u.arbitrary()? {
                    u.int_in_range(1..=MAX_EXTRA_CAPACITY)?
                } else {
                    0
                };
                Self::ReadAtBuf {
                    slot,
                    offset,
                    len,
                    chunks: cuts(u, len + extra)?,
                    dont_cache: u.arbitrary()?,
                    fault: sample_armed(u)?,
                }
            }
            17 | 18 => Self::ReadMany {
                slot: slot(u)?,
                ranges: read_ranges(u)?,
                dont_cache: u.arbitrary()?,
                fault: sample_armed(u)?,
            },
            19 => Self::StartReadMany {
                slot: slot(u)?,
                ranges: read_ranges(u)?,
                dont_cache: u.arbitrary()?,
                wait: u.arbitrary()?,
                fault: sample_armed(u)?,
            },
            20..=22 => {
                let slot = slot(u)?;
                let len = bounded(u, MAX_SIZE)?;
                Self::Resize {
                    slot,
                    len,
                    fault: if sample_armed(u)? {
                        Some(resize_fault(u)?)
                    } else {
                        None
                    },
                }
            }
            23 | 24 => Self::Sync {
                slot: slot(u)?,
                fault: sample_armed(u)?,
            },
            25 | 26 => Self::StartSync {
                slot: slot(u)?,
                wait: u.arbitrary()?,
                fault: sample_armed(u)?,
            },
            27 => Self::Remove {
                partition: partition(u)?,
                name: if u.ratio(1u8, 4u8)? {
                    None
                } else {
                    Some(blob_name(u)?)
                },
                fault: sample_armed(u)?,
            },
            28 => Self::Scan {
                partition: partition(u)?,
                fault: sample_armed(u)?,
            },
            29 => Self::Drop { slot: slot(u)? },
            _ => Self::Crash,
        })
    }
}

/// The input of one run: the input operations and the deterministic runtime's entropy.
#[derive(Clone, Debug)]
pub struct FuzzInput {
    pub ops: Vec<Op>,
    pub entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let empty = u.is_empty();
        let (stream, entropy) = decode(u)?;
        if empty {
            return Ok(Self {
                ops: Vec::new(),
                entropy,
            });
        }
        let u = &mut Unstructured::new(&stream);
        let ops = (0..u.int_in_range(1..=MAX_OPS)?)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self { ops, entropy })
    }
}

/// The four operations every run starts with (SF-R3).
fn baseline() -> [Op; BASELINE_OPS] {
    [
        Op::Open {
            slot: 0,
            partition: PartitionName::P0,
            name: BlobName::A,
            versions: (0, 0),
            fault: false,
        },
        Op::Write {
            slot: 0,
            offset: Offset::At(0),
            chunks: vec![BASELINE_LEN],
            sync: false,
            dont_cache: false,
            write_fault: None,
            sync_fault: false,
        },
        Op::ReadAt {
            slot: 0,
            offset: Offset::At(0),
            len: BASELINE_LEN,
            dont_cache: false,
            fault: false,
        },
        Op::Sync {
            slot: 0,
            fault: false,
        },
    ]
}

/// A log entry: one mutation issued to a blob generation since its last durability cut.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Any subset of the bytes is written at a crash, from none to all.
    Torn { offset: u64, bytes: Vec<u8> },
    /// Every byte marked by `mask` is written.
    Kept {
        offset: u64,
        bytes: Vec<u8>,
        mask: Vec<bool>,
    },
    /// The resize is applied or skipped.
    MaybeResize(u64),
    /// The resize is applied at a crash, and may be skipped at a reopen.
    ForcedResize(u64),
}

/// Which reach set [reachable] tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// `Reach_crash`: every `ForcedResize` is applied.
    Crash,
    /// `Reach_reopen`: every `ForcedResize` may also be skipped.
    Reopen,
}

/// One replay step with its freedom.
enum Step<'a> {
    Write {
        offset: usize,
        bytes: &'a [u8],
        mask: Option<&'a [bool]>,
        optional: bool,
    },
    Resize {
        len: usize,
        optional: bool,
    },
}

impl Step<'_> {
    fn marked(&self, i: usize) -> bool {
        match self {
            Self::Write { mask, .. } => mask.is_none_or(|mask| mask[i]),
            Self::Resize { .. } => false,
        }
    }
}

/// Relaxations of the replay, used to name the invariant a crash image breaks (SF-R13a).
#[derive(Clone, Copy, Default)]
struct Relax {
    forced_optional: bool,
    failed_kept_torn: bool,
    sync_kept_torn: bool,
}

fn step<'a>(entry: &'a Entry, failed_write: bool, relax: Relax) -> Step<'a> {
    match entry {
        Entry::Torn { offset, bytes } => Step::Write {
            offset: *offset as usize,
            bytes,
            mask: None,
            optional: true,
        },
        Entry::Kept {
            offset,
            bytes,
            mask,
        } => Step::Write {
            offset: *offset as usize,
            bytes,
            mask: Some(mask),
            optional: if failed_write {
                relax.failed_kept_torn
            } else {
                relax.sync_kept_torn
            },
        },
        Entry::MaybeResize(len) => Step::Resize {
            len: *len as usize,
            optional: true,
        },
        Entry::ForcedResize(len) => Step::Resize {
            len: *len as usize,
            optional: relax.forced_optional,
        },
    }
}

/// Whether `image` is in the reach set of `base` and `log` under `rule` (SF-R13).
///
/// Replaying the log entry by entry, in issue order, over every combination of choices gives the
/// reach set. Writing bytes past the end grows the image to the highest written position plus one,
/// with zeros in the gap. A resize cuts or zero-extends.
pub fn reachable(base: &[u8], log: &[Entry], rule: Rule, image: &[u8]) -> bool {
    let relax = Relax {
        forced_optional: rule == Rule::Reopen,
        ..Relax::default()
    };
    let steps: Vec<Step<'_>> = log.iter().map(|entry| step(entry, false, relax)).collect();
    reach(base, &steps, image)
}

/// A requirement on the value of one position: any value, one value, or none.
const ANY: u16 = 256;
const NONE: u16 = 257;

const fn accepts(need: u16, value: u8) -> bool {
    need == ANY || need == value as u16
}

/// Exact membership test.
///
/// For a fixed sequence of lengths after each step, positions are independent. A position whose
/// final value comes from before step `i` must be present at every later step, so later steps
/// act on it through their masks only, and the requirement on its value after step `i` (`need`)
/// does not depend on the lengths. A position created at step `c` (absent before, present after)
/// and never absent again takes its value at `c`. A backward pass over (step, length) states
/// keeps, for each state, the smallest suffix minimum of lengths that a valid suffix can reach:
/// positions below it must come from earlier, and fewer such positions is never worse.
fn reach(base: &[u8], steps: &[Step<'_>], image: &[u8]) -> bool {
    let m = steps.len();
    let width = steps
        .iter()
        .map(|step| match step {
            Step::Resize { len, .. } => *len,
            Step::Write { offset, bytes, .. } => offset + bytes.len(),
        })
        .chain([base.len(), image.len()])
        .max()
        .unwrap_or(0);
    let mut targets = Vec::new();

    // Lengths reachable after each step, ignoring values.
    let mut lens: Vec<Vec<usize>> = vec![vec![base.len()]];
    let mut seen = vec![usize::MAX; width + 1];
    for (i, step) in steps.iter().enumerate() {
        let mut next = Vec::new();
        for &len in &lens[i] {
            transitions(step, len, &mut targets);
            for &target in &targets {
                if seen[target] != i {
                    seen[target] = i;
                    next.push(target);
                }
            }
        }
        lens.push(next);
    }
    if !lens[m].contains(&image.len()) {
        return false;
    }

    // need[i][q]: what the value of q after step i must be, for a position that keeps its value
    // through every later step.
    let mut need = vec![vec![ANY; width]; m + 1];
    for (q, value) in image.iter().enumerate() {
        need[m][q] = u16::from(*value);
    }
    for i in (0..m).rev() {
        let mut current = need[i + 1].clone();
        if let Step::Write {
            offset,
            bytes,
            optional,
            ..
        } = &steps[i]
        {
            for (j, byte) in bytes.iter().enumerate() {
                if !steps[i].marked(j) {
                    continue;
                }
                let q = offset + j;
                let n = current[q];
                current[q] = if n == ANY || n == NONE {
                    n
                } else if n == u16::from(*byte) {
                    ANY
                } else if *optional {
                    n
                } else {
                    NONE
                };
            }
        }
        need[i] = current;
    }

    // best[len] after step i: the smallest suffix minimum of lengths over valid suffixes from
    // that state, or `usize::MAX` when none is valid.
    let mut best = vec![usize::MAX; width + 1];
    best[image.len()] = image.len();
    let mut previous = vec![usize::MAX; width + 1];
    for i in (0..m).rev() {
        // `previous` takes the values after step `i + 1`; `best` is all `usize::MAX` again.
        std::mem::swap(&mut best, &mut previous);
        let checks = Checks::new(&steps[i], &need[i + 1], width);
        let mut found_any = Vec::with_capacity(lens[i].len());
        for &len in &lens[i] {
            let mut found = usize::MAX;
            transitions(&steps[i], len, &mut targets);
            for &target in &targets {
                let low = previous[target];
                if low != usize::MAX && checks.feasible(&steps[i], len, target, low) {
                    found = found.min(low.min(len));
                }
            }
            found_any.push((len, found));
        }
        for &len in &lens[i + 1] {
            previous[len] = usize::MAX;
        }
        for (len, found) in found_any {
            best[len] = found;
        }
    }
    let low = best[base.len()];
    if low == usize::MAX {
        return false;
    }
    base[..low]
        .iter()
        .enumerate()
        .all(|(q, value)| accepts(need[0][q], *value))
}

/// Lengths a step can leave, from `len`, ignoring values.
fn transitions(step: &Step<'_>, len: usize, out: &mut Vec<usize>) {
    out.clear();
    match step {
        Step::Resize {
            len: target,
            optional,
        } => {
            if *optional && *target != len {
                out.push(len);
            }
            out.push(*target);
        }
        Step::Write {
            offset,
            bytes,
            optional,
            ..
        } => {
            if !optional {
                let end = (0..bytes.len())
                    .rev()
                    .find(|j| step.marked(*j))
                    .map_or(0, |j| offset + j + 1);
                out.push(len.max(end));
                return;
            }
            out.push(len);
            let marked = (0..bytes.len()).filter(|j| step.marked(*j));
            out.extend(marked.map(|j| offset + j + 1).filter(|end| *end > len));
        }
    }
}

/// Per-step tables that make the check of one transition constant time.
struct Checks {
    /// `ok[q]` prefix counts: position `q`, created by this step, can take a value its
    /// requirement accepts.
    ok_prefix: Vec<u32>,
    /// `written[q]`: position `q` is marked and its written byte is accepted.
    written: Vec<bool>,
}

impl Checks {
    fn new(step: &Step<'_>, after: &[u16], width: usize) -> Self {
        let mut ok = vec![false; width];
        let mut written = vec![false; width];
        for q in 0..width {
            ok[q] = accepts(after[q], 0);
        }
        if let Step::Write {
            offset,
            bytes,
            optional,
            ..
        } = step
        {
            for (j, byte) in bytes.iter().enumerate() {
                let q = offset + j;
                if q >= width || !step.marked(j) {
                    continue;
                }
                written[q] = accepts(after[q], *byte);
                ok[q] = written[q] || (*optional && accepts(after[q], 0));
            }
        }
        let mut ok_prefix = vec![0u32; width + 1];
        for q in 0..width {
            ok_prefix[q + 1] = ok_prefix[q] + u32::from(ok[q]);
        }
        Self { ok_prefix, written }
    }

    fn all_ok(&self, from: usize, to: usize) -> bool {
        from >= to || self.ok_prefix[to] - self.ok_prefix[from] == (to - from) as u32
    }

    /// Whether the step can go from `len` to `target` when positions below `low` keep the value
    /// they get here.
    fn feasible(&self, step: &Step<'_>, len: usize, target: usize, low: usize) -> bool {
        if target <= len {
            return true;
        }
        match step {
            Step::Resize { .. } => self.all_ok(len, low.min(target)),
            Step::Write { optional, .. } => {
                if !optional {
                    return self.all_ok(len, low.min(target));
                }
                // The last position of the new length is written; every other new position is
                // written or zero.
                let last = target - 1;
                self.all_ok(len, low.min(last)) && (last >= low || self.written[last])
            }
        }
    }
}

/// Where a recorded storage call came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Baseline,
    Input,
    Verification,
}

/// A storage call with its resolved parameters. `slot` is `None` for a handle that the oracle
/// opened itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Open {
        partition: String,
        name: Vec<u8>,
        versions: (u16, u16),
        /// Issued through `Storage::open`, which returns no version.
        default: bool,
    },
    ReadAt {
        slot: Option<usize>,
        offset: u64,
        len: usize,
        dont_cache: bool,
    },
    ReadAtBuf {
        slot: usize,
        offset: u64,
        len: usize,
        chunks: Vec<usize>,
        dont_cache: bool,
    },
    ReadMany {
        slot: usize,
        ranges: Vec<(u64, usize)>,
        dont_cache: bool,
    },
    StartReadMany {
        slot: usize,
        ranges: Vec<(u64, usize)>,
        dont_cache: bool,
        wait: bool,
    },
    Write {
        slot: usize,
        offset: u64,
        /// The submitted bytes.
        bytes: Vec<u8>,
        chunks: Vec<usize>,
        sync: bool,
        dont_cache: bool,
    },
    Resize {
        slot: usize,
        len: u64,
    },
    Sync {
        slot: usize,
    },
    StartSync {
        slot: usize,
        wait: bool,
    },
    Remove {
        partition: String,
        name: Option<Vec<u8>>,
    },
    Scan {
        partition: String,
    },
}

/// The result of a storage call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallResult {
    /// The size, and the version when the call returns one.
    Opened {
        size: u64,
        version: Option<u16>,
    },
    Unit,
    /// The bytes of every range, in range order.
    Bytes(Vec<Vec<u8>>),
    /// The names of a scan, sorted.
    Names(Vec<Vec<u8>>),
    /// A started operation whose handle was dropped.
    Dropped,
    /// The `Debug` text of the error.
    Err(String),
}

/// One storage call of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub session: usize,
    pub origin: Origin,
    /// The index in the run of the operation the call belongs to: baseline operations are 0 to
    /// 3, input operation `i` is `4 + i`, and a recovery verification takes the index of the
    /// crash before it (the mandatory crash is `4 + ops.len()`).
    pub index: usize,
    pub call: Call,
    /// The fault written to the configuration for the call.
    pub fault: Fault,
    pub result: CallResult,
    /// The log entry the model recorded for this call, if any.
    pub logged: Option<Entry>,
}

/// Every storage call of a run, in call order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trace {
    pub records: Vec<Record>,
}

/// Generate the invariants with their ids and classes.
macro_rules! invariants {
    ($($variant:ident => $id:literal, $class:ident;)*) => {
        /// One row of the invariants table.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Invariant {
            $($variant,)*
        }

        impl Invariant {
            /// Every row, in table order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)*];

            /// The row's id, such as `SF-I1a`.
            pub const fn id(self) -> &'static str {
                match self {
                    $(Self::$variant => $id,)*
                }
            }

            /// The failure class of the row. SF-I17 has none: its panic passes through.
            pub const fn class(self) -> Option<Class> {
                match self {
                    $(Self::$variant => invariants!(@class $class),)*
                }
            }
        }
    };
    (@class none) => { None };
    (@class $class:ident) => { Some(Class::$class) };
}

invariants! {
    I1a => "SF-I1a", ReadBytes;
    I1b => "SF-I1b", ReadLen;
    I2a => "SF-I2a", BufferLayout;
    I2b => "SF-I2b", ReadMany;
    I2c => "SF-I2c", ReadMany;
    I3a => "SF-I3a", OpenError;
    I3b => "SF-I3b", OpenError;
    I3c => "SF-I3c", OpenError;
    I3d => "SF-I3d", PartitionName;
    I3e => "SF-I3e", PartitionName;
    I3f => "SF-I3f", Create;
    I3g => "SF-I3g", OpenVersion;
    I3h => "SF-I3h", Create;
    I4a => "SF-I4a", FailedWrite;
    I4b => "SF-I4b", FailedWrite;
    I4c => "SF-I4c", FailedWrite;
    I4d => "SF-I4d", FailedWrite;
    I5a => "SF-I5a", FailedResize;
    I5b => "SF-I5b", FailedResize;
    I5c => "SF-I5c", FailedResize;
    I6a => "SF-I6a", FailedOpEffect;
    I6b => "SF-I6b", FailedOpEffect;
    I6c => "SF-I6c", FailedOpEffect;
    I6d => "SF-I6d", FailedOpEffect;
    I6e => "SF-I6e", FailedOpEffect;
    I7 => "SF-I7", CrashImage;
    I8 => "SF-I8", CrashImage;
    I9 => "SF-I9", CrashImage;
    I10 => "SF-I10", CrashImage;
    I11 => "SF-I11", CrashImage;
    I12 => "SF-I12", ReopenImage;
    I13 => "SF-I13", CrashImage;
    I14a => "SF-I14a", Scan;
    I14b => "SF-I14b", CrashNamespace;
    I15 => "SF-I15", RemovedRead;
    I16a => "SF-I16a", UnexpectedError;
    I16b => "SF-I16b", UnexpectedError;
    I16c => "SF-I16c", UnexpectedError;
    I16d => "SF-I16d", UnexpectedError;
    I16e => "SF-I16e", UnexpectedError;
    I16f => "SF-I16f", UnexpectedError;
    I16g => "SF-I16g", UnexpectedError;
    I17 => "SF-I17", none;
    I18a => "SF-I18a", OpenSize;
    I18b => "SF-I18b", OpenSize;
}

/// Generate the failure classes, each with a stable tag and its own cold panic function, so
/// that the top frame of a crash and the start of its message name the class.
macro_rules! classes {
    ($($variant:ident => $name:ident,)*) => {
        /// A failure class.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum Class {
            $($variant,)*
        }

        impl Class {
            /// The class tag, such as `crash_image`.
            pub const fn tag(self) -> &'static str {
                match self {
                    $(Self::$variant => stringify!($name),)*
                }
            }

            /// Panic from the class's own function with `report`.
            pub fn fail(self, report: &str) -> ! {
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
    ReadBytes => read_bytes,
    ReadLen => read_len,
    ReadMany => read_many,
    BufferLayout => buffer_layout,
    OpenError => open_error,
    PartitionName => partition_name,
    Create => create,
    OpenVersion => open_version,
    OpenSize => open_size,
    Scan => scan,
    RemovedRead => removed_read,
    FailedWrite => failed_write,
    FailedResize => failed_resize,
    FailedOpEffect => failed_op_effect,
    ReopenImage => reopen_image,
    CrashImage => crash_image,
    CrashNamespace => crash_namespace,
    UnexpectedError => unexpected_error,
}

/// The first violation of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub invariant: Invariant,
    pub class: Class,
    pub session: usize,
    /// The index of the operation, as in [Record::index].
    pub index: usize,
    /// The operation with its fault, the observation and the model state of the blob.
    pub message: String,
}

/// The result of [run].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub trace: Trace,
    pub violation: Option<Violation>,
    /// The invariants measured by the run (SF-R32).
    pub measured: BTreeSet<Invariant>,
}

/// How often each verification operation is issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verify {
    Once,
    /// Every verification operation twice in a row (SF-R25).
    Twice,
}

/// Run `input` with the identity seam and panic on a violation.
pub fn fuzz(input: FuzzInput) {
    let outcome = run(&input, |context| context, Verify::Once);
    if let Some(violation) = &outcome.violation {
        violation.class.fail(&report(&input, &outcome, violation));
    }
}

fn report(input: &FuzzInput, outcome: &Outcome, violation: &Violation) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "storage_faults: {} violated in session {} at op {}: {}",
        violation.invariant.id(),
        violation.session,
        violation.index,
        violation.message
    );
    let _ = writeln!(out, "input ops: {}", input.ops.len());
    let records = &outcome.trace.records;
    let skip = records.len().saturating_sub(REPORT_RECORDS);
    let _ = writeln!(
        out,
        "last {} of {} storage calls:",
        records.len() - skip,
        records.len()
    );
    for record in &records[skip..] {
        let _ = writeln!(
            out,
            "  s{} #{} {:?} {:?} fault={:?} -> {}",
            record.session,
            record.index,
            record.origin,
            record.call,
            record.fault,
            describe(&record.result)
        );
    }
    out
}

fn describe(result: &CallResult) -> String {
    match result {
        CallResult::Bytes(bufs) => format!(
            "Bytes([{}])",
            bufs.iter()
                .map(|b| format!("len={} {:02x?}", b.len(), &b[..b.len().min(8)]))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        CallResult::Names(names) => format!(
            "Names({:?})",
            names.iter().map(|n| display_name(n)).collect::<Vec<_>>()
        ),
        other => format!("{other:?}"),
    }
}

/// A durability cut of a generation's history (SF-R13a).
#[derive(Clone, Copy, PartialEq, Eq)]
enum CutKind {
    Sync,
    Reopen,
}

#[derive(Clone)]
struct Logged {
    entry: Entry,
    /// A `Kept` entry made by a failed write rather than a `SYNC` write.
    failed_write: bool,
}

struct Cut {
    kind: CutKind,
    base: Vec<u8>,
    log: Vec<Logged>,
}

/// The durability state of one live generation.
#[derive(Default)]
struct Durable {
    base: Vec<u8>,
    log: Vec<Logged>,
    /// Every cut since the generation was created or last recovered.
    history: Vec<Cut>,
}

impl Durable {
    fn cut(&mut self, kind: CutKind, image: Vec<u8>) {
        let base = std::mem::replace(&mut self.base, image);
        let log = std::mem::take(&mut self.log);
        self.history.push(Cut { kind, base, log });
    }

    fn entries(&self) -> impl Iterator<Item = &Logged> {
        self.history
            .iter()
            .flat_map(|cut| cut.log.iter())
            .chain(self.log.iter())
    }

    /// Whether `image` is reachable after replaying the cuts from `from` on and the current log,
    /// starting from the base before cut `from`.
    fn reaches(&self, from: usize, relax: Relax, image: &[u8]) -> bool {
        let base = self.history.get(from).map_or(&self.base, |cut| &cut.base);
        let steps: Vec<Step<'_>> = self.history[from.min(self.history.len())..]
            .iter()
            .flat_map(|cut| cut.log.iter())
            .chain(self.log.iter())
            .map(|logged| step(&logged.entry, logged.failed_write, relax))
            .collect();
        reach(base, &steps, image)
    }

    /// The crash invariant an image outside `Reach_crash` breaks (SF-R13a).
    fn crash_violation(&self, image: &[u8]) -> Invariant {
        let now = self.history.len();
        let mut relax = Relax {
            forced_optional: true,
            ..Relax::default()
        };
        if self.reaches(now, relax, image) {
            return Invariant::I10;
        }
        relax.failed_kept_torn = true;
        if self.reaches(now, relax, image) {
            return Invariant::I9;
        }
        relax.sync_kept_torn = true;
        if self.reaches(now, relax, image) {
            return Invariant::I8;
        }
        let after_reopen = self
            .history
            .iter()
            .rposition(|cut| cut.kind == CutKind::Reopen)
            .map_or(0, |i| i + 1);
        if after_reopen < now && self.reaches(after_reopen, relax, image) {
            return Invariant::I7;
        }
        if self.reaches(0, relax, image) {
            return Invariant::I11;
        }
        Invariant::I13
    }

    /// The crash rows whose conditions this history meets (SF-R32).
    fn crash_rows(&self) -> Vec<Invariant> {
        let mut rows = Vec::new();
        if self
            .history
            .iter()
            .any(|cut| cut.kind == CutKind::Sync && !cut.log.is_empty())
        {
            rows.push(Invariant::I7);
        }
        if self
            .entries()
            .any(|l| matches!(l.entry, Entry::Kept { .. }) && !l.failed_write)
        {
            rows.push(Invariant::I8);
        }
        if self.entries().any(|l| {
            l.failed_write && matches!(&l.entry, Entry::Kept { mask, .. } if mask.contains(&true))
        }) {
            rows.push(Invariant::I9);
        }
        if self
            .entries()
            .any(|l| matches!(l.entry, Entry::ForcedResize(_)))
        {
            rows.push(Invariant::I10);
        }
        if self.history.iter().any(|cut| cut.kind == CutKind::Reopen) {
            rows.push(Invariant::I11);
        }
        if self
            .log
            .iter()
            .any(|l| matches!(l.entry, Entry::Torn { .. } | Entry::MaybeResize(_)))
        {
            rows.push(Invariant::I13);
        }
        rows
    }
}

/// State that lives across the sessions of one run.
struct Harness {
    verify: Verify,
    model: Model,
    durable: BTreeMap<u64, Durable>,
    trace: Trace,
    measured: BTreeSet<Invariant>,
    violation: Option<Violation>,
    session: usize,
    index: usize,
    /// The operation being judged, with its fault, for reports.
    op: String,
    /// The trace record of the operation's own storage call, which its log entry annotates.
    op_record: Option<usize>,
}

type Judged = Result<(), Violation>;

/// What an open is expected to find.
#[derive(Clone, Copy)]
enum Opening {
    New { lo: u16, hi: u16 },
    Existing { version: u16 },
}

impl Harness {
    fn new(verify: Verify) -> Self {
        Self {
            verify,
            model: Model::new(Kind::Deterministic),
            durable: BTreeMap::new(),
            trace: Trace::default(),
            measured: BTreeSet::new(),
            violation: None,
            session: 0,
            index: 0,
            op: String::new(),
            op_record: None,
        }
    }

    fn fail(
        &self,
        invariant: Invariant,
        observation: String,
        generation: Option<u64>,
    ) -> Violation {
        let state = generation
            .and_then(|g| self.model.blobs.get(&g))
            .map_or_else(String::new, |blob| format!("; model: {}", blob.summary()));
        let durable = generation
            .and_then(|g| self.durable.get(&g))
            .map_or_else(String::new, |d| {
                format!(
                    "; base len {} log {:?}",
                    d.base.len(),
                    d.log
                        .iter()
                        .map(|l| summarize(&l.entry))
                        .collect::<Vec<_>>()
                )
            });
        Violation {
            invariant,
            class: invariant.class().expect("SF-I17 is never returned"),
            session: self.session,
            index: self.index,
            message: format!("{}: {observation}{state}{durable}", self.op),
        }
    }

    fn measure(&mut self, invariant: Invariant) {
        self.measured.insert(invariant);
    }

    fn reps(&self) -> usize {
        match self.verify {
            Verify::Once => 1,
            Verify::Twice => 2,
        }
    }

    fn view(&self, generation: u64) -> &[u8] {
        &self.model.blobs[&generation].data
    }

    fn set_view(&mut self, generation: u64, image: Vec<u8>) {
        let blob = self.model.blobs.get_mut(&generation).unwrap();
        blob.flags = vec![KNOWN; image.len()];
        blob.data = image;
    }

    fn log(&mut self, generation: u64, entry: Entry, failed_write: bool) {
        if let Some(durable) = self.durable.get_mut(&generation) {
            durable.log.push(Logged {
                entry: entry.clone(),
                failed_write,
            });
        }
        if let Some(record) = self.op_record.and_then(|i| self.trace.records.get_mut(i)) {
            record.logged = Some(entry);
        }
    }

    fn sync_cut(&mut self, generation: u64) {
        let view = self.view(generation).to_vec();
        if let Some(durable) = self.durable.get_mut(&generation) {
            durable.cut(CutKind::Sync, view);
        }
        self.model.blobs.get_mut(&generation).unwrap().sync();
    }
}

fn summarize(entry: &Entry) -> String {
    match entry {
        Entry::Torn { offset, bytes } => format!("Torn({offset}, {})", bytes.len()),
        Entry::Kept {
            offset,
            bytes,
            mask,
        } => format!(
            "Kept({offset}, {}, {} marked)",
            bytes.len(),
            mask.iter().filter(|m| **m).count()
        ),
        Entry::MaybeResize(len) => format!("MaybeResize({len})"),
        Entry::ForcedResize(len) => format!("ForcedResize({len})"),
    }
}

fn is_io(error: &Error) -> bool {
    matches!(error, Error::Io(_))
}

fn err(error: &Error) -> CallResult {
    CallResult::Err(format!("{error:?}"))
}

fn read_options(dont_cache: bool) -> ReadOptions {
    if dont_cache {
        ReadOptions::DONT_CACHE
    } else {
        ReadOptions::default()
    }
}

/// What a read of `len` bytes at `offset` must do on a view of `size` bytes: `Some(true)` succeed,
/// `Some(false)` fail, `None` either (a zero-length read past the end).
fn read_expect(size: u64, offset: u64, len: usize) -> Option<bool> {
    match offset.checked_add(len as u64) {
        Some(end) if end <= size => Some(true),
        _ if len == 0 => None,
        _ => Some(false),
    }
}

/// Check that `read_at_buf` returned the caller's buffers (SF-I2a), as `storage_differential`
/// does: the total capacity of the nonzero chunks, the single-chunk shape, the readable length of
/// each chunk, and each readable chunk's start address.
fn buf_layout(buf: &IoBufsMut, chunks: &[usize], starts: &[usize], len: usize) -> Option<String> {
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
        .filter(|(_, (slice, start))| slice.as_ptr() as usize != **start)
        .map(|(i, _)| i)
        .collect();
    (buf.capacity() != capacity
        || buf.is_single() != single
        || readable != expected
        || !moved.is_empty())
    .then(|| {
        format!(
            "read_at_buf changed the buffers of capacities {capacities:?}: capacity {} (expected {capacity}), single {} (expected {single}), readable {readable:?} (expected {expected:?}), chunks {moved:?} moved",
            buf.capacity(),
            buf.is_single(),
        )
    })
}

/// One session: the storage the seam returned, the fault configuration and the open handles.
struct Session<'a, S: Storage> {
    h: &'a mut Harness,
    storage: &'a S,
    faults: &'a Arc<RwLock<FaultConfig>>,
    slots: [Option<Arc<S::Blob>>; SLOTS],
}

impl<S: Storage> Session<'_, S> {
    fn arm(&self, fault: Fault) {
        if fault.armed() {
            *self.faults.write() = fault.config();
        }
    }

    fn disarm(&self, fault: Fault) {
        if fault.armed() {
            *self.faults.write() = FaultConfig::default();
        }
    }

    fn record(&mut self, origin: Origin, call: Call, fault: Fault, result: CallResult) {
        if origin != Origin::Verification {
            self.h.op_record = Some(self.h.trace.records.len());
        }
        self.h.trace.records.push(Record {
            session: self.h.session,
            origin,
            index: self.h.index,
            call,
            fault,
            result,
            logged: None,
        });
    }

    fn slot(&self, slot: usize) -> Option<(Arc<S::Blob>, u64)> {
        let blob = self.slots[slot].clone()?;
        let generation = self.h.model.slots[slot].expect("open slot is modeled");
        Some((blob, generation))
    }

    fn close_slot(&mut self, slot: usize) {
        drop(self.slots[slot].take());
        self.h.model.close_slot(slot);
    }

    /// A verification read of `len` bytes at `offset`, within [MAX_SIZE].
    async fn vread(
        &mut self,
        blob: &Arc<S::Blob>,
        slot: Option<usize>,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, Error> {
        assert!(
            offset <= MAX_SIZE && len as u64 <= MAX_SIZE,
            "verification read past MAX_SIZE"
        );
        let mut last = None;
        for _ in 0..self.h.reps() {
            let result = blob
                .read_at(offset, len, ReadOptions::default())
                .await
                .map(|buf| buf.coalesce().as_ref().to_vec());
            self.record(
                Origin::Verification,
                Call::ReadAt {
                    slot,
                    offset,
                    len,
                    dont_cache: false,
                },
                Fault::default(),
                result
                    .as_ref()
                    .map_or_else(err, |bytes| CallResult::Bytes(vec![bytes.clone()])),
            );
            last = Some(result);
        }
        last.unwrap()
    }

    /// A 1-byte probe at `offset`: whether it succeeded with one byte.
    /// A successful read of another length is a violation of `invariant`, never a failed probe.
    async fn probe(
        &mut self,
        blob: &Arc<S::Blob>,
        slot: Option<usize>,
        offset: u64,
        invariant: Invariant,
        generation: Option<u64>,
    ) -> Result<bool, Violation> {
        match self.vread(blob, slot, offset, 1).await {
            Ok(bytes) if bytes.len() == 1 => Ok(true),
            Ok(bytes) => Err(self.h.fail(
                invariant,
                format!("a 1-byte read at {offset} returned {} bytes", bytes.len()),
                generation,
            )),
            Err(_) => Ok(false),
        }
    }

    /// Read the whole blob of `len` bytes, or an empty image for `len` 0.
    async fn whole(
        &mut self,
        blob: &Arc<S::Blob>,
        slot: Option<usize>,
        len: u64,
    ) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        match self.vread(blob, slot, 0, len as usize).await {
            Ok(bytes) if bytes.len() as u64 == len => Some(bytes),
            _ => None,
        }
    }

    /// A verification scan.
    async fn vscan(&mut self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        let mut last = None;
        for _ in 0..self.h.reps() {
            let result = self.storage.scan(partition).await.map(|mut names| {
                names.sort();
                names
            });
            self.record(
                Origin::Verification,
                Call::Scan {
                    partition: partition.to_string(),
                },
                Fault::default(),
                result
                    .as_ref()
                    .map_or_else(err, |names| CallResult::Names(names.clone())),
            );
            last = Some(result);
        }
        last.unwrap()
    }

    /// Scan `partition` and compare with the model (SF-R10 item 1): a held partition returns
    /// exactly its live names, each once; another may fail or return no name.
    async fn scan_check(&mut self, partition: &str, invariant: Invariant) -> Judged {
        let result = self.vscan(partition).await;
        let expected = self.h.model.names(partition);
        let ok = match (&result, &expected) {
            (Ok(got), Some(names)) => got.iter().eq(names.iter()),
            (Ok(got), None) => got.is_empty(),
            (Err(_), Some(_)) => false,
            (Err(_), None) => true,
        };
        if !ok {
            return Err(self.h.fail(
                invariant,
                format!(
                    "scan of {} returned {:?}, model: {}",
                    display_partition(partition),
                    result.map(|names| names.iter().map(|n| display_name(n)).collect::<Vec<_>>()),
                    self.h.model.partition_summary(partition)
                ),
                None,
            ));
        }
        Ok(())
    }

    /// The unchecked view must be unchanged (SF-R11 item 3).
    async fn unchanged(
        &mut self,
        slot: usize,
        blob: &Arc<S::Blob>,
        generation: u64,
        invariant: Invariant,
    ) -> Judged {
        let view = self.h.view(generation).to_vec();
        let len = view.len() as u64;
        if self
            .probe(blob, Some(slot), len, invariant, Some(generation))
            .await?
        {
            return Err(self.h.fail(
                invariant,
                format!("a 1-byte read at the view length {len} succeeded"),
                Some(generation),
            ));
        }
        if len > 0
            && !self
                .probe(blob, Some(slot), len - 1, invariant, Some(generation))
                .await?
        {
            return Err(self.h.fail(
                invariant,
                format!("a 1-byte read at {} failed", len - 1),
                Some(generation),
            ));
        }
        match self.whole(blob, Some(slot), len).await {
            Some(image) if image == view => Ok(()),
            Some(image) => {
                let at = image
                    .iter()
                    .zip(&view)
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                Err(self.h.fail(
                    invariant,
                    format!(
                        "byte {at} changed from {:#04x} to {:#04x}",
                        view[at], image[at]
                    ),
                    Some(generation),
                ))
            }
            None => Err(self.h.fail(
                invariant,
                "the read of the whole view failed".into(),
                Some(generation),
            )),
        }
    }

    /// Find the length after an injected failed write or resize, at most `bound`, and read the
    /// blob (SF-R11 item 2). A probe or read that contradicts the search names `contradiction`.
    async fn search(
        &mut self,
        slot: usize,
        blob: &Arc<S::Blob>,
        generation: u64,
        bound: u64,
        contradiction: Invariant,
    ) -> Result<Vec<u8>, Violation> {
        if self
            .probe(blob, Some(slot), bound, contradiction, Some(generation))
            .await?
        {
            return Err(self.h.fail(
                contradiction,
                format!("a 1-byte read at the bound {bound} succeeded"),
                Some(generation),
            ));
        }
        let (mut lo, mut hi) = (0, bound);
        let mut reads = 0;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            reads += 1;
            if self
                .probe(blob, Some(slot), mid, contradiction, Some(generation))
                .await?
            {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        debug_assert!(reads <= MAX_SEARCH_READS);
        match self.whole(blob, Some(slot), lo).await {
            Some(image) => Ok(image),
            None => Err(self.h.fail(
                contradiction,
                format!("the read of the {lo} bytes the search found failed"),
                Some(generation),
            )),
        }
    }

    /// The checks after a successful open (SF-R11 item 1). Returns the image.
    async fn after_open(
        &mut self,
        blob: &Arc<S::Blob>,
        size: u64,
        version: Option<u16>,
        opening: Opening,
    ) -> Result<Vec<u8>, Violation> {
        match (opening, version) {
            (Opening::New { lo, hi }, Some(version)) if !(lo..=hi).contains(&version) => {
                return Err(self.h.fail(
                    Invariant::I3f,
                    format!("a new blob opened with version {version}, requested {lo}..={hi}"),
                    None,
                ));
            }
            (Opening::Existing { version: recorded }, Some(version)) if version != recorded => {
                return Err(self.h.fail(
                    Invariant::I3g,
                    format!("an existing blob opened with version {version}, recorded {recorded}"),
                    None,
                ));
            }
            _ => {}
        }
        if size > MAX_SIZE {
            return Err(self.h.fail(
                Invariant::I18a,
                format!("the open returned size {size}, above {MAX_SIZE}"),
                None,
            ));
        }
        if self.probe(blob, None, size, Invariant::I18b, None).await? {
            return Err(self.h.fail(
                Invariant::I18b,
                format!("a 1-byte read at the returned size {size} succeeded"),
                None,
            ));
        }
        if size > 0
            && !self
                .probe(blob, None, size - 1, Invariant::I18b, None)
                .await?
        {
            return Err(self.h.fail(
                Invariant::I18b,
                format!("a 1-byte read at {} failed", size - 1),
                None,
            ));
        }
        let image = match opening {
            Opening::New { .. } => {
                if size != 0 {
                    return Err(self.h.fail(
                        Invariant::I3h,
                        format!("a new blob opened with size {size}"),
                        None,
                    ));
                }
                self.h.measure(Invariant::I3f);
                self.h.measure(Invariant::I3h);
                Vec::new()
            }
            Opening::Existing { .. } => {
                let Some(image) = self.whole(blob, None, size).await else {
                    return Err(self.h.fail(
                        Invariant::I18b,
                        format!("the read of the {size} bytes the open returned failed"),
                        None,
                    ));
                };
                self.h.measure(Invariant::I3g);
                image
            }
        };
        self.h.measure(Invariant::I18a);
        self.h.measure(Invariant::I18b);
        Ok(image)
    }

    /// Run one session: the recovery verification after a crash, then the operations.
    async fn run(&mut self, recovery: Option<usize>, ops: &[(usize, Origin, Op)]) -> Judged {
        if let Some(index) = recovery {
            self.h.index = index;
            self.h.op = format!("recovery verification after the crash at op {index}");
            self.recover().await?;
        }
        for (index, origin, op) in ops {
            self.h.index = *index;
            self.h.op = format!("{op:?}");
            self.h.op_record = None;
            self.step(*origin, op).await?;
        }
        Ok(())
    }

    /// SF-R10.
    async fn recover(&mut self) -> Judged {
        for partition in ["p0", "p1"] {
            self.scan_check(partition, Invariant::I14b).await?;
        }
        let live: Vec<(String, Vec<u8>, u64)> = self
            .h
            .model
            .partitions
            .iter()
            .flat_map(|(p, names)| names.iter().map(|(n, g)| (p.clone(), n.clone(), *g)))
            .collect();
        for (partition, name, generation) in live {
            let (lo, hi) = RECOVERY_VERSIONS;
            let mut opened = None;
            for _ in 0..self.h.reps() {
                drop(opened.take());
                let result = self
                    .storage
                    .open_versioned(
                        &partition,
                        &name,
                        BlobVersion::new(lo)..=BlobVersion::new(hi),
                    )
                    .await;
                self.record(
                    Origin::Verification,
                    Call::Open {
                        partition: partition.clone(),
                        name: name.clone(),
                        versions: (lo, hi),
                        default: false,
                    },
                    Fault::default(),
                    match &result {
                        Ok((_, size, version)) => CallResult::Opened {
                            size: *size,
                            version: Some(version.get()),
                        },
                        Err(e) => err(e),
                    },
                );
                match result {
                    Ok(opened_blob) => opened = Some(opened_blob),
                    Err(e) => {
                        return Err(self.h.fail(
                            Invariant::I14b,
                            format!(
                                "live blob {}/{} did not open: {e:?}",
                                display_partition(&partition),
                                display_name(&name)
                            ),
                            Some(generation),
                        ));
                    }
                }
            }
            let (blob, size, version) = opened.unwrap();
            let blob = Arc::new(blob);
            let recorded = self.h.model.blobs[&generation].version;
            let image = self
                .after_open(
                    &blob,
                    size,
                    Some(version.get()),
                    Opening::Existing { version: recorded },
                )
                .await
                .map_err(|mut v| {
                    v.message += &format!(
                        "; blob {}/{}",
                        display_partition(&partition),
                        display_name(&name)
                    );
                    v
                })?;
            drop(blob);
            let durable = &self.h.durable[&generation];
            if !reachable_crash(durable, &image) {
                let invariant = durable.crash_violation(&image);
                return Err(self.h.fail(
                    invariant,
                    format!(
                        "the image of {}/{} after the crash ({} bytes, {:02x?}) is not reachable",
                        display_partition(&partition),
                        display_name(&name),
                        image.len(),
                        &image[..image.len().min(16)]
                    ),
                    Some(generation),
                ));
            }
            for row in durable.crash_rows() {
                self.h.measure(row);
            }
            let durable = self.h.durable.get_mut(&generation).unwrap();
            durable.base = image.clone();
            durable.log.clear();
            durable.history.clear();
            self.h.set_view(generation, image);
            self.h.model.blobs.get_mut(&generation).unwrap().sync();
        }
        self.h.measure(Invariant::I14b);
        Ok(())
    }

    async fn step(&mut self, origin: Origin, op: &Op) -> Judged {
        match op {
            Op::Open {
                slot,
                partition,
                name,
                versions,
                fault,
            } => {
                self.open(origin, *slot, *partition, *name, Some(*versions), *fault)
                    .await
            }
            Op::OpenDefault {
                slot,
                partition,
                name,
                fault,
            } => {
                self.open(origin, *slot, *partition, *name, None, *fault)
                    .await
            }
            Op::Write { .. } => self.write(origin, op).await,
            Op::ReadAt {
                slot,
                offset,
                len,
                dont_cache,
                ..
            } => {
                let Some((blob, generation)) = self.slot(*slot) else {
                    return Ok(());
                };
                let size = self.h.view(generation).len() as u64;
                let range = (offset.resolve(size, MAX_READ_OFFSET), *len);
                let fault = op.fault();
                self.arm(fault);
                let result = blob
                    .read_at(range.0, range.1, read_options(*dont_cache))
                    .await
                    .map(|buf| vec![buf.coalesce().as_ref().to_vec()]);
                self.disarm(fault);
                self.record(
                    origin,
                    Call::ReadAt {
                        slot: Some(*slot),
                        offset: range.0,
                        len: range.1,
                        dont_cache: *dont_cache,
                    },
                    fault,
                    result
                        .as_ref()
                        .map_or_else(err, |b| CallResult::Bytes(b.clone())),
                );
                self.judge_read(*slot, &blob, generation, &[range], result, fault)
                    .await
            }
            Op::ReadAtBuf {
                slot,
                offset,
                len,
                chunks,
                dont_cache,
                ..
            } => {
                let Some((blob, generation)) = self.slot(*slot) else {
                    return Ok(());
                };
                let size = self.h.view(generation).len() as u64;
                let range = (offset.resolve(size, MAX_READ_OFFSET), *len);
                let bufs: Vec<IoBufMut> =
                    chunks.iter().map(|c| IoBufMut::with_capacity(*c)).collect();
                let starts: Vec<usize> = bufs
                    .iter()
                    .filter(|buf| buf.capacity() > 0)
                    .map(|buf| buf.as_ref().as_ptr() as usize)
                    .collect();
                let fault = op.fault();
                self.arm(fault);
                let result = blob
                    .read_at_buf(
                        range.0,
                        range.1,
                        IoBufsMut::from(bufs),
                        read_options(*dont_cache),
                    )
                    .await;
                self.disarm(fault);
                let layout = result
                    .as_ref()
                    .ok()
                    .and_then(|buf| buf_layout(buf, chunks, &starts, range.1));
                let result = result.map(|buf| vec![buf.coalesce().as_ref().to_vec()]);
                self.record(
                    origin,
                    Call::ReadAtBuf {
                        slot: *slot,
                        offset: range.0,
                        len: range.1,
                        chunks: chunks.clone(),
                        dont_cache: *dont_cache,
                    },
                    fault,
                    result
                        .as_ref()
                        .map_or_else(err, |b| CallResult::Bytes(b.clone())),
                );
                let blob_model = &self.h.model.blobs[&generation];
                if !blob_model.unchecked && result.is_ok() {
                    if let Some(message) = layout {
                        return Err(self.h.fail(Invariant::I2a, message, Some(generation)));
                    }
                    self.h.measure(Invariant::I2a);
                }
                self.judge_read(*slot, &blob, generation, &[range], result, fault)
                    .await
            }
            Op::ReadMany {
                slot,
                ranges,
                dont_cache,
                ..
            } => {
                let Some((blob, generation)) = self.slot(*slot) else {
                    return Ok(());
                };
                let ranges = self.resolve(generation, ranges);
                let fault = op.fault();
                self.arm(fault);
                let mut bufs: Vec<Option<Vec<u8>>> = vec![None; ranges.len()];
                let mut yields = Ok(());
                let mut error = None;
                {
                    let stream = blob.read_many(&ranges, read_options(*dont_cache));
                    let mut stream = std::pin::pin!(stream);
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok((i, buf)) => match bufs.get_mut(i) {
                                Some(entry @ None) => {
                                    *entry = Some(buf.coalesce().as_ref().to_vec())
                                }
                                Some(Some(_)) => {
                                    yields = yields
                                        .and(Err(format!("read_many yielded range {i} twice")));
                                }
                                None => {
                                    yields = yields.and(Err(format!(
                                        "read_many yielded range {i} of {}",
                                        ranges.len()
                                    )));
                                }
                            },
                            Err(e) => {
                                error = Some(e);
                                break;
                            }
                        }
                    }
                }
                self.disarm(fault);
                let result = match error {
                    Some(e) => Err(e),
                    None => {
                        let missing: Vec<usize> =
                            (0..bufs.len()).filter(|i| bufs[*i].is_none()).collect();
                        if !missing.is_empty() {
                            yields = yields.and(Err(format!(
                                "read_many ended without an error or ranges {missing:?}"
                            )));
                        }
                        Ok(bufs
                            .into_iter()
                            .map(Option::unwrap_or_default)
                            .collect::<Vec<_>>())
                    }
                };
                self.record(
                    origin,
                    Call::ReadMany {
                        slot: *slot,
                        ranges: ranges.clone(),
                        dont_cache: *dont_cache,
                    },
                    fault,
                    result
                        .as_ref()
                        .map_or_else(err, |b| CallResult::Bytes(b.clone())),
                );
                let injected = fault.armed() && result.as_ref().is_err_and(is_io);
                if !self.h.model.blobs[&generation].unchecked && !injected {
                    // Each range exactly once is promised only when no error is yielded (SF-I2b).
                    if result.is_ok()
                        && let Err(message) = yields
                    {
                        return Err(self.h.fail(Invariant::I2b, message, Some(generation)));
                    }
                    self.h.measure(Invariant::I2b);
                }
                self.judge_read(*slot, &blob, generation, &ranges, result, fault)
                    .await
            }
            Op::StartReadMany {
                slot,
                ranges,
                dont_cache,
                wait,
                ..
            } => {
                let Some((blob, generation)) = self.slot(*slot) else {
                    return Ok(());
                };
                let ranges = self.resolve(generation, ranges);
                let fault = op.fault();
                self.arm(fault);
                let handle = blob
                    .start_read_many(&ranges, read_options(*dont_cache))
                    .await;
                let call = Call::StartReadMany {
                    slot: *slot,
                    ranges: ranges.clone(),
                    dont_cache: *dont_cache,
                    wait: *wait,
                };
                if !*wait {
                    drop(handle);
                    self.disarm(fault);
                    self.record(origin, call, fault, CallResult::Dropped);
                    return Ok(());
                }
                let result = handle.await.map(|bufs| {
                    bufs.into_iter()
                        .map(|buf| buf.coalesce().as_ref().to_vec())
                        .collect::<Vec<_>>()
                });
                self.disarm(fault);
                self.record(
                    origin,
                    call,
                    fault,
                    result
                        .as_ref()
                        .map_or_else(err, |b| CallResult::Bytes(b.clone())),
                );
                if !self.h.model.blobs[&generation].unchecked
                    && let Ok(bufs) = &result
                {
                    if bufs.len() != ranges.len() {
                        return Err(self.h.fail(
                            Invariant::I2c,
                            format!(
                                "start_read_many returned {} buffers for {} ranges",
                                bufs.len(),
                                ranges.len()
                            ),
                            Some(generation),
                        ));
                    }
                    self.h.measure(Invariant::I2c);
                }
                let result = result.map(|bufs| {
                    let mut bufs = bufs;
                    bufs.resize(ranges.len(), Vec::new());
                    bufs
                });
                self.judge_read(*slot, &blob, generation, &ranges, result, fault)
                    .await
            }
            Op::Resize { slot, len, .. } => {
                let Some((blob, generation)) = self.slot(*slot) else {
                    return Ok(());
                };
                let old = self.h.view(generation).to_vec();
                let target = len.resolve(old.len() as u64, MAX_SIZE);
                let fault = op.fault();
                let checked = self.mutation_checked(generation);
                self.arm(fault);
                let result = blob.resize(target).await;
                self.disarm(fault);
                self.record(
                    origin,
                    Call::Resize {
                        slot: *slot,
                        len: target,
                    },
                    fault,
                    result.as_ref().map_or_else(err, |()| CallResult::Unit),
                );
                if !checked {
                    return Ok(());
                }
                match result {
                    Ok(()) => {
                        self.h
                            .model
                            .blobs
                            .get_mut(&generation)
                            .unwrap()
                            .resize(target);
                        self.h.log(generation, Entry::MaybeResize(target), false);
                        self.h.measure(Invariant::I16c);
                        Ok(())
                    }
                    Err(e) if fault.armed() && is_io(&e) => {
                        self.failed_resize(*slot, &blob, generation, &old, target)
                            .await
                    }
                    Err(e) => Err(self.h.fail(
                        Invariant::I16c,
                        format!("resize to {target} failed with {e:?}"),
                        Some(generation),
                    )),
                }
            }
            Op::Sync { slot, .. } => {
                let Some((blob, generation)) = self.slot(*slot) else {
                    return Ok(());
                };
                let fault = op.fault();
                let checked = self.mutation_checked(generation);
                self.arm(fault);
                let result = blob.sync().await;
                self.disarm(fault);
                self.record(
                    origin,
                    Call::Sync { slot: *slot },
                    fault,
                    result.as_ref().map_or_else(err, |()| CallResult::Unit),
                );
                if !checked {
                    return Ok(());
                }
                self.synced(*slot, &blob, generation, result, fault, Invariant::I16d)
                    .await
            }
            Op::StartSync { slot, wait, .. } => {
                let Some((blob, generation)) = self.slot(*slot) else {
                    return Ok(());
                };
                let fault = op.fault();
                let checked = self.mutation_checked(generation);
                self.arm(fault);
                let handle = blob.start_sync().await;
                let call = Call::StartSync {
                    slot: *slot,
                    wait: *wait,
                };
                if !*wait {
                    drop(handle);
                    self.disarm(fault);
                    self.record(origin, call, fault, CallResult::Dropped);
                    // The memory backend finishes an accepted sync before it returns the handle
                    // (SF-C2); an armed one was refused.
                    if checked && !fault.armed() {
                        self.h.sync_cut(generation);
                    }
                    return Ok(());
                }
                let result = handle.await;
                self.disarm(fault);
                self.record(
                    origin,
                    call,
                    fault,
                    result.as_ref().map_or_else(err, |()| CallResult::Unit),
                );
                if !checked {
                    return Ok(());
                }
                self.synced(*slot, &blob, generation, result, fault, Invariant::I16e)
                    .await
            }
            Op::Remove {
                partition,
                name,
                fault: _,
            } => {
                let partition = partition.get();
                let name = name.map(BlobName::get);
                let fault = op.fault();
                let valid = valid_partition(&partition);
                let removed: Option<Vec<u64>> = match &name {
                    Some(name) => self.h.model.current(&partition, name).map(|g| vec![g]),
                    None => self
                        .h
                        .model
                        .partitions
                        .get(&partition)
                        .map(|names| names.values().copied().collect()),
                };
                self.arm(fault);
                let result = self.storage.remove(&partition, name.as_deref()).await;
                self.disarm(fault);
                self.record(
                    origin,
                    Call::Remove {
                        partition: partition.clone(),
                        name: name.clone(),
                    },
                    fault,
                    result.as_ref().map_or_else(err, |()| CallResult::Unit),
                );
                match result {
                    Err(e) if fault.armed() && is_io(&e) => {
                        if valid {
                            self.scan_check(&partition, Invariant::I6d).await?;
                            self.h.measure(Invariant::I6d);
                        }
                        Ok(())
                    }
                    Ok(()) if !valid => Err(self.h.fail(
                        Invariant::I3d,
                        "remove of an invalid partition succeeded".into(),
                        None,
                    )),
                    Err(_) if !valid => {
                        self.h.measure(Invariant::I3d);
                        Ok(())
                    }
                    Ok(()) => {
                        if let Some(generations) = removed {
                            self.h.model.unlink(&partition, name.as_deref());
                            for generation in generations {
                                self.h.durable.remove(&generation);
                            }
                            self.h.measure(Invariant::I16f);
                        }
                        Ok(())
                    }
                    Err(e) if removed.is_some() => Err(self.h.fail(
                        Invariant::I16f,
                        format!("remove of a held target failed with {e:?}"),
                        None,
                    )),
                    Err(_) => Ok(()),
                }
            }
            Op::Scan { partition, .. } => {
                let partition = partition.get();
                let fault = op.fault();
                let valid = valid_partition(&partition);
                self.arm(fault);
                let result = self.storage.scan(&partition).await.map(|mut names| {
                    names.sort();
                    names
                });
                self.disarm(fault);
                self.record(
                    origin,
                    Call::Scan {
                        partition: partition.clone(),
                    },
                    fault,
                    result
                        .as_ref()
                        .map_or_else(err, |n| CallResult::Names(n.clone())),
                );
                let expected = self.h.model.names(&partition);
                match result {
                    Err(e) if fault.armed() && is_io(&e) => {
                        if valid {
                            self.scan_check(&partition, Invariant::I6e).await?;
                            self.h.measure(Invariant::I6e);
                        }
                        Ok(())
                    }
                    Ok(_) if !valid => Err(self.h.fail(
                        Invariant::I3e,
                        "scan of an invalid partition succeeded".into(),
                        None,
                    )),
                    Err(_) if !valid => {
                        self.h.measure(Invariant::I3e);
                        Ok(())
                    }
                    Ok(got) => {
                        let ok = expected
                            .as_ref()
                            .map_or(got.is_empty(), |names| got.iter().eq(names.iter()));
                        if !ok {
                            return Err(self.h.fail(
                                Invariant::I14a,
                                format!(
                                    "scan returned {:?}, model: {}",
                                    got.iter().map(|n| display_name(n)).collect::<Vec<_>>(),
                                    self.h.model.partition_summary(&partition)
                                ),
                                None,
                            ));
                        }
                        self.h.measure(Invariant::I14a);
                        if expected.is_some() {
                            self.h.measure(Invariant::I16g);
                        }
                        Ok(())
                    }
                    Err(e) if expected.is_some() => Err(self.h.fail(
                        Invariant::I16g,
                        format!("scan of a held partition failed with {e:?}"),
                        None,
                    )),
                    Err(_) => Ok(()),
                }
            }
            Op::Drop { slot } => {
                self.close_slot(*slot);
                Ok(())
            }
            Op::Crash => unreachable!("sessions end at crashes"),
        }
    }

    fn resolve(&self, generation: u64, ranges: &[(Offset, usize)]) -> Vec<(u64, usize)> {
        let size = self.h.view(generation).len() as u64;
        ranges
            .iter()
            .map(|(offset, len)| (offset.resolve(size, MAX_READ_OFFSET), *len))
            .collect()
    }

    /// Whether a mutation through this handle is judged. The first mutation through a handle of a
    /// removed generation makes it unchecked (SF-X8).
    fn mutation_checked(&mut self, generation: u64) -> bool {
        let blob = self.h.model.blobs.get_mut(&generation).unwrap();
        if blob.removed {
            blob.unchecked = true;
        }
        !blob.unchecked
    }

    async fn open(
        &mut self,
        origin: Origin,
        slot: usize,
        partition: PartitionName,
        name: BlobName,
        versions: Option<(u16, u16)>,
        fault: bool,
    ) -> Judged {
        self.close_slot(slot);
        let partition = partition.get();
        let name = name.get();
        let fault = Fault {
            open: fault,
            ..Fault::default()
        };
        let (lo, hi) = versions.unwrap_or((0, 0));
        self.arm(fault);
        let result = match versions {
            Some(_) => self
                .storage
                .open_versioned(
                    &partition,
                    &name,
                    BlobVersion::new(lo)..=BlobVersion::new(hi),
                )
                .await
                .map(|(blob, size, version)| (blob, size, Some(version.get()))),
            None => self
                .storage
                .open(&partition, &name)
                .await
                .map(|(blob, size)| (blob, size, None)),
        };
        self.disarm(fault);
        self.record(
            origin,
            Call::Open {
                partition: partition.clone(),
                name: name.clone(),
                versions: (lo, hi),
                default: versions.is_none(),
            },
            fault,
            match &result {
                Ok((_, size, version)) => CallResult::Opened {
                    size: *size,
                    version: *version,
                },
                Err(e) => err(e),
            },
        );
        let valid = valid_partition(&partition);
        if fault.armed() && result.as_ref().is_err_and(is_io) {
            if valid {
                self.scan_check(&partition, Invariant::I6a).await?;
                self.h.measure(Invariant::I6a);
            }
            return Ok(());
        }
        if !valid {
            return match result {
                Ok(_) => Err(self.h.fail(
                    Invariant::I3c,
                    "an open on an invalid partition succeeded".into(),
                    None,
                )),
                Err(_) => {
                    self.h.measure(Invariant::I3c);
                    Ok(())
                }
            };
        }
        let existing = self.h.model.current(&partition, &name);
        if let Some(generation) = existing {
            let blob = &self.h.model.blobs[&generation];
            let (recorded, open) = (blob.version, blob.open);
            if !(lo..=hi).contains(&recorded) {
                return match result {
                    Err(Error::BlobVersionMismatch { .. }) => {
                        self.h.measure(Invariant::I3b);
                        Ok(())
                    }
                    other => Err(self.h.fail(
                        Invariant::I3b,
                        format!(
                            "open of version {recorded} with {lo}..={hi} returned {:?}",
                            other.map(|(_, s, v)| (s, v))
                        ),
                        Some(generation),
                    )),
                };
            }
            if open {
                return match result {
                    Err(Error::BlobAlreadyOpen(..)) => {
                        self.h.measure(Invariant::I3a);
                        Ok(())
                    }
                    other => Err(self.h.fail(
                        Invariant::I3a,
                        format!(
                            "open of an open blob returned {:?}",
                            other.map(|(_, s, v)| (s, v))
                        ),
                        Some(generation),
                    )),
                };
            }
        }
        let (blob, size, version) = match result {
            Ok(opened) => opened,
            Err(e) => {
                return Err(self.h.fail(
                    Invariant::I16a,
                    format!("open failed with {e:?}"),
                    existing,
                ));
            }
        };
        self.h.measure(Invariant::I16a);
        let blob = Arc::new(blob);
        let generation = match existing {
            Some(generation) => {
                let recorded = self.h.model.blobs[&generation].version;
                let image = self
                    .after_open(
                        &blob,
                        size,
                        version,
                        Opening::Existing { version: recorded },
                    )
                    .await?;
                let durable = &self.h.durable[&generation];
                let logged = !durable.log.is_empty();
                let steps: Vec<Step<'_>> = durable
                    .log
                    .iter()
                    .map(|l| {
                        step(
                            &l.entry,
                            l.failed_write,
                            Relax {
                                forced_optional: true,
                                ..Relax::default()
                            },
                        )
                    })
                    .collect();
                if !reach(&durable.base, &steps, &image) {
                    return Err(self.h.fail(
                        Invariant::I12,
                        format!(
                            "the image after the reopen ({} bytes, {:02x?}) is not in Reach_reopen",
                            image.len(),
                            &image[..image.len().min(16)]
                        ),
                        Some(generation),
                    ));
                }
                if logged {
                    self.h.measure(Invariant::I12);
                }
                self.h
                    .durable
                    .get_mut(&generation)
                    .unwrap()
                    .cut(CutKind::Reopen, image.clone());
                self.h.set_view(generation, image);
                self.h.model.blobs.get_mut(&generation).unwrap().sync();
                generation
            }
            None => {
                self.after_open(&blob, size, version, Opening::New { lo, hi })
                    .await?;
                let version = version.unwrap_or(lo);
                let generation =
                    self.h
                        .model
                        .create(partition, name, version, Some(DEFAULT_BLOB_LAYOUT));
                self.h.durable.insert(generation, Durable::default());
                generation
            }
        };
        self.h.model.blobs.get_mut(&generation).unwrap().open = true;
        self.h.model.slots[slot] = Some(generation);
        self.slots[slot] = Some(blob);
        Ok(())
    }

    async fn write(&mut self, origin: Origin, op: &Op) -> Judged {
        let Op::Write {
            slot,
            offset,
            chunks,
            sync,
            dont_cache,
            write_fault,
            sync_fault,
        } = op
        else {
            unreachable!()
        };
        let Some((blob, generation)) = self.slot(*slot) else {
            return Ok(());
        };
        let old = self.h.view(generation).to_vec();
        let total: usize = chunks.iter().sum();
        let mut offset = offset.resolve(old.len() as u64, MAX_OFFSET);
        // SF-X5: an empty write without SYNC never starts past the end.
        if total == 0 && !*sync {
            offset = offset.min(old.len() as u64);
        }
        let fails = write_fault.is_some_and(|f| f.fails);
        let bytes: Vec<u8> = (0..total as u64)
            .map(|i| {
                let position = offset + i;
                let byte = value(self.h.index, position);
                // SF-R30: a failing write differs from the view at every position.
                match old.get(position as usize) {
                    Some(old) if fails && *old == byte => byte % 255 + 1,
                    _ => byte,
                }
            })
            .collect();
        let mut bufs = Vec::with_capacity(chunks.len());
        let mut start = 0;
        for len in chunks {
            bufs.push(IoBuf::from(bytes[start..start + len].to_vec()));
            start += len;
        }
        let mut options = WriteOptions::default();
        if *sync {
            options |= WriteOptions::SYNC;
        }
        if *dont_cache {
            options |= WriteOptions::DONT_CACHE;
        }
        let fault = op.fault();
        let checked = self.mutation_checked(generation);
        self.arm(fault);
        let result = blob.write_at(offset, IoBufs::from(bufs), options).await;
        self.disarm(fault);
        self.record(
            origin,
            Call::Write {
                slot: *slot,
                offset,
                bytes: bytes.clone(),
                chunks: chunks.clone(),
                sync: *sync,
                dont_cache: *dont_cache,
            },
            fault,
            result.as_ref().map_or_else(err, |()| CallResult::Unit),
        );
        if !checked {
            return Ok(());
        }
        let can_fail = fails || (*sync && *sync_fault);
        match result {
            Ok(()) => {
                if total > 0 {
                    self.h
                        .model
                        .blobs
                        .get_mut(&generation)
                        .unwrap()
                        .write(offset, &bytes, *sync);
                    let entry = if *sync {
                        Entry::Kept {
                            offset,
                            bytes,
                            mask: vec![true; total],
                        }
                    } else {
                        Entry::Torn { offset, bytes }
                    };
                    self.h.log(generation, entry, false);
                }
                self.h.measure(Invariant::I16b);
                Ok(())
            }
            Err(e) if can_fail && is_io(&e) => {
                self.failed_write(*slot, &blob, generation, &old, offset, &bytes, fails)
                    .await
            }
            Err(e) => Err(self.h.fail(
                Invariant::I16b,
                format!("write of {total} bytes at {offset} failed with {e:?}"),
                Some(generation),
            )),
        }
    }

    /// SF-R16 (`kept`: a write fault with `failure_rate` 1) and SF-R17 (a sync fault in a fused
    /// write).
    #[allow(clippy::too_many_arguments)]
    async fn failed_write(
        &mut self,
        slot: usize,
        blob: &Arc<S::Blob>,
        generation: u64,
        old: &[u8],
        offset: u64,
        bytes: &[u8],
        kept: bool,
    ) -> Judged {
        let start = offset as usize;
        let end = start + bytes.len();
        let bound = old.len().max(end) as u64;
        let image = self
            .search(slot, blob, generation, bound, Invariant::I4c)
            .await?;
        let inside = |p: usize| p >= start && p < end;
        if let Some(p) =
            (0..old.len().min(image.len())).find(|p| !inside(*p) && image[*p] != old[*p])
        {
            return Err(self.h.fail(
                Invariant::I4a,
                format!(
                    "byte {p} outside the write changed from {:#04x} to {:#04x}",
                    old[p], image[p]
                ),
                Some(generation),
            ));
        }
        if let Some(p) = (start..end.min(image.len())).find(|p| {
            let got = image[*p];
            got != bytes[p - start] && old.get(*p).map_or(got != 0, |o| got != *o)
        }) {
            return Err(self.h.fail(
                Invariant::I4b,
                format!(
                    "byte {p} in the write is {:#04x}: neither submitted {:#04x} nor old",
                    image[p],
                    bytes[p - start]
                ),
                Some(generation),
            ));
        }
        let highest = (start..end.min(image.len()))
            .filter(|p| image[*p] == bytes[*p - start])
            .max()
            .map_or(0, |p| p + 1);
        let expected = old.len().max(highest);
        let stray = (old.len()..image.len())
            .find(|p| image[*p] != 0 && !(inside(*p) && image[*p] == bytes[*p - start]));
        if image.len() != expected || stray.is_some() {
            return Err(self.h.fail(
                Invariant::I4c,
                format!(
                    "length {} (expected {expected}, old {}), nonzero stray byte at {stray:?}",
                    image.len(),
                    old.len()
                ),
                Some(generation),
            ));
        }
        if !kept {
            if let Some(p) = (start..end).find(|p| image.get(*p) != Some(&bytes[*p - start])) {
                return Err(self.h.fail(
                    Invariant::I4d,
                    format!(
                        "byte {p} of the fused write is {:?}, submitted {:#04x}",
                        image.get(p),
                        bytes[p - start]
                    ),
                    Some(generation),
                ));
            }
            self.h.measure(Invariant::I4d);
        }
        self.h.measure(Invariant::I4a);
        self.h.measure(Invariant::I4b);
        self.h.measure(Invariant::I4c);
        let mask: Vec<bool> = (start..end)
            .map(|p| image.get(p) == Some(&bytes[p - start]))
            .collect();
        let entry = if kept {
            mask.contains(&true).then(|| Entry::Kept {
                offset,
                bytes: bytes.to_vec(),
                mask,
            })
        } else {
            (!bytes.is_empty()).then(|| Entry::Torn {
                offset,
                bytes: bytes.to_vec(),
            })
        };
        if let Some(entry) = entry {
            self.h.log(generation, entry, kept);
        }
        self.h.set_view(generation, image);
        Ok(())
    }

    /// SF-R18.
    async fn failed_resize(
        &mut self,
        slot: usize,
        blob: &Arc<S::Blob>,
        generation: u64,
        old: &[u8],
        target: u64,
    ) -> Judged {
        let a = old.len() as u64;
        let image = self
            .search(slot, blob, generation, a.max(target), Invariant::I5a)
            .await?;
        let len = image.len() as u64;
        if len != a && !(len > a.min(target) && len < a.max(target)) {
            return Err(self.h.fail(
                Invariant::I5a,
                format!("length {len} after a failed resize from {a} to {target}"),
                Some(generation),
            ));
        }
        let kept = old.len().min(image.len());
        if let Some(p) = (0..kept).find(|p| image[*p] != old[*p]) {
            return Err(self.h.fail(
                Invariant::I5b,
                format!("byte {p} changed from {:#04x} to {:#04x}", old[p], image[p]),
                Some(generation),
            ));
        }
        if let Some(p) = (old.len()..image.len()).find(|p| image[*p] != 0) {
            return Err(self.h.fail(
                Invariant::I5c,
                format!("added byte {p} is {:#04x}", image[p]),
                Some(generation),
            ));
        }
        self.h.measure(Invariant::I5a);
        if kept > 0 {
            self.h.measure(Invariant::I5b);
        }
        if len > a {
            self.h.measure(Invariant::I5c);
        }
        if len != a {
            self.h.log(generation, Entry::ForcedResize(len), false);
        }
        self.h.set_view(generation, image);
        Ok(())
    }

    /// The result of a `Sync` or an awaited `StartSync` through a checked handle.
    async fn synced(
        &mut self,
        slot: usize,
        blob: &Arc<S::Blob>,
        generation: u64,
        result: Result<(), Error>,
        fault: Fault,
        unexpected: Invariant,
    ) -> Judged {
        match result {
            Ok(()) => {
                self.h.sync_cut(generation);
                self.h.measure(unexpected);
                Ok(())
            }
            Err(e) if fault.armed() && is_io(&e) => {
                self.unchanged(slot, blob, generation, Invariant::I6c)
                    .await?;
                self.h.measure(Invariant::I6c);
                Ok(())
            }
            Err(e) => Err(self.h.fail(
                unexpected,
                format!("sync failed with {e:?}"),
                Some(generation),
            )),
        }
    }

    /// Judge a baseline or input read (SF-I1, SF-I15), or check after its injected failure.
    async fn judge_read(
        &mut self,
        slot: usize,
        blob: &Arc<S::Blob>,
        generation: u64,
        ranges: &[(u64, usize)],
        result: Result<Vec<Vec<u8>>, Error>,
        fault: Fault,
    ) -> Judged {
        let model = &self.h.model.blobs[&generation];
        let (removed, checked) = (model.removed, !model.unchecked);
        if fault.armed() && result.as_ref().is_err_and(is_io) {
            if checked {
                self.unchanged(slot, blob, generation, Invariant::I6b)
                    .await?;
                self.h.measure(Invariant::I6b);
            }
            return Ok(());
        }
        let (bytes_row, len_row) = if removed {
            (Invariant::I15, Invariant::I15)
        } else {
            (Invariant::I1a, Invariant::I1b)
        };
        if let Ok(bufs) = &result
            && let Some((i, (buf, (_, len)))) = bufs
                .iter()
                .zip(ranges)
                .enumerate()
                .find(|(_, (buf, (_, len)))| buf.len() != *len)
        {
            return Err(self.h.fail(
                len_row,
                format!("range {i} returned {} bytes, requested {len}", buf.len()),
                Some(generation),
            ));
        }
        if !checked {
            return Ok(());
        }
        let view = self.h.view(generation);
        let size = view.len() as u64;
        let expects: Vec<Option<bool>> = ranges
            .iter()
            .map(|(offset, len)| read_expect(size, *offset, *len))
            .collect();
        let must_fail = expects.contains(&Some(false));
        let must_succeed = expects.iter().all(|e| *e == Some(true));
        match &result {
            Ok(_) if must_fail => {
                return Err(self.h.fail(
                    len_row,
                    format!("a read of {ranges:?} past the view length {size} succeeded"),
                    Some(generation),
                ));
            }
            Err(e) if must_succeed => {
                return Err(self.h.fail(
                    len_row,
                    format!("a read of {ranges:?} inside the view length {size} failed with {e:?}"),
                    Some(generation),
                ));
            }
            _ => {}
        }
        if let Ok(bufs) = &result {
            for (i, (buf, (offset, _))) in bufs.iter().zip(ranges).enumerate() {
                let Some(start) = usize::try_from(*offset).ok().filter(|o| *o <= view.len()) else {
                    continue;
                };
                let want = &view[start..(start + buf.len()).min(view.len())];
                if let Some(j) = buf.iter().zip(want).position(|(a, b)| a != b) {
                    return Err(self.h.fail(
                        bytes_row,
                        format!("range {i} differs from the view at blob offset {}: got {:#04x}, view {:#04x}", start + j, buf[j], want[j]),
                        Some(generation),
                    ));
                }
            }
        }
        self.h.measure(len_row);
        if result.is_ok() {
            self.h.measure(bytes_row);
        }
        Ok(())
    }
}

fn reachable_crash(durable: &Durable, image: &[u8]) -> bool {
    durable.reaches(durable.history.len(), Relax::default(), image)
}

/// Run `input` through `seam` and return its trace, its first violation and the measured
/// invariants. A panic raised by the storage passes through.
pub fn run<S, F>(input: &FuzzInput, seam: F, verify: Verify) -> Outcome
where
    S: Storage,
    F: Fn(deterministic::Context) -> S,
{
    // Sessions: the baseline and the input operations up to each crash that takes effect, then
    // the session of the final check after the mandatory crash.
    let mut sessions: Vec<Vec<(usize, Origin, Op)>> = vec![
        baseline()
            .into_iter()
            .enumerate()
            .map(|(i, op)| (i, Origin::Baseline, op))
            .collect(),
    ];
    let mut crashes = Vec::new();
    for (i, op) in input.ops.iter().enumerate() {
        let index = BASELINE_OPS + i;
        if matches!(op, Op::Crash) {
            if crashes.len() < MAX_EXTRA_CRASHES {
                crashes.push(index);
                sessions.push(Vec::new());
            }
            continue;
        }
        sessions
            .last_mut()
            .unwrap()
            .push((index, Origin::Input, op.clone()));
    }
    crashes.push(BASELINE_OPS + input.ops.len());
    sessions.push(Vec::new());

    let mut h = Harness::new(verify);
    let cfg = deterministic::Config::new()
        .with_rng(FuzzRng::from(input.entropy.clone()))
        .with_storage_fault_config(FaultConfig::default());
    let mut runner = deterministic::Runner::new(cfg);
    for (session, ops) in sessions.iter().enumerate() {
        if h.violation.is_some() {
            break;
        }
        h.session = session;
        let recovery = session.checked_sub(1).map(|i| crashes[i]);
        let (h_ref, seam_ref) = (&mut h, &seam);
        let ((), checkpoint) = runner.start_and_recover(|context| async move {
            let faults = context.storage_fault_config();
            let storage = seam_ref(context);
            let mut s = Session {
                h: h_ref,
                storage: &storage,
                faults: &faults,
                slots: Default::default(),
            };
            if let Err(violation) = s.run(recovery, ops).await {
                s.h.violation = Some(violation);
            }
            for slot in 0..SLOTS {
                s.close_slot(slot);
            }
            drop(storage);
        });
        runner = deterministic::Runner::from(checkpoint);
    }
    Outcome {
        trace: h.trace,
        violation: h.violation,
        measured: h.measured,
    }
}
