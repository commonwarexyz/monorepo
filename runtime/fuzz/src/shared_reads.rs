//! Concurrent readers that share the page reads of one page cache.
//!
//! One run seals a blob of full pages through a small shared [CacheRef], clears the cache, and
//! reads the blob through clones of the [Sealed] handle on the deterministic runtime. The blob is
//! wrapped in [MigratingReadBlob], which holds every backend read in flight for one poll, so a
//! read that misses a page can join the standalone fetch or the batch another read has in flight.
//!
//! The read phase has two parts. The opening reads one cold page twice from the root task, so the
//! second read registers on the first one's fetch (SR-R9). Then several reader tasks run their
//! operations; a flagged operation is polled once and dropped when it is pending (SR-R10). Every
//! read that completes is judged against [value], every read that is not cancelled must succeed,
//! and the whole read phase must end before [DEADLINE] of simulated time.
//!
//! [fuzz] is the fuzz entry. [run] is the same run with a seam around the counting blob and no
//! panic on a violation, so tests can plant faults and read the result; [run_observed] also
//! returns the order of the run's steps. See `runtime/fuzz/SPEC.md`, target `shared_reads`, for
//! the requirements (SR-R) and invariants (SR-I) named below.

use crate::decode;
use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{
    Blob, Clock as _, Error, Handle, IoBufs, IoBufsMut, ReadOptions, Runner as _, Spawner as _,
    Storage as _, Supervisor as _, WriteOptions,
    buffer::paged::{CHECKSUM_SIZE, CacheRef, Sealed, Writer},
    deterministic,
    mocks::MigratingReadBlob,
};
use commonware_utils::{Entropy, FuzzRng, sync::Mutex};
use futures::{
    StreamExt as _,
    future::{Either, select},
    poll,
    stream::FuturesUnordered,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    num::{NonZeroU16, NonZeroUsize},
    ops::RangeInclusive,
    pin::pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

/// Logical bytes of a page.
pub const PAGE_SIZE: u64 = 64;
/// Bytes of a page as stored in the blob.
pub const PHYSICAL_PAGE_SIZE: u64 = PAGE_SIZE + CHECKSUM_SIZE;
/// Fewest pages of the sealed blob.
pub const MIN_PAGES: u64 = 2;
/// Most pages of the sealed blob.
pub const MAX_PAGES: u64 = 16;
/// Fewest readers of the free phase.
pub const MIN_READERS: usize = 2;
/// Most readers of the free phase.
pub const MAX_READERS: usize = 6;
/// Fewest operations of one reader.
pub const MIN_OPS: usize = 1;
/// Most operations of one reader.
pub const MAX_OPS: usize = 8;
/// Most consecutive pages the ranges of one read touch.
pub const MAX_SPAN: u64 = 4;
/// Most ranges of one free-phase `read_ranges_into`.
pub const MAX_RANGES: usize = 4;
/// Most ranges of the opening's `read_ranges_into`.
pub const MAX_OPENING_RANGES: usize = 2;
/// Simulated time the read phase may take.
pub const DEADLINE: Duration = Duration::from_secs(10);
/// Partition of the blob.
pub const PARTITION: &str = "shared_reads";
/// Name of the blob.
pub const BLOB: &[u8] = b"blob";
/// Write buffer of the writer that fills the blob.
const WRITE_BUFFER: usize = 2 * PAGE_SIZE as usize;

/// The byte the blob holds at logical offset `offset`. No byte is zero, and two pages differ at
/// every offset inside the page.
pub const fn value(offset: u64) -> u8 {
    (((offset / PAGE_SIZE) * 37 + offset % PAGE_SIZE) % 255 + 1) as u8
}

/// Which read call an operation makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    ReadAt,
    ReadInto,
    ReadRangesInto,
}

/// One read: its form, its `(offset, len)` ranges and its drop flag. `ReadAt` and `ReadInto`
/// have one range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub form: Form,
    pub ranges: Vec<(u64, usize)>,
    pub drop: bool,
}

/// The opening: read A (`first`) and read B (`second`) of `page` (SR-R9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub page: u64,
    pub first: Op,
    pub second: Op,
}

/// The input of one run. A hand-written value is used as it is; one outside the bounds or
/// against SR-R4 makes [run] panic before the runtime starts.
#[derive(Clone, Debug)]
pub struct FuzzInput {
    pub pages: u64,
    pub cache_pages: usize,
    pub opening: Opening,
    pub readers: Vec<Vec<Op>>,
    pub entropy: Entropy,
}

/// Draw the drop flag of a free-phase operation: one selector in `0..=3`, flagged on 3.
pub fn sample_drop(u: &mut Unstructured<'_>) -> arbitrary::Result<bool> {
    Ok(u.int_in_range(0..=3u8)? == 3)
}

/// Draw the drop flag of the opening's read A: one selector in `0..=1`, flagged on 1.
pub fn sample_opening_drop(u: &mut Unstructured<'_>) -> arbitrary::Result<bool> {
    Ok(u.int_in_range(0..=1u8)? == 1)
}

/// One range that starts in `starts` and ends at `end` at the latest.
fn sample_range(
    u: &mut Unstructured<'_>,
    starts: RangeInclusive<u64>,
    end: u64,
) -> arbitrary::Result<(u64, usize)> {
    let offset = u.int_in_range(starts)?;
    let len = u.int_in_range(1..=end - offset)?;
    Ok((offset, len as usize))
}

/// 1 to `max` sorted ranges that do not overlap, the first starting in `first`, all ending at
/// `end` at the latest.
fn sample_ranges(
    u: &mut Unstructured<'_>,
    first: RangeInclusive<u64>,
    end: u64,
    max: usize,
) -> arbitrary::Result<Vec<(u64, usize)>> {
    let count = u.int_in_range(1..=max)?;
    let mut ranges = vec![sample_range(u, first, end)?];
    while ranges.len() < count {
        let (offset, len) = ranges[ranges.len() - 1];
        let next = offset + len as u64;
        if next == end {
            break;
        }
        ranges.push(sample_range(u, next..=end - 1, end)?);
    }
    Ok(ranges)
}

/// A free-phase operation. Its window of pages starts at `hot` when given, and its first range
/// then starts inside that page (SR-R6).
fn sample_op(u: &mut Unstructured<'_>, pages: u64, hot: Option<u64>) -> arbitrary::Result<Op> {
    let form = match u.int_in_range(0..=2u8)? {
        0 => Form::ReadAt,
        1 => Form::ReadInto,
        _ => Form::ReadRangesInto,
    };
    let first_page = match hot {
        Some(page) => page,
        None => u.int_in_range(0..=pages - 1)?,
    };
    let span = u.int_in_range(1..=MAX_SPAN.min(pages - first_page))?;
    let start = first_page * PAGE_SIZE;
    let end = (first_page + span) * PAGE_SIZE;
    let first = match hot {
        Some(_) => start..=start + PAGE_SIZE - 1,
        None => start..=end - 1,
    };
    let ranges = match form {
        Form::ReadRangesInto => sample_ranges(u, first, end, MAX_RANGES)?,
        Form::ReadAt | Form::ReadInto => vec![sample_range(u, first, end)?],
    };
    let drop = sample_drop(u)?;
    Ok(Op { form, ranges, drop })
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let (stream, entropy) = decode(u)?;
        let u = &mut Unstructured::new(&stream);
        let pages = u.int_in_range(MIN_PAGES..=MAX_PAGES)?;
        let cache_pages = u.int_in_range(1..=pages as usize - 1)?;

        let page = u.int_in_range(0..=pages - 1)?;
        let start = page * PAGE_SIZE;
        let end = start + PAGE_SIZE;
        let form = if u.int_in_range(0..=1u8)? == 0 {
            Form::ReadAt
        } else {
            Form::ReadInto
        };
        let first = Op {
            form,
            ranges: vec![sample_range(u, start..=end - 1, end)?],
            drop: sample_opening_drop(u)?,
        };
        let form = match u.int_in_range(0..=2u8)? {
            0 => Form::ReadAt,
            1 => Form::ReadInto,
            _ => Form::ReadRangesInto,
        };
        let ranges = match form {
            Form::ReadRangesInto => sample_ranges(u, start..=end - 1, end, MAX_OPENING_RANGES)?,
            Form::ReadAt | Form::ReadInto => vec![sample_range(u, start..=end - 1, end)?],
        };
        let second = Op {
            form,
            ranges,
            drop: false,
        };

        let hot = u.int_in_range(0..=pages - 2)?;
        let hot = if hot >= page { hot + 1 } else { hot };
        let mut readers = Vec::new();
        for _ in 0..u.int_in_range(MIN_READERS..=MAX_READERS)? {
            let mut ops = Vec::new();
            for i in 0..u.int_in_range(MIN_OPS..=MAX_OPS)? {
                ops.push(sample_op(u, pages, (i == 0).then_some(hot))?);
            }
            readers.push(ops);
        }
        Ok(Self {
            pages,
            cache_pages,
            opening: Opening {
                page,
                first,
                second,
            },
            readers,
            entropy,
        })
    }
}

/// Panic unless `op` has between 1 and `max` ranges that are sorted, do not overlap, hold at
/// least one byte each, lie inside `lo..hi` and touch at most [MAX_SPAN] pages.
fn validate_op(what: &str, op: &Op, lo: u64, hi: u64, max: usize) {
    let max = match op.form {
        Form::ReadAt | Form::ReadInto => 1,
        Form::ReadRangesInto => max,
    };
    assert!(
        (1..=max).contains(&op.ranges.len()),
        "invalid input: {what} has {} ranges",
        op.ranges.len()
    );
    let mut next = lo;
    for &(offset, len) in &op.ranges {
        assert!(len >= 1, "invalid input: {what} has an empty range");
        assert!(
            offset >= next && offset.checked_add(len as u64).is_some_and(|e| e <= hi),
            "invalid input: {what} range ({offset}, {len}) is out of order or outside {lo}..{hi}"
        );
        next = offset + len as u64;
    }
    let first = op.ranges[0].0 / PAGE_SIZE;
    let last = (next - 1) / PAGE_SIZE;
    assert!(
        last - first < MAX_SPAN,
        "invalid input: {what} touches pages {first} to {last}"
    );
}

/// Panic on an input outside the bounds or against SR-R4.
fn validate(input: &FuzzInput) {
    let pages = input.pages;
    assert!(
        (MIN_PAGES..=MAX_PAGES).contains(&pages),
        "invalid input: {pages} pages"
    );
    assert!(
        input.cache_pages >= 1 && (input.cache_pages as u64) < pages,
        "invalid input: {} cache pages for {pages} pages",
        input.cache_pages
    );
    let opening = &input.opening;
    assert!(
        opening.page < pages,
        "invalid input: opening page {}",
        opening.page
    );
    let (lo, hi) = (opening.page * PAGE_SIZE, (opening.page + 1) * PAGE_SIZE);
    assert!(
        opening.first.form != Form::ReadRangesInto,
        "invalid input: read A is read_ranges_into"
    );
    validate_op("read A", &opening.first, lo, hi, 1);
    assert!(!opening.second.drop, "invalid input: read B is flagged");
    validate_op("read B", &opening.second, lo, hi, MAX_OPENING_RANGES);
    assert!(
        (MIN_READERS..=MAX_READERS).contains(&input.readers.len()),
        "invalid input: {} readers",
        input.readers.len()
    );
    for (reader, ops) in input.readers.iter().enumerate() {
        assert!(
            (MIN_OPS..=MAX_OPS).contains(&ops.len()),
            "invalid input: reader {reader} has {} operations",
            ops.len()
        );
        for (index, op) in ops.iter().enumerate() {
            let what = format!("reader {reader} operation {index}");
            validate_op(&what, op, 0, pages * PAGE_SIZE, MAX_RANGES);
        }
    }
}

/// The model's bytes of `ranges`, back to back.
fn expected(ranges: &[(u64, usize)]) -> Vec<u8> {
    ranges
        .iter()
        .flat_map(|&(offset, len)| (offset..offset + len as u64).map(value))
        .collect()
}

/// The logical offset of byte `index` of the concatenation of `ranges`. An index past the end
/// counts on from the end of the last range.
fn offset_of(ranges: &[(u64, usize)], mut index: usize) -> u64 {
    for &(offset, len) in ranges {
        if index < len {
            return offset + index as u64;
        }
        index -= len;
    }
    let (offset, len) = ranges[ranges.len() - 1];
    offset + (len + index) as u64
}

/// Shared counts of backend reads, by physical page.
type Counts = Arc<Mutex<BTreeMap<u64, usize>>>;

/// A [Blob] that counts its backend reads (SR-R13): every `read_at` and `read_at_buf` adds one
/// to the count of each physical page its range touches, then forwards the call. Every other call
/// is forwarded unchanged.
pub struct Counter {
    blob: deterministic::Blob,
    counts: Counts,
}

impl Counter {
    /// Count the reads of `blob`, starting from no reads.
    pub fn new(blob: deterministic::Blob) -> Self {
        Self {
            blob,
            counts: Arc::default(),
        }
    }

    /// The reads counted so far, by physical page. A page never read has no entry.
    pub fn counts(&self) -> BTreeMap<u64, usize> {
        self.counts.lock().clone()
    }

    fn count(&self, offset: u64, len: usize) {
        if len == 0 {
            return;
        }
        let first = offset / PHYSICAL_PAGE_SIZE;
        let last = (offset + len as u64 - 1) / PHYSICAL_PAGE_SIZE;
        let mut counts = self.counts.lock();
        for page in first..=last {
            *counts.entry(page).or_default() += 1;
        }
    }
}

impl Blob for Counter {
    fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send {
        self.count(offset, len);
        self.blob.read_at_buf(offset, len, bufs, options)
    }

    fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send {
        self.count(offset, len);
        self.blob.read_at(offset, len, options)
    }

    fn read_many(
        &self,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> impl futures::Stream<Item = Result<(usize, IoBufsMut), Error>> + Send {
        self.blob.read_many(ranges, options)
    }

    fn start_read_many(
        &self,
        ranges: &[(u64, usize)],
        options: ReadOptions,
    ) -> impl Future<Output = Handle<Vec<IoBufsMut>>> + Send {
        self.blob.start_read_many(ranges, options)
    }

    fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        self.blob.write_at(offset, bufs, options)
    }

    fn resize(&self, len: u64) -> impl Future<Output = Result<(), Error>> + Send {
        self.blob.resize(len)
    }

    fn sync(&self) -> impl Future<Output = Result<(), Error>> + Send {
        self.blob.sync()
    }

    fn start_sync(&self) -> impl Future<Output = Handle<()>> + Send {
        self.blob.start_sync()
    }
}

/// One row of the invariants table that has a class. SR-I4 has none: its panic passes through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Invariant {
    I1,
    I2a,
    I2b,
    I3,
}

impl Invariant {
    /// Every row, in table order.
    pub const ALL: &'static [Self] = &[Self::I1, Self::I2a, Self::I2b, Self::I3];

    /// The row's id, such as `SR-I1`.
    pub const fn id(self) -> &'static str {
        match self {
            Self::I1 => "SR-I1",
            Self::I2a => "SR-I2a",
            Self::I2b => "SR-I2b",
            Self::I3 => "SR-I3",
        }
    }

    /// The failure class of the row.
    pub const fn class(self) -> Class {
        match self {
            Self::I1 => Class::ReadBytes,
            Self::I2a => Class::ReadIncomplete,
            Self::I2b => Class::ReadError,
            Self::I3 => Class::SingleFetchCount,
        }
    }
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
            /// The class tag, such as `read_bytes`.
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
    ReadIncomplete => read_incomplete,
    ReadError => read_error,
    SingleFetchCount => single_fetch_count,
}

/// A read of the opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Opener {
    A,
    B,
}

/// Where a reader was when the deadline won.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderState {
    /// The free phase had not started.
    NotStarted,
    /// On the operation with this index.
    At(usize),
    Finished,
}

/// Where a violation happened (SR-R14). A trace record has one of the first two kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Location {
    /// A read of the opening. `drop` is the drop flag of read A, and `None` for read B.
    Opening {
        read: Opener,
        form: Form,
        ranges: Vec<(u64, usize)>,
        drop: Option<bool>,
    },
    /// A read of the free phase.
    Reader {
        reader: usize,
        op: usize,
        form: Form,
        ranges: Vec<(u64, usize)>,
        drop: bool,
    },
    /// The opening as a whole, with its backend reads by physical page.
    OpeningCounts {
        page: u64,
        opening_reads: BTreeMap<u64, usize>,
    },
    /// The read phase when the deadline won.
    Deadline {
        opening_ended: bool,
        opening_pending: Vec<Opener>,
        readers: Vec<ReaderState>,
    },
}

/// How a read ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadResult {
    Cancelled,
    /// The error, formatted with `Debug`.
    Failed(String),
    /// The bytes the read returned, back to back.
    Completed(Vec<u8>),
}

/// One read that completed, failed or was cancelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub location: Location,
    pub result: ReadResult,
}

/// The reads of a run in the order they ended. A read still pending at the deadline has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trace {
    pub records: Vec<Record>,
}

/// The first byte of a read that differs from the model. `offset` is the logical offset of that
/// byte; past the expected length it counts on from the end of the last range, and the missing
/// side is `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    pub offset: u64,
    pub expected: Option<u8>,
    pub observed: Option<u8>,
}

/// The first violation of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub invariant: Invariant,
    pub class: Class,
    /// Whether a read of the run was cancelled before the violation.
    pub after_cancellation: bool,
    pub location: Location,
    /// The first differing byte, for SR-I1 only.
    pub mismatch: Option<Mismatch>,
}

/// The result of [run].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub trace: Trace,
    pub violation: Option<Violation>,
    /// The rows whose condition occurred and whose check passed (SR-R15).
    pub measured: BTreeSet<Invariant>,
    pub cancellations: usize,
    /// Backend reads of the opening, by physical page. When the opening did not end, the reads
    /// counted until the run stopped.
    pub opening_reads: BTreeMap<u64, usize>,
    /// Backend reads of the free phase, by physical page.
    pub run_reads: BTreeMap<u64, usize>,
}

/// A read, as [Event]s name it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadId {
    Opening(Opener),
    Reader { reader: usize, op: usize },
}

/// One step of a run, in the order [run_observed] saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The one runner of the run was created with this configuration.
    Runner {
        cycle: Duration,
        timeout: Option<Duration>,
        catch_panics: bool,
    },
    /// The blob was opened with this size.
    Opened {
        partition: String,
        size: u64,
    },
    /// The model bytes were appended with one call of this length.
    Appended {
        len: usize,
    },
    /// The writer was sealed; `size` is the sealed blob's size.
    Sealed {
        size: u64,
    },
    /// The sync handle of the seal resolved.
    Synced,
    /// The cache was cleared.
    Cleared,
    /// The read counts were reset; `residue` is what they held before.
    CountsReset {
        residue: BTreeMap<u64, usize>,
    },
    /// The read phase started, with the deadline armed.
    ReadPhaseStarted,
    /// The future of a read was created.
    Created(ReadId),
    /// The future of a read was polled once by hand.
    Polled {
        read: ReadId,
        ready: bool,
    },
    /// The pending future of a flagged read was dropped.
    Dropped(ReadId),
    /// The future of a read is awaited.
    Awaited(ReadId),
    /// The future of a read resolved.
    Resolved {
        read: ReadId,
        ok: bool,
    },
    OpeningEnded,
    /// A reader task was spawned.
    Spawned {
        reader: usize,
    },
    ReaderFinished {
        reader: usize,
    },
    /// The read phase ended before the deadline, with or without a violation.
    ReadPhaseEnded,
    /// The deadline won.
    Deadline,
}

/// Ends a task or a phase at the first violation; the violation itself is in [State].
struct Stop;

#[derive(Default)]
struct State {
    trace: Trace,
    violation: Option<Violation>,
    measured: BTreeSet<Invariant>,
    cancellations: usize,
    opening_ended: bool,
    opening_pending: BTreeSet<Opener>,
    opening_reads: Option<BTreeMap<u64, usize>>,
    free_started: bool,
    readers: Vec<ReaderState>,
}

impl State {
    fn violate(&mut self, invariant: Invariant, location: Location, mismatch: Option<Mismatch>) {
        self.violation = Some(Violation {
            invariant,
            class: invariant.class(),
            after_cancellation: self.cancellations > 0,
            location,
            mismatch,
        });
    }
}

struct Shared {
    state: Mutex<State>,
    log: Option<Mutex<Vec<Event>>>,
}

impl Shared {
    fn note(&self, event: impl FnOnce() -> Event) {
        if let Some(log) = &self.log {
            log.lock().push(event());
        }
    }

    fn stopped(&self) -> bool {
        self.state.lock().violation.is_some()
    }

    /// Record a cancelled read.
    fn cancel(&self, location: Location) -> Result<(), Stop> {
        let mut state = self.state.lock();
        if state.violation.is_some() {
            return Err(Stop);
        }
        state.cancellations += 1;
        state.trace.records.push(Record {
            location,
            result: ReadResult::Cancelled,
        });
        Ok(())
    }

    /// Record a resolved read and judge it (SR-I1, SR-I2b).
    fn check(
        &self,
        location: Location,
        ranges: &[(u64, usize)],
        result: Result<Vec<u8>, Error>,
    ) -> Result<(), Stop> {
        let mut state = self.state.lock();
        if state.violation.is_some() {
            return Err(Stop);
        }
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(err) => {
                state.trace.records.push(Record {
                    location: location.clone(),
                    result: ReadResult::Failed(format!("{err:?}")),
                });
                state.violate(Invariant::I2b, location, None);
                return Err(Stop);
            }
        };
        state.measured.insert(Invariant::I2b);
        let expected = expected(ranges);
        let differs = (0..expected.len().max(bytes.len()))
            .find(|&i| expected.get(i) != bytes.get(i))
            .map(|i| Mismatch {
                offset: offset_of(ranges, i),
                expected: expected.get(i).copied(),
                observed: bytes.get(i).copied(),
            });
        state.trace.records.push(Record {
            location: location.clone(),
            result: ReadResult::Completed(bytes),
        });
        if let Some(mismatch) = differs {
            state.violate(Invariant::I1, location, Some(mismatch));
            return Err(Stop);
        }
        state.measured.insert(Invariant::I1);
        Ok(())
    }
}

/// Make the read `op` describes and return its bytes back to back.
async fn perform<B: Blob>(sealed: &Sealed<B>, op: &Op) -> Result<Vec<u8>, Error> {
    match op.form {
        Form::ReadAt => {
            let (offset, len) = op.ranges[0];
            Ok(sealed
                .read_at(offset, len)
                .await?
                .coalesce()
                .as_ref()
                .to_vec())
        }
        Form::ReadInto => {
            let (offset, len) = op.ranges[0];
            let mut buf = vec![0; len];
            sealed.read_into(&mut buf, offset).await?;
            Ok(buf)
        }
        Form::ReadRangesInto => {
            let mut buf = vec![0; op.ranges.iter().map(|&(_, len)| len).sum()];
            sealed.read_ranges_into(&mut buf, &op.ranges).await?;
            Ok(buf)
        }
    }
}

fn opening_location(read: Opener, op: &Op) -> Location {
    Location::Opening {
        read,
        form: op.form,
        ranges: op.ranges.clone(),
        drop: (read == Opener::A).then_some(op.drop),
    }
}

/// The opening (SR-R9), then the check of its backend reads (SR-I3).
async fn opening<B: Blob>(
    sealed: &Sealed<B>,
    opening: &Opening,
    shared: &Shared,
    counts: &Counts,
) -> Result<(), Stop> {
    let (op_a, op_b) = (&opening.first, &opening.second);
    let (id_a, id_b) = (ReadId::Opening(Opener::A), ReadId::Opening(Opener::B));
    let resolved = |read: Opener, ok: bool| {
        shared.state.lock().opening_pending.remove(&read);
        shared.note(|| Event::Resolved {
            read: ReadId::Opening(read),
            ok,
        });
    };

    shared.state.lock().opening_pending.insert(Opener::A);
    let mut a = Some(Box::pin(perform(sealed, op_a)));
    shared.note(|| Event::Created(id_a));
    let first_a = poll!(a.as_mut().unwrap());
    shared.note(|| Event::Polled {
        read: id_a,
        ready: first_a.is_ready(),
    });
    let a_pending = first_a.is_pending();
    if let Poll::Ready(result) = first_a {
        a = None;
        resolved(Opener::A, result.is_ok());
        shared.check(opening_location(Opener::A, op_a), &op_a.ranges, result)?;
    }

    shared.state.lock().opening_pending.insert(Opener::B);
    let mut b = Some(Box::pin(perform(sealed, op_b)));
    shared.note(|| Event::Created(id_b));
    let first_b = poll!(b.as_mut().unwrap());
    shared.note(|| Event::Polled {
        read: id_b,
        ready: first_b.is_ready(),
    });
    if let Poll::Ready(result) = first_b {
        b = None;
        resolved(Opener::B, result.is_ok());
        shared.check(opening_location(Opener::B, op_b), &op_b.ranges, result)?;
    }

    if a_pending && op_a.drop {
        drop(a.take());
        shared.state.lock().opening_pending.remove(&Opener::A);
        shared.note(|| Event::Dropped(id_a));
        shared.cancel(opening_location(Opener::A, op_a))?;
    }
    if let Some(b) = b {
        shared.note(|| Event::Awaited(id_b));
        let result = b.await;
        resolved(Opener::B, result.is_ok());
        shared.check(opening_location(Opener::B, op_b), &op_b.ranges, result)?;
    }
    if let Some(a) = a {
        shared.note(|| Event::Awaited(id_a));
        let result = a.await;
        resolved(Opener::A, result.is_ok());
        shared.check(opening_location(Opener::A, op_a), &op_a.ranges, result)?;
    }

    let reads = counts.lock().clone();
    let mut state = shared.state.lock();
    state.opening_ended = true;
    state.opening_reads = Some(reads.clone());
    shared.note(|| Event::OpeningEnded);
    if a_pending {
        if reads.get(&opening.page).copied().unwrap_or(0) != 1 {
            let location = Location::OpeningCounts {
                page: opening.page,
                opening_reads: reads,
            };
            state.violate(Invariant::I3, location, None);
            return Err(Stop);
        }
        state.measured.insert(Invariant::I3);
    }
    Ok(())
}

/// One reader of the free phase (SR-R10).
async fn reader<B: Blob>(
    index: usize,
    sealed: Sealed<B>,
    ops: Vec<Op>,
    shared: Arc<Shared>,
) -> Result<(), Stop> {
    for (i, op) in ops.iter().enumerate() {
        if shared.stopped() {
            return Err(Stop);
        }
        shared.state.lock().readers[index] = ReaderState::At(i);
        let id = ReadId::Reader {
            reader: index,
            op: i,
        };
        let location = Location::Reader {
            reader: index,
            op: i,
            form: op.form,
            ranges: op.ranges.clone(),
            drop: op.drop,
        };
        let mut read = Box::pin(perform(&sealed, op));
        shared.note(|| Event::Created(id));
        if op.drop {
            let first = poll!(read.as_mut());
            shared.note(|| Event::Polled {
                read: id,
                ready: first.is_ready(),
            });
            match first {
                Poll::Ready(result) => {
                    shared.note(|| Event::Resolved {
                        read: id,
                        ok: result.is_ok(),
                    });
                    shared.check(location, &op.ranges, result)?;
                }
                Poll::Pending => {
                    drop(read);
                    shared.note(|| Event::Dropped(id));
                    shared.cancel(location)?;
                }
            }
        } else {
            shared.note(|| Event::Awaited(id));
            let result = read.await;
            shared.note(|| Event::Resolved {
                read: id,
                ok: result.is_ok(),
            });
            shared.check(location, &op.ranges, result)?;
        }
    }
    shared.state.lock().readers[index] = ReaderState::Finished;
    shared.note(|| Event::ReaderFinished { reader: index });
    Ok(())
}

/// Spawn every reader in one turn, then await them all, stopping at the first violation.
async fn free_phase<B: Blob>(
    context: &deterministic::Context,
    sealed: &Sealed<B>,
    readers: &[Vec<Op>],
    shared: &Arc<Shared>,
) -> Result<(), Stop> {
    {
        let mut state = shared.state.lock();
        state.free_started = true;
        state.readers = vec![ReaderState::At(0); readers.len()];
    }
    let mut handles = FuturesUnordered::new();
    for (index, ops) in readers.iter().enumerate() {
        let (sealed, ops, task_shared) = (sealed.clone(), ops.clone(), shared.clone());
        handles.push(
            context
                .child("reader")
                .with_attribute("index", index)
                .spawn(move |_| reader(index, sealed, ops, task_shared)),
        );
        shared.note(|| Event::Spawned { reader: index });
    }
    while let Some(result) = handles.next().await {
        result.expect("reader task ended without a result")?;
    }
    Ok(())
}

/// Open, fill, seal and sync the blob, then clear the cache and the counts (SR-R3).
async fn construct<S: Blob>(
    context: &deterministic::Context,
    input: &FuzzInput,
    seam: impl FnOnce(Counter) -> S,
    shared: &Shared,
) -> (Sealed<MigratingReadBlob<S>>, Counts) {
    let (blob, size) = context.open(PARTITION, BLOB).await.expect("open the blob");
    shared.note(|| Event::Opened {
        partition: PARTITION.to_string(),
        size,
    });
    assert_eq!(size, 0, "the blob is not new");
    let counter = Counter::new(blob);
    let counts = counter.counts.clone();
    let blob = MigratingReadBlob::new(seam(counter), false);

    let page_size = NonZeroU16::new(PAGE_SIZE as u16).unwrap();
    let cache_pages = NonZeroUsize::new(input.cache_pages).unwrap();
    let cache = CacheRef::new(page_size, cache_pages);
    let writer = Writer::new(blob, 0, WRITE_BUFFER, cache.clone())
        .await
        .expect("create the writer");
    let model: Vec<u8> = (0..input.pages * PAGE_SIZE).map(value).collect();
    let (writer, _) = writer.append(&model).await.expect("append the pages");
    shared.note(|| Event::Appended { len: model.len() });
    let (sealed, sync) = writer.seal().await.expect("seal the blob");
    shared.note(|| Event::Sealed {
        size: sealed.size(),
    });
    sync.await.expect("sync the sealed blob");
    shared.note(|| Event::Synced);
    assert_eq!(
        sealed.size(),
        input.pages * PAGE_SIZE,
        "sealed size differs from the pages appended"
    );
    cache.clear();
    shared.note(|| Event::Cleared);
    let residue = std::mem::take(&mut *counts.lock());
    shared.note(|| Event::CountsReset { residue });
    (sealed, counts)
}

fn execute<S: Blob>(
    input: &FuzzInput,
    seam: impl FnOnce(Counter) -> S,
    log: Option<Mutex<Vec<Event>>>,
) -> (Outcome, Vec<Event>) {
    validate(input);
    let shared = Arc::new(Shared {
        state: Mutex::default(),
        log,
    });
    let cfg = deterministic::Config::new().with_rng(FuzzRng::from(input.entropy.clone()));
    shared.note(|| Event::Runner {
        cycle: cfg.cycle(),
        timeout: cfg.timeout(),
        catch_panics: cfg.catch_panics(),
    });
    let runner = deterministic::Runner::new(cfg);
    let run_shared = shared.clone();
    let counts = runner.start(|context| async move {
        let shared = run_shared;
        let (sealed, counts) = construct(&context, input, seam, &shared).await;

        shared.note(|| Event::ReadPhaseStarted);
        let phase = pin!(async {
            opening(&sealed, &input.opening, &shared, &counts).await?;
            free_phase(&context, &sealed, &input.readers, &shared).await
        });
        let deadline = pin!(context.sleep(DEADLINE));
        match select(phase, deadline).await {
            Either::Left((result, _)) => {
                shared.note(|| Event::ReadPhaseEnded);
                if result.is_ok() {
                    shared.state.lock().measured.insert(Invariant::I2a);
                }
            }
            Either::Right(_) => {
                shared.note(|| Event::Deadline);
                let mut state = shared.state.lock();
                if state.violation.is_none() {
                    let location = Location::Deadline {
                        opening_ended: state.opening_ended,
                        opening_pending: state.opening_pending.iter().copied().collect(),
                        readers: if state.free_started {
                            state.readers.clone()
                        } else {
                            vec![ReaderState::NotStarted; input.readers.len()]
                        },
                    };
                    state.violate(Invariant::I2a, location, None);
                }
            }
        }
        counts.lock().clone()
    });

    let mut state = std::mem::take(&mut *shared.state.lock());
    let (opening_reads, run_reads) = match state.opening_reads.take() {
        Some(opening_reads) if state.free_started => {
            let run_reads = counts
                .into_iter()
                .filter_map(|(page, n)| {
                    let n = n - opening_reads.get(&page).copied().unwrap_or(0);
                    (n > 0).then_some((page, n))
                })
                .collect();
            (opening_reads, run_reads)
        }
        Some(opening_reads) => (opening_reads, BTreeMap::new()),
        None => (counts, BTreeMap::new()),
    };
    let events = shared
        .log
        .as_ref()
        .map(|log| std::mem::take(&mut *log.lock()))
        .unwrap_or_default();
    let outcome = Outcome {
        trace: state.trace,
        violation: state.violation,
        measured: state.measured,
        cancellations: state.cancellations,
        opening_reads,
        run_reads,
    };
    (outcome, events)
}

/// Run `input` with `MigratingReadBlob::new(seam(counter), false)` as the blob and return its
/// trace, its first violation and what it measured. A panic raised by the code under test, by the
/// seam, or by an input outside the bounds passes through.
pub fn run<S: Blob>(input: &FuzzInput, seam: impl FnOnce(Counter) -> S) -> Outcome {
    execute(input, seam, None).0
}

/// [run], and the steps of the run in the order they happened.
pub fn run_observed<S: Blob>(
    input: &FuzzInput,
    seam: impl FnOnce(Counter) -> S,
) -> (Outcome, Vec<Event>) {
    execute(input, seam, Some(Mutex::default()))
}

/// Records of the trace a failure report shows.
const REPORT_RECORDS: usize = 8;

fn report(input: &FuzzInput, outcome: &Outcome, violation: &Violation) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} violated (after a cancellation: {}) at {:?}",
        violation.invariant.id(),
        violation.after_cancellation,
        violation.location
    );
    if let Some(mismatch) = &violation.mismatch {
        let _ = writeln!(out, "first differing byte: {mismatch:?}");
    }
    let _ = writeln!(
        out,
        "pages {}, cache pages {}, opening {:?}",
        input.pages, input.cache_pages, input.opening
    );
    for (reader, ops) in input.readers.iter().enumerate() {
        let _ = writeln!(out, "reader {reader}: {ops:?}");
    }
    let records = &outcome.trace.records;
    let skip = records.len().saturating_sub(REPORT_RECORDS);
    let _ = writeln!(
        out,
        "last {} of {} reads:",
        records.len() - skip,
        records.len()
    );
    for record in &records[skip..] {
        let _ = writeln!(out, "  {record:?}");
    }
    out
}

/// Run `input` with the identity seam and panic on a violation.
pub fn fuzz(input: FuzzInput) {
    let outcome = run(&input, |counter| counter);
    if let Some(violation) = &outcome.violation {
        violation.class.fail(&report(&input, &outcome, violation));
    }
}
