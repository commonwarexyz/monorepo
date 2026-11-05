//! A segmented append log: fixed-width index rows that locate values in per-segment blobs.
//!
//! Positions are global append sequence numbers: segment `s` holds positions
//! `[s * capacity, (s + 1) * capacity)`, and a position is never reused. Each segment is its own
//! index and value journal pair, so a segment is reclaimed by removing its partitions. A durable
//! manifest names the segments; a segment it does not name is residue, reset before reuse.
//!
//! # Jobs
//!
//! The owner never awaits storage. Every mutation is a job that borrows what it needs from the
//! log and hands it back when the owner finishes it, and at most one job runs per log at a time:
//!
//! - [`Log::start_append`] appends rows to the current segment, opening it first when the
//!   previous one filled.
//! - [`Log::start_cut`] flushes every dirty segment and the manifest, closes segments that filled,
//!   and captures snapshot readers. Positions below the cut become durable when the returned
//!   [`Durability`] completes, which does not hold the log: appends continue meanwhile.
//! - [`Log::start_reclaim`] removes segments with no live row, after the manifest stops naming
//!   them.
//!
//! # Reads
//!
//! Values are read through cloneable [`Reader`]s, off the owner. A position is readable once a
//! cut covering it started. The log holds one snapshot per readable segment it has captured or
//! opened, opening a segment it does not hold through one [`OpenJob`] at a time, and every
//! [`Reader`] it hands out pins its segment against reclamation until it is dropped.

use super::{Buffers, Error, record::DurableRecord};
use bytes::BufMut;
use commonware_codec::{
    Buf, CodecShared, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_runtime::{Handle, ReadOptions, Storage};
use commonware_storage::{
    Context,
    journal::{
        self,
        segmented::{
            glob,
            oversized::{self, Oversized, Record},
        },
    },
};
use commonware_utils::futures::try_join_all;
use futures::{FutureExt as _, future::BoxFuture};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

/// Version byte leading every encoded [`Manifest`].
const MANIFEST_VERSION: u8 = 1;

/// Partition family holding a segment's index rows.
const INDEX: &str = "index";
/// Partition family holding a segment's values.
const VALUES: &str = "values";
/// Partition family holding a segment's recovery markers.
const MARKERS: &str = "markers";

/// Segments removed concurrently by one reclamation.
const REMOVE_BATCH: usize = 16;

/// A segment's index and value journals.
type Journal<E, I, V> = Oversized<E, I, V>;

/// A frozen, cloneable view of one segment's values.
pub(crate) type Snapshot<E, V> = glob::Reader<<E as Storage>::Blob, V>;

/// Construction inputs for a [`Log`].
pub(crate) struct Config<C> {
    /// Prefix from which every partition of the log is derived.
    pub(crate) prefix: String,
    /// Journal buffers and page cache.
    pub(crate) buffers: Buffers,
    /// Codec configuration of the values.
    pub(crate) codec: C,
    /// Positions in each segment; fixed when the log is created.
    pub(crate) segment_capacity: NonZeroU64,
    /// Most segments the manifest may name.
    pub(crate) max_segments: NonZeroUsize,
}

/// The segments a log retains.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Manifest {
    /// Positions in each segment.
    capacity: u64,
    /// Retained segments, strictly ascending.
    segments: Vec<u64>,
}

impl Write for Manifest {
    fn write(&self, buf: &mut impl BufMut) {
        MANIFEST_VERSION.write(buf);
        self.capacity.write(buf);
        self.segments.write(buf);
    }
}

impl EncodeSize for Manifest {
    fn encode_size(&self) -> usize {
        MANIFEST_VERSION.encode_size() + self.capacity.encode_size() + self.segments.encode_size()
    }
}

impl Read for Manifest {
    /// The most segments.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_segments: &usize) -> Result<Self, CodecError> {
        let version = u8::read(buf)?;
        if version != MANIFEST_VERSION {
            return Err(CodecError::InvalidEnum(version));
        }
        let capacity = u64::read(buf)?;
        let segments = Vec::<u64>::read_cfg(buf, &(RangeCfg::from(0..=*max_segments), ()))?;
        if segments.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(CodecError::Invalid(
                "consensus::multimmit::marshal::Manifest",
                "segments are not strictly ascending",
            ));
        }
        Ok(Self { capacity, segments })
    }
}

/// Everything needed to open one segment's journals or values, detached from the log.
struct Opener<E: Context, C> {
    context: E,
    config: oversized::Config<C>,
    markers: String,
    partitions: [String; 3],
    /// Whether the manifest named the segment before; an unnamed one is reset before use.
    named: bool,
    capacity: u64,
}

impl<E: Context, C: Clone + Send + Sync + 'static> Opener<E, C> {
    /// Opens the segment's journals, returning every recovered row in order.
    async fn open<I: Record, V: CodecShared<Cfg = C>>(
        self,
    ) -> Result<(Journal<E, I, V>, Vec<I>), Error> {
        if !self.named {
            remove_partitions(&self.context, &self.partitions).await?;
        }
        let mut replay = Journal::<E, I, V>::init_with_metadata(
            self.context,
            self.config,
            self.markers,
            ReadOptions::default(),
        )
        .await?;
        let mut rows = Vec::new();
        let mut end = 0u64;
        while let Some(row) = replay.next().await {
            let (section, position, row) = row?;
            if section != 0 || position != rows.len() as u64 || position >= self.capacity {
                return Err(Error::Inconsistent("log segment bounds are invalid"));
            }
            let (offset, size) = row.value_location();
            if offset != end {
                return Err(Error::Inconsistent("log value location is invalid"));
            }
            end = offset
                .checked_add(u64::from(size))
                .ok_or(Error::Inconsistent("log value location overflows"))?;
            rows.push(row);
        }
        Ok((replay.finish_tracked().await?, rows))
    }
}

/// Removes every partition of a segment, ignoring the ones already missing.
async fn remove_partitions<E: Context>(context: &E, partitions: &[String]) -> Result<(), Error> {
    for partition in partitions {
        match context.remove(partition, None).await {
            Ok(()) | Err(commonware_runtime::Error::PartitionMissing(_)) => {}
            Err(error) => return Err(journal::Error::from(error).into()),
        }
    }
    Ok(())
}

/// A reader of one segment's values that pins the segment while it lives.
pub(crate) struct Reader<E: Context, V: CodecShared> {
    snapshot: Snapshot<E, V>,
    _pin: Arc<()>,
}

impl<E: Context, V: CodecShared> Clone for Reader<E, V> {
    fn clone(&self) -> Self {
        Self {
            snapshot: self.snapshot.clone(),
            _pin: Arc::clone(&self._pin),
        }
    }
}

impl<E: Context, V: CodecShared> Reader<E, V> {
    /// Reads the value at `(offset, size)`.
    pub(crate) async fn get(&self, offset: u64, size: u32) -> Result<V, Error> {
        Ok(self.snapshot.get(offset, size).await?)
    }
}

/// How the value at a position can be read.
pub(crate) enum Access<E: Context, V: CodecShared> {
    /// Through this reader.
    Ready(Reader<E, V>),
    /// Once this job opens the segment and [`Log::finish_open`] installs it.
    Open(OpenJob<E, V>),
    /// Once the open already in flight is installed.
    Opening,
    /// Not until a cut covers the position.
    Uncut,
}

/// An open of one segment's values the log holds no snapshot of.
pub(crate) struct OpenJob<E: Context, V: CodecShared> {
    segment: u64,
    context: E,
    config: glob::Config<V::Cfg>,
}

/// A completed open, to hand back through [`Log::finish_open`].
pub(crate) struct Opened<E: Context, V: CodecShared> {
    segment: u64,
    snapshot: Snapshot<E, V>,
}

impl<E: Context, V: CodecShared> Opened<E, V> {
    /// Returns a reader of the opened segment.
    ///
    /// The segment cannot be reclaimed while it is being opened, so the reader needs no pin of
    /// its own until the log installs the segment.
    pub(crate) fn reader(&self) -> Reader<E, V> {
        Reader {
            snapshot: self.snapshot.clone(),
            _pin: Arc::new(()),
        }
    }
}

impl<E: Context, V: CodecShared> OpenJob<E, V> {
    /// Opens the segment's values. It accepts no more appends, so it is opened alone.
    pub(crate) async fn run(self) -> Result<Opened<E, V>, Error> {
        Ok(Opened {
            segment: self.segment,
            snapshot: glob::Reader::open(&self.context, self.config, 0).await?,
        })
    }
}

/// An append of rows to one segment.
pub(crate) struct AppendJob<E: Context, I: Record, V: CodecShared> {
    segment: u64,
    first: u64,
    /// Segment-local index of the first row.
    local: u64,
    target: Target<E, I, V>,
    entries: Vec<(I, V)>,
}

/// The journal an append writes to.
enum Target<E: Context, I: Record, V: CodecShared> {
    Open(Journal<E, I, V>),
    Closed(Opener<E, V::Cfg>),
}

/// A completed append, to hand back through [`Log::finish_append`].
pub(crate) struct Appended<E: Context, I: Record, V: CodecShared> {
    segment: u64,
    first: u64,
    journal: Journal<E, I, V>,
    rows: Vec<I>,
}

impl<E: Context, I: Record, V: CodecShared> AppendJob<E, I, V> {
    /// Appends the rows and their values.
    pub(crate) async fn run(self) -> Result<Appended<E, I, V>, Error> {
        let journal = match self.target {
            Target::Open(journal) => journal,
            Target::Closed(opener) => {
                let (journal, rows) = opener.open::<I, V>().await?;
                if !rows.is_empty() {
                    return Err(Error::Inconsistent("a new log segment holds rows"));
                }
                journal
            }
        };
        if segment_len(&journal)? != self.local {
            return Err(Error::Inconsistent(
                "log segment does not match the append position",
            ));
        }
        let count = self.entries.len() as u64;
        let (journal, last, locations) = journal
            .append_many(
                0,
                self.entries.iter().map(|(row, value)| (row.clone(), value)),
            )
            .await?;
        if last != self.local + count - 1 {
            return Err(Error::Inconsistent(
                "log segment assigned an unexpected position",
            ));
        }
        let rows = self
            .entries
            .into_iter()
            .zip(locations)
            .map(|((row, _), (offset, size))| row.with_location(offset, size))
            .collect();
        Ok(Appended {
            segment: self.segment,
            first: self.first,
            journal,
            rows,
        })
    }
}

/// Returns the number of rows appended to a segment.
fn segment_len<E: Context, I: Record, V: CodecShared>(
    journal: &Journal<E, I, V>,
) -> Result<u64, Error> {
    match journal.size(0) {
        Ok(size) => Ok(size / I::SIZE as u64),
        Err(journal::Error::SectionOutOfRange(_)) => Ok(0),
        Err(error) => Err(error.into()),
    }
}

/// A cut: flushes the dirty segments and the manifest.
pub(crate) struct CutJob<E: Context, I: Record, V: CodecShared> {
    end: u64,
    /// The current segment, when dirty.
    current: Option<(u64, Journal<E, I, V>)>,
    /// Full segments, closed by this cut.
    sealed: Vec<(u64, Journal<E, I, V>)>,
    manifest: Option<DurableRecord<E, Manifest>>,
}

/// A segment's journal and the snapshot a cut captured of it.
type Captured<E, I, V> = (u64, Journal<E, I, V>, Snapshot<E, V>);

/// A started cut, to hand back through [`Log::finish_cut`].
pub(crate) struct CutStarted<E: Context, I: Record, V: CodecShared> {
    end: u64,
    current: Option<Captured<E, I, V>>,
    sealed: Vec<(u64, Snapshot<E, V>)>,
    manifest: Option<DurableRecord<E, Manifest>>,
    handles: Vec<Handle<()>>,
}

impl<E: Context, I: Record, V: CodecShared> CutJob<E, I, V> {
    /// Flushes every dirty segment and the manifest, and closes the full segments.
    pub(crate) async fn run(self) -> Result<CutStarted<E, I, V>, Error> {
        let Self {
            end,
            current,
            sealed,
            manifest,
        } = self;
        let current = async move {
            match current {
                Some((segment, journal)) => {
                    let (journal, handle) = journal.start_sync(0).await?;
                    let snapshot = journal.capture(0)?;
                    Ok::<_, Error>(Some((segment, journal, snapshot, handle)))
                }
                None => Ok(None),
            }
        };
        let sealed = try_join_all(sealed.into_iter().map(|(segment, journal)| async move {
            let (journal, _) = journal.start_sync(0).await?;
            let snapshot = journal.capture(0)?;
            journal.close().await?;
            Ok::<_, Error>((segment, snapshot))
        }));
        let manifest = async move {
            match manifest {
                Some(mut manifest) => {
                    let handle = manifest.start_sync().await?;
                    Ok::<_, Error>(Some((manifest, handle)))
                }
                None => Ok(None),
            }
        };
        let (current, sealed, manifest) = futures::try_join!(current, sealed, manifest)?;
        let mut handles = Vec::with_capacity(2);
        let current = current.map(|(segment, journal, snapshot, handle)| {
            handles.push(handle);
            (segment, journal, snapshot)
        });
        let manifest = manifest.map(|(manifest, handle)| {
            handles.push(handle);
            manifest
        });
        Ok(CutStarted {
            end,
            current,
            sealed,
            manifest,
            handles,
        })
    }
}

/// Completes with the end of a cut once every position below it is durable.
pub(crate) type Durability = BoxFuture<'static, Result<u64, Error>>;

/// A reclamation: unnames segments in the manifest, then removes them.
pub(crate) struct ReclaimJob<E: Context> {
    context: E,
    segments: Vec<u64>,
    partitions: Vec<[String; 3]>,
    manifest: DurableRecord<E, Manifest>,
    named: Manifest,
}

/// A completed reclamation, to hand back through [`Log::finish_reclaim`].
pub(crate) struct Reclaimed<E: Context> {
    segments: Vec<u64>,
    manifest: DurableRecord<E, Manifest>,
}

impl<E: Context> ReclaimJob<E> {
    /// Persists the manifest without the segments, then removes their partitions.
    ///
    /// A crash between the two leaves unnamed residue, which reuse would reset; segment
    /// identifiers are never reused, so the residue is never read.
    pub(crate) async fn run(mut self) -> Result<Reclaimed<E>, Error> {
        self.manifest.put_sync(self.named).await?;
        for batch in self.partitions.chunks(REMOVE_BATCH) {
            try_join_all(
                batch
                    .iter()
                    .map(|partitions| remove_partitions(&self.context, partitions)),
            )
            .await?;
        }
        Ok(Reclaimed {
            segments: self.segments,
            manifest: self.manifest,
        })
    }
}

/// A storage job of one log.
pub(crate) enum Job<E: Context, I: Record, V: CodecShared> {
    /// An append.
    Append(AppendJob<E, I, V>),
    /// A cut.
    Cut(CutJob<E, I, V>),
    /// A reclamation.
    Reclaim(ReclaimJob<E>),
}

/// A completed storage job, to hand back to the log that issued it.
pub(crate) enum Done<E: Context, I: Record, V: CodecShared> {
    /// An append.
    Append(Appended<E, I, V>),
    /// A started cut.
    Cut(CutStarted<E, I, V>),
    /// A reclamation.
    Reclaim(Reclaimed<E>),
}

impl<E: Context, I: Record, V: CodecShared> Job<E, I, V> {
    /// Runs the job.
    pub(crate) async fn run(self) -> Result<Done<E, I, V>, Error> {
        match self {
            Self::Append(job) => job.run().await.map(Done::Append),
            Self::Cut(job) => job.run().await.map(Done::Cut),
            Self::Reclaim(job) => job.run().await.map(Done::Reclaim),
        }
    }
}

/// What finishing a job produced.
pub(crate) enum Finished<I> {
    /// Rows appended at these positions, not yet durable.
    Appended(Vec<(u64, I)>),
    /// A cut whose durability completes with its end.
    Cut(Durability),
    /// Segments were reclaimed.
    Reclaimed,
}

/// A segmented append log.
pub(crate) struct Log<E: Context, I: Record, V: CodecShared> {
    context: E,
    prefix: String,
    buffers: Buffers,
    codec: V::Cfg,
    capacity: u64,
    /// Absent while a job holds it.
    manifest: Option<DurableRecord<E, Manifest>>,
    /// Whether the manifest changed since the last cut started.
    manifest_dirty: bool,
    /// Segments the manifest names, including ones staged for the next cut.
    segments: BTreeSet<u64>,
    /// The current segment's journal; absent while a job holds it or before the segment opens.
    current: Option<Journal<E, I, V>>,
    /// Full segments with appends no cut covers yet.
    sealed: BTreeMap<u64, Journal<E, I, V>>,
    /// Whether the current segment has appends no cut covers yet.
    current_dirty: bool,
    /// Snapshots held for reads, each with the pin its readers share.
    snapshots: BTreeMap<u64, (Snapshot<E, V>, Arc<()>)>,
    /// Segments whose values an [`OpenJob`] is opening.
    opening: BTreeSet<u64>,
    /// Live rows per segment.
    live: BTreeMap<u64, u64>,
    /// Next position.
    next: u64,
    /// Positions below this are covered by a started cut, so readable.
    captured: u64,
    /// Positions below this are durable.
    durable: u64,
    /// Whether a job holds part of the log.
    busy: bool,
}

impl<E, I, V> Log<E, I, V>
where
    E: Context,
    I: Record,
    V: CodecShared,
{
    /// Opens the log and returns every recovered row with its position, in position order.
    ///
    /// Every recovered row starts live; the caller releases the ones it does not keep.
    pub(crate) async fn open(
        context: E,
        config: Config<V::Cfg>,
    ) -> Result<(Self, Vec<(u64, I)>), Error> {
        let Config {
            prefix,
            buffers,
            codec,
            segment_capacity,
            max_segments,
        } = config;
        let mut manifest = DurableRecord::init(
            context.child("manifest"),
            format!("{prefix}_manifest"),
            max_segments.get(),
            None,
        )
        .await?;
        let named = match manifest.get()?.cloned() {
            Some(named) => named,
            None => {
                let named = Manifest {
                    capacity: segment_capacity.get(),
                    segments: Vec::new(),
                };
                manifest.put_sync(named.clone()).await?;
                named
            }
        };
        if named.capacity != segment_capacity.get() {
            return Err(Error::Inconsistent(
                "log segment capacity differs from storage",
            ));
        }
        let mut log = Self {
            context,
            prefix,
            buffers,
            codec,
            capacity: segment_capacity.get(),
            manifest: Some(manifest),
            manifest_dirty: false,
            segments: named.segments.iter().copied().collect(),
            current: None,
            sealed: BTreeMap::new(),
            current_dirty: false,
            snapshots: BTreeMap::new(),
            opening: BTreeSet::new(),
            live: BTreeMap::new(),
            next: 0,
            captured: 0,
            durable: 0,
            busy: false,
        };

        let mut rows = Vec::new();
        let last = named.segments.last().copied();
        for segment in named.segments {
            let start = segment
                .checked_mul(log.capacity)
                .ok_or(Error::Inconsistent("log position overflows"))?;
            let (journal, recovered) = log.opener(segment).open::<I, V>().await?;
            let count = recovered.len() as u64;
            if count > 0 {
                log.live.insert(segment, count);
            }
            rows.extend((start..).zip(recovered));
            if Some(segment) == last {
                log.next = start + count;
                if count < log.capacity {
                    if count > 0 {
                        let (journal, snapshot) = journal.value_snapshot(0).await?;
                        log.snapshots.insert(segment, (snapshot, Arc::new(())));
                        log.current = Some(journal);
                    } else {
                        log.current = Some(journal);
                    }
                    continue;
                }
            }
            journal.close().await?;
        }
        log.captured = log.next;
        log.durable = log.next;
        Ok((log, rows))
    }

    /// Returns the next position.
    #[cfg(test)]
    pub(crate) const fn next(&self) -> u64 {
        self.next
    }

    /// Returns the end of the durable positions.
    pub(crate) const fn durable(&self) -> u64 {
        self.durable
    }

    /// Returns whether no job holds part of the log.
    pub(crate) const fn idle(&self) -> bool {
        !self.busy
    }

    /// Returns whether appends no started cut covers exist.
    pub(crate) fn dirty(&self) -> bool {
        self.current_dirty || !self.sealed.is_empty() || self.manifest_dirty
    }

    /// Returns how many rows the current segment still takes.
    pub(crate) const fn room(&self) -> u64 {
        self.capacity - self.next % self.capacity
    }

    /// Returns the segment holding `position`.
    pub(crate) const fn segment(&self, position: u64) -> u64 {
        position / self.capacity
    }

    /// Starts an append of `entries` at [`Self::next`].
    ///
    /// # Panics
    ///
    /// Panics if a job is running, or if `entries` is empty or exceeds [`Self::room`].
    pub(crate) fn start_append(&mut self, entries: Vec<(I, V)>) -> AppendJob<E, I, V> {
        assert!(!self.busy, "one job at a time");
        assert!(
            !entries.is_empty() && entries.len() as u64 <= self.room(),
            "an append fits the current segment"
        );
        let first = self.next;
        let segment = self.segment(first);
        let local = first % self.capacity;
        let target = match self.current.take() {
            Some(journal) => Target::Open(journal),
            None => {
                let opener = self.opener(segment);
                if self.segments.insert(segment) {
                    self.manifest_dirty = true;
                }
                Target::Closed(opener)
            }
        };
        self.busy = true;
        self.next += entries.len() as u64;
        AppendJob {
            segment,
            first,
            local,
            target,
            entries,
        }
    }

    /// Takes back a completed job.
    pub(crate) fn finish(&mut self, done: Done<E, I, V>) -> Finished<I> {
        match done {
            Done::Append(appended) => Finished::Appended(self.finish_append(appended)),
            Done::Cut(started) => Finished::Cut(self.finish_cut(started)),
            Done::Reclaim(reclaimed) => {
                self.finish_reclaim(reclaimed);
                Finished::Reclaimed
            }
        }
    }

    /// Takes back a completed append and returns its located rows with their positions.
    pub(crate) fn finish_append(&mut self, appended: Appended<E, I, V>) -> Vec<(u64, I)> {
        let Appended {
            segment,
            first,
            journal,
            rows,
        } = appended;
        self.busy = false;
        *self.live.entry(segment).or_default() += rows.len() as u64;
        if self.segment(self.next) == segment {
            self.current = Some(journal);
            self.current_dirty = true;
        } else {
            // The segment filled: the next cut closes it, and the next append opens its
            // successor.
            self.sealed.insert(segment, journal);
            self.current_dirty = false;
        }
        (first..).zip(rows).collect()
    }

    /// Starts a cut of every append so far, or returns `None` when nothing is dirty.
    ///
    /// # Panics
    ///
    /// Panics if a job is running.
    pub(crate) fn start_cut(&mut self) -> Result<Option<CutJob<E, I, V>>, Error> {
        assert!(!self.busy, "one job at a time");
        if !self.dirty() {
            return Ok(None);
        }
        let manifest = if self.manifest_dirty {
            let named = self.named();
            let manifest = self.manifest.as_mut().ok_or(Error::Poisoned)?;
            manifest.stage(named)?;
            self.manifest_dirty = false;
            self.manifest.take()
        } else {
            None
        };
        let current = if self.current_dirty {
            self.current_dirty = false;
            let journal = self
                .current
                .take()
                .expect("a dirty current segment is open");
            Some((self.segment(self.next), journal))
        } else {
            None
        };
        let sealed = std::mem::take(&mut self.sealed).into_iter().collect();
        self.busy = true;
        Ok(Some(CutJob {
            end: self.next,
            current,
            sealed,
            manifest,
        }))
    }

    /// Takes back a started cut and returns its durability.
    pub(crate) fn finish_cut(&mut self, started: CutStarted<E, I, V>) -> Durability {
        let CutStarted {
            end,
            current,
            sealed,
            manifest,
            handles,
        } = started;
        self.busy = false;
        if let Some((segment, journal, snapshot)) = current {
            self.hold(segment, snapshot);
            if self.segment(self.next) == segment {
                self.current = Some(journal);
            } else {
                // The segment filled after the cut started: the next cut closes it.
                self.sealed.insert(segment, journal);
            }
        }
        for (segment, snapshot) in sealed {
            self.hold(segment, snapshot);
        }
        if let Some(manifest) = manifest {
            self.manifest = Some(manifest);
        }
        self.captured = self.captured.max(end);
        async move {
            try_join_all(handles).await?;
            Ok(end)
        }
        .boxed()
    }

    /// Records that a cut ending at `end` is durable.
    pub(crate) fn mark_durable(&mut self, end: u64) {
        self.durable = self.durable.max(end);
    }

    /// Marks the row at `position` dead. A segment with no live row may be reclaimed.
    pub(crate) fn release(&mut self, position: u64) {
        let segment = self.segment(position);
        if let Some(live) = self.live.get_mut(&segment) {
            *live -= 1;
            if *live == 0 {
                self.live.remove(&segment);
            }
        }
    }

    /// Starts reclaiming every segment with no live row that no job or outside snapshot holds,
    /// or returns `None` when there is none.
    ///
    /// # Panics
    ///
    /// Panics if a job is running.
    pub(crate) fn start_reclaim(&mut self) -> Option<ReclaimJob<E>> {
        assert!(!self.busy, "one job at a time");
        let current = self.segment(self.next);
        let segments = self
            .segments
            .iter()
            .copied()
            .filter(|segment| {
                *segment != current
                    && !self.live.contains_key(segment)
                    && !self.sealed.contains_key(segment)
                    && !self.opening.contains(segment)
                    && self
                        .snapshots
                        .get(segment)
                        .is_none_or(|(_, pin)| Arc::strong_count(pin) == 1)
            })
            .collect::<Vec<_>>();
        if segments.is_empty() {
            return None;
        }
        for segment in &segments {
            self.segments.remove(segment);
            self.snapshots.remove(segment);
        }
        let Some(manifest) = self.manifest.take() else {
            unreachable!("the manifest is held while no job runs");
        };
        // The cut that names a segment precedes any reclamation of it, so this write never
        // unnames a staged segment early.
        self.manifest_dirty = false;
        self.busy = true;
        Some(ReclaimJob {
            context: self.context.child("reclaim"),
            partitions: segments
                .iter()
                .map(|segment| self.partitions(*segment))
                .collect(),
            segments,
            manifest,
            named: self.named(),
        })
    }

    /// Takes back a completed reclamation and returns the reclaimed segments.
    pub(crate) fn finish_reclaim(&mut self, reclaimed: Reclaimed<E>) -> Vec<u64> {
        self.busy = false;
        self.manifest = Some(reclaimed.manifest);
        reclaimed.segments
    }

    /// Returns how the value at `position` can be read.
    ///
    /// The position must belong to a retained segment.
    pub(crate) fn access(&mut self, position: u64) -> Access<E, V> {
        if position >= self.captured {
            return Access::Uncut;
        }
        let segment = self.segment(position);
        if let Some((snapshot, pin)) = self.snapshots.get(&segment) {
            return Access::Ready(Reader {
                snapshot: snapshot.clone(),
                _pin: Arc::clone(pin),
            });
        }
        if !self.opening.insert(segment) {
            return Access::Opening;
        }
        Access::Open(OpenJob {
            segment,
            context: self
                .context
                .child("values")
                .with_attribute("segment", segment),
            config: self.value_config(segment),
        })
    }

    /// Installs an opened segment's snapshot.
    pub(crate) fn finish_open(&mut self, opened: Opened<E, V>) {
        self.opening.remove(&opened.segment);
        self.hold(opened.segment, opened.snapshot);
    }

    /// Drops held snapshots of full segments no reader uses, so their files close.
    pub(crate) fn release_snapshots(&mut self) {
        let current = self.segment(self.next);
        self.snapshots
            .retain(|segment, (_, pin)| *segment == current || Arc::strong_count(pin) > 1);
    }

    /// Holds `snapshot` of `segment`, keeping the pin its earlier readers share.
    fn hold(&mut self, segment: u64, snapshot: Snapshot<E, V>) {
        match self.snapshots.get_mut(&segment) {
            Some((held, _)) => *held = snapshot,
            None => {
                self.snapshots.insert(segment, (snapshot, Arc::new(())));
            }
        }
    }

    fn named(&self) -> Manifest {
        Manifest {
            capacity: self.capacity,
            segments: self.segments.iter().copied().collect(),
        }
    }

    fn partition(&self, family: &str, segment: u64) -> String {
        format!("{}_{family}_{segment}", self.prefix)
    }

    fn partitions(&self, segment: u64) -> [String; 3] {
        [
            self.partition(INDEX, segment),
            self.partition(VALUES, segment),
            self.partition(MARKERS, segment),
        ]
    }

    /// Values are stored uncompressed, so a value's frame size is its encoded length plus the
    /// fixed checksum trailer.
    fn value_config(&self, segment: u64) -> glob::Config<V::Cfg> {
        glob::Config {
            partition: self.partition(VALUES, segment),
            compression: None,
            codec_config: self.codec.clone(),
            write_buffer: self.buffers.value_write_buffer,
        }
    }

    fn opener(&self, segment: u64) -> Opener<E, V::Cfg> {
        Opener {
            context: self
                .context
                .child("segments")
                .with_attribute("segment", segment),
            config: oversized::Config {
                index_partition: self.partition(INDEX, segment),
                value_partition: self.partition(VALUES, segment),
                index_page_cache: self.buffers.page_cache.clone(),
                index_write_buffer: self.buffers.index_write_buffer,
                value_write_buffer: self.buffers.value_write_buffer,
                replay_buffer: self.buffers.replay_buffer,
                compression: None,
                codec_config: self.codec.clone(),
            },
            markers: self.partition(MARKERS, segment),
            partitions: self.partitions(segment),
            named: self.segments.contains(&segment),
            capacity: self.capacity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use commonware_codec::FixedSize;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};

    /// A test row: a key and the location of its value.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Row {
        key: u64,
        offset: u64,
        size: u32,
    }

    impl Row {
        const fn new(key: u64) -> Self {
            Self {
                key,
                offset: 0,
                size: 0,
            }
        }
    }

    impl Write for Row {
        fn write(&self, buf: &mut impl BufMut) {
            self.key.write(buf);
            self.offset.write(buf);
            self.size.write(buf);
        }
    }

    impl FixedSize for Row {
        const SIZE: usize = u64::SIZE + u64::SIZE + u32::SIZE;
    }

    impl Read for Row {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
            Ok(Self {
                key: u64::read(buf)?,
                offset: u64::read(buf)?,
                size: u32::read(buf)?,
            })
        }
    }

    impl Record for Row {
        fn value_location(&self) -> (u64, u32) {
            (self.offset, self.size)
        }

        fn with_location(mut self, offset: u64, size: u32) -> Self {
            self.offset = offset;
            self.size = size;
            self
        }
    }

    type TestLog = Log<deterministic::Context, Row, u64>;

    fn config(capacity: u64) -> Config<()> {
        Config {
            prefix: "log".into(),
            buffers: Buffers {
                page_cache: CacheRef::new(NZU16!(1024), NZUsize!(16)),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            codec: (),
            segment_capacity: NZU64!(capacity),
            max_segments: NZUsize!(1024),
        }
    }

    async fn open(context: &deterministic::Context, capacity: u64) -> (TestLog, Vec<(u64, Row)>) {
        Log::open(context.child("log"), config(capacity))
            .await
            .unwrap()
    }

    /// Appends `keys` (each value equals its key) across as many segments as needed.
    async fn append(log: &mut TestLog, keys: impl IntoIterator<Item = u64>) -> Vec<(u64, Row)> {
        let mut keys = keys.into_iter().peekable();
        let mut appended = Vec::new();
        while keys.peek().is_some() {
            let batch = keys
                .by_ref()
                .take(log.room() as usize)
                .map(|key| (Row::new(key), key))
                .collect();
            let job = log.start_append(batch);
            let done = job.run().await.unwrap();
            appended.extend(log.finish_append(done));
        }
        appended
    }

    /// Cuts every append and waits until it is durable.
    async fn cut(log: &mut TestLog) {
        let Some(job) = log.start_cut().unwrap() else {
            return;
        };
        let started = job.run().await.unwrap();
        let durability = log.finish_cut(started);
        let end = durability.await.unwrap();
        log.mark_durable(end);
    }

    /// Returns a reader of the segment holding `position`, opening it when needed.
    async fn reader(log: &mut TestLog, position: u64) -> Reader<deterministic::Context, u64> {
        match log.access(position) {
            Access::Ready(reader) => reader,
            Access::Open(job) => {
                let opened = job.run().await.unwrap();
                log.finish_open(opened);
                let Access::Ready(reader) = log.access(position) else {
                    panic!("an opened segment is readable");
                };
                reader
            }
            Access::Opening | Access::Uncut => panic!("position is not readable"),
        }
    }

    async fn read(log: &mut TestLog, position: u64, row: Row) -> u64 {
        reader(log, position)
            .await
            .get(row.offset, row.size)
            .await
            .unwrap()
    }

    fn keys(rows: &[(u64, Row)]) -> Vec<(u64, u64)> {
        rows.iter()
            .map(|(position, row)| (*position, row.key))
            .collect()
    }

    #[test]
    fn appends_roll_segments_and_survive_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let (mut log, rows) = open(&context, 3).await;
            assert!(rows.is_empty());
            let appended = append(&mut log, 10..17).await;
            assert_eq!(keys(&appended), (0..7).zip(10..17).collect::<Vec<_>>());
            assert_eq!(log.next(), 7);
            assert_eq!(log.durable(), 0);
            // Nothing is readable before a cut covers it.
            assert!(matches!(log.access(6), Access::Uncut));

            cut(&mut log).await;
            assert_eq!(log.durable(), 7);
            assert!(!log.dirty());
            for (position, row) in &appended {
                assert_eq!(read(&mut log, *position, *row).await, row.key);
            }
            drop(log);

            let (mut log, rows) = open(&context, 3).await;
            assert_eq!(keys(&rows), keys(&appended));
            assert_eq!((log.next(), log.durable()), (7, 7));
            for (position, row) in &rows {
                assert_eq!(read(&mut log, *position, *row).await, row.key);
            }
            // Appends continue in the partially filled segment.
            let more = append(&mut log, [20, 21]).await;
            assert_eq!(keys(&more), vec![(7, 20), (8, 21)]);
            cut(&mut log).await;
            drop(log);
            let (_, rows) = open(&context, 3).await;
            assert_eq!(rows.len(), 9);
        });
    }

    #[test]
    fn uncut_appends_are_not_durable_and_unnamed_segments_reset() {
        deterministic::Runner::default().start(|context| async move {
            let (mut log, _) = open(&context, 2).await;
            append(&mut log, [1, 2]).await;
            cut(&mut log).await;
            // The next append opens segment 1, which only the next cut names.
            append(&mut log, [3]).await;
            assert!(log.dirty());
            drop(log);

            let (mut log, rows) = open(&context, 2).await;
            assert_eq!(keys(&rows), vec![(0, 1), (1, 2)]);
            assert_eq!(log.next(), 2);
            // Reusing the residue segment starts it empty.
            let appended = append(&mut log, [4]).await;
            assert_eq!(keys(&appended), vec![(2, 4)]);
            cut(&mut log).await;
            drop(log);
            let (_, rows) = open(&context, 2).await;
            assert_eq!(keys(&rows), vec![(0, 1), (1, 2), (2, 4)]);
        });
    }

    #[test]
    fn released_segments_are_reclaimed_unless_pinned() {
        deterministic::Runner::default().start(|context| async move {
            let (mut log, _) = open(&context, 2).await;
            let appended = append(&mut log, 0..6).await;
            cut(&mut log).await;
            // Segment 0 loses its rows; segment 1 keeps one; segment 2 is current.
            for position in [0, 1, 2] {
                log.release(position);
            }
            let job = log.start_reclaim().unwrap();
            assert_eq!(log.finish_reclaim(job.run().await.unwrap()), vec![0]);
            assert!(log.start_reclaim().is_none());
            assert_eq!(read(&mut log, 3, appended[3].1).await, 3);
            drop(log);

            let (mut log, rows) = open(&context, 2).await;
            assert_eq!(
                keys(&rows),
                (2..6).map(|key| (key, key)).collect::<Vec<_>>()
            );
            // A reader pins its segment: a closed segment is opened once, then shared.
            let pinned = reader(&mut log, 2).await;
            let shared = reader(&mut log, 3).await;
            log.release(2);
            log.release(3);
            assert!(log.start_reclaim().is_none());
            drop(pinned);
            assert!(log.start_reclaim().is_none());
            drop(shared);
            log.release_snapshots();
            let job = log.start_reclaim().unwrap();
            assert_eq!(log.finish_reclaim(job.run().await.unwrap()), vec![1]);
            drop(log);
            let (_, rows) = open(&context, 2).await;
            assert_eq!(keys(&rows), vec![(4, 4), (5, 5)]);
        });
    }

    #[test]
    fn concurrent_reads_of_a_closed_segment_share_one_open() {
        deterministic::Runner::default().start(|context| async move {
            let (mut log, _) = open(&context, 2).await;
            append(&mut log, 0..3).await;
            cut(&mut log).await;
            drop(log);
            let (mut log, rows) = open(&context, 2).await;
            let Access::Open(job) = log.access(0) else {
                panic!("a closed segment opens on demand");
            };
            assert!(matches!(log.access(1), Access::Opening));
            log.finish_open(job.run().await.unwrap());
            let Access::Ready(reader) = log.access(1) else {
                panic!("an opened segment is shared");
            };
            let (offset, size) = rows[1].1.value_location();
            assert_eq!(reader.get(offset, size).await.unwrap(), 1);
        });
    }

    #[test]
    fn an_append_that_fills_a_dirty_segment_seals_it() {
        deterministic::Runner::default().start(|context| async move {
            let (mut log, _) = open(&context, 3).await;
            append(&mut log, [1]).await;
            // The second append fills the segment the first one dirtied.
            append(&mut log, [2, 3]).await;
            cut(&mut log).await;
            assert_eq!(log.durable(), 3);
            append(&mut log, [4]).await;
            cut(&mut log).await;
            drop(log);
            let (_, rows) = open(&context, 3).await;
            assert_eq!(keys(&rows), vec![(0, 1), (1, 2), (2, 3), (3, 4)]);
        });
    }

    #[test]
    fn appends_continue_while_a_cut_is_pending() {
        deterministic::Runner::default().start(|context| async move {
            let (mut log, _) = open(&context, 4).await;
            append(&mut log, [1, 2]).await;
            let started = log.start_cut().unwrap().unwrap().run().await.unwrap();
            let durability = log.finish_cut(started);
            // The log is idle again before the cut is durable.
            assert!(log.idle());
            append(&mut log, [3, 4, 5]).await;
            let end = durability.await.unwrap();
            assert_eq!(end, 2);
            log.mark_durable(end);
            assert_eq!(log.durable(), 2);
            cut(&mut log).await;
            assert_eq!(log.durable(), 5);
        });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use arbitrary::{Arbitrary, Unstructured};
        use commonware_codec::{Decode as _, Encode as _, conformance::generate_value};
        use commonware_conformance::Conformance;

        impl<'a> Arbitrary<'a> for Manifest {
            fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
                let count = u.int_in_range(0..=16usize)?;
                let mut next = u64::from(u.arbitrary::<u32>()?);
                let mut segments = Vec::with_capacity(count);
                for _ in 0..count {
                    segments.push(next);
                    next += 1 + u64::from(u.arbitrary::<u16>()?);
                }
                Ok(Self {
                    capacity: u.arbitrary()?,
                    segments,
                })
            }
        }

        struct ManifestConformance;

        impl Conformance for ManifestConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let manifest = generate_value::<Manifest>(seed);
                let encoded = manifest.encode();
                assert_eq!(
                    Manifest::decode_cfg(encoded.clone(), &manifest.segments.len()).unwrap(),
                    manifest
                );
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            ManifestConformance => 256,
        }
    }
}
