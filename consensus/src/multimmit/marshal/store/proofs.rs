//! Proofs: the L-QCs, tip-history records and cut entries marshal orders its output from.
//!
//! One [`Log`] holds three immutable, content-addressed parts:
//!
//! - an L-QC, keyed by its [`CertificateId`], linked to its leader's history commitment;
//! - a tip-history record, keyed by its commitment, linked to its parent commitment;
//! - a cut entry, keyed by the L-QC whose cut it closes, with the exact boundary blocks.
//!
//! Every row carries its key and link, so the [`Index`] is rebuilt at open from rows alone.
//! Records connect to the base (the genesis history, or the record of the floor marshal last
//! installed or pruned to) through parent links, and every connected record gets a local
//! ordinal, one above its parent's. Ordinals start at zero for the base at open and never
//! change while the store is open: a rebase keeps them, and a base that is not connected starts
//! a fresh range above every ordinal used so far. They are never persisted or sent to peers.
//!
//! Every part on the finalized history is quorum-authenticated before it is stored, so two
//! connected records at one ordinal mean the history forked: a [`Fork`] is fatal.

use super::{
    Buffers, Error,
    log::{self, Access, Durability, Log},
};
use crate::{
    Viewable as _,
    multimmit::{
        scheme::Scheme,
        types::{Artifact, BlockRef, CertificateId, CodecConfig, Lqc, LqcProof, TipRecord},
    },
    types::View,
};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_cryptography::Digest;
use commonware_storage::{Context, journal::segmented::oversized::Record};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

/// The kind of a stored part.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Kind {
    Lqc = 0,
    Record = 1,
    Cut = 2,
}

impl Kind {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Lqc),
            1 => Some(Self::Record),
            2 => Some(Self::Cut),
            _ => None,
        }
    }
}

/// An index row: a part's kind, key, link and number, and its location.
///
/// - L-QC: key = certificate identifier, link = leader history, number = view.
/// - Record: key = commitment, link = parent commitment, number = zero.
/// - Cut entry: key = the L-QC's identifier, link = the L-QC's leader history, number = the
///   output index the cut closes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row<D: Digest> {
    kind: Kind,
    key: D,
    link: D,
    number: u64,
    offset: u64,
    size: u32,
}

impl<D: Digest> Row<D> {
    const fn new(kind: Kind, key: D, link: D, number: u64) -> Self {
        Self {
            kind,
            key,
            link,
            number,
            offset: 0,
            size: 0,
        }
    }
}

impl<D: Digest> Write for Row<D> {
    fn write(&self, buf: &mut impl BufMut) {
        (self.kind as u8).write(buf);
        self.key.write(buf);
        self.link.write(buf);
        self.number.write(buf);
        self.offset.write(buf);
        self.size.write(buf);
    }
}

impl<D: Digest> FixedSize for Row<D> {
    const SIZE: usize = u8::SIZE + 2 * D::SIZE + u64::SIZE + u64::SIZE + u32::SIZE;
}

impl<D: Digest> Read for Row<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let kind = u8::read(buf)?;
        let kind = Kind::from_u8(kind).ok_or(CodecError::InvalidEnum(kind))?;
        Ok(Self {
            kind,
            key: D::read(buf)?,
            link: D::read(buf)?,
            number: u64::read(buf)?,
            offset: u64::read(buf)?,
            size: u32::read(buf)?,
        })
    }
}

impl<D: Digest> Record for Row<D> {
    fn value_location(&self) -> (u64, u32) {
        (self.offset, self.size)
    }

    fn with_location(mut self, offset: u64, size: u32) -> Self {
        self.offset = offset;
        self.size = size;
        self
    }
}

/// The exact boundary of an L-QC's cut: the last emitted block of every chain once the order
/// the L-QC proves (its leader's history, then its final sweep) is emitted.
///
/// The rest of the cut follows from the L-QC: its history is the leader's history commitment,
/// its tips are that record's tips, and its index is the sum of the boundary heights.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CutEntry<D: Digest> {
    /// The L-QC whose cut this closes.
    pub(crate) lqc: CertificateId<D>,
    /// The last emitted block of every chain, in chain order.
    pub(crate) boundary: Vec<BlockRef<D>>,
}

impl<D: Digest> CutEntry<D> {
    /// Returns the output index of the cut.
    pub(crate) fn index(&self) -> u64 {
        self.boundary.iter().map(|block| block.height().get()).sum()
    }
}

impl<D: Digest> Write for CutEntry<D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.lqc.write(buf);
        self.boundary.write(buf);
    }
}

impl<D: Digest> EncodeSize for CutEntry<D> {
    fn encode_size(&self) -> usize {
        self.lqc.encode_size() + self.boundary.encode_size()
    }
}

impl<D: Digest> Read for CutEntry<D> {
    /// The number of chains.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, chains: &usize) -> Result<Self, CodecError> {
        Ok(Self {
            lqc: CertificateId::read(buf)?,
            boundary: Vec::<BlockRef<D>>::read_cfg(buf, &(RangeCfg::exact(*chains), ()))?,
        })
    }
}

/// A stored part.
///
/// An L-QC is held as the artifact consensus shares, so storing it copies nothing; only
/// [`Part::lqc`] constructs one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Part<S: Scheme, D: Digest> {
    Lqc(Arc<Artifact<S, D>>),
    Record(Arc<TipRecord<D>>),
    Cut(Arc<CutEntry<D>>),
}

impl<S: Scheme, D: Digest> Part<S, D> {
    /// Returns the part holding the L-QC of `proof`.
    pub(crate) fn lqc(proof: &LqcProof<S, D>) -> Self {
        Self::Lqc(Arc::clone(proof.artifact()))
    }

    /// Returns the L-QC this part holds, as a proof identified by `id`.
    pub(crate) fn into_proof(self, id: CertificateId<D>) -> Option<LqcProof<S, D>> {
        match self {
            Self::Lqc(artifact) => LqcProof::new(id, artifact),
            Self::Record(_) | Self::Cut(_) => None,
        }
    }
}

/// Returns the L-QC an L-QC part's artifact holds.
fn inner<S: Scheme, D: Digest>(artifact: &Artifact<S, D>) -> &Lqc<S, D> {
    let Artifact::Lqc(lqc) = artifact else {
        unreachable!("L-QC parts hold L-QCs");
    };
    lqc
}

impl<S: Scheme, D: Digest> Write for Part<S, D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Lqc(artifact) => {
                (Kind::Lqc as u8).write(buf);
                inner(artifact).write(buf);
            }
            Self::Record(record) => {
                (Kind::Record as u8).write(buf);
                record.write(buf);
            }
            Self::Cut(cut) => {
                (Kind::Cut as u8).write(buf);
                cut.write(buf);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Part<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Lqc(artifact) => inner(artifact).encode_size(),
            Self::Record(record) => record.encode_size(),
            Self::Cut(cut) => cut.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Part<S, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &CodecConfig) -> Result<Self, CodecError> {
        let kind = u8::read(buf)?;
        match Kind::from_u8(kind).ok_or(CodecError::InvalidEnum(kind))? {
            Kind::Lqc => Ok(Self::Lqc(Arc::new(Artifact::Lqc(Lqc::read_cfg(
                buf, config,
            )?)))),
            Kind::Record => Ok(Self::Record(Arc::new(TipRecord::read_cfg(buf, config)?))),
            Kind::Cut => Ok(Self::Cut(Arc::new(CutEntry::read_cfg(
                buf,
                &config.chains(),
            )?))),
        }
    }
}

/// A stored part's log position and frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Stored {
    /// The log position.
    pub(crate) position: u64,
    /// The frame location in its segment.
    pub(crate) location: (u64, u32),
}

/// A stored record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecordEntry<D: Digest> {
    /// The parent commitment.
    pub(crate) parent: D,
    /// Where it is stored.
    pub(crate) stored: Stored,
}

/// A stored L-QC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LqcEntry<D: Digest> {
    /// The leader's history commitment.
    pub(crate) history: D,
    /// The leader's view.
    pub(crate) view: View,
    /// Where it is stored.
    pub(crate) stored: Stored,
}

/// A stored cut entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CutRow<D: Digest> {
    /// The L-QC whose cut the entry closes.
    pub(crate) lqc: CertificateId<D>,
    /// The leader history of that L-QC.
    pub(crate) history: D,
    /// Where it is stored.
    pub(crate) stored: Stored,
}

/// Two connected records claim one ordinal: the finalized history forked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("finalized history forked at ordinal {0}")]
pub(crate) struct Fork(pub(crate) u64);

/// The index of stored parts.
pub(crate) struct Index<D: Digest> {
    /// The record (or genesis history) every connected record descends from.
    base: D,
    /// The base's ordinal.
    first: u64,
    /// Stored records by commitment.
    records: HashMap<D, RecordEntry<D>>,
    /// Stored records by parent commitment.
    children: HashMap<D, Vec<D>>,
    /// Connected records in ordinal order: `chain[k]` has ordinal `first + k + 1`.
    chain: Vec<D>,
    /// Ordinals of the base and every connected record.
    ordinals: HashMap<D, u64>,
    /// Stored L-QCs.
    lqcs: HashMap<CertificateId<D>, LqcEntry<D>>,
    /// Stored L-QCs by leader history.
    by_history: HashMap<D, Vec<CertificateId<D>>>,
    /// Stored L-QCs whose leader history is connected, by that history's ordinal.
    by_ordinal: BTreeMap<u64, Vec<CertificateId<D>>>,
    /// Stored L-QCs whose leader history is not connected, by view.
    unconnected: BTreeSet<(View, CertificateId<D>)>,
    /// Stored cut entries by output index.
    cuts: BTreeMap<u64, Vec<CutRow<D>>>,
    /// Output indices of stored cut entries by L-QC.
    cut_of: HashMap<CertificateId<D>, u64>,
}

impl<D: Digest> Index<D> {
    /// Creates an empty index counting ordinals from `base`.
    pub(crate) fn new(base: D) -> Self {
        Self {
            base,
            first: 0,
            records: HashMap::new(),
            children: HashMap::new(),
            chain: Vec::new(),
            ordinals: HashMap::from([(base, 0)]),
            lqcs: HashMap::new(),
            by_history: HashMap::new(),
            by_ordinal: BTreeMap::new(),
            unconnected: BTreeSet::new(),
            cuts: BTreeMap::new(),
            cut_of: HashMap::new(),
        }
    }

    /// Returns the base commitment.
    #[cfg(test)]
    pub(crate) const fn base(&self) -> D {
        self.base
    }

    /// Returns the base's ordinal.
    #[cfg(test)]
    pub(crate) const fn first(&self) -> u64 {
        self.first
    }

    /// Returns the ordinal of a connected commitment (the base included).
    pub(crate) fn ordinal(&self, commitment: &D) -> Option<u64> {
        self.ordinals.get(commitment).copied()
    }

    /// Returns the connected commitment at `ordinal`.
    pub(crate) fn at(&self, ordinal: u64) -> Option<D> {
        match ordinal.checked_sub(self.first)? {
            0 => Some(self.base),
            offset => self.chain.get(offset as usize - 1).copied(),
        }
    }

    /// Returns the newest connected ordinal.
    pub(crate) const fn tip(&self) -> u64 {
        self.first + self.chain.len() as u64
    }

    /// Returns the stored record with `commitment`.
    pub(crate) fn record(&self, commitment: &D) -> Option<&RecordEntry<D>> {
        self.records.get(commitment)
    }

    /// Returns the stored L-QC with `id`.
    pub(crate) fn lqc(&self, id: &CertificateId<D>) -> Option<&LqcEntry<D>> {
        self.lqcs.get(id)
    }

    /// Returns the stored L-QCs whose leader history is `history`.
    #[cfg(test)]
    pub(crate) fn lqcs_of(&self, history: &D) -> &[CertificateId<D>] {
        self.by_history.get(history).map_or(&[], Vec::as_slice)
    }

    /// Returns the stored L-QCs whose leader history is connected at an ordinal of at least
    /// `from`, grouped by that ordinal in ascending order.
    pub(crate) fn connected_from(
        &self,
        from: u64,
    ) -> impl DoubleEndedIterator<Item = (u64, &[CertificateId<D>])> {
        self.by_ordinal
            .range(from..)
            .map(|(ordinal, ids)| (*ordinal, ids.as_slice()))
    }

    /// Returns the stored L-QCs whose leader history is connected at `ordinal`.
    pub(crate) fn connected_at(&self, ordinal: u64) -> &[CertificateId<D>] {
        self.by_ordinal.get(&ordinal).map_or(&[], Vec::as_slice)
    }

    /// Returns the stored L-QCs whose leader history is not connected, newest view first.
    pub(crate) fn unconnected(&self) -> impl Iterator<Item = (CertificateId<D>, &LqcEntry<D>)> {
        self.unconnected
            .iter()
            .rev()
            .filter_map(|(_, id)| self.lqcs.get(id).map(|entry| (*id, entry)))
    }

    /// Returns the stored cut entries closing output indices at most `at`, newest first.
    pub(crate) fn cuts_at_most(&self, at: u64) -> impl Iterator<Item = (u64, &CutRow<D>)> {
        self.cuts
            .range(..=at)
            .rev()
            .flat_map(|(index, rows)| rows.iter().map(move |row| (*index, row)))
    }

    /// Returns the output index and row of the cut entry of `lqc`.
    pub(crate) fn cut_of(&self, lqc: &CertificateId<D>) -> Option<(u64, &CutRow<D>)> {
        let index = *self.cut_of.get(lqc)?;
        self.cuts
            .get(&index)?
            .iter()
            .find(|row| row.lqc == *lqc)
            .map(|row| (index, row))
    }

    /// Indexes a record, connecting it and every stored descendant it completes.
    ///
    /// Returns the commitments newly connected, oldest first, or `None` when the record is
    /// already indexed. The base's own record is indexed but connects nothing: the base is
    /// connected by definition.
    fn insert_record(
        &mut self,
        commitment: D,
        entry: RecordEntry<D>,
    ) -> Result<Option<Vec<D>>, Fork> {
        if self.records.contains_key(&commitment) {
            return Ok(None);
        }
        self.records.insert(commitment, entry);
        if commitment == self.base {
            return Ok(Some(Vec::new()));
        }
        self.children
            .entry(entry.parent)
            .or_default()
            .push(commitment);
        if self.ordinals.contains_key(&entry.parent) {
            self.connect_from(entry.parent).map(Some)
        } else {
            Ok(Some(Vec::new()))
        }
    }

    /// Connects the stored descendants of the connected `from`.
    fn connect_from(&mut self, from: D) -> Result<Vec<D>, Fork> {
        let mut connected = Vec::new();
        let mut cursor = from;
        loop {
            let ordinal = self.ordinals[&cursor];
            let mut next = None;
            for child in self.children.get(&cursor).into_iter().flatten() {
                if self.ordinals.contains_key(child) {
                    continue;
                }
                // Only the newest connected record may gain a child, and only one.
                if ordinal != self.tip() || next.is_some() {
                    return Err(Fork(ordinal + 1));
                }
                next = Some(*child);
            }
            let Some(next) = next else {
                return Ok(connected);
            };
            self.chain.push(next);
            self.ordinals.insert(next, ordinal + 1);
            for id in self.by_history.get(&next).into_iter().flatten() {
                if let Some(entry) = self.lqcs.get(id) {
                    self.unconnected.remove(&(entry.view, *id));
                    self.by_ordinal.entry(ordinal + 1).or_default().push(*id);
                }
            }
            connected.push(next);
            cursor = next;
        }
    }

    /// Indexes an L-QC, returning whether it was not indexed yet.
    fn insert_lqc(&mut self, id: CertificateId<D>, entry: LqcEntry<D>) -> bool {
        if self.lqcs.contains_key(&id) {
            return false;
        }
        self.lqcs.insert(id, entry);
        self.by_history.entry(entry.history).or_default().push(id);
        match self.ordinals.get(&entry.history) {
            Some(ordinal) => self.by_ordinal.entry(*ordinal).or_default().push(id),
            None => {
                self.unconnected.insert((entry.view, id));
            }
        }
        true
    }

    /// Rebuilds the L-QC indexes by connection after the connected chain changed wholesale.
    fn reindex_lqcs(&mut self) {
        self.by_ordinal.clear();
        self.unconnected.clear();
        for (id, entry) in &self.lqcs {
            match self.ordinals.get(&entry.history) {
                Some(ordinal) => self.by_ordinal.entry(*ordinal).or_default().push(*id),
                None => {
                    self.unconnected.insert((entry.view, *id));
                }
            }
        }
    }

    /// Indexes a cut entry, returning whether its L-QC had none yet.
    fn insert_cut(&mut self, index: u64, row: CutRow<D>) -> bool {
        if self.cut_of.contains_key(&row.lqc) {
            return false;
        }
        self.cut_of.insert(row.lqc, index);
        self.cuts.entry(index).or_default().push(row);
        true
    }

    /// Moves the base to `base` and drops what it makes obsolete (see [`Self::drop_obsolete`]),
    /// returning the log positions dropped. `floor_view` is the view of the floor's L-QC.
    ///
    /// A connected base keeps its ordinal; one that is not starts above every ordinal used so
    /// far.
    fn rebase(&mut self, base: D, floor_view: Option<View>) -> Result<Vec<u64>, Fork> {
        self.first = self.ordinal(&base).unwrap_or(self.tip() + 1);
        self.base = base;
        self.chain.clear();
        self.ordinals = HashMap::from([(base, self.first)]);
        self.connect_from(base)?;
        let dropped = self.drop_obsolete(floor_view);
        Ok(dropped)
    }

    /// Drops every part the base makes obsolete, returning their log positions:
    ///
    /// - L-QCs whose leader history is not connected, unless newer than the floor's L-QC (a
    ///   repair may still connect them), and their cut entries;
    /// - records that are not connected, unless a kept L-QC's history reaches them through parent
    ///   links (a repair in progress).
    fn drop_obsolete(&mut self, floor_view: Option<View>) -> Vec<u64> {
        let mut dropped = Vec::new();
        let ordinals = &self.ordinals;
        let mut gone = HashSet::new();
        self.lqcs.retain(|id, entry| {
            let keep = ordinals.contains_key(&entry.history)
                || floor_view.is_none_or(|floor| entry.view > floor);
            if !keep {
                dropped.push(entry.stored.position);
                gone.insert(*id);
            }
            keep
        });
        let mut reached = HashSet::new();
        for entry in self.lqcs.values() {
            let mut cursor = entry.history;
            while !ordinals.contains_key(&cursor) && reached.insert(cursor) {
                match self.records.get(&cursor) {
                    Some(record) => cursor = record.parent,
                    None => break,
                }
            }
        }
        self.records.retain(|commitment, entry| {
            let keep = ordinals.contains_key(commitment) || reached.contains(commitment);
            if !keep {
                dropped.push(entry.stored.position);
            }
            keep
        });
        let records = &self.records;
        let base = self.base;
        self.children.retain(|_, children| {
            children.retain(|child| *child != base && records.contains_key(child));
            !children.is_empty()
        });
        self.by_history.retain(|_, ids| {
            ids.retain(|id| !gone.contains(id));
            !ids.is_empty()
        });
        self.cut_of.retain(|id, _| !gone.contains(id));
        self.cuts.retain(|_, rows| {
            rows.retain(|row| {
                let keep = !gone.contains(&row.lqc);
                if !keep {
                    dropped.push(row.stored.position);
                }
                keep
            });
            !rows.is_empty()
        });
        self.reindex_lqcs();
        dropped
    }
}

/// Construction inputs for [`Proofs`].
pub(crate) struct Config {
    /// Prefix from which every partition is derived.
    pub(crate) prefix: String,
    /// Journal buffers and page cache.
    pub(crate) buffers: Buffers,
    /// Bounds used to decode parts.
    pub(crate) codec: CodecConfig,
    /// Parts in each segment; fixed when the store is created.
    pub(crate) segment_capacity: NonZeroU64,
    /// Most segments retained.
    pub(crate) max_segments: NonZeroUsize,
}

/// A storage job of the proofs log.
pub(crate) type Job<E, S, D> = log::Job<E, Row<D>, Part<S, D>>;

/// A completed storage job of the proofs log.
pub(crate) type Done<E, S, D> = log::Done<E, Row<D>, Part<S, D>>;

/// The log of proof parts.
type PartLog<E, S, D> = Log<E, Row<D>, Part<S, D>>;

/// What finishing a job produced.
pub(crate) enum Finished<D: Digest> {
    /// Parts stored.
    Appended {
        /// The records they connected, oldest first.
        connected: Vec<D>,
        /// The L-QCs they indexed.
        lqcs: Vec<CertificateId<D>>,
    },
    /// A cut whose durability completes with its end.
    Cut(Durability),
    /// Segments reclaimed.
    Reclaimed,
}

/// Every proof part marshal holds.
pub(crate) struct Proofs<E: Context, S: Scheme, D: Digest> {
    index: Index<D>,
    log: PartLog<E, S, D>,
    /// Parts waiting for the log, with their rows.
    queued: Vec<(Row<D>, Part<S, D>)>,
    /// Keys of records and L-QCs queued or being appended.
    pending: HashSet<D>,
    /// L-QCs whose cut entries are queued or being appended.
    pending_cuts: HashSet<CertificateId<D>>,
}

impl<E: Context, S: Scheme, D: Digest> Proofs<E, S, D> {
    /// Opens the store and rebuilds the index, counting ordinals from `base`, the history of the
    /// L-QC `floor` (or the genesis history). Duplicated rows and parts the base makes obsolete
    /// are released, as a live rebase would have released them.
    pub(crate) async fn open(
        context: E,
        config: Config,
        base: D,
        floor: Option<CertificateId<D>>,
    ) -> Result<Self, Error> {
        let (mut log, rows) = PartLog::<E, S, D>::open(
            context,
            log::Config {
                prefix: config.prefix,
                buffers: config.buffers,
                codec: config.codec,
                segment_capacity: config.segment_capacity,
                max_segments: config.max_segments,
            },
        )
        .await?;
        let mut index = Index::new(base);
        // Records are indexed before L-QCs and cut entries only for clarity; nothing depends on
        // the order. Parents may follow children in the log (walks store newest first).
        for (position, row) in rows {
            let indexed = index_row(&mut index, position, &row)
                .map_err(|_| Error::Inconsistent("stored history forks"))?;
            if indexed.is_none() {
                log.release(position);
            }
        }
        let floor_view = floor
            .and_then(|floor| index.lqc(&floor))
            .map(|entry| entry.view);
        for position in index.drop_obsolete(floor_view) {
            log.release(position);
        }
        log.release_snapshots();
        Ok(Self {
            index,
            log,
            queued: Vec::new(),
            pending: HashSet::new(),
            pending_cuts: HashSet::new(),
        })
    }

    /// Returns the index of stored parts.
    pub(crate) const fn index(&self) -> &Index<D> {
        &self.index
    }

    /// Returns whether the part at `stored` is durable.
    pub(crate) const fn durable(&self, stored: Stored) -> bool {
        stored.position < self.log.durable()
    }

    /// Returns whether a part with `key` is stored or queued.
    pub(crate) fn known(&self, key: &D) -> bool {
        self.pending.contains(key)
            || self.index.records.contains_key(key)
            || self.index.lqcs.contains_key(&CertificateId::new(*key))
    }

    /// Queues a record whose commitment is `commitment`; returns whether it was new.
    pub(crate) fn insert_record(&mut self, commitment: D, record: Arc<TipRecord<D>>) -> bool {
        if self.known(&commitment) {
            return false;
        }
        let row = Row::new(Kind::Record, commitment, record.parent(), 0);
        self.enqueue(commitment, row, Part::Record(record));
        true
    }

    /// Queues the L-QC of `proof`; returns whether it was new.
    pub(crate) fn insert_lqc(&mut self, proof: &LqcProof<S, D>) -> bool {
        let id = proof.id();
        if self.known(&id.get()) {
            return false;
        }
        let leader = proof.lqc().leader();
        let row = Row::new(Kind::Lqc, id.get(), leader.history(), leader.view().get());
        self.enqueue(id.get(), row, Part::lqc(proof));
        true
    }

    /// Queues the cut entry of the L-QC with leader history `history`; returns whether it was
    /// new.
    pub(crate) fn insert_cut(&mut self, history: D, cut: CutEntry<D>) -> bool {
        if self.index.cut_of.contains_key(&cut.lqc) || !self.pending_cuts.insert(cut.lqc) {
            return false;
        }
        let row = Row::new(Kind::Cut, cut.lqc.get(), history, cut.index());
        self.queued.push((row, Part::Cut(Arc::new(cut))));
        true
    }

    fn enqueue(&mut self, key: D, row: Row<D>, part: Part<S, D>) {
        self.pending.insert(key);
        self.queued.push((row, part));
    }

    /// Returns whether appends no started cut covers exist.
    pub(crate) fn dirty(&self) -> bool {
        self.log.dirty()
    }

    /// Returns whether no job runs.
    pub(crate) const fn idle(&self) -> bool {
        self.log.idle()
    }

    /// Starts appending queued parts, up to the current segment's room, or returns `None`.
    pub(crate) fn start_append(&mut self) -> Option<Job<E, S, D>> {
        if !self.log.idle() || self.queued.is_empty() {
            return None;
        }
        let room = self.log.room() as usize;
        let take = room.min(self.queued.len());
        let entries = self.queued.drain(..take).collect();
        Some(log::Job::Append(self.log.start_append(entries)))
    }

    /// Starts a cut, or returns `None` when nothing is dirty or a job runs.
    pub(crate) fn start_cut(&mut self) -> Result<Option<Job<E, S, D>>, Error> {
        if !self.log.idle() {
            return Ok(None);
        }
        Ok(self.log.start_cut()?.map(log::Job::Cut))
    }

    /// Starts reclaiming segments without retained parts, or returns `None`.
    pub(crate) fn start_reclaim(&mut self) -> Option<Job<E, S, D>> {
        if !self.log.idle() {
            return None;
        }
        self.log.start_reclaim().map(log::Job::Reclaim)
    }

    /// Takes back a completed job.
    pub(crate) fn finish(&mut self, done: Done<E, S, D>) -> Result<Finished<D>, Error> {
        Ok(match self.log.finish(done) {
            log::Finished::Appended(rows) => {
                let mut connected = Vec::new();
                let mut lqcs = Vec::new();
                for (position, row) in rows {
                    if row.kind == Kind::Cut {
                        self.pending_cuts.remove(&CertificateId::new(row.key));
                    } else {
                        self.pending.remove(&row.key);
                    }
                    match index_row(&mut self.index, position, &row)
                        .map_err(|_| Error::Inconsistent("finalized history forked"))?
                    {
                        Some(newly) => {
                            if row.kind == Kind::Lqc {
                                lqcs.push(CertificateId::new(row.key));
                            }
                            connected.extend(newly);
                        }
                        // Indexed already: the row is a duplicate.
                        None => self.log.release(position),
                    }
                }
                Finished::Appended { connected, lqcs }
            }
            log::Finished::Cut(durability) => Finished::Cut(durability),
            log::Finished::Reclaimed => Finished::Reclaimed,
        })
    }

    /// Records that the cut ending at `end` is durable.
    pub(crate) fn mark_durable(&mut self, end: u64) {
        self.log.mark_durable(end);
    }

    /// Moves the base to the connected `base`, the history of the L-QC `floor`, and releases
    /// everything it drops.
    ///
    /// The caller persists the new base first, so a crash cannot resurrect what is dropped here.
    pub(crate) fn rebase(&mut self, base: D, floor: Option<CertificateId<D>>) -> Result<(), Error> {
        let floor_view = floor
            .and_then(|floor| self.index.lqc(&floor))
            .map(|entry| entry.view);
        let dropped = self
            .index
            .rebase(base, floor_view)
            .map_err(|_| Error::Inconsistent("finalized history forked"))?;
        for position in dropped {
            self.log.release(position);
        }
        self.log.release_snapshots();
        Ok(())
    }

    /// Returns how the part at `stored` can be read.
    pub(crate) fn access(&mut self, stored: Stored) -> Access<E, Part<S, D>> {
        self.log.access(stored.position)
    }

    /// Installs an opened segment.
    pub(crate) fn finish_open(&mut self, opened: log::Opened<E, Part<S, D>>) {
        self.log.finish_open(opened);
    }
}

/// Indexes one stored row, returning the records it connected, or `None` when the row duplicates
/// an indexed part.
fn index_row<D: Digest>(
    index: &mut Index<D>,
    position: u64,
    row: &Row<D>,
) -> Result<Option<Vec<D>>, Fork> {
    let stored = Stored {
        position,
        location: (row.offset, row.size),
    };
    match row.kind {
        Kind::Record => index.insert_record(
            row.key,
            RecordEntry {
                parent: row.link,
                stored,
            },
        ),
        Kind::Lqc => Ok(index
            .insert_lqc(
                CertificateId::new(row.key),
                LqcEntry {
                    history: row.link,
                    view: View::new(row.number),
                    stored,
                },
            )
            .then(Vec::new)),
        Kind::Cut => Ok(index
            .insert_cut(
                row.number,
                CutRow {
                    lqc: CertificateId::new(row.key),
                    history: row.link,
                    stored,
                },
            )
            .then(Vec::new)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            mocks::Bls,
            types::{ChainId, PathLimits},
        },
        types::Height,
    };
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};

    type D = Sha256Digest;
    type TestProofs = Proofs<deterministic::Context, Bls<MinPk>, D>;

    fn base() -> D {
        Sha256::hash(&[b"base"])
    }

    fn tip(chain: u32, height: u64) -> BlockRef<D> {
        BlockRef::new(
            ChainId::new(chain),
            Height::new(height),
            Sha256::hash(&[&chain.to_be_bytes(), &height.to_be_bytes()]),
        )
    }

    /// A chain of `len` records above `base`, oldest first, with their commitments.
    fn records(from: D, len: u64) -> Vec<(D, Arc<TipRecord<D>>)> {
        let mut parent = from;
        (1..=len)
            .map(|height| {
                let record =
                    TipRecord::at_tips(parent, vec![tip(0, height), tip(1, height)]).unwrap();
                parent = record.commitment::<Sha256>();
                (parent, Arc::new(record))
            })
            .collect()
    }

    fn entry(parent: D, position: u64) -> RecordEntry<D> {
        RecordEntry {
            parent,
            stored: Stored {
                position,
                location: (0, 0),
            },
        }
    }

    #[test]
    fn records_connect_in_any_arrival_order() {
        let chain = records(base(), 4);
        let mut index = Index::new(base());
        // Newest first, as a walk stores them: nothing connects until the oldest arrives.
        for (position, (commitment, record)) in chain.iter().enumerate().rev().take(3) {
            assert_eq!(
                index
                    .insert_record(*commitment, entry(record.parent(), position as u64))
                    .unwrap(),
                Some(Vec::new())
            );
        }
        let (first, record) = &chain[0];
        let connected = index
            .insert_record(*first, entry(record.parent(), 9))
            .unwrap();
        assert_eq!(
            connected,
            Some(chain.iter().map(|(c, _)| *c).collect::<Vec<_>>())
        );
        assert_eq!(index.tip(), 4);
        for (ordinal, (commitment, _)) in chain.iter().enumerate() {
            assert_eq!(index.ordinal(commitment), Some(ordinal as u64 + 1));
            assert_eq!(index.at(ordinal as u64 + 1), Some(*commitment));
        }
        assert_eq!(index.at(0), Some(base()));
        // Re-inserting indexes nothing.
        assert_eq!(index.insert_record(*first, entry(base(), 9)).unwrap(), None);
    }

    #[test]
    fn a_second_child_of_a_connected_record_forks() {
        let chain = records(base(), 2);
        let mut index = Index::new(base());
        for (position, (commitment, record)) in chain.iter().enumerate() {
            index
                .insert_record(*commitment, entry(record.parent(), position as u64))
                .unwrap();
        }
        // A rival of the second record, also extending the first.
        let rival = TipRecord::at_tips(chain[0].0, vec![tip(0, 9), tip(1, 9)]).unwrap();
        assert_eq!(
            index.insert_record(rival.commitment::<Sha256>(), entry(chain[0].0, 5)),
            Err(Fork(2))
        );
        // A rival of the first record forks at ordinal one.
        let mut index = Index::new(base());
        index.insert_record(chain[0].0, entry(base(), 0)).unwrap();
        let rival = TipRecord::at_tips(base(), vec![tip(0, 7), tip(1, 7)]).unwrap();
        assert_eq!(
            index.insert_record(rival.commitment::<Sha256>(), entry(base(), 1)),
            Err(Fork(1))
        );
    }

    #[test]
    fn rebase_drops_older_and_unconnected_parts() {
        let chain = records(base(), 4);
        let stray = records(Sha256::hash(&[b"unknown"]), 1);
        let mut index = Index::new(base());
        for (position, (commitment, record)) in chain.iter().chain(&stray).enumerate() {
            index
                .insert_record(*commitment, entry(record.parent(), position as u64))
                .unwrap();
        }
        let stored = |position| Stored {
            position,
            location: (0, 0),
        };
        let old = CertificateId::new(Sha256::hash(&[b"old"]));
        let kept = CertificateId::new(Sha256::hash(&[b"kept"]));
        index.insert_lqc(
            old,
            LqcEntry {
                history: chain[0].0,
                view: View::new(1),
                stored: stored(10),
            },
        );
        index.insert_lqc(
            kept,
            LqcEntry {
                history: chain[1].0,
                view: View::new(2),
                stored: stored(11),
            },
        );
        index.insert_cut(
            3,
            CutRow {
                lqc: old,
                history: chain[0].0,
                stored: stored(12),
            },
        );
        index.insert_cut(
            5,
            CutRow {
                lqc: kept,
                history: chain[1].0,
                stored: stored(13),
            },
        );

        let mut dropped = index.rebase(chain[1].0, Some(View::new(2))).unwrap();
        dropped.sort_unstable();
        // The first record, the stray, the old L-QC and its cut entry.
        assert_eq!(dropped, vec![0, 4, 10, 12]);
        assert_eq!(index.base(), chain[1].0);
        // Ordinals do not move.
        assert_eq!(index.ordinal(&chain[1].0), Some(2));
        assert_eq!(index.first(), 2);
        assert_eq!(index.ordinal(&chain[3].0), Some(4));
        assert_eq!(index.at(4), Some(chain[3].0));
        assert_eq!(index.at(1), None);
        assert!(index.record(&chain[1].0).is_some());
        assert!(index.lqc(&old).is_none());
        assert_eq!(index.lqcs_of(&chain[1].0), &[kept]);
        assert_eq!(
            index.cuts_at_most(10).map(|(at, _)| at).collect::<Vec<_>>(),
            vec![5]
        );
        // Records keep connecting above the new base.
        let next = records(chain[3].0, 1);
        assert_eq!(
            index
                .insert_record(next[0].0, entry(chain[3].0, 20))
                .unwrap(),
            Some(vec![next[0].0])
        );
        assert_eq!(index.tip(), 5);

        // A base that is not connected starts a fresh range above every ordinal used so far.
        let unrelated = records(Sha256::hash(&[b"elsewhere"]), 2);
        for (position, (commitment, record)) in unrelated.iter().enumerate() {
            index
                .insert_record(*commitment, entry(record.parent(), 30 + position as u64))
                .unwrap();
        }
        let dropped = index.rebase(unrelated[0].0, Some(View::new(2))).unwrap();
        // The four records of the old chain, its L-QC and its cut entry.
        assert_eq!(dropped.len(), 6);
        assert_eq!(index.ordinal(&unrelated[0].0), Some(6));
        assert_eq!(index.ordinal(&unrelated[1].0), Some(7));
    }

    fn config() -> Config {
        Config {
            prefix: "proofs".into(),
            buffers: Buffers {
                page_cache: CacheRef::new(NZU16!(1024), NZUsize!(16)),
                index_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            codec: CodecConfig::new(4, 2, PathLimits::new(2, 1)).unwrap(),
            segment_capacity: NZU64!(2),
            max_segments: NZUsize!(1024),
        }
    }

    async fn flush(proofs: &mut TestProofs) -> Vec<D> {
        let mut connected = Vec::new();
        while let Some(job) = proofs.start_append() {
            let Finished::Appended {
                connected: more, ..
            } = proofs.finish(job.run().await.unwrap()).unwrap()
            else {
                panic!("an append appends");
            };
            connected.extend(more);
        }
        if let Some(job) = proofs.start_cut().unwrap() {
            let Finished::Cut(durability) = proofs.finish(job.run().await.unwrap()).unwrap() else {
                panic!("a cut cuts");
            };
            let end = durability.await.unwrap();
            proofs.mark_durable(end);
        }
        connected
    }

    async fn read(proofs: &mut TestProofs, stored: Stored) -> Part<Bls<MinPk>, D> {
        let reader = match proofs.access(stored) {
            Access::Ready(reader) => reader,
            Access::Open(job) => {
                proofs.finish_open(job.run().await.unwrap());
                let Access::Ready(reader) = proofs.access(stored) else {
                    panic!("an opened segment is readable");
                };
                reader
            }
            Access::Opening | Access::Uncut => panic!("part is not readable"),
        };
        reader
            .get(stored.location.0, stored.location.1)
            .await
            .unwrap()
    }

    #[test]
    fn parts_survive_reopen_and_reconnect() {
        deterministic::Runner::default().start(|context| async move {
            let chain = records(base(), 3);
            let mut proofs = TestProofs::open(context.child("first"), config(), base(), None)
                .await
                .unwrap();
            for (commitment, record) in chain.iter().rev() {
                assert!(proofs.insert_record(*commitment, record.clone()));
                assert!(!proofs.insert_record(*commitment, record.clone()));
            }
            let lqc = CertificateId::new(Sha256::hash(&[b"lqc"]));
            let cut = CutEntry {
                lqc,
                boundary: vec![tip(0, 3), tip(1, 2)],
            };
            assert!(proofs.insert_cut(chain[2].0, cut.clone()));
            assert!(!proofs.insert_cut(chain[2].0, cut.clone()));
            let connected = flush(&mut proofs).await;
            assert_eq!(connected, chain.iter().map(|(c, _)| *c).collect::<Vec<_>>());
            let entry = *proofs.index().record(&chain[1].0).unwrap();
            assert!(proofs.durable(entry.stored));
            assert_eq!(
                read(&mut proofs, entry.stored).await,
                Part::Record(chain[1].1.clone())
            );
            drop(proofs);

            let mut proofs = TestProofs::open(context.child("second"), config(), base(), None)
                .await
                .unwrap();
            assert_eq!(proofs.index().tip(), 3);
            let (index, row) = proofs.index().cut_of(&lqc).unwrap();
            assert_eq!(index, 5);
            let row = *row;
            assert_eq!(row.history, chain[2].0);
            assert_eq!(
                read(&mut proofs, row.stored).await,
                Part::Cut(Arc::new(cut))
            );

            // Rebasing drops the older records from disk, durably once the caller cuts.
            proofs.rebase(chain[1].0, None).unwrap();
            assert!(proofs.index().record(&chain[0].0).is_none());
            if let Some(job) = proofs.start_reclaim() {
                proofs.finish(job.run().await.unwrap()).unwrap();
            }
            drop(proofs);
            let proofs = TestProofs::open(context.child("third"), config(), chain[1].0, None)
                .await
                .unwrap();
            assert_eq!(proofs.index().tip(), 1);
            assert_eq!(proofs.index().ordinal(&chain[2].0), Some(1));
            // The base's own record stays indexed, so a floor at the base stays servable.
            assert!(proofs.index().record(&chain[1].0).is_some());
        });
    }

    #[test]
    fn lqcs_are_indexed_by_their_historys_ordinal_once_it_connects() {
        let chain = records(base(), 3);
        let mut index = Index::new(base());
        let lqc = |name: &[u8], history, view| {
            (
                CertificateId::new(Sha256::hash(&[name])),
                LqcEntry {
                    history,
                    view: View::new(view),
                    stored: Stored {
                        position: view,
                        location: (0, 0),
                    },
                },
            )
        };
        // An L-QC whose history is not stored yet is unconnected.
        let (late, late_entry) = lqc(b"late", chain[2].0, 9);
        assert!(index.insert_lqc(late, late_entry));
        assert_eq!(
            index.unconnected().map(|(id, _)| id).collect::<Vec<_>>(),
            vec![late]
        );
        for (position, (commitment, record)) in chain.iter().enumerate() {
            index
                .insert_record(*commitment, entry(record.parent(), position as u64))
                .unwrap();
        }
        // Connecting its history moves it to that ordinal.
        assert_eq!(index.unconnected().count(), 0);
        assert_eq!(index.connected_at(3), &[late]);
        // An L-QC of a connected history is indexed at once; levels come in ordinal order.
        let (early, early_entry) = lqc(b"early", chain[0].0, 4);
        assert!(index.insert_lqc(early, early_entry));
        assert_eq!(
            index
                .connected_from(0)
                .map(|(ordinal, ids)| (ordinal, ids.to_vec()))
                .collect::<Vec<_>>(),
            vec![(1, vec![early]), (3, vec![late])]
        );
        assert_eq!(index.connected_from(2).count(), 1);
    }

    #[test]
    fn reindexing_keeps_the_base_record_and_drops_what_the_floor_obsoletes() {
        let chain = records(base(), 4);
        // Records a repair of a newer L-QC stored, not yet connected to the base.
        let repair = records(Sha256::hash(&[b"ahead"]), 2);
        // The index rebuilt at open after a floor at the second record.
        let mut index = Index::new(chain[1].0);
        for (position, (commitment, record)) in chain.iter().chain(&repair).enumerate() {
            index
                .insert_record(*commitment, entry(record.parent(), position as u64))
                .unwrap();
        }
        assert!(
            index.record(&chain[1].0).is_some(),
            "the base record is indexed"
        );
        assert_eq!(index.ordinal(&chain[3].0), Some(2));
        let stored = |position| Stored {
            position,
            location: (0, 0),
        };
        let lqc = |name: &[u8], history, view, position| {
            (
                CertificateId::new(Sha256::hash(&[name])),
                LqcEntry {
                    history,
                    view: View::new(view),
                    stored: stored(position),
                },
            )
        };
        let (old, old_entry) = lqc(b"old", chain[0].0, 1, 10);
        let (floor, floor_entry) = lqc(b"floor", chain[1].0, 2, 11);
        let (ahead, ahead_entry) = lqc(b"ahead", repair[1].0, 5, 12);
        assert!(index.insert_lqc(old, old_entry));
        assert!(index.insert_lqc(floor, floor_entry));
        assert!(index.insert_lqc(ahead, ahead_entry));
        assert!(
            !index.insert_lqc(ahead, ahead_entry),
            "a duplicate row is not indexed"
        );

        let mut dropped = index.drop_obsolete(Some(View::new(2)));
        dropped.sort_unstable();
        // The record below the base and the L-QC on it; the repair and its target stay.
        assert_eq!(dropped, vec![0, 10]);
        assert!(index.lqc(&old).is_none());
        assert!(index.lqc(&floor).is_some());
        assert!(index.lqc(&ahead).is_some());
        assert!(index.record(&repair[0].0).is_some());
        assert!(index.record(&repair[1].0).is_some());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::multimmit::types::arbitrary_codec_config;
        use arbitrary::{Arbitrary, Unstructured};
        use commonware_codec::{
            Decode as _, DecodeExt as _, Encode as _, conformance::generate_value,
        };
        use commonware_conformance::Conformance;
        use commonware_cryptography::bls12381::primitives::variant::MinSig;

        type TestPart = Part<Bls<MinSig>, Sha256Digest>;

        impl<'a> Arbitrary<'a> for Row<Sha256Digest> {
            fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
                let kind = match u.int_in_range(0..=2u8)? {
                    0 => Kind::Lqc,
                    1 => Kind::Record,
                    _ => Kind::Cut,
                };
                Ok(Self {
                    kind,
                    key: u.arbitrary()?,
                    link: u.arbitrary()?,
                    number: u.arbitrary()?,
                    offset: u.arbitrary()?,
                    size: u.arbitrary()?,
                })
            }
        }

        impl<'a> Arbitrary<'a> for TestPart {
            fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
                Ok(match u.int_in_range(0..=2u8)? {
                    0 => Self::Lqc(Arc::new(Artifact::Lqc(u.arbitrary()?))),
                    1 => Self::Record(Arc::new(u.arbitrary()?)),
                    _ => {
                        let boundary = (0..arbitrary_codec_config().chains())
                            .map(|chain| {
                                Ok(BlockRef::new(
                                    ChainId::new(chain as u32),
                                    u.arbitrary()?,
                                    u.arbitrary()?,
                                ))
                            })
                            .collect::<arbitrary::Result<_>>()?;
                        Self::Cut(Arc::new(CutEntry {
                            lqc: u.arbitrary()?,
                            boundary,
                        }))
                    }
                })
            }
        }

        struct RowConformance;

        impl Conformance for RowConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let row = generate_value::<Row<Sha256Digest>>(seed);
                let encoded = row.encode();
                assert_eq!(Row::decode(encoded.clone()).unwrap(), row);
                encoded.to_vec()
            }
        }

        struct PartConformance;

        impl Conformance for PartConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let part = generate_value::<TestPart>(seed);
                let encoded = part.encode();
                assert_eq!(
                    TestPart::decode_cfg(encoded.clone(), &arbitrary_codec_config()).unwrap(),
                    part
                );
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            RowConformance => 256,
            PartConformance => 128,
        }
    }
}
