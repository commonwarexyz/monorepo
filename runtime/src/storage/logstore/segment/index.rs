//! The in-memory extent index of one family: every committed log's logical
//! state, and where each committed byte physically lives.
//!
//! [Index::apply] is the backend's one application function. Live commits fold
//! their durable frame into the index, and recovery folds every replayed frame
//! through the same code, so the runtime index and the recovered index cannot
//! disagree. Everything here is pure bookkeeping: no I/O, no locks.

use super::format::{
    BlockSite, CatalogRow, ExtentRow, LogId, LogOffset, MAX_BLOCK_BYTES, NetOp, SegmentOffset,
    SegmentSeq, TxnSeq, ValidatedTxn,
};
use std::collections::BTreeMap;

/// Where `len` committed bytes physically live: at `payload` in `segment`,
/// with their 4-byte block checksum at `crc`. One extent is exactly one
/// checksummed block, so verifying any read of it hashes the whole extent.
#[derive(Clone, Copy, Debug)]
pub(super) struct Extent {
    pub len: u64,
    pub segment: SegmentSeq,
    pub payload: SegmentOffset,
    pub crc: SegmentOffset,
}

/// One committed log.
pub(super) struct LogState {
    pub name: Vec<u8>,
    /// Bumped by every committed mutation; frame descriptors carry the value
    /// they were validated against, and [Index::apply] checks it.
    pub generation: u64,
    /// Committed length in bytes.
    pub committed: u64,
    /// Extents by logical start offset, tiling `[0, committed)`. Rewind never
    /// touches disk, so an extent may physically extend past its successor's
    /// start; the successor is authoritative where they overlap.
    pub extents: BTreeMap<LogOffset, Extent>,
}

/// One step of a planned read: fetch the whole block of `extent`, verify its
/// checksum against the log and `at`, and serve `take` bytes starting `skip`
/// into it.
pub(super) struct ReadStep {
    /// The block's logical start offset (part of its checksum binding).
    pub at: LogOffset,
    pub extent: Extent,
    pub skip: u64,
    pub take: u64,
}

impl LogState {
    /// Plans a read of `[offset, offset + len)`, which the caller has checked
    /// against the committed length: the touched extents in order, each with
    /// the slice of its block to serve.
    pub fn plan(&self, offset: u64, len: u64) -> Vec<ReadStep> {
        let end = offset + len;
        let mut steps = Vec::new();
        let mut pos = offset;
        while pos < end {
            let (&at, extent) = self
                .extents
                .range(..=LogOffset(pos))
                .next_back()
                .expect("extents tile the committed range");
            let next = self
                .extents
                .range(LogOffset(at.0 + 1)..)
                .next()
                .map_or(u64::MAX, |(&next, _)| next.0);
            let usable = (at.0 + extent.len).min(next).min(end);
            steps.push(ReadStep {
                at,
                extent: *extent,
                skip: pos - at.0,
                take: usable - pos,
            });
            pos = usable;
        }
        steps
    }
}

/// The committed state of one family: what commits mutate and recovery
/// rebuilds.
#[derive(Default)]
pub(super) struct Index {
    /// Committed log name -> id.
    pub names: BTreeMap<Vec<u8>, LogId>,
    /// Committed log id -> log.
    pub logs: BTreeMap<LogId, LogState>,
    /// Log id minting floor; ids are never reused within an incarnation.
    pub next_log: LogId,
    /// The sequence the next committed frame must carry.
    pub next_txn: TxnSeq,
    /// Total extents across all logs, maintained so admission can fail closed
    /// before committing state a checkpoint could not hold.
    pub extent_count: u64,
    /// Committed payload bytes per segment (the live bytes cleaning
    /// measures). A key exists only while extents reference the segment, so
    /// the key set is exactly the referenced-segment list a checkpoint
    /// carries.
    pub live: BTreeMap<SegmentSeq, u64>,
}

/// One extent's move to a cleaned copy: the block serving `log` at `at` now
/// lives at `to`.
pub(super) struct Relocation {
    pub log: LogId,
    pub at: LogOffset,
    pub to: Extent,
}

impl Index {
    /// The one application function: folds one durable frame into the index.
    ///
    /// `sites` locate the frame's payload blocks
    /// ([ValidatedTxn::block_sites]) and `record_at` is where the record
    /// begins in `segment`. Every expectation the frame carries -- its
    /// sequence, and each descriptor's generation and committed length -- is
    /// checked against the index before anything mutates, so a failed apply
    /// leaves the index untouched. Failure means the frame does not extend
    /// the state every prior frame produced: corruption when replaying, a bug
    /// when live.
    pub fn apply(
        &mut self,
        txn: &ValidatedTxn,
        sites: &[BlockSite],
        segment: SegmentSeq,
        record_at: SegmentOffset,
    ) -> Result<(), String> {
        self.check(txn, sites)?;
        let mut sites = sites.iter();
        for (log, op) in txn.ops() {
            match op {
                NetOp::Create { name, run } => {
                    let id = self.next_log;
                    self.next_log = id.next();
                    self.names.insert(name.clone(), id);
                    let mut state = LogState {
                        name: name.clone(),
                        generation: 0,
                        committed: 0,
                        extents: BTreeMap::new(),
                    };
                    let added =
                        extend(&mut state, run.len() as u64, &mut sites, segment, record_at);
                    self.extent_count += added;
                    self.credit(segment, run.len() as u64);
                    self.logs.insert(id, state);
                }
                NetOp::Mutate { rewind_to, run, .. } => {
                    let state = self.logs.get_mut(log).expect("checked");
                    if let Some(to) = rewind_to {
                        let cut = state.extents.split_off(&LogOffset(*to));
                        state.committed = *to;
                        self.extent_count -= cut.len() as u64;
                        for extent in cut.values() {
                            self.debit(extent.segment, extent.len);
                        }
                    }
                    let state = self.logs.get_mut(log).expect("checked");
                    state.generation += 1;
                    let added = extend(state, run.len() as u64, &mut sites, segment, record_at);
                    self.extent_count += added;
                    self.credit(segment, run.len() as u64);
                }
                NetOp::Remove { .. } => {
                    let state = self.logs.remove(log).expect("checked");
                    self.extent_count -= state.extents.len() as u64;
                    for extent in state.extents.values() {
                        self.debit(extent.segment, extent.len);
                    }
                    self.names.remove(&state.name);
                }
            }
        }
        self.next_txn = self.next_txn.next();
        Ok(())
    }

    /// Adds `bytes` of committed payload to `segment`'s live count.
    fn credit(&mut self, segment: SegmentSeq, bytes: u64) {
        if bytes > 0 {
            *self.live.entry(segment).or_insert(0) += bytes;
        }
    }

    /// Removes `bytes` of committed payload from `segment`'s live count,
    /// dropping the key at zero so `live`'s key set stays exactly the
    /// referenced segments.
    fn debit(&mut self, segment: SegmentSeq, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let live = self.live.get_mut(&segment).expect("credited when added");
        *live -= bytes;
        if *live == 0 {
            self.live.remove(&segment);
        }
    }

    /// Moves extents to their cleaned copies. Physical bookkeeping only: no
    /// logical state changes, so this is deliberately NOT part of
    /// [Index::apply] -- its durability counterpart is the checkpoint that
    /// carries the new mappings, loaded back through
    /// [Index::from_checkpoint]. Every move must name an existing extent of
    /// the same length; validation completes before anything mutates.
    pub fn relocate(&mut self, moves: &[Relocation]) -> Result<(), String> {
        for m in moves {
            let log = self.logs.get(&m.log).ok_or("relocation of an absent log")?;
            let extent = log
                .extents
                .get(&m.at)
                .ok_or("relocation of an absent extent")?;
            if extent.len != m.to.len {
                return Err("relocation changes the extent length".into());
            }
        }
        for m in moves {
            let log = self.logs.get_mut(&m.log).expect("validated");
            let old = log.extents.insert(m.at, m.to).expect("validated");
            self.debit(old.segment, old.len);
            self.credit(m.to.segment, m.to.len);
        }
        Ok(())
    }

    /// Validates every expectation of the frame against the current index,
    /// mutating nothing.
    fn check(&self, txn: &ValidatedTxn, sites: &[BlockSite]) -> Result<(), String> {
        if txn.seq() != self.next_txn {
            return Err(format!(
                "frame sequence {} does not match expected {}",
                txn.seq().0,
                self.next_txn.0
            ));
        }
        let mut minted = self.next_log;
        let mut created: Vec<&[u8]> = Vec::new();
        let mut sites = sites.iter();
        for (log, op) in txn.ops() {
            let (anchor, mut run) = match op {
                NetOp::Create { name, run } => {
                    if *log != minted {
                        return Err("created log id is out of mint order".into());
                    }
                    minted = minted.next();
                    if self.names.contains_key(name) || created.contains(&name.as_slice()) {
                        return Err("created name is already taken".into());
                    }
                    created.push(name);
                    (0, run.len() as u64)
                }
                NetOp::Mutate {
                    generation,
                    committed,
                    rewind_to,
                    run,
                } => {
                    let state = self.logs.get(log).ok_or("operation on an absent log")?;
                    if state.generation != *generation || state.committed != *committed {
                        return Err("descriptor expectations do not match the log".into());
                    }
                    (rewind_to.unwrap_or(*committed), run.len() as u64)
                }
                NetOp::Remove {
                    generation,
                    committed,
                } => {
                    let state = self.logs.get(log).ok_or("operation on an absent log")?;
                    if state.generation != *generation || state.committed != *committed {
                        return Err("descriptor expectations do not match the log".into());
                    }
                    continue;
                }
            };
            // The sites must tile this op's run: same log, contiguous from
            // its anchor. A mismatch is a caller bug, caught before any
            // mutation.
            let mut at = anchor;
            while run > 0 {
                let Some(site) = sites.next() else {
                    return Err("payload sites do not match the frame".into());
                };
                if site.log != *log || site.at.0 != at || site.len > run {
                    return Err("payload sites do not match the frame".into());
                }
                at += site.len;
                run -= site.len;
            }
        }
        if sites.next().is_some() {
            return Err("payload sites do not match the frame".into());
        }
        Ok(())
    }

    /// Rebuilds the committed state a checkpoint describes, validating it as
    /// a whole (the shadow-index load): log ids strictly ascending and below
    /// the minting floor, names unique, and each log's extents -- in
    /// ascending (log, offset) order -- tiling its committed range exactly as
    /// [Index::apply] would have left them. Any violation is corruption: no
    /// sequence of applied frames produces it.
    pub fn from_checkpoint<'a>(
        rows: impl Iterator<Item = &'a CatalogRow>,
        extents: impl Iterator<Item = &'a ExtentRow>,
        next_log: LogId,
        next_txn: TxnSeq,
    ) -> Result<Self, String> {
        let mut index = Self {
            next_log,
            next_txn,
            ..Self::default()
        };
        let mut previous: Option<LogId> = None;
        for row in rows {
            if previous.is_some_and(|p| p >= row.log) {
                return Err("catalog rows are not in ascending log order".into());
            }
            previous = Some(row.log);
            if row.log >= next_log {
                return Err("catalog row at or above the log minting floor".into());
            }
            if index.names.insert(row.name.clone(), row.log).is_some() {
                return Err("duplicate log name in the catalog".into());
            }
            index.logs.insert(
                row.log,
                LogState {
                    name: row.name.clone(),
                    generation: row.generation,
                    committed: row.committed,
                    extents: BTreeMap::new(),
                },
            );
        }
        let mut previous: Option<(LogId, LogOffset)> = None;
        for extent in extents {
            if previous.is_some_and(|p| p >= (extent.log, extent.at)) {
                return Err("extents are not in ascending order".into());
            }
            previous = Some((extent.log, extent.at));
            if extent.len == 0 || extent.len > MAX_BLOCK_BYTES as u64 {
                return Err("invalid extent length".into());
            }
            let log = index
                .logs
                .get_mut(&extent.log)
                .ok_or("extent for an absent log")?;
            // Contiguity: the first extent starts the log; each next one
            // starts within its predecessor's reach (rewind can leave them
            // overlapping, never gapped).
            let reach = log
                .extents
                .last_key_value()
                .map(|(at, e)| at.0 + e.len)
                .unwrap_or(0);
            if extent.at.0 > reach {
                return Err("extents do not tile the committed range".into());
            }
            if extent.at.0 >= log.committed {
                return Err("extent past the committed length".into());
            }
            log.extents.insert(
                extent.at,
                Extent {
                    len: extent.len,
                    segment: extent.segment,
                    payload: extent.start,
                    crc: extent.crc,
                },
            );
            index.extent_count += 1;
            index.credit(extent.segment, extent.len);
        }
        for log in index.logs.values() {
            let covered = log
                .extents
                .last_key_value()
                .map(|(at, e)| at.0 + e.len)
                .unwrap_or(0);
            if covered < log.committed {
                return Err("extents do not cover the committed length".into());
            }
        }
        Ok(index)
    }
}

/// Records the checked sites tiling `run` appended bytes as extents of
/// `state`, advancing its committed length. Returns how many extents were
/// added.
fn extend<'a>(
    state: &mut LogState,
    run: u64,
    sites: &mut impl Iterator<Item = &'a BlockSite>,
    segment: SegmentSeq,
    record_at: SegmentOffset,
) -> u64 {
    let mut covered = 0;
    let mut added = 0;
    while covered < run {
        let site = sites.next().expect("sites checked against the frame");
        let replaced = state.extents.insert(
            site.at,
            Extent {
                len: site.len,
                segment,
                payload: SegmentOffset(record_at.0 + site.payload as u64),
                crc: SegmentOffset(record_at.0 + site.crc as u64),
            },
        );
        // New appends land above every surviving key (rewind cut anything at
        // or past the anchor), so this never replaces.
        debug_assert!(replaced.is_none());
        state.committed += site.len;
        covered += site.len;
        added += 1;
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sites tiling the runs of `ops` in order, with fabricated record
    /// positions (32 bytes apart, checksums at 1000 + 4i).
    fn sites(ops: &[(LogId, NetOp)]) -> Vec<BlockSite> {
        let mut sites = Vec::new();
        for (log, op) in ops {
            let anchor = match op {
                NetOp::Create { .. } => 0,
                NetOp::Mutate {
                    committed,
                    rewind_to,
                    ..
                } => rewind_to.unwrap_or(*committed),
                NetOp::Remove { .. } => continue,
            };
            let run = match op {
                NetOp::Create { run, .. } | NetOp::Mutate { run, .. } => run.len() as u64,
                NetOp::Remove { .. } => 0,
            };
            if run > 0 {
                let i = sites.len();
                sites.push(BlockSite {
                    log: *log,
                    at: LogOffset(anchor),
                    len: run,
                    payload: 32 * i,
                    crc: 1000 + 4 * i,
                });
            }
        }
        sites
    }

    fn apply(index: &mut Index, seq: u64, ops: Vec<(LogId, NetOp)>) -> Result<(), String> {
        let txn = ValidatedTxn::new(0, TxnSeq(seq), ops).unwrap();
        let sites = sites(txn.ops());
        index.apply(&txn, &sites, SegmentSeq(1), SegmentOffset(4096))
    }

    fn create(name: &[u8], run: &[u8]) -> NetOp {
        NetOp::Create {
            name: name.to_vec(),
            run: run.to_vec(),
        }
    }

    #[test]
    fn apply_folds_and_plan_covers_rewound_extents() {
        let mut index = Index::default();
        apply(&mut index, 0, vec![(LogId(0), create(b"a", b"hello"))]).unwrap();
        apply(
            &mut index,
            1,
            vec![(
                LogId(0),
                NetOp::Mutate {
                    generation: 0,
                    committed: 5,
                    rewind_to: None,
                    run: b" world".to_vec(),
                },
            )],
        )
        .unwrap();
        // Rewind into the middle of the second extent, then reappend: the old
        // block still serves [5, 8), the new extent starts at 8.
        apply(
            &mut index,
            2,
            vec![(
                LogId(0),
                NetOp::Mutate {
                    generation: 1,
                    committed: 11,
                    rewind_to: Some(8),
                    run: b"XYZ".to_vec(),
                },
            )],
        )
        .unwrap();
        let log = &index.logs[&LogId(0)];
        assert_eq!((log.generation, log.committed), (2, 11));
        let steps = log.plan(0, 11);
        let spans: Vec<_> = steps.iter().map(|s| (s.at, s.skip, s.take)).collect();
        assert_eq!(
            spans,
            vec![
                (LogOffset(0), 0, 5),
                (LogOffset(5), 0, 3),
                (LogOffset(8), 0, 3)
            ]
        );
        // A read within the straddled block verifies against the block's
        // original binding.
        let steps = log.plan(6, 2);
        assert_eq!(steps.len(), 1);
        assert_eq!(
            (steps[0].at, steps[0].skip, steps[0].take),
            (LogOffset(5), 1, 2)
        );
    }

    #[test]
    fn apply_rejects_mismatched_expectations() {
        let mut index = Index::default();
        apply(&mut index, 0, vec![(LogId(0), create(b"a", b"x"))]).unwrap();
        // Wrong sequence.
        assert!(apply(&mut index, 5, Vec::new()).is_err());
        // Wrong generation.
        assert!(
            apply(
                &mut index,
                1,
                vec![(
                    LogId(0),
                    NetOp::Remove {
                        generation: 3,
                        committed: 1
                    }
                )],
            )
            .is_err()
        );
        // Wrong committed length.
        assert!(
            apply(
                &mut index,
                1,
                vec![(
                    LogId(0),
                    NetOp::Mutate {
                        generation: 0,
                        committed: 2,
                        rewind_to: None,
                        run: b"y".to_vec()
                    }
                )],
            )
            .is_err()
        );
        // Absent log, taken name, and an out-of-order mint.
        assert!(
            apply(
                &mut index,
                1,
                vec![(
                    LogId(9),
                    NetOp::Remove {
                        generation: 0,
                        committed: 0
                    }
                )],
            )
            .is_err()
        );
        assert!(apply(&mut index, 1, vec![(LogId(1), create(b"a", b""))]).is_err());
        assert!(apply(&mut index, 1, vec![(LogId(7), create(b"b", b""))]).is_err());
        // Every rejection left the index untouched.
        assert_eq!(index.next_txn, TxnSeq(1));
        assert_eq!(index.logs[&LogId(0)].generation, 0);
        // A matching frame still applies.
        apply(
            &mut index,
            1,
            vec![(
                LogId(0),
                NetOp::Remove {
                    generation: 0,
                    committed: 1,
                },
            )],
        )
        .unwrap();
        assert!(index.names.is_empty());
    }

    /// Builds the rewind-overlap index of
    /// [apply_folds_and_plan_covers_rewound_extents]: extents at 0, 5, and 8,
    /// committed length 11, where the extent at 5 physically reaches past its
    /// successor.
    fn overlapping_index() -> Index {
        let mut index = Index::default();
        apply(&mut index, 0, vec![(LogId(0), create(b"a", b"hello"))]).unwrap();
        for (seq, (generation, committed, rewind_to, run)) in [
            (0, 5, None, b" world".to_vec()),
            (1, 11, Some(8), b"XYZ".to_vec()),
        ]
        .into_iter()
        .enumerate()
        {
            apply(
                &mut index,
                seq as u64 + 1,
                vec![(
                    LogId(0),
                    NetOp::Mutate {
                        generation,
                        committed,
                        rewind_to,
                        run,
                    },
                )],
            )
            .unwrap();
        }
        apply(&mut index, 3, vec![(LogId(1), create(b"empty", b""))]).unwrap();
        index
    }

    /// Snapshots rows and extents the way a checkpoint does.
    fn snapshot(index: &Index) -> (Vec<CatalogRow>, Vec<ExtentRow>) {
        let rows = index
            .logs
            .iter()
            .map(|(&log, s)| CatalogRow {
                log,
                generation: s.generation,
                committed: s.committed,
                name: s.name.clone(),
            })
            .collect();
        let extents = index
            .logs
            .iter()
            .flat_map(|(&log, s)| {
                s.extents.iter().map(move |(&at, e)| ExtentRow {
                    log,
                    at,
                    segment: e.segment,
                    start: e.payload,
                    len: e.len,
                    crc: e.crc,
                })
            })
            .collect();
        (rows, extents)
    }

    /// A snapshotted index rebuilds identically through the validating load,
    /// including overlapping rewound extents and empty logs.
    #[test]
    fn from_checkpoint_rebuilds_the_index() {
        let index = overlapping_index();
        let (rows, extents) = snapshot(&index);
        let rebuilt =
            Index::from_checkpoint(rows.iter(), extents.iter(), index.next_log, index.next_txn)
                .unwrap();
        assert_eq!(rebuilt.names, index.names);
        assert_eq!(rebuilt.next_log, index.next_log);
        assert_eq!(rebuilt.next_txn, index.next_txn);
        assert_eq!(rebuilt.extent_count, index.extent_count);
        assert_eq!(rebuilt.live, index.live);
        for (id, log) in &index.logs {
            let restored = &rebuilt.logs[id];
            assert_eq!(restored.generation, log.generation);
            assert_eq!(restored.committed, log.committed);
            let plan = |l: &LogState| {
                l.plan(0, l.committed)
                    .iter()
                    .map(|s| (s.at, s.extent.payload, s.skip, s.take))
                    .collect::<Vec<_>>()
            };
            assert_eq!(plan(restored), plan(log));
        }
    }

    /// The validating load rejects every state no sequence of applied frames
    /// can produce.
    #[test]
    fn from_checkpoint_rejects_impossible_states() {
        let index = overlapping_index();
        let (rows, extents) = snapshot(&index);
        let load = |rows: &[CatalogRow], extents: &[ExtentRow]| {
            Index::from_checkpoint(rows.iter(), extents.iter(), index.next_log, index.next_txn)
        };

        // Rows out of order, above the minting floor, or name-colliding.
        let reversed: Vec<CatalogRow> = rows.iter().rev().cloned().collect();
        assert!(load(&reversed, &extents).is_err());
        let mut floored = rows.clone();
        floored[1].log = index.next_log;
        assert!(load(&floored, &extents).is_err());
        let mut collided = rows.clone();
        collided[1].name = rows[0].name.clone();
        assert!(load(&collided, &extents).is_err());

        // Extents out of order, gapped, short, orphaned, past the committed
        // length, or with an impossible length.
        let swapped: Vec<ExtentRow> = extents.iter().rev().cloned().collect();
        assert!(load(&rows, &swapped).is_err());
        let gapped: Vec<ExtentRow> = vec![extents[0], extents[2]];
        assert!(load(&rows, &gapped).is_err());
        assert!(load(&rows, &extents[..1]).is_err());
        let mut orphaned = extents.clone();
        orphaned[0].log = LogId(9);
        assert!(load(&rows, &orphaned).is_err());
        let mut past = extents.clone();
        past[2].at = LogOffset(11);
        assert!(load(&rows, &past).is_err());
        let mut hollow = extents;
        hollow[0].len = 0;
        assert!(load(&rows, &hollow).is_err());
    }

    /// Live bytes per segment follow appends, rewinds, and removes: rewinds
    /// refund a cut extent's full length (the straddled block stays live
    /// whole), and a segment's key vanishes with its last extent.
    #[test]
    fn live_bytes_track_apply() {
        let mut index = overlapping_index();
        // Extents: "hello" (5), " world" (6), "XYZ" (3), all in segment 1.
        assert_eq!(index.live, BTreeMap::from([(SegmentSeq(1), 14)]));
        // Remove log 0: only the empty log remains, referencing nothing.
        apply(
            &mut index,
            4,
            vec![(
                LogId(0),
                NetOp::Remove {
                    generation: 2,
                    committed: 11,
                },
            )],
        )
        .unwrap();
        assert!(index.live.is_empty());
    }

    /// Relocation moves extents between segments, keeps live bytes exact,
    /// preserves read plans, and rejects moves no cleaning can produce.
    #[test]
    fn relocate_moves_extents() {
        let mut index = overlapping_index();
        let plan_before: Vec<_> = index.logs[&LogId(0)]
            .plan(0, 11)
            .iter()
            .map(|s| (s.at, s.skip, s.take))
            .collect();

        // Reject: absent log, absent extent, changed length.
        let to = Extent {
            len: 6,
            segment: SegmentSeq(9),
            payload: SegmentOffset(4096),
            crc: SegmentOffset(5000),
        };
        for (log, at, to) in [
            (LogId(7), LogOffset(5), to),
            (LogId(0), LogOffset(6), to),
            (LogId(0), LogOffset(5), Extent { len: 7, ..to }),
        ] {
            assert!(index.relocate(&[Relocation { log, at, to }]).is_err());
        }
        assert_eq!(index.live, BTreeMap::from([(SegmentSeq(1), 14)]));

        // Move the extent at 5 to segment 9.
        index
            .relocate(&[Relocation {
                log: LogId(0),
                at: LogOffset(5),
                to,
            }])
            .unwrap();
        assert_eq!(
            index.live,
            BTreeMap::from([(SegmentSeq(1), 8), (SegmentSeq(9), 6)])
        );
        let log = &index.logs[&LogId(0)];
        let plan_after: Vec<_> = log
            .plan(0, 11)
            .iter()
            .map(|s| (s.at, s.skip, s.take))
            .collect();
        assert_eq!(plan_before, plan_after);
        let moved = log.plan(6, 1);
        assert_eq!(moved[0].extent.segment, SegmentSeq(9));
        assert_eq!(moved[0].extent.payload, SegmentOffset(4096));
    }

    /// The extent counter follows appends, rewinds, and removes.
    #[test]
    fn extent_count_tracks_apply() {
        let mut index = overlapping_index();
        assert_eq!(index.extent_count, 3);
        // Rewind to 7 cuts the extent at 8 (the one at 5 still straddles);
        // the reappend adds one back.
        apply(
            &mut index,
            4,
            vec![(
                LogId(0),
                NetOp::Mutate {
                    generation: 2,
                    committed: 11,
                    rewind_to: Some(7),
                    run: b"12".to_vec(),
                },
            )],
        )
        .unwrap();
        assert_eq!(index.extent_count, 3);
        apply(
            &mut index,
            5,
            vec![(
                LogId(0),
                NetOp::Remove {
                    generation: 3,
                    committed: 9,
                },
            )],
        )
        .unwrap();
        assert_eq!(index.extent_count, 0);
    }
}
