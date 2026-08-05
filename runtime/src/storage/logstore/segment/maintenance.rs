//! Post-commit maintenance of one family: checkpoints, rotation, and the
//! cleaner, sharing one publication pipeline and one root flip.
//!
//! The v1 posture is one writer and no background tasks, so maintenance runs
//! inline while the writer is held: after the commit that made it due, when
//! admission detects reserve pressure, and when an open loads a family whose
//! uncheckpointed span already reached the trigger (so a family can never
//! wedge against the replay ceilings). Every pass is the same pipeline, and
//! the root flip is its single commit point:
//!
//! 1. **Copy.** Live extents of victim segments are re-verified and
//!    rewritten as [RelocatedExtent] records into a fresh copy segment,
//!    published under the reachability rule. Victims are selected by
//!    measured copy economics and age only: oldest first, encoded copy cost
//!    at most half the record bytes it reclaims, and at most one output
//!    segment of copy work per pass. A dead segment (zero live bytes) needs
//!    no copy at all -- any checkpoint stops referencing it.
//! 2. **Rotate.** When the active segment's records reach the segment
//!    target, a fresh active segment is published. The old active is sealed
//!    by the root flip below and never written again.
//! 3. **Checkpoint.** The committed index -- relocations applied -- is
//!    written as a dedicated sealed segment, and the root flips to it.
//!    Crash before the flip: the copies and the fresh active are
//!    unreferenced garbage the next open sweeps, and the old segments stay
//!    authoritative. Crash after: the copies are authoritative and the
//!    victims became garbage.
//! 4. **Retire.** Segments the new root no longer references are unlinked
//!    once no in-flight read pins them; a pinned segment waits in the
//!    retired set for a later pass. Unlink durability rides later barriers:
//!    a resurrected leftover is swept at the next open.
//!
//! Failure anywhere after planning poisons the family (uncertain mutable
//! I/O); recovery reloads the last durable root, under which an unfinished
//! pass never happened. Counters are plain [Metrics] fields read by tests;
//! real telemetry arrives with the runtime integration.

use super::{
    super::family::Liveness,
    format::{
        CatalogRow, Checkpoint, CheckpointLocator, CheckpointSeq, ExtentRow, Identity, LogId,
        LogOffset, RelocatedExtent, Root, SEGMENT_RECORDS, Salt, SegmentHeader, SegmentOffset,
        SegmentSeq, relocated_bytes_bound,
    },
    index::{Extent, Relocation},
    medium::Medium,
    publish::{flip_root, publish},
    store::{
        BlockFault, Sealed, Shared, corrupt, poison, read_verified_block, segment_name,
        staging_name,
    },
};
use crate::Error;
use std::{collections::BTreeMap, sync::Arc};

/// Plain counters of maintenance activity, read by tests.
#[derive(Default)]
pub(super) struct Metrics {
    pub checkpoints: u64,
    pub rotations: u64,
    /// Passes that copied at least one extent.
    pub cleanings: u64,
    pub relocated_extents: u64,
    pub relocated_bytes: u64,
    /// Transactions committed as dedicated segments.
    pub dedicated_segments: u64,
    pub retired_segments: u64,
    pub unlinked_segments: u64,
}

/// One extent to copy: where its verified bytes are read from.
struct CopySource<M: Medium> {
    log: LogId,
    at: LogOffset,
    file: M::File,
    extent: Extent,
}

/// One maintenance pass, planned under the state lock and executed outside
/// it. The transaction (or open) holding the writer keeps the index from
/// moving; sealed segments are immutable, so the copy sources stay valid.
struct Pass<M: Medium> {
    manifest: M::File,
    copies: Vec<CopySource<M>>,
    /// Minted sequence for the copy segment; Some exactly when `copies` is
    /// nonempty.
    copy_seq: Option<SegmentSeq>,
    /// Minted sequence for rotation's fresh active segment.
    rotate_seq: Option<SegmentSeq>,
    /// Minted sequence for the checkpoint segment.
    checkpoint_file: SegmentSeq,
    checkpoint_seq: CheckpointSeq,
    /// The mint floor once this pass installs.
    next_segment: SegmentSeq,
}

/// Runs one maintenance pass if anything is due (`force` makes the
/// checkpoint mandatory: a dedicated-segment commit is unreachable to replay
/// until a checkpoint references it). Callers hold the family's writer.
/// Failure after planning poisons the family and returns the error the
/// caller reports.
pub(super) async fn maintain<M: Medium>(
    shared: &Arc<Shared<M>>,
    session: u64,
    force: bool,
) -> Result<(), Error> {
    // The pass has not run, but the caller's commit has: skipping maintenance
    // on a failed probe would leave a dedicated commit replay-unreachable (a
    // silent seq gap that truncates its acknowledged successors), so a probe
    // failure poisons like any other uncertain maintenance outcome.
    let free = match shared.medium.free_bytes().await {
        Ok(free) => free,
        Err(_) => return Err(super::store::poison(shared)),
    };

    let pass = match plan(shared, session, free, force) {
        Ok(Some(pass)) => pass,
        Ok(None) => return drain_retired(shared, session).await,
        // The family was poisoned or destroyed in the window since the
        // commit installed. An active-segment frame is already
        // replay-reachable, so a non-forced pass stands down and the commit
        // stays acknowledged. A forced pass must report: its dedicated
        // segment is unreferenced until a checkpoint lands, and
        // acknowledging would let recovery sweep an acknowledged
        // transaction.
        Err(error) => return if force { Err(error) } else { Ok(()) },
    };

    let (copy, moves) = copy_live(shared, &pass).await?;

    // Rotate: publish the fresh active segment (header only) so its dentry
    // is durable before the root flip names it.
    let rotated = match pass.rotate_seq {
        None => None,
        Some(seq) => {
            let bytes = SegmentHeader {
                incarnation: shared.incarnation,
                seq,
            }
            .encode();
            let name = segment_name(&shared.name, seq);
            let staging = staging_name(&shared.name);
            match publish(&shared.medium, &shared.dir, &staging, &name, bytes).await {
                Ok(file) => Some((seq, file)),
                Err(_) => return Err(poison(shared)),
            }
        }
    };

    let (checkpoint, mut root, old_checkpoint, salt) =
        snapshot(shared, session, &pass, copy, &moves)?;

    // Publish the checkpoint, then flip the root to it: the pass's one
    // commit point.
    let ident = Identity {
        salt,
        segment: pass.checkpoint_file,
    };
    let mut bytes = SegmentHeader {
        incarnation: shared.incarnation,
        seq: pass.checkpoint_file,
    }
    .encode();
    checkpoint.encode(&ident, &mut bytes);
    let len = (bytes.len() - SEGMENT_RECORDS.0 as usize) as u64;
    let name = segment_name(&shared.name, pass.checkpoint_file);
    let staging = staging_name(&shared.name);
    if publish(&shared.medium, &shared.dir, &staging, &name, bytes)
        .await
        .is_err()
    {
        return Err(poison(shared));
    }
    root.checkpoint = Some(CheckpointLocator {
        segment: pass.checkpoint_file,
        start: SEGMENT_RECORDS,
        len,
        seq: pass.checkpoint_seq,
        hash: checkpoint.end().hash,
    });
    if flip_root(&pass.manifest, &shared.incarnation, &root)
        .await
        .is_err()
    {
        return Err(poison(shared));
    }

    install(shared, session, &pass, root, rotated)?;

    // The superseded checkpoint is unreferenced once the new root is
    // durable. Its removal need not be durable: recovery sweeps resurrected
    // leftovers.
    if let Some(old) = old_checkpoint {
        let name = segment_name(&shared.name, old);
        if shared.medium.remove(&shared.dir, &name).await.is_err() {
            return Err(poison(shared));
        }
    }
    drain_retired(shared, session).await
}

/// Decides one pass under the state lock: what is due, which victims to
/// clean, and the segment sequences the pass will mint. Ok(None) when
/// nothing is due; an error when the family is no longer this session's to
/// maintain (nothing effectful has run, so the caller owns what a bail
/// means).
fn plan<M: Medium>(
    shared: &Arc<Shared<M>>,
    session: u64,
    free: Option<u64>,
    force: bool,
) -> Result<Option<Pass<M>>, Error> {
    let mut state = shared.state.lock();
    // Test fuse: models a concurrent read poisoning the family in the window
    // between a commit's install and its maintenance pass.
    if state.control.poison_next_maintenance {
        state.control.poison_next_maintenance = false;
        if matches!(state.control.liveness, Liveness::Open) {
            state.control.liveness = Liveness::Poisoned;
        }
    }
    state.control.ensure_open(&shared.name, session)?;
    let target = shared.limits.segment_target_bytes;
    let rotate_due = state.tail.0 - SEGMENT_RECORDS.0 >= target;
    let span_bytes = state.tail.0 - state.root.replay_at.0;
    let span_txns = state.index.next_txn.0 - state.root.replay_from.0;
    let span_due = span_bytes >= shared.limits.checkpoint_trigger_bytes
        || span_txns >= shared.limits.checkpoint_trigger_txns;

    // The cleaner's economics, in encoded bytes: copying a sealed segment's
    // live extents costs their relocated records, and unlinking it then
    // reclaims its record bytes. A segment is eligible only when the copy
    // pays for itself (at most half the record bytes), and only realizable
    // gain counts as reclaimable -- live payload and its framing are not
    // garbage, and a segment whose extents are too small to move profitably
    // must not keep cleaning due forever.
    let mut costs: BTreeMap<SegmentSeq, u64> = state.sealed.keys().map(|&seq| (seq, 0)).collect();
    for log in state.index.logs.values() {
        for extent in log.extents.values() {
            if let Some(cost) = costs.get_mut(&extent.segment) {
                *cost += relocated_bytes_bound(extent.len);
            }
        }
    }
    let mut dead = false;
    let mut reclaimable = 0u64;
    let mut eligible: Vec<SegmentSeq> = Vec::new();
    for (seq, sealed) in &state.sealed {
        let records = sealed.bytes - SEGMENT_RECORDS.0;
        let cost = costs[seq];
        if cost == 0 {
            // Dead: any checkpoint stops referencing it; no copy at all.
            dead = true;
            reclaimable += records;
        } else if 2 * cost <= records {
            reclaimable += records - cost;
            eligible.push(*seq);
        }
    }
    let pressure = free.is_some_and(|f| f < shared.limits.admission_floor(&shared.bounds));
    let clean_due = reclaimable >= target || (pressure && reclaimable > 0);

    // Victims by age only among the eligible: oldest first, one output
    // segment of encoded copy work per pass.
    let mut victims: Vec<SegmentSeq> = Vec::new();
    let mut copies: Vec<CopySource<M>> = Vec::new();
    if clean_due {
        let mut budget = target;
        for seq in eligible {
            let cost = costs[&seq];
            if cost <= budget {
                budget -= cost;
                victims.push(seq);
            }
        }
        for (&log, ls) in &state.index.logs {
            for (&at, extent) in &ls.extents {
                if victims.contains(&extent.segment) {
                    copies.push(CopySource {
                        log,
                        at,
                        file: state.sealed[&extent.segment].file.clone(),
                        extent: *extent,
                    });
                }
            }
        }
    }

    // A cleaning-only pass must have something to gain; dead segments are
    // dropped by the checkpoint itself.
    if !(force || rotate_due || span_due || (clean_due && (dead || !victims.is_empty()))) {
        return Ok(None);
    }
    let mut next = state.next_segment;
    let mut mint = || {
        let seq = next;
        next = SegmentSeq(next.0 + 1);
        seq
    };
    let copy_seq = (!copies.is_empty()).then(&mut mint);
    let rotate_seq = rotate_due.then(&mut mint);
    let checkpoint_file = mint();
    Ok(Some(Pass {
        manifest: state.manifest.clone(),
        copies,
        copy_seq,
        rotate_seq,
        checkpoint_file,
        checkpoint_seq: state
            .root
            .checkpoint
            .map_or(CheckpointSeq(0), |c| CheckpointSeq(c.seq.0 + 1)),
        next_segment: next,
    }))
}

/// The cleaner's copy stage: read and re-verify every victim extent, encode
/// the [RelocatedExtent] records, and publish them as a fresh sealed segment
/// under the reachability rule. Returns the published segment (None when the
/// pass copies nothing) and the relocations the snapshot installs.
async fn copy_live<M: Medium>(
    shared: &Arc<Shared<M>>,
    pass: &Pass<M>,
) -> Result<(Option<(SegmentSeq, Sealed<M::File>)>, Vec<Relocation>), Error> {
    let Some(seq) = pass.copy_seq else {
        return Ok((None, Vec::new()));
    };
    let ident = Identity {
        salt: shared.state.lock().salt,
        segment: seq,
    };
    let mut bytes = SegmentHeader {
        incarnation: shared.incarnation,
        seq,
    }
    .encode();
    let mut moves = Vec::with_capacity(pass.copies.len());
    for source in &pass.copies {
        let block = match read_verified_block(
            &source.file,
            &ident.salt,
            source.log,
            source.at,
            &source.extent,
        )
        .await
        {
            Ok(block) => block,
            Err(BlockFault::Io(_)) => return Err(poison(shared)),
            // The same corruption classes the read path reports, naming the
            // damaged victim.
            Err(fault) => {
                let victim = source.extent.segment.0;
                let reason = match fault {
                    BlockFault::Short => {
                        format!("extent read past the end of victim segment {victim}")
                    }
                    _ => format!("payload block checksum mismatch in victim segment {victim}"),
                };
                let _ = poison(shared);
                return Err(corrupt(&shared.name, reason));
            }
        };
        let record = RelocatedExtent::new(source.log, source.at, block)
            .expect("index extents are valid blocks");
        let start = bytes.len();
        let site = record.encode(&ident, &mut bytes);
        moves.push(Relocation {
            log: source.log,
            at: source.at,
            to: Extent {
                len: source.extent.len,
                segment: seq,
                payload: SegmentOffset((start + site.payload) as u64),
                crc: SegmentOffset((start + site.crc) as u64),
            },
        });
    }
    let total = bytes.len() as u64;
    let name = segment_name(&shared.name, seq);
    let staging = staging_name(&shared.name);
    let file = publish(&shared.medium, &shared.dir, &staging, &name, bytes)
        .await
        .map_err(|_| poison(shared))?;
    Ok((Some((seq, Sealed { file, bytes: total })), moves))
}

/// The snapshot stage, under the state lock: install the relocations, then
/// derive the checkpoint and the root that will govern once it flips. From
/// here every concurrent read follows the moved extents: their copy
/// segment's dentry is already durable, and the victims stay on disk until
/// retirement.
fn snapshot<M: Medium>(
    shared: &Arc<Shared<M>>,
    session: u64,
    pass: &Pass<M>,
    copy: Option<(SegmentSeq, Sealed<M::File>)>,
    moves: &[Relocation],
) -> Result<(Checkpoint, Root, Option<SegmentSeq>, Salt), Error> {
    let mut state = shared.state.lock();
    state.control.ensure_open(&shared.name, session)?;
    if let Some((seq, sealed)) = copy {
        state.sealed.insert(seq, sealed);
        state.metrics.cleanings += 1;
        state.metrics.relocated_extents += moves.len() as u64;
        state.metrics.relocated_bytes += moves.iter().map(|m| m.to.len).sum::<u64>();
    }
    if let Err(reason) = state.index.relocate(moves) {
        state.control.liveness = Liveness::Poisoned;
        return Err(corrupt(&shared.name, reason));
    }
    let rows: Vec<CatalogRow> = state
        .index
        .logs
        .iter()
        .map(|(&log, s)| CatalogRow {
            log,
            generation: s.generation,
            committed: s.committed,
            name: s.name.clone(),
        })
        .collect();
    let extents: Vec<ExtentRow> = state
        .index
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
    // The referenced-segment list is exactly the segments live extents
    // occupy.
    let segments: Vec<SegmentSeq> = state.index.live.keys().copied().collect();
    let root = Root {
        seq: state.root.seq + 1,
        epoch: state.salt.epoch(),
        checkpoint: None,
        active_segment: pass.rotate_seq.unwrap_or(state.active_seq),
        replay_from: state.index.next_txn,
        replay_at: if pass.rotate_seq.is_some() {
            SEGMENT_RECORDS
        } else {
            state.tail
        },
        next_log: state.index.next_log,
        next_txn: state.index.next_txn,
    };
    let old_checkpoint = state.root.checkpoint.map(|c| c.segment);
    let checkpoint = match Checkpoint::new(
        pass.checkpoint_seq,
        rows,
        extents,
        segments,
        root.next_log,
        root.replay_from,
    ) {
        Ok(checkpoint) => checkpoint,
        // Unreachable while admission fails closed on the checkpoint
        // caps; poison rather than trust the state.
        Err(reason) => {
            state.control.liveness = Liveness::Poisoned;
            return Err(corrupt(&shared.name, reason));
        }
    };
    Ok((checkpoint, root, old_checkpoint, state.salt))
}

/// The install stage, under the state lock: the durable root now governs.
/// Seal the rotated-out active segment, and retire every sealed segment the
/// new checkpoint stopped referencing.
fn install<M: Medium>(
    shared: &Arc<Shared<M>>,
    session: u64,
    pass: &Pass<M>,
    root: Root,
    rotated: Option<(SegmentSeq, M::File)>,
) -> Result<(), Error> {
    let mut state = shared.state.lock();
    state.control.ensure_open(&shared.name, session)?;
    state.root = root;
    state.next_segment = pass.next_segment;
    state.metrics.checkpoints += 1;
    if let Some((seq, file)) = rotated {
        let old_seq = state.active_seq;
        let old_file = std::mem::replace(&mut state.active, file);
        let old_bytes = state.tail.0;
        state.active_seq = seq;
        state.tail = SEGMENT_RECORDS;
        if state.index.live.contains_key(&old_seq) {
            state.sealed.insert(
                old_seq,
                Sealed {
                    file: old_file,
                    bytes: old_bytes,
                },
            );
        } else {
            state.retired.push(old_seq);
            state.metrics.retired_segments += 1;
        }
        state.metrics.rotations += 1;
    }
    let gone: Vec<SegmentSeq> = state
        .sealed
        .keys()
        .filter(|seq| !state.index.live.contains_key(seq))
        .copied()
        .collect();
    for seq in gone {
        state.sealed.remove(&seq);
        state.retired.push(seq);
        state.metrics.retired_segments += 1;
    }
    Ok(())
}

/// Unlinks retired segments no in-flight read pins; pinned ones wait for a
/// later pass. Unlink failure poisons: the family's view of its directory is
/// uncertain.
pub(super) async fn drain_retired<M: Medium>(
    shared: &Arc<Shared<M>>,
    session: u64,
) -> Result<(), Error> {
    let unlinkable: Vec<SegmentSeq> = {
        let mut state = shared.state.lock();
        // Stand down silently: the retirements belong to the live session.
        if state.control.ensure_open(&shared.name, session).is_err() {
            return Ok(());
        }
        let pins = std::mem::take(&mut state.pins);
        let (drop_now, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut state.retired)
            .into_iter()
            .partition(|seq| !pins.contains_key(seq));
        state.pins = pins;
        state.retired = keep;
        drop_now
    };
    for seq in unlinkable {
        let name = segment_name(&shared.name, seq);
        if shared.medium.remove(&shared.dir, &name).await.is_err() {
            return Err(poison(shared));
        }
        shared.state.lock().metrics.unlinked_segments += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            format::PAGE,
            medium::{File as _, Sim},
            store::{
                Limits, Log, LogStorage,
                tests::{
                    DIR, EVERY_COMMIT, Fault, Model, commit_append, commit_log, family_shared,
                    governing_root, limited_store, read_all, read_state, run_crash_scenario,
                },
            },
        },
        *,
    };
    use crate::{Error, LogFamily as _, LogStorage as _, LogTransaction as _};

    /// Limits scaled so rotation and cleaning are reachable in a few small
    /// commits: `target` bytes per segment, checkpoint caps and reserve to
    /// match.
    fn tiny(target: u64) -> Limits {
        Limits {
            checkpoint_logs: 64,
            checkpoint_extents: 256,
            segment_target_bytes: target,
            cleaner_reserve_bytes: 64 << 10,
            ..Limits::default()
        }
    }

    /// A store with `target`-sized segments and the default trigger, so only
    /// rotation and cleaning force checkpoints.
    fn rotating_store(sim: &Sim, entropy: u8, target: u64) -> LogStorage<Sim> {
        limited_store(sim, entropy, tiny(target))
    }

    /// The family's segment files and their total bytes.
    async fn family_footprint(sim: &Sim, family: &str) -> (usize, u64) {
        let prefix = format!("{family}.");
        let mut count = 0;
        let mut bytes = 0;
        for name in sim.list(DIR).await.unwrap().unwrap_or_default() {
            if !name.starts_with(&prefix) {
                continue;
            }
            count += 1;
            bytes += sim
                .open(DIR, &name)
                .await
                .unwrap()
                .unwrap()
                .size()
                .await
                .unwrap();
        }
        (count, bytes)
    }

    /// Rotation: the active segment seals at the target and reads span the
    /// sealed segments; a crash-reopen rebuilds the identical image.
    #[tokio::test]
    async fn test_rotation_and_multi_segment_reads() {
        let sim = Sim::new(201);
        let mut expected = Vec::new();
        {
            let storage = rotating_store(&sim, 1, 1024);
            let family = storage.open_family("fam").await.unwrap();
            let a = commit_log(&family, b"a", &[0u8; 512]).await;
            expected.extend_from_slice(&[0u8; 512]);
            for i in 1..6u8 {
                commit_append(&family, &a, &[i; 512]).await;
                expected.extend_from_slice(&[i; 512]);
            }
            let shared = family_shared(&storage, "fam");
            assert!(shared.state.lock().metrics.rotations >= 2);
            assert_eq!(read_all(&a).await, expected, "multi-segment read");
            let root = governing_root(&sim, "fam").await;
            assert!(root.active_segment.0 > 1);
            assert!(root.checkpoint.is_some());
        }
        sim.crash();

        let storage = rotating_store(&sim, 2, 1024);
        let family = storage.open_family("fam").await.unwrap();
        let a = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&a).await, expected);
        commit_append(&family, &a, b"+post").await;
        expected.extend_from_slice(b"+post");
        assert_eq!(read_all(&a).await, expected);
    }

    /// A rotating commit is four file barriers (frame, fresh active segment,
    /// checkpoint, root flip) plus two directory barriers, both pinned.
    #[tokio::test]
    async fn test_rotating_commit_barrier_counts() {
        let sim = Sim::new(203);
        let storage = rotating_store(&sim, 1, 1024);
        let family = storage.open_family("fam").await.unwrap();
        let a = commit_log(&family, b"a", &[7u8; 512]).await;
        let before = sim.sync_count();
        commit_append(&family, &a, &[7u8; 512]).await;
        assert_eq!(sim.sync_count(), before + 4);
        assert_eq!(
            family_shared(&storage, "fam")
                .state
                .lock()
                .metrics
                .rotations,
            1
        );

        // The full protocol, directory barriers included, measured as the
        // smallest fuse a rotating commit outlives.
        let mut barriers = None;
        for fuse in 0..10 {
            let sim = Sim::new(0);
            let storage = rotating_store(&sim, 1, 1024);
            let family = storage.open_family("fam").await.unwrap();
            let a = commit_log(&family, b"a", &[7u8; 512]).await;
            sim.fail_syncs_after(fuse);
            let mut txn = family.transaction().await.unwrap();
            txn.append(&a, vec![7u8; 512]).unwrap();
            if txn.commit().await.is_ok() {
                barriers = Some(fuse);
                break;
            }
        }
        assert_eq!(barriers, Some(6), "rotating commit barriers changed");
    }

    /// A transaction whose frame exceeds the segment target gets a dedicated
    /// sealed segment: three file barriers (segment, checkpoint, root flip)
    /// plus two directory barriers, readable and durable across a crash.
    #[tokio::test]
    async fn test_dedicated_segment_commit() {
        let sim = Sim::new(205);
        let mut expected = b"small".to_vec();
        {
            let storage = rotating_store(&sim, 1, 512);
            let family = storage.open_family("fam").await.unwrap();
            let a = commit_log(&family, b"a", b"small").await;
            let before = sim.sync_count();
            commit_append(&family, &a, &[9u8; 800]).await;
            expected.extend_from_slice(&[9u8; 800]);
            assert_eq!(sim.sync_count(), before + 3);
            let shared = family_shared(&storage, "fam");
            assert_eq!(shared.state.lock().metrics.dedicated_segments, 1);
            assert_eq!(shared.state.lock().metrics.rotations, 0);
            assert_eq!(read_all(&a).await, expected);
            // The dedicated segment exists as its own sealed file.
            assert!(
                sim.list(DIR)
                    .await
                    .unwrap()
                    .unwrap()
                    .contains(&segment_name("fam", SegmentSeq(2)))
            );
        }
        sim.crash();

        let storage = rotating_store(&sim, 2, 512);
        let family = storage.open_family("fam").await.unwrap();
        let a = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&a).await, expected);
        commit_append(&family, &a, b"+post").await;

        // The smallest fuse a dedicated commit outlives: segment sync, its
        // dentry, checkpoint sync, its dentry, and the root flip.
        let mut barriers = None;
        for fuse in 0..10 {
            let sim = Sim::new(0);
            let storage = rotating_store(&sim, 1, 512);
            let family = storage.open_family("fam").await.unwrap();
            let a = commit_log(&family, b"a", b"small").await;
            sim.fail_syncs_after(fuse);
            let mut txn = family.transaction().await.unwrap();
            txn.append(&a, vec![9u8; 800]).unwrap();
            if txn.commit().await.is_ok() {
                barriers = Some(fuse);
                break;
            }
        }
        assert_eq!(barriers, Some(5), "dedicated commit barriers changed");
    }

    /// A sealed segment with zero live bytes is dropped by the next
    /// checkpoint and unlinked without any copy.
    #[tokio::test]
    async fn test_dead_segment_fast_path() {
        let sim = Sim::new(207);
        let storage = rotating_store(&sim, 1, 1024);
        let family = storage.open_family("fam").await.unwrap();
        let b = commit_log(&family, b"b", &[6u8; 512]).await;
        commit_append(&family, &b, &[6u8; 512]).await; // rotates: segment 1 seals
        let c = commit_log(&family, b"c", b"keep").await;
        let sealed = segment_name("fam", SegmentSeq(1));
        assert!(sim.list(DIR).await.unwrap().unwrap().contains(&sealed));

        // Removing b leaves segment 1 dead; the same commit's maintenance
        // checkpoints and unlinks it, copying nothing.
        let mut txn = family.transaction().await.unwrap();
        txn.remove(&b).unwrap();
        txn.commit().await.unwrap();
        {
            let shared = family_shared(&storage, "fam");
            let state = shared.state.lock();
            assert_eq!(state.metrics.cleanings, 0, "dead fast path must not copy");
            assert_eq!(state.metrics.relocated_extents, 0);
            assert_eq!(state.metrics.unlinked_segments, 1);
        }
        assert!(!sim.list(DIR).await.unwrap().unwrap().contains(&sealed));
        assert_eq!(read_all(&c).await, b"keep");

        sim.crash();
        let storage = rotating_store(&sim, 2, 1024);
        let family = storage.open_family("fam").await.unwrap();
        assert!(family.open(b"b").await.unwrap().is_none());
        let c = family.open(b"c").await.unwrap().unwrap();
        assert_eq!(read_all(&c).await, b"keep");
    }

    /// The cleaner re-verifies every block it copies: a corrupted victim
    /// block poisons the family instead of propagating into the copy.
    #[tokio::test]
    async fn test_cleaning_verifies_copied_blocks() {
        let sim = Sim::new(209);
        let storage = rotating_store(&sim, 1, 1024);
        let family = storage.open_family("fam").await.unwrap();
        // Three extents per sealed segment, so the one survivor of the
        // rewind below is a profitable cleaning victim.
        let a = commit_log(&family, b"a", &[7u8; 384]).await;
        for _ in 0..5 {
            commit_append(&family, &a, &[7u8; 384]).await;
        }
        assert_eq!(
            family_shared(&storage, "fam")
                .state
                .lock()
                .metrics
                .rotations,
            2
        );

        // Flip one payload byte of segment 1 behind the store's back (the
        // payload is the only run of 32 consecutive 0x07 bytes).
        let file = sim
            .open(DIR, &segment_name("fam", SegmentSeq(1)))
            .await
            .unwrap()
            .unwrap();
        let size = file.size().await.unwrap();
        let bytes = file.read_at(0, size as usize).await.unwrap();
        let at = bytes
            .windows(32)
            .position(|w| w == [7u8; 32])
            .expect("payload run")
            + 10;
        file.write_at(at as u64, vec![8u8]).await.unwrap();

        // The rewind makes segment 1 a cleaning victim; the copy pass
        // detects the corruption and poisons.
        let mut txn = family.transaction().await.unwrap();
        txn.rewind(&a, 100).unwrap();
        let handle = txn.start_commit().await.unwrap();
        assert!(matches!(handle.await, Err(Error::FamilyCorrupt(..))));
        assert!(matches!(family.scan().await, Err(Error::FamilyPoisoned(_))));

        // Recovery replays fine, but cleaning is still due at open and the
        // copy re-verifies the same damaged block: the family fail-stops at
        // open rather than propagating the corruption into a copy. (Fixing
        // the media, or restoring the block, is an operator problem.)
        assert!(matches!(
            storage.open_family("fam").await,
            Err(Error::FamilyCorrupt(..))
        ));
    }

    /// Sustained churn keeps the family's footprint bounded: rotation seals
    /// segments, cleaning copies the straddled survivors and unlinks the
    /// rest, and the on-disk image stays at its steady state (a measured
    /// 35 KiB peak, page-sized headers dominating) despite hundreds of
    /// commits. Beyond append/rewind churn on "a", a second log "b" is
    /// removed and recreated through the run, so whole-log removal and name
    /// reuse feed the cleaner too.
    #[tokio::test]
    async fn test_bounded_growth_soak() {
        let sim = Sim::new(211);
        let storage = rotating_store(&sim, 1, 1024);
        let family = storage.open_family("fam").await.unwrap();
        let a = commit_log(&family, b"a", &[9u8; 128]).await;
        let mut model = vec![9u8; 128];
        let mut b: Option<(Log<Sim>, Vec<u8>)> = None;
        for i in 0..150u32 {
            match i % 10 {
                4 => match b.take() {
                    Some((log, _)) => {
                        let mut txn = family.transaction().await.unwrap();
                        txn.remove(&log).unwrap();
                        txn.commit().await.unwrap();
                    }
                    None => {
                        let content = vec![i as u8; 64];
                        b = Some((commit_log(&family, b"b", &content).await, content));
                    }
                },
                7 => {
                    let mut txn = family.transaction().await.unwrap();
                    txn.rewind(&a, 64).unwrap();
                    txn.commit().await.unwrap();
                    model.truncate(64);
                }
                2 if b.is_some() => {
                    let (log, content) = b.as_mut().unwrap();
                    commit_append(&family, log, &[i as u8; 64]).await;
                    content.extend_from_slice(&[i as u8; 64]);
                }
                _ => {
                    commit_append(&family, &a, &[i as u8; 128]).await;
                    model.extend_from_slice(&[i as u8; 128]);
                }
            }
            let (files, bytes) = family_footprint(&sim, "fam").await;
            assert!(files <= 8, "unbounded file count: {files} at commit {i}");
            assert!(bytes <= 36 << 10, "unbounded bytes: {bytes} at commit {i}");
        }
        assert_eq!(read_all(&a).await, model);
        if let Some((log, content)) = &b {
            assert_eq!(read_all(log).await, *content);
        }
        let shared = family_shared(&storage, "fam");
        let state = shared.state.lock();
        assert!(state.metrics.rotations >= 10);
        assert!(state.metrics.cleanings >= 1, "the copy path never ran");
        assert!(state.metrics.unlinked_segments >= 10);
    }

    /// The reserve gate: admission refuses a frame that would dip free space
    /// below the reserve, the inline cleaner frees garbage from inside the
    /// reserve, and the same commit then proceeds. When nothing is
    /// reclaimable the refusal is a clean FamilyFull, not a poison.
    #[tokio::test]
    async fn test_reserve_gate_and_cleaner_escape() {
        let sim = Sim::new(213);
        let limits = tiny(1024);
        let storage = limited_store(&sim, 1, limits);
        let family = storage.open_family("fam").await.unwrap();
        // Segment 1 seals with b and a; removing b leaves sub-target garbage
        // the eager per-commit maintenance does not collect.
        let b = commit_log(&family, b"b", &[0x66u8; 700]).await;
        let a = commit_log(&family, b"a", &[0x77u8; 400]).await;
        let mut txn = family.transaction().await.unwrap();
        txn.remove(&b).unwrap();
        txn.commit().await.unwrap();
        let shared = family_shared(&storage, "fam");
        assert_eq!(shared.state.lock().metrics.rotations, 1);
        assert_eq!(shared.state.lock().metrics.cleanings, 0);

        // Free space 100 bytes short of the next append's admission need:
        // the gate refuses, the inline cleaner relocates a's extent and
        // unlinks segment 1 (freeing far more than 100 bytes), and the
        // commit proceeds.
        let need = limits.cleaner_reserve_bytes
            + PAGE as u64
            + super::super::format::frame_bytes_bound(400, 1, 64);
        sim.set_capacity(Some(need - 100));
        commit_append(&family, &a, &[0x88u8; 400]).await;
        {
            let state = shared.state.lock();
            assert_eq!(state.metrics.cleanings, 1);
            assert_eq!(state.metrics.relocated_bytes, 400);
        }
        let mut expected = vec![0x77u8; 400];
        expected.extend_from_slice(&[0x88; 400]);
        assert_eq!(read_all(&a).await, expected);

        // With no garbage left to reclaim, the gate refuses cleanly and the
        // family is not poisoned.
        sim.set_capacity(Some(1000));
        let mut txn = family.transaction().await.unwrap();
        txn.append(&a, vec![1u8; 100]).unwrap();
        assert!(matches!(
            txn.start_commit().await,
            Err(Error::FamilyFull(_))
        ));
        sim.set_capacity(None);
        commit_append(&family, &a, &[1u8; 100]).await;
    }

    /// A wedged family -- its uncheckpointed span at the replay ceiling, so
    /// admission fails closed -- is relieved by checkpoint-on-open: the next
    /// open checkpoints before returning, and commits flow again.
    #[tokio::test]
    async fn test_checkpoint_on_open_relieves_family_full() {
        let sim = Sim::new(215);
        let limits = Limits {
            replay_txns: 3,
            ..Limits::default()
        };
        {
            let storage = limited_store(&sim, 1, limits);
            let family = storage.open_family("fam").await.unwrap();
            let a = commit_log(&family, b"a", b"x").await;
            commit_append(&family, &a, b"y").await;
            commit_append(&family, &a, b"z").await;
            // The span reached the replay ceiling: wedged.
            let mut txn = family.transaction().await.unwrap();
            txn.append(&a, b"!".to_vec()).unwrap();
            assert!(matches!(
                txn.start_commit().await,
                Err(Error::FamilyFull(_))
            ));
        }

        // Reopening with the trigger due checkpoints during the open itself,
        // resetting the span before any commit is attempted.
        let storage = limited_store(
            &sim,
            2,
            Limits {
                checkpoint_trigger_bytes: u64::MAX,
                checkpoint_trigger_txns: 3,
                ..limits
            },
        );
        let family = storage.open_family("fam").await.unwrap();
        let root = governing_root(&sim, "fam").await;
        assert!(root.checkpoint.is_some(), "open did not checkpoint");
        assert_eq!(root.replay_from, root.next_txn);
        let a = family.open(b"a").await.unwrap().unwrap();
        commit_append(&family, &a, b"!").await;
        assert_eq!(read_all(&a).await, b"xyz!");
    }

    /// The commit crash grid under a rotating segment target: whichever
    /// barrier of a rotating commit fails, recovery serves a committed
    /// prefix. The grid accumulates the maintenance it drove and asserts
    /// rotation actually ran (cleaning and unlink coverage lives in the
    /// dedicated grid below, whose geometry makes them due).
    #[tokio::test]
    async fn test_rotation_crash_enumeration() {
        let mut rotations = 0;
        // Fuse span: up to six pinned barriers per rotating commit
        // (test_rotating_commit_barrier_counts) times the script steps.
        for fuse in 0..=(6 * 4u64) {
            for seed in 0..8 {
                let outcome = run_crash_scenario(Fault::Sync, fuse, seed, tiny(500), false).await;
                rotations += outcome.rotations;
            }
        }
        assert!(rotations > 0, "the grid never rotated");
    }

    /// The commit crash grid with a target so small every scripted commit
    /// takes the dedicated-segment path, layering cleaning of dead and
    /// half-live dedicated segments on top. The grid accumulates the
    /// maintenance it drove and asserts each mechanism actually ran.
    #[tokio::test]
    async fn test_dedicated_and_cleaning_crash_enumeration() {
        let (mut dedicated, mut cleanings, mut unlinked) = (0, 0, 0);
        // Fuse span: up to five pinned barriers per dedicated commit
        // (test_dedicated_segment_commit) plus cleaning's copy publication,
        // times the script steps.
        for fuse in 0..=(7 * 4u64) {
            for seed in 0..8 {
                let outcome = run_crash_scenario(Fault::Sync, fuse, seed, tiny(64), false).await;
                dedicated += outcome.dedicated;
                cleanings += outcome.cleanings;
                unlinked += outcome.unlinked;
            }
        }
        assert!(dedicated > 0, "the grid never took the dedicated path");
        assert!(cleanings > 0, "the grid never cleaned");
        assert!(unlinked > 0, "the grid never unlinked a retired segment");
    }

    /// The limits the capacity-fuse scenarios run under: a zero reserve, so
    /// the admission gate covers only the frame itself and the sweep can
    /// reach exhaustion inside every maintenance write, not just at the
    /// gate. (A validated reserve exists precisely to prevent what this
    /// scenario forces.)
    fn space_limits() -> Limits {
        Limits {
            cleaner_reserve_bytes: 0,
            ..tiny(1024)
        }
    }

    /// One capacity-fuse scenario: with `budget` free bytes, scripted commits
    /// run until one is refused (FamilyFull: state unchanged) or a
    /// maintenance write hits ENOSPC (poison: outcome indeterminate by one).
    /// Space then heals; in-process recovery, a crash, and a fresh reopen
    /// must each serve the same committed prefix, and the family stays
    /// functional. Returns what was observed, plus the bytes a completed run
    /// consumed.
    async fn run_space_scenario(budget: u64, seed: u64) -> (bool, bool, bool, u64) {
        let ctx = format!("space budget {budget} seed {seed}");
        let steps: usize = 4;
        let mut states = vec![Model::from([(b"a".to_vec(), vec![7u8; 300])])];
        for step in 0..steps {
            let mut next = states[step].clone();
            let a = next.get_mut(b"a".as_slice()).unwrap();
            if step == 1 {
                a.truncate(2);
            }
            a.extend_from_slice(&[step as u8; 300]);
            states.push(next);
        }

        let sim = Sim::new(seed);
        let storage = limited_store(&sim, 1, space_limits());
        let family = storage.open_family("fam").await.unwrap();
        let a = commit_log(&family, b"a", &[7u8; 300]).await;
        sim.set_capacity(Some(budget));

        let mut acked = 0;
        let (mut full, mut poisoned) = (false, false);
        for step in 0..steps {
            let mut txn = family.transaction().await.unwrap();
            if step == 1 {
                txn.rewind(&a, 2).unwrap();
            }
            txn.append(&a, vec![step as u8; 300]).unwrap();
            match txn.start_commit().await {
                Ok(handle) => match handle.await {
                    Ok(()) => acked += 1,
                    Err(Error::FamilyPoisoned(_) | Error::FamilyCorrupt(..)) => {
                        poisoned = true;
                        break;
                    }
                    Err(error) => panic!("{ctx}: commit failed with {error:?}"),
                },
                Err(Error::FamilyFull(_)) => {
                    full = true;
                    break;
                }
                // The gate's inline cleaning attempt can itself hit ENOSPC.
                Err(Error::FamilyPoisoned(_)) => {
                    poisoned = true;
                    break;
                }
                Err(error) => panic!("{ctx}: admission failed with {error:?}"),
            }
        }
        let consumed = budget - sim.free_bytes().await.unwrap().unwrap();
        sim.set_capacity(None);

        // In-process reopen: recovery when poisoned, a plain reopen
        // otherwise. The result is a committed prefix (the poisoned commit's
        // frame may have become durable before maintenance failed).
        let family = storage
            .open_family("fam")
            .await
            .unwrap_or_else(|error| panic!("{ctx}: recovery failed: {error:?}"));
        let recovered = read_state(&family).await;
        let landed = (acked..=acked + usize::from(poisoned))
            .find(|&j| recovered == states[j])
            .unwrap_or_else(|| panic!("{ctx}: no committed prefix: {recovered:?}"));

        // The adopted prefix is durable: a crash changes nothing.
        sim.crash();
        let storage = limited_store(&sim, 2, space_limits());
        let family = storage
            .open_family("fam")
            .await
            .unwrap_or_else(|error| panic!("{ctx}: post-crash reopen failed: {error:?}"));
        assert_eq!(
            read_state(&family).await,
            states[landed],
            "{ctx}: durable state moved across the crash"
        );
        let a = family.open(b"a").await.unwrap().unwrap();
        commit_append(&family, &a, b"+post").await;
        (full, poisoned, acked == steps, consumed)
    }

    /// ENOSPC everywhere (to-do coverage): sweep capacity budgets from
    /// nothing to enough, hitting exhaustion inside frame admission,
    /// rotation, checkpointing, and cleaning. Every budget must land on a
    /// committed prefix, and the sweep must observe all three outcomes:
    /// clean refusal, poison-and-recover, and completion.
    #[tokio::test]
    async fn test_space_exhaustion_enumeration() {
        // Measure a full run, then sweep every budget below it.
        let (_, _, completed, used) = run_space_scenario(1 << 20, 0).await;
        assert!(completed, "the measuring run must complete");

        let (mut saw_full, mut saw_poison, mut saw_complete) = (false, false, false);
        // A fine sweep through the exhaustion range (admission windows are
        // only a few hundred bytes wide), then a coarse one above it: the
        // measured consumption is net of unlink refunds, so completion needs
        // headroom over the peak.
        let mut budgets: Vec<u64> = (0..=used).step_by(64).collect();
        budgets.extend((used..=used + (16 << 10)).step_by(1024));
        for budget in budgets {
            for seed in 0..3 {
                let (full, poisoned, completed, _) = run_space_scenario(budget, seed).await;
                saw_full |= full;
                saw_poison |= poisoned;
                saw_complete |= completed;
            }
        }
        assert!(saw_full, "no budget produced a clean refusal");
        assert!(saw_poison, "no budget produced an ENOSPC poison");
        assert!(saw_complete, "no budget completed");
    }

    /// A dedicated-segment commit whose family is poisoned (by a concurrent
    /// read) between the install and the forced checkpoint resolves
    /// indeterminate: the segment is unreferenced until a checkpoint lands,
    /// so acknowledging would let recovery sweep an acknowledged
    /// transaction. Recovery serves the pre-transaction state and sweeps the
    /// orphaned segment.
    #[tokio::test]
    async fn test_dedicated_commit_poisoned_before_checkpoint_is_indeterminate() {
        let sim = Sim::new(225);
        let storage = rotating_store(&sim, 1, 512);
        let family = storage.open_family("fam").await.unwrap();
        let a = commit_log(&family, b"a", b"small").await;
        let shared = family_shared(&storage, "fam");
        shared.state.lock().control.poison_next_maintenance = true;

        // Past the target: the dedicated path, whose checkpoint is forced.
        let mut txn = family.transaction().await.unwrap();
        txn.append(&a, vec![9u8; 800]).unwrap();
        let handle = txn.start_commit().await.unwrap();
        assert!(matches!(handle.await, Err(Error::FamilyPoisoned(_))));

        let family = storage.open_family("fam").await.unwrap();
        let a = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&a).await, b"small", "pre-transaction state");
        let dedicated = segment_name("fam", SegmentSeq(2));
        assert!(
            !sim.list(DIR).await.unwrap().unwrap().contains(&dedicated),
            "the unreferenced dedicated segment must be swept"
        );
        commit_append(&family, &a, b"+post").await;
    }

    /// The active-frame analogue stays acknowledged: a frame in the active
    /// segment is already replay-reachable, so maintenance standing down on
    /// the poisoned family does not disturb the acknowledgment, and recovery
    /// serves the acknowledged bytes.
    #[tokio::test]
    async fn test_active_commit_poisoned_before_maintenance_stays_acknowledged() {
        let sim = Sim::new(227);
        let storage = rotating_store(&sim, 1, 1024);
        let family = storage.open_family("fam").await.unwrap();
        let a = commit_log(&family, b"a", b"base").await;
        let shared = family_shared(&storage, "fam");
        shared.state.lock().control.poison_next_maintenance = true;

        let mut txn = family.transaction().await.unwrap();
        txn.append(&a, b"+live".to_vec()).unwrap();
        let handle = txn.start_commit().await.unwrap();
        handle.await.unwrap();
        assert!(matches!(family.scan().await, Err(Error::FamilyPoisoned(_))));

        let family = storage.open_family("fam").await.unwrap();
        let a = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&a).await, b"base+live");
    }

    /// A failed superseded-checkpoint removal poisons the family; the commit
    /// itself is durable (its root flipped first), so recovery serves it and
    /// the next open's sweep completes the removal.
    #[tokio::test]
    async fn test_superseded_checkpoint_removal_failure_poisons() {
        let sim = Sim::new(217);
        let storage = limited_store(&sim, 1, EVERY_COMMIT);
        let family = storage.open_family("fam").await.unwrap();
        let a = commit_log(&family, b"a", b"one").await;
        let old = governing_root(&sim, "fam")
            .await
            .checkpoint
            .unwrap()
            .segment;

        sim.fail_removes_after(0);
        let mut txn = family.transaction().await.unwrap();
        txn.append(&a, b"two".to_vec()).unwrap();
        let handle = txn.start_commit().await.unwrap();
        assert!(matches!(handle.await, Err(Error::FamilyPoisoned(_))));
        assert!(matches!(family.scan().await, Err(Error::FamilyPoisoned(_))));

        sim.fail_removes_after(u64::MAX);
        let family = storage.open_family("fam").await.unwrap();
        let a = family.open(b"a").await.unwrap().unwrap();
        assert_eq!(read_all(&a).await, b"onetwo");
        let stale = segment_name("fam", old);
        assert!(
            !sim.list(DIR).await.unwrap().unwrap().contains(&stale),
            "the sweep must complete the removal"
        );
        commit_append(&family, &a, b"+post").await;
    }

    /// A failed retired-segment unlink poisons the family without counting
    /// the unlink; the removal transaction is durable, so recovery serves it
    /// and the next open's sweep completes the unlink.
    #[tokio::test]
    async fn test_retired_unlink_failure_poisons() {
        let sim = Sim::new(219);
        let storage = rotating_store(&sim, 1, 1024);
        let family = storage.open_family("fam").await.unwrap();
        let b = commit_log(&family, b"b", &[6u8; 512]).await;
        commit_append(&family, &b, &[6u8; 512]).await; // rotates: segment 1 seals
        commit_log(&family, b"c", b"keep").await;
        let sealed = segment_name("fam", SegmentSeq(1));

        // Removing b makes segment 1 dead. The pass removes the superseded
        // checkpoint first (fuse survivor 1), then the retired unlink fails.
        sim.fail_removes_after(1);
        let mut txn = family.transaction().await.unwrap();
        txn.remove(&b).unwrap();
        let handle = txn.start_commit().await.unwrap();
        assert!(matches!(handle.await, Err(Error::FamilyPoisoned(_))));
        {
            let shared = family_shared(&storage, "fam");
            assert_eq!(shared.state.lock().metrics.unlinked_segments, 0);
        }

        sim.fail_removes_after(u64::MAX);
        let family = storage.open_family("fam").await.unwrap();
        assert!(family.open(b"b").await.unwrap().is_none());
        let c = family.open(b"c").await.unwrap().unwrap();
        assert_eq!(read_all(&c).await, b"keep");
        assert!(
            !sim.list(DIR).await.unwrap().unwrap().contains(&sealed),
            "the sweep must complete the unlink"
        );
    }

    /// A sealed segment whose live extents are too small to move profitably
    /// -- the encoded copies would cost more than half the record bytes
    /// unlinking reclaims -- is neither selected as a victim nor counted as
    /// reclaimable, so reserve pressure yields a clean refusal instead of
    /// copy passes that cannot realize their gain.
    #[tokio::test]
    async fn test_unprofitable_victims_never_selected() {
        let sim = Sim::new(229);
        let limits = tiny(512);
        let storage = limited_store(&sim, 1, limits);
        let family = storage.open_family("fam").await.unwrap();
        // Many one-byte logs: every sealed segment's live payload is framing
        // dominated, so each extent costs ~40 encoded bytes to relocate but
        // holds one live byte.
        for i in 0..30u32 {
            commit_log(&family, &i.to_be_bytes(), &[i as u8]).await;
        }
        let shared = family_shared(&storage, "fam");
        let session = shared.state.lock().control.session;
        assert!(shared.state.lock().metrics.rotations >= 1);
        assert!(!shared.state.lock().sealed.is_empty());

        // Under reserve pressure (free space at zero) the planner still
        // finds nothing reclaimable: no victims, no cleaning-only pass.
        let planned = plan(&shared, session, Some(0), false).unwrap();
        assert!(planned.is_none(), "unprofitable victims were selected");

        // The admission gate agrees: a clean FamilyFull, no copy pass, no
        // poison.
        let need = limits.cleaner_reserve_bytes;
        sim.set_capacity(Some(need));
        let mut txn = family.transaction().await.unwrap();
        txn.append(
            &family.open(&0u32.to_be_bytes()).await.unwrap().unwrap(),
            vec![1u8; 64],
        )
        .unwrap();
        assert!(matches!(
            txn.start_commit().await,
            Err(Error::FamilyFull(_))
        ));
        assert_eq!(shared.state.lock().metrics.cleanings, 0);
        sim.set_capacity(None);
        let a = family.open(&0u32.to_be_bytes()).await.unwrap().unwrap();
        commit_append(&family, &a, b"+post").await;
    }
}
