//! Append-and-sync persistence for machine-selected safety decisions.
//!
//! The journal stores exactly the machine's persistence barriers as plain codec items in a
//! [`segmented::variable::Journal`](commonware_storage::journal::segmented::variable::Journal).
//! Integrity is layered where it belongs: the paged buffer
//! checksums every page, the segmented journal frames and repairs an incomplete tail, and recovery
//! here validates every complete record and its cursor continuity against the checkpoint the
//! [`SnapshotStore`] holds. A complete record that fails decoding or validation is corruption:
//! it may contain an already externalized safety decision, so recovery must never discard it.
//!
//! Checkpoints do not enter the journal. A checkpoint rolls the journal to a fresh section
//! and persists the machine snapshot in the [`SnapshotStore`]; once the snapshot is durable
//! the older sections are pruned wholesale.
//!
//! [`SnapshotStore`]: super::SnapshotStore

use crate::{
    Epochable as _,
    multimmit::{
        config::Profile,
        machine::{
            BarrierAck, BatchId, Cursor, DomainEvent, DomainEventCodecConfig, Generation,
            MAX_BATCH_BYTES, MAX_BATCH_EVENTS, PersistJob,
        },
    },
    types::Epoch,
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::{
    Handle, Metrics, ReadOptions, Storage, Supervisor, buffer::paged::CacheRef,
};
use commonware_storage::journal::{
    Error as StorageError,
    segmented::variable::{Config as StorageConfig, Journal, Replay},
};
use commonware_utils::NZUsize;
use core::num::NonZeroUsize;
use std::sync::Arc;
use tracing::warn;

/// Bytes buffered before the journal writes to a blob.
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);

/// Bytes read ahead while the journal replays at startup.
const REPLAY_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);

/// Bytes reserved above the largest encoded batch for record framing.
const RECORD_FRAMING_BYTES: usize = 128;

/// Configuration for one epoch's safety journal.
#[derive(Clone)]
pub(crate) struct Config {
    /// Runtime storage partition dedicated to this epoch.
    pub(crate) partition: String,
    /// Epoch expected in every recovered event.
    pub(crate) epoch: Epoch,
    /// Bounds for the self-contained machine events.
    pub(crate) event_codec: DomainEventCodecConfig,
    /// Greatest number of events accepted in one machine persistence barrier.
    pub(crate) max_events_per_record: NonZeroUsize,
    /// Greatest encoded record size.
    pub(crate) max_record_bytes: NonZeroUsize,
    /// Shared page cache used by the segmented journal.
    pub(crate) page_cache: CacheRef,
    /// Buffered writer capacity for each open journal section.
    pub(crate) write_buffer: NonZeroUsize,
    /// Read buffer capacity used while replaying the journal at startup.
    pub(crate) replay_buffer: NonZeroUsize,
}

impl Config {
    /// Sizes the journal in `partition` for `profile`'s machine.
    ///
    /// A record holds one persistence barrier: at most the machine's batch event count, and at
    /// most its batch byte cap. One indivisible event may exceed that cap, so the record bound
    /// reserves framing above the larger of the cap and the largest event rather than multiplying
    /// the largest event by the event count; the machine never constructs such a record.
    pub(crate) fn from_profile<D: Digest>(
        profile: &Profile<D>,
        partition: String,
        page_cache: CacheRef,
    ) -> Self {
        let event_codec = DomainEventCodecConfig::from_profile(profile);
        let max_record_bytes = MAX_BATCH_BYTES
            .max(event_codec.max_encoded_size())
            .saturating_add(RECORD_FRAMING_BYTES);
        Self {
            partition,
            epoch: profile.protocol().epoch(),
            event_codec,
            max_events_per_record: NonZeroUsize::new(MAX_BATCH_EVENTS)
                .expect("machine batches contain at least one event"),
            max_record_bytes: NonZeroUsize::new(max_record_bytes)
                .expect("record framing adds non-zero bytes"),
            page_cache,
            write_buffer: WRITE_BUFFER,
            replay_buffer: REPLAY_BUFFER,
        }
    }
}

/// Internal decoding bounds carried by the segmented journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordCodecConfig {
    event: DomainEventCodecConfig,
    max_events: usize,
}

/// One self-contained machine persistence barrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JournalRecord<V: Variant, D: Digest> {
    barrier: BatchId,
    generation: Generation,
    previous: Cursor,
    events: Arc<Vec<DomainEvent<V, D>>>,
}

impl<V: Variant, D: Digest> JournalRecord<V, D> {
    fn from_job(job: &PersistJob<V, D>) -> Self {
        Self {
            barrier: job.id(),
            generation: job.generation(),
            previous: job.previous(),
            events: job.shared_events(),
        }
    }

    /// Returns the barrier issued by the machine.
    pub(crate) const fn barrier(&self) -> BatchId {
        self.barrier
    }

    /// Returns the process generation that issued the barrier.
    pub(crate) const fn generation(&self) -> Generation {
        self.generation
    }

    /// Returns the cursor immediately before this barrier.
    pub(crate) const fn previous(&self) -> Cursor {
        self.previous
    }

    /// Returns the ordered events in this barrier.
    pub(crate) fn events(&self) -> &[DomainEvent<V, D>] {
        self.events.as_slice()
    }

    /// Consumes the record and returns its events, cloning them only if the allocation is shared.
    pub(crate) fn into_events(self) -> Vec<DomainEvent<V, D>> {
        Arc::unwrap_or_clone(self.events)
    }

    /// Returns the final cursor established by this barrier.
    pub(crate) fn end_cursor(&self) -> Cursor {
        self.events
            .last()
            .map_or(self.previous, DomainEvent::cursor)
    }

    /// Returns the acknowledgement that releases this barrier once it is durable.
    fn ack(&self) -> BarrierAck {
        BarrierAck::new(self.barrier, self.generation, self.end_cursor())
    }

    /// Returns the encoded size of the record that persists `job`.
    pub(crate) fn encoded_size(job: &PersistJob<V, D>) -> usize {
        encoded_size(job.id(), job.generation(), job.previous(), job.events())
    }
}

/// Returns the encoded size of a record with these fields.
fn encoded_size<V: Variant, D: Digest>(
    barrier: BatchId,
    generation: Generation,
    previous: Cursor,
    events: &[DomainEvent<V, D>],
) -> usize {
    barrier.encode_size()
        + generation.encode_size()
        + previous.encode_size()
        + events.len().encode_size()
        + events.iter().map(EncodeSize::encode_size).sum::<usize>()
}

impl<V: Variant, D: Digest> Write for JournalRecord<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.barrier.write(buf);
        self.generation.write(buf);
        self.previous.write(buf);
        self.events.len().write(buf);
        for event in self.events.iter() {
            event.write(buf);
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for JournalRecord<V, D> {
    fn encode_size(&self) -> usize {
        encoded_size(self.barrier, self.generation, self.previous, self.events())
    }
}

impl<V: Variant, D: Digest> Read for JournalRecord<V, D> {
    type Cfg = RecordCodecConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let barrier = BatchId::read(buf)?;
        let generation = Generation::read(buf)?;
        let previous = Cursor::read(buf)?;
        let events: Vec<DomainEvent<V, D>> = Vec::<DomainEvent<V, D>>::read_cfg(
            buf,
            &(RangeCfg::from(1..=cfg.max_events), cfg.event),
        )?;
        Ok(Self {
            barrier,
            generation,
            previous,
            events: Arc::new(events),
        })
    }
}

/// Open safety journal after recovery has completed.
pub(crate) struct SafetyJournal<E: Storage + Metrics, V: Variant, D: Digest> {
    journal: Journal<E, JournalRecord<V, D>>,
    config: Config,
    cursor: Cursor,
    last: Option<JournalRecord<V, D>>,
    section: u64,
}

/// A journal or recovery failure. All variants are fatal to the current instance.
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The underlying segmented journal failed.
    #[error("segmented journal failed: {0}")]
    Storage(#[from] StorageError),
    /// A barrier does not extend the journal's cursor.
    #[error("safety journal cursor is not contiguous")]
    Cursor,
    /// A record carries no events or more events than one barrier admits.
    #[error("safety journal record has {count} events, expected 1..={max}")]
    EventCount { count: usize, max: usize },
    /// A record belongs to another epoch.
    #[error("safety journal record belongs to epoch {actual}, expected {expected}")]
    EpochMismatch { expected: Epoch, actual: Epoch },
    /// A duplicate live barrier differs from the already durable barrier.
    #[error("duplicate safety journal barrier is not byte-identical")]
    Duplicate,
    /// A record exceeds the configured byte ceiling.
    #[error("safety journal record exceeds the byte limit")]
    ByteLimit,
    /// A recovered record does not extend the validated prefix: earlier data is missing, or a
    /// stale crash generation overlaps the tail.
    #[error("safety journal is corrupt")]
    Corrupt,
}

impl<E, V, D> SafetyJournal<E, V, D>
where
    E: Storage + Metrics,
    V: Variant,
    D: Digest,
{
    /// Opens the segmented journal and returns a reader over the suffix after `covered`.
    ///
    /// `covered` is the cursor of the newest durable checkpoint; records at or below it are
    /// skipped, and the first retained record must extend it exactly.
    pub(crate) async fn open(
        context: E,
        config: Config,
        covered: Cursor,
    ) -> Result<SuffixReplay<E, V, D>, JournalError>
    where
        E: Supervisor,
    {
        let journal = Journal::init(context, Self::storage_config(&config)).await?;
        let replay = journal
            .replay(0, 0, config.replay_buffer, ReadOptions::default())
            .await?;
        Ok(SuffixReplay {
            replay,
            config,
            covered,
            cursor: covered,
            suffix_section: None,
            section: 0,
        })
    }

    fn storage_config(config: &Config) -> StorageConfig<RecordCodecConfig> {
        StorageConfig {
            partition: config.partition.clone(),
            compression: None,
            codec_config: RecordCodecConfig {
                event: config.event_codec,
                max_events: config.max_events_per_record.get(),
            },
            page_cache: config.page_cache.clone(),
            write_buffer: config.write_buffer,
        }
    }

    /// Appends the machine-issued barrier and starts syncing it.
    ///
    /// An error reported by the returned handle is fatal. The returned journal must not be used
    /// after such an error.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) async fn start_persist(
        self,
        job: &PersistJob<V, D>,
    ) -> Result<(Self, BarrierAck, Handle<()>), JournalError> {
        let (journal, result) = self.append_persist(job).await?;
        let (journal, sync) = journal.start_sync().await?;
        Ok((journal, result, sync))
    }

    /// Starts syncing every appended barrier.
    ///
    /// A sync makes the whole appended prefix durable, so one handle acknowledges every barrier
    /// appended before it. An error reported by the handle is fatal.
    pub(crate) async fn start_sync(self) -> Result<(Self, Handle<()>), JournalError> {
        let section = self.section;
        let (journal, sync) = self.journal.start_sync(section).await?;
        Ok((Self { journal, ..self }, sync))
    }

    /// Appends the machine-issued barrier without starting a sync.
    ///
    /// The barrier becomes durable when a later sync covers it; callers that release external
    /// effects must sync first.
    pub(crate) async fn append_persist(
        self,
        job: &PersistJob<V, D>,
    ) -> Result<(Self, BarrierAck), JournalError> {
        if let Some(last) = self.last.as_ref()
            && last.barrier() == job.id()
            && last.generation() == job.generation()
        {
            let duplicate = JournalRecord::from_job(job);
            if last != &duplicate {
                return Err(JournalError::Duplicate);
            }
            let ack = last.ack();
            return Ok((self, ack));
        }
        if job.previous() != self.cursor {
            return Err(JournalError::Cursor);
        }
        let record = JournalRecord::from_job(job);
        validate_events(&record, &self.config)?;
        if record.encode_size() > self.config.max_record_bytes.get() {
            return Err(JournalError::ByteLimit);
        }
        let section = self.section;
        let (journal, _, _) = self.journal.append(section, &record).await?;
        let cursor = record.end_cursor();
        let ack = record.ack();
        Ok((
            Self {
                journal,
                config: self.config,
                cursor,
                last: Some(record),
                section,
            },
            ack,
        ))
    }

    /// Rolls the journal to a fresh section for the barriers after a checkpoint.
    ///
    /// The caller persists the checkpoint's snapshot separately; once that snapshot is
    /// durable, pruning before the rolled [`Self::section`] with [`Self::prune_before`]
    /// discards every section before the roll.
    pub(crate) fn roll(self) -> Self {
        Self {
            section: self.section + 1,
            last: None,
            ..self
        }
    }

    /// Returns the section new barriers are appended to.
    pub(crate) const fn section(&self) -> u64 {
        self.section
    }

    /// Prunes every whole section strictly below `section`, leaving the append section unchanged.
    ///
    /// Sound only once a checkpoint covering all pruned events is durable.
    pub(crate) async fn prune_before(self, section: u64) -> Result<Self, JournalError> {
        let (journal, _) = self.journal.prune(section).await?;
        Ok(Self { journal, ..self })
    }
}

/// Streaming reader over the journal records a checkpoint does not cover.
pub(crate) struct SuffixReplay<E: Storage + Metrics + Supervisor, V: Variant, D: Digest> {
    replay: Replay<E, JournalRecord<V, D>>,
    config: Config,
    covered: Cursor,
    cursor: Cursor,
    suffix_section: Option<u64>,
    section: u64,
}

impl<E, V, D> SuffixReplay<E, V, D>
where
    E: Storage + Metrics + Supervisor,
    V: Variant,
    D: Digest,
{
    /// Returns the first section containing an event not covered by the checkpoint.
    pub(crate) const fn suffix_section(&self) -> Option<u64> {
        self.suffix_section
    }

    /// Returns the next barrier after the covered checkpoint, validating continuity.
    ///
    /// The segmented journal repairs incomplete outer framing before yielding records. Any
    /// complete record yielded here must decode and extend the validated prefix exactly.
    pub(crate) async fn next(&mut self) -> Result<Option<JournalRecord<V, D>>, JournalError> {
        loop {
            let Some(item) = self.replay.next().await else {
                return Ok(None);
            };
            let (section, _, _, record) = item?;
            self.section = section;
            // A record from another epoch is a configuration error, not crash debris.
            validate_events(&record, &self.config)?;
            // Pruning lags the checkpoint, so records the checkpoint already covers may
            // remain; they were validated when written and chain below the checkpoint.
            if record.end_cursor() <= self.covered {
                continue;
            }
            // A record that does not extend the validated prefix is never tail debris, in any
            // section: ancestry ahead of the prefix means earlier data is missing entirely, and
            // ancestry behind it (not covered by the checkpoint) is a stale crash generation
            // overlapping the tail.
            if record.previous() != self.cursor {
                warn!(
                    section,
                    previous = record.previous().get(),
                    expected = self.cursor.get(),
                    "journal record does not extend the recovered prefix"
                );
                return Err(JournalError::Corrupt);
            }
            self.suffix_section.get_or_insert(section);
            self.cursor = record.end_cursor();
            return Ok(Some(record));
        }
    }

    /// Finishes the replay and returns the live append-and-sync handle.
    ///
    /// Appends continue in the last section that held a record, or section zero when the journal
    /// is empty. Physical tail repair is completed by the segmented journal before this handle is
    /// returned.
    pub(crate) fn finish(self) -> Result<SafetyJournal<E, V, D>, JournalError> {
        let journal = self.replay.finish()?;
        Ok(SafetyJournal {
            journal,
            config: self.config,
            cursor: self.cursor,
            last: None,
            section: self.section,
        })
    }
}

fn validate_events<V: Variant, D: Digest>(
    record: &JournalRecord<V, D>,
    cfg: &Config,
) -> Result<(), JournalError> {
    let count = record.events().len();
    let max = cfg.max_events_per_record.get();
    if count == 0 || count > max {
        return Err(JournalError::EventCount { count, max });
    }
    let mut previous = record.previous();
    for event in record.events() {
        if event.epoch() != cfg.epoch {
            return Err(JournalError::EpochMismatch {
                expected: cfg.epoch,
                actual: event.epoch(),
            });
        }
        if previous.next() != Some(event.cursor()) {
            return Err(JournalError::Cursor);
        }
        previous = event.cursor();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::{
        machine::Change,
        types::{CodecConfig, PathLimits},
    };
    use commonware_codec::{Decode as _, Encode, varint::UInt};
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        Blob as _, BufferPooler, Runner, WriteOptions,
        buffer::paged::CacheRef,
        deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
    };
    use commonware_utils::{NZU16, NZUsize};

    type TestRecord = JournalRecord<MinPk, Sha256Digest>;
    type TestJournal = SafetyJournal<DeterministicContext, MinPk, Sha256Digest>;

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use arbitrary::Arbitrary;
        use commonware_conformance::Conformance;
        use commonware_cryptography::bls12381::primitives::variant::{MinSig, Variant};

        fn record<V: Variant>(seed: u64) -> JournalRecord<V, Sha256Digest>
        where
            V::Signature: for<'a> Arbitrary<'a>,
        {
            let count = seed as usize % 4 + 1;
            let previous = Cursor::new(seed * 4);
            let events = (1..=count)
                .map(|offset| {
                    DomainEvent::conformance(
                        seed + (offset as u64 - 1) * 128,
                        Cursor::new(previous.get() + offset as u64),
                    )
                })
                .collect();
            JournalRecord {
                barrier: BatchId::new(seed + 1),
                generation: Generation::new(seed + 1),
                previous,
                events: Arc::new(events),
            }
        }

        fn record_bytes<V: Variant>(seed: u64) -> Vec<u8>
        where
            V::Signature: for<'a> Arbitrary<'a>,
        {
            let record = record::<V>(seed);
            let encoded = record.encode();
            let config = RecordCodecConfig {
                event: DomainEventCodecConfig::new(
                    CodecConfig::new(6, 6, PathLimits::new(2, 2).unwrap()).unwrap(),
                    1024 * 1024,
                    16,
                    16,
                ),
                max_events: 4,
            };
            assert_eq!(
                <JournalRecord<V, Sha256Digest> as commonware_codec::Decode>::decode_cfg(
                    encoded.clone(),
                    &config,
                )
                .unwrap(),
                record,
            );
            encoded.to_vec()
        }

        #[test]
        fn generated_records_cover_every_nonempty_batch_length() {
            let mut lengths = 0u8;
            for seed in 0..128 {
                let record = record::<MinPk>(seed);
                lengths |= 1 << (record.events().len() - 1);
                let mut previous = record.previous();
                for event in record.events() {
                    assert_eq!(previous.next(), Some(event.cursor()));
                    previous = event.cursor();
                }
            }
            assert_eq!(lengths, 0b1111);
        }

        struct JournalRecordMinPkConformance;
        struct JournalRecordMinSigConformance;

        impl Conformance for JournalRecordMinPkConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                record_bytes::<MinPk>(seed)
            }
        }

        impl Conformance for JournalRecordMinSigConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                record_bytes::<MinSig>(seed)
            }
        }

        commonware_conformance::conformance_tests! {
            JournalRecordMinPkConformance => 128,
            JournalRecordMinSigConformance => 128,
        }
    }

    fn event_codec() -> DomainEventCodecConfig {
        DomainEventCodecConfig::new(
            CodecConfig::new(1, 1, PathLimits::new(1, 0).unwrap()).unwrap(),
            4096,
            16,
            16,
        )
    }

    fn event(epoch: Epoch, cursor: u64, generation: u64) -> DomainEvent<MinPk, Sha256Digest> {
        DomainEvent::new(
            epoch,
            Cursor::new(cursor),
            Change::GenerationAdvanced(Generation::new(generation)),
        )
    }

    fn job(
        epoch: Epoch,
        barrier: u64,
        previous: u64,
        generation: u64,
    ) -> PersistJob<MinPk, Sha256Digest> {
        PersistJob::new(
            BatchId::new(barrier),
            Generation::new(generation),
            Cursor::new(previous),
            vec![event(epoch, previous + 1, generation + 1)],
            true,
        )
    }

    fn config(context: &impl BufferPooler, partition: &str, epoch: Epoch) -> Config {
        Config {
            partition: partition.to_owned(),
            epoch,
            event_codec: event_codec(),
            max_events_per_record: NZUsize!(4),
            max_record_bytes: NZUsize!(16 * 1024),
            page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
            write_buffer: NZUsize!(16 * 1024),
            replay_buffer: NZUsize!(16 * 1024),
        }
    }

    #[test]
    fn record_reuses_the_persist_job_event_allocation() {
        let job = job(Epoch::new(8), 1, 0, 0);
        let record = JournalRecord::from_job(&job);
        assert_eq!(record.events.as_ptr(), job.events().as_ptr());
    }

    #[test]
    fn unique_record_yields_its_events_without_copying() {
        let job = job(Epoch::new(8), 1, 0, 0);
        let record = TestRecord::decode_cfg(
            JournalRecord::from_job(&job).encode(),
            &RecordCodecConfig {
                event: event_codec(),
                max_events: 4,
            },
        )
        .unwrap();
        let shared = record.events.as_ptr();
        let events = record.into_events();
        assert_eq!(events.as_ptr(), shared);
    }

    async fn open_empty(
        context: &DeterministicContext,
        cfg: Config,
        label: &'static str,
    ) -> TestJournal {
        let mut recovery = TestJournal::open(context.child(label), cfg, Cursor::zero())
            .await
            .unwrap();
        assert!(recovery.next().await.unwrap().is_none());
        recovery.finish().unwrap()
    }

    #[test]
    fn persisted_records_replay_in_order() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let cfg = config(&context, "multimmit-replay", epoch);
            let journal = open_empty(&context, cfg.clone(), "initial").await;

            let first = job(epoch, 1, 0, 1);
            let second = job(epoch, 2, 1, 1);
            let expected = [
                JournalRecord::from_job(&first),
                JournalRecord::from_job(&second),
            ];
            let (journal, completion, sync) = journal.start_persist(&first).await.unwrap();
            assert_eq!(completion.barrier(), first.id());
            assert_eq!(completion.cursor(), Cursor::new(1));
            sync.await.unwrap();
            let (journal, _, sync) = journal.start_persist(&second).await.unwrap();
            sync.await.unwrap();
            assert_eq!(journal.cursor, Cursor::new(2));
            drop(journal);

            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::zero())
                .await
                .unwrap();
            assert_eq!(recovery.next().await.unwrap(), Some(expected[0].clone()));
            assert_eq!(recovery.next().await.unwrap(), Some(expected[1].clone()));
            assert!(recovery.next().await.unwrap().is_none());
            assert_eq!(recovery.cursor, Cursor::new(2));
            let journal = recovery.finish().unwrap();
            assert_eq!(journal.cursor, Cursor::new(2));
        });
    }

    #[test]
    fn duplicate_barrier_must_be_identical() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let cfg = config(&context, "multimmit-duplicate", epoch);
            let journal = open_empty(&context, cfg, "initial").await;

            let first = job(epoch, 1, 0, 1);
            let (journal, _, sync) = journal.start_persist(&first).await.unwrap();
            sync.await.unwrap();
            // Re-persisting the identical barrier replays the completion without appending.
            let (journal, completion) = journal.append_persist(&first).await.unwrap();
            assert_eq!(completion.cursor(), Cursor::new(1));
            // A same-id barrier with different content is rejected.
            let forged = PersistJob::new(
                BatchId::new(1),
                Generation::new(1),
                Cursor::new(0),
                vec![event(epoch, 1, 7)],
                true,
            );
            assert!(matches!(
                journal.append_persist(&forged).await,
                Err(JournalError::Duplicate)
            ));
        });
    }

    #[test]
    fn discontiguous_barrier_is_rejected() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let cfg = config(&context, "multimmit-gap", epoch);
            let journal = open_empty(&context, cfg, "initial").await;
            let gap = job(epoch, 1, 5, 1);
            assert!(matches!(
                journal.append_persist(&gap).await,
                Err(JournalError::Cursor)
            ));
        });
    }

    #[test]
    fn record_event_count_is_bounded() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let cfg = config(&context, "multimmit-event-count", epoch);
            let max = cfg.max_events_per_record.get();
            let oversized = (1..=max as u64 + 1)
                .map(|cursor| event(epoch, cursor, 1))
                .collect();
            for (label, events, expected) in [
                ("empty", Vec::new(), 0),
                ("oversized", oversized, max + 1),
            ] {
                let journal = open_empty(&context, cfg.clone(), label).await;
                let job = PersistJob::new(
                    BatchId::new(1),
                    Generation::new(1),
                    Cursor::zero(),
                    events,
                    true,
                );
                assert!(matches!(
                    journal.append_persist(&job).await,
                    Err(JournalError::EventCount { count, max: limit }) if count == expected && limit == max
                ));
            }
        });
    }

    #[test]
    fn oversized_record_is_rejected() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let mut cfg = config(&context, "multimmit-bytes", epoch);
            cfg.max_record_bytes = NZUsize!(8);
            let journal = open_empty(&context, cfg, "initial").await;
            assert!(matches!(
                journal.append_persist(&job(epoch, 1, 0, 1)).await,
                Err(JournalError::ByteLimit)
            ));
        });
    }

    #[test]
    fn recovery_skips_records_a_checkpoint_covers() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let cfg = config(&context, "multimmit-covered", epoch);
            let journal = open_empty(&context, cfg.clone(), "initial").await;

            let first = job(epoch, 1, 0, 1);
            let second = job(epoch, 2, 1, 1);
            let expected = JournalRecord::from_job(&second);
            let (journal, _, sync) = journal.start_persist(&first).await.unwrap();
            sync.await.unwrap();
            let (journal, _, sync) = journal.start_persist(&second).await.unwrap();
            sync.await.unwrap();
            drop(journal);

            for covered in [1, 2] {
                let mut recovery =
                    TestJournal::open(context.child("recovery"), cfg.clone(), Cursor::new(covered))
                        .await
                        .unwrap();
                let expected = (covered == 1).then(|| expected.clone());
                assert_eq!(recovery.next().await.unwrap(), expected);
                assert!(recovery.next().await.unwrap().is_none());
                assert_eq!(recovery.suffix_section(), (covered == 1).then_some(0));
                recovery.finish().unwrap();
            }
        });
    }

    #[test]
    fn rolled_sections_prune_behind_a_checkpoint() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let cfg = config(&context, "multimmit-prune", epoch);
            let journal = open_empty(&context, cfg.clone(), "initial").await;

            let first = job(epoch, 1, 0, 1);
            let (journal, _, sync) = journal.start_persist(&first).await.unwrap();
            sync.await.unwrap();
            // Checkpoint at cursor one: roll, then prune once the snapshot is durable.
            let journal = journal.roll();
            let second = job(epoch, 2, 1, 1);
            let expected = JournalRecord::from_job(&second);
            let (journal, _, sync) = journal.start_persist(&second).await.unwrap();
            sync.await.unwrap();
            let section = journal.section();
            let journal = journal.prune_before(section).await.unwrap();
            drop(journal);

            // Only the post-checkpoint suffix remains on disk.
            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::new(1))
                .await
                .unwrap();
            assert_eq!(recovery.next().await.unwrap(), Some(expected));
            assert!(recovery.next().await.unwrap().is_none());
            let journal = recovery.finish().unwrap();
            assert_eq!(journal.cursor, Cursor::new(2));
        });
    }

    #[test]
    fn replay_resumes_appends_in_the_last_record_section() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let cfg = config(&context, "multimmit-resume-section", epoch);
            let journal = open_empty(&context, cfg.clone(), "initial").await;
            assert_eq!(journal.section(), 0);

            let (journal, _, sync) = journal.start_persist(&job(epoch, 1, 0, 1)).await.unwrap();
            sync.await.unwrap();
            let journal = journal.roll();
            assert_eq!(journal.section(), 1);
            let (journal, _, sync) = journal.start_persist(&job(epoch, 2, 1, 1)).await.unwrap();
            sync.await.unwrap();
            // A roll without a later record leaves no blob for the empty section.
            let journal = journal.roll();
            assert_eq!(journal.section(), 2);
            drop(journal);

            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::zero())
                .await
                .unwrap();
            while recovery.next().await.unwrap().is_some() {}
            assert_eq!(recovery.finish().unwrap().section(), 1);
        });
    }

    #[test]
    fn recovery_prunes_only_below_the_first_uncovered_section() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let cfg = config(&context, "multimmit-recovery-prune-floor", epoch);
            let journal = open_empty(&context, cfg.clone(), "initial").await;

            let first = job(epoch, 1, 0, 1);
            let second = job(epoch, 2, 1, 1);
            let third = job(epoch, 3, 2, 1);
            let (journal, _, sync) = journal.start_persist(&first).await.unwrap();
            sync.await.unwrap();
            let (journal, _, sync) = journal.roll().start_persist(&second).await.unwrap();
            sync.await.unwrap();
            let (journal, _, sync) = journal.roll().start_persist(&third).await.unwrap();
            sync.await.unwrap();
            drop(journal);

            let mut recovery =
                TestJournal::open(context.child("first_recovery"), cfg.clone(), Cursor::new(1))
                    .await
                    .unwrap();
            assert_eq!(
                recovery.next().await.unwrap().unwrap().end_cursor(),
                Cursor::new(2)
            );
            assert_eq!(
                recovery.next().await.unwrap().unwrap().end_cursor(),
                Cursor::new(3)
            );
            assert!(recovery.next().await.unwrap().is_none());
            assert_eq!(recovery.suffix_section(), Some(1));
            let journal = recovery.finish().unwrap().prune_before(1).await.unwrap();
            drop(journal);

            // A second crash must still recover the section-one prefix needed above the old
            // checkpoint, even though section zero was compacted during the first restart.
            let mut recovery =
                TestJournal::open(context.child("second_recovery"), cfg, Cursor::new(1))
                    .await
                    .unwrap();
            assert_eq!(
                recovery.next().await.unwrap().unwrap().end_cursor(),
                Cursor::new(2)
            );
            assert_eq!(
                recovery.next().await.unwrap().unwrap().end_cursor(),
                Cursor::new(3)
            );
            assert!(recovery.next().await.unwrap().is_none());
        });
    }

    #[test]
    fn recovery_rejects_complete_invalid_tail_record() {
        // Once a record is synced, the machine may externalize the safety decisions it contains.
        // Corruption must not make recovery forget those decisions and authorize conflicting ones.
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(9);
            let cfg = config(&context, "multimmit-torn-tail", epoch);
            let journal = open_empty(&context, cfg.clone(), "initial").await;

            let first = job(epoch, 1, 0, 1);
            let expected = JournalRecord::from_job(&first);
            let (journal, _, sync) = journal.start_persist(&first).await.unwrap();
            sync.await.unwrap();
            drop(journal);

            // Append and sync a complete outer frame whose payload violates the record codec.
            // This models corruption above the segmented journal's incomplete-tail repair.
            let invalid = JournalRecord {
                barrier: BatchId::new(2),
                generation: Generation::new(1),
                previous: Cursor::new(1),
                events: Arc::new(Vec::new()),
            };
            let raw: Journal<_, TestRecord> =
                Journal::init(context.child("inject"), TestJournal::storage_config(&cfg))
                    .await
                    .unwrap();
            let mut replay = raw
                .replay(0, 0, cfg.replay_buffer, ReadOptions::default())
                .await
                .unwrap();
            while let Some(record) = replay.next().await {
                record.unwrap();
            }
            let raw = replay.finish().unwrap();
            let (raw, _, _) = raw.append(0, &invalid).await.unwrap();
            let (raw, sync) = raw.start_sync(0).await.unwrap();
            sync.await.unwrap();
            drop(raw);

            // The complete first record remains readable, but recovery must reject the corrupt
            // synced tail instead of silently rewinding it.
            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::zero())
                .await
                .unwrap();
            assert_eq!(recovery.next().await.unwrap(), Some(expected));
            assert!(recovery.next().await.is_err());
        });
    }

    #[test]
    fn sealed_section_corruption_is_fatal() {
        // Sections behind a roll were synced whole; an invalid record there is rot, not crash
        // debris, and recovery must refuse rather than silently regress a checkpointed prefix.
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(9);
            let cfg = config(&context, "multimmit-sealed", epoch);
            let journal = open_empty(&context, cfg.clone(), "initial").await;

            let first = job(epoch, 1, 0, 1);
            let expected = JournalRecord::from_job(&first);
            let (journal, _, sync) = journal.start_persist(&first).await.unwrap();
            sync.await.unwrap();
            let journal = journal.roll();
            let second = job(epoch, 2, 1, 1);
            let (journal, _, sync) = journal.start_persist(&second).await.unwrap();
            sync.await.unwrap();
            drop(journal);

            // Corrupt the sealed (first) section's record body.
            let partition = "multimmit-sealed";
            let mut blobs = context.scan(partition).await.unwrap();
            blobs.sort();
            let name = blobs.first().expect("journal wrote two sections").clone();
            let (blob, _) = context.open(partition, &name).await.unwrap();
            let torn = UInt(expected.encode_size() as u32).encode_size() as u64 + 4;
            let byte = blob
                .read_at(torn, 1, ReadOptions::default())
                .await
                .unwrap()
                .coalesce()
                .as_ref()[0];
            blob.write_at(torn, vec![byte ^ 0x01], WriteOptions::SYNC)
                .await
                .unwrap();
            drop(blob);

            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::zero())
                .await
                .unwrap();
            let result = loop {
                match recovery.next().await {
                    Ok(Some(_)) => continue,
                    other => break other,
                }
            };
            assert!(matches!(result, Err(JournalError::Corrupt)));
        });
    }

    #[test]
    fn wrong_epoch_record_is_an_epoch_mismatch() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(9);
            let cfg = config(&context, "multimmit-epoch", epoch);
            let journal = open_empty(&context, cfg.clone(), "initial").await;
            let (journal, _, sync) = journal.start_persist(&job(epoch, 1, 0, 1)).await.unwrap();
            sync.await.unwrap();
            drop(journal);

            let mut wrong = cfg;
            wrong.epoch = Epoch::new(10);
            let mut recovery = TestJournal::open(context.child("recovery"), wrong, Cursor::zero())
                .await
                .unwrap();
            assert!(matches!(
                recovery.next().await,
                Err(JournalError::EpochMismatch { expected, actual })
                    if expected == Epoch::new(10) && actual == epoch
            ));
        });
    }

    #[test]
    fn record_codec_roundtrips() {
        let epoch = Epoch::new(8);
        let record = TestRecord::from_job(&job(epoch, 3, 2, 1));
        let encoded = record.encode();
        let cfg = RecordCodecConfig {
            event: event_codec(),
            max_events: 4,
        };
        let decoded = <TestRecord as commonware_codec::Decode>::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(decoded, record);
        assert_eq!(decoded.end_cursor(), Cursor::new(3));
    }
}
