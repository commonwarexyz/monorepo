//! Append-and-sync persistence for machine-selected safety decisions.
//!
//! The journal stores exactly the machine's persistence barriers as plain codec items in a
//! [`segmented::variable::Journal`](commonware_storage::journal::segmented::variable::Journal).
//! Integrity is layered where it belongs: the paged buffer
//! checksums every page, the segmented journal frames and repairs an incomplete tail, and recovery
//! here validates every complete record and its cursor continuity against the checkpoint the
//! [`CheckpointStore`] holds. A complete record that fails decoding or validation is corruption:
//! it may contain an already externalized safety decision, so recovery must never discard it.
//!
//! Checkpoints do not enter the journal. A checkpoint rolls the journal to a fresh section
//! and persists the machine snapshot in the [`CheckpointStore`]; once the snapshot is durable
//! the older sections are pruned wholesale.
//!
//! [`CheckpointStore`]: super::CheckpointStore

use crate::{
    multimmit::machine::{
        BarrierAck, BarrierId, Cursor, DomainEvent, DomainEventCodecConfig, PersistJob,
    },
    types::Epoch,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_cryptography::{Digest, bls12381::primitives::variant::Variant};
use commonware_runtime::{
    Error as RuntimeError, Handle, Metrics, Storage, Supervisor, buffer::paged::CacheRef,
};
use commonware_storage::journal::{
    Error as StorageError,
    segmented::variable::{Config as StorageConfig, Journal, Replay},
};
use core::num::NonZeroUsize;
use std::sync::Arc;
use tracing::warn;

/// Configuration for one epoch's safety journal.
#[derive(Clone)]
pub struct Config {
    /// Runtime storage partition dedicated to this epoch.
    pub partition: String,
    /// Epoch expected in every recovered event.
    pub epoch: Epoch,
    /// Bounds for the self-contained machine events.
    pub event_codec: DomainEventCodecConfig,
    /// Greatest number of events accepted in one machine persistence barrier.
    pub max_events_per_record: NonZeroUsize,
    /// Greatest encoded record size.
    pub max_record_bytes: NonZeroUsize,
    /// Shared page cache used by the segmented journal.
    pub page_cache: CacheRef,
    /// Buffered writer capacity for each open journal section.
    pub write_buffer: NonZeroUsize,
}

/// Internal decoding bounds carried by the segmented journal.
#[derive(Clone, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct RecordCodecConfig {
    event: DomainEventCodecConfig,
    max_events: usize,
}

/// One self-contained machine persistence barrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalRecord<V: Variant, D: Digest> {
    barrier: BarrierId,
    generation: u64,
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
    pub const fn barrier(&self) -> BarrierId {
        self.barrier
    }

    /// Returns the process generation that issued the barrier.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the cursor immediately before this barrier.
    pub const fn previous(&self) -> Cursor {
        self.previous
    }

    /// Returns the exact ordered events in this barrier.
    pub fn events(&self) -> &[DomainEvent<V, D>] {
        self.events.as_slice()
    }

    /// Returns the final cursor established by this barrier.
    pub fn result(&self) -> Cursor {
        self.events
            .last()
            .map_or(self.previous, DomainEvent::cursor)
    }
}

impl<V: Variant, D: Digest> Write for JournalRecord<V, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.barrier.get().write(buf);
        self.generation.write(buf);
        self.previous.get().write(buf);
        self.events.len().write(buf);
        for event in self.events.iter() {
            event.write(buf);
        }
    }
}

impl<V: Variant, D: Digest> EncodeSize for JournalRecord<V, D> {
    fn encode_size(&self) -> usize {
        self.barrier.get().encode_size()
            + self.generation.encode_size()
            + self.previous.get().encode_size()
            + self.events.len().encode_size()
            + self
                .events
                .iter()
                .map(EncodeSize::encode_size)
                .sum::<usize>()
    }
}

impl<V: Variant, D: Digest> Read for JournalRecord<V, D> {
    type Cfg = RecordCodecConfig;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let barrier = BarrierId::new(u64::read(buf)?);
        let generation = u64::read(buf)?;
        let previous = Cursor::new(u64::read(buf)?);
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
pub struct SafetyJournal<E: Storage + Metrics, V: Variant, D: Digest> {
    journal: Journal<E, JournalRecord<V, D>>,
    config: Config,
    cursor: Cursor,
    last: Option<JournalRecord<V, D>>,
    section: u64,
}

/// A journal or recovery failure. All variants are fatal to the current instance.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The underlying segmented journal failed.
    #[error("segmented journal failed: {0}")]
    Storage(#[from] StorageError),
    /// The runtime failed a storage operation.
    #[error("runtime failed: {0}")]
    Runtime(#[from] RuntimeError),
    /// A barrier does not extend the journal's cursor.
    #[error("safety journal cursor is not contiguous")]
    Cursor,
    /// A persisted record belongs to another epoch.
    #[error("safety journal context does not match the epoch manifest")]
    Context,
    /// A duplicate live barrier differs from the already durable barrier.
    #[error("duplicate safety journal barrier is not byte-identical")]
    Duplicate,
    /// A record exceeds the configured byte ceiling.
    #[error("safety journal record exceeds the byte limit")]
    ByteLimit,
    /// The journal contains a discontiguous record.
    #[error("safety journal is corrupt")]
    Corrupt,
}

impl<E, V, D> SafetyJournal<E, V, D>
where
    E: Storage + Metrics,
    V: Variant,
    D: Digest,
{
    /// Opens the segmented journal and returns its recovery reader.
    ///
    /// `covered` is the cursor of the newest durable checkpoint; records at or below it are
    /// skipped, and the first retained record must extend it exactly.
    pub async fn open(
        context: E,
        config: Config,
        covered: Cursor,
    ) -> Result<Recovery<E, V, D>, Error>
    where
        E: Supervisor,
    {
        let journal = Journal::init(context, Self::storage_config(&config)).await?;
        let replay = journal.replay(0, 0, config.write_buffer).await?;
        Ok(Recovery {
            replay,
            config,
            covered,
            cursor: covered,
            suffix: Vec::new(),
            suffix_section: None,
            saw_record: false,
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

    /// Appends the exact machine-issued barrier and starts syncing it.
    ///
    /// An error reported by the returned handle is fatal. The returned journal must not be used
    /// after such an error.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn start_persist(
        self,
        job: &PersistJob<V, D>,
    ) -> Result<(Self, BarrierAck, Handle<()>), Error> {
        let (journal, result) = self.append_persist(job).await?;
        let (journal, sync) = journal.start_sync().await?;
        Ok((journal, result, sync))
    }

    /// Starts syncing every appended barrier.
    ///
    /// A sync makes the whole appended prefix durable, so one handle acknowledges every barrier
    /// appended before it. An error reported by the handle is fatal.
    pub async fn start_sync(self) -> Result<(Self, Handle<()>), Error> {
        let section = self.section;
        let (journal, sync) = self.journal.start_sync(section).await?;
        Ok((Self { journal, ..self }, sync))
    }

    /// Appends the exact machine-issued barrier without starting a sync.
    ///
    /// The barrier becomes durable when a later sync covers it; callers that release external
    /// effects must sync first.
    pub async fn append_persist(self, job: &PersistJob<V, D>) -> Result<(Self, BarrierAck), Error> {
        if let Some(last) = self.last.as_ref()
            && last.barrier() == job.id()
            && last.generation() == job.generation()
        {
            let duplicate = JournalRecord::from_job(job);
            if last != &duplicate {
                return Err(Error::Duplicate);
            }
            let result = completion(last);
            return Ok((self, result));
        }
        if job.previous() != self.cursor {
            return Err(Error::Cursor);
        }
        let record = JournalRecord::from_job(job);
        validate_events(&record, &self.config)?;
        if record.encode_size() > self.config.max_record_bytes.get() {
            return Err(Error::ByteLimit);
        }
        let section = self.section;
        let (journal, _, _) = self.journal.append(section, &record).await?;
        let cursor = record.result();
        let result = completion(&record);
        Ok((
            Self {
                journal,
                config: self.config,
                cursor,
                last: Some(record),
                section,
            },
            result,
        ))
    }

    #[cfg(test)]
    const fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Rolls the journal to a fresh section for the barriers after a checkpoint.
    ///
    /// The caller persists the checkpoint's snapshot separately; once that snapshot is
    /// durable, [`Self::prune`] discards every section before the roll.
    pub fn roll(self) -> Self {
        Self {
            section: self.section + 1,
            last: None,
            ..self
        }
    }

    /// Prunes every whole section before the current one.
    ///
    /// Sound only once a checkpoint covering all pruned events is durable.
    pub async fn prune(self) -> Result<Self, Error> {
        let (journal, _) = self.journal.prune(self.section).await?;
        Ok(Self { journal, ..self })
    }

    /// Prunes sections strictly below a checkpoint-covered floor without changing the append
    /// section recovered from a later suffix.
    pub(crate) async fn prune_before(self, section: u64) -> Result<Self, Error> {
        let (journal, _) = self.journal.prune(section).await?;
        Ok(Self { journal, ..self })
    }
}

/// Streaming recovery over a segmented safety journal.
pub struct Recovery<E: Storage + Metrics + Supervisor, V: Variant, D: Digest> {
    replay: Replay<E, JournalRecord<V, D>>,
    config: Config,
    covered: Cursor,
    cursor: Cursor,
    suffix: Vec<JournalRecord<V, D>>,
    suffix_section: Option<u64>,
    saw_record: bool,
    section: u64,
}

impl<E, V, D> Recovery<E, V, D>
where
    E: Storage + Metrics + Supervisor,
    V: Variant,
    D: Digest,
{
    #[cfg(test)]
    const fn cursor(&self) -> Cursor {
        self.cursor
    }

    /// Returns the contiguous event suffix after the covered checkpoint.
    pub fn suffix(&self) -> &[JournalRecord<V, D>] {
        &self.suffix
    }

    /// Returns the first section containing an event not covered by the checkpoint.
    pub const fn suffix_section(&self) -> Option<u64> {
        self.suffix_section
    }

    /// Returns whether the journal contained any complete record.
    pub const fn saw_record(&self) -> bool {
        self.saw_record
    }

    /// Returns the next barrier after the covered checkpoint, validating continuity.
    ///
    /// The segmented journal repairs incomplete outer framing before yielding records. Any
    /// complete record yielded here must decode and extend the validated prefix exactly.
    pub async fn next(&mut self) -> Result<Option<JournalRecord<V, D>>, Error> {
        loop {
            let Some(item) = self
                .replay
                .next_bounded(self.config.max_record_bytes.get())
                .await
            else {
                return Ok(None);
            };
            let (section, _, _, record) = match item {
                Ok(item) => item,
                Err(StorageError::ItemTooLarge(_)) => return Err(Error::ByteLimit),
                Err(error) => return Err(error.into()),
            };
            self.saw_record = true;
            self.section = section;
            // A record from another epoch is a configuration error, not crash debris.
            validate_events(&record, &self.config)?;
            // Pruning lags the checkpoint, so records the checkpoint already covers may
            // remain; they were validated when written and chain below the checkpoint.
            if record.result() <= self.covered {
                continue;
            }
            // A record whose ancestry is ahead of the validated prefix means earlier data is
            // missing entirely: that is prefix loss, never tail debris, in any section.
            if record.previous() > self.cursor {
                warn!(
                    section,
                    previous = record.previous().get(),
                    expected = self.cursor.get(),
                    "journal prefix is missing"
                );
                return Err(Error::Corrupt);
            }
            // A record behind the validated prefix (that the checkpoint does not cover) is a
            // stale crash generation overlapping the tail.
            if record.previous() < self.cursor {
                return Err(Error::Corrupt);
            }
            self.suffix_section.get_or_insert(section);
            self.cursor = record.result();
            self.suffix.push(record.clone());
            return Ok(Some(record));
        }
    }

    /// Finishes recovery and returns the live append-and-sync handle.
    ///
    /// Physical tail repair is completed by the segmented journal before this handle is returned.
    pub fn finish(self) -> Result<SafetyJournal<E, V, D>, Error> {
        let section = if self.saw_record { self.section } else { 0 };
        let journal = self.replay.finish()?;
        Ok(SafetyJournal {
            journal,
            config: self.config,
            cursor: self.cursor,
            last: None,
            section,
        })
    }
}

fn validate_events<V: Variant, D: Digest>(
    record: &JournalRecord<V, D>,
    cfg: &Config,
) -> Result<(), Error> {
    if record.events().is_empty() || record.events().len() > cfg.max_events_per_record.get() {
        return Err(Error::Cursor);
    }
    let mut previous = record.previous();
    for event in record.events() {
        if event.epoch() != cfg.epoch {
            return Err(Error::Context);
        }
        if previous.next() != Some(event.cursor()) {
            return Err(Error::Cursor);
        }
        previous = event.cursor();
    }
    Ok(())
}

fn completion<V: Variant, D: Digest>(record: &JournalRecord<V, D>) -> BarrierAck {
    BarrierAck::new(record.barrier(), record.generation(), record.result())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::{CodecConfig, Limits},
            machine::Change,
        },
        types::View,
    };
    use commonware_codec::{Encode, varint::UInt};
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
                barrier: BarrierId::new(seed + 1),
                generation: seed + 1,
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
                    CodecConfig::new(6, 6, Limits::new(2, 2).unwrap()).unwrap(),
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
            CodecConfig::new(1, 1, Limits::new(1, 0).unwrap()).unwrap(),
            4096,
            16,
            16,
        )
    }

    fn event(epoch: Epoch, cursor: u64, generation: u64) -> DomainEvent<MinPk, Sha256Digest> {
        DomainEvent::new(
            epoch,
            Cursor::new(cursor),
            Change::GenerationAdvanced(generation),
        )
    }

    fn job(
        epoch: Epoch,
        barrier: u64,
        previous: u64,
        generation: u64,
    ) -> PersistJob<MinPk, Sha256Digest> {
        PersistJob::new(
            BarrierId::new(barrier),
            generation,
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
        }
    }

    #[test]
    fn record_reuses_the_persist_job_event_allocation() {
        let job = job(Epoch::new(8), 1, 0, 0);
        let record = JournalRecord::from_job(&job);
        assert_eq!(record.events.as_ptr(), job.events().as_ptr());
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
            assert_eq!(journal.cursor(), Cursor::new(2));
            drop(journal);

            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::zero())
                .await
                .unwrap();
            assert_eq!(recovery.next().await.unwrap(), Some(expected[0].clone()));
            assert_eq!(recovery.next().await.unwrap(), Some(expected[1].clone()));
            assert!(recovery.next().await.unwrap().is_none());
            assert_eq!(recovery.cursor(), Cursor::new(2));
            assert!(recovery.saw_record());
            let journal = recovery.finish().unwrap();
            assert_eq!(journal.cursor(), Cursor::new(2));
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
                BarrierId::new(1),
                1,
                Cursor::new(0),
                vec![event(epoch, 1, 7)],
                true,
            );
            assert!(matches!(
                journal.append_persist(&forged).await,
                Err(Error::Duplicate)
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
                Err(Error::Cursor)
            ));
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
                Err(Error::ByteLimit)
            ));
        });
    }

    #[test]
    fn recovery_rejects_oversized_complete_record() {
        DeterministicRunner::default().start(|context| async move {
            let epoch = Epoch::new(8);
            let mut cfg = config(&context, "multimmit-recovery-bytes", epoch);
            cfg.max_record_bytes = NZUsize!(8);

            // Bypass the live safety-journal admission check to model a complete hostile or
            // corrupt frame already present on disk.
            let raw: Journal<_, TestRecord> =
                Journal::init(context.child("inject"), TestJournal::storage_config(&cfg))
                    .await
                    .unwrap();
            let record = JournalRecord::from_job(&job(epoch, 1, 0, 1));
            let (raw, _, _) = raw.append(0, &record).await.unwrap();
            let (raw, sync) = raw.start_sync(0).await.unwrap();
            sync.await.unwrap();
            drop(raw);

            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::zero())
                .await
                .unwrap();
            assert!(matches!(recovery.next().await, Err(Error::ByteLimit)));
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

            // A checkpoint covering cursor one leaves only the second record to replay, even
            // though pruning has not yet removed the first.
            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::new(1))
                .await
                .unwrap();
            assert_eq!(recovery.next().await.unwrap(), Some(expected));
            assert!(recovery.next().await.unwrap().is_none());
            recovery.finish().unwrap();
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
            let journal = journal.prune().await.unwrap();
            drop(journal);

            // Only the post-checkpoint suffix remains on disk.
            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::new(1))
                .await
                .unwrap();
            assert_eq!(recovery.next().await.unwrap(), Some(expected));
            assert!(recovery.next().await.unwrap().is_none());
            let journal = recovery.finish().unwrap();
            assert_eq!(journal.cursor(), Cursor::new(2));
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
                recovery.next().await.unwrap().unwrap().result(),
                Cursor::new(2)
            );
            assert_eq!(
                recovery.next().await.unwrap().unwrap().result(),
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
                recovery.next().await.unwrap().unwrap().result(),
                Cursor::new(2)
            );
            assert_eq!(
                recovery.next().await.unwrap().unwrap().result(),
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
                barrier: BarrierId::new(2),
                generation: 1,
                previous: Cursor::new(1),
                events: Arc::new(Vec::new()),
            };
            let raw: Journal<_, TestRecord> =
                Journal::init(context.child("inject"), TestJournal::storage_config(&cfg))
                    .await
                    .unwrap();
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
            let byte = blob.read_at(torn, 1).await.unwrap().coalesce().as_ref()[0];
            blob.write_at(torn, vec![byte ^ 0x01], WriteOptions::SYNC)
                .await
                .unwrap();

            let mut recovery = TestJournal::open(context.child("recovery"), cfg, Cursor::zero())
                .await
                .unwrap();
            let result = loop {
                match recovery.next().await {
                    Ok(Some(_)) => continue,
                    other => break other,
                }
            };
            assert!(matches!(result, Err(Error::Corrupt)));
        });
    }

    #[test]
    fn wrong_epoch_record_is_a_context_error() {
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
            assert!(matches!(recovery.next().await, Err(Error::Context)));
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
        assert_eq!(decoded.result(), Cursor::new(3));
        let _ = View::zero();
    }
}
