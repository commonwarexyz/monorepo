//! Startup recovery for one Multimmit engine.
//!
//! [`recover`] rebuilds the machine from durable state before any actor starts, in a fixed order:
//!
//! 1. Open the checkpoint store and the safety journal.
//! 2. Restore the newest checkpoint and stream the journal suffix after it into the machine.
//! 3. Verify every self-contained artifact the recovered machine retains.
//! 4. Prune journal sections the checkpoint covers.
//! 5. Compact a suffix of at least one checkpoint interval into a new checkpoint.
//!
//! Compaction makes the recovered state the new base, so it must follow the retained-artifact
//! check. One entry point makes that order structural rather than a convention every caller
//! repeats.
//!
//! Recovery never asks the application to verify payloads again: a full acceptance rests on a
//! verdict that already promised the body survives a crash, and an adopted header never needed
//! one.
//!
//! # Fresh start
//!
//! A node with no durable checkpoint and an empty journal starts fresh; otherwise it recovers
//! from its newest complete checkpoint and contiguous journal suffix. A validator deployment may
//! use the fresh path only with a never-active epoch key and a new partition prefix. The engine has
//! no trusted-checkpoint import or external key-use registry, so it cannot distinguish a first
//! start from storage loss under an active key.

use super::{
    JournalConfig, JournalError, SafetyJournal, SnapshotError, SnapshotStore, journal::SuffixReplay,
};
use crate::{
    Epochable as _,
    multimmit::{
        config::{Error as ConfigError, Profile},
        machine::{
            CoreBootstrapError, CoreError, CoreState, Cursor, ReplayError, Snapshot,
            SnapshotCodecConfig,
        },
        scheme::bls12381::{Scheme, Signed},
        types::Artifact,
    },
};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_parallel::Strategy;
use commonware_runtime::{buffer::paged::CacheRef, telemetry::traces::TracedExt as _};
use commonware_storage::Context as StorageContext;
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use std::{collections::HashSet, num::NonZeroU64, sync::Arc};
use tracing::{Instrument as _, field::Empty, info_span};

/// Joins an engine's partition prefix and the name of each store it owns.
const PARTITION_SUFFIX: &str = "machine";

/// The storage partitions an engine owns under its prefix.
pub(crate) struct Partitions {
    /// The safety journal.
    pub(crate) journal: String,
    /// The checkpoint store.
    pub(crate) checkpoints: String,
}

/// Returns the partitions an engine derives from `prefix`.
pub(crate) fn partitions(prefix: &str) -> Partitions {
    Partitions {
        journal: format!("{prefix}_{PARTITION_SUFFIX}_journal"),
        checkpoints: format!("{prefix}_{PARTITION_SUFFIX}_checkpoints"),
    }
}

/// Returns whether `prefix` is a non-empty run of ASCII alphanumerics and underscores, the form
/// every storage partition prefix takes.
pub(crate) fn valid_partition_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Opaque failure while deriving the machine's scheduling limits from its profile.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct CoreInitializationError(CoreError);

/// A failure to open an engine: an invalid configuration, or fatal storage recovery.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The configuration is invalid; no storage was touched.
    #[error("invalid configuration: {0}")]
    Config(#[from] ConfigError),
    /// The safety journal failed to open, replay, or prune.
    #[error("safety journal failed: {0}")]
    Journal(#[from] JournalError),
    /// The checkpoint store failed to open or store a snapshot.
    #[error("checkpoint store failed: {0}")]
    Checkpoint(#[from] SnapshotError),
    /// The machine rejected the checkpoint or a replayed journal event.
    #[error("machine recovery failed: {0}")]
    Recovery(#[from] ReplayError),
    /// The machine could not derive its scheduling limits from the profile.
    #[error("protocol core initialization failed")]
    CoreInitialization(#[source] CoreInitializationError),
    /// The recovered machine holds staged or unacknowledged state, so it has no checkpoint cut.
    #[error("recovered machine has no acknowledged checkpoint cut")]
    NoCheckpointCut,
    /// An artifact the recovered machine retains failed verification.
    #[error("recovered machine contains an invalid artifact")]
    InvalidArtifact,
}

impl From<CoreBootstrapError> for OpenError {
    fn from(error: CoreBootstrapError) -> Self {
        match error {
            CoreBootstrapError::Core(error) => {
                Self::CoreInitialization(CoreInitializationError(error))
            }
            CoreBootstrapError::Recovery(error) => Self::Recovery(error),
        }
    }
}

/// Configuration for [`recover`].
pub(crate) struct RecoveryConfig<'a, H: Hasher, P: PublicKey, V: Variant, T: Strategy> {
    /// The immutable local machine profile.
    pub profile: Profile<H::Digest>,
    /// Storage partition prefix owned exclusively by this engine.
    pub partition_prefix: &'a str,
    /// Scheme that verifies the recovered machine's retained artifacts.
    pub scheme: &'a Scheme<P, V>,
    /// Execution strategy for the retained-artifact check.
    pub strategy: &'a T,
    /// Page cache for the safety journal.
    pub page_cache: CacheRef,
    /// Replayed journal events at which recovery compacts the suffix into a new checkpoint.
    pub checkpoint_interval: NonZeroU64,
}

/// The machine and stores rebuilt from durable state, before any actor starts.
pub(crate) struct Recovered<E: StorageContext, H: Hasher, V: Variant> {
    /// The protocol owner: fresh, or restored from the checkpoint and replayed journal suffix.
    pub core: CoreState<H, V>,
    /// The safety journal, open for appends after the replayed suffix.
    pub journal: SafetyJournal<E, V, H::Digest>,
    /// Durable machine checkpoints.
    pub checkpoints: SnapshotStore<E, V, H::Digest>,
    /// Journal events replayed after the newest checkpoint, or `None` for a fresh start.
    pub replayed: Option<u64>,
}

impl<E, H, V> Recovered<E, H, V>
where
    E: StorageContext,
    H: Hasher,
    V: Variant,
{
    /// Replaces a replayed suffix of at least `interval` events with a new checkpoint.
    ///
    /// The snapshot is synced before the journal rolls, so a crash at any later point reopens
    /// either the old suffix or the new checkpoint. Compaction makes the recovered state the new
    /// base, so [`recover`] runs it only after the retained-artifact check.
    #[tracing::instrument(
        name = "multimmit.engine.compact_recovery_suffix",
        level = "info",
        skip_all
    )]
    async fn compact(self, interval: NonZeroU64) -> Result<Self, OpenError> {
        if self
            .replayed
            .is_none_or(|replayed| replayed < interval.get())
        {
            return Ok(self);
        }
        let snapshot = self
            .core
            .machine()
            .checkpoint_cut()
            .ok_or(OpenError::NoCheckpointCut)?;
        let checkpoints = self
            .checkpoints
            .store(snapshot)
            .instrument(info_span!(
                "multimmit.engine.compact_recovery_suffix.checkpoint"
            ))
            .await?;
        let journal = self.journal.roll();
        let floor = journal.section();
        let journal = journal
            .prune_before(floor)
            .instrument(info_span!(
                "multimmit.engine.compact_recovery_suffix.journal"
            ))
            .await?;
        Ok(Self {
            core: self.core,
            journal,
            checkpoints,
            replayed: Some(0),
        })
    }
}

/// Opens (or reopens) every durable store for one engine and rebuilds its machine.
///
/// Runs the steps in the module documentation in order. `context` labels the stores and seeds the
/// retained-artifact check.
pub(crate) async fn recover<E, H, P, V, T>(
    context: &mut E,
    config: RecoveryConfig<'_, H, P, V, T>,
) -> Result<Recovered<E, H, V>, OpenError>
where
    E: CryptoRng + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    let checkpoint_interval = config.checkpoint_interval;
    let recovered = open_stores(context, config).await?;
    recovered.compact(checkpoint_interval).await
}

/// Opens the stores, replays the journal suffix, verifies retained artifacts, and prunes covered
/// journal sections.
#[tracing::instrument(
    name = "multimmit.engine.open_stores",
    level = "info",
    skip_all,
    fields(epoch = config.profile.protocol().epoch().get().traced())
)]
async fn open_stores<E, H, P, V, T>(
    context: &mut E,
    config: RecoveryConfig<'_, H, P, V, T>,
) -> Result<Recovered<E, H, V>, OpenError>
where
    E: CryptoRng + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    let RecoveryConfig {
        profile,
        partition_prefix,
        scheme,
        strategy,
        page_cache,
        ..
    } = config;
    let partitions = partitions(partition_prefix);
    let (checkpoints, checkpoint) = SnapshotStore::open(
        context.child("checkpoints"),
        partitions.checkpoints,
        SnapshotCodecConfig::from_profile(&profile),
        profile.protocol().epoch(),
    )
    .instrument(info_span!("multimmit.engine.open_stores.checkpoint"))
    .await?;
    let has_checkpoint = checkpoint.is_some();
    let covered = checkpoint.as_ref().map_or(Cursor::zero(), Snapshot::cursor);
    let mut suffix =
        open_journal::<_, H, V>(context, &profile, partitions.journal, page_cache, covered).await?;
    let restored = replay_journal(&mut suffix, profile, checkpoint).await?;
    let suffix_section = suffix.suffix_section();
    let journal = suffix.finish()?;
    if restored.replayed.is_some() {
        verify_retained_artifacts(scheme, strategy, context, &restored.core).await?;
    }
    // A fresh start has no checkpoint, so it never prunes.
    let journal = if has_checkpoint {
        prune_covered(journal, suffix_section).await?
    } else {
        journal
    };
    Ok(Recovered {
        core: restored.core,
        journal,
        checkpoints,
        replayed: restored.replayed,
    })
}

/// Opens the safety journal for a replay of the suffix after `covered`.
async fn open_journal<E, H, V>(
    context: &E,
    profile: &Profile<H::Digest>,
    partition: String,
    page_cache: CacheRef,
    covered: Cursor,
) -> Result<SuffixReplay<E, V, H::Digest>, JournalError>
where
    E: StorageContext,
    H: Hasher,
    V: Variant,
{
    let config = JournalConfig::from_profile(profile, partition, page_cache);
    SafetyJournal::open(context.child("journal"), config, covered)
        .instrument(info_span!("multimmit.engine.open_stores.journal"))
        .await
}

/// The machine rebuilt from the checkpoint and journal suffix.
struct Restored<H: Hasher, V: Variant> {
    /// The fresh or restored protocol owner.
    core: CoreState<H, V>,
    /// Journal events replayed after the checkpoint, or `None` for a fresh start.
    replayed: Option<u64>,
}

/// Streams the journal suffix into the machine restored from `checkpoint`.
///
/// Without a checkpoint the suffix replays over the genesis cut, which puts the machine in
/// recovery mode the same way a checkpoint does. With neither a checkpoint nor a journal record,
/// the machine starts fresh.
async fn replay_journal<E, H, V>(
    suffix: &mut SuffixReplay<E, V, H::Digest>,
    profile: Profile<H::Digest>,
    checkpoint: Option<Snapshot<V, H::Digest>>,
) -> Result<Restored<H, V>, OpenError>
where
    E: StorageContext,
    H: Hasher,
    V: Variant,
{
    let span = info_span!(
        "multimmit.engine.open_stores.replay",
        records = Empty,
        events = Empty,
    );
    async {
        let mut next = suffix.next().await?;
        if next.is_none() && checkpoint.is_none() {
            return Ok(Restored {
                core: CoreState::fresh(profile)?,
                replayed: None,
            });
        }
        let snapshot = match checkpoint {
            Some(snapshot) => snapshot,
            None => CoreState::<H, V>::fresh(profile.clone())?
                .machine()
                .checkpoint_cut()
                .ok_or(OpenError::NoCheckpointCut)?,
        };
        let mut core = CoreState::restore(profile, snapshot)?;
        let mut records = 0usize;
        let mut events = 0u64;
        let replay = async {
            while let Some(record) = next {
                records += 1;
                for event in record.into_events() {
                    core.replay(event)?;
                    events += 1;
                }
                next = suffix.next().await?;
            }
            Ok::<_, OpenError>(())
        }
        .await;
        // Record the counts before propagating a failure: they locate the rejected record.
        span.record("records", records.traced());
        span.record("events", events.traced());
        replay?;
        Ok(Restored {
            core,
            replayed: Some(events),
        })
    }
    .instrument(span.clone())
    .await
}

/// Returns each artifact `snapshot` retains once.
///
/// An artifact with several durable holders, such as a certificate that is both forwarded and a
/// view's exit proof, appears once, so recovery verifies it once.
fn retained_once<H: Hasher, V: Variant>(
    snapshot: &Snapshot<V, H::Digest>,
) -> Vec<Arc<Artifact<V, H::Digest>>> {
    let mut ids = HashSet::new();
    snapshot
        .retained_artifacts()
        .filter(|artifact| ids.insert(artifact.id::<H>()))
        .collect()
}

/// Verifies every self-contained artifact the recovered machine retains on a `strategy` worker.
///
/// A vote update signs the content it rebuilds over its signer's earlier updates, so it cannot be
/// checked in isolation; the replayed machine owns that content.
async fn verify_retained_artifacts<H, P, V, T>(
    scheme: &Scheme<P, V>,
    strategy: &T,
    rng: &mut impl CryptoRng,
    core: &CoreState<H, V>,
) -> Result<(), OpenError>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
{
    let snapshot = core
        .machine()
        .checkpoint_cut()
        .ok_or(OpenError::NoCheckpointCut)?;
    let artifacts = retained_once::<H, V>(&snapshot);
    let scheme = scheme.clone();
    let mut rng = StdRng::from_rng(rng);
    let span = info_span!(
        "multimmit.engine.open_stores.verify_artifacts",
        artifacts = artifacts.len().traced(),
    );
    let worker_span = span.clone();
    let verdicts = strategy
        .spawn(artifacts.len(), move |worker| {
            worker_span.in_scope(|| {
                let unverified = artifacts
                    .iter()
                    .filter_map(|artifact| self_contained(artifact))
                    .collect::<Vec<_>>();
                scheme.verify_batch::<_, H, H::Digest>(&mut rng, &unverified, &worker)
            })
        })
        .instrument(span)
        .await;
    if verdicts.iter().any(|verdict| !verdict.is_valid()) {
        return Err(OpenError::InvalidArtifact);
    }
    Ok(())
}

/// Returns the batch item that verifies `artifact` on its own, or `None` for a vote update.
fn self_contained<V: Variant, D: Digest>(artifact: &Artifact<V, D>) -> Option<Signed<'_, V, D>> {
    match artifact {
        Artifact::TransactionBlock(block) => Some(Signed::TransactionBlock(block)),
        Artifact::LeaderBlock(block) => Some(Signed::LeaderBlock(block)),
        Artifact::Vqc(certificate) => Some(Signed::Vqc(certificate)),
        Artifact::Lqc(certificate) => Some(Signed::Lqc(certificate)),
        Artifact::Floor(floor) => Some(Signed::Lqc(floor.lqc())),
        Artifact::Update(_) => None,
    }
}

/// Prunes journal sections the checkpoint covers, completing any prune a crash interrupted.
///
/// The restored machine accepted the checkpoint and suffix, so every section below the first
/// uncovered one is obsolete. With no uncovered record, the journal rolls past every section.
async fn prune_covered<E, V, D>(
    journal: SafetyJournal<E, V, D>,
    suffix_section: Option<u64>,
) -> Result<SafetyJournal<E, V, D>, JournalError>
where
    E: StorageContext,
    V: Variant,
    D: Digest,
{
    let journal = if suffix_section.is_some() {
        journal
    } else {
        journal.roll()
    };
    let floor = suffix_section.unwrap_or_else(|| journal.section());
    journal
        .prune_before(floor)
        .instrument(info_span!("multimmit.engine.open_stores.prune"))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            config::{Role, Tuning},
            machine::{
                BatchId, Change, DomainEvent, DomainEventCodecConfig, Generation, MAX_BATCH_BYTES,
                MAX_BATCH_EVENTS, PersistJob,
            },
            mocks::Committee,
        },
        types::View,
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Storage as _, Supervisor as _,
        buffer::paged,
        deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
    };
    use commonware_utils::{NZU64, NZUsize};

    fn observer(committee: &Committee<MinPk>) -> Profile<Sha256Digest> {
        Profile::new::<MinPk>(committee.config.clone(), Role::Observer, Tuning::default()).unwrap()
    }

    /// Replays and compaction never check a generation event's content beyond its order.
    fn generation(committee: &Committee<MinPk>, index: u64) -> DomainEvent<MinPk, Sha256Digest> {
        DomainEvent::new(
            committee.config.epoch(),
            Cursor::new(index),
            Change::GenerationAdvanced(Generation::new(index)),
        )
    }

    fn certificate(
        committee: &Committee<MinPk>,
        index: u64,
        signer: &Committee<MinPk>,
    ) -> DomainEvent<MinPk, Sha256Digest> {
        DomainEvent::new(
            committee.config.epoch(),
            Cursor::new(index),
            Change::CertificateCreated {
                artifact: Arc::new(Artifact::Vqc(signer.vqc(View::new(1)))),
            },
        )
    }

    fn page_cache(context: &DeterministicContext) -> CacheRef {
        CacheRef::from_pooler(context, paged::page_size(4_096), NZUsize!(8))
    }

    /// Appends one durable record per event to `prefix`'s journal, after the events it holds.
    async fn append(
        context: &DeterministicContext,
        committee: &Committee<MinPk>,
        prefix: &str,
        events: Vec<DomainEvent<MinPk, Sha256Digest>>,
    ) {
        let config = JournalConfig::from_profile(
            &observer(committee),
            partitions(prefix).journal,
            page_cache(context),
        );
        let mut replay = SafetyJournal::<_, MinPk, Sha256Digest>::open(
            context.child("append"),
            config,
            Cursor::zero(),
        )
        .await
        .unwrap();
        while replay.next().await.unwrap().is_some() {}
        let mut journal = replay.finish().unwrap();
        for event in events {
            let previous = Cursor::new(event.cursor().get() - 1);
            let job = PersistJob::new(
                BatchId::new(event.cursor().get()),
                Generation::new(1),
                previous,
                vec![event],
                false,
            );
            let (next, _, sync) = journal.start_persist(&job).await.unwrap();
            sync.await.unwrap();
            journal = next;
        }
    }

    async fn reopen(
        context: &DeterministicContext,
        committee: &Committee<MinPk>,
        prefix: &str,
        checkpoint_interval: NonZeroU64,
    ) -> Result<Recovered<DeterministicContext, Sha256, MinPk>, OpenError> {
        let mut store_context = context.child("stores");
        Box::pin(recover::<_, Sha256, _, _, _>(
            &mut store_context,
            RecoveryConfig {
                profile: observer(committee),
                partition_prefix: prefix,
                scheme: &committee.verifier,
                strategy: &Sequential,
                page_cache: page_cache(context),
                checkpoint_interval,
            },
        ))
        .await
    }

    async fn journal_sections(context: &DeterministicContext, prefix: &str) -> Vec<Vec<u8>> {
        let mut sections = context.scan(&partitions(prefix).journal).await.unwrap();
        sections.sort();
        sections
    }

    fn section(index: u64) -> Vec<u8> {
        index.to_be_bytes().to_vec()
    }

    #[test_traced]
    fn empty_stores_start_fresh() {
        DeterministicRunner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(79, 6).build();
            let mut store_context: DeterministicContext = context.child("stores");
            let recovered = Box::pin(recover::<_, Sha256, _, _, _>(
                &mut store_context,
                RecoveryConfig {
                    profile: observer(&committee),
                    partition_prefix: "fresh",
                    scheme: &committee.verifier,
                    strategy: &Sequential,
                    page_cache: CacheRef::from_pooler(
                        &context,
                        paged::page_size(4_096),
                        NZUsize!(8),
                    ),
                    checkpoint_interval: NZU64!(1),
                },
            ))
            .await
            .unwrap();

            assert_eq!(recovered.replayed, None);
            assert_eq!(recovered.journal.section(), 0);
        });
    }

    #[test_traced]
    fn a_journal_without_a_checkpoint_replays_over_genesis() {
        DeterministicRunner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(79, 6).build();
            let events = (1..=3).map(|index| generation(&committee, index)).collect();
            append(&context, &committee, "suffix", events).await;

            for _ in 0..2 {
                let recovered = reopen(&context, &committee, "suffix", NZU64!(4))
                    .await
                    .unwrap();
                assert_eq!(recovered.replayed, Some(3));
                assert_eq!(recovered.journal.section(), 0);
                let cut = recovered.core.machine().checkpoint_cut().unwrap();
                assert_eq!(cut.cursor(), Cursor::new(3));
            }
            assert_eq!(journal_sections(&context, "suffix").await, vec![section(0)]);
        });
    }

    #[test_traced]
    fn a_suffix_of_one_interval_compacts_into_a_checkpoint() {
        DeterministicRunner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(79, 6).build();
            let events = (1..=2).map(|index| generation(&committee, index)).collect();
            append(&context, &committee, "compact", events).await;

            let recovered = reopen(&context, &committee, "compact", NZU64!(1))
                .await
                .unwrap();
            assert_eq!(recovered.replayed, Some(0));
            assert_eq!(recovered.journal.section(), 1);
            drop(recovered);
            assert!(journal_sections(&context, "compact").await.is_empty());

            // The checkpoint now holds every event: the empty suffix replays nothing, and appends
            // resume in the section after every pruned one.
            let recovered = reopen(&context, &committee, "compact", NZU64!(1))
                .await
                .unwrap();
            assert_eq!(recovered.replayed, Some(0));
            assert_eq!(recovered.journal.section(), 1);
            let cut = recovered.core.machine().checkpoint_cut().unwrap();
            assert_eq!(cut.cursor(), Cursor::new(2));
        });
    }

    #[test_traced]
    fn a_crash_before_pruning_a_stored_checkpoint_prunes_on_recovery() {
        DeterministicRunner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(79, 6).build();
            let events = (1..=2).map(|index| generation(&committee, index)).collect();
            append(&context, &committee, "interrupted", events).await;

            // Store the checkpoint compaction would, then stop before the journal rolls.
            let recovered = reopen(&context, &committee, "interrupted", NZU64!(4))
                .await
                .unwrap();
            let cut = recovered.core.machine().checkpoint_cut().unwrap();
            let checkpoints = recovered.checkpoints.store(cut).await.unwrap();
            drop((checkpoints, recovered.journal));
            assert_eq!(
                journal_sections(&context, "interrupted").await,
                vec![section(0)]
            );

            let recovered = reopen(&context, &committee, "interrupted", NZU64!(4))
                .await
                .unwrap();
            assert_eq!(recovered.replayed, Some(0));
            assert_eq!(recovered.journal.section(), 1);
            let cut = recovered.core.machine().checkpoint_cut().unwrap();
            assert_eq!(cut.cursor(), Cursor::new(2));
            drop(recovered);
            assert!(journal_sections(&context, "interrupted").await.is_empty());
        });
    }

    #[test_traced]
    fn a_retained_artifact_that_fails_verification_aborts_recovery() {
        DeterministicRunner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(79, 6).build();
            append(
                &context,
                &committee,
                "valid",
                vec![certificate(&committee, 1, &committee)],
            )
            .await;
            let recovered = reopen(&context, &committee, "valid", NZU64!(4)).await;
            assert_eq!(recovered.unwrap().replayed, Some(1));

            // The same keys signing under another namespace yield a V-QC that decodes and replays
            // but does not verify.
            let forged = Committee::<MinPk>::builder(79, 6)
                .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_FORGED")
                .build();
            append(
                &context,
                &committee,
                "forged",
                vec![certificate(&committee, 1, &forged)],
            )
            .await;
            let recovered = reopen(&context, &committee, "forged", NZU64!(4)).await;
            assert!(matches!(recovered, Err(OpenError::InvalidArtifact)));
        });
    }

    #[test]
    fn journal_sizing_covers_every_machine_batch() {
        let committee = Committee::<MinPk>::builder(79, 6).build();
        let profile = observer(&committee);
        let page_cache = DeterministicRunner::default().start(|context| async move {
            CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(8))
        });
        let journal = JournalConfig::from_profile(&profile, "journal".into(), page_cache);
        let event_bytes =
            DomainEventCodecConfig::from_profile(&profile).max_encoded_size::<Sha256Digest>();

        assert_eq!(journal.max_events_per_record.get(), MAX_BATCH_EVENTS);
        assert!(journal.max_record_bytes.get() >= MAX_BATCH_BYTES.max(event_bytes) + 128);
    }
}
