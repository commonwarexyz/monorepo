//! Startup recovery for one Multimmit engine.
//!
//! [`recover`] rebuilds the machine from durable state before any actor starts, in a fixed order:
//!
//! 1. Open the checkpoint store and the safety journal.
//! 2. Restore the newest checkpoint and stream the journal suffix after it into the machine.
//! 3. Verify every artifact the recovered machine retains.
//! 4. Prune journal sections the checkpoint covers.
//! 5. Ask the application to verify every recovered payload (the custody fence).
//! 6. Compact a suffix of at least one checkpoint interval into a new checkpoint.
//!
//! Compaction makes the recovered state the new base, so it must follow the custody fence. One
//! entry point makes that order structural rather than a convention every caller repeats.
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
    Automaton, Epochable as _,
    multimmit::{
        config::{Error as ConfigError, Profile},
        machine::{
            CoreBootstrapError, CoreError, CoreState, Cursor, ReplayError, Snapshot,
            SnapshotCodecConfig,
        },
        scheme::bls12381_threshold::Scheme,
        types::{Artifact, Context},
    },
};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_parallel::Strategy;
use commonware_runtime::{Supervisor, buffer::paged::CacheRef, telemetry::traces::TracedExt as _};
use commonware_storage::Context as StorageContext;
use futures::{StreamExt as _, TryStreamExt as _, stream};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use std::{
    collections::HashSet,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};
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
    #[error("protocol core initialization failed: {0}")]
    CoreInitialization(#[source] CoreInitializationError),
    /// The recovered machine holds staged or unacknowledged state, so it has no checkpoint cut.
    #[error("recovered machine has no acknowledged checkpoint cut")]
    NoCheckpointCut,
    /// An artifact the recovered machine retains failed verification.
    #[error("recovered machine contains an invalid artifact")]
    InvalidArtifact,
    /// The application did not verify a payload the recovered machine depends on.
    #[error("application recovery verification did not succeed for a recovered payload")]
    RecoveredPayloadUnverified,
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
    /// Greatest number of recovered payloads the application verifies concurrently.
    pub inflight_application: NonZeroUsize,
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
    /// base, so [`recover`] runs it only after the custody fence.
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
pub(crate) async fn recover<E, H, P, V, T, A>(
    context: &mut E,
    config: RecoveryConfig<'_, H, P, V, T>,
    automaton: &A,
) -> Result<Recovered<E, H, V>, OpenError>
where
    E: CryptoRng + StorageContext + Supervisor,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
{
    let checkpoint_interval = config.checkpoint_interval;
    let inflight_application = config.inflight_application;
    let recovered = open_stores(context, config).await?;
    // A fresh machine depends on no recovered payload, so the fence passes trivially.
    verify_recovered_payloads(
        automaton,
        recovered.core.machine().recovered_payloads(),
        inflight_application,
    )
    .await?;
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
    E: CryptoRng + StorageContext + Supervisor,
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
    E: StorageContext + Supervisor,
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
    E: StorageContext + Supervisor,
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

/// Verifies every artifact the recovered machine retains on a `strategy` worker.
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
                let unverified = artifacts.iter().map(AsRef::as_ref).collect::<Vec<_>>();
                scheme.verify_artifacts::<_, H, H::Digest>(&mut rng, &unverified, &[], &worker)
            })
        })
        .instrument(span)
        .await;
    if verdicts.into_iter().any(|valid| !valid) {
        return Err(OpenError::InvalidArtifact);
    }
    Ok(())
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

/// Asks the application to verify every recovered payload, at most `max_inflight` at a time.
#[tracing::instrument(
    name = "multimmit.engine.verify_recovered_payloads",
    level = "info",
    skip_all,
    fields(payloads = requirements.len().traced())
)]
async fn verify_recovered_payloads<A, D>(
    automaton: &A,
    requirements: Vec<(Context<D>, D)>,
    max_inflight: NonZeroUsize,
) -> Result<(), OpenError>
where
    D: Digest,
    A: Automaton<Context = Context<D>, Digest = D>,
{
    stream::iter(requirements)
        .map(|(context, commitment)| {
            let mut automaton = automaton.clone();
            async move {
                let verdict = automaton.verify(context, commitment).await;
                if matches!(verdict.await, Ok(true)) {
                    Ok(())
                } else {
                    Err(OpenError::RecoveredPayloadUnverified)
                }
            }
        })
        .buffer_unordered(max_inflight.get())
        .try_collect::<()>()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            actors::verifier::verify,
            config::{Role, Tuning},
            machine::{
                Capability, CoreTurn, DomainEventCodecConfig, Input, MAX_BATCH_BYTES,
                MAX_BATCH_EVENTS, PersistDirective,
            },
            mocks::{Committee, MockApplication},
            types::ChainId,
        },
        types::{Epoch, Height, View},
    };
    use commonware_codec::EncodeSize as _;
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_macros::{select, test_traced};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock as _, Runner as _, Spawner as _,
        buffer::paged,
        deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
    };
    use commonware_utils::{NZU64, NZUsize};
    use std::{collections::BTreeSet, time::Duration};

    fn observer(committee: &Committee<MinPk>) -> Profile<Sha256Digest> {
        Profile::new::<MinPk>(committee.config.clone(), Role::Observer, Tuning::default()).unwrap()
    }

    /// Drives `core` until it is idle, acknowledging every barrier and verifying every job, after
    /// observing `artifacts` once it is live.
    fn drive(
        core: &mut CoreState<Sha256, MinPk>,
        committee: &Committee<MinPk>,
        artifacts: Vec<Artifact<MinPk, Sha256Digest>>,
    ) {
        let observed = artifacts
            .into_iter()
            .map(|artifact| artifact.identify::<Sha256>(&mut Vec::new()))
            .collect::<Vec<_>>();
        let resident_bytes = observed
            .iter()
            .map(|identified| identified.id.encode_size() + identified.artifact.encode_size())
            .sum();
        let mut observed = Some((observed, resident_bytes));
        loop {
            let capabilities = match core.next_action(|_| {}).unwrap() {
                CoreTurn::Input(serviced) => serviced.transition.into_parts().0,
                CoreTurn::Work(work) => work.capabilities,
                CoreTurn::YieldRequired => {
                    core.resume_after_yield().unwrap();
                    continue;
                }
                CoreTurn::Idle if observed.is_none() => break,
                CoreTurn::Idle => panic!("the core idled before observing the fixture"),
            };
            for capability in capabilities {
                match capability {
                    Capability::Journal(PersistDirective { job, .. }) => {
                        core.enqueue(Input::Persisted(job.ack())).unwrap();
                    }
                    Capability::Verify(job) => {
                        let completion = verify::<Sha256, _, _>(
                            &job,
                            &mut commonware_utils::test_rng(),
                            &committee.verifier,
                            &Sequential,
                        );
                        core.enqueue(Input::Verified(completion)).unwrap();
                    }
                    _ => {}
                }
            }
            if core.machine().inspect().is_live()
                && let Some((observed, resident_bytes)) = observed.take()
            {
                core.observe(observed, resident_bytes).unwrap();
            }
        }
    }

    #[test]
    fn recovery_verifies_a_forwarded_exit_certificate_once() {
        let committee = Committee::<MinPk>::builder(83, 6).build();
        let mut core = CoreState::fresh(observer(&committee)).unwrap();
        core.enqueue(Input::Start).unwrap();
        let nullification = Artifact::Nullification(committee.nullification(View::new(1)));
        let id = nullification.id::<Sha256>();
        drive(&mut core, &committee, vec![nullification]);

        let snapshot = core
            .machine()
            .checkpoint_cut()
            .expect("the driven core is quiescent");
        let held = snapshot
            .retained_artifacts()
            .filter(|artifact| artifact.id::<Sha256>() == id)
            .count();
        // The forwarded set, the view's exit, and the forwarding publication each hold it.
        assert!(
            held >= 2,
            "the certificate has several durable holders: {held}"
        );

        // The verified set holds the certificate once and every other retained artifact once.
        let verified = retained_once::<Sha256, MinPk>(&snapshot);
        let verified_ids = verified
            .iter()
            .map(|artifact| artifact.id::<Sha256>())
            .collect::<Vec<_>>();
        assert_eq!(verified_ids.iter().filter(|&&other| other == id).count(), 1);
        let retained_ids = snapshot
            .retained_artifacts()
            .map(|artifact| artifact.id::<Sha256>())
            .collect::<BTreeSet<_>>();
        assert_eq!(verified_ids.len(), retained_ids.len());
    }

    #[test_traced]
    fn empty_stores_start_fresh_without_custody_checks() {
        DeterministicRunner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(79, 6).build();
            let application = MockApplication::new();
            let mut store_context: DeterministicContext = context.child("stores");
            let recovered = Box::pin(recover::<_, Sha256, _, _, _, _>(
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
                    inflight_application: NZUsize!(2),
                },
                &application,
            ))
            .await
            .unwrap();

            assert_eq!(recovered.replayed, None);
            assert!(!recovered.core.machine().inspect().is_recovering());
            assert_eq!(recovered.journal.section(), 0);
            assert!(application.log().lock().verifications.is_empty());
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
        let event_bytes = DomainEventCodecConfig::from_profile(&profile).max_encoded_size();

        assert_eq!(journal.max_events_per_record.get(), MAX_BATCH_EVENTS);
        assert!(journal.max_record_bytes.get() >= MAX_BATCH_BYTES.max(event_bytes) + 128);
    }

    #[test_traced]
    fn recovered_payload_verification_is_bounded_and_unordered() {
        DeterministicRunner::timed(Duration::from_secs(1)).start(|context| async move {
            let application = MockApplication::new();
            verify_recovered_payloads(&application, Vec::new(), NZUsize!(2))
                .await
                .unwrap();
            let log = application.log();
            assert!(log.lock().verifications.is_empty());

            let mut gates = application.gate_verifications(3);
            let payload_context = Context::new(
                Epoch::new(1),
                ChainId::new(0),
                Height::new(1),
                Sha256::hash(&[b"parent"]),
            )
            .unwrap();
            let requirements = (0u8..3)
                .map(|index| (payload_context, Sha256::hash(&[&[index]])))
                .collect();
            let check = context
                .child("bounded_recovery_verification")
                .spawn(move |_| async move {
                    verify_recovered_payloads(&application, requirements, NZUsize!(2)).await
                });

            gates[0].wait_started().await;
            gates[1].wait_started().await;
            assert_eq!(log.lock().verifications.len(), 2);
            gates[1].release();
            gates[2].wait_started().await;
            assert_eq!(log.lock().verifications.len(), 3);
            gates[0].release();
            gates[2].release();
            check.await.unwrap().unwrap();
        });
    }

    #[test_traced]
    fn recovered_payload_verification_fails_closed() {
        DeterministicRunner::default().start(|context| async move {
            let payload_context = Context::new(
                Epoch::new(1),
                ChainId::new(0),
                Height::new(1),
                Sha256::hash(&[b"parent"]),
            )
            .unwrap();
            let commitment = Sha256::hash(&[b"payload"]);
            for result in [Some(false), None] {
                let application = MockApplication::builder().verify_result(result).build();
                let failure = verify_recovered_payloads(
                    &application,
                    vec![(payload_context, commitment)],
                    NZUsize!(8),
                )
                .await
                .expect_err("recovery cannot continue without application verification");
                assert!(matches!(failure, OpenError::RecoveredPayloadUnverified));
            }

            for result in [Some(false), None] {
                let application = MockApplication::builder().verify_result(result).build();
                let mut pending = application.gate_verification();
                let check = context
                    .child("recovery_verification")
                    .spawn(move |_| async move {
                        verify_recovered_payloads(
                            &application,
                            vec![
                                (payload_context, commitment),
                                (payload_context, Sha256::hash(&[b"other payload"])),
                            ],
                            NZUsize!(2),
                        )
                        .await
                    });
                pending.wait_started().await;
                let failure = select! {
                    result = check => result
                        .expect("recovery verification task runs")
                        .expect_err("one terminal sibling must fail payload verification"),
                    () = context.sleep(Duration::from_millis(100)) => {
                        panic!("a pending sibling hid a terminal payload-verification verdict");
                    },
                };
                assert!(matches!(failure, OpenError::RecoveredPayloadUnverified));
            }
        });
    }
}
