//! One attached Multimmit engine.
//!
//! [`Engine`] composes the batcher, voter, and resolver over one immutable [`Profile`] and one
//! storage partition prefix. Startup is gated: stores open and recover before any actor accepts
//! ingress, and readiness resolves only after the voter's first durability barrier is acknowledged
//! and its initial producer wake is submitted. Any mandatory actor exit stops the whole engine;
//! joining the engine's root task is the only evidence that its children stopped and its signing
//! material was dropped.
//!
//! The committee is fixed and the engine runs indefinitely. Memory stays bounded by the machine's
//! view-retention window rather than by any end state, so a node whose finality has stalled still
//! retires each view once it has advanced past it.
//!
//! Committee rotation is a deployment concern, as it is for Simplex. The epoch in [`Profile`] is
//! an immutable label bound into every signed subject; a deployment that wants a different
//! committee stops this engine and starts another under a new label and its own partition prefix.

use crate::{
    Automaton, Relay, Reporter,
    multimmit::{
        actors::{
            batcher::{self, IngressLimits},
            resolver,
            voter::{self, Startup, VoterLimits},
        },
        machine::{
            CoreBootstrapError, CoreState, DomainEventCodecConfig, Inspection, Profile,
            ReplayError, Role, SnapshotCodecConfig, ViewProof,
        },
        scheme::bls12381_threshold::Scheme,
        storage::{
            CheckpointError, CheckpointStore, JournalConfig, JournalError, Recovered, SafetyJournal,
        },
        types::{Activity, Context},
    },
    types::View,
};
use commonware_actor::mailbox;
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage, Supervisor,
    buffer::paged::CacheRef, spawn_cell, telemetry::traces::TracedExt as _,
};
use commonware_storage::Context as StorageContext;
use commonware_utils::{N5f1, NZU16, NZU64, NZUsize, channel::oneshot};
use futures::{StreamExt as _, stream::FuturesUnordered};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use std::{
    collections::HashSet,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};
use tracing::{Instrument as _, debug, info, info_span};

/// Storage sizing for one engine's durable stores.
///
/// The defaults are deliberately generous test-grade bounds; production deployments size them
/// from expected throughput.
#[derive(Copy, Clone, Debug)]
pub(crate) struct StorageTuning {
    /// Greatest number of events accepted in one persistence barrier.
    max_events_per_record: NonZeroUsize,
    /// Greatest encoded journal record size.
    max_record_bytes: NonZeroUsize,
}

impl Default for StorageTuning {
    fn default() -> Self {
        Self {
            max_events_per_record: NZUsize!(64),
            max_record_bytes: NZUsize!(4 * 1024 * 1024),
        }
    }
}

/// Durable events between machine checkpoints.
const CHECKPOINT_INTERVAL: NonZeroU64 = NZU64!(4096);

/// Fixed root suffix for the durable format.
const DURABILITY_STORAGE_NAMESPACE: &str = "multimmit-machine";

/// Bytes buffered before a store writes to a blob.
const WRITE_BUFFER: NonZeroUsize = NZUsize!(1024 * 1024);

/// Derives the storage sizing every durable store uses from the machine's own bounds.
///
/// The machine's artifact cache is itself derived from the view-retention window, so every store
/// is sized against the live state one retention window can hold, scaled by the largest artifact
/// the deployment admits.
fn storage_tuning<H: Hasher, V: Variant>(profile: &Profile<H, V>) -> StorageTuning {
    let max_events_per_record = NonZeroUsize::new(CoreState::<H, V>::MAX_BATCH_EVENTS)
        .expect("machine batches contain at least one event");
    let event_codec = DomainEventCodecConfig::from_profile(profile);
    // Ordinary batches are byte-capped, but one indivisible event may exceed that cap. Reserve
    // framing above the larger ceiling rather than multiplying the single-event maximum by the
    // event count: the machine never constructs such a record.
    let max_record_bytes = CoreState::<H, V>::MAX_BATCH_BYTES
        .max(event_codec.max_encoded_size())
        .saturating_add(128);
    StorageTuning {
        max_events_per_record,
        max_record_bytes: NonZeroUsize::new(max_record_bytes)
            .expect("record framing adds non-zero bytes"),
    }
}

/// Derives ingress bounds from the committee and byte ceilings.
fn ingress_limits<H: Hasher, V: Variant>(profile: &Profile<H, V>) -> IngressLimits {
    let resources = profile.resources();
    let fault_domains = N5f1::f_plus_one(profile.protocol().codec_config().participants()) as usize;
    let max_ingress_group_bytes = profile
        .protocol()
        .codec_config()
        .encoded_bounds::<V, H::Digest>()
        .expect("profile validated encoded protocol bounds")
        .max_ingress_group_bytes();
    IngressLimits {
        cohort_items: NonZeroUsize::new(resources.max_verification_batch()).expect("non-zero"),
        lane_items: NonZeroUsize::new(resources.max_cached_artifacts()).expect("non-zero"),
        lane_bytes: NonZeroUsize::new(
            max_ingress_group_bytes
                .saturating_mul(fault_domains)
                .max(16 * 1024 * 1024),
        )
        .expect("ingress byte floor is non-zero"),
        inflight_jobs: NonZeroUsize::new(resources.max_inflight_verifications()).expect("non-zero"),
        coalesce: Duration::from_millis(5),
    }
}

/// Derives voter bounds from the configured timers.
fn voter_limits<H: Hasher, V: Variant>(
    profile: &Profile<H, V>,
    checkpoint_interval: NonZeroU64,
) -> VoterLimits {
    let view_timeout = profile.timers().view_timeout();
    let codec = profile.protocol().codec_config();
    let inflight_application = 8usize.max(
        codec
            .chains()
            .min(N5f1::f_plus_one(codec.participants()) as usize),
    );
    VoterLimits {
        inflight_application: NonZeroUsize::new(inflight_application)
            .expect("application throughput floor is non-zero"),
        retry_initial: (view_timeout / 8).max(Duration::from_nanos(1)),
        retry_ceiling: view_timeout.saturating_mul(2),
        heartbeat: view_timeout.saturating_mul(5),
        // One Base per full journal section: compaction prunes whole blobs on their natural
        // boundary instead of churning a fresh blob every few dozen events, and replaying a
        // worst-case suffix of this size costs low tens of milliseconds.
        checkpoint_interval,
    }
}

/// Every durable store one engine needs, opened and recovered under one partition prefix.
pub(crate) struct Stores<E, H, V>
where
    E: Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    V: Variant,
{
    /// How the voter must start its machine.
    pub startup: Startup<E, H, V>,
    /// Durable machine checkpoints.
    pub checkpoints: CheckpointStore<E, V, H::Digest>,
}

/// Bounds a replayed suffix before recovery creates another durable process generation.
///
/// The recovered snapshot is synced before the journal is rolled, so a crash at any later point
/// can reopen either the old suffix or the new checkpoint. Application custody must be verified
/// before calling this function because compaction makes the recovered state the new base.
#[tracing::instrument(
    name = "multimmit.engine.compact_recovery_suffix",
    level = "info",
    skip_all
)]
pub(crate) async fn compact_recovery_suffix<E, H, V>(
    stores: Stores<E, H, V>,
    checkpoint_interval: NonZeroU64,
) -> Result<Stores<E, H, V>, OpenError>
where
    E: Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    V: Variant,
{
    let Stores {
        startup,
        checkpoints,
    } = stores;
    let Startup::Recovered(recovered) = startup else {
        return Ok(Stores {
            startup,
            checkpoints,
        });
    };
    if recovered.events_since_checkpoint < checkpoint_interval.get() {
        return Ok(Stores {
            startup: Startup::Recovered(recovered),
            checkpoints,
        });
    }

    let Recovered {
        core,
        journal,
        events_since_checkpoint: _,
    } = *recovered;
    let checkpoints = checkpoints
        .store(core.snapshot())
        .instrument(info_span!(
            "multimmit.engine.compact_recovery_suffix.checkpoint"
        ))
        .await?;
    let journal = journal
        .roll()
        .prune()
        .instrument(info_span!(
            "multimmit.engine.compact_recovery_suffix.journal"
        ))
        .await?;
    Ok(Stores {
        startup: Startup::Recovered(Box::new(Recovered {
            core,
            journal,
            events_since_checkpoint: 0,
        })),
        checkpoints,
    })
}

/// Fatal storage recovery error during engine startup.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("safety journal failed: {0}")]
    Journal(#[from] JournalError),
    #[error("checkpoint store failed: {0}")]
    Checkpoint(#[from] CheckpointError),
    #[error("machine recovery failed: {0}")]
    Recovery(#[from] ReplayError),
    #[error("protocol core initialization failed")]
    CoreInitialization,
    #[error("recovered machine contains an invalid artifact")]
    InvalidArtifact,
    #[error("application recovery verification did not succeed for a recovered payload")]
    RecoveredPayloadUnverified,
    #[error("runtime storage inspection failed: {0}")]
    Storage(#[from] commonware_runtime::Error),
}

impl From<CoreBootstrapError> for OpenError {
    fn from(error: CoreBootstrapError) -> Self {
        match error {
            CoreBootstrapError::Core(_) => Self::CoreInitialization,
            CoreBootstrapError::Recovery(error) => Self::Recovery(error),
        }
    }
}

/// Verifies recovered application payloads before their dependent consensus authority becomes live.
#[tracing::instrument(
    name = "multimmit.engine.verify_recovered_payloads",
    level = "info",
    skip_all,
    fields(payloads = requirements.len().traced())
)]
pub(crate) async fn verify_recovered_payloads<A, D>(
    automaton: &A,
    requirements: Vec<(Context<D>, D)>,
    max_inflight: NonZeroUsize,
) -> Result<(), OpenError>
where
    D: Digest,
    A: Automaton<Context = Context<D>, Digest = D>,
{
    let mut requirements = requirements.into_iter();
    let mut verifications = FuturesUnordered::new();
    let verify = |context, commitment| {
        let mut automaton = automaton.clone();
        async move {
            let verdict = automaton.verify(context, commitment).await;
            verdict.await
        }
    };
    loop {
        while verifications.len() < max_inflight.get() {
            let Some((context, commitment)) = requirements.next() else {
                break;
            };
            verifications.push(verify(context, commitment));
        }
        let Some(verdict) = verifications.next().await else {
            return Ok(());
        };
        if !matches!(verdict, Ok(true)) {
            return Err(OpenError::RecoveredPayloadUnverified);
        }
    }
}

/// Opens (or reopens) every durable store for one engine and prepares the startup path.
///
/// A node with no durable checkpoint and an empty journal starts fresh; otherwise it recovers
/// from its newest complete checkpoint and contiguous journal suffix. A validator deployment may
/// use the fresh path only with a never-active epoch key and a new partition prefix. The engine has
/// no trusted-checkpoint import or external key-use registry, so it cannot distinguish a first
/// start from storage loss under an active key.
#[tracing::instrument(
    name = "multimmit.engine.open_stores",
    level = "info",
    skip_all,
    fields(epoch = profile.protocol().epoch().get().traced())
)]
pub(crate) async fn open_stores<E, H, P, V>(
    context: &mut E,
    profile: Profile<H, V>,
    prefix: &str,
    scheme: &Scheme<P, V>,
    strategy: &impl Strategy,
    application_tasks: NonZeroUsize,
) -> Result<Stores<E, H, V>, OpenError>
where
    E: CryptoRng + Storage + Metrics + BufferPooler + StorageContext + Supervisor,
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    let storage_prefix = format!("{prefix}-{DURABILITY_STORAGE_NAMESPACE}");
    let prefix = storage_prefix.as_str();
    let tuning = storage_tuning(&profile);
    let protocol = profile.protocol().clone();
    let epoch = protocol.epoch();
    let checkpoint_codec = SnapshotCodecConfig::from_profile(&profile);
    let (checkpoints, checkpoint) = CheckpointStore::<_, V, H::Digest>::open_bounded(
        context.child("checkpoints"),
        format!("{prefix}-checkpoints"),
        checkpoint_codec,
        checkpoint_codec.max_checkpoint_blob_size(),
        epoch,
    )
    .instrument(info_span!("multimmit.engine.open_stores.checkpoint"))
    .await?;
    let has_checkpoint = checkpoint.is_some();
    let covered = checkpoint
        .as_ref()
        .map_or(crate::multimmit::machine::Cursor::zero(), |snapshot| {
            snapshot.cursor()
        });
    let journal_config = JournalConfig {
        partition: format!("{prefix}-journal"),
        epoch,
        event_codec: DomainEventCodecConfig::from_profile(&profile),
        max_events_per_record: tuning.max_events_per_record,
        max_record_bytes: tuning.max_record_bytes,
        page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
        write_buffer: WRITE_BUFFER,
    };
    let mut journal = SafetyJournal::open(context.child("journal"), journal_config, covered)
        .instrument(info_span!("multimmit.engine.open_stores.journal"))
        .await?;

    // Buffer the journal suffix so an empty, never-started node can be told apart from a
    // recovering one.
    async {
        while journal.next().await?.is_some() {}
        Ok::<_, JournalError>(())
    }
    .instrument(info_span!("multimmit.engine.open_stores.read_suffix"))
    .await?;
    let records = journal.suffix().to_vec();
    let events_since_checkpoint: u64 = records
        .iter()
        .map(|record| record.events().len() as u64)
        .sum();
    let suffix_section = journal.suffix_section();
    let saw_record = journal.saw_record();
    let journal = journal.finish()?;
    let startup = if !saw_record && checkpoint.is_none() {
        Startup::Fresh {
            core: Box::new(CoreState::fresh(profile, application_tasks)?),
            journal: Box::new(journal),
        }
    } else {
        let snapshot = match checkpoint {
            Some(snapshot) => snapshot,
            None => CoreState::fresh(profile.clone(), application_tasks)?.snapshot(),
        };
        let mut core = CoreState::restore(profile, snapshot, application_tasks)?;
        info_span!(
            "multimmit.engine.open_stores.replay",
            records = records.len().traced(),
            events = events_since_checkpoint.traced(),
        )
        .in_scope(|| {
            for record in records {
                for event in record.events() {
                    core.replay(event.clone())?;
                }
            }
            Ok::<_, ReplayError>(())
        })?;

        let snapshot = core.snapshot();
        let mut artifact_ids = HashSet::new();
        let artifacts = snapshot
            .retained_artifacts()
            .filter(|artifact| artifact_ids.insert(artifact.id::<H>()))
            .collect::<Vec<_>>();
        let scheme = scheme.clone();
        let worker = strategy.clone();
        let mut rng = StdRng::from_rng(&mut *context);
        let artifact_span = info_span!(
            "multimmit.engine.open_stores.verify_artifacts",
            artifacts = artifacts.len().traced(),
        );
        let worker_span = artifact_span.clone();
        if worker
            .spawn(move |worker| {
                worker_span.in_scope(|| {
                    let unverified = artifacts
                        .iter()
                        .map(|artifact| artifact.unverified())
                        .collect::<Vec<_>>();
                    scheme.verify_artifacts::<_, H, H::Digest>(&mut rng, &unverified, &worker)
                })
            })
            .instrument(artifact_span)
            .await
            .into_iter()
            .any(|valid| !valid)
        {
            return Err(OpenError::InvalidArtifact);
        }

        // The restored core accepted the checkpoint and suffix, so every older whole section is
        // obsolete. Complete any prune interrupted before the crash before admitting authority.
        let journal = if has_checkpoint {
            async {
                match suffix_section {
                    Some(section) => journal.prune_before(section).await,
                    None => journal.roll().prune().await,
                }
            }
            .instrument(info_span!("multimmit.engine.open_stores.prune"))
            .await?
        } else {
            journal
        };

        Startup::Recovered(Box::new(Recovered {
            core,
            journal,
            events_since_checkpoint,
        }))
    };

    Ok(Stores {
        startup,
        checkpoints,
    })
}

/// Configuration for one Multimmit engine.
pub struct Config<H, P, V, A, R, F, T, B>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    B: Blocker<PublicKey = P>,
{
    /// The immutable local machine profile.
    pub profile: Profile<H, V>,
    /// Role-appropriate cryptographic material for the epoch.
    pub scheme: Scheme<P, V>,
    /// Application commitment construction and validation.
    pub automaton: A,
    /// Application dissemination notification by commitment.
    pub relay: R,
    /// Authenticated activity reporting.
    pub reporter: F,
    /// Execution strategy for CPU-heavy cryptography.
    pub strategy: T,
    /// Peer blocker for invalid traffic.
    pub blocker: B,
    /// Storage partition prefix owned exclusively by this engine.
    pub partition_prefix: String,
    /// Mailbox capacity for every actor.
    pub mailbox_size: NonZeroUsize,
}

/// A running engine's external handle.
pub struct Running<V: Variant, D: Digest> {
    readiness: Readiness,
    voter: mailbox::UnreliableSender<voter::Query<D>>,
    resolver: mailbox::UnreliableSender<resolver::Query<V, D>>,
    task: Handle<()>,
}

enum Readiness {
    Pending(oneshot::Receiver<()>),
    Ready,
    Failed,
}

impl Readiness {
    async fn wait(&mut self) -> bool {
        match self {
            Self::Pending(receiver) => {
                let ready = receiver.await.is_ok();
                *self = if ready { Self::Ready } else { Self::Failed };
                ready
            }
            Self::Ready => true,
            Self::Failed => false,
        }
    }
}

/// A cloneable handle for reading a running engine's diagnostic state.
#[derive(Clone)]
pub struct Inspector<D: Digest> {
    voter: mailbox::UnreliableSender<voter::Query<D>>,
}

impl<D: Digest> Inspector<D> {
    /// Reads the machine's normalized diagnostic projection.
    pub async fn inspect(&self) -> Option<Inspection<D>> {
        let (responder, receiver) = oneshot::channel();
        if !self
            .voter
            .enqueue(voter::Query::Inspect { responder })
            .accepted()
        {
            return None;
        }
        receiver.await.ok()
    }
}

impl<V: Variant, D: Digest> Running<V, D> {
    /// Resolves once startup or recovery is durable and the initial producer wake is submitted.
    ///
    /// Returns `false` if the engine failed before becoming ready.
    pub async fn ready(&mut self) -> bool {
        self.readiness.wait().await
    }

    /// Reads the machine's normalized diagnostic projection.
    pub async fn inspect(&self) -> Option<Inspection<D>> {
        self.inspector().inspect().await
    }

    /// Returns a cloneable handle for polling diagnostics independently of lifecycle ownership.
    pub fn inspector(&self) -> Inspector<D> {
        Inspector {
            voter: self.voter.clone(),
        }
    }

    /// Reads one object the engine can serve to a peer.
    ///
    /// Returns `None` when the engine is stopped or does not retain useful evidence.
    pub async fn serve(&self, view: View) -> Option<ViewProof<V, D>> {
        let (responder, receiver) = oneshot::channel();
        if !self
            .resolver
            .enqueue(resolver::Query::Serve { view, responder })
            .accepted()
        {
            return None;
        }
        receiver
            .await
            .ok()
            .flatten()
            .map(|proof| proof.as_ref().clone())
    }

    /// Consumes the handle and waits for every engine child to stop.
    pub async fn join(self) {
        let _ = self.task.await;
    }

    /// Requests engine shutdown; `join` remains the only evidence of completion.
    pub fn abort(&self) {
        self.task.abort();
    }
}

/// One attached Multimmit engine.
pub struct Engine<E, H, P, V, A, R, F, T, B>
where
    E: Clock + CryptoRng + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    B: Blocker<PublicKey = P>,
{
    context: ContextCell<E>,
    config: Config<H, P, V, A, R, F, T, B>,
    checkpoint_interval: NonZeroU64,
}

impl<E, H, P, V, A, R, F, T, B> Engine<E, H, P, V, A, R, F, T, B>
where
    E: Clock + CryptoRng + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    B: Blocker<PublicKey = P> + Clone + Send + 'static,
{
    /// Validates configuration consistency without starting work.
    ///
    /// # Panics
    ///
    /// Panics when the scheme, profile, and role disagree; a mismatch would otherwise surface as
    /// runtime signing failures.
    pub fn new(context: E, config: Config<H, P, V, A, R, F, T, B>) -> Self {
        use crate::Epochable as _;
        let protocol = config.profile.protocol();
        assert_eq!(
            config.scheme.epoch(),
            protocol.epoch(),
            "scheme and profile must agree on the epoch"
        );
        assert!(
            config.scheme.matches_namespace(protocol.namespace()),
            "scheme and profile must agree on the namespace"
        );
        assert_eq!(
            config.scheme.codec_config(),
            protocol.codec_config(),
            "scheme and profile must agree on protocol limits"
        );
        assert!(
            config.scheme.matches_producers(protocol.producers()),
            "scheme and profile must agree on producer ownership"
        );
        match config.profile.role() {
            Role::Validator(participant) => {
                assert_eq!(
                    config.scheme.me(),
                    Some(participant),
                    "a validator's scheme must hold its own key material"
                );
            }
            Role::Observer => {
                assert!(
                    config.scheme.me().is_none(),
                    "an observer's scheme must not hold signing material"
                );
            }
        }
        Self {
            context: ContextCell::new(context),
            config,
            checkpoint_interval: CHECKPOINT_INTERVAL,
        }
    }

    /// Overrides checkpoint cadence for bounded recovery tests.
    #[cfg(test)]
    pub(crate) const fn with_checkpoint_interval(
        mut self,
        checkpoint_interval: NonZeroU64,
    ) -> Self {
        self.checkpoint_interval = checkpoint_interval;
        self
    }

    /// Starts the engine over its four registered planes.
    ///
    /// Stores open and recover before any actor starts; the returned handle's `ready` resolves
    /// after startup or recovery is durable and the initial producer wake is submitted.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "multimmit.engine.start",
        level = "info",
        skip_all,
        err,
        fields(epoch = self.config.profile.protocol().epoch().get().traced())
    )]
    pub async fn start(
        mut self,
        data: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        consensus: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        certificates: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        resolver: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Result<Running<V, H::Digest>, OpenError> {
        let (ready_sender, ready_receiver) = oneshot::channel();
        let config = self.config;
        let checkpoint_interval = self.checkpoint_interval;
        let voter_limits = voter_limits(&config.profile, checkpoint_interval);

        // Gated startup: open and recover stores before any actor accepts ingress.
        let stores = open_stores(
            self.context.as_present_mut(),
            config.profile.clone(),
            &config.partition_prefix,
            &config.scheme,
            &config.strategy,
            voter_limits.inflight_application,
        )
        .await?;
        if let Startup::Recovered(recovered) = &stores.startup {
            verify_recovered_payloads(
                &config.automaton,
                recovered.core.recovered_payloads(),
                voter_limits.inflight_application,
            )
            .await?;
        }
        let stores = compact_recovery_suffix(stores, checkpoint_interval).await?;
        let context = self.context.as_ref();

        // Construct actors and control channels before any ingress can flow.
        let protocol = config.profile.protocol();
        let epoch = protocol.epoch();
        let codec = protocol.codec_config();
        let me = config
            .scheme
            .me()
            .and_then(|participant| config.scheme.participants().get(participant.into()))
            .cloned();
        let (batcher, batcher_mailbox) = batcher::Actor::<E, H, P, V, B, T>::new(
            context.child("batcher"),
            batcher::Config {
                scheme: config.scheme.clone(),
                blocker: config.blocker.clone(),
                strategy: config.strategy.clone(),
                codec,
                limits: ingress_limits(&config.profile),
                mailbox_size: config.mailbox_size,
                observation_capacity: config.mailbox_size,
            },
        );
        let (observation_sender, observation_receiver) =
            mailbox::new_unreliable(context.child("observations"), config.mailbox_size);
        let (completion_sender, completion_receiver) =
            mailbox::new(context.child("completions"), config.mailbox_size);
        let (resolver_actor, resolver_mailbox) = resolver::Actor::<E, H, P, V, B, T>::new(
            context.child("resolver"),
            resolver::Config {
                peers: config.scheme.participants().as_ref().to_vec(),
                me,
                blocker: config.blocker,
                epoch,
                codec,
                strategy: config.strategy.clone(),
                fetch_timeout: config.profile.timers().view_timeout(),
                mailbox_size: config.mailbox_size,
            },
        );
        let resolver::Mailbox {
            control: resolver_control,
            queries: resolver_queries,
        } = resolver_mailbox;
        let (voter, voter_mailbox) = voter::Actor::new(
            context.child("voter"),
            voter::Config {
                scheme: config.scheme,
                strategy: config.strategy,
                automaton: config.automaton,
                relay: config.relay,
                reporter: config.reporter,
                startup: stores.startup,
                checkpoints: stores.checkpoints,
                limits: voter_limits,
                mailbox_size: config.mailbox_size,
            },
        );
        let voter::Mailbox {
            control: voter_control,
            queries: voter_queries,
        } = voter_mailbox;

        let task = spawn_cell!(self.context, async move {
            let root = self.context;
            let mut batcher_task = batcher.start(
                observation_sender,
                completion_sender,
                data.1,
                consensus.1,
                certificates.1,
            );
            let mut resolver_task = resolver_actor.start(voter_control, resolver);
            let mut voter_task = voter.start(
                ready_sender,
                batcher_mailbox,
                observation_receiver,
                completion_receiver,
                resolver_control,
                data.0,
                consensus.0,
                certificates.0,
            );

            info!("engine started");
            let mut shutdown = root.stopped();
            select! {
                _ = &mut shutdown => {
                    debug!("context shutdown, stopping engine");
                },
                voter = &mut voter_task => {
                    debug!(?voter, "voter stopped, shutting down engine");
                },
                batcher = &mut batcher_task => {
                    debug!(?batcher, "batcher stopped, shutting down engine");
                },
                resolver = &mut resolver_task => {
                    debug!(?resolver, "resolver stopped, shutting down engine");
                },
            }
        });

        Ok(Running {
            readiness: Readiness::Pending(ready_receiver),
            voter: voter_queries,
            resolver: resolver_queries,
            task,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CHECKPOINT_INTERVAL, Config, Engine, OpenError, Readiness, Running, Startup,
        ingress_limits, open_stores, storage_tuning, verify_recovered_payloads, voter_limits,
    };
    use crate::{
        multimmit::{
            actors::wire::{CertificateMessage, DataMessage, Envelope, EnvelopeConfig},
            config::Limits,
            machine::{
                CoreState, DomainEventCodecConfig, Inspection, Profile, PublicationDischarge, Role,
                Tuning, ViewProof,
            },
            mocks::{
                Committee, MockApplication, NoopBlocker, NoopReporter,
                cluster::{QUOTA, link_all, start_network},
            },
            types::{ChainId, Context, Height, SignedTransactionBlock},
        },
        types::{Epoch, Participant, View},
    };
    use commonware_codec::{Decode as _, Encode as _};
    use commonware_cryptography::{
        Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::{select, test_traced};
    use commonware_p2p::{Receiver as _, Recipients, Sender as _, simulated::Oracle};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock as _, Runner as _, Spawner as _, Storage as _, Supervisor as _,
        deterministic::{self, Runner as DeterministicRunner},
    };
    use commonware_utils::{NZUsize, channel::oneshot};
    use std::{
        collections::BTreeSet,
        num::{NonZeroU64, NonZeroUsize},
        time::Duration,
    };

    fn profile(committee: &Committee<MinPk>, role: Role) -> Profile<Sha256, MinPk> {
        Profile::new(
            committee.config.clone(),
            role,
            Tuning {
                view_timeout: Duration::from_millis(500),
                production_interval: Duration::from_millis(100),
                ..Tuning::default()
            },
        )
        .unwrap()
    }

    fn config(
        committee: &Committee<MinPk>,
        index: usize,
        prefix: &str,
    ) -> Config<
        Sha256,
        ed25519::PublicKey,
        MinPk,
        MockApplication,
        MockApplication,
        NoopReporter<MinPk, Sha256Digest>,
        Sequential,
        NoopBlocker,
    > {
        let role = Role::Validator(Participant::new(index as u32));
        let profile = profile(committee, role);
        let application = MockApplication::new();
        Config {
            scheme: committee.signers[index].clone(),
            automaton: application.clone(),
            relay: application,
            reporter: NoopReporter::default(),
            strategy: Sequential,
            blocker: NoopBlocker,
            profile,
            partition_prefix: format!("{prefix}-{index}"),
            mailbox_size: NonZeroUsize::new(128).unwrap(),
        }
    }

    fn assert_same_durable_prefix(
        live: &Inspection<Sha256Digest>,
        recovered: &Inspection<Sha256Digest>,
    ) {
        assert!(live.is_live());
        assert!(!live.is_recovering());
        assert!(!recovered.is_live());
        assert!(recovered.is_recovering());
        // Admission queues and jobs are generation-local service metadata. The fields below are
        // the semantic projection owned by the checkpoint and contiguous journal suffix.
        assert_eq!(recovered.epoch(), live.epoch());
        assert_eq!(recovered.view(), live.view());
        assert_eq!(recovered.generation(), live.generation());
        assert_eq!(recovered.cursor(), live.cursor());
        assert_eq!(recovered.local_artifacts(), live.local_artifacts());
        assert_eq!(recovered.outbox(), live.outbox());
        assert_eq!(recovered.produced_blocks(), live.produced_blocks());
        assert_eq!(recovered.chain_progress(), live.chain_progress());
        assert_eq!(recovered.pools(), live.pools());
        assert_eq!(recovered.finality(), live.finality());
        assert_eq!(
            recovered.retained_artifact_references(),
            live.retained_artifact_references()
        );
        assert_eq!(
            recovered.nullification_suffix(),
            live.nullification_suffix()
        );
        assert_eq!(recovered.retired_view(), live.retired_view());
        assert_eq!(recovered.finality_floor(), live.finality_floor());

        let live_producer = live.producer().expect("validator has producer state");
        let recovered_producer = recovered.producer().expect("producer state recovers");
        assert_eq!(recovered_producer.chain(), live_producer.chain());
        assert_eq!(recovered_producer.produced(), live_producer.produced());
        assert_eq!(recovered_producer.certified(), live_producer.certified());
        assert_eq!(recovered_producer.da_quorum(), live_producer.da_quorum());
        assert_eq!(
            recovered_producer.pipeline_depth(),
            live_producer.pipeline_depth()
        );
    }

    #[test]
    fn voter_limits_are_nonzero_and_overflow_safe() {
        let committee = Committee::<MinPk>::new(77, 6, Limits::new(2, 1).unwrap());
        for view_timeout in [Duration::from_nanos(1), Duration::MAX] {
            let profile: Profile<Sha256, MinPk> = Profile::new(
                committee.config.clone(),
                Role::Observer,
                Tuning {
                    view_timeout,
                    production_interval: Duration::from_millis(1),
                    ..Tuning::default()
                },
            )
            .unwrap();
            let limits = voter_limits(&profile, CHECKPOINT_INTERVAL);
            assert_eq!(limits.inflight_application.get(), 8);
            assert!(!limits.retry_initial.is_zero());
            assert!(limits.retry_initial <= limits.retry_ceiling);
            assert!(limits.retry_ceiling <= limits.heartbeat);
        }
    }

    #[test]
    fn voter_limits_leave_capacity_for_a_correct_producer_chain() {
        let producers = (0..9).map(Participant::new).collect();
        let committee = Committee::<MinPk>::new_with_namespace_and_producers(
            80,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_APPLICATION_CAPACITY_TEST",
            41,
            producers,
            Limits::new(2, 1).unwrap(),
        );
        let first_profile = profile(&committee, Role::Observer);

        assert_eq!(
            voter_limits(&first_profile, CHECKPOINT_INTERVAL)
                .inflight_application
                .get(),
            9,
        );

        let producers = (0..10).map(Participant::new).collect();
        let committee = Committee::<MinPk>::new_with_namespace_and_producers(
            83,
            b"_COMMONWARE_CONSENSUS_MULTIMMIT_CHAIN_CAPACITY_TEST",
            51,
            producers,
            Limits::new(2, 1).unwrap(),
        );
        let second_profile = profile(&committee, Role::Observer);
        assert_eq!(
            voter_limits(&second_profile, CHECKPOINT_INTERVAL)
                .inflight_application
                .get(),
            10,
        );
    }

    #[test]
    fn ingress_limits_reserve_one_codec_group_per_fault_domain() {
        let committee = Committee::<MinPk>::new(81, 6, Limits::new(25_000, 0).unwrap());
        let bounds = committee
            .codec()
            .encoded_bounds::<MinPk, Sha256Digest>()
            .unwrap();
        let required = bounds.max_ingress_group_bytes();
        assert!(required > 4 * 1024 * 1024);
        assert!(required < 16 * 1024 * 1024);
        let profile: Profile<Sha256, MinPk> = Profile::new(
            committee.config,
            Role::Observer,
            Tuning {
                max_artifact_bytes: NonZeroUsize::new(bounds.max_artifact_bytes()).unwrap(),
                ..Tuning::default()
            },
        )
        .unwrap();
        let limits = ingress_limits(&profile);

        assert_eq!(
            limits.lane_bytes.get(),
            required.saturating_mul(2).max(16 * 1024 * 1024),
        );
    }

    #[test]
    fn ingress_limits_scale_large_codec_groups_by_fault_domains() {
        let committee = Committee::<MinPk>::new(82, 6, Limits::new(60_000, 0).unwrap());
        let bounds = committee
            .codec()
            .encoded_bounds::<MinPk, Sha256Digest>()
            .unwrap();
        let profile: Profile<Sha256, MinPk> = Profile::new(
            committee.config,
            Role::Observer,
            Tuning {
                max_artifact_bytes: NonZeroUsize::new(bounds.max_artifact_bytes()).unwrap(),
                ..Tuning::default()
            },
        )
        .unwrap();
        let required = bounds.max_ingress_group_bytes();
        let limits = ingress_limits(&profile);

        assert!(required > 16 * 1024 * 1024);
        assert_eq!(limits.lane_bytes.get(), required.saturating_mul(2));
    }

    #[test]
    fn journal_sizing_covers_every_machine_batch() {
        let committee = Committee::<MinPk>::new(79, 6, Limits::new(2, 1).unwrap());
        let profile = profile(&committee, Role::Observer);
        let tuning = storage_tuning(&profile);
        let event_bytes = DomainEventCodecConfig::from_profile(&profile).max_encoded_size();

        assert_eq!(
            tuning.max_events_per_record.get(),
            CoreState::<Sha256, MinPk>::MAX_BATCH_EVENTS
        );
        assert!(
            tuning.max_record_bytes.get()
                >= CoreState::<Sha256, MinPk>::MAX_BATCH_BYTES.max(event_bytes) + 128
        );
    }

    #[test_traced]
    fn readiness_wait_survives_cancellation_and_remembers_failure() {
        DeterministicRunner::default().start(|context| async move {
            let (sender, receiver) = oneshot::channel();
            let mut readiness = Readiness::Pending(receiver);
            select! {
                result = readiness.wait() => panic!("pending readiness resolved: {result}"),
                () = context.sleep(Duration::from_millis(1)) => {},
            }

            drop(sender);
            assert!(!readiness.wait().await);
            assert!(!readiness.wait().await);

            let (sender, receiver) = oneshot::channel();
            let mut readiness = Readiness::Pending(receiver);
            sender.send(()).unwrap();
            assert!(readiness.wait().await);
            assert!(readiness.wait().await);
        });
    }

    #[test_traced]
    fn maximum_timer_durations_do_not_overflow_actor_deadlines() {
        DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
            let committee = Committee::<MinPk>::new(78, 6, Limits::new(2, 1).unwrap());
            let oracle =
                start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
            let me = committee.identities[0].clone();
            let mut planes = Vec::new();
            for channel in 0..4u64 {
                planes.push(
                    oracle
                        .control(me.clone())
                        .register(channel, QUOTA)
                        .await
                        .unwrap(),
                );
            }
            let mut config = config(&committee, 0, "maximum-timer-durations");
            config.profile = Profile::new(
                committee.config.clone(),
                Role::Validator(Participant::new(0)),
                Tuning {
                    view_timeout: Duration::MAX,
                    production_interval: Duration::MAX,
                    ..Tuning::default()
                },
            )
            .unwrap();
            let mut planes = planes.into_iter();

            Box::pin(Engine::new(context.child("engine"), config).start(
                planes.next().unwrap(),
                planes.next().unwrap(),
                planes.next().unwrap(),
                planes.next().unwrap(),
            ))
            .await
            .expect("the voter starts with representable saturated deadlines");
        });
    }

    fn proof_covers_view(proof: &ViewProof<MinPk, Sha256Digest>, requested: View) -> bool {
        match proof {
            ViewProof::Nullification(_) | ViewProof::Vqc(_) => proof.view() == requested,
            ViewProof::Lqc(_) => proof.view() >= requested,
        }
    }

    #[test]
    #[should_panic(expected = "scheme and profile must agree on producer ownership")]
    fn engine_rejects_a_mismatched_producer_map() {
        let runner = DeterministicRunner::timed(Duration::from_secs(1));
        runner.start(|context| async move {
            let limits = Limits::new(2, 1).unwrap();
            let namespace = b"_COMMONWARE_CONSENSUS_MULTIMMIT_ENGINE_PRODUCER_MAP_TEST";
            let scheme_committee = Committee::<MinPk>::new_with_namespace_and_producers(
                76,
                namespace,
                6,
                vec![Participant::new(1), Participant::new(4)],
                limits,
            );
            let profile_committee = Committee::<MinPk>::new_with_namespace_and_producers(
                76,
                namespace,
                6,
                vec![Participant::new(4), Participant::new(1)],
                limits,
            );
            let mut config = config(&scheme_committee, 0, "producer-map-mismatch");
            config.profile = profile(&profile_committee, Role::Validator(Participant::new(0)));
            let _ = Engine::new(context.child("engine"), config);
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
                let application = MockApplication::with_verification_result(result);
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
                let (application, mut pending) =
                    MockApplication::with_gated_verification_result(result);
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

    /// Starts one engine over four freshly registered planes with a fixed checkpoint cadence.
    async fn launch(
        context: &deterministic::Context,
        oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
        committee: Committee<MinPk>,
        index: usize,
        label: &'static str,
        prefix: &str,
        checkpoint_interval: NonZeroU64,
    ) -> Running<MinPk, Sha256Digest> {
        launch_with_application(
            context,
            oracle,
            committee,
            index,
            label,
            prefix,
            checkpoint_interval,
            MockApplication::new(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn launch_with_application(
        context: &deterministic::Context,
        oracle: &Oracle<ed25519::PublicKey, deterministic::Context>,
        committee: Committee<MinPk>,
        index: usize,
        label: &'static str,
        prefix: &str,
        checkpoint_interval: NonZeroU64,
        application: MockApplication,
    ) -> Running<MinPk, Sha256Digest> {
        let me = committee.identities[index].clone();
        let mut planes = Vec::new();
        for channel in 0..4u64 {
            planes.push(
                oracle
                    .control(me.clone())
                    .register(channel, QUOTA)
                    .await
                    .unwrap(),
            );
        }
        let mut planes = planes.into_iter();
        let mut config = config(&committee, index, prefix);
        config.automaton = application.clone();
        config.relay = application;
        let engine =
            Engine::new(context.child(label), config).with_checkpoint_interval(checkpoint_interval);
        Box::pin(engine.start(
            planes.next().unwrap(),
            planes.next().unwrap(),
            planes.next().unwrap(),
            planes.next().unwrap(),
        ))
        .await
        .expect("engine starts")
    }

    #[test_traced]
    fn recovery_verification_precedes_actor_construction_and_dependent_effects() {
        let seed = 72;
        let runner = DeterministicRunner::timed(Duration::from_secs(120));
        let (before, checkpoint) = runner.start_and_recover(|context| async move {
            let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
            let oracle =
                start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
            link_all(&oracle, &committee.identities).await;
            let application = MockApplication::new();
            application.permit_builds(1);
            let mut engine = Box::pin(launch_with_application(
                &context,
                &oracle,
                committee,
                0,
                "first",
                "restart",
                CHECKPOINT_INTERVAL,
                application,
            ))
            .await;
            assert!(engine.ready().await);
            // Wait until the validator produced a block and consumed its persistence barrier,
            // then crash uncleanly. Production is applied before acknowledgement so private work
            // can overlap storage, and is not by itself evidence that recovery can replay it.
            for _ in 0..600 {
                context.sleep(Duration::from_millis(50)).await;
                let inspection = engine.inspect().await.expect("engine runs");
                if inspection.produced_blocks() >= 1
                    && inspection.pending_barrier().is_none()
                    && inspection.verification_jobs().is_empty()
                {
                    return inspection;
                }
            }
            panic!("no block was produced before the crash");
        });

        let runner = DeterministicRunner::from(checkpoint);
        runner.start(|context| async move {
            let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
            let oracle =
                start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
            link_all(&oracle, &committee.identities).await;
            let mut rebuild = context.child("rebuild");
            let rebuilt = Box::pin(open_stores(
                &mut rebuild,
                profile(&committee, Role::Validator(Participant::new(0))),
                "restart-0",
                &committee.verifier,
                &Sequential,
                NZUsize!(8),
            ))
            .await
            .expect("stores reopen");
            let Startup::Recovered(recovered) = &rebuilt.startup else {
                panic!("durable state must select recovery startup");
            };
            let inspection = recovered.core.inspection();
            assert_same_durable_prefix(&before, &inspection);
            assert!(inspection.is_recovering());
            assert!(!inspection.is_live());
            assert!(
                inspection.produced_blocks() >= 1,
                "recovery restored durable production state"
            );
            assert!(
                !inspection.outbox().is_empty(),
                "recovery restored the outbox"
            );
            let requirements = recovered.core.recovered_payloads();
            assert!(!requirements.is_empty());
            drop(rebuilt);

            let (application, mut verification) = MockApplication::with_gated_verify();
            application.pause_building();
            let application_log = application.log();
            let mut starting = Box::pin(launch_with_application(
                &context,
                &oracle,
                committee,
                0,
                "second",
                "restart",
                CHECKPOINT_INTERVAL,
                application,
            ));
            select! {
                () = verification.wait_started() => {},
                _ = &mut starting => {
                    panic!("the recovered engine started before checking application custody");
                },
            }
            assert_eq!(application_log.lock().verifications, requirements);
            assert_eq!(application_log.lock().proposed, 0);
            select! {
                _ = &mut starting => {
                    panic!("the recovered engine crossed the pending application custody fence");
                },
                () = context.sleep(Duration::from_millis(100)) => {},
            }
            verification.release();

            let mut engine = starting.await;
            assert!(engine.ready().await, "recovered engine becomes ready");
            let inspection = engine.inspect().await.expect("engine runs");
            assert!(
                inspection.produced_blocks() >= 1,
                "durable production state survived the crash"
            );
            assert!(!inspection.outbox().is_empty(), "the outbox was reissued");
        });
    }

    #[test_traced]
    fn engine_restart_preserves_every_active_publication_family() {
        let seed = 75;
        let prefix = "typed-obligation-restart";
        let runner = DeterministicRunner::timed(Duration::from_secs(120));
        let ((first, second), checkpoint) = runner.start_and_recover(|context| async move {
            let fixture = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
            let oracle = start_network(&context, fixture.identities.clone(), 4 * 1024 * 1024).await;
            link_all(&oracle, &fixture.identities).await;

            let peer = fixture.identities[1].clone();
            let (mut data_tx, mut data_rx) = oracle
                .control(peer.clone())
                .register(0, QUOTA)
                .await
                .unwrap();
            let (mut certificates_tx, _) = oracle.control(peer).register(2, QUOTA).await.unwrap();
            let mut planes = Vec::new();
            for channel in 0..4u64 {
                planes.push(
                    oracle
                        .control(fixture.identities[0].clone())
                        .register(channel, QUOTA)
                        .await
                        .unwrap(),
                );
            }
            let mut planes = planes.into_iter();
            let application = MockApplication::new();
            application.pause_building();
            application.permit_builds(2);
            let mut engine_config = config(
                &Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap()),
                0,
                prefix,
            );
            engine_config.automaton = application.clone();
            engine_config.relay = application;
            let engine = Engine::new(context.child("typed_first"), engine_config)
                .with_checkpoint_interval(commonware_utils::NZU64!(2));
            let mut engine = Box::pin(engine.start(
                planes.next().unwrap(),
                planes.next().unwrap(),
                planes.next().unwrap(),
                planes.next().unwrap(),
            ))
            .await
            .expect("engine starts");
            assert!(engine.ready().await);

            let mut blocks = Vec::new();
            let deadline = context.current() + Duration::from_secs(5);
            while blocks.len() < 2 {
                select! {
                    result = data_rx.recv() => {
                        let (_, bytes) = result.expect("network remains connected");
                        let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                            bytes,
                            &EnvelopeConfig {
                                max_frame_bytes: usize::MAX,
                                epoch: fixture.config.epoch(),
                                payload: (),
                            },
                        )
                        .expect("engine emits canonical data");
                        let DataMessage::Block(block) = envelope.into_payload() else {
                            continue;
                        };
                        if !blocks.iter().any(|existing: &SignedTransactionBlock<_, _>| {
                            existing.header().height() == block.header().height()
                        }) {
                            blocks.push(block);
                            blocks.sort_unstable_by_key(|block| block.header().height());
                        }
                    },
                    () = context.sleep_until(deadline) => {
                        panic!("engine did not create two active block publications");
                    },
                }
            }
            let first = blocks[0].clone();
            let second = blocks[1].clone();
            assert_eq!(first.header().height(), Height::new(1));
            assert_eq!(second.header().height(), Height::new(2));

            // Let the view timeout create the local NoVote/Nullify batch before admitting its
            // exact exit. The two DA blocks remain below the pipeline limit while this happens.
            context.sleep(Duration::from_millis(600)).await;
            let votes = (0..fixture.codec().da_quorum())
                .map(|signer| fixture.da_vote(signer, first.header().clone()))
                .collect::<Vec<_>>();
            let certificate = fixture
                .verifier
                .assemble_da_certificate(&votes, &Sequential)
                .expect("a quorum of valid shares recovers the DA certificate");
            let _ = data_tx.send(
                Recipients::One(fixture.identities[0].clone()),
                Envelope::new(
                    fixture.config.epoch(),
                    DataMessage::<MinPk, Sha256Digest>::DaCertificate(certificate),
                )
                .encode(),
                false,
            );
            let _ = certificates_tx.send(
                Recipients::One(fixture.identities[0].clone()),
                Envelope::new(
                    fixture.config.epoch(),
                    CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                        fixture.nullification(1),
                    ),
                )
                .encode(),
                true,
            );

            let exit_view = View::new(1);
            let deadline = context.current() + Duration::from_secs(10);
            loop {
                let settled = engine.inspect().await.is_some_and(|inspection| {
                    inspection.view() >= View::new(2)
                        && inspection
                            .producer()
                            .is_some_and(|producer| producer.certified() >= first.header().height())
                        && inspection.pending_barrier().is_none()
                });
                let view_retained = engine
                    .serve(exit_view)
                    .await
                    .is_some_and(|proof| proof_covers_view(&proof, exit_view));
                if settled && view_retained {
                    break;
                }
                assert!(
                    context.current() < deadline,
                    "typed obligations did not settle"
                );
                context.sleep(Duration::from_millis(25)).await;
            }

            let checkpoint_partition = format!("{prefix}-0-multimmit-machine-checkpoints");
            let deadline = context.current() + Duration::from_secs(10);
            loop {
                if context
                    .scan(&checkpoint_partition)
                    .await
                    .is_ok_and(|blobs| !blobs.is_empty())
                {
                    break;
                }
                assert!(
                    context.current() < deadline,
                    "checkpoint sync did not complete"
                );
                context.sleep(Duration::from_millis(25)).await;
            }

            // No more application work is permitted and the next view timer is still distant.
            // Give the acknowledged snapshot a quiet interval before the unclean stop.
            context.sleep(Duration::from_millis(100)).await;

            engine.abort();
            engine.join().await;
            (first, second)
        });

        DeterministicRunner::from(checkpoint).start(move |context| async move {
            let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
            let mut store_context = context.child("typed_stores");
            let stores = Box::pin(open_stores(
                &mut store_context,
                profile(&committee, Role::Validator(Participant::new(0))),
                &format!("{prefix}-0"),
                &committee.verifier,
                &Sequential,
                NZUsize!(8),
            ))
            .await
            .expect("stores recover");
            let Startup::Recovered(recovered) = &stores.startup else {
                panic!("active typed obligations must select recovery startup");
            };
            let snapshot = recovered.core.snapshot();
            assert_eq!(
                snapshot.outbox().keys().collect::<Vec<_>>(),
                snapshot.obligations().keys().collect::<Vec<_>>(),
                "every active publication has exactly one typed obligation row"
            );

            let mut families = BTreeSet::new();
            for (effect, obligation) in snapshot.obligations() {
                assert_eq!(obligation.effect(), *effect);
                for discharge in obligation.discharges() {
                    assert_eq!(discharge.effect(), *effect);
                    match discharge {
                        PublicationDischarge::BlockCertifiedAtLeast { height, .. } => {
                            assert_eq!(*height, second.header().height());
                            families.insert("block");
                        }
                        PublicationDischarge::VoteCertifiedAtLeast { height, .. } => {
                            assert_eq!(*height, second.header().height());
                            families.insert("vote");
                        }
                        PublicationDischarge::CertificateSupersededAbove { height, .. } => {
                            assert_eq!(*height, first.header().height());
                            families.insert("certificate");
                        }
                        PublicationDischarge::ExitReplacedAfter { view, .. } => {
                            assert_eq!(*view, View::new(1));
                            families.insert("exit");
                        }
                        PublicationDischarge::ViewRetired { .. } => {
                            families.insert("own-message");
                        }
                    }
                }
            }
            assert_eq!(
                families,
                BTreeSet::from(["block", "certificate", "exit", "own-message", "vote"])
            );

            drop(stores);

            let oracle =
                start_network(&context, committee.identities.clone(), 4 * 1024 * 1024).await;
            link_all(&oracle, &committee.identities).await;
            let mut engine = Box::pin(launch(
                &context,
                &oracle,
                committee,
                0,
                "typed_second",
                prefix,
                commonware_utils::NZU64!(2),
            ))
            .await;
            assert!(engine.ready().await);
            let deadline = context.current() + Duration::from_secs(10);
            loop {
                let exit_view = View::new(1);
                let view_ready = engine
                    .serve(exit_view)
                    .await
                    .is_some_and(|proof| proof_covers_view(&proof, exit_view));
                if view_ready {
                    break;
                }
                assert!(
                    context.current() < deadline,
                    "recovered view proof did not become ready"
                );
                context.sleep(Duration::from_millis(25)).await;
            }
        });
    }
}
