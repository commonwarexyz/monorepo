//! Compose and run Multimmit's actors for one epoch.
//!
//! [`Engine::open`] validates the configuration and derives this node's profile from it before
//! touching storage, recovers durable state, and builds the ingress, verifier, voter, and resolver
//! actors with their channels, without spawning anything. [`Engine::start`] spawns them over the
//! four network [`Planes`] and returns a [`Running`] handle. Readiness resolves only after the
//! voter's first durability barrier is acknowledged and its initial producer wake is submitted. Any
//! mandatory actor exit stops the whole engine; joining the engine's root task is the only evidence
//! that its children stopped and its signing material was dropped.
//!
//! Recovery reverifies payloads before consensus authority returns: for every recovered
//! `(Context, payload digest)` whose custody still backs producer-dependent authority, the engine
//! completes `Automaton::verify` before any actor, timer, or publication starts. Once every call
//! returns `true`, the core starts a new process generation and reissues its live durable
//! obligations.

use crate::{
    Automaton, Epochable as _, Relay, Reporter,
    multimmit::{
        actors::{
            ingress::{self, IngressLimits},
            resolver, verifier,
            voter::{self, Endpoints, VoterLimits, VoterTypes, validation_capacity},
        },
        config::{Error as ConfigError, Profile, Protocol, Role, Tuning},
        machine::Inspection,
        scheme::bls12381_threshold::Scheme,
        storage::{OpenError, Recovered, RecoveryConfig, recover, valid_partition_prefix},
        types::{Activity, Context, EpochGenesis},
    },
};
use commonware_cryptography::{Digest, Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_macros::select;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Error as RuntimeError, Handle, Metrics, Spawner, Storage,
    buffer::paged::CacheRef, spawn_cell, telemetry::traces::TracedExt as _,
};
use commonware_storage::Context as StorageContext;
use commonware_utils::{NZU64, channel::oneshot};
use rand_core::CryptoRng;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, info};

/// Durable journal events between machine checkpoints.
///
/// A checkpoint writes a new Base, the snapshot that replay starts from. One Base per full
/// journal section lets compaction prune whole blobs on their natural boundary instead of
/// churning a fresh blob every few dozen events, and replaying a worst-case suffix of this size
/// costs low tens of milliseconds.
const CHECKPOINT_INTERVAL: NonZeroU64 = NZU64!(4096);

/// Returns the thread count a view-critical execution pool needs for a committee of
/// `participants`: one thread per eight participants, and at least two.
///
/// The floor keeps the two view-critical crypto classes, one signing job and one certificate
/// assembly, from waiting on each other.
pub fn critical_threads(participants: usize) -> NonZeroUsize {
    NonZeroUsize::new((participants / 8).max(2)).expect("the floor is non-zero")
}

/// Derives how many recovered payloads the application verifies concurrently at startup.
fn inflight_application<D: Digest>(profile: &Profile<D>) -> NonZeroUsize {
    NonZeroUsize::new(validation_capacity(profile))
        .expect("validated profile has at least one producer-chain position")
}

/// Configuration for one Multimmit engine.
pub struct Config<H: Hasher, P: PublicKey, V: Variant, A, R, F, T, C, B> {
    /// Cryptographic material for the epoch, holding the
    /// [`Parameters`](crate::multimmit::config::Parameters) the engine runs under.
    ///
    /// A signer runs the engine as the validator it holds keys for; a verifier runs it as an
    /// observer.
    pub scheme: Scheme<P, V>,
    /// The epoch's genesis facts, checked against the scheme's parameters.
    pub genesis: EpochGenesis<H::Digest>,
    /// The operator's tuning, from which every internal bound is derived.
    pub tuning: Tuning,
    /// Application commitment construction and validation.
    pub automaton: A,
    /// Transaction-header dissemination notification by canonical header digest.
    pub relay: R,
    /// Authenticated activity reporting.
    pub reporter: F,
    /// Execution strategy for bulk CPU-heavy cryptography, the work a view does not wait on.
    pub strategy: T,
    /// Execution strategy for view-critical CPU-heavy cryptography.
    ///
    /// Size it with [`critical_threads`] so a view's own cryptography never queues behind bulk
    /// work.
    pub critical_strategy: C,
    /// Peer blocker for objectively attributed protocol faults.
    pub blocker: B,
    /// Storage partition prefix owned exclusively by this engine: ASCII alphanumerics and
    /// underscores.
    ///
    /// A marshal may share the prefix; their partition names do not collide.
    pub partition_prefix: String,
    /// Page cache for the safety journal, including its logical page size and capacity.
    ///
    /// Use `paged::page_size` to select an aligned physical size.
    /// The page size must remain unchanged when reopening this partition: changing it is a
    /// destructive storage-format change that can truncate the journal during recovery.
    pub page_cache: CacheRef,
    /// Mailbox capacity for every actor.
    pub mailbox_size: NonZeroUsize,
}

/// The four network channels one engine runs over, as `(sender, receiver)` pairs.
///
/// Every participant must register the same four distinct channels.
pub struct Planes<S, R> {
    /// Carries transaction-block headers, data-availability votes, and data-availability
    /// certificates.
    ///
    /// Producers publish their blocks here and validators answer with the votes that certify a
    /// block's availability. This is the bulk plane: its traffic scales with application
    /// throughput, so it is kept apart from the messages a round waits on.
    pub data: (S, R),
    /// Carries leader proposals, votes, novotes, and nullify shares.
    ///
    /// The ingress actor batches these for verification before the voter tallies them.
    pub consensus: (S, R),
    /// Carries nullifications, V-QCs, and L-QCs.
    ///
    /// Certificates travel apart from individual votes so a node that receives a certificate can
    /// skip the votes it covers.
    pub certificates: (S, R),
    /// Carries view-proof requests and responses.
    ///
    /// A node that missed a view fetches the certificate or covering L-QC that crosses it from
    /// its peers here.
    pub resolver: (S, R),
}

/// The engine stopped before it became ready.
#[derive(Debug, thiserror::Error)]
#[error("the engine stopped before becoming ready")]
pub struct Stopped;

/// A running engine's external handle.
pub struct Running<D: Digest> {
    handle: Handle<()>,
    readiness: Readiness,
    inspector: Inspector<D>,
}

enum Readiness {
    Pending(oneshot::Receiver<()>),
    Ready,
    Failed,
}

impl Readiness {
    async fn wait(&mut self) -> Result<(), Stopped> {
        match self {
            Self::Pending(receiver) => {
                let ready = receiver.await.is_ok();
                *self = if ready { Self::Ready } else { Self::Failed };
                if ready { Ok(()) } else { Err(Stopped) }
            }
            Self::Ready => Ok(()),
            Self::Failed => Err(Stopped),
        }
    }
}

/// A cloneable handle for reading a running engine's diagnostic state.
#[derive(Clone)]
pub struct Inspector<D: Digest> {
    voter: voter::Inspector<D>,
}

impl<D: Digest> Inspector<D> {
    /// Reads the machine's normalized diagnostic projection.
    pub async fn inspect(&self) -> Option<Inspection<D>> {
        self.voter.inspect().await
    }
}

impl<D: Digest> Running<D> {
    /// Resolves once startup or recovery is durable and the initial producer wake is submitted.
    ///
    /// # Errors
    ///
    /// Returns [`Stopped`] if the engine stopped before becoming ready.
    pub async fn ready(&mut self) -> Result<(), Stopped> {
        self.readiness.wait().await
    }

    /// Returns the handle for polling diagnostics independently of lifecycle ownership.
    pub const fn inspector(&self) -> &Inspector<D> {
        &self.inspector
    }

    /// Consumes the handle and waits for every engine child to stop.
    ///
    /// # Errors
    ///
    /// Returns the runtime's error when the engine's root task was aborted or panicked.
    pub async fn join(self) -> Result<(), RuntimeError> {
        self.handle.await
    }

    /// Requests engine shutdown; `join` remains the only evidence of completion.
    pub fn abort(&self) {
        self.handle.abort();
    }
}

/// Crate-private settings tests use to force checkpoint and journal edge cases.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Overrides {
    /// Replayed journal events between machine checkpoints.
    pub(crate) checkpoint_interval: NonZeroU64,
    /// Command capacity of the voter's persistence actor, when bounded below its default.
    pub(crate) journal_capacity: Option<NonZeroUsize>,
}

impl Default for Overrides {
    fn default() -> Self {
        Self {
            checkpoint_interval: CHECKPOINT_INTERVAL,
            journal_capacity: None,
        }
    }
}

/// The settings of the actors an engine wires, derived from its profile.
///
/// Tests wire the same actors from these settings and override only what a scenario needs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ActorLimits {
    /// Buffering bounds of the ingress actor.
    pub(crate) ingress: IngressLimits,
    /// Observation cohorts the ingress actor may queue for the voter.
    pub(crate) observation_capacity: NonZeroUsize,
    /// Verification jobs the verifier runs concurrently.
    pub(crate) inflight_verifications: NonZeroUsize,
    /// How long the resolver waits for a view proof before requesting it again.
    pub(crate) fetch_timeout: Duration,
    /// Retry, heartbeat, and checkpoint policy of the voter.
    pub(crate) voter: VoterLimits,
    /// Command capacity of the voter's persistence actor, when bounded below its default.
    pub(crate) journal_capacity: Option<NonZeroUsize>,
}

impl ActorLimits {
    /// Derives every actor setting from `profile`, with `overrides` applied.
    pub(crate) fn from_profile<V: Variant, D: Digest>(
        profile: &Profile<D>,
        overrides: Overrides,
    ) -> Self {
        let resources = profile.resources();
        Self {
            ingress: IngressLimits::from_profile::<V, D>(profile),
            observation_capacity: NonZeroUsize::new(resources.max_verification_batch())
                .expect("verification batch is non-zero"),
            inflight_verifications: NonZeroUsize::new(resources.max_inflight_verifications())
                .expect("non-zero"),
            // A view proof that does not arrive within one view is requested again.
            fetch_timeout: profile.tuning().view_timeout,
            voter: VoterLimits::from_profile(profile, overrides.checkpoint_interval),
            journal_capacity: overrides.journal_capacity,
        }
    }
}

/// Multimmit's actors for one epoch, wired over recovered state but not yet started.
pub(crate) struct Actors<E, H, P, V, T, C, B, W>
where
    E: Clock + CryptoRng + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    T: Strategy,
    C: Strategy,
    B: Blocker<PublicKey = P>,
{
    pub(crate) ingress: ingress::Actor<E, H, P, V, T, C>,
    pub(crate) ingress_mailbox: ingress::Mailbox,
    pub(crate) verifier: verifier::Verifier<E, H, P, V, T, C>,
    pub(crate) verifier_mailbox: verifier::Mailbox<V, H::Digest>,
    pub(crate) resolver: resolver::Actor<E, H, P, V, B, T>,
    pub(crate) resolver_mailbox: resolver::Mailbox<V, H::Digest>,
    pub(crate) voter: W,
    pub(crate) voter_mailbox: voter::Mailbox<P, V, H::Digest>,
}

/// Wires the ingress, verifier, resolver, and voter over `recovered` under `root`, without
/// spawning anything.
///
/// `new_voter` builds the voter from its context, the context that labels its queues, and its
/// configuration, which lets tests attach hooks.
pub(crate) fn wire_actors<E, H, P, V, A, R, F, T, C, B, K>(
    root: &E,
    config: Config<H, P, V, A, R, F, T, C, B>,
    profile: &Profile<H::Digest>,
    recovered: Recovered<E, H, V>,
    limits: ActorLimits,
    new_voter: impl FnOnce(
        E,
        &E,
        voter::Config<E, H, P, V, A, R, F, T, C, B>,
    ) -> (voter::Actor<K>, voter::Mailbox<P, V, H::Digest>),
) -> Actors<E, H, P, V, T, C, B, voter::Actor<K>>
where
    E: Clock + CryptoRng + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    C: Strategy,
    B: Blocker<PublicKey = P>,
    K: VoterTypes,
{
    let protocol = profile.protocol();
    let codec = protocol.codec_config();
    let (ingress, ingress_mailbox) = ingress::Actor::new(
        root.child("batcher"),
        ingress::Config {
            epoch: protocol.epoch(),
            participants: Arc::new(config.scheme.participants().clone()),
            strategy: config.strategy.clone(),
            critical_strategy: config.critical_strategy.clone(),
            codec,
            bounds: codec
                .encoded_bounds::<V, H::Digest>()
                .expect("profile validated encoded protocol bounds"),
            limits: limits.ingress,
            mailbox_size: config.mailbox_size,
            observation_capacity: limits.observation_capacity,
        },
    );
    let (verifier, verifier_mailbox) = verifier::Verifier::new(
        root.child("batcher"),
        verifier::Config {
            scheme: config.scheme.clone(),
            strategy: config.strategy.clone(),
            critical_strategy: config.critical_strategy.clone(),
            inflight_jobs: limits.inflight_verifications,
            mailbox_size: config.mailbox_size,
        },
    );
    let (resolver, resolver_mailbox) = resolver::Actor::new(
        root.child("resolver"),
        resolver::Config {
            scheme: config.scheme.clone(),
            blocker: config.blocker.clone(),
            strategy: config.strategy.clone(),
            fetch_timeout: limits.fetch_timeout,
            mailbox_size: config.mailbox_size,
        },
    );
    let blocked = voter::blocked_counter(root);
    let (voter, voter_mailbox) = new_voter(
        root.child("voter"),
        // Labeled under the engine so the registered backoff metric names stay stable.
        root,
        voter::Config {
            scheme: config.scheme,
            strategy: config.strategy,
            critical_strategy: config.critical_strategy,
            automaton: config.automaton,
            relay: config.relay,
            reporter: config.reporter,
            blocker: config.blocker,
            blocked,
            recovered,
            limits: limits.voter,
            mailbox_size: config.mailbox_size,
        },
    );
    let voter = match limits.journal_capacity {
        Some(capacity) => voter.with_journal_capacity(capacity),
        None => voter,
    };
    Actors {
        ingress,
        ingress_mailbox,
        verifier,
        verifier_mailbox,
        resolver,
        resolver_mailbox,
        voter,
        voter_mailbox,
    }
}

/// The voter the engine runs, with no test hooks.
type Voter<E, H, P, V, A, R, F, T, C, B> = voter::Actor<(E, H, P, V, A, R, F, T, C, B)>;

/// The actors the engine runs.
type EngineActors<E, H, P, V, A, R, F, T, C, B> =
    Actors<E, H, P, V, T, C, B, Voter<E, H, P, V, A, R, F, T, C, B>>;

/// Multimmit's actors for one epoch, recovered and wired but not yet running.
pub struct Engine<E, H, P, V, A, R, F, T, C, B>
where
    E: Clock + CryptoRng + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    C: Strategy,
    B: Blocker<PublicKey = P>,
{
    context: ContextCell<E>,
    actors: EngineActors<E, H, P, V, A, R, F, T, C, B>,
}

impl<E, H, P, V, A, R, F, T, C, B> Engine<E, H, P, V, A, R, F, T, C, B>
where
    E: Clock + CryptoRng + Spawner + Storage + Metrics + BufferPooler + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    T: Strategy,
    C: Strategy,
    B: Blocker<PublicKey = P>,
{
    /// Validates `config`, recovers the engine's durable state, and builds its actors.
    ///
    /// Stores open and recover before any actor exists, so nothing accepts ingress until
    /// [`Self::start`].
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::Config`] before touching storage when the configuration is invalid,
    /// and another [`OpenError`] when durable state cannot be opened or recovered.
    pub async fn open(
        context: E,
        config: Config<H, P, V, A, R, F, T, C, B>,
    ) -> Result<Self, OpenError> {
        // Boxed so callers can await `open` without boxing a large future themselves.
        Box::pin(Self::open_with(context, config, Overrides::default())).await
    }

    /// Opens the engine with crate-private `overrides`.
    ///
    /// The returned future is large; box it before awaiting it inside another large future.
    // Registered span name; covers recovery and actor construction.
    #[tracing::instrument(
        name = "multimmit.engine.start",
        level = "info",
        skip_all,
        err,
        fields(epoch = config.scheme.parameters().epoch().get().traced())
    )]
    pub(crate) async fn open_with(
        context: E,
        config: Config<H, P, V, A, R, F, T, C, B>,
        overrides: Overrides,
    ) -> Result<Self, OpenError> {
        let profile = derive_profile(&config)?;
        let mut context = ContextCell::new(context);
        let limits = ActorLimits::from_profile::<V, _>(&profile, overrides);

        // Gated startup: recover durable state before any actor exists.
        let recovered = Box::pin(recover(
            context.as_present_mut(),
            RecoveryConfig {
                profile: profile.clone(),
                partition_prefix: &config.partition_prefix,
                scheme: &config.scheme,
                strategy: &config.strategy,
                page_cache: config.page_cache.clone(),
                checkpoint_interval: overrides.checkpoint_interval,
                inflight_application: inflight_application(&profile),
            },
            &config.automaton,
        ))
        .await?;
        let actors = wire_actors(
            context.as_ref(),
            config,
            &profile,
            recovered,
            limits,
            voter::Actor::new,
        );
        Ok(Self { context, actors })
    }

    /// Returns the handle tests use to read the view proofs this engine serves to peers.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn proofs(&self) -> resolver::Server<V, H::Digest> {
        self.actors.resolver_mailbox.server()
    }

    /// Returns the handle tests use to demand durability for every journal append this engine
    /// admits.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn flusher(&self) -> voter::Flusher {
        self.actors.voter.flusher()
    }

    /// Spawns the engine's actors over its four network planes.
    ///
    /// The returned handle's [`Running::ready`] resolves after startup or recovery is durable and
    /// the initial producer wake is submitted.
    pub fn start<S, Rx>(self, planes: Planes<S, Rx>) -> Running<H::Digest>
    where
        S: Sender<PublicKey = P>,
        Rx: Receiver<PublicKey = P>,
    {
        let (ready_sender, ready_receiver) = oneshot::channel();
        let Self {
            mut context,
            actors:
                Actors {
                    ingress,
                    ingress_mailbox,
                    verifier,
                    verifier_mailbox,
                    resolver,
                    resolver_mailbox,
                    voter,
                    voter_mailbox,
                },
        } = self;
        // Each producer holds only its own endpoint, so the voter observes any of them stopping.
        let Endpoints {
            resolutions,
            observations,
            completions,
            inspector,
        } = voter_mailbox.into_endpoints();
        let Planes {
            data: (data_sender, data_receiver),
            consensus: (consensus_sender, consensus_receiver),
            certificates: (certificates_sender, certificates_receiver),
            resolver: resolver_network,
        } = planes;
        let handle = spawn_cell!(context, async move {
            let root = context;
            let mut ingress_task = ingress.start(
                verifier,
                completions,
                observations,
                data_receiver,
                consensus_receiver,
                certificates_receiver,
            );
            let mut resolver_task = resolver.start(resolutions, resolver_network);
            let mut voter_task = voter.start(
                ready_sender,
                voter::Planes {
                    data: data_sender,
                    consensus: consensus_sender,
                    certificates: certificates_sender,
                },
                ingress_mailbox,
                verifier_mailbox,
                resolver_mailbox,
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
                ingress = &mut ingress_task => {
                    debug!(?ingress, "ingress or verifier stopped, shutting down engine");
                },
                resolver = &mut resolver_task => {
                    debug!(?resolver, "resolver stopped, shutting down engine");
                },
            }
        });
        Running {
            handle,
            readiness: Readiness::Pending(ready_receiver),
            inspector: Inspector { voter: inspector },
        }
    }
}

/// Validates `config` and derives the profile it describes.
///
/// The protocol pairs the scheme's parameters with the genesis, and the role follows from the
/// scheme's key material, so the scheme, protocol, and role cannot disagree.
pub(crate) fn derive_profile<H, P, V, A, R, F, T, C, B>(
    config: &Config<H, P, V, A, R, F, T, C, B>,
) -> Result<Profile<H::Digest>, ConfigError>
where
    H: Hasher,
    P: PublicKey,
    V: Variant,
{
    if !valid_partition_prefix(&config.partition_prefix) {
        return Err(ConfigError::InvalidPartitionPrefix);
    }
    let protocol =
        Protocol::from_parameters(config.scheme.parameters().clone(), config.genesis.clone())?;
    let role = config.scheme.me().map_or(Role::Observer, Role::Validator);
    Profile::new::<V>(protocol, role, config.tuning)
}

#[cfg(test)]
mod tests;
