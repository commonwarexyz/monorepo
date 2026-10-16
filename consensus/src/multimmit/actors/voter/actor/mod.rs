//! The voter actor: construction, startup, and the live loop around the core.
//!
//! [`Actor::new`] registers the voter's metrics and inbound queues. [`Actor::start`] spawns one
//! dedicated task that runs [`startup::Starting`] until the startup barrier is durable and then
//! the [`live::Live`] loop until the runtime stops or a fatal error.

mod app;
mod chains;
mod crypto;
mod dispatch;
mod hooks;
mod live;
mod persist;
mod publish;
mod sources;
mod startup;
#[cfg(test)]
mod test_hooks;
mod timers;
mod verification;

use super::{
    Config,
    mailbox::{Inbox, Mailbox},
    persistence::{self, Admission, NoHooks},
    telemetry::{TraceContext, metrics::Metrics},
};
use crate::{
    Automaton, Relay, Reporter,
    multimmit::{
        actors::{
            ingress, resolver, verifier,
            voter::tasks::{TaskError, TaskPermit},
        },
        machine::{CoreError, StepError},
        scheme::bls12381::Error as SchemeError,
        types::{Activity, Context},
        wire::Plane,
    },
};
use commonware_cryptography::{Hasher, PublicKey, bls12381::primitives::variant::Variant};
use commonware_p2p::{Blocker, Sender};
use commonware_parallel::Strategy;
use commonware_runtime::{ContextCell, Handle, Spawner};
use commonware_storage::Context as StorageContext;
use commonware_utils::channel::oneshot;
pub(crate) use hooks::Hooks;
use rand_core::CryptoRng;
use startup::{Parts, Starting};
#[cfg(test)]
pub(crate) use test_hooks::{TestEvent, TestHooks};
use tracing::{Span, error, info};

/// The types one voter runs over, named once instead of repeating their bounds.
///
/// Implemented for the tuple of a voter's generic parameters.
pub(crate) trait VoterTypes: 'static {
    type Context: CryptoRng + Spawner + StorageContext;
    type Hasher: Hasher;
    type PublicKey: PublicKey;
    type Variant: Variant;
    type Automaton: Automaton<Context = Context<DigestOf<Self>>, Digest = DigestOf<Self>>;
    type Relay: Relay<Digest = DigestOf<Self>, PublicKey = Self::PublicKey, Plan = ()>;
    type Reporter: Reporter<Activity = Activity<Self::Variant, DigestOf<Self>>>;
    /// Execution strategy for view-critical CPU-heavy cryptography.
    type CriticalStrategy: Strategy;
    /// Peer blocker for participants the machine proves equivocated.
    type Blocker: Blocker<PublicKey = Self::PublicKey>;
    /// Observes the voter's typed boundaries.
    type Hooks: Hooks<Self::Variant, DigestOf<Self>>;
}

/// The digest type of a voter's hasher.
pub(crate) type DigestOf<T> = <<T as VoterTypes>::Hasher as Hasher>::Digest;

/// The configuration of a voter over `T`.
pub(crate) type ConfigOf<T> = Config<
    <T as VoterTypes>::Context,
    <T as VoterTypes>::Hasher,
    <T as VoterTypes>::PublicKey,
    <T as VoterTypes>::Variant,
    <T as VoterTypes>::Automaton,
    <T as VoterTypes>::Relay,
    <T as VoterTypes>::Reporter,
    <T as VoterTypes>::CriticalStrategy,
    <T as VoterTypes>::Blocker,
>;

/// The inbound queue endpoints of a voter over `T`.
pub(crate) type MailboxOf<T> = Mailbox<<T as VoterTypes>::Variant, DigestOf<T>>;

/// A voter's generic parameters, in [`Config`] order, name its [`VoterTypes`].
impl<E, H, P, V, A, R, F, C, B> VoterTypes for (E, H, P, V, A, R, F, C, B)
where
    E: CryptoRng + Spawner + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    C: Strategy,
    B: Blocker<PublicKey = P>,
{
    type Context = E;
    type Hasher = H;
    type PublicKey = P;
    type Variant = V;
    type Automaton = A;
    type Relay = R;
    type Reporter = F;
    type CriticalStrategy = C;
    type Blocker = B;
    type Hooks = NoHooks;
}

/// A voter's generic parameters followed by its hooks name its [`VoterTypes`].
impl<E, H, P, V, A, R, F, C, B, K> VoterTypes for (E, H, P, V, A, R, F, C, B, K)
where
    E: CryptoRng + Spawner + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    C: Strategy,
    B: Blocker<PublicKey = P>,
    K: Hooks<V, H::Digest>,
{
    type Context = E;
    type Hasher = H;
    type PublicKey = P;
    type Variant = V;
    type Automaton = A;
    type Relay = R;
    type Reporter = F;
    type CriticalStrategy = C;
    type Blocker = B;
    type Hooks = K;
}

/// The network planes the voter publishes on.
pub(crate) struct Planes<S> {
    /// Transaction blocks.
    pub(crate) data: S,
    /// Leader proposals and vote updates.
    pub(crate) consensus: S,
    /// V-QCs and L-QCs.
    pub(crate) certificates: S,
}

impl<S> Planes<S> {
    /// Returns the sender for `plane`.
    const fn sender(&mut self, plane: Plane) -> &mut S {
        match plane {
            Plane::Data => &mut self.data,
            Plane::Consensus => &mut self.consensus,
            Plane::Certificate => &mut self.certificates,
        }
    }
}

/// A finished runtime task: its capacity permit, trace context, and outcome.
pub(crate) struct Finished<O> {
    pub(crate) permit: TaskPermit,
    pub(crate) trace: TraceContext,
    pub(crate) outcome: O,
}

/// A fatal epoch error: the voter stops and the engine must tear down.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Fatal {
    /// The machine rejected a step or an effect the voter was asked to execute.
    #[error("machine step failed: {0}")]
    Step(#[from] StepError),
    /// The core's input scheduling or capacity accounting failed.
    #[error("core failed: {0}")]
    CoreState(#[from] CoreError),
    /// The core's task permit accounting failed.
    #[error("core task admission failed: {0}")]
    Task(#[from] TaskError),
    /// The persistence actor failed or closed.
    #[error("persistence failed: {0}")]
    Persistence(#[from] persistence::Error),
    /// A local signature or certificate could not be produced.
    #[error("signing or certificate assembly failed: {0}")]
    Scheme(#[from] SchemeError),
    /// The application declined or failed a mandatory build or custody check.
    #[error("the automaton failed a mandatory application operation")]
    Automaton,
    /// A worker panicked while signing, assembling, or recovering.
    #[error("a cryptographic worker panicked")]
    CryptoTaskPanicked,
    /// A mandatory peer actor stopped accepting messages.
    #[error("a mandatory control channel closed")]
    Closed,
    /// The verifier stopped accepting verification jobs.
    #[error("the verifier closed")]
    VerificationClosed,
}

impl From<Admission> for Fatal {
    fn from(admission: Admission) -> Self {
        match admission {
            // The voter checks capacity before core work that may stage a command.
            Admission::Full => CoreError::SchedulerInvariant.into(),
            Admission::Closed => persistence::Error::Closed.into(),
        }
    }
}

/// A fatal error paired with the root span of the work that failed.
pub(crate) type Failure = (Span, Fatal);

/// Records one terminal failure on the root of the work that failed.
pub(crate) fn record_fatal(metrics: &Metrics, root: &Span, fatal: &Fatal) {
    metrics.fatal.inc();
    root.in_scope(|| error!(?fatal, "voter failed"));
}

/// Attaches the root span that records a fatal error.
pub(crate) trait AtRoot<T> {
    /// Pairs an error with `root`, the span that owns the failed work.
    fn at(self, root: &Span) -> Result<T, Failure>;
}

impl<T, E: Into<Fatal>> AtRoot<T> for Result<T, E> {
    fn at(self, root: &Span) -> Result<T, Failure> {
        self.map_err(|error| (root.clone(), error.into()))
    }
}

/// The voter for one fixed epoch, before it starts.
pub(crate) struct Actor<T: VoterTypes> {
    context: ContextCell<T::Context>,
    config: ConfigOf<T>,
    inbox: Inbox<T::Variant, DigestOf<T>>,
    metrics: Metrics,
    hooks: T::Hooks,
    /// The persistence actor's flush channel, opened before the actor starts.
    flushes: persistence::Flushes,
}

impl<E, H, P, V, A, R, F, C, B> Actor<(E, H, P, V, A, R, F, C, B)>
where
    E: CryptoRng + Spawner + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    C: Strategy,
    B: Blocker<PublicKey = P>,
{
    /// Creates the voter and the typed endpoints of its inbound queues.
    ///
    /// `queues` labels the observation and completion queues.
    pub(crate) fn new(
        context: E,
        queues: &E,
        config: Config<E, H, P, V, A, R, F, C, B>,
    ) -> (Self, Mailbox<V, H::Digest>) {
        Self::build(context, queues, config, NoHooks)
    }
}

#[cfg(test)]
impl<E, H, P, V, A, R, F, C, B, K> Actor<(E, H, P, V, A, R, F, C, B, K)>
where
    E: CryptoRng + Spawner + StorageContext,
    H: Hasher,
    P: PublicKey,
    V: Variant,
    A: Automaton<Context = Context<H::Digest>, Digest = H::Digest>,
    R: Relay<Digest = H::Digest, PublicKey = P, Plan = ()>,
    F: Reporter<Activity = Activity<V, H::Digest>>,
    C: Strategy,
    B: Blocker<PublicKey = P>,
    K: Hooks<V, H::Digest>,
{
    /// Creates the voter observed by `hooks` and the typed endpoints of its inbound queues.
    pub(crate) fn new_with_hooks(
        context: E,
        queues: &E,
        config: Config<E, H, P, V, A, R, F, C, B>,
        hooks: K,
    ) -> (Self, Mailbox<V, H::Digest>) {
        Self::build(context, queues, config, hooks)
    }
}

impl<T: VoterTypes> Actor<T> {
    fn build(
        context: T::Context,
        queues: &T::Context,
        config: ConfigOf<T>,
        hooks: T::Hooks,
    ) -> (Self, MailboxOf<T>) {
        let profile = config.recovered.core.machine().profile();
        let chain_count = profile.codec().chains();
        let metrics = Metrics::new(&context, chain_count);
        let (mailbox, inbox) = Mailbox::new(
            &context,
            queues,
            config.mailbox_size,
            config.observation_capacity,
        );
        (
            Self {
                context: ContextCell::new(context),
                config,
                inbox,
                metrics,
                hooks,
                flushes: persistence::Flushes::default(),
            },
            mailbox,
        )
    }

    /// Returns a handle that requests durability for every append the persistence actor admits.
    #[cfg(any(test, feature = "mocks"))]
    pub(crate) fn flusher(&self) -> persistence::Flusher {
        self.flushes.flusher()
    }

    /// Starts the voter over its peers' already-registered fixed-epoch planes.
    ///
    /// `ready` resolves once the startup or recovery durability barrier is acknowledged and the
    /// resolver has been seeded. Ingress queued by the surrounding actors cannot enter the core
    /// until that point.
    pub(crate) fn start<S>(
        mut self,
        ready: oneshot::Sender<()>,
        planes: Planes<S>,
        ingress: ingress::Mailbox,
        verifier: verifier::Mailbox<T::Variant, DigestOf<T>>,
        resolver: resolver::Mailbox<T::Variant, DigestOf<T>>,
    ) -> Handle<()>
    where
        S: Sender<PublicKey = T::PublicKey>,
    {
        // `spawn_cell!` spawns on the shared executor; the voter needs its own dedicated thread.
        let context = self.context.take();
        context.dedicated().spawn(move |context| async move {
            let Self {
                config,
                inbox,
                metrics,
                hooks,
                flushes,
                ..
            } = self;
            let failures = metrics.clone();
            let starting = Starting::<T, S>::new(Parts {
                context,
                config,
                inbox,
                planes,
                ingress,
                verifier,
                resolver,
                metrics,
                hooks,
                flushes,
            });
            let live = match starting.run().await {
                Ok(live) => live,
                Err((root, fatal)) => {
                    record_fatal(&failures, &root, &fatal);
                    return;
                }
            };
            info!(epoch = live.epoch.get(), "voter is live");
            let _ = ready.send(());
            live.run().await;
        })
    }
}
