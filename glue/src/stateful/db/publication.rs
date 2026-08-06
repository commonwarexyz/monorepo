//! Durable snapshot publication, the writer's post-durability handoff to serving.
//!
//! [`super::DatabaseSet::finalize`] captures one snapshot per member at the apply boundary
//! and returns it with the generation's [`super::Barrier`]. Actor orchestration stages the
//! capture through a [`Publisher`] and installs it once the barrier proves every member
//! durable; resolver actors serve the latest installed generation through cloned
//! [`MemberSource`]s. Publication is atomic at the set level because one [`SetSnapshot`]
//! carries every member: a single source load can never observe members from different
//! generations. That atomicity covers one [`ServeSource::serve`] (or `latest`) call;
//! independent calls may straddle an installation and observe different generations.
//! While a generation's durability is pending, sources continue to serve the previous
//! installed generation.
//!
//! Flushes may be pipelined, so several staged generations can await durability at once.
//! Staging order fixes generation numbers and installation is monotone, which keeps the
//! served sequence moving forward even if pool completions are observed out of order.
//!
//! A source serves nothing before the first installation (the node has not finished
//! starting) and nothing after the [`Publisher`] drops (writer failure and clean shutdown
//! degrade identically); snapshots already handed out drain naturally. Serving code sees
//! only [`ServeSource::serve`]'s `Option`. The distinction between those states, like the
//! generation numbers, stays internal.

use commonware_runtime::{Metrics as RuntimeMetrics, telemetry::metrics::Registered};
use commonware_utils::sync::Mutex;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::sync::Arc;

/// One installed generation of a database set, every member's snapshot captured at the same
/// apply boundary and proven durable before installation.
#[derive(Debug)]
pub(crate) struct SetSnapshot<S> {
    generation: u64,
    members: S,
}

impl<S> SetSnapshot<S> {
    /// Monotonically increasing installation identifier (the set's commit generation).
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    /// The member snapshots.
    pub(crate) const fn members(&self) -> &S {
        &self.members
    }
}

enum State<S> {
    Empty,
    Live(Arc<SetSnapshot<S>>),
    Detached,
}

/// Shared between the [`Publisher`], its [`Staged`] tokens, and every source.
struct Slot<S> {
    state: Mutex<State<S>>,
    metrics: Metrics,
}

impl<S> Slot<S> {
    /// Install `snapshot` unless a newer generation is already live.
    fn install(&self, snapshot: Arc<SetSnapshot<S>>) {
        let generation = snapshot.generation();
        // Metrics update under the lock so the gauge can never trail a newer install.
        // The replaced snapshot is dropped only after the guard: its destructor may
        // free a whole generation and must not stall serving.
        let mut state = self.state.lock();
        let replaced = match &*state {
            State::Detached => return,
            State::Live(live) if live.generation() > generation => return,
            State::Empty | State::Live(_) => std::mem::replace(&mut *state, State::Live(snapshot)),
        };
        self.metrics.generation.set(generation as i64);
        self.metrics.installed.inc();
        drop(state);
        drop(replaced);
    }
}

/// Publication metrics, registered on the publishing actor's context.
struct Metrics {
    /// Generation of the latest installed snapshot.
    generation: Registered<Gauge>,
    /// Installations since startup.
    installed: Registered<Counter>,
}

impl Metrics {
    fn register<E: RuntimeMetrics>(context: &E) -> Self {
        Self {
            generation: context.register(
                "published_generation",
                "Generation of the latest installed snapshot",
                Gauge::default(),
            ),
            installed: context.register(
                "publications",
                "Snapshot installations since startup",
                Counter::default(),
            ),
        }
    }
}

/// The writer-side handle that stages captured generations for installation.
///
/// Owned by actor orchestration. Dropping it detaches every source.
pub(crate) struct Publisher<S> {
    slot: Arc<Slot<S>>,
    next_generation: u64,
}

impl<S> Publisher<S> {
    /// Create a publisher and its source. The source serves nothing until the first staged
    /// generation installs.
    pub(crate) fn new<E: RuntimeMetrics>(context: &E) -> (Self, SetSource<S>) {
        let slot = Arc::new(Slot {
            state: Mutex::new(State::Empty),
            metrics: Metrics::register(context),
        });
        let publisher = Self {
            slot: slot.clone(),
            next_generation: 0,
        };
        (publisher, SetSource { slot })
    }

    /// Stage `members` as the next generation, returning the token that installs it.
    ///
    /// Staging fixes the generation number, so callers must stage in apply order. The token
    /// must be installed only after the generation's durability is proven. The caller holds
    /// it across the barrier await and installs on success.
    pub(crate) fn stage(&mut self, members: S) -> Staged<S> {
        let generation = self.next_generation;
        self.next_generation += 1;
        Staged {
            slot: self.slot.clone(),
            snapshot: Arc::new(SetSnapshot {
                generation,
                members,
            }),
        }
    }

    /// Stage and immediately install `members`, for state that is already durable
    /// (startup recovery and sync handoff).
    pub(crate) fn install_durable(&mut self, members: S) {
        self.stage(members).install();
    }
}

impl<S> Drop for Publisher<S> {
    fn drop(&mut self) {
        // Detach serving so new requests decline while held snapshots drain. Drop
        // the displaced snapshot outside the lock.
        let mut state = self.slot.state.lock();
        let replaced = std::mem::replace(&mut *state, State::Detached);
        drop(state);
        drop(replaced);
    }
}

/// A staged generation awaiting its durability proof.
///
/// Dropping the token without installing simply skips this generation, as on a runtime
/// shutdown before its flush completed. Later generations still install.
pub(crate) struct Staged<S> {
    slot: Arc<Slot<S>>,
    snapshot: Arc<SetSnapshot<S>>,
}

impl<S> Staged<S> {
    /// Install the staged generation unless a newer one already installed.
    pub(crate) fn install(self) {
        self.slot.install(self.snapshot);
    }
}

/// A reader-side handle to the latest installed generation.
///
/// Cloned freely. Each request clones the current generation's Arc once and uses that
/// generation for its whole lifetime. Public only so set implementations can name it in
/// [`super::DatabaseSet::member_sources`]; everything it can do is crate-internal.
pub struct SetSource<S> {
    slot: Arc<Slot<S>>,
}

impl<S> Clone for SetSource<S> {
    fn clone(&self) -> Self {
        Self {
            slot: self.slot.clone(),
        }
    }
}

impl<S> SetSource<S> {
    /// The latest installed generation, or `None` before the first installation and after
    /// the publisher drops.
    pub(crate) fn latest(&self) -> Option<Arc<SetSnapshot<S>>> {
        match &*self.slot.state.lock() {
            State::Live(snapshot) => Some(snapshot.clone()),
            State::Empty | State::Detached => None,
        }
    }
}

/// A source projected to one member of the set.
///
/// Reads the set atomically (one slot load), then clones the member's snapshot Arc, so
/// per-member serving still can never observe a torn cross-member generation.
pub struct MemberSource<S, M> {
    source: SetSource<S>,
    project: fn(&S) -> &M,
}

impl<S, M> Clone for MemberSource<S, M> {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            project: self.project,
        }
    }
}

impl<S, M: Clone> MemberSource<S, M> {
    /// Create a projection of `source` via `project`.
    ///
    /// Public so [`super::DatabaseSet::member_sources`] is implementable outside this
    /// crate; the source only reads installed generations, so nothing mutation-capable
    /// escapes.
    pub fn new(source: SetSource<S>, project: fn(&S) -> &M) -> Self {
        Self { source, project }
    }
}

/// A source of per-request serving handles backed by the latest installed generation.
///
/// Serving actors hold a source and take one handle per request. The handle is an owned
/// snapshot, so serving never touches the live database.
pub trait ServeSource: Clone + Send + Sync + 'static {
    /// The per-request serving handle.
    type Serve: Send + Sync + 'static;

    /// The serving handle for the latest installed generation, or `None` when there is
    /// nothing to serve (before the node finishes starting, or after writer shutdown).
    fn serve(&self) -> Option<Self::Serve>;
}

impl<S, M> ServeSource for MemberSource<S, M>
where
    S: Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type Serve = M;

    fn serve(&self) -> Option<M> {
        let set = self.source.latest()?;
        Some((self.project)(set.members()).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn empty_then_live_then_detached() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, source) = Publisher::<u32>::new(&context);
            assert!(source.latest().is_none());

            publisher.install_durable(7);
            let first = source.latest().unwrap();
            assert_eq!(first.generation(), 0);
            assert_eq!(*first.members(), 7);

            publisher.install_durable(8);
            let held = source.latest().unwrap();
            assert_eq!(held.generation(), 1);
            assert_eq!(*held.members(), 8);

            drop(publisher);
            // New requests decline while the held Arc still serves.
            assert!(source.latest().is_none());
            assert_eq!(*held.members(), 8);
        });
    }

    #[test]
    fn pipelined_installation_is_monotone() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, source) = Publisher::<u32>::new(&context);
            // Two generations staged before either installs, as pipelined flushes allow.
            let first = publisher.stage(1);
            let second = publisher.stage(2);

            // The newer generation resolving first must win and stay won.
            second.install();
            assert_eq!(*source.latest().unwrap().members(), 2);
            first.install();
            let live = source.latest().unwrap();
            assert_eq!(live.generation(), 1);
            assert_eq!(*live.members(), 2);
        });
    }

    #[test]
    fn dropped_stage_skips_a_generation() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, source) = Publisher::<u32>::new(&context);
            // A shutdown drop of one staged generation must not block later ones.
            drop(publisher.stage(1));
            publisher.install_durable(2);
            let live = source.latest().unwrap();
            assert_eq!(live.generation(), 1);
            assert_eq!(*live.members(), 2);
        });
    }

    #[test]
    fn member_projection_is_atomic() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, source) = Publisher::<(u32, u32)>::new(&context);
            let member: MemberSource<(u32, u32), u32> = MemberSource::new(source, |set| &set.0);
            assert!(member.serve().is_none());
            publisher.install_durable((1, 10));
            assert_eq!(member.serve(), Some(1));
            publisher.install_durable((2, 20));
            assert_eq!(member.serve(), Some(2));
        });
    }
}
