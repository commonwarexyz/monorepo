//! Publishing database snapshots from the writer to readers.
//!
//! A [`Generation`] is every database's snapshot, captured at
//! the same apply boundary. The writer stages each generation through its
//! [`Publisher`], which numbers them in apply order, and publishes it once its flush
//! proves durable, so readers only ever see durable state. Publication is monotonic:
//! flushes finishing out of order never move readers backward.
//!
//! Readers hold a [`SetReader`], or a [`DbReader`] narrowed to one database, and
//! take the latest published generation once per request. A take never mixes
//! generations and never changes afterward. A reader yields nothing before the first
//! publish and nothing after the publisher drops (crash and clean shutdown look the
//! same to readers), but generations already taken keep working.

use commonware_runtime::{Metrics as RuntimeMetrics, telemetry::metrics::Registered};
use commonware_utils::sync::Mutex;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::sync::Arc;

/// Every database's snapshot, captured at the same apply boundary and numbered.
#[derive(Debug)]
pub(crate) struct Generation<S> {
    number: u64,
    snapshots: S,
}

impl<S> Generation<S> {
    /// The generation number, assigned in staging order.
    pub(crate) const fn number(&self) -> u64 {
        self.number
    }

    /// The databases' snapshots.
    pub(crate) const fn snapshots(&self) -> &S {
        &self.snapshots
    }
}

enum State<S> {
    Empty,
    Published(Arc<Generation<S>>),
    Detached,
}

/// Shared between the [`Publisher`], its [`Staged`] tokens, and every [`SetReader`].
struct Slot<S> {
    state: Mutex<State<S>>,
    metrics: Metrics,
}

impl<S> Slot<S> {
    /// Publish `generation` unless a newer one is already published.
    fn publish(&self, generation: Arc<Generation<S>>) {
        let number = generation.number();
        let mut state = self.state.lock();
        let replaced = match &*state {
            State::Detached => return,
            State::Published(published) if published.number() > number => return,
            State::Empty | State::Published(_) => {
                std::mem::replace(&mut *state, State::Published(generation))
            }
        };
        // Update metrics under the lock so the gauge matches what readers see.
        self.metrics.generation.set(number as i64);
        self.metrics.published.inc();
        drop(state);
        // Free the displaced generation outside the lock so readers never wait on it.
        drop(replaced);
    }
}

/// Publication metrics.
struct Metrics {
    /// Number of the latest published generation.
    generation: Registered<Gauge>,
    /// Generations published since startup.
    published: Registered<Counter>,
}

impl Metrics {
    fn register<E: RuntimeMetrics>(context: &E) -> Self {
        let generation = context.register(
            "published_generation",
            "Number of the latest published generation, or -1 when nothing is servable",
            Gauge::default(),
        );
        generation.set(-1);
        Self {
            generation,
            published: context.register(
                "publications",
                "Generations published since startup",
                Counter::default(),
            ),
        }
    }
}

/// The writer's handle: stages generations and publishes them.
///
/// Dropping it detaches every reader.
pub(crate) struct Publisher<S> {
    slot: Arc<Slot<S>>,
    next_generation: u64,
}

impl<S> Publisher<S> {
    /// Create a publisher and its reader.
    pub(crate) fn new<E: RuntimeMetrics>(context: &E) -> (Self, SetReader<S>) {
        let slot = Arc::new(Slot {
            state: Mutex::new(State::Empty),
            metrics: Metrics::register(context),
        });
        let publisher = Self {
            slot: slot.clone(),
            next_generation: 0,
        };
        (publisher, SetReader { slot })
    }

    /// Stage `snapshots` as the next generation.
    ///
    /// Stage in apply order, and publish only once the generation is durable.
    pub(crate) fn stage(&mut self, snapshots: S) -> Staged<S> {
        let number = self.next_generation;
        self.next_generation += 1;
        Staged {
            slot: self.slot.clone(),
            generation: Arc::new(Generation { number, snapshots }),
        }
    }

    /// Stage and publish in one step, for state that is already durable.
    pub(crate) fn publish_durable(&mut self, snapshots: S) {
        self.stage(snapshots).publish();
    }
}

impl<S> Drop for Publisher<S> {
    fn drop(&mut self) {
        // Free the displaced generation outside the lock.
        let mut state = self.slot.state.lock();
        let replaced = std::mem::replace(&mut *state, State::Detached);
        self.slot.metrics.generation.set(-1);
        drop(state);
        drop(replaced);
    }
}

/// A staged generation, not yet published.
///
/// Dropping it skips the generation. Later ones still publish.
pub(crate) struct Staged<S> {
    slot: Arc<Slot<S>>,
    generation: Arc<Generation<S>>,
}

impl<S> Staged<S> {
    /// Publish the staged generation unless a newer one already published.
    pub(super) fn publish(self) {
        self.slot.publish(self.generation);
    }
}

/// A reader's handle to the latest published generation.
///
/// Cloned freely. Public only so set implementations can name it in
/// [`super::DatabaseSet::readers`]. Everything it can do is crate-internal.
pub struct SetReader<S> {
    slot: Arc<Slot<S>>,
}

impl<S> Clone for SetReader<S> {
    fn clone(&self) -> Self {
        Self {
            slot: self.slot.clone(),
        }
    }
}

impl<S> SetReader<S> {
    /// The latest published generation, or `None` before the first publish or after
    /// the publisher drops.
    pub(crate) fn latest(&self) -> Option<Arc<Generation<S>>> {
        match &*self.slot.state.lock() {
            State::Published(generation) => Some(generation.clone()),
            State::Empty | State::Detached => None,
        }
    }
}

/// A [`SetReader`] narrowed to one database.
///
/// Takes the whole set once, so even per-database reads come from a single generation.
pub struct DbReader<S, M> {
    reader: SetReader<S>,
    project: fn(&S) -> &M,
}

impl<S, M> Clone for DbReader<S, M> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            project: self.project,
        }
    }
}

impl<S, M> DbReader<S, M> {
    /// Narrow `reader` to the database `project` selects.
    ///
    /// Public so [`super::DatabaseSet::readers`] is implementable outside this
    /// crate. Readers only see published generations, so nothing here can mutate
    /// the database.
    pub fn new(reader: SetReader<S>, project: fn(&S) -> &M) -> Self {
        Self { reader, project }
    }
}

/// Per-request read handles backed by the latest published generation.
///
/// Readers take one handle per request. The handle is an owned snapshot, so reads
/// never touch the live database.
pub trait ServeSource: Clone + Send + Sync + 'static {
    /// The per-request read handle.
    type Serve: Send + Sync + 'static;

    /// The handle for the latest published generation, or `None` before the first
    /// publish or after the publisher drops.
    fn latest(&self) -> Option<Self::Serve>;
}

impl<S, M> ServeSource for DbReader<S, M>
where
    S: Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type Serve = M;

    fn latest(&self) -> Option<M> {
        let set = self.reader.latest()?;
        Some((self.project)(set.snapshots()).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};

    /// The value of the `published_generation` gauge.
    fn published_generation(context: &deterministic::Context) -> i64 {
        context
            .encode()
            .lines()
            .find_map(|line| line.strip_prefix("published_generation "))
            .expect("gauge must be registered")
            .parse()
            .expect("gauge must be an integer")
    }

    #[test]
    fn empty_then_live_then_detached() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            assert!(reader.latest().is_none());
            assert_eq!(published_generation(&context), -1);

            publisher.publish_durable(7);
            let first = reader.latest().unwrap();
            assert_eq!(first.number(), 0);
            assert_eq!(*first.snapshots(), 7);
            assert_eq!(published_generation(&context), 0);

            publisher.publish_durable(8);
            let held = reader.latest().unwrap();
            assert_eq!(held.number(), 1);
            assert_eq!(*held.snapshots(), 8);
            assert_eq!(published_generation(&context), 1);

            drop(publisher);
            // New requests decline while the held Arc still serves.
            assert!(reader.latest().is_none());
            assert_eq!(*held.snapshots(), 8);
            assert_eq!(published_generation(&context), -1);
        });
    }

    #[test]
    fn pipelined_publication_is_monotone() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            // Two generations staged before either publishes, as pipelined flushes allow.
            let first = publisher.stage(1);
            let second = publisher.stage(2);

            // The newer generation resolving first must win and stay won.
            second.publish();
            assert_eq!(*reader.latest().unwrap().snapshots(), 2);
            first.publish();
            let live = reader.latest().unwrap();
            assert_eq!(live.number(), 1);
            assert_eq!(*live.snapshots(), 2);
        });
    }

    #[test]
    fn publish_after_publisher_drop_stays_detached() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            // A pool future can outlive the publisher, so its publish must not
            // resurrect a live state.
            let staged = publisher.stage(1);
            drop(publisher);
            staged.publish();
            assert!(reader.latest().is_none());
        });
    }

    #[test]
    fn dropped_stage_skips_a_generation() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            // A shutdown drop of one staged generation must not block later ones.
            drop(publisher.stage(1));
            publisher.publish_durable(2);
            let live = reader.latest().unwrap();
            assert_eq!(live.number(), 1);
            assert_eq!(*live.snapshots(), 2);
        });
    }

    #[test]
    fn db_reader_projects_published_snapshot() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, set_reader) = Publisher::<(u32, u32)>::new(&context);
            let reader: DbReader<(u32, u32), u32> = DbReader::new(set_reader, |set| &set.0);
            assert!(reader.latest().is_none());
            publisher.publish_durable((1, 10));
            assert_eq!(reader.latest(), Some(1));
            publisher.publish_durable((2, 20));
            assert_eq!(reader.latest(), Some(2));
        });
    }
}
