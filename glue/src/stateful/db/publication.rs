//! Publishing database snapshots from the writer to readers.
//!
//! [`Publisher::new`] creates a [`Publisher`] and a [`Reader`] over one shared
//! slot. The writer stages each generation of snapshots (numbered in apply order) and
//! publishes it once its flush proves durable, so readers only ever see durable
//! state. Publication is monotonic: flushes finishing out of order never move
//! readers backward.
//!
//! A [`Reader`] takes the latest published generation once per request. The reader
//! from [`Publisher::new`] sees the whole snapshot set; [`view`](Reader::view) makes
//! readers for its parts, one per database. A take never mixes generations and
//! never changes afterward. A reader yields nothing before the first publish and
//! nothing after the publisher drops (crash and clean shutdown look the same to
//! readers), but snapshots already taken keep working.

use commonware_runtime::{Metrics as RuntimeMetrics, telemetry::metrics::Registered};
use commonware_utils::sync::Mutex;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::sync::Arc;

/// Every database's snapshot, captured at the same apply boundary and numbered
/// in staging order.
#[derive(Debug)]
struct Generation<S> {
    /// Monotonic generation number.
    number: u64,
    /// The generation's snapshots.
    snapshots: S,
}

enum State<S> {
    Empty,
    Published(Arc<Generation<S>>),
    Detached,
}

/// Shared between the [`Publisher`] and its [`Reader`]s.
struct Slot<S> {
    state: Mutex<State<S>>,
    metrics: Metrics,
}

impl<S> Slot<S> {
    /// Publish `generation` unless a newer one is already published.
    fn publish(&self, generation: Arc<Generation<S>>) {
        let number = generation.number;
        let mut state = self.state.lock();
        let _replaced = match &*state {
            State::Detached => return,
            State::Published(published) if published.number > number => return,
            State::Empty | State::Published(_) => {
                std::mem::replace(&mut *state, State::Published(generation))
            }
        };
        // Update metrics under the lock so the gauge matches what readers see.
        self.metrics.generation.set(number as i64);
        self.metrics.published.inc();
        // Release the lock before `_replaced` drops at end of scope, so freeing
        // the displaced generation never blocks readers.
        drop(state);
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
pub struct Publisher<S> {
    slot: Arc<Slot<S>>,
    next_generation: u64,
}

impl<S> Publisher<S> {
    /// Create a snapshot [`Publisher`] and a [`Reader`] connected to it.
    ///
    /// Publication metrics register under `context`.
    pub fn new<E: RuntimeMetrics>(context: &E) -> (Self, Reader<S>) {
        let slot = Arc::new(Slot {
            state: Mutex::new(State::Empty),
            metrics: Metrics::register(context),
        });
        (
            Self {
                slot: slot.clone(),
                next_generation: 0,
            },
            Reader {
                slot,
                view: |snapshots| snapshots,
            },
        )
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
        // Without a writer the last generation would only grow staler, so mark
        // the slot detached: reads decline rather than serve unboundedly old state.
        let mut state = self.slot.state.lock();
        let _replaced = std::mem::replace(&mut *state, State::Detached);
        self.slot.metrics.generation.set(-1);
        // Release the lock before `_replaced` drops at end of scope, so freeing
        // the displaced generation never blocks readers.
        drop(state);
    }
}

/// A staged generation, not yet published.
///
/// Dropping it (at shutdown, or when its flush never proves durable) abandons the
/// generation: readers keep what they have, and later generations publish as usual.
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

/// Reads the latest published generation, or one part of it after
/// [`view`](Reader::view).
pub struct Reader<S, M = S> {
    slot: Arc<Slot<S>>,
    view: fn(&S) -> &M,
}

impl<S, M> Clone for Reader<S, M> {
    fn clone(&self) -> Self {
        Self {
            slot: self.slot.clone(),
            view: self.view,
        }
    }
}

impl<S> Reader<S> {
    /// Derive a reader for the part of each generation that `view` returns:
    /// typically one database's snapshot out of the set.
    pub fn view<M>(&self, view: fn(&S) -> &M) -> Reader<S, M> {
        Reader {
            slot: self.slot.clone(),
            view,
        }
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

impl<S, M> ServeSource for Reader<S, M>
where
    S: Send + Sync + 'static,
    M: Clone + Send + Sync + 'static,
{
    type Serve = M;

    fn latest(&self) -> Option<M> {
        let generation = match &*self.slot.state.lock() {
            State::Published(generation) => generation.clone(),
            State::Empty | State::Detached => return None,
        };
        Some((self.view)(&generation.snapshots).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};

    impl<S, M> Reader<S, M> {
        /// The latest published generation's number, or `None` before the first
        /// publish or after the publisher drops.
        pub(crate) fn generation(&self) -> Option<u64> {
            match &*self.slot.state.lock() {
                State::Published(generation) => Some(generation.number),
                State::Empty | State::Detached => None,
            }
        }
    }

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
            assert_eq!(reader.latest(), Some(7));
            assert_eq!(reader.generation(), Some(0));
            assert_eq!(published_generation(&context), 0);

            publisher.publish_durable(8);
            assert_eq!(reader.latest(), Some(8));
            assert_eq!(reader.generation(), Some(1));
            assert_eq!(published_generation(&context), 1);

            drop(publisher);
            assert!(reader.latest().is_none());
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
            assert_eq!(reader.latest(), Some(2));
            first.publish();
            assert_eq!(reader.latest(), Some(2));
            assert_eq!(reader.generation(), Some(1));
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
            assert_eq!(reader.latest(), Some(2));
            assert_eq!(reader.generation(), Some(1));
        });
    }

    #[test]
    fn viewed_reader_serves_its_part_of_the_snapshot() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<(u32, u32)>::new(&context);
            let first_db = reader.view(|set| &set.0);
            assert!(first_db.latest().is_none());
            publisher.publish_durable((1, 10));
            assert_eq!(first_db.latest(), Some(1));
            publisher.publish_durable((2, 20));
            assert_eq!(first_db.latest(), Some(2));
        });
    }
}
