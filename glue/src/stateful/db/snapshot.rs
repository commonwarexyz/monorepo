//! Serving the latest durable snapshots of the databases.
//!
//! [`Publisher::new`] creates a [`Publisher`] and a [`Reader`] over a shared
//! cell holding the latest published snapshots, one per database, captured
//! together at one height.
//!
//! Snapshots are captured as blocks apply, but their flushes finish in any
//! order, and snapshots may only be served once everything in them is on disk.
//! So the publisher publishes the newest staged snapshots whose flush, and
//! every flush before it, has finished. If one completion makes several
//! heights publishable at once, only the newest publishes and the rest are
//! dropped without ever serving.
//!
//! Pruning has one wrinkle. The served snapshots were captured before the
//! prune, so they still hold the pruned storage, and so does everything staged
//! before the prune. The space frees once snapshots captured after the prune
//! publish, either from a later block or from a fresh capture once every
//! flush has drained.

use commonware_consensus::types::Height;
use commonware_runtime::{Metrics as RuntimeMetrics, telemetry::metrics::Registered};
use commonware_utils::sync::Mutex;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{collections::BTreeMap, sync::Arc};

enum State<S> {
    Empty,
    Published(Arc<S>),
    Closed,
}

/// Shared between the [`Publisher`] and its [`Reader`]s.
struct Cell<S> {
    state: Mutex<State<S>>,
    metrics: Metrics,
}

/// Publication metrics.
struct Metrics {
    /// Height of the latest published snapshots.
    height: Registered<Gauge>,
    /// Publications since startup.
    publications: Registered<Counter>,
}

impl Metrics {
    fn register<E: RuntimeMetrics>(context: &E) -> Self {
        let height = context.register(
            "published_height",
            "Height of the latest published snapshots, or -1 when nothing is servable",
            Gauge::default(),
        );
        height.set(-1);
        Self {
            height,
            publications: context.register(
                "publications",
                "Snapshot publications since startup",
                Counter::default(),
            ),
        }
    }
}

/// Snapshots held back from serving until they and everything captured
/// before them have durably flushed.
struct Staged<S> {
    /// The snapshots of each database.
    snapshots: S,
    /// Whether these snapshots' own flush has finished. Publishing also
    /// waits for every earlier flush.
    flushed: bool,
}

/// Publishes the latest durable snapshots to its [`Reader`]s.
pub struct Publisher<S> {
    /// The cell readers take the served snapshots from.
    cell: Arc<Cell<S>>,
    /// Snapshots waiting to publish, keyed by capture height.
    staged: BTreeMap<Height, Staged<S>>,
    /// When a prune runs, this records the highest height captured at that
    /// moment, staged or already served. Snapshots captured at or below it
    /// predate the prune, so serving them still pins the pruned storage.
    /// Cleared once snapshots captured after the prune publish.
    stale_boundary: Option<Height>,
    /// Height of the latest published snapshots.
    last_published: Option<Height>,
}

impl<S> Publisher<S> {
    /// Create a [`Publisher`] and a [`Reader`] of what it publishes.
    pub fn new<E: RuntimeMetrics>(context: &E) -> (Self, Reader<S>) {
        let cell = Arc::new(Cell {
            state: Mutex::new(State::Empty),
            metrics: Metrics::register(context),
        });
        (
            Self {
                cell: cell.clone(),
                staged: BTreeMap::new(),
                stale_boundary: None,
                last_published: None,
            },
            Reader {
                cell,
                view: |snapshots| snapshots,
            },
        )
    }

    /// Hold `snapshots`, captured at `height`, until they and all
    /// earlier-captured snapshots have been durably flushed.
    pub(crate) fn stage(&mut self, height: Height, snapshots: S) {
        let replaced = self.staged.insert(
            height,
            Staged {
                snapshots,
                flushed: false,
            },
        );
        assert!(replaced.is_none(), "staged height must be unique");
    }

    /// Record that `height`'s flush finished durably, publishing the newest
    /// snapshots that are now fully on disk and dropping any older ones still
    /// held.
    pub(crate) fn complete(&mut self, height: Height) {
        let staged = self
            .staged
            .get_mut(&height)
            .expect("completed flush must be staged");
        staged.flushed = true;

        // The newest staged height whose flush, and every flush before it,
        // has finished.
        let Some(frontier) = self
            .staged
            .iter()
            .take_while(|(_, staged)| staged.flushed)
            .map(|(height, _)| *height)
            .last()
        else {
            return;
        };
        let pending = self.staged.split_off(&frontier.next());
        let (height, staged) = std::mem::replace(&mut self.staged, pending)
            .pop_last()
            .expect("frontier must be staged");
        self.publish(height, staged.snapshots);
    }

    /// Publish `snapshots`, captured at `height`, immediately.
    ///
    /// Only for state that is already on disk, whether recovered at startup,
    /// synced at transition, or captured after every flush finished.
    pub(crate) fn publish_now(&mut self, height: Height, snapshots: S) {
        assert!(
            self.staged.is_empty(),
            "immediate publication requires every staged flush to have drained",
        );
        self.publish(height, snapshots);
        // Freshly captured snapshots never predate a prune, even at the same
        // height.
        self.stale_boundary = None;
    }

    /// Replace the served snapshots with `snapshots`, captured at `height`.
    fn publish(&mut self, height: Height, snapshots: S) {
        assert!(
            self.last_published.is_none_or(|last| height >= last),
            "published height must not regress"
        );
        self.last_published = Some(height);
        let mut state = self.cell.state.lock();
        let _replaced = std::mem::replace(&mut *state, State::Published(Arc::new(snapshots)));
        // Update metrics under the lock so the gauge matches what readers see.
        self.cell.metrics.height.set(height.get() as i64);
        self.cell.metrics.publications.inc();
        // Release the lock before `_replaced` drops at end of scope, so freeing
        // the displaced snapshots never blocks readers.
        drop(state);

        // A publish only clears the staleness if its snapshots were captured
        // after the prune.
        if self
            .stale_boundary
            .is_some_and(|boundary| height > boundary)
        {
            self.stale_boundary = None;
        }
    }

    /// Whether a flush at or below `barrier` is still running, blocking a prune.
    pub(crate) fn blocks_prune(&self, barrier: Height) -> bool {
        self.staged
            .iter()
            .find(|(_, staged)| !staged.flushed)
            .is_some_and(|(height, _)| *height <= barrier)
    }

    /// Mark all snapshots captured so far, staged or served, as predating a
    /// prune. Check [`needs_refresh`](Self::needs_refresh) afterwards.
    pub(crate) fn mark_stale(&mut self) {
        self.stale_boundary = self.staged.keys().last().copied().or(self.last_published);
    }

    /// Whether the caller must capture fresh snapshots and
    /// [`publish_now`](Self::publish_now). True when the served snapshots are
    /// stale from a prune and nothing staged remains to replace them.
    pub(crate) fn needs_refresh(&self) -> bool {
        self.stale_boundary.is_some() && self.staged.is_empty()
    }
}

impl<S> Drop for Publisher<S> {
    fn drop(&mut self) {
        // Without a publisher the last snapshots would only grow staler, so
        // close the cell and let reads decline instead.
        let mut state = self.cell.state.lock();
        let _replaced = std::mem::replace(&mut *state, State::Closed);
        self.cell.metrics.height.set(-1);
        // Release the lock before `_replaced` drops at end of scope.
        drop(state);
    }
}

/// Reads the latest published snapshots.
pub struct Reader<S, M = S> {
    /// The cell containing the latest published snapshots.
    cell: Arc<Cell<S>>,
    /// A function to select a part of the snapshot set.
    view: fn(&S) -> &M,
}

impl<S, M> Clone for Reader<S, M> {
    fn clone(&self) -> Self {
        Self {
            cell: self.cell.clone(),
            view: self.view,
        }
    }
}

impl<S> Reader<S> {
    /// Derive a reader for the part of the snapshot set that `view` returns.
    pub fn view<M>(&self, view: fn(&S) -> &M) -> Reader<S, M> {
        Reader {
            cell: self.cell.clone(),
            view,
        }
    }
}

impl<S, M> Reader<S, M> {
    /// The latest published snapshots, or `None` before the first publish or
    /// after the publisher drops.
    pub fn latest(&self) -> Option<M>
    where
        M: Clone,
    {
        let snapshots = match &*self.cell.state.lock() {
            State::Published(snapshots) => snapshots.clone(),
            State::Empty | State::Closed => return None,
        };
        Some((self.view)(&snapshots).clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};

    /// The value of the `published_height` gauge.
    fn published_height(context: &deterministic::Context) -> i64 {
        context
            .encode()
            .lines()
            .find_map(|line| line.strip_prefix("published_height "))
            .expect("gauge must be registered")
            .parse()
            .expect("gauge must be an integer")
    }

    #[test]
    fn empty_then_live_then_closed() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            assert!(reader.latest().is_none());
            assert_eq!(published_height(&context), -1);

            publisher.publish_now(Height::new(1), 7);
            assert_eq!(reader.latest(), Some(7));
            assert_eq!(published_height(&context), 1);

            publisher.publish_now(Height::new(2), 8);
            assert_eq!(reader.latest(), Some(8));
            assert_eq!(published_height(&context), 2);

            // A snapshot taken before the publisher drops keeps working.
            let held = reader.latest().unwrap();
            drop(publisher);
            assert!(reader.latest().is_none());
            assert_eq!(held, 8);
            assert_eq!(published_height(&context), -1);
        });
    }

    #[test]
    fn viewed_reader_serves_its_part_of_the_snapshot() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<(u32, u32)>::new(&context);
            let first_db = reader.view(|set| &set.0);
            assert!(first_db.latest().is_none());
            publisher.publish_now(Height::new(1), (1, 10));
            assert_eq!(first_db.latest(), Some(1));
            publisher.publish_now(Height::new(2), (2, 20));
            assert_eq!(first_db.latest(), Some(2));
        });
    }

    #[test]
    fn publishes_at_the_durable_frontier() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            publisher.stage(Height::new(5), 50);
            publisher.stage(Height::new(6), 60);
            publisher.stage(Height::new(7), 70);
            assert!(reader.latest().is_none());

            // Height 6 lands first, so nothing publishes while 5 is pending.
            publisher.complete(Height::new(6));
            assert!(reader.latest().is_none());

            // Height 5 lands and 6 publishes, superseding 5 unseen.
            publisher.complete(Height::new(5));
            assert_eq!(reader.latest(), Some(60));

            publisher.complete(Height::new(7));
            assert_eq!(reader.latest(), Some(70));
        });
    }

    #[test]
    fn prune_blocks_on_pending_flushes_only() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, _reader) = Publisher::<u32>::new(&context);
            publisher.stage(Height::new(1), 10);
            publisher.stage(Height::new(2), 20);
            assert!(publisher.blocks_prune(Height::new(1)));
            publisher.complete(Height::new(1));
            assert!(!publisher.blocks_prune(Height::new(1)));
            assert!(publisher.blocks_prune(Height::new(2)));
        });
    }

    #[test]
    fn staleness_clears_only_above_the_boundary() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            publisher.stage(Height::new(1), 10);
            publisher.stage(Height::new(2), 20);
            publisher.complete(Height::new(1));

            // Height 2 is still pending when the prune runs, so its snapshots
            // predate the prune and their publish must not clear the staleness.
            publisher.mark_stale();
            assert!(!publisher.needs_refresh());
            publisher.complete(Height::new(2));
            assert_eq!(reader.latest(), Some(20));
            assert!(publisher.needs_refresh());

            // Freshly captured snapshots publish at the same height.
            publisher.publish_now(Height::new(2), 21);
            assert_eq!(reader.latest(), Some(21));
            assert!(!publisher.needs_refresh());
        });
    }

    #[test]
    fn later_flush_publishes_post_prune_snapshots() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            publisher.stage(Height::new(2), 20);
            publisher.mark_stale();

            // Height 3 was captured after the prune, so its publish clears
            // the staleness without a fresh capture.
            publisher.stage(Height::new(3), 30);
            publisher.complete(Height::new(2));
            assert!(!publisher.needs_refresh());
            publisher.complete(Height::new(3));
            assert_eq!(reader.latest(), Some(30));
            assert!(!publisher.needs_refresh());
        });
    }

    #[test]
    fn prune_with_nothing_staged_requires_a_refresh() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            publisher.publish_now(Height::new(1), 10);

            // Nothing is staged, so only freshly captured snapshots can
            // replace the served ones, at the same height.
            publisher.mark_stale();
            assert!(publisher.needs_refresh());
            publisher.publish_now(Height::new(1), 11);
            assert_eq!(reader.latest(), Some(11));
            assert!(!publisher.needs_refresh());
        });
    }
}
