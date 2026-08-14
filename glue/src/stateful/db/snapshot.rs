//! Serving the latest durable capture of database snapshots.
//!
//! [`Publisher::new`] creates a [`Publisher`] and a [`Reader`] over a shared
//! cell containing the latest durable capture of snapshots.
//!
//! Snapshots are staged as blocks apply, but their flushes finish in any order,
//! and a snapshot may only be served once everything in it is on disk. So the
//! publisher publishes the newest staged snapshot whose flush, and every flush
//! before it, has finished. If one completion makes several snapshots
//! publishable at once, only the newest publishes. The rest are dropped without
//! ever serving.
//!
//! Pruning has one wrinkle: the served snapshot was captured before the prune,
//! so it still holds the pruned storage, and so does everything staged before
//! the prune. The space frees once a snapshot captured after the prune
//! publishes: either a later block's own publish, or a fresh capture once
//! every flush has drained.

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
    /// Height of the latest published capture.
    height: Registered<Gauge>,
    /// Captures published since startup.
    published: Registered<Counter>,
}

impl Metrics {
    fn register<E: RuntimeMetrics>(context: &E) -> Self {
        let height = context.register(
            "published_height",
            "Height of the latest published capture, or -1 when nothing is servable",
            Gauge::default(),
        );
        height.set(-1);
        Self {
            height,
            published: context.register(
                "publications",
                "Captures published since startup",
                Counter::default(),
            ),
        }
    }
}

/// A capture held back from serving until it is safe to publish. That is, it
/// and every earlier capture has durably flushed.
struct Staged<S> {
    /// The snapshots of each database.
    snapshots: S,
    /// Whether this capture's own flush has finished. That alone is not
    /// enough to serve it. Publishing also waits for every earlier flush.
    flushed: bool,
}

/// Publishes the latest durable capture of snapshots to its [`Reader`]s.
pub struct Publisher<S> {
    /// The cell readers take the served capture from.
    cell: Arc<Cell<S>>,
    /// Captures awaiting publication, keyed by height.
    staged: BTreeMap<Height, Staged<S>>,
    /// When a prune runs, this records the highest height staged at that
    /// moment. Every capture at or below it predates the prune, so serving one
    /// still pins the pruned storage. Cleared once a capture
    /// captured after the prune publishes.
    stale_boundary: Option<Height>,
    /// Height of the latest published capture.
    last_published: Option<Height>,
}

impl<S> Publisher<S> {
    /// Create a [`Publisher`] and a [`Reader`] of database set snapshots.
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

    /// Hold `snapshots`, captured at `height`, until it and all earlier
    /// captures have been durably flushed.
    pub fn stage(&mut self, height: Height, snapshots: S) {
        let replaced = self.staged.insert(
            height,
            Staged {
                snapshots,
                flushed: false,
            },
        );
        assert!(replaced.is_none(), "staged height must be unique");
    }

    /// Record that `height`'s flush finished. Returns whether it was durable
    /// (`false` means the runtime shut down mid-flush, so the caller must stop).
    ///
    /// A durable completion publishes the newest snapshot that is now fully on
    /// disk, dropping any older ones still held.
    pub fn complete(&mut self, height: Height, durable: bool) -> bool {
        let staged = self
            .staged
            .get_mut(&height)
            .expect("completed flush must be staged");
        if !durable {
            return false;
        }
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
            return true;
        };
        let pending = self.staged.split_off(&frontier.next());
        let (height, staged) = std::mem::replace(&mut self.staged, pending)
            .pop_last()
            .expect("frontier must be staged");
        self.publish(height, staged.snapshots);
        true
    }

    /// Publish `snapshots`, captured at `height`, immediately.
    ///
    /// Only for state that is already on disk: recovered at startup, synced at
    /// transition, or captured after every flush finished.
    pub fn publish_now(&mut self, height: Height, snapshots: S) {
        assert!(
            self.staged.is_empty(),
            "immediate publication requires every staged flush to have drained",
        );
        self.publish(height, snapshots);
        // A fresh capture never predates a prune, even at the same height.
        self.stale_boundary = None;
    }

    /// Replace the served capture with `snapshots`, taken at `height`.
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
        self.cell.metrics.published.inc();
        // Release the lock before `_replaced` drops at end of scope, so freeing
        // the displaced capture never blocks readers.
        drop(state);

        // Only a snapshot captured after the prune serves post-prune state.
        if self
            .stale_boundary
            .is_some_and(|boundary| height > boundary)
        {
            self.stale_boundary = None;
        }
    }

    /// Whether a flush at or below `barrier` is still running, blocking a prune.
    pub fn blocks_prune(&self, barrier: Height) -> bool {
        self.staged
            .iter()
            .find(|(_, staged)| !staged.flushed)
            .is_some_and(|(height, _)| *height <= barrier)
    }

    /// Mark the served snapshot stale after a prune. Returns false when nothing
    /// is staged, so the caller must publish a fresh capture immediately.
    pub fn mark_stale(&mut self) -> bool {
        self.stale_boundary = self.staged.keys().last().copied();
        self.stale_boundary.is_some()
    }

    /// Whether the caller must capture a new snapshot of the databases and
    /// [`publish_now`](Self::publish_now): the served capture is stale from
    /// a prune, and nothing staged remains to replace it.
    pub fn needs_refresh(&self) -> bool {
        self.stale_boundary.is_some() && self.staged.is_empty()
    }
}

impl<S> Drop for Publisher<S> {
    fn drop(&mut self) {
        // Without a publisher the last capture would only grow staler, so
        // close the cell: reads decline rather than serve unboundedly old state.
        let mut state = self.cell.state.lock();
        let _replaced = std::mem::replace(&mut *state, State::Closed);
        self.cell.metrics.height.set(-1);
        // Release the lock before `_replaced` drops at end of scope.
        drop(state);
    }
}

/// Reads the latest published capture of snapshots.
pub struct Reader<S, M = S> {
    /// The cell containing the latest published capture of snapshots.
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
    /// Derive a reader for the part of each capture that `view` returns.
    pub fn view<M>(&self, view: fn(&S) -> &M) -> Reader<S, M> {
        Reader {
            cell: self.cell.clone(),
            view,
        }
    }
}

impl<S, M> Reader<S, M> {
    /// The latest published capture, or `None` before the first publish or
    /// after the publisher drops.
    pub fn latest(&self) -> Option<M>
    where
        M: Clone,
    {
        let capture = match &*self.cell.state.lock() {
            State::Published(capture) => capture.clone(),
            State::Empty | State::Closed => return None,
        };
        Some((self.view)(&capture).clone())
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

            // Height 6 lands first: the frontier is stuck behind 5.
            assert!(publisher.complete(Height::new(6), true));
            assert!(reader.latest().is_none());

            // Height 5 lands: the frontier jumps to 6, superseding 5 unseen.
            assert!(publisher.complete(Height::new(5), true));
            assert_eq!(reader.latest(), Some(60));

            assert!(publisher.complete(Height::new(7), true));
            assert_eq!(reader.latest(), Some(70));
        });
    }

    #[test]
    fn non_durable_completion_publishes_nothing() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            publisher.stage(Height::new(1), 10);
            assert!(!publisher.complete(Height::new(1), false));
            assert!(reader.latest().is_none());
        });
    }

    #[test]
    fn prune_blocks_on_pending_flushes_only() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, _reader) = Publisher::<u32>::new(&context);
            publisher.stage(Height::new(1), 10);
            publisher.stage(Height::new(2), 20);
            assert!(publisher.blocks_prune(Height::new(1)));
            assert!(publisher.complete(Height::new(1), true));
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
            assert!(publisher.complete(Height::new(1), true));

            // Prune with height 2 still pending: its capture predates the prune,
            // so its publish must not clear the staleness.
            assert!(publisher.mark_stale());
            assert!(!publisher.needs_refresh());
            assert!(publisher.complete(Height::new(2), true));
            assert_eq!(reader.latest(), Some(20));
            assert!(publisher.needs_refresh());

            // The fresh capture publishes at the same height.
            publisher.publish_now(Height::new(2), 21);
            assert_eq!(reader.latest(), Some(21));
            assert!(!publisher.needs_refresh());
        });
    }

    #[test]
    fn later_flush_publishes_a_post_prune_capture() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, reader) = Publisher::<u32>::new(&context);
            publisher.stage(Height::new(2), 20);
            assert!(publisher.mark_stale());

            // Height 3's capture postdates the prune, so its publish clears the
            // staleness without a separate capture.
            publisher.stage(Height::new(3), 30);
            assert!(publisher.complete(Height::new(2), true));
            assert!(!publisher.needs_refresh());
            assert!(publisher.complete(Height::new(3), true));
            assert_eq!(reader.latest(), Some(30));
            assert!(!publisher.needs_refresh());
        });
    }
}
