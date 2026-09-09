//! Serving the latest published database snapshots.
//!
//! [`Publisher::new`] creates a [`Publisher`] and a [`Subscriber`] over a shared
//! cell containing the latest published snapshots. Each finalization publishes
//! its snapshots as soon as the block applies, so served state may run ahead of
//! disk. That is safe because peers verify everything they fetch against a
//! finalized root, and finalized state survives any local crash by replay.
//! Publication is monotone by construction, since finalizations arrive in
//! order.
//!
//! A prune leaves the served snapshots pinning the pruned storage, so the prune
//! path captures and publishes fresh snapshots right after pruning.

use commonware_consensus::types::Height;
use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{GaugeExt as _, Registered},
};
use commonware_utils::sync::Mutex;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::sync::Arc;

enum State<S> {
    Empty,
    Published(Arc<S>),
    Closed,
}

/// Shared between the [`Publisher`] and its [`Subscriber`]s.
struct Cell<S> {
    state: Mutex<State<S>>,
    metrics: Metrics,
}

/// Publication metrics.
struct Metrics {
    /// Height of the latest published snapshots.
    height: Registered<Gauge>,
    /// Publications since startup.
    published: Registered<Counter>,
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
            published: context.register(
                "publications",
                "Publications since startup",
                Counter::default(),
            ),
        }
    }
}

/// Publishes the latest snapshots to its [`Subscriber`]s.
pub struct Publisher<S> {
    /// The cell subscribers take the served snapshots from.
    cell: Arc<Cell<S>>,
    /// Height of the latest published snapshots.
    last_published: Option<Height>,
}

impl<S> Publisher<S> {
    /// Create a [`Publisher`] and a [`Subscriber`] of the published values.
    pub fn new<E: RuntimeMetrics>(context: &E) -> (Self, Subscriber<S>) {
        let cell = Arc::new(Cell {
            state: Mutex::new(State::Empty),
            metrics: Metrics::register(context),
        });
        (
            Self {
                cell: cell.clone(),
                last_published: None,
            },
            Subscriber {
                cell,
                view: |snapshots| snapshots,
            },
        )
    }

    /// Replace the served set with `snapshots`, taken at `height`.
    pub(crate) fn publish(&mut self, height: Height, snapshots: S) {
        assert!(
            self.last_published.is_none_or(|last| height >= last),
            "published height must not regress"
        );
        self.last_published = Some(height);
        *self.cell.state.lock() = State::Published(Arc::new(snapshots));
        let _ = self.cell.metrics.height.try_set(height.get());
        self.cell.metrics.published.inc();
    }
}

impl<S> Drop for Publisher<S> {
    fn drop(&mut self) {
        // Without a publisher the served snapshots would only grow staler. Close
        // the cell so reads decline instead.
        *self.cell.state.lock() = State::Closed;
        self.cell.metrics.height.set(-1);
    }
}

/// Reads the latest published snapshots.
pub struct Subscriber<S, M = S> {
    /// The cell containing the latest published snapshots.
    cell: Arc<Cell<S>>,
    /// A function to select a part of the snapshot set.
    view: fn(&S) -> &M,
}

impl<S, M> Clone for Subscriber<S, M> {
    fn clone(&self) -> Self {
        Self {
            cell: self.cell.clone(),
            view: self.view,
        }
    }
}

impl<S> Subscriber<S> {
    /// Derive a subscriber for the part of each snapshot set that `view` returns.
    pub fn view<M>(&self, view: fn(&S) -> &M) -> Subscriber<S, M> {
        Subscriber {
            cell: self.cell.clone(),
            view,
        }
    }
}

impl<S, M> Subscriber<S, M> {
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
            let (mut publisher, subscriber) = Publisher::<u32>::new(&context);
            assert!(subscriber.latest().is_none());
            assert_eq!(published_height(&context), -1);

            publisher.publish(Height::new(1), 7);
            assert_eq!(subscriber.latest(), Some(7));
            assert_eq!(published_height(&context), 1);

            publisher.publish(Height::new(2), 8);
            assert_eq!(subscriber.latest(), Some(8));
            assert_eq!(published_height(&context), 2);

            // A snapshot taken before the publisher drops keeps working.
            let held = subscriber.latest().unwrap();
            drop(publisher);
            assert!(subscriber.latest().is_none());
            assert_eq!(held, 8);
            assert_eq!(published_height(&context), -1);
        });
    }

    #[test]
    fn viewed_subscriber_serves_its_part_of_the_snapshot() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, subscriber) = Publisher::<(u32, u32)>::new(&context);
            let first_db = subscriber.view(|set| &set.0);
            assert!(first_db.latest().is_none());
            publisher.publish(Height::new(1), (1, 10));
            assert_eq!(first_db.latest(), Some(1));
            publisher.publish(Height::new(2), (2, 20));
            assert_eq!(first_db.latest(), Some(2));
        });
    }
}
