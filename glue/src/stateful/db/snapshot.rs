//! Serving the latest published database snapshots.
//!
//! [`Publisher::new`] creates a [`Publisher`] and a [`Subscriber`] over a shared
//! cell containing the latest published snapshots. Snapshots are captured and
//! published when a barrier starts over applied state, or after every finalized
//! block when the set's snapshots are cheap (see
//! [`DatabaseSet::CHEAP_SNAPSHOT`](super::DatabaseSet::CHEAP_SNAPSHOT)). A set with
//! both cheap and costly members refreshes only its cheap members after every
//! finalized block, so its members can serve different heights. Served state may
//! therefore run ahead of disk. That is safe because peers verify
//! everything they fetch against a finalized root, and finalized state survives
//! any local crash by replay. Every publish site labels at the latest applied
//! height, so publication stays monotone (asserted in [`Publisher::publish`]).
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
use std::{mem::replace, sync::Arc};

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
    /// Height at which every member was last published.
    height: Registered<Gauge>,
    /// Height at which the cheap members of a mixed set were last refreshed.
    refreshed: Registered<Gauge>,
    /// Publications since startup.
    published: Registered<Counter>,
}

impl Metrics {
    fn register<E: RuntimeMetrics>(context: &E) -> Self {
        let height = context.register(
            "published_height",
            "Height at which every member was last published, or -1 when nothing is servable",
            Gauge::default(),
        );
        height.set(-1);
        let refreshed = context.register(
            "refreshed_height",
            "Height at which the cheap members of a mixed set were last refreshed, or -1",
            Gauge::default(),
        );
        refreshed.set(-1);
        Self {
            height,
            refreshed,
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

    /// Replace the served set with `snapshots`, every member taken at `height`.
    pub(crate) fn publish(&mut self, height: Height, snapshots: S) {
        self.replace(height, snapshots);
        let _ = self.cell.metrics.height.try_set(height.get());
    }

    /// Replace the served set with `snapshots`, whose cheap members were taken at `height` and
    /// whose other members come from an earlier publication (see
    /// [`DatabaseSet::refresh_cheap`](super::DatabaseSet::refresh_cheap)).
    pub(crate) fn refresh(&mut self, height: Height, snapshots: S) {
        self.replace(height, snapshots);
        let _ = self.cell.metrics.refreshed.try_set(height.get());
    }

    /// The served set, or `None` before the first publish.
    pub(crate) fn served(&self) -> Option<Arc<S>> {
        match &*self.cell.state.lock() {
            State::Published(snapshots) => Some(snapshots.clone()),
            State::Empty | State::Closed => None,
        }
    }

    fn replace(&mut self, height: Height, snapshots: S) {
        assert!(
            self.last_published.is_none_or(|last| height >= last),
            "published height must not regress"
        );
        self.last_published = Some(height);
        let replaced = replace(
            &mut *self.cell.state.lock(),
            State::Published(Arc::new(snapshots)),
        );
        self.cell.metrics.published.inc();

        // Releasing the last reference to a snapshot can close storage handles, so do it
        // after the lock that readers take.
        drop(replaced);
    }
}

impl<S> Drop for Publisher<S> {
    fn drop(&mut self) {
        // Without a publisher the served snapshots would only grow staler. Close
        // the cell so reads decline instead.
        let replaced = replace(&mut *self.cell.state.lock(), State::Closed);
        self.cell.metrics.height.set(-1);
        self.cell.metrics.refreshed.set(-1);
        drop(replaced);
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
    /// after the publisher drops. The members of a set with cheap and costly
    /// members may reflect different heights.
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

    /// The value of the gauge `name`.
    fn gauge(context: &deterministic::Context, name: &str) -> i64 {
        let prefix = format!("{name} ");
        context
            .encode()
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()).map(str::to_string))
            .expect("gauge must be registered")
            .parse()
            .expect("gauge must be an integer")
    }

    /// The value of the `published_height` gauge.
    fn published_height(context: &deterministic::Context) -> i64 {
        gauge(context, "published_height")
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

    /// A refresh replaces the served set without moving the full publication height.
    #[test]
    fn refresh_serves_new_cheap_members() {
        deterministic::Runner::default().start(|context| async move {
            let (mut publisher, subscriber) = Publisher::<(u32, u32)>::new(&context);
            let cheap = subscriber.view(|set| &set.0);
            let costly = subscriber.view(|set| &set.1);
            assert!(publisher.served().is_none());

            publisher.publish(Height::new(1), (1, 10));
            publisher.refresh(Height::new(2), (2, 10));
            assert_eq!(publisher.served().as_deref(), Some(&(2, 10)));
            assert_eq!((cheap.latest(), costly.latest()), (Some(2), Some(10)));
            assert_eq!(published_height(&context), 1);
            assert_eq!(gauge(&context, "refreshed_height"), 2);

            drop(publisher);
            assert!(cheap.latest().is_none());
            assert_eq!(gauge(&context, "refreshed_height"), -1);
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
