//! The runtime context each engine is given.
//!
//! An [`EngineContext`] wraps the deterministic context and names one engine
//! of the run. Every task spawned from it, or from a context derived from it,
//! runs attributed to that engine, so a panic recorded by
//! [`tolerating`](crate::stateful::runner::tolerating) names the engine that
//! raised it. Everything else is forwarded to the wrapped context unchanged,
//! except that the blobs of a paced context may hold their writes (see
//! [`pacing`](super::pacing)).

use super::pacing::{EnginePacing, PacedBlob};
use crate::stateful::runner::attributed;
use commonware_runtime::{
    BlobVersion, Clock, Error, Handle, Metrics, Name, Network, SinkOf, Spawner, Storage, StreamOf,
    Supervisor, deterministic,
    signal::Signal,
    telemetry::metrics::{Metric, Registered},
};
use governor::clock::{Clock as GovernorClock, ReasonablyRealtime};
use rand_core::{TryCryptoRng, TryRng};
use std::{
    fmt::Display,
    future::Future,
    net::SocketAddr,
    ops::RangeInclusive,
    time::{Duration, SystemTime},
};

/// The deterministic context of one engine.
pub(super) struct EngineContext {
    inner: deterministic::Context,
    engine: usize,
    /// The pacing of the blobs opened through this context, or none if the
    /// engine's storage is not paced.
    pacing: Option<EnginePacing>,
}

impl EngineContext {
    /// Wrap `inner` as the context of the engine at index `engine`. Its
    /// storage is not paced.
    pub(super) const fn new(inner: deterministic::Context, engine: usize) -> Self {
        Self {
            inner,
            engine,
            pacing: None,
        }
    }

    /// This context with the writes of every blob opened through it, or
    /// through a context derived from it, paced by `pacing`, or not paced if
    /// there is none.
    pub(super) fn paced(mut self, pacing: Option<EnginePacing>) -> Self {
        self.pacing = pacing;
        self
    }
}

impl Supervisor for EngineContext {
    fn name(&self) -> Name {
        self.inner.name()
    }

    fn child(&self, label: &'static str) -> Self {
        Self {
            inner: self.inner.child(label),
            engine: self.engine,
            pacing: self.pacing.clone(),
        }
    }

    fn with_attribute(self, key: &'static str, value: impl Display) -> Self {
        Self {
            inner: self.inner.with_attribute(key, value),
            engine: self.engine,
            pacing: self.pacing,
        }
    }
}

impl Spawner for EngineContext {
    fn shared(mut self, blocking: bool) -> Self {
        self.inner = self.inner.shared(blocking);
        self
    }

    fn dedicated(mut self) -> Self {
        self.inner = self.inner.dedicated();
        self
    }

    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let engine = self.engine;
        let pacing = self.pacing;
        self.inner.spawn(move |inner| {
            attributed(engine, move || {
                f(Self {
                    inner,
                    engine,
                    pacing,
                })
            })
        })
    }

    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        self.inner.stop(value, timeout).await
    }

    fn stopped(&self) -> Signal {
        self.inner.stopped()
    }
}

impl Metrics for EngineContext {
    fn register<N: Into<String>, H: Into<String>, M: Metric>(
        &self,
        name: N,
        help: H,
        metric: M,
    ) -> Registered<M> {
        self.inner.register(name, help, metric)
    }

    fn encode(&self) -> String {
        self.inner.encode()
    }
}

impl Clock for EngineContext {
    fn current(&self) -> SystemTime {
        self.inner.current()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static + use<> {
        self.inner.sleep(duration)
    }

    fn sleep_until(
        &self,
        deadline: SystemTime,
    ) -> impl Future<Output = ()> + Send + 'static + use<> {
        self.inner.sleep_until(deadline)
    }
}

impl GovernorClock for EngineContext {
    type Instant = SystemTime;

    fn now(&self) -> Self::Instant {
        self.current()
    }
}

impl ReasonablyRealtime for EngineContext {}

impl TryRng for EngineContext {
    type Error = <deterministic::Context as TryRng>::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.inner.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.inner.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.try_fill_bytes(dest)
    }
}

impl TryCryptoRng for EngineContext {}

impl Storage for EngineContext {
    type Blob = PacedBlob<<deterministic::Context as Storage>::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        let (blob, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        Ok((
            PacedBlob::new(blob, self.pacing.as_ref(), partition),
            len,
            version,
        ))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

impl Network for EngineContext {
    type Listener = <deterministic::Context as Network>::Listener;

    async fn bind(&self, socket: SocketAddr) -> Result<Self::Listener, Error> {
        self.inner.bind(socket).await
    }

    async fn dial(&self, socket: SocketAddr) -> Result<(SinkOf<Self>, StreamOf<Self>), Error> {
        self.inner.dial(socket).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dkg::fixtures::raised,
        stateful::runner::{tolerating, unattributed},
    };
    use commonware_runtime::Runner as _;

    /// Run `body` under a runtime that catches task panics and return the
    /// engine and the message of every panic it raised, sorted.
    fn recorded<F, Fut>(body: F) -> Vec<(Option<usize>, String)>
    where
        F: FnOnce(deterministic::Context) -> Fut,
        Fut: Future<Output = ()>,
    {
        let config = deterministic::Config::new().with_catch_panics(true);
        let (result, panics) = tolerating(|| deterministic::Runner::new(config).start(body));
        result.expect("the root task returns");
        let mut recorded = raised(panics);
        recorded.sort();
        recorded
    }

    #[test]
    fn panic_is_attributed_to_the_engine_that_raised_it() {
        let recorded = recorded(|context| async move {
            let first = EngineContext::new(context.child("first"), 1);
            let second = EngineContext::new(context.child("second"), 4);
            drop(first.spawn(|_| async { panic!("one") }));
            drop(second.spawn(|_| async { panic!("four") }));
            drop(context.child("harness").spawn(|_| async { panic!("none") }));
            context.sleep(Duration::from_millis(10)).await;
        });
        assert_eq!(
            recorded,
            vec![
                (None, "none".to_string()),
                (Some(1), "one".to_string()),
                (Some(4), "four".to_string()),
            ]
        );
    }

    #[test]
    fn attribution_follows_derived_contexts_and_nested_tasks() {
        let recorded = recorded(|context| async move {
            let engine = EngineContext::new(context.child("engine"), 3);
            drop(
                engine
                    .child("actor")
                    .with_attribute("epoch", 0)
                    .shared(true)
                    .spawn(|context| async move {
                        // A task the engine's task spawns, after yielding.
                        context.sleep(Duration::from_millis(1)).await;
                        drop(
                            context
                                .child("worker")
                                .dedicated()
                                .spawn(|context| async move {
                                    context.sleep(Duration::from_millis(1)).await;
                                    panic!("nested")
                                }),
                        );
                        std::future::pending::<()>().await;
                    }),
            );
            context.sleep(Duration::from_millis(10)).await;
        });
        assert_eq!(recorded, vec![(Some(3), "nested".to_string())]);
    }

    #[test]
    fn attribution_ends_with_the_poll() {
        let recorded = recorded(|context| async move {
            let engine = EngineContext::new(context.child("engine"), 2);
            let handle = engine.spawn(|context| async move {
                context.sleep(Duration::from_millis(1)).await;
            });
            handle.await.expect("the engine task returns");
            drop(
                context
                    .child("harness")
                    .spawn(|_| async { panic!("after") }),
            );
            context.sleep(Duration::from_millis(10)).await;
        });
        assert_eq!(recorded, vec![(None, "after".to_string())]);
    }

    #[test]
    fn panic_while_building_a_task_is_attributed() {
        let recorded = recorded(|context| async move {
            let engine = EngineContext::new(context.child("engine"), 2);
            drop(context.child("harness").spawn(move |_| async move {
                drop(engine.spawn(|_| -> std::future::Ready<()> { panic!("building") }));
            }));
            context.sleep(Duration::from_millis(10)).await;
        });
        assert_eq!(recorded, vec![(Some(2), "building".to_string())]);
    }

    #[test]
    fn harness_code_an_engine_task_calls_is_not_attributed() {
        let recorded = recorded(|context| async move {
            let engine = EngineContext::new(context.child("engine"), 2);
            drop(engine.spawn(|_| async {
                unattributed(|| panic!("harness"));
            }));
            context.sleep(Duration::from_millis(10)).await;
        });
        assert_eq!(recorded, vec![(None, "harness".to_string())]);
    }

    #[test]
    fn panic_while_an_aborted_task_is_dropped_is_attributed() {
        struct Bomb;

        impl Drop for Bomb {
            fn drop(&mut self) {
                panic!("dropping");
            }
        }

        // The panic leaves the runtime, so only the record is examined.
        let config = deterministic::Config::new().with_catch_panics(true);
        let (_, panics) = tolerating(|| {
            deterministic::Runner::new(config).start(|context| async move {
                let engine = EngineContext::new(context.child("engine"), 2);
                let handle = engine.spawn(|_| async {
                    let _bomb = Bomb;
                    std::future::pending::<()>().await;
                });
                context.sleep(Duration::from_millis(10)).await;
                handle.abort();
                context.sleep(Duration::from_millis(10)).await;
            })
        });
        let engines: Vec<_> = panics.iter().map(|panic| panic.engine).collect();
        assert_eq!(engines, vec![Some(2)]);
    }
}
