//! Utility functions for interacting with any runtime.

use crate::Error;
#[cfg(test)]
use crate::{Runner, Spawner};
#[cfg(test)]
use futures::stream::{FuturesUnordered, StreamExt};
use futures::{
    channel::oneshot,
    stream::{AbortHandle, Abortable},
    FutureExt,
};
use prometheus_client::metrics::gauge::Gauge;
use std::{
    any::Any,
    collections::HashMap,
    future::Future,
    panic::{resume_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Mutex, Once, RwLock},
    task::{Context, Poll, Waker},
};
use tracing::error;

/// Yield control back to the runtime.
pub async fn reschedule() {
    struct Reschedule {
        yielded: bool,
    }

    impl Future for Reschedule {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    Reschedule { yielded: false }.await
}

fn extract_panic_message(err: &(dyn Any + Send)) -> String {
    if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else {
        format!("{:?}", err)
    }
}

/// Handle to a spawned task.
pub struct Handle<T>
where
    T: Send + 'static,
{
    aborter: AbortHandle,
    receiver: oneshot::Receiver<Result<T, Error>>,

    running: Gauge,
    once: Arc<Once>,
}

impl<T> Handle<T>
where
    T: Send + 'static,
{
    pub(crate) fn init<F>(
        f: F,
        running: Gauge,
        catch_panic: bool,
    ) -> (impl Future<Output = ()>, Self)
    where
        F: Future<Output = T> + Send + 'static,
    {
        // Increment running counter
        running.inc();

        // Initialize channels to handle result/abort
        let once = Arc::new(Once::new());
        let (sender, receiver) = oneshot::channel();
        let (aborter, abort_registration) = AbortHandle::new_pair();

        // Wrap the future to handle panics
        let wrapped = {
            let once = once.clone();
            let running = running.clone();
            async move {
                // Run future
                let result = AssertUnwindSafe(f).catch_unwind().await;

                // Decrement running counter
                once.call_once(|| {
                    running.dec();
                });

                // Handle result
                let result = match result {
                    Ok(result) => Ok(result),
                    Err(err) => {
                        if !catch_panic {
                            resume_unwind(err);
                        }
                        let err = extract_panic_message(&*err);
                        error!(?err, "task panicked");
                        Err(Error::Exited)
                    }
                };
                let _ = sender.send(result);
            }
        };

        // Make the future abortable
        let abortable = Abortable::new(wrapped, abort_registration);
        (
            abortable.map(|_| ()),
            Self {
                aborter,
                receiver,

                running,
                once,
            },
        )
    }

    pub fn abort(&self) {
        // Stop task
        self.aborter.abort();

        // Decrement running counter
        self.once.call_once(|| {
            self.running.dec();
        });
    }
}

impl<T> Future for Handle<T>
where
    T: Send + 'static,
{
    type Output = Result<T, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.receiver)
            .poll(cx)
            .map(|res| res.map_err(|_| Error::Closed).and_then(|r| r))
    }
}

struct StopperInner {
    waiting: HashMap<u128, Waker>,
    stopped: bool,
}

struct Stopper {
    inner: Arc<Mutex<StopperInner>>,
}

impl Stopper {
    pub fn stop(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.stopped = true;
        for (_, waker) in inner.waiting.drain() {
            waker.wake();
        }
    }

    pub fn is_stopped(&self, id: u128) -> impl Future<Output = ()> + Send + 'static {
        Waiter {
            id,
            stopper: self.inner.clone(),
        }
    }
}

struct Waiter {
    id: u128,
    stopper: Arc<Mutex<StopperInner>>,
}

impl Future for Waiter {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut stopper = self.stopper.lock().unwrap();
        if stopper.stopped {
            Poll::Ready(())
        } else {
            stopper.waiting.insert(self.id, cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        let mut stopper = self.stopper.lock().unwrap();
        stopper.waiting.remove(&self.id);
    }
}

#[cfg(test)]
async fn task(i: usize) -> usize {
    for _ in 0..5 {
        reschedule().await;
    }
    i
}

#[cfg(test)]
pub fn run_tasks(tasks: usize, runner: impl Runner, context: impl Spawner) -> Vec<usize> {
    runner.start(async move {
        // Randomly schedule tasks
        let mut handles = FuturesUnordered::new();
        for i in 0..tasks - 1 {
            handles.push(context.spawn("test", task(i)));
        }
        handles.push(context.spawn("test", task(tasks - 1)));

        // Collect output order
        let mut outputs = Vec::new();
        while let Some(result) = handles.next().await {
            outputs.push(result.unwrap());
        }
        assert_eq!(outputs.len(), tasks);
        outputs
    })
}
