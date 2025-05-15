use crate::{utils::extract_panic_message, Error};
use futures::{
    channel::oneshot,
    stream::{AbortHandle, Abortable},
    FutureExt as _,
};
use prometheus_client::metrics::gauge::Gauge;
use std::{
    future::Future,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Once},
    task::{Context, Poll},
};
use tracing::error;

/// Handle to a spawned task.
pub struct Handle<T>
where
    T: Send + 'static,
{
    aborter: Option<AbortHandle>,
    receiver: oneshot::Receiver<Result<T, Error>>,

    running: Gauge,
    once: Arc<Once>,
}

impl<T> Handle<T>
where
    T: Send + 'static,
{
    pub(crate) fn init_future<F>(
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
                aborter: Some(aborter),
                receiver,

                running,
                once,
            },
        )
    }

    pub(crate) fn init_blocking<F>(f: F, running: Gauge, catch_panic: bool) -> (impl FnOnce(), Self)
    where
        F: FnOnce() -> T + Send + 'static,
    {
        // Increment the running tasks gauge
        running.inc();

        // Initialize channel to handle result
        let once = Arc::new(Once::new());
        let (sender, receiver) = oneshot::channel();

        // Wrap the closure with panic handling
        let f = {
            let once = once.clone();
            let running = running.clone();
            move || {
                // Run blocking task
                let result = catch_unwind(AssertUnwindSafe(f));

                // Decrement running counter
                once.call_once(|| {
                    running.dec();
                });

                // Handle result
                let result = match result {
                    Ok(value) => Ok(value),
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

        // Return the task and handle
        (
            f,
            Self {
                aborter: None,
                receiver,

                running,
                once,
            },
        )
    }

    /// Abort the task (if not blocking).
    pub fn abort(&self) {
        // Get aborter and abort
        let Some(aborter) = &self.aborter else {
            return;
        };
        aborter.abort();

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
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(Ok(value))) => {
                self.once.call_once(|| {
                    self.running.dec();
                });
                Poll::Ready(Ok(value))
            }
            Poll::Ready(Ok(Err(err))) => {
                self.once.call_once(|| {
                    self.running.dec();
                });
                Poll::Ready(Err(err))
            }
            Poll::Ready(Err(_)) => {
                self.once.call_once(|| {
                    self.running.dec();
                });
                Poll::Ready(Err(Error::Closed))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
