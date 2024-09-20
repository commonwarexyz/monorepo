//! Utility functions for interacting with any runtime.

#[cfg(test)]
use crate::Runner;
use crate::{Clock, Error, Spawner};
#[cfg(test)]
use futures::stream::{FuturesUnordered, StreamExt};
use futures::{
    channel::oneshot,
    stream::{AbortHandle, Abortable},
    FutureExt,
};
use std::{
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

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

/// Handle to a spawned task.
pub struct Handle<T>
where
    T: Send + 'static,
{
    aborter: AbortHandle,
    receiver: oneshot::Receiver<Result<T, Error>>,
}

impl<T> Handle<T>
where
    T: Send + 'static,
{
    pub(crate) fn init<F>(f: F) -> (impl Future<Output = ()>, Self)
    where
        F: Future<Output = T> + Send + 'static,
    {
        // Initialize channels to handle result/abort
        let (sender, receiver) = oneshot::channel();
        let (aborter, abort_registration) = AbortHandle::new_pair();

        // Wrap the future to handle panics
        let wrapped = async move {
            let result = AssertUnwindSafe(f).catch_unwind().await;
            let result = match result {
                Ok(result) => Ok(result),
                Err(_) => Err(Error::Exited),
            };
            let _ = sender.send(result);
        };

        // Make the future abortable
        let abortable = Abortable::new(wrapped, abort_registration);
        (abortable.map(|_| ()), Self { aborter, receiver })
    }

    pub fn abort(&self) {
        self.aborter.abort();
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

pub struct Timeout<E, F, T>
where
    E: Clock + Spawner,
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    context: E,
    future: Mutex<Pin<Box<F>>>,
    timeout: SystemTime,
}

pub fn timeout<E, F, T>(context: E, timeout: Duration, future: F) -> Handle<Result<T, Error>>
where
    E: Clock + Spawner,
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let f = Timeout {
        context: context.clone(),
        future: Mutex::new(Box::pin(future)),
        timeout: context.current() + timeout,
    };
    context.spawn(f)
}

impl<E, F, T> Future for Timeout<E, F, T>
where
    E: Clock + Spawner,
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    type Output = Result<T, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Poll the user's future
        match self.future.lock().unwrap().as_mut().poll(cx) {
            Poll::Ready(output) => {
                // Future completed, clean up and return the result
                return Poll::Ready(Ok(output));
            }
            Poll::Pending => {
                // Future not ready yet, continue polling
            }
        }

        // Check if we've timed out
        if self.context.current() >= self.timeout {
            return Poll::Ready(Err(Error::Timeout));
        }

        // Neither future is ready, indicate that we're still pending
        Poll::Pending
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
            handles.push(context.spawn(task(i)));
        }
        handles.push(context.spawn(task(tasks - 1)));

        // Collect output order
        let mut outputs = Vec::new();
        while let Some(result) = handles.next().await {
            outputs.push(result.unwrap());
        }
        assert_eq!(outputs.len(), tasks);
        outputs
    })
}
