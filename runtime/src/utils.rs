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
    future::Future,
    panic::{resume_unwind, AssertUnwindSafe},
    path::{Component, PathBuf},
    pin::Pin,
    sync::{Arc, Once},
    task::{Context, Poll},
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

pub fn extract_crate_from_caller(caller: &str) -> String {
    // Parse the path and reverse it to search upwards.
    let caller = caller.replace('\\', "/");
    let path = PathBuf::from(caller);
    let mut components = path.components().collect::<Vec<_>>();
    components.reverse();

    // Look for the first "src" component with a parent directory.
    let mut found_src = false;
    for component in components {
        match component {
            Component::Normal(os_str) => {
                let part = os_str.to_string_lossy();
                if found_src {
                    return part.into_owned();
                } else if part == "src" {
                    found_src = true;
                }
            }
            _ => continue,
        }
    }

    // If no "src" was found, return "unknown".
    "unknown".into()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_src_in_path() {
        // Scenario where "src" is in the path and there's a parent directory.
        let file_path = "/home/user/my_crate/src/lib.rs";
        let crate_name = extract_crate_from_caller(file_path);
        assert_eq!(crate_name, "my_crate");
    }

    #[test]
    fn test_without_src_in_path() {
        // Scenario where "src" is not in the path but the path is not empty.
        let file_path = "/home/user/other_crate/main.rs";
        let crate_name = extract_crate_from_caller(file_path);
        assert_eq!(crate_name, "unknown");
    }

    #[test]
    fn test_with_src_at_root() {
        // Scenario where "src" is the first element in the path.
        let file_path = "src/lib.rs";
        let crate_name = extract_crate_from_caller(file_path);
        assert_eq!(crate_name, "unknown");
    }

    #[test]
    fn test_with_empty_path() {
        // Scenario where the file path is empty.
        let file_path = "";
        let crate_name = extract_crate_from_caller(file_path);
        assert_eq!(crate_name, "unknown");
    }

    #[test]
    fn test_with_only_src() {
        // Scenario where the file path is only "src".
        let file_path = "src";
        let crate_name = extract_crate_from_caller(file_path);
        assert_eq!(crate_name, "unknown");
    }

    #[test]
    fn test_with_multiple_src_in_path() {
        // Scenario with multiple "src" occurrences in the path.
        let file_path = "/home/user/src/my_crate/src/lib.rs";
        let crate_name = extract_crate_from_caller(file_path);
        // It should find the first "src" with a parent directory.
        assert_eq!(crate_name, "my_crate");
    }

    #[test]
    fn test_windows_path() {
        // Scenario with Windows-style path separators.
        let file_path = r"C:\Users\User\my_crate\src\lib.rs";
        let crate_name = extract_crate_from_caller(file_path);
        assert_eq!(crate_name, "my_crate");
    }

    #[test]
    fn test_with_no_parent_before_src() {
        // Scenario where "src" is at the beginning with no parent directory.
        let file_path = "/src/lib.rs";
        let crate_name = extract_crate_from_caller(file_path);
        assert_eq!(crate_name, "unknown");
    }

    #[test]
    fn test_with_nested_src_directories() {
        // Scenario with nested "src" directories.
        let file_path = "/home/user/my_crate/src/nested/src/lib.rs";
        let crate_name = extract_crate_from_caller(file_path);
        // It should return "nested" from the first "src" occurrence.
        assert_eq!(crate_name, "nested");
    }

    #[test]
    fn test_with_nonstandard_structure() {
        // Scenario where the structure doesn't follow the standard.
        let file_path = "/some/odd/path/without/src/anywhere";
        let crate_name = extract_crate_from_caller(file_path);
        assert_eq!(crate_name, "without");
    }
}
