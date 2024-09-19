//! Utility functions for interacting with any runtime.

#[cfg(test)]
use crate::{Runner, Spawner};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(test)]
use tokio::sync::mpsc;

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

#[cfg(test)]
async fn task(name: String, messages: mpsc::UnboundedSender<String>) {
    for _ in 0..5 {
        reschedule().await;
    }
    messages.send(name).unwrap();
}

#[cfg(test)]
pub fn run_tasks(tasks: usize, runner: impl Runner, context: impl Spawner) -> Vec<String> {
    runner.start(async move {
        // Randomly schedule tasks
        let (sender, mut receiver) = mpsc::unbounded_channel();
        for i in 0..tasks - 1 {
            context.spawn(task(format!("Task {}", i), sender.clone()));
        }
        context.spawn(task(format!("Task {}", tasks - 1), sender));

        // Collect output order
        let mut outputs = Vec::new();
        while let Some(message) = receiver.recv().await {
            outputs.push(message);
        }
        assert_eq!(outputs.len(), tasks);
        outputs
    })
}
