#[cfg(test)]
use crate::{Runner, Spawner};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
#[cfg(test)]
use tokio::sync::mpsc;

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
pub fn run_work(runner: impl Runner, context: impl Spawner) -> Vec<&'static str> {
    async fn work(name: &'static str, messages: mpsc::UnboundedSender<&'static str>) {
        for _ in 0..5 {
            reschedule().await;
        }
        messages.send(name).unwrap();
    }
    runner.start(async move {
        // Randomly schedule tasks
        let (sender, mut receiver) = mpsc::unbounded_channel();
        context.spawn(work("Task 1", sender.clone()));
        context.spawn(work("Task 2", sender.clone()));
        context.spawn(work("Task 3", sender));

        // Collect output order
        let mut outputs = Vec::new();
        while let Some(message) = receiver.recv().await {
            outputs.push(message);
        }
        assert_eq!(outputs.len(), 3);
        outputs
    })
}
