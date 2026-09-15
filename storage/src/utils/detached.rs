//! Test support for detached strategy jobs.

use commonware_codec::{FixedSize, Read, Write};
use commonware_parallel::{Rayon, Strategy as _};
use commonware_utils::sync::Mutex;
use std::{
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

/// Occupy `workers` Rayon workers until the returned sender is dropped.
pub(crate) fn block_strategy(strategy: &Rayon, workers: usize) -> mpsc::Sender<()> {
    // The jobs block until released, so they must never run inline on the calling task.
    let manual = strategy.manual();
    assert!(
        manual.parallelism() >= 2,
        "block_strategy requires a multi-worker pool"
    );
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = Arc::new(Mutex::new(release_rx));
    for _ in 0..workers {
        let started_tx = started_tx.clone();
        let release_rx = Arc::clone(&release_rx);
        drop(manual.spawn(1, move |_| {
            started_tx.send(()).unwrap();
            let _ = release_rx.lock().recv();
        }));
    }
    drop(started_tx);
    for _ in 0..workers {
        started_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("strategy worker did not start");
    }
    release_tx
}

/// An item that preserves `T`'s encoding and reports whether its tracked instance unwound.
#[derive(Write, Read)]
#[read_cfg(T::Cfg)]
pub(crate) struct DropMonitor<T> {
    inner: T,
    #[codec(encode_with = {})]
    #[codec(read_with = { Ok(None) })]
    clean_drop: Option<mpsc::Sender<bool>>,
}

impl<T> DropMonitor<T> {
    /// Create an item that does not report when it is dropped.
    pub(crate) const fn untracked(inner: T) -> Self {
        Self {
            inner,
            clean_drop: None,
        }
    }

    /// Create an item and a receiver that reports whether it was dropped outside an unwind.
    pub(crate) fn tracked(inner: T) -> (Self, mpsc::Receiver<bool>) {
        let (clean_drop, receiver) = mpsc::channel();
        (
            Self {
                inner,
                clean_drop: Some(clean_drop),
            },
            receiver,
        )
    }
}

impl<T: FixedSize> FixedSize for DropMonitor<T> {
    const SIZE: usize = T::SIZE;
}

impl<T> Drop for DropMonitor<T> {
    fn drop(&mut self) {
        if let Some(clean_drop) = self.clean_drop.take() {
            let _ = clean_drop.send(!thread::panicking());
        }
    }
}
