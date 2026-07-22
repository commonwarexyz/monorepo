//! Persist and retrieve data from an abstract store.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

commonware_macros::stability_scope!(BETA, cfg(feature = "std") {
use futures::{stream::FuturesUnordered, StreamExt as _};

async fn indexed_result<Fut, T, E>(index: usize, future: Fut) -> (usize, Result<T, E>)
where
    Fut: std::future::Future<Output = Result<T, E>>,
{
    (index, future.await)
}

/// Runs up to `concurrency` operations at once. After the first observed error, stops scheduling
/// new work but drains every operation already in flight before returning the earliest error in
/// input order among the operations that were started.
async fn try_collect_concurrent<I, F, Fut, T, E>(
    items: I,
    concurrency: std::num::NonZeroUsize,
    mut operation: F,
) -> Result<Vec<T>, E>
where
    I: IntoIterator,
    F: FnMut(I::Item) -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let mut items = items.into_iter();
    let mut pending = FuturesUnordered::new();
    let mut next_index = 0usize;
    while pending.len() < concurrency.get() {
        let Some(item) = items.next() else {
            break;
        };
        pending.push(indexed_result(next_index, operation(item)));
        next_index += 1;
    }

    let mut outputs = Vec::new();
    let mut first_error: Option<(usize, E)> = None;
    while let Some((index, result)) = pending.next().await {
        match result {
            Ok(output) if first_error.is_none() => {
                outputs.push(output);
                if let Some(item) = items.next() {
                    pending.push(indexed_result(next_index, operation(item)));
                    next_index += 1;
                }
            }
            Ok(_) => {}
            Err(error) => {
                if first_error
                    .as_ref()
                    .is_none_or(|(first_index, _)| index < *first_index)
                {
                    first_error = Some((index, error));
                }
            }
        }
    }

    first_error.map_or_else(|| Ok(outputs), |(_, error)| Err(error))
}

#[cfg(test)]
mod concurrent_tests {
    use super::try_collect_concurrent;
    use commonware_utils::sync::Mutex;
    use futures::{channel::oneshot, executor::block_on};
    use std::{
        num::NonZeroUsize,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn test_try_collect_concurrent_drains_without_scheduling_more() {
        let started = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicBool::new(false));
        let scheduled_after_error = Arc::new(AtomicBool::new(false));
        let (release_sender, release_receiver) = oneshot::channel();
        let release_receiver = Arc::new(Mutex::new(Some(release_receiver)));

        let thread_started = started.clone();
        let thread_completed = completed.clone();
        let thread_scheduled_after_error = scheduled_after_error.clone();
        let handle = thread::spawn(move || {
            block_on(try_collect_concurrent(
                0..4,
                NonZeroUsize::new(2).unwrap(),
                move |item| {
                    let started = thread_started.clone();
                    let completed = thread_completed.clone();
                    let scheduled_after_error = thread_scheduled_after_error.clone();
                    let release = (item == 1).then(|| release_receiver.lock().take().unwrap());
                    async move {
                        started.fetch_add(1, Ordering::SeqCst);
                        match item {
                            0 => Err("first error"),
                            1 => {
                                release.unwrap().await.unwrap();
                                completed.store(true, Ordering::SeqCst);
                                Ok(item)
                            }
                            _ => {
                                scheduled_after_error.store(true, Ordering::SeqCst);
                                Ok(item)
                            }
                        }
                    }
                },
            ))
        });

        let deadline = Instant::now() + Duration::from_secs(1);
        while started.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert!(!handle.is_finished(), "in-flight operation was not drained");
        assert!(!scheduled_after_error.load(Ordering::SeqCst));

        release_sender.send(()).unwrap();
        assert_eq!(handle.join().unwrap(), Err("first error"));
        assert!(completed.load(Ordering::SeqCst));
        assert_eq!(started.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_try_collect_concurrent_returns_earliest_started_error() {
        let later_failed = Arc::new(AtomicBool::new(false));
        let (release_sender, release_receiver) = oneshot::channel();

        let thread_later_failed = later_failed.clone();
        let handle = thread::spawn(move || {
            let mut release_receiver = Some(release_receiver);
            block_on(try_collect_concurrent(
                0..2,
                NonZeroUsize::new(2).unwrap(),
                move |item| {
                    let later_failed = thread_later_failed.clone();
                    let release = (item == 0).then(|| release_receiver.take().unwrap());
                    async move {
                        if let Some(release) = release {
                            release.await.unwrap();
                            Err::<(), _>("earlier input error")
                        } else {
                            later_failed.store(true, Ordering::SeqCst);
                            Err::<(), _>("later input error")
                        }
                    }
                },
            ))
        });

        let deadline = Instant::now() + Duration::from_secs(1);
        while !later_failed.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(later_failed.load(Ordering::SeqCst));
        release_sender.send(()).unwrap();
        assert_eq!(handle.join().unwrap(), Err("earlier input error"));
    }
}
});

commonware_macros::stability_scope!(ALPHA {
    extern crate alloc;

    pub mod bmt;
    pub mod merkle;
    pub use merkle::{mmb, mmr};
});
commonware_macros::stability_scope!(ALPHA, cfg(feature = "std") {
    mod bitmap;
    pub mod qmdb;
    pub use crate::bitmap::{BitMap as AuthenticatedBitMap, MerkleizedBitMap, UnmerkleizedBitMap};
    pub mod cache;
    pub mod queue;
    #[cfg(any(test, feature = "test-utils"))]
    pub mod utils;
});
commonware_macros::stability_scope!(BETA, cfg(feature = "std") {
    pub mod archive;
    pub mod freezer;
    pub mod index;
    pub mod journal;
    pub mod metadata;
    pub mod ordinal;
    pub mod rmap;

    /// Section selector for storage operations that act on one or more sections.
    pub trait Sections {
        /// Iterator over selected sections.
        type Iter: Iterator<Item = u64>;

        /// Convert into selected section indices.
        ///
        /// This trait does not impose ordering or uniqueness; each storage operation decides how
        /// to handle duplicates and missing sections.
        fn sections(self) -> Self::Iter;
    }

    impl Sections for u64 {
        type Iter = core::iter::Once<Self>;

        fn sections(self) -> Self::Iter {
            core::iter::once(self)
        }
    }

    impl<const N: usize> Sections for [u64; N] {
        type Iter = core::array::IntoIter<u64, N>;

        fn sections(self) -> Self::Iter {
            self.into_iter()
        }
    }

    impl<'a, const N: usize> Sections for &'a [u64; N] {
        type Iter = core::iter::Copied<core::slice::Iter<'a, u64>>;

        fn sections(self) -> Self::Iter {
            self.iter().copied()
        }
    }

    impl<'a> Sections for &'a [u64] {
        type Iter = core::iter::Copied<core::slice::Iter<'a, u64>>;

        fn sections(self) -> Self::Iter {
            self.iter().copied()
        }
    }

    impl Sections for Vec<u64> {
        type Iter = std::vec::IntoIter<u64>;

        fn sections(self) -> Self::Iter {
            self.into_iter()
        }
    }

    impl<'a> Sections for &'a Vec<u64> {
        type Iter = core::iter::Copied<core::slice::Iter<'a, u64>>;

        fn sections(self) -> Self::Iter {
            self.iter().copied()
        }
    }

    impl Sections for std::collections::BTreeSet<u64> {
        type Iter = std::collections::btree_set::IntoIter<u64>;

        fn sections(self) -> Self::Iter {
            self.into_iter()
        }
    }

    impl<'a> Sections for &'a std::collections::BTreeSet<u64> {
        type Iter = core::iter::Copied<std::collections::btree_set::Iter<'a, u64>>;

        fn sections(self) -> Self::Iter {
            self.iter().copied()
        }
    }

    /// A runtime context providing storage, timing, and metrics capabilities.
    ///
    /// This is a convenience alias for the trait bound `BufferPooler + Storage + Clock + Metrics`
    /// that appears on nearly every type in this crate.
    pub trait Context:
        commonware_runtime::BufferPooler
        + commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics
    {
    }
    impl<
        T: commonware_runtime::BufferPooler
            + commonware_runtime::Storage
            + commonware_runtime::Clock
            + commonware_runtime::Metrics,
    > Context for T
    {
    }
});
commonware_macros::stability_scope!(BETA {
    pub mod translator;
});
