#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::futures::{AbortablePool, Aborter, OptionFuture, Pool};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use std::future::Future;

const MIN_OPERATIONS: usize = 4;
const MAX_OPERATIONS: usize = 64;

#[derive(Debug)]
struct FuzzInput {
    pool_type: PoolType,
    operations: Vec<Operation>,
}

/// `int_in_range(MIN..=MAX)` keeps the op list non-empty and dense even for
/// short inputs; Push is `Operation` variant 0, so an exhausted input's
/// zero-padded tail keeps pushing futures for later completions to drain.
impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let pool_type = PoolType::arbitrary(u)?;
        let num_operations = u.int_in_range(MIN_OPERATIONS..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_operations);
        for _ in 0..num_operations {
            operations.push(Operation::arbitrary(u)?);
        }
        Ok(FuzzInput {
            pool_type,
            operations,
        })
    }
}

#[derive(Arbitrary, Debug)]
enum PoolType {
    Regular,
    Abortable,
}

#[derive(Arbitrary, Debug)]
enum Operation {
    Push { value: i32 },
    NextCompleted { limit: u8 },
    CancelAll,
    CheckLen,
    CheckIsEmpty,
    DefaultOptionFuture,
    ReadyOptionFuture { value: i32 },
}

enum PoolWrapper {
    Regular(Pool<i32>),
    Abortable(AbortablePool<i32>, Vec<Aborter>),
}

impl PoolWrapper {
    fn new(pool_type: PoolType) -> Self {
        match pool_type {
            PoolType::Regular => PoolWrapper::Regular(Pool::default()),
            PoolType::Abortable => PoolWrapper::Abortable(AbortablePool::default(), Vec::new()),
        }
    }

    fn push(&mut self, future: impl std::future::Future<Output = i32> + Send + 'static) {
        match self {
            PoolWrapper::Regular(pool) => {
                pool.push(future);
            }
            PoolWrapper::Abortable(pool, aborters) => {
                let aborter = pool.push(future);
                aborters.push(aborter);
            }
        }
    }

    async fn next_completed(&mut self) -> i32 {
        match self {
            PoolWrapper::Regular(pool) => pool.next_completed().await,
            PoolWrapper::Abortable(pool, _) => pool.next_completed().await.unwrap_or(0),
        }
    }

    fn len(&self) -> usize {
        match self {
            PoolWrapper::Regular(pool) => pool.len(),
            PoolWrapper::Abortable(pool, _) => pool.len(),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            PoolWrapper::Regular(pool) => pool.is_empty(),
            PoolWrapper::Abortable(pool, _) => pool.is_empty(),
        }
    }

    async fn cancel_all(&mut self) {
        match self {
            PoolWrapper::Regular(pool) => {
                pool.cancel_all();
            }
            PoolWrapper::Abortable(pool, aborters) => {
                let num_to_abort = aborters.len();
                aborters.clear();
                for _ in 0..num_to_abort {
                    if !pool.is_empty() {
                        // Aborters were just dropped, so draining yields aborted results.
                        assert!(pool.next_completed().await.is_err());
                    }
                }
            }
        }
    }
}

async fn fuzz(input: FuzzInput) {
    let mut pool = PoolWrapper::new(input.pool_type);
    let mut expected_count = 0;
    let mut completed_count = 0;
    // Multiset of pushed-but-not-yet-completed values: a completion must return a
    // value that was actually pushed (no conjured or duplicated results).
    let mut outstanding: Vec<i32> = Vec::new();

    for op in input.operations {
        match op {
            Operation::Push { value } => {
                pool.push(async move { value });
                outstanding.push(value);
                expected_count += 1;
                assert_eq!(pool.len(), expected_count - completed_count);
            }

            Operation::NextCompleted { limit } => {
                let max_iterations = limit.min(10) as usize;
                for _ in 0..max_iterations {
                    if expected_count > completed_count {
                        let result = pool.next_completed().await;
                        let pos = outstanding
                            .iter()
                            .position(|&v| v == result)
                            .expect("completed value was never pushed");
                        outstanding.swap_remove(pos);
                        completed_count += 1;
                    } else {
                        break;
                    }
                }
            }

            Operation::CancelAll => match &pool {
                PoolWrapper::Abortable(_, _) => {
                    pool.cancel_all().await;
                    expected_count = 0;
                    completed_count = 0;
                    outstanding.clear();
                    continue;
                }
                PoolWrapper::Regular(_) => {
                    pool.cancel_all().await;
                    expected_count = 0;
                    completed_count = 0;
                    outstanding.clear();
                    assert_eq!(pool.len(), 0);
                    assert!(pool.is_empty());
                }
            },

            Operation::CheckLen => {
                assert_eq!(pool.len(), expected_count - completed_count);
            }

            Operation::CheckIsEmpty => {
                assert_eq!(pool.is_empty(), expected_count == completed_count);
            }

            Operation::DefaultOptionFuture => {
                let option_future = OptionFuture::<std::future::Ready<i32>>::default();
                assert!(option_future.is_none());

                let waker = futures::task::noop_waker();
                let mut cx = std::task::Context::from_waker(&waker);
                let mut pinned = Box::pin(option_future);
                assert!(pinned.as_mut().poll(&mut cx).is_pending());
            }

            Operation::ReadyOptionFuture { value } => {
                let option_future = OptionFuture::from(Some(std::future::ready(value)));
                assert!(option_future.is_some());

                let waker = futures::task::noop_waker();
                let mut cx = std::task::Context::from_waker(&waker);
                let mut pinned = Box::pin(option_future);
                assert_eq!(pinned.as_mut().poll(&mut cx), std::task::Poll::Ready(value));
            }
        }
    }

    while expected_count > completed_count {
        let result = pool.next_completed().await;
        let pos = outstanding
            .iter()
            .position(|&v| v == result)
            .expect("completed value was never pushed");
        outstanding.swap_remove(pos);
        completed_count += 1;
    }

    assert!(outstanding.is_empty());
    assert_eq!(pool.len(), 0);
    assert!(pool.is_empty());
}

fuzz_target!(|input: FuzzInput| {
    block_on(async {
        fuzz(input).await;
    });
});
