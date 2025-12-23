#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::futures::{AbortablePool, Aborter, Pool};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    pool_type: PoolType,
    operations: Vec<Operation>,
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
                        let _result = pool.next_completed().await;
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

    for op in input.operations {
        match op {
            Operation::Push { value } => {
                pool.push(async move { value });
                expected_count += 1;
                assert_eq!(pool.len(), expected_count - completed_count);
            }

            Operation::NextCompleted { limit } => {
                let max_iterations = limit.min(10) as usize;
                for _ in 0..max_iterations {
                    if expected_count > completed_count {
                        let _result = pool.next_completed().await;
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
                    continue;
                }
                PoolWrapper::Regular(_) => {
                    pool.cancel_all().await;
                    expected_count = 0;
                    completed_count = 0;
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
        }
    }

    while expected_count > completed_count {
        let _result = pool.next_completed().await;
        completed_count += 1;
    }

    assert_eq!(pool.len(), 0);
    assert!(pool.is_empty());
}

fuzz_target!(|input: FuzzInput| {
    block_on(async {
        fuzz(input).await;
    });
});
