#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::{
    FuzzRng,
    futures::{AbortablePool, Aborter, OptionFuture, Pool, rebind, rebind_entry},
};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::{collections::BTreeMap, future::Future};

const MIN_OPERATIONS: usize = 4;
const MAX_OPERATIONS: usize = 64;

/// Bytes of the stream an input is sampled from, and of the input's head that seeds it.
const STREAM_BYTES: usize = 1 << 12;
const SEED_BYTES: usize = 8;

/// Keys a [Operation::RebindEntry] map uses, few so that entries are rebound repeatedly.
const ENTRY_KEYS: u8 = 4;

#[derive(Debug)]
struct FuzzInput {
    pool_type: PoolType,
    operations: Vec<Operation>,
}

/// The input's head seeds a fixed-size stream that the rest of the input overwrites from its
/// start, so even the empty input samples a whole list of operations.
impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let u = &mut Unstructured::new(&stream);

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

#[derive(Arbitrary, Clone, Copy, Debug)]
enum PoolType {
    Regular,
    Abortable,
}

#[derive(Arbitrary, Clone, Debug)]
enum Operation {
    Push {
        value: i32,
    },
    NextCompleted {
        limit: u8,
    },
    CancelAll,
    CheckLen,
    CheckIsEmpty,
    DefaultOptionFuture,
    ReadyOptionFuture {
        value: i32,
    },
    Rebind {
        value: i32,
        delta: i32,
        first: u8,
        second: u16,
        arity: u8,
        fail: bool,
    },
    RebindEntry {
        key: u8,
        value: i32,
        delta: i32,
        first: u8,
        second: u16,
        arity: u8,
        fail: bool,
    },
}

/// The error a rebound operation returns when it fails.
#[derive(Debug, PartialEq)]
struct Failed;

/// The outputs a rebound operation returns beside its value, one shape per `arity % 3`.
#[derive(Debug, PartialEq)]
enum Extras {
    None,
    One(u8),
    Two(u8, u16),
}

impl Extras {
    fn new(arity: u8, first: u8, second: u16) -> Self {
        match arity % 3 {
            0 => Self::None,
            1 => Self::One(first),
            _ => Self::Two(first, second),
        }
    }
}

/// The value a rebound operation returns: `value + delta`, or [Failed] when `fail`.
fn rebound(value: i32, delta: i32, fail: bool) -> std::future::Ready<Result<i32, Failed>> {
    std::future::ready(if fail {
        Err(Failed)
    } else {
        Ok(value.wrapping_add(delta))
    })
}

async fn rebind_slot(
    slot: &mut Option<i32>,
    delta: i32,
    extras: Extras,
    fail: bool,
) -> Result<Extras, Failed> {
    match extras {
        Extras::None => rebind(slot, |v| rebound(v, delta, fail))
            .await
            .map(|()| Extras::None),
        Extras::One(a) => rebind(
            slot,
            |v| async move { Ok((rebound(v, delta, fail).await?, a)) },
        )
        .await
        .map(Extras::One),
        Extras::Two(a, b) => rebind(slot, |v| async move {
            Ok((rebound(v, delta, fail).await?, a, b))
        })
        .await
        .map(|(a, b)| Extras::Two(a, b)),
    }
}

async fn rebind_key(
    map: &mut BTreeMap<u8, i32>,
    key: u8,
    delta: i32,
    extras: Extras,
    fail: bool,
) -> Result<Extras, Failed> {
    match extras {
        Extras::None => rebind_entry(map, &key, |v| rebound(v, delta, fail))
            .await
            .map(|()| Extras::None),
        Extras::One(a) => rebind_entry(map, &key, |v| async move {
            Ok((rebound(v, delta, fail).await?, a))
        })
        .await
        .map(Extras::One),
        Extras::Two(a, b) => rebind_entry(map, &key, |v| async move {
            Ok((rebound(v, delta, fail).await?, a, b))
        })
        .await
        .map(|(a, b)| Extras::Two(a, b)),
    }
}

enum PoolWrapper {
    Regular(Pool<'static, i32>),
    Abortable(AbortablePool<'static, i32>, Vec<Aborter>),
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
    let other = match input.pool_type {
        PoolType::Regular => PoolType::Abortable,
        PoolType::Abortable => PoolType::Regular,
    };
    for pool_type in [input.pool_type, other] {
        run(pool_type, &input.operations).await;
    }
}

async fn run(pool_type: PoolType, operations: &[Operation]) {
    let mut pool = PoolWrapper::new(pool_type);
    let mut expected_count = 0;
    let mut completed_count = 0;
    // Multiset of pushed-but-not-yet-completed values: a completion must return a
    // value that was actually pushed (no conjured or duplicated results).
    let mut outstanding: Vec<i32> = Vec::new();
    let mut entries = BTreeMap::new();
    let mut entries_model = BTreeMap::new();

    for op in operations.iter().cloned() {
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
                let mut option_future = OptionFuture::from(Some(std::future::ready(value)));
                assert!(option_future.is_some());
                let inner = option_future.take();
                assert!(option_future.is_none());
                *option_future = inner;
                assert!(option_future.is_some());

                let waker = futures::task::noop_waker();
                let mut cx = std::task::Context::from_waker(&waker);
                let mut pinned = Box::pin(option_future);
                assert_eq!(pinned.as_mut().poll(&mut cx), std::task::Poll::Ready(value));
            }

            Operation::Rebind {
                value,
                delta,
                first,
                second,
                arity,
                fail,
            } => {
                let mut slot = Some(value);
                let result =
                    rebind_slot(&mut slot, delta, Extras::new(arity, first, second), fail).await;
                if fail {
                    assert_eq!(result, Err(Failed));
                    assert_eq!(slot, None);
                } else {
                    assert_eq!(result, Ok(Extras::new(arity, first, second)));
                    assert_eq!(slot, Some(value.wrapping_add(delta)));
                }
            }

            Operation::RebindEntry {
                key,
                value,
                delta,
                first,
                second,
                arity,
                fail,
            } => {
                let key = key % ENTRY_KEYS;
                let stored = *entries_model.entry(key).or_insert_with(|| {
                    entries.insert(key, value);
                    value
                });
                let extras = Extras::new(arity, first, second);
                let result = rebind_key(&mut entries, key, delta, extras, fail).await;
                if fail {
                    assert_eq!(result, Err(Failed));
                    entries_model.remove(&key);
                } else {
                    assert_eq!(result, Ok(Extras::new(arity, first, second)));
                    entries_model.insert(key, stored.wrapping_add(delta));
                }
                assert_eq!(entries, entries_model);
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
