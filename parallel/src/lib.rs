#![cfg_attr(not(any(test, feature = "std")), no_std)]

#[cfg(feature = "std")]
use rayon::{
    iter::{IntoParallelIterator as RIntoParallelIterator, ParallelIterator},
    ThreadPool,
};
#[cfg(feature = "std")]
use std::sync::Arc;

pub trait Strategy: Clone + Send + Sync {
    fn fold<I, T, ID, F, R>(&self, iter: I, identity: ID, fold_op: F, reduce_op: R) -> T
    where
        I: IntoParallelIterator + Send,
        T: Send,
        ID: Fn() -> T + Send + Sync,
        F: Fn(T, I::Item) -> T + Send + Sync,
        R: Fn(T, T) -> T + Send + Sync;

    fn join<L, LO, R, RO>(&self, left: L, right: R) -> (LO, RO)
    where
        L: FnOnce() -> LO + Send,
        R: FnOnce() -> RO + Send,
        LO: Send,
        RO: Send;
}

pub trait IntoParallelIterator: IntoIterator {
    #[cfg(feature = "std")]
    type ParIter: ParallelIterator<Item = <Self as IntoIterator>::Item>;

    #[cfg(feature = "std")]
    fn into_par_iter(self) -> Self::ParIter;
}

#[cfg(feature = "std")]
impl<T> IntoParallelIterator for T
where
    T: IntoIterator,
    T: RIntoParallelIterator<Item = <T as IntoIterator>::Item>,
{
    type ParIter = <T as RIntoParallelIterator>::Iter;

    fn into_par_iter(self) -> Self::ParIter {
        RIntoParallelIterator::into_par_iter(self)
    }
}

#[cfg(not(feature = "std"))]
impl<T> IntoParallelIterator for T where T: IntoIterator {}

#[derive(Default, Debug, Clone)]
pub struct Sequential;

impl Strategy for Sequential {
    fn fold<I, T, ID, F, R>(&self, iter: I, identity: ID, fold_op: F, _reduce_op: R) -> T
    where
        I: IntoParallelIterator + Send,
        T: Send,
        ID: Fn() -> T + Send + Sync,
        F: Fn(T, I::Item) -> T + Send + Sync,
        R: Fn(T, T) -> T + Send + Sync,
    {
        iter.into_iter().fold(identity(), fold_op)
    }

    fn join<L, LO, R, RO>(&self, left: L, right: R) -> (LO, RO)
    where
        L: FnOnce() -> LO + Send,
        R: FnOnce() -> RO + Send,
        LO: Send,
        RO: Send,
    {
        (left(), right())
    }
}

#[cfg(feature = "std")]
#[derive(Debug, Clone)]
pub struct Parallel {
    thread_pool: Arc<ThreadPool>,
}

impl Parallel {
    pub const fn new(thread_pool: Arc<ThreadPool>) -> Self {
        Self { thread_pool }
    }
}

impl From<Arc<ThreadPool>> for Parallel {
    fn from(thread_pool: Arc<ThreadPool>) -> Self {
        Self::new(thread_pool)
    }
}

#[cfg(feature = "std")]
impl Strategy for Parallel {
    fn fold<I, T, ID, F, R>(&self, iter: I, identity: ID, fold_op: F, reduce_op: R) -> T
    where
        I: IntoParallelIterator + Send,
        T: Send,
        ID: Fn() -> T + Send + Sync,
        F: Fn(T, I::Item) -> T + Send + Sync,
        R: Fn(T, T) -> T + Send + Sync,
    {
        self.thread_pool.install(|| {
            iter.into_par_iter()
                .fold(&identity, fold_op)
                .reduce(&identity, reduce_op)
        })
    }

    fn join<L, LO, R, RO>(&self, left: L, right: R) -> (LO, RO)
    where
        L: FnOnce() -> LO + Send,
        R: FnOnce() -> RO + Send,
        LO: Send,
        RO: Send,
    {
        self.thread_pool.install(|| rayon::join(left, right))
    }
}

#[cfg(test)]
mod test {
    use crate::{Parallel, Sequential, Strategy};
    use rayon::ThreadPoolBuilder;
    use std::sync::Arc;

    #[test]
    fn test_sequential_fold() {
        let strategy = Sequential;
        let data = vec![1, 2, 3, 4, 5];

        let res = strategy.fold(&data, || 0, |acc, item| acc + item, |a, b| a + b);
        assert_eq!(res, 15);
    }

    #[test]
    fn test_parallel_fold() {
        let thread_pool = ThreadPoolBuilder::new().build().unwrap();
        let strategy = Parallel {
            thread_pool: Arc::new(thread_pool),
        };
        let data = vec![1, 2, 3, 4, 5];

        let res = strategy.fold(&data, || 0, |acc, item| acc + item, |a, b| a + b);
        assert_eq!(res, 15);
    }

    #[test]
    fn test_sequential_join() {
        let strategy = Sequential;

        let (a, b) = strategy.join(|| 2 + 3, || 4 + 5);
        assert_eq!(a, 5);
        assert_eq!(b, 9);
    }

    #[test]
    fn test_parallel_join() {
        let thread_pool = ThreadPoolBuilder::new().build().unwrap();
        let strategy = Parallel {
            thread_pool: Arc::new(thread_pool),
        };

        let (a, b) = strategy.join(|| 2 + 3, || 4 + 5);
        assert_eq!(a, 5);
        assert_eq!(b, 9);
    }
}
