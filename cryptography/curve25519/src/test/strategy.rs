//! Strategy probes for MSM operation boundaries.

use commonware_parallel::{Batches, Grid, Sequential, Strategy, Tiles};
use commonware_utils::sync::Mutex;
use core::{any::type_name, cmp::Ordering, future::Future, num::NonZeroUsize};
use std::{panic::panic_any, sync::Arc};

/// Stops at the strategy boundary and records the operation's assembled output type.
#[derive(Clone, Debug, Default)]
pub(crate) struct Assembly {
    pub(crate) outputs: Arc<Mutex<Vec<&'static str>>>,
}

/// The panic payload with which [`Assembly`] stops an operation.
#[derive(Debug)]
pub(crate) struct AssemblyBoundary;

// The operations the probe does not observe run sequentially.
impl Strategy for Assembly {
    fn spawn<F, T>(&self, len: usize, f: F) -> impl Future<Output = T> + Send + 'static
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        let strategy = self.clone();
        Sequential.spawn(len, move |_| f(strategy))
    }

    fn fold_init<I, INIT, T, R, ID, F, RD>(
        &self,
        iter: I,
        init: INIT,
        identity: ID,
        fold_op: F,
        reduce_op: RD,
    ) -> R
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        Sequential.fold_init(iter, init, identity, fold_op, reduce_op)
    }

    fn try_fold<I, R, E, ID, F, RD>(
        &self,
        iter: I,
        identity: ID,
        fold_op: F,
        reduce_op: RD,
    ) -> Result<R, E>
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        R: Send,
        E: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, I::Item) -> Result<R, E> + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        Sequential.try_fold(iter, identity, fold_op, reduce_op)
    }

    fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        Sequential.join(a, b)
    }

    fn sort_by<T, F>(&self, items: &mut [T], compare: F)
    where
        T: Send,
        F: Fn(&T, &T) -> Ordering + Send + Sync,
    {
        Sequential.sort_by(items, compare)
    }

    fn run<R, SEQ, PAR>(&self, _len: usize, _serial: SEQ, parallel: PAR) -> R
    where
        R: Send,
        SEQ: FnOnce() -> R + Send,
        PAR: FnOnce() -> R + Send,
    {
        // Take the parallel body, which always reaches `run_batches` or `run_tiles`.
        parallel()
    }

    fn try_run<R, E, SEQ, PAR>(&self, _len: usize, _serial: SEQ, parallel: PAR) -> Result<R, E>
    where
        R: Send,
        E: Send,
        SEQ: FnOnce() -> Result<R, E> + Send,
        PAR: FnOnce() -> Result<R, E> + Send,
    {
        // Take the parallel body, which always reaches `run_batches` or `run_tiles`.
        parallel()
    }

    fn try_run_batches<R, E, F>(
        &self,
        _len: usize,
        _minimum: NonZeroUsize,
        _multiplier: usize,
        _run: F,
    ) -> Result<R, E>
    where
        R: Send,
        E: Send,
        F: for<'scope> FnOnce(Batches<'scope, Self>) -> Result<R, E> + Send,
    {
        // Record the type the callback must assemble, then stop without running it.
        self.outputs.lock().push(type_name::<R>());
        panic_any(AssemblyBoundary)
    }

    fn run_tiles<R, F>(&self, _len: usize, _grids: &[Grid], _multiplier: usize, _run: F) -> R
    where
        R: Send,
        F: for<'scope> FnOnce(Tiles<'scope, Self>) -> R + Send,
    {
        // Record the type the callback must assemble, then stop without running it.
        self.outputs.lock().push(type_name::<R>());
        panic_any(AssemblyBoundary)
    }
}
