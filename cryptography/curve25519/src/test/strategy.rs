//! Strategy probes for completion accounting and MSM operation boundaries.

use commonware_parallel::{Batches, Manual, Sequential, Strategy, Tiles};
use commonware_utils::sync::Mutex;
use core::{any::type_name, cmp::Ordering, future::Future, num::NonZeroUsize};
use std::{panic::panic_any, sync::Arc};

macro_rules! sequential_operations {
    () => {
        fn manual(&self) -> Manual<Self> {
            unreachable!("these verification paths leave scheduling to Strategy")
        }

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
    };
}

/// Records whether each selected operation admits a complete-work sample.
#[derive(Clone, Debug)]
pub(crate) struct Recording {
    pub(crate) parallel: bool,
    pub(crate) samples: Arc<Mutex<Vec<bool>>>,
}

impl Recording {
    pub(crate) fn new(parallel: bool) -> Self {
        Self {
            parallel,
            samples: Arc::default(),
        }
    }
}

impl Strategy for Recording {
    sequential_operations!();

    fn run<R, SEQ, PAR>(&self, _len: usize, serial: SEQ, parallel: PAR) -> R
    where
        R: Send,
        SEQ: FnOnce() -> R + Send,
        PAR: FnOnce() -> R + Send,
    {
        let result = if self.parallel { parallel() } else { serial() };
        self.samples.lock().push(true);
        result
    }

    fn try_run<R, E, SEQ, PAR>(&self, _len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
    where
        R: Send,
        E: Send,
        SEQ: FnOnce() -> Result<R, E> + Send,
        PAR: FnOnce() -> Result<R, E> + Send,
    {
        let result = if self.parallel { parallel() } else { serial() };
        self.samples.lock().push(result.is_ok());
        result
    }
}

/// Stops at the strategy boundary and records the operation's assembled output type.
#[derive(Clone, Debug, Default)]
pub(crate) struct Assembly {
    pub(crate) outputs: Arc<Mutex<Vec<&'static str>>>,
}

#[derive(Debug)]
pub(crate) struct AssemblyBoundary;

impl Strategy for Assembly {
    sequential_operations!();

    fn run<R, SEQ, PAR>(&self, _len: usize, _serial: SEQ, parallel: PAR) -> R
    where
        R: Send,
        SEQ: FnOnce() -> R + Send,
        PAR: FnOnce() -> R + Send,
    {
        parallel()
    }

    fn try_run<R, E, SEQ, PAR>(&self, _len: usize, _serial: SEQ, parallel: PAR) -> Result<R, E>
    where
        R: Send,
        E: Send,
        SEQ: FnOnce() -> Result<R, E> + Send,
        PAR: FnOnce() -> Result<R, E> + Send,
    {
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
        self.outputs.lock().push(type_name::<R>());
        panic_any(AssemblyBoundary)
    }

    fn run_tiles<R, F>(
        &self,
        _rows: usize,
        _len: usize,
        _cost: NonZeroUsize,
        _multiplier: usize,
        _run: F,
    ) -> R
    where
        R: Send,
        F: for<'scope> FnOnce(Tiles<'scope, Self>) -> R + Send,
    {
        self.outputs.lock().push(type_name::<R>());
        panic_any(AssemblyBoundary)
    }
}
