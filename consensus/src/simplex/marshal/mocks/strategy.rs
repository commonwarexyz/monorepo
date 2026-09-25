use commonware_parallel::{Sequential, Strategy};
use commonware_runtime::{Spawner, Supervisor, deterministic};
use commonware_utils::{
    channel::{fallible::OneshotExt as _, oneshot},
    sync::Mutex,
};
use std::{cmp::Ordering, fmt, future::Future, sync::Arc};

/// Controls one submitted job independently of the future waiting for its result.
pub struct Gate {
    pub started: oneshot::Receiver<()>,
    pub release: oneshot::Sender<()>,
}

struct Pending {
    started: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

/// Runs jobs on the deterministic runtime and gates the next submission when armed.
#[derive(Clone)]
pub struct GatedStrategy {
    context: Arc<deterministic::Context>,
    pending: Arc<Mutex<Option<Pending>>>,
}

impl fmt::Debug for GatedStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatedStrategy").finish_non_exhaustive()
    }
}

impl GatedStrategy {
    /// Uses a context whose owning task outlives the callers waiting on jobs.
    pub fn new(context: deterministic::Context) -> Self {
        Self {
            context: Arc::new(context),
            pending: Arc::new(Mutex::new(None)),
        }
    }

    /// Gates exactly the next call to `spawn`.
    pub fn arm(&self) -> Gate {
        let (started_tx, started) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let mut pending = self.pending.lock();
        assert!(pending.is_none(), "a job is already armed");
        *pending = Some(Pending {
            started: started_tx,
            release: release_rx,
        });
        Gate { started, release }
    }
}

impl Strategy for GatedStrategy {
    fn spawn<F, T>(&self, _len: usize, f: F) -> impl Future<Output = T> + Send + 'static + use<F, T>
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        let pending = self.pending.lock().take();
        let strategy = self.clone();
        let (result_tx, result_rx) = oneshot::channel();
        self.context
            .child("job")
            .shared(true)
            .spawn(move |_| async move {
                if let Some(pending) = pending {
                    pending.started.send_lossy(());
                    pending.release.await.expect("job release dropped");
                }
                let result = f(strategy);
                result_tx.send_lossy(result);
            });
        async move { result_rx.await.expect("job result dropped") }
    }

    fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
    where
        R: Send,
        SEQ: FnOnce() -> R + Send,
        PAR: FnOnce() -> R + Send,
    {
        Sequential.run(len, serial, parallel)
    }

    fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
    where
        R: Send,
        E: Send,
        SEQ: FnOnce() -> Result<R, E> + Send,
        PAR: FnOnce() -> Result<R, E> + Send,
    {
        Sequential.try_run(len, serial, parallel)
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
}
