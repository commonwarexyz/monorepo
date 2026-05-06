use crate::{types::Epoch, Application, Block};
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::sync::Mutex;
use rand::Rng;
use std::sync::Arc;

/// Shared one-entry cache for the latest application-provided genesis entry.
#[derive(Clone)]
pub(crate) struct Cache<T> {
    inner: Arc<Mutex<Option<(Epoch, T)>>>,
}

impl<T> Cache<T> {
    /// Creates an empty [`Cache`].
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }
}

impl<T: Clone> Cache<T> {
    /// Returns the cached genesis entry for `epoch`, fetching and deriving it if needed.
    pub(crate) async fn get_or_insert_with<E, A, B, F>(
        &self,
        application: &mut A,
        epoch: Epoch,
        derive: F,
    ) -> T
    where
        E: Rng + Spawner + Metrics + Clock,
        A: Application<E, Block = B>,
        B: Block,
        F: FnOnce(B) -> T,
    {
        if let Some((cached_epoch, cached_entry)) = self.inner.lock().as_ref() {
            if *cached_epoch == epoch {
                return cached_entry.clone();
            }
        }

        // Do not hold the blocking lock across the application call.
        let genesis = application.genesis(epoch).await;
        let entry = derive(genesis);
        *self.inner.lock() = Some((epoch, entry.clone()));
        entry
    }
}

impl<B: Block> Cache<B> {
    /// Returns the cached genesis block for `epoch`, fetching and caching it if needed.
    pub(crate) async fn get<E, A>(&self, application: &mut A, epoch: Epoch) -> B
    where
        E: Rng + Spawner + Metrics + Clock,
        A: Application<E, Block = B>,
    {
        self.get_or_insert_with::<E, A, B, _>(application, epoch, |genesis| genesis)
            .await
    }
}
