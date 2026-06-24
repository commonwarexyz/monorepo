//! Shared durability bookkeeping for buffered blob wrappers.

use crate::{Blob, Error, Handle};
use futures::{
    future::{BoxFuture, Shared as FuturesShared},
    FutureExt as _,
};
use std::future::Future;

/// A cloneable observer for an issued sync.
pub(crate) type Shared = FuturesShared<BoxFuture<'static, ()>>;

/// Converts a sync future into a shared completion.
///
/// Sync failures are fatal for these buffered wrappers, so observers panic with the supplied
/// message instead of cloning and returning the underlying error.
pub(crate) fn share(
    fut: impl Future<Output = Result<(), Error>> + Send + 'static,
    message: &'static str,
) -> Shared {
    async move { fut.await.expect(message) }.boxed().shared()
}

/// Returns a handle that observes a shared sync completion.
pub(crate) fn observe(sync: Shared) -> Handle<()> {
    Handle::from_future(async move {
        sync.await;
        Ok(())
    })
}

/// Durability state for mutations already issued to the underlying blob.
///
/// Bytes still held only in a write buffer are not represented here. Once those bytes are flushed
/// to the blob, callers update this state through the methods below.
#[derive(Clone)]
pub(crate) enum State {
    /// No issued mutation requires a sync.
    Clean,

    /// At least one issued plain write or resize requires a full blob sync.
    Dirty,

    /// A full blob sync has been issued and can be observed by multiple callers.
    InFlight(Shared),
}

impl State {
    pub(crate) const fn dirty() -> Self {
        Self::Dirty
    }

    pub(crate) const fn is_dirty(&self) -> bool {
        matches!(self, Self::Dirty)
    }

    pub(crate) fn mark_dirty(&mut self) {
        *self = Self::Dirty;
    }

    /// Marks the blob dirty while a range sync is in progress.
    ///
    /// If [`Blob::write_at_sync`] fails, this conservative state remains in place so a later sync
    /// cannot report success without a full durability barrier.
    pub(crate) const fn prepare_range_sync(&mut self) -> Self {
        std::mem::replace(self, Self::Dirty)
    }

    pub(crate) fn restore(&mut self, previous: Self) {
        *self = previous;
    }

    pub(crate) async fn sync<B: Blob>(&mut self, blob: &B) -> Result<bool, Error> {
        match self {
            Self::Clean => Ok(false),
            Self::Dirty => {
                blob.sync().await?;
                *self = Self::Clean;
                Ok(true)
            }
            Self::InFlight(syncing) => {
                syncing.clone().await;
                *self = Self::Clean;
                Ok(true)
            }
        }
    }

    /// Observe an in-flight sync without clearing it early if this observer is dropped.
    pub(crate) async fn observe_in_flight(&mut self) {
        let Self::InFlight(syncing) = self else {
            return;
        };
        syncing.clone().await;
        *self = Self::Clean;
    }

    pub(crate) async fn start<B: Blob>(
        &mut self,
        blob: &B,
        message: &'static str,
    ) -> Option<Shared> {
        match self {
            Self::Clean => None,
            Self::Dirty => {
                let syncing = share(blob.start_sync().await, message);
                *self = Self::InFlight(syncing.clone());
                Some(syncing)
            }
            Self::InFlight(syncing) => Some(syncing.clone()),
        }
    }
}
