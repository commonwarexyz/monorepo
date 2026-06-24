//! Shared sync observation and durability bookkeeping for buffered blob wrappers.

use crate::{Blob, Error, Handle};
use futures::{
    future::{join_all, BoxFuture, Shared as FuturesShared},
    FutureExt as _,
};
use std::future::Future;

/// A cloneable observer for an issued sync.
pub type Shared = FuturesShared<BoxFuture<'static, Result<(), Error>>>;

/// Converts a sync future into a shared completion.
pub fn share(fut: impl Future<Output = Result<(), Error>> + Send + 'static) -> Shared {
    fut.boxed().shared()
}

/// Converts a sync handle into a shared completion.
pub fn share_handle(handle: Handle<()>) -> Shared {
    handle.boxed().shared()
}

/// Returns a handle that observes a shared sync completion.
pub fn observe(sync: Shared) -> Handle<()> {
    Handle::from_future(async move { sync.await })
}

/// Returns a handle that observes all shared sync completions.
pub fn observe_all(syncs: impl IntoIterator<Item = Shared>) -> Handle<()> {
    let syncs = syncs.into_iter().collect();
    Handle::from_future(async move { wait_all(syncs).await })
}

/// Waits for all shared sync completions.
pub async fn wait_all(syncs: Vec<Shared>) -> Result<(), Error> {
    for result in join_all(syncs).await {
        result?;
    }
    Ok(())
}

/// Returns whether a shared sync has already completed successfully.
pub fn completed_successfully(sync: &Shared) -> bool {
    matches!(sync.clone().now_or_never(), Some(Ok(())))
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
    /// Returns a state that requires a full blob sync.
    pub(crate) const fn dirty() -> Self {
        Self::Dirty
    }

    /// Returns whether a full sync still needs to be issued.
    pub(crate) const fn is_dirty(&self) -> bool {
        matches!(self, Self::Dirty)
    }

    /// Records that an issued mutation must be covered by a future full sync.
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

    /// Restores the state saved before a successful range sync.
    ///
    /// If the range sync fails, callers should leave the conservative dirty state installed by
    /// [`Self::prepare_range_sync`].
    pub(crate) fn restore(&mut self, previous: Self) {
        *self = previous;
    }

    /// Ensures mutations represented by this state are durable.
    ///
    /// Returns `true` when this call issues or observes a sync, and `false` when the state was
    /// already clean.
    pub(crate) async fn sync<B: Blob>(&mut self, blob: &B) -> Result<bool, Error> {
        match self {
            Self::Clean => Ok(false),
            Self::Dirty => {
                blob.sync().await?;
                *self = Self::Clean;
                Ok(true)
            }
            Self::InFlight(syncing) => {
                syncing.clone().await?;
                *self = Self::Clean;
                Ok(true)
            }
        }
    }

    /// Observes any in-flight sync without clearing it early if this observer is dropped.
    pub(crate) async fn observe_in_flight(&mut self) -> Result<(), Error> {
        let Self::InFlight(syncing) = self else {
            return Ok(());
        };
        syncing.clone().await?;
        *self = Self::Clean;
        Ok(())
    }

    /// Starts a full blob sync or returns the in-flight sync that already covers this state.
    ///
    /// Returns `None` when no issued mutation requires a sync.
    pub(crate) async fn start<B: Blob>(&mut self, blob: &B) -> Option<Shared> {
        match self {
            Self::Clean => None,
            Self::Dirty => {
                let syncing = share(blob.start_sync().await);
                *self = Self::InFlight(syncing.clone());
                Some(syncing)
            }
            Self::InFlight(syncing) => Some(syncing.clone()),
        }
    }
}
