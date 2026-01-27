use crate::mmr::Location;
use std::{future::Future, ops::Range};

/// Journal of operations used by a [super::Database]
pub trait Journal: Sized + Send {
    /// The context of the journal
    type Context;

    /// The configuration of the journal
    type Config;

    /// The type of operations in the journal
    type Op: Send;

    /// The error type returned by the journal
    type Error: std::error::Error + Send + 'static + Into<crate::qmdb::Error>;

    /// Create/open a journal for syncing the given range.
    ///
    /// The implementation must:
    /// - Reuse any on-disk data whose logical locations lie within the range.
    /// - Discard/ignore any data outside the range.
    /// - Report `size()` equal to the next location to be filled.
    fn new(
        context: Self::Context,
        config: Self::Config,
        range: Range<Location>,
    ) -> impl Future<Output = Result<Self, Self::Error>>;

    /// Discard all operations before the given location.
    ///
    /// If current `size() <= start`, initialize as empty at the given location.
    /// Otherwise prune data before the given location.
    fn resize(&mut self, start: Location) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Persist the journal.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Get the number of operations in the journal
    fn size(&self) -> impl Future<Output = u64> + Send;

    /// Append an operation to the journal
    fn append(&mut self, op: Self::Op) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<E, V> Journal for crate::journal::contiguous::variable::Journal<E, V>
where
    E: commonware_runtime::Clock + commonware_runtime::Storage + commonware_runtime::Metrics,
    V: commonware_codec::CodecShared,
{
    type Context = E;
    type Config = crate::journal::contiguous::variable::Config<V::Cfg>;
    type Op = V;
    type Error = crate::journal::Error;

    async fn new(
        context: Self::Context,
        config: Self::Config,
        range: Range<Location>,
    ) -> Result<Self, Self::Error> {
        Self::init_sync(context, config.clone(), *range.start..*range.end).await
    }

    async fn resize(&mut self, start: Location) -> Result<(), Self::Error> {
        if self.size() <= start {
            self.clear_to_size(*start).await
        } else {
            self.prune(*start).await.map(|_| ())
        }
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Self::sync(self).await
    }

    async fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        Self::append(self, op).await.map(|_| ())
    }
}

impl<E, A> Journal for crate::journal::contiguous::fixed::Journal<E, A>
where
    E: commonware_runtime::Clock + commonware_runtime::Storage + commonware_runtime::Metrics,
    A: commonware_codec::CodecFixedShared,
{
    type Context = E;
    type Config = crate::journal::contiguous::fixed::Config;
    type Op = A;
    type Error = crate::journal::Error;

    async fn new(
        context: Self::Context,
        config: Self::Config,
        range: Range<Location>,
    ) -> Result<Self, Self::Error> {
        Self::init_sync(context, config, *range.start..*range.end).await
    }

    async fn resize(&mut self, start: Location) -> Result<(), Self::Error> {
        if self.size() <= start {
            self.clear_to_size(*start).await
        } else {
            self.prune(*start).await.map(|_| ())
        }
    }

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Self::sync(self).await
    }

    async fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        Self::append(self, op).await.map(|_| ())
    }
}
