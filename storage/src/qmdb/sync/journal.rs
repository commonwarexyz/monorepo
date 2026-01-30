use crate::mmr::Location;
use std::future::Future;

/// Journal of operations used by a [super::Database]
pub trait Journal: Sized + Send {
    /// The context of the journal.
    type Context: Clone;

    /// The configuration of the journal.
    type Config: Clone;

    /// The type of operations in the journal.
    type Op: Send;

    /// The error type returned by the journal.
    type Error: std::error::Error
        + Send
        + 'static
        + Into<crate::qmdb::Error>
        + From<crate::journal::Error>;

    /// Open or create a journal.
    fn init(
        context: Self::Context,
        config: Self::Config,
    ) -> impl Future<Output = Result<Self, Self::Error>>;

    /// Initialize at a specific size (empty journal with pruning boundary set).
    fn init_at_size(
        context: Self::Context,
        config: Self::Config,
        size: u64,
    ) -> impl Future<Output = Result<Self, Self::Error>>;

    /// Destroy the journal and all its data.
    fn destroy(self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Current size (next location to fill).
    fn size(&self) -> u64;

    /// Discard all operations before the given location.
    ///
    /// If current `size() <= start`, initialize as empty at the given location.
    /// Otherwise prune data before the given location.
    fn resize(&mut self, start: Location) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Persist the journal.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Append an operation to the journal.
    fn append(&mut self, op: Self::Op) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<E, V> Journal for crate::journal::contiguous::variable::Journal<E, V>
where
    E: commonware_runtime::Clock
        + commonware_runtime::Storage
        + commonware_runtime::Metrics
        + Clone,
    V: commonware_codec::CodecShared,
    V::Cfg: Clone,
{
    type Context = E;
    type Config = crate::journal::contiguous::variable::Config<V::Cfg>;
    type Op = V;
    type Error = crate::journal::Error;

    async fn init(context: Self::Context, config: Self::Config) -> Result<Self, Self::Error> {
        Self::init(context, config).await
    }

    async fn init_at_size(
        context: Self::Context,
        config: Self::Config,
        size: u64,
    ) -> Result<Self, Self::Error> {
        Self::init_at_size(context, config, size).await
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        Self::destroy(self).await
    }

    fn size(&self) -> u64 {
        Self::size(self)
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

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        Self::append(self, op).await.map(|_| ())
    }
}

impl<E, A> Journal for crate::journal::contiguous::fixed::Journal<E, A>
where
    E: commonware_runtime::Clock
        + commonware_runtime::Storage
        + commonware_runtime::Metrics
        + Clone,
    A: commonware_codec::CodecFixedShared,
{
    type Context = E;
    type Config = crate::journal::contiguous::fixed::Config;
    type Op = A;
    type Error = crate::journal::Error;

    async fn init(context: Self::Context, config: Self::Config) -> Result<Self, Self::Error> {
        Self::init(context, config).await
    }

    async fn init_at_size(
        context: Self::Context,
        config: Self::Config,
        size: u64,
    ) -> Result<Self, Self::Error> {
        Self::init_at_size(context, config, size).await
    }

    async fn destroy(self) -> Result<(), Self::Error> {
        Self::destroy(self).await
    }

    fn size(&self) -> u64 {
        Self::size(self)
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

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        Self::append(self, op).await.map(|_| ())
    }
}
