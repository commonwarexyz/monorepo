use crate::mmr::Location;
use std::{future::Future, ops::Range};

/// Journal of operations used by a [super::Database]
pub trait Journal: Sized {
    type Context;

    /// The type of operations in the journal
    type Op;

    type Config;

    /// The error type returned by the journal
    type Error: std::error::Error + Send + 'static + Into<crate::qmdb::Error>;

    /// Persist the journal.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Get the number of operations in the journal
    fn size(&self) -> impl Future<Output = u64>;

    /// Append an operation to the journal
    fn append(&mut self, op: Self::Op) -> impl Future<Output = Result<(), Self::Error>>;

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
}

impl<E, V> Journal for crate::journal::contiguous::variable::Journal<E, V>
where
    E: commonware_runtime::Storage + commonware_runtime::Metrics,
    V: commonware_codec::Codec,
{
    type Context = E;
    type Op = V;
    type Error = crate::journal::Error;
    type Config = crate::journal::contiguous::variable::Config<V::Cfg>;

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Self::sync(self).await
    }

    async fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        self.append(op).await.map(|_| ())
    }

    async fn new(
        context: Self::Context,
        config: Self::Config,
        range: Range<Location>,
    ) -> Result<Self, Self::Error> {
        Self::init_sync(
            context.with_label("log"),
            config.clone(),
            *range.start..*range.end,
        )
        .await
    }
}

impl<E, A> Journal for crate::journal::contiguous::fixed::Journal<E, A>
where
    E: commonware_runtime::Storage + commonware_runtime::Metrics,
    A: commonware_codec::CodecFixed<Cfg = ()>,
{
    type Context = E;
    type Op = A;
    type Error = crate::journal::Error;
    type Config = crate::journal::contiguous::fixed::Config;

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Self::sync(self).await
    }

    async fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        self.append(op).await.map(|_| ())
    }

    async fn new(
        context: Self::Context,
        config: Self::Config,
        range: Range<Location>,
    ) -> Result<Self, Self::Error> {
        Self::init_sync(
            context.with_label("log"),
            config.clone(),
            *range.start..*range.end,
        )
        .await
    }
}
