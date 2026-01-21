use std::future::Future;

/// Journal of operations used by a [super::Database]
pub trait Journal: Send {
    /// The type of operations in the journal
    type Op: Send;

    /// The error type returned by the journal
    type Error: std::error::Error + Send + 'static + Into<crate::qmdb::Error>;

    /// Persist the journal.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Get the number of operations in the journal
    fn size(&self) -> impl Future<Output = u64> + Send;

    /// Append an operation to the journal
    fn append(&mut self, op: Self::Op) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Clear all data and reset the journal to a new starting position.
    ///
    /// After clearing, the journal will behave as if initialized at `new_size`.
    fn clear(&mut self, new_size: u64) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

impl<E, V> Journal for crate::journal::contiguous::variable::Journal<E, V>
where
    E: commonware_runtime::Storage + commonware_runtime::Metrics,
    V: commonware_codec::CodecShared,
{
    type Op = V;
    type Error = crate::journal::Error;

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Self::sync(self).await
    }

    async fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        Self::append(self, op).await.map(|_| ())
    }

    async fn clear(&mut self, new_size: u64) -> Result<(), Self::Error> {
        self.clear_to_size(new_size).await
    }
}

impl<E, A> Journal for crate::journal::contiguous::fixed::Journal<E, A>
where
    E: commonware_runtime::Storage + commonware_runtime::Metrics,
    A: commonware_codec::CodecFixedShared,
{
    type Op = A;
    type Error = crate::journal::Error;

    async fn sync(&mut self) -> Result<(), Self::Error> {
        Self::sync(self).await
    }

    async fn size(&self) -> u64 {
        Self::size(self)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        Self::append(self, op).await.map(|_| ())
    }

    async fn clear(&mut self, new_size: u64) -> Result<(), Self::Error> {
        self.clear_to_size(new_size).await
    }
}
