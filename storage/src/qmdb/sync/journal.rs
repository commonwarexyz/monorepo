use std::future::Future;

/// Journal of operations used by a [super::Database]
pub trait Journal {
    /// The type of operations in the journal
    type Op;

    /// The error type returned by the journal
    type Error: std::error::Error + Send + 'static + Into<crate::qmdb::Error>;

    /// Persist the journal.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Get the number of operations in the journal
    fn size(&self) -> impl Future<Output = u64>;

    /// Append an operation to the journal
    fn append(&mut self, op: Self::Op) -> impl Future<Output = Result<(), Self::Error>>;
}

impl<E, V> Journal for crate::journal::contiguous::variable::Journal<E, V>
where
    E: commonware_runtime::Storage + commonware_runtime::Metrics,
    V: commonware_codec::Codec,
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
        self.append(op).await.map(|_| ())
    }
}

impl<E, A> Journal for crate::journal::contiguous::fixed::Journal<E, A>
where
    E: commonware_runtime::Storage + commonware_runtime::Metrics,
    A: commonware_codec::CodecFixed<Cfg = ()>,
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
        self.append(op).await.map(|_| ())
    }
}
