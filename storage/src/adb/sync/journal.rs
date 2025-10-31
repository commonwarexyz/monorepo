use std::future::Future;

/// Journal of operations used by a [super::Database]
pub trait Journal {
    /// The type of operations in the journal
    type Op;

    /// The error type returned by the journal
    type Error: std::error::Error + Send + 'static + Into<crate::adb::Error>;

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

    async fn size(&self) -> u64 {
        crate::journal::contiguous::variable::Journal::size(self)
    }

    async fn append(&mut self, op: Self::Op) -> Result<(), Self::Error> {
        crate::journal::contiguous::variable::Journal::append(self, op).await?;
        Ok(())
    }
}
