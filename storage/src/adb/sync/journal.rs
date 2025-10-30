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
