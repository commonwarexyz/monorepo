use std::future::Future;

/// Journal of operations used by a [super::Database]
pub trait Journal {
    type Op;
    type Error: std::error::Error + Send + 'static;

    /// Get the number of operations in the journal
    fn size(&self) -> impl Future<Output = Result<u64, Self::Error>>;

    /// Append an operation to the journal
    fn append(&mut self, op: Self::Op) -> impl Future<Output = Result<(), Self::Error>>;

    /// Close the journal and release resources
    fn close(self) -> impl Future<Output = Result<(), Self::Error>>;
}
