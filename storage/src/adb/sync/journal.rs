use std::future::Future;

/// Journal of operations used by a [super::Database]
pub trait Journal {
    type Op;
    type Error: std::error::Error + Send + 'static;

    /// Get the number of operations in the journal
    fn size(&self) -> impl Future<Output = Result<u64, Self::Error>>;

    /// Check if the journal has any operations at or after the given location
    /// This is used to determine if the journal needs to be recreated or can be pruned
    fn has_operations_from(&self, location: u64)
        -> impl Future<Output = Result<bool, Self::Error>>;

    /// Append an operation to the journal
    fn append(&mut self, op: Self::Op) -> impl Future<Output = Result<(), Self::Error>>;

    /// Close the journal and release resources
    fn close(self) -> impl Future<Output = Result<(), Self::Error>>;
}
