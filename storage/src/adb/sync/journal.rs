use std::future::Future;

/// Journal that stores Data used by a [super::Database]
pub trait Journal {
    /// The type of data that composes the journal
    type Data;

    /// The error type returned by the journal
    type Error: std::error::Error + Send + 'static;

    /// Get the number of data items in the journal
    fn size(&self) -> impl Future<Output = Result<u64, Self::Error>>;

    /// Append a data item to the journal
    fn append(&mut self, data: Self::Data) -> impl Future<Output = Result<(), Self::Error>>;

    /// Close the journal and release resources
    fn close(self) -> impl Future<Output = Result<(), Self::Error>>;
}
