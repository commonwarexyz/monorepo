use commonware_codec::{Decode, Encode};
use std::{
    error::Error as StdError,
    fmt::{Debug, Display},
    future::Future,
    hash::Hash,
    ops::RangeInclusive,
};
use thiserror::Error;

mod engine;
use engine::{config::Config, engine::Engine, ingress::Ingress};

/// Represents data that has a linear order.
pub trait OrderedData: Encode + Decode + Clone + Debug + Send + Sync + 'static {
    /// The type used for indexing or sequencing the data (e.g., block number, MMR index).
    type Index: Copy + Ord + Hash + Debug + Display + Send + Sync + 'static;

    /// Returns the index of this data item.
    fn index(&self) -> Self::Index;
}

/// Represents a proof that can verify one or more `OrderedData` items.
pub trait Proof: Encode + Decode + Clone + Debug + Send + Sync + 'static {
    /// The type of index this proof applies to.
    ///
    /// Must match the `OrderedData::Index`.
    type Index: Copy + Ord + Hash + Debug + Display + Send + Sync + 'static;

    /// Indicates the range of indices this proof covers or is relevant for.
    ///
    /// For single-item proofs, start and end can be the same.
    fn covers_range(&self) -> RangeInclusive<Self::Index>;
}

/// Represents a proof that can verify one or more `OrderedData` items.
pub trait Verifiable<D: OrderedData>: Proof {
    type Error: StdError + Send + Sync + 'static;

    /// Any additional context needed for verification.
    type Context: Debug + Send + Sync + 'static;

    /// Verifies a single data item using this proof.
    fn verify_item(
        &self,
        item: &D,
        context: &Self::Context,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Verifies a range of data items using this proof.
    /// `items` must be sorted by index.
    fn verify_range(
        &self,
        items: &[D],
        context: &Self::Context,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Trait for sources from which `OrderedData` or `Proof`s can be fetched.
pub trait DataSource<D: OrderedData, P: Proof<Index = D::Index>>:
    Debug + Send + Sync + 'static
{
    type Error: StdError + Send + Sync + 'static;

    /// Fetches a single data item by its index.
    fn fetch_item(
        &self,
        index: D::Index,
    ) -> impl Future<Output = Result<Option<D>, Self::Error>> + Send;

    /// Fetches a range of data items.
    /// The source may return fewer items than requested if they are unavailable.
    /// Items must be returned sorted by index.
    fn fetch_range(
        &self,
        range: RangeInclusive<D::Index>,
    ) -> impl Future<Output = Result<Vec<D>, Self::Error>> + Send;

    /// Fetches the latest available proof relevant to the given index range hint.
    /// This could be a proof for the latest item, a root hash, etc.
    /// The source should aim to return the proof covering the highest possible index.
    fn fetch_latest_proof(
        &self,
        hint_range: Option<RangeInclusive<D::Index>>,
    ) -> impl Future<Output = Result<Option<P>, Self::Error>> + Send;
}

/// Trait for persistent storage of `OrderedData`.
pub trait PersistentStore<D: OrderedData>: Debug + Send + Sync + 'static {
    type Error: StdError + Send + Sync + 'static;

    /// Stores a single data item.
    fn put(&mut self, item: &D) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Stores multiple data items.
    ///
    /// `items` must be sorted by index.
    fn put_range(&mut self, items: &[D]) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves a single data item by its index.
    fn get(&self, index: D::Index) -> impl Future<Output = Result<Option<D>, Self::Error>> + Send;

    /// Retrieves a range of data items.
    ///
    /// Items should be returned sorted by index.
    fn get_range(
        &self,
        range: RangeInclusive<D::Index>,
    ) -> impl Future<Output = Result<Vec<D>, Self::Error>> + Send;

    /// Returns the index of the latest contiguous item stored successfully.
    fn head(&self) -> impl Future<Output = Result<Option<D::Index>, Self::Error>> + Send;

    /// Returns the index of the first (oldest) item stored.
    fn tail(&self) -> impl Future<Output = Result<Option<D::Index>, Self::Error>> + Send;

    /// Finds the first missing index starting from `search_from_index`.
    ///
    /// Returns `Ok(None)` if no gap is found up to the current head.
    fn next_gap(
        &self,
        from: D::Index,
    ) -> impl Future<Output = Result<Option<D::Index>, Self::Error>> + Send;

    /// Prunes data *up to* (but not including) the specified index.
    fn prune(&mut self, to: D::Index) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Trait for observing (and possibly persisting) data as it becomes contiguous and verified.
pub trait Indexer<D: OrderedData>: Send + Sync + 'static {
    type Error: StdError + Send + Sync + 'static;

    /// Persist the item.
    ///
    /// Called when an item has been successfully verified and stored.
    fn index(&mut self, item: &D) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Common error type for the library.
#[derive(Error, Debug)]
pub enum Error {}
