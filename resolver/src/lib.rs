//! TODO

use std::future::Future;

use bytes::Bytes;
use commonware_utils::Serialize;
use futures::channel::oneshot;
use std::fmt::Debug;

pub mod p2p;

/// Used as the key to identify unique data.
pub trait Key: Serialize + Clone + Debug + PartialEq + Eq + Ord + Send + Sync + 'static {}

/// Client is the interface responsible for fetching data from the network.
pub trait Client: Clone + Send + 'static {
    /// The key type used to identify data.
    type Key: Key;

    /// Fetch data from the network.
    fn fetch(&mut self, key: Self::Key) -> impl Future<Output = oneshot::Receiver<Bytes>> + Send;
}

/// Server is the interface responsible for serving data requested by the network.
pub trait Server: Clone + Send + 'static {
    /// The key type used to identify data.
    type Key: Key;

    /// Serve a request received from the network.
    fn serve(&mut self, key: Self::Key) -> impl Future<Output = oneshot::Receiver<Bytes>> + Send;
}

/// Director is the interface responsible for managing the list of peers that can be used to fetch data.
pub trait Director: Clone + Send + 'static {
    type PublicKey;

    /// Returns the current list of peers that can be used to fetch data.
    ///
    /// This is also used to filter requests from peers.
    fn peers(&self) -> Vec<Self::PublicKey>;
}
