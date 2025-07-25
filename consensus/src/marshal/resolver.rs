use commonware_resolver::{p2p, Resolver};
use commonware_utils::Array;
use std::collections::BTreeSet;

/// A wrapper around a resolver that tracks outstanding requests.
///
/// Allows for canceling of all requests less than a given value.
pub struct Tracked<K: Array> {
    /// The wrapped resolver.
    resolver: p2p::Mailbox<K>,
    /// The set of outstanding requests.
    outstanding: BTreeSet<K>,
}

impl<K: Array> Tracked<K> {
    /// Initialize a wrapped resolver.
    pub fn new(resolver: p2p::Mailbox<K>) -> Self {
        Self {
            resolver,
            outstanding: BTreeSet::new(),
        }
    }

    /// Cancel any outstanding requests less than the given value.
    pub async fn prune(&mut self, value: K) {
        let remaining = self.outstanding.split_off(&value);
        let to_cancel = std::mem::replace(&mut self.outstanding, remaining);
        for view in to_cancel {
            self.resolver.cancel(view).await;
        }
    }

    /// Fetch a value from the resolver.
    pub async fn fetch(&mut self, value: K) {
        if self.outstanding.insert(value.clone()) {
            self.resolver.fetch(value).await;
        }
    }

    /// Cancel a value from the resolver.
    pub async fn cancel(&mut self, value: K) {
        self.outstanding.remove(&value);
        self.resolver.cancel(value).await;
    }
}
