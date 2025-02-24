use crate::p2p::wire::{self, peer_msg::Payload};
use bimap::BiHashMap;
use commonware_cryptography::{Array, Scheme};
use commonware_p2p::{
    utils::requester::{Requester, ID},
    Recipients, Sender,
};
use commonware_runtime::Clock;
use commonware_utils::PrioritySet;
use governor::clock::Clock as GClock;
use prost::Message;
use rand::Rng;
use std::{
    marker::PhantomData,
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tracing::warn;

/// Errors that can occur when using the fetcher.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("duplicate fetch")]
    DuplicateFetch,
    #[error("too many fetches")]
    TooManyFetches,
}

/// Errors that can occur when sending network messages.
/// Only used in this file.
#[derive(Error, Debug, PartialEq)]
enum SendError<S: Sender> {
    #[error("send failed")]
    Empty,
    #[error("send failed: {0}")]
    Failed(S::Error),
}

/// Maintains requests for data from other peers, called fetches.
///
/// Requests are called fetches. Fetches may be in one of two states:
/// - Active: Sent to a peer and is waiting for a response.
/// - Pending: Not successfully sent to a peer. Waiting to be retried.
pub struct Fetcher<
    E: Clock + GClock + Rng,
    C: Scheme,
    Key: Array,
    NetS: Sender<PublicKey = C::PublicKey>,
> {
    ////////////////////////////////////////
    // Interfaces
    ////////////////////////////////////////
    runtime: E,
    _s: PhantomData<NetS>,

    ////////////////////////////////////////
    // Active State
    ////////////////////////////////////////

    // Helps find peers to fetch from
    requester: Requester<E, C>,

    // Bi-directional map between requester ids and keys
    // The requester does not necessarily exist in the requester still
    active: BiHashMap<ID, Key>,

    ////////////////////////////////////////
    // Pending State
    ////////////////////////////////////////

    // If fetches fail to make a request to a peer, they are instead added to this map
    // and are retried after the deadline
    pending: PrioritySet<Key, SystemTime>,

    ////////////////////////////////////////
    // Configuration
    ////////////////////////////////////////

    // Time that fetches remain in the pending queue before being retried
    retry_timeout: Duration,
}

impl<E: Clock + GClock + Rng, C: Scheme, Key: Array, NetS: Sender<PublicKey = C::PublicKey>>
    Fetcher<E, C, Key, NetS>
{
    pub fn new(runtime: E, requester: Requester<E, C>, retry_timeout: Duration) -> Self {
        Self {
            runtime,
            requester,
            active: BiHashMap::new(),
            pending: PrioritySet::new(),
            retry_timeout,
            _s: PhantomData,
        }
    }

    /// Makes a new fetch request.
    pub async fn fetch_new(&mut self, sender: &mut NetS, key: Key) -> Result<(), Error> {
        self.fetch_inner(sender, key, false).await
    }

    /// Makes a fetch request that has been popped.
    ///
    /// The request must have been removed before immediately before this is called using
    /// one of the `pop_*` methods.
    pub async fn fetch_retry(&mut self, sender: &mut NetS, key: Key) {
        // Panic if an error was returned.
        self.fetch_inner(sender, key, true).await.unwrap();
    }

    /// Updates all data structures for fetching.
    ///
    /// Returns an error if the fetch was rejected.
    async fn fetch_inner(
        &mut self,
        sender: &mut NetS,
        key: Key,
        shuffle: bool,
    ) -> Result<(), Error> {
        // Check if the fetch is already in progress
        if self.active.contains_right(&key) || self.pending.contains(&key) {
            return Err(Error::DuplicateFetch);
        }

        // Get peer to send request to
        let Some((peer, id)) = self.requester.request(shuffle) else {
            // If there are no peers, add the key to the pending queue
            warn!(?key, "requester failed");
            self.add_pending(key);
            return Ok(());
        };

        // Send message to peer
        let payload = Some(Payload::Request(key.to_vec()));
        let msg = wire::PeerMsg { id, payload }.encode_to_vec().into();
        let result = sender.send(Recipients::One(peer.clone()), msg, false).await;
        let result = match result {
            Err(err) => Err(SendError::Failed::<NetS>(err)),
            Ok(to) if to.is_empty() => Err(SendError::Empty),
            Ok(_) => Ok(()),
        };

        // Insert the request into the relevant map
        match result {
            // If the message was not sent successfully, treat it instantly as a peer timeout
            Err(err) => {
                warn!(?err, ?peer, "send failed");
                let req = self.requester.handle(&peer, id).unwrap(); // Unwrap is safe
                self.requester.timeout(req);
                self.add_pending(key);
            }
            // If the message was sent to someone, add the request to the map
            Ok(()) => {
                self.active.insert(id, key);
            }
        }

        Ok(())
    }

    /// Cancels a fetch request.
    ///
    /// Returns `true` if the fetch was canceled.
    pub fn cancel(&mut self, key: &Key) -> bool {
        // Check the pending queue first
        if self.pending.remove(key) {
            return true;
        }

        // Check the outstanding fetches map second
        self.active.remove_by_right(key).is_some()

        // Do not remove the requester entry.
        // It is useful for measuring performance if the peer ever responds.
        // If the peer never responds, the requester entry will be removed by timeout.
    }

    /// Adds a key to the pending queue.
    ///
    /// Panics if the key is already pending.
    pub fn add_pending(&mut self, key: Key) {
        assert!(!self.pending.contains(&key));
        let deadline = self.runtime.current() + self.retry_timeout;
        self.pending.put(key, deadline);
    }

    /// Returns the deadline for the next pending retry.
    pub fn get_pending_deadline(&self) -> Option<SystemTime> {
        self.pending.peek().map(|(_, deadline)| *deadline)
    }

    /// Returns the deadline for the next requester timeout.
    pub fn get_active_deadline(&self) -> Option<SystemTime> {
        self.requester.next().map(|(_, deadline)| deadline)
    }

    /// Removes and returns the pending key with the earliest deadline.
    ///
    /// Panics if there are no pending keys.
    pub fn pop_pending(&mut self) -> Key {
        let (key, _deadline) = self.pending.pop().unwrap();
        key
    }

    /// Removes and returns the key with the next requester timeout.
    ///
    /// Panics if there are no timeouts.
    pub fn pop_active(&mut self) -> Option<Key> {
        // The ID must exist
        let (id, _) = self.requester.next().unwrap();

        // The request must exist
        let request = self.requester.cancel(id).unwrap();
        self.requester.timeout(request);

        // Remove the existing request information, if any.
        // It is possible that the request was canceled before it timed out.
        self.active.remove_by_left(&id).map(|(_id, key)| key)
    }

    /// Processes a response from a peer. Removes and returns the relevant key.
    ///
    /// Returns the key that was fetched if the response was valid.
    /// Returns None if the response was invalid or not needed.
    pub fn pop_by_id(&mut self, id: ID, peer: &C::PublicKey, has_response: bool) -> Option<Key> {
        // Pop the request from requester if the peer was assigned to this id, otherwise return none
        let request = self.requester.handle(peer, id)?;

        // Update the peer's performance, treating a lack of response as a timeout
        match has_response {
            true => self.requester.resolve(request),
            false => self.requester.timeout(request),
        };

        // Remove and return the relevant key if it exists
        // The key may not exist if the request was canceled before the peer responded
        self.active.remove_by_left(&id).map(|(_id, key)| key)
    }

    /// Returns the number of fetches that are currently being processed.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.active.len() + self.pending.len()
    }

    /// Reconciles the list of peers that can be used to fetch data.
    pub fn reconcile(&mut self, keep: &[C::PublicKey]) {
        self.requester.reconcile(keep);
    }
}
