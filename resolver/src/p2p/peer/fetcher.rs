use std::{
    marker::PhantomData,
    time::{Duration, SystemTime},
};

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
use thiserror::Error;
use tracing::warn;

use crate::p2p::wire::{self, peer_msg::Payload};

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
/// - Open: Sent to a peer and is waiting for a response.
/// - Held: Not successfully sent to a peer. Waiting to be retried.
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
    // Open State
    ////////////////////////////////////////

    // Helps find peers to fetch from
    requester: Requester<E, C>,

    // Bi-directional map between requester ids and keys
    // The requester does not necessarily exist in the requester still
    open: BiHashMap<ID, Key>,

    ////////////////////////////////////////
    // Held State
    ////////////////////////////////////////

    // If fetches fail to make a request to a peer, they are instead added to this map
    // and are retried after the deadline
    held: PrioritySet<Key, SystemTime>,

    ////////////////////////////////////////
    // Configuration
    ////////////////////////////////////////

    // Maximum number of fetches to be waiting for a response for
    max_size: usize,

    // Time that fetches remain in the held queue before being retried
    retry_timeout: Duration,
}

impl<E: Clock + GClock + Rng, C: Scheme, Key: Array, NetS: Sender<PublicKey = C::PublicKey>>
    Fetcher<E, C, Key, NetS>
{
    pub fn new(
        runtime: E,
        requester: Requester<E, C>,
        max_size: usize,
        retry_timeout: Duration,
    ) -> Self {
        Self {
            runtime,
            requester,
            open: BiHashMap::new(),
            held: PrioritySet::new(),
            max_size,
            retry_timeout,
            _s: PhantomData,
        }
    }

    /// Updates all data structures for fetching.
    ///
    /// Returns an error if the fetch was rejected.
    pub async fn fetch(&mut self, sender: &mut NetS, key: Key, shuffle: bool) -> Result<(), Error> {
        // If there are are too many fetches, return an error
        if self.len() >= self.max_size {
            return Err(Error::TooManyFetches);
        }

        // Check if the fetch is already in progress
        if self.open.contains_right(&key) || self.held.contains(&key) {
            return Err(Error::DuplicateFetch);
        }

        // Get peer to send request to
        let Some((peer, id)) = self.requester.request(shuffle) else {
            // If there are no peers, add the key to the held queue
            warn!(?key, "requester failed");
            self.hold(key);
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
                self.hold(key);
            }
            // If the message was sent to someone, add the request to the map
            Ok(()) => {
                self.open.insert(id, key);
            }
        }

        Ok(())
    }

    /// Cancels a fetch request.
    ///
    /// Returns `true` if the fetch was canceled.
    pub fn cancel(&mut self, key: &Key) -> bool {
        // Check the held map first
        if self.held.remove(key) {
            return true;
        }

        // Check the outstanding fetches map second
        self.open.remove_by_right(key).is_some()

        // Do not remove the requester entry.
        // It is useful for measuring performance if the peer ever responds.
        // If the peer never responds, the requester entry will be removed by timeout.
    }

    /// Adds a key to the held queue.
    /// Panics if the key is already held.
    pub fn hold(&mut self, key: Key) {
        assert!(!self.held.contains(&key));
        self.held
            .put(key, self.runtime.current() + self.retry_timeout);
    }

    /// Returns the deadline for the next held retry.
    pub fn get_held_deadline(&self) -> Option<SystemTime> {
        self.held.peek().map(|(_, deadline)| *deadline)
    }

    /// Returns the deadline for the next requester timeout.
    pub fn get_open_deadline(&self) -> Option<SystemTime> {
        self.requester.next().map(|(_, deadline)| deadline)
    }

    /// Removes and returns the held key with the earliest deadline.
    ///
    /// Panics if there are no held keys.
    pub fn pop_held(&mut self) -> Key {
        let (key, _deadline) = self.held.pop().unwrap();
        key
    }

    /// Removes and returns the key with the next requester timeout.
    ///
    /// Panics if there are no timeouts.
    pub fn pop_open(&mut self) -> Option<Key> {
        // The ID must exist
        let (id, _) = self.requester.next().unwrap();

        // The request must exist
        let request = self.requester.cancel(id).unwrap();
        self.requester.timeout(request);

        // Remove the existing request information, if any.
        // It is possible that the request was canceled before it timed out.
        self.open.remove_by_left(&id).map(|(_id, key)| key)
    }

    /// Returns the number of fetches that are currently being processed.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.open.len() + self.held.len()
    }

    /// Reconciles the list of peers that can be used to fetch data.
    pub fn reconcile(&mut self, keep: &[C::PublicKey]) {
        self.requester.reconcile(keep);
    }

    /// Updates the fetcher with the response from a peer.
    /// Returns the key that was fetched if the response was valid.
    /// Returns None if the response was invalid or not needed.
    pub fn got_response(&mut self, peer: &C::PublicKey, id: ID, has_response: bool) -> Option<Key> {
        // Update the requester
        let request = self.requester.handle(peer, id)?;

        // Update the peer's score.
        // If they don't give a reponse, treat it as a timeout
        match has_response {
            true => self.requester.resolve(request),
            false => self.requester.timeout(request),
        };

        // Remove and return the relevant key if it exists
        self.open.remove_by_left(&id).map(|(_id, key)| key)
    }
}
