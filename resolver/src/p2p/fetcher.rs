use crate::p2p::wire;
use bimap::BiHashMap;
use commonware_p2p::{
    utils::{
        codec::WrappedSender,
        requester::{Config, Requester, ID},
    },
    Recipients, Sender,
};
use commonware_runtime::{Clock, Metrics};
use commonware_utils::{Array, PrioritySet};
use governor::clock::Clock as GClock;
use rand::Rng;
use std::{
    marker::PhantomData,
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tracing::warn;

/// Errors that can occur when sending network messages.
#[derive(Error, Debug, PartialEq)]
enum SendError<S: Sender> {
    #[error("send returned empty")]
    Empty,
    #[error("send failed: {0}")]
    Failed(S::Error),
}

/// Maintains requests for data from other peers, called fetches.
///
/// Requests are called fetches. Fetches may be in one of two states:
/// - Active: Sent to a peer and is waiting for a response.
/// - Pending: Not successfully sent to a peer. Waiting to be retried by timeout.
///
/// Both types of requests will be retried after a timeout if not resolved (i.e. a response or a
/// cancellation). Upon retry, requests may either be placed in active or pending state again.
pub struct Fetcher<
    E: Clock + GClock + Rng + Metrics,
    P: Array,
    Key: Array,
    NetS: Sender<PublicKey = P>,
> {
    context: E,

    /// Helps find peers to fetch from and tracks which peers are assigned to which request ids.
    requester: Requester<E, P>,

    /// Manages active requests. If a fetch is sent to a peer, it is added to this map.
    active: BiHashMap<ID, Key>,

    /// Manages pending requests. If fetches fail to make a request to a peer, they are instead
    /// added to this map and are retried after the deadline.
    pending: PrioritySet<Key, SystemTime>,

    /// How long fetches remain in the pending queue before being retried
    retry_timeout: Duration,

    /// Whether requests are sent with priority over other network messages
    priority_requests: bool,

    /// Phantom data for networking types
    _s: PhantomData<NetS>,
}

impl<E: Clock + GClock + Rng + Metrics, P: Array, Key: Array, NetS: Sender<PublicKey = P>>
    Fetcher<E, P, Key, NetS>
{
    /// Creates a new fetcher.
    pub fn new(
        context: E,
        requester_config: Config<P>,
        retry_timeout: Duration,
        priority_requests: bool,
    ) -> Self {
        let requester = Requester::new(context.with_label("requester"), requester_config);
        Self {
            context,
            requester,
            active: BiHashMap::new(),
            pending: PrioritySet::new(),
            retry_timeout,
            priority_requests,
            _s: PhantomData,
        }
    }

    /// Makes a fetch request.
    ///
    /// If `is_new` is true, the fetch is treated as a new request.
    /// If false, the fetch is treated as a retry.
    ///
    /// Panics if the key is already being fetched.
    pub async fn fetch(
        &mut self,
        sender: &mut WrappedSender<NetS, (), wire::Message<Key>>,
        key: Key,
        is_new: bool,
    ) {
        // Panic if the key is already being fetched
        assert!(!self.contains(&key));

        // Get peer to send request to
        let shuffle = !is_new;
        let Some((peer, id)) = self.requester.request(shuffle) else {
            // If there are no peers, add the key to the pending queue
            warn!(?key, "requester failed");
            self.add_pending(key);
            return;
        };

        // Send message to peer
        let result = sender
            .send(
                Recipients::One(peer.clone()),
                wire::Message {
                    id,
                    payload: wire::Payload::Request(key.clone()),
                },
                self.priority_requests,
            )
            .await;
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
        let deadline = self.context.current() + self.retry_timeout;
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
    pub fn pop_by_id(&mut self, id: ID, peer: &P, has_response: bool) -> Option<Key> {
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

    /// Returns true if the fetch is in progress.
    pub fn contains(&self, key: &Key) -> bool {
        self.active.contains_right(key) || self.pending.contains(key)
    }

    /// Reconciles the list of peers that can be used to fetch data.
    pub fn reconcile(&mut self, keep: &[P]) {
        self.requester.reconcile(keep);
    }

    /// Blocks a peer from being used to fetch data.
    pub fn block(&mut self, peer: P) {
        self.requester.block(peer);
    }

    /// Returns the number of pending fetches.
    pub fn len_pending(&self) -> usize {
        self.pending.len()
    }

    /// Returns the number of active fetches.
    pub fn len_active(&self) -> usize {
        self.active.len()
    }

    /// Returns the number of blocked peers.
    pub fn len_blocked(&self) -> usize {
        self.requester.len_blocked()
    }
}
