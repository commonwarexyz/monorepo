//! Finalization request tracking for epoch transitions.
//!
//! Tracks peers that should have a finalization for an epoch, manages in-flight
//! requests with timeout handling, and emits timeout events when requests need
//! to be retried with a different peer.

use commonware_consensus::types::Epoch;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, Handle, Metrics, Spawner};
use futures::channel::mpsc;
use std::{collections::VecDeque, time::Duration};

/// Maximum number of peers to track per epoch.
const MAX_PEERS: usize = 10;

/// Tracks finalization requests and known peers for a single epoch.
/// Emits timeout events via a stream when requests need to be retried.
///
/// Only tracks one epoch at a time since we only ever request a finalization for our
/// latest known epoch.
pub struct FinalizationTracker<E, P> {
    /// Runtime context for spawning timeout tasks.
    context: E,
    /// Timeout duration for requests.
    timeout: Duration,
    /// The epoch we're currently tracking (if any).
    epoch: Option<Epoch>,
    /// Peers that are known to likely have a finalization for the epoch.
    /// Limited to MAX_PEERS entries.
    known_peers: VecDeque<P>,
    /// Current in-flight request, if any.
    pending: Option<PendingRequest<P>>,
    /// Channel for emitting timeout events.
    event_sender: mpsc::Sender<Epoch>,
}

struct PendingRequest<P> {
    peer: P,
    timeout_handle: Handle<()>,
}

impl<P> Drop for PendingRequest<P> {
    fn drop(&mut self) {
        self.timeout_handle.abort();
    }
}

impl<E, P> FinalizationTracker<E, P>
where
    E: Spawner + Metrics + Clock,
    P: PublicKey,
{
    /// Creates a new [`FinalizationTracker`] and returns its event stream.
    ///
    /// The event stream emits epochs when a request times out and needs to be retried.
    pub fn new(context: E, timeout: Duration) -> (Self, mpsc::Receiver<Epoch>) {
        let (sender, receiver) = mpsc::channel(1);
        (
            Self {
                context,
                timeout,
                epoch: None,
                known_peers: VecDeque::new(),
                pending: None,
                event_sender: sender,
            },
            receiver,
        )
    }

    /// Try to initiate a request to a peer that should have the finalization for an
    /// epoch.
    ///
    /// If `epoch` differs from current, resets state to the new epoch.
    /// Returns `true` if no pending request exists (caller should send request).
    /// Returns `false` if a request is already in-flight or the peer is a duplicate.
    pub fn try_request(&mut self, epoch: Epoch, peer: P) -> bool {
        // If different epoch, reset state
        if self.epoch != Some(epoch) {
            self.epoch = Some(epoch);
            self.known_peers.clear();
            self.pending = None;
        }

        // Ignore duplicates
        if self.known_peers.contains(&peer) {
            return false;
        }

        // Ignore if this peer is the current pending request
        if let Some(pending) = &self.pending {
            if pending.peer == peer {
                return false;
            }
        }

        // If no pending request, caller should send to this peer
        if self.pending.is_none() {
            return true;
        }

        // Add to the queue for later, evicting oldest if at capacity
        if self.known_peers.len() >= MAX_PEERS {
            self.known_peers.pop_front();
        }
        self.known_peers.push_back(peer);
        false
    }

    /// Get the next peer to request from (after a timeout).
    ///
    /// Returns `None` if there are no more peers to try.
    pub fn next_peer(&mut self) -> Option<P> {
        // Prefer the last peer we tracked
        self.known_peers.pop_back()
    }

    /// Mark a request as sent to a peer. Spawns a timeout task.
    ///
    /// When the timeout fires (and hasn't been aborted), an event is sent
    /// to the event stream with the epoch.
    pub fn mark_sent(&mut self, epoch: Epoch, peer: P) {
        let mut sender = self.event_sender.clone();
        let timeout = self.timeout;
        let timeout_handle =
            self.context
                .with_label("request_timeout")
                .spawn(move |context| async move {
                    context.sleep(timeout).await;
                    let _ = sender.try_send(epoch);
                });

        self.pending = Some(PendingRequest {
            peer,
            timeout_handle,
        });
    }

    /// Handle a response from a peer.
    ///
    /// Returns `true` if this was the expected response (cancels timeout),
    /// `false` if it should be ignored.
    pub fn handle_response(&mut self, epoch: Epoch, from: &P) -> bool {
        if self.epoch != Some(epoch) {
            return false;
        }
        if let Some(pending) = self.pending.take() {
            if &pending.peer == from {
                return true;
            }
            self.pending = Some(pending);
        }
        false
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.epoch = None;
        self.known_peers.clear();
        self.pending = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        PrivateKeyExt, Signer,
    };
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{deterministic, Clock, Runner};
    use futures::StreamExt;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn make_peer(seed: u64) -> PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    #[test_traced]
    fn test_try_request() {
        let runner = deterministic::Runner::timed(Duration::from_secs(1));
        runner.start(|context| async move {
            let (mut tracker, _events) = FinalizationTracker::new(context, TIMEOUT);

            let peer1 = make_peer(1);
            let peer2 = make_peer(2);
            let peer3 = make_peer(3);
            let epoch1 = Epoch::new(1);
            let epoch2 = Epoch::new(2);

            // No pending request
            assert!(tracker.try_request(epoch1, peer1.clone()));
            tracker.mark_sent(epoch1, peer1.clone());

            // Duplicate of pending peer, ignored (not queued)
            assert!(!tracker.try_request(epoch1, peer1.clone()));
            assert_eq!(tracker.next_peer(), None);

            // Pending exists, returns false and queues peer
            assert!(!tracker.try_request(epoch1, peer2.clone()));
            assert_eq!(tracker.next_peer(), Some(peer2.clone()));

            // Duplicate peer, ignored
            tracker.mark_sent(epoch1, peer1.clone());
            assert!(!tracker.try_request(epoch1, peer2.clone()));
            assert!(!tracker.try_request(epoch1, peer2.clone()));
            assert_eq!(tracker.next_peer(), Some(peer2.clone()));
            assert_eq!(tracker.next_peer(), None);

            // Epoch change resets state
            tracker.mark_sent(epoch1, peer1);
            assert!(!tracker.try_request(epoch1, peer2));
            assert!(tracker.try_request(epoch2, peer3));
            assert_eq!(tracker.next_peer(), None);
        });
    }

    #[test_traced]
    fn test_eviction() {
        let runner = deterministic::Runner::timed(Duration::from_secs(1));
        runner.start(|context| async move {
            let (mut tracker, _events) = FinalizationTracker::new(context, TIMEOUT);

            let epoch = Epoch::new(1);
            let first_peer = make_peer(0);

            // Start pending request
            assert!(tracker.try_request(epoch, first_peer.clone()));
            tracker.mark_sent(epoch, first_peer);

            // Fill queue
            for i in 1..=MAX_PEERS {
                assert!(!tracker.try_request(epoch, make_peer(i as u64)));
            }

            // Add one more, evicts oldest
            let new_peer = make_peer(100);
            assert!(!tracker.try_request(epoch, new_peer.clone()));

            // Prefer newest
            assert_eq!(tracker.next_peer(), Some(new_peer));
            assert_eq!(tracker.next_peer(), Some(make_peer(MAX_PEERS as u64)));
        });
    }

    #[test_traced]
    fn test_handle_response() {
        let runner = deterministic::Runner::timed(Duration::from_secs(1));
        runner.start(|context| async move {
            let (mut tracker, _events) = FinalizationTracker::new(context, TIMEOUT);

            let epoch1 = Epoch::new(1);
            let epoch2 = Epoch::new(2);
            let peer1 = make_peer(1);
            let peer2 = make_peer(2);

            assert!(tracker.try_request(epoch1, peer1.clone()));
            tracker.mark_sent(epoch1, peer1.clone());

            // Wrong epoch, rejected
            assert!(!tracker.handle_response(epoch2, &peer1));

            // Wrong peer, rejected
            assert!(!tracker.handle_response(epoch1, &peer2));

            // Correct epoch and peer, accepted
            assert!(tracker.handle_response(epoch1, &peer1));

            // No more pending
            assert!(!tracker.handle_response(epoch1, &peer1));
        });
    }

    #[test_traced]
    fn test_clear() {
        let runner = deterministic::Runner::timed(Duration::from_secs(1));
        runner.start(|context| async move {
            let (mut tracker, _events) = FinalizationTracker::new(context, TIMEOUT);

            let epoch = Epoch::new(1);

            assert!(tracker.try_request(epoch, make_peer(1)));
            tracker.mark_sent(epoch, make_peer(1));
            assert!(!tracker.try_request(epoch, make_peer(2)));

            tracker.clear();

            // Fresh state after clear
            assert!(tracker.try_request(epoch, make_peer(3)));
            assert_eq!(tracker.next_peer(), None);
        });
    }

    #[test_traced]
    fn test_timeout_and_cancellation() {
        let runner = deterministic::Runner::timed(Duration::from_secs(10));
        runner.start(|context| async move {
            let timeout = Duration::from_millis(100);
            let (mut tracker, mut events) = FinalizationTracker::new(context.clone(), timeout);

            let epoch = Epoch::new(1);
            let peer1 = make_peer(1);
            let peer2 = make_peer(2);

            // Timeout fires when not cancelled
            assert!(tracker.try_request(epoch, peer1.clone()));
            tracker.mark_sent(epoch, peer1.clone());
            assert!(!tracker.try_request(epoch, peer2.clone()));
            context.sleep(Duration::from_millis(200)).await;
            assert_eq!(events.next().await, Some(epoch));

            // After timeout, get next peer and retry
            assert_eq!(tracker.next_peer(), Some(peer2.clone()));
            tracker.mark_sent(epoch, peer2.clone());

            // Response before timeout cancels it
            context.sleep(Duration::from_millis(50)).await;
            assert!(tracker.handle_response(epoch, &peer2));

            // Verify no event fires
            select! {
                _ = events.next() => { panic!("timeout should have been cancelled") },
                _ = context.sleep(Duration::from_millis(200)) => {},
            };
        });
    }
}
