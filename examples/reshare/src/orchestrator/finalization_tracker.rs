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
