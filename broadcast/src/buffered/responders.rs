use commonware_utils::{Array, PrioritySet};
use futures::channel::oneshot;
use std::{
    collections::{BTreeSet, HashMap},
    time::SystemTime,
};

/// Used to store and manage pending requests from the application.
pub struct Responders<D: Array, B> {
    /// The next ID to assign to a new request.
    next_id: u64,

    /// The pending requests by ID.
    /// Allows for efficient removal of a request by ID.
    responders: HashMap<u64, (D, oneshot::Sender<B>)>,

    /// Request IDs by deadline.
    /// Allows for tracking the next deadline.
    deadlines: PrioritySet<u64, SystemTime>,

    /// Request IDs by digest.
    /// Allows for efficient removal of all pending requests for a given digest.
    /// BTreeSet is used to ensure deterministic iteration order.
    digests: HashMap<D, BTreeSet<u64>>,
}

impl<D: Array, B> Responders<D, B> {
    /// Creates a new `Responders`.
    pub fn new() -> Self {
        Self {
            next_id: 0,
            responders: HashMap::new(),
            deadlines: PrioritySet::new(),
            digests: HashMap::new(),
        }
    }

    /// Returns the next deadline from the list of pending requests.
    pub fn next_deadline(&self) -> Option<SystemTime> {
        self.deadlines.peek().map(|(_, deadline)| *deadline)
    }

    /// Removes the next deadline from the list of pending requests.
    ///
    /// Panics if there are no pending requests.
    /// Does not check if the deadline has passed.
    pub fn pop_deadline(&mut self) {
        // Remove the next deadline, panic if there are no pending requests
        let (id, _deadline) = self.deadlines.pop().expect("missing deadline");

        // Remove the responder; we need the digest to remove the ID from the digest list
        let (digest, _responder) = self.responders.remove(&id).expect("missing responder");

        // Remove the ID from the digest list, and remove the digest list if it's empty
        if let Some(ids) = self.digests.get_mut(&digest) {
            assert!(ids.remove(&id), "missing id");
            if ids.is_empty() {
                self.digests.remove(&digest);
            }
        }
    }

    /// Adds a new responder to the list of pending requests.
    pub fn add(&mut self, digest: D, responder: oneshot::Sender<B>, deadline: SystemTime) {
        // Increment and return ID
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        assert!(!self.responders.contains_key(&id), "duplicate ID");

        // Update internal data structures
        self.responders.insert(id, (digest.clone(), responder));
        self.deadlines.put(id, deadline);
        self.digests.entry(digest).or_default().insert(id);
    }

    /// Removes and returns all responders for the given digest.
    pub fn take(&mut self, digest: &D) -> Vec<oneshot::Sender<B>> {
        // If the digest isn't found, return an empty vector
        let Some(ids) = self.digests.remove(digest) else {
            return Vec::new();
        };

        // Clean up and collect responders
        let mut responders = Vec::with_capacity(ids.len());
        for id in ids {
            // Remove from deadlines
            assert!(self.deadlines.remove(&id), "missing deadline");

            // Extract responder
            let (_, responder) = self.responders.remove(&id).expect("missing responder");
            responders.push(responder);
        }

        responders
    }
}
