//! Subscribers attached to resolver requests made by the resolver [`Actor`](super::Actor).

use super::mailbox::Reply;
use std::cmp::Ordering;

/// A caller's reply route, identified independently of the peer-visible request.
pub(super) struct Subscriber<R> {
    pub id: u64,
    pub reply: Reply<R>,
}

impl<R> Clone for Subscriber<R> {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            reply: self.reply.clone(),
        }
    }
}

impl<R> PartialEq for Subscriber<R> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<R> Eq for Subscriber<R> {}

impl<R> PartialOrd for Subscriber<R> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<R> Ord for Subscriber<R> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}
