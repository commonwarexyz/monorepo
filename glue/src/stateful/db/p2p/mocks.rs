//! Observe resolver submissions without running a network actor.

use commonware_actor::Feedback;
use commonware_resolver::{Fetch, Resolver, request};
use commonware_storage::{mmr, qmdb::sync::Request};
use commonware_utils::channel::mpsc;

/// Sends fetches to the test so it can deliver responses with their assigned identities.
#[derive(Clone)]
pub(super) struct RecordingResolver(
    mpsc::UnboundedSender<Fetch<Request<mmr::Family>, request::Id>>,
);

impl Resolver for RecordingResolver {
    type Key = Request<mmr::Family>;
    type Subscriber = request::Id;

    fn fetch<F>(&mut self, fetch: F) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        self.0
            .send(fetch.into())
            .map_or(Feedback::Closed, |_| Feedback::Ok)
    }

    fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
    where
        F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
    {
        for fetch in fetches {
            if self.fetch(fetch) == Feedback::Closed {
                return Feedback::Closed;
            }
        }
        Feedback::Ok
    }

    fn retain(
        &mut self,
        _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        Feedback::Ok
    }
}

/// Capture fetches for tests of database attachment, decoding, and handler queue policy.
pub(super) fn resolver() -> (
    RecordingResolver,
    mpsc::UnboundedReceiver<Fetch<Request<mmr::Family>, request::Id>>,
) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (RecordingResolver(sender), receiver)
}
