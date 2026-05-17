use crate::{Fetch, Resolver};
use commonware_actor::{
    mailbox::{Overflow, Policy, Sender},
    Feedback,
};
use commonware_cryptography::PublicKey;
use commonware_utils::{vec::NonEmptyVec, Span};
use std::collections::VecDeque;

type Predicate<S> = Box<dyn Fn(&S) -> bool + Send>;

/// A request to fetch data, optionally with target peers.
pub struct FetchRequest<R, P, S> {
    /// The request to fetch.
    pub request: R,
    /// The subscribers used to decide whether the fetch should be retained.
    pub subscribers: Vec<S>,
    /// Target peers to restrict the fetch to.
    ///
    /// - `None`: No targeting (or clear existing targeting), try any available peer
    /// - `Some(peers)`: Only try the specified peers
    pub targets: Option<NonEmptyVec<P>>,
}

/// Messages that can be sent to the peer actor.
pub enum Message<R, P, S> {
    /// Initiate fetch requests.
    Fetch(Vec<FetchRequest<R, P, S>>),

    /// Cancel a subscriber's outstanding fetch interest.
    Cancel { subscriber: S },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests without a subscriber that satisfies the predicate.
    Retain { predicate: Predicate<S> },
}

enum Modification<S> {
    Cancel { subscriber: S },
    Retain { predicate: Predicate<S> },
}

/// Pending resolver messages retained after the mailbox fills.
pub struct Pending<R, P, S> {
    clear: bool,
    modifications: VecDeque<Modification<S>>,
    fetches: Vec<FetchRequest<R, P, S>>,
}

impl<R, P, S> Default for Pending<R, P, S> {
    fn default() -> Self {
        Self {
            clear: false,
            modifications: VecDeque::new(),
            fetches: Vec::new(),
        }
    }
}

impl<R, P, S> Overflow<Message<R, P, S>> for Pending<R, P, S> {
    fn is_empty(&self) -> bool {
        !self.clear && self.modifications.is_empty() && self.fetches.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<R, P, S>) -> Option<Message<R, P, S>>,
    {
        // Clear drains before later modifications and fetches.
        if self.clear {
            self.clear = false;
            if let Some(message) = push(Message::Clear) {
                self.push_front(message);
                return;
            }
        }

        // Drain cancels and retains in the order they were received.
        while let Some(modification) = self.modifications.pop_front() {
            let message = match modification {
                Modification::Cancel { subscriber } => Message::Cancel { subscriber },
                Modification::Retain { predicate } => Message::Retain { predicate },
            };
            if let Some(message) = push(message) {
                self.push_front(message);
                return;
            }
        }

        // Fetches are deduplicated and drained as one batch.
        if !self.fetches.is_empty() {
            let fetches = std::mem::take(&mut self.fetches);
            if let Some(message) = push(Message::Fetch(fetches)) {
                self.push_front(message);
            }
        }
    }
}

impl<R, P, S> Pending<R, P, S> {
    fn push_front(&mut self, message: Message<R, P, S>) {
        match message {
            Message::Clear => self.clear = true,
            Message::Retain { predicate } => {
                self.modifications
                    .push_front(Modification::Retain { predicate });
            }
            Message::Cancel { subscriber } => {
                self.modifications
                    .push_front(Modification::Cancel { subscriber });
            }
            Message::Fetch(fetches) => {
                self.fetches.splice(0..0, fetches);
            }
        }
    }
}

fn retain_fetch<S>(
    subscribers: &mut Vec<S>,
    predicate: &(dyn Fn(&S) -> bool + Send),
) -> bool {
    subscribers.retain(|subscriber| predicate(subscriber));
    !subscribers.is_empty()
}

fn cancel_subscriber<S: Eq>(subscribers: &mut Vec<S>, canceled: &S) -> bool {
    subscribers.retain(|subscriber| subscriber != canceled);
    !subscribers.is_empty()
}

// Merge target metadata for duplicate pending fetches.
fn merge_targets<P: Eq>(existing: &mut Option<NonEmptyVec<P>>, incoming: Option<NonEmptyVec<P>>) {
    // An unrestricted fetch clears existing targets.
    let Some(incoming) = incoming else {
        *existing = None;
        return;
    };

    // Existing unrestricted fetch already covers all targets.
    let Some(existing) = existing else {
        return;
    };

    // Merge target sets without duplicating peers.
    for target in incoming {
        if !existing.contains(&target) {
            existing.push(target);
        }
    }
}

impl<R, P, S> Policy for Message<R, P, S>
where
    R: Clone + Eq,
    P: Eq,
    S: Eq,
{
    type Overflow = Pending<R, P, S>;

    fn handle(overflow: &mut Pending<R, P, S>, message: Self) {
        match message {
            Self::Fetch(requests) => {
                for request in requests {
                    let FetchRequest {
                        request,
                        subscribers,
                        targets,
                    } = request;
                    if subscribers.is_empty() {
                        continue;
                    }

                    // Merge duplicate fetches for the same request.
                    if let Some(existing) = overflow
                        .fetches
                        .iter_mut()
                        .find(|existing| existing.request == request)
                    {
                        existing.subscribers.extend(subscribers);
                        merge_targets(&mut existing.targets, targets);
                    } else {
                        overflow.fetches.push(FetchRequest {
                            request,
                            subscribers,
                            targets,
                        });
                    }
                }
            }
            Self::Cancel { subscriber } => {
                // Cancel removes this subscriber from any pending fetches.
                overflow
                    .fetches
                    .retain_mut(|fetch| cancel_subscriber(&mut fetch.subscribers, &subscriber));

                // Retain only the first queued cancel for a subscriber.
                if overflow
                    .modifications
                    .iter()
                    .all(|modification| {
                        !matches!(modification, Modification::Cancel { subscriber: cancel } if cancel == &subscriber)
                    })
                {
                    overflow
                        .modifications
                        .push_back(Modification::Cancel { subscriber });
                }
            }
            Self::Clear => {
                // Clear supersedes pending modifications and fetches.
                overflow.clear = true;
                overflow.modifications.clear();
                overflow.fetches.clear();
            }
            Self::Retain { predicate } => {
                // Retain prunes pending fetch subscribers before queued fetches drain.
                overflow
                    .fetches
                    .retain_mut(|request| {
                        retain_fetch(&mut request.subscribers, predicate.as_ref())
                    });
                overflow
                    .modifications
                    .push_back(Modification::Retain { predicate });
            }
        }
    }
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<R: Span, P: Eq, S: Eq> {
    /// The channel that delivers messages to the peer actor.
    sender: Sender<Message<R, P, S>>,
}

impl<R: Span, P: Eq, S: Eq> Mailbox<R, P, S> {
    /// Create a new mailbox.
    pub(super) const fn new(sender: Sender<Message<R, P, S>>) -> Self {
        Self { sender }
    }
}

impl<R, P, S> Resolver for Mailbox<R, P, S>
where
    R: Span,
    P: PublicKey,
    S: Clone + Eq + Send + 'static,
{
    type Request = R;
    type Subscriber = S;
    type PublicKey = P;

    /// Send a fetch request to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch<D>(&mut self, request: D) -> Feedback
    where
        D: Into<Fetch<Self::Request, Self::Subscriber>> + Send,
    {
        let request = request.into();
        let (request, subscriber) = request.into_parts();
        self.sender.enqueue(Message::Fetch(vec![FetchRequest {
            request,
            subscribers: vec![subscriber],
            targets: None,
        }]))
    }

    /// Send a fetch request to the peer actor for a batch of requests.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all<D>(&mut self, requests: Vec<D>) -> Feedback
    where
        D: Into<Fetch<Self::Request, Self::Subscriber>> + Send,
    {
        self.sender.enqueue(Message::Fetch(
            requests
                .into_iter()
                .map(|request| {
                    let (request, subscriber) = request.into().into_parts();
                    FetchRequest {
                        request,
                        subscribers: vec![subscriber],
                        targets: None,
                    }
                })
                .collect(),
        ))
    }

    /// Send a targeted fetch request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_targeted(
        &mut self,
        request: impl Into<Fetch<Self::Request, Self::Subscriber>> + Send,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        let request = request.into();
        let (request, subscriber) = request.into_parts();
        self.sender.enqueue(Message::Fetch(vec![FetchRequest {
            request,
            subscribers: vec![subscriber],
            targets: Some(targets),
        }]))
    }

    /// Send targeted fetch requests to the peer actor for a batch of keys.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all_targeted<D>(
        &mut self,
        requests: Vec<(D, NonEmptyVec<Self::PublicKey>)>,
    ) -> Feedback
    where
        D: Into<Fetch<Self::Request, Self::Subscriber>> + Send,
    {
        self.sender.enqueue(Message::Fetch(
            requests
                .into_iter()
                .map(|(request, targets)| {
                    let (request, subscriber) = request.into().into_parts();
                    FetchRequest {
                        request,
                        subscribers: vec![subscriber],
                        targets: Some(targets),
                    }
                })
                .collect(),
        ))
    }

    /// Send a cancel request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn cancel(&mut self, subscriber: Self::Subscriber) -> Feedback {
        self.sender.enqueue(Message::Cancel { subscriber })
    }

    /// Send a retain request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn retain(
        &mut self,
        predicate: impl Fn(&Self::Subscriber) -> bool + Send + 'static,
    ) -> Feedback {
        self.sender.enqueue(Message::Retain {
            predicate: Box::new(predicate),
        })
    }

    /// Send a clear request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn clear(&mut self) -> Feedback {
        self.sender.enqueue(Message::Clear)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestMessage = Message<u8, u8, u16>;
    type TestPending = Pending<u8, u8, u16>;

    fn fetch(request: u8, subscriber: u16, targets: Option<NonEmptyVec<u8>>) -> TestMessage {
        Message::Fetch(vec![FetchRequest {
            request,
            subscribers: vec![subscriber],
            targets,
        }])
    }

    fn fetch_with_subscribers(request: u8, subscribers: Vec<u16>, targets: Option<NonEmptyVec<u8>>) -> TestMessage {
        Message::Fetch(vec![FetchRequest {
            request,
            subscribers,
            targets,
        }])
    }

    fn subscriber_is(value: u16) -> impl Fn(&u16) -> bool + Send {
        move |subscriber| *subscriber == value
    }

    fn targets(values: &[u8]) -> NonEmptyVec<u8> {
        NonEmptyVec::from_unchecked(values.to_vec())
    }

    fn drain(pending: &mut TestPending) -> Vec<TestMessage> {
        let mut messages = Vec::new();
        Overflow::drain(pending, |message| {
            messages.push(message);
            None
        });
        messages
    }

    fn assert_fetch(message: &TestMessage, expected_request: u8, expected_targets: Option<&[u8]>) {
        let Message::Fetch(requests) = message else {
            panic!("expected fetch");
        };
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].request, expected_request);
        match (&requests[0].targets, expected_targets) {
            (None, None) => {}
            (Some(actual), Some(expected)) => assert_eq!(&actual[..], expected),
            _ => panic!("unexpected targets"),
        }
    }

    fn assert_fetch_requests(message: &TestMessage, expected: &[u8]) {
        let Message::Fetch(requests) = message else {
            panic!("expected fetch");
        };
        let actual: Vec<_> = requests.iter().map(|request| request.request).collect();
        assert_eq!(actual, expected);
    }

    fn assert_fetch_subscribers(
        message: &TestMessage,
        expected_request: u8,
        expected_subscribers: &[u16],
    ) {
        let Message::Fetch(requests) = message else {
            panic!("expected fetch");
        };
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].request, expected_request);
        assert_eq!(requests[0].subscribers, expected_subscribers);
    }

    #[test]
    fn targeted_fetches_for_same_request_are_merged() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch(1, 10, Some(targets(&[2, 3]))));
        Policy::handle(&mut pending, fetch(1, 11, Some(targets(&[3, 4]))));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_fetch(&messages[0], 1, Some(&[2, 3, 4]));
        assert_fetch_subscribers(&messages[0], 1, &[10, 11]);
    }

    #[test]
    fn duplicate_fetches_for_same_request_merge_subscribers() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![10], None));
        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![11], None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_fetch_subscribers(&messages[0], 1, &[10, 11]);
    }

    #[test]
    fn unrestricted_fetch_dominates_targeted_fetches() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch(1, 10, Some(targets(&[2]))));
        Policy::handle(&mut pending, fetch(1, 11, None));
        Policy::handle(&mut pending, fetch(1, 12, Some(targets(&[3]))));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert_fetch(&messages[0], 1, None);
    }

    #[test]
    fn cancel_removes_pending_subscriber_but_is_retained() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch(1, 10, None));
        Policy::handle(&mut pending, fetch(2, 11, None));
        Policy::handle(&mut pending, Message::Cancel { subscriber: 10 });

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Cancel { subscriber: 10 }));
        assert_fetch(&messages[1], 2, None);
    }

    #[test]
    fn fetch_after_cancel_is_retained() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, Message::Cancel { subscriber: 10 });
        Policy::handle(&mut pending, fetch(1, 10, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Cancel { subscriber: 10 }));
        assert_fetch(&messages[1], 1, None);
    }

    #[test]
    fn duplicate_cancel_keeps_original_position() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, Message::Cancel { subscriber: 10 });
        Policy::handle(&mut pending, fetch(2, 11, None));
        Policy::handle(&mut pending, Message::Cancel { subscriber: 10 });

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Cancel { subscriber: 10 }));
        assert_fetch(&messages[1], 2, None);
    }

    #[test]
    fn retain_removes_fetches_for_dropped_subscribers() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch(1, 10, None));
        Policy::handle(&mut pending, fetch(2, 11, None));
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(subscriber_is(11)),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Retain { .. }));
        assert_fetch(&messages[1], 2, None);
    }

    #[test]
    fn retain_prunes_pending_fetch_subscribers() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![10, 11], None));
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(subscriber_is(11)),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Retain { .. }));
        assert_fetch_subscribers(&messages[1], 1, &[11]);
    }

    #[test]
    fn retain_drops_pending_fetch_when_all_subscribers_are_dropped() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch_with_subscribers(1, vec![10, 11], None));
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(subscriber_is(12)),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 1);
        assert!(matches!(messages[0], Message::Retain { .. }));
    }

    #[test]
    fn clear_supersedes_prior_pending_actions() {
        let mut pending = TestPending::default();

        Policy::handle(&mut pending, fetch(1, 10, None));
        Policy::handle(&mut pending, Message::Cancel { subscriber: 11 });
        Policy::handle(&mut pending, Message::Clear);
        Policy::handle(&mut pending, fetch(3, 12, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Clear));
        assert_fetch(&messages[1], 3, None);
    }

    #[test]
    fn fetch_after_retain_is_retained_when_subscriber_is_dropped() {
        let mut pending = TestPending::default();

        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(|subscriber| *subscriber != 10),
            },
        );
        Policy::handle(&mut pending, fetch(1, 10, None));
        Policy::handle(&mut pending, fetch(2, 11, None));

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Retain { .. }));
        assert_fetch_requests(&messages[1], &[1, 2]);
    }

    #[test]
    fn clear_supersedes_prior_modifications() {
        let mut pending = TestPending::default();

        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(|subscriber| *subscriber != 10),
            },
        );
        Policy::handle(&mut pending, Message::Clear);
        Policy::handle(
            &mut pending,
            Message::Retain {
                predicate: Box::new(|subscriber| *subscriber != 11),
            },
        );

        let messages = drain(&mut pending);
        assert_eq!(messages.len(), 2);
        assert!(matches!(messages[0], Message::Clear));
        let Message::Retain { predicate } = &messages[1] else {
            panic!("expected retain");
        };
        assert!(predicate(&10));
        assert!(!predicate(&11));
    }
}
