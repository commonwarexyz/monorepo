use crate::Resolver;
use commonware_actor::{
    mailbox::{Policy, Sender},
    Feedback,
};
use commonware_cryptography::PublicKey;
use commonware_utils::{
    vec::NonEmptyVec,
    Span,
};
use std::collections::VecDeque;

type Predicate<K> = Box<dyn Fn(&K) -> bool + Send>;

/// A request to fetch data for a key, optionally with target peers.
pub struct FetchRequest<K, P> {
    /// The key to fetch.
    pub key: K,
    /// Target peers to restrict the fetch to.
    ///
    /// - `None`: No targeting (or clear existing targeting), try any available peer
    /// - `Some(peers)`: Only try the specified peers
    pub targets: Option<NonEmptyVec<P>>,
}

/// Messages that can be sent to the peer actor.
pub enum Message<K, P> {
    /// Initiate fetch requests.
    Fetch(Vec<FetchRequest<K, P>>),

    /// Cancel a fetch request by key.
    Cancel { key: K },

    /// Cancel all fetch requests.
    Clear,

    /// Cancel all fetch requests that do not satisfy the predicate.
    Retain { predicate: Predicate<K> },
}

impl<K: Span, P: PublicKey> Policy for Message<K, P> {
    fn handle(overflow: &mut VecDeque<Self>, message: Self) -> bool {
        match message {
            Self::Fetch(requests) => {
                push_fetch(overflow, coalesce_requests(requests));
            }
            Self::Cancel { key } => {
                remove_key(overflow, &key);
                if !has_clear(overflow) {
                    overflow.push_back(Self::Cancel { key });
                }
            }
            Self::Clear => {
                overflow.clear();
                overflow.push_back(Self::Clear);
            }
            Self::Retain { predicate } => {
                retain_keys(overflow, predicate.as_ref());
                if has_clear(overflow) {
                    return true;
                }
                match overflow.pop_back() {
                    Some(Self::Retain {
                        predicate: previous,
                    }) => {
                        let predicate = Box::new(move |key: &K| previous(key) && predicate(key));
                        overflow.push_back(Self::Retain { predicate });
                    }
                    Some(message) => {
                        overflow.push_back(message);
                        overflow.push_back(Self::Retain { predicate });
                    }
                    None => overflow.push_back(Self::Retain { predicate }),
                }
            }
        }
        true
    }
}

fn coalesce_requests<K: Span, P: PublicKey>(
    requests: Vec<FetchRequest<K, P>>,
) -> Vec<FetchRequest<K, P>> {
    let mut coalesced: Vec<FetchRequest<K, P>> = Vec::new();
    for request in requests {
        if let Some(existing) = coalesced.iter_mut().find(|old| old.key == request.key) {
            merge_request(existing, request);
        } else {
            coalesced.push(request);
        }
    }
    coalesced
}

fn push_fetch<K: Span, P: PublicKey>(
    overflow: &mut VecDeque<Message<K, P>>,
    mut requests: Vec<FetchRequest<K, P>>,
) {
    for message in overflow.iter_mut() {
        let Message::Fetch(pending) = message else {
            continue;
        };

        let mut index = 0;
        while index < pending.len() {
            let Some(request) = requests
                .iter_mut()
                .find(|request| request.key == pending[index].key)
            else {
                index += 1;
                continue;
            };
            merge_request(request, pending.remove(index));
        }
    }
    overflow.retain(|message| !matches!(message, Message::Fetch(requests) if requests.is_empty()));

    if requests.is_empty() {
        return;
    }
    if let Some(Message::Fetch(pending)) = overflow.back_mut() {
        pending.extend(requests);
    } else {
        overflow.push_back(Message::Fetch(requests));
    }
}

fn merge_request<K, P: PublicKey>(
    target: &mut FetchRequest<K, P>,
    previous: FetchRequest<K, P>,
) {
    target.targets = match (previous.targets, target.targets.take()) {
        (Some(mut previous), Some(current)) => {
            for peer in current {
                if !previous.contains(&peer) {
                    previous.push(peer);
                }
            }
            Some(previous)
        }
        _ => None,
    };
}

fn remove_key<K: Span, P: PublicKey>(overflow: &mut VecDeque<Message<K, P>>, key: &K) {
    overflow.retain_mut(|message| match message {
        Message::Fetch(requests) => {
            requests.retain(|request| &request.key != key);
            !requests.is_empty()
        }
        Message::Cancel { key: pending } => pending != key,
        Message::Clear | Message::Retain { .. } => true,
    });
}

fn has_clear<K, P>(overflow: &VecDeque<Message<K, P>>) -> bool {
    overflow
        .iter()
        .any(|message| matches!(message, Message::Clear))
}

fn retain_keys<K: Span, P: PublicKey>(
    overflow: &mut VecDeque<Message<K, P>>,
    predicate: &dyn Fn(&K) -> bool,
) {
    overflow.retain_mut(|message| match message {
        Message::Fetch(requests) => {
            requests.retain(|request| predicate(&request.key));
            !requests.is_empty()
        }
        Message::Cancel { key } => predicate(key),
        Message::Clear | Message::Retain { .. } => true,
    });
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<K: Span, P: PublicKey> {
    /// The channel that delivers messages to the peer actor.
    sender: Sender<Message<K, P>>,
}

impl<K: Span, P: PublicKey> Mailbox<K, P> {
    /// Create a new mailbox.
    pub(super) const fn new(sender: Sender<Message<K, P>>) -> Self {
        Self { sender }
    }
}

impl<K: Span, P: PublicKey> Resolver for Mailbox<K, P> {
    type Key = K;
    type PublicKey = P;

    /// Send a fetch request to the peer actor.
    ///
    /// If a fetch is already in progress for this key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch(&mut self, key: Self::Key) -> Feedback {
        self.sender.enqueue(Message::Fetch(vec![FetchRequest {
            key,
            targets: None,
        }]))
    }

    /// Send a fetch request to the peer actor for a batch of keys.
    ///
    /// If a fetch is already in progress for any key, this clears any existing
    /// targets for that key (the fetch will try any available peer).
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all(&mut self, keys: Vec<Self::Key>) -> Feedback {
        self.sender.enqueue(Message::Fetch(
            keys.into_iter()
                .map(|key| FetchRequest { key, targets: None })
                .collect(),
        ))
    }

    /// Send a targeted fetch request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_targeted(
        &mut self,
        key: Self::Key,
        targets: NonEmptyVec<Self::PublicKey>,
    ) -> Feedback {
        self.sender.enqueue(Message::Fetch(vec![FetchRequest {
            key,
            targets: Some(targets),
        }]))
    }

    /// Send targeted fetch requests to the peer actor for a batch of keys.
    ///
    /// If the engine has shut down, this is a no-op.
    fn fetch_all_targeted(
        &mut self,
        requests: Vec<(Self::Key, NonEmptyVec<Self::PublicKey>)>,
    ) -> Feedback {
        self.sender.enqueue(Message::Fetch(
            requests
                .into_iter()
                .map(|(key, targets)| FetchRequest {
                    key,
                    targets: Some(targets),
                })
                .collect(),
        ))
    }

    /// Send a cancel request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn cancel(&mut self, key: Self::Key) -> Feedback {
        self.sender.enqueue(Message::Cancel { key })
    }

    /// Send a retain request to the peer actor.
    ///
    /// If the engine has shut down, this is a no-op.
    fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) -> Feedback {
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
    use commonware_cryptography::{
        ed25519::{PrivateKey, PublicKey},
        Signer,
    };
    use commonware_utils::non_empty_vec;

    fn peer(seed: u64) -> PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    fn fetch(
        key: u64,
        targets: Option<NonEmptyVec<PublicKey>>,
    ) -> Message<u64, PublicKey> {
        Message::Fetch(vec![FetchRequest { key, targets }])
    }

    #[test]
    fn targeted_fetches_for_same_key_are_merged() {
        let peer_1 = peer(1);
        let peer_2 = peer(2);
        let mut overflow = VecDeque::new();

        assert!(Message::handle(
            &mut overflow,
            fetch(1, Some(non_empty_vec![peer_1.clone()]))
        ));
        assert!(Message::handle(
            &mut overflow,
            fetch(1, Some(non_empty_vec![peer_2.clone()]))
        ));

        let Some(Message::Fetch(requests)) = overflow.pop_front() else {
            panic!("expected fetch");
        };
        assert!(overflow.is_empty());
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].key, 1);
        assert_eq!(
            requests[0].targets.as_ref().map(AsRef::as_ref),
            Some([peer_1, peer_2].as_slice())
        );
    }

    #[test]
    fn untargeted_fetch_clears_queued_targets() {
        let mut overflow = VecDeque::new();

        assert!(Message::handle(
            &mut overflow,
            fetch(1, Some(non_empty_vec![peer(1)]))
        ));
        assert!(Message::handle(&mut overflow, fetch(1, None)));

        let Some(Message::Fetch(requests)) = overflow.pop_front() else {
            panic!("expected fetch");
        };
        assert!(overflow.is_empty());
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].key, 1);
        assert!(requests[0].targets.is_none());
    }

    #[test]
    fn cancel_removes_queued_fetch_for_key() {
        let mut overflow = VecDeque::new();

        assert!(Message::handle(&mut overflow, fetch(1, None)));
        assert!(Message::handle(&mut overflow, fetch(2, None)));
        assert!(Message::handle(&mut overflow, Message::Cancel { key: 1 }));

        let Some(Message::Fetch(requests)) = overflow.pop_front() else {
            panic!("expected fetch");
        };
        assert_eq!(requests.iter().map(|request| request.key).collect::<Vec<_>>(), vec![2]);
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Cancel { key: 1 })
        ));
        assert!(overflow.is_empty());
    }

    #[test]
    fn clear_absorbs_later_retain_and_cancel_after_pruning() {
        let mut overflow = VecDeque::new();

        assert!(Message::handle(&mut overflow, fetch(1, None)));
        assert!(Message::handle(&mut overflow, Message::Clear));
        assert!(Message::handle(&mut overflow, fetch(2, None)));
        assert!(Message::handle(
            &mut overflow,
            Message::Retain {
                predicate: Box::new(|key| *key != 2),
            }
        ));
        assert!(Message::handle(&mut overflow, Message::Cancel { key: 3 }));

        assert!(matches!(overflow.pop_front(), Some(Message::Clear)));
        assert!(overflow.is_empty());
    }

    #[test]
    fn retain_keeps_fetches_that_match() {
        let mut overflow = VecDeque::new();

        assert!(Message::handle(&mut overflow, fetch(1, None)));
        assert!(Message::handle(
            &mut overflow,
            Message::Retain {
                predicate: Box::new(|key| *key == 1),
            }
        ));

        let Some(Message::Fetch(requests)) = overflow.pop_front() else {
            panic!("expected fetch");
        };
        assert_eq!(
            requests
                .iter()
                .map(|request| request.key)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert!(matches!(
            overflow.pop_front(),
            Some(Message::Retain { .. })
        ));
        assert!(overflow.is_empty());
    }
}
