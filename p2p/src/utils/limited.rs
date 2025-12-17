//! Rate-limited [`Sender`] wrapper.

use crate::{Recipients, Sender};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, KeyedRateLimiter, Quota};
use commonware_utils::channels::ring;
use futures::{lock::Mutex, Future, FutureExt, StreamExt};
use std::{cmp, fmt, sync::Arc, time::SystemTime};

/// Provides peer subscriptions for resolving [`Recipients::All`].
///
/// Implementations must be clonable so that each clone of [`LimitedSender`]
/// can establish its own peer subscription.
pub trait Connected: Clone + Send + Sync + 'static {
    type PublicKey: PublicKey;

    /// Subscribe to peer updates.
    ///
    /// Returns a receiver that yields the current set of known peers whenever it changes.
    ///
    /// It is assumed that when a new subscription is created, the current set of known peers
    /// is sent immediately.
    fn subscribe(&mut self) -> impl Future<Output = ring::Receiver<Vec<Self::PublicKey>>> + Send;
}

/// A wrapper around a [`Sender`] that provides rate limiting with retry-time feedback.
pub struct LimitedSender<E, S, P>
where
    E: Clock,
    S: Sender,
    P: Connected<PublicKey = S::PublicKey>,
{
    sender: S,
    rate_limit: Arc<Mutex<KeyedRateLimiter<S::PublicKey, E>>>,
    peers: P,
    peer_subscription: Option<ring::Receiver<Vec<S::PublicKey>>>,
    known_peers: Vec<S::PublicKey>,
}

impl<E, S, P> Clone for LimitedSender<E, S, P>
where
    E: Clock,
    S: Sender,
    P: Connected<PublicKey = S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            rate_limit: self.rate_limit.clone(),
            peers: self.peers.clone(),
            peer_subscription: None,
            known_peers: Vec::new(),
        }
    }
}

impl<E, S, P> fmt::Debug for LimitedSender<E, S, P>
where
    E: Clock,
    S: Sender,
    P: Connected<PublicKey = S::PublicKey>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LimitedSender")
            .field("known_peers", &self.known_peers.len())
            .finish_non_exhaustive()
    }
}

impl<E, S, P> LimitedSender<E, S, P>
where
    E: Clock,
    S: Sender,
    P: Connected<PublicKey = S::PublicKey>,
{
    /// Create a new [`LimitedSender`] with the given sender, [`Quota`], and peer source.
    pub fn new(sender: S, quota: Quota, clock: E, peers: P) -> Self {
        let rate_limit = Arc::new(Mutex::new(KeyedRateLimiter::hashmap_with_clock(
            quota, clock,
        )));
        Self {
            sender,
            rate_limit,
            peers,
            peer_subscription: None,
            known_peers: Vec::new(),
        }
    }

    /// Check that a given set of [`Recipients`] are within the rate limit.
    ///
    /// Returns a [`CheckedSender`] with only the recipients that are not
    /// currently rate-limited. If _all_ recipients are rate-limited, returns
    /// the earliest instant at which all recipients will be available.
    pub async fn check(
        &mut self,
        recipients: Recipients<S::PublicKey>,
    ) -> Result<CheckedSender<'_, S>, SystemTime> {
        // Lazily establish peer subscription on first use
        if self.peer_subscription.is_none() {
            self.peer_subscription = Some(self.peers.subscribe().await);
        }

        let rate_limit = self.rate_limit.lock().await;

        // Update known peers from subscription if available (non-blocking)
        if let Some(ref mut subscription) = self.peer_subscription {
            if let Some(peers) = subscription.next().now_or_never().flatten() {
                self.known_peers = peers;
                rate_limit.retain_recent();
            }
        }

        let recipients = match recipients {
            Recipients::One(ref peer) => match rate_limit.check_key(peer) {
                Ok(()) => recipients,
                Err(not_until) => return Err(not_until.earliest_possible()),
            },
            Recipients::Some(ref peers) => {
                let (allowed, max_retry) = filter_rate_limited(peers.iter(), &rate_limit);
                if allowed.is_empty() {
                    match max_retry {
                        Some(retry) => return Err(retry),
                        None => recipients,
                    }
                } else {
                    Recipients::Some(allowed)
                }
            }
            Recipients::All => {
                let (allowed, max_retry) =
                    filter_rate_limited(self.known_peers.iter(), &rate_limit);
                if allowed.is_empty() {
                    match max_retry {
                        Some(retry) => return Err(retry),
                        None => Recipients::Some(Vec::new()),
                    }
                } else {
                    Recipients::Some(allowed)
                }
            }
        };

        Ok(CheckedSender {
            recipients,
            sender: &mut self.sender,
        })
    }
}

/// Filters peers by rate limit, returning those that pass and the latest retry
/// time among those that don't.
pub(crate) fn filter_rate_limited<'a, K, C>(
    peers: impl Iterator<Item = &'a K>,
    rate_limit: &KeyedRateLimiter<K, C>,
) -> (Vec<K>, Option<SystemTime>)
where
    K: PublicKey,
    C: Clock,
{
    peers.fold(
        (Vec::new(), None),
        |(mut allowed, max_retry), p| match rate_limit.check_key(p) {
            Ok(()) => {
                allowed.push(p.clone());
                (allowed, max_retry)
            }
            Err(not_until) => {
                let earliest = not_until.earliest_possible();
                let new_max = max_retry.map_or(earliest, |current| cmp::max(current, earliest));
                (allowed, Some(new_max))
            }
        },
    )
}

/// An exclusive reference to an [`Sender`] with a pre-checked list of
/// recipients that are not currently rate-limited.
///
/// A [`CheckedSender`] can only be acquired via [`LimitedSender::check`].
#[derive(Debug)]
pub struct CheckedSender<'a, S: Sender> {
    sender: &'a mut S,
    recipients: Recipients<S::PublicKey>,
}

impl<'a, S: Sender> crate::CheckedSender for CheckedSender<'a, S> {
    type PublicKey = S::PublicKey;
    type Error = S::Error;

    async fn send(
        self,
        message: Bytes,
        priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Self::Error> {
        self.sender.send(self.recipients, message, priority).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckedSender as _;
    use bytes::Bytes;
    use commonware_cryptography::{ed25519, Signer as _};
    use commonware_runtime::{deterministic::Runner, Quota, Runner as _};
    use commonware_utils::{channels::ring, NZUsize, NZU32};
    use thiserror::Error;

    type PublicKey = ed25519::PublicKey;
    type SentMessage = (Recipients<PublicKey>, Bytes, bool);

    #[derive(Debug, Error)]
    #[error("mock send error")]
    struct MockError;

    #[derive(Debug, Clone)]
    struct MockSender {
        sent: Arc<Mutex<Vec<SentMessage>>>,
    }

    impl MockSender {
        fn new() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }

        async fn sent_messages(&self) -> Vec<SentMessage> {
            self.sent.lock().await.clone()
        }
    }

    impl Sender for MockSender {
        type Error = MockError;
        type PublicKey = PublicKey;

        async fn send(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
            message: Bytes,
            priority: bool,
        ) -> Result<Vec<Self::PublicKey>, Self::Error> {
            let sent_to = match &recipients {
                Recipients::One(pk) => vec![pk.clone()],
                Recipients::Some(pks) => pks.clone(),
                Recipients::All => Vec::new(),
            };
            self.sent.lock().await.push((recipients, message, priority));
            Ok(sent_to)
        }
    }

    #[derive(Clone)]
    struct MockPeers {
        sender: ring::Sender<Vec<PublicKey>>,
    }

    impl MockPeers {
        fn new() -> (Self, ring::Sender<Vec<PublicKey>>) {
            let (sender, _receiver) = ring::channel(NZUsize!(16));
            let peers = Self {
                sender: sender.clone(),
            };
            (peers, sender)
        }
    }

    impl Connected for MockPeers {
        type PublicKey = PublicKey;

        async fn subscribe(&mut self) -> ring::Receiver<Vec<Self::PublicKey>> {
            let (sender, receiver) = ring::channel(NZUsize!(16));
            // Replace our sender with a new one connected to the returned receiver
            self.sender = sender;
            receiver
        }
    }

    fn key(seed: u64) -> PublicKey {
        ed25519::PrivateKey::from_seed(seed).public_key()
    }

    fn quota_per_second(n: u32) -> Quota {
        Quota::per_second(NZU32!(n))
    }

    #[test]
    fn check_one_not_rate_limited() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _peer_sender) = MockPeers::new();
            let mut limited = LimitedSender::new(sender, quota_per_second(10), context, peers);

            let peer = key(1);
            let checked = limited.check(Recipients::One(peer.clone())).await.unwrap();
            let sent_to = checked.send(Bytes::from("hello"), false).await.unwrap();
            assert_eq!(sent_to, vec![peer]);
        });
    }

    #[test]
    fn check_one_rate_limited() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _peer_sender) = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);

            let peer = key(1);

            // First check should succeed and consume the quota
            let checked = limited.check(Recipients::One(peer.clone())).await.unwrap();
            checked.send(Bytes::from("first"), false).await.unwrap();

            // Second check should fail (rate limited)
            let result = limited.check(Recipients::One(peer)).await;
            assert!(result.is_err());
        });
    }

    #[test]
    fn check_some_all_not_rate_limited() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _peer_sender) = MockPeers::new();
            let mut limited = LimitedSender::new(sender, quota_per_second(1), context, peers);

            let peers_list = vec![key(1), key(2), key(3)];
            let checked = limited
                .check(Recipients::Some(peers_list.clone()))
                .await
                .unwrap();
            let sent_to = checked.send(Bytes::from("hello"), false).await.unwrap();
            assert_eq!(sent_to.len(), 3);
        });
    }

    #[test]
    fn check_some_filters_rate_limited_peers() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _peer_sender) = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);

            let peer1 = key(1);
            let peer2 = key(2);
            let peer3 = key(3);

            // Rate limit peer1 by sending to it first
            let checked = limited.check(Recipients::One(peer1.clone())).await.unwrap();
            checked.send(Bytes::from("limit"), false).await.unwrap();

            // Now check with all three peers - peer1 should be filtered out
            let checked = limited
                .check(Recipients::Some(vec![
                    peer1.clone(),
                    peer2.clone(),
                    peer3.clone(),
                ]))
                .await
                .unwrap();
            let sent_to = checked.send(Bytes::from("filtered"), false).await.unwrap();

            // peer1 should be filtered out since it's rate limited
            assert_eq!(sent_to.len(), 2);
            assert!(!sent_to.contains(&peer1));
            assert!(sent_to.contains(&peer2));
            assert!(sent_to.contains(&peer3));
        });
    }

    #[test]
    fn check_some_all_rate_limited_returns_error() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _peer_sender) = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);

            let peer1 = key(1);
            let peer2 = key(2);

            // Rate limit both peers
            limited
                .check(Recipients::One(peer1.clone()))
                .await
                .unwrap()
                .send(Bytes::from("limit1"), false)
                .await
                .unwrap();

            limited
                .check(Recipients::One(peer2.clone()))
                .await
                .unwrap()
                .send(Bytes::from("limit2"), false)
                .await
                .unwrap();

            // Now both are rate limited - should return error with retry time
            assert!(limited
                .check(Recipients::Some(vec![peer1, peer2]))
                .await
                .is_err());
        });
    }

    #[test]
    fn check_some_empty_returns_as_is() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _peer_sender) = MockPeers::new();
            let mut limited = LimitedSender::new(sender, quota_per_second(10), context, peers);

            // Empty recipients should pass through
            limited.check(Recipients::Some(Vec::new())).await.unwrap();
        });
    }

    #[test]
    fn check_all_uses_known_peers() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _) = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(10), context, peers);

            // First call establishes subscription - no known peers yet
            let checked = limited.check(Recipients::All).await.unwrap();
            let sent_to = checked.send(Bytes::from("empty"), false).await.unwrap();
            assert!(sent_to.is_empty());

            // Verify that the sender received the message with empty Recipients::Some
            let messages = sender.sent_messages().await;
            assert_eq!(messages.len(), 1);
            match &messages[0].0 {
                Recipients::Some(pks) => assert!(pks.is_empty()),
                _ => panic!("expected Recipients::Some"),
            }
        });
    }

    #[test]
    fn check_all_filters_rate_limited_known_peers() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _) = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);

            let peer1 = key(1);
            let peer2 = key(2);

            // First call to establish subscription
            let _ = limited.check(Recipients::All).await;

            // Manually set known peers (simulating peer updates)
            limited.known_peers = vec![peer1.clone(), peer2.clone()];

            // Rate limit peer1
            limited
                .check(Recipients::One(peer1.clone()))
                .await
                .unwrap()
                .send(Bytes::from("limit"), false)
                .await
                .unwrap();

            // Check All should filter out peer1
            let checked = limited.check(Recipients::All).await.unwrap();
            let sent_to = checked.send(Bytes::from("filtered"), false).await.unwrap();

            assert_eq!(sent_to.len(), 1);
            assert!(!sent_to.contains(&peer1));
            assert!(sent_to.contains(&peer2));
        });
    }

    #[test]
    fn check_all_returns_error_when_all_known_peers_rate_limited() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _) = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);

            let peer1 = key(1);
            let peer2 = key(2);

            // First call to establish subscription
            let _ = limited.check(Recipients::All).await;

            // Set known peers
            limited.known_peers = vec![peer1.clone(), peer2.clone()];

            // Rate limit both peers
            limited
                .check(Recipients::One(peer1.clone()))
                .await
                .unwrap()
                .send(Bytes::from("limit1"), false)
                .await
                .unwrap();

            limited
                .check(Recipients::One(peer2.clone()))
                .await
                .unwrap()
                .send(Bytes::from("limit2"), false)
                .await
                .unwrap();

            // Check All should fail since all known peers are rate limited
            assert!(limited.check(Recipients::All).await.is_err());
        });
    }

    #[test]
    fn clone_creates_independent_subscription() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _) = MockPeers::new();
            let mut limited1 = LimitedSender::new(sender, quota_per_second(10), context, peers);

            // Establish subscription on first instance
            let _ = limited1.check(Recipients::All).await;
            limited1.known_peers = vec![key(1)];

            // Clone should not have a subscription or known peers
            let limited2 = limited1.clone();
            assert!(limited2.peer_subscription.is_none());
            assert!(limited2.known_peers.is_empty());
        });
    }

    #[test]
    fn checked_sender_sends_with_priority() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _peer_sender) = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(10), context, peers);

            let peer = key(1);
            limited
                .check(Recipients::One(peer))
                .await
                .unwrap()
                .send(Bytes::from("priority"), true)
                .await
                .unwrap();

            let messages = sender.sent_messages().await;
            assert_eq!(messages.len(), 1);
            assert!(messages[0].2); // priority flag
        });
    }

    #[test]
    fn rate_limit_shared_across_clones() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let (peers, _) = MockPeers::new();
            let mut limited1 =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);
            let mut limited2 = limited1.clone();

            let peer = key(1);

            // Rate limit peer via first instance
            limited1
                .check(Recipients::One(peer.clone()))
                .await
                .unwrap()
                .send(Bytes::from("limit"), false)
                .await
                .unwrap();

            // Second instance should see the rate limit
            assert!(limited2.check(Recipients::One(peer)).await.is_err());
        });
    }
}
