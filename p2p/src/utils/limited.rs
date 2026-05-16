//! Rate-limited [`UnlimitedSender`] wrapper.

use crate::{Recipients, UnlimitedSender};
use commonware_actor::Feedback;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, IoBufs, KeyedRateLimiter, Quota};
use commonware_utils::{channel::ring, sync::Mutex};
use futures::{FutureExt, StreamExt};
use std::{cmp, fmt, sync::Arc, time::SystemTime};

/// Provides peer snapshots for resolving [`Recipients::All`].
pub trait Connected: Clone + Send + Sync + 'static {
    type PublicKey: PublicKey;

    /// Return the current peer snapshot.
    fn peers(&self) -> Vec<Self::PublicKey> {
        Vec::new()
    }

    /// Subscribe to peer updates.
    ///
    /// The receiver yields the current set of known peers whenever it changes.
    /// New subscriptions should publish the current set promptly so callers do
    /// not have to wait for the next membership change.
    fn subscribe(&self) -> ring::Receiver<Vec<Self::PublicKey>>;
}

/// A wrapper around a [`UnlimitedSender`] that provides rate limiting with retry-time feedback.
pub struct LimitedSender<E, S, P>
where
    E: Clock,
    S: UnlimitedSender,
    P: Connected<PublicKey = S::PublicKey>,
{
    sender: S,
    state: Arc<Mutex<State<S::PublicKey, E>>>,
    peers: P,
}

struct State<P: PublicKey, E: Clock> {
    // Per-peer rate limiter shared by all clones
    rate_limit: KeyedRateLimiter<P, E>,
    // Latest peer updates from the source used for Recipients::All
    peer_subscription: ring::Receiver<Vec<P>>,
    // Snapshot used until the subscription yields a newer peer list
    known_peers: Vec<P>,
}

impl<E, S, P> Clone for LimitedSender<E, S, P>
where
    E: Clock,
    S: UnlimitedSender,
    P: Connected<PublicKey = S::PublicKey>,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            state: self.state.clone(),
            peers: self.peers.clone(),
        }
    }
}

impl<E, S, P> fmt::Debug for LimitedSender<E, S, P>
where
    E: Clock,
    S: UnlimitedSender,
    P: Connected<PublicKey = S::PublicKey>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let known_peers = self.state.lock().known_peers.len();
        f.debug_struct("LimitedSender")
            .field("known_peers", &known_peers)
            .finish_non_exhaustive()
    }
}

impl<E, S, P> LimitedSender<E, S, P>
where
    E: Clock,
    S: UnlimitedSender,
    P: Connected<PublicKey = S::PublicKey>,
{
    /// Create a new [`LimitedSender`] with the given sender, [`Quota`], and peer source.
    pub fn new(sender: S, quota: Quota, clock: E, peers: P) -> Self {
        let state = Arc::new(Mutex::new(State {
            rate_limit: KeyedRateLimiter::hashmap_with_clock(quota, clock),
            peer_subscription: peers.subscribe(),
            known_peers: peers.peers(),
        }));
        Self {
            sender,
            state,
            peers,
        }
    }

    /// Check that a given set of [`Recipients`] are within the rate limit.
    ///
    /// Returns a [`CheckedSender`] with only the recipients that are not
    /// currently rate-limited. If _all_ recipients are rate-limited, returns
    /// the earliest instant at which all recipients will be available.
    pub fn check(
        &mut self,
        recipients: Recipients<S::PublicKey>,
    ) -> Result<CheckedSender<'_, S>, SystemTime> {
        let mut state = self.state.lock();
        if matches!(&recipients, Recipients::All) {
            if let Some(peers) = state.peer_subscription.next().now_or_never().flatten() {
                state.known_peers = peers;
                state.rate_limit.retain_recent();
            }
        }

        let recipients = match recipients {
            Recipients::One(peer) => match state.rate_limit.check_key(&peer) {
                Ok(()) => Recipients::One(peer),
                Err(not_until) => return Err(not_until.earliest_possible()),
            },
            Recipients::Some(peers) => {
                let (allowed, max_retry) = filter_rate_limited(peers.iter(), &state.rate_limit);
                if allowed.is_empty() {
                    match max_retry {
                        Some(retry) => return Err(retry),
                        None => Recipients::Some(Vec::new()),
                    }
                } else {
                    Recipients::Some(allowed)
                }
            }
            Recipients::All => {
                let (allowed, max_retry) =
                    filter_rate_limited(state.known_peers.iter(), &state.rate_limit);
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
        drop(state);

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

/// An exclusive reference to an [`UnlimitedSender`] with a pre-checked list of
/// recipients that are not currently rate-limited.
///
/// A [`CheckedSender`] can only be acquired via [`LimitedSender::check`].
#[derive(Debug)]
pub struct CheckedSender<'a, S: UnlimitedSender> {
    sender: &'a mut S,
    recipients: Recipients<S::PublicKey>,
}

impl<'a, S: UnlimitedSender> CheckedSender<'a, S> {
    /// Extracts the inner [`UnlimitedSender`] reference.
    ///
    /// # Warning
    ///
    /// Rate limiting has already been applied to the original recipients. Any
    /// messages sent via the extracted sender will bypass the rate limiter.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) fn into_inner(self) -> &'a mut S {
        self.sender
    }
}

impl<'a, S: UnlimitedSender> crate::CheckedSender for CheckedSender<'a, S> {
    type PublicKey = S::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        match &self.recipients {
            Recipients::All => Vec::new(),
            Recipients::Some(peers) => peers.clone(),
            Recipients::One(peer) => vec![peer.clone()],
        }
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Feedback {
        self.sender.send(self.recipients, message, priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckedSender as _;
    use commonware_cryptography::{ed25519, Signer as _};
    use commonware_runtime::{deterministic::Runner, IoBuf, Quota, Runner as _};
    use commonware_utils::{channel::ring, NZUsize, NZU32};
    use futures::SinkExt;

    type PublicKey = ed25519::PublicKey;
    type SentMessage = (Recipients<PublicKey>, IoBuf, bool);

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

        fn sent_messages(&self) -> Vec<SentMessage> {
            self.sent.lock().clone()
        }
    }

    fn assert_sent_to(sender: &MockSender, index: usize, expected: &[PublicKey]) {
        let messages = sender.sent_messages();
        let Recipients::Some(sent) = &messages[index].0 else {
            panic!("expected Recipients::Some");
        };
        assert_eq!(sent, expected);
    }

    impl UnlimitedSender for MockSender {
        type PublicKey = PublicKey;

        fn send(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
            message: impl Into<IoBufs> + Send,
            priority: bool,
        ) -> Feedback {
            let message = message.into().coalesce();
            self.sent.lock().push((recipients, message, priority));
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct MockPeers {
        peers: Vec<PublicKey>,
    }

    #[derive(Clone)]
    struct UpdatingPeers {
        peers: Vec<PublicKey>,
        receiver: Arc<Mutex<Option<ring::Receiver<Vec<PublicKey>>>>>,
    }

    impl MockPeers {
        fn new() -> Self {
            Self { peers: Vec::new() }
        }

        fn with_peers(peers: Vec<PublicKey>) -> Self {
            Self { peers }
        }
    }

    impl Connected for MockPeers {
        type PublicKey = PublicKey;

        fn peers(&self) -> Vec<Self::PublicKey> {
            self.peers.clone()
        }

        fn subscribe(&self) -> ring::Receiver<Vec<Self::PublicKey>> {
            let (_sender, receiver) = ring::channel(NZUsize!(16));
            receiver
        }
    }

    impl Connected for UpdatingPeers {
        type PublicKey = PublicKey;

        fn peers(&self) -> Vec<Self::PublicKey> {
            self.peers.clone()
        }

        fn subscribe(&self) -> ring::Receiver<Vec<Self::PublicKey>> {
            self.receiver
                .lock()
                .take()
                .expect("subscription should only be created once")
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
            let peers = MockPeers::new();
            let mut limited = LimitedSender::new(sender, quota_per_second(10), context, peers);

            let checked = limited.check(Recipients::One(key(1))).unwrap();
            assert_eq!(checked.send(IoBuf::from(b"hello"), false), Feedback::Ok);
        });
    }

    #[test]
    fn check_one_rate_limited() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited = LimitedSender::new(sender, quota_per_second(1), context, peers);

            let peer = key(1);

            // First check should succeed and consume the quota
            let checked = limited.check(Recipients::One(peer.clone())).unwrap();
            checked.send(IoBuf::from(b"first"), false);

            // Second check should fail (rate limited)
            let result = limited.check(Recipients::One(peer));
            assert!(result.is_err());
        });
    }

    #[test]
    fn check_some_all_not_rate_limited() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);

            let peers_list = vec![key(1), key(2), key(3)];
            let checked = limited.check(Recipients::Some(peers_list)).unwrap();
            assert_eq!(checked.send(IoBuf::from(b"hello"), false), Feedback::Ok);
            assert_sent_to(&sender, 0, &[key(1), key(2), key(3)]);
        });
    }

    #[test]
    fn check_some_filters_rate_limited_peers() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);

            let peer1 = key(1);
            let peer2 = key(2);
            let peer3 = key(3);

            // Rate limit peer1 by sending to it first
            let checked = limited.check(Recipients::One(peer1.clone())).unwrap();
            checked.send(IoBuf::from(b"limit"), false);

            // Now check with all three peers - peer1 should be filtered out
            let expected = vec![peer2.clone(), peer3.clone()];
            let checked = limited
                .check(Recipients::Some(vec![peer1, peer2, peer3]))
                .unwrap();
            checked.send(IoBuf::from(b"filtered"), false);
            assert_sent_to(&sender, 1, &expected);
        });
    }

    #[test]
    fn check_some_all_rate_limited_returns_error() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited = LimitedSender::new(sender, quota_per_second(1), context, peers);

            let peer1 = key(1);
            let peer2 = key(2);

            // Rate limit both peers
            limited
                .check(Recipients::One(peer1.clone()))
                .unwrap()
                .send(IoBuf::from(b"limit1"), false);

            limited
                .check(Recipients::One(peer2.clone()))
                .unwrap()
                .send(IoBuf::from(b"limit2"), false);

            // Now both are rate limited - should return error with retry time
            assert!(limited.check(Recipients::Some(vec![peer1, peer2])).is_err());
        });
    }

    #[test]
    fn check_some_empty_returns_as_is() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited = LimitedSender::new(sender, quota_per_second(10), context, peers);

            // Empty recipients should pass through
            limited.check(Recipients::Some(Vec::new())).unwrap();
        });
    }

    #[test]
    fn check_all_uses_known_peers() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(10), context, peers);

            // No known peers yet
            let checked = limited.check(Recipients::All).unwrap();
            assert!(crate::CheckedSender::recipients(&checked).is_empty());
            checked.send(IoBuf::from(b"empty"), false);

            // Verify that the sender received the message with empty Recipients::Some.
            assert_sent_to(&sender, 0, &[]);
        });
    }

    #[test]
    fn check_all_filters_rate_limited_known_peers() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peer1 = key(1);
            let peer2 = key(2);
            let peers = MockPeers::with_peers(vec![peer1.clone(), peer2.clone()]);
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);

            // Rate limit peer1
            limited
                .check(Recipients::One(peer1))
                .unwrap()
                .send(IoBuf::from(b"limit"), false);

            // Check All should filter out peer1
            let checked = limited.check(Recipients::All).unwrap();
            checked.send(IoBuf::from(b"filtered"), false);
            assert_sent_to(&sender, 1, &[peer2]);
        });
    }

    #[test]
    fn check_all_returns_error_when_all_known_peers_rate_limited() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peer1 = key(1);
            let peer2 = key(2);
            let peers = MockPeers::with_peers(vec![peer1.clone(), peer2.clone()]);
            let mut limited = LimitedSender::new(sender, quota_per_second(1), context, peers);

            // Rate limit both peers
            limited
                .check(Recipients::One(peer1))
                .unwrap()
                .send(IoBuf::from(b"limit1"), false);

            limited
                .check(Recipients::One(peer2))
                .unwrap()
                .send(IoBuf::from(b"limit2"), false);

            // Check All should fail since all known peers are rate limited
            assert!(limited.check(Recipients::All).is_err());
        });
    }

    #[test]
    fn clone_shares_peer_updates() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let initial = key(1);
            let updated = key(2);
            let (updates, receiver) = ring::channel(NZUsize!(1));
            let peers = UpdatingPeers {
                peers: vec![initial],
                receiver: Arc::new(Mutex::new(Some(receiver))),
            };
            let mut limited1 = LimitedSender::new(sender, quota_per_second(10), context, peers);

            let mut limited2 = limited1.clone();
            let mut updates = updates;
            updates.send(vec![updated.clone()]).await.unwrap();

            let checked = limited2.check(Recipients::All).unwrap();
            assert_eq!(crate::CheckedSender::recipients(&checked), vec![updated]);

            let checked = limited1.check(Recipients::All).unwrap();
            assert_eq!(crate::CheckedSender::recipients(&checked), vec![key(2)]);
        });
    }

    #[test]
    fn checked_sender_sends_with_priority() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(10), context, peers);

            let peer = key(1);
            limited
                .check(Recipients::One(peer))
                .unwrap()
                .send(IoBuf::from(b"priority"), true);

            let messages = sender.sent_messages();
            assert_eq!(messages.len(), 1);
            assert!(messages[0].2); // priority flag
        });
    }

    #[test]
    fn rate_limit_shared_across_clones() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited1 = LimitedSender::new(sender, quota_per_second(1), context, peers);
            let mut limited2 = limited1.clone();

            let peer = key(1);

            // Rate limit peer via first instance
            limited1
                .check(Recipients::One(peer.clone()))
                .unwrap()
                .send(IoBuf::from(b"limit"), false);

            // Second instance should see the rate limit
            assert!(limited2.check(Recipients::One(peer)).is_err());
        });
    }
}
