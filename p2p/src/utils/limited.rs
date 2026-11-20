//! Rate-limited [`UnlimitedSender`] wrapper.

use crate::{Recipients, UnlimitedSender};
use commonware_actor::{Feedback, Unreliable};
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, IoBufs, KeyedRateLimiter, Quota};
use commonware_utils::{channel::ring, sync::Mutex};
use std::{cmp, collections::HashSet, fmt, iter, mem, sync::Arc, time::SystemTime};

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
///
/// # Accounting
///
/// [`LimitedSender::check`] only probes the rate limit. A recipient's quota is charged when
/// [`CheckedSender::send`](crate::CheckedSender::send) submits a message to it and the
/// submission is accepted, so a dropped [`CheckedSender`] or an unaccepted submission consumes
/// nothing. Each recipient is charged (and sent the message) at most once per send, even if it is
/// listed more than once.
///
/// # Clones
///
/// Clones share one rate limiter. If a clone consumes a recipient's quota between a check and its
/// send, the send skips that recipient. If every checked recipient is skipped, the send is
/// rejected. The wrapped sender submits under the shared limiter lock. Its send method must
/// return without blocking and must not call back into a clone of this wrapper.
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

// Minimum number of tracked peers before the rate limiter is pruned
const MIN_PRUNE_AT: usize = 64;

struct State<P: PublicKey, E: Clock> {
    // Per-peer rate limiter shared by all clones
    rate_limit: KeyedRateLimiter<P, E>,
    // Latest peer updates from the source used for Recipients::All
    peer_subscription: ring::Receiver<Vec<P>>,
    // Snapshot used until the subscription yields a newer peer list
    known_peers: Vec<P>,
    // Number of tracked peers at which the rate limiter is next pruned
    prune_at: usize,
}

impl<P: PublicKey, E: Clock> State<P, E> {
    /// Returns the unique `recipients` that are not currently rate-limited, without charging
    /// them.
    ///
    /// If _all_ recipients are rate-limited, returns the earliest instant at which all recipients
    /// will be available.
    fn available(&mut self, recipients: Recipients<P>) -> Result<Recipients<P>, SystemTime> {
        let (allowed, max_retry) = match recipients {
            Recipients::One(peer) => {
                self.rate_limit.check_key_available(&peer)?;
                return Ok(Recipients::One(peer));
            }
            Recipients::Some(peers) => filter_rate_limited(peers.iter(), &mut self.rate_limit),
            Recipients::All => {
                if let Ok(peers) = self.peer_subscription.try_recv() {
                    self.known_peers = peers;
                }
                filter_rate_limited(self.known_peers.iter(), &mut self.rate_limit)
            }
        };
        match max_retry {
            Some(retry) if allowed.is_empty() => Err(retry),
            _ => Ok(Recipients::Some(allowed)),
        }
    }

    /// Charges each of `peers` for one message.
    ///
    /// Space out pruning passes by the number of keys retained by the last pass.
    fn charge<'a>(&mut self, peers: impl Iterator<Item = &'a P>) {
        for peer in peers {
            // The caller verified availability under the same lock
            let _ = self.rate_limit.check_key(peer);
        }
        if self.rate_limit.len() >= self.prune_at {
            self.rate_limit.retain_recent();
            self.prune_at = cmp::max(MIN_PRUNE_AT, self.rate_limit.len().saturating_mul(2));
        }
    }
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
            rate_limit: KeyedRateLimiter::new(quota, clock),
            peer_subscription: peers.subscribe(),
            known_peers: peers.peers(),
            prune_at: MIN_PRUNE_AT,
        }));
        Self {
            sender,
            state,
            peers,
        }
    }

    /// Check that a given set of [`Recipients`] are within the rate limit.
    ///
    /// Returns a [`CheckedSender`] with only the unique recipients that are not
    /// currently rate-limited. If _all_ recipients are rate-limited, returns
    /// the earliest instant at which all recipients will be available.
    ///
    /// No quota is charged until the returned [`CheckedSender`] sends.
    pub fn check(
        &mut self,
        recipients: Recipients<S::PublicKey>,
    ) -> Result<CheckedSender<'_, S, E>, SystemTime> {
        let recipients = self.state.lock().available(recipients)?;
        Ok(CheckedSender {
            recipients,
            sender: &mut self.sender,
            state: &self.state,
        })
    }
}

/// Filters peers by rate limit without charging them, returning the unique peers that pass and
/// the latest retry time among those that don't.
fn filter_rate_limited<'a, K, C>(
    peers: impl Iterator<Item = &'a K>,
    rate_limit: &mut KeyedRateLimiter<K, C>,
) -> (Vec<K>, Option<SystemTime>)
where
    K: PublicKey,
    C: Clock,
{
    let mut seen = HashSet::new();
    let mut allowed = Vec::new();
    let mut max_retry: Option<SystemTime> = None;
    for peer in peers {
        if !seen.insert(peer) {
            continue;
        }
        match rate_limit.check_key_available(peer) {
            Ok(()) => allowed.push(peer.clone()),
            Err(retry) => {
                max_retry = Some(max_retry.map_or(retry, |current| cmp::max(current, retry)));
            }
        }
    }
    (allowed, max_retry)
}

/// An exclusive reference to an [`UnlimitedSender`] with a pre-checked list of
/// recipients that are not currently rate-limited.
///
/// A [`CheckedSender`] can only be acquired via [`LimitedSender::check`].
pub struct CheckedSender<'a, S: UnlimitedSender, E: Clock> {
    sender: &'a mut S,
    state: &'a Mutex<State<S::PublicKey, E>>,
    recipients: Recipients<S::PublicKey>,
}

impl<S: UnlimitedSender, E: Clock> fmt::Debug for CheckedSender<'_, S, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedSender")
            .field("recipients", &self.recipients)
            .finish_non_exhaustive()
    }
}

impl<S: UnlimitedSender, E: Clock> CheckedSender<'_, S, E> {
    /// Sends a message to `recipients` instead of the checked recipients.
    ///
    /// The rate limit is applied to `recipients` exactly as it is to the checked recipients in
    /// [`CheckedSender::send`](crate::CheckedSender::send).
    #[commonware_macros::stability(BETA)]
    pub(crate) fn send_to(
        self,
        recipients: Recipients<S::PublicKey>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Unreliable<Feedback> {
        // Convert the message before taking the lock shared by all clones
        let message = message.into();

        // Hold the lock from the availability check until the charge, so no clone can spend the
        // same quota in between and nothing is charged unless the submission is accepted.
        let mut state = self.state.lock();
        let Ok(recipients) = state.available(recipients) else {
            return Unreliable::Rejected;
        };
        let feedback = self.sender.send(recipients.clone(), message, priority);
        if feedback.accepted() {
            match &recipients {
                Recipients::One(peer) => state.charge(iter::once(peer)),
                Recipients::Some(peers) => state.charge(peers.iter()),
                Recipients::All => unreachable!("available recipients are always resolved"),
            }
        }
        feedback
    }
}

impl<S: UnlimitedSender, E: Clock> crate::CheckedSender for CheckedSender<'_, S, E> {
    type PublicKey = S::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        match &self.recipients {
            Recipients::All => Vec::new(),
            Recipients::Some(peers) => peers.clone(),
            Recipients::One(peer) => vec![peer.clone()],
        }
    }

    fn send(mut self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        let recipients = mem::replace(&mut self.recipients, Recipients::Some(Vec::new()));
        self.send_to(recipients, message, priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckedSender as _;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_runtime::{IoBuf, Quota, Runner as _, Supervisor as _, deterministic::Runner};
    use commonware_utils::{NZU32, NZUsize, channel::ring};
    use futures::SinkExt;
    use std::time::Duration;

    type PublicKey = ed25519::PublicKey;
    type SentMessage = (Recipients<PublicKey>, IoBuf, bool);

    #[derive(Debug, Clone)]
    struct MockSender {
        sent: Arc<Mutex<Vec<SentMessage>>>,
        feedback: Arc<Mutex<Unreliable<Feedback>>>,
    }

    impl MockSender {
        fn new() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
                feedback: Arc::new(Mutex::new(Unreliable::new(Feedback::Ok))),
            }
        }

        fn set_feedback(&self, feedback: Unreliable<Feedback>) {
            *self.feedback.lock() = feedback;
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
        ) -> Unreliable<Feedback> {
            let message = message.into().coalesce();
            let feedback = *self.feedback.lock();
            if feedback.accepted() {
                self.sent.lock().push((recipients, message, priority));
            }
            feedback
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
            assert_eq!(
                checked.send(IoBuf::from(b"hello"), false),
                Unreliable::new(Feedback::Ok)
            );
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
            assert_eq!(
                checked.send(IoBuf::from(b"hello"), false),
                Unreliable::new(Feedback::Ok)
            );
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

            // Check all three peers and expect peer1 to be filtered out
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

            // With both peers rate limited, check should return an error with a retry time
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

    #[test]
    fn check_does_not_charge() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);
            let peer = key(1);

            // Dropping a checked sender without sending consumes nothing
            for _ in 0..3 {
                drop(limited.check(Recipients::One(peer.clone())).unwrap());
                drop(limited.check(Recipients::Some(vec![peer.clone()])).unwrap());
            }

            // The only charge is the send
            limited
                .check(Recipients::One(peer.clone()))
                .unwrap()
                .send(IoBuf::from(b"sent"), false);
            assert_eq!(sender.sent_messages().len(), 1);
            assert!(limited.check(Recipients::One(peer)).is_err());
        });
    }

    #[test]
    fn unaccepted_send_does_not_charge() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);
            let peer1 = key(1);
            let peer2 = key(2);

            for feedback in [Unreliable::Rejected, Unreliable::new(Feedback::Closed)] {
                sender.set_feedback(feedback);
                let checked = limited.check(Recipients::One(peer1.clone())).unwrap();
                assert_eq!(checked.send(IoBuf::from(b"dropped"), false), feedback);
                let checked = limited
                    .check(Recipients::Some(vec![peer1.clone(), peer2.clone()]))
                    .unwrap();
                assert_eq!(checked.send(IoBuf::from(b"dropped"), false), feedback);
            }

            // Both peers still have their full quota, and accepted overflow is charged
            sender.set_feedback(Unreliable::new(Feedback::Backoff));
            let checked = limited
                .check(Recipients::Some(vec![peer1.clone(), peer2.clone()]))
                .unwrap();
            assert_eq!(
                checked.send(IoBuf::from(b"sent"), false),
                Unreliable::new(Feedback::Backoff)
            );
            assert_sent_to(&sender, 0, &[peer1.clone(), peer2.clone()]);
            assert!(limited.check(Recipients::Some(vec![peer1, peer2])).is_err());
        });
    }

    #[test]
    fn duplicate_recipients_charged_once() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(2), context, peers);
            let peer1 = key(1);
            let peer2 = key(2);

            // A repeated recipient is sent to once
            let checked = limited
                .check(Recipients::Some(vec![
                    peer1.clone(),
                    peer2.clone(),
                    peer1.clone(),
                ]))
                .unwrap();
            assert_eq!(checked.recipients(), vec![peer1.clone(), peer2.clone()]);
            checked.send(IoBuf::from(b"first"), false);
            assert_sent_to(&sender, 0, &[peer1.clone(), peer2]);

            // Only one of the two messages in the burst was consumed
            limited
                .check(Recipients::One(peer1.clone()))
                .unwrap()
                .send(IoBuf::from(b"second"), false);
            assert!(limited.check(Recipients::One(peer1)).is_err());
        });
    }

    #[test]
    fn send_skips_recipients_consumed_by_clone() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited1 =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);
            let mut limited2 = limited1.clone();
            let peer1 = key(1);
            let peer2 = key(2);

            // Both clones pass the check for peer1 before either sends
            let checked1 = limited1
                .check(Recipients::Some(vec![peer1.clone(), peer2.clone()]))
                .unwrap();
            let checked2 = limited2.check(Recipients::One(peer1.clone())).unwrap();
            assert_eq!(
                checked2.send(IoBuf::from(b"winner"), false),
                Unreliable::new(Feedback::Ok)
            );

            // The slower clone only reaches the recipient that is still available
            assert_eq!(
                checked1.send(IoBuf::from(b"loser"), false),
                Unreliable::new(Feedback::Ok)
            );
            let messages = sender.sent_messages();
            assert_eq!(messages.len(), 2);
            assert!(matches!(&messages[0].0, Recipients::One(peer) if peer == &peer1));
            assert_sent_to(&sender, 1, std::slice::from_ref(&peer2));

            // Neither peer was charged twice
            assert!(
                limited1
                    .check(Recipients::Some(vec![peer1, peer2]))
                    .is_err()
            );
        });
    }

    #[test]
    fn send_rejected_when_all_recipients_consumed_by_clone() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited1 =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);
            let mut limited2 = limited1.clone();
            let peer = key(1);

            let checked1 = limited1.check(Recipients::One(peer.clone())).unwrap();
            let checked2 = limited2.check(Recipients::Some(vec![peer])).unwrap();
            checked2.send(IoBuf::from(b"winner"), false);
            assert_eq!(
                checked1.send(IoBuf::from(b"loser"), false),
                Unreliable::Rejected
            );
            assert_eq!(sender.sent_messages().len(), 1);
        });
    }

    #[test]
    fn stale_check_does_not_restore_quota() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited1 = LimitedSender::new(
                sender.clone(),
                quota_per_second(1),
                context.child("limiter"),
                peers,
            );
            let mut limited2 = limited1.clone();
            let peer = key(1);

            // Hold a checked sender while a clone sends, the quota refills, and the clone
            // sends again
            let stale = limited1.check(Recipients::One(peer.clone())).unwrap();
            limited2
                .check(Recipients::One(peer.clone()))
                .unwrap()
                .send(IoBuf::from(b"first"), false);
            context.sleep(Duration::from_secs(1)).await;
            limited2
                .check(Recipients::One(peer.clone()))
                .unwrap()
                .send(IoBuf::from(b"second"), false);

            // Dropping the stale checked sender must not erase the latest charge
            drop(stale);
            assert!(limited2.check(Recipients::One(peer.clone())).is_err());
            assert!(limited1.check(Recipients::One(peer)).is_err());
            assert_eq!(sender.sent_messages().len(), 2);
        });
    }

    #[test]
    fn targeted_sends_prune_replenished_peers() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender, quota_per_second(1), context.child("limiter"), peers);

            // Send to many peers without ever addressing Recipients::All
            let rounds = 8u64;
            let per_round = 2 * MIN_PRUNE_AT as u64;
            for round in 0..rounds {
                for i in 0..per_round {
                    let peer = key(round * per_round + i);
                    limited
                        .check(Recipients::One(peer))
                        .unwrap()
                        .send(IoBuf::from(b"hello"), false);
                }
                context.sleep(Duration::from_secs(2)).await;
            }

            // Peers from earlier rounds have fully replenished and are no longer tracked
            let tracked = limited.state.lock().rate_limit.len();
            assert!(tracked <= 2 * per_round as usize, "tracked {tracked} peers");

            // A peer that has not replenished is retained across pruning
            let limited_peer = key(u64::MAX);
            limited
                .check(Recipients::One(limited_peer.clone()))
                .unwrap()
                .send(IoBuf::from(b"hello"), false);
            for i in 0..per_round {
                limited
                    .check(Recipients::One(key(rounds * per_round + i)))
                    .unwrap()
                    .send(IoBuf::from(b"hello"), false);
            }
            assert!(limited.check(Recipients::One(limited_peer)).is_err());
        });
    }
}
