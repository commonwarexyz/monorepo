//! Rate-limited [`UnlimitedSender`] wrapper.

use crate::{Recipients, SendReceipt, UnlimitedSender};
use commonware_actor::Unreliable;
use commonware_cryptography::PublicKey;
use commonware_runtime::{Clock, IoBufs, KeyedRateLimiter, Quota};
use commonware_utils::{channel::ring, sync::Mutex};
use std::{cmp, collections::HashSet, fmt, mem, sync::Arc, time::SystemTime};

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
/// [`CheckedSender::send_with_receipt`](crate::CheckedSender::send_with_receipt) submits a
/// message to it and the submission is accepted, so a dropped [`CheckedSender`] or an unaccepted
/// submission consumes nothing. Each recipient is charged (and sent the message) at most once per
/// send, even if it is listed more than once. The receipt lists exactly the charged recipients.
///
/// # Clones
///
/// Clones share one rate limiter. If a clone consumes a recipient's quota between a check and its
/// send, the send skips that recipient. If every checked recipient is skipped, the send is
/// rejected.
///
/// A send reserves its recipients while the wrapped sender submits the message, outside the
/// shared limiter lock. A send that overlaps another send to the same recipient skips that
/// recipient, even if the other submission is ultimately not accepted, while sends to different
/// recipients proceed independently. [`LimitedSender::check`] ignores reservations, so it may
/// retain a recipient that a later send skips. The wrapped sender's send method must return
/// without blocking.
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
    // Peers reserved by sends whose submission has not yet returned
    in_flight: HashSet<P>,
    // Number of tracked peers at which the rate limiter is next pruned
    prune_at: usize,
}

impl<P: PublicKey, E: Clock> State<P, E> {
    /// Refreshes the peers used for [`Recipients::All`] from the subscription.
    fn refresh_known_peers(&mut self) {
        if let Ok(peers) = self.peer_subscription.try_recv() {
            self.known_peers = peers;
            self.prune();
        }
    }

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
                self.refresh_known_peers();
                filter_rate_limited(self.known_peers.iter(), &mut self.rate_limit)
            }
        };
        match max_retry {
            Some(retry) if allowed.is_empty() => Err(retry),
            _ => Ok(Recipients::Some(allowed)),
        }
    }

    /// Reserves the unique `recipients` that are neither rate-limited nor reserved by another
    /// send, appending each to `reserved` as soon as it is marked.
    /// For [`Recipients::Some`], the caller provides space for the full list.
    ///
    /// Returns whether the reservation should be submitted: `false` if recipients were requested
    /// but none could be reserved.
    fn reserve(&mut self, recipients: Recipients<P>, reserved: &mut Vec<P>) -> bool {
        // A peer that is already reserved, including an earlier duplicate in the same list, is
        // skipped, so the reservation set also removes duplicates
        let empty_request = match recipients {
            Recipients::One(peer) => {
                if reservable(&mut self.rate_limit, &self.in_flight, &peer) {
                    reserved.reserve_exact(1);
                    self.in_flight.insert(peer.clone());
                    reserved.push(peer);
                }
                false
            }
            Recipients::Some(peers) => {
                let empty = peers.is_empty();
                for peer in peers {
                    if reservable(&mut self.rate_limit, &self.in_flight, &peer) {
                        self.in_flight.insert(peer.clone());
                        reserved.push(peer);
                    }
                }
                empty
            }
            Recipients::All => {
                self.refresh_known_peers();
                reserved.reserve_exact(self.known_peers.len());
                for peer in &self.known_peers {
                    if reservable(&mut self.rate_limit, &self.in_flight, peer) {
                        let owned = peer.clone();
                        self.in_flight.insert(peer.clone());
                        reserved.push(owned);
                    }
                }
                self.known_peers.is_empty()
            }
        };
        empty_request || !reserved.is_empty()
    }

    /// Releases the reservations of `peers`.
    fn release(&mut self, peers: &[P]) {
        for peer in peers {
            self.in_flight.remove(peer);
        }
    }

    /// Charges each of `peers` for one message, leaving their reservations in place.
    fn charge(&mut self, peers: &[P]) {
        for peer in peers {
            // The reservation kept every other send from spending this quota since it was checked
            let charged = self.rate_limit.check_key(peer);
            debug_assert!(charged.is_ok(), "reserved recipient must have quota");
        }
    }

    /// Prunes the rate limiter if it has grown enough since the last pass.
    ///
    /// Space out pruning passes by the number of keys retained by the last pass.
    fn maybe_prune(&mut self) {
        if self.rate_limit.len() >= self.prune_at {
            self.prune();
        }
    }

    /// Forgets peers whose quota has fully replenished.
    fn prune(&mut self) {
        self.rate_limit.retain_recent();
        self.prune_at = cmp::max(MIN_PRUNE_AT, self.rate_limit.len().saturating_mul(2));
    }
}

/// Returns whether `peer` is neither reserved nor rate-limited.
///
/// Callers mark a reservable peer and record it in spare capacity of the reservation's list
/// without any fallible step in between, so every mark is owned as soon as it exists.
fn reservable<P: PublicKey, E: Clock>(
    rate_limit: &mut KeyedRateLimiter<P, E>,
    in_flight: &HashSet<P>,
    peer: &P,
) -> bool {
    !in_flight.contains(peer) && rate_limit.check_key_available(peer).is_ok()
}

/// Reservations held by one send, released without charge unless committed.
///
/// Owns every mark from the moment it is inserted until it is removed under the same lock as the
/// final charge, so an unwind at any point (including from [`Clock::current`]) releases exactly
/// the marks this send holds.
struct Reservation<'a, P: PublicKey, E: Clock> {
    state: &'a Mutex<State<P, E>>,
    peers: Vec<P>,
}

impl<P: PublicKey, E: Clock> Reservation<'_, P, E> {
    /// Charges the reserved peers, releases them, and returns them.
    fn commit(mut self) -> Vec<P> {
        let mut state = self.state.lock();

        // Keep the marks until every charge succeeds, so an unwinding charge releases them all
        // and cannot leave a gap in which another send reserves a peer this one later releases
        state.charge(&self.peers);
        state.release(&self.peers);
        let peers = mem::take(&mut self.peers);
        state.maybe_prune();
        peers
    }
}

impl<P: PublicKey, E: Clock> Drop for Reservation<'_, P, E> {
    fn drop(&mut self) {
        if !self.peers.is_empty() {
            self.state.lock().release(&self.peers);
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
            in_flight: HashSet::new(),
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
    /// [`CheckedSender::send_with_receipt`](crate::CheckedSender::send_with_receipt).
    #[commonware_macros::stability(BETA)]
    pub(crate) fn send_to(
        self,
        recipients: Recipients<S::PublicKey>,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> SendReceipt<S::PublicKey> {
        // Convert the message before reserving recipients, as the conversion may run arbitrary
        // code
        let message = message.into();

        // Reserve the recipients so no other send can spend their quota until this submission
        // returns. The wrapped sender then runs without the lock shared by all clones, as it may
        // drop messages whose release runs arbitrary code. The reservation exists before the
        // first mark, so an unwind while reserving releases every mark already taken.
        let single = matches!(recipients, Recipients::One(_));
        let mut reservation = Reservation {
            state: self.state,
            peers: match &recipients {
                Recipients::Some(peers) => Vec::with_capacity(peers.len()),
                _ => Vec::new(),
            },
        };
        if !self
            .state
            .lock()
            .reserve(recipients, &mut reservation.peers)
        {
            return SendReceipt::new(Unreliable::Rejected, Vec::new());
        }
        let recipients = if single {
            Recipients::One(reservation.peers[0].clone())
        } else {
            Recipients::Some(reservation.peers.clone())
        };

        // Charge only an accepted submission. Otherwise, including on unwind, dropping the
        // reservation releases it without charge.
        let feedback = self.sender.send(recipients, message, priority);
        if !feedback.accepted() {
            return SendReceipt::new(feedback, Vec::new());
        }
        SendReceipt::new(feedback, reservation.commit())
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

    fn send_with_receipt(
        mut self,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> SendReceipt<Self::PublicKey> {
        let recipients = mem::replace(&mut self.recipients, Recipients::Some(Vec::new()));
        self.send_to(recipients, message, priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckedSender as _;
    use commonware_actor::Feedback;
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_runtime::{IoBuf, Quota, Runner as _, Supervisor as _, deterministic::Runner};
    use commonware_utils::{NZU32, NZUsize, channel::ring};
    use futures::SinkExt;
    use std::time::Duration;

    type PublicKey = ed25519::PublicKey;
    type SentMessage = (Recipients<PublicKey>, IoBuf, bool);
    type Hook = Box<dyn FnOnce() + Send>;

    #[derive(Clone)]
    struct MockSender {
        sent: Arc<Mutex<Vec<SentMessage>>>,
        feedback: Arc<Mutex<Unreliable<Feedback>>>,
        // Runs once during the next submission, before it returns
        hook: Arc<Mutex<Option<Hook>>>,
        // Latest submission, whatever its feedback, replaced (and dropped) by the next one
        held: Arc<Mutex<Option<IoBuf>>>,
        hold: bool,
    }

    impl MockSender {
        fn new() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
                feedback: Arc::new(Mutex::new(Unreliable::new(Feedback::Ok))),
                hook: Arc::new(Mutex::new(None)),
                held: Arc::new(Mutex::new(None)),
                hold: false,
            }
        }

        fn set_feedback(&self, feedback: Unreliable<Feedback>) {
            *self.feedback.lock() = feedback;
        }

        fn set_hook(&self, hook: impl FnOnce() + Send + 'static) {
            *self.hook.lock() = Some(Box::new(hook));
        }

        fn sent_messages(&self) -> Vec<SentMessage> {
            self.sent.lock().clone()
        }
    }

    impl fmt::Debug for MockSender {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockSender").finish_non_exhaustive()
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
            let hook = self.hook.lock().take();
            if let Some(hook) = hook {
                hook();
            }
            if self.hold {
                let previous = self.held.lock().replace(message.clone());
                drop(previous);
            }
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
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(10), context, peers);

            // Empty recipients pass through and are submitted as an empty set
            let checked = limited.check(Recipients::Some(Vec::new())).unwrap();
            assert!(checked.recipients().is_empty());
            let receipt = checked.send_with_receipt(IoBuf::from(b"empty"), false);
            assert_eq!(receipt.feedback(), Unreliable::new(Feedback::Ok));
            assert!(receipt.recipients().is_empty());
            assert_eq!(sender.sent_messages().len(), 1);
            assert_sent_to(&sender, 0, &[]);
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
            let both = Recipients::Some(vec![peer1.clone(), peer2.clone()]);

            for feedback in [Unreliable::Rejected, Unreliable::new(Feedback::Closed)] {
                sender.set_feedback(feedback);
                for recipients in [Recipients::One(peer1.clone()), both.clone()] {
                    let receipt = limited
                        .check(recipients)
                        .unwrap()
                        .send_with_receipt(IoBuf::from(b"dropped"), false);
                    assert_eq!(receipt.feedback(), feedback);
                    assert!(receipt.recipients().is_empty());
                }
            }

            // Every peer still has its full quota, and accepted overflow is charged
            sender.set_feedback(Unreliable::new(Feedback::Backoff));
            let receipt = limited
                .check(both.clone())
                .unwrap()
                .send_with_receipt(IoBuf::from(b"sent"), false);
            assert_eq!(receipt.feedback(), Unreliable::new(Feedback::Backoff));
            assert_eq!(receipt.recipients(), [peer1.clone(), peer2.clone()]);
            assert_sent_to(&sender, 0, &[peer1, peer2]);
            assert!(limited.check(both).is_err());
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
            let receipt = checked1.send_with_receipt(IoBuf::from(b"loser"), false);
            assert_eq!(receipt.feedback(), Unreliable::new(Feedback::Ok));
            assert_eq!(receipt.recipients(), std::slice::from_ref(&peer2));
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
            let receipt = checked1.send_with_receipt(IoBuf::from(b"loser"), false);
            assert_eq!(receipt.feedback(), Unreliable::Rejected);
            assert!(receipt.recipients().is_empty());
            assert_eq!(sender.sent_messages().len(), 1);
        });
    }

    /// Buffer owner that records, when released, whether the limiter lock was free.
    struct LockProbe {
        lock_free: Arc<dyn Fn() -> bool + Send + Sync>,
        releases: Arc<Mutex<Vec<bool>>>,
    }

    impl AsRef<[u8]> for LockProbe {
        fn as_ref(&self) -> &[u8] {
            b"probe"
        }
    }

    impl Drop for LockProbe {
        fn drop(&mut self) {
            // Probe without blocking so a violation fails the test instead of deadlocking
            self.releases.lock().push((self.lock_free)());
        }
    }

    #[test]
    fn message_released_outside_limiter_lock() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let peers = MockPeers::new();
            let mut limited =
                LimitedSender::new(sender.clone(), quota_per_second(1), context, peers);
            let state = limited.state.clone();
            let lock_free: Arc<dyn Fn() -> bool + Send + Sync> =
                Arc::new(move || state.try_lock().is_some());
            let releases = Arc::new(Mutex::new(Vec::new()));
            let probe = || {
                IoBuf::from(bytes::Bytes::from_owner(LockProbe {
                    lock_free: lock_free.clone(),
                    releases: releases.clone(),
                }))
            };
            let peer = key(1);

            // The wrapped sender drops unaccepted submissions before returning
            for feedback in [Unreliable::Rejected, Unreliable::new(Feedback::Closed)] {
                sender.set_feedback(feedback);
                let receipt = limited
                    .check(Recipients::One(peer.clone()))
                    .unwrap()
                    .send_with_receipt(probe(), false);
                assert_eq!(receipt.feedback(), feedback);
            }
            assert_eq!(*releases.lock(), vec![true, true]);

            // An accepted submission is charged and retained by the wrapped sender
            sender.set_feedback(Unreliable::new(Feedback::Ok));
            let checked = limited.check(Recipients::One(peer)).unwrap();
            assert!(checked.send(probe(), false).accepted());
            assert_eq!(releases.lock().len(), 2);
            sender.sent.lock().clear();
            assert_eq!(*releases.lock(), vec![true, true, true]);

            // A send whose recipient was charged through a clone since the check is not submitted
            let mut other = limited.clone();
            let stale = limited.check(Recipients::One(key(2))).unwrap();
            other
                .check(Recipients::One(key(2)))
                .unwrap()
                .send(IoBuf::from(b"winner"), false);
            assert_eq!(stale.send(probe(), false), Unreliable::Rejected);
            assert_eq!(*releases.lock(), vec![true, true, true, true]);
        });
    }

    #[test]
    fn queued_payload_released_outside_limiter_lock() {
        Runner::default().start(|context| async move {
            let mut sender = MockSender::new();
            sender.hold = true;
            sender.set_feedback(Unreliable::Rejected);
            let mut limited =
                LimitedSender::new(sender, quota_per_second(1), context, MockPeers::new());
            let state = limited.state.clone();
            let lock_free: Arc<dyn Fn() -> bool + Send + Sync> =
                Arc::new(move || state.try_lock().is_some());
            let releases = Arc::new(Mutex::new(Vec::new()));
            let probe = || {
                IoBuf::from(bytes::Bytes::from_owner(LockProbe {
                    lock_free: lock_free.clone(),
                    releases: releases.clone(),
                }))
            };

            // The wrapped sender retains the first payload and drops it while submitting the
            // second, as a queue discarding earlier work would
            for _ in 0..2 {
                let checked = limited.check(Recipients::One(key(1))).unwrap();
                assert_eq!(checked.send(probe(), false), Unreliable::Rejected);
            }
            assert_eq!(*releases.lock(), vec![true]);
            assert!(limited.state.lock().in_flight.is_empty());
        });
    }

    #[test]
    fn overlapping_send_skips_only_reserved_peers() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let mut limited = LimitedSender::new(
                sender.clone(),
                quota_per_second(2),
                context,
                MockPeers::new(),
            );
            let (busy, unrelated) = (key(1), key(2));

            // While the submission to busy is in flight, a clone reaches only the unrelated peer
            let mut other = limited.clone();
            let overlapping = Arc::new(Mutex::new(Vec::new()));
            sender.set_hook({
                let (busy, unrelated, overlapping) =
                    (busy.clone(), unrelated.clone(), overlapping.clone());
                move || {
                    let both = Recipients::Some(vec![busy.clone(), unrelated]);
                    let receipt = other
                        .check(both)
                        .unwrap()
                        .send_with_receipt(IoBuf::from(b"both"), false);
                    overlapping.lock().push(receipt);
                    let receipt = other
                        .check(Recipients::One(busy))
                        .unwrap()
                        .send_with_receipt(IoBuf::from(b"busy"), false);
                    overlapping.lock().push(receipt);
                }
            });
            let receipt = limited
                .check(Recipients::One(busy.clone()))
                .unwrap()
                .send_with_receipt(IoBuf::from(b"first"), false);
            assert_eq!(receipt.recipients(), std::slice::from_ref(&busy));

            let overlapping = overlapping.lock();
            assert_eq!(overlapping[0].feedback(), Unreliable::new(Feedback::Ok));
            assert_eq!(
                overlapping[0].recipients(),
                std::slice::from_ref(&unrelated)
            );
            assert_eq!(overlapping[1].feedback(), Unreliable::Rejected);
            assert!(overlapping[1].recipients().is_empty());

            // Each accepted submission charged its recipients once and released them
            assert!(limited.state.lock().in_flight.is_empty());
            assert_eq!(sender.sent_messages().len(), 2);
            for peer in [busy, unrelated] {
                let receipt = limited
                    .check(Recipients::One(peer.clone()))
                    .unwrap()
                    .send_with_receipt(IoBuf::from(b"remaining cell"), false);
                assert_eq!(receipt.recipients(), std::slice::from_ref(&peer));
                assert!(limited.check(Recipients::One(peer)).is_err());
            }
        });
    }

    #[test]
    fn unaccepted_or_panicked_send_releases_reservations() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let mut limited = LimitedSender::new(
                sender.clone(),
                quota_per_second(1),
                context,
                MockPeers::new(),
            );
            let peers = Recipients::Some(vec![key(1), key(2)]);

            // A rejected submission releases its reservations without charge
            sender.set_feedback(Unreliable::Rejected);
            let checked = limited.check(peers.clone()).unwrap();
            assert_eq!(
                checked.send(IoBuf::from(b"rejected"), false),
                Unreliable::Rejected
            );
            assert!(limited.state.lock().in_flight.is_empty());

            // A panicking submission releases its reservations without charge
            sender.set_feedback(Unreliable::new(Feedback::Ok));
            sender.set_hook(|| panic!("submission panicked"));
            let checked = limited.check(peers.clone()).unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                checked.send(IoBuf::from(b"panicked"), false)
            }));
            assert!(result.is_err());
            assert!(limited.state.lock().in_flight.is_empty());

            // Both recipients still have their full quota
            let receipt = limited
                .check(peers.clone())
                .unwrap()
                .send_with_receipt(IoBuf::from(b"accepted"), false);
            assert_eq!(receipt.into_recipients(), vec![key(1), key(2)]);
            assert!(limited.state.lock().in_flight.is_empty());
            assert!(limited.check(peers).is_err());
        });
    }

    /// A fixed clock whose read panics once a countdown of reads elapses.
    #[derive(Clone)]
    struct FaultyClock {
        countdown: Arc<Mutex<Option<usize>>>,
    }

    impl FaultyClock {
        fn new() -> Self {
            Self {
                countdown: Arc::new(Mutex::new(None)),
            }
        }

        /// Makes the `reads`-th subsequent read panic.
        fn panic_on_read(&self, reads: usize) {
            *self.countdown.lock() = Some(reads);
        }
    }

    impl commonware_runtime::Clock for FaultyClock {
        fn current(&self) -> SystemTime {
            let fault = {
                let mut countdown = self.countdown.lock();
                let remaining = countdown.map(|remaining| remaining - 1);
                *countdown = remaining.filter(|remaining| *remaining > 0);
                remaining == Some(0)
            };
            assert!(!fault, "clock read failed");
            SystemTime::UNIX_EPOCH
        }

        fn sleep(&self, _: Duration) -> impl Future<Output = ()> + Send + 'static + use<> {
            std::future::ready(())
        }

        fn sleep_until(&self, _: SystemTime) -> impl Future<Output = ()> + Send + 'static + use<> {
            std::future::ready(())
        }
    }

    #[test]
    fn clock_panic_while_reserving_releases_marks() {
        let sender = MockSender::new();
        let clock = FaultyClock::new();
        let mut limited = LimitedSender::new(
            sender.clone(),
            quota_per_second(1),
            clock.clone(),
            MockPeers::new(),
        );
        let peers = Recipients::Some(vec![key(1), key(2)]);

        // The first peer is marked before reading the clock for the second panics
        let checked = limited.check(peers.clone()).unwrap();
        clock.panic_on_read(2);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            checked.send(IoBuf::from(b"reserving"), false)
        }));
        assert!(result.is_err());
        assert!(limited.state.lock().in_flight.is_empty());
        assert!(sender.sent_messages().is_empty());

        // Nothing was charged, so both peers remain reachable
        let receipt = limited
            .check(peers)
            .unwrap()
            .send_with_receipt(IoBuf::from(b"accepted"), false);
        assert_eq!(receipt.into_recipients(), vec![key(1), key(2)]);
    }

    #[test]
    fn clock_panic_while_charging_releases_marks() {
        let sender = MockSender::new();
        let clock = FaultyClock::new();
        let mut limited = LimitedSender::new(
            sender.clone(),
            quota_per_second(1),
            clock.clone(),
            MockPeers::new(),
        );
        let peers = Recipients::Some(vec![key(1), key(2)]);

        // Reserving reads the clock once per peer, and charging the second peer panics after the
        // submission was accepted
        let checked = limited.check(peers).unwrap();
        clock.panic_on_read(4);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            checked.send(IoBuf::from(b"charging"), false)
        }));
        assert!(result.is_err());
        assert_eq!(sender.sent_messages().len(), 1);
        assert!(limited.state.lock().in_flight.is_empty());

        // Released marks let a later send reserve any peer it still has quota for
        let receipt = limited
            .check(Recipients::One(key(2)))
            .unwrap()
            .send_with_receipt(IoBuf::from(b"after"), false);
        assert_eq!(receipt.into_recipients(), vec![key(2)]);
        assert!(limited.state.lock().in_flight.is_empty());
    }

    #[test]
    fn peer_update_prunes_replenished_peers() {
        Runner::default().start(|context| async move {
            let sender = MockSender::new();
            let stale = key(1);
            let partial = key(2);
            let (mut updates, receiver) = ring::channel(NZUsize!(1));
            let peers = UpdatingPeers {
                peers: vec![stale.clone(), partial.clone()],
                receiver: Arc::new(Mutex::new(Some(receiver))),
            };
            let mut limited =
                LimitedSender::new(sender, quota_per_second(2), context.child("limiter"), peers);

            // stale fully replenishes while partial still has one message of its burst spent
            limited
                .check(Recipients::One(stale.clone()))
                .unwrap()
                .send(IoBuf::from(b"hello"), false);
            context.sleep(Duration::from_secs(1)).await;
            limited
                .check(Recipients::One(partial.clone()))
                .unwrap()
                .send(IoBuf::from(b"hello"), false);
            assert_eq!(limited.state.lock().rate_limit.len(), 2);

            // Addressing all peers without a membership update does not prune
            drop(limited.check(Recipients::All).unwrap());
            assert_eq!(limited.state.lock().rate_limit.len(), 2);

            // A membership update prunes the replenished peer and retains the partial one
            updates.send(vec![stale, partial.clone()]).await.unwrap();
            drop(limited.check(Recipients::All).unwrap());
            assert_eq!(limited.state.lock().rate_limit.len(), 1);

            // partial retained its spent quota, so one more message exhausts its burst
            limited
                .check(Recipients::One(partial.clone()))
                .unwrap()
                .send(IoBuf::from(b"hello"), false);
            assert!(limited.check(Recipients::One(partial)).is_err());
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
