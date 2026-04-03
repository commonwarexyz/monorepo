//! Interleave a live channel with follower traffic.
//!
//! This utility merges two sender/receiver pairs that share the same public key
//! space. A common use case is exposing an additional transport for follower
//! nodes while keeping the existing authenticated channel untouched.
//!
//! The wrapper is intentionally transport-agnostic:
//! - callers decide how direct recipients are partitioned between the live and
//!   follower transports
//! - `Recipients::All` can be mirrored to both sides
//! - inbound traffic from both sides is received through a single [`Receiver`]
//!
//! Callers should ensure the two transports address disjoint peers unless
//! duplicate delivery is acceptable.

use crate::{CheckedSender, LimitedSender, Message, Receiver, Recipients, Sender};
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_runtime::IoBufs;
use std::{cmp, fmt::Debug, time::SystemTime};
use thiserror::Error;

/// Routed recipients for an interleaved send.
#[derive(Clone, Debug)]
pub struct RoutedRecipients<P: PublicKey> {
    /// Recipients to send over the live transport.
    pub live: Option<Recipients<P>>,
    /// Recipients to send over the follower transport.
    pub follower: Option<Recipients<P>>,
}

impl<P: PublicKey> RoutedRecipients<P> {
    /// Create a new routing decision.
    pub const fn new(live: Option<Recipients<P>>, follower: Option<Recipients<P>>) -> Self {
        Self { live, follower }
    }

    /// Route the same recipients to both transports.
    pub fn mirror(recipients: &Recipients<P>) -> Self {
        Self {
            live: Some(recipients.clone()),
            follower: Some(recipients.clone()),
        }
    }
}

/// Partition recipients between live and follower transports.
pub trait Router<P: PublicKey>:
    Fn(&Recipients<P>) -> RoutedRecipients<P> + Clone + Send + Sync + 'static
{
}

impl<P: PublicKey, F> Router<P> for F where
    F: Fn(&Recipients<P>) -> RoutedRecipients<P> + Clone + Send + Sync + 'static
{
}

/// Wrap a live and follower transport pair.
pub const fn wrap<S1, R1, S2, R2, F>(
    live_sender: S1,
    live_receiver: R1,
    follower_sender: S2,
    follower_receiver: R2,
    router: F,
) -> (
    InterleavedSender<S1, S2, F>,
    InterleavedReceiver<R1, R2>,
)
where
    S1: Sender,
    R1: Receiver<PublicKey = S1::PublicKey>,
    S2: Sender<PublicKey = S1::PublicKey>,
    R2: Receiver<PublicKey = S1::PublicKey>,
    F: Router<S1::PublicKey>,
{
    (
        InterleavedSender::new(live_sender, follower_sender, router),
        InterleavedReceiver::new(live_receiver, follower_receiver),
    )
}

/// Errors that can occur while sending over an interleaved channel.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum SendError<L, F> {
    #[error("live send failed: {0}")]
    Live(L),
    #[error("follower send failed: {0}")]
    Follower(F),
    #[error("live send failed: {live}; follower send failed: {follower}")]
    Both { live: L, follower: F },
}

/// Errors that can occur while receiving over an interleaved channel.
#[derive(Error, Debug)]
pub enum ReceiveError<L, F> {
    #[error("live receiver closed: {0}")]
    Live(L),
    #[error("follower receiver closed: {0}")]
    Follower(F),
    #[error("live receiver closed: {live}; follower receiver closed: {follower}")]
    Both { live: L, follower: F },
    #[error("both receivers are closed")]
    Closed,
}

/// Sender that partitions outbound traffic across a live and follower transport.
#[derive(Clone, Debug)]
pub struct InterleavedSender<S1: Sender, S2: Sender<PublicKey = S1::PublicKey>, F> {
    live: S1,
    follower: S2,
    router: F,
}

impl<S1, S2, F> InterleavedSender<S1, S2, F>
where
    S1: Sender,
    S2: Sender<PublicKey = S1::PublicKey>,
    F: Router<S1::PublicKey>,
{
    /// Create a new interleaved sender.
    pub const fn new(live: S1, follower: S2, router: F) -> Self {
        Self {
            live,
            follower,
            router,
        }
    }
}

impl<S1, S2, F> LimitedSender for InterleavedSender<S1, S2, F>
where
    S1: Sender,
    S2: Sender<PublicKey = S1::PublicKey>,
    F: Router<S1::PublicKey>,
{
    type PublicKey = S1::PublicKey;
    type Checked<'a>
        = InterleavedCheckedSender<'a, S1, S2>
    where
        Self: 'a;

    async fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        let RoutedRecipients { live, follower } = (self.router)(&recipients);

        let mut live_retry = None;
        let mut follower_retry = None;

        let live = match live {
            Some(recipients) => match self.live.check(recipients).await {
                Ok(checked) => Some(checked),
                Err(retry) => {
                    live_retry = Some(retry);
                    None
                }
            },
            None => None,
        };

        let follower = match follower {
            Some(recipients) => match self.follower.check(recipients).await {
                Ok(checked) => Some(checked),
                Err(retry) => {
                    follower_retry = Some(retry);
                    None
                }
            },
            None => None,
        };

        if live.is_some()
            || follower.is_some()
            || (live_retry.is_none() && follower_retry.is_none())
        {
            Ok(InterleavedCheckedSender { live, follower })
        } else {
            Err(match (live_retry, follower_retry) {
                (Some(live), Some(follower)) => cmp::min(live, follower),
                (Some(live), None) => live,
                (None, Some(follower)) => follower,
                (None, None) => SystemTime::UNIX_EPOCH,
            })
        }
    }
}

/// Checked sender for an [`InterleavedSender`].
pub struct InterleavedCheckedSender<
    'a,
    S1: Sender,
    S2: Sender<PublicKey = S1::PublicKey>,
> {
    live: Option<S1::Checked<'a>>,
    follower: Option<S2::Checked<'a>>,
}

impl<'a, S1, S2> CheckedSender for InterleavedCheckedSender<'a, S1, S2>
where
    S1: Sender,
    S2: Sender<PublicKey = S1::PublicKey>,
{
    type PublicKey = S1::PublicKey;
    type Error = SendError<
        <S1::Checked<'a> as CheckedSender>::Error,
        <S2::Checked<'a> as CheckedSender>::Error,
    >;

    async fn send(
        self,
        message: impl Into<IoBufs> + Send,
        priority: bool,
    ) -> Result<Vec<Self::PublicKey>, Self::Error> {
        let message = message.into().coalesce();

        let live: Result<
            Vec<Self::PublicKey>,
            SendError<
                <S1::Checked<'a> as CheckedSender>::Error,
                <S2::Checked<'a> as CheckedSender>::Error,
            >,
        > = match self.live {
            Some(sender) => sender
                .send(message.clone(), priority)
                .await
                .map_err(|err| SendError::Live(err)),
            None => Ok(Vec::new()),
        };
        let follower: Result<
            Vec<Self::PublicKey>,
            SendError<
                <S1::Checked<'a> as CheckedSender>::Error,
                <S2::Checked<'a> as CheckedSender>::Error,
            >,
        > = match self.follower {
            Some(sender) => sender
                .send(message, priority)
                .await
                .map_err(|err| SendError::Follower(err)),
            None => Ok(Vec::new()),
        };

        match (live, follower) {
            (Ok(mut live), Ok(follower)) => {
                extend_unique(&mut live, follower);
                Ok(live)
            }
            (Err(SendError::Live(live)), Ok(_)) => Err(SendError::Live(live)),
            (Ok(_), Err(SendError::Follower(follower))) => Err(SendError::Follower(follower)),
            (Err(SendError::Live(live)), Err(SendError::Follower(follower))) => {
                Err(SendError::Both { live, follower })
            }
            _ => unreachable!("interleaved sender only constructs tagged errors"),
        }
    }
}

/// Receiver that merges inbound live and follower traffic.
#[derive(Debug)]
pub struct InterleavedReceiver<R1: Receiver, R2: Receiver<PublicKey = R1::PublicKey>> {
    live: Option<R1>,
    follower: Option<R2>,
    prefer_live: bool,
    live_error: Option<R1::Error>,
    follower_error: Option<R2::Error>,
}

impl<R1, R2> InterleavedReceiver<R1, R2>
where
    R1: Receiver,
    R2: Receiver<PublicKey = R1::PublicKey>,
{
    /// Create a new interleaved receiver.
    pub const fn new(live: R1, follower: R2) -> Self {
        Self {
            live: Some(live),
            follower: Some(follower),
            prefer_live: true,
            live_error: None,
            follower_error: None,
        }
    }

    fn take_error(&mut self) -> ReceiveError<R1::Error, R2::Error> {
        match (self.live_error.take(), self.follower_error.take()) {
            (Some(live), Some(follower)) => ReceiveError::Both { live, follower },
            (Some(live), None) => ReceiveError::Live(live),
            (None, Some(follower)) => ReceiveError::Follower(follower),
            (None, None) => ReceiveError::Closed,
        }
    }
}

impl<R1, R2> Receiver for InterleavedReceiver<R1, R2>
where
    R1: Receiver,
    R2: Receiver<PublicKey = R1::PublicKey>,
{
    type Error = ReceiveError<R1::Error, R2::Error>;
    type PublicKey = R1::PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        enum Source<L, LE, F, FE> {
            Live(Result<L, LE>),
            Follower(Result<F, FE>),
        }

        loop {
            match (&mut self.live, &mut self.follower) {
                (Some(live), Some(follower)) => {
                    let prefer_live = self.prefer_live;
                    let result = if prefer_live {
                        select! {
                            result = live.recv() => Source::Live(result),
                            result = follower.recv() => Source::Follower(result),
                        }
                    } else {
                        select! {
                            result = follower.recv() => Source::Follower(result),
                            result = live.recv() => Source::Live(result),
                        }
                    };

                    self.prefer_live = !self.prefer_live;
                    match result {
                        Source::Live(Ok(message)) => return Ok(message),
                        Source::Follower(Ok(message)) => return Ok(message),
                        Source::Live(Err(err)) => {
                            self.live = None;
                            self.live_error = Some(err);
                        }
                        Source::Follower(Err(err)) => {
                            self.follower = None;
                            self.follower_error = Some(err);
                        }
                    }
                }
                (Some(live), None) => match live.recv().await {
                    Ok(message) => return Ok(message),
                    Err(err) => {
                        self.live = None;
                        self.live_error = Some(err);
                    }
                },
                (None, Some(follower)) => match follower.recv().await {
                    Ok(message) => return Ok(message),
                    Err(err) => {
                        self.follower = None;
                        self.follower_error = Some(err);
                    }
                },
                (None, None) => return Err(self.take_error()),
            }
        }
    }
}

fn extend_unique<P: PublicKey>(target: &mut Vec<P>, source: Vec<P>) {
    for peer in source {
        if !target.contains(&peer) {
            target.push(peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{ed25519, Signer as _};
    use commonware_runtime::{deterministic, IoBuf, IoBufs, Runner as _};
    use commonware_utils::channel::mpsc;
    use std::{
        io,
        sync::{Arc, Mutex},
    };
    use thiserror::Error;

    type PublicKey = ed25519::PublicKey;
    type SentMessage = (Recipients<PublicKey>, IoBuf, bool);

    #[derive(Debug, Error, PartialEq, Eq)]
    enum MockError {
        #[error("message too large: {0}")]
        MessageTooLarge(usize),
    }

    #[derive(Clone, Debug)]
    struct MockSender {
        peers: Vec<PublicKey>,
        max_size: usize,
        sent: Arc<Mutex<Vec<SentMessage>>>,
    }

    impl MockSender {
        fn new(peers: Vec<PublicKey>, max_size: usize) -> Self {
            Self {
                peers,
                max_size,
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn sent_messages(&self) -> Vec<SentMessage> {
            self.sent.lock().unwrap().clone()
        }
    }

    struct MockCheckedSender<'a> {
        sender: &'a mut MockSender,
        recipients: Recipients<PublicKey>,
    }

    impl LimitedSender for MockSender {
        type PublicKey = PublicKey;
        type Checked<'a>
            = MockCheckedSender<'a>
        where
            Self: 'a;

        async fn check(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'_>, SystemTime> {
            let recipients = match recipients {
                Recipients::All => Recipients::Some(self.peers.clone()),
                Recipients::Some(peers) => {
                    let peers = peers
                        .into_iter()
                        .filter(|peer| self.peers.contains(peer))
                        .collect::<Vec<_>>();
                    if peers.is_empty() {
                        return Err(SystemTime::UNIX_EPOCH);
                    }
                    Recipients::Some(peers)
                }
                Recipients::One(peer) => {
                    if !self.peers.contains(&peer) {
                        return Err(SystemTime::UNIX_EPOCH);
                    }
                    Recipients::One(peer)
                }
            };

            Ok(MockCheckedSender {
                sender: self,
                recipients,
            })
        }
    }

    impl CheckedSender for MockCheckedSender<'_> {
        type PublicKey = PublicKey;
        type Error = MockError;

        async fn send(
            self,
            message: impl Into<IoBufs> + Send,
            priority: bool,
        ) -> Result<Vec<Self::PublicKey>, Self::Error> {
            let message = message.into().coalesce();
            if message.len() > self.sender.max_size {
                return Err(MockError::MessageTooLarge(message.len()));
            }

            self.sender
                .sent
                .lock()
                .unwrap()
                .push((self.recipients.clone(), message.clone(), priority));

            Ok(match self.recipients {
                Recipients::All => unreachable!("check expands Recipients::All"),
                Recipients::Some(peers) => peers,
                Recipients::One(peer) => vec![peer],
            })
        }
    }

    #[derive(Debug)]
    struct MockReceiver {
        receiver: mpsc::UnboundedReceiver<Message<PublicKey>>,
    }

    impl Receiver for MockReceiver {
        type Error = io::Error;
        type PublicKey = PublicKey;

        async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
            self.receiver
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    fn pk(seed: u64) -> PublicKey {
        ed25519::PrivateKey::from_seed(seed).public_key()
    }

    fn split_followers(
        followers: Vec<PublicKey>,
    ) -> impl Fn(&Recipients<PublicKey>) -> RoutedRecipients<PublicKey> + Clone {
        move |recipients| match recipients {
            Recipients::All => RoutedRecipients::mirror(recipients),
            Recipients::Some(peers) => {
                let (mut live, mut follower) = (Vec::new(), Vec::new());
                for peer in peers {
                    if followers.contains(peer) {
                        follower.push(peer.clone());
                    } else {
                        live.push(peer.clone());
                    }
                }
                RoutedRecipients::new(
                    (!live.is_empty()).then_some(Recipients::Some(live)),
                    (!follower.is_empty()).then_some(Recipients::Some(follower)),
                )
            }
            Recipients::One(peer) => {
                if followers.contains(peer) {
                    RoutedRecipients::new(None, Some(Recipients::One(peer.clone())))
                } else {
                    RoutedRecipients::new(Some(Recipients::One(peer.clone())), None)
                }
            }
        }
    }

    #[test]
    fn send_all_hits_live_and_followers() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let live_peer = pk(1);
            let follower_peer = pk(2);
            let (mut sender, _) = wrap(
                MockSender::new(vec![live_peer.clone()], 1024),
                MockReceiver {
                    receiver: mpsc::unbounded_channel().1,
                },
                MockSender::new(vec![follower_peer.clone()], 1024),
                MockReceiver {
                    receiver: mpsc::unbounded_channel().1,
                },
                RoutedRecipients::mirror,
            );

            let sent = sender
                .send(Recipients::All, &b"hello"[..], true)
                .await
                .unwrap();
            assert_eq!(sent.len(), 2);
            assert!(sent.contains(&live_peer));
            assert!(sent.contains(&follower_peer));
        });
    }

    #[test]
    fn direct_sends_respect_partitioning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let live_peer = pk(1);
            let follower_peer = pk(2);
            let live = MockSender::new(vec![live_peer.clone()], 1024);
            let follower = MockSender::new(vec![follower_peer.clone()], 1);
            let live_log = live.clone();
            let follower_log = follower.clone();
            let (mut sender, _) = wrap(
                live,
                MockReceiver {
                    receiver: mpsc::unbounded_channel().1,
                },
                follower,
                MockReceiver {
                    receiver: mpsc::unbounded_channel().1,
                },
                split_followers(vec![follower_peer.clone()]),
            );

            let sent = sender
                .send(Recipients::One(live_peer.clone()), &b"live"[..], false)
                .await
                .unwrap();
            assert_eq!(sent, vec![live_peer.clone()]);
            assert_eq!(live_log.sent_messages().len(), 1);
            assert!(follower_log.sent_messages().is_empty());

            let err = sender
                .send(Recipients::One(follower_peer.clone()), &b"wide"[..], false)
                .await
                .unwrap_err();
            assert_eq!(
                err,
                SendError::Follower(MockError::MessageTooLarge(b"wide".len()))
            );
            assert_eq!(live_log.sent_messages().len(), 1);
            assert_eq!(follower_log.sent_messages().len(), 0);
        });
    }

    #[test]
    fn receiver_interleaves_and_survives_one_side_closing() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let live_peer = pk(1);
            let follower_peer = pk(2);
            let (live_tx, live_rx) = mpsc::unbounded_channel();
            let (follower_tx, follower_rx) = mpsc::unbounded_channel();
            let mut receiver = InterleavedReceiver::new(
                MockReceiver { receiver: live_rx },
                MockReceiver {
                    receiver: follower_rx,
                },
            );

            live_tx.send((live_peer.clone(), IoBuf::from(b"live"))).unwrap();
            let (from, payload) = receiver.recv().await.unwrap();
            assert_eq!(from, live_peer);
            assert_eq!(payload, b"live");

            follower_tx
                .send((follower_peer.clone(), IoBuf::from(b"follower")))
                .unwrap();
            let (from, payload) = receiver.recv().await.unwrap();
            assert_eq!(from, follower_peer);
            assert_eq!(payload, b"follower");

            drop(follower_tx);
            live_tx
                .send((live_peer.clone(), IoBuf::from(b"still-live")))
                .unwrap();
            let (from, payload) = receiver.recv().await.unwrap();
            assert_eq!(from, live_peer);
            assert_eq!(payload, b"still-live");

            drop(live_tx);
            let err = receiver.recv().await.unwrap_err();
            assert!(matches!(err, ReceiveError::Both { .. }));
        });
    }

    #[test]
    fn check_prefers_available_side() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let live_peer = pk(1);
            let follower_peer = pk(2);
            let (mut sender, _) = wrap(
                MockSender::new(vec![live_peer.clone()], 1024),
                MockReceiver {
                    receiver: mpsc::unbounded_channel().1,
                },
                MockSender::new(vec![follower_peer.clone()], 1024),
                MockReceiver {
                    receiver: mpsc::unbounded_channel().1,
                },
                split_followers(vec![follower_peer]),
            );

            let checked = sender.check(Recipients::One(live_peer.clone())).await.unwrap();
            let sent = checked.send(&b"x"[..], false).await.unwrap();
            assert_eq!(sent, vec![live_peer]);
        });
    }
}
