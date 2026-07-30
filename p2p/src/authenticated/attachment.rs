//! Authentication and attachment of established transport connections.

use super::{
    Mailbox,
    admission::{InboundAdmission, Rejection},
};
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{self, UnreliablePolicy},
};
use commonware_cryptography::{PublicKey, Signer};
use commonware_macros::{select_loop, stability};
use commonware_runtime::{
    BufferPooler, Clock, Connection, ConnectionInfo, ContextCell, Handle, Metrics, Scheduler,
    spawn_cell,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_stream::encrypted::{self, Config as StreamConfig};
use commonware_utils::{PlatformSend, PlatformSync, channel::oneshot, concurrency::Limiter};
use rand_core::CryptoRng;
use std::{
    collections::VecDeque,
    future::Future,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
};
use thiserror::Error;
use tracing::debug;

/// Failure to authenticate or attach a transport connection.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// The attachment actor is no longer available.
    #[error("attachment actor unavailable")]
    Unavailable,
    /// The network cannot accept another connection without exceeding configured capacity.
    #[error("too many pending connection handshakes")]
    Busy,
    /// The inbound admission policy rejected the connection.
    #[error("connection rejected: {0}")]
    Rejected(Rejection),
    /// The encrypted handshake failed.
    #[error("encrypted handshake failed")]
    Handshake,
    /// The authenticated peer could not be reserved.
    #[error("peer unavailable")]
    PeerUnavailable,
    /// The peer spawner rejected the connection due to backpressure or shutdown.
    #[error("peer spawner unavailable")]
    SpawnerUnavailable,
}

pub(crate) enum Direction {
    Outbound,
    Inbound,
}

/// Connects an authenticated stream to a protocol-specific peer actor.
pub(crate) trait Protocol<P: PublicKey, N: Connection>:
    Clone + PlatformSend + PlatformSync + 'static
{
    type Reservation: PlatformSend + 'static;

    fn acceptable(
        &self,
        peer: P,
        direction: &Direction,
        info: &ConnectionInfo<N::Origin>,
    ) -> impl Future<Output = bool> + PlatformSend;

    fn reserve(
        &self,
        peer: P,
        direction: &Direction,
        info: &ConnectionInfo<N::Origin>,
    ) -> impl Future<Output = Option<Self::Reservation>> + PlatformSend;

    fn spawn(
        &self,
        connection: (encrypted::Sender<N::Sink>, encrypted::Receiver<N::Stream>),
        reservation: Self::Reservation,
    ) -> bool;
}

/// Authenticates an established outbound connection as an exact peer.
pub(crate) async fn authenticate_outbound<E, C, N>(
    context: E,
    stream_cfg: StreamConfig<C>,
    expected_peer: C::PublicKey,
    connection: N,
) -> Result<
    (
        (encrypted::Sender<N::Sink>, encrypted::Receiver<N::Stream>),
        ConnectionInfo<N::Origin>,
    ),
    Error,
>
where
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
{
    let (sink, stream, info) = connection.split();
    let encrypted = encrypted::dial(context, stream_cfg, expected_peer, stream, sink)
        .await
        .map_err(|_| Error::Handshake)?;
    Ok((encrypted, info))
}

enum Message<N, P, T>
where
    N: Connection,
    P: PublicKey,
{
    #[allow(dead_code, reason = "constructed by ALPHA attachment APIs")]
    Outbound {
        expected_peer: P,
        connection: N,
        responder: oneshot::Sender<Result<(), Error>>,
    },
    Inbound {
        connection: Inbound<N, T>,
        responder: oneshot::Sender<Result<(), Error>>,
    },
}

struct Inbound<N: Connection, T> {
    sink: N::Sink,
    stream: N::Stream,
    info: ConnectionInfo<N::Origin>,
    permit: T,
}

impl<N: Connection, P: PublicKey, T: PlatformSend> UnreliablePolicy for Message<N, P, T> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

/// Handle for attaching established transport connections to an authenticated network.
pub struct Attachments<N, P, A>
where
    N: Connection,
    P: PublicKey,
    A: InboundAdmission<P, N::Origin>,
{
    mailbox: Mailbox<Message<N, P, A::Permit>>,
    admission: Arc<A>,
}

impl<N, P, A> Clone for Attachments<N, P, A>
where
    N: Connection,
    P: PublicKey,
    A: InboundAdmission<P, N::Origin>,
{
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
            admission: self.admission.clone(),
        }
    }
}

impl<N, P, A> Attachments<N, P, A>
where
    N: Connection,
    P: PublicKey,
    A: InboundAdmission<P, N::Origin>,
{
    fn enqueue(&self, message: Message<N, P, A::Permit>) -> Result<(), Error> {
        match self.mailbox.0.enqueue(message) {
            Unreliable::Outcome(Feedback::Ok | Feedback::Backoff) => Ok(()),
            Unreliable::Outcome(Feedback::Closed) => Err(Error::Unavailable),
            Unreliable::Rejected => Err(Error::Busy),
        }
    }

    /// Attaches an outbound connection expected to authenticate as `expected_peer`.
    #[stability(ALPHA)]
    pub async fn attach_outbound(&self, expected_peer: P, connection: N) -> Result<(), Error> {
        let receiver = self.submit_outbound(expected_peer, connection)?;
        receiver.await.unwrap_or(Err(Error::Unavailable))
    }

    /// Attaches an inbound connection whose peer identity is learned during authentication.
    #[stability(ALPHA)]
    pub async fn attach_inbound(&self, connection: N) -> Result<(), Error> {
        let receiver = self.submit_inbound(connection)?;
        receiver.await.unwrap_or(Err(Error::Unavailable))
    }

    #[stability(ALPHA)]
    fn submit_outbound(
        &self,
        expected_peer: P,
        connection: N,
    ) -> Result<oneshot::Receiver<Result<(), Error>>, Error> {
        let (responder, receiver) = oneshot::channel();
        self.enqueue(Message::Outbound {
            expected_peer,
            connection,
            responder,
        })?;
        Ok(receiver)
    }

    /// Submits an inbound connection without waiting for its handshake to finish.
    ///
    /// Listener actors use this method to keep accepting connections while earlier handshakes are
    /// in progress.
    pub(crate) fn submit_inbound(
        &self,
        connection: N,
    ) -> Result<oneshot::Receiver<Result<(), Error>>, Error> {
        let (sink, stream, info) = connection.split();
        let permit = self.admission.pre_auth(&info).map_err(Error::Rejected)?;
        let (responder, receiver) = oneshot::channel();
        self.enqueue(Message::Inbound {
            connection: Inbound {
                sink,
                stream,
                info,
                permit,
            },
            responder,
        })?;
        Ok(receiver)
    }
}

/// Shared engine for authenticating established transport connections.
pub(crate) struct Actor<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: InboundAdmission<C::PublicKey, N::Origin>,
> {
    context: ContextCell<E>,
    stream_cfg: StreamConfig<C>,
    admission: Arc<A>,
    handshake_limiter: Limiter,
    receiver: mailbox::UnreliableReceiver<Message<N, C::PublicKey, A::Permit>>,
    handshakes_concurrent_rate_limited: Counter,
}

impl<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: InboundAdmission<C::PublicKey, N::Origin>,
> Actor<E, C, N, A>
{
    pub(crate) fn new(
        context: E,
        stream_cfg: StreamConfig<C>,
        admission: A,
        mailbox_size: NonZeroUsize,
        max_concurrent_handshakes: NonZeroU32,
    ) -> (Self, Attachments<N, C::PublicKey, A>) {
        let (mailbox, receiver) = Mailbox::new(context.child("mailbox"), mailbox_size);
        let handshakes_concurrent_rate_limited = context.counter(
            "handshake_concurrent_rate_limited",
            "number of handshake attempts dropped because maximum concurrent handshakes was reached",
        );
        let admission = Arc::new(admission);
        (
            Self {
                context: ContextCell::new(context),
                stream_cfg,
                admission: admission.clone(),
                handshake_limiter: Limiter::new(max_concurrent_handshakes),
                receiver,
                handshakes_concurrent_rate_limited,
            },
            Attachments { mailbox, admission },
        )
    }

    pub(crate) fn start<H>(mut self, protocol: H) -> Handle<()>
    where
        H: Protocol<C::PublicKey, N>,
    {
        spawn_cell!(self.context, self.run(protocol))
    }

    async fn run<H>(mut self, protocol: H)
    where
        H: Protocol<C::PublicKey, N>,
    {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping attachment actor");
            },
            Some(message) = self.receiver.recv() else {
                debug!("attachment mailbox closed");
                break;
            } => {
                let Some(handshake_reservation) = self.handshake_limiter.try_acquire() else {
                    self.handshakes_concurrent_rate_limited.inc();
                    let responder = match message {
                        Message::Outbound { responder, .. }
                        | Message::Inbound { responder, .. } => responder,
                    };
                    let _ = responder.send(Err(Error::Busy));
                    continue;
                };

                let stream_cfg = self.stream_cfg.clone();
                let admission = self.admission.clone();
                let protocol = protocol.clone();
                self.context.child("handshake").spawn(move |context| async move {
                    let _handshake_reservation = handshake_reservation;
                    let (result, responder) = match message {
                        Message::Outbound { expected_peer, connection, responder } => (
                            Self::attach_outbound(
                                context,
                                stream_cfg,
                                expected_peer,
                                connection,
                                protocol,
                            ).await,
                            responder,
                        ),
                        Message::Inbound { connection, responder } => (
                            Self::attach_inbound(
                                context,
                                stream_cfg,
                                admission,
                                connection,
                                protocol,
                            ).await,
                            responder,
                        ),
                    };
                    let _ = responder.send(result);
                });
            },
        }
    }

    async fn attach_outbound<H>(
        context: E,
        stream_cfg: StreamConfig<C>,
        expected_peer: C::PublicKey,
        connection: N,
        protocol: H,
    ) -> Result<(), Error>
    where
        H: Protocol<C::PublicKey, N>,
    {
        let (encrypted, info) =
            authenticate_outbound(context, stream_cfg, expected_peer.clone(), connection).await?;
        let direction = Direction::Outbound;
        let reservation = protocol
            .reserve(expected_peer, &direction, &info)
            .await
            .ok_or(Error::PeerUnavailable)?;
        if protocol.spawn(encrypted, reservation) {
            Ok(())
        } else {
            Err(Error::SpawnerUnavailable)
        }
    }

    async fn attach_inbound<H>(
        context: E,
        stream_cfg: StreamConfig<C>,
        admission: Arc<A>,
        connection: Inbound<N, A::Permit>,
        protocol: H,
    ) -> Result<(), Error>
    where
        H: Protocol<C::PublicKey, N>,
    {
        let Inbound {
            sink,
            stream,
            info,
            permit,
        } = connection;
        let direction = Direction::Inbound;
        let acceptable_protocol = protocol.clone();
        let acceptable_admission = admission.clone();
        let (peer, sender, receiver) = encrypted::listen(
            context,
            |peer| async {
                if !acceptable_admission.accept_peer(&peer, &info) {
                    return false;
                }
                acceptable_protocol
                    .acceptable(peer, &direction, &info)
                    .await
            },
            stream_cfg,
            stream,
            sink,
        )
        .await
        .map_err(|_| Error::Handshake)?;
        let reservation = protocol
            .reserve(peer.clone(), &direction, &info)
            .await
            .ok_or(Error::PeerUnavailable)?;
        admission
            .post_auth(permit, &peer, &info)
            .await
            .map_err(Error::Rejected)?;
        if protocol.spawn((sender, receiver), reservation) {
            Ok(())
        } else {
            Err(Error::SpawnerUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::admission::{TcpAdmission, TcpAdmissionConfig};
    use commonware_cryptography::ed25519::{PrivateKey, PublicKey as Ed25519PublicKey};
    use commonware_runtime::{
        Quota, Runner as _, Supervisor as _, TcpOrigin, deterministic, mocks,
    };
    use commonware_utils::{NZU32, NZUsize};
    use std::{
        collections::{HashMap, HashSet},
        net::{Ipv4Addr, SocketAddr},
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    struct TestConnection {
        sink: mocks::Sink,
        stream: mocks::Stream,
        origin: Option<u8>,
    }

    impl Connection for TestConnection {
        type Sink = mocks::Sink;
        type Stream = mocks::Stream;
        type Origin = u8;

        fn split(self) -> (Self::Sink, Self::Stream, ConnectionInfo<Self::Origin>) {
            (
                self.sink,
                self.stream,
                ConnectionInfo {
                    origin: self.origin,
                    transport: "test",
                },
            )
        }
    }

    fn connection(origin: Option<u8>) -> (TestConnection, (mocks::Sink, mocks::Stream)) {
        let (local_sink, remote_stream) = mocks::Channel::init();
        let (remote_sink, local_stream) = mocks::Channel::init();
        (
            TestConnection {
                sink: local_sink,
                stream: local_stream,
                origin,
            },
            (remote_sink, remote_stream),
        )
    }

    struct TcpTestConnection {
        sink: mocks::Sink,
        stream: mocks::Stream,
        origin: TcpOrigin,
    }

    impl Connection for TcpTestConnection {
        type Sink = mocks::Sink;
        type Stream = mocks::Stream;
        type Origin = TcpOrigin;

        fn split(self) -> (Self::Sink, Self::Stream, ConnectionInfo<Self::Origin>) {
            (
                self.sink,
                self.stream,
                ConnectionInfo {
                    origin: Some(self.origin),
                    transport: "tcp",
                },
            )
        }
    }

    fn tcp_connection(
        remote: SocketAddr,
    ) -> (TcpTestConnection, (mocks::Sink, mocks::Stream)) {
        let (local_sink, remote_stream) = mocks::Channel::init();
        let (remote_sink, local_stream) = mocks::Channel::init();
        (
            TcpTestConnection {
                sink: local_sink,
                stream: local_stream,
                origin: TcpOrigin { remote },
            },
            (remote_sink, remote_stream),
        )
    }

    struct TestAdmission {
        accepted: Arc<AtomicBool>,
    }

    impl InboundAdmission<Ed25519PublicKey, u8> for TestAdmission {
        type Permit = ();

        fn pre_auth(&self, info: &ConnectionInfo<u8>) -> Result<Self::Permit, Rejection> {
            if info.origin.is_none() {
                return Err(Rejection::MissingOrigin);
            }
            self.accepted.store(true, Ordering::Relaxed);
            Ok(())
        }

        async fn post_auth(
            &self,
            _permit: Self::Permit,
            _peer: &Ed25519PublicKey,
            _info: &ConnectionInfo<u8>,
        ) -> Result<(), Rejection> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestProtocol;

    impl Protocol<Ed25519PublicKey, TestConnection> for TestProtocol {
        type Reservation = ();

        async fn acceptable(
            &self,
            _peer: Ed25519PublicKey,
            _direction: &Direction,
            _info: &ConnectionInfo<u8>,
        ) -> bool {
            true
        }

        async fn reserve(
            &self,
            _peer: Ed25519PublicKey,
            _direction: &Direction,
            _info: &ConnectionInfo<u8>,
        ) -> Option<Self::Reservation> {
            Some(())
        }

        fn spawn(
            &self,
            _connection: (
                encrypted::Sender<mocks::Sink>,
                encrypted::Receiver<mocks::Stream>,
            ),
            _reservation: Self::Reservation,
        ) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct TrackingTcpProtocol {
        reserved: Arc<AtomicBool>,
    }

    impl Protocol<Ed25519PublicKey, TcpTestConnection> for TrackingTcpProtocol {
        type Reservation = ();

        async fn acceptable(
            &self,
            _peer: Ed25519PublicKey,
            _direction: &Direction,
            _info: &ConnectionInfo<TcpOrigin>,
        ) -> bool {
            true
        }

        async fn reserve(
            &self,
            _peer: Ed25519PublicKey,
            _direction: &Direction,
            _info: &ConnectionInfo<TcpOrigin>,
        ) -> Option<Self::Reservation> {
            self.reserved.store(true, Ordering::Relaxed);
            Some(())
        }

        fn spawn(
            &self,
            _connection: (
                encrypted::Sender<mocks::Sink>,
                encrypted::Receiver<mocks::Stream>,
            ),
            _reservation: Self::Reservation,
        ) -> bool {
            true
        }
    }

    struct RevalidationAdmission {
        invalidated: Arc<AtomicBool>,
    }

    impl InboundAdmission<Ed25519PublicKey, u8> for RevalidationAdmission {
        type Permit = ();

        fn pre_auth(&self, _info: &ConnectionInfo<u8>) -> Result<Self::Permit, Rejection> {
            Ok(())
        }

        async fn post_auth(
            &self,
            _permit: Self::Permit,
            _peer: &Ed25519PublicKey,
            _info: &ConnectionInfo<u8>,
        ) -> Result<(), Rejection> {
            if self.invalidated.load(Ordering::Relaxed) {
                return Err(Rejection::UnregisteredIp);
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct RevalidatingProtocol {
        invalidated: Arc<AtomicBool>,
    }

    impl Protocol<Ed25519PublicKey, TestConnection> for RevalidatingProtocol {
        type Reservation = ();

        async fn acceptable(
            &self,
            _peer: Ed25519PublicKey,
            _direction: &Direction,
            _info: &ConnectionInfo<u8>,
        ) -> bool {
            true
        }

        async fn reserve(
            &self,
            _peer: Ed25519PublicKey,
            _direction: &Direction,
            _info: &ConnectionInfo<u8>,
        ) -> Option<Self::Reservation> {
            self.invalidated.store(true, Ordering::Relaxed);
            Some(())
        }

        fn spawn(
            &self,
            _connection: (
                encrypted::Sender<mocks::Sink>,
                encrypted::Receiver<mocks::Stream>,
            ),
            _reservation: Self::Reservation,
        ) -> bool {
            true
        }
    }

    fn stream_config(signing_key: PrivateKey) -> StreamConfig<PrivateKey> {
        StreamConfig {
            signing_key,
            namespace: b"test-attachment-admission".to_vec(),
            max_message_size: 1_024,
            synchrony_bound: Duration::from_secs(10),
            max_handshake_age: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
        }
    }

    #[test]
    fn test_pre_auth_rejection_does_not_consume_attachment_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let (_actor, attachments) = Actor::new(
                context.child("attachment"),
                stream_config(PrivateKey::from_seed(0)),
                TestAdmission {
                    accepted: Arc::new(AtomicBool::new(false)),
                },
                NZUsize!(1),
                NZU32!(1),
            );
            let (rejected, _remote) = connection(None);
            assert!(matches!(
                attachments.submit_inbound(rejected),
                Err(Error::Rejected(Rejection::MissingOrigin))
            ));

            let (accepted, _remote) = connection(Some(1));
            assert!(attachments.submit_inbound(accepted).is_ok());
        });
    }

    #[test]
    fn test_tcp_peer_origin_mismatch_rejected_before_reservation() {
        deterministic::Runner::default().start(|context| async move {
            let listener_key = PrivateKey::from_seed(0);
            let peer_a = PrivateKey::from_seed(1).public_key();
            let peer_b_key = PrivateKey::from_seed(2);
            let peer_b = peer_b_key.public_key();
            let origin_a = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 1000));
            let origin_b = SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 1000));
            let (admission, updates) = TcpAdmission::with_updates(
                context.child("admission"),
                TcpAdmissionConfig {
                    allow_private_ips: false,
                    require_registered_ip: true,
                    allowed_handshake_rate_per_ip: Quota::per_second(NZU32!(100)),
                    allowed_handshake_rate_per_subnet: Quota::per_second(NZU32!(100)),
                },
            );
            updates.set(HashMap::from([
                (peer_a, HashSet::from([origin_a.ip()])),
                (peer_b, HashSet::from([origin_b.ip()])),
            ]));
            let reserved = Arc::new(AtomicBool::new(false));
            let (actor, attachments) = Actor::new(
                context.child("attachment"),
                stream_config(listener_key.clone()),
                admission,
                NZUsize!(1),
                NZU32!(1),
            );
            let _actor = actor.start(TrackingTcpProtocol {
                reserved: reserved.clone(),
            });

            let (connection, (remote_sink, remote_stream)) = tcp_connection(origin_a);
            let attach = attachments.attach_inbound(connection);
            let dial = encrypted::dial(
                context.child("dialer"),
                stream_config(peer_b_key),
                listener_key.public_key(),
                remote_stream,
                remote_sink,
            );
            let (result, _remote) = futures::join!(attach, dial);

            assert!(result.is_err());
            assert!(!reserved.load(Ordering::Relaxed));
        });
    }

    #[test]
    fn test_inbound_reservation_precedes_final_admission_check() {
        deterministic::Runner::default().start(|context| async move {
            let listener_key = PrivateKey::from_seed(0);
            let peer_key = PrivateKey::from_seed(1);
            let invalidated = Arc::new(AtomicBool::new(false));
            let (actor, attachments) = Actor::new(
                context.child("attachment"),
                stream_config(listener_key.clone()),
                RevalidationAdmission {
                    invalidated: invalidated.clone(),
                },
                NZUsize!(1),
                NZU32!(1),
            );
            let _actor = actor.start(RevalidatingProtocol { invalidated });

            let (connection, (remote_sink, remote_stream)) = connection(Some(1));
            let attach = attachments.attach_inbound(connection);
            let dial = encrypted::dial(
                context.child("dialer"),
                stream_config(peer_key),
                listener_key.public_key(),
                remote_stream,
                remote_sink,
            );
            let (result, _remote) = futures::join!(attach, dial);

            assert_eq!(
                result,
                Err(Error::Rejected(Rejection::UnregisteredIp))
            );
        });
    }

    #[test]
    fn test_pre_auth_rejection_does_not_require_handshake_permit() {
        deterministic::Runner::default().start(|context| async move {
            let accepted = Arc::new(AtomicBool::new(false));
            let (actor, attachments) = Actor::new(
                context.child("attachment"),
                stream_config(PrivateKey::from_seed(0)),
                TestAdmission {
                    accepted: accepted.clone(),
                },
                NZUsize!(2),
                NZU32!(1),
            );
            let _actor = actor.start(TestProtocol);

            let (pending, _pending_remote) = connection(Some(1));
            let _pending_result = attachments.submit_inbound(pending).unwrap();
            while !accepted.load(Ordering::Relaxed) {
                commonware_runtime::utils::reschedule().await;
            }

            let (rejected, _rejected_remote) = connection(None);
            assert!(matches!(
                attachments.submit_inbound(rejected),
                Err(Error::Rejected(Rejection::MissingOrigin))
            ));
        });
    }
}
