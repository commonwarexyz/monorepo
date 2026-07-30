//! Explicitly attached connections.

use crate::authenticated::{
    Mailbox,
    lookup::actors::{spawner, tracker},
};
use commonware_actor::mailbox::{self, UnreliablePolicy};
use commonware_cryptography::{PublicKey, Signer};
use commonware_macros::select_loop;
use commonware_runtime::{
    BufferPooler, Clock, Connection, ConnectionInfo, ContextCell, Handle, Metrics, PlatformSend,
    PlatformSync, Scheduler, spawn_cell,
};
use commonware_stream::encrypted::{self, Config as StreamConfig};
use commonware_utils::channel::oneshot;
use rand_core::CryptoRng;
use std::{collections::VecDeque, future::Future, sync::Arc};
use thiserror::Error;
use tracing::debug;

/// A connection was rejected by the application's admission policy.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("connection rejected")]
pub struct Rejected;

/// Failure to attach a connection.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum Error {
    /// The attachment actor is no longer available.
    #[error("attachment actor unavailable")]
    Unavailable,
    /// The application's admission policy rejected the connection.
    #[error("connection rejected")]
    Rejected,
    /// The encrypted handshake failed.
    #[error("encrypted handshake failed")]
    Handshake,
    /// The peer could not be reserved.
    #[error("peer unavailable")]
    PeerUnavailable,
    /// The peer spawner rejected the connection due to backpressure or shutdown.
    #[error("peer spawner unavailable")]
    SpawnerUnavailable,
}

/// Authorizes inbound connections before and after peer authentication.
///
/// The pre-authentication permit can reserve application resources or carry authorization state
/// across the handshake. It is dropped without calling `post_auth` if the handshake fails.
pub trait PeerAdmission<P: PublicKey, O>: PlatformSend + PlatformSync + 'static {
    /// State retained while the encrypted handshake is in progress.
    type Permit: PlatformSend + 'static;

    /// Decide whether to begin authenticating a transport connection.
    fn pre_auth(&self, info: &ConnectionInfo<O>) -> Result<Self::Permit, Rejected>;

    /// Decide whether the authenticated peer may use the transport connection.
    fn post_auth(
        &self,
        permit: Self::Permit,
        peer: &P,
        info: &ConnectionInfo<O>,
    ) -> impl Future<Output = Result<(), Rejected>> + PlatformSend;
}

enum Message<N: Connection, P: PublicKey> {
    Outbound {
        expected_peer: P,
        connection: N,
        responder: oneshot::Sender<Result<(), Error>>,
    },
    Inbound {
        connection: N,
        responder: oneshot::Sender<Result<(), Error>>,
    },
}

impl<N: Connection, P: PublicKey> UnreliablePolicy for Message<N, P> {
    type Overflow = VecDeque<Self>;

    fn handle(_overflow: &mut Self::Overflow, _message: Self) -> bool {
        false
    }
}

/// Handle for attaching transport connections to an authenticated network.
pub struct Attachments<N: Connection, P: PublicKey> {
    mailbox: Mailbox<Message<N, P>>,
}

impl<N: Connection, P: PublicKey> Clone for Attachments<N, P> {
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
        }
    }
}

impl<N: Connection, P: PublicKey> Attachments<N, P> {
    /// Attach an outbound connection that is expected to authenticate as `expected_peer`.
    pub async fn attach_outbound(&self, expected_peer: P, connection: N) -> Result<(), Error> {
        let (responder, receiver) = oneshot::channel();
        if !self
            .mailbox
            .0
            .enqueue(Message::Outbound {
                expected_peer,
                connection,
                responder,
            })
            .accepted()
        {
            return Err(Error::Unavailable);
        }
        receiver.await.unwrap_or(Err(Error::Unavailable))
    }

    /// Attach an inbound connection whose peer identity will be learned during authentication.
    pub async fn attach_inbound(&self, connection: N) -> Result<(), Error> {
        let (responder, receiver) = oneshot::channel();
        if !self
            .mailbox
            .0
            .enqueue(Message::Inbound {
                connection,
                responder,
            })
            .accepted()
        {
            return Err(Error::Unavailable);
        }
        receiver.await.unwrap_or(Err(Error::Unavailable))
    }
}

pub struct Actor<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: PeerAdmission<C::PublicKey, N::Origin>,
> {
    context: ContextCell<E>,
    stream_cfg: StreamConfig<C>,
    admission: Arc<A>,
    receiver: mailbox::UnreliableReceiver<Message<N, C::PublicKey>>,
}

impl<
    E: Scheduler + BufferPooler + Clock + CryptoRng + Metrics,
    C: Signer,
    N: Connection,
    A: PeerAdmission<C::PublicKey, N::Origin>,
> Actor<E, C, N, A>
{
    pub fn new(
        context: E,
        stream_cfg: StreamConfig<C>,
        admission: A,
        mailbox_size: std::num::NonZeroUsize,
    ) -> (Self, Attachments<N, C::PublicKey>) {
        let (mailbox, receiver) = Mailbox::new(context.child("mailbox"), mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                stream_cfg,
                admission: Arc::new(admission),
                receiver,
            },
            Attachments { mailbox },
        )
    }

    pub fn start(
        mut self,
        tracker: tracker::Mailbox<C::PublicKey>,
        spawner: Mailbox<spawner::Message<N::Sink, N::Stream, C::PublicKey>>,
    ) -> Handle<()> {
        spawn_cell!(self.context, self.run(tracker, spawner))
    }

    async fn run(
        mut self,
        tracker: tracker::Mailbox<C::PublicKey>,
        spawner: Mailbox<spawner::Message<N::Sink, N::Stream, C::PublicKey>>,
    ) {
        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping attachment actor");
            },
            Some(message) = self.receiver.recv() else {
                debug!("attachment mailbox closed");
                break;
            } => {
                let stream_cfg = self.stream_cfg.clone();
                let admission = self.admission.clone();
                let tracker = tracker.clone();
                let spawner = spawner.clone();
                self.context.child("handshake").spawn(move |context| async move {
                    let (result, responder) = match message {
                        Message::Outbound { expected_peer, connection, responder } => {
                            (
                                Self::attach_outbound(
                                    context,
                                    stream_cfg,
                                    expected_peer,
                                    connection,
                                    tracker,
                                    spawner,
                                ).await,
                                responder,
                            )
                        }
                        Message::Inbound { connection, responder } => {
                            (
                                Self::attach_inbound(
                                    context,
                                    stream_cfg,
                                    admission,
                                    connection,
                                    tracker,
                                    spawner,
                                ).await,
                                responder,
                            )
                        }
                    };
                    let _ = responder.send(result);
                });
            },
        }
    }

    async fn attach_outbound(
        context: E,
        stream_cfg: StreamConfig<C>,
        expected_peer: C::PublicKey,
        connection: N,
        tracker: tracker::Mailbox<C::PublicKey>,
        mut spawner: Mailbox<spawner::Message<N::Sink, N::Stream, C::PublicKey>>,
    ) -> Result<(), Error> {
        let (sink, stream, _) = connection.split();
        let encrypted = encrypted::dial(context, stream_cfg, expected_peer.clone(), stream, sink)
            .await
            .map_err(|_| Error::Handshake)?;
        let reservation = tracker
            .attach(expected_peer, false)
            .await
            .ok_or(Error::PeerUnavailable)?;
        if spawner.spawn(encrypted, reservation).accepted() {
            Ok(())
        } else {
            Err(Error::SpawnerUnavailable)
        }
    }

    async fn attach_inbound(
        context: E,
        stream_cfg: StreamConfig<C>,
        admission: Arc<A>,
        connection: N,
        tracker: tracker::Mailbox<C::PublicKey>,
        mut spawner: Mailbox<spawner::Message<N::Sink, N::Stream, C::PublicKey>>,
    ) -> Result<(), Error> {
        let (sink, stream, info) = connection.split();
        let permit = admission.pre_auth(&info).map_err(|_| Error::Rejected)?;
        let (peer, sender, receiver) =
            encrypted::listen(context, |_| async { true }, stream_cfg, stream, sink)
                .await
                .map_err(|_| Error::Handshake)?;
        admission
            .post_auth(permit, &peer, &info)
            .await
            .map_err(|_| Error::Rejected)?;
        let reservation = tracker
            .attach(peer, true)
            .await
            .ok_or(Error::PeerUnavailable)?;
        if spawner.spawn((sender, receiver), reservation).accepted() {
            Ok(())
        } else {
            Err(Error::SpawnerUnavailable)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::lookup::actors::tracker;
    use commonware_actor::mailbox;
    use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
    use commonware_runtime::{ConnectionInfo, Runner as _, Supervisor as _, deterministic, mocks};
    use commonware_utils::{NZUsize, sync::Mutex};
    use std::{sync::Arc, time::Duration};

    const NAMESPACE: &[u8] = b"test_lookup_attachments";

    struct TestConnection {
        sink: mocks::Sink,
        stream: mocks::Stream,
        origin: u64,
    }

    impl Connection for TestConnection {
        type Sink = mocks::Sink;
        type Stream = mocks::Stream;
        type Origin = u64;

        fn split(self) -> (Self::Sink, Self::Stream, ConnectionInfo<Self::Origin>) {
            (
                self.sink,
                self.stream,
                ConnectionInfo {
                    origin: Some(self.origin),
                    transport: "test",
                },
            )
        }
    }

    fn connections() -> (TestConnection, TestConnection) {
        let (left_sink, right_stream) = mocks::Channel::init();
        let (right_sink, left_stream) = mocks::Channel::init();
        (
            TestConnection {
                sink: left_sink,
                stream: left_stream,
                origin: 1,
            },
            TestConnection {
                sink: right_sink,
                stream: right_stream,
                origin: 2,
            },
        )
    }

    fn stream_config(key: PrivateKey) -> StreamConfig<PrivateKey> {
        StreamConfig {
            signing_key: key,
            namespace: NAMESPACE.to_vec(),
            max_message_size: 64 * 1024,
            synchrony_bound: Duration::from_secs(5),
            max_handshake_age: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(5),
        }
    }

    struct Allow {
        authenticated: Arc<Mutex<Vec<PublicKey>>>,
    }

    impl PeerAdmission<PublicKey, u64> for Allow {
        type Permit = u64;

        fn pre_auth(&self, info: &ConnectionInfo<u64>) -> Result<Self::Permit, Rejected> {
            info.origin.ok_or(Rejected)
        }

        async fn post_auth(
            &self,
            permit: Self::Permit,
            peer: &PublicKey,
            info: &ConnectionInfo<u64>,
        ) -> Result<(), Rejected> {
            if info.origin != Some(permit) {
                return Err(Rejected);
            }
            self.authenticated.lock().push(peer.clone());
            Ok(())
        }
    }

    fn tracker(
        context: deterministic::Context,
        key: PrivateKey,
    ) -> (
        tracker::Actor<deterministic::Context, PrivateKey>,
        tracker::Mailbox<PublicKey>,
    ) {
        let (listener, _updates) = crate::authenticated::lookup::actors::listener::Mailbox::new();
        let (actor, mailbox, _oracle) = tracker::Actor::new(
            context,
            tracker::Config {
                crypto: key,
                mailbox_size: NZUsize!(16),
                tracked_peer_sets: NZUsize!(1),
                peer_connection_cooldown: Duration::ZERO,
                allow_private_ips: true,
                allow_dns: true,
                bypass_ip_check: true,
                listener,
                block_duration: Duration::from_secs(1),
            },
        );
        (actor, mailbox)
    }

    #[test]
    fn outbound_rejects_unexpected_key() {
        deterministic::Runner::default().start(|context| async move {
            let local = PrivateKey::from_seed(1);
            let remote = PrivateKey::from_seed(2);
            let unexpected = PrivateKey::from_seed(3).public_key();
            let (local_connection, remote_connection) = connections();
            let admission = Allow {
                authenticated: Arc::new(Mutex::new(Vec::new())),
            };
            let (actor, attachments) = Actor::new(
                context.child("attachments"),
                stream_config(local),
                admission,
                NZUsize!(16),
            );
            let (_tracker_sender, tracker_receiver) =
                mailbox::new(context.child("tracker_mailbox"), NZUsize!(1));
            let tracker = tracker::Mailbox::new(_tracker_sender);
            let (spawner, _spawner_receiver) =
                crate::authenticated::Mailbox::new(context.child("spawner_mailbox"), NZUsize!(1));
            let _actor = actor.start(tracker, spawner);

            let remote_task = context.child("remote").spawn(move |context| async move {
                let (sink, stream, _) = remote_connection.split();
                encrypted::listen(
                    context,
                    |_| async { true },
                    stream_config(remote),
                    stream,
                    sink,
                )
                .await
            });
            let result = attachments
                .attach_outbound(unexpected, local_connection)
                .await;
            assert_eq!(result, Err(Error::Handshake));
            assert!(remote_task.await.unwrap().is_err());
            drop(tracker_receiver);
        });
    }

    #[test]
    fn inbound_dynamically_authorizes_unknown_peer() {
        deterministic::Runner::default().start(|context| async move {
            let local = PrivateKey::from_seed(11);
            let remote = PrivateKey::from_seed(12);
            let remote_public = remote.public_key();
            let authenticated = Arc::new(Mutex::new(Vec::new()));
            let admission = Allow {
                authenticated: authenticated.clone(),
            };
            let (local_connection, remote_connection) = connections();
            let (tracker_actor, tracker) = tracker(context.child("tracker"), local.clone());
            let _tracker = tracker_actor.start();
            let (actor, attachments) = Actor::new(
                context.child("attachments"),
                stream_config(local.clone()),
                admission,
                NZUsize!(16),
            );
            let (spawner, mut spawned) =
                crate::authenticated::Mailbox::new(context.child("spawner_mailbox"), NZUsize!(16));
            let _actor = actor.start(tracker, spawner);

            let dialer = context.child("remote").spawn(move |context| async move {
                let (sink, stream, _) = remote_connection.split();
                encrypted::dial(
                    context,
                    stream_config(remote),
                    local.public_key(),
                    stream,
                    sink,
                )
                .await
            });
            assert_eq!(attachments.attach_inbound(local_connection).await, Ok(()));
            let remote_connection = dialer.await.unwrap().expect("remote handshake failed");
            let spawner::Message::Spawn {
                peer,
                connection,
                reservation: _reservation,
            } = spawned.recv().await.expect("connection was not spawned");
            assert_eq!(peer, remote_public);
            assert_eq!(authenticated.lock().as_slice(), &[remote_public]);
            drop(remote_connection);
            drop(connection);
        });
    }
}
