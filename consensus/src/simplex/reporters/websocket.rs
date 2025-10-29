//! WebSocket reporter for real-time consensus activity streaming.
//!
//! This module provides a WebSocket-based reporter that exposes all consensus
//! activities as binary over the network. Clients connect via WebSocket and receive
//! a stream of encoded events including votes, certificates, and Byzantine fault evidence.
//!
//! This reporter is useful for:
//! - Building monitoring dashboards and visualizations
//! - Real-time consensus state inspection for debugging
//! - Integration with external analytics systems
//! - Creating audit logs of consensus activity
//!
//! # Runtime Requirements
//!
//! **IMPORTANT**: This reporter requires a tokio runtime. The context passed to
//! [`WebSocketReporter::new`] must be a tokio-based runtime (e.g., [`commonware_runtime::tokio::Runner`]).
//! It will not work with other runtime implementations like the deterministic runtime.
//!
//! # Connection Protocol
//!
//! When a client connects, they first receive a [`Context`] message containing:
//! - List of participant public keys (as encoded bytes)
//! - This node's validator index (or `None` if observer)
//!
//! After the initial context, clients receive a continuous stream of [`crate::simplex::types::Activity`]
//! messages as consensus progresses.
//!
//! # Lagging Behavior
//!
//! The broadcast channel has a fixed capacity of messages. If a client cannot keep up
//! with the stream it will lag behind and skip messages, but it will continue receiving
//! new activities.

use crate::{
    simplex::{signing_scheme::Scheme, types::Activity},
    Reporter,
};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{Digest, PublicKey};
use commonware_macros::select;
use commonware_runtime::{spawn_cell, ContextCell, Metrics, Spawner};
use commonware_utils::set::Ordered;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::broadcast,
};
use tokio_tungstenite::{
    tungstenite::{Message as WsMessage, Result as WsResult},
    WebSocketStream,
};
use tracing::debug;

/// The capacity of the broadcast channel used to stream activities to clients.
const BROADCAST_CHANNEL_CAPACITY: usize = 1024;

/// Context information sent to clients when they first connect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context<P: PublicKey> {
    /// Participants in the committee.
    pub participants: Ordered<P>,
    /// The index of "self" in the participant set, if available (`None` if observer).
    pub me: Option<u32>,
}

impl<P: PublicKey> Write for Context<P> {
    fn write(&self, writer: &mut impl BufMut) {
        self.participants.write(writer);
        self.me.write(writer);
    }
}

impl<P: PublicKey> Read for Context<P> {
    type Cfg = <Ordered<P> as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Context {
            participants: Ordered::read_cfg(reader, cfg)?,
            me: Option::read(reader)?,
        })
    }
}

impl<P: PublicKey> EncodeSize for Context<P> {
    fn encode_size(&self) -> usize {
        self.participants.encode_size() + self.me.encode_size()
    }
}

/// Messages sent over the WebSocket connection.
#[derive(Clone, Debug)]
pub enum Message<S: Scheme, D: Digest> {
    /// Initial context message with participant information.
    Context(Context<S::PublicKey>),
    /// Consensus activity event.
    Activity(Activity<S, D>),
}

impl<S: Scheme, D: Digest> Write for Message<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Message::Context(context) => {
                0u8.write(writer);
                context.write(writer);
            }
            Message::Activity(activity) => {
                1u8.write(writer);
                activity.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> Read for Message<S, D> {
    type Cfg = (
        <Context<S::PublicKey> as Read>::Cfg,
        <Activity<S, D> as Read>::Cfg,
    );

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => Ok(Message::Context(Context::read_cfg(reader, &cfg.0)?)),
            1 => Ok(Message::Activity(Activity::read_cfg(reader, &cfg.1)?)),
            _ => Err(Error::Invalid(
                "consensus::simplex::reporter::websocket::Message",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Message<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Message::Context(context) => context.encode_size(),
            Message::Activity(activity) => activity.encode_size(),
        }
    }
}

/// WebSocket server that accepts connections and streams activities.
///
/// This is a consumable actor that binds to a socket address and accepts
/// incoming WebSocket connections. Each connected client receives:
/// 1. An initial [`Context`] message with participant information
/// 2. A continuous stream of [`Activity`] messages
///
/// # Client Handling
///
/// Each client connection is handled in a separate spawned task. If a client
/// lags behind the broadcast stream, they will skip messages but continue
/// receiving new activities.
pub struct WebSocketServer<E, S, D>
where
    E: Spawner + Metrics,
    S: Scheme,
    D: Digest,
{
    /// Runtime context for spawning client handlers
    context: ContextCell<E>,
    /// Participants in the committee.
    participants: Ordered<S::PublicKey>,
    /// The index of "self" in the participant set, if available (`None` if observer).
    me: Option<u32>,
    /// Receiver for activity broadcasts
    receiver: broadcast::Receiver<Activity<S, D>>,
}

impl<E, S, D> WebSocketServer<E, S, D>
where
    E: Spawner + Metrics,
    S: Scheme,
    D: Digest,
{
    /// Starts the WebSocket server on the specified address.
    ///
    /// This method consumes the server and spawns the server loop as a background task.
    /// The server will accept connections on the provided address and run until the
    /// process exits.
    ///
    /// # Panics
    ///
    /// Panics if the server cannot bind to the specified address.
    pub fn start(mut self, addr: SocketAddr) {
        spawn_cell!(self.context, self.run(addr).await);
    }

    /// Main server loop.
    async fn run(self, addr: SocketAddr) {
        // Bind TCP listener
        let listener = TcpListener::bind(addr)
            .await
            .expect("Failed to bind WebSocket server");

        // Accept connections
        while let Ok((stream, peer)) = listener.accept().await {
            let receiver = self.receiver.resubscribe();
            let context = Context {
                participants: self.participants.clone(),
                me: self.me,
            };

            // Spawn handler for this connection
            self.context
                .with_label(&format!("client-{peer}"))
                .spawn(async move |_| {
                    if let Ok(ws) = tokio_tungstenite::accept_async(stream).await {
                        let _ = Self::handle_client(peer, ws, receiver, context).await;
                    }
                });
        }
    }

    /// Handles communication with a connected client.
    async fn handle_client(
        peer: SocketAddr,
        mut ws: WebSocketStream<TcpStream>,
        mut activity: broadcast::Receiver<Activity<S, D>>,
        context: Context<S::PublicKey>,
    ) -> WsResult<()> {
        // Send initial context message
        let msg = Message::<S, D>::Context(context);
        ws.send(WsMessage::Binary(msg.encode().freeze())).await?;

        loop {
            select! {
                // Process any websocket messages from the client
                msg = ws.next() => {
                    match msg {
                        Some(msg) => {
                            if msg?.is_close() {
                                break;
                            }
                        },
                        None => {
                            break;
                        }
                    }
                },
                // Broadcast activities to client
                result = activity.recv() => {
                    match result {
                        Ok(activity) => {
                            // Create activity message
                            let msg = Message::Activity(activity);

                            // Send to client as binary message
                            ws.send(WsMessage::Binary(msg.encode().freeze())).await?;
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            debug!("Client {peer} lagged behind, skipped {skipped} messages");
                            // Continue streaming
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// WebSocket reporter that streams consensus activities.
///
/// This reporter wraps an inner reporter and additionally broadcasts all activities to
/// connected WebSocket clients.
#[derive(Clone)]
pub struct WebSocketReporter<S, D, R>
where
    S: Scheme,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
{
    /// Inner reporter to forward activities to
    inner: R,
    /// Broadcast sender to all the server clients
    broadcast: broadcast::Sender<Activity<S, D>>,
}

impl<S, D, R> WebSocketReporter<S, D, R>
where
    S: Scheme,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
{
    /// Creates a new WebSocket reporter and server.
    ///
    /// Returns a tuple of (reporter, server). The reporter implements the `Reporter`
    /// trait and can be passed to the consensus engine. The server is a consumable
    /// actor that must be started separately.
    ///
    /// # Parameters
    ///
    /// - `context`: Runtime context for spawning the server and client handlers (must be tokio-based)
    /// - `participants`: Participants in the committee
    /// - `me`: The index of "self" in the participant set, if available (`None` if observer)
    /// - `inner`: Inner reporter to forward activities to
    pub fn new<E>(
        context: E,
        participants: Ordered<S::PublicKey>,
        me: Option<u32>,
        inner: R,
    ) -> (Self, WebSocketServer<E, S, D>)
    where
        E: Spawner + Metrics,
    {
        let (broadcast, receiver) = broadcast::channel(BROADCAST_CHANNEL_CAPACITY);

        // Create reporter
        let reporter = Self { inner, broadcast };

        // Create server
        let server = WebSocketServer {
            context: ContextCell::new(context),
            participants,
            me,
            receiver,
        };

        (reporter, server)
    }
}

impl<S, D, R> Reporter for WebSocketReporter<S, D, R>
where
    S: Scheme,
    D: Digest,
    R: Reporter<Activity = Activity<S, D>>,
{
    type Activity = Activity<S, D>;

    async fn report(&mut self, activity: Self::Activity) {
        // Forward to inner reporter first
        self.inner.report(activity.clone()).await;

        // Then broadcast to all connected WebSocket clients
        // Ignore errors if no receivers are connected
        let _ = self.broadcast.send(activity);
    }
}
