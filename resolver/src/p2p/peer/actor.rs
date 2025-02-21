//! Contains an Actor struct which implements the Resolver trait.

use super::{
    config::Config,
    ingress::{Mailbox, Message},
};
use crate::{
    p2p::{
        wire::{self, peer_msg::Payload},
        Value,
    },
    Consumer, Director, Producer,
};
use bimap::BiHashMap;
use bytes::Bytes;
use commonware_cryptography::{Array, Scheme};
use commonware_macros::select;
use commonware_p2p::utils::requester::{self, Requester};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::futures::Pool as FuturesPool;
use futures::{
    channel::{mpsc, oneshot},
    future::Either,
    StreamExt,
};
use governor::clock::Clock as GClock;
use prost::Message as _;
use rand::Rng;
use std::marker::PhantomData;
use tracing::{debug, error, warn};

/// TODO
pub struct Actor<
    E: Clock + GClock + Spawner + Rng,
    C: Scheme,
    D: Director<PublicKey = C::PublicKey>,
    Key: Array,
    Con: Consumer<Key = Key, Value = Value, FailureCode = ()>,
    Pro: Producer<Key = Key, Value = Value>,
    NetS: Sender<PublicKey = C::PublicKey>,
    NetR: Receiver<PublicKey = C::PublicKey>,
> {
    runtime: E,
    mailbox: mpsc::Receiver<Message<Key>>,

    consumer: Con,
    producer: Pro,
    director: D,

    // Outgoing requests
    requester: Requester<E, C>,
    fetches: BiHashMap<requester::ID, Key>,
    fetch_concurrent: usize,

    // Incoming requests
    serves: FuturesPool<(C::PublicKey, u64, Result<Value, oneshot::Canceled>)>,
    serve_concurrent: usize,

    // Network
    _s: PhantomData<NetS>,
    _r: PhantomData<NetR>,
}

impl<
        E: Clock + GClock + Spawner + Rng,
        C: Scheme,
        D: Director<PublicKey = C::PublicKey>,
        Key: Array,
        Con: Consumer<Key = Key, Value = Value, FailureCode = ()>,
        Pro: Producer<Key = Key, Value = Value>,
        NetS: Sender<PublicKey = C::PublicKey>,
        NetR: Receiver<PublicKey = C::PublicKey>,
    > Actor<E, C, D, Key, Con, Pro, NetS, NetR>
{
    pub async fn new(runtime: E, cfg: Config<C, D, Key, Con, Pro>) -> (Self, Mailbox<Key>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        let requester = Requester::new(runtime.clone(), cfg.requester_config);
        (
            Self {
                runtime,
                consumer: cfg.consumer,
                producer: cfg.producer,
                director: cfg.director,
                mailbox: receiver,
                requester,
                fetch_concurrent: cfg.fetch_concurrent,
                serve_concurrent: cfg.serve_concurrent,
                fetches: BiHashMap::new(),
                serves: FuturesPool::new(),
                _s: PhantomData,
                _r: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    pub async fn run(&mut self, network: (NetS, NetR)) {
        let (mut sender, mut receiver) = network;
        let mut shutdown = self.runtime.stopped();

        loop {
            // Update peer list
            self.requester.reconcile(&self.director.peers());

            // Get requester timeout (if any)
            let (id_timeout, timeout) = if let Some((id_timeout, timeout)) = self.requester.next() {
                (id_timeout, Either::Left(self.runtime.sleep_until(timeout)))
            } else {
                // 0 is a valid value, but the future will never resolve
                (0, Either::Right(futures::future::pending()))
            };

            // Handle shutdown signal
            select! {
                _ = &mut shutdown => {
                    debug!("shutdown");
                    self.serves.cancel_all();
                    return;
                },

                // Handle mailbox messages
                msg = self.mailbox.next() => {
                    debug!("mailbox message");
                    let Some(msg) = msg else {
                        error!("mailbox closed");
                        return;
                    };
                    match msg {
                        Message::Fetch { key } => {
                            self.handle_fetch(&mut sender, key.clone()).await;
                        }
                        Message::Cancel { key } => {
                            self.handle_cancel(key);
                        }
                    }
                },

                // Handle completed server requests
                msg = self.serves.stream() => {
                    debug!("pending request completed");
                    let (peer, id, result) = msg;
                    Self::handle_serve(&mut sender, peer, id, result).await;
                },

                // Handle network messages
                msg = receiver.recv() => {
                    debug!("network message");
                    let (peer, msg) = match msg {
                        Ok(msg) => msg,
                        Err(err) => {
                            error!(?err, "receiver closed");
                            return;
                        }
                    };
                    let msg = match wire::PeerMsg::decode(msg){
                        Err(err) => {
                            warn!(?err, ?peer, "decode failed");
                            continue;
                        },
                        Ok(msg) => msg,
                    };
                    let id = msg.id;
                    match msg.payload {
                        Some(Payload::Request(request)) => {
                            let Ok(key) = Key::try_from(request) else {
                                warn!(?peer, ?id, "invalid request");
                                continue;
                            };
                            self.handle_request(peer, id, key);
                        },
                        Some(Payload::Response(response)) => self.handle_response(&mut sender, peer, id, Some(response)).await,
                        None => self.handle_response(&mut sender, peer, id, None).await,
                    }
                },

                // Handle requester timeout
                _ = timeout => {
                    debug!("requester timeout");
                    self.handle_timeout_fetch(&mut sender, id_timeout).await;
                },
            }
        }
    }

    /// Handles the case where a request times out.
    async fn handle_timeout_fetch(&mut self, sender: &mut NetS, id: requester::ID) {
        // The request must exist
        let request = self.requester.cancel(id).unwrap();
        self.requester.timeout(request);

        // Remove the existing request information, if any.
        // It is possible that the request was canceled before it timed out.
        let Some((_id, key)) = self.fetches.remove_by_left(&id) else {
            // If the request was previously canceled, do nothing
            return;
        };

        // Retry the request
        self.handle_fetch(sender, key).await;
    }

    /// Handles the case where the application wants to fetch a key from an external peer.
    async fn handle_fetch(&mut self, sender: &mut NetS, key: Key) {
        // If we are already fetching the key, do nothing
        if self.fetches.contains_right(&key) {
            debug!(?key, "already fetching");
            return;
        }

        // If there are too many pending requests, drop the request
        let n = self.fetches.len();
        if n >= self.fetch_concurrent {
            warn!(?n, ?key, "too many pending fetches");
            return self.consumer.failed(key, ()).await;
        }

        // Get peer to send request to
        let Some((peer, id)) = self.requester.request(false) else {
            warn!(?key, "requester failed");
            return self.consumer.failed(key, ()).await;
        };
        let recipient = Recipients::One(peer.clone());

        // Encode message
        let msg: Bytes = wire::PeerMsg {
            id,
            payload: Some(Payload::Request(key.to_vec())),
        }
        .encode_to_vec()
        .into();

        // Send message to peer
        let success = match sender.send(recipient, msg, false).await {
            // Return early on failure
            Err(err) => {
                error!(?err, ?peer, ?key, "failed to send request");
                return self.consumer.failed(key, ()).await;
            }
            Ok(sent_to) => !sent_to.is_empty(),
        };

        // If the message was not sent successfully, treat it instantly as a peer timeout
        // TODO: consider letting this timeout naturally or deal with it in a different way. Ideally we can kind of retry the request instantly again but we don't want to get stuck in an infinite loop.
        if !success {
            warn!(?peer, ?key, "failed to send request");
            // We can unwrap the value since we know it exists
            let req = self.requester.handle(&peer, id).unwrap();
            self.requester.timeout(req);
            return self.consumer.failed(key, ()).await;
        }

        // If the message was sent to someone, add the request to the map
        self.fetches.insert(id, key);
    }

    /// Handles the case where the application wants to cancel a fetch request.
    fn handle_cancel(&mut self, key: Key) {
        // Don't need to check the return value
        self.fetches.remove_by_right(&key);
    }

    /// Handles the case where the application responds to a request from an external peer.
    async fn handle_serve(
        sender: &mut NetS,
        peer: C::PublicKey,
        id: u64,
        response: Result<Value, oneshot::Canceled>,
    ) {
        // Encode message
        let msg: Bytes = wire::PeerMsg {
            id,
            payload: match response {
                Ok(response) => Some(Payload::Response(response)),
                Err(_) => None,
            },
        }
        .encode_to_vec()
        .into();

        // Send message to peer
        let recipients = Recipients::One(peer.clone());
        match sender.send(recipients, msg, false).await {
            Ok(sent_to) => {
                if sent_to.is_empty() {
                    warn!(?peer, ?id, "failed to send response");
                }
            }
            Err(err) => {
                error!(?err, ?peer, ?id, "failed to send response");
            }
        }
    }

    /// Handles the case where a peer sends a request to this peer.
    fn handle_request(&mut self, peer: C::PublicKey, id: u64, request: Key) {
        debug!(?peer, ?id, "peer request");

        // If there are too many pending requests, drop the request
        // TODO: consider sending a failure response
        let n = self.serves.len();
        if n >= self.serve_concurrent {
            warn!(?peer, ?id, ?n, "too many pending requests");
            return;
        }

        // Serve the request
        let mut producer = self.producer.clone();
        self.serves.push(async move {
            let receiver = producer.produce(request).await;
            let result = receiver.await;
            (peer, id, result)
        });
    }

    /// Handles the case where a peer returns a response to a request.
    /// The response may be a success or a failure.
    ///
    /// The id of the response may not be valid.
    async fn handle_response(
        &mut self,
        sender: &mut NetS,
        peer: C::PublicKey,
        id: u64,
        response: Option<Value>,
    ) {
        // Logging
        match response {
            Some(_) => debug!(?peer, ?id, "peer response"),
            None => warn!(?peer, ?id, "peer error response"),
        }

        // Update the requester
        let Some(request) = self.requester.handle(&peer, id) else {
            // Malicious peer used a request id not assigned to it
            warn!(?peer, ?id, "peer gave invalid id");
            return;
        };
        self.requester.resolve(request);

        let Some((_id, key)) = self.fetches.remove_by_left(&id) else {
            // If the request was canceled, do nothing
            debug!(?peer, ?id, "peer responded to canceled request");
            return;
        };

        // Either keep trying to fetch the key or deliver the response
        if let Some(data) = response {
            self.consumer.deliver(key, data).await;
        } else {
            self.handle_fetch(sender, key).await;
        }
    }
}
