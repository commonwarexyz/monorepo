//! Contains an Actor struct which implements the Resolver trait.

use std::{collections::HashMap, marker::PhantomData};

use crate::{p2p::wire, Director, Key, Server};

use super::{
    config::Config,
    ingress::{Mailbox, Message},
};
use bytes::Bytes;
use commonware_cryptography::Scheme;
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
use tracing::{debug, error, warn};

pub struct Actor<
    E: Clock + GClock + Spawner + Rng,
    C: Scheme,
    K: Key,
    A: Server<Key = K>,
    D: Director<PublicKey = C::PublicKey>,
    NetS: Sender<PublicKey = C::PublicKey>,
    NetR: Receiver<PublicKey = C::PublicKey>,
> {
    runtime: E,
    mailbox: mpsc::Receiver<Message<K>>,
    requester: Requester<E, C>,
    server: A,
    director: D,
    fetch_concurrent: usize,
    serve_concurrent: usize,
    fetches: HashMap<requester::ID, (C::PublicKey, oneshot::Sender<Bytes>)>,
    serves: FuturesPool<(C::PublicKey, u64, Result<Bytes, oneshot::Canceled>)>,

    _sender: PhantomData<NetS>,
    _receiver: PhantomData<NetR>,
}

impl<
        E: Clock + GClock + Spawner + Rng,
        C: Scheme,
        K: Key,
        A: Server<Key = K>,
        D: Director<PublicKey = C::PublicKey>,
        NetS: Sender<PublicKey = C::PublicKey>,
        NetR: Receiver<PublicKey = C::PublicKey>,
    > Actor<E, C, K, A, D, NetS, NetR>
{
    pub async fn new(runtime: E, cfg: Config<C, K, A, D>) -> (Self, Mailbox<K>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        let requester = Requester::new(runtime.clone(), cfg.requester_config);
        (
            Self {
                runtime,
                server: cfg.server,
                director: cfg.director,
                mailbox: receiver,
                requester,
                fetch_concurrent: cfg.fetch_concurrent,
                serve_concurrent: cfg.serve_concurrent,
                fetches: HashMap::new(),
                serves: FuturesPool::new(),
                _sender: PhantomData,
                _receiver: PhantomData,
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
                (0, Either::Right(futures::future::pending()))
            };

            // Handle shutdown signal
            select! {
                _ = &mut shutdown => {
                    debug!("shutdown");
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
                        Message::Fetch { key, response } => {
                            match self.handle_self_fetch(&mut sender, key, response).await {
                                Ok(true) => {},
                                Ok(false) => {
                                    warn!("handle fetch failed");
                                    continue;
                                },
                                Err(err) => {
                                    error!(?err, "handle fetch failed");
                                    break;
                                },
                            }
                        }
                    }
                },

                // Handle completed server requests
                msg = self.serves.stream() => {
                    debug!("pending request completed");
                    let (peer, id, result) = msg;
                    Self::handle_self_serve(&mut sender, peer, id, result).await;
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
                            warn!(?err, ?peer, "dec");
                            continue;
                        },
                        Ok(msg) => msg,
                    };
                    let id = msg.id;
                    match msg.payload {
                        Some(wire::peer_msg::Payload::Request(request)) => {
                            self.handle_peer_request(peer, id, request);
                        },
                        Some(wire::peer_msg::Payload::Response(response)) => {
                            self.handle_peer_response(peer, id, response);
                        },
                        Some(wire::peer_msg::Payload::ErrorCode(code)) => {
                            self.handle_peer_error(peer, id, code);
                        },
                        None => {
                            warn!(?peer, ?id, "no payload");
                            continue;
                        },
                    };
                },

                // Handle requester timeout
                _ = timeout => {
                    debug!("requester timeout");
                    let Some(req) = self.requester.cancel(id_timeout) else {
                        error!("requester timeout not found");
                        continue;
                    };
                    self.requester.timeout(req);
                },
            }
        }
    }

    /// Handles the case where the application wants to fetch a key from an external peer.
    async fn handle_self_fetch(
        &mut self,
        sender: &mut NetS,
        key: K,
        response: oneshot::Sender<Bytes>,
    ) -> Result<bool, <NetS as Sender>::Error> {
        // If there are too many pending requests, drop the request
        let n = self.fetches.len();
        if n >= self.fetch_concurrent {
            warn!(?n, "too many pending fetches");
            drop(response);
            return Ok(false);
        }

        // Get peer to send request to
        let Some((peer, id)) = self.requester.request(false) else {
            error!("requester failed");
            drop(response);
            return Ok(false);
        };
        let recipient = Recipients::One(peer.clone());

        // Encode message
        let msg: Bytes = wire::PeerMsg {
            id,
            payload: Some(wire::peer_msg::Payload::Request(key.serialize())),
        }
        .encode_to_vec()
        .into();

        // Send message to peer
        return match sender.send(recipient, msg, false).await {
            Ok(sent_to) => {
                if sent_to.is_empty() {
                    // If the message was not sent to anyone, timeout the request
                    // We can unwrap the value since we know it exists
                    let req = self.requester.handle(&peer, id).unwrap();
                    self.requester.timeout(req);
                    Ok(false)
                } else {
                    // If the message was sent to someone, add the request to the map
                    self.fetches.insert(id, (peer, response));
                    Ok(true)
                }
            }
            Err(err) => Err(err),
        };
    }

    /// Handles the case where the application responds to a request from an external peer.
    async fn handle_self_serve(
        sender: &mut NetS,
        peer: C::PublicKey,
        id: u64,
        response: Result<Bytes, oneshot::Canceled>,
    ) {
        // Encode message
        let msg: Bytes = wire::PeerMsg {
            id,
            payload: Some(match response {
                Ok(response) => wire::peer_msg::Payload::Response(response.to_vec()),
                Err(_) => wire::peer_msg::Payload::ErrorCode(0),
            }),
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
    fn handle_peer_request(&mut self, peer: C::PublicKey, id: u64, request: Vec<u8>) {
        debug!(?peer, ?id, "peer request");

        // If there are too many pending requests, drop the request
        let n = self.serves.len();
        if n >= self.serve_concurrent {
            warn!(?peer, ?id, ?n, "too many pending requests");
            return;
        }

        // Get the key from the request
        let Some(key) = K::deserialize(&request[..]) else {
            warn!(?peer, ?id, ?request, "peer gave invalid request");
            return;
        };

        // Serve the request
        let mut server = self.server.clone();
        self.serves.push(async move {
            let result = server.serve(key).await;
            let result = result.await;
            (peer, id, result)
        });
    }

    /// Handles the case where a peer returns a response to a request.
    ///
    /// The id of the response may not be valid.
    fn handle_peer_response(&mut self, peer: C::PublicKey, id: u64, response: Vec<u8>) {
        debug!(?peer, ?id, "peer response");

        // If the ID is not in the map, the request may have already been cancelled
        let Some((expected, _)) = self.fetches.get(&id) else {
            return;
        };

        // If the peer is not as-expected, it means that the peer is malicious
        if expected != &peer {
            warn!(?peer, ?expected, ?id, "peer gave invalid id");
            return;
        }

        // Update the requester
        let req = self.requester.handle(&peer, id).unwrap();
        self.requester.resolve(req);

        // Send the response to the requester
        // We can unwrap the value since we know it exists
        let (_, result) = self.fetches.remove(&id).unwrap();
        result.send(response.into()).unwrap();
    }

    /// Handles the case where a peer returns an error response to a request.
    ///
    /// The id of the error response may not be valid.
    fn handle_peer_error(&mut self, peer: C::PublicKey, id: u64, error_code: u64) {
        warn!(?error_code, ?peer, ?id, "peer error_code");

        // If the ID is not in the map, the request may have already been cancelled
        let Some((expected, _)) = self.fetches.get(&id) else {
            return;
        };

        // If the peer is not as-expected, it means that the peer is malicious
        if expected != &peer {
            warn!(?peer, ?expected, ?id, "peer gave invalid id");
            return;
        }

        // Update the requester
        let req = self.requester.handle(&peer, id).unwrap();
        self.requester.resolve(req);

        // Drop the response since the request failed
        // We can unwrap the value since we know it exists
        let (_, result) = self.fetches.remove(&id).unwrap();
        drop(result);
    }
}
