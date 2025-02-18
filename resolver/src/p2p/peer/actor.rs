//! Contains an Actor struct which implements the Resolver trait.

use super::{
    config::Config,
    ingress::{Mailbox, Message},
};
use crate::{
    p2p::wire::{self, peer_msg::Payload},
    Director, Key, Server,
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
use std::{collections::HashMap, marker::PhantomData};
use tracing::{debug, error, info, warn};

/// TODO
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
    fetches: HashMap<requester::ID, oneshot::Sender<Bytes>>,
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
                        Message::Fetch { key, response } => {
                            if let Err(err) = self.handle_fetch(&mut sender, key, response).await {
                                error!(?err, "handle fetch failed");
                                break;
                            }
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
                        Some(Payload::Request(request)) => self.handle_request(peer, id, request),
                        Some(Payload::Response(response)) => self.handle_response(peer, id, Some(response)),
                        None => self.handle_response(peer, id, None),
                    }
                },

                // Handle requester timeout
                _ = timeout => {
                    debug!("requester timeout");
                    self.handle_timeout_fetch(id_timeout);
                },
            }
        }
    }

    /// Handles the case where a request times out.
    fn handle_timeout_fetch(&mut self, id: requester::ID) {
        // The request must exist
        let request = self.requester.cancel(id).unwrap();
        self.requester.timeout(request);

        // Drop the oneshot sender since the request timed out
        drop(self.fetches.remove(&id));
    }

    /// Handles the case where the application wants to fetch a key from an external peer.
    async fn handle_fetch(
        &mut self,
        sender: &mut NetS,
        key: K,
        response: oneshot::Sender<Bytes>,
    ) -> Result<(), <NetS as Sender>::Error> {
        // If there are too many pending requests, drop the request
        let n = self.fetches.len();
        if n >= self.fetch_concurrent {
            warn!(?n, "too many pending fetches");
            drop(response);
            return Ok(());
        }

        // Get peer to send request to
        let Some((peer, id)) = self.requester.request(false) else {
            warn!("requester failed");
            drop(response);
            return Ok(());
        };
        let recipient = Recipients::One(peer.clone());

        // Encode message
        let msg: Bytes = wire::PeerMsg {
            id,
            payload: Some(Payload::Request(key.serialize())),
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
                    drop(response);
                    warn!(?peer, ?id, "failed to send request");
                    Ok(())
                } else {
                    // If the message was sent to someone, add the request to the map
                    self.fetches.insert(id, response);
                    Ok(())
                }
            }
            Err(err) => Err(err),
        };
    }

    /// Handles the case where the application responds to a request from an external peer.
    async fn handle_serve(
        sender: &mut NetS,
        peer: C::PublicKey,
        id: u64,
        response: Result<Bytes, oneshot::Canceled>,
    ) {
        // Encode message
        let msg: Bytes = wire::PeerMsg {
            id,
            payload: match response {
                Ok(response) => Some(Payload::Response(response.to_vec())),
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
    fn handle_request(&mut self, peer: C::PublicKey, id: u64, request: Vec<u8>) {
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
            let receiver = server.serve(key).await;
            let result = receiver.await;
            (peer, id, result)
        });
    }

    /// Handles the case where a peer returns a response to a request.
    /// The response may be a success or a failure.
    ///
    /// The id of the response may not be valid.
    fn handle_response(&mut self, peer: C::PublicKey, id: u64, response: Option<Vec<u8>>) {
        // Logging
        match response {
            Some(_) => debug!(?peer, ?id, "peer response"),
            None => warn!(?peer, ?id, "peer error response"),
        }

        // Update the requester
        // If the request is not in the map, the request may have already been canceled or
        // the peer may be malicious (responding to a request it did not receive)
        let Some(request) = self.requester.handle(&peer, id) else {
            match self.fetches.contains_key(&id) {
                true => warn!(?peer, ?id, "peer gave invalid id"),
                false => info!(?peer, ?id, "peer gave unknown id"),
            }
            return;
        };
        self.requester.resolve(request);

        // Update the oneshot sender
        // We can unwrap the value since it must exist
        let result = self.fetches.remove(&id).unwrap();

        // Either send the response to the requester or drop it
        if let Some(data) = response {
            // Send the response to the requester
            if let Err(err) = result.send(data.into()) {
                info!(?err, ?peer, ?id, "failed to respond to requester");
            }
        } else {
            // Drop the response since the request failed
            drop(result);
        }
    }
}
