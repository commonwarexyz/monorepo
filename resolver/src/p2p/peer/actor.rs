use super::{
    config::Config,
    fetcher::Fetcher,
    ingress::{Mailbox, Message},
};
use crate::{
    p2p::{
        wire::{self, peer_msg::Payload},
        Director, Producer,
    },
    Consumer,
};
use bytes::Bytes;
use commonware_cryptography::Scheme;
use commonware_macros::select;
use commonware_p2p::utils::requester::Requester;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Spawner};
use commonware_utils::{futures::Pool as FuturesPool, Array};
use futures::{
    channel::{mpsc, oneshot},
    future::{self, Either},
    StreamExt,
};
use governor::clock::Clock as GClock;
use prost::Message as _;
use rand::Rng;
use std::marker::PhantomData;
use tracing::{debug, error, warn};

/// Manages incoming and outgoing P2P requests, coordinating fetch and serve operations.
pub struct Actor<
    E: Clock + GClock + Spawner + Rng,
    C: Scheme,
    D: Director<PublicKey = C::PublicKey>,
    Key: Array,
    Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
    Pro: Producer<Key = Key>,
    NetS: Sender<PublicKey = C::PublicKey>,
    NetR: Receiver<PublicKey = C::PublicKey>,
> {
    runtime: E,

    /// Consumes data that is fetched from the network
    consumer: Con,

    /// Produces data for incoming requests
    producer: Pro,

    /// Manages the list of peers that can be used to fetch data
    director: D,

    /// Mailbox that makes and cancels fetch requests
    mailbox: mpsc::Receiver<Message<Key>>,

    /// Manages outgoing fetch requests
    fetcher: Fetcher<E, C, Key, NetS>,

    /// Holds futures that resolve once the `Producer` has produced the data.
    /// Once the future is resolved, the data (or an error) is sent to the peer.
    /// Has unbounded size; the number of concurrent requests should be limited
    /// by the `Producer` which may drop requests.
    serves: FuturesPool<(C::PublicKey, u64, Result<Bytes, oneshot::Canceled>)>,

    /// Phantom data for networking types
    _s: PhantomData<NetS>,
    _r: PhantomData<NetR>,
}

impl<
        E: Clock + GClock + Spawner + Rng,
        C: Scheme,
        D: Director<PublicKey = C::PublicKey>,
        Key: Array,
        Con: Consumer<Key = Key, Value = Bytes, Failure = ()>,
        Pro: Producer<Key = Key>,
        NetS: Sender<PublicKey = C::PublicKey>,
        NetR: Receiver<PublicKey = C::PublicKey>,
    > Actor<E, C, D, Key, Con, Pro, NetS, NetR>
{
    pub async fn new(runtime: E, cfg: Config<C, D, Key, Con, Pro>) -> (Self, Mailbox<Key>) {
        let (sender, receiver) = mpsc::channel(cfg.mailbox_size);
        let requester = Requester::new(runtime.clone(), cfg.requester_config);
        let fetcher = Fetcher::new(runtime.clone(), requester, cfg.fetch_retry_timeout);
        (
            Self {
                runtime,
                consumer: cfg.consumer,
                producer: cfg.producer,
                director: cfg.director,
                mailbox: receiver,
                fetcher,
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
            self.fetcher.reconcile(self.director.peers());

            // Get retry timeout (if any)
            let deadline_pending = match self.fetcher.get_pending_deadline() {
                Some(deadline) => Either::Left(self.runtime.sleep_until(deadline)),
                None => Either::Right(future::pending()),
            };

            // Get requester timeout (if any)
            let deadline_active = match self.fetcher.get_active_deadline() {
                Some(deadline) => Either::Left(self.runtime.sleep_until(deadline)),
                None => Either::Right(future::pending()),
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
                    let Some(msg) = msg else {
                        error!("mailbox closed");
                        return;
                    };
                    match msg {
                        Message::Fetch { key } => {
                            debug!(?key, "mailbox: fetch");
                            if let Err(err) = self.fetcher.fetch_new(&mut sender, key.clone()).await {
                                warn!(?err, ?key, "failed to fetch");
                                self.consumer.failed(key, ()).await;
                            }
                        }
                        Message::Cancel { key } => {
                            debug!(?key, "mailbox: cancel");
                            self.fetcher.cancel(&key);
                            self.consumer.failed(key, ()).await;
                        }
                    }
                },

                // Handle completed server requests
                msg = self.serves.stream() => {
                    let (peer, id, result) = msg;
                    Self::handle_serve(&mut sender, peer, id, result).await;
                },

                // Handle network messages
                msg = receiver.recv() => {
                    let (peer, msg) = match msg {
                        Ok(msg) => msg,
                        Err(err) => {
                            error!(?err, "receiver closed");
                            return;
                        }
                    };
                    let msg = match wire::PeerMsg::decode(msg) {
                        Ok(msg) => msg,
                        Err(err) => {
                            warn!(?err, ?peer, "decode failed");
                            continue;
                        }
                    };
                    let id = msg.id;
                    match msg.payload {
                        // Peer is requesting data
                        Some(Payload::Request(request)) => {
                            // Parse request
                            let Ok(key) = Key::try_from(request) else {
                                warn!(?peer, ?id, "peer invalid request");
                                continue;
                            };
                            self.handle_request(peer, id, key);
                        },
                        // Peer is responding to a request with a full response
                        Some(Payload::Response(response)) => {
                            debug!(?peer, ?id, "peer response: data");

                            // Get the key associate with the response, if any
                            let Some(key) = self.fetcher.pop_by_id(id, &peer, true) else {
                                continue;
                            };

                            // The peer had the data, so we can deliver it to the consumer
                            self.consumer.deliver(key, Bytes::from(response)).await;
                        },
                        // Peer is responding to a request with an error
                        None => {
                            warn!(?peer, ?id, "peer response: error");

                            // Get the key associate with the response, if any
                            let Some(key) = self.fetcher.pop_by_id(id, &peer, false) else {
                                continue;
                            };

                            // The peer did not have the data, so we need to try again
                            self.fetcher.fetch_retry(&mut sender, key).await;
                        },
                    }
                },

                // Handle pending deadline
                _ = deadline_pending => {
                    let key = self.fetcher.pop_pending();
                    debug!(?key, "retrying");
                    self.fetcher.fetch_retry(&mut sender, key).await;
                },

                // Handle active deadline
                _ = deadline_active => {
                    if let Some(key) = self.fetcher.pop_active() {
                        debug!(?key, "requester timeout");
                        self.fetcher.fetch_retry(&mut sender, key).await;
                    }
                },
            }
        }
    }

    /// Handles the case where the application responds to a request from an external peer.
    async fn handle_serve(
        sender: &mut NetS,
        peer: C::PublicKey,
        id: u64,
        response: Result<Bytes, oneshot::Canceled>,
    ) {
        // Encode message. If the response is an error, send an empty response.
        let msg = wire::PeerMsg {
            id,
            payload: response.ok().map(|bytes| Payload::Response(bytes.to_vec())),
        }
        .encode_to_vec()
        .into();

        // Send message to peer
        let result = sender.send(Recipients::One(peer.clone()), msg, false).await;

        // Log result, but do not handle errors
        match result {
            Err(err) => error!(?err, ?peer, ?id, "serve send failed"),
            Ok(to) if to.is_empty() => warn!(?peer, ?id, "serve send failed"),
            Ok(_) => debug!(?peer, ?id, "serve sent"),
        };
    }

    /// Handles the case where a peer sends a request to this peer.
    fn handle_request(&mut self, peer: C::PublicKey, id: u64, request: Key) {
        // If the peer is not allowed to request, drop the request
        if !self.director.is_peer(&peer) {
            warn!(?peer, ?id, "dropping request: peer not allowed");
            return;
        }

        // Serve the request
        debug!(?peer, ?id, "peer request");
        let mut producer = self.producer.clone();
        self.serves.push(async move {
            let receiver = producer.produce(request).await;
            let result = receiver.await;
            (peer, id, result)
        });
    }
}
