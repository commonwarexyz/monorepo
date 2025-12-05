use super::{Config, Mailbox};
use crate::simplex::signing_scheme::Scheme;
use commonware_codec::Encode;
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Listener, Metrics, Sink, Spawner, Storage};
use commonware_stream::utils::codec;
use futures::{channel::mpsc, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use rand::{CryptoRng, Rng};
use tracing::{debug, warn};
use crate::simplex::types::Certificate;

/// Observer broadcaster actor that accepts TCP connections and broadcasts
/// certificates to all connected observers.
pub struct Actor<
    E: Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
    S: Scheme,
    D: Digest,
    L: Listener,
> {
    context: ContextCell<E>,
    mailbox_receiver: mpsc::Receiver<Certificate<S, D>>,

    observers: HashMap<SocketAddr, L::Sink>,
    max_observers: usize,

    _phantom: std::marker::PhantomData<L>,
}

impl<
    E: Clock + Rng + CryptoRng + Spawner + Storage + Metrics,
    S: Scheme,
    D: Digest,
    L: Listener,
> Actor<E, S, D, L>
{
    /// Creates a new observer actor and returns the actor and its mailbox.
    pub fn new(context: E, config: Config) -> (Self, Mailbox<S, D>) {
        let (mailbox_sender, mailbox_receiver) = mpsc::channel(1000);
        let actor = Self {
            context: ContextCell::new(context),
            mailbox_receiver,
            observers: HashMap::new(),
            max_observers: config.max_observers,
            _phantom: std::marker::PhantomData,
        };
        let mailbox = Mailbox::new(mailbox_sender);
        (actor, mailbox)
    }

    pub fn start(mut self, listener: L) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(listener).await,
        )
    }

    /// Runs the observer actor event loop.
    pub async fn run(mut self, mut listener: L) {
        select_loop! {
            self.context,
            on_stopped => {
                // TODO: cleanup
            },
            // Accept new observer connections
            result = listener.accept() => {
                match result {
                    Ok((address, sink, _stream)) => {
                        if self.observers.len() >= self.max_observers {
                            debug!("rejecting observer connection: max observers reached");
                            drop(sink);
                        } else {
                            debug!(?address, "accepted observer connection");
                            self.observers.insert(address, sink);
                        }
                    }
                    Err(e) => {
                        warn!(?e, "failed to accept observer connection");
                    }
                }
            },
            // Receive certificates to broadcast
            certificate = self.mailbox_receiver.next() => {
                let Some(certificate) = certificate else {
                    debug!("observer mailbox closed, shutting down");
                    break;
                };

                self.broadcast(certificate).await;
            },
        }
    }

    async fn broadcast(&mut self, msg: Certificate<S, D>) {
        let encoded = msg.encode();
        let mut to_remove = vec![];

        for (address, sink) in self.observers.iter_mut() {
            match codec::send_frame(sink, &encoded, 10 * 1024 * 1024).await {
                Ok(_) => {
                    // Successfully sent
                }
                Err(e) => {
                    debug!(?address, ?e, "failed to send to observer, disconnecting");
                    to_remove.push(*address);
                }
            }
        }

        for address in to_remove {
            let conn = self.observers.remove(&address);
        }
    }
}