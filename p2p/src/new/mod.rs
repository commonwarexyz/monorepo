use std::marker::PhantomData;

use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_runtime::{Sink, Spawner, Stream};
use commonware_stream::{public_key::Connection, Receiver, Sender};
use futures::{channel::mpsc, SinkExt as _, StreamExt as _};

enum Event<P: PublicKey> {
    PeerConnected(P),
    PeerReady(P),
    PeerDisconnected(P),
    ReceivedMessage(P, Vec<u8>),
    SentMessage(P),
}

struct Network<P: PublicKey> {
    _phantom: PhantomData<P>,
}

impl<P: PublicKey> Network<P> {
    async fn run(mut self) {
        loop {
            // Handle incoming events
            let event = self.next_event().await;
            match event {
                Event::PeerConnected(peer) => {
                    println!("Peer connected: {:?}", peer);
                }
                Event::PeerReady(peer) => {
                    println!("Peer ready: {:?}", peer);
                }
                Event::PeerDisconnected(peer) => {
                    println!("Peer disconnected: {:?}", peer);
                }
                Event::ReceivedMessage(peer, message) => {
                    println!("Received message from {:?}: {:?}", peer, message);
                }
                Event::SentMessage(peer) => {
                    println!("Sent message to {:?}", peer);
                }
            }
        }
    }

    async fn next_event(&mut self) -> Event<P> {
        todo!()
    }
}

struct Peer<P: PublicKey, S: Sender, R: Receiver> {
    // The peer's public key
    id: P,
    // Sends messages to the peer
    conn_sender: S,
    // Receives messages from the peer
    conn_receiver: R,
    outbound: mpsc::Receiver<Vec<u8>>,
    // Received messages go here
    handler: mpsc::Sender<Vec<u8>>,
}

impl<P: PublicKey, S: Sender, R: Receiver> Peer<P, S, R> {
    fn new(
        id: P,
        conn_sender: S,
        conn_receiver: R,
        outbound: mpsc::Receiver<Vec<u8>>,
        handler: mpsc::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            id,
            conn_sender,
            conn_receiver,
            outbound,
            handler,
        }
    }

    async fn run<Sp: Spawner>(mut self, spawner: Sp) -> Error {
        // Receive loop
        let mut receive_handle = spawner.clone().spawn(|_| async move {
            loop {
                let Ok(msg) = self.conn_receiver.receive().await else {
                    return Ok(());
                };

                // TODO remove to_vec / change API
                if let Err(_) = self.handler.send(msg.to_vec()).await {
                    return Err(Error::ReceiveError);
                }
            }
        });

        // Send loop
        let mut send_handle = spawner.spawn(|_| async move {
            loop {
                // Wait for messages to send
                let Some(msg) = self.outbound.next().await else {
                    return Ok(());
                };
                // Send the message to the peer
                if let Err(_) = self.conn_sender.send(&msg).await {
                    return Err(Error::SendError);
                }
            }
        });

        // If one loop completes, cancel the other
        let result = select! {
            send_result = &mut send_handle => {
                receive_handle.abort();
                send_result
            },
            receive_result = &mut receive_handle => {
                send_handle.abort();
                receive_result
            }
        };

        // Parse error
        match result {
            Ok(e) => e.unwrap_err(),
            Err(_e) => Error::TODO,
        }
    }
}

#[derive(Clone, Debug)]
enum Error {
    SendError,
    ReceiveError,
    TODO,
}
