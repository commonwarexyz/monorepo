use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_runtime::Spawner;
use commonware_stream::{Receiver, Sender};
use futures::{channel::mpsc, SinkExt as _, StreamExt as _};

struct Peer<P: PublicKey, S: Sender, R: Receiver> {
    // The peer's public key
    id: P,
    // Sends messages to the peer
    conn_sender: S,
    // Receives messages from the peer
    conn_receiver: R,
    // Messages received here are sent to the peer
    outbound_rx: mpsc::Receiver<Vec<u8>>,
    // Messages received from the peer are sent here
    inbound_tx: mpsc::Sender<Vec<u8>>,
}

impl<P: PublicKey, S: Sender, R: Receiver> Peer<P, S, R> {
    // fn new(
    //     id: P,
    //     conn_sender: S,
    //     conn_receiver: R,
    //     outbound_rx: mpsc::Receiver<Vec<u8>>,
    //     inbound_tx: mpsc::Sender<Vec<u8>>,
    // ) -> Self {
    //     Self {
    //         id,
    //         conn_sender,
    //         conn_receiver,
    //         outbound_rx,
    //         inbound_tx,
    //     }
    // }

    async fn run<Sp: Spawner>(mut self, spawner: Sp) -> Error {
        // Receive loop
        let mut receive_handle = spawner.clone().spawn(|_| async move {
            loop {
                let Ok(msg) = self.conn_receiver.receive().await else {
                    return Ok(());
                };

                // TODO remove to_vec / change API
                // TODO use error
                if let Err(_) = self.inbound_tx.send(msg.to_vec()).await {
                    return Err(Error::ReceiveError);
                }
            }
        });

        // Send loop
        let mut send_handle = spawner.spawn(|_| async move {
            loop {
                // Wait for messages to send
                let Some(msg) = self.outbound_rx.next().await else {
                    return Ok(());
                };
                // Send the message to the peer
                // TODO use error
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
