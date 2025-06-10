use std::marker::PhantomData;

use commonware_cryptography::PublicKey;

mod peer;

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
