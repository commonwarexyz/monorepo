use std::{marker::PhantomData, u32};

use super::{
    ingress::{Mailbox, Message},
    supervisor::Supervisor,
    Config,
};
use commonware_consensus::simplex::Prover;
use commonware_cryptography::{Hasher, Scheme};
use commonware_utils::hex;
use futures::{channel::mpsc, StreamExt};
use rand::Rng;
use tracing::info;

const GENESIS: &[u8] = b"commonware is neat";

pub struct Application<R: Rng, C: Scheme, H: Hasher> {
    runtime: R,
    prover: Prover<C, H>,
    hasher: H,
    mailbox: mpsc::Receiver<Message>,

    _phantom_crypto: PhantomData<C>,
}

impl<R: Rng, C: Scheme, H: Hasher> Application<R, C, H> {
    pub fn new(runtime: R, config: Config<C, H>) -> (Self, Supervisor<C, H>, Mailbox) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                runtime,
                prover: config.prover.clone(),
                hasher: config.hasher,
                mailbox,

                _phantom_crypto: PhantomData,
            },
            Supervisor::new(config.prover, config.participants),
            Mailbox::new(sender),
        )
    }

    pub async fn run(mut self) {
        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::Genesis { response } => {
                    // Use the hash of the genesis message as the initial
                    // payload.
                    //
                    // Since we don't verify that proposed messages link
                    // to some parent, this doesn't really do anything
                    // in this example.
                    self.hasher.update(GENESIS);
                    let digest = self.hasher.finalize();
                    let _ = response.send(digest);
                }
                Message::Propose {
                    context: _,
                    response,
                } => {
                    // Generate a random message (secret to us)
                    let mut msg = vec![0; 128];
                    self.runtime.fill(&mut msg[..]);

                    // Hash the message and send it to consensus
                    self.hasher.update(&msg);
                    let digest = self.hasher.finalize();
                    let _ = response.send(digest);
                }
                Message::Verify {
                    context: _,
                    payload,
                    response,
                } => {
                    // If we linked payloads to their parent, we would verify
                    // the parent included in the payload matches the provided context.
                    let valid = H::validate(&payload);
                    let _ = response.send(valid);
                }
                Message::Broadcast { payload: _ } => {
                    // We don't broadcast our raw messages to other peers.
                    //
                    // If we were building an EVM blockchain, for example, we'd
                    // send the block to other peers here.
                }
                Message::Prepared { proof, payload } => {
                    let (view, _, _, _) = self
                        .prover
                        .deserialize_notarization(proof, u32::MAX, false)
                        .unwrap();
                    info!(view, payload = hex(&payload), "prepared")
                }
                Message::Finalized { proof, payload } => {
                    let (view, _, _, _) = self
                        .prover
                        .deserialize_finalization(proof, u32::MAX, false)
                        .unwrap();
                    info!(view, payload = hex(&payload), "finalized")
                }
            }
        }
    }
}
