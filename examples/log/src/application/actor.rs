use std::marker::PhantomData;

use super::{
    ingress::{Mailbox, Message},
    supervisor::Supervisor,
    Config,
};
use commonware_cryptography::{Hasher, Scheme};
use commonware_utils::hex;
use futures::{channel::mpsc, StreamExt};
use rand::Rng;
use tracing::debug;

const GENESIS: &[u8] = b"commonware is neat";

pub struct Application<R: Rng, C: Scheme, H: Hasher> {
    runtime: R,
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
                    self.hasher.update(GENESIS);
                    let digest = self.hasher.finalize();
                    let _ = response.send(digest);
                }
                Message::Propose { context, response } => {
                    let msg: [u8; 32] = self.runtime.gen();
                    self.hasher.update(&msg);
                    let digest = self.hasher.finalize();
                    let _ = response.send(digest);
                }
                Message::Verify {
                    context,
                    payload,
                    response,
                } => {
                    let valid = H::validate(&payload);
                    let _ = response.send(valid);
                }
                Message::Broadcast { payload } => {
                    // We don't broadcast our raw messages
                }
                Message::Notarized { proof, payload } => {
                    debug!(payload = hex(&payload), "notarized")
                }
                Message::Finalized { proof, payload } => {
                    debug!(payload = hex(&payload), "finalized")
                }
            }
        }
    }
}
