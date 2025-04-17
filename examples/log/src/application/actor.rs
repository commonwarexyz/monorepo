use std::marker::PhantomData;

use super::{
    ingress::{Mailbox, Message},
    supervisor::Supervisor,
    Config,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Handle, Spawner};
use commonware_utils::{hex, Array};
use futures::{channel::mpsc, StreamExt};
use rand::Rng;
use tracing::info;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Application actor.
pub struct Application<R: Rng + Spawner, P: Array, S: Array, H: Hasher> {
    context: R,
    hasher: H,
    mailbox: mpsc::Receiver<Message<H::Digest>>,

    _phantom_p: PhantomData<P>,
    _phantom_s: PhantomData<S>,
}

impl<R: Rng + Spawner, P: Array, S: Array, H: Hasher> Application<R, P, S, H> {
    /// Create a new application actor.
    #[allow(clippy::type_complexity)]
    pub fn new(
        context: R,
        config: Config<P, H>,
    ) -> (Self, Supervisor<P, S, H::Digest>, Mailbox<H::Digest>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                hasher: config.hasher,
                mailbox,
                _phantom_s: PhantomData,
                _phantom_p: PhantomData,
            },
            Supervisor::new(config.participants),
            Mailbox::new(sender),
        )
    }

    /// Run the application actor.
    pub fn start(mut self) -> Handle<()> {
        self.context.spawn_ref()(self.run())
    }

    async fn run(mut self) {
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
                Message::Propose { response } => {
                    // Generate a random message (secret to us)
                    let mut msg = vec![0; 16];
                    self.context.fill(&mut msg[..]);

                    // Hash the message
                    self.hasher.update(&msg);
                    let digest = self.hasher.finalize();
                    info!(msg = hex(&msg), payload = ?digest, "proposed");

                    // Send digest to consensus
                    let _ = response.send(digest);
                }
                Message::Verify { response } => {
                    // Digests are already verified by consensus, so we don't need to check they are valid.
                    //
                    // If we linked payloads to their parent, we would verify
                    // the parent included in the payload matches the provided context.
                    let _ = response.send(true);
                }
            }
        }
    }
}
