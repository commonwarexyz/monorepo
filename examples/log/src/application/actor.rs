use super::{
    ingress::{Mailbox, Message},
    reporter::{self, Reporter},
    Config, Scheme,
};
use commonware_actor::mailbox::{self, Receiver};
use commonware_consensus::types::Epoch;
use commonware_cryptography::Hasher;
use commonware_formatting::hex;
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use rand::Rng;
use std::num::NonZeroUsize;
use tracing::info;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Application actor.
pub struct Application<R: Rng + Spawner, H: Hasher> {
    context: ContextCell<R>,
    hasher: H,
    mailbox: Receiver<Message<H::Digest>>,
}

impl<R: Rng + Spawner, H: Hasher> Application<R, H> {
    /// Create a new application actor.
    #[allow(clippy::type_complexity)]
    pub fn new(
        context: R,
        config: Config<H>,
    ) -> (Self, Scheme, Reporter<H::Digest>, Mailbox<H::Digest>) {
        let (sender, receiver) = mailbox::new(
            NonZeroUsize::new(config.mailbox_size).expect("mailbox size must be non-zero"),
        );
        let mailbox = Mailbox::new(sender);
        let reporter = Reporter::new(&mailbox);
        (
            Self {
                context: ContextCell::new(context),
                hasher: config.hasher,
                mailbox: receiver,
            },
            config.scheme,
            reporter,
            mailbox,
        )
    }

    /// Run the application actor.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.mailbox.recv().await {
            match message {
                Message::Genesis { epoch, response } => {
                    // Sanity check. We don't support multiple epochs.
                    assert_eq!(epoch, Epoch::zero(), "epoch must be 0");

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
                Message::Report { activity } => {
                    reporter::log(activity);
                }
            }
        }
    }
}
