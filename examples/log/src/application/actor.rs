use super::{
    ingress::{Mailbox, Message},
    reporter::Reporter,
    Config, Scheme,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{spawn_cell, ContextCell, Handle, Spawner};
use commonware_utils::{channel::mpsc, hex};
use rand::Rng;
use tracing::info;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

pub fn genesis<H: Hasher>() -> H::Digest {
    let mut hasher = H::default();
    hasher.update(GENESIS);
    hasher.finalize()
}

/// Application actor.
pub struct Application<R: Rng + Spawner, H: Hasher> {
    context: ContextCell<R>,
    hasher: H,
    mailbox: mpsc::Receiver<Message<H::Digest>>,
}

impl<R: Rng + Spawner, H: Hasher> Application<R, H> {
    /// Create a new application actor.
    #[allow(clippy::type_complexity)]
    pub fn new(
        context: R,
        config: Config<H>,
    ) -> (Self, Scheme, Reporter<H::Digest>, Mailbox<H::Digest>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                hasher: config.hasher,
                mailbox,
            },
            config.scheme,
            Reporter::new(),
            Mailbox::new(sender),
        )
    }

    /// Run the application actor.
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        while let Some(message) = self.mailbox.recv().await {
            match message {
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
