use super::{
    ingress::{Mailbox, Message},
    supervisor::Supervisor,
    Config,
};
use commonware_consensus::simplex::Prover;
use commonware_cryptography::Hasher;
use commonware_utils::hex;
use futures::{channel::mpsc, StreamExt};
use rand::Rng;
use tracing::info;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Application actor.
pub struct Application<R: Rng, H: Hasher> {
    runtime: R,
    prover: Prover<H>,
    hasher: H,
    mailbox: mpsc::Receiver<Message>,
}

impl<R: Rng, H: Hasher> Application<R, H> {
    /// Create a new application actor.
    pub fn new(runtime: R, config: Config<H>) -> (Self, Supervisor, Mailbox) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                runtime,
                prover: config.prover,
                hasher: config.hasher,
                mailbox,
            },
            Supervisor::new(config.identity, config.participants, config.share),
            Mailbox::new(sender),
        )
    }

    /// Run the application actor.
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
                Message::Propose { response } => {
                    // Generate a random message (secret to us)
                    let mut msg = vec![0; 16];
                    self.runtime.fill(&mut msg[..]);

                    // Hash the message
                    self.hasher.update(&msg);
                    let digest = self.hasher.finalize();
                    info!(msg = hex(&msg), payload = hex(&digest), "proposed");

                    // Send digest to consensus
                    let _ = response.send(digest);
                }
                Message::Verify { payload, response } => {
                    // If we linked payloads to their parent, we would verify
                    // the parent included in the payload matches the provided context.
                    let valid = H::validate(&payload);
                    let _ = response.send(valid);
                }
                Message::Prepared { proof, payload } => {
                    let (view, _, _, _, _) = self.prover.deserialize_notarization(proof).unwrap();
                    info!(view, payload = hex(&payload), "prepared")
                }
                Message::Finalized { proof, payload } => {
                    let (view, _, _, _, _) = self.prover.deserialize_finalization(proof).unwrap();
                    info!(view, payload = hex(&payload), "finalized")
                }
            }
        }
    }
}
