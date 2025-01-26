use super::{
    ingress::{Mailbox, Message},
    supervisor::Supervisor,
    Config,
};
use commonware_consensus::{simplex::Prover, DigestBytes};
use commonware_cryptography::{Hasher, Scheme};
use commonware_utils::hex;
use futures::{channel::mpsc, StreamExt};
use rand::Rng;
use tracing::info;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Application actor.
pub struct Application<R: Rng, C: Scheme, H: Hasher> {
    runtime: R,
    prover: Prover<C, H>,
    hasher: H,
    mailbox: mpsc::Receiver<Message>,
}

impl<R: Rng, C: Scheme, H: Hasher> Application<R, C, H> {
    /// Create a new application actor.
    pub fn new(runtime: R, config: Config<C, H>) -> (Self, Supervisor, Mailbox) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                runtime,
                prover: config.prover,
                hasher: config.hasher,
                mailbox,
            },
            Supervisor::new(config.participants),
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
                    let digest = DigestBytes::copy_from_slice(self.hasher.finalize().as_ref());
                    let _ = response.send(digest);
                }
                Message::Propose { response } => {
                    // Generate a random message (secret to us)
                    let mut msg = vec![0; 16];
                    self.runtime.fill(&mut msg[..]);

                    // Hash the message
                    self.hasher.update(&msg);
                    let digest = DigestBytes::copy_from_slice(self.hasher.finalize().as_ref());
                    info!(msg = hex(&msg), payload = hex(digest.as_ref()), "proposed");

                    // Send digest to consensus
                    let _ = response.send(digest);
                }
                Message::Verify { payload, response } => {
                    // If we linked payloads to their parent, we would verify
                    // the parent included in the payload matches the provided context.
                    let valid = H::validate(&H::from(&payload));
                    let _ = response.send(valid);
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
