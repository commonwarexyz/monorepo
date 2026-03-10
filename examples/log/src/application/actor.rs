use super::{
    ingress::{Mailbox, MailboxMessage, MailboxReadWriteMessage},
    reporter::Reporter,
    Config,
};
use commonware_actor::{
    service::{ActorService, ServiceBuilder},
    Actor,
};
use commonware_consensus::types::Epoch;
use commonware_cryptography::Hasher;
use commonware_runtime::Spawner;
use commonware_utils::{channel::fallible::OneshotExt, hex};
use rand::Rng;
use std::convert::Infallible;
use tracing::info;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Application actor.
pub struct Application<H: Hasher> {
    hasher: H,
}

impl<E: Rng + Spawner, H: Hasher> Actor<E> for Application<H> {
    type Mailbox = Mailbox<H::Digest>;
    type Ingress = MailboxMessage<H::Digest>;
    type Error = Infallible;
    type Args = ();
    type Snapshot = ();

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {}

    async fn on_read_write(
        &mut self,
        context: &mut E,
        _args: &mut Self::Args,
        message: MailboxReadWriteMessage<H::Digest>,
    ) -> Result<(), Self::Error> {
        match message {
            MailboxReadWriteMessage::GetGenesis { epoch, response } => {
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
                response.send_lossy(digest);
            }
            MailboxReadWriteMessage::CreateProposal { response } => {
                // Generate a random message (secret to us)
                let mut msg = vec![0; 16];
                context.fill(&mut msg[..]);

                // Hash the message
                self.hasher.update(&msg);
                let digest = self.hasher.finalize();
                info!(msg = hex(&msg), payload = ?digest, "proposed");

                // Send digest to consensus
                response.send_lossy(digest);
            }
            MailboxReadWriteMessage::VerifyProposal { response } => {
                // Digests are already verified by consensus, so we don't need to check they are valid.
                //
                // If we linked payloads to their parent, we would verify
                // the parent included in the payload matches the provided context.
                response.send_lossy(true);
            }
        }
        Ok(())
    }
}

pub struct ApplicationHandle<R: Rng + Spawner, H: Hasher> {
    pub reporter: Reporter<H::Digest>,
    pub service: ActorService<R, Application<H>>,
    pub mailbox: Mailbox<H::Digest>,
}

impl<H: Hasher> Application<H> {
    /// Create a new application actor and start the service.
    pub fn init<R: Rng + Spawner>(context: R, config: Config<H>) -> ApplicationHandle<R, H> {
        let actor = Self {
            hasher: config.hasher,
        };
        let (mailbox, service) =
            ServiceBuilder::new(actor).build_with_capacity(context, config.mailbox_size);
        ApplicationHandle {
            reporter: Reporter::new(),
            service,
            mailbox,
        }
    }
}
