use super::{
    ingress::{Mailbox, Message},
    supervisor::Supervisor,
    Config,
};
use commonware_consensus::simplex::Prover;
use commonware_cryptography::{
    bls12381::primitives::{
        group::{self, Element},
        poly,
    },
    Hasher,
};
use commonware_log::wire;
use commonware_runtime::{Sink, Stream};
use commonware_stream::{public_key::Connection, Receiver, Sender};
use commonware_utils::hex;
use futures::{channel::mpsc, StreamExt};
use prost::Message as _;
use rand::Rng;
use tracing::info;

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Application actor.
pub struct Application<R: Rng, H: Hasher, Si: Sink, St: Stream> {
    runtime: R,
    indexer: Connection<Si, St>,
    public: Vec<u8>,
    prover: Prover<H>,
    hasher: H,
    mailbox: mpsc::Receiver<Message>,
}

impl<R: Rng, H: Hasher, Si: Sink, St: Stream> Application<R, H, Si, St> {
    /// Create a new application actor.
    pub fn new(runtime: R, config: Config<H, Si, St>) -> (Self, Supervisor, Mailbox) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                runtime,
                indexer: config.indexer,
                public: poly::public(&config.identity).serialize(),
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
        let (mut indexer_sender, mut indexer_receiver) = self.indexer.split();
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
                    let (view, _, _, signature, seed) =
                        self.prover.deserialize_notarization(proof).unwrap();
                    let signature = signature.serialize();
                    let seed = seed.serialize();
                    info!(
                        view,
                        payload = hex(&payload),
                        signature = hex(&signature),
                        seed = hex(&seed),
                        "prepared"
                    )
                }
                Message::Finalized { proof, payload } => {
                    let (view, _, _, signature, seed) =
                        self.prover.deserialize_finalization(proof.clone()).unwrap();
                    let signature = signature.serialize();
                    let seed = seed.serialize();
                    info!(
                        view,
                        payload = hex(&payload),
                        signature = hex(&signature),
                        seed = hex(&seed),
                        "finalized"
                    );

                    // Post finalization
                    let msg = wire::PutFinalization {
                        network: self.public.clone(),
                        data: proof,
                    }
                    .encode_to_vec();
                    indexer_sender
                        .send(&msg)
                        .await
                        .expect("failed to send finalization to indexer");
                    let result = indexer_receiver
                        .receive()
                        .await
                        .expect("failed to receive from indexer");
                    let msg = wire::Outbound::decode(result).expect("failed to decode result");
                    let payload = msg.payload.expect("missing payload");
                    let success = match payload {
                        wire::outbound::Payload::Success(s) => s,
                        _ => panic!("unexpected response"),
                    };
                    info!(success, "finalization posted");
                }
            }
        }
    }
}
