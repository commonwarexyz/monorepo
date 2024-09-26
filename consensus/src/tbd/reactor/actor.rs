use super::ingress::Message;
use crate::tbd::wire;
use crate::tbd::Error;
use bytes::Bytes;
use commonware_cryptography::{PublicKey, Scheme};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use prost::Message as _;
use std::time::{Duration, UNIX_EPOCH};

pub struct Actor<C: Scheme, E: Clock, S: Sender, R: Receiver> {
    crypto: C,
    runtime: E,

    sender: S,
    receiver: R,

    control: mpsc::Sender<Message>,

    epoch_length: u64,

    epoch: u64,
    view: u64,

    locked: u64,
    notarized: u64,

    participants: Vec<PublicKey>,
}

impl<C: Scheme, E: Clock, S: Sender, R: Receiver> Actor<C, E, S, R> {
    pub fn new(
        crypto: C,
        runtime: E,
        sender: S,
        receiver: R,
        participants: Vec<PublicKey>,
    ) -> (Self, mpsc::Receiver<Message>) {
        let (control, handler) = mpsc::channel(1024);
        (
            Self {
                crypto,
                runtime,
                sender,
                receiver,
                control,

                epoch_length: 100,
                epoch: 0,
                view: 0,
                locked: 0,
                notarized: 0,
                participants,
            },
            handler,
        )
    }

    pub async fn run(mut self) {}

    async fn run_view(&mut self, seed: Bytes) -> Result<(u64, u64), Error> {
        // Configure round
        let now = self.runtime.current();
        let mut leader_timeout = now + Duration::from_secs(2);
        let mut advance_timeout = leader_timeout + Duration::from_secs(1);
        let timestamp = now.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let mut timed_out = false;

        // Get parent block info
        let height = self.notarized + 1;
        let parent = Bytes::default(); // TODO: populate with parent block hash

        // Select leader
        let seed_number = BigUint::from_bytes_be(&seed);
        let leader_index = seed_number % self.participants.len();
        let leader = self.participants[leader_index.to_usize().unwrap()].clone();

        // If leader, propose and broadcast block
        if leader == self.crypto.public_key() {
            // Get payload from application
            let (payload_sender, payload_receiver) = oneshot::channel();
            let block = self
                .control
                .send({
                    Message::Payload {
                        timestamp,
                        parent,
                        height,
                        payload: payload_sender,
                    }
                })
                .await
                .map_err(|_| Error::NetworkClosed)?;
            let (hash, payload) = payload_receiver.await.map_err(|_| Error::NetworkClosed)?;

            // Broadcast block to other peers
            let msg = wire::Propose {
                timestamp,
                epoch: self.epoch,
                view: self.view,
                height,
                partials: Vec::new(),
                parent,
                payload,
                signature: Some(wire::Signature {
                    public_key: self.crypto.public_key(),
                    signature: self.crypto.sign("block", &[u8; 32]),
                }),
            };
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Propose(msg)),
            }
            .encode_to_vec()
            .into();
            self.sender
                .send(Recipients::All, msg, true)
                .await
                .map_err(|_| Error::NetworkClosed)?;
        }

        // Process messages
        loop {
            select! {
                _leader_timeout = self.runtime.sleep_until(leader_timeout) => {
                    timed_out = true;
                },
                _advance_timeout = self.runtime.sleep_until(advance_timeout) => {
                    timed_out = true;
                },
                msg = self.receiver.recv() => {
                    let msg = match msg {
                        Ok(msg) => msg,
                        Err(e) => { return Err(Error::NetworkClosed) },
                    };
                    match msg {
                        Message::Propose { epoch, view, block, signature, payload } => {
                            // TODO: verify block (need to ensure anyone that can veriy against header)

                            // Set leader timeout to be infinite
                            leader_timeout = UNIX_EPOCH + Duration::MAX;
                        },
                        Message::Vote { epoch, view, block, signature } => {
                            // If 2f + 1,
                            advance_timeout = UNIX_EPOCH + Duration::MAX;
                            // TODO: move signature aggregation outside of this loop to continue processing messages

                            // If dummy,
                            break;
                        },
                        Message::Finalize { epoch, view, block, notarization, signature } => {
                            // TODO: need to continue processing finalize messages in next view
                        },
                        Message::Advance { epoch, view, block, notarization } => {
                            break;
                        },
                        Message::Lock { epoch, view, block, notarization, finalization } => {
                            // TODO: send ancestors along finalization channel if not sent yet
                            break;
                        },
                        Message::Seed { epoch, view, signature } => {},
                    };
                },
            };
        }

        // TODO: when a block is finalized, send along channel
        // with seed to execute it (created after commitment)

        // TODO: return next epoch and view or error
        Ok((0, 0))
    }
}
