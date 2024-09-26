use super::ingress::Message;
use crate::tbd::wire;
use crate::tbd::Error;
use bytes::Bytes;
use commonware_cryptography::bls12381::primitives::poly;
use commonware_cryptography::{
    bls12381,
    utils::{hex, payload},
    PublicKey, Scheme,
};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{select, Clock};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt, StreamExt,
};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use prost::Message as _;
use sha2::{Digest, Sha256};
use std::time::{Duration, UNIX_EPOCH};
use tracing::debug;

const BLOCK_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_TBD_BLOCK_";
const SEED_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_TBD_SEED_";
const VOTE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_TBD_VOTE_";

// TODO: include partials (need to if determine execution)?
fn block_hash(
    timestamp: u64,
    epoch: u64,
    view: u64,
    height: u64,
    parent: Bytes,
    payload: Bytes,
) -> Bytes {
    // TODO: hash everything other than payload together first to make proof against payload
    // minimal
    let mut hasher = Sha256::new();
    hasher.update(timestamp.to_be_bytes());
    hasher.update(epoch.to_be_bytes());
    hasher.update(view.to_be_bytes());
    hasher.update(height.to_be_bytes());
    hasher.update(parent);
    hasher.update(payload);
    hasher.finalize().to_vec().into()
}

fn seed_hash(epoch: u64, view: u64) -> Bytes {
    let mut hasher = Sha256::new();
    hasher.update(epoch.to_be_bytes());
    hasher.update(view.to_be_bytes());
    hasher.finalize().to_vec().into()
}

fn vote_hash(epoch: u64, view: u64, block: Bytes) -> Bytes {
    let mut hasher = Sha256::new();
    hasher.update(epoch.to_be_bytes());
    hasher.update(view.to_be_bytes());
    hasher.update(block);
    hasher.finalize().to_vec().into()
}

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

    async fn run_view(&mut self, group: &poly::Public, seed: Bytes) -> Result<(u64, u64), Error> {
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
            self.control
                .send({
                    Message::Payload {
                        timestamp,
                        parent: parent.clone(),
                        height,
                        payload: payload_sender,
                    }
                })
                .await
                .map_err(|_| Error::NetworkClosed)?;
            let (payload_hash, payload) =
                payload_receiver.await.map_err(|_| Error::NetworkClosed)?;

            // Broadcast block to other peers
            let block_hash = block_hash(
                timestamp,
                self.epoch,
                self.view,
                height,
                parent.clone(),
                payload_hash,
            );
            let msg = wire::Propose {
                timestamp,
                epoch: self.epoch,
                view: self.view,
                height,
                parent: parent.clone(),
                payload: payload.clone(),
                signature: Some(wire::Signature {
                    public_key: self.crypto.public_key(),
                    signature: self.crypto.sign(BLOCK_NAMESPACE, &block_hash),
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

            // Broadcast vote to other peers
            let vote_hash = vote_hash(self.epoch, self.view, block_hash.clone());
            let msg = wire::Vote {
                epoch: self.epoch,
                view: self.view,
                block: block_hash.clone(),
                signature: Some(wire::Signature {
                    public_key: self.crypto.public_key(),
                    signature: self.crypto.sign(VOTE_NAMESPACE, &vote_hash),
                }),
            };
            let msg = wire::Message {
                payload: Some(wire::message::Payload::Vote(msg)),
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
                    // Parse message
                    let (sender, msg) = msg.map_err(|_| Error::NetworkClosed)?;
                    // TODO: continue here rather than exiting
                    let msg = wire::Message::decode(msg).map_err(|_| Error::InvalidMessage)?;
                    match msg.payload{
                        Some(wire::message::Payload::Propose(propose)) => {
                            // Check if timed out
                            if timed_out {
                                continue;
                            }

                            // Verify leader
                            if propose.epoch != self.epoch || propose.view != self.view || sender != leader {
                                // Drop any unexpected blocks (and collect signature for fault if a validator)
                                debug!(epoch = propose.epoch, view = propose.view, leader = hex(&leader), sender = hex(&sender), "unexpected block");
                                continue;
                            }

                            // Verify block (need to ensure anyone that can veriy against header)
                            let (sender, receiver) = oneshot::channel();
                            self.control.send(Message::Verify{
                                timestamp: propose.timestamp,
                                height: propose.height,
                                parent: propose.parent.clone(),
                                payload: propose.payload,
                                result: sender,
                            }).await.map_err(|_| Error::NetworkClosed)?;
                            let payload_hash = receiver.await.map_err(|_| Error::NetworkClosed)?.ok_or(Error::InvalidBlock)?;

                            // Set leader timeout to be infinite
                            leader_timeout = UNIX_EPOCH + Duration::MAX;

                            // Send vote if correct leader and first block at (epoch, view)
                            // TODO: assert correct leader and first block
                            let block_hash = block_hash(
                                propose.timestamp,
                                self.epoch,
                                self.view,
                                propose.height,
                                propose.parent.clone(),
                                payload_hash,
                            );
                            let vote_hash = vote_hash(self.epoch, self.view, block_hash.clone());
                            // TODO: change to partial sign
                            let msg = wire::Vote {
                                epoch: self.epoch,
                                view: self.view,
                                block: block_hash.clone(),
                                signature: Some(wire::Signature {
                                    public_key: self.crypto.public_key(),
                                    signature: self.crypto.sign(VOTE_NAMESPACE, &vote_hash),
                                }),
                            };
                            let msg = wire::Message {
                                payload: Some(wire::message::Payload::Vote(msg)),
                            }.encode_to_vec().into();
                            self.sender.send(Recipients::All, msg, true).await.map_err(|_| Error::NetworkClosed)?;

                            // Send seed
                            // TODO: change to partial sign
                            let seed_hash = seed_hash(self.epoch, self.view);
                            let msg = wire::Seed {
                                epoch: self.epoch,
                                view: self.view,
                                signature: Some(wire::Signature {
                                    public_key: self.crypto.public_key(),
                                    signature: self.crypto.sign(SEED_NAMESPACE, &seed_hash),
                                }),
                            };
                            let msg = wire::Message {
                                payload: Some(wire::message::Payload::Seed(msg)),
                            }.encode_to_vec().into();
                            self.sender.send(Recipients::All, msg, true).await.map_err(|_| Error::NetworkClosed)?;

                        },
                        Some(wire::message::Payload::Vote(vote)) => {
                            // Verify vote against public polynomial
                            let vote_hash = vote_hash(vote.epoch, vote.view, vote.block.clone());
                            let digest = payload(VOTE_NAMESPACE, &vote_hash);
                            let signature = vote.signature.ok_or(Error::InvalidSignature)?;
                            let signature = bls12381::primitives::poly::Eval<group::Signature>::deserialize(signature.as_ref()).ok_or(Error::InvalidSignature)?;
                            bls12381::primitives::ops::partial_verify(&group, &digest, &signature.signature);

                            // If 2f + 1,
                            advance_timeout = UNIX_EPOCH + Duration::MAX;
                            // TODO: move signature aggregation outside of this loop to continue processing messages

                            // If dummy,
                            break;
                        },
                        Some(wire::message::Payload::Finalize(finalize)) => {
                            // TODO: need to continue processing finalize messages in next view
                        },
                        Some(wire::message::Payload::Advance(advance)) => {
                            // TODO: handle view moving ahead view we are finalizing
                            break;
                        },
                        Some(wire::message::Payload::Lock(lock)) => {
                            // TODO: send ancestors along finalization channel if not sent yet
                            break;
                        },
                        Some(wire::message::Payload::Seed(seed)) => {}
                        None => {
                            // TODO: could get messages from a newer version we don't know about
                        }
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
