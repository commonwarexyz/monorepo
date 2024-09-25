use super::ingress::{Mailbox, Message};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use std::time::Duration;

pub struct Actor {
    receiver: mpsc::Receiver<Message>,

    epoch_length: u64,

    epoch: u64,
    view: u64,

    locked: u64,
    notarized: u64,

    participants: Vec<PublicKey>,
}

impl Actor {
    pub fn new(participants: Vec<PublicKey>) -> (Self, Mailbox) {
        let (sender, receiver) = mpsc::channel(1024);
        (
            Self {
                receiver,
                epoch_length: 100,
                epoch: 0,
                view: 0,
                locked: 0,
                notarized: 0,
                participants,
            },
            Mailbox::new(sender),
        )
    }

    pub async fn run(mut self) {}

    async fn run_view(&mut self, seed: Bytes) -> Result<(u64, u64), Error> {
        // Configure round
        let mut leader_timeout = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut advance_timeout = leader_timeout + Duration::from_secs(1);
        let mut timed_out = false;

        // Select leader
        let seed_number = BigUint::from_bytes_be(&seed);
        let leader_index = seed_number % self.participants.len();
        let leader = self.participants[leader_index.to_usize().unwrap()].clone();

        // If leader, propose block
        // TODO: use a channel to request from external
        // TODO: wrap user block (just application data in chain data they don't
        // need to know about? or require any block to be able to answer certain functions?)
        // TODO: propose can provide parent and timestamp and epoch/view to builder but they don't
        // need to manage it themselves? -> handle linking blocks for you (handles end of epoch behavior)
        let block = self.view.to_be_bytes().to_vec();

        // TODO: broadcast block

        // Process messages
        loop {
            select! {
                biased;

                _ = tokio::time::sleep_until(leader_timeout) => {
                    timed_out = true;
                }
                _ = tokio::time::sleep_until(advance_timeout) => {
                    timed_out = true;
                }
                msg = self.receiver.recv() => match msg{
                    Some(Message::Propose { epoch, view, block, signature }) => {
                        // TODO: verify block (need to ensure anyone that can veriy against header)

                        // Set leader timeout to be infinite
                        leader_timeout = Duration::MAX;
                    },
                    Some(Message::Vote { epoch, view, block, signature }) => {
                        // If 2f + 1,
                        advance_timeout = Duration::MAX;
                        // TODO: move signature aggregation outside of this loop to continue processing messages

                        // If dummy,
                        break;
                    },
                    Some(Message::Finalize { epoch, view, block, notarization, signature }) => {
                        // TODO: need to continue processing finalize messages in next view
                    },
                    Some(Message::Advance { epoch, view, block, notarization }) => {
                        break;
                    },
                    Some(Message::Lock { epoch, view, block, notarization, finalization }) => {
                        // TODO: send ancestors along finalization channel if not sent yet
                        break;
                    },
                    Some(Message::Seed { epoch, view, signature }) => {},
                    None => { break; },
                },
            }
        }

        // TODO: when a block is finalized, send along channel
        // with seed to execute it (created after commitment)

        // TODO: return next epoch and view or error
    }
}
