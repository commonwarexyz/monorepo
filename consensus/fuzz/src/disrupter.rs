use crate::{types::Message, FuzzInput, EPOCH};
use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_consensus::{
    simplex::{
        signing_scheme::Scheme,
        types::{Certificate, Finalize, Notarize, Nullify, Proposal, Vote},
    },
    types::{Epoch, Round, View},
    Epochable, Viewable,
};
use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest};
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, Spawner};
use commonware_utils::ordered::{Quorum, Set};
use rand::{CryptoRng, Rng};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_millis(500);

/// Which fields to mutate when creating a malformed proposal.
#[derive(Debug, Clone, Arbitrary)]
pub enum Mutation {
    Payload,
    View,
    Parent,
    All,
}

/// Byzantine actor that disrupts consensus by sending malformed/mutated messages.
pub struct Disrupter<E: Clock + Spawner + Rng + CryptoRng, S: Scheme> {
    context: E,
    validator: PublicKey,
    scheme: S,
    participants: Set<PublicKey>,
    namespace: Vec<u8>,
    fuzz_input: FuzzInput,
    last_vote: u64,
    last_finalized: u64,
    last_nullified: u64,
    last_notarized: u64,
}

impl<E: Clock + Spawner + Rng + CryptoRng, S: Scheme> Disrupter<E, S>
where
    <S::Certificate as Read>::Cfg: Default,
{
    pub fn new(
        context: E,
        validator: PublicKey,
        scheme: S,
        participants: Set<PublicKey>,
        namespace: Vec<u8>,
        fuzz_input: FuzzInput,
    ) -> Self {
        Self {
            last_vote: 0,
            last_finalized: 0,
            last_nullified: 0,
            last_notarized: 0,
            context,
            validator,
            scheme,
            participants,
            namespace,
            fuzz_input,
        }
    }

    fn mutation(&mut self) -> Mutation {
        match self.fuzz_input.random_byte() % 4 {
            0 => Mutation::Payload,
            1 => Mutation::View,
            2 => Mutation::Parent,
            _ => Mutation::All,
        }
    }

    fn message(&mut self) -> Message {
        match self.fuzz_input.random_byte() % 4 {
            0 => Message::Notarize,
            1 => Message::Finalize,
            2 => Message::Nullify,
            _ => Message::Random,
        }
    }

    fn random_view(&mut self, current: u64) -> u64 {
        let last_finalized = self.last_finalized;
        let last_notarized = self.last_notarized;
        let last_nullified = self.last_nullified;

        match self.fuzz_input.random_byte() % 7 {
            // Too old (pre-finalized) - should be filtered
            0 => {
                if last_finalized == 0 {
                    last_finalized
                } else {
                    self.fuzz_input.random_u64() % last_finalized
                }
            }
            // Active past: [last_finalized, current_view]
            1 => {
                if current <= last_finalized {
                    last_finalized
                } else {
                    last_finalized + (self.fuzz_input.random_u64() % (current - last_finalized + 1))
                }
            }
            // Active band: [last_finalized, min(last_notarized, current_view)]
            2 => {
                let hi = last_notarized.min(current).max(last_finalized);
                last_finalized + (self.fuzz_input.random_u64() % (hi - last_finalized + 1))
            }
            // Near future: [current_view+1, current_view+4]
            3 => current + 1 + (self.fuzz_input.random_byte() as u64 % 4),
            // Moderate future: [current_view+5, current_view+10]
            4 => current.saturating_add(5 + (self.fuzz_input.random_byte() as u64 % 6)),
            // Nullification-based future: start after max(current_view, last_nullified)
            5 => {
                let base = current.max(last_nullified);
                base.saturating_add(1 + (self.fuzz_input.random_byte() as u64 % 10))
            }
            // Pure random
            _ => self.fuzz_input.random_u64(),
        }
    }

    fn parent(&mut self) -> u64 {
        self.fuzz_input.random_u64()
    }

    fn payload(&mut self) -> Sha256Digest {
        let bytes = self.fuzz_input.random(32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32.min(bytes.len())]);
        Sha256Digest::from(arr)
    }

    fn bytes(&mut self) -> Vec<u8> {
        let len = self.fuzz_input.random_byte();
        self.fuzz_input.random(len as usize)
    }

    fn mutate_bytes(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return vec![0];
        }

        let mut result = input.to_vec();
        let pos = (self.fuzz_input.random_byte() as usize) % result.len();

        match self.fuzz_input.random_byte() % 5 {
            0 => result[pos] = result[pos].wrapping_add(1),
            1 => result[pos] = result[pos].wrapping_sub(1),
            2 => result[pos] ^= 0xFF,
            3 => result[pos] = 0,
            _ => result[pos] = 0xFF,
        }

        result
    }

    pub fn start(
        self,
        vote_network: (impl Sender, impl Receiver),
        certificate_network: (impl Sender, impl Receiver),
    ) -> Handle<()> {
        let context = self.context.clone();
        context.spawn(|_| self.run(vote_network, certificate_network))
    }

    async fn run(
        mut self,
        vote_network: (impl Sender, impl Receiver),
        certificate_network: (impl Sender, impl Receiver),
    ) {
        let (mut vote_sender, mut vote_receiver) = vote_network;
        let (mut cert_sender, mut cert_receiver) = certificate_network;

        loop {
            if self.fuzz_input.random_byte() % 100 < 10 {
                self.send_random(&mut vote_sender).await;
            }

            select! {
                result = vote_receiver.recv().fuse() => {
                    if let Ok((_, msg)) = result {
                        self.handle_vote(&mut vote_sender, msg.to_vec()).await;
                    }
                },
                result = cert_receiver.recv().fuse() => {
                    if let Ok((_, msg)) = result {
                        self.handle_certificate(&mut cert_sender, msg.to_vec()).await;
                    }
                },
                // We ignore resolver messages
                _ = self.context.sleep(TIMEOUT) => {
                    self.send_random(&mut vote_sender).await;
                }
            }
        }
    }

    async fn handle_vote(&mut self, sender: &mut impl Sender, msg: Vec<u8>) {
        if self.fuzz_input.random_bool() {
            let _ = sender
                .send(Recipients::All, Bytes::from(msg.clone()), true)
                .await;
        }

        let Ok(vote) = Vote::<S, Sha256Digest>::read(&mut msg.as_slice()) else {
            return;
        };
        self.last_vote = vote.view().get();
        match vote {
            Vote::Notarize(notarize) => {
                if self.fuzz_input.random_bool() {
                    let mutated = self.mutate_bytes(&msg);
                    let _ = sender.send(Recipients::All, mutated.into(), true).await;
                } else {
                    let proposal = self.mutate_proposal(&notarize.proposal);
                    if let Some(v) = Notarize::sign(&self.scheme, &self.namespace, proposal) {
                        let msg = Vote::<S, Sha256Digest>::Notarize(v).encode().into();
                        let _ = sender.send(Recipients::All, msg, true).await;
                    }
                }
            }
            Vote::Finalize(finalize) => {
                if self.fuzz_input.random_bool() {
                    let mutated = self.mutate_bytes(&msg);
                    let _ = sender.send(Recipients::All, mutated.into(), true).await;
                } else {
                    let proposal = self.mutate_proposal(&finalize.proposal);
                    if let Some(v) = Finalize::sign(&self.scheme, &self.namespace, proposal) {
                        let msg = Vote::<S, Sha256Digest>::Finalize(v).encode().into();
                        let _ = sender.send(Recipients::All, msg, true).await;
                    }
                }
            }
            Vote::Nullify(_) => {
                if self.fuzz_input.random_bool() {
                    let mutated = self.mutate_bytes(&msg);
                    let _ = sender.send(Recipients::All, mutated.into(), true).await;
                } else {
                    let v = self.random_view(self.last_vote);
                    let round = Round::new(Epoch::new(EPOCH), View::new(v));
                    if let Some(v) =
                        Nullify::<S>::sign::<Sha256Digest>(&self.scheme, &self.namespace, round)
                    {
                        let msg = Vote::<S, Sha256Digest>::Nullify(v).encode().into();
                        let _ = sender.send(Recipients::All, msg, true).await;
                    }
                }
            }
        }
    }

    async fn handle_certificate(&mut self, sender: &mut impl Sender, msg: Vec<u8>) {
        if self.fuzz_input.random_bool() {
            let _ = sender
                .send(Recipients::All, Bytes::from(msg.clone()), true)
                .await;
        }

        let cfg = self.scheme.certificate_codec_config();
        let Ok(cert) = Certificate::<S, Sha256Digest>::read_cfg(&mut msg.as_slice(), &cfg) else {
            return;
        };

        match cert {
            Certificate::Notarization(n) => {
                self.last_notarized = n.view().get();
            }
            Certificate::Nullification(n) => {
                self.last_nullified = n.view().get();
            }
            Certificate::Finalization(f) => {
                self.last_finalized = f.view().get();
            }
        }

        // Optionally send mutated certificate
        if self.fuzz_input.random_bool() {
            let mutated = self.mutate_bytes(&msg);
            let _ = sender.send(Recipients::All, mutated.into(), true).await;
        }
    }

    fn mutate_proposal(&mut self, original: &Proposal<Sha256Digest>) -> Proposal<Sha256Digest> {
        match self.mutation() {
            Mutation::Payload => Proposal::new(
                Round::new(original.epoch(), original.view()),
                original.parent,
                self.payload(),
            ),
            Mutation::View => Proposal::new(
                Round::new(
                    original.epoch(),
                    View::new(self.random_view(original.view().get())),
                ),
                original.parent,
                original.payload,
            ),
            Mutation::Parent => Proposal::new(
                Round::new(original.epoch(), original.view()),
                View::new(self.parent()),
                original.payload,
            ),
            Mutation::All => Proposal::new(
                Round::new(
                    original.epoch(),
                    View::new(self.random_view(original.view().get())),
                ),
                View::new(self.parent()),
                self.payload(),
            ),
        }
    }

    async fn send_random(&mut self, sender: &mut impl Sender) {
        let proposal = Proposal::new(
            Round::new(
                Epoch::new(EPOCH),
                View::new(self.random_view(self.last_vote)),
            ),
            View::new(self.parent()),
            self.payload(),
        );

        if self.participants.index(&self.validator).is_none() {
            let bytes = self.bytes();
            let _ = sender.send(Recipients::All, bytes.into(), true).await;
            return;
        }

        match self.message() {
            Message::Notarize => {
                if let Some(vote) = Notarize::sign(&self.scheme, &self.namespace, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Notarize(vote).encode().into();
                    let _ = sender.send(Recipients::All, msg, true).await;
                }
            }
            Message::Finalize => {
                if let Some(vote) = Finalize::sign(&self.scheme, &self.namespace, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Finalize(vote).encode().into();
                    let _ = sender.send(Recipients::All, msg, true).await;
                }
            }
            Message::Nullify => {
                let round = Round::new(
                    Epoch::new(EPOCH),
                    View::new(self.random_view(self.last_vote)),
                );
                if let Some(vote) =
                    Nullify::<S>::sign::<Sha256Digest>(&self.scheme, &self.namespace, round)
                {
                    let msg = Vote::<S, Sha256Digest>::Nullify(vote).encode().into();
                    let _ = sender.send(Recipients::All, msg, true).await;
                }
            }
            Message::Random => {
                let bytes = self.bytes();
                let _ = sender.send(Recipients::All, bytes.into(), true).await;
            }
        }
    }
}
