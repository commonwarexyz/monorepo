use crate::{types::Message, FuzzInput, EPOCH};
use arbitrary::Arbitrary;
use bytes::Bytes;
use commonware_codec::{Encode, Read, ReadExt};
use commonware_consensus::{
    simplex::{
        scheme::Scheme,
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
use rand_core::CryptoRngCore;
use std::{collections::VecDeque, time::Duration};

const TIMEOUT: Duration = Duration::from_millis(100);
const LATEST_PROPOSALS_MIN_LEN: u64 = 10;
const LATEST_PROPOSALS_MAX_LEN: usize = 100;

/// Which fields to mutate when creating a malformed proposal.
#[derive(Debug, Clone, Arbitrary)]
pub enum Mutation {
    Payload,
    View,
    Parent,
    All,
}

/// Byzantine actor that disrupts consensus by sending malformed/mutated messages.
pub struct Disrupter<E: Clock + Spawner + CryptoRngCore, S: Scheme<Sha256Digest>> {
    context: E,
    validator: PublicKey,
    scheme: S,
    participants: Set<PublicKey>,
    fuzz_input: FuzzInput,
    last_vote: u64,
    last_finalized: u64,
    last_nullified: u64,
    last_notarized: u64,
    latest_proposals: VecDeque<Proposal<Sha256Digest>>,
}

impl<E: Clock + Spawner + CryptoRngCore, S: Scheme<Sha256Digest>> Disrupter<E, S>
where
    <S::Certificate as Read>::Cfg: Default,
{
    pub fn new(
        context: E,
        validator: PublicKey,
        scheme: S,
        participants: Set<PublicKey>,
        fuzz_input: FuzzInput,
    ) -> Self {
        Self {
            last_vote: 0,
            last_finalized: 0,
            last_nullified: 0,
            last_notarized: 0,
            latest_proposals: VecDeque::new(),
            context,
            validator,
            scheme,
            participants,
            fuzz_input,
        }
    }

    fn sample_inclusive(&mut self, lo: u64, hi: u64) -> u64 {
        if hi < lo {
            return lo;
        }
        if lo == 0 && hi == u64::MAX {
            return self.fuzz_input.random_u64();
        }
        let width = (hi - lo) + 1;
        lo + (self.fuzz_input.random_u64() % width)
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

    fn prune_latest_proposals(&mut self) {
        let active_range_size = self
            .last_notarized
            .max(self.last_vote)
            .saturating_sub(self.last_finalized)
            .saturating_add(1);

        let keep_count = (active_range_size.max(LATEST_PROPOSALS_MIN_LEN))
            .min(LATEST_PROPOSALS_MAX_LEN as u64) as usize;

        while self.latest_proposals.len() > keep_count {
            self.latest_proposals.pop_front();
        }
    }

    fn get_proposal(&mut self) -> Proposal<Sha256Digest> {
        let random_proposal = self.random_proposal();
        let v = self.random_view_for_proposal(self.last_vote);

        let proposal = match self.fuzz_input.random_byte() % 5 {
            0 => random_proposal,
            1 => {
                let len = self.latest_proposals.len();
                if len == 0 {
                    random_proposal
                } else {
                    let i = (self.fuzz_input.random_u64() % len as u64) as usize;
                    let p = self.latest_proposals.get(i).unwrap_or(&random_proposal);
                    self.proposal_with_view(p, v)
                }
            }
            2 => {
                let p = self.latest_proposals.back().unwrap_or(&random_proposal);
                self.proposal_with_view(p, v)
            }
            3 => {
                let p = self.latest_proposals.back().unwrap_or(&random_proposal);
                self.proposal_with_parent_view(p, v)
            }
            _ => {
                let Some(p) = self.latest_proposals.front() else {
                    return random_proposal;
                };
                self.proposal_with_view(p, v)
            }
        };

        self.prune_latest_proposals();
        proposal
    }

    fn proposal_with_view(
        &self,
        old: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(view)),
            old.parent,
            old.payload,
        )
    }

    fn proposal_with_parent_view(
        &self,
        old: &Proposal<Sha256Digest>,
        view: u64,
    ) -> Proposal<Sha256Digest> {
        Proposal::new(old.round, View::new(view), old.payload)
    }

    fn random_proposal(&mut self) -> Proposal<Sha256Digest> {
        let v = self.random_view_for_proposal(self.last_vote);
        Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(v)),
            View::new(self.random_parent_view(v)),
            self.random_payload(),
        )
    }

    fn random_view_for_proposal(&mut self, current_view: u64) -> u64 {
        let last_finalized = self.last_finalized;
        let last_notarized = self.last_notarized;
        let last_nullified = self.last_nullified;

        match self.fuzz_input.random_byte() % 7 {
            // Active band: [last_finalized, min(last_notarized, current_view)]
            0 => {
                let hi = last_notarized.min(current_view).max(last_finalized);
                self.sample_inclusive(last_finalized, hi)
            }
            1 => current_view,
            2 => current_view.saturating_add(1),
            3 => last_notarized.saturating_add(1),
            4 => last_notarized.saturating_add(2),
            5 => last_nullified.saturating_add(1),
            _ => self.fuzz_input.random_u64(),
        }
    }

    fn add_or_sample_at_or_above(&mut self, view: u64, delta: u64) -> u64 {
        view.checked_add(delta)
            .unwrap_or_else(|| self.sample_inclusive(view, u64::MAX))
    }

    fn random_view(&mut self, current_view: u64) -> u64 {
        let last_finalized = self.last_finalized;
        let last_notarized = self.last_notarized;
        let last_nullified = self.last_nullified;

        match self.fuzz_input.random_byte() % 7 {
            0 => {
                if last_finalized == 0 {
                    last_finalized
                } else {
                    self.sample_inclusive(0, last_finalized - 1)
                }
            }
            1 => {
                if current_view <= last_finalized {
                    last_finalized
                } else {
                    self.sample_inclusive(last_finalized, current_view)
                }
            }
            2 => {
                let hi = last_notarized.min(current_view).max(last_finalized);
                self.sample_inclusive(last_finalized, hi)
            }
            3 => {
                let k = 1 + (self.fuzz_input.random_byte() as u64 % 4);
                self.add_or_sample_at_or_above(current_view, k)
            }
            4 => {
                let k = 5 + (self.fuzz_input.random_byte() as u64 % 6);
                self.add_or_sample_at_or_above(current_view, k)
            }
            5 => {
                let base = current_view.max(last_nullified);
                let k = 1 + (self.fuzz_input.random_byte() as u64 % 10);
                self.add_or_sample_at_or_above(base, k)
            }
            _ => self.fuzz_input.random_u64(),
        }
    }

    fn random_parent_view(&mut self, view: u64) -> u64 {
        self.random_view(view.saturating_sub(1))
    }

    fn random_payload(&mut self) -> Sha256Digest {
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
        vote_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        certificate_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
    ) -> Handle<()> {
        let context = self.context.clone();
        context.spawn(|_| self.run(vote_network, certificate_network, resolver_network))
    }

    async fn run(
        mut self,
        vote_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        certificate_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
        resolver_network: (
            impl Sender<PublicKey = S::PublicKey>,
            impl Receiver<PublicKey = S::PublicKey>,
        ),
    ) {
        let (mut vote_sender, mut vote_receiver) = vote_network;
        let (mut cert_sender, mut cert_receiver) = certificate_network;
        let (mut resolver_sender, mut resolver_receiver) = resolver_network;

        loop {
            // Send disruptive messages across all channels
            match self.fuzz_input.random_byte() % 7 {
                0 => self.send_random_vote(&mut vote_sender).await,
                1 => self.send_proposal(&mut vote_sender).await,
                2 => {
                    // Equivocation attack: send multiple different proposals
                    self.send_proposal(&mut vote_sender).await;
                    self.send_proposal(&mut vote_sender).await;
                }
                3 => {
                    self.send_random_message(&mut cert_sender).await;
                }
                4 => {
                    self.send_random_message(&mut resolver_sender).await;
                }
                5 => {
                    // flood random victim
                    self.flood_victim(&mut vote_sender).await;
                }
                _ => {
                    // Send on multiple channels simultaneously
                    self.send_proposal(&mut vote_sender).await;
                    self.send_random_message(&mut cert_sender).await;
                    self.send_random_message(&mut resolver_sender).await;
                }
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
                result = resolver_receiver.recv().fuse() => {
                    if let Ok((_, msg)) = result {
                        self.handle_resolver(&mut resolver_sender, msg.to_vec()).await;
                    }
                },
                _ = self.context.sleep(TIMEOUT) => {
                    self.send_random_vote(&mut vote_sender).await;
                    self.send_random_message(&mut cert_sender).await;
                    self.send_random_message(&mut resolver_sender).await;
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
                self.latest_proposals.push_back(notarize.proposal.clone());

                if self.fuzz_input.random_bool() {
                    let mutated = self.mutate_bytes(&msg);
                    let _ = sender.send(Recipients::All, mutated.into(), true).await;
                } else {
                    let proposal = self.mutate_proposal(&notarize.proposal);
                    if let Some(v) = Notarize::sign(&self.scheme, proposal) {
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
                    if let Some(v) = Finalize::sign(&self.scheme, proposal) {
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
                    if let Some(v) = Nullify::<S>::sign::<Sha256Digest>(&self.scheme, round) {
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

    async fn handle_resolver(&mut self, sender: &mut impl Sender, msg: Vec<u8>) {
        // Randomly forward, drop, or respond with malformed data to resolver requests
        match self.fuzz_input.random_byte() % 4 {
            0 => {
                let _ = sender.send(Recipients::All, Bytes::from(msg), true).await;
            }
            1 => {
                // Send mutated resolver response
                let mutated = self.mutate_bytes(&msg);
                let _ = sender.send(Recipients::All, mutated.into(), true).await;
            }
            2 => {
                // Send random garbage as resolver response
                let garbage = self.bytes();
                let _ = sender.send(Recipients::All, garbage.into(), true).await;
            }
            _ => {
                // Drop the message (ignore resolver request)
            }
        }
    }

    fn mutate_proposal(&mut self, original: &Proposal<Sha256Digest>) -> Proposal<Sha256Digest> {
        let epoch = original.epoch();
        let base_view_u64 = original.view().get();

        let mut view = original.view();
        let mut parent = original.parent;
        let mut payload = original.payload;

        match self.mutation() {
            Mutation::Payload => {
                payload = self.random_payload();
            }
            Mutation::View => {
                view = View::new(self.random_view(base_view_u64));
            }
            Mutation::Parent => {
                parent = View::new(self.random_parent_view(base_view_u64));
            }
            Mutation::All => {
                view = View::new(self.random_view(base_view_u64));
                parent = View::new(self.random_parent_view(base_view_u64));
                payload = self.random_payload();
            }
        }

        Proposal::new(Round::new(epoch, view), parent, payload)
    }

    async fn flood_victim(&mut self, sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        let Some(me) = self.scheme.me() else {
            return;
        };

        let participants: Vec<_> = self
            .scheme
            .participants()
            .iter()
            .enumerate()
            .filter(|(idx, _)| u32::try_from(*idx).ok() != Some(me))
            .map(|(_, pk)| pk.clone())
            .collect();

        if participants.is_empty() {
            return;
        }

        let idx = (self.fuzz_input.random_u64() as usize) % participants.len();
        let victim = participants[idx].clone();

        // Send 10 messages to victim
        for _ in 0..10 {
            let proposal = self.get_proposal();
            let msg = proposal.encode().into();
            let _ = sender
                .send(Recipients::One(victim.clone()), msg, true)
                .await;
            // Also send a random vote directly to the victim to vary disruption.
            self.send_random_vote_to(sender, Recipients::One(victim.clone()))
                .await;
        }
    }

    async fn send_proposal(&mut self, sender: &mut impl Sender) {
        let proposal = self.get_proposal();
        let msg = proposal.encode().into();
        let _ = sender.send(Recipients::All, msg, true).await;
    }

    async fn send_random_message(&mut self, sender: &mut impl Sender) {
        let cert = self.bytes();
        let _ = sender.send(Recipients::All, cert.into(), true).await;
    }

    async fn send_random_vote(&mut self, sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        self.send_random_vote_to(sender, Recipients::All).await;
    }

    async fn send_random_vote_to(
        &mut self,
        sender: &mut impl Sender<PublicKey = S::PublicKey>,
        recipients: Recipients<S::PublicKey>,
    ) {
        if self.participants.index(&self.validator).is_none() {
            let bytes = self.bytes();
            let _ = sender.send(Recipients::All, bytes.into(), true).await;
            return;
        }

        let proposal = self.get_proposal();

        match self.message() {
            Message::Notarize => {
                if let Some(vote) = Notarize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Notarize(vote).encode().into();
                    let _ = sender.send(recipients, msg, true).await;
                }
            }
            Message::Finalize => {
                if let Some(vote) = Finalize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Finalize(vote).encode().into();
                    let _ = sender.send(recipients, msg, true).await;
                }
            }
            Message::Nullify => {
                let round = Round::new(
                    Epoch::new(EPOCH),
                    View::new(self.random_view(self.last_vote)),
                );
                if let Some(vote) = Nullify::<S>::sign::<Sha256Digest>(&self.scheme, round) {
                    let msg = Vote::<S, Sha256Digest>::Nullify(vote).encode().into();
                    let _ = sender.send(recipients, msg, true).await;
                }
            }
            Message::Random => {
                let bytes = self.bytes();
                let _ = sender.send(recipients, bytes.into(), true).await;
            }
        }
    }
}
