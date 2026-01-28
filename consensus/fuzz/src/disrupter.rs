use crate::{strategy::Strategy, types::Message, FuzzInput, EPOCH};
use commonware_codec::{Encode, Read, ReadExt};
use commonware_consensus::{
    simplex::{
        scheme::Scheme,
        types::{Certificate, Finalize, Notarize, Nullify, Proposal, Vote},
    },
    types::{Epoch, Participant, Round, View},
    Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, IoBuf, Spawner};
use rand_core::CryptoRngCore;
use std::{collections::VecDeque, time::Duration};

const TIMEOUT: Duration = Duration::from_millis(100);
const LATEST_PROPOSALS_MIN_LEN: u64 = 10;
const LATEST_PROPOSALS_MAX_LEN: usize = 100;

/// Byzantine actor that disrupts consensus by sending malformed/mutated messages.
pub struct Disrupter<
    E: Clock + Spawner + CryptoRngCore,
    S: Scheme<Sha256Digest>,
    St: Strategy + 'static,
> {
    context: E,
    scheme: S,
    fuzz_input: FuzzInput,
    strategy: St,
    last_vote_view: u64,
    last_finalized_view: u64,
    last_nullified_view: u64,
    last_notarized_view: u64,
    latest_proposals: VecDeque<Proposal<Sha256Digest>>,
}

impl<E: Clock + Spawner + CryptoRngCore, S: Scheme<Sha256Digest>, St: Strategy + 'static>
    Disrupter<E, S, St>
where
    <S::Certificate as Read>::Cfg: Default,
{
    pub fn new(context: E, scheme: S, fuzz_input: FuzzInput, strategy: St) -> Self {
        Self {
            last_vote_view: 0,
            last_finalized_view: 0,
            last_nullified_view: 0,
            last_notarized_view: 0,
            latest_proposals: VecDeque::new(),
            context,
            scheme,
            fuzz_input,
            strategy,
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
            .last_notarized_view
            .max(self.last_vote_view)
            .saturating_sub(self.last_finalized_view)
            .saturating_add(1);

        let keep_count = (active_range_size.max(LATEST_PROPOSALS_MIN_LEN))
            .min(LATEST_PROPOSALS_MAX_LEN as u64) as usize;

        while self.latest_proposals.len() > keep_count {
            self.latest_proposals.pop_front();
        }
    }

    fn get_proposal(&mut self) -> Proposal<Sha256Digest> {
        let payload_source = self
            .strategy
            .repeated_proposal_index(&self.fuzz_input, self.latest_proposals.len())
            .and_then(|idx| self.latest_proposals.get(idx).cloned())
            .unwrap_or_else(|| {
                self.strategy.random_proposal(
                    &self.fuzz_input,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                )
            });

        let view = self.strategy.random_view_for_proposal(
            &self.fuzz_input,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        let parent_view = self.strategy.random_parent_view(
            &self.fuzz_input,
            view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        let proposal = Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(view)),
            View::new(parent_view),
            payload_source.payload,
        );

        self.prune_latest_proposals();
        proposal
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
                    // Equivocation style: send multiple different proposals
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
                        self.handle_vote(&mut vote_sender, msg.into()).await;
                    }
                },
                result = cert_receiver.recv().fuse() => {
                    if let Ok((_, msg)) = result {
                        self.handle_certificate(&mut cert_sender, msg.into()).await;
                    }
                },
                result = resolver_receiver.recv().fuse() => {
                    if let Ok((_, msg)) = result {
                        self.handle_resolver(&mut resolver_sender, msg.into()).await;
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
        // Optionally send mutated vote
        if self.fuzz_input.random_bool() {
            let mutated = self.mutate_bytes(&msg);
            let _ = sender.send(Recipients::All, mutated, true).await;
        }

        let Ok(vote) = Vote::<S, Sha256Digest>::read(&mut msg.as_slice()) else {
            return;
        };
        self.last_vote_view = vote.view().get();
        match vote {
            Vote::Notarize(notarize) => {
                self.latest_proposals.push_back(notarize.proposal.clone());

                let proposal = self.strategy.mutate_proposal(
                    &self.fuzz_input,
                    &notarize.proposal,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                if let Some(v) = Notarize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Notarize(v).encode();
                    let _ = sender.send(Recipients::All, msg, true).await;
                }
            }
            Vote::Finalize(finalize) => {
                let proposal = self.strategy.mutate_proposal(
                    &self.fuzz_input,
                    &finalize.proposal,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                if let Some(v) = Finalize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Finalize(v).encode();
                    let _ = sender.send(Recipients::All, msg, true).await;
                }
            }
            Vote::Nullify(_) => {
                let v = self.strategy.mutate_nullify_view(
                    &self.fuzz_input,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let round = Round::new(Epoch::new(EPOCH), View::new(v));
                if let Some(v) = Nullify::<S>::sign::<Sha256Digest>(&self.scheme, round) {
                    let msg = Vote::<S, Sha256Digest>::Nullify(v).encode();
                    let _ = sender.send(Recipients::All, msg, true).await;
                }
            }
        }
    }

    async fn handle_certificate(&mut self, sender: &mut impl Sender, msg: Vec<u8>) {
        // Optionally send mutated certificate
        if self.fuzz_input.random_bool() {
            let cert = self
                .strategy
                .mutate_certificate_bytes(&self.fuzz_input, &msg);
            let _ = sender.send(Recipients::All, &cert[..], true).await;
        }

        let cfg = self.scheme.certificate_codec_config();
        let Ok(cert) = Certificate::<S, Sha256Digest>::read_cfg(&mut msg.as_slice(), &cfg) else {
            return;
        };

        match cert {
            Certificate::Notarization(n) => {
                self.last_notarized_view = n.view().get();
            }
            Certificate::Nullification(n) => {
                self.last_nullified_view = n.view().get();
            }
            Certificate::Finalization(f) => {
                self.last_finalized_view = f.view().get();
            }
        }
    }

    async fn handle_resolver(&mut self, sender: &mut impl Sender, msg: Vec<u8>) {
        // Optionally send malformed resolver data
        if self.fuzz_input.random_bool() {
            let mutated = self.strategy.mutate_resolver_bytes(&self.fuzz_input, &msg);
            let _ = sender
                .send(Recipients::All, IoBuf::from(mutated), true)
                .await;
        }
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
            .filter(|(idx, _)| Participant::from_usize(*idx) != me)
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
            let proposal = self.strategy.mutate_proposal(
                &self.fuzz_input,
                &proposal,
                self.last_vote_view,
                self.last_finalized_view,
                self.last_notarized_view,
                self.last_nullified_view,
            );
            let msg = proposal.encode();
            let _ = sender
                .send(Recipients::One(victim.clone()), msg, true)
                .await;
        }
    }

    async fn send_proposal(&mut self, sender: &mut impl Sender) {
        let proposal = self.get_proposal();
        let proposal = self.strategy.mutate_proposal(
            &self.fuzz_input,
            &proposal,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );
        let msg = proposal.encode();
        let _ = sender.send(Recipients::All, msg, true).await;
    }

    async fn send_random_message(&mut self, sender: &mut impl Sender) {
        let cert = self.bytes();
        let _ = sender.send(Recipients::All, IoBuf::from(cert), true).await;
    }

    async fn send_random_vote(&mut self, sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        self.send_random_vote_to(sender, Recipients::All).await;
    }

    async fn send_random_vote_to(
        &mut self,
        sender: &mut impl Sender<PublicKey = S::PublicKey>,
        recipients: Recipients<S::PublicKey>,
    ) {
        let proposal = self.get_proposal();

        match self.message() {
            Message::Notarize => {
                let proposal = self.strategy.mutate_proposal(
                    &self.fuzz_input,
                    &proposal,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                if let Some(vote) = Notarize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Notarize(vote).encode();
                    let _ = sender.send(recipients, msg, true).await;
                }
            }
            Message::Finalize => {
                let proposal = self.strategy.mutate_proposal(
                    &self.fuzz_input,
                    &proposal,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                if let Some(vote) = Finalize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Finalize(vote).encode();
                    let _ = sender.send(recipients, msg, true).await;
                }
            }
            Message::Nullify => {
                let view = self.strategy.mutate_nullify_view(
                    &self.fuzz_input,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let round = Round::new(Epoch::new(EPOCH), View::new(view));
                if let Some(vote) = Nullify::<S>::sign::<Sha256Digest>(&self.scheme, round) {
                    let msg = Vote::<S, Sha256Digest>::Nullify(vote).encode();
                    let _ = sender.send(recipients, msg, true).await;
                }
            }
            Message::Random => {
                let bytes = self.bytes();
                let _ = sender.send(recipients, bytes, true).await;
            }
        }
    }
}
