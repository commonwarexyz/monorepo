use crate::{
    EPOCH,
    block_relay::{self, Relay as BlockRelay},
    strategy::Strategy,
    types::Message,
};
use commonware_codec::{Encode, Read, ReadExt};
use commonware_consensus::{
    Viewable,
    simplex::{
        scheme::Scheme,
        types::{Certificate, Finalize, Notarize, Nullify, Proposal, Vote},
    },
    types::{Epoch, Participant, Round, View},
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, ContextCell, Handle, IoBuf, Spawner, spawn_cell};
use commonware_utils::ordered::Quorum;
use rand::RngExt as _;
use rand_core::CryptoRng;
use std::{
    collections::VecDeque,
    future::{Future as _, poll_fn},
    sync::Arc,
    task::Poll,
    time::Duration,
};

const TIMEOUT: Duration = Duration::from_millis(100);
const LATEST_PROPOSALS_MIN_LEN: u64 = 10;
const LATEST_PROPOSALS_MAX_LEN: usize = 100;

/// Poll one receive operation without waiting when the channel is empty.
async fn try_receive<R: Receiver>(
    receiver: &mut R,
) -> Option<commonware_p2p::Message<R::PublicKey>> {
    let mut receive = std::pin::pin!(receiver.recv());
    poll_fn(|context| {
        Poll::Ready(match receive.as_mut().poll(context) {
            Poll::Ready(result) => result.ok(),
            Poll::Pending => None,
        })
    })
    .await
}

/// Byzantine actor that disrupts consensus by sending malformed/mutated messages.
pub struct Disrupter<
    E: Clock + Spawner + CryptoRng,
    S: Scheme<Sha256Digest>,
    St: Strategy + 'static,
> {
    context: ContextCell<E>,
    scheme: S,
    strategy: St,
    faulty_views: Option<Vec<View>>,
    /// Epoch stamped on every proposal/nullify this disrupter emits. Defaults to
    /// the harness-wide [`EPOCH`]; callers that run honest engines in a different
    /// epoch (e.g. the marshal liveness target) pass their epoch so the byzantine
    /// messages are admitted into the same consensus instance.
    epoch: Epoch,
    last_vote_view: u64,
    last_finalized_view: u64,
    last_nullified_view: u64,
    last_notarized_view: u64,
    latest_proposals: VecDeque<Proposal<Sha256Digest>>,
    block_relay: Option<Arc<BlockRelay<S::PublicKey>>>,
    block_relay_tag: Option<u64>,
}

impl<E: Clock + Spawner + CryptoRng, S: Scheme<Sha256Digest>, St: Strategy + 'static>
    Disrupter<E, S, St>
where
    <S::Certificate as Read>::Cfg: Default,
{
    pub fn new(context: E, scheme: S, strategy: St, required_containers: u64) -> Self {
        Self::new_with_epoch(
            context,
            scheme,
            strategy,
            required_containers,
            Epoch::new(EPOCH),
        )
    }

    /// Like [`Self::new`] but stamps emitted messages with `epoch` instead of the
    /// harness-wide [`EPOCH`].
    pub fn new_with_epoch(
        context: E,
        scheme: S,
        strategy: St,
        required_containers: u64,
        epoch: Epoch,
    ) -> Self {
        Self::new_with_epoch_and_relay(context, scheme, strategy, required_containers, epoch, None)
    }

    /// Like [`Self::new_with_epoch`] but also publishes generated mock blocks
    /// through the fuzz-local block relay.
    pub(crate) fn new_with_epoch_and_relay(
        context: E,
        scheme: S,
        strategy: St,
        required_containers: u64,
        epoch: Epoch,
        block_relay: Option<Arc<BlockRelay<S::PublicKey>>>,
    ) -> Self {
        Self::new_with_epoch_relay_and_tag(
            context,
            scheme,
            strategy,
            required_containers,
            epoch,
            block_relay,
            None,
        )
    }

    /// Like [`Self::new_with_epoch_and_relay`] but tags generated block relay
    /// broadcasts as one half of a simulated twin identity.
    pub(crate) fn new_with_epoch_relay_and_tag(
        mut context: E,
        scheme: S,
        strategy: St,
        required_containers: u64,
        epoch: Epoch,
        block_relay: Option<Arc<BlockRelay<S::PublicKey>>>,
        block_relay_tag: Option<u64>,
    ) -> Self {
        let faulty_views = strategy.disrupter_faults(required_containers, &mut context);
        Self {
            last_vote_view: 0,
            last_finalized_view: 0,
            last_nullified_view: 0,
            last_notarized_view: 0,
            latest_proposals: VecDeque::new(),
            context: ContextCell::new(context),
            scheme,
            strategy,
            faulty_views,
            epoch,
            block_relay,
            block_relay_tag,
        }
    }

    /// Re-stamp a (possibly strategy-mutated) proposal with this disrupter's
    /// epoch. `strategy.rs` hardcodes [`EPOCH`] when rebuilding rounds, so its
    /// output is normalized here before signing/sending.
    fn normalize_epoch(&self, proposal: Proposal<Sha256Digest>) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(self.epoch, proposal.view()),
            proposal.parent,
            proposal.payload,
        )
    }

    fn attach_mock_block(
        &mut self,
        proposal: Proposal<Sha256Digest>,
        recipients: Recipients<S::PublicKey>,
    ) -> Proposal<Sha256Digest> {
        let proposal = self.normalize_epoch(proposal);
        let Some(block_relay) = &self.block_relay else {
            return proposal;
        };
        if self.strategy.preserves_proposal_payload() {
            return proposal;
        }
        let Some(me) = self.scheme.me() else {
            return proposal;
        };
        let Some(sender) = self.scheme.participants().key(me).cloned() else {
            return proposal;
        };
        let Some((proposal, contents)) =
            block_relay::genesis_backed_mock_block(&proposal, self.context.random::<u64>())
        else {
            return proposal;
        };
        match self.block_relay_tag {
            Some(tag) => block_relay.broadcast_with_tag(
                &sender,
                tag,
                recipients,
                (proposal.payload, contents),
            ),
            None => block_relay.broadcast(&sender, recipients, (proposal.payload, contents)),
        }
        proposal
    }

    fn message(&mut self) -> Message {
        match (self.context.random::<u8>()) % 4 {
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

    fn current_view(&self) -> u64 {
        self.last_vote_view
            .max(self.last_notarized_view)
            .max(self.last_finalized_view)
            .max(self.last_nullified_view)
    }

    fn is_faulty_view(&self, view: u64) -> bool {
        self.faulty_views
            .as_ref()
            .is_none_or(|views| views.iter().any(|faulty| faulty.get() == view))
    }

    fn get_proposal(&mut self) -> Proposal<Sha256Digest> {
        let proposals_len = self.latest_proposals.len();
        let payload_source = self
            .strategy
            .repeated_proposal_index(self.context.as_mut(), proposals_len)
            .and_then(|idx| self.latest_proposals.get(idx).cloned())
            .unwrap_or_else(|| {
                self.strategy.random_proposal(
                    self.context.as_mut(),
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                )
            });

        let view = self.strategy.random_view_for_proposal(
            self.context.as_mut(),
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        let parent_view = self.strategy.random_parent_view(
            self.context.as_mut(),
            view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        let proposal = Proposal::new(
            Round::new(self.epoch, View::new(view)),
            View::new(parent_view),
            payload_source.payload,
        );

        self.prune_latest_proposals();
        proposal
    }

    fn mutate_bytes(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return vec![0];
        }

        let mut result = input.to_vec();
        let pos = self.context.random_range(0..result.len());

        match (self.context.random::<u8>()) % 5 {
            0 => result[pos] = result[pos].wrapping_add(1),
            1 => result[pos] = result[pos].wrapping_sub(1),
            2 => result[pos] ^= 0xFF,
            3 => result[pos] = 0,
            _ => result[pos] = 0xFF,
        }

        result
    }

    pub fn start(
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
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(vote_network, certificate_network, resolver_network)
        )
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
            // Emit a sampled proactive vote action.
            match (self.context.random::<u8>()) % 7 {
                0 => self.send_random_vote(&mut vote_sender).await,
                1 => self.send_proposal_vote(&mut vote_sender).await,
                2 => {
                    // Equivocation style: send multiple different proposals
                    self.send_proposal_vote(&mut vote_sender).await;
                    self.send_proposal_vote(&mut vote_sender).await;
                }
                3 | 4 => self.send_random_vote(&mut vote_sender).await,
                5 => {
                    // flood random victim
                    self.flood_victim(&mut vote_sender).await;
                }
                _ => {
                    // Burst multiple vote actions.
                    self.send_proposal_vote(&mut vote_sender).await;
                    self.send_random_vote(&mut vote_sender).await;
                    self.send_random_vote(&mut vote_sender).await;
                }
            }

            let mut received = false;
            loop {
                let mut pass_received = false;
                if let Some((_, message)) = try_receive(&mut vote_receiver).await {
                    self.handle_vote(&mut vote_sender, message.into()).await;
                    pass_received = true;
                }
                if let Some((_, message)) = try_receive(&mut cert_receiver).await {
                    self.handle_certificate(&mut cert_sender, message.into())
                        .await;
                    pass_received = true;
                }
                if let Some((_, message)) = try_receive(&mut resolver_receiver).await {
                    self.handle_resolver(&mut resolver_sender, message.into())
                        .await;
                    pass_received = true;
                }
                if !pass_received {
                    break;
                }
                received = true;
            }

            if !received {
                // Keep non-finalizing configurations from spinning at one simulated timestamp.
                self.context.sleep(TIMEOUT).await;
            }
        }
    }

    async fn handle_vote(&mut self, sender: &mut impl Sender, msg: Vec<u8>) {
        let Ok(vote) = Vote::<S, Sha256Digest>::read(&mut msg.as_slice()) else {
            return;
        };

        // Update the state for effective fuzzing
        self.last_vote_view = self.last_vote_view.max(vote.view().get());
        if let Vote::Notarize(notarize) = &vote {
            self.latest_proposals.push_back(notarize.proposal.clone());
        }

        if !self.is_faulty_view(self.last_vote_view) {
            return;
        }

        // Optionally send mutated vote
        if self.context.random_bool(0.5) {
            let mutated = self.mutate_bytes(&msg);
            let _ = sender.send(Recipients::All, mutated, true);
        }
        match vote {
            Vote::Notarize(notarize) => {
                let proposal = self.strategy.mutate_proposal(
                    self.context.as_mut(),
                    &notarize.proposal,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let proposal = self.attach_mock_block(proposal, Recipients::All);
                if let Some(v) = Notarize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Notarize(v).encode();
                    let _ = sender.send(Recipients::All, msg, true);
                }
            }
            Vote::Finalize(finalize) => {
                let proposal = self.strategy.mutate_proposal(
                    self.context.as_mut(),
                    &finalize.proposal,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let proposal = self.attach_mock_block(proposal, Recipients::All);
                if let Some(v) = Finalize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Finalize(v).encode();
                    let _ = sender.send(Recipients::All, msg, true);
                }
            }
            Vote::Nullify(_) => {
                let v = self.strategy.mutate_nullify_view(
                    self.context.as_mut(),
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let round = Round::new(self.epoch, View::new(v));
                if let Some(v) = Nullify::<S>::sign::<Sha256Digest>(&self.scheme, round) {
                    let msg = Vote::<S, Sha256Digest>::Nullify(v).encode();
                    let _ = sender.send(Recipients::All, msg, true);
                }
            }
        }
    }

    async fn handle_certificate(&mut self, sender: &mut impl Sender, msg: Vec<u8>) {
        let cfg = self.scheme.certificate_codec_config();
        let Ok(cert) = Certificate::<S, Sha256Digest>::read_cfg(&mut msg.as_slice(), &cfg) else {
            return;
        };

        let view = match cert {
            Certificate::Notarization(n) => {
                let view = n.view().get();
                self.last_notarized_view = self.last_notarized_view.max(view);
                view
            }
            Certificate::Nullification(n) => {
                let view = n.view().get();
                self.last_nullified_view = self.last_nullified_view.max(view);
                view
            }
            Certificate::Finalization(f) => {
                let view = f.view().get();
                self.last_finalized_view = self.last_finalized_view.max(view);
                view
            }
        };

        if !self.is_faulty_view(view) {
            return;
        }

        // Optionally send mutated certificate
        if self.context.random_bool(0.5) {
            let cert = self
                .strategy
                .mutate_certificate_bytes(self.context.as_mut(), &msg);
            let _ = sender.send(Recipients::All, cert, true);
        }
    }

    async fn handle_resolver(&mut self, sender: &mut impl Sender, msg: Vec<u8>) {
        if !self.is_faulty_view(self.current_view()) {
            return;
        }
        // Optionally send malformed resolver data
        if self.context.random_bool(0.5) {
            let mutated = self
                .strategy
                .mutate_resolver_bytes(self.context.as_mut(), &msg);
            let _ = sender.send(Recipients::All, IoBuf::from(mutated), true);
        }
    }

    async fn flood_victim(&mut self, sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        if !self.is_faulty_view(self.current_view()) {
            return;
        }
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

        let idx = self.context.random_range(0..participants.len());
        let victim = participants[idx].clone();

        // Send 10 messages to victim
        for _ in 0..10 {
            let proposal = self.get_proposal();
            let proposal = self.strategy.mutate_proposal(
                self.context.as_mut(),
                &proposal,
                self.last_vote_view,
                self.last_finalized_view,
                self.last_notarized_view,
                self.last_nullified_view,
            );
            let proposal = self.attach_mock_block(proposal, Recipients::One(victim.clone()));
            if let Some(vote) = Notarize::sign(&self.scheme, proposal) {
                let message = Vote::<S, Sha256Digest>::Notarize(vote).encode();
                let _ = sender.send(Recipients::One(victim.clone()), message, true);
            }
        }
    }

    async fn send_proposal_vote(&mut self, sender: &mut impl Sender) {
        if !self.is_faulty_view(self.current_view()) {
            return;
        }
        let proposal = self.get_proposal();
        let proposal = self.strategy.mutate_proposal(
            self.context.as_mut(),
            &proposal,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );
        let proposal = self.attach_mock_block(proposal, Recipients::All);
        if let Some(vote) = Notarize::sign(&self.scheme, proposal) {
            let message = Vote::<S, Sha256Digest>::Notarize(vote).encode();
            let _ = sender.send(Recipients::All, message, true);
        }
    }

    async fn send_random_vote(&mut self, sender: &mut impl Sender<PublicKey = S::PublicKey>) {
        self.send_random_vote_to(sender, Recipients::All).await;
    }

    async fn send_random_vote_to(
        &mut self,
        sender: &mut impl Sender<PublicKey = S::PublicKey>,
        recipients: Recipients<S::PublicKey>,
    ) {
        if !self.is_faulty_view(self.current_view()) {
            return;
        }
        let proposal = self.get_proposal();

        match self.message() {
            Message::Notarize => {
                let proposal = self.strategy.mutate_proposal(
                    self.context.as_mut(),
                    &proposal,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let proposal = self.attach_mock_block(proposal, recipients.clone());
                if let Some(vote) = Notarize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Notarize(vote).encode();
                    let _ = sender.send(recipients, msg, true);
                }
            }
            Message::Finalize => {
                let proposal = self.strategy.mutate_proposal(
                    self.context.as_mut(),
                    &proposal,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let proposal = self.attach_mock_block(proposal, recipients.clone());
                if let Some(vote) = Finalize::sign(&self.scheme, proposal) {
                    let msg = Vote::<S, Sha256Digest>::Finalize(vote).encode();
                    let _ = sender.send(recipients, msg, true);
                }
            }
            Message::Nullify => {
                let view = self.strategy.mutate_nullify_view(
                    self.context.as_mut(),
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let round = Round::new(self.epoch, View::new(view));
                if let Some(vote) = Nullify::<S>::sign::<Sha256Digest>(&self.scheme, round) {
                    let msg = Vote::<S, Sha256Digest>::Nullify(vote).encode();
                    let _ = sender.send(recipients, msg, true);
                }
            }
            Message::Random => {
                let proposal = self.strategy.mutate_proposal(
                    self.context.as_mut(),
                    &proposal,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                );
                let proposal = self.attach_mock_block(proposal, recipients.clone());
                if let Some(vote) = Notarize::sign(&self.scheme, proposal) {
                    let message = Vote::<S, Sha256Digest>::Notarize(vote).encode();
                    let _ = sender.send(recipients, message, true);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex_certificate_mock as cert_mock,
        strategy::{HeaderMutation, HeaderScope, SmallScope, SplitHeader},
    };
    use commonware_runtime::{Runner as _, Supervisor as _};

    fn genesis_parent_proposal(payload: Sha256Digest) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(1)),
            View::new(0),
            payload,
        )
    }

    #[test]
    fn attach_mock_block_preserves_header_strategy_payloads() {
        let executor = commonware_runtime::deterministic::Runner::seeded(17);
        executor.start(|mut context| async move {
            let schemes = cert_mock::fixture(&mut context, b"disrupter_attach", 4).schemes;
            let payload = Sha256Digest::from([7u8; 32]);
            let proposal = genesis_parent_proposal(payload);

            let relay = Arc::new(BlockRelay::new());
            let mut header = Disrupter::new_with_epoch_and_relay(
                context.child("header"),
                schemes[0].clone(),
                HeaderScope {
                    fault_rounds: 1,
                    fault_rounds_bound: 1,
                    mutation: HeaderMutation::PreviousParent,
                },
                1,
                Epoch::new(EPOCH),
                Some(relay.clone()),
            );
            let attached = header.attach_mock_block(proposal.clone(), Recipients::All);
            assert_eq!(attached.payload, payload);

            let mut split = Disrupter::new_with_epoch_and_relay(
                context.child("split"),
                schemes[0].clone(),
                SplitHeader {
                    fault_rounds: 1,
                    fault_rounds_bound: 1,
                },
                1,
                Epoch::new(EPOCH),
                Some(relay.clone()),
            );
            let attached = split.attach_mock_block(proposal.clone(), Recipients::All);
            assert_eq!(attached.payload, payload);

            let mut small = Disrupter::new_with_epoch_and_relay(
                context.child("small"),
                schemes[0].clone(),
                SmallScope {
                    fault_rounds: 1,
                    fault_rounds_bound: 1,
                },
                1,
                Epoch::new(EPOCH),
                Some(relay),
            );
            let attached = small.attach_mock_block(proposal, Recipients::All);
            assert_ne!(attached.payload, payload);
        });
    }
}
