use super::strategy::MinimmitStrategy;
use crate::{simplex::types::Message, EPOCH};
use commonware_codec::{Encode, Read, ReadExt};
use commonware_consensus::{
    minimmit::{
        scheme::Scheme,
        types::{Certificate, Notarize, Nullify, Proposal, Vote},
    },
    types::{Epoch, Participant, Round, View},
    Viewable,
};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Clock, Handle, IoBuf, Spawner};
use rand::Rng;
use rand_core::CryptoRngCore;
use std::{collections::VecDeque, time::Duration};

const TIMEOUT: Duration = Duration::from_millis(100);
const LATEST_PROPOSALS_MIN_LEN: u64 = 10;
const LATEST_PROPOSALS_MAX_LEN: usize = 100;

/// Byzantine actor that disrupts minimmit consensus by sending malformed/mutated messages.
pub struct MinimmitDisrupter<
    E: Clock + Spawner + CryptoRngCore,
    S: Scheme<Sha256Digest>,
    St: MinimmitStrategy + 'static,
> {
    context: E,
    scheme: S,
    strategy: St,
    fault_offset: u64,
    last_vote_view: u64,
    last_finalized_view: u64,
    last_nullified_view: u64,
    last_notarized_view: u64,
    latest_proposals: VecDeque<Proposal<Sha256Digest>>,
}

impl<
        E: Clock + Spawner + CryptoRngCore,
        S: Scheme<Sha256Digest>,
        St: MinimmitStrategy + 'static,
    > MinimmitDisrupter<E, S, St>
where
    <S::Certificate as Read>::Cfg: Default,
{
    pub fn new(mut context: E, scheme: S, strategy: St) -> Self {
        let fault_offset = context.next_u64();
        Self {
            last_vote_view: 0,
            last_finalized_view: 0,
            last_nullified_view: 0,
            last_notarized_view: 0,
            latest_proposals: VecDeque::new(),
            context,
            scheme,
            strategy,
            fault_offset,
        }
    }

    fn message(&mut self) -> Message {
        match (self.context.gen::<u8>()) % 3 {
            0 => Message::Notarize,
            1 => Message::Nullify,
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
        let Some((faults, bound)) = self.strategy.fault_bounds() else {
            return true;
        };
        if bound == 0 {
            return false;
        }
        let faults = faults.min(bound);
        if faults == 0 {
            return false;
        }
        let round_fault = self.fault_offset.wrapping_add(view) % bound;
        round_fault < faults
    }

    fn get_proposal(&mut self) -> Proposal<Sha256Digest> {
        let proposals_len = self.latest_proposals.len();
        let payload_source = self
            .strategy
            .repeated_proposal_index(&mut self.context, proposals_len)
            .and_then(|idx| self.latest_proposals.get(idx).cloned())
            .unwrap_or_else(|| {
                self.strategy.random_proposal(
                    &mut self.context,
                    self.last_vote_view,
                    self.last_finalized_view,
                    self.last_notarized_view,
                    self.last_nullified_view,
                )
            });

        let view = self.strategy.random_view_for_proposal(
            &mut self.context,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        let parent_view = self.strategy.random_parent_view(
            &mut self.context,
            view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );

        let proposal = Proposal::new(
            Round::new(Epoch::new(EPOCH), View::new(view)),
            View::new(parent_view),
            payload_source.parent_payload,
            payload_source.payload,
        );

        self.prune_latest_proposals();
        proposal
    }

    fn bytes(&mut self) -> Vec<u8> {
        let len = self.context.gen::<u8>();
        let mut bytes = vec![0u8; len as usize];
        self.context.fill_bytes(&mut bytes);
        bytes
    }

    fn mutate_bytes(&mut self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return vec![0];
        }

        let mut result = input.to_vec();
        let pos = self.context.gen_range(0..result.len());

        match (self.context.gen::<u8>()) % 5 {
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
            match (self.context.gen::<u8>()) % 7 {
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
                result = vote_receiver.recv() => {
                    if let Ok((_, msg)) = result {
                        self.handle_vote(&mut vote_sender, msg.into()).await;
                    }
                },
                result = cert_receiver.recv() => {
                    if let Ok((_, msg)) = result {
                        self.handle_certificate(&mut cert_sender, msg.into()).await;
                    }
                },
                result = resolver_receiver.recv() => {
                    if let Ok((_, msg)) = result {
                        self.handle_resolver(&mut resolver_sender, msg.into()).await;
                    }
                },
                _ = self.context.sleep(TIMEOUT) => {
                    self.send_random_vote(&mut vote_sender).await;
                    self.send_random_message(&mut cert_sender).await;
                    self.send_random_message(&mut resolver_sender).await;
                },
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
        if self.context.gen_bool(0.5) {
            let mutated = self.mutate_bytes(&msg);
            let _ = sender.send(Recipients::All, mutated, true).await;
        }
        match vote {
            Vote::Notarize(notarize) => {
                let proposal = self.strategy.mutate_proposal(
                    &mut self.context,
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
            Vote::Nullify(_) => {
                let v = self.strategy.mutate_nullify_view(
                    &mut self.context,
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
        let cfg = self.scheme.certificate_codec_config();
        let Ok(cert) = Certificate::<S, Sha256Digest>::read_cfg(&mut msg.as_slice(), &cfg) else {
            return;
        };

        let view = match cert {
            Certificate::MNotarization(n) => {
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
        if self.context.gen_bool(0.5) {
            let cert = self
                .strategy
                .mutate_certificate_bytes(&mut self.context, &msg);
            let _ = sender.send(Recipients::All, cert, true).await;
        }
    }

    async fn handle_resolver(&mut self, sender: &mut impl Sender, msg: Vec<u8>) {
        if !self.is_faulty_view(self.current_view()) {
            return;
        }
        // Optionally send malformed resolver data
        if self.context.gen_bool(0.5) {
            let mutated = self.strategy.mutate_resolver_bytes(&mut self.context, &msg);
            let _ = sender
                .send(Recipients::All, IoBuf::from(mutated), true)
                .await;
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

        let idx = self.context.gen_range(0..participants.len());
        let victim = participants[idx].clone();

        // Send 10 messages to victim
        for _ in 0..10 {
            let proposal = self.get_proposal();
            let proposal = self.strategy.mutate_proposal(
                &mut self.context,
                &proposal,
                self.last_vote_view,
                self.last_finalized_view,
                self.last_notarized_view,
                self.last_nullified_view,
            );
            if let Some(vote) = Notarize::sign(&self.scheme, proposal) {
                let msg = Vote::<S, Sha256Digest>::Notarize(vote).encode();
                let _ = sender
                    .send(Recipients::One(victim.clone()), msg, true)
                    .await;
            }
        }
    }

    async fn send_proposal(&mut self, sender: &mut impl Sender) {
        if !self.is_faulty_view(self.current_view()) {
            return;
        }
        let proposal = self.get_proposal();
        let proposal = self.strategy.mutate_proposal(
            &mut self.context,
            &proposal,
            self.last_vote_view,
            self.last_finalized_view,
            self.last_notarized_view,
            self.last_nullified_view,
        );
        if let Some(vote) = Notarize::sign(&self.scheme, proposal) {
            let msg = Vote::<S, Sha256Digest>::Notarize(vote).encode();
            let _ = sender.send(Recipients::All, msg, true).await;
        }
    }

    async fn send_random_message(&mut self, sender: &mut impl Sender) {
        if !self.is_faulty_view(self.current_view()) {
            return;
        }
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
        if !self.is_faulty_view(self.current_view()) {
            return;
        }
        let proposal = self.get_proposal();

        match self.message() {
            Message::Notarize => {
                let proposal = self.strategy.mutate_proposal(
                    &mut self.context,
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
            Message::Nullify => {
                let view = self.strategy.mutate_nullify_view(
                    &mut self.context,
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
            Message::Random | Message::Finalize => {
                let bytes = self.bytes();
                let _ = sender.send(recipients, bytes, true).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minimmit::strategy::MinimmitAnyScope;
    use commonware_consensus::minimmit::scheme::ed25519;
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey as Ed25519PublicKey,
    };
    use commonware_p2p::{CheckedSender, LimitedSender};
    use commonware_runtime::{deterministic, IoBufs, Metrics, Runner as _};
    use commonware_utils::sync::Mutex;
    use std::{sync::Arc, time::SystemTime};

    const TEST_NAMESPACE: &[u8] = b"minimmit-disrupter-regression";
    const TEST_PARTICIPANTS: u32 = 6;

    #[derive(Clone, Debug)]
    struct CapturedMessage {
        recipients: Recipients<Ed25519PublicKey>,
        message: Vec<u8>,
    }

    #[derive(Clone, Debug, Default)]
    struct CapturingSender {
        sent: Arc<Mutex<Vec<CapturedMessage>>>,
    }

    impl CapturingSender {
        fn messages(&self) -> Vec<CapturedMessage> {
            self.sent.lock().clone()
        }
    }

    #[derive(Debug)]
    struct MockSendError;

    impl std::fmt::Display for MockSendError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "mock send failed")
        }
    }

    impl std::error::Error for MockSendError {}

    struct CapturingCheckedSender<'a> {
        sender: &'a mut CapturingSender,
        recipients: Recipients<Ed25519PublicKey>,
    }

    impl LimitedSender for CapturingSender {
        type PublicKey = Ed25519PublicKey;
        type Checked<'a> = CapturingCheckedSender<'a>;

        async fn check(
            &mut self,
            recipients: Recipients<Self::PublicKey>,
        ) -> Result<Self::Checked<'_>, SystemTime> {
            Ok(CapturingCheckedSender {
                sender: self,
                recipients,
            })
        }
    }

    impl CheckedSender for CapturingCheckedSender<'_> {
        type PublicKey = Ed25519PublicKey;
        type Error = MockSendError;

        async fn send(
            self,
            message: impl Into<IoBufs> + Send,
            _priority: bool,
        ) -> Result<Vec<Self::PublicKey>, Self::Error> {
            let message = message.into().coalesce().as_ref().to_vec();
            self.sender.sent.lock().push(CapturedMessage {
                recipients: self.recipients.clone(),
                message,
            });
            let recipients = match self.recipients {
                Recipients::All => Vec::new(),
                Recipients::Some(peers) => peers,
                Recipients::One(peer) => vec![peer],
            };
            Ok(recipients)
        }
    }

    #[test]
    fn send_proposal_emits_notarize_vote_encoding() {
        let runner = deterministic::Runner::seeded(3);
        runner.start(|mut context| async move {
            let Fixture { mut schemes, .. } =
                ed25519::fixture(&mut context, TEST_NAMESPACE, TEST_PARTICIPANTS);

            let mut disrupter = MinimmitDisrupter::new(
                context.with_label("disrupter"),
                schemes.remove(0),
                MinimmitAnyScope,
            );
            let mut sender = CapturingSender::default();

            disrupter.send_proposal(&mut sender).await;

            let sent = sender.messages();
            assert_eq!(sent.len(), 1, "send_proposal should send exactly one vote");
            let message = sent[0].message.clone();
            let vote = Vote::<ed25519::Scheme, Sha256Digest>::read(&mut message.as_slice())
                .expect("vote channel payload should decode as Vote");
            assert!(
                matches!(vote, Vote::Notarize(_)),
                "send_proposal should emit Vote::Notarize",
            );
            assert!(
                matches!(sent[0].recipients, Recipients::All),
                "send_proposal should target all peers",
            );
        });
    }

    #[test]
    fn flood_victim_emits_notarize_vote_encoding() {
        let runner = deterministic::Runner::seeded(7);
        runner.start(|mut context| async move {
            let Fixture { mut schemes, .. } =
                ed25519::fixture(&mut context, TEST_NAMESPACE, TEST_PARTICIPANTS);

            let mut disrupter = MinimmitDisrupter::new(
                context.with_label("disrupter"),
                schemes.remove(0),
                MinimmitAnyScope,
            );
            let mut sender = CapturingSender::default();

            disrupter.flood_victim(&mut sender).await;

            let sent = sender.messages();
            assert_eq!(sent.len(), 10, "flood_victim should send 10 votes");

            for captured in sent {
                let mut bytes = captured.message.as_slice();
                let vote = Vote::<ed25519::Scheme, Sha256Digest>::read(&mut bytes)
                    .expect("vote channel payload should decode as Vote");
                assert!(
                    matches!(vote, Vote::Notarize(_)),
                    "flood_victim should emit Vote::Notarize",
                );
                assert!(
                    matches!(captured.recipients, Recipients::One(_)),
                    "flood_victim should target a single victim",
                );
            }
        });
    }
}
