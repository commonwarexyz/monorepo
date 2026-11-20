use crate::reach;
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    Automaton as Au, CertifiableAutomaton as CAu, Handoff, Relay as Re,
    simplex::{
        Plan,
        mocks::application::{self, Certifier},
        types::{Context, Proposal},
    },
    types::{Round, View},
};
use commonware_cryptography::{Hasher, PublicKey, Sha256, sha256::Digest as Sha256Digest};
use commonware_macros::select_loop;
use commonware_p2p::Recipients;
use commonware_runtime::{Clock, ContextCell, Handle, Spawner, spawn_cell};
use commonware_utils::{
    channel::{
        fallible::{FallibleExt, OneshotExt},
        mpsc, oneshot,
    },
    sync::Mutex,
};
use rand::{Rng, RngExt as _};
use rand_distr::{Distribution, Normal};
use std::{
    collections::{BTreeMap, HashMap, HashSet, btree_map::Entry},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tracing::{debug, error, warn};

pub const RELAY_TAG_TWIN_PRIMARY: u64 = 1;
pub const RELAY_TAG_TWIN_SECONDARY: u64 = 2;

/// Label an honest node's `Vote` answer to a handoff request counts under: a
/// pipelined vote at a term start whose parent is uncertified. The twin halves,
/// which share the compromised identity, count nothing.
pub const HANDOFF_VOTE: &str = "handoff_vote";
/// Label an honest node's `Stage` answer to a handoff request counts under.
pub const HANDOFF_STAGE: &str = "handoff_stage";

type Filter<P> = Arc<dyn Fn(&P, Option<u64>, &P, u64, &Sha256Digest, &Bytes) -> bool + Send + Sync>;

#[derive(Clone, Copy)]
pub(crate) struct Registration {
    tag: u64,
}

#[derive(Clone)]
struct Listener {
    registration: Registration,
    sender: mpsc::UnboundedSender<(Sha256Digest, Bytes)>,
}

/// Fuzz-local block relay with per-recipient filtering.
pub struct Relay<P: PublicKey> {
    recipients: Mutex<BTreeMap<P, Vec<Listener>>>,
    filter: Mutex<Option<Filter<P>>>,
    certify_requires_block: AtomicBool,
    /// A trusted continuation's block gate, consulted before the filter: a block it
    /// accepts is held (the gate keeps it), not delivered.
    gate: Mutex<Option<Filter<P>>>,
    /// Per-recipient application latencies a trusted continuation overrides.
    latencies: Mutex<BTreeMap<P, crate::continuation::Latencies>>,
    overridden: AtomicBool,
}

impl<P: PublicKey> Relay<P> {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self {
            recipients: Mutex::new(BTreeMap::new()),
            filter: Mutex::new(None),
            certify_requires_block: AtomicBool::new(false),
            gate: Mutex::new(None),
            latencies: Mutex::new(BTreeMap::new()),
            overridden: AtomicBool::new(false),
        }
    }

    /// Installs a trusted continuation's block gate: it returns true for a block it
    /// holds instead of delivering.
    pub(crate) fn set_gate(
        &self,
        gate: impl Fn(&P, Option<u64>, &P, u64, &Sha256Digest, &Bytes) -> bool + Send + Sync + 'static,
    ) {
        *self.gate.lock() = Some(Arc::new(gate));
    }

    /// Removes the block gate.
    pub(crate) fn clear_gate(&self) {
        *self.gate.lock() = None;
    }

    /// Delivers a block the gate held to `recipient`, past the gate and through the
    /// filter, as `sender` (with its twin tag) sent it; returns how many of the
    /// recipient's applications took it.
    pub(crate) fn redeliver(
        &self,
        sender: &P,
        sender_tag: Option<u64>,
        recipient: P,
        block: (Sha256Digest, Bytes),
    ) -> usize {
        self.broadcast_from(
            false,
            sender_tag.map(|tag| Registration { tag }),
            sender,
            Recipients::One(recipient),
            block,
        )
    }

    /// Drops `who`'s registrations whose application is gone, as after a crash, before a
    /// restarted application registers anew.
    pub(crate) fn forget_closed(&self, who: &P) {
        if let Some(listeners) = self.recipients.lock().get_mut(who) {
            listeners.retain(|listener| !listener.sender.is_closed());
        }
    }

    /// Overrides `who`'s application latencies, or restores its own with `None`.
    pub(crate) fn set_latency(&self, who: &P, latencies: Option<crate::continuation::Latencies>) {
        let mut overrides = self.latencies.lock();
        match latencies {
            Some(latencies) => {
                overrides.insert(who.clone(), latencies);
            }
            None => {
                overrides.remove(who);
            }
        }
        self.overridden
            .store(!overrides.is_empty(), Ordering::Relaxed);
    }

    fn latency(&self, who: &P) -> Option<crate::continuation::Latencies> {
        if !self.overridden.load(Ordering::Relaxed) {
            return None;
        }
        self.latencies.lock().get(who).copied()
    }

    /// When enabled, a mock [`Application`] backed by this relay holds a certify
    /// request open until the payload's block bytes arrive, so a withheld block
    /// yields a genuinely pending certify. Left off (the default), certification
    /// follows the [`Certifier`] regardless of block possession, matching the
    /// upstream mock application; harnesses whose block drops are recoverable
    /// in-flight faults (e.g. ByzzFuzz pre-GST partitions) rely on that.
    pub fn set_certify_requires_block(&self, requires: bool) {
        self.certify_requires_block
            .store(requires, Ordering::Relaxed);
    }

    pub(crate) fn certify_requires_block(&self) -> bool {
        self.certify_requires_block.load(Ordering::Relaxed)
    }

    pub fn set_filter(
        &self,
        filter: impl Fn(&P, Option<u64>, &P, u64, &Sha256Digest, &Bytes) -> bool + Send + Sync + 'static,
    ) {
        *self.filter.lock() = Some(Arc::new(filter));
    }

    pub(crate) fn register_with_tag(
        &self,
        public_key: P,
        tag: u64,
    ) -> (Registration, mpsc::UnboundedReceiver<(Sha256Digest, Bytes)>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let registration = Registration { tag };
        {
            let mut recipients = self.recipients.lock();
            match recipients.entry(public_key.clone()) {
                Entry::Vacant(vacant) => {
                    vacant.insert(vec![Listener {
                        registration,
                        sender,
                    }]);
                }
                Entry::Occupied(mut occupied) => {
                    warn!(?public_key, "duplicate block relay registration");
                    occupied.get_mut().push(Listener {
                        registration,
                        sender,
                    });
                }
            }
        }
        (registration, receiver)
    }

    pub(crate) fn broadcast(
        &self,
        sender: &P,
        recipients: Recipients<P>,
        (payload, data): (Sha256Digest, Bytes),
    ) {
        self.broadcast_from(true, None, sender, recipients, (payload, data));
    }

    pub(crate) fn broadcast_with_tag(
        &self,
        sender: &P,
        sender_tag: u64,
        recipients: Recipients<P>,
        (payload, data): (Sha256Digest, Bytes),
    ) {
        self.broadcast_from(
            true,
            Some(Registration { tag: sender_tag }),
            sender,
            recipients,
            (payload, data),
        );
    }

    /// Returns how many applications took the block; `gated` consults the gate.
    fn broadcast_from(
        &self,
        gated: bool,
        registration: Option<Registration>,
        sender: &P,
        recipients: Recipients<P>,
        (payload, data): (Sha256Digest, Bytes),
    ) -> usize {
        let channels = {
            let mut channels = Vec::new();
            // A snapshot, so the gate and the filter run with no lock held and may relay.
            let registered = self.recipients.lock().clone();
            let filter = self.filter.lock().clone();
            let gate = if gated {
                self.gate.lock().clone()
            } else {
                None
            };
            let allow = |recipient: &P, listener: &Listener| {
                if recipient == sender
                    && registration
                        .is_some_and(|registration| listener.registration.tag == registration.tag)
                {
                    return false;
                }
                if let Some(gate) = &gate
                    && gate(
                        sender,
                        registration.map(|registration| registration.tag),
                        recipient,
                        listener.registration.tag,
                        &payload,
                        &data,
                    )
                {
                    return false;
                }
                filter.as_ref().is_none_or(|filter| {
                    filter(
                        sender,
                        registration.map(|registration| registration.tag),
                        recipient,
                        listener.registration.tag,
                        &payload,
                        &data,
                    )
                })
            };
            match recipients {
                Recipients::All => {
                    for (public_key, listeners) in registered.iter() {
                        for listener in listeners {
                            if allow(public_key, listener) {
                                channels.push((public_key.clone(), listener.sender.clone()));
                            }
                        }
                    }
                }
                Recipients::Some(peers) => {
                    for public_key in peers {
                        if let Some(listeners) = registered.get(&public_key) {
                            for listener in listeners {
                                if allow(&public_key, listener) {
                                    channels.push((public_key.clone(), listener.sender.clone()));
                                }
                            }
                        }
                    }
                }
                Recipients::One(public_key) => {
                    if let Some(listeners) = registered.get(&public_key) {
                        for listener in listeners {
                            if allow(&public_key, listener) {
                                channels.push((public_key.clone(), listener.sender.clone()));
                            }
                        }
                    }
                }
            }
            channels
        };
        let mut taken = 0;
        for (recipient, listener) in channels {
            if let Err(e) = listener.send((payload, data.clone())) {
                error!(?e, ?recipient, "failed to send block relay payload");
            } else {
                taken += 1;
            }
        }
        taken
    }
}

type Latency = (f64, f64);
type Waiters<P> = HashMap<Sha256Digest, Vec<(Context<Sha256Digest, P>, oneshot::Sender<bool>)>>;
type CertWaiters = HashMap<Sha256Digest, Vec<(Round, oneshot::Sender<bool>)>>;

pub struct Config<P: PublicKey> {
    pub relay: Arc<Relay<P>>,
    pub me: P,
    pub propose_latency: Latency,
    pub verify_latency: Latency,
    pub certify_latency: Latency,
    pub should_certify: Certifier<Sha256Digest>,
}

pub(crate) enum Message<P: PublicKey> {
    Prepare {
        context: Context<Sha256Digest, P>,
        response: oneshot::Sender<Handoff<Sha256Digest>>,
    },
    Propose {
        context: Context<Sha256Digest, P>,
        response: oneshot::Sender<Sha256Digest>,
    },
    Verify {
        context: Context<Sha256Digest, P>,
        payload: Sha256Digest,
        response: oneshot::Sender<bool>,
    },
    Certify {
        round: Round,
        payload: Sha256Digest,
        response: oneshot::Sender<bool>,
    },
    Broadcast {
        payload: Sha256Digest,
        plan: Plan<P>,
    },
}

#[derive(Clone)]
pub struct Mailbox<P: PublicKey> {
    sender: mpsc::UnboundedSender<Message<P>>,
}

impl<P: PublicKey> Mailbox<P> {
    const fn new(sender: mpsc::UnboundedSender<Message<P>>) -> Self {
        Self { sender }
    }
}

impl<P: PublicKey> Au for Mailbox<P> {
    type Digest = Sha256Digest;
    type Context = Context<Sha256Digest, P>;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Propose { context, response });
        receiver
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        self.sender.send_lossy(Message::Verify {
            context,
            payload,
            response,
        });
        receiver
    }
}

impl<P: PublicKey> CAu for Mailbox<P> {
    async fn prepare(
        &mut self,
        context: Self::Context,
    ) -> oneshot::Receiver<Handoff<Self::Digest>> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send_lossy(Message::Prepare { context, response });
        receiver
    }

    async fn certify(&mut self, round: Round, payload: Self::Digest) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        self.sender.send_lossy(Message::Certify {
            round,
            payload,
            response,
        });
        receiver
    }
}

impl<P: PublicKey> Re for Mailbox<P> {
    type Digest = Sha256Digest;
    type PublicKey = P;
    type Plan = Plan<P>;

    fn broadcast(&mut self, payload: Self::Digest, plan: Plan<P>) -> Feedback {
        if self.sender.send_lossy(Message::Broadcast { payload, plan }) {
            Feedback::Ok
        } else {
            Feedback::Closed
        }
    }
}

/// Fuzz-local mock application backed by the filterable relay above.
///
/// Unlike the consensus mock application, certification waits for missing block
/// contents so payload-denial schedules can exercise pending certify behavior.
pub struct Application<E: Clock + Rng + Spawner, P: PublicKey> {
    context: ContextCell<E>,
    me: P,
    relay: Arc<Relay<P>>,
    relay_registration: Registration,
    broadcast: mpsc::UnboundedReceiver<(Sha256Digest, Bytes)>,
    mailbox: mpsc::UnboundedReceiver<Message<P>>,
    propose_latency: Normal<f64>,
    verify_latency: Normal<f64>,
    certify_latency: Normal<f64>,
    should_certify: Certifier<Sha256Digest>,
    /// The relay tag this application registered under: a twin tag for a half
    /// of the compromised identity, zero for an honest node.
    relay_tag: u64,
    /// The decision attached to a handoff candidate. `Wait` builds nothing.
    handoff: Handoff<()>,
    pending: HashMap<Sha256Digest, Bytes>,
    seen: HashMap<Sha256Digest, Bytes>,
    verified: HashSet<Sha256Digest>,
    pending_certifications: Vec<oneshot::Sender<bool>>,
    certification_waiters: CertWaiters,
}

impl<E: Clock + Rng + Spawner, P: PublicKey> Application<E, P> {
    pub(crate) fn new(context: E, cfg: Config<P>) -> (Self, Mailbox<P>) {
        Self::new_with_relay_tag(context, cfg, 0)
    }

    pub fn new_with_relay_tag(context: E, cfg: Config<P>, relay_tag: u64) -> (Self, Mailbox<P>) {
        let (relay_registration, broadcast) =
            cfg.relay.register_with_tag(cfg.me.clone(), relay_tag);
        let propose_latency = Normal::new(cfg.propose_latency.0, cfg.propose_latency.1).unwrap();
        let verify_latency = Normal::new(cfg.verify_latency.0, cfg.verify_latency.1).unwrap();
        let certify_latency = Normal::new(cfg.certify_latency.0, cfg.certify_latency.1).unwrap();
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            Self {
                context: ContextCell::new(context),
                me: cfg.me,
                relay: cfg.relay,
                relay_registration,
                broadcast,
                mailbox: receiver,
                propose_latency,
                verify_latency,
                certify_latency,
                should_certify: cfg.should_certify,
                relay_tag,
                handoff: Handoff::Wait,
                pending: HashMap::new(),
                seen: HashMap::new(),
                verified: HashSet::new(),
                pending_certifications: Vec::new(),
                certification_waiters: HashMap::new(),
            },
            Mailbox::new(sender),
        )
    }

    /// Sets the handoff decision, which defaults to `Wait`.
    pub const fn set_handoff(&mut self, handoff: Handoff<()>) {
        self.handoff = handoff;
    }

    /// A latency sample: from the override a trusted continuation set for this
    /// application, else from its own distribution. Either takes one sample.
    fn sample(
        &mut self,
        own: fn(&Self) -> &Normal<f64>,
        pick: fn(&crate::continuation::Latencies) -> Latency,
    ) -> f64 {
        match self.relay.latency(&self.me).and_then(|latencies| {
            let (mean, deviation) = pick(&latencies);
            Normal::new(mean, deviation).ok()
        }) {
            Some(normal) => normal.sample(self.context.as_mut()),
            None => {
                let normal = *own(self);
                normal.sample(self.context.as_mut())
            }
        }
    }

    async fn propose(&mut self, context: Context<Sha256Digest, P>) -> Sha256Digest {
        let duration = self.sample(|app| &app.propose_latency, |latencies| latencies.propose);
        self.context
            .sleep(Duration::from_millis(duration as u64))
            .await;
        let contents = (
            context.round,
            context.parent.1,
            self.context.random::<u64>(),
        )
            .encode();
        let payload = Sha256::hash(&[&contents]);
        self.verified.insert(payload);
        self.pending.insert(payload, contents);
        payload
    }

    async fn verify(
        &mut self,
        context: Context<Sha256Digest, P>,
        payload: Sha256Digest,
        mut contents: Bytes,
    ) -> bool {
        let duration = self.sample(|app| &app.verify_latency, |latencies| latencies.verify);
        self.context
            .sleep(Duration::from_millis(duration as u64))
            .await;
        let Ok((parsed_round, parent, _)) = <(Round, Sha256Digest, u64)>::decode(&mut contents)
        else {
            return false;
        };
        if parsed_round != context.round || parent != context.parent.1 {
            return false;
        }
        self.verified.insert(payload);
        true
    }

    async fn certify(
        &mut self,
        round: Round,
        payload: Sha256Digest,
        response: oneshot::Sender<bool>,
    ) {
        let duration = self.sample(|app| &app.certify_latency, |latencies| latencies.certify);
        self.context
            .sleep(Duration::from_millis(duration as u64))
            .await;
        match &self.should_certify {
            Certifier::Always => {
                response.send_lossy(true);
            }
            Certifier::Custom(func) => {
                response.send_lossy(func(round, payload));
            }
            Certifier::Controlled(controller) => controller(round, payload, response),
            Certifier::Cancel => {}
            Certifier::Pending => self.pending_certifications.push(response),
        }
    }

    fn broadcast(&mut self, payload: Sha256Digest, plan: Plan<P>) {
        let (contents, recipients) = match plan {
            // A held candidate is sent when consensus requests `Plan::Prepare`.
            // Its later `Plan::Propose` broadcast does not send it again,
            // mirroring marshal's relay.
            Plan::Prepare { .. } => {
                let contents = self.pending.get(&payload).expect("missing payload").clone();
                self.seen.insert(payload, contents.clone());
                (contents, Recipients::All)
            }
            Plan::Propose { .. } => {
                let contents = self.pending.remove(&payload).expect("missing payload");
                if self.seen.insert(payload, contents.clone()).is_some() {
                    return;
                }
                (contents, Recipients::All)
            }
            Plan::Forward { recipients, .. } => {
                let contents = match self.seen.get(&payload).cloned() {
                    Some(contents) => contents,
                    None => {
                        let Some(contents) = self.pending.get(&payload).cloned() else {
                            debug!("payload not found for forwarding");
                            return;
                        };
                        self.seen.insert(payload, contents.clone());
                        contents
                    }
                };
                (contents, recipients)
            }
        };
        self.relay.broadcast_from(
            true,
            Some(self.relay_registration),
            &self.me,
            recipients,
            (payload, contents),
        );
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        let mut waiters: Waiters<P> = HashMap::new();

        select_loop! {
            self.context,
            on_stopped => {
                debug!("context shutdown, stopping fuzz application");
            },
            Some(message) = self.mailbox.recv() else break => {
                match message {
                    Message::Prepare { context, response } => {
                        let decision = self.handoff;
                        if decision.is_wait() {
                            response.send_lossy(Handoff::Wait);
                            continue;
                        }
                        let digest = self.propose(context).await;
                        let honest = self.relay_tag != RELAY_TAG_TWIN_PRIMARY
                            && self.relay_tag != RELAY_TAG_TWIN_SECONDARY;
                        match decision {
                            Handoff::Vote(()) if honest => reach::record(HANDOFF_VOTE),
                            Handoff::Stage(()) if honest => reach::record(HANDOFF_STAGE),
                            _ => {}
                        }
                        response.send_lossy(decision.map(|()| digest));
                    }
                    Message::Propose { context, response } => {
                        let digest = self.propose(context).await;
                        response.send_lossy(digest);
                    }
                    Message::Verify {
                        context,
                        payload,
                        response,
                    } => {
                        if let Some(contents) = self.seen.get(&payload) {
                            let verified = self.verify(context, payload, contents.clone()).await;
                            response.send_lossy(verified);
                        } else {
                            waiters
                                .entry(payload)
                                .or_default()
                                .push((context, response));
                        }
                    }
                    Message::Certify {
                        round,
                        payload,
                        response,
                    } => {
                        if matches!(self.should_certify, Certifier::Cancel) {
                            // Cancel: drop sender -> immediate RecvError on receiver.
                            drop(response);
                        } else if self.relay.certify_requires_block()
                            && !self.seen.contains_key(&payload)
                        {
                            self.certification_waiters
                                .entry(payload)
                                .or_default()
                                .push((round, response));
                        } else {
                            self.certify(round, payload, response).await;
                        }
                    }
                    Message::Broadcast { payload, plan } => {
                        self.broadcast(payload, plan);
                    }
                }
            },
            Some((digest, contents)) = self.broadcast.recv() else break => {
                self.seen.insert(digest, contents.clone());
                if let Some(waiters) = waiters.remove(&digest) {
                    for (context, sender) in waiters {
                        let verified = self.verify(context, digest, contents.clone()).await;
                        sender.send_lossy(verified);
                    }
                }
                if let Some(waiters) = self.certification_waiters.remove(&digest) {
                    for (round, sender) in waiters {
                        self.certify(round, digest, sender).await;
                    }
                }
            },
        }
    }
}

pub(crate) fn mock_block_round(contents: &Bytes) -> Option<Round> {
    <(Round, Sha256Digest, u64)>::decode(contents.clone())
        .ok()
        .map(|(round, _, _)| round)
}

pub fn mock_block_view(contents: &Bytes) -> Option<View> {
    mock_block_round(contents).map(|round| round.view())
}

pub(crate) fn mock_block(round: Round, parent: Sha256Digest, nonce: u64) -> (Sha256Digest, Bytes) {
    let contents = (round, parent, nonce).encode();
    let payload = Sha256::hash(&[&contents]);
    (payload, contents)
}

pub(crate) fn genesis_backed_mock_block(
    proposal: &Proposal<Sha256Digest>,
    nonce: u64,
) -> Option<(Proposal<Sha256Digest>, Bytes)> {
    if !proposal.parent.is_zero() {
        return None;
    }
    let (payload, contents) = mock_block(
        proposal.round,
        application::genesis::<Sha256>(proposal.round.epoch()),
        nonce,
    );
    Some((
        Proposal::new(proposal.round, proposal.parent, payload),
        contents,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex_certificate_mock as cert_mock;
    use commonware_p2p::Recipients;
    use commonware_utils::test_rng;

    #[test]
    fn broadcast_with_tag_exposes_sender_tag_to_filter() {
        let relay = Relay::new();
        let fixture = cert_mock::fixture(&mut test_rng(), b"block-relay", 2);
        let sender = fixture.participants[0].clone();
        let recipient = fixture.participants[1].clone();
        let (_primary, mut primary_rx) =
            relay.register_with_tag(recipient.clone(), RELAY_TAG_TWIN_PRIMARY);
        let (_secondary, mut secondary_rx) =
            relay.register_with_tag(recipient.clone(), RELAY_TAG_TWIN_SECONDARY);
        relay.set_filter(|_, sender_tag, _, recipient_tag, _, _| {
            sender_tag != Some(RELAY_TAG_TWIN_SECONDARY)
                || recipient_tag == RELAY_TAG_TWIN_SECONDARY
        });
        let payload = Sha256Digest::from([1u8; 32]);
        let contents = Bytes::from_static(b"block");

        relay.broadcast(
            &sender,
            Recipients::One(recipient.clone()),
            (payload, contents.clone()),
        );
        assert!(primary_rx.try_recv().is_ok());
        assert!(secondary_rx.try_recv().is_ok());

        relay.broadcast_with_tag(
            &sender,
            RELAY_TAG_TWIN_SECONDARY,
            Recipients::One(recipient),
            (payload, contents),
        );
        assert!(primary_rx.try_recv().is_err());
        assert!(secondary_rx.try_recv().is_ok());
    }
}
