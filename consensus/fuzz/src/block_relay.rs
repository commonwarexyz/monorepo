use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_codec::{DecodeExt, Encode};
use commonware_consensus::{
    Automaton as Au, CertifiableAutomaton as CAu, Relay as Re,
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

pub(crate) const RELAY_TAG_TWIN_PRIMARY: u64 = 1;
pub(crate) const RELAY_TAG_TWIN_SECONDARY: u64 = 2;

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
pub(crate) struct Relay<P: PublicKey> {
    recipients: Mutex<BTreeMap<P, Vec<Listener>>>,
    filter: Mutex<Option<Filter<P>>>,
    certify_requires_block: AtomicBool,
}

impl<P: PublicKey> Relay<P> {
    pub(crate) const fn new() -> Self {
        Self {
            recipients: Mutex::new(BTreeMap::new()),
            filter: Mutex::new(None),
            certify_requires_block: AtomicBool::new(false),
        }
    }

    /// When enabled, a mock [`Application`] backed by this relay holds a certify
    /// request open until the payload's block bytes arrive, so a withheld block
    /// yields a genuinely pending certify. Left off (the default), certification
    /// follows the [`Certifier`] regardless of block possession, matching the
    /// upstream mock application; harnesses whose block drops are recoverable
    /// in-flight faults (e.g. ByzzFuzz pre-GST partitions) rely on that.
    pub(crate) fn set_certify_requires_block(&self, requires: bool) {
        self.certify_requires_block
            .store(requires, Ordering::Relaxed);
    }

    pub(crate) fn certify_requires_block(&self) -> bool {
        self.certify_requires_block.load(Ordering::Relaxed)
    }

    pub(crate) fn set_filter(
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
        self.broadcast_from(None, sender, recipients, (payload, data));
    }

    pub(crate) fn broadcast_with_tag(
        &self,
        sender: &P,
        sender_tag: u64,
        recipients: Recipients<P>,
        (payload, data): (Sha256Digest, Bytes),
    ) {
        self.broadcast_from(
            Some(Registration { tag: sender_tag }),
            sender,
            recipients,
            (payload, data),
        );
    }

    fn broadcast_from(
        &self,
        registration: Option<Registration>,
        sender: &P,
        recipients: Recipients<P>,
        (payload, data): (Sha256Digest, Bytes),
    ) {
        let channels = {
            let mut channels = Vec::new();
            let registered = self.recipients.lock();
            let filter = self.filter.lock().clone();
            let allow = |recipient: &P, listener: &Listener| {
                if recipient == sender
                    && registration
                        .is_some_and(|registration| listener.registration.tag == registration.tag)
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
        for (recipient, listener) in channels {
            if let Err(e) = listener.send((payload, data.clone())) {
                error!(?e, ?recipient, "failed to send block relay payload");
            }
        }
    }
}

type Latency = (f64, f64);
type Waiters<P> = HashMap<Sha256Digest, Vec<(Context<Sha256Digest, P>, oneshot::Sender<bool>)>>;
type CertWaiters = HashMap<Sha256Digest, Vec<(Round, oneshot::Sender<bool>)>>;

pub(crate) struct Config<P: PublicKey> {
    pub(crate) relay: Arc<Relay<P>>,
    pub(crate) me: P,
    pub(crate) propose_latency: Latency,
    pub(crate) verify_latency: Latency,
    pub(crate) certify_latency: Latency,
    pub(crate) should_certify: Certifier<Sha256Digest>,
}

pub(crate) enum Message<P: PublicKey> {
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
pub(crate) struct Mailbox<P: PublicKey> {
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
pub(crate) struct Application<E: Clock + Rng + Spawner, P: PublicKey> {
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

    pub(crate) fn new_with_relay_tag(
        context: E,
        cfg: Config<P>,
        relay_tag: u64,
    ) -> (Self, Mailbox<P>) {
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
                pending: HashMap::new(),
                seen: HashMap::new(),
                verified: HashSet::new(),
                pending_certifications: Vec::new(),
                certification_waiters: HashMap::new(),
            },
            Mailbox::new(sender),
        )
    }

    async fn propose(&mut self, context: Context<Sha256Digest, P>) -> Sha256Digest {
        let duration = self.propose_latency.sample(self.context.as_mut());
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
        let duration = self.verify_latency.sample(self.context.as_mut());
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

    async fn certify(&mut self, round: Round, payload: Sha256Digest) -> Option<bool> {
        let duration = self.certify_latency.sample(self.context.as_mut());
        self.context
            .sleep(Duration::from_millis(duration as u64))
            .await;
        match &self.should_certify {
            Certifier::Always => Some(true),
            Certifier::Custom(func) => Some(func(round, payload)),
            Certifier::Cancel | Certifier::Pending => None,
        }
    }

    fn broadcast(&mut self, payload: Sha256Digest, plan: Plan<P>) {
        let (contents, recipients) = match plan {
            Plan::Propose { .. } => {
                let contents = self.pending.remove(&payload).expect("missing payload");
                self.seen.insert(payload, contents.clone());
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
            Some(self.relay_registration),
            &self.me,
            recipients,
            (payload, contents),
        );
    }

    pub(crate) fn start(mut self) -> Handle<()> {
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
                        } else if let Some(certified) = self.certify(round, payload).await {
                            response.send_lossy(certified);
                        } else if matches!(self.should_certify, Certifier::Pending) {
                            self.pending_certifications.push(response);
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
                        if let Some(certified) = self.certify(round, digest).await {
                            sender.send_lossy(certified);
                        } else if matches!(self.should_certify, Certifier::Pending) {
                            self.pending_certifications.push(sender);
                        }
                    }
                }
            },
        }
    }
}

pub(crate) fn mock_block_round(contents: &Bytes) -> Option<Round> {
    <(Round, Sha256Digest, u64)>::decode(&mut contents.as_ref())
        .ok()
        .map(|(round, _, _)| round)
}

pub(crate) fn mock_block_view(contents: &Bytes) -> Option<View> {
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
