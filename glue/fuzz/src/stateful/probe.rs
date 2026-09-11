//! The probe driver: real `Probe` actors over the deterministic simulated
//! network, driven through their public mailbox and P2P boundaries by a
//! bounded adversarial event program, with every floor they derive checked
//! against a provenance ledger.
//!
//! Four mock-scheme committee identities form the solicited committee: one
//! runs the discovering probe and three run source probes, each attached to a
//! real marshal actor seeded with the finalized history the input selects. A
//! fifth identity is not a committee member. Heights span three epochs, the
//! discovering probe's provider knows only the first two, and a source's
//! history may be certified by a foreign committee instead, so a source's
//! response is valid, stale (below the configured minimum epoch), unjudgeable
//! (no verifier for its epoch), or unverifiable (a certificate the provider
//! does not cover) by construction of the input.
//!
//! Every source probe's sender is wrapped so the real encoded response it
//! builds is captured as opaque bytes instead of being sent; the event program
//! then releases, duplicates, mutates, or replays those bytes, and injects raw
//! payloads, all through the same simulated P2P boundary. The discovering
//! probe's sender and receiver are wrapped too, so the ledger records, in the
//! actor's own processing order, every request it issued and every message it
//! received.
//!
//! Nothing here decodes the wire format or reproduces the probe's
//! verification, floor selection, or state transitions. A delivered message is
//! known by content alone, as byte-for-byte a response some source built or as
//! starting like the request a probe sends, and the oracle asserts only what
//! the public contract settles: which responses may form a floor, that what it
//! forbids never contributed, and that data the contract calls malformed or
//! unverifiable is blocked while the probe is certainly discovering. Every
//! adversarial message the program sends is chosen so that the contract
//! settles what the probe must do with it; where it would not, the message is
//! not sent. Blocks are observed at the discovering probe's public `Blocker`
//! boundary as they happen, so each delivery is judged by the blocks placed
//! by the time it was processed.

use super::{
    Digest, IO_BUFFER_SIZE, MAILBOX_SIZE, MAX_RAW_PAYLOAD, MAX_SOURCE_HEIGHT, NUM_SOURCES,
    PAGE_CACHE_SIZE, PAGE_SIZE, PROBE_EPOCH_LENGTH, PROBE_KNOWN_EPOCHS, PROBE_RETRY_TIMEOUT,
    PROBE_RUN_TIMEOUT, PROBE_STEP, PublicKey, Scheme,
    app::Block,
    backend::{Any, AnyCommitment, Backend as _},
    input::{ProbeEvent, StatefulProbeFuzzInput},
    runner::{self, Reportable},
    stack::{TEST_QUOTA, archive_config},
};
use commonware_actor::Feedback;
use commonware_consensus::{
    Epochable as _, Reporter,
    marshal::{
        self, Start, Update,
        core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
        resolver::p2p as marshal_resolver,
        standard::Standard,
    },
    simplex::types::{Activity, Context, Finalization, Finalize, Proposal},
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View, ViewDelta},
};
use commonware_cryptography::{
    Digestible, Signer as _,
    certificate::{ConstantProvider, Provider, Scoped},
    ed25519,
};
use commonware_glue::stateful::probe::{Config as ProbeConfig, Mailbox as ProbeMailbox, Probe};
use commonware_macros::select;
use commonware_p2p::{
    BlockedSubscription, Blocker, Recipients, Sender as _,
    simulated::{
        Config as NetworkConfig, Control, Link, Network as SimulatedNetwork, Oracle, Receiver,
        Sender,
    },
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::archive::prunable;
use commonware_utils::{
    Acknowledgement as _, Faults, FuzzRng, N3f1, NZDuration, NZU64, NZUsize,
    channel::oneshot::{self, error::TryRecvError},
    non_empty, probability,
    sync::Mutex,
};
use std::{fmt, num::NonZeroU64, sync::Arc, time::Duration};

/// Label this driver reports under.
const TARGET: &str = "glue-stateful-probe";

/// Namespace for the committee's mock certificate scheme fixture.
const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_FUZZ_PROBE";

/// Namespace for the foreign committee whose certificates the discovering
/// probe cannot verify.
const FOREIGN_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_FUZZ_PROBE_FOREIGN";

/// Seed of the identity outside the committee.
const NON_MEMBER_SEED: u64 = 0x6e6f6e6d656d62;

/// Channel ids.
const CHANNEL_PROBE: u64 = 0;
const CHANNEL_BACKFILL: u64 = 1;

/// Open floor subscriptions the program may hold at once.
const MAX_SUBSCRIPTIONS: usize = 2;

/// Committee members: the discovering probe and its sources.
const COMMITTEE: u32 = NUM_SOURCES as u32 + 1;

/// Every directed link stays up for the whole run and delivers reliably, so
/// every message the program sends reaches the discovering probe, blocked or
/// not.
const LINK: Link = Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(1),
    success_rate: probability!(1.0),
};

const RESOLVER_TIMEOUT: Duration = Duration::from_millis(500);
const RESOLVER_RETRY: Duration = Duration::from_millis(100);
const VIEW_RETENTION: ViewDelta = ViewDelta::new(10);
const SECTION_ITEMS: NonZeroU64 = NZU64!(10);

/// The block the sources' marshals store. The probe never looks inside a
/// block, so the cluster's block over the `any` commitment serves.
type ProbeBlock = Block<AnyCommitment>;
type Variant = Standard<ProbeBlock>;
type Floor = Finalization<Scheme, Digest>;
type Mailbox = ProbeMailbox<Scheme, Variant>;
type Marshal = MarshalMailbox<Scheme, Variant>;
type RawSender = Sender<PublicKey, deterministic::Context>;

/// libFuzzer entry point.
pub fn fuzz_stateful_probe(input: StatefulProbeFuzzInput) {
    let raw_bytes = input.raw_bytes.clone();
    runner::report(&raw_bytes, || run_stateful_probe(input));
}

/// Run one event program and return what it observed.
///
/// A run is fully determined by its input bytes.
pub fn run_stateful_probe(input: StatefulProbeFuzzInput) -> ProbeReport {
    let config = deterministic::Config::new().with_rng(FuzzRng::new(input.raw_bytes.clone()));
    deterministic::Runner::new(config).start(|context| run(context, input))
}

/// Why a probe run stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Every event was executed.
    Program,
    /// The run's bounded timeout expired.
    Timeout,
}

impl fmt::Display for ProbeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Program => f.write_str("program"),
            Self::Timeout => f.write_str("timeout"),
        }
    }
}

/// What one probe run observed, so a run in which nothing was checked is
/// visible as such.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    /// Why the run stopped.
    pub outcome: ProbeOutcome,
    /// Events executed.
    pub events: usize,
    /// Requests the discovering probe issued.
    pub requests: usize,
    /// Responses captured from the source probes.
    pub captures: usize,
    /// Messages delivered to the discovering probe.
    pub deliveries: usize,
    /// Deliveries of a source's own response that the discovering probe must
    /// set aside: stale or unjudgeable for its epoch.
    pub ignored: usize,
    /// Deliveries the oracle required the discovering probe to block, each
    /// checked on its own.
    pub block_checks: usize,
    /// Whether the discovering probe was ever delivered a sufficient valid
    /// sample within one request attempt.
    pub floor_expected: bool,
    /// Whether the discovering probe emitted a floor.
    pub floor_selected: bool,
    /// Whether an emitted floor was checked against the ledger.
    pub floor_checked: bool,
    /// Calls the discovering probe made to its blocker, one per delivery it
    /// blocked; a peer blocked more than once counts each time.
    pub block_calls: usize,
}

impl ProbeReport {
    /// Whether the run reached the check this target exists for.
    pub const fn measured(&self) -> bool {
        self.floor_selected && self.floor_checked
    }
}

impl Reportable for ProbeReport {
    fn measured(&self) -> bool {
        Self::measured(self)
    }
}

impl fmt::Display for ProbeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{TARGET}] outcome={} events={} requests={} captures={} deliveries={} ignored={} \
             block_checks={} floor_expected={} floor_selected={} floor_checked={} \
             block_calls={}{}",
            self.outcome,
            self.events,
            self.requests,
            self.captures,
            self.deliveries,
            self.ignored,
            self.block_checks,
            self.floor_expected,
            self.floor_selected,
            self.floor_checked,
            self.block_calls,
            if self.measured() {
                ""
            } else {
                " UNMEASURED (no floor was selected)"
            },
        )
    }
}

/// The discovering probe's certificate provider: one scheme for the first
/// epochs only, so a finalization from a later epoch cannot be judged.
#[derive(Clone)]
struct EpochProvider {
    scheme: Arc<Scheme>,
    epochs: u64,
}

impl EpochProvider {
    fn new(scheme: &Scheme, epochs: u64) -> Self {
        Self {
            scheme: Arc::new(scheme.clone()),
            epochs,
        }
    }

    fn knows(&self, epoch: Epoch) -> bool {
        epoch.get() < self.epochs
    }
}

impl Provider for EpochProvider {
    type Scope = Epoch;
    type Scheme = Scheme;

    fn scoped(&self, scope: Epoch) -> Option<Scoped<Scheme>> {
        self.knows(scope)
            .then(|| Scoped::scheme(self.scheme.clone()))
    }
}

/// One thing the discovering probe did on the network, in its own order.
#[derive(Clone, Debug)]
enum Traffic {
    /// It sent a message. In discovery every message it sends is a request to
    /// the committee, which opens a new attempt; its marshal never holds a
    /// finalization, so in service it never answers anything.
    Requested,
    /// It received a message.
    Delivered(Box<Delivery>),
}

/// A message delivered to the discovering probe.
#[derive(Clone, Debug)]
struct Delivery {
    peer: PublicKey,
    bytes: Vec<u8>,
}

/// A response a source probe built and would have sent.
#[derive(Clone, Debug)]
struct Capture {
    source: usize,
    bytes: Vec<u8>,
}

/// A block the discovering probe placed, and the delivery it was processing.
#[derive(Clone, Debug)]
struct BlockEvent {
    peer: PublicKey,
    traffic_index: usize,
}

#[derive(Default)]
struct Log {
    traffic: Vec<Traffic>,
    captures: Vec<Capture>,
    blocks: Vec<BlockEvent>,
}

/// The ledger beside the opaque messages: what the discovering probe sent and
/// received, and every response the sources built.
#[derive(Clone, Default)]
struct Ledger(Arc<Mutex<Log>>);

impl Ledger {
    fn note_request(&self) {
        self.0.lock().traffic.push(Traffic::Requested);
    }

    fn note_delivery(&self, peer: PublicKey, bytes: Vec<u8>) {
        self.0
            .lock()
            .traffic
            .push(Traffic::Delivered(Box::new(Delivery { peer, bytes })));
    }

    fn capture(&self, source: usize, bytes: Vec<u8>) {
        self.0.lock().captures.push(Capture { source, bytes });
    }

    /// Record a block against the delivery being processed: the last one
    /// logged, since the probe blocks only while handling a message.
    fn note_block(&self, peer: PublicKey) {
        let mut log = self.0.lock();
        let traffic_index = log
            .traffic
            .iter()
            .rposition(|traffic| matches!(traffic, Traffic::Delivered(_)))
            .expect("a block follows a delivery");
        log.blocks.push(BlockEvent {
            peer,
            traffic_index,
        });
    }

    fn blocks(&self) -> Vec<BlockEvent> {
        self.0.lock().blocks.clone()
    }

    /// Whether `peer` was blocked while the delivery at `index` or an earlier
    /// one was processed.
    fn blocked_by(&self, peer: &PublicKey, index: usize) -> bool {
        self.0
            .lock()
            .blocks
            .iter()
            .any(|block| block.peer == *peer && block.traffic_index <= index)
    }

    /// Whether `peer` was blocked while the delivery at `index` was processed.
    fn blocked_at(&self, peer: &PublicKey, index: usize) -> bool {
        self.0
            .lock()
            .blocks
            .iter()
            .any(|block| block.peer == *peer && block.traffic_index == index)
    }

    /// The response most recently captured from `source`.
    fn latest_capture(&self, source: usize) -> Option<Vec<u8>> {
        self.0
            .lock()
            .captures
            .iter()
            .rev()
            .find(|capture| capture.source == source)
            .map(|capture| capture.bytes.clone())
    }

    fn traffic(&self) -> Vec<Traffic> {
        self.0.lock().traffic.clone()
    }

    fn captures(&self) -> Vec<Capture> {
        self.0.lock().captures.clone()
    }

    fn deliveries(&self) -> usize {
        self.0
            .lock()
            .traffic
            .iter()
            .filter(|traffic| matches!(traffic, Traffic::Delivered(_)))
            .count()
    }

    fn requests(&self) -> usize {
        self.0
            .lock()
            .traffic
            .iter()
            .filter(|traffic| matches!(traffic, Traffic::Requested))
            .count()
    }
}

/// A probe's receiver. The discovering probe's records every delivery in the
/// ledger at the moment the actor takes it; a source's records nothing.
struct Observed {
    inner: Receiver<PublicKey>,
    ledger: Option<Ledger>,
}

impl fmt::Debug for Observed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observed")
            .field("inner", &self.inner)
            .finish()
    }
}

impl commonware_p2p::Receiver for Observed {
    type Error = commonware_p2p::simulated::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<commonware_p2p::Message<PublicKey>, Self::Error> {
        let (peer, bytes) = self.inner.recv().await?;
        if let Some(ledger) = &self.ledger {
            ledger.note_delivery(peer.clone(), bytes.as_ref().to_vec());
        }
        Ok((peer, bytes))
    }
}

/// The discovering probe's blocker: records every block in the ledger against
/// the delivery being processed, then places it on the simulated network.
#[derive(Clone)]
struct ObservedBlocker {
    inner: Control<PublicKey, deterministic::Context>,
    ledger: Ledger,
}

impl Blocker for ObservedBlocker {
    type PublicKey = PublicKey;

    // The probe has already logged the block it places; this only forwards it.
    #[allow(clippy::disallowed_methods)]
    fn block(&mut self, peer: PublicKey) -> Feedback {
        self.ledger.note_block(peer.clone());
        self.inner.block(peer)
    }

    fn blocked(&mut self) -> BlockedSubscription<PublicKey> {
        self.inner.blocked()
    }
}

/// Acknowledges every block marshal delivers; the sources run no application.
#[derive(Clone)]
struct Acking;

impl Reporter for Acking {
    type Activity = Update<ProbeBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Update::Block(_, ack) = activity {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

/// One committee member's stack: its probe, the marshal its probe may be
/// attached to, and a raw handle on its probe channel.
struct Member {
    identity: PublicKey,
    probe: Mailbox,
    marshal: Marshal,
    sender: RawSender,
    /// The finalization this member's marshal holds, if any: the source-state
    /// model the floor is checked against.
    finalization: Option<Floor>,
    /// Whether that finalization is certified by the foreign committee.
    foreign: bool,
    /// The bytes this member most recently delivered as itself.
    released: Option<Vec<u8>>,
}

/// One message the program sent to the discovering probe. Sends are
/// separated by a settle period much longer than the link latency, so the
/// ledger's deliveries pair with them in order.
#[derive(Clone, Debug)]
struct Sent {
    origin: PublicKey,
    kind: Kind,
}

/// What the program sent, by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A captured response, from the source that built it.
    Response,
    /// A captured response, from the non-member.
    Replayed,
    /// A strict prefix of a captured response the probe judges, from the
    /// source that built it or any other identity: malformed.
    Truncated,
    /// Bytes starting like neither message the probe exchanges: malformed.
    Junk,
}

/// What the contract requires of the discovering probe's blocker for one
/// delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// The sender must be blocked: a pending committee member sent malformed
    /// or unverifiable data, or the non-member sent a finalization.
    Block,
    /// The sender must not be blocked: a committee member sent its own valid
    /// response.
    Pass,
    /// The contract requires nothing.
    Open,
}

/// How a delivered message is known to the ledger, by its content alone.
/// Whether it was delivered by the source that built it is a separate
/// question the sample asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Known {
    /// Byte-for-byte a response `source` built, certified by the committee,
    /// from an epoch the discovering probe can judge and does not treat as
    /// stale.
    Valid { source: usize },
    /// Byte-for-byte a response `source` built, from an epoch below the
    /// discovering probe's minimum.
    Stale { source: usize },
    /// Byte-for-byte a response `source` built, from an epoch the discovering
    /// probe has no verifier for.
    Unjudgeable { source: usize },
    /// Byte-for-byte a response `source` built, from an epoch the discovering
    /// probe judges, certified by the foreign committee.
    Unverifiable { source: usize },
    /// Bytes starting like the request a probe sends.
    Request,
    /// Anything else: not a response any source built, and shorter than every
    /// response, so nothing a probe could accept or set aside.
    Other,
}

struct Harness {
    context: deterministic::Context,
    oracle: Oracle<PublicKey, deterministic::Context>,
    ledger: Ledger,
    /// The committee: the discovering probe at index zero, then the sources.
    members: Vec<Member>,
    non_member: (PublicKey, RawSender),
    provider: EpochProvider,
    minimum_epoch: Epoch,
    /// The encoded request a probe sends, captured from a reference probe
    /// before the program runs.
    request: Vec<u8>,
    subscriptions: Vec<oneshot::Receiver<Floor>>,
    /// Whether the discovering probe's marshal has been attached.
    attached: bool,
    /// Position in the ledger's traffic from which the discovering probe is no
    /// longer certainly discovering: its marshal is attached and, since the
    /// attachment, the program has at some point held no open subscription.
    unheld_from: Option<usize>,
    /// Messages the program sent, in order.
    sent: Vec<Sent>,
    /// Deliveries already accounted for.
    seen: usize,
    /// The floor the discovering probe emitted, once observed.
    floor: Option<Floor>,
    report: ProbeReport,
}

async fn run(context: deterministic::Context, input: StatefulProbeFuzzInput) -> ProbeReport {
    let mut harness = Harness::setup(
        context,
        &input.sources,
        &input.unverifiable,
        Epoch::new(input.minimum_epoch.into()),
    )
    .await;
    let timeout = harness.context.sleep(PROBE_RUN_TIMEOUT);
    let program = async {
        for event in &input.events {
            harness.step(event).await;
        }
        ProbeOutcome::Program
    };
    let outcome = select! {
        _ = timeout => ProbeOutcome::Timeout,
        outcome = program => outcome,
    };
    harness.finish(outcome).await
}

impl Harness {
    /// Derive the committee and the non-member, start the network, and start
    /// every marshal and probe.
    async fn setup(
        mut context: deterministic::Context,
        sources: &[u8],
        unverifiable: &[bool],
        minimum_epoch: Epoch,
    ) -> Self {
        let fixture = commonware_consensus::simplex::mocks::scheme::fixture_with::<
            false,
            true,
            true,
            _,
        >(&mut context, NAMESPACE, COMMITTEE);
        let committee = fixture.participants.clone();
        let non_member = ed25519::PrivateKey::from_seed(NON_MEMBER_SEED).public_key();
        assert!(
            !committee.contains(&non_member),
            "the non-member identity must be outside the committee"
        );

        let mut peers = committee.clone();
        peers.push(non_member.clone());
        let (network, oracle) = SimulatedNetwork::new_with_peers(
            context.child("network"),
            NetworkConfig {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(peers.len()),
                disconnect_on_block: false,
                tracked_peer_sets: NZUsize!(1),
            },
            peers.iter().cloned(),
        )
        .await;
        network.start();
        for sender in &peers {
            for receiver in &peers {
                if sender == receiver {
                    continue;
                }
                oracle
                    .add_link(sender.clone(), receiver.clone(), LINK)
                    .await
                    .expect("link must be installed");
            }
        }

        // The finalized histories the sources are seeded from: one chain
        // certified by the committee, so two sources holding the same height
        // hold the same finalization, and one over different blocks certified
        // by a foreign committee, which the discovering probe cannot verify.
        let epocher = FixedEpocher::new(PROBE_EPOCH_LENGTH);
        let chain = Chain::new(&committee, &fixture.schemes, &epocher);
        let foreign_fixture = commonware_consensus::simplex::mocks::scheme::fixture_with::<
            false,
            true,
            true,
            _,
        >(&mut context, FOREIGN_NAMESPACE, COMMITTEE);
        let foreign = Chain::new(
            &foreign_fixture.participants,
            &foreign_fixture.schemes,
            &epocher,
        );
        for finalization in &foreign.finalizations {
            assert!(
                !finalization.verify(&mut context, &fixture.verifier, &Sequential),
                "harness defect: a foreign finalization verifies under the committee"
            );
        }

        let ledger = Ledger::default();
        let provider = EpochProvider::new(&fixture.schemes[0], PROBE_KNOWN_EPOCHS);
        let mut members = Vec::with_capacity(committee.len());
        for (index, identity) in committee.iter().enumerate() {
            let scheme = fixture.schemes[index].clone();
            let node = context.child("member").with_attribute("index", index);
            let control = oracle.control(identity.clone());
            let page_cache = CacheRef::from_pooler(&node, PAGE_SIZE, PAGE_CACHE_SIZE);
            let prefix = format!("member-{index}");

            // Marshal, with its backfill resolver and archives. Its provider
            // covers every epoch: only the discovering probe's is limited.
            let backfill = control
                .register(CHANNEL_BACKFILL, TEST_QUOTA)
                .await
                .expect("channel registration failed");
            let resolver = marshal_resolver::init(
                node.child("marshal_resolver"),
                marshal_resolver::Config {
                    public_key: identity.clone(),
                    peer_provider: oracle.manager(),
                    blocker: oracle.control(identity.clone()),
                    mailbox_size: MAILBOX_SIZE,
                    timeout: RESOLVER_TIMEOUT,
                    fetch_retry_timeout: RESOLVER_RETRY,
                    priority_requests: false,
                    priority_responses: false,
                },
                backfill,
            );
            let finalizations_by_height = prunable::Archive::init(
                node.child("finalizations_by_height"),
                archive_config(&prefix, "finalizations", page_cache.clone(), ()),
            )
            .await
            .expect("failed to initialize finalizations archive");
            let finalized_blocks = prunable::Archive::init(
                node.child("finalized_blocks"),
                archive_config(&prefix, "blocks", page_cache.clone(), ()),
            )
            .await
            .expect("failed to initialize blocks archive");
            let history = if index > 0 && unverifiable[index - 1] {
                &foreign
            } else {
                &chain
            };
            let (marshal_actor, marshal, _) = MarshalActor::<_, Variant, _, _, _, _, _>::init(
                node.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider: ConstantProvider::new(scheme.clone()),
                    epocher: epocher.clone(),
                    start: Start::Genesis(history.blocks[0].clone().into()),
                    partition_prefix: prefix,
                    mailbox_size: MAILBOX_SIZE,
                    view_retention: VIEW_RETENTION,
                    prunable_items_per_section: SECTION_ITEMS,
                    page_cache,
                    replay_buffer: IO_BUFFER_SIZE,
                    key_write_buffer: IO_BUFFER_SIZE,
                    value_write_buffer: IO_BUFFER_SIZE,
                    block_codec_config: (),
                    max_repair: NZUsize!(10),
                    max_pending_acks: NZUsize!(1),
                    strategy: Sequential,
                },
            )
            .await;
            drop(marshal_actor.start_unbuffered(Acking, resolver));

            // Seed a source's marshal with its finalized history before any
            // discovery begins, and record exactly what it holds.
            let mut finalization = None;
            if index > 0 {
                let height = usize::from(sources[index - 1]);
                for h in 1..=height {
                    history.inject(&marshal, h).await;
                }
                finalization = (height > 0).then(|| history.finalizations[height].clone());
            }

            // The probe, over a wrapped sender: the discovering probe's sends
            // are recorded as requests and forwarded; a source's sends are
            // captured and withheld for the program to deliver.
            let (sender, receiver) = control
                .register(CHANNEL_PROBE, TEST_QUOTA)
                .await
                .expect("channel registration failed");
            let wrapped = {
                let ledger = ledger.clone();
                sender.clone().split_with(move |_, intended, message| {
                    if index == 0 {
                        ledger.note_request();
                        Some(intended.clone())
                    } else {
                        ledger.capture(index - 1, message.as_ref().to_vec());
                        None
                    }
                })
            };
            let receiver = Observed {
                inner: receiver,
                ledger: (index == 0).then(|| ledger.clone()),
            };
            let blocker = ObservedBlocker {
                inner: oracle.control(identity.clone()),
                ledger: ledger.clone(),
            };
            let (probe, mailbox) = Probe::new(ProbeConfig {
                context: node.child("probe"),
                provider: provider.clone(),
                strategy: Sequential,
                capacity: MAILBOX_SIZE,
                blocker,
                minimum_epoch,
                retry_timeout: NZDuration!(PROBE_RETRY_TIMEOUT),
            });
            drop(probe.start((wrapped.0, receiver)));

            members.push(Member {
                identity: identity.clone(),
                probe: mailbox,
                marshal,
                sender,
                finalization,
                foreign: index > 0 && unverifiable[index - 1],
                released: None,
            });
        }

        let (sender, receiver) = oracle
            .control(non_member.clone())
            .register(CHANNEL_PROBE, TEST_QUOTA)
            .await
            .expect("channel registration failed");

        // Learn what a request looks like from a reference probe on the
        // non-member's channel: its solicitation is captured and withheld,
        // and it is stopped before the program starts.
        let captured: Arc<Mutex<Option<Vec<u8>>>> = Arc::default();
        let (reference, reference_mailbox) = Probe::<_, _, _, Variant, _, _, _>::new(ProbeConfig {
            context: context.child("reference"),
            provider: provider.clone(),
            strategy: Sequential,
            capacity: MAILBOX_SIZE,
            blocker: oracle.control(non_member.clone()),
            minimum_epoch,
            retry_timeout: NZDuration!(PROBE_RETRY_TIMEOUT),
        });
        let withheld = {
            let captured = captured.clone();
            sender.clone().split_with(move |_, _, message| {
                captured.lock().get_or_insert(message.as_ref().to_vec());
                None
            })
        };
        let reference = reference.start((withheld.0, receiver));
        let solicitation = reference_mailbox.subscribe();
        context.sleep(PROBE_STEP).await;
        reference.abort();
        drop(solicitation);
        let request = captured
            .lock()
            .take()
            .expect("harness defect: the reference probe issued no request");

        Self {
            context,
            oracle,
            ledger,
            members,
            non_member: (non_member, sender),
            provider,
            minimum_epoch,
            request,
            subscriptions: Vec::new(),
            attached: false,
            unheld_from: None,
            sent: Vec::new(),
            seen: 0,
            floor: None,
            report: ProbeReport {
                outcome: ProbeOutcome::Program,
                events: 0,
                requests: 0,
                captures: 0,
                deliveries: 0,
                ignored: 0,
                block_checks: 0,
                floor_expected: false,
                floor_selected: false,
                floor_checked: false,
                block_calls: 0,
            },
        }
    }

    fn discoverer(&self) -> &PublicKey {
        &self.members[0].identity
    }

    fn source(&self, selector: u8) -> usize {
        usize::from(selector % NUM_SOURCES)
    }

    /// How a source's own response is known, from the harness's model of
    /// that source alone: the epoch of the finalization it was seeded with
    /// and the committee that certified it.
    fn class(&self, source: usize) -> Known {
        let member = &self.members[source + 1];
        let epoch = member
            .finalization
            .as_ref()
            .expect("a source that responded holds a finalization")
            .epoch();
        if epoch < self.minimum_epoch {
            Known::Stale { source }
        } else if !self.provider.knows(epoch) {
            Known::Unjudgeable { source }
        } else if member.foreign {
            Known::Unverifiable { source }
        } else {
            Known::Valid { source }
        }
    }

    /// Send `bytes` to the discovering probe as `origin`, and record the send.
    fn send(&mut self, mut sender: RawSender, origin: PublicKey, kind: Kind, bytes: Vec<u8>) {
        let discoverer = self.discoverer().clone();
        sender.send(Recipients::One(discoverer), bytes, false);
        self.sent.push(Sent { origin, kind });
    }

    /// Execute one event, let the actors settle, and observe.
    async fn step(&mut self, event: &ProbeEvent) {
        // Whether a subscription opened by an earlier event is still waiting:
        // if it resolves during this event, the floor was selected during it.
        let waiting = !self.subscriptions.is_empty();
        match event {
            ProbeEvent::Subscribe => {
                if self.subscriptions.len() < MAX_SUBSCRIPTIONS {
                    let subscription = self.members[0].probe.subscribe();
                    self.subscriptions.push(subscription);
                }
            }
            ProbeEvent::Unsubscribe => {
                if !self.subscriptions.is_empty() {
                    self.subscriptions.remove(0);
                }
            }
            ProbeEvent::Attach { node } => {
                let node = usize::from(node % (NUM_SOURCES + 1));
                let member = &self.members[node];
                member.probe.attach(member.marshal.clone());
                if node == 0 {
                    self.attached = true;
                }
            }
            ProbeEvent::Release { source } => {
                let source = self.source(*source);
                if let Some(bytes) = self.ledger.latest_capture(source) {
                    let member = &mut self.members[source + 1];
                    member.released = Some(bytes.clone());
                    let (sender, origin) = (member.sender.clone(), member.identity.clone());
                    self.send(sender, origin, Kind::Response, bytes);
                }
            }
            ProbeEvent::Duplicate { source } => {
                let source = self.source(*source);
                let member = &self.members[source + 1];
                if let Some(bytes) = member.released.clone() {
                    let (sender, origin) = (member.sender.clone(), member.identity.clone());
                    self.send(sender, origin, Kind::Response, bytes);
                }
            }
            // Only a response the probe judges is replayed or damaged: the
            // contract settles nothing about a stale or unjudgeable one sent
            // by a non-member or damaged.
            ProbeEvent::Replay { source } => {
                let source = self.source(*source);
                if let Some(bytes) = self.judged_capture(source) {
                    let (origin, sender) = self.non_member.clone();
                    self.send(sender, origin, Kind::Replayed, bytes);
                }
            }
            ProbeEvent::Truncate { source, keep } => {
                let source = self.source(*source);
                if let Some(bytes) = self.judged_capture(source) {
                    let member = &self.members[source + 1];
                    let (sender, origin) = (member.sender.clone(), member.identity.clone());
                    self.send(sender, origin, Kind::Truncated, prefix(&bytes, *keep));
                }
            }
            ProbeEvent::Fragment {
                origin,
                source,
                keep,
            } => {
                let source = self.source(*source);
                if let Some(bytes) = self.judged_capture(source) {
                    let (sender, origin) = self.origin(*origin);
                    self.send(sender, origin, Kind::Truncated, prefix(&bytes, *keep));
                }
            }
            ProbeEvent::Junk { origin, payload } => {
                // Junk starts like neither message: not like the request, and
                // not like a response, which needs one captured to compare
                // against. It is bounded below every response length.
                let payload = payload[..payload.len().min(usize::from(MAX_RAW_PAYLOAD))].to_vec();
                let response = self
                    .ledger
                    .captures()
                    .first()
                    .map(|capture| capture.bytes.clone());
                let leading = payload.first().copied();
                let junk = match (leading, response) {
                    (Some(leading), Some(response)) => {
                        Some(leading) != self.request.first().copied()
                            && Some(leading) != response.first().copied()
                    }
                    _ => false,
                };
                if junk {
                    let (sender, origin) = self.origin(*origin);
                    self.send(sender, origin, Kind::Junk, payload);
                }
            }
            ProbeEvent::Advance { steps } => {
                self.context.sleep(PROBE_STEP * u32::from(*steps)).await;
            }
        }
        self.context.sleep(PROBE_STEP).await;
        self.report.events += 1;
        self.observe(waiting);
    }

    /// The response most recently captured from `source`, if the discovering
    /// probe judges it rather than setting it aside.
    fn judged_capture(&self, source: usize) -> Option<Vec<u8>> {
        let bytes = self.ledger.latest_capture(source)?;
        matches!(
            self.class(source),
            Known::Valid { .. } | Known::Unverifiable { .. }
        )
        .then_some(bytes)
    }

    /// The sender and identity an origin selector names: a source, or the
    /// non-member.
    fn origin(&self, origin: u8) -> (RawSender, PublicKey) {
        let origin = usize::from(origin);
        if origin < usize::from(NUM_SOURCES) {
            let member = &self.members[origin + 1];
            (member.sender.clone(), member.identity.clone())
        } else {
            let (origin, sender) = self.non_member.clone();
            (sender, origin)
        }
    }

    /// Account for what this event delivered, judge it, poll the
    /// subscriptions, and note when the discovering probe stops being
    /// certainly in discovery.
    fn observe(&mut self, waiting: bool) {
        let deliveries = self.ledger.deliveries();
        assert!(
            deliveries <= self.seen + 1,
            "harness defect: {} messages were delivered to the discovering probe in one event",
            deliveries - self.seen
        );
        assert_eq!(
            deliveries,
            self.sent.len(),
            "harness defect: a message the program sent was not delivered"
        );
        let delivered_now = deliveries > self.seen;
        self.seen = deliveries;
        if delivered_now {
            self.judge();
        }

        let mut resolved = Vec::new();
        self.subscriptions
            .retain_mut(|subscription| match subscription.try_recv() {
                Ok(floor) => {
                    resolved.push(floor);
                    false
                }
                Err(TryRecvError::Empty) => true,
                Err(TryRecvError::Closed) => false,
            });
        for floor in resolved {
            // A subscription that was already waiting resolves only when the
            // floor is selected, so the floor was selected during this event;
            // one opened by this event may be served a floor cached earlier.
            self.on_floor(floor, waiting && delivered_now);
        }

        // By its contract, an attached marshal takes effect only once no
        // subscription opened before it is still waiting, and a subscription
        // dropped before a floor is selected may or may not end discovery.
        // So the probe is certainly discovering while its marshal is not
        // attached or the program has held a subscription open ever since the
        // attachment, and from the first moment it holds none, nothing about
        // its state is certain any more. Events that empty the program's
        // subscriptions deliver nothing, so the boundary needs no finer
        // placement.
        if self.attached && self.unheld_from.is_none() && self.subscriptions.is_empty() {
            self.unheld_from = Some(self.ledger.traffic().len());
        }
    }

    /// Check an emitted floor against the ledger. With `now`, the floor was
    /// selected during this event, so the resolving sample is everything the
    /// current attempt delivered; otherwise it is a prefix of that.
    fn on_floor(&mut self, floor: Floor, now: bool) {
        self.report.floor_selected = true;
        if let Some(first) = &self.floor {
            assert_eq!(
                *first, floor,
                "I8 violated: the discovering probe emitted a second, different floor"
            );
            return;
        }
        let traffic = self.ledger.traffic();
        let attempt = self.attempt(&traffic);
        // The sample the probe resolved on holds at least `f + 1` distinct
        // valid responses of the attempt, in delivery order, and the floor is
        // the highest among them. Only the earliest such prefix is required;
        // the contract does not say when the probe stops collecting.
        let prefixes = attempt
            .iter()
            .enumerate()
            .skip(sample_size() - 1)
            .filter(|(index, _)| !now || *index == attempt.len() - 1);
        let mut highest = None;
        let mut consistent = false;
        for (index, _) in prefixes {
            highest = attempt[..=index]
                .iter()
                .map(|(_, finalization)| finalization)
                .max_by_key(|finalization| finalization.round());
            if highest == Some(&floor) {
                consistent = true;
                break;
            }
        }
        assert!(
            consistent,
            "I7 violated: floor {floor:?} is not the highest finalization of any sample of at \
             least {} distinct valid committee responses in the resolving attempt; the attempt \
             delivered {attempt:?} and its highest is {highest:?}; traffic={traffic:?}",
            sample_size()
        );
        let (supplier, _) = attempt
            .iter()
            .find(|(_, finalization)| *finalization == floor)
            .expect("the floor is in the attempt");
        assert_eq!(
            self.members[supplier + 1].finalization.as_ref(),
            Some(&floor),
            "I7 violated: source {supplier} supplied floor {floor:?} but its marshal holds {:?}",
            self.members[supplier + 1].finalization
        );
        self.floor = Some(floor);
        self.report.floor_checked = true;
    }

    /// The valid responses of the current attempt: every source's own valid
    /// response delivered after the discovering probe's last request, once
    /// per source, in delivery order.
    fn attempt(&self, traffic: &[Traffic]) -> Vec<(usize, Floor)> {
        let Some(last_request) = traffic
            .iter()
            .rposition(|traffic| matches!(traffic, Traffic::Requested))
        else {
            return Vec::new();
        };
        let captures = self.ledger.captures();
        let mut members: Vec<(usize, Floor)> = Vec::new();
        for traffic in traffic.iter().skip(last_request + 1) {
            let Traffic::Delivered(delivery) = traffic else {
                continue;
            };
            let Known::Valid { source } = self.classify(&captures, &delivery.peer, &delivery.bytes)
            else {
                continue;
            };
            if !self.own(source, &delivery.peer)
                || members.iter().any(|(member, _)| *member == source)
            {
                continue;
            }
            let finalization = self.members[source + 1]
                .finalization
                .clone()
                .expect("a source that responded holds a finalization");
            members.push((source, finalization));
        }
        members
    }

    /// Classify a delivered message by content: a response some source
    /// built, known by that source's model; bytes starting like a request; or
    /// anything else. Two sources at one height build identical responses,
    /// so a response is attributed to the delivering peer when it built it.
    fn classify(&self, captures: &[Capture], peer: &PublicKey, bytes: &[u8]) -> Known {
        let built = |capture: &&Capture| capture.bytes == bytes;
        let own = |capture: &&Capture| self.members[capture.source + 1].identity == *peer;
        if let Some(capture) = captures
            .iter()
            .find(|capture| built(capture) && own(capture))
            .or_else(|| captures.iter().find(built))
        {
            return self.class(capture.source);
        }
        if bytes.starts_with(&self.request) {
            return Known::Request;
        }
        Known::Other
    }

    /// Whether `peer` is `source`.
    fn own(&self, source: usize, peer: &PublicKey) -> bool {
        self.members[source + 1].identity == *peer
    }

    /// Judge the delivery this event produced: what the contract requires of
    /// the blocker for it, checked against the blocks the probe had placed by
    /// the time it processed this delivery.
    fn judge(&mut self) {
        let traffic = self.ledger.traffic();
        let captures = self.ledger.captures();
        let (index, delivery) = traffic
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, traffic)| match traffic {
                Traffic::Delivered(delivery) => Some((index, delivery.as_ref())),
                Traffic::Requested => None,
            })
            .expect("a delivery was logged");
        let sent = self.sent.last().expect("a message was sent").clone();
        assert_eq!(
            sent.origin, delivery.peer,
            "harness defect: a delivery came from an identity other than its sender"
        );
        let peer = &delivery.peer;
        let known = self.classify(&captures, peer, &delivery.bytes);

        // The probe judges a message only while certainly discovering without
        // a floor: before its state is uncertain, and before the attempt
        // could have completed a sample.
        let judged = self.unheld_from.is_none_or(|from| index < from)
            && !self.sufficient_before(&traffic, index);
        // A committee member is judged for what it sends only while pending:
        // not counted in the current attempt, which it certainly is not when
        // none of its own valid responses was delivered since the probe's
        // last request. The non-member is never counted.
        let pending = |peer: &PublicKey| {
            self.members
                .iter()
                .position(|member| member.identity == *peer)
                .is_none_or(|member| {
                    let source = member - 1;
                    !counted_since_last_request(&traffic, index, |peer, bytes| {
                        self.classify(&captures, peer, bytes) == Known::Valid { source }
                            && self.own(source, peer)
                    })
                })
        };
        let verdict = match (sent.kind, known) {
            (Kind::Response, Known::Valid { source }) => {
                assert!(
                    self.own(source, peer),
                    "harness defect: a response was delivered by a source other than its builder"
                );
                Verdict::Pass
            }
            (Kind::Response, Known::Stale { .. } | Known::Unjudgeable { .. }) => {
                self.report.ignored += 1;
                Verdict::Open
            }
            (Kind::Response, Known::Unverifiable { .. }) if judged && pending(peer) => {
                Verdict::Block
            }
            (Kind::Replayed, Known::Valid { .. } | Known::Unverifiable { .. }) if judged => {
                Verdict::Block
            }
            (Kind::Truncated | Kind::Junk, Known::Other) if judged && pending(peer) => {
                Verdict::Block
            }
            (Kind::Response | Kind::Replayed, Known::Valid { .. } | Known::Unverifiable { .. })
            | (Kind::Truncated | Kind::Junk, Known::Other) => Verdict::Open,
            (kind, known) => panic!(
                "harness defect: a {kind:?} send was delivered as {known:?} at traffic index \
                 {index}"
            ),
        };

        match verdict {
            Verdict::Block => {
                self.report.block_checks += 1;
                assert!(
                    self.ledger.blocked_by(peer, index),
                    "I8 violated: {peer} sent {kind:?} bytes known as {known:?} at traffic index \
                     {index} while the probe was discovering and was not blocked by then",
                    kind = sent.kind
                );
            }
            Verdict::Pass => assert!(
                !self.ledger.blocked_at(peer, index),
                "I8 violated: {peer} was blocked for its own valid response at traffic index \
                 {index}"
            ),
            Verdict::Open => {}
        }
    }

    /// Whether the attempt containing `index` delivered `f + 1` distinct valid
    /// responses before `index`, from which point the probe may hold a floor.
    fn sufficient_before(&self, traffic: &[Traffic], index: usize) -> bool {
        let captures = self.ledger.captures();
        let mut sources = Vec::new();
        for traffic in traffic[..index]
            .iter()
            .rev()
            .take_while(|traffic| !matches!(traffic, Traffic::Requested))
        {
            let Traffic::Delivered(delivery) = traffic else {
                continue;
            };
            let Known::Valid { source } = self.classify(&captures, &delivery.peer, &delivery.bytes)
            else {
                continue;
            };
            if self.own(source, &delivery.peer) && !sources.contains(&source) {
                sources.push(source);
            }
        }
        sources.len() >= sample_size()
    }

    /// Learn whether a floor was cached, confirm every block reached the
    /// network, and report.
    async fn finish(mut self, outcome: ProbeOutcome) -> ProbeReport {
        self.report.outcome = outcome;

        // A floor selected while no subscription was open is cached; a final
        // subscription surfaces it. In discovery without a floor this issues
        // one more request, after every delivery the program made.
        let final_subscription = self.members[0].probe.subscribe();
        self.subscriptions.push(final_subscription);
        self.context.sleep(PROBE_STEP).await;
        self.observe(false);

        // Every block the probe placed through its blocker is a block the
        // simulated network holds.
        let blocked = self.oracle.blocked().await.expect("network is up");
        let discoverer = self.discoverer().clone();
        let blocks = self.ledger.blocks();
        for block in &blocks {
            assert!(
                blocked.contains(&(discoverer.clone(), block.peer.clone())),
                "harness defect: a block on {} did not reach the network",
                block.peer
            );
        }
        assert!(
            blocked
                .iter()
                .filter(|(from, _)| *from == discoverer)
                .all(|(_, to)| blocks.iter().any(|block| block.peer == *to)),
            "harness defect: the network holds a block the probe did not place"
        );

        let traffic = self.ledger.traffic();
        self.report.requests = self.ledger.requests();
        self.report.captures = self.ledger.captures().len();
        self.report.deliveries = self.ledger.deliveries();
        self.report.block_calls = blocks.len();
        self.report.floor_expected = self.attempt(&traffic).len() >= sample_size();
        self.report
    }
}

/// The responses a floor needs: `f + 1` distinct committee members.
fn sample_size() -> usize {
    N3f1::max_faults(COMMITTEE) as usize + 1
}

/// Whether a delivery `counts` decides the discovering probe recorded lies
/// between its last request before `index` and `index`. If none does for a
/// source, the probe cannot have counted that source and it is pending at
/// `index`.
fn counted_since_last_request(
    traffic: &[Traffic],
    index: usize,
    counts: impl Fn(&PublicKey, &[u8]) -> bool,
) -> bool {
    traffic[..index]
        .iter()
        .rev()
        .take_while(|traffic| !matches!(traffic, Traffic::Requested))
        .any(|traffic| match traffic {
            Traffic::Delivered(delivery) => counts(&delivery.peer, &delivery.bytes),
            Traffic::Requested => false,
        })
}

/// A strict prefix of a captured response, possibly empty.
fn prefix(bytes: &[u8], keep: u8) -> Vec<u8> {
    let keep = if bytes.is_empty() {
        0
    } else {
        usize::from(keep) % bytes.len()
    };
    bytes[..keep].to_vec()
}

/// A finalized history sources are seeded from.
struct Chain {
    blocks: Vec<ProbeBlock>,
    finalizations: Vec<Floor>,
}

impl Chain {
    /// Build blocks and finalizations for every height a source may hold,
    /// each in the epoch `epocher` assigns its height and certified once by
    /// the whole of `schemes`. The blocks name `leaders`, so chains with
    /// different leaders are different chains.
    fn new(leaders: &[PublicKey], schemes: &[Scheme], epocher: &FixedEpocher) -> Self {
        let genesis = Block::genesis(leaders[0].clone(), Any::initial());
        let mut blocks = vec![genesis];
        let mut finalizations = vec![Self::finalization(schemes, &blocks[0])];
        for height in 1..=usize::from(MAX_SOURCE_HEIGHT) {
            let parent = &blocks[height - 1];
            let epoch = epocher
                .containing(Height::new(height as u64))
                .expect("every source height has an epoch")
                .epoch();
            let block = Block {
                context: Context {
                    round: Round::new(epoch, View::new(height as u64)),
                    leader: leaders[height % leaders.len()].clone(),
                    parent: (View::new(height as u64 - 1), parent.digest()),
                },
                parent: parent.digest(),
                height: Height::new(height as u64),
                commitment: Any::initial(),
            };
            finalizations.push(Self::finalization(schemes, &block));
            blocks.push(block);
        }
        Self {
            blocks,
            finalizations,
        }
    }

    fn finalization(schemes: &[Scheme], block: &ProbeBlock) -> Floor {
        let proposal = Proposal {
            round: block.context.round,
            parent: block.context.parent.0,
            payload: block.digest(),
        };
        let finalizes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
            .collect();
        Finalization::from_finalizes(&schemes[0], non_empty![@finalizes.iter()], &Sequential)
            .expect("assemble finalization")
    }

    /// Inject the finalized block at `height` into a source's marshal, so it
    /// stores and serves the finalization.
    async fn inject(&self, marshal: &Marshal, height: usize) {
        let block = self.blocks[height].clone();
        let finalization = self.finalizations[height].clone();
        let round = finalization.round();
        assert!(
            marshal.verified(round, block).await,
            "marshal must persist the seeded block"
        );
        let _ = marshal.clone().report(Activity::Finalization(finalization));
        assert!(
            marshal
                .get_finalization(Height::new(height as u64))
                .await
                .is_some(),
            "marshal must store the seeded finalization"
        );
    }
}

/// Assert the receiver and sender traits are in scope.
const _: fn() = || {
    fn assert_receiver<R: commonware_p2p::Receiver<PublicKey = PublicKey>>() {}
    assert_receiver::<Observed>();
    fn assert_sender<S: commonware_p2p::Sender<PublicKey = PublicKey>>() {}
    assert_sender::<RawSender>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn tape(seed: u8) -> Vec<u8> {
        (0..64u8)
            .map(|byte| byte.wrapping_mul(29).wrapping_add(seed))
            .collect()
    }

    /// A run with nothing stale: heights 4 and 5 are unjudgeable.
    fn input(sources: [u8; 3], events: Vec<ProbeEvent>, seed: u8) -> StatefulProbeFuzzInput {
        StatefulProbeFuzzInput {
            sources,
            unverifiable: [false; 3],
            minimum_epoch: 0,
            events,
            raw_bytes: tape(seed),
        }
    }

    /// Runs one fixed input expected to resolve a floor and asserts it was
    /// checked.
    fn resolved(input: StatefulProbeFuzzInput) -> ProbeReport {
        let report = run_stateful_probe(input);
        println!("{report}");
        assert_eq!(report.outcome, ProbeOutcome::Program);
        assert!(
            report.floor_expected,
            "the program must deliver a sufficient sample: {report}"
        );
        assert!(
            report.measured(),
            "no floor was selected and checked: {report}"
        );
        report
    }

    /// Runs one fixed input expected not to resolve a floor.
    fn unresolved(input: StatefulProbeFuzzInput) -> ProbeReport {
        let report = run_stateful_probe(input);
        println!("{report}");
        assert_eq!(report.outcome, ProbeOutcome::Program);
        assert!(!report.floor_selected, "a floor was selected: {report}");
        report
    }

    /// Attach every source, subscribe, and release the sources' responses in
    /// `order`.
    fn program(order: &[u8]) -> Vec<ProbeEvent> {
        let mut events = vec![
            ProbeEvent::Attach { node: 1 },
            ProbeEvent::Attach { node: 2 },
            ProbeEvent::Attach { node: 3 },
            ProbeEvent::Subscribe,
        ];
        events.extend(
            order
                .iter()
                .map(|source| ProbeEvent::Release { source: *source }),
        );
        events
    }

    /// The floor is the highest finalization among the first `f + 1` distinct
    /// valid responses, not the first or the most common one.
    #[test]
    fn selects_highest_of_differing_sources() {
        let report = resolved(input([1, 3, 2], program(&[0, 2, 1]), 1));
        assert_eq!(report.captures, 3);
        assert_eq!(report.deliveries, 3);
        assert_eq!(report.block_calls, 0);
        resolved(input([3, 2, 1], program(&[1, 0]), 2));
    }

    /// A duplicate from a counted source does not inflate the sample.
    #[test]
    fn duplicates_do_not_inflate_the_sample() {
        let mut events = program(&[0]);
        events.push(ProbeEvent::Duplicate { source: 0 });
        events.push(ProbeEvent::Duplicate { source: 0 });
        let report = unresolved(input([2, 3, 1], events, 3));
        assert_eq!(report.deliveries, 3);
        assert_eq!(report.block_calls, 0);

        // One more distinct source completes it.
        let mut events = program(&[0]);
        events.push(ProbeEvent::Duplicate { source: 0 });
        events.push(ProbeEvent::Release { source: 1 });
        resolved(input([2, 3, 1], events, 4));
    }

    /// A pending committee member that sends a truncated response is blocked
    /// whatever the cut, and the run still resolves from the others.
    #[test]
    fn truncated_response_from_pending_member_is_blocked() {
        for keep in [0u8, 1, 3, 9, 20, 40, 43, 100] {
            let mut events = program(&[]);
            events.push(ProbeEvent::Truncate { source: 0, keep });
            events.push(ProbeEvent::Release { source: 1 });
            events.push(ProbeEvent::Release { source: 2 });
            let report = resolved(input([2, 3, 1], events, 5));
            assert_eq!(report.block_checks, 1, "keep={keep}: {report}");
            assert_eq!(report.block_calls, 1, "keep={keep}: {report}");
        }
    }

    /// A fragment of a judged response is malformed from whoever sends it: a
    /// pending member other than its builder, or the non-member.
    #[test]
    fn fragment_from_any_pending_identity_is_blocked() {
        for origin in [1u8, 3] {
            let mut events = program(&[]);
            events.push(ProbeEvent::Fragment {
                origin,
                source: 0,
                keep: 12,
            });
            events.push(ProbeEvent::Release { source: 0 });
            events.push(ProbeEvent::Release { source: 2 });
            let report = resolved(input([2, 3, 1], events, 6));
            assert_eq!(report.block_checks, 1, "origin={origin}: {report}");
            assert_eq!(report.block_calls, 1, "origin={origin}: {report}");
        }
    }

    /// A stale or unjudgeable response is neither truncated, fragmented, nor
    /// replayed: the contract settles nothing about it, so nothing is sent.
    #[test]
    fn set_aside_responses_are_not_damaged_or_replayed() {
        // Source 1 holds height 5, epoch 2, which the provider cannot judge.
        let mut events = program(&[]);
        events.push(ProbeEvent::Truncate { source: 1, keep: 9 });
        events.push(ProbeEvent::Fragment {
            origin: 3,
            source: 1,
            keep: 9,
        });
        events.push(ProbeEvent::Replay { source: 1 });
        events.push(ProbeEvent::Release { source: 0 });
        events.push(ProbeEvent::Release { source: 2 });
        let report = resolved(input([2, 5, 1], events, 7));
        assert_eq!(report.deliveries, 2, "{report}");
        assert_eq!(report.block_checks, 0, "{report}");
        assert_eq!(report.block_calls, 0, "{report}");
    }

    /// A pending committee member whose history the discovering probe cannot
    /// verify is blocked, and so is a non-member replaying such a response.
    #[test]
    fn unverifiable_response_is_blocked() {
        let mut input = input([2, 3, 1], program(&[0, 1, 2]), 8);
        input.unverifiable = [true, false, false];
        let report = resolved(input.clone());
        assert_eq!(report.block_checks, 1, "{report}");
        assert_eq!(report.block_calls, 1, "{report}");

        input.events = program(&[]);
        input.events.push(ProbeEvent::Replay { source: 0 });
        input.events.push(ProbeEvent::Release { source: 1 });
        input.events.push(ProbeEvent::Release { source: 2 });
        let report = resolved(input);
        assert_eq!(report.block_checks, 1, "{report}");
        assert_eq!(report.block_calls, 1, "{report}");
    }

    /// Blocks are attributed to the delivery the probe was processing: a
    /// valid response in between is not blamed for the blocks around it, and
    /// a member blocked twice is blocked twice.
    #[test]
    fn blocks_are_attributed_to_their_delivery() {
        let mut input = input([2, 3, 1], program(&[]), 9);
        input.unverifiable = [true, false, false];
        input.events.push(ProbeEvent::Release { source: 0 });
        input.events.push(ProbeEvent::Release { source: 1 });
        input
            .events
            .push(ProbeEvent::Truncate { source: 0, keep: 7 });
        input.events.push(ProbeEvent::Release { source: 2 });
        let report = resolved(input);
        assert_eq!(report.block_checks, 2, "{report}");
        assert_eq!(report.block_calls, 2, "{report}");
    }

    /// A non-member replaying a valid response is blocked and does not count.
    #[test]
    fn non_member_replay_is_blocked_and_ignored() {
        let mut events = program(&[0]);
        events.push(ProbeEvent::Replay { source: 1 });
        events.push(ProbeEvent::Replay { source: 2 });
        let report = unresolved(input([2, 3, 1], events, 10));
        assert_eq!(report.block_checks, 2);
        assert_eq!(report.block_calls, 2);

        let mut events = program(&[0]);
        events.push(ProbeEvent::Replay { source: 1 });
        events.push(ProbeEvent::Release { source: 1 });
        let report = resolved(input([2, 3, 1], events, 11));
        assert_eq!(report.block_calls, 1);
    }

    /// Junk never contributes and blocks a pending member or the non-member;
    /// bytes starting like the request or like a response are not junk and
    /// are not sent; the run still resolves from the valid responses.
    #[test]
    fn junk_is_blocked_and_look_alikes_are_not_sent() {
        let mut events = program(&[]);
        // Nothing is captured yet, so nothing is sent.
        events.insert(
            0,
            ProbeEvent::Junk {
                origin: 1,
                payload: vec![0xFF; 32],
            },
        );
        // Starts like the request, like a response, and like neither.
        events.push(ProbeEvent::Junk {
            origin: 0,
            payload: vec![0, 7, 7],
        });
        events.push(ProbeEvent::Junk {
            origin: 3,
            payload: vec![1, 2, 3],
        });
        events.push(ProbeEvent::Junk {
            origin: 1,
            payload: vec![0xFF; 32],
        });
        events.push(ProbeEvent::Junk {
            origin: 3,
            payload: vec![9],
        });
        events.push(ProbeEvent::Release { source: 1 });
        events.push(ProbeEvent::Release { source: 2 });
        let report = resolved(input([2, 3, 1], events, 12));
        assert_eq!(report.deliveries, 4, "{report}");
        assert_eq!(report.block_checks, 2, "{report}");
        assert_eq!(report.block_calls, 2, "{report}");
    }

    /// Dropping the only subscription is noticed lazily: a response arriving
    /// before the actor wakes again may still complete the sample and cache a
    /// floor, which a later subscription is served.
    #[test]
    fn floor_cached_across_lazily_noticed_cancellation() {
        let mut events = program(&[0]);
        events.push(ProbeEvent::Unsubscribe);
        events.push(ProbeEvent::Release { source: 1 });
        events.push(ProbeEvent::Subscribe);
        let report = resolved(input([2, 3, 1], events, 13));
        assert_eq!(report.requests, 1, "{report}");
    }

    /// Once the actor notices every subscription is gone, discovery is
    /// cancelled: responses reset the sample, and a floor needs a new
    /// subscription and the request it issues.
    #[test]
    fn cancelled_subscription_needs_a_new_request() {
        // The retry wakes the actor, which then notices the dropped
        // subscription; the responses after that are discarded. The run's
        // closing subscription finds no floor and issues the third request.
        let mut events = program(&[0]);
        events.push(ProbeEvent::Unsubscribe);
        events.push(ProbeEvent::Advance { steps: 11 });
        events.push(ProbeEvent::Release { source: 1 });
        events.push(ProbeEvent::Release { source: 2 });
        let report = unresolved(input([2, 3, 1], events, 14));
        assert_eq!(report.requests, 3, "{report}");
        assert_eq!(report.deliveries, 3, "{report}");

        // A new subscription re-requests, and the sample forms again.
        let mut events = program(&[0]);
        events.push(ProbeEvent::Unsubscribe);
        events.push(ProbeEvent::Advance { steps: 11 });
        events.push(ProbeEvent::Subscribe);
        events.push(ProbeEvent::Release { source: 1 });
        events.push(ProbeEvent::Release { source: 2 });
        let report = resolved(input([2, 3, 1], events, 15));
        assert_eq!(report.requests, 3, "{report}");
    }

    /// Attaching the discovering probe's marshal before any subscription puts
    /// it in service: it never solicits, never resolves a floor, and, holding
    /// no finalization, never answers a request either, which is what lets
    /// the ledger count every message it sends as a request.
    #[test]
    fn attachment_before_subscription_enters_service() {
        let mut events = vec![ProbeEvent::Attach { node: 0 }];
        events.extend(program(&[0, 1, 2]));
        events.push(ProbeEvent::Truncate { source: 0, keep: 0 });
        let report = unresolved(input([2, 3, 1], events, 16));
        assert_eq!(report.requests, 0, "{report}");
        assert_eq!(report.captures, 0, "{report}");
        assert_eq!(report.deliveries, 0, "{report}");
        assert_eq!(report.block_checks, 0, "{report}");
    }

    /// Attaching the discovering probe's marshal while a subscription waits
    /// keeps it in discovery: it still judges what it is sent, blocking a
    /// non-member's replay and a member's truncated response, and still
    /// resolves.
    #[test]
    fn attachment_while_waiting_keeps_discovery_judging() {
        let mut events = program(&[]);
        events.push(ProbeEvent::Attach { node: 0 });
        events.push(ProbeEvent::Replay { source: 1 });
        events.push(ProbeEvent::Truncate {
            source: 0,
            keep: 30,
        });
        events.push(ProbeEvent::Release { source: 1 });
        events.push(ProbeEvent::Release { source: 2 });
        let report = resolved(input([2, 3, 1], events, 17));
        assert_eq!(report.block_checks, 2, "{report}");
        assert_eq!(report.block_calls, 2, "{report}");
    }

    /// Dropping the last subscription after the marshal is attached leaves the
    /// probe's state to the actor, which notices the drop only at its next
    /// wake-up: today the delivery that wakes it is still judged, and only
    /// later traffic is served. The oracle requires nothing here; this pins
    /// the current behaviour.
    #[test]
    fn delivery_after_unsubscribe_is_left_to_the_actor() {
        for (event, block_calls) in [
            (ProbeEvent::Truncate { source: 0, keep: 5 }, 1),
            (ProbeEvent::Replay { source: 1 }, 1),
            (ProbeEvent::Release { source: 1 }, 0),
        ] {
            let mut events = program(&[]);
            events.push(ProbeEvent::Attach { node: 0 });
            events.push(ProbeEvent::Unsubscribe);
            events.push(event.clone());
            events.push(ProbeEvent::Subscribe);
            events.push(ProbeEvent::Release { source: 2 });
            let report = unresolved(input([2, 3, 1], events, 18));
            assert_eq!(report.block_checks, 0, "{event:?}: {report}");
            assert_eq!(report.block_calls, block_calls, "{event:?}: {report}");
            assert_eq!(report.requests, 1, "{event:?}: {report}");
        }
    }

    /// A source attached only after the first request answers the retry, and
    /// a response released after the retry counts toward the new attempt.
    #[test]
    fn retry_resets_the_sample() {
        let events = vec![
            ProbeEvent::Attach { node: 1 },
            ProbeEvent::Subscribe,
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Attach { node: 2 },
            ProbeEvent::Advance { steps: 11 },
            ProbeEvent::Release { source: 1 },
            ProbeEvent::Release { source: 0 },
        ];
        let report = resolved(input([2, 3, 1], events, 19));
        assert!(report.requests >= 2, "{report}");
    }

    /// A response below the minimum epoch is stale: never counted, and the
    /// floor comes from the others. The actor is left to decide about the
    /// sender; today it is not blocked.
    #[test]
    fn stale_responses_are_ignored() {
        // Height 1 is epoch 0; with the minimum at 1 it is stale, while
        // heights 2 and 3 are epoch 1.
        let mut input = input([1, 3, 2], program(&[0, 0, 1]), 20);
        input.minimum_epoch = 1;
        let report = unresolved(input.clone());
        assert_eq!(report.ignored, 2, "{report}");
        assert_eq!(report.block_calls, 0, "{report}");

        input.events.push(ProbeEvent::Release { source: 2 });
        let report = resolved(input);
        assert_eq!(report.ignored, 2, "{report}");
        assert_eq!(report.block_calls, 0, "{report}");
    }

    /// A response from an epoch the discovering probe has no verifier for is
    /// unjudgeable: never counted, even when it is the highest finalization
    /// on offer. The actor is left to decide about the sender; today it is
    /// not blocked.
    #[test]
    fn unjudgeable_responses_are_ignored() {
        // Heights 4 and 5 are epoch 2, beyond the provider's epochs.
        let report = unresolved(input([5, 4, 2], program(&[0, 1]), 21));
        assert_eq!(report.ignored, 2, "{report}");
        assert_eq!(report.block_calls, 0, "{report}");

        let report = resolved(input([5, 3, 2], program(&[0, 1, 2]), 22));
        assert_eq!(report.ignored, 1, "{report}");
        assert_eq!(report.block_calls, 0, "{report}");
    }

    /// Sources without a finalization answer nothing, so no sample forms.
    #[test]
    fn empty_sources_yield_no_floor() {
        let report = unresolved(input([0, 0, 0], program(&[0, 1, 2]), 23));
        assert_eq!(report.captures, 0);
        assert!(!report.floor_expected);
    }

    /// The program with no events measures nothing and says so.
    #[test]
    fn empty_program_is_unmeasured() {
        let report = run_stateful_probe(input([1, 1, 1], Vec::new(), 24));
        assert!(!report.measured());
        assert_eq!(report.events, 0);
    }

    /// I6: a replayed input observes the same thing.
    #[test]
    fn replay_is_reproducible() {
        let first = run_stateful_probe(input([1, 3, 2], program(&[0, 2, 1]), 25));
        let second = run_stateful_probe(input([1, 3, 2], program(&[0, 2, 1]), 25));
        assert_eq!(first, second);
    }

    /// P5: the byte tape never reaches `Debug` output; its length may.
    #[test]
    fn debug_elides_the_tape() {
        let mut input = input([1, 2, 3], vec![ProbeEvent::Subscribe], 0);
        input.raw_bytes = vec![0xAB; 1024];
        let rendered = format!("{input:?}");
        assert!(rendered.contains("raw_bytes_len: 1024"));
        assert!(!rendered.contains("171"));
    }
}
