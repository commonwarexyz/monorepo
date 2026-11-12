//! The probe driver: real [`probe::Actor`]s over the deterministic simulated
//! network, driven through their public mailbox and P2P boundaries by a
//! bounded adversarial event program. No consensus and no ceremony runs.
//!
//! Five identities take part. Four are the dealers of every epoch: one runs
//! the discovering probe and three run source probes, each over a real marshal
//! actor seeded with the finalized history the input selects. The fifth is
//! tracked as a next player and is not a dealer; the program sends as it.
//!
//! The history is a fabricated chain: blocks of the reshare chain's type in
//! epochs of two blocks, each final block of an epoch carrying the description
//! of the next, every description built from a trusted deal over the mock
//! group, and every block finalized under the threshold scheme of the first
//! deal, whose group public key every marshal and probe verifies with. A
//! source may instead hold a foreign chain: the same construction over other
//! deals, so its finalizations decode and do not verify.
//!
//! Every source probe's sender is wrapped so that the response it builds is
//! captured as opaque bytes instead of being sent, together with the request
//! it answers. The event program then releases, duplicates, replays, or cuts
//! those bytes, and injects junk, all through the simulated network. The
//! discovering probe's sender, receiver, and blocker are wrapped too, so the
//! run's ledger holds, in the probe's own order, every request it sent, every
//! message it took, and every block it placed.
//!
//! Nothing here decodes a probe message or reproduces the probe's
//! verification, floor selection, or state transitions. The driver records
//! what happened and [`invariants`] judges it once the runtime has stopped:
//! the artifact against what each source was seeded with (I12, I13) and every
//! block against what was delivered (I14). No artifact is required of a run.

use super::{
    COMMITTEE, DkgProbeFuzzInput, Info, MockGroup, PublicKey, RESHARE_NAMESPACE,
    app::{BLOCK_CFG, Block, BlockContext},
    context::EngineContext,
    invariants::{
        self, PROBE_TAGS, ProbeArtifact, ProbeChain, ProbeCounts, ProbeFinalization, ProbeLedger,
        ProbeRun, ProbeSend, ProbeShape, ProbeSource, ProbeStep,
    },
    joiner::Probe,
    network::harness,
    probe_input::SOURCES,
    public_keys,
    reshare_stack::{Variant, archives, backfill_config, marshal_config},
    runner::{self, Report},
    scheme::{Scheme, certificate_verifier},
    signers,
};
use crate::stateful::{
    MAILBOX_SIZE, MAX_ADVANCE_STEPS, MAX_RAW_PAYLOAD, MAX_SOURCE_HEIGHT, PAGE_CACHE_SIZE,
    PAGE_SIZE, PROBE_EPOCH_LENGTH, PROBE_RETRY_TIMEOUT, PROBE_STEP, ProbeEvent,
    observe::{Acking, Observed, ObservedBlocker, Witness, certify, inject, prefix},
    runner::network,
    stack::TEST_QUOTA,
};
use commonware_consensus::{
    marshal::{
        Start,
        core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
        resolver::p2p as marshal_resolver,
    },
    simplex::types::{Context, Proposal},
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View},
};
use commonware_cryptography::{
    Digestible as _,
    bls12381::{dkg::feldman_desmedt::deal, primitives::sharing::Mode},
};
use commonware_glue::dkg::{
    probe,
    types::{EpochOutcome, Payload},
};
use commonware_macros::select;
use commonware_p2p::{
    Recipients, Sender as _,
    simulated::{Oracle, Receiver, Sender},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, IoBuf, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{
    N3f1, NZDuration,
    channel::oneshot::{self, error::TryRecvError},
    ordered::Set,
    sequence::Unit,
};
use futures::future::select_all;
use std::{collections::BTreeMap, fmt, time::Duration};

/// Label the driver reports under.
const TARGET: &str = "glue-dkg-probe";

/// Channel identifiers.
const CHANNEL_PROBE: u64 = 0;
const CHANNEL_BACKFILL: u64 = 1;

/// The engine of the discovering probe. The sources are the engines after it.
const DISCOVERER: usize = 0;

/// Artifact subscriptions the program may hold open at once.
const MAX_SUBSCRIPTIONS: usize = 2;

/// How long the discovering probe waits before it asks again or tries
/// another responder. It is the stateful probe target's timeout, which the
/// event bounds this target reuses were set for: ten event settles, so a
/// phase of a discovery that takes more events is retried, and shorter than
/// an advance of ten steps with its settle, so one such advance lets it
/// expire whenever the probe last sent a request.
const RETRY_TIMEOUT: Duration = PROBE_RETRY_TIMEOUT;

// An advance of the most steps a program draws outlasts the retry timeout.
const _: () =
    assert!(PROBE_STEP.as_millis() * MAX_ADVANCE_STEPS as u128 > RETRY_TIMEOUT.as_millis());

/// Bound on the simulated duration of a run. The longest program, of only the
/// longest advances, ends before it, so it is reached only by a run that
/// stalls.
const RUN_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a marshal's fetch waits for a peer. No marshal of this target
/// fetches.
const FETCH_TIMEOUT: Duration = Duration::from_millis(500);

/// The kinds of event, in the order the report counts them.
const KINDS: [&str; 10] = [
    "subscribe",
    "unsubscribe",
    "attach",
    "release",
    "duplicate",
    "replay",
    "truncate",
    "fragment",
    "junk",
    "advance",
];

type Marshal = MarshalMailbox<Scheme, Variant>;
type RawSender = Sender<PublicKey, deterministic::Context>;

/// Why a probe run stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Every event was executed.
    Program,
    /// The run's bounded timeout expired.
    Timeout,
    /// A marshal or a probe stopped.
    Stopped,
}

impl fmt::Display for ProbeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Program => f.write_str("program"),
            Self::Timeout => f.write_str("timeout"),
            Self::Stopped => f.write_str("stopped"),
        }
    }
}

/// What one probe run observed. The counts show how much each check
/// compared, so a run that emitted no artifact reads as such.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeReport {
    /// Why the run stopped.
    pub outcome: ProbeOutcome,
    /// Events executed, by kind: subscribe, unsubscribe, attach, release,
    /// duplicate, replay, truncate, fragment, junk, advance.
    pub events: [usize; KINDS.len()],
    /// How much each check compared.
    pub counts: ProbeCounts,
}

impl ProbeReport {
    /// Whether the discovering probe emitted an artifact, which the checks
    /// then compared.
    pub const fn measured(&self) -> bool {
        self.counts.floors > 0 && self.counts.comparisons > 0
    }
}

impl fmt::Display for ProbeReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{TARGET}] outcome={} events={}",
            self.outcome,
            self.events.iter().sum::<usize>(),
        )?;
        for (kind, count) in KINDS.iter().zip(self.events) {
            write!(f, " {kind}={count}")?;
        }
        write!(
            f,
            " solicitations={} fetches={} latest_replies={} boundary_replies={} block_replies={} \
             deliveries={} refusals={} admissions={} unsettled={} blocks={} blocked_peers={} \
             artifacts={} floors={} comparisons={}",
            self.counts.solicitations,
            self.counts.fetches,
            self.counts.latest_replies,
            self.counts.boundary_replies,
            self.counts.block_replies,
            self.counts.deliveries,
            self.counts.refusals,
            self.counts.admissions,
            self.counts.unsettled,
            self.counts.blocks,
            self.counts.blocked_peers,
            self.counts.artifacts,
            self.counts.floors,
            self.counts.comparisons,
        )
    }
}

impl Report for ProbeReport {
    fn measured(&self) -> bool {
        Self::measured(self)
    }
}

/// libFuzzer entry point.
pub fn fuzz_dkg_probe(input: DkgProbeFuzzInput) {
    runner::fuzz(input.raw_bytes.clone(), input, run_dkg_probe);
}

/// Run one event program and return what the run measured.
///
/// A run is fully determined by its input.
pub fn run_dkg_probe(input: DkgProbeFuzzInput) -> ProbeReport {
    measure(&observe(input))
}

/// What a run observed, to be checked once the runtime has stopped.
struct Observations {
    outcome: ProbeOutcome,
    events: [usize; KINDS.len()],
    run: ProbeRun,
    /// Engines of which a marshal or a probe stopped before the run ended.
    stopped: Vec<usize>,
}

/// Where a run stands when a negative control may plant a fault in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Every actor has started and no event has been executed.
    Started,
    /// Every event has been executed and the closing window begins.
    Closing,
}

/// Run one event program and return what was observed of it.
fn observe(input: DkgProbeFuzzInput) -> Observations {
    observe_planted(input, async |_, _| {})
}

/// Run one event program with `plant` called at every [`Stage`], and return
/// what was observed of it.
///
/// libFuzzer plants nothing. A test plants a fault in the running harness, so
/// that the fault is rejected by the measurement every run goes through. No
/// engine of this target is compromised, so no panic is tolerated.
fn observe_planted(
    input: DkgProbeFuzzInput,
    plant: impl AsyncFn(&mut Harness, Stage),
) -> Observations {
    let (observed, panics) = runner::execute(input.raw_bytes.clone(), |context| {
        run(context, input, plant)
    });
    invariants::check_panics(&panics, &[]);
    invariants::check_engines_running(&observed.stopped);
    observed
}

/// Measurement point, outside the runtime so a violation is never caught.
fn measure(observed: &Observations) -> ProbeReport {
    ProbeReport {
        outcome: observed.outcome,
        events: observed.events,
        counts: invariants::check_probe(&observed.run),
    }
}

/// A chain the harness fabricates: the description of every epoch, the block
/// at every height a source may hold, and the finalization of each.
struct Chain {
    /// Verifies the chain's finalizations, in every epoch.
    verifier: Scheme,
    /// The description of each epoch, from epoch zero.
    infos: Vec<Info>,
    /// The block at each height, from genesis.
    blocks: Vec<Block>,
    /// The finalization of the block at each height, from height one.
    finalizations: Vec<ProbeFinalization>,
}

impl Chain {
    /// Fabricate a chain among `committee`, whose members deal and receive
    /// every epoch's shares, with `next` announced as each epoch's next
    /// players.
    ///
    /// Every epoch's description carries the output of its own trusted deal.
    /// The first deal's shares finalize every block, as a group public key
    /// that no reshare changes would.
    fn new(
        context: &mut deterministic::Context,
        mode: Mode,
        committee: &Set<PublicKey>,
        next: &Set<PublicKey>,
        epocher: &FixedEpocher,
    ) -> Self {
        let top = u64::from(MAX_SOURCE_HEIGHT);
        let last_epoch = epocher
            .containing(Height::new(top))
            .expect("every source height has an epoch")
            .epoch();
        let mut signers = Vec::new();
        let infos: Vec<Info> = (0..=last_epoch.next().get())
            .map(|epoch| {
                let (output, shares) =
                    deal::<MockGroup, _, N3f1>(&mut *context, mode, committee.clone())
                        .expect("a trusted deal among the committee must succeed");
                if epoch == 0 {
                    signers = shares
                        .values()
                        .iter()
                        .map(|share| {
                            Scheme::signer(
                                RESHARE_NAMESPACE,
                                committee.clone(),
                                output.public().clone(),
                                share.clone(),
                            )
                            .expect("a dealt share must sign")
                        })
                        .collect();
                }
                Info {
                    outcome: EpochOutcome::Success,
                    epoch: Epoch::new(epoch),
                    output,
                    players: committee.clone(),
                    next_players: next.clone(),
                    directory: Unit,
                }
            })
            .collect();
        let verifier = certificate_verifier(*infos[0].output.public().public());

        let mut blocks = vec![Block::genesis(committee[0].clone(), infos[0].clone())];
        let mut finalizations = Vec::new();
        for height in 1..=top {
            let parent = blocks[height as usize - 1].digest();
            let bounds = epocher
                .containing(Height::new(height))
                .expect("every source height has an epoch");
            let payload = (bounds.last() == Height::new(height))
                .then(|| Payload::EpochInfo(infos[bounds.epoch().next().get() as usize].clone()));
            let context: BlockContext = Context {
                round: Round::new(bounds.epoch(), View::new(height)),
                leader: committee[height as usize % committee.len()].clone(),
                parent: (View::new(height - 1), parent),
            };
            let proposal_round = context.round;
            let block = Block::new(context, parent, Height::new(height), payload);
            finalizations.push(certify(
                &signers,
                Proposal::new(proposal_round, View::new(height - 1), block.digest()),
            ));
            blocks.push(block);
        }
        Self {
            verifier,
            infos,
            blocks,
            finalizations,
        }
    }

    /// The finalization of the block at `height`, which is at least one.
    fn finalization(&self, height: u64) -> &ProbeFinalization {
        &self.finalizations[height as usize - 1]
    }

    /// What the oracle is told of this chain.
    fn record(&self, epocher: &FixedEpocher) -> ProbeChain {
        let boundaries: BTreeMap<_, _> = self
            .infos
            .iter()
            .skip(1)
            .map(|info| {
                let height = info
                    .epoch
                    .previous()
                    .and_then(|ending| epocher.last(ending))
                    .expect("every later epoch follows a final block");
                (
                    info.epoch,
                    (self.finalization(height.get()).clone(), info.clone()),
                )
            })
            .collect();
        ProbeChain {
            genesis: self.infos[0].clone(),
            finalizations: self.finalizations.clone(),
            boundaries,
        }
    }
}

/// What a member's wrappers report to the run's ledger. The discovering
/// probe's deliveries and blocks are steps of the run. A source's deliveries
/// are the requests its responses answer, and its blocks are read from the
/// network's record.
#[derive(Clone)]
struct Tap {
    ledger: ProbeLedger,
    member: usize,
}

impl Witness for Tap {
    fn delivered(&self, peer: &PublicKey, bytes: &[u8]) {
        match self.member.checked_sub(1) {
            None => self.ledger.note(ProbeStep::Delivered {
                peer: peer.clone(),
                bytes: bytes.to_vec(),
            }),
            Some(source) => self.ledger.asked(source, bytes),
        }
    }

    fn blocked(&self, peer: &PublicKey) {
        if self.member == DISCOVERER {
            self.ledger.note(ProbeStep::Blocked { peer: peer.clone() });
        }
    }
}

/// One dealer's stack: its probe, the marshal its probe may be attached to,
/// and a raw handle on its probe channel.
struct Member {
    identity: PublicKey,
    probe: Probe,
    marshal: Marshal,
    sender: RawSender,
    /// The captured response this member most recently delivered as itself.
    released: Option<(usize, Vec<u8>)>,
}

struct Harness {
    context: deterministic::Context,
    oracle: Oracle<PublicKey, deterministic::Context>,
    ledger: ProbeLedger,
    /// The dealers: the discovering probe, then the sources.
    members: Vec<Member>,
    /// The identity that is tracked and is not a dealer, and its channel. The
    /// receiver is kept so the channel stays open.
    outsider: (PublicKey, RawSender, Receiver<PublicKey>),
    subscriptions: Vec<oneshot::Receiver<ProbeArtifact>>,
    events: [usize; KINDS.len()],
}

/// What setup leaves for the oracle beside the running harness.
struct Fixture {
    sources: Vec<ProbeSource>,
    chain: ProbeChain,
    foreign: ProbeChain,
    bootstrap: Epoch,
    persisted: Option<ProbeFinalization>,
    /// Every marshal's and every probe's handle, with its engine.
    handles: Vec<(usize, Handle<()>)>,
}

async fn run(
    context: deterministic::Context,
    input: DkgProbeFuzzInput,
    plant: impl AsyncFn(&mut Harness, Stage),
) -> Observations {
    let (mut harness, fixture) = Harness::setup(context, &input).await;
    let (engines, handles): (Vec<usize>, Vec<Handle<()>>) = fixture.handles.into_iter().unzip();
    let timeout = harness.context.sleep(RUN_TIMEOUT);
    let mut stopped = Vec::new();

    // Every marshal and every probe is watched from the first event to the
    // end of the closing window, so one that stops at any point is recorded.
    let outcome = {
        let session = async {
            plant(&mut harness, Stage::Started).await;
            let outcome = {
                let program = async {
                    for event in &input.events {
                        harness.step(event).await;
                    }
                };
                select! {
                    _ = timeout => ProbeOutcome::Timeout,
                    _ = program => ProbeOutcome::Program,
                }
            };
            plant(&mut harness, Stage::Closing).await;
            harness.finish().await;
            outcome
        };
        select! {
            (_, index, _) = select_all(handles) => {
                stopped.push(engines[index]);
                ProbeOutcome::Stopped
            },
            outcome = session => outcome,
        }
    };

    let blocked = runner::blocked(&harness.oracle).await;
    Observations {
        outcome,
        events: harness.events,
        run: ProbeRun {
            discoverer: harness.members[DISCOVERER].identity.clone(),
            outsider: harness.outsider.0.clone(),
            sources: fixture.sources,
            chain: fixture.chain,
            foreign: fixture.foreign,
            bootstrap: fixture.bootstrap,
            persisted: fixture.persisted,
            steps: harness.ledger.steps(),
            captures: harness.ledger.captures(),
            blocked,
        },
        stopped,
    }
}

impl Harness {
    /// Fabricate the chains, start the network, and start every dealer's
    /// marshal and probe, seeding each source with the history the input
    /// selects.
    async fn setup(
        mut context: deterministic::Context,
        input: &DkgProbeFuzzInput,
    ) -> (Self, Fixture) {
        let identities: Vec<PublicKey> = public_keys(&signers(COMMITTEE.get() + 1));
        let (dealers, outsider) = identities.split_at(SOURCES + 1);
        let outsider = outsider[0].clone();
        let oracle = network(&context, &identities).await;

        // The dealers deal and receive every epoch's shares. The identity
        // outside them is announced as a next player, so every probe tracks
        // it without soliciting it.
        let committee = Set::from_iter_dedup(dealers.iter().cloned());
        let next = Set::from_iter_dedup(
            dealers[1..]
                .iter()
                .cloned()
                .chain(std::iter::once(outsider.clone())),
        );
        let epocher = FixedEpocher::new(PROBE_EPOCH_LENGTH);
        let chain = Chain::new(
            &mut context,
            input.sharing_mode,
            &committee,
            &next,
            &epocher,
        );
        let foreign = Chain::new(
            &mut context,
            input.sharing_mode,
            &committee,
            &next,
            &epocher,
        );
        for (ours, theirs) in chain.finalizations.iter().zip(&foreign.finalizations) {
            assert!(
                ours.verify(&mut context, &chain.verifier, &Sequential),
                "harness defect: a finalization of the fabricated chain does not verify"
            );
            assert!(
                !theirs.verify(&mut context, &chain.verifier, &Sequential),
                "harness defect: a foreign finalization verifies under the fabricated chain's key"
            );
        }

        // What the discovering probe is configured with: the checkpoint of
        // the selected epoch, and the persisted floor if one is selected. A
        // control beyond what the chain holds selects the last it holds.
        let checkpoint =
            &chain.infos[usize::from(input.bootstrap_epoch).min(chain.infos.len() - 1)];
        let bootstrap = checkpoint.epoch;
        let persisted = input.floor.map(|height| {
            chain
                .finalization(u64::from(height.clamp(1, MAX_SOURCE_HEIGHT)))
                .clone()
        });

        let ledger = ProbeLedger::default();
        let mut members = Vec::with_capacity(dealers.len());
        let mut sources = Vec::with_capacity(SOURCES);
        let mut handles = Vec::new();
        for (member, identity) in dealers.iter().enumerate() {
            let source = member.checked_sub(1);
            let history = match source {
                Some(source) if input.foreign[source] => &foreign,
                _ => &chain,
            };
            let node = EngineContext::new(
                context.child("member").with_attribute("index", member),
                member,
            );
            let control = oracle.control(identity.clone());
            let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
            let prefix = format!("member-{member}");

            // Marshal, with its backfill resolver and archives, starting from
            // the genesis of the chain the member holds.
            let backfill = control
                .register(CHANNEL_BACKFILL, TEST_QUOTA)
                .await
                .expect("channel registration failed");
            let resolver = marshal_resolver::init(
                node.child("marshal_resolver"),
                backfill_config(
                    identity,
                    oracle.manager(),
                    control.clone(),
                    NZDuration!(FETCH_TIMEOUT),
                ),
                backfill,
            );
            let (finalizations, blocks) = archives(&node, &prefix, &page_cache).await;
            let (marshal_actor, marshal, _): (_, Marshal, _) = MarshalActor::init(
                node.child("marshal"),
                finalizations,
                blocks,
                marshal_config(
                    history.verifier.clone(),
                    epocher.clone(),
                    Start::Genesis(history.blocks[0].clone().digested()),
                    prefix,
                    page_cache,
                ),
            )
            .await;
            handles.push((
                member,
                marshal_actor.start_unbuffered(Acking::<Block>::default(), resolver),
            ));

            // Seed a source's marshal before any discovery begins, and record
            // exactly what it then holds.
            if let Some(source) = source {
                let mut held = Vec::new();
                for height in 1..=u64::from(input.sources[source].min(MAX_SOURCE_HEIGHT)) {
                    inject(
                        &marshal,
                        Height::new(height),
                        history.blocks[height as usize].clone().digested(),
                        history.finalization(height).clone(),
                    )
                    .await;
                    let stored = marshal
                        .get_finalization(Height::new(height))
                        .await
                        .expect("marshal must hold the seeded finalization");
                    let block = marshal
                        .get_block(Height::new(height))
                        .await
                        .expect("marshal must hold the seeded block");
                    assert!(
                        stored == *history.finalization(height)
                            && block.digest() == history.blocks[height as usize].digest(),
                        "harness defect: marshal holds another block or finalization than it \
                         was seeded"
                    );
                    held.push(stored);
                }
                sources.push(ProbeSource {
                    engine: member,
                    identity: identity.clone(),
                    foreign: input.foreign[source],
                    finalizations: held,
                });
            }

            // The probe, over a wrapped sender: the discovering probe's sends
            // are recorded as requests and forwarded, and a source's are
            // captured and withheld for the program to deliver.
            let (sender, receiver) = control
                .register(CHANNEL_PROBE, TEST_QUOTA)
                .await
                .expect("channel registration failed");
            let tap = Tap {
                ledger: ledger.clone(),
                member,
            };
            let (wrapped, _) = sender.clone().split_with(harness({
                let ledger = ledger.clone();
                move |_, intended: &Recipients<PublicKey>, message: &IoBuf| match source {
                    None => {
                        ledger.note(ProbeStep::Requested {
                            recipients: intended.clone(),
                            bytes: message.as_ref().to_vec(),
                        });
                        Some(intended.clone())
                    }
                    Some(source) => {
                        ledger.captured(source, message.as_ref());
                        None
                    }
                }
            }));
            let (bootstrap, floor) = match source {
                None => (
                    probe::Bootstrap {
                        epoch: bootstrap,
                        participants: checkpoint.participants(),
                        directory: Unit,
                    },
                    persisted.clone(),
                ),
                Some(_) => (
                    probe::Bootstrap {
                        epoch: Epoch::zero(),
                        participants: history.infos[0].participants(),
                        directory: Unit,
                    },
                    None,
                ),
            };
            let (actor, mailbox) =
                probe::Actor::<_, _, Scheme, Variant, _, _>::new(probe::Config {
                    context: node.child("probe"),
                    manager: oracle.manager(),
                    bootstrap,
                    floor,
                    verifier: history.verifier.clone(),
                    genesis: history.infos[0].clone(),
                    strategy: Sequential,
                    blocker: ObservedBlocker::new(control, tap.clone()),
                    blocks_per_epoch: PROBE_EPOCH_LENGTH,
                    retry_timeout: NZDuration!(RETRY_TIMEOUT),
                    mailbox_size: MAILBOX_SIZE,
                    block_codec_config: BLOCK_CFG,
                });
            handles.push((
                member,
                actor.start((wrapped, Observed::new(receiver, Some(tap)))),
            ));

            members.push(Member {
                identity: identity.clone(),
                probe: mailbox,
                marshal,
                sender,
                released: None,
            });
        }

        let (sender, receiver) = oracle
            .control(outsider.clone())
            .register(CHANNEL_PROBE, TEST_QUOTA)
            .await
            .expect("channel registration failed");
        let fixture = Fixture {
            sources,
            chain: chain.record(&epocher),
            foreign: foreign.record(&epocher),
            bootstrap,
            persisted,
            handles,
        };
        let harness = Self {
            context,
            oracle,
            ledger,
            members,
            outsider: (outsider, sender, receiver),
            subscriptions: Vec::new(),
            events: [0; KINDS.len()],
        };
        (harness, fixture)
    }

    /// The position of the source a selector names.
    const fn source(selector: u8) -> usize {
        selector as usize % SOURCES
    }

    /// The response of a source a selector names, with its position among
    /// the captures: the selector modulo the source count names the source,
    /// and the quotient how many distinct responses to go back from its
    /// newest.
    fn captured(&self, selector: u8) -> Option<(usize, Vec<u8>)> {
        self.ledger
            .recent(Self::source(selector), usize::from(selector) / SOURCES)
    }

    /// The sender and identity an origin selector names: a source, or the
    /// identity that is not a dealer.
    fn origin(&self, origin: u8) -> (RawSender, PublicKey) {
        match self.members.get(usize::from(origin) + 1) {
            Some(member) => (member.sender.clone(), member.identity.clone()),
            None => (self.outsider.1.clone(), self.outsider.0.clone()),
        }
    }

    /// The sender and identity of the source at `position`.
    fn sender(&self, position: usize) -> (RawSender, PublicKey) {
        let member = &self.members[position + 1];
        (member.sender.clone(), member.identity.clone())
    }

    /// Send `bytes` to the discovering probe as `origin`, and record the send.
    fn send(
        &self,
        (mut sender, origin): (RawSender, PublicKey),
        shape: ProbeShape,
        bytes: Vec<u8>,
    ) {
        self.ledger.note(ProbeStep::Sent(ProbeSend {
            origin,
            shape,
            bytes: bytes.clone(),
        }));
        let discoverer = self.members[DISCOVERER].identity.clone();
        sender.send(Recipients::One(discoverer), bytes, false);
    }

    /// Execute one event, let the actors settle, and observe.
    async fn step(&mut self, event: &ProbeEvent) {
        let kind = match event {
            ProbeEvent::Subscribe => {
                if self.subscriptions.len() < MAX_SUBSCRIPTIONS {
                    self.subscribe();
                }
                0
            }
            ProbeEvent::Unsubscribe => {
                if !self.subscriptions.is_empty() {
                    self.subscriptions.remove(0);
                    self.ledger.note(ProbeStep::Unsubscribed);
                }
                1
            }
            ProbeEvent::Attach { node } => {
                let node = usize::from(*node) % self.members.len();
                let member = &self.members[node];
                member.probe.attach(member.marshal.clone());
                if node == DISCOVERER {
                    self.ledger.note(ProbeStep::Attached);
                }
                2
            }
            ProbeEvent::Release { source } => {
                if let Some((capture, bytes)) = self.captured(*source) {
                    let source = Self::source(*source);
                    self.members[source + 1].released = Some((capture, bytes.clone()));
                    self.send(self.sender(source), ProbeShape::Response(capture), bytes);
                }
                3
            }
            ProbeEvent::Duplicate { source } => {
                let source = Self::source(*source);
                if let Some((capture, bytes)) = self.members[source + 1].released.clone() {
                    self.send(self.sender(source), ProbeShape::Response(capture), bytes);
                }
                4
            }
            ProbeEvent::Replay { source } => {
                if let Some((capture, bytes)) = self.captured(*source) {
                    let outsider = (self.outsider.1.clone(), self.outsider.0.clone());
                    self.send(outsider, ProbeShape::Response(capture), bytes);
                }
                5
            }
            ProbeEvent::Truncate { source, keep } => {
                if let Some((capture, bytes)) = self.captured(*source) {
                    self.send(
                        self.sender(Self::source(*source)),
                        ProbeShape::Prefix(capture),
                        prefix(&bytes, *keep),
                    );
                }
                6
            }
            ProbeEvent::Fragment {
                origin,
                source,
                keep,
            } => {
                if let Some((capture, bytes)) = self.captured(*source) {
                    self.send(
                        self.origin(*origin),
                        ProbeShape::Prefix(capture),
                        prefix(&bytes, *keep),
                    );
                }
                7
            }
            ProbeEvent::Junk { origin, payload } => {
                // Junk starts with no tag of the wire format, so it is
                // malformed whatever the probe is doing. Bytes that start
                // with a tag are not sent.
                let payload = &payload[..payload.len().min(usize::from(MAX_RAW_PAYLOAD))];
                if payload.first().is_some_and(|tag| *tag >= PROBE_TAGS) {
                    self.send(self.origin(*origin), ProbeShape::Junk, payload.to_vec());
                }
                8
            }
            ProbeEvent::Advance { steps } => {
                self.context.sleep(PROBE_STEP * u32::from(*steps)).await;
                9
            }
        };
        self.events[kind] += 1;
        self.context.sleep(PROBE_STEP).await;
        self.observe();
    }

    /// Open an artifact subscription on the discovering probe.
    fn subscribe(&mut self) {
        self.subscriptions
            .push(self.members[DISCOVERER].probe.subscribe());
        self.ledger.note(ProbeStep::Subscribed);
    }

    /// Record every subscription that resolved or closed.
    fn observe(&mut self) {
        let ledger = &self.ledger;
        self.subscriptions
            .retain_mut(|subscription| match subscription.try_recv() {
                Ok(artifact) => {
                    ledger.note(ProbeStep::Resolved(Box::new(artifact)));
                    false
                }
                Err(TryRecvError::Empty) => true,
                Err(TryRecvError::Closed) => {
                    ledger.note(ProbeStep::Closed);
                    false
                }
            });
    }

    /// Let whatever is in flight settle, and learn whether an artifact was
    /// resolved while no subscription was open: the probe keeps it, and a
    /// final subscription surfaces it.
    async fn finish(&mut self) {
        self.context.sleep(PROBE_STEP).await;
        self.observe();
        self.subscribe();
        self.context.sleep(PROBE_STEP).await;
        self.observe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{fixtures::decode, probe_input::drawable};
    use commonware_consensus::Epochable as _;
    use commonware_runtime::Spawner as _;

    /// Run one input whose program the decoder can draw, and return what was
    /// observed of it.
    fn observe(input: DkgProbeFuzzInput) -> Observations {
        observe_planted(input, async |_, _| {})
    }

    /// Run one input whose program the decoder can draw with `plant` called
    /// at every stage, and return what was observed of it.
    fn observe_planted(
        input: DkgProbeFuzzInput,
        plant: impl AsyncFn(&mut Harness, Stage),
    ) -> Observations {
        assert!(
            drawable(&input.events),
            "no input decodes to the program {:?}",
            input.events
        );
        super::observe_planted(input, plant)
    }

    fn tape(seed: u8) -> Vec<u8> {
        (0..96u8)
            .map(|byte| byte.wrapping_mul(29).wrapping_add(seed))
            .collect()
    }

    /// A run over the fabricated chain alone, bootstrapping from epoch zero
    /// with no persisted floor.
    fn input(sources: [u8; SOURCES], events: Vec<ProbeEvent>, seed: u8) -> DkgProbeFuzzInput {
        DkgProbeFuzzInput {
            sources,
            foreign: [false; SOURCES],
            bootstrap_epoch: 0,
            floor: None,
            sharing_mode: Mode::NonZeroCounter,
            events,
            raw_bytes: tape(seed),
        }
    }

    /// Attach every source, subscribe, release the sources' newest responses
    /// in `order`, and then execute `rest`.
    fn program(order: &[u8], rest: &[ProbeEvent]) -> Vec<ProbeEvent> {
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
        events.extend(rest.iter().cloned());
        events
    }

    /// The releases after which a run among three sources at height three
    /// has discovered its boundary: two latest finalizations, then the
    /// boundary finalization and the block of the first source.
    const DISCOVERY: [u8; 4] = [0, 1, 0, 0];

    /// An advance the decoder draws that lets the retry timeout expire on
    /// its own, whenever the probe last sent a request, and expire once.
    const RETRY: ProbeEvent = ProbeEvent::Advance { steps: 10 };

    /// Run one fixed input in which the discovering probe must emit an
    /// artifact, and assert the checks compared it.
    fn discovered(input: DkgProbeFuzzInput) -> ProbeReport {
        let report = measure(&observe(input));
        println!("{report}");
        assert_eq!(report.outcome, ProbeOutcome::Program);
        assert!(report.measured(), "no artifact was compared: {report}");
        report
    }

    /// Run one fixed input in which the discovering probe must not emit an
    /// artifact.
    fn undiscovered(input: DkgProbeFuzzInput) -> ProbeReport {
        let report = measure(&observe(input));
        println!("{report}");
        assert_eq!(report.outcome, ProbeOutcome::Program);
        assert_eq!(
            report.counts.artifacts, 0,
            "an artifact was emitted: {report}"
        );
        assert!(!report.measured());
        report
    }

    /// The artifact a run's first subscription resolved with.
    fn artifact(observed: &Observations) -> &ProbeArtifact {
        observed
            .run
            .steps
            .iter()
            .find_map(|step| match step {
                ProbeStep::Resolved(artifact) => Some(artifact.as_ref()),
                _ => None,
            })
            .expect("the run emitted an artifact")
    }

    /// The discovering probe samples two latest finalizations, fetches the
    /// boundary finalization and block of the floor's epoch, and emits an
    /// artifact that the checks compare with the fabricated chain.
    #[test]
    fn discovers_the_boundary_of_the_floor_epoch() {
        let observed = observe(input([2, 3, 1], program(&DISCOVERY, &[]), 1));
        let report = measure(&observed);
        println!("{report}");
        assert!(report.measured());
        assert_eq!(report.counts.solicitations, 1);
        assert_eq!(report.counts.fetches, 2);
        assert_eq!(report.counts.latest_replies, 3);
        assert_eq!(report.counts.boundary_replies, 3);
        assert_eq!(report.counts.block_replies, 1);
        assert_eq!(report.counts.deliveries, 4);
        assert_eq!(report.counts.admissions, 4);
        assert_eq!(report.counts.blocks, 0);

        // The second source holds height three, in epoch one, whose
        // description the block at height one carries.
        let run = &observed.run;
        let artifact = artifact(&observed);
        assert_eq!(artifact.floor, run.sources[1].finalizations[2]);
        assert_eq!(artifact.floor.epoch(), Epoch::new(1));
        let (boundary, info) = &run.chain.boundaries[&Epoch::new(1)];
        assert_eq!(artifact.finalization.as_ref(), Some(boundary));
        assert_eq!(artifact.info, *info);
        assert_eq!(*boundary, run.sources[0].finalizations[0]);
    }

    /// The floor is the highest finalization of the sample, whichever source
    /// delivers first, and a source that does not hold the floor epoch's
    /// boundary answers nothing for it.
    #[test]
    fn floor_is_the_highest_of_the_sample() {
        for order in [[0, 1, 1, 1], [1, 0, 1, 1]] {
            let observed = observe(input([1, 5, 3], program(&order, &[]), 2));
            let report = measure(&observed);
            assert!(report.measured(), "{report}");
            assert_eq!(
                artifact(&observed).floor,
                observed.run.sources[1].finalizations[4]
            );

            // Only the sources at heights five and three hold height three.
            assert_eq!(report.counts.boundary_replies, 2, "{report}");
        }
    }

    /// A floor in epoch zero resolves from the configured genesis description
    /// with no boundary fetch.
    #[test]
    fn genesis_floor_resolves_without_a_boundary() {
        let observed = observe(input([1, 1, 0], program(&[0, 1], &[]), 3));
        let report = measure(&observed);
        assert!(report.measured(), "{report}");
        assert_eq!(report.counts.fetches, 0);
        assert_eq!(report.counts.boundary_replies, 0);
        let artifact = artifact(&observed);
        assert!(artifact.finalization.is_none());
        assert_eq!(artifact.info, observed.run.chain.genesis);
    }

    /// A duplicate does not inflate the sample, and one latest finalization
    /// is not a floor.
    #[test]
    fn duplicates_do_not_inflate_the_sample() {
        let rest = [
            ProbeEvent::Duplicate { source: 0 },
            ProbeEvent::Duplicate { source: 0 },
        ];
        let report = undiscovered(input([3, 3, 3], program(&[0], &rest), 4));
        assert_eq!(report.counts.deliveries, 3);
        assert_eq!(report.counts.admissions, 3);
        assert_eq!(report.counts.fetches, 0);
    }

    /// A source of the foreign chain is blocked for its latest finalization
    /// while the probe samples and for its boundary finalization while the
    /// probe awaits one, and nothing of the foreign chain reaches the
    /// artifact.
    #[test]
    fn foreign_source_is_blocked_and_kept_out_of_the_artifact() {
        let mut input = input([3, 3, 3], program(&[0, 1, 2, 0, 1, 1], &[]), 5);
        input.foreign = [true, false, false];
        let observed = observe(input);
        let report = measure(&observed);
        println!("{report}");
        assert!(report.measured());
        assert_eq!(report.counts.refusals, 2, "{report}");
        assert_eq!(report.counts.blocks, 2, "{report}");
        assert_eq!(report.counts.blocked_peers, 1, "{report}");
        let run = &observed.run;
        assert_eq!(
            run.blocked,
            vec![(run.discoverer.clone(), run.sources[0].identity.clone())]
        );
        let artifact = artifact(&observed);
        assert_eq!(artifact.floor, run.chain.finalizations[2]);
        assert_ne!(artifact.floor, run.foreign.finalizations[2]);
    }

    /// With two sources on the foreign chain no sample forms, whatever they
    /// hold.
    #[test]
    fn foreign_majority_yields_no_artifact() {
        let mut input = input([5, 5, 5], program(&[0, 1, 2, 0, 1, 2], &[]), 6);
        input.foreign = [true, true, false];
        let report = undiscovered(input);
        assert_eq!(report.counts.blocked_peers, 2, "{report}");
        assert_eq!(report.counts.fetches, 0, "{report}");
    }

    /// A latest finalization below the bootstrap epoch is stale: it is set
    /// aside without a block, from the fabricated chain and from the foreign
    /// one alike, and the floor comes from the others.
    #[test]
    fn stale_replies_are_set_aside() {
        // Heights four and five are in epoch two; height three is in epoch
        // one, below the checkpoint.
        let mut input = input([3, 4, 5], program(&[0, 0, 1], &[]), 7);
        input.bootstrap_epoch = 2;
        input.foreign = [true, false, false];
        let report = undiscovered(input.clone());
        assert_eq!(report.counts.blocks, 0, "{report}");
        assert_eq!(report.counts.admissions, 3, "{report}");

        input.events.extend([
            ProbeEvent::Release { source: 2 },
            ProbeEvent::Release { source: 2 },
            ProbeEvent::Release { source: 2 },
        ]);
        let report = discovered(input);
        assert_eq!(report.counts.blocks, 0, "{report}");
    }

    /// A persisted floor raises the minimum epoch above the checkpoint's, and
    /// one below the checkpoint does not lower it.
    #[test]
    fn persisted_floor_bounds_the_sample() {
        // The floor at height four is in epoch two: the sources at height
        // three are stale.
        let mut input = input([3, 3, 5], program(&[0, 1, 2], &[]), 8);
        input.floor = Some(4);
        let report = undiscovered(input.clone());
        assert_eq!(report.counts.fetches, 0, "{report}");
        assert_eq!(report.counts.blocks, 0, "{report}");

        input.sources = [4, 3, 5];
        input.events = program(&[0, 1, 2, 2, 2], &[]);
        let observed = observe(input.clone());
        assert!(measure(&observed).measured());
        assert_eq!(artifact(&observed).floor.epoch(), Epoch::new(2));

        // The floor at height one is in epoch zero, below the checkpoint.
        input.floor = Some(1);
        input.bootstrap_epoch = 2;
        input.sources = [3, 3, 5];
        input.events = program(&[0, 1, 2], &[]);
        undiscovered(input);
    }

    /// The identity that is not a dealer is blocked for a latest finalization
    /// while the probe samples. Its boundary finalization is as good as a
    /// dealer's: the probe asks it for the block, fails over to another
    /// responder when it stays silent, and resolves.
    #[test]
    fn non_dealer_is_refused_as_a_sample_and_accepted_as_a_responder() {
        let events = [
            ProbeEvent::Replay { source: 0 },
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 1 },
            ProbeEvent::Replay { source: 2 },
            ProbeEvent::Release { source: 0 },
            RETRY,
            ProbeEvent::Replay { source: 0 },
            ProbeEvent::Release { source: 0 },
        ];
        let observed = observe(input([3, 3, 3], program(&[], &events), 9));
        let report = measure(&observed);
        println!("{report}");
        assert!(report.measured());
        assert_eq!(report.counts.refusals, 1, "{report}");
        assert_eq!(report.counts.blocks, 1, "{report}");
        assert_eq!(report.counts.unsettled, 0, "{report}");
        let run = &observed.run;
        assert_eq!(
            run.blocked,
            vec![(run.discoverer.clone(), run.outsider.clone())]
        );

        // The block was requested from the silent responder first.
        let asked: Vec<_> = run
            .steps
            .iter()
            .filter_map(|step| match step {
                ProbeStep::Requested {
                    recipients: Recipients::One(peer),
                    ..
                } => Some(peer.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            asked,
            vec![run.outsider.clone(), run.sources[0].identity.clone()]
        );
    }

    /// The identity that is not a dealer can supply the block too, once the
    /// probe has turned to it.
    #[test]
    fn non_dealer_supplies_the_boundary_block() {
        let events = [
            ProbeEvent::Replay { source: 1 },
            RETRY,
            ProbeEvent::Replay { source: 0 },
        ];
        let report = discovered(input([3, 3, 3], program(&[0, 1, 0], &events), 10));
        assert_eq!(report.counts.block_replies, 1, "{report}");
        assert_eq!(report.counts.admissions, 5, "{report}");
        assert_eq!(report.counts.blocks, 0, "{report}");
    }

    /// Once the floor is selected, a latest finalization from the identity
    /// that is not a dealer is no longer judged.
    #[test]
    fn late_latest_reply_from_the_non_dealer_is_ignored() {
        let events = [
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 1 },
            ProbeEvent::Replay { source: 2 },
        ];
        // The third source holds nothing of epoch one's boundary, so its
        // newest response stays its latest finalization.
        let mut input = input([3, 3, 3], program(&[], &events), 11);
        input.sources[2] = 0;
        let report = undiscovered(input.clone());
        assert_eq!(report.counts.deliveries, 2, "{report}");

        input.sources = [5, 5, 2];
        let report = undiscovered(input);
        assert_eq!(report.counts.deliveries, 3, "{report}");
        assert_eq!(report.counts.admissions, 3, "{report}");
        assert_eq!(report.counts.blocks, 0, "{report}");
    }

    /// A finalization response cut short is blocked whatever the cut and
    /// whoever sends it, while the probe samples and while it awaits its
    /// boundary, and the run still resolves from the others.
    #[test]
    fn cut_finalization_is_blocked_while_discovering() {
        for keep in [0u8, 1, 2, 9, 40, 67, 200] {
            // A cut latest finalization from its source, and a cut boundary
            // finalization from another source and from the non-dealer.
            let events = [
                ProbeEvent::Truncate { source: 2, keep },
                ProbeEvent::Release { source: 0 },
                ProbeEvent::Release { source: 1 },
                ProbeEvent::Fragment {
                    origin: 2,
                    source: 0,
                    keep,
                },
                ProbeEvent::Fragment {
                    origin: 3,
                    source: 1,
                    keep,
                },
                ProbeEvent::Release { source: 0 },
                ProbeEvent::Release { source: 0 },
            ];
            let report = discovered(input([3, 3, 3], program(&[], &events), 12));
            assert_eq!(report.counts.refusals, 3, "keep={keep}: {report}");
            assert_eq!(report.counts.blocks, 3, "keep={keep}: {report}");
            assert_eq!(report.counts.blocked_peers, 2, "keep={keep}: {report}");
            assert_eq!(report.counts.unsettled, 0, "keep={keep}: {report}");
        }
    }

    /// A cut block from the responder the block was requested from is
    /// blocked. Cut inside its tag it is refused before the probe looks at
    /// what it answers, so the request stands and the responder's whole block
    /// still resolves. Cut later it fails the request, and the probe turns to
    /// the next responder at once.
    #[test]
    fn cut_block_from_the_requested_responder_is_blocked() {
        for (keep, block_replies) in [(0u8, 1), (1, 1), (2, 2), (40, 2), (250, 2)] {
            let events = [
                ProbeEvent::Truncate { source: 0, keep },
                ProbeEvent::Release { source: 1 },
                ProbeEvent::Release { source: 0 },
            ];
            let report = discovered(input([3, 3, 3], program(&[0, 1, 0, 1], &events), 13));
            assert_eq!(report.counts.refusals, 1, "keep={keep}: {report}");
            assert_eq!(report.counts.blocks, 1, "keep={keep}: {report}");
            assert_eq!(report.counts.unsettled, 0, "keep={keep}: {report}");
            assert_eq!(
                report.counts.block_replies, block_replies,
                "keep={keep}: {report}"
            );
        }
    }

    /// A cut block from anyone else is decoded no further than its epoch, so
    /// its sender must not be blocked unless the cut leaves no more than the
    /// tag. That holds from another source and from the identity that is not
    /// a dealer, while the responder's block is awaited.
    #[test]
    fn cut_block_from_another_identity_is_ignored() {
        for origin in [2u8, 3] {
            for (keep, refusals) in [(0u8, 1), (1, 1), (2, 0), (40, 0), (250, 0)] {
                let events = [
                    ProbeEvent::Fragment {
                        origin,
                        source: 0,
                        keep,
                    },
                    ProbeEvent::Release { source: 0 },
                ];
                let report = discovered(input([3, 3, 3], program(&[0, 1, 0], &events), 14));
                let case = format!("origin={origin} keep={keep}: {report}");
                assert_eq!(report.counts.refusals, refusals, "{case}");
                assert_eq!(report.counts.blocks, refusals, "{case}");
                assert_eq!(report.counts.admissions, 5 - refusals, "{case}");
                assert_eq!(report.counts.unsettled, 0, "{case}");
            }
        }
    }

    /// The whole block from an identity the block was not requested from
    /// resolves nothing, so the probe still awaits its boundary and what it
    /// is sent next is still judged: a foreign boundary finalization and a
    /// cut block from the responder are blocked, and the run resolves from
    /// the responder once it is asked again.
    #[test]
    fn block_from_another_identity_leaves_the_boundary_awaited() {
        let events = [
            ProbeEvent::Replay { source: 0 },
            ProbeEvent::Release { source: 2 },
            ProbeEvent::Truncate { source: 0, keep: 9 },
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 0 },
        ];
        let mut input = input([3, 3, 3], program(&[0, 1, 0], &events), 43);
        input.foreign = [false, false, true];
        let observed = observe(input);
        let report = measure(&observed);
        println!("{report}");
        assert!(report.measured());
        assert_eq!(report.counts.artifacts, 2, "{report}");
        assert_eq!(report.counts.block_replies, 2, "{report}");
        assert_eq!(report.counts.deliveries, 8, "{report}");
        assert_eq!(report.counts.refusals, 2, "{report}");
        assert_eq!(report.counts.blocks, 2, "{report}");
        assert_eq!(report.counts.unsettled, 0, "{report}");
        let run = &observed.run;
        assert_eq!(
            run.blocked,
            vec![
                (run.discoverer.clone(), run.sources[0].identity.clone()),
                (run.discoverer.clone(), run.sources[2].identity.clone()),
            ]
        );
    }

    /// Once the probe holds its artifact it awaits no block, so a cut block
    /// from the responder the block was requested from must not be blocked.
    /// That is required only when a subscription showed the artifact: after
    /// the responder delivered the whole block with no subscription open,
    /// nothing at the probe's boundaries shows whether the artifact resolved,
    /// and the cut block is left open. One from anyone else must not be
    /// blocked either way.
    #[test]
    fn cut_block_after_the_block_is_judged_once_the_artifact_is_seen() {
        let cuts = [
            ProbeEvent::Truncate { source: 0, keep: 9 },
            ProbeEvent::Fragment {
                origin: 1,
                source: 0,
                keep: 9,
            },
        ];
        let report = discovered(input([3, 3, 3], program(&DISCOVERY, &cuts), 47));
        assert_eq!(report.counts.deliveries, 6, "{report}");
        assert_eq!(report.counts.admissions, 6, "{report}");
        assert_eq!(report.counts.unsettled, 0, "{report}");
        assert_eq!(report.counts.blocks, 0, "{report}");

        let mut events = vec![
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Unsubscribe,
            ProbeEvent::Release { source: 1 },
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 0 },
        ];
        events.extend(cuts);
        let report = discovered(input([3, 3, 3], program(&[], &events), 44));
        assert_eq!(report.counts.artifacts, 1, "{report}");
        assert_eq!(report.counts.deliveries, 6, "{report}");
        assert_eq!(report.counts.admissions, 5, "{report}");
        assert_eq!(report.counts.unsettled, 1, "{report}");
        assert_eq!(report.counts.blocks, 0, "{report}");
    }

    /// Junk is blocked in every state: before any subscription, while the
    /// probe samples, while it awaits its boundary, once it holds its
    /// artifact, and while it serves. Bytes that start with a tag are not
    /// sent.
    #[test]
    fn junk_is_blocked_in_every_state() {
        let junk = |origin: u8, tag: u8| ProbeEvent::Junk {
            origin,
            payload: vec![tag, 7, 7],
        };
        let events = vec![
            junk(0, 6),
            ProbeEvent::Attach { node: 1 },
            ProbeEvent::Attach { node: 2 },
            ProbeEvent::Attach { node: 3 },
            ProbeEvent::Subscribe,
            junk(1, 0xff),
            junk(3, 0),
            junk(3, 5),
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 1 },
            junk(2, 200),
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 0 },
            junk(3, 77),
            ProbeEvent::Attach { node: 0 },
            junk(0, 9),
        ];
        let report = discovered(input([3, 3, 3], events, 15));
        assert_eq!(report.events[8], 7, "{report}");
        assert_eq!(report.counts.deliveries, 9, "{report}");
        assert_eq!(report.counts.refusals, 5, "{report}");
        assert_eq!(report.counts.blocks, 5, "{report}");
        assert_eq!(report.counts.blocked_peers, 4, "{report}");
    }

    /// A probe whose marshal is attached before any subscription serves: it
    /// asks for nothing and resolves nothing.
    #[test]
    fn attachment_before_subscription_serves() {
        let mut events = vec![ProbeEvent::Attach { node: 0 }];
        events.extend(program(&DISCOVERY, &[]));
        let report = undiscovered(input([3, 3, 3], events, 16));
        assert_eq!(report.counts.solicitations, 0, "{report}");
        assert_eq!(report.counts.latest_replies, 0, "{report}");
        assert_eq!(report.counts.deliveries, 0, "{report}");
    }

    /// A serving probe reads requests only: it ignores a response, whole or
    /// cut short, and still blocks a message with no tag.
    #[test]
    fn serving_probe_ignores_responses() {
        // The probe serves once its artifact is resolved and its marshal
        // attached.
        let rest = [
            ProbeEvent::Attach { node: 0 },
            ProbeEvent::Truncate { source: 1, keep: 9 },
            ProbeEvent::Fragment {
                origin: 3,
                source: 0,
                keep: 30,
            },
            ProbeEvent::Replay { source: 2 },
            ProbeEvent::Duplicate { source: 0 },
            ProbeEvent::Truncate { source: 2, keep: 0 },
        ];
        let report = discovered(input([3, 3, 3], program(&DISCOVERY, &rest), 17));
        assert_eq!(report.counts.deliveries, 9, "{report}");
        assert_eq!(report.counts.admissions, 8, "{report}");
        assert_eq!(report.counts.refusals, 1, "{report}");
        assert_eq!(report.counts.blocks, 1, "{report}");
        assert_eq!(report.counts.unsettled, 0, "{report}");

        // It also serves once its marshal is attached while no subscription
        // is open, with no artifact.
        let events = vec![
            ProbeEvent::Attach { node: 1 },
            ProbeEvent::Subscribe,
            ProbeEvent::Unsubscribe,
            ProbeEvent::Attach { node: 0 },
            ProbeEvent::Truncate { source: 0, keep: 9 },
            ProbeEvent::Release { source: 0 },
        ];
        let report = undiscovered(input([3, 3, 3], events, 18));
        assert_eq!(report.counts.admissions, 2, "{report}");
        assert_eq!(report.counts.blocks, 0, "{report}");
    }

    /// Attaching the discovering probe's marshal while a subscription waits
    /// keeps it discovering: it still judges what it is sent and resolves.
    #[test]
    fn attachment_while_waiting_keeps_discovery_judging() {
        let events = [
            ProbeEvent::Attach { node: 0 },
            ProbeEvent::Replay { source: 1 },
            ProbeEvent::Truncate {
                source: 0,
                keep: 30,
            },
            ProbeEvent::Release { source: 1 },
            ProbeEvent::Release { source: 2 },
            ProbeEvent::Release { source: 1 },
            ProbeEvent::Release { source: 1 },
        ];
        let report = discovered(input([3, 3, 3], program(&[], &events), 19));
        assert_eq!(report.counts.refusals, 2, "{report}");
        assert_eq!(report.counts.blocks, 2, "{report}");
        assert_eq!(report.counts.unsettled, 0, "{report}");
    }

    /// Dropping the last subscription after the marshal is attached leaves
    /// the probe's state to the actor, which notices the drop only when it
    /// next wakes: the delivery that wakes it is still judged, and later ones
    /// are served. The oracle requires nothing for a damaged response here.
    #[test]
    fn delivery_after_unsubscribe_is_left_to_the_actor() {
        let cut = ProbeEvent::Truncate { source: 0, keep: 5 };
        let events = [
            ProbeEvent::Attach { node: 0 },
            ProbeEvent::Unsubscribe,
            cut.clone(),
            cut,
        ];
        let report = undiscovered(input([3, 3, 3], program(&[], &events), 20));
        assert_eq!(report.counts.deliveries, 2, "{report}");
        assert_eq!(report.counts.unsettled, 2, "{report}");
        assert_eq!(report.counts.blocks, 1, "{report}");
    }

    /// A sample that is not complete when the retry timeout expires is
    /// discarded and asked for again, and the floor comes from the replies
    /// delivered since.
    #[test]
    fn retry_asks_again_and_discards_the_sample() {
        let events = [
            ProbeEvent::Release { source: 0 },
            RETRY,
            ProbeEvent::Release { source: 1 },
        ];
        let report = undiscovered(input([3, 3, 3], program(&[], &events), 21));
        assert_eq!(report.counts.solicitations, 2, "{report}");
        assert_eq!(report.counts.fetches, 0, "{report}");

        let events = [
            ProbeEvent::Release { source: 0 },
            RETRY,
            ProbeEvent::Release { source: 1 },
            ProbeEvent::Release { source: 2 },
            ProbeEvent::Release { source: 1 },
            ProbeEvent::Release { source: 1 },
        ];
        let report = discovered(input([3, 3, 3], program(&[], &events), 22));
        assert_eq!(report.counts.solicitations, 2, "{report}");
    }

    /// An artifact resolved while no subscription was open is kept and served
    /// to the run's closing subscription.
    #[test]
    fn artifact_resolved_unseen_is_checked() {
        let events = [
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Unsubscribe,
            ProbeEvent::Release { source: 1 },
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 0 },
        ];
        let report = discovered(input([3, 3, 3], program(&[], &events), 23));
        assert_eq!(report.counts.artifacts, 1, "{report}");
    }

    /// A selector reaches a source's older responses: its block while the
    /// probe awaits a boundary finalization again, which is ignored, and its
    /// latest finalization from the identity that is not a dealer, which is
    /// no longer judged.
    #[test]
    fn older_responses_are_released_by_selector() {
        // After the retry the probe has no responder left and asks everyone
        // for the boundary finalization again, so the first source's newest
        // response is that finalization and the one before it its block.
        let events = [
            RETRY,
            ProbeEvent::Release {
                source: SOURCES as u8,
            },
            ProbeEvent::Replay {
                source: 2 * SOURCES as u8,
            },
        ];
        let observed = observe(input([3, 3, 3], program(&[0, 1, 0], &events), 40));
        let report = measure(&observed);
        println!("{report}");
        assert_eq!(report.counts.artifacts, 0, "{report}");
        assert_eq!(report.counts.block_replies, 1, "{report}");
        assert_eq!(report.counts.admissions, 5, "{report}");
        assert_eq!(report.counts.blocks, 0, "{report}");
        let sent: Vec<_> = observed
            .run
            .steps
            .iter()
            .filter_map(|step| match step {
                ProbeStep::Sent(send) => Some(send.shape),
                _ => None,
            })
            .collect();

        // The first source built its latest finalization, the boundary
        // finalization, its block, and the boundary finalization again.
        let first: Vec<_> = observed
            .run
            .captures
            .iter()
            .enumerate()
            .filter(|(_, capture)| capture.source == 0)
            .map(|(position, _)| position)
            .collect();
        assert_eq!(first.len(), 4);
        assert_eq!(
            sent[2..],
            [
                ProbeShape::Response(first[1]),
                ProbeShape::Response(first[2]),
                ProbeShape::Response(first[0]),
            ]
        );

        // The source's newest response and then its block still resolve.
        let mut events = events.to_vec();
        events.extend([
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 0 },
        ]);
        discovered(input([3, 3, 3], program(&[0, 1, 0], &events), 41));
    }

    /// A control beyond what the fabricated chain holds selects the last the
    /// chain holds.
    #[test]
    fn controls_beyond_the_chain_are_bounded() {
        let mut input = input([200, 9, 5], program(&[0, 1, 2, 2, 2], &[]), 42);
        input.bootstrap_epoch = 77;
        input.floor = Some(0);
        undiscovered(input.clone());
        input.floor = Some(99);
        input.bootstrap_epoch = 2;
        let observed = observe(input);
        assert!(measure(&observed).measured());
        assert_eq!(observed.run.sources[0].finalizations.len(), 5);
    }

    /// Sources that hold nothing, or are never attached, answer nothing.
    #[test]
    fn silent_sources_yield_no_artifact() {
        let report = undiscovered(input([0, 0, 0], program(&DISCOVERY, &[]), 24));
        assert_eq!(report.counts.latest_replies, 0);
        let events = vec![
            ProbeEvent::Subscribe,
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 1 },
        ];
        let report = undiscovered(input([3, 3, 3], events, 25));
        assert_eq!(report.counts.solicitations, 1);
        assert_eq!(report.counts.latest_replies, 0);
    }

    /// Both sharing modes and every bootstrap epoch run, and the checkpoint
    /// of a later epoch is tracked under its own peer set.
    #[test]
    fn every_mode_and_checkpoint_discovers() {
        for (mode, bootstrap_epoch) in [
            (Mode::RootsOfUnity, 0),
            (Mode::NonZeroCounter, 1),
            (Mode::RootsOfUnity, 2),
        ] {
            let mut input = input([5, 5, 5], program(&DISCOVERY, &[]), 26);
            input.sharing_mode = mode;
            input.bootstrap_epoch = bootstrap_epoch;
            let observed = observe(input);
            assert!(measure(&observed).measured());
            assert_eq!(artifact(&observed).floor.epoch(), Epoch::new(2));
        }
    }

    /// The entry point libFuzzer calls returns on a run that discovers and on
    /// one that does not.
    #[test]
    fn fuzz_entry_point_runs() {
        fuzz_dkg_probe(input([2, 3, 1], program(&DISCOVERY, &[]), 27));
        fuzz_dkg_probe(input([0, 0, 0], Vec::new(), 28));
    }

    /// The program with no events compares nothing, and its report says so.
    #[test]
    fn empty_program_compares_nothing() {
        let report = undiscovered(input([3, 3, 3], Vec::new(), 29));
        assert_eq!(report.events, [0; KINDS.len()]);
        assert_eq!(report.counts.deliveries, 0);
        assert!(
            report
                .to_string()
                .ends_with("artifacts=0 floors=0 comparisons=0")
        );
    }

    /// I10: a replayed input observes the same thing.
    #[test]
    fn replay_is_reproducible() {
        let run = || {
            let mut input = input([3, 2, 3], program(&[0, 1, 2, 0, 2, 2], &[]), 30);
            input.foreign = [false, true, false];
            measure(&observe(input))
        };
        assert_eq!(run(), run());
    }

    /// Short inputs sample whole sessions: across the one-byte inputs every
    /// event kind is executed, every response kind is built, the probe is
    /// required to block and required not to, and artifacts are compared in
    /// every epoch a floor can be in.
    #[test]
    fn short_inputs_reach_every_event_and_response_kind() {
        let mut events = [0usize; KINDS.len()];
        let mut counts = ProbeCounts::default();
        let mut epochs = BTreeMap::new();
        for byte in 0..=255u8 {
            let observed = observe(decode(&[byte]));
            let report = measure(&observed);
            assert_ne!(report.outcome, ProbeOutcome::Stopped);
            for (total, executed) in events.iter_mut().zip(report.events) {
                *total += executed;
            }
            counts.latest_replies += report.counts.latest_replies;
            counts.boundary_replies += report.counts.boundary_replies;
            counts.block_replies += report.counts.block_replies;
            counts.refusals += report.counts.refusals;
            counts.admissions += report.counts.admissions;
            counts.floors += report.counts.floors;
            counts.comparisons += report.counts.comparisons;
            if report.measured() {
                *epochs
                    .entry(artifact(&observed).floor.epoch())
                    .or_insert(0usize) += 1;
            }
        }
        println!("events={events:?} counts={counts:?} epochs={epochs:?}");
        assert!(events.iter().all(|executed| *executed >= 64), "{events:?}");
        assert!(counts.latest_replies >= 256, "{counts:?}");
        assert!(counts.boundary_replies >= 64, "{counts:?}");
        assert!(counts.block_replies >= 32, "{counts:?}");
        assert!(counts.refusals >= 256, "{counts:?}");
        assert!(counts.admissions >= 256, "{counts:?}");
        assert!(counts.floors >= 32 && counts.comparisons == counts.floors);
        for epoch in 0..=2 {
            assert!(epochs.contains_key(&Epoch::new(epoch)), "{epochs:?}");
        }
    }

    /// Replace the floor of every artifact the run observed.
    fn plant(observed: &mut Observations, plant: impl Fn(&mut ProbeArtifact)) {
        for step in &mut observed.run.steps {
            if let ProbeStep::Resolved(artifact) = step {
                plant(artifact);
            }
        }
    }

    /// A run whose artifact has its floor at height three, selected from the
    /// sources at heights two and three, in epoch one.
    fn sampled() -> Observations {
        observe(input([2, 3, 1], program(&DISCOVERY, &[]), 31))
    }

    /// I12 negative control: an artifact whose floor is a valid finalization
    /// of the sample, in the floor's epoch, and not its highest.
    #[test]
    #[should_panic(expected = "I12 violated: the floor of the artifact")]
    fn floor_below_the_highest_of_the_sample_is_rejected() {
        let mut observed = sampled();
        let lower = observed.run.sources[0].finalizations[1].clone();
        plant(&mut observed, |artifact| artifact.floor = lower.clone());
        measure(&observed);
    }

    /// I12 negative control: a floor no delivered reply carries, although the
    /// fabricated chain holds it.
    #[test]
    #[should_panic(expected = "I12 violated: the floor of the artifact")]
    fn floor_nobody_sent_is_rejected() {
        let mut observed = observe(input([2, 2, 3], program(&DISCOVERY, &[]), 32));
        let unsent = observed.run.sources[2].finalizations[2].clone();
        plant(&mut observed, |artifact| artifact.floor = unsent.clone());
        measure(&observed);
    }

    /// I12 negative control: a floor from a sample of one. The delivery of
    /// the second latest finalization is removed from the record.
    #[test]
    #[should_panic(expected = "I12 violated: the floor of the artifact")]
    fn floor_from_one_reply_is_rejected() {
        let mut observed = observe(input([3, 3, 3], program(&DISCOVERY, &[]), 33));
        let first = observed
            .run
            .steps
            .iter()
            .position(|step| matches!(step, ProbeStep::Sent(_)))
            .expect("the program sent a message");
        observed.run.steps.drain(first..first + 2);
        measure(&observed);
    }

    /// A latest reply a sample leaves out, and how a run delivers it.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Excluded {
        /// Delivered before the probe asked for latest finalizations again.
        Earlier,
        /// Relayed by the identity that is not a dealer.
        Relayed,
        /// A finalization of the foreign chain.
        Foreign,
        /// Below the epoch of the probe's checkpoint.
        Stale,
        /// A second delivery of a reply already counted.
        Repeated,
    }

    const EXCLUSIONS: [Excluded; 5] = [
        Excluded::Earlier,
        Excluded::Relayed,
        Excluded::Foreign,
        Excluded::Stale,
        Excluded::Repeated,
    ];

    /// A run among sources at the heights `sources` whose sample is the
    /// latest replies of the second source and then of the third, and which
    /// resolves from the third. Between or before the two, one more reply is
    /// delivered that the sample leaves out: the second source's again, or
    /// the first source's in the way `excluded` names.
    fn excluding(excluded: Excluded, sources: [u8; SOURCES]) -> DkgProbeFuzzInput {
        let left_out = match excluded {
            Excluded::Earlier | Excluded::Foreign | Excluded::Stale => {
                ProbeEvent::Release { source: 0 }
            }
            Excluded::Relayed => ProbeEvent::Replay { source: 0 },
            Excluded::Repeated => ProbeEvent::Duplicate { source: 1 },
        };
        let mut events = if excluded == Excluded::Earlier {
            vec![left_out, RETRY, ProbeEvent::Release { source: 1 }]
        } else {
            vec![ProbeEvent::Release { source: 1 }, left_out]
        };
        events.extend(vec![ProbeEvent::Release { source: 2 }; 3]);
        let mut input = input(sources, program(&[], &events), 45);
        input.foreign[0] = excluded == Excluded::Foreign;
        input.bootstrap_epoch = u8::from(excluded == Excluded::Stale);
        input
    }

    /// The floor comes from the replies the probe counts and from no other:
    /// not from one delivered before it asked again, relayed by the identity
    /// that is not a dealer, of the foreign chain, below its checkpoint's
    /// epoch, or delivered twice. That holds whether the reply left out is
    /// lower than the sample's or higher.
    #[test]
    fn floor_comes_from_the_counted_replies_alone() {
        // Heights one, two, and three: the reply left out is the lowest, and
        // the floor is the third source's, in epoch one.
        for excluded in EXCLUSIONS {
            let observed = observe(excluding(excluded, [1, 2, 3]));
            let report = measure(&observed);
            assert!(report.measured(), "{excluded:?}: {report}");
            assert_eq!(
                artifact(&observed).floor,
                observed.run.sources[2].finalizations[2],
                "{excluded:?}"
            );
            assert_eq!(
                report.counts.solicitations,
                1 + usize::from(excluded == Excluded::Earlier),
                "{excluded:?}: {report}"
            );
            assert_eq!(
                report.counts.blocks,
                usize::from(matches!(excluded, Excluded::Relayed | Excluded::Foreign)),
                "{excluded:?}: {report}"
            );
            assert_eq!(report.counts.unsettled, 0, "{excluded:?}: {report}");
        }

        // Heights five, three, and three: the reply left out is the highest
        // and does not raise the floor. A stale reply is never the highest,
        // and a repeated one is counted once already.
        for excluded in [Excluded::Earlier, Excluded::Relayed, Excluded::Foreign] {
            let observed = observe(excluding(excluded, [5, 3, 3]));
            let report = measure(&observed);
            assert!(report.measured(), "{excluded:?}: {report}");
            assert_eq!(
                artifact(&observed).floor,
                observed.run.sources[1].finalizations[2],
                "{excluded:?}"
            );
        }
    }

    /// I12 negative control over [`excluding`], among sources at heights one,
    /// two, and three: the floor a probe would select had it counted the
    /// reply the sample leaves out, which is the second source's latest
    /// finalization, the higher of the first two replies delivered. It is a
    /// valid finalization of the floor's epoch, so nothing but the sample
    /// tells it from the floor.
    fn counting(excluded: Excluded) {
        let mut observed = observe(excluding(excluded, [1, 2, 3]));
        assert_eq!(
            artifact(&observed).floor,
            observed.run.sources[2].finalizations[2],
            "the run did not select the third source's finalization"
        );
        let lower = observed.run.sources[1].finalizations[1].clone();
        plant(&mut observed, |artifact| artifact.floor = lower.clone());
        measure(&observed);
    }

    /// I12 negative control: a floor that counts a reply delivered before the
    /// probe last asked for latest finalizations.
    #[test]
    #[should_panic(expected = "I12 violated: the floor of the artifact")]
    fn floor_counting_a_reply_from_before_the_last_request_is_rejected() {
        counting(Excluded::Earlier);
    }

    /// I12 negative control: a floor that counts a reply sent by another
    /// identity than the source that built it.
    #[test]
    #[should_panic(expected = "I12 violated: the floor of the artifact")]
    fn floor_counting_a_relayed_reply_is_rejected() {
        counting(Excluded::Relayed);
    }

    /// I12 negative control: a floor that counts a reply of the foreign chain.
    #[test]
    #[should_panic(expected = "I12 violated: the floor of the artifact")]
    fn floor_counting_a_foreign_reply_is_rejected() {
        counting(Excluded::Foreign);
    }

    /// I12 negative control: a floor that counts a stale reply.
    #[test]
    #[should_panic(expected = "I12 violated: the floor of the artifact")]
    fn floor_counting_a_stale_reply_is_rejected() {
        counting(Excluded::Stale);
    }

    /// I12 negative control: a floor that counts one source twice.
    #[test]
    #[should_panic(expected = "I12 violated: the floor of the artifact")]
    fn floor_counting_one_source_twice_is_rejected() {
        counting(Excluded::Repeated);
    }

    /// A run among sources at the heights `sources` whose floor is selected
    /// from the latest replies of the first two sources, and in which the
    /// third source's latest reply is delivered after them and before the
    /// boundary. Once the probe has asked for the boundary, the third
    /// source's newest response is its boundary finalization and the one
    /// before it its latest reply. The run resolves from the first source.
    fn trailing(sources: [u8; SOURCES]) -> DkgProbeFuzzInput {
        let events = [
            ProbeEvent::Release {
                source: 2 + SOURCES as u8,
            },
            ProbeEvent::Release { source: 0 },
            ProbeEvent::Release { source: 0 },
        ];
        input(sources, program(&[0, 1], &events), 48)
    }

    /// The floor is selected when the second dealer's reply arrives. A
    /// third reply delivered after it does not raise the floor, in the
    /// floor's epoch or in a later one, and does not get its sender blocked.
    #[test]
    fn reply_after_the_floor_is_selected_does_not_raise_it() {
        for sources in [[2, 2, 3], [3, 3, 5]] {
            let observed = observe(trailing(sources));
            let report = measure(&observed);
            assert!(report.measured(), "{sources:?}: {report}");
            assert_eq!(report.counts.solicitations, 1, "{sources:?}: {report}");
            assert_eq!(report.counts.deliveries, 5, "{sources:?}: {report}");
            assert_eq!(report.counts.admissions, 5, "{sources:?}: {report}");
            assert_eq!(report.counts.blocks, 0, "{sources:?}: {report}");

            // The third message the program sent is the first response the
            // third source built, which is its latest reply.
            let run = &observed.run;
            let reply = run
                .captures
                .iter()
                .position(|capture| capture.source == 2)
                .expect("the third source answered");
            let sent: Vec<_> = run
                .steps
                .iter()
                .filter_map(|step| match step {
                    ProbeStep::Sent(send) => Some(send.shape),
                    _ => None,
                })
                .collect();
            assert_eq!(sent[2], ProbeShape::Response(reply), "{sources:?}");

            let latest = |source: usize| {
                run.sources[source]
                    .finalizations
                    .last()
                    .expect("the source holds a finalization")
            };
            let floor = &artifact(&observed).floor;
            assert_eq!(floor, latest(0), "{sources:?}");
            assert!(latest(2).round() > floor.round(), "{sources:?}");
        }
    }

    /// I12 negative control: a floor raised by a reply delivered after the
    /// floor was selected. The planted floor is the third source's latest
    /// finalization: a valid one of the floor's epoch, which its own source
    /// delivered after the probe last asked and before the artifact resolved,
    /// so only its place after the first two replies tells it from the floor.
    #[test]
    #[should_panic(
        expected = "I12 violated: the floor of the artifact, at round (1, 3), is not the \
                    highest finalization of the first 2 valid latest replies from distinct \
                    dealers that were delivered since engine 0 last asked for them, [\"engine 1 \
                    at round (1, 2)\", \"engine 2 at round (1, 2)\"]; [\"engine 3 at round (1, \
                    3)\"] were delivered after them"
    )]
    fn floor_raised_by_a_reply_after_the_selection_is_rejected() {
        let mut observed = observe(trailing([2, 2, 3]));
        let later = observed.run.sources[2].finalizations[2].clone();
        plant(&mut observed, |artifact| artifact.floor = later.clone());
        measure(&observed);
    }

    /// I13 negative control: an artifact that describes another epoch than
    /// its floor's.
    #[test]
    #[should_panic(
        expected = "I13 violated: the artifact for epoch 1 does not carry the epoch \
                               description"
    )]
    fn description_of_another_epoch_is_rejected() {
        let mut observed = sampled();
        let other = observed.run.chain.boundaries[&Epoch::new(2)].1.clone();
        plant(&mut observed, |artifact| artifact.info = other.clone());
        measure(&observed);
    }

    /// I13 negative control: an artifact with the boundary finalization of
    /// another epoch.
    #[test]
    #[should_panic(
        expected = "I13 violated: the artifact for epoch 1 does not carry the \
                               fabricated chain's boundary finalization"
    )]
    fn boundary_of_another_epoch_is_rejected() {
        let mut observed = sampled();
        let other = observed.run.chain.boundaries[&Epoch::new(2)].0.clone();
        plant(&mut observed, |artifact| {
            artifact.finalization = Some(other.clone())
        });
        measure(&observed);
    }

    /// I13 negative control: an artifact with the foreign chain's boundary
    /// for the floor's epoch.
    #[test]
    #[should_panic(
        expected = "I13 violated: the boundary finalization of the artifact for epoch \
                               1 is a finalization of the foreign chain"
    )]
    fn foreign_boundary_is_rejected() {
        let mut observed = sampled();
        let (finalization, info) = observed.run.foreign.boundaries[&Epoch::new(1)].clone();
        plant(&mut observed, |artifact| {
            artifact.finalization = Some(finalization.clone());
            artifact.info = info.clone();
        });
        measure(&observed);
    }

    /// I13 negative control: an artifact with the foreign chain's epoch
    /// description under the fabricated chain's boundary finalization.
    #[test]
    #[should_panic(expected = "I13 violated: the artifact for epoch 1 carries an epoch \
                               description of the foreign chain")]
    fn foreign_description_is_rejected() {
        let mut observed = sampled();
        let info = observed.run.foreign.boundaries[&Epoch::new(1)].1.clone();
        plant(&mut observed, |artifact| artifact.info = info.clone());
        measure(&observed);
    }

    /// I13 negative control: an artifact for epoch zero that carries a
    /// boundary finalization, and one that carries another description than
    /// the configured genesis one.
    #[test]
    #[should_panic(
        expected = "I13 violated: the artifact for epoch 0 carries a boundary \
                               finalization"
    )]
    fn genesis_artifact_with_a_boundary_is_rejected() {
        let mut observed = observe(input([1, 1, 0], program(&[0, 1], &[]), 34));
        let boundary = observed.run.chain.finalizations[0].clone();
        plant(&mut observed, |artifact| {
            artifact.finalization = Some(boundary.clone())
        });
        measure(&observed);
    }

    #[test]
    #[should_panic(
        expected = "I13 violated: the artifact for epoch 0 does not carry the \
                               configured genesis description"
    )]
    fn genesis_artifact_with_another_description_is_rejected() {
        let mut observed = observe(input([1, 1, 0], program(&[0, 1], &[]), 35));
        let other = observed.run.chain.boundaries[&Epoch::new(1)].1.clone();
        plant(&mut observed, |artifact| artifact.info = other.clone());
        measure(&observed);
    }

    /// I13 negative control: a second subscription resolved with another
    /// artifact than the first.
    #[test]
    #[should_panic(expected = "I13 violated: engine 0 emitted a second, different artifact")]
    fn second_different_artifact_is_rejected() {
        let mut observed = sampled();
        let other = observed.run.chain.boundaries[&Epoch::new(2)].1.clone();
        let second = observed
            .run
            .steps
            .iter_mut()
            .filter_map(|step| match step {
                ProbeStep::Resolved(artifact) => Some(artifact),
                _ => None,
            })
            .nth(1)
            .expect("the closing subscription resolved");
        second.info = other;
        measure(&observed);
    }

    /// I13 negative control: an artifact whose boundary no source of the
    /// fabricated chain holds.
    #[test]
    #[should_panic(
        expected = "I13 violated: the artifact carries the boundary of epoch 1, which \
                               no source of the fabricated chain holds"
    )]
    fn boundary_nobody_holds_is_rejected() {
        let mut observed = sampled();
        for source in &mut observed.run.sources {
            source.foreign = true;
        }
        invariants::check_probe_artifact(&observed.run);
    }

    /// The step after which a planted block is attributed to the delivery at
    /// `position` among the run's deliveries.
    fn delivery(observed: &Observations, position: usize) -> usize {
        observed
            .run
            .steps
            .iter()
            .enumerate()
            .filter(|(_, step)| matches!(step, ProbeStep::Delivered { .. }))
            .nth(position)
            .expect("the run made the delivery")
            .0
    }

    /// I14 negative control: a source blocked for its own valid latest
    /// finalization.
    #[test]
    #[should_panic(expected = "I14 violated: engine 2 was blocked for delivery 1")]
    fn block_for_a_valid_response_is_rejected() {
        let mut observed = sampled();
        let peer = observed.run.sources[1].identity.clone();
        let at = delivery(&observed, 1);
        observed
            .run
            .steps
            .insert(at + 1, ProbeStep::Blocked { peer: peer.clone() });
        observed
            .run
            .blocked
            .push((observed.run.discoverer.clone(), peer));
        measure(&observed);
    }

    /// I14 negative control: a damaged response whose sender was not blocked.
    #[test]
    #[should_panic(expected = "I14 violated: engine 1 was not blocked for delivery 0")]
    fn unblocked_damaged_response_is_rejected() {
        let events = [ProbeEvent::Truncate { source: 0, keep: 9 }];
        let mut observed = observe(input([3, 3, 3], program(&[], &events), 36));
        observed
            .run
            .steps
            .retain(|step| !matches!(step, ProbeStep::Blocked { .. }));
        observed.run.blocked.clear();
        measure(&observed);
    }

    /// I14 negative control: a latest finalization replayed by the identity
    /// that is not a dealer, and one from the foreign chain, that did not get
    /// their sender blocked.
    #[test]
    #[should_panic(
        expected = "I14 violated: the identity that is not a dealer was not blocked \
                               for delivery 0"
    )]
    fn unblocked_non_dealer_is_rejected() {
        let events = [ProbeEvent::Replay { source: 0 }];
        let mut observed = observe(input([3, 3, 3], program(&[], &events), 37));
        observed
            .run
            .steps
            .retain(|step| !matches!(step, ProbeStep::Blocked { .. }));
        observed.run.blocked.clear();
        measure(&observed);
    }

    #[test]
    #[should_panic(expected = "I14 violated: engine 1 was not blocked for delivery 0")]
    fn unblocked_foreign_response_is_rejected() {
        let mut input = input([3, 3, 3], program(&[0], &[]), 38);
        input.foreign = [true, false, false];
        let mut observed = observe(input);
        observed
            .run
            .steps
            .retain(|step| !matches!(step, ProbeStep::Blocked { .. }));
        observed.run.blocked.clear();
        measure(&observed);
    }

    /// I14 negative control: the probe blocked another peer than the sender
    /// of the message it was processing.
    #[test]
    #[should_panic(
        expected = "I14 violated: engine 0 blocked engine 3 while it processed \
                               delivery 0, which engine 1 sent"
    )]
    fn block_of_a_bystander_is_rejected() {
        let mut observed = sampled();
        let bystander = observed.run.sources[2].identity.clone();
        let at = delivery(&observed, 0);
        observed
            .run
            .steps
            .insert(at + 1, ProbeStep::Blocked { peer: bystander });
        measure(&observed);
    }

    /// I14 negative control: the network holds a block the probe did not
    /// place, by the discovering probe and by a source.
    #[test]
    #[should_panic(
        expected = "I14 violated: the network recorded that engine 0 blocked engine \
                               2, a block engine 0 did not place"
    )]
    fn block_the_probe_did_not_place_is_rejected() {
        let mut observed = sampled();
        observed.run.blocked.push((
            observed.run.discoverer.clone(),
            observed.run.sources[1].identity.clone(),
        ));
        measure(&observed);
    }

    #[test]
    #[should_panic(
        expected = "I14 violated: the network recorded that engine 2 blocked engine \
                               0, a block engine 0 did not place"
    )]
    fn block_by_a_source_is_rejected() {
        let mut observed = sampled();
        observed.run.blocked.push((
            observed.run.sources[1].identity.clone(),
            observed.run.discoverer.clone(),
        ));
        measure(&observed);
    }

    /// I14 negative control: a block the probe placed that the network does
    /// not hold.
    #[test]
    #[should_panic(
        expected = "I14 violated: the block engine 0 placed on engine 1 did not \
                               reach the network"
    )]
    fn block_that_did_not_reach_the_network_is_rejected() {
        let events = [ProbeEvent::Truncate { source: 0, keep: 9 }];
        let mut observed = observe(input([3, 3, 3], program(&[], &events), 39));
        observed.run.blocked.clear();
        measure(&observed);
    }

    /// A fault an I8 negative control plants in a running harness.
    #[derive(Clone, Copy)]
    enum Fault {
        /// Close the probe channel of this engine, so that its probe ends on
        /// its own.
        Sever(usize),
        /// Panic in a task of this engine.
        EnginePanic(usize),
        /// Panic in a task of the harness, which belongs to no engine.
        HarnessPanic,
    }

    /// Run a program that discovers its boundary with `fault` planted at
    /// `stage`, through the measurement every run goes through.
    fn faulted(stage: Stage, fault: Fault) -> ProbeReport {
        let input = input([2, 3, 1], program(&DISCOVERY, &[]), 46);
        let plant = async |harness: &mut Harness, at: Stage| {
            if at != stage {
                return;
            }
            match fault {
                Fault::Sever(engine) => {
                    // Registering a channel again closes the receiver the
                    // probe holds.
                    let identity = harness.members[engine].identity.clone();
                    let control = harness.oracle.control(identity);
                    drop(control.register(CHANNEL_PROBE, TEST_QUOTA).await);
                }
                Fault::EnginePanic(engine) => {
                    let context = harness.context.child("planted");
                    drop(
                        EngineContext::new(context, engine).spawn(|_| async { panic!("planted") }),
                    );
                }
                Fault::HarnessPanic => {
                    let context = harness.context.child("planted");
                    drop(context.spawn(|_| async { panic!("planted") }));
                }
            }
        };
        measure(&observe_planted(input, plant))
    }

    /// The run the I8 negative controls plant their faults in is healthy
    /// without one.
    #[test]
    fn run_without_a_fault_is_accepted() {
        let report = measure(&observe(input([2, 3, 1], program(&DISCOVERY, &[]), 46)));
        assert_eq!(report.outcome, ProbeOutcome::Program);
        assert!(report.measured(), "{report}");
    }

    /// I8 negative control: a probe that stops while the program runs.
    #[test]
    #[should_panic(expected = "I8 violated: correct engines [2] stopped before the run ended")]
    fn actor_that_stops_is_rejected() {
        faulted(Stage::Started, Fault::Sever(2));
    }

    /// I8 negative control: a probe that stops after the last event, in the
    /// closing window, which is watched like the program.
    #[test]
    #[should_panic(expected = "I8 violated: correct engines [0] stopped before the run ended")]
    fn actor_that_stops_in_the_closing_window_is_rejected() {
        faulted(Stage::Closing, Fault::Sever(0));
    }

    /// I8 negative control: a panic in a task of an engine. No engine of this
    /// target is compromised, so it is a violation whatever it says.
    #[test]
    #[should_panic(expected = "I8 violated: correct engine 1 panicked")]
    fn engine_panic_is_rejected() {
        faulted(Stage::Started, Fault::EnginePanic(1));
    }

    /// I8 negative control: a panic in a task of the harness.
    #[test]
    #[should_panic(expected = "I8 violated: a task of no engine panicked")]
    fn harness_panic_is_rejected() {
        faulted(Stage::Started, Fault::HarnessPanic);
    }
}
