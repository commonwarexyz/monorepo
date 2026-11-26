//! Proposal switch: an old vote must not join a certificate after the selected
//! proposal of its round changes.
//!
//! The batcher keeps votes per round, verified against the round's selected
//! proposal, and drops buffered votes for any other proposal when the selection
//! changes (`consensus/src/simplex/actors/batcher/verifier.rs`,
//! `Verifier::set_proposal`: "if the selected proposal changes, drops buffered
//! notarize and finalize votes for any other proposal"). A vote that outlives the
//! change can be joined with votes for the new proposal into a certificate that
//! carries one proposal and signatures over another. The voter takes such a
//! certificate on its trusted path, reports it and broadcasts it.
//!
//! The scenario runs one production engine, the victim, on the production
//! secp256r1 scheme, which is not batchable: the batcher verifies each vote as it
//! arrives, so every valid vote enters the verified buffer at once. The other three
//! participants run no engine. They send the victim fuzzer-chosen votes and
//! certificates for views 1 and 2, signed with their own keys, at fuzzer-chosen
//! times, and drain everything the victim sends them. The first five steps of every
//! input default to a fixed schedule that switches view 1 from proposal A, for which
//! the leader already voted finalize, to proposal B through a notarization, then
//! sends two finalize votes for B: an old finalize vote kept across the switch
//! completes a quorum of three.
//!
//! Every certificate a scripted participant receives from the victim must decode
//! and verify for its own subject ([`OUTBOUND_LABEL`]), and the victim's reporter,
//! which verifies every certificate it is given, must count no invalid certificate
//! at the end of the run ([`REPORTED_LABEL`]). Neither check needs a fault bound:
//! the victim counts only votes it verified itself, so the scripted participants
//! may equivocate freely.
//!
//! Not asserted: batchable schemes, a vote that is in flight in a verification job
//! while the proposal changes, agreement, liveness, the application and marshal
//! layers, the validity of votes the victim reports, views above 2 and restarts.

use crate::{
    blackout::{CERTIFICATION_TIMEOUT, LEADER_TIMEOUT},
    chaos::runner::ChaosReporter,
};
use arbitrary::{Arbitrary, Unstructured};
use commonware_actor::{Feedback, Unreliable};
use commonware_codec::{Copying, Decode as _, Encode as _};
use commonware_consensus::{
    Handoff, Reporter as _, Viewable as _,
    simplex::{
        ForwardPolicy,
        elector::{Config as ElectorConfig, Elector},
        mocks::relay,
        types::{
            Activity, Certificate, Finalization, Finalize, Notarization, Notarize, Nullification,
            Nullify, Proposal, Vote,
        },
    },
    types::{Epoch, Round, TermLength, View, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    BlockFilterChoice, CertCfgOf, CertifyChoice, DEFAULT_MAILBOX_SIZE, EPOCH,
    FuzzInput as BaseInput, N4F0C4, PublicKeyOf, ReporterWiring, build_validator_with_reporter,
    setup_network,
    simplex::{Simplex, SimplexSecp256r1},
    strategy::StrategyChoice,
    utils::Partition,
};
use commonware_cryptography::{certificate::Verifier as _, sha256::Digest as Sha256Digest};
use commonware_p2p::{CheckedSender, LimitedSender, Receiver as _, Recipients, Sender as _};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, IoBuf, IoBufs, Runner, Spawner as _, Supervisor as _, deterministic,
};
use commonware_utils::{
    FuzzRng, TestRng, TryCollect as _, non_empty,
    ordered::{Quorum as _, Set},
    sync::Mutex,
};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

/// Most input bytes kept as the runtime's entropy.
pub const MAX_RAW_BYTES: usize = commonware_consensus_fuzz_core::MAX_RAW_BYTES;
/// Steps every input runs first; [`Op::Canonical`] at these positions sends the
/// fixed schedule.
pub const CANONICAL_STEPS: usize = 5;
/// Most steps decoded after the first [`CANONICAL_STEPS`].
pub const MAX_EXTRA_STEPS: usize = 27;
/// Upper bound of the gap before a step, in milliseconds. Decoded in reverse, so
/// an exhausted input gets the longest gap.
pub const MAX_GAP_MS: u64 = 100;
/// Highest view a step names; views start at 1.
pub const MAX_VIEW: u64 = 2;
/// Number of proposals a step can name per view.
pub const PROPOSALS: usize = 3;
/// Simulated wait after the last step before the end check.
pub const SETTLE_MS: u64 = 2_000;
/// Participants in the committee.
pub const PARTICIPANTS: usize = 4;
/// Participants that run no engine and send the scripted messages.
pub const SCRIPTED: usize = PARTICIPANTS - 1;
/// Vote channel of every registration.
pub const VOTE_CHANNEL: u64 = 0;
/// Certificate channel of every registration.
pub const CERTIFICATE_CHANNEL: u64 = 1;
/// Resolver channel of every registration.
pub const RESOLVER_CHANNEL: u64 = 2;
/// Payload digests of proposals 0, 1 and 2: A, B and C.
pub const PAYLOADS: [[u8; 32]; PROPOSALS] = [[1; 32], [2; 32], [3; 32]];
/// The proposal a plant puts in place of the real one: C.
pub const PLANTED_PROPOSAL: usize = 2;

/// Panic label of the check on certificates the victim sends.
pub const OUTBOUND_LABEL: &str = "outbound certificate invalid:";
/// Panic label of the check on the victim reporter's invalid-certificate count.
pub const REPORTED_LABEL: &str = "reported invalid certificates:";
/// Panic label of [`assert_floor`].
pub const VACUOUS_LABEL: &str = "proposal switch vacuous:";

type P = SimplexSecp256r1;
type S = <P as Simplex>::Scheme;
type K = PublicKeyOf<P>;
type D = Sha256Digest;
type VictimElector = <<P as Simplex>::Elector as ElectorConfig<S>>::Elector;

/// What one step sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// Step `k` of the fixed schedule at positions below [`CANONICAL_STEPS`];
    /// nothing after.
    Canonical,
    /// A notarize vote for `prop(view, p)` by the leader of `view`.
    LeaderNotarize,
    /// A notarize vote for `prop(view, p)` by `scripted[s]`.
    Notarize,
    /// A finalize vote for `prop(view, p)` by `scripted[s]`.
    Finalize,
    /// A nullify vote for `view` by `scripted[s]`.
    Nullify,
    /// A notarization of `prop(view, p)` from every scripted participant, sent
    /// by `scripted[s]`.
    Notarization,
    /// A finalization of `prop(view, p)` from every scripted participant, sent
    /// by `scripted[s]`.
    Finalization,
    /// A nullification of `view` from every scripted participant, sent by
    /// `scripted[s]`.
    Nullification,
}

impl Op {
    /// Every op in decode order: a step draws an index into `ALL`.
    pub const ALL: [Self; 8] = [
        Self::Canonical,
        Self::LeaderNotarize,
        Self::Notarize,
        Self::Finalize,
        Self::Nullify,
        Self::Notarization,
        Self::Finalization,
        Self::Nullification,
    ];
}

/// One step of the script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub op: Op,
    /// In `1..=MAX_VIEW`.
    pub view: u64,
    /// Position in the scripted set, in `0..SCRIPTED`.
    pub s: usize,
    /// Proposal, in `0..PROPOSALS`.
    pub p: usize,
    /// Simulated wait before this step, in `0..=MAX_GAP_MS`.
    pub gap_ms: u64,
}

impl Step {
    /// A step with the empty input's gap.
    pub const fn new(op: Op, view: u64, s: usize, p: usize) -> Self {
        Self {
            op,
            view,
            s,
            p,
            gap_ms: MAX_GAP_MS,
        }
    }

    /// The step an exhausted input decodes.
    pub const fn canonical() -> Self {
        Self::new(Op::Canonical, 1, 0, 0)
    }
}

/// The scenario's input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzInput {
    /// The runtime's entropy: a copy of the whole input, at most
    /// [`MAX_RAW_BYTES`].
    pub raw_bytes: Vec<u8>,
    /// From [`CANONICAL_STEPS`] to `CANONICAL_STEPS + MAX_EXTRA_STEPS` steps.
    pub steps: Vec<Step>,
}

impl FuzzInput {
    /// An input with `steps` whose runtime entropy is `seed` as eight big-endian
    /// bytes, for fixed scenarios that do not decode bytes.
    pub fn from_steps(seed: u64, steps: Vec<Step>) -> Self {
        Self {
            raw_bytes: seed.to_be_bytes().to_vec(),
            steps,
        }
    }
}

impl<'a> Arbitrary<'a> for Step {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let op = Op::ALL[u.int_in_range(0..=Op::ALL.len() - 1)?];
        let view = u.int_in_range(1..=MAX_VIEW)?;
        let s = u.int_in_range(0..=SCRIPTED - 1)?;
        let p = u.int_in_range(0..=PROPOSALS - 1)?;
        let gap_ms = MAX_GAP_MS - u.int_in_range(0..=MAX_GAP_MS)?;
        Ok(Self {
            op,
            view,
            s,
            p,
            gap_ms,
        })
    }
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let raw_bytes = u
            .peek_bytes(u.len().min(MAX_RAW_BYTES))
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        let extra = u.int_in_range(0..=MAX_EXTRA_STEPS)?;
        let steps = (0..CANONICAL_STEPS + extra)
            .map(|_| Step::arbitrary(u))
            .collect::<arbitrary::Result<_>>()?;
        Ok(Self { raw_bytes, steps })
    }
}

/// The participants' roles, by index in fixture order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Roles {
    /// The only participant that runs an engine: the lowest index that leads
    /// neither view 1 nor view 2.
    pub victim: usize,
    /// Leaders of views 1 and 2.
    pub leaders: [usize; 2],
    /// Every other index, in index order.
    pub scripted: [usize; SCRIPTED],
    /// Positions in `scripted` of the two scripted participants other than the
    /// leader of view 1, in index order.
    pub x: usize,
    pub y: usize,
}

impl Roles {
    /// Roles under the elector the victim runs over `participants`.
    pub fn new(participants: &[K]) -> Self {
        let set: Set<K> = participants
            .iter()
            .cloned()
            .try_collect()
            .expect("public keys are unique");
        let elector: VictimElector = <<P as Simplex>::Elector as ElectorConfig<S>>::build(
            P::elector(TermLength::ONE, ViewDelta::zero()),
            &set,
        );
        let leader = |view: u64| {
            // Round robin elects by index and takes no certificate input.
            let leader = elector.elect(Round::new(Epoch::new(EPOCH), View::new(view)), ());
            let key = set.key(leader).expect("leader is a participant");
            participants
                .iter()
                .position(|participant| participant == key)
                .expect("leader is a participant")
        };
        let leaders = [leader(1), leader(MAX_VIEW)];
        let victim = (0..PARTICIPANTS)
            .find(|index| !leaders.contains(index))
            .expect("two leaders leave a victim among four participants");
        let mut scripted = [0; SCRIPTED];
        for (slot, index) in scripted
            .iter_mut()
            .zip((0..PARTICIPANTS).filter(|index| *index != victim))
        {
            *slot = index;
        }
        let mut others = (0..SCRIPTED).filter(|position| scripted[*position] != leaders[0]);
        let x = others.next().expect("two scripted participants follow");
        let y = others.next().expect("two scripted participants follow");
        Self {
            victim,
            leaders,
            scripted,
            x,
            y,
        }
    }

    /// Position in `scripted` of participant `index`.
    pub fn position(&self, index: usize) -> usize {
        self.scripted
            .iter()
            .position(|scripted| *scripted == index)
            .expect("index is scripted")
    }
}

/// Kind of a certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CertificateKind {
    Notarization,
    Nullification,
    Finalization,
    /// The bytes did not decode as a certificate.
    Undecodable,
}

/// A certificate a scripted participant received from the victim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checked {
    /// Simulated milliseconds since the victim's engine started.
    pub at_ms: u64,
    pub receiver: usize,
    pub kind: CertificateKind,
    /// Zero for an undecodable certificate.
    pub view: u64,
    /// The proposal's payload; `None` for a nullification or undecodable bytes.
    pub digest: Option<[u8; 32]>,
    /// Decoded and verified for its own subject.
    pub valid: bool,
}

/// The result of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub victim: usize,
    pub leaders: [usize; 2],
    /// Per step: simulated milliseconds since the victim's engine started, op,
    /// view, `s`, `p`. Every decoded step is listed, also one that sends nothing.
    pub sent: Vec<(u64, Op, u64, usize, usize)>,
    /// Every certificate a scripted participant received from the victim, in
    /// receive order.
    pub checked: Vec<Checked>,
    /// The victim reporter's notarize (kind 0) and finalize (kind 1) votes as
    /// (view, kind, signer index, digest).
    pub reported_votes: BTreeSet<(u64, u8, usize, [u8; 32])>,
    /// The victim reporter's notarizations (kind 0) and finalizations (kind 1) as
    /// (kind, view, digest).
    pub reported_certificates: BTreeSet<(u8, u64, [u8; 32])>,
    pub invalid_certificates: usize,
    /// Recorded, judged by nothing.
    pub invalid_votes: usize,
}

impl Report {
    /// `checked` holds a valid finalization of `view` with payload `digest`.
    pub fn has_valid_finalization(&self, view: u64, digest: [u8; 32]) -> bool {
        self.checked.iter().any(|checked| {
            checked.valid
                && checked.kind == CertificateKind::Finalization
                && checked.view == view
                && checked.digest == Some(digest)
        })
    }
}

/// Panics with [`VACUOUS_LABEL`] unless `report` holds a valid finalization of
/// `view` with payload `digest`.
pub fn assert_floor(report: &Report, view: u64, digest: [u8; 32]) {
    assert!(
        report.has_valid_finalization(view, digest),
        "{VACUOUS_LABEL} no valid finalization of view {view} with digest {} among {} checked \
         certificates",
        hex(&digest),
        report.checked.len()
    );
}

/// A fault planted at the observation boundary of one check, for negative
/// controls. [`fuzz`] and [`run`] plant nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plant {
    None,
    /// The victim's certificate sender puts proposal C in the first finalization
    /// it sends, keeping the certificate. The victim's state is unchanged.
    RewriteFirstFinalization,
    /// After the settle wait, the victim reporter is given its first
    /// finalization again with proposal C and the original certificate. The
    /// engine and the network never see it.
    ReportForgedFinalization,
}

/// Which checks panic. Both always record what they measure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checks {
    /// Certificates the victim sends ([`OUTBOUND_LABEL`]).
    pub outbound: bool,
    /// The victim reporter's invalid-certificate count ([`REPORTED_LABEL`]).
    pub reported: bool,
}

impl Checks {
    pub const BOTH: Self = Self {
        outbound: true,
        reported: true,
    };
}

/// Options of [`run_observed`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub plant: Plant,
    pub checks: Checks,
    /// Once the engine starts, a copy of the victim's resolver sender sends one
    /// message to every scripted participant.
    pub resolver_probe: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            plant: Plant::None,
            checks: Checks::BOTH,
            resolver_probe: false,
        }
    }
}

/// Kind of a scripted message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Notarize,
    Finalize,
    Nullify,
    Notarization,
    Finalization,
    Nullification,
}

/// A message a scripted participant sent to the victim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub kind: MessageKind,
    pub epoch: u64,
    pub view: u64,
    /// The proposal's parent view; `None` for a nullify vote or nullification.
    pub parent: Option<u64>,
    /// The proposal's payload; `None` for a nullify vote or nullification.
    pub digest: Option<[u8; 32]>,
    /// Indices of the participants that signed it, in index order.
    pub signers: Vec<usize>,
}

/// One step of a run, for tests that check the scenario's wiring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    /// The committee and its roles.
    Committee { participants: usize, roles: Roles },
    /// The core input given to the shared network setup.
    Network {
        configuration: (u32, u32, u32),
        connected: bool,
        degraded: bool,
    },
    /// `participant` holds a registration on each of `channels`.
    Registered {
        participant: usize,
        channels: Vec<u64>,
    },
    /// An engine started for `participant`.
    EngineStarted {
        participant: usize,
        reporter: &'static str,
        wiring: ReporterWiring,
        certify: CertifyChoice,
        leader_timeout: Duration,
        certification_timeout: Duration,
    },
    /// Step `step` was sent, or attempted when its op sends nothing at its
    /// position (`message` is `None`).
    Sent {
        step: usize,
        op: Op,
        sender: Option<usize>,
        recipient: Option<usize>,
        channel: Option<u64>,
        message: Option<Message>,
    },
    /// The resolver probe sent one message to `to`.
    ResolverProbe { to: usize },
    /// A scripted participant drained one message.
    Received {
        receiver: usize,
        channel: u64,
        from: usize,
    },
    /// A plant changed something; reported when the settle wait ends for
    /// [`Plant::RewriteFirstFinalization`], at the change for the other plant.
    Planted(Plant),
    /// The end check of the reporter count ran.
    EndCheck { invalid_certificates: usize },
    /// The run returned its report.
    Completed,
}

/// An [`Observation`] with its simulated time since the run started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observed {
    pub at: Duration,
    pub what: Observation,
}

/// The fuzz entry.
pub fn fuzz(input: FuzzInput) {
    run(&input);
}

/// Run one scenario and return its report.
pub fn run(input: &FuzzInput) -> Report {
    run_inner(input, Options::default(), false).0
}

/// [`run`] with `options`, also returning every [`Observation`].
pub fn run_observed(input: &FuzzInput, options: Options) -> (Report, Vec<Observed>) {
    run_inner(input, options, true)
}

/// `prop(view, p)`: the proposal for `view` with parent `view - 1` and payload
/// [`PAYLOADS`]`[p]`.
pub fn prop(view: u64, p: usize) -> Proposal<D> {
    Proposal::new(
        Round::new(Epoch::new(EPOCH), View::new(view)),
        View::new(view - 1),
        D::from(PAYLOADS[p]),
    )
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The core input given to the shared network setup: four connected
/// participants on lossless links.
fn base_input(raw_bytes: Vec<u8>) -> BaseInput {
    BaseInput {
        raw_bytes,
        required_containers: 1,
        term_length: TermLength::ONE,
        optimistic_views: ViewDelta::zero(),
        heterogeneous_optimism: false,
        handoff: Handoff::Wait,
        degraded_network: false,
        configuration: N4F0C4,
        partition: Partition::Connected,
        strategy: StrategyChoice::AnyScope,
        mailbox_size: DEFAULT_MAILBOX_SIZE,
        forwarding: ForwardPolicy::Disabled,
        certify: CertifyChoice::Always,
        block_filter: BlockFilterChoice::None,
        reporting: ReporterWiring::Solo,
    }
}

/// Shared log of [`Observed`] events; records nothing when disabled.
#[derive(Clone)]
struct Log {
    enabled: bool,
    start: SystemTime,
    events: Arc<Mutex<Vec<Observed>>>,
}

impl Log {
    fn push(&self, at: SystemTime, what: Observation) {
        if self.enabled {
            let at = at
                .duration_since(self.start)
                .expect("simulated time never runs backwards");
            self.events.lock().push(Observed { at, what });
        }
    }
}

fn millis_since(at: SystemTime, start: SystemTime) -> u64 {
    at.duration_since(start)
        .expect("simulated time never runs backwards")
        .as_millis() as u64
}

/// The victim's certificate sender. With the plant on, the first finalization
/// it sends carries proposal C.
#[derive(Clone)]
struct Rewriting<T> {
    inner: T,
    plant: bool,
    done: Arc<AtomicBool>,
    cfg: CertCfgOf<P>,
}

impl<T: LimitedSender> LimitedSender for Rewriting<T> {
    type PublicKey = T::PublicKey;
    type Checked<'a>
        = RewritingChecked<T::Checked<'a>>
    where
        Self: 'a;

    fn check(
        &mut self,
        recipients: Recipients<Self::PublicKey>,
    ) -> Result<Self::Checked<'_>, SystemTime> {
        let plant = self.plant;
        let done = self.done.clone();
        let cfg = self.cfg;
        self.inner.check(recipients).map(|inner| RewritingChecked {
            inner,
            plant,
            done,
            cfg,
        })
    }
}

struct RewritingChecked<C> {
    inner: C,
    plant: bool,
    done: Arc<AtomicBool>,
    cfg: CertCfgOf<P>,
}

impl<C: CheckedSender> CheckedSender for RewritingChecked<C> {
    type PublicKey = C::PublicKey;

    fn recipients(&self) -> Vec<Self::PublicKey> {
        self.inner.recipients()
    }

    fn send(self, message: impl Into<IoBufs> + Send, priority: bool) -> Unreliable<Feedback> {
        if !self.plant || self.done.load(Ordering::Relaxed) {
            return self.inner.send(message, priority);
        }
        let message: IoBufs = message.into();
        let bytes = message.coalesce();
        let Ok(Certificate::Finalization(finalization)) =
            Certificate::<S, D>::decode_cfg(Copying(bytes.as_ref()), &self.cfg)
        else {
            return self.inner.send(bytes, priority);
        };
        self.done.store(true, Ordering::Relaxed);
        let rewritten = Certificate::<S, D>::Finalization(Finalization {
            proposal: prop(finalization.view().get(), PLANTED_PROPOSAL),
            certificate: finalization.certificate,
        });
        self.inner.send(IoBuf::from(rewritten.encode()), priority)
    }
}

/// Checks one certificate a scripted participant received.
fn check_certificate(bytes: &[u8], verifier: &S, at_ms: u64, receiver: usize) -> Checked {
    let Ok(certificate) =
        Certificate::<S, D>::decode_cfg(Copying(bytes), &verifier.certificate_codec_config())
    else {
        return Checked {
            at_ms,
            receiver,
            kind: CertificateKind::Undecodable,
            view: 0,
            digest: None,
            valid: false,
        };
    };
    // A generator of its own: verification draws nothing from the run.
    let valid = certificate.verify(&mut TestRng::new(0), verifier, &Sequential);
    let (kind, digest) = match &certificate {
        Certificate::Notarization(notarization) => (
            CertificateKind::Notarization,
            Some(notarization.proposal.payload.0),
        ),
        Certificate::Nullification(_) => (CertificateKind::Nullification, None),
        Certificate::Finalization(finalization) => (
            CertificateKind::Finalization,
            Some(finalization.proposal.payload.0),
        ),
    };
    Checked {
        at_ms,
        receiver,
        kind,
        view: certificate.view().get(),
        digest,
        valid,
    }
}

/// The scripted side's signing material and message builders.
struct Script<'a> {
    roles: Roles,
    schemes: &'a [S],
}

impl Script<'_> {
    fn notarize(&self, signer: usize, view: u64, p: usize) -> Notarize<S, D> {
        Notarize::sign(&self.schemes[signer], prop(view, p)).expect("a participant signs")
    }

    fn finalize(&self, signer: usize, view: u64, p: usize) -> Finalize<S, D> {
        Finalize::sign(&self.schemes[signer], prop(view, p)).expect("a participant signs")
    }

    fn nullify(&self, signer: usize, view: u64) -> Nullify<S> {
        Nullify::sign::<D>(
            &self.schemes[signer],
            Round::new(Epoch::new(EPOCH), View::new(view)),
        )
        .expect("a participant signs")
    }

    fn assembler(&self) -> &S {
        &self.schemes[self.roles.scripted[0]]
    }

    fn notarization(&self, view: u64, p: usize) -> Notarization<S, D> {
        let votes: Vec<_> = self
            .roles
            .scripted
            .iter()
            .map(|signer| self.notarize(*signer, view, p))
            .collect();
        Notarization::from_notarizes(self.assembler(), non_empty![@votes.iter()], &Sequential)
            .expect("a quorum of votes for one proposal assembles")
    }

    fn finalization(&self, view: u64, p: usize) -> Finalization<S, D> {
        let votes: Vec<_> = self
            .roles
            .scripted
            .iter()
            .map(|signer| self.finalize(*signer, view, p))
            .collect();
        Finalization::from_finalizes(self.assembler(), non_empty![@votes.iter()], &Sequential)
            .expect("a quorum of votes for one proposal assembles")
    }

    fn nullification(&self, view: u64) -> Nullification<S> {
        let votes: Vec<_> = self
            .roles
            .scripted
            .iter()
            .map(|signer| self.nullify(*signer, view))
            .collect();
        Nullification::from_nullifies(self.assembler(), non_empty![@votes.iter()], &Sequential)
            .expect("a quorum of votes for one round assembles")
    }

    fn vote(&self, kind: MessageKind, signer: usize, view: u64, p: usize) -> (Vec<u8>, Message) {
        let (bytes, parent, digest) = match kind {
            MessageKind::Notarize => (
                Vote::<S, D>::Notarize(self.notarize(signer, view, p)).encode(),
                Some(view - 1),
                Some(PAYLOADS[p]),
            ),
            MessageKind::Finalize => (
                Vote::<S, D>::Finalize(self.finalize(signer, view, p)).encode(),
                Some(view - 1),
                Some(PAYLOADS[p]),
            ),
            MessageKind::Nullify => (
                Vote::<S, D>::Nullify(self.nullify(signer, view)).encode(),
                None,
                None,
            ),
            _ => unreachable!("a vote kind"),
        };
        (
            bytes.to_vec(),
            Message {
                kind,
                epoch: EPOCH,
                view,
                parent,
                digest,
                signers: vec![signer],
            },
        )
    }

    fn certificate(&self, kind: MessageKind, view: u64, p: usize) -> (Vec<u8>, Message) {
        let (bytes, parent, digest) = match kind {
            MessageKind::Notarization => (
                Certificate::<S, D>::Notarization(self.notarization(view, p)).encode(),
                Some(view - 1),
                Some(PAYLOADS[p]),
            ),
            MessageKind::Finalization => (
                Certificate::<S, D>::Finalization(self.finalization(view, p)).encode(),
                Some(view - 1),
                Some(PAYLOADS[p]),
            ),
            MessageKind::Nullification => (
                Certificate::<S, D>::Nullification(self.nullification(view)).encode(),
                None,
                None,
            ),
            _ => unreachable!("a certificate kind"),
        };
        (
            bytes.to_vec(),
            Message {
                kind,
                epoch: EPOCH,
                view,
                parent,
                digest,
                signers: self.roles.scripted.to_vec(),
            },
        )
    }

    /// What step `position` sends: sender index, channel, bytes and their
    /// description; `None` for [`Op::Canonical`] past the fixed schedule.
    fn outbound(&self, position: usize, step: &Step) -> Option<(usize, u64, Vec<u8>, Message)> {
        let roles = &self.roles;
        let leader_1 = roles.leaders[0];
        let x = roles.scripted[roles.x];
        let y = roles.scripted[roles.y];
        let by = roles.scripted[step.s];
        let (sender, channel, (bytes, message)) = match step.op {
            Op::Canonical => match position {
                0 => (
                    leader_1,
                    VOTE_CHANNEL,
                    self.vote(MessageKind::Notarize, leader_1, 1, 0),
                ),
                1 => (
                    leader_1,
                    VOTE_CHANNEL,
                    self.vote(MessageKind::Finalize, leader_1, 1, 0),
                ),
                2 => (
                    x,
                    CERTIFICATE_CHANNEL,
                    self.certificate(MessageKind::Notarization, 1, 1),
                ),
                3 => (x, VOTE_CHANNEL, self.vote(MessageKind::Finalize, x, 1, 1)),
                4 => (y, VOTE_CHANNEL, self.vote(MessageKind::Finalize, y, 1, 1)),
                _ => return None,
            },
            Op::LeaderNotarize => {
                let leader = roles.leaders[(step.view - 1) as usize];
                (
                    leader,
                    VOTE_CHANNEL,
                    self.vote(MessageKind::Notarize, leader, step.view, step.p),
                )
            }
            Op::Notarize => (
                by,
                VOTE_CHANNEL,
                self.vote(MessageKind::Notarize, by, step.view, step.p),
            ),
            Op::Finalize => (
                by,
                VOTE_CHANNEL,
                self.vote(MessageKind::Finalize, by, step.view, step.p),
            ),
            Op::Nullify => (
                by,
                VOTE_CHANNEL,
                self.vote(MessageKind::Nullify, by, step.view, step.p),
            ),
            Op::Notarization => (
                by,
                CERTIFICATE_CHANNEL,
                self.certificate(MessageKind::Notarization, step.view, step.p),
            ),
            Op::Finalization => (
                by,
                CERTIFICATE_CHANNEL,
                self.certificate(MessageKind::Finalization, step.view, step.p),
            ),
            Op::Nullification => (
                by,
                CERTIFICATE_CHANNEL,
                self.certificate(MessageKind::Nullification, step.view, step.p),
            ),
        };
        Some((sender, channel, bytes, message))
    }
}

fn run_inner(input: &FuzzInput, options: Options, observe: bool) -> (Report, Vec<Observed>) {
    let base = base_input(input.raw_bytes.clone());
    let steps = input.steps.clone();
    let rng = FuzzRng::new(input.raw_bytes.clone());
    let executor = deterministic::Runner::new(deterministic::Config::new().with_rng(rng));
    executor.start(|mut context| async move {
        let log = Log {
            enabled: observe,
            start: context.current(),
            events: Arc::default(),
        };
        let (oracle, participants, schemes, mut registrations) =
            setup_network::<P>(&mut context, &base).await;
        assert_eq!(
            participants.len(),
            PARTICIPANTS,
            "proposal switch: committee size"
        );
        let roles = Roles::new(&participants);
        log.push(
            context.current(),
            Observation::Committee {
                participants: participants.len(),
                roles,
            },
        );
        log.push(
            context.current(),
            Observation::Network {
                configuration: (
                    base.configuration.n,
                    base.configuration.faults,
                    base.configuration.correct,
                ),
                connected: base.partition.is_connected(),
                degraded: base.degraded_network,
            },
        );
        for (index, participant) in participants.iter().enumerate() {
            if registrations.contains_key(participant) {
                log.push(
                    context.current(),
                    Observation::Registered {
                        participant: index,
                        channels: vec![VOTE_CHANNEL, CERTIFICATE_CHANNEL, RESOLVER_CHANNEL],
                    },
                );
            }
        }

        // The scripted side: keep the senders, drain the vote and resolver
        // channels, and check every certificate on arrival.
        let checked: Arc<Mutex<Vec<Checked>>> = Arc::default();
        let engine_start: Arc<Mutex<Option<SystemTime>>> = Arc::default();
        let mut senders = Vec::with_capacity(SCRIPTED);
        for &index in &roles.scripted {
            let (
                (vote_sender, vote_receiver),
                (certificate_sender, mut certificate_receiver),
                (resolver_sender, resolver_receiver),
            ) = registrations
                .remove(&participants[index])
                .expect("proposal switch: participant was not registered");
            senders.push((index, vote_sender, certificate_sender, resolver_sender));

            for (channel, mut receiver) in [
                (VOTE_CHANNEL, vote_receiver),
                (RESOLVER_CHANNEL, resolver_receiver),
            ] {
                let participants = participants.clone();
                let log = log.clone();
                context
                    .child("drain")
                    .with_attribute("participant", index)
                    .spawn(move |ctx| async move {
                        while let Ok((from, _)) = receiver.recv().await {
                            let from = participants
                                .iter()
                                .position(|participant| *participant == from)
                                .expect("sender is a participant");
                            log.push(
                                ctx.current(),
                                Observation::Received {
                                    receiver: index,
                                    channel,
                                    from,
                                },
                            );
                        }
                    });
            }

            let participants = participants.clone();
            let log = log.clone();
            let checked = checked.clone();
            let engine_start = engine_start.clone();
            let verifier = schemes[index].clone();
            let victim = roles.victim;
            let outbound = options.checks.outbound;
            context
                .child("checker")
                .with_attribute("participant", index)
                .spawn(move |ctx| async move {
                    while let Ok((from, bytes)) = certificate_receiver.recv().await {
                        let now = ctx.current();
                        let from = participants
                            .iter()
                            .position(|participant| *participant == from)
                            .expect("sender is a participant");
                        log.push(
                            now,
                            Observation::Received {
                                receiver: index,
                                channel: CERTIFICATE_CHANNEL,
                                from,
                            },
                        );
                        if from != victim {
                            continue;
                        }
                        let start = engine_start
                            .lock()
                            .expect("certificates arrive after the engine starts");
                        let item = check_certificate(
                            bytes.as_ref(),
                            &verifier,
                            millis_since(now, start),
                            index,
                        );
                        let valid = item.valid;
                        checked.lock().push(item.clone());
                        if outbound && !valid {
                            panic!(
                                "{OUTBOUND_LABEL} {:?} for view {} with digest {} received by \
                                 participant {index} at {} ms",
                                item.kind,
                                item.view,
                                item.digest.as_ref().map_or_else(|| "none".to_string(), hex),
                                item.at_ms
                            );
                        }
                    }
                });
        }

        // The victim.
        let victim_key = participants[roles.victim].clone();
        let (pending, (certificate_sender, certificate_receiver), resolver) = registrations
            .remove(&victim_key)
            .expect("proposal switch: victim was not registered");
        let rewritten = Arc::new(AtomicBool::new(false));
        let certificate_sender = Rewriting {
            inner: certificate_sender,
            plant: options.plant == Plant::RewriteFirstFinalization,
            done: rewritten.clone(),
            cfg: schemes[roles.victim].certificate_codec_config(),
        };
        let mut probe = options.resolver_probe.then(|| resolver.0.clone());
        let term_length = P::effective_term_length(base.term_length);
        let relay = Arc::new(relay::Relay::new());
        let validator = build_validator_with_reporter::<P, _, ChaosReporter<P>, _, _, _, _, _, _>(
            None,
            context
                .child("validator")
                .with_attribute("public_key", &victim_key),
            &oracle,
            &participants,
            schemes[roles.victim].clone(),
            victim_key.clone(),
            P::elector(term_length, base.optimistic_views),
            relay,
            LEADER_TIMEOUT,
            CERTIFICATION_TIMEOUT,
            base.mailbox_size,
            base.forwarding,
            victim_key.to_string(),
            pending,
            (certificate_sender, certificate_receiver),
            resolver,
            base.certify,
            base.handoff,
            base.reporting,
        );
        let reporter = validator.reporter();
        let t0 = context.current();
        *engine_start.lock() = Some(t0);
        log.push(
            t0,
            Observation::EngineStarted {
                participant: roles.victim,
                reporter: "ChaosReporter",
                wiring: base.reporting,
                certify: base.certify,
                leader_timeout: LEADER_TIMEOUT,
                certification_timeout: CERTIFICATION_TIMEOUT,
            },
        );
        if let Some(probe) = probe.as_mut() {
            for &to in &roles.scripted {
                probe.send(
                    Recipients::One(participants[to].clone()),
                    IoBuf::from(vec![0u8]),
                    false,
                );
                log.push(context.current(), Observation::ResolverProbe { to });
            }
        }

        // The script.
        let script = Script {
            roles,
            schemes: &schemes,
        };
        let mut sent = Vec::with_capacity(steps.len());
        let mut due = t0;
        for (position, step) in steps.iter().enumerate() {
            due += Duration::from_millis(step.gap_ms);
            context.sleep_until(due).await;
            let at_ms = millis_since(context.current(), t0);
            sent.push((at_ms, step.op, step.view, step.s, step.p));
            let Some((sender, channel, bytes, message)) = script.outbound(position, step) else {
                log.push(
                    context.current(),
                    Observation::Sent {
                        step: position,
                        op: step.op,
                        sender: None,
                        recipient: None,
                        channel: None,
                        message: None,
                    },
                );
                continue;
            };
            let entry = senders
                .iter_mut()
                .find(|(index, ..)| *index == sender)
                .expect("the sender is scripted");
            let recipients = match channel {
                VOTE_CHANNEL => entry.1.send(
                    Recipients::One(victim_key.clone()),
                    IoBuf::from(bytes),
                    true,
                ),
                _ => entry.2.send(
                    Recipients::One(victim_key.clone()),
                    IoBuf::from(bytes),
                    true,
                ),
            };
            assert_eq!(
                recipients,
                vec![victim_key.clone()],
                "proposal switch: the network refused step {position}"
            );
            log.push(
                context.current(),
                Observation::Sent {
                    step: position,
                    op: step.op,
                    sender: Some(sender),
                    recipient: Some(roles.victim),
                    channel: Some(channel),
                    message: Some(message),
                },
            );
        }

        context
            .sleep_until(due + Duration::from_millis(SETTLE_MS))
            .await;
        if rewritten.load(Ordering::Relaxed) {
            log.push(
                context.current(),
                Observation::Planted(Plant::RewriteFirstFinalization),
            );
        }

        let inner = reporter.inner();
        if options.plant == Plant::ReportForgedFinalization {
            let first = inner
                .finalizations
                .lock()
                .iter()
                .min_by_key(|(view, _)| **view)
                .map(|(_, (finalization, _))| finalization.clone())
                .expect("the plant needs a finalization at the victim");
            let forged = Finalization {
                proposal: prop(first.view().get(), PLANTED_PROPOSAL),
                certificate: first.certificate,
            };
            inner.clone().report(Activity::Finalization(forged));
            log.push(
                context.current(),
                Observation::Planted(Plant::ReportForgedFinalization),
            );
        }

        let invalid_certificates = *inner.invalid_certificates.lock();
        log.push(
            context.current(),
            Observation::EndCheck {
                invalid_certificates,
            },
        );
        if options.checks.reported && invalid_certificates != 0 {
            panic!(
                "{REPORTED_LABEL} the victim's reporter counted {invalid_certificates} invalid \
                 certificates"
            );
        }

        let index_of = |key: &K| {
            participants
                .iter()
                .position(|participant| participant == key)
                .expect("signer is a participant")
        };
        let mut reported_votes = BTreeSet::new();
        for (kind, votes) in [(0u8, &inner.notarizes), (1u8, &inner.finalizes)] {
            for (view, by_digest) in votes.lock().iter() {
                for (digest, signers) in by_digest {
                    for signer in signers {
                        reported_votes.insert((view.get(), kind, index_of(signer), digest.0));
                    }
                }
            }
        }
        let mut reported_certificates = BTreeSet::new();
        for (view, notarization) in inner.notarizations.lock().iter() {
            reported_certificates.insert((0u8, view.get(), notarization.proposal.payload.0));
        }
        for (view, (finalization, _)) in inner.finalizations.lock().iter() {
            reported_certificates.insert((1u8, view.get(), finalization.proposal.payload.0));
        }
        let report = Report {
            victim: roles.victim,
            leaders: roles.leaders,
            sent,
            checked: checked.lock().clone(),
            reported_votes,
            reported_certificates,
            invalid_certificates,
            invalid_votes: *inner.invalid_votes.lock(),
        };
        log.push(context.current(), Observation::Completed);
        drop(validator);
        drop(reporter);
        let events = log.events.lock().clone();
        (report, events)
    })
}
