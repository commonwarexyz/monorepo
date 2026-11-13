//! What each correct engine observed of a ceremony, and every safety check
//! over those records.
//!
//! Records are taken from what an engine reported and from its secret store,
//! never from harness-side bookkeeping about what should have happened, and
//! are keyed by engine. Both halves of the compromised identity are excluded
//! from every record: all agreement claims are about correct nodes.
//!
//! The probe target's records are of another kind: what each source was
//! seeded with, the responses the sources built, and what crossed the
//! discovering probe's public boundaries, in the order it happened.
//!
//! Every check panics with a message naming the invariant of `SPEC.md` it
//! enforces, the engines involved, and the epoch.

use super::{
    BootstrapInfo, Digest, Directory, EPOCH_LENGTH, Info, MockGroup, PublicKey,
    schedule::Schedule,
    scheme::{Registration, Scheme},
};
use crate::stateful::runner::Panic;
use commonware_consensus::{
    Epochable as _,
    simplex::types::Finalization,
    types::{Epoch, EpochPhase, Epocher as _, FixedEpocher, Height, Round},
};
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::deal,
    primitives::{
        group::Share,
        ops::{self, threshold},
        sharing::Mode,
    },
};
use commonware_glue::dkg::{
    network,
    probe::Artifact,
    types::{EpochInfo, EpochOutcome, Payload, SchemeInfo},
};
use commonware_p2p::Recipients;
use commonware_parallel::Sequential;
use commonware_utils::{
    Faults as _, N3f1, Participant, TestRng, channel::mpsc, ordered::Set, sync::Mutex,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

/// Namespace and message of the signature the reconstruction check recovers.
const RECONSTRUCTION_NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_FUZZ_DKG_RECONSTRUCTION";
const RECONSTRUCTION_MESSAGE: &[u8] = b"reconstruction";

/// How a ceremony ended at one engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Ending {
    /// The ceremony produced this output.
    Success(Box<BootstrapInfo>),
    /// The ceremony failed and produced no output.
    Failure,
}

/// What one correct engine observed of a ceremony.
#[derive(Clone, Debug)]
pub(crate) struct Observed {
    /// The engine, for failure messages.
    pub(crate) engine: usize,
    /// The identity the engine runs as.
    pub(crate) identity: PublicKey,
    /// How the ceremony ended at this engine, if it completed there.
    pub(crate) ending: Option<Ending>,
    /// The share the engine's secret store holds for the ceremony's epoch.
    pub(crate) share: Option<Share>,
}

/// One ceremony as the correct engines observed it.
#[derive(Clone, Debug)]
pub(crate) struct Ceremony {
    /// The epoch whose key the ceremony produces.
    pub(crate) epoch: Epoch,
    /// The correct engines.
    pub(crate) nodes: Vec<Observed>,
}

/// What one correct engine of a bootstrap run observed, across every instance
/// of it the run started.
#[derive(Clone, Debug)]
pub(crate) struct Bootstrapper {
    /// The engine, for failure messages.
    pub(crate) engine: usize,
    /// The identity the engine runs as.
    pub(crate) identity: PublicKey,
    /// How the ceremony ended at each instance that reported it, in the order
    /// the instances reported, each with the share the engine's secret store
    /// held for epoch zero when the report was recorded.
    pub(crate) completions: Vec<(Ending, Option<Share>)>,
    /// Every distinct share the engine's secret store held for epoch zero, in
    /// the order stored, a share later overwritten included.
    pub(crate) held: Vec<Share>,
    /// The share the engine's secret store holds for epoch zero at the end of
    /// the run.
    pub(crate) share: Option<Share>,
}

impl Bootstrapper {
    /// This engine's record of the ceremony with `ending` and `share`.
    fn observed(&self, ending: Option<Ending>, share: Option<Share>) -> Observed {
        Observed {
            engine: self.engine,
            identity: self.identity.clone(),
            ending,
            share,
        }
    }
}

/// A bootstrap run as the correct engines observed it.
#[derive(Clone, Debug)]
pub(crate) struct Bootstrap {
    /// The sharing mode every engine is configured with.
    pub(crate) mode: Mode,
    /// The correct engines.
    pub(crate) nodes: Vec<Bootstrapper>,
}

impl Bootstrap {
    /// The ceremony as the end of the run leaves it: how it ended at the
    /// first instance of each engine that reported it, and the share each
    /// engine holds.
    fn ended(&self) -> Ceremony {
        Ceremony {
            epoch: Epoch::zero(),
            nodes: self
                .nodes
                .iter()
                .map(|node| {
                    let first = node.completions.first().map(|(ending, _)| ending.clone());
                    node.observed(first, node.share.clone())
                })
                .collect(),
        }
    }

    /// Every report an instance of a correct engine made, each with the share
    /// the engine held when the report was recorded.
    fn reported(&self) -> Ceremony {
        Ceremony {
            epoch: Epoch::zero(),
            nodes: self
                .nodes
                .iter()
                .flat_map(|node| {
                    node.completions
                        .iter()
                        .map(|(ending, share)| node.observed(Some(ending.clone()), share.clone()))
                })
                .collect(),
        }
    }

    /// Every share a correct engine held, each on its own, with no report.
    fn held(&self) -> Ceremony {
        Ceremony {
            epoch: Epoch::zero(),
            nodes: self
                .nodes
                .iter()
                .flat_map(|node| {
                    node.held
                        .iter()
                        .map(|share| node.observed(None, Some(share.clone())))
                })
                .collect(),
        }
    }
}

/// How much each check compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Correct engines observed.
    pub correct_nodes: usize,
    /// Correct engines at which the ceremony completed.
    pub completed: usize,
    /// Ceremonies the correct engines agreed had succeeded.
    pub successes: usize,
    /// Cross-engine result comparisons made under I1.
    pub agreements: usize,
    /// Shares checked under I2: every distinct share a correct engine held,
    /// against the agreed output, or against the committee if no correct
    /// engine reported.
    pub shares: usize,
    /// Share subsets of the size the output requires that recovered, under
    /// I3, a signature its key verifies, or the signature every other such
    /// subset recovered if no correct engine reported.
    pub reconstructions: usize,
    /// Blocks the network recorded, by any identity.
    pub blocks: usize,
    /// Panics tolerated because they stop a half of the compromised identity.
    pub tolerated_panics: usize,
}

/// I1: any two correct engines that completed the same ceremony hold the
/// same result for it.
///
/// Returns the result they agree on, if any engine completed, and the number
/// of comparisons made.
pub(crate) fn check_output_agreement(ceremony: &Ceremony) -> (Option<&Ending>, usize) {
    let mut completed = ceremony
        .nodes
        .iter()
        .filter_map(|node| node.ending.as_ref().map(|ending| (node.engine, ending)));
    let Some((first, agreed)) = completed.next() else {
        return (None, 0);
    };
    let mut comparisons = 0;
    for (engine, ending) in completed {
        assert!(
            ending == agreed,
            "I1 violated: engines {first} and {engine} disagree on the ceremony of epoch {}: \
             {agreed:?} != {ending:?}",
            ceremony.epoch,
        );
        comparisons += 1;
    }
    (Some(agreed), comparisons)
}

/// I1, for a bootstrap: a successful result describes the ceremony that was
/// run. It is the successful output of the ceremony's epoch, among exactly
/// the committee, with no next players, and its sharing needs the committee's
/// quorum of shares.
pub(crate) fn check_bootstrap_output(
    ceremony: &Ceremony,
    info: &BootstrapInfo,
    committee: &[PublicKey],
) {
    let epoch = ceremony.epoch;
    assert!(
        info.outcome == EpochOutcome::Success && info.epoch == epoch,
        "I1 violated: the successful ceremony of epoch {epoch} reports outcome {:?} for epoch {}",
        info.outcome,
        info.epoch,
    );
    let members = |players: &Set<PublicKey>| players.iter().eq(committee.iter());
    assert!(
        members(info.output.players()) && members(&info.players),
        "I1 violated: the output of epoch {epoch} is not among the committee: output players \
         {:?}, players {:?}",
        info.output.players(),
        info.players,
    );
    assert!(
        info.next_players.is_empty(),
        "I1 violated: the bootstrap output of epoch {epoch} names next players {:?}",
        info.next_players,
    );
    let sharing = info.output.public();
    assert!(
        sharing.total().get() as usize == committee.len()
            && sharing.required() == info.output.quorum::<N3f1>(),
        "I1 violated: the sharing of epoch {epoch} is among {} participants and needs {} \
         shares, but the committee has {} members and a quorum of {}",
        sharing.total(),
        sharing.required(),
        committee.len(),
        info.output.quorum::<N3f1>(),
    );
}

/// I2: every share a correct engine holds carries the engine's index in the
/// agreed output, and its public key is the output's partial public key at
/// that index. An engine at which the ceremony completed successfully holds
/// one.
///
/// Returns the number of shares checked.
pub(crate) fn check_share_validity<D: network::Directory<PublicKey>>(
    ceremony: &Ceremony,
    info: &EpochInfo<MockGroup, PublicKey, D>,
) -> usize {
    let sharing = info.output.public();
    let mut checked = 0;
    for node in &ceremony.nodes {
        let Some(share) = &node.share else {
            assert!(
                node.ending.is_none(),
                "I2 violated: engine {} completed the successful ceremony of epoch {} without \
                 a share",
                node.engine,
                ceremony.epoch,
            );
            continue;
        };
        let index = info
            .output
            .players()
            .position(&node.identity)
            .map(Participant::from_usize);
        assert!(
            index == Some(share.index),
            "I2 violated: engine {} holds a share of epoch {} at index {:?}, but its identity \
             is at {index:?} in the output's players",
            node.engine,
            ceremony.epoch,
            share.index,
        );
        assert!(
            sharing.partial_public(share.index).ok() == Some(share.public::<MockGroup>()),
            "I2 violated: the share engine {} holds for epoch {} does not match the output's \
             partial public key at index {:?}",
            node.engine,
            ceremony.epoch,
            share.index,
        );
        checked += 1;
    }
    checked
}

/// Every subset of `0..n` with exactly `k` members.
fn subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
    (0u32..1 << n)
        .filter(|mask| mask.count_ones() as usize == k)
        .map(|mask| (0..n).filter(|bit| mask & (1 << bit) != 0).collect())
        .collect()
}

/// I3: every subset of exactly `required()` correct shares recovers a
/// signature that verifies under the output's group public key, and no
/// subset one smaller recovers one.
///
/// Returns the number of subsets that reconstructed the key.
pub(crate) fn check_reconstruction<D: network::Directory<PublicKey>>(
    ceremony: &Ceremony,
    info: &EpochInfo<MockGroup, PublicKey, D>,
) -> usize {
    let sharing = info.output.public();
    let required = sharing.required() as usize;
    let holders: Vec<(usize, &Share)> = ceremony
        .nodes
        .iter()
        .filter_map(|node| node.share.as_ref().map(|share| (node.engine, share)))
        .collect();
    let partials: Vec<_> = holders
        .iter()
        .map(|(_, share)| {
            threshold::sign_message::<MockGroup>(
                share,
                RECONSTRUCTION_NAMESPACE,
                RECONSTRUCTION_MESSAGE,
            )
        })
        .collect();
    let engines = |subset: &[usize]| -> Vec<usize> {
        subset.iter().map(|member| holders[*member].0).collect()
    };

    let mut reconstructed = 0;
    for subset in subsets(holders.len(), required) {
        let chosen: Vec<_> = subset.iter().map(|member| &partials[*member]).collect();
        let verified = threshold::recover::<MockGroup, _>(sharing, chosen, &Sequential)
            .ok()
            .is_some_and(|signature| {
                ops::verify_message::<MockGroup>(
                    sharing.public(),
                    RECONSTRUCTION_NAMESPACE,
                    RECONSTRUCTION_MESSAGE,
                    &signature,
                )
                .is_ok()
            });
        assert!(
            verified,
            "I3 violated: the shares of engines {:?} do not reconstruct the key of epoch {}",
            engines(&subset),
            ceremony.epoch,
        );
        reconstructed += 1;
    }
    if required > 0 {
        for subset in subsets(holders.len(), required - 1) {
            let chosen: Vec<_> = subset.iter().map(|member| &partials[*member]).collect();
            assert!(
                threshold::recover::<MockGroup, _>(sharing, chosen, &Sequential).is_err(),
                "I3 violated: the shares of engines {:?}, one fewer than required, recover a \
                 signature for epoch {}",
                engines(&subset),
                ceremony.epoch,
            );
        }
    }
    reconstructed
}

/// I6, for a bootstrap: after a failed ceremony no correct engine holds a
/// share of its epoch.
pub(crate) fn check_failed_bootstrap(ceremony: &Ceremony) {
    for node in &ceremony.nodes {
        assert!(
            node.share.is_none(),
            "I6 violated: engine {} holds a share of epoch {} although the ceremony failed",
            node.engine,
            ceremony.epoch,
        );
    }
}

/// I2 and I3 for a bootstrap that no correct engine reported, judged without
/// its output.
///
/// A bootstrap engine makes its outcome known only by reporting it: the final
/// block that carries the outcome stays in the engine's storage. An engine
/// that has stored its share reports at every later start, so a share that
/// no report accompanies is left only when the run ends between the write of
/// the share and a report: before the engine reports, or after a crash
/// between the two and before a later start has reported. Every output I1
/// accepts is among exactly `committee` and needs the committee's quorum of
/// shares. So I2 requires that a share a correct engine held carry the
/// engine's position in the committee and that no engine held two different
/// shares, and I3 requires that every quorum of the engines' shares recover
/// one and the same signature, since no key verifies two. Recovery reads of a
/// sharing only its mode, its size, and the number of shares it needs, so the
/// shares are recovered under the sharing of a trusted deal among the
/// committee in the run's mode. That sharing's key is not the ceremony's, and
/// no recovered signature is verified.
///
/// Not judged: whether the ceremony succeeded, so a share held after a failed
/// ceremony, which I6 forbids, passes; whether the shares are those of the
/// output the ceremony produced, which takes the output's partial public
/// keys; and, when no more engines hold a share than a quorum, whether the
/// shares lie on one polynomial, which any quorum of them does.
///
/// Returns the number of shares checked and of quorums of shares recovered.
pub(crate) fn check_unreported_shares(
    bootstrap: &Bootstrap,
    committee: &[PublicKey],
) -> (usize, usize) {
    let epoch = Epoch::zero();
    let mut checked = 0;
    let mut holders: Vec<(usize, &Share)> = Vec::new();
    for node in &bootstrap.nodes {
        let position = committee
            .iter()
            .position(|member| *member == node.identity)
            .map(Participant::from_usize);
        for share in &node.held {
            assert!(
                position == Some(share.index),
                "I2 violated: engine {} holds a share of epoch {epoch} at index {:?}, but its \
                 identity is at {position:?} in the committee",
                node.engine,
                share.index,
            );
            checked += 1;
        }
        let Some((share, others)) = node.held.split_first() else {
            continue;
        };
        assert!(
            others.iter().all(|other| other == share),
            "I2 violated: engine {} held two different shares of epoch {epoch}",
            node.engine,
        );
        holders.push((node.engine, share));
    }

    let players = Set::from_iter_dedup(committee.iter().cloned());
    let (frame, _) = deal::<MockGroup, _, N3f1>(TestRng::new(0), bootstrap.mode, players)
        .expect("a trusted deal among the committee must succeed");
    let sharing = frame.public();
    let required = sharing.required() as usize;
    let partials: Vec<_> = holders
        .iter()
        .map(|(_, share)| {
            threshold::sign_message::<MockGroup>(
                share,
                RECONSTRUCTION_NAMESPACE,
                RECONSTRUCTION_MESSAGE,
            )
        })
        .collect();
    let engines = |subset: &[usize]| -> Vec<usize> {
        subset.iter().map(|member| holders[*member].0).collect()
    };

    let mut recovered = None;
    let mut quorums = 0;
    for subset in subsets(holders.len(), required) {
        let chosen: Vec<_> = subset.iter().map(|member| &partials[*member]).collect();
        let signature = threshold::recover::<MockGroup, _>(sharing, chosen, &Sequential).ok();
        if let Some((first, agreed)) = &recovered {
            assert!(
                signature == *agreed,
                "I3 violated: the shares of engines {first:?} and the shares of engines {:?} \
                 recover different signatures for epoch {epoch}",
                engines(&subset),
            );
        } else {
            recovered = Some((engines(&subset), signature));
        }
        quorums += 1;
    }
    if required > 0 {
        for subset in subsets(holders.len(), required - 1) {
            let chosen: Vec<_> = subset.iter().map(|member| &partials[*member]).collect();
            assert!(
                threshold::recover::<MockGroup, _>(sharing, chosen, &Sequential).is_err(),
                "I3 violated: the shares of engines {:?}, one fewer than required, recover a \
                 signature for epoch {epoch}",
                engines(&subset),
            );
        }
    }
    (checked, quorums)
}

/// I8: no task panics, except a task of a half of the compromised identity.
///
/// `panics` lists every panic the run raised, each with the engine whose task
/// raised it, and `halves` lists the engines of the compromised identity. A
/// half holds secrets that differ from its twin's under one identity, and the
/// DKG module stops a node whose secrets contradict what its identity signed,
/// so a half may panic, whatever the panic says. A panic of any other engine,
/// or of a task that belongs to no engine, is a violation. Returns the number
/// of panics tolerated.
pub(crate) fn check_panics(panics: &[Panic], halves: &[usize]) -> usize {
    for panic in panics {
        match panic.engine {
            Some(engine) if halves.contains(&engine) => {}
            Some(engine) => panic!(
                "I8 violated: correct engine {engine} panicked: {}",
                panic.message
            ),
            None => panic!(
                "I8 violated: a task of no engine panicked: {}",
                panic.message
            ),
        }
    }
    panics.len()
}

/// I8: no correct engine stops before the run ends.
///
/// `stopped` lists the correct engines that did.
pub(crate) fn check_engines_running(stopped: &[usize]) {
    assert!(
        stopped.is_empty(),
        "I8 violated: correct engines {stopped:?} stopped before the run ended",
    );
}

/// How one instance of a correct engine left a run that restarts engines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Exit {
    /// The instance was running when the run ended.
    Running,
    /// The restart schedule aborted the instance.
    Crashed,
    /// The instance's task ended although nothing aborted it.
    Stopped,
}

/// One instance of a correct engine: the engine as the run first started it,
/// or as one restart brought it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Instance {
    /// The engine, for failure messages.
    pub(crate) engine: usize,
    /// How the instance left the run.
    pub(crate) exit: Exit,
}

/// I8: the run's root task, which is the harness itself, does not panic.
///
/// `result` is what the root task returned, or the payload of the panic that
/// left it, and `panics` lists every panic the run raised. Returns what the
/// root task returned.
pub(crate) fn check_root_task<T>(result: std::thread::Result<T>, panics: &[Panic]) -> T {
    result.unwrap_or_else(|_| panic!("I8 violated: the run's root task panicked: {panics:?}"))
}

/// I8, under a restart schedule: an instance of a correct engine leaves the
/// run only when the schedule crashes it.
///
/// An instance the schedule aborted did not stop, and one whose task ended
/// without being aborted did, whether it returned or failed. Returns the
/// number of instances the schedule crashed.
pub(crate) fn check_instances_running(instances: &[Instance]) -> usize {
    let stopped: Vec<usize> = instances
        .iter()
        .filter(|instance| instance.exit == Exit::Stopped)
        .map(|instance| instance.engine)
        .collect();
    check_engines_running(&stopped);
    instances
        .iter()
        .filter(|instance| instance.exit == Exit::Crashed)
        .count()
}

/// I1, across restarts: every instance of a correct engine that completed the
/// bootstrap holds the same result for it.
///
/// An engine restarted after it completed reports the ceremony again from its
/// storage, and a restart must not change what it reports. Returns the number
/// of comparisons made.
pub(crate) fn check_reports_agree(bootstrap: &Bootstrap) -> usize {
    let epoch = Epoch::zero();
    let mut comparisons = 0;
    for node in &bootstrap.nodes {
        let Some(((first, _), repeated)) = node.completions.split_first() else {
            continue;
        };
        for (ending, _) in repeated {
            assert!(
                ending == first,
                "I1 violated: engine {} reported different results for the ceremony of epoch \
                 {epoch} across restarts: {first:?} != {ending:?}",
                node.engine,
            );
            comparisons += 1;
        }
    }
    comparisons
}

/// I9: no correct identity blocks another correct identity.
///
/// `blocked` lists every `(blocker, blocked)` pair the network recorded.
/// Returns its length.
pub(crate) fn check_no_correct_blocks(
    blocked: &[(PublicKey, PublicKey)],
    correct: &[PublicKey],
) -> usize {
    for (blocker, target) in blocked {
        assert!(
            !(correct.contains(blocker) && correct.contains(target)),
            "I9 violated: correct identity {blocker} blocked correct identity {target}",
        );
    }
    blocked.len()
}

/// Check a bootstrap run among `committee` and the blocks recorded during it,
/// and report how much was compared.
///
/// I1 compares the first report of every correct engine. After a successful
/// ceremony I2 is checked at every report, against the share the engine held
/// when the report was recorded, at the end, against the share each engine
/// holds, and for every share each engine ever held, a share later
/// overwritten included; I3 is checked over the shares the engines hold. I2
/// leaves each engine one share its output accepts, so I3 over those holds at
/// every report as well. After a failed ceremony no correct engine may ever
/// have held a share (I6). If no correct engine reported, the shares are
/// judged without the outcome, and I6 is not judged (see
/// [`check_unreported_shares`]).
pub(crate) fn check_bootstrap(
    bootstrap: &Bootstrap,
    committee: &[PublicKey],
    blocked: &[(PublicKey, PublicKey)],
) -> Counts {
    let ended = bootstrap.ended();
    let correct: Vec<PublicKey> = bootstrap
        .nodes
        .iter()
        .map(|node| node.identity.clone())
        .collect();
    let mut counts = Counts {
        correct_nodes: bootstrap.nodes.len(),
        completed: ended
            .nodes
            .iter()
            .filter(|node| node.ending.is_some())
            .count(),
        blocks: check_no_correct_blocks(blocked, &correct),
        ..Counts::default()
    };
    let (agreed, agreements) = check_output_agreement(&ended);
    counts.agreements = agreements;
    match agreed {
        Some(Ending::Success(info)) => {
            counts.successes = 1;
            check_bootstrap_output(&ended, info, committee);
            check_share_validity(&bootstrap.reported(), info);
            check_share_validity(&ended, info);
            counts.shares = check_share_validity(&bootstrap.held(), info);
            counts.reconstructions = check_reconstruction(&ended, info);
        }
        Some(Ending::Failure) => check_failed_bootstrap(&bootstrap.held()),
        None => {
            (counts.shares, counts.reconstructions) = check_unreported_shares(bootstrap, committee);
        }
    }
    counts
}

/// The kind of reshare payload a finalized block carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Carried {
    /// No payload.
    Nothing,
    /// A signed dealer log.
    DealerLog,
    /// An epoch description.
    EpochInfo,
}

impl fmt::Display for Carried {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Nothing => "no payload",
            Self::DealerLog => "a dealer log",
            Self::EpochInfo => "an epoch description",
        })
    }
}

/// What one engine reports of a reshare run, recorded as it happens: what
/// every finalized block its marshal delivers carries, the epoch descriptions
/// among them, and the scheme material its reshare actor registers.
#[derive(Clone, Default)]
pub(crate) struct Records(Arc<Mutex<Recorded>>);

#[derive(Default)]
struct Recorded {
    placed: BTreeSet<(Height, Carried)>,
    delivered: Vec<(Epoch, Info)>,
    registered: Vec<(Epoch, Registration)>,
    watchers: Vec<mpsc::UnboundedSender<Epoch>>,
    finalized: BTreeSet<(Round, Height, Digest)>,
    committed: BTreeSet<(Height, Digest)>,
    endorsed: BTreeSet<(Height, Digest)>,
    commit_watchers: Vec<mpsc::UnboundedSender<Height>>,
    /// Each step with the number of schemes the engine had registered when
    /// the step was recorded.
    steps: Vec<(Step, usize)>,
}

impl Records {
    /// Record the kind of `payload`, which the finalized block at `height`
    /// carried when marshal delivered it to the engine.
    pub(crate) fn placed(
        &self,
        height: Height,
        payload: Option<&Payload<MockGroup, PublicKey, Directory>>,
    ) {
        let carried = match payload {
            None => Carried::Nothing,
            Some(Payload::DealerLog(_)) => Carried::DealerLog,
            Some(Payload::EpochInfo(_)) => Carried::EpochInfo,
        };
        self.0.lock().placed.insert((height, carried));
    }

    /// Record the description of `epoch` that marshal delivered to the
    /// engine, in the final block of the epoch before it.
    pub(crate) fn delivered(&self, epoch: Epoch, info: Info) {
        let delivery = (epoch, info);
        let mut recorded = self.0.lock();
        if !recorded.delivered.contains(&delivery) {
            recorded.delivered.push(delivery);
        }
    }

    /// Record the scheme material the engine registered for `epoch`.
    pub(crate) fn registered(&self, epoch: Epoch, registration: Registration) {
        let mut recorded = self.0.lock();
        recorded.registered.push((epoch, registration));
        recorded
            .watchers
            .retain(|watcher| watcher.send(epoch).is_ok());
    }

    /// The epochs the engine registers a scheme for from now on, each as it
    /// is registered.
    pub(crate) fn watch(&self) -> mpsc::UnboundedReceiver<Epoch> {
        let (watcher, registered) = mpsc::unbounded_channel();
        self.0.lock().watchers.push(watcher);
        registered
    }

    /// What every finalized block delivered so far carries, in height order.
    /// A block delivered again is listed once.
    pub(crate) fn placements(&self) -> Vec<(Height, Carried)> {
        self.0.lock().placed.iter().copied().collect()
    }

    /// Every distinct epoch description delivered so far, in order.
    pub(crate) fn deliveries(&self) -> Vec<(Epoch, Info)> {
        self.0.lock().delivered.clone()
    }

    /// Every registration so far, in order.
    pub(crate) fn registrations(&self) -> Vec<(Epoch, Registration)> {
        self.0.lock().registered.clone()
    }

    /// Record a finalized tip the engine's marshal reported: the round of the
    /// finalization, and the height and digest of the block it finalizes.
    pub(crate) fn finalized(&self, round: Round, height: Height, digest: Digest) {
        self.0.lock().finalized.insert((round, height, digest));
    }

    /// Record the height and digest of a finalized block marshal delivered to
    /// the engine.
    pub(crate) fn committed(&self, height: Height, digest: Digest) {
        let mut recorded = self.0.lock();
        recorded.committed.insert((height, digest));
        recorded
            .commit_watchers
            .retain(|watcher| watcher.send(height).is_ok());
    }

    /// Record the height and digest of a block the engine's application
    /// built, or verified and accepted, for consensus.
    pub(crate) fn endorsed(&self, height: Height, digest: Digest) {
        self.0.lock().endorsed.insert((height, digest));
    }

    /// The height of every finalized block marshal delivers to the engine
    /// from now on, each as it is delivered.
    pub(crate) fn watch_commits(&self) -> mpsc::UnboundedReceiver<Height> {
        let (watcher, committed) = mpsc::unbounded_channel();
        self.0.lock().commit_watchers.push(watcher);
        committed
    }

    /// Record a step of the engine's entry through state sync.
    pub(crate) fn stepped(&self, step: Step) {
        let mut recorded = self.0.lock();
        let registered = recorded.registered.len();
        recorded.steps.push((step, registered));
    }

    /// Every finalized tip reported so far.
    pub(crate) fn finalizations(&self) -> Vec<(Round, Height, Digest)> {
        self.0.lock().finalized.iter().copied().collect()
    }

    /// The height and digest of every block delivered so far, in height
    /// order. A block delivered again is listed once.
    pub(crate) fn commits(&self) -> Vec<(Height, Digest)> {
        self.0.lock().committed.iter().copied().collect()
    }

    /// The height and digest of every block the engine's application built
    /// or accepted so far, in height order.
    pub(crate) fn endorsements(&self) -> Vec<(Height, Digest)> {
        self.0.lock().endorsed.iter().copied().collect()
    }

    /// Every step of the engine's entry through state sync so far, in order.
    pub(crate) fn steps(&self) -> Vec<Step> {
        let recorded = self.0.lock();
        recorded
            .steps
            .iter()
            .map(|(step, _)| step.clone())
            .collect()
    }

    /// The epochs the engine entered through state sync and registered a
    /// scheme for without having played the ceremony that leads into them.
    ///
    /// The DKG module registers the epoch of the floor it starts from before
    /// it has applied a block. When the floor lies after the midpoint of its
    /// epoch, the module follows the rest of that epoch without taking part
    /// in its ceremony and registers the next epoch from the final block. The
    /// floor's height is the height at which marshal delivered its block to
    /// the engine, which it does before the engine can apply that final
    /// block.
    ///
    /// An entry excuses neither epoch if the engine had registered its
    /// scheme before the entry. An engine syncs a second time when a crash
    /// finds the completion of its sync not on its caller's record, and it
    /// may have run on until then: a scheme it registered before the second
    /// entry, for an epoch no earlier entry excuses, is one it registered at
    /// the end of a ceremony it played, with the share that ceremony gave
    /// it. A later floor in that epoch takes nothing of that away.
    pub(crate) fn unplayed(&self) -> Vec<Epoch> {
        let recorded = self.0.lock();
        let epocher = FixedEpocher::new(EPOCH_LENGTH);
        let mut unplayed = BTreeSet::new();
        for (step, registered) in &recorded.steps {
            let Step::Entered(material) = step else {
                continue;
            };
            let epoch = material.info.epoch;
            let followed = recorded.committed.iter().any(|(height, digest)| {
                *digest == material.digest
                    && epocher
                        .containing(*height)
                        .is_some_and(|bounds| bounds.phase() == EpochPhase::Late)
            });
            let before = &recorded.registered[..*registered];
            for entered in [Some(epoch), followed.then(|| epoch.next())] {
                let Some(entered) = entered else {
                    continue;
                };
                if before.iter().all(|(epoch, _)| *epoch != entered) {
                    unplayed.insert(entered);
                }
            }
        }
        unplayed.into_iter().collect()
    }
}

/// What one correct engine observed of a reshare run.
#[derive(Clone, Debug)]
pub(crate) struct Resharer {
    /// The engine, for failure messages.
    pub(crate) engine: usize,
    /// The identity the engine runs as.
    pub(crate) identity: PublicKey,
    /// The height of every finalized block that marshal delivered to the
    /// engine, with the kind of payload the block carried.
    pub(crate) placed: Vec<(Height, Carried)>,
    /// The description of each epoch that marshal delivered to the engine, in
    /// the final block of the epoch before it.
    pub(crate) delivered: Vec<(Epoch, Info)>,
    /// The scheme material the engine registered, with the epoch it was
    /// registered for. The engine registers an epoch's scheme once it has
    /// processed the block that introduces the epoch, so a registration marks
    /// the ceremony before it as complete at this engine.
    pub(crate) registered: Vec<(Epoch, Registration)>,
    /// Every distinct share the engine's secret store held, with the epoch it
    /// was stored for.
    pub(crate) shares: Vec<(Epoch, Share)>,
    /// The epochs the engine entered through state sync without having played
    /// the ceremony that leads into them (see [`Records::unplayed`]). An
    /// engine that starts at the height-zero block has none.
    pub(crate) unplayed: Vec<Epoch>,
}

impl Resharer {
    /// The record of the engine `engine` running as `identity`, from what it
    /// reported and what its secret store held.
    pub(crate) fn observed(
        engine: usize,
        identity: PublicKey,
        records: &Records,
        shares: Vec<(Epoch, Share)>,
    ) -> Self {
        Self {
            engine,
            identity,
            placed: records.placements(),
            delivered: records.deliveries(),
            registered: records.registrations(),
            shares,
            unplayed: records.unplayed(),
        }
    }
}

/// A reshare run as the correct engines observed it.
#[derive(Clone, Debug)]
pub(crate) struct Reshare {
    /// The description of epoch zero, which every engine is started with.
    pub(crate) genesis: Info,
    /// The configured player set of every epoch's ceremony.
    pub(crate) schedule: Schedule,
    /// The correct engines.
    pub(crate) nodes: Vec<Resharer>,
}

impl Reshare {
    /// The correct engines' shares of the output of `epoch` as one ceremony
    /// record: every share each engine held, or only the one it stored last.
    ///
    /// No ending is recorded: which engines must hold a share is judged by
    /// [`check_players_hold_shares`].
    fn holders(&self, epoch: Epoch, every: bool) -> Ceremony {
        let mut nodes = Vec::new();
        for node in &self.nodes {
            let held: Vec<&Share> = node
                .shares
                .iter()
                .filter(|(stored, _)| *stored == epoch)
                .map(|(_, share)| share)
                .collect();
            let first = if every {
                0
            } else {
                held.len().saturating_sub(1)
            };
            nodes.extend(held[first..].iter().map(|share| Observed {
                engine: node.engine,
                identity: node.identity.clone(),
                ending: None,
                share: Some((*share).clone()),
            }));
        }
        Ceremony { epoch, nodes }
    }
}

/// How much each check of a reshare run compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReshareCounts {
    /// Correct engines observed.
    pub correct_nodes: usize,
    /// Epochs past the first that a correct engine holds a description of.
    pub epochs: usize,
    /// Epoch descriptions delivered, summed over the correct engines.
    pub boundaries: usize,
    /// Ceremonies the correct engines agree succeeded.
    pub successes: usize,
    /// Ceremonies the correct engines agree failed.
    pub failures: usize,
    /// Cross-engine comparisons of an epoch's description made under I1.
    pub agreements: usize,
    /// Registered schemes checked against the agreed sharing under I2.
    pub registrations: usize,
    /// Shares checked against the agreed output under I2.
    pub shares: usize,
    /// Correct engines that completed a successful ceremony as a player of
    /// its output, each of which was required to hold a share of it under I2.
    pub players: usize,
    /// Share subsets that reconstructed the key under I3.
    pub reconstructions: usize,
    /// Epoch boundaries checked under I4.
    pub continuities: usize,
    /// Share sets mixing two outputs that were checked under I5.
    pub isolations: usize,
    /// Shares checked against a carried-forward output under I6.
    pub carried: usize,
    /// Correct engines that reached an epoch as a player of the output a
    /// failed ceremony carried into it, each of which was required under I2
    /// to hold, under that epoch, the share it held of the output before.
    pub kept: usize,
    /// Blocks the network recorded, by any identity.
    pub blocks: usize,
    /// Finalized blocks whose payload placement was checked under I18, summed
    /// over the correct engines.
    pub placements: usize,
    /// Of those blocks, the ones that carry a dealer log.
    pub dealer_logs: usize,
    /// Of those blocks, the ones that carry an epoch description.
    pub epoch_infos: usize,
    /// Panics tolerated because they stop a half of the compromised identity.
    pub tolerated_panics: usize,
}

/// I1, for a reshare: any two correct engines that completed the same
/// ceremony hold an identical description of the epoch it leads into.
///
/// Returns the description the engines agree on for every epoch any of them
/// holds one for, with epoch zero's from the run's configuration, and the
/// number of comparisons made.
pub(crate) fn check_epoch_agreement(reshare: &Reshare) -> (BTreeMap<Epoch, Info>, usize) {
    let mut agreed: BTreeMap<Epoch, (Option<usize>, &Info)> = BTreeMap::new();
    agreed.insert(Epoch::zero(), (None, &reshare.genesis));
    let mut comparisons = 0;
    for node in &reshare.nodes {
        for (epoch, info) in &node.delivered {
            let Some((first, held)) = agreed.get(epoch) else {
                agreed.insert(*epoch, (Some(node.engine), info));
                continue;
            };
            let first = first.map_or_else(
                || "the configuration".to_string(),
                |engine| format!("engine {engine}"),
            );
            assert!(
                info == *held,
                "I1 violated: {first} and engine {} disagree on the description of epoch \
                 {epoch}: {held:?} != {info:?}",
                node.engine,
            );
            comparisons += 1;
        }
    }
    let agreed = agreed
        .into_iter()
        .map(|(epoch, (_, info))| (epoch, info.clone()))
        .collect();
    (agreed, comparisons)
}

/// I2, for the scheme a correct engine registers for an epoch: it carries the
/// epoch's agreed public sharing among the agreed output's players, a sharing
/// among those players that needs their quorum, and it names the engine's
/// role in that output. A verifier is outside the players, a member is one of
/// them under the engine's own key, and a share registered with it is the
/// engine's valid share of that output.
///
/// The DKG module builds every registration from the node's own key and the
/// share it holds, as a signer if it holds one, as a member if it is one of
/// the players, and as a verifier otherwise. What passes this check is what
/// the harness's registrar builds a scheme from.
pub(crate) fn check_registration(
    node: &Resharer,
    epoch: Epoch,
    registration: &Registration,
    info: &Info,
) {
    let (SchemeInfo::Verifier {
        participants,
        sharing,
    }
    | SchemeInfo::Member {
        participants,
        sharing,
        ..
    }
    | SchemeInfo::Signer {
        participants,
        sharing,
        ..
    }) = registration;
    assert!(
        participants == info.output.players() && sharing == info.output.public(),
        "I2 violated: engine {} registered a scheme for epoch {epoch} that does not carry the \
         agreed public sharing: {registration:?}",
        node.engine,
    );
    let quorum = info.output.quorum::<N3f1>();
    assert!(
        sharing.total().get() as usize == participants.len() && sharing.required() == quorum,
        "I2 violated: engine {} registered a scheme for epoch {epoch} whose sharing is among {} \
         participants and needs {} shares, but it names {} players with a quorum of {quorum}",
        node.engine,
        sharing.total(),
        sharing.required(),
        participants.len(),
    );
    let player = participants.position(&node.identity).is_some();
    match registration {
        SchemeInfo::Verifier { .. } => assert!(
            !player,
            "I2 violated: engine {} registered the scheme of epoch {epoch} as a verifier, but \
             it is one of the players of the agreed output",
            node.engine,
        ),
        SchemeInfo::Member { public_key, .. } => assert!(
            player && *public_key == node.identity,
            "I2 violated: engine {} registered the scheme of epoch {epoch} as the member {}, \
             which is not the engine's own place among the players",
            node.engine,
            public_key,
        ),
        SchemeInfo::Signer { share, .. } => {
            let registered = Ceremony {
                epoch,
                nodes: vec![Observed {
                    engine: node.engine,
                    identity: node.identity.clone(),
                    ending: None,
                    share: Some(share.clone()),
                }],
            };
            check_share_validity(&registered, info);
        }
    }
}

/// I4: the description of `epoch` continues the description of the epoch
/// before it. It names `epoch`, its players are the next players announced
/// before, and its next players are the configured ones. If the ceremony
/// succeeded, the new output is among the previous players and keeps the
/// group public key.
pub(crate) fn check_continuity(schedule: &Schedule, epoch: Epoch, previous: &Info, info: &Info) {
    assert!(
        info.epoch == epoch,
        "I4 violated: the boundary into epoch {epoch} carries the description of epoch {}",
        info.epoch,
    );
    assert!(
        info.players == previous.next_players,
        "I4 violated: the players of epoch {epoch} are {:?}, but the next players announced \
         before it are {:?}",
        info.players,
        previous.next_players,
    );
    let scheduled = schedule.players(epoch.next());
    assert!(
        info.next_players == scheduled,
        "I4 violated: the next players of epoch {epoch} are {:?}, but the schedule names {:?}",
        info.next_players,
        scheduled,
    );
    if info.outcome != EpochOutcome::Success {
        return;
    }
    assert!(
        info.output.players() == &previous.players,
        "I4 violated: the output reshared into epoch {epoch} is among {:?}, but the players of \
         its ceremony were {:?}",
        info.output.players(),
        previous.players,
    );
    assert!(
        info.output.public().public() == previous.output.public().public(),
        "I4 violated: the reshare into epoch {epoch} changed the group public key from {:?} to \
         {:?}",
        previous.output.public().public(),
        info.output.public().public(),
    );
}

/// I5: after the successful reshare into `epoch`, no set of exactly
/// `required()` shares that mixes shares of the previous output with shares
/// of the new one recovers a signature that verifies under the group public
/// key, whichever of the two sharings interpolates it.
///
/// `old` and `new` hold the correct engines' shares of the previous and of
/// the new output. Returns the number of mixed sets checked.
pub(crate) fn check_isolation(
    epoch: Epoch,
    previous: &Info,
    info: &Info,
    old: &Ceremony,
    new: &Ceremony,
) -> usize {
    let partials = |ceremony: &Ceremony| -> Vec<_> {
        ceremony
            .nodes
            .iter()
            .filter_map(|node| {
                let share = node.share.as_ref()?;
                Some((
                    node.engine,
                    threshold::sign_message::<MockGroup>(
                        share,
                        RECONSTRUCTION_NAMESPACE,
                        RECONSTRUCTION_MESSAGE,
                    ),
                ))
            })
            .collect()
    };
    let (old, new) = (partials(old), partials(new));
    let required = info.output.public().required() as usize;

    let mut mixed = 0;
    for from_old in 1..required {
        for old_subset in subsets(old.len(), from_old) {
            for new_subset in subsets(new.len(), required - from_old) {
                let chosen: Vec<_> = old_subset
                    .iter()
                    .map(|member| &old[*member].1)
                    .chain(new_subset.iter().map(|member| &new[*member].1))
                    .collect();
                for sharing in [previous.output.public(), info.output.public()] {
                    let verified = threshold::recover::<MockGroup, _>(
                        sharing,
                        chosen.iter().copied(),
                        &Sequential,
                    )
                    .ok()
                    .is_some_and(|signature| {
                        ops::verify_message::<MockGroup>(
                            info.output.public().public(),
                            RECONSTRUCTION_NAMESPACE,
                            RECONSTRUCTION_MESSAGE,
                            &signature,
                        )
                        .is_ok()
                    });
                    assert!(
                        !verified,
                        "I5 violated: the shares engines {:?} held before the reshare into \
                         epoch {epoch}, mixed with the shares engines {:?} hold after it, \
                         reconstruct the key",
                        old_subset
                            .iter()
                            .map(|member| old[*member].0)
                            .collect::<Vec<_>>(),
                        new_subset
                            .iter()
                            .map(|member| new[*member].0)
                            .collect::<Vec<_>>(),
                    );
                }
                mixed += 1;
            }
        }
    }
    mixed
}

/// I6, for a reshare: the failed ceremony that leads into `epoch` carries the
/// previous output forward unchanged, and every share a correct engine held
/// of the previous output is valid under the output carried forward.
///
/// `old` holds the correct engines' shares of the previous output. Returns
/// the number of shares checked.
pub(crate) fn check_failed_reshare(
    epoch: Epoch,
    previous: &Info,
    info: &Info,
    old: &Ceremony,
) -> usize {
    let mut checked = 0;
    for node in &old.nodes {
        let Some(share) = &node.share else {
            continue;
        };
        let index = info
            .output
            .players()
            .position(&node.identity)
            .map(Participant::from_usize);
        let valid = index == Some(share.index)
            && info.output.public().partial_public(share.index).ok()
                == Some(share.public::<MockGroup>());
        assert!(
            valid,
            "I6 violated: the share engine {} held before the failed ceremony is not valid \
             under the output carried into epoch {epoch}",
            node.engine,
        );
        checked += 1;
    }
    assert!(
        info.output == previous.output,
        "I6 violated: the failed ceremony did not carry the previous output into epoch {epoch} \
         unchanged: {:?} != {:?}",
        previous.output,
        info.output,
    );
    checked
}

/// I2, for a reshare: a correct engine that completed a successful ceremony as
/// a player of its output holds a share of it.
///
/// An engine has completed the ceremony into `epoch` once it registered the
/// scheme of that epoch, which the DKG module does only after it stored the
/// share. An engine that has not is not judged, and neither is an engine that
/// entered `epoch` through state sync without having played the ceremony
/// (I17). Returns the number of engines required to hold a share.
pub(crate) fn check_players_hold_shares(reshare: &Reshare, epoch: Epoch, info: &Info) -> usize {
    let mut players = 0;
    for node in &reshare.nodes {
        let completed = node
            .registered
            .iter()
            .any(|(registered, _)| *registered == epoch);
        if !completed
            || node.unplayed.contains(&epoch)
            || info.output.players().position(&node.identity).is_none()
        {
            continue;
        }
        assert!(
            node.shares.iter().any(|(stored, _)| *stored == epoch),
            "I2 violated: engine {} completed the successful reshare into epoch {epoch} as a \
             player of its output and holds no share of it",
            node.engine,
        );
        players += 1;
    }
    players
}

/// I2, for a failed reshare: a correct engine that reached `epoch` as a
/// player of the output the failed ceremony carried into it holds, under
/// `epoch`, the share it held of that output under the epoch before.
///
/// An engine has reached `epoch` once it registered the scheme of that epoch.
/// The DKG module stores the carried share under `epoch` before it registers
/// the epoch: when it applies the final block of the epoch before, from the
/// share it holds under that epoch, and at a start that finds it in `epoch`,
/// from the share it holds under `epoch` or under the newest earlier epoch
/// that has one. An engine that has not registered `epoch` is not judged, so
/// a crash between deriving the failure and storing the share, or between
/// storing the share and registering, leaves nothing to judge. Neither is an
/// engine that entered `epoch` through state sync without having played the
/// ceremony (I17), which registers the epoch from the state-sync material
/// before it stores anything under it, nor an engine that held no share
/// under the epoch before. Returns the number of engines required to hold
/// the carried share.
pub(crate) fn check_carried_shares_held(reshare: &Reshare, epoch: Epoch, info: &Info) -> usize {
    let Some(before) = epoch.previous() else {
        return 0;
    };
    let mut holders = 0;
    for node in &reshare.nodes {
        let reached = node
            .registered
            .iter()
            .any(|(registered, _)| *registered == epoch);
        if !reached
            || node.unplayed.contains(&epoch)
            || info.output.players().position(&node.identity).is_none()
        {
            continue;
        }
        let mut carried = node
            .shares
            .iter()
            .filter(|(stored, _)| *stored == before)
            .map(|(_, share)| share)
            .peekable();
        if carried.peek().is_none() {
            continue;
        }
        for share in carried {
            assert!(
                node.shares
                    .iter()
                    .any(|(stored, held)| *stored == epoch && held == share),
                "I2 violated: engine {} reached epoch {epoch} through a failed reshare as a \
                 player of the output carried into it and does not hold, under that epoch, the \
                 share it held of that output",
                node.engine,
            );
        }
        holders += 1;
    }
    holders
}

/// How many finalized blocks I18 examined, summed over the correct engines,
/// and what they carried.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Placed {
    /// Blocks examined.
    pub(crate) blocks: usize,
    /// Of those, the blocks that carry a dealer log.
    pub(crate) dealer_logs: usize,
    /// Of those, the blocks that carry an epoch description.
    pub(crate) epoch_infos: usize,
}

/// I18: every finalized block that marshal delivered to a correct engine
/// carries its reshare payload where the epoch schedule of `epocher` allows
/// it. A block before the midpoint of its epoch carries no payload, a block
/// from the midpoint up to the final block carries no payload or a dealer
/// log, and the final block of an epoch carries an epoch description.
///
/// A block is judged by its height and the kind of its payload alone, as a
/// correct node judges it when it verifies the block. The height-zero block
/// is not judged: it is the block every engine is configured with, and it
/// carries the description of epoch zero. Nothing requires a dealer log to
/// appear, and neither the dealer that signed a log nor the number of logs a
/// dealer has on the chain is judged.
///
/// Returns what was examined.
pub(crate) fn check_placement(epocher: &FixedEpocher, reshare: &Reshare) -> Placed {
    let mut placed = Placed::default();
    for node in &reshare.nodes {
        for (height, carried) in &node.placed {
            if *height == Height::zero() {
                continue;
            }
            let bounds = epocher.containing(*height);
            let last = bounds.is_some_and(|bounds| bounds.last() == *height);
            let inclusion = bounds.is_some_and(|bounds| {
                matches!(bounds.phase(), EpochPhase::Midpoint | EpochPhase::Late)
            });
            let in_place = match carried {
                Carried::Nothing => !last,
                Carried::DealerLog => inclusion && !last,
                Carried::EpochInfo => last,
            };
            let position = match bounds {
                None => "outside every epoch".to_string(),
                Some(bounds) if last => format!("the final block of epoch {}", bounds.epoch()),
                Some(bounds) if inclusion => format!(
                    "between the midpoint and the final block of epoch {}",
                    bounds.epoch(),
                ),
                Some(bounds) => format!("before the midpoint of epoch {}", bounds.epoch()),
            };
            assert!(
                in_place,
                "I18 violated: engine {} was delivered a finalized block at height {height}, \
                 {position}, that carries {carried}",
                node.engine,
            );
            placed.blocks += 1;
            placed.dealer_logs += usize::from(*carried == Carried::DealerLog);
            placed.epoch_infos += usize::from(*carried == Carried::EpochInfo);
        }
    }
    placed
}

/// I2: every time a correct engine registers the scheme of an epoch it holds a
/// share for, it registers that share.
///
/// An engine registers the scheme of an epoch when it completes the ceremony
/// that leads into the epoch, and again at every start that finds it in the
/// epoch, each time from the share its secret store then holds. The DKG
/// module stores a share before it registers with it, and a restart retains
/// the secret store, so an engine whose store ever held a share for an epoch
/// registers that epoch as a signer with that share, every time.
/// [`check_registration`] accepts a member's registration from a player that
/// holds a share, and [`check_players_hold_shares`] judges an engine by every
/// share its store ever held, so it passes an engine whose restart did not
/// find its share again. Returns the number of registrations checked.
pub(crate) fn check_registered_shares(reshare: &Reshare) -> usize {
    let mut checked = 0;
    for node in &reshare.nodes {
        for (epoch, registration) in &node.registered {
            let mut held = node
                .shares
                .iter()
                .filter(|(stored, _)| stored == epoch)
                .map(|(_, share)| share)
                .peekable();
            if held.peek().is_none() {
                continue;
            }
            let registered = match registration {
                SchemeInfo::Signer { share, .. } => Some(share),
                SchemeInfo::Member { .. } | SchemeInfo::Verifier { .. } => None,
            };
            assert!(
                registered.is_some_and(|share| held.any(|held| held == share)),
                "I2 violated: engine {} registered the scheme of epoch {epoch} without the share \
                 it holds for it: {registration:?}",
                node.engine,
            );
            checked += 1;
        }
    }
    checked
}

/// Check a reshare run and the blocks recorded during it, and report how much
/// was compared.
///
/// Every epoch boundary a correct engine processed is checked, in epoch
/// order: I1 across the engines, I4 against the epoch before, I5 or I6 by the
/// ceremony's outcome, and I2 and I3 for the output the epoch runs with. I2
/// requires a share of the players that reached the epoch: the new one after
/// a successful ceremony, the carried one after a failed ceremony.
/// Every finalized block a correct engine was delivered is then checked
/// under I18.
pub(crate) fn check_reshare(
    reshare: &Reshare,
    blocked: &[(PublicKey, PublicKey)],
) -> ReshareCounts {
    let correct: Vec<PublicKey> = reshare
        .nodes
        .iter()
        .map(|node| node.identity.clone())
        .collect();
    let (agreed, agreements) = check_epoch_agreement(reshare);
    let mut counts = ReshareCounts {
        correct_nodes: reshare.nodes.len(),
        epochs: agreed.len() - 1,
        boundaries: reshare.nodes.iter().map(|node| node.delivered.len()).sum(),
        agreements,
        blocks: check_no_correct_blocks(blocked, &correct),
        ..ReshareCounts::default()
    };

    for (epoch, info) in &agreed {
        let before = epoch
            .previous()
            .and_then(|before| Some((before, agreed.get(&before)?)));
        if let Some((before, previous)) = before {
            check_continuity(&reshare.schedule, *epoch, previous, info);
            counts.continuities += 1;
            let old = reshare.holders(before, true);
            match info.outcome {
                EpochOutcome::Success => {
                    counts.successes += 1;
                    counts.isolations += check_isolation(
                        *epoch,
                        previous,
                        info,
                        &old,
                        &reshare.holders(*epoch, true),
                    );
                    counts.players += check_players_hold_shares(reshare, *epoch, info);
                }
                EpochOutcome::Failure => {
                    counts.failures += 1;
                    counts.carried += check_failed_reshare(*epoch, previous, info, &old);
                    counts.kept += check_carried_shares_held(reshare, *epoch, info);
                }
            }
        }
        counts.shares += check_share_validity(&reshare.holders(*epoch, true), info);
        counts.reconstructions += check_reconstruction(&reshare.holders(*epoch, false), info);
    }

    // An engine stores a share and registers a scheme for an epoch only after
    // marshal delivered the block that introduces the epoch, so each belongs
    // to an epoch the engines hold a description of.
    for node in &reshare.nodes {
        for (epoch, _) in &node.shares {
            assert!(
                agreed.contains_key(epoch),
                "I2 violated: engine {} holds a share for epoch {epoch}, which no correct \
                 engine holds a description of",
                node.engine,
            );
        }
        for (epoch, registration) in &node.registered {
            let Some(info) = agreed.get(epoch) else {
                panic!(
                    "I2 violated: engine {} registered a scheme for epoch {epoch}, which no \
                     correct engine holds a description of",
                    node.engine,
                );
            };
            check_registration(node, *epoch, registration, info);
            counts.registrations += 1;
        }
    }

    // The windows are those of the schedule every engine's reshare actor and
    // application wrapper are configured with.
    let placed = check_placement(&FixedEpocher::new(EPOCH_LENGTH), reshare);
    counts.placements = placed.blocks;
    counts.dealer_logs = placed.dealer_logs;
    counts.epoch_infos = placed.epoch_infos;
    counts
}

/// I10: two runs of one input measure the same thing.
///
/// `first` and `second` are what two runs of the same input measured, which
/// the regression suite of every driver compares when it replays an input.
#[cfg(test)]
pub(crate) fn check_replay<T: PartialEq + fmt::Debug>(first: T, second: T) {
    assert!(
        first == second,
        "I10 violated: two runs of one input measured different things: {first:?} != {second:?}",
    );
}

/// A finalization of a chain the probe target fabricates.
pub(crate) type ProbeFinalization = Finalization<Scheme, Digest>;

/// The artifact a discovering probe emits.
pub(crate) type ProbeArtifact = Artifact<Scheme, Digest, MockGroup, Directory>;

/// Tags of the DKG probe's wire format. Every message starts with a byte
/// below this, as the module documentation of [`commonware_glue::dkg::probe`]
/// lays out, so a message that starts with any other byte, or with none, is
/// malformed whatever the probe is doing.
pub(crate) const PROBE_TAGS: u8 = 6;

/// One chain as the probe target fabricated it, recorded before any probe
/// starts.
#[derive(Clone, Debug)]
pub(crate) struct ProbeChain {
    /// The description of epoch zero, which the chain's genesis carries.
    pub(crate) genesis: Info,
    /// The finalization of every block, from height one.
    pub(crate) finalizations: Vec<ProbeFinalization>,
    /// For every later epoch, the finalization of the final block of the
    /// epoch before it and the description of the epoch that block carries.
    pub(crate) boundaries: BTreeMap<Epoch, (ProbeFinalization, Info)>,
}

impl ProbeChain {
    /// Whether `finalization` certifies a block of this chain.
    fn certifies(&self, finalization: &ProbeFinalization) -> bool {
        self.finalizations.contains(finalization)
    }

    /// Whether `info` describes an epoch of this chain.
    fn describes(&self, info: &Info) -> bool {
        self.genesis == *info || self.boundaries.values().any(|(_, held)| held == info)
    }
}

/// What one source of a probe run holds, recorded before any probe starts.
#[derive(Clone, Debug)]
pub(crate) struct ProbeSource {
    /// The engine, for failure messages.
    pub(crate) engine: usize,
    /// The identity the source runs as.
    pub(crate) identity: PublicKey,
    /// Whether the source holds the foreign chain instead of the fabricated
    /// one.
    pub(crate) foreign: bool,
    /// The finalization of every block the source's marshal holds, in height
    /// order. The last is what the source answers a request for its latest
    /// finalization with.
    pub(crate) finalizations: Vec<ProbeFinalization>,
}

/// A response a source built, which the harness withheld.
#[derive(Clone, Debug)]
pub(crate) struct ProbeCapture {
    /// The source that built it, as a position among the run's sources.
    pub(crate) source: usize,
    /// The message the source had last taken from its receiver: the request
    /// the response answers.
    pub(crate) request: Vec<u8>,
    /// The response as the source encoded it.
    pub(crate) bytes: Vec<u8>,
}

/// What a message the program sent to the discovering probe is, by
/// construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeShape {
    /// The whole of the captured response at this position.
    Response(usize),
    /// A strict prefix, possibly empty, of the captured response at this
    /// position.
    Prefix(usize),
    /// Bytes that start with no tag of the wire format.
    Junk,
    /// The request for latest finalizations the discovering probe sent,
    /// which the harness sends back to it to wake it.
    Request,
}

/// A message the program sent to the discovering probe.
#[derive(Clone, Debug)]
pub(crate) struct ProbeSend {
    /// The identity it was sent as.
    pub(crate) origin: PublicKey,
    /// What it is.
    pub(crate) shape: ProbeShape,
    /// Its bytes.
    pub(crate) bytes: Vec<u8>,
}

/// One thing that happened at the discovering probe's public boundaries.
#[derive(Clone, Debug)]
pub(crate) enum ProbeStep {
    /// The program opened a subscription.
    Subscribed,
    /// The program dropped a subscription that had not resolved.
    Unsubscribed,
    /// The program attached the probe's marshal.
    Attached,
    /// A subscription resolved with this artifact.
    Resolved(Box<ProbeArtifact>),
    /// A subscription closed without an artifact.
    Closed,
    /// The program sent the probe a message.
    Sent(ProbeSend),
    /// The probe sent a request.
    Requested {
        /// Whom the probe addressed.
        recipients: Recipients<PublicKey>,
        /// The request as the probe encoded it.
        bytes: Vec<u8>,
    },
    /// The probe took a message from its receiver.
    Delivered {
        /// The identity that sent it.
        peer: PublicKey,
        /// Its bytes.
        bytes: Vec<u8>,
    },
    /// The probe blocked a peer.
    Blocked {
        /// The peer.
        peer: PublicKey,
    },
}

#[derive(Default)]
struct ProbeLog {
    steps: Vec<ProbeStep>,
    captures: Vec<ProbeCapture>,
    /// The message each source last took from its receiver.
    asked: BTreeMap<usize, Vec<u8>>,
}

/// Where a probe run is recorded as it happens. The program's own actions
/// and what the discovering probe does on the network enter one sequence, the
/// probe's in the order its task did them.
#[derive(Clone, Default)]
pub(crate) struct ProbeLedger(Arc<Mutex<ProbeLog>>);

impl ProbeLedger {
    /// Record `step` after everything recorded so far.
    pub(crate) fn note(&self, step: ProbeStep) {
        self.0.lock().steps.push(step);
    }

    /// Record that the source at position `source` took `bytes` from its
    /// receiver.
    pub(crate) fn asked(&self, source: usize, bytes: &[u8]) {
        self.0.lock().asked.insert(source, bytes.to_vec());
    }

    /// Record the response `bytes` the source at position `source` built, as
    /// the answer to the message it last took.
    pub(crate) fn captured(&self, source: usize, bytes: &[u8]) {
        let mut log = self.0.lock();
        let request = log.asked.get(&source).cloned().unwrap_or_default();
        log.captures.push(ProbeCapture {
            source,
            request,
            bytes: bytes.to_vec(),
        });
    }

    /// The position and bytes of a response the source at position `source`
    /// built: its newest when `back` is zero, and otherwise the one `back`
    /// distinct responses before that, or its oldest if it built fewer.
    pub(crate) fn recent(&self, source: usize, back: usize) -> Option<(usize, Vec<u8>)> {
        let log = self.0.lock();
        let mut distinct: Vec<(usize, &[u8])> = Vec::new();
        for (position, capture) in log.captures.iter().enumerate().rev() {
            if capture.source != source || distinct.iter().any(|(_, bytes)| *bytes == capture.bytes)
            {
                continue;
            }
            distinct.push((position, &capture.bytes));
            if distinct.len() > back {
                break;
            }
        }
        distinct
            .last()
            .map(|(position, bytes)| (*position, bytes.to_vec()))
    }

    /// The request for latest finalizations as the discovering probe encoded
    /// it, once the probe has sent one.
    pub(crate) fn solicitation(&self) -> Option<Vec<u8>> {
        self.0.lock().steps.iter().find_map(|step| match step {
            ProbeStep::Requested { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
    }

    /// Whether the last message the program sent is the whole of a response
    /// to the discovering probe's most recent request, which the probe
    /// addressed to the sender alone, and no subscription was opened or
    /// resolved since.
    ///
    /// The probe addresses a request to one peer only for its boundary block,
    /// and sends another as soon as it gives that peer up. A probe that is
    /// still discovering takes the response as the block it awaits and
    /// resolves its artifact with it or refuses it and asks someone else, so
    /// once the probe has taken the response this holds only if it resolved.
    pub(crate) fn answered_alone(&self) -> bool {
        let log = self.0.lock();
        let Some((at, send)) =
            log.steps
                .iter()
                .enumerate()
                .rev()
                .find_map(|(at, step)| match step {
                    ProbeStep::Sent(send) => Some((at, send)),
                    _ => None,
                })
        else {
            return false;
        };
        if log.steps[at..]
            .iter()
            .any(|step| matches!(step, ProbeStep::Subscribed | ProbeStep::Resolved(_)))
        {
            return false;
        }
        let request = log.steps.iter().rev().find_map(|step| match step {
            ProbeStep::Requested { recipients, bytes } => Some((recipients, bytes)),
            _ => None,
        });
        let Some((Recipients::One(asked), request)) = request else {
            return false;
        };
        matches!(send.shape, ProbeShape::Response(capture)
            if *asked == send.origin && log.captures[capture].request == *request)
    }

    /// Everything recorded at the discovering probe's boundaries, in order.
    pub(crate) fn steps(&self) -> Vec<ProbeStep> {
        self.0.lock().steps.clone()
    }

    /// Every response the sources built, in the order built.
    pub(crate) fn captures(&self) -> Vec<ProbeCapture> {
        self.0.lock().captures.clone()
    }
}

/// A probe run as the harness observed it.
#[derive(Clone, Debug)]
pub(crate) struct ProbeRun {
    /// The identity of the discovering probe, which is engine zero.
    pub(crate) discoverer: PublicKey,
    /// The identity that is tracked and is not a dealer.
    pub(crate) outsider: PublicKey,
    /// The sources. With the discovering probe they are the dealers.
    pub(crate) sources: Vec<ProbeSource>,
    /// The fabricated chain, which the discovering probe verifies.
    pub(crate) chain: ProbeChain,
    /// The foreign chain, signed under another dealt key.
    pub(crate) foreign: ProbeChain,
    /// The epoch of the checkpoint the discovering probe bootstraps from.
    pub(crate) bootstrap: Epoch,
    /// The floor the discovering probe was given as persisted, if any.
    pub(crate) persisted: Option<ProbeFinalization>,
    /// What happened at the discovering probe's boundaries, in order.
    pub(crate) steps: Vec<ProbeStep>,
    /// Every response the sources built.
    pub(crate) captures: Vec<ProbeCapture>,
    /// Every `(blocker, blocked)` pair the network recorded.
    pub(crate) blocked: Vec<(PublicKey, PublicKey)>,
}

/// What a source's response answers, known from the request that drew it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeAnswer {
    /// The source's latest finalization.
    Latest,
    /// The finalization of a boundary block.
    Boundary,
    /// A boundary block.
    Block,
}

impl ProbeRun {
    /// Valid latest replies from distinct dealers a floor needs: one more
    /// than the dealers' fault bound.
    fn required(&self) -> usize {
        N3f1::max_faults(self.sources.len() + 1) as usize + 1
    }

    /// The epoch below which the discovering probe treats a latest
    /// finalization as stale: the later of its checkpoint's epoch and its
    /// persisted floor's.
    fn minimum(&self) -> Epoch {
        self.persisted
            .as_ref()
            .map_or(self.bootstrap, |floor| floor.epoch().max(self.bootstrap))
    }

    /// The request for latest finalizations as the discovering probe encodes
    /// it: discovery begins with it, so it is the first request the probe
    /// sent.
    fn solicitation(&self) -> Option<&[u8]> {
        self.steps.iter().find_map(|step| match step {
            ProbeStep::Requested { bytes, .. } => Some(bytes.as_slice()),
            _ => None,
        })
    }

    /// What `capture` answers. A source answers only the discovering probe,
    /// which asks its dealers for their latest finalization, every peer for
    /// a boundary finalization, and one peer for the block.
    fn answer(&self, capture: &ProbeCapture) -> ProbeAnswer {
        if self.solicitation() == Some(capture.request.as_slice()) {
            return ProbeAnswer::Latest;
        }
        let mut asked = self.steps.iter().filter_map(|step| match step {
            ProbeStep::Requested { recipients, bytes } if *bytes == capture.request => {
                Some(recipients)
            }
            _ => None,
        });
        match asked.next() {
            Some(Recipients::One(_)) => ProbeAnswer::Block,
            Some(_) => ProbeAnswer::Boundary,
            None => panic!(
                "harness defect: engine {} answered a request the discovering probe did not send",
                self.sources[capture.source].engine,
            ),
        }
    }

    /// Whether the source at position `source` answers a request for its
    /// latest finalization with one below the discovering probe's minimum
    /// epoch.
    fn stale(&self, source: usize) -> bool {
        self.sources[source]
            .finalizations
            .last()
            .is_some_and(|latest| latest.epoch() < self.minimum())
    }

    /// The source `send` counts for in a sample: `send` is the whole of a
    /// latest reply, sent by the source that built it, from the fabricated
    /// chain and not stale.
    fn counted(&self, send: &ProbeSend) -> Option<usize> {
        let ProbeShape::Response(capture) = send.shape else {
            return None;
        };
        let capture = &self.captures[capture];
        let source = &self.sources[capture.source];
        (self.answer(capture) == ProbeAnswer::Latest
            && source.identity == send.origin
            && !source.foreign
            && !self.stale(capture.source))
        .then_some(capture.source)
    }

    /// How failure messages name `peer`.
    fn name(&self, peer: &PublicKey) -> String {
        if *peer == self.discoverer {
            return "engine 0".to_string();
        }
        if *peer == self.outsider {
            return "the identity that is not a dealer".to_string();
        }
        self.sources
            .iter()
            .find(|source| source.identity == *peer)
            .map_or_else(
                || format!("unknown identity {peer}"),
                |source| format!("engine {}", source.engine),
            )
    }
}

/// How much each check of a probe run compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProbeCounts {
    /// Requests for latest finalizations the discovering probe sent.
    pub solicitations: usize,
    /// Requests for a boundary finalization or block the discovering probe
    /// sent.
    pub fetches: usize,
    /// Latest finalizations the sources answered with.
    pub latest_replies: usize,
    /// Boundary finalizations the sources answered with.
    pub boundary_replies: usize,
    /// Boundary blocks the sources answered with.
    pub block_replies: usize,
    /// Messages delivered to the discovering probe.
    pub deliveries: usize,
    /// Deliveries I14 required the discovering probe to block the sender of.
    pub refusals: usize,
    /// Deliveries I14 forbade the discovering probe to block the sender of.
    pub admissions: usize,
    /// Deliveries I14 required nothing for, because the probe did not select
    /// its floor or resolve its artifact when a correct probe would have.
    pub unsettled: usize,
    /// Blocks the discovering probe placed, one per delivery it blocked.
    pub blocks: usize,
    /// Peers the network recorded as blocked.
    pub blocked_peers: usize,
    /// Subscriptions that resolved with an artifact.
    pub artifacts: usize,
    /// Floors checked against the delivered samples under I12.
    pub floors: usize,
    /// Artifacts compared with the fabricated chain under I13.
    pub comparisons: usize,
}

/// I12: the floor of the artifact the discovering probe emitted is the
/// highest-round finalization among the valid latest replies of the first
/// `f + 1` distinct dealers to deliver one since the probe last asked for
/// them, each sent by the source that built it.
///
/// The probe selects its floor when the reply of the `f + 1`-th distinct
/// dealer arrives and judges no latest reply after that, so the floor is the
/// highest of exactly those replies: one delivered later, however high, does
/// not change it. Each reply stands for the finalization its source was
/// recorded to hold as its latest. Returns the number of floors checked.
pub(crate) fn check_probe_floor(run: &ProbeRun) -> usize {
    let solicitation = run.solicitation();
    let mut replies: Vec<(usize, &ProbeFinalization)> = Vec::new();
    let mut sent = None;
    let mut artifact = None;
    for step in &run.steps {
        match step {
            ProbeStep::Requested { bytes, .. } if solicitation == Some(bytes.as_slice()) => {
                replies.clear();
            }
            ProbeStep::Sent(send) => sent = Some(send),
            ProbeStep::Delivered { .. } => {
                let Some(source) = sent.take().and_then(|send| run.counted(send)) else {
                    continue;
                };
                if replies.iter().any(|(counted, _)| *counted == source) {
                    continue;
                }
                let latest = run.sources[source]
                    .finalizations
                    .last()
                    .expect("a source that answered holds a finalization");
                replies.push((source, latest));
            }
            ProbeStep::Resolved(resolved) => {
                artifact = Some(resolved);
                break;
            }
            _ => {}
        }
    }
    let Some(artifact) = artifact else {
        return 0;
    };

    // The replies the probe selects from, and those delivered after them.
    let required = run.required();
    let (sample, later) = replies.split_at(required.min(replies.len()));
    let highest = sample
        .iter()
        .map(|(_, latest)| *latest)
        .max_by_key(|latest| latest.round());
    let named = |replies: &[(usize, &ProbeFinalization)]| -> Vec<String> {
        replies
            .iter()
            .map(|(source, latest)| {
                let engine = run.sources[*source].engine;
                format!("engine {engine} at round {}", latest.round())
            })
            .collect()
    };
    assert!(
        sample.len() == required && highest == Some(&artifact.floor),
        "I12 violated: the floor of the artifact, at round {}, is not the highest finalization \
         of the first {required} valid latest replies from distinct dealers that were delivered \
         since engine 0 last asked for them, {:?}; {:?} were delivered after them",
        artifact.floor.round(),
        named(sample),
        named(later),
    );
    1
}

/// I13: the artifact the discovering probe emitted carries the fabricated
/// chain's boundary finalization and epoch description for its floor's epoch,
/// or no finalization and the configured genesis description at epoch zero.
/// Nothing in it comes from the foreign chain, the boundary is one a source
/// of the fabricated chain held, and every subscription resolved with the
/// same artifact.
///
/// Returns the number of artifacts compared with the chain.
pub(crate) fn check_probe_artifact(run: &ProbeRun) -> usize {
    let mut artifacts = run.steps.iter().filter_map(|step| match step {
        ProbeStep::Resolved(artifact) => Some(artifact),
        _ => None,
    });
    let Some(artifact) = artifacts.next() else {
        return 0;
    };
    let epoch = artifact.floor.epoch();
    for other in artifacts {
        assert!(
            other.floor == artifact.floor
                && other.finalization == artifact.finalization
                && other.info == artifact.info,
            "I13 violated: engine 0 emitted a second, different artifact: the first has its \
             floor at round {} and describes epoch {}, the second has its floor at round {} and \
             describes epoch {}",
            artifact.floor.round(),
            artifact.info.epoch,
            other.floor.round(),
            other.info.epoch,
        );
    }

    assert!(
        !run.foreign.certifies(&artifact.floor),
        "I13 violated: the floor of the artifact, at round {}, is a finalization of the foreign \
         chain",
        artifact.floor.round(),
    );
    assert!(
        !artifact
            .finalization
            .as_ref()
            .is_some_and(|finalization| run.foreign.certifies(finalization)),
        "I13 violated: the boundary finalization of the artifact for epoch {epoch} is a \
         finalization of the foreign chain",
    );
    assert!(
        !run.foreign.describes(&artifact.info),
        "I13 violated: the artifact for epoch {epoch} carries an epoch description of the \
         foreign chain",
    );

    if epoch.is_zero() {
        assert!(
            artifact.finalization.is_none(),
            "I13 violated: the artifact for epoch 0 carries a boundary finalization at round {:?}",
            artifact.finalization.as_ref().map(|found| found.round()),
        );
        assert!(
            artifact.info == run.chain.genesis,
            "I13 violated: the artifact for epoch 0 does not carry the configured genesis \
             description: {:?} != {:?}",
            artifact.info,
            run.chain.genesis,
        );
        return 1;
    }
    let Some((finalization, info)) = run.chain.boundaries.get(&epoch) else {
        panic!(
            "I13 violated: the floor of the artifact is in epoch {epoch}, whose boundary the \
             fabricated chain does not hold"
        );
    };
    assert!(
        artifact.finalization.as_ref() == Some(finalization),
        "I13 violated: the artifact for epoch {epoch} does not carry the fabricated chain's \
         boundary finalization, at round {}: it carries the one at round {:?}",
        finalization.round(),
        artifact.finalization.as_ref().map(|found| found.round()),
    );
    assert!(
        artifact.info == *info,
        "I13 violated: the artifact for epoch {epoch} does not carry the epoch description of \
         the fabricated chain's boundary block: {:?} != {info:?}",
        artifact.info,
    );
    assert!(
        run.sources
            .iter()
            .any(|source| !source.foreign && source.finalizations.contains(finalization)),
        "I13 violated: the artifact carries the boundary of epoch {epoch}, which no source of \
         the fabricated chain holds",
    );
    1
}

/// What I14 requires of the discovering probe's blocker for one delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeVerdict {
    /// The sender must be blocked.
    Block,
    /// The sender must not be blocked.
    Pass,
    /// Nothing is required: the probe did not select its floor or resolve
    /// its artifact when a correct probe would have, and a probe that failed
    /// to do so takes the message differently from one that did not. A run
    /// that stalls is healthy, so neither is required.
    Open,
}

/// What the harness knows of the discovering probe's state when the probe
/// takes a message, from the probe's public boundaries alone: what the
/// program did to its mailbox, what the probe sent, and what was delivered to
/// it.
///
/// This is a small model of the probe's state, kept to what those boundaries
/// settle: which loop the probe runs, whether its floor is selected, whether
/// it awaits its boundary, which peer it last addressed, and which peers it
/// holds as responders. It reproduces neither the probe's sample nor its
/// verification. The driver places the boundaries that settle the rest: once
/// the program drops its last subscription it wakes the probe, which then
/// looks at its subscriptions before the next event, and once the responder
/// the block was requested from delivers it with no subscription open it
/// opens one, which shows the artifact.
#[derive(Default)]
struct ProbeKnowledge<'a> {
    /// The program attached the probe's marshal.
    attached: bool,
    /// Subscriptions the program holds open.
    open: usize,
    /// The program dropped its last subscription and the probe has taken no
    /// message since. The next message is the wake the driver sends.
    dropped: bool,
    /// A subscription resolved, so the probe holds its artifact.
    resolved: bool,
    /// The probe certainly serves: its marshal was attached while no
    /// subscription was pending, it was woken with its marshal attached
    /// after the program dropped its last subscription, a subscription
    /// closed without an artifact, or its marshal is attached and its
    /// subscriptions resolved.
    serving: bool,
    /// The probe sent a request other than for latest finalizations, which
    /// it does only once it has selected its floor.
    fetching: bool,
    /// Whom the probe addressed its most recent request to.
    asked: Option<&'a Recipients<PublicKey>>,
    /// Sources whose own valid latest reply was delivered since the probe
    /// last asked for latest finalizations.
    counted: BTreeSet<usize>,
    /// Identities that delivered the whole of a boundary finalization of the
    /// fabricated chain and that the probe still holds as responders: a peer
    /// it holds is retired when the probe asks another peer, or every peer,
    /// for what it asked that peer alone.
    vouched: Vec<&'a PublicKey>,
    /// The whole of a boundary block of the fabricated chain was delivered
    /// by the peer the probe's most recent request was addressed to alone.
    /// The probe takes a block from the responder it requested the block
    /// from and from nobody else, so only such a delivery resolves the
    /// artifact through the boundary.
    fetched: bool,
}

/// Which loop the discovering probe runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbePhase {
    Discovering,
    Serving,
}

impl<'a> ProbeKnowledge<'a> {
    /// Take in a step other than a delivery.
    fn learn(&mut self, solicitation: Option<&[u8]>, step: &'a ProbeStep) {
        match step {
            ProbeStep::Subscribed => self.open += 1,
            ProbeStep::Unsubscribed => {
                self.open = self.open.saturating_sub(1);
                self.dropped = self.open == 0;
            }
            ProbeStep::Attached => {
                self.attached = true;
                self.serving |= self.open == 0;
            }
            ProbeStep::Resolved(_) => {
                self.open = self.open.saturating_sub(1);
                self.resolved = true;
            }
            ProbeStep::Closed => {
                self.open = self.open.saturating_sub(1);
                self.serving |= self.attached;
            }
            ProbeStep::Requested { recipients, bytes } => {
                if solicitation == Some(bytes.as_slice()) {
                    self.counted.clear();
                } else {
                    self.fetching = true;
                    // The probe asks for a boundary finalization or block
                    // only once it awaits a block from nobody: the peer it
                    // last asked alone is no longer its responder, and a
                    // request to every peer shows it holds none at all.
                    match (self.asked, recipients) {
                        (Some(Recipients::One(last)), Recipients::One(next)) if last != next => {
                            self.vouched.retain(|held| *held != last);
                        }
                        (_, Recipients::One(_)) => {}
                        _ => self.vouched.clear(),
                    }
                }
                self.asked = Some(recipients);
            }
            ProbeStep::Sent(_) | ProbeStep::Delivered { .. } | ProbeStep::Blocked { .. } => {}
        }
        self.serving |= self.attached && self.resolved;
    }

    /// Take in the delivery of `send`.
    fn deliver(&mut self, run: &ProbeRun, send: &'a ProbeSend) {
        if self.dropped {
            assert!(
                send.shape == ProbeShape::Request,
                "harness defect: engine 0 was not woken after the program dropped its last \
                 subscription"
            );
            self.dropped = false;
            self.serving |= self.attached;
        }
        if let Some(source) = run.counted(send) {
            self.counted.insert(source);
        }
        let ProbeShape::Response(capture) = send.shape else {
            return;
        };
        let capture = &run.captures[capture];
        if run.sources[capture.source].foreign {
            return;
        }
        match run.answer(capture) {
            ProbeAnswer::Latest => {}
            ProbeAnswer::Boundary => self.vouched.push(&send.origin),
            ProbeAnswer::Block => self.fetched |= self.asked_only(&send.origin),
        }
    }

    const fn phase(&self) -> ProbePhase {
        if self.serving {
            ProbePhase::Serving
        } else {
            ProbePhase::Discovering
        }
    }

    /// The probe has certainly selected its floor.
    const fn selected(&self) -> bool {
        self.fetching || self.resolved
    }

    /// The probe has certainly not selected its floor: it selects once
    /// `required` valid latest replies are recorded, it records none while
    /// it has no subscriber, and fewer were delivered since it last asked.
    ///
    /// A probe with no subscription open has noticed so: the driver wakes it
    /// once the program drops its last one, and the next subscription makes
    /// it ask again, so every reply counted since it last asked reached it
    /// while it had a subscriber.
    fn sampling(&self, required: usize) -> bool {
        !self.selected() && (self.open == 0 || self.counted.len() < required)
    }

    /// The probe certainly waits for its boundary: it asked for one, no
    /// subscription resolved, and the responder it requested the block from
    /// did not deliver the whole of it.
    const fn fetching(&self) -> bool {
        self.fetching && !self.resolved && !self.fetched
    }

    /// The probe addressed its most recent request to `peer` alone. Only a
    /// request for the block is addressed to one peer. The probe sends it
    /// when it starts to await that peer's block, and sends another request,
    /// to its next responder or to everyone, when it gives that peer up, so
    /// while the boundary is awaited `peer` is the responder whose block the
    /// probe awaits.
    fn asked_only(&self, peer: &PublicKey) -> bool {
        matches!(self.asked, Some(Recipients::One(asked)) if asked == peer)
    }
}

/// What I14 requires for the delivery of `send`, given what the harness knows
/// of the discovering probe.
///
/// This is the blocking table of the DKG probe, read off its code. While
/// discovering, the probe decodes every message before anything else and
/// blocks the sender of one that does not decode: one with no tag or an
/// unknown tag, or a finalization response cut short. It ignores a request.
/// A block response is decoded past its epoch only when it comes from the
/// peer the block was requested from, and is ignored from anyone else. A
/// latest reply is judged only until the floor is selected: a sender that is
/// not a dealer is blocked, a stale reply is set aside, and a reply that does
/// not verify blocks its sender. A boundary finalization is judged only while
/// the boundary is awaited and from a sender the probe does not hold as a
/// responder, and one that does not verify blocks its sender. While serving,
/// the probe reads requests only: it blocks the sender of a message with no
/// tag or an unknown tag and ignores every response, whole or cut short. It
/// answers a request from its marshal, which holds nothing in this target.
///
/// A verdict stays open only where a correct probe would have moved on and
/// the run shows no sign that it did, in two cases of a probe that
/// discovers. A latest reply the probe would refuse, once enough valid
/// replies for a floor reached it while it had a subscriber and neither a
/// request for the boundary nor an artifact followed: a probe that selected
/// its floor ignores the reply. A foreign boundary finalization, or a cut
/// block from the responder the block was requested from, once that responder
/// delivered the whole block and no subscription resolved, not even the one
/// the driver opens to show the artifact: a probe that resolved ignores both.
fn probe_verdict(run: &ProbeRun, known: &ProbeKnowledge<'_>, send: &ProbeSend) -> ProbeVerdict {
    let outsider = send.origin == run.outsider;
    let discovering = match send.shape {
        ProbeShape::Junk => ProbeVerdict::Block,
        ProbeShape::Request => ProbeVerdict::Pass,
        // A prefix this short ends inside the tag or right after it.
        ProbeShape::Prefix(_) if send.bytes.len() <= 1 => ProbeVerdict::Block,
        ProbeShape::Prefix(capture) => match run.answer(&run.captures[capture]) {
            ProbeAnswer::Latest | ProbeAnswer::Boundary => ProbeVerdict::Block,
            // The body of a block response is decoded only when the response
            // comes from the responder the block was requested from.
            ProbeAnswer::Block if !known.asked_only(&send.origin) => ProbeVerdict::Pass,
            ProbeAnswer::Block if known.fetching() => ProbeVerdict::Block,
            // The probe holds its artifact and awaits no block.
            ProbeAnswer::Block if known.resolved => ProbeVerdict::Pass,
            ProbeAnswer::Block => ProbeVerdict::Open,
        },
        ProbeShape::Response(capture) => {
            let capture = &run.captures[capture];
            let source = &run.sources[capture.source];
            assert!(
                outsider || source.identity == send.origin,
                "harness defect: {} sent a whole response another source built",
                run.name(&send.origin),
            );
            match run.answer(capture) {
                // A reply the probe refuses for as long as it samples.
                ProbeAnswer::Latest
                    if outsider || (source.foreign && !run.stale(capture.source)) =>
                {
                    if known.sampling(run.required()) {
                        ProbeVerdict::Block
                    } else if known.selected() {
                        ProbeVerdict::Pass
                    } else {
                        ProbeVerdict::Open
                    }
                }
                ProbeAnswer::Latest => ProbeVerdict::Pass,
                ProbeAnswer::Boundary if !source.foreign => ProbeVerdict::Pass,
                // A responder the probe holds is ignored before its boundary
                // finalization is verified.
                ProbeAnswer::Boundary if known.fetching() => {
                    if known.vouched.contains(&&send.origin) {
                        ProbeVerdict::Pass
                    } else {
                        ProbeVerdict::Block
                    }
                }
                ProbeAnswer::Boundary if known.resolved => ProbeVerdict::Pass,
                ProbeAnswer::Boundary => ProbeVerdict::Open,
                ProbeAnswer::Block => {
                    // A source builds a block only when the probe requests
                    // one from it, which the probe does only of a peer whose
                    // boundary finalization verified. A source of the foreign
                    // chain sends no such finalization, so the table has no
                    // row for a foreign block.
                    assert!(
                        !source.foreign,
                        "harness defect: engine {} holds the foreign chain and built a boundary \
                         block, which engine 0 can have requested of no such source",
                        source.engine,
                    );
                    ProbeVerdict::Pass
                }
            }
        }
    };

    match known.phase() {
        ProbePhase::Discovering => discovering,
        // While serving, only a message with no tag or an unknown tag blocks.
        ProbePhase::Serving => match send.shape {
            ProbeShape::Junk => ProbeVerdict::Block,
            ProbeShape::Prefix(_) if send.bytes.is_empty() => ProbeVerdict::Block,
            ProbeShape::Prefix(_) | ProbeShape::Response(_) | ProbeShape::Request => {
                ProbeVerdict::Pass
            }
        },
    }
}

/// I14: the discovering probe blocks the sender of a damaged response, of a
/// latest reply replayed by the identity that is not a dealer, and of a
/// response that does not verify, in the states where it decodes and judges
/// that message, and blocks nobody else. The blocks the network recorded are
/// exactly the ones the probe placed.
///
/// Every delivery is judged on its own, by [`probe_verdict`], against the
/// blocks the probe placed while it processed that delivery. Returns the
/// number of deliveries that had to be blocked, that had to pass, and for
/// which nothing was required, and the number of blocks the probe placed.
pub(crate) fn check_probe_blocks(run: &ProbeRun) -> (usize, usize, usize, usize) {
    // The delivery the probe is processing: its position among the deliveries,
    // what it is, what I14 requires for it, and whether the probe blocked its
    // sender.
    struct Judged<'a> {
        position: usize,
        send: &'a ProbeSend,
        verdict: ProbeVerdict,
        blocked: bool,
    }
    let settle = |judged: Option<Judged<'_>>| {
        let Some(judged) = judged else {
            return;
        };
        let sender = run.name(&judged.send.origin);
        match judged.verdict {
            ProbeVerdict::Block => assert!(
                judged.blocked,
                "I14 violated: {sender} was not blocked for delivery {}, {:?} of {} bytes, which \
                 engine 0 decodes and judges in the state it took it in",
                judged.position,
                judged.send.shape,
                judged.send.bytes.len(),
            ),
            ProbeVerdict::Pass => assert!(
                !judged.blocked,
                "I14 violated: {sender} was blocked for delivery {}, {:?} of {} bytes, which \
                 engine 0 must not block in the state it took it in",
                judged.position,
                judged.send.shape,
                judged.send.bytes.len(),
            ),
            ProbeVerdict::Open => {}
        }
    };

    let solicitation = run.solicitation();
    let mut known = ProbeKnowledge::default();
    let mut sent: Option<&ProbeSend> = None;
    let mut judged: Option<Judged<'_>> = None;
    let (mut refusals, mut admissions, mut unsettled, mut deliveries) = (0, 0, 0, 0);
    let mut placed = Vec::new();
    for step in &run.steps {
        match step {
            ProbeStep::Sent(send) => {
                assert!(
                    sent.replace(send).is_none(),
                    "harness defect: a message the program sent was not delivered before the next"
                );
            }
            ProbeStep::Delivered { peer, bytes } => {
                settle(judged.take());
                let send = sent
                    .take()
                    .expect("harness defect: engine 0 took a message the program did not send");
                assert!(
                    send.origin == *peer && send.bytes == *bytes,
                    "harness defect: engine 0 took a message other than the one the program sent"
                );
                let verdict = probe_verdict(run, &known, send);
                match verdict {
                    ProbeVerdict::Block => refusals += 1,
                    ProbeVerdict::Pass => admissions += 1,
                    ProbeVerdict::Open => unsettled += 1,
                }
                judged = Some(Judged {
                    position: deliveries,
                    send,
                    verdict,
                    blocked: false,
                });
                deliveries += 1;
                known.deliver(run, send);
            }
            ProbeStep::Blocked { peer } => {
                let Some(judged) = judged.as_mut() else {
                    panic!(
                        "I14 violated: engine 0 blocked {} before it took any message",
                        run.name(peer)
                    );
                };
                assert!(
                    judged.send.origin == *peer,
                    "I14 violated: engine 0 blocked {} while it processed delivery {}, which {} \
                     sent",
                    run.name(peer),
                    judged.position,
                    run.name(&judged.send.origin),
                );
                judged.blocked = true;
                placed.push(peer);
            }
            step => known.learn(solicitation, step),
        }
    }
    settle(judged);
    assert!(
        sent.is_none(),
        "harness defect: a message the program sent was never delivered"
    );

    // The network holds the blocks the probe placed and no others: no source
    // blocks anyone, since the discovering probe sends only requests.
    for (blocker, target) in &run.blocked {
        assert!(
            *blocker == run.discoverer && placed.contains(&target),
            "I14 violated: the network recorded that {} blocked {}, a block engine 0 did not \
             place",
            run.name(blocker),
            run.name(target),
        );
    }
    for peer in &placed {
        assert!(
            run.blocked
                .iter()
                .any(|(blocker, target)| *blocker == run.discoverer && target == *peer),
            "I14 violated: the block engine 0 placed on {} did not reach the network",
            run.name(peer),
        );
    }
    (refusals, admissions, unsettled, placed.len())
}

/// Check a probe run and report how much was compared.
pub(crate) fn check_probe(run: &ProbeRun) -> ProbeCounts {
    let solicitation = run.solicitation();
    let (mut solicitations, mut fetches, mut artifacts) = (0, 0, 0);
    for step in &run.steps {
        match step {
            ProbeStep::Requested { bytes, .. } if solicitation == Some(bytes.as_slice()) => {
                solicitations += 1;
            }
            ProbeStep::Requested { .. } => fetches += 1,
            ProbeStep::Resolved(_) => artifacts += 1,
            _ => {}
        }
    }
    let answers = |answer| {
        run.captures
            .iter()
            .filter(|capture| run.answer(capture) == answer)
            .count()
    };
    let (refusals, admissions, unsettled, blocks) = check_probe_blocks(run);
    ProbeCounts {
        solicitations,
        fetches,
        latest_replies: answers(ProbeAnswer::Latest),
        boundary_replies: answers(ProbeAnswer::Boundary),
        block_replies: answers(ProbeAnswer::Block),
        deliveries: refusals + admissions + unsettled,
        refusals,
        admissions,
        unsettled,
        blocks,
        blocked_peers: run.blocked.len(),
        artifacts,
        floors: check_probe_floor(run),
        comparisons: check_probe_artifact(run),
    }
}

/// What the caller of an engine that enters through state sync decided at one
/// start of the engine, from the record it keeps across restarts.
///
/// The driver requests state sync at every start of such an engine, so a
/// start carries no request of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Startup {
    /// The round of the floor an interrupted sync left on the caller's
    /// record, if the start found one.
    pub(crate) resumed: Option<Round>,
    /// The height of the floor of the completed sync on the caller's record,
    /// if the start found one.
    pub(crate) synced: Option<Height>,
    /// Whether the start chose state sync.
    pub(crate) syncs: bool,
}

/// What one start of an engine that chose state sync handed marshal and the
/// DKG module to start from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Material {
    /// The round of the floor.
    pub(crate) round: Round,
    /// The block the floor finalizes.
    pub(crate) digest: Digest,
    /// The epoch description paired with the floor.
    pub(crate) info: Box<Info>,
    /// Whether the probe's artifact carried the finalization of a boundary
    /// block, which it does for every epoch but the first.
    pub(crate) boundary: bool,
}

/// One step of an engine's entry through state sync, as its caller took it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// The engine started.
    Started(Startup),
    /// The start obtained a probe artifact and handed marshal and the DKG
    /// module this material.
    Entered(Material),
    /// The sync completed: marshal delivered the floor's block, at this
    /// height, to the engine, and the caller recorded the completion.
    Synced(Height),
}

/// What one engine of a state-sync run reports of the chain, and the steps of
/// its entry if it entered through state sync.
#[derive(Clone, Debug)]
pub(crate) struct Chain {
    /// The engine, for failure messages.
    pub(crate) engine: usize,
    /// Every finalized tip the engine's marshal reported: the round of the
    /// finalization, and the height and digest of the block it finalizes.
    pub(crate) finalized: Vec<(Round, Height, Digest)>,
    /// The height and digest of every finalized block marshal delivered to
    /// the engine.
    pub(crate) committed: Vec<(Height, Digest)>,
    /// The height and digest of every block the engine's application built,
    /// or verified and accepted, for consensus.
    pub(crate) endorsed: Vec<(Height, Digest)>,
    /// The description of each epoch that marshal delivered to the engine, in
    /// the final block of the epoch before it.
    pub(crate) delivered: Vec<(Epoch, Info)>,
    /// The steps of the engine's entry through state sync, in order. An
    /// engine that starts at the height-zero block takes none.
    pub(crate) steps: Vec<Step>,
}

impl Chain {
    /// The record of the engine `engine`, from what it reported.
    pub(crate) fn observed(engine: usize, records: &Records) -> Self {
        Self {
            engine,
            finalized: records.finalizations(),
            committed: records.commits(),
            endorsed: records.endorsements(),
            delivered: records.deliveries(),
            steps: records.steps(),
        }
    }

    /// Whether the engine has a record of the block `digest` at `height`: it
    /// was delivered the block, its marshal reported a finalization of it,
    /// or its application built or accepted it.
    fn vouches(&self, height: Height, digest: Digest) -> bool {
        self.committed.contains(&(height, digest))
            || self.endorsed.contains(&(height, digest))
            || self
                .finalized
                .iter()
                .any(|(_, at, finalized)| *at == height && *finalized == digest)
    }
}

/// A state-sync run as its engines observed it.
#[derive(Clone, Debug)]
pub(crate) struct StateSync {
    /// The description of epoch zero, which every engine is configured with.
    pub(crate) genesis: Info,
    /// The engine that started late and entered through state sync.
    pub(crate) joiner: usize,
    /// Every engine, the joiner included. The others started at the
    /// height-zero block.
    pub(crate) nodes: Vec<Chain>,
}

impl StateSync {
    /// The joiner's record.
    fn joined(&self) -> &Chain {
        self.nodes
            .iter()
            .find(|node| node.engine == self.joiner)
            .expect("the joiner is among the engines")
    }

    /// The records of the engines that started at the height-zero block.
    fn sources(&self) -> impl Iterator<Item = &Chain> {
        self.nodes.iter().filter(|node| node.engine != self.joiner)
    }
}

/// How much each check of the joiner's state sync compared.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncCounts {
    /// Starts of the joiner judged under I15.
    pub starts: usize,
    /// Of those, the starts that chose state sync.
    pub syncs: usize,
    /// Of those, the starts that resumed an interrupted sync from the floor
    /// it left on record.
    pub resumptions: usize,
    /// Starts that obtained a probe artifact and entered from its material.
    pub entries: usize,
    /// Of those, the entries whose artifact carried the finalization of a
    /// boundary block: the joiner discovered a boundary.
    pub boundaries: usize,
    /// Syncs that completed.
    pub completions: usize,
    /// Starts after the sync completed, none of which may sync again.
    pub later: usize,
    /// Floors traced to a finalization of a node that started at genesis,
    /// under I16.
    pub floors: usize,
    /// Epoch descriptions paired with a floor that were compared with the
    /// one the nodes that started at genesis hold, under I16.
    pub pairings: usize,
    /// Comparisons of a block the joiner committed with the block another
    /// engine committed at its height, under I17.
    pub blocks: usize,
    /// Comparisons of an epoch description the joiner committed with the one
    /// another engine committed for its epoch, under I17.
    pub descriptions: usize,
    /// The height of the newest floor the joiner entered from, if marshal
    /// delivered its block to the joiner.
    pub floor: Option<Height>,
}

/// I15: an engine state syncs once, and durably.
///
/// Walking the steps of the engine's entry in order: a start after a floor
/// was selected finds a floor on record that is not earlier; a floor selected
/// later is never at an earlier round; and once the sync completed, every
/// later start finds the completion on record and does not sync again. A
/// start that finds a completion no step reported was crashed between
/// recording it durably and reporting it.
///
/// Every step is one the harness's own caller of the engine reports of its
/// own record, so this judges whether that caller keeps the contract the DKG
/// module documents for it. It reads nothing the DKG module reports, and no
/// defect of the DKG module can make it fail. The driver requests state sync
/// at every start of the engine, so a start that syncs without a request
/// cannot occur and is not looked for.
///
/// Returns how many steps of each kind were judged.
pub(crate) fn check_single_sync(node: &Chain) -> SyncCounts {
    let engine = node.engine;
    let mut counts = SyncCounts::default();
    let mut floor: Option<Round> = None;
    let mut synced: Option<Height> = None;
    let mut syncing = false;
    for (index, step) in node.steps.iter().enumerate() {
        match step {
            Step::Started(start) => {
                if let Some(height) = synced {
                    assert!(
                        start.synced.is_some(),
                        "I15 violated: engine {engine} lost the record of its state sync, which \
                         completed at height {height}, by step {index}: {start:?}",
                    );
                }
                synced = synced.or(start.synced);
                if let Some(height) = synced {
                    assert!(
                        !start.syncs,
                        "I15 violated: engine {engine} chose state sync after its sync \
                         completed at height {height}, at step {index}: {start:?}",
                    );
                    counts.later += 1;
                } else {
                    if let Some(selected) = floor {
                        assert!(
                            start.resumed.is_some_and(|resumed| resumed >= selected),
                            "I15 violated: engine {engine} lost the floor of round {selected} \
                             of its interrupted state sync by step {index}: {start:?}",
                        );
                    }
                    floor = floor.max(start.resumed);
                }
                syncing = start.syncs;
                counts.starts += 1;
                counts.syncs += usize::from(start.syncs);
                counts.resumptions += usize::from(start.syncs && start.resumed.is_some());
            }
            Step::Entered(material) => {
                assert!(
                    syncing && synced.is_none(),
                    "I15 violated: engine {engine} entered through state sync at step {index} \
                     in a start that did not choose it: {material:?}",
                );
                if let Some(selected) = floor {
                    assert!(
                        material.round >= selected,
                        "I15 violated: engine {engine} moved the floor of its state sync from \
                         round {selected} back to round {} at step {index}",
                        material.round,
                    );
                }
                floor = Some(material.round);
                counts.entries += 1;
                counts.boundaries += usize::from(material.boundary);
            }
            Step::Synced(height) => {
                assert!(
                    syncing && synced.is_none() && floor.is_some(),
                    "I15 violated: engine {engine} completed a state sync at step {index} that \
                     its start did not enter",
                );
                synced = Some(*height);
                counts.completions += 1;
            }
        }
    }
    counts
}

/// I16: the floor the joiner starts from, and the epoch description it pairs
/// with it, are ones the nodes that started at genesis finalized.
///
/// The floor must be a finalized tip the marshal of such a node reported, at
/// the same round over the same block. The description must be of the
/// floor's epoch and equal the one such nodes were delivered in the final
/// block of the epoch before it, or the configured one for epoch zero.
///
/// The clause on the description's epoch never reports a run: the DKG module
/// panics when it is handed a floor and a description of different epochs,
/// and the panic of an engine is reported under I8, which is judged first.
/// The clause is kept for records that are not a run's.
///
/// Returns the number of floors and of descriptions compared.
pub(crate) fn check_floor_provenance(sync: &StateSync) -> (usize, usize) {
    let joiner = sync.joined();
    let (mut floors, mut pairings) = (0, 0);
    for step in &joiner.steps {
        let Step::Entered(material) = step else {
            continue;
        };
        let finalized = sync.sources().any(|node| {
            node.finalized
                .iter()
                .any(|(round, _, digest)| *round == material.round && *digest == material.digest)
        });
        assert!(
            finalized,
            "I16 violated: engine {} started from a floor of round {} over block {}, which no \
             node that started at genesis finalized",
            joiner.engine, material.round, material.digest,
        );
        floors += 1;

        let epoch = material.info.epoch;
        assert!(
            epoch == material.round.epoch(),
            "I16 violated: engine {} paired its floor of round {} with the description of \
             epoch {epoch}",
            joiner.engine,
            material.round,
        );
        let held: Vec<&Info> = if epoch == Epoch::zero() {
            vec![&sync.genesis]
        } else {
            sync.sources()
                .flat_map(|node| &node.delivered)
                .filter(|(delivered, _)| *delivered == epoch)
                .map(|(_, info)| info)
                .collect()
        };
        assert!(
            !held.is_empty(),
            "I16 violated: engine {} paired its floor with a description of epoch {epoch}, \
             which no node that started at genesis finalized",
            joiner.engine,
        );
        for info in held {
            assert!(
                *info == *material.info,
                "I16 violated: engine {} paired its floor with a description of epoch {epoch} \
                 other than the one the nodes that started at genesis finalized: {:?} != {info:?}",
                joiner.engine,
                material.info,
            );
        }
        pairings += 1;
    }
    (floors, pairings)
}

/// I17: every block and every epoch description the joiner commits above its
/// floor equals what the other engines committed at that height or for that
/// epoch, and is one of theirs.
///
/// Marshal delivers the joiner nothing below its floor, so everything it was
/// delivered is judged. A block must equal every block another engine was
/// delivered, or reported finalized, at its height, and some engine that
/// started at genesis must have a record of it: it was delivered the block,
/// its marshal reported a finalization of it, or its application built or
/// accepted it. The last record exists before a quorum can finalize the
/// block, whenever the run ends and whichever engine is down: of the three
/// committee members whose finalize votes a finalization needs, at most one
/// is the joiner, and a correct member votes to finalize only a block its
/// application built or accepted, or a block that ends an epoch proposed
/// again, which it notarizes only on that block's acceptance in an earlier
/// view. A block that a finalized one extends was accepted the same way,
/// before its child could be notarized.
///
/// A description must equal every description another engine was delivered
/// for its epoch. If no engine that started at genesis was delivered it, the
/// block that carried it to the joiner, the final block of the epoch before,
/// must be one of theirs as above: the digest of a block covers its payload.
///
/// The comparison of descriptions repeats I1, which compares the description
/// of every epoch among all engines, the joiner included: the state-sync
/// measurement runs this check first, so a description on which the joiner
/// differs is reported here, and I1 would report it otherwise. Returns the
/// number of comparisons made of a block with one another engine was
/// delivered, and of a description with one another engine was delivered.
pub(crate) fn check_agreement_after_sync(sync: &StateSync) -> (usize, usize) {
    let joiner = sync.joined();
    let epocher = FixedEpocher::new(EPOCH_LENGTH);
    let vouched =
        |height: Height, digest: Digest| sync.sources().any(|node| node.vouches(height, digest));
    let (mut blocks, mut descriptions) = (0, 0);
    for (epoch, info) in &joiner.delivered {
        let mut held = false;
        for node in sync.sources() {
            for (_, other) in node.delivered.iter().filter(|(at, _)| at == epoch) {
                assert!(
                    other == info,
                    "I17 violated: engine {} committed a description of epoch {epoch} above its \
                     floor other than the one engine {} committed: {info:?} != {other:?}",
                    joiner.engine,
                    node.engine,
                );
                descriptions += 1;
                held = true;
            }
        }
        if held {
            continue;
        }
        let boundary = epoch.previous().and_then(|previous| epocher.last(previous));
        let carrier = joiner
            .committed
            .iter()
            .find(|(height, _)| Some(*height) == boundary);
        assert!(
            carrier.is_some_and(|(height, digest)| vouched(*height, *digest)),
            "I17 violated: engine {} committed a description of epoch {epoch} above its floor \
             that no node that started at genesis committed, carried by a block none of them has \
             a record of: {carrier:?}",
            joiner.engine,
        );
    }
    for (index, (height, digest)) in joiner.committed.iter().enumerate() {
        let conflicting = joiner.committed[..index]
            .iter()
            .find(|(committed, _)| committed == height);
        assert!(
            conflicting.is_none(),
            "I17 violated: engine {} committed two blocks at height {height} above its floor: \
             {conflicting:?} and {digest}",
            joiner.engine,
        );
        for node in sync.sources() {
            for (_, other) in node.committed.iter().filter(|(at, _)| at == height) {
                assert!(
                    other == digest,
                    "I17 violated: engine {} committed block {digest} at height {height} above \
                     its floor, and engine {} committed block {other}",
                    joiner.engine,
                    node.engine,
                );
                blocks += 1;
            }
            for (round, _, other) in node.finalized.iter().filter(|(_, at, _)| at == height) {
                assert!(
                    other == digest,
                    "I17 violated: engine {} committed block {digest} at height {height} above \
                     its floor, and engine {} finalized block {other} there in round {round}",
                    joiner.engine,
                    node.engine,
                );
            }
        }
        assert!(
            vouched(*height, *digest),
            "I17 violated: engine {} committed block {digest} at height {height} above its \
             floor, of which no node that started at genesis has a record",
            joiner.engine,
        );
    }
    (blocks, descriptions)
}

/// Check the joiner's state sync, I15 to I17, and report how much was
/// compared.
pub(crate) fn check_state_sync(sync: &StateSync) -> SyncCounts {
    let joiner = sync.joined();
    let mut counts = check_single_sync(joiner);
    (counts.floors, counts.pairings) = check_floor_provenance(sync);
    (counts.blocks, counts.descriptions) = check_agreement_after_sync(sync);
    counts.floor = joiner
        .steps
        .iter()
        .rev()
        .find_map(|step| match step {
            Step::Entered(material) => Some(material.digest),
            _ => None,
        })
        .and_then(|floor| {
            joiner
                .committed
                .iter()
                .find(|(_, digest)| *digest == floor)
                .map(|(height, _)| *height)
        });
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{fixtures::committee, identities};
    use bytes::Bytes;
    use commonware_codec::{Decode as _, Encode as _, FixedSize as _, Write as _};
    use commonware_cryptography::{
        Signer as _,
        bls12381::{
            dkg::feldman_desmedt::{
                Dealer, Info as Round, Logs, Output, Player, Reveal, deal, observe,
            },
            primitives::sharing::{Mode, ModeVersion},
        },
        ed25519,
        transcript::Summary,
    };
    use commonware_utils::{NZU32, TestRng, sequence::Unit};

    /// The public description of a successful bootstrap with `output`.
    fn successful(output: Output<MockGroup, PublicKey>, players: Set<PublicKey>) -> BootstrapInfo {
        BootstrapInfo {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output,
            players,
            next_players: Set::default(),
            directory: Unit,
        }
    }

    /// The record of the engine `engine` running as `identity` that reported
    /// `ending`, if any, once and held `share` from before its report to the
    /// end of the run.
    fn bootstrapper(
        engine: usize,
        identity: PublicKey,
        ending: Option<Ending>,
        share: Option<Share>,
    ) -> Bootstrapper {
        Bootstrapper {
            engine,
            identity,
            completions: ending
                .map(|ending| (ending, share.clone()))
                .into_iter()
                .collect(),
            held: share.iter().cloned().collect(),
            share,
        }
    }

    /// Have `node` hold `share` instead, from before its reports to the end
    /// of the run.
    fn hold(node: &mut Bootstrapper, share: Option<Share>) {
        for (_, held) in &mut node.completions {
            held.clone_from(&share);
        }
        node.held = share.iter().cloned().collect();
        node.share = share;
    }

    /// Have `node` report `ending` once instead, if anything, holding the
    /// share it holds.
    fn report(node: &mut Bootstrapper, ending: Option<Ending>) {
        node.completions = ending
            .map(|ending| (ending, node.share.clone()))
            .into_iter()
            .collect();
    }

    /// A ceremony dealt by a trusted dealer under `seed` in `mode`, as four
    /// correct engines would observe it had it succeeded.
    fn dealt_in(seed: u64, mode: Mode) -> (Bootstrap, BootstrapInfo) {
        let identities = identities();
        let players = Set::from_iter_dedup(identities.iter().map(|signer| signer.public_key()));
        let (output, shares) =
            deal::<MockGroup, _, N3f1>(TestRng::new(seed), mode, players.clone())
                .expect("a trusted deal must succeed");
        let info = successful(output, players);
        let nodes = identities
            .iter()
            .enumerate()
            .map(|(engine, signer)| {
                bootstrapper(
                    engine,
                    signer.public_key(),
                    Some(Ending::Success(Box::new(info.clone()))),
                    shares.get_value(&signer.public_key()).cloned(),
                )
            })
            .collect();
        (Bootstrap { mode, nodes }, info)
    }

    /// A ceremony dealt by a trusted dealer under `seed`, as four correct
    /// engines would observe it had it succeeded.
    fn dealt(seed: u64) -> (Bootstrap, BootstrapInfo) {
        dealt_in(seed, Mode::NonZeroCounter)
    }

    /// A ceremony run through the real dealer and player state machines in
    /// which the identity at `victim` acknowledges no dealing, so every
    /// dealer reveals its share, as the four engines would observe it.
    fn revealing(victim: usize) -> Bootstrap {
        let mut rng = TestRng::new(7);
        let identities = identities();
        let players = Set::from_iter_dedup(identities.iter().map(|signer| signer.public_key()));
        let round = Round::<MockGroup, PublicKey>::new::<N3f1>(
            b"revealing",
            0,
            None,
            Mode::NonZeroCounter,
            Reveal::V1,
            players.clone(),
            players.clone(),
        )
        .expect("the round must be valid");
        let mut states: Vec<_> = identities
            .iter()
            .map(|signer| {
                Player::<MockGroup, ed25519::PrivateKey>::new(round.clone(), signer.clone())
                    .expect("every identity is a player")
            })
            .collect();
        let mut logs = Logs::<MockGroup, PublicKey, N3f1>::new(round.clone());
        for signer in &identities {
            let (mut dealer, public, privates) = Dealer::<MockGroup, ed25519::PrivateKey>::start::<
                N3f1,
            >(
                &mut rng, round.clone(), signer.clone(), None
            )
            .expect("every identity is a dealer");
            for (player, private) in privates {
                let index = players.position(&player).expect("a dealing names a player");
                if index == victim {
                    continue;
                }
                let ack = states[index]
                    .dealer_message::<N3f1>(signer.public_key(), public.clone(), private)
                    .expect("the dealing is valid")
                    .expect("the dealing is the dealer's first");
                dealer
                    .receive_player_ack(player, ack)
                    .expect("the ack is valid");
            }
            let (dealer, log) = dealer
                .finalize::<N3f1>()
                .check(&round)
                .expect("the dealer's log must verify");
            logs.record(dealer, log);
        }
        let output = observe::<MockGroup, PublicKey, N3f1>(&mut rng, logs.clone(), &Sequential)
            .expect("the ceremony must succeed");
        let info = successful(output, players);
        let nodes = identities
            .iter()
            .zip(states)
            .enumerate()
            .map(|(engine, (signer, player))| {
                let share = player
                    .finalize::<N3f1>(&mut rng, logs.clone(), &Sequential)
                    .expect("every player derives its share")
                    .1;
                bootstrapper(
                    engine,
                    signer.public_key(),
                    Some(Ending::Success(Box::new(info.clone()))),
                    Some(share),
                )
            })
            .collect();
        Bootstrap {
            mode: Mode::NonZeroCounter,
            nodes,
        }
    }

    #[test]
    fn dealt_ceremony_passes_every_check() {
        let (bootstrap, _) = dealt(1);
        let counts = check_bootstrap(&bootstrap, &committee(), &[]);
        assert_eq!(counts.correct_nodes, 4);
        assert_eq!(counts.completed, 4);
        assert_eq!(counts.successes, 1);
        assert_eq!(counts.agreements, 3);
        assert_eq!(counts.shares, 4);

        // Four holders and three required: four subsets reconstruct.
        assert_eq!(counts.reconstructions, 4);
    }

    #[test]
    fn incomplete_engines_are_not_compared() {
        let (mut bootstrap, _) = dealt(1);
        report(&mut bootstrap.nodes[2], None);
        report(&mut bootstrap.nodes[3], None);
        hold(&mut bootstrap.nodes[3], None);
        let counts = check_bootstrap(&bootstrap, &committee(), &[]);
        assert_eq!(counts.completed, 2);
        assert_eq!(counts.agreements, 1);
        assert_eq!(counts.shares, 3);
        assert_eq!(counts.reconstructions, 1);
    }

    /// No engine reported, so the shares are judged without the output: in
    /// both modes, four shares that carry their holders' positions and four
    /// quorums of them that recover one signature.
    #[test]
    fn unreported_shares_are_judged_without_the_output() {
        for mode in [Mode::NonZeroCounter, Mode::RootsOfUnity] {
            let (mut bootstrap, _) = dealt_in(1, mode);
            for node in &mut bootstrap.nodes {
                report(node, None);
            }
            let counts = check_bootstrap(&bootstrap, &committee(), &[]);
            assert_eq!(counts.completed, 0, "{mode:?}");
            assert_eq!(counts.successes, 0, "{mode:?}");
            assert_eq!(counts.shares, 4, "{mode:?}");
            assert_eq!(counts.reconstructions, 4, "{mode:?}");
        }
    }

    #[test]
    #[should_panic(expected = "I2 violated: engine 1 holds a share of epoch 0 at index \
                               Participant(2), but its identity is at Some(Participant(1)) in \
                               the committee")]
    fn unreported_share_at_another_index_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        for node in &mut bootstrap.nodes {
            report(node, None);
        }
        let share = bootstrap.nodes[2].share.clone();
        hold(&mut bootstrap.nodes[1], share);
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: engine 1 held two different shares of epoch 0")]
    fn unreported_shares_that_differ_at_one_engine_are_rejected() {
        let (mut bootstrap, _) = dealt(1);
        let (other, _) = dealt(2);
        for node in &mut bootstrap.nodes {
            report(node, None);
        }
        bootstrap.nodes[1].held.extend(other.nodes[1].share.clone());
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    #[should_panic(
        expected = "I3 violated: the shares of engines [0, 1, 2] and the shares of \
                               engines [0, 1, 3] recover different signatures for epoch 0"
    )]
    fn unreported_share_of_another_output_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        let (other, _) = dealt(2);
        for node in &mut bootstrap.nodes {
            report(node, None);
        }
        hold(&mut bootstrap.nodes[2], other.nodes[2].share.clone());
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    /// Without the output, shares no more numerous than a quorum are
    /// consistent with some output whatever they are: a share of another
    /// output among three is not found.
    #[test]
    fn unreported_shares_of_one_quorum_are_not_compared() {
        let (mut bootstrap, _) = dealt(1);
        let (other, _) = dealt(2);
        for node in &mut bootstrap.nodes {
            report(node, None);
        }
        hold(&mut bootstrap.nodes[2], other.nodes[2].share.clone());
        bootstrap.nodes.remove(3);
        let counts = check_bootstrap(&bootstrap, &committee(), &[]);
        assert_eq!((counts.shares, counts.reconstructions), (3, 1));
    }

    #[test]
    #[should_panic(expected = "I1 violated: engines 0 and 2 disagree")]
    fn differing_outputs_are_rejected() {
        let (mut bootstrap, _) = dealt(1);
        let (other, _) = dealt(2);
        bootstrap.nodes[2].completions = other.nodes[2].completions.clone();
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    #[should_panic(expected = "I1 violated: engines 0 and 3 disagree")]
    fn success_against_failure_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        report(&mut bootstrap.nodes[3], Some(Ending::Failure));
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    #[should_panic(expected = "I1 violated: the output of epoch 0 is not among the committee")]
    fn output_among_other_players_is_rejected() {
        let (bootstrap, _) = dealt(1);
        let mut committee = committee();
        committee.pop();
        check_bootstrap(&bootstrap, &committee, &[]);
    }

    #[test]
    #[should_panic(expected = "I1 violated: the sharing of epoch 0 is among 7 participants")]
    fn output_with_a_sharing_of_another_size_is_rejected() {
        // The committee's output, carrying the public sharing of a deal
        // among seven participants.
        let (mut bootstrap, info) = dealt(1);
        let wider = Set::from_iter_dedup(
            (0..7).map(|seed| ed25519::PrivateKey::from_seed(seed).public_key()),
        );
        let (other, _) = deal::<MockGroup, _, N3f1>(TestRng::new(2), Mode::NonZeroCounter, wider)
            .expect("a trusted deal must succeed");
        let mut forged = info.output.encode()[..Summary::SIZE].to_vec();
        other.public().write(&mut forged);
        info.output.dealers().write(&mut forged);
        info.output.players().write(&mut forged);
        info.output.revealed().write(&mut forged);
        let output = Output::decode_cfg(Bytes::from(forged), &(NZU32!(7), ModeVersion::v1()))
            .expect("the forged output decodes");
        let forged = successful(output, info.players.clone());
        for node in &mut bootstrap.nodes {
            report(node, Some(Ending::Success(Box::new(forged.clone()))));
        }
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    #[should_panic(expected = "I1 violated: the successful ceremony of epoch 0 reports outcome")]
    fn output_of_another_epoch_is_rejected() {
        let (mut bootstrap, mut info) = dealt(1);
        info.epoch = Epoch::new(1);
        for node in &mut bootstrap.nodes {
            report(node, Some(Ending::Success(Box::new(info.clone()))));
        }
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    #[should_panic(expected = "I1 violated: the bootstrap output of epoch 0 names next players")]
    fn output_with_next_players_is_rejected() {
        let (mut bootstrap, mut info) = dealt(1);
        info.next_players = info.players.clone();
        for node in &mut bootstrap.nodes {
            report(node, Some(Ending::Success(Box::new(info.clone()))));
        }
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: engine 1 holds a share of epoch 0 at index")]
    fn share_at_another_index_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        let share = bootstrap.nodes[2].share.clone();
        hold(&mut bootstrap.nodes[1], share);
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: the share engine 1 holds for epoch 0 does not match")]
    fn share_of_another_sharing_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        let (other, _) = dealt(2);
        hold(&mut bootstrap.nodes[1], other.nodes[1].share.clone());
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    /// A share the engine held and later overwrote with its valid one is
    /// judged like the one it holds.
    #[test]
    #[should_panic(expected = "I2 violated: the share engine 2 holds for epoch 0 does not match")]
    fn overwritten_share_of_another_sharing_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        let (other, _) = dealt(2);
        let overwritten = other.nodes[2].share.clone().expect("every player is dealt");
        bootstrap.nodes[2].held.insert(0, overwritten);
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: engine 3 completed the successful ceremony")]
    fn completion_without_a_share_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        hold(&mut bootstrap.nodes[3], None);
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    /// An engine that reported the success before it held its share is
    /// judged at its report, whatever it holds at the end.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 3 completed the successful ceremony of epoch 0 \
                               without a share"
    )]
    fn report_made_before_the_share_was_held_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        bootstrap.nodes[3].completions[0].1 = None;
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    // A share that fails I3 also fails I2, which runs first, so this control
    // calls the check directly.
    #[test]
    #[should_panic(expected = "I3 violated: the shares of engines [0, 1, 2] do not reconstruct")]
    fn foreign_share_does_not_reconstruct() {
        let (mut bootstrap, info) = dealt(1);
        let (other, _) = dealt(2);
        hold(&mut bootstrap.nodes[1], other.nodes[1].share.clone());
        check_reconstruction(&bootstrap.ended(), &info);
    }

    #[test]
    #[should_panic(expected = "I6 violated: engine 2 holds a share of epoch 0")]
    fn share_after_a_failed_ceremony_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        for node in &mut bootstrap.nodes {
            hold(node, None);
            report(node, Some(Ending::Failure));
        }
        let (other, _) = dealt(1);
        hold(&mut bootstrap.nodes[2], other.nodes[2].share.clone());
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    /// A share held during a failed ceremony is a violation even if the
    /// engine holds none at the end.
    #[test]
    #[should_panic(expected = "I6 violated: engine 2 holds a share of epoch 0")]
    fn share_held_during_a_failed_ceremony_is_rejected() {
        let (mut bootstrap, _) = dealt(1);
        for node in &mut bootstrap.nodes {
            hold(node, None);
            report(node, Some(Ending::Failure));
        }
        let (other, _) = dealt(1);
        bootstrap.nodes[2].held.extend(other.nodes[2].share.clone());
        check_bootstrap(&bootstrap, &committee(), &[]);
    }

    #[test]
    fn revealed_share_is_accepted() {
        // Every dealer reveals the compromised identity's share, and no
        // correct engine runs as it.
        let mut bootstrap = revealing(2);
        bootstrap.nodes.remove(2);
        let counts = check_bootstrap(&bootstrap, &committee(), &[]);
        assert_eq!(counts.shares, 3);
        assert_eq!(counts.reconstructions, 1);
    }

    fn raised(engine: Option<usize>, said: &str) -> Panic {
        Panic {
            engine,
            message: format!("panicked at src/lib.rs:1:1:\n{said}"),
        }
    }

    #[test]
    fn half_panics_are_tolerated_whatever_they_say() {
        let panics = [
            raised(Some(0), "DKG participant must receive a share"),
            raised(Some(4), "failed dkg: Exited"),
            raised(Some(4), "boom"),
        ];
        assert_eq!(check_panics(&panics, &[0, 4]), 3);
    }

    #[test]
    #[should_panic(
        expected = "I8 violated: correct engine 1 panicked: panicked at src/lib.rs:1:1:\n\
                               DKG participant must receive a share"
    )]
    fn correct_engine_panic_is_rejected_whatever_it_says() {
        check_panics(
            &[
                raised(Some(0), "DKG participant must receive a share"),
                raised(Some(1), "DKG participant must receive a share"),
            ],
            &[0, 4],
        );
    }

    #[test]
    #[should_panic(expected = "I8 violated: a task of no engine panicked: panicked at \
                               src/lib.rs:1:1:\nboom")]
    fn panic_of_no_engine_is_rejected() {
        check_panics(&[raised(Some(4), "boom"), raised(None, "boom")], &[0, 4]);
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engine 0 panicked")]
    fn engine_panic_without_a_compromised_identity_is_rejected() {
        check_panics(&[raised(Some(0), "boom")], &[]);
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engines [2] stopped")]
    fn stopped_correct_engine_is_rejected() {
        check_engines_running(&[2]);
    }

    fn instance(engine: usize, exit: Exit) -> Instance {
        Instance { engine, exit }
    }

    #[test]
    fn crashed_instances_did_not_stop() {
        let instances = [
            instance(0, Exit::Running),
            instance(1, Exit::Crashed),
            instance(2, Exit::Crashed),
            instance(1, Exit::Running),
            instance(2, Exit::Crashed),
        ];
        assert_eq!(check_instances_running(&instances), 3);
        assert_eq!(check_instances_running(&[]), 0);
    }

    #[test]
    #[should_panic(expected = "I8 violated: correct engines [2] stopped")]
    fn instance_that_stopped_on_its_own_is_rejected() {
        check_instances_running(&[
            instance(0, Exit::Running),
            instance(2, Exit::Crashed),
            instance(2, Exit::Stopped),
        ]);
    }

    #[test]
    fn root_task_that_returns_is_accepted() {
        assert_eq!(check_root_task(Ok(7), &[]), 7);
    }

    #[test]
    #[should_panic(expected = "I8 violated: the run's root task panicked: [Panic { engine: None")]
    fn root_task_panic_is_rejected() {
        check_root_task::<()>(Err(Box::new("boom")), &[raised(None, "boom")]);
    }

    /// A run in which the engines of `reports` reported, in order, the
    /// endings each lists, holding no share.
    fn reports(reports: Vec<(usize, Vec<Ending>)>) -> Bootstrap {
        let committee = committee();
        Bootstrap {
            mode: Mode::NonZeroCounter,
            nodes: reports
                .into_iter()
                .map(|(engine, endings)| Bootstrapper {
                    engine,
                    identity: committee[engine].clone(),
                    completions: endings.into_iter().map(|ending| (ending, None)).collect(),
                    held: Vec::new(),
                    share: None,
                })
                .collect(),
        }
    }

    #[test]
    fn repeated_reports_that_agree_are_counted() {
        let (_, info) = dealt(1);
        let success = || Ending::Success(Box::new(info.clone()));
        let comparisons = check_reports_agree(&reports(vec![
            (0, Vec::new()),
            (1, vec![success()]),
            (2, vec![success(), success(), success()]),
            (3, vec![Ending::Failure, Ending::Failure]),
        ]));
        assert_eq!(comparisons, 3);
    }

    #[test]
    #[should_panic(expected = "I1 violated: engine 2 reported different results for the \
                               ceremony of epoch 0 across restarts")]
    fn report_of_another_output_after_a_restart_is_rejected() {
        let (_, info) = dealt(1);
        let (_, other) = dealt(2);
        check_reports_agree(&reports(vec![(
            2,
            vec![
                Ending::Success(Box::new(info)),
                Ending::Success(Box::new(other)),
            ],
        )]));
    }

    #[test]
    #[should_panic(expected = "I1 violated: engine 1 reported different results for the \
                               ceremony of epoch 0 across restarts")]
    fn failure_reported_after_a_success_is_rejected() {
        let (_, info) = dealt(1);
        check_reports_agree(&reports(vec![(
            1,
            vec![
                Ending::Success(Box::new(info.clone())),
                Ending::Success(Box::new(info)),
                Ending::Failure,
            ],
        )]));
    }

    #[test]
    #[should_panic(expected = "I9 violated: correct identity")]
    fn block_between_correct_identities_is_rejected() {
        let (bootstrap, _) = dealt(1);
        let committee = committee();
        check_bootstrap(
            &bootstrap,
            &committee,
            &[(committee[1].clone(), committee[2].clone())],
        );
    }

    #[test]
    fn blocks_involving_the_compromised_identity_are_accepted() {
        let (mut bootstrap, _) = dealt(1);
        bootstrap.nodes.remove(0);
        let committee = committee();
        let blocked = [
            (committee[0].clone(), committee[1].clone()),
            (committee[2].clone(), committee[0].clone()),
        ];
        assert_eq!(check_bootstrap(&bootstrap, &committee, &blocked).blocks, 2);
    }
}

#[cfg(test)]
mod reshare_tests {
    use super::*;
    use crate::dkg::{
        COMMITTEE, RESHARE_IDENTITIES,
        faulty::spare_log,
        fixtures::{identities, resummarized},
        reshare_input::Rotation,
        schedule::directory_of,
        signers,
    };
    use commonware_cryptography::{
        Signer as _,
        bls12381::{
            dkg::feldman_desmedt::{
                Dealer, Info as Round, Logs, Output, Player, Reveal, deal, observe,
            },
            primitives::sharing::Mode,
        },
        ed25519,
    };
    use commonware_utils::{FuzzRng, N5f1, NZU64, TestRng};

    type Shares = Vec<(PublicKey, Share)>;

    fn keys() -> Vec<ed25519::PrivateKey> {
        signers(RESHARE_IDENTITIES)
    }

    /// An output a trusted dealer deals to `players` under `seed`, and each
    /// player's share of it.
    fn dealt(seed: u64, players: &Set<PublicKey>) -> (Output<MockGroup, PublicKey>, Shares) {
        let (output, shares) =
            deal::<MockGroup, _, N3f1>(TestRng::new(seed), Mode::NonZeroCounter, players.clone())
                .expect("a trusted deal must succeed");
        let shares = players
            .iter()
            .map(|player| {
                let share = shares.get_value(player).expect("every player is dealt");
                (player.clone(), share.clone())
            })
            .collect();
        (output, shares)
    }

    /// The reshare of `previous` to `players`, run through the real dealer
    /// and player state machines with every dealing acknowledged: the new
    /// output and each player's share of it.
    fn reshared(
        seed: u64,
        previous: &Output<MockGroup, PublicKey>,
        shares: &Shares,
        players: &Set<PublicKey>,
    ) -> (Output<MockGroup, PublicKey>, Shares) {
        reshared_in(Mode::NonZeroCounter, seed, previous, shares, players)
    }

    /// Like [`reshared`], with the new shares assigned in the sharing mode
    /// `mode`, whatever mode `previous` was dealt in.
    fn reshared_in(
        mode: Mode,
        seed: u64,
        previous: &Output<MockGroup, PublicKey>,
        shares: &Shares,
        players: &Set<PublicKey>,
    ) -> (Output<MockGroup, PublicKey>, Shares) {
        let mut rng = TestRng::new(seed);
        let keys = keys();
        let signer = |identity: &PublicKey| {
            keys.iter()
                .find(|signer| signer.public_key() == *identity)
                .expect("every identity has a key")
                .clone()
        };
        let round = Round::<MockGroup, PublicKey>::new::<N3f1>(
            b"reshared",
            1,
            Some(previous.clone()),
            mode,
            Reveal::V1,
            previous.players().clone(),
            players.clone(),
        )
        .expect("the round must be valid");
        let mut states: Vec<_> = players
            .iter()
            .map(|player| {
                Player::<MockGroup, ed25519::PrivateKey>::new(round.clone(), signer(player))
                    .expect("every player is in the round")
            })
            .collect();
        let mut logs = Logs::<MockGroup, PublicKey, N3f1>::new(round.clone());
        for (dealer, share) in shares {
            let (mut state, public, privates) =
                Dealer::<MockGroup, ed25519::PrivateKey>::start::<N3f1>(
                    &mut rng,
                    round.clone(),
                    signer(dealer),
                    Some(share.clone()),
                )
                .expect("every share holder deals");
            for (player, private) in privates {
                let index = players.position(&player).expect("a dealing names a player");
                let ack = states[index]
                    .dealer_message::<N3f1>(dealer.clone(), public.clone(), private)
                    .expect("the dealing is valid")
                    .expect("the dealing is the dealer's first");
                state
                    .receive_player_ack(player, ack)
                    .expect("the ack is valid");
            }
            let (dealer, log) = state
                .finalize::<N3f1>()
                .check(&round)
                .expect("the dealer's log must verify");
            logs.record(dealer, log);
        }
        let output = observe::<MockGroup, PublicKey, N3f1>(&mut rng, logs.clone(), &Sequential)
            .expect("the reshare must succeed");
        let shares = players
            .iter()
            .cloned()
            .zip(states)
            .map(|(player, state)| {
                let (_, share) = state
                    .finalize::<N3f1>(&mut rng, logs.clone(), &Sequential)
                    .expect("every player derives its share");
                (player, share)
            })
            .collect();
        (output, shares)
    }

    /// With 32 blocks in an epoch, the last block before the midpoint of
    /// epoch zero, its midpoint, and its final block.
    const EARLY: u64 = 15;
    const MIDPOINT: u64 = 16;
    const FINAL: u64 = 31;

    /// What the blocks of epoch zero carry at an engine that was delivered
    /// all of them: the description of epoch zero in the height-zero block,
    /// one dealer log in each of the four blocks from the midpoint on, the
    /// description of epoch one in the final block, and nothing elsewhere.
    fn first_epoch() -> Vec<(Height, Carried)> {
        (0..=FINAL)
            .map(|height| {
                let carried = match height {
                    0 | FINAL => Carried::EpochInfo,
                    height if (MIDPOINT..MIDPOINT + 4).contains(&height) => Carried::DealerLog,
                    _ => Carried::Nothing,
                };
                (Height::new(height), carried)
            })
            .collect()
    }

    /// One epoch boundary as five correct engines, one per identity, would
    /// observe it: the run and the shares held for epoch zero and epoch one.
    struct Fixture {
        reshare: Reshare,
        old: Shares,
        new: Shares,
    }

    impl Fixture {
        /// Give every engine the description `info` of epoch one, the scheme
        /// it would register for it, and its share in `shares`, if any.
        fn boundary(&mut self, info: &Info, shares: &Shares) {
            for node in &mut self.reshare.nodes {
                let share = shares
                    .iter()
                    .find(|(player, _)| *player == node.identity)
                    .map(|(_, share)| share.clone());
                node.delivered = vec![(Epoch::new(1), info.clone())];
                node.registered.truncate(1);
                node.registered.push((
                    Epoch::new(1),
                    SchemeInfo::new(
                        &node.identity,
                        info.output.players().clone(),
                        info.output.public().clone(),
                        share.clone(),
                    ),
                ));
                node.shares.truncate(usize::from(!node.shares.is_empty()));
                node.shares
                    .extend(share.map(|share| (Epoch::new(1), share)));
            }
            self.new = shares.clone();
        }

        /// The description of epoch one the engines hold.
        fn info(&self) -> Info {
            self.reshare.nodes[0].delivered[0].1.clone()
        }

        /// Replace the description of epoch one at every engine.
        fn describe(&mut self, info: &Info) {
            for node in &mut self.reshare.nodes {
                node.delivered = vec![(Epoch::new(1), info.clone())];
            }
        }

        /// Make the block at `height` carry `carried` at `engine`.
        fn place(&mut self, engine: usize, height: u64, carried: Carried) {
            let placed = &mut self.reshare.nodes[engine].placed;
            placed.retain(|(at, _)| at.get() != height);
            placed.push((Height::new(height), carried));
        }
    }

    /// A run that starts from the committee of the first four identities and
    /// applies `rotation` before the first ceremony, which succeeds.
    fn succeeded(rotation: Rotation) -> Fixture {
        let identities = identities();
        let schedule = Schedule::new(&identities, COMMITTEE.get() as usize, &[rotation]);
        let (output, old) = dealt(1, &schedule.committee());
        let genesis = Info {
            outcome: EpochOutcome::Success,
            epoch: Epoch::zero(),
            output: output.clone(),
            players: schedule.players(Epoch::zero()),
            next_players: schedule.players(Epoch::new(1)),
            directory: directory_of(
                output.players(),
                &schedule.players(Epoch::zero()),
                &schedule.players(Epoch::new(1)),
            ),
        };
        let nodes = identities
            .iter()
            .enumerate()
            .map(|(engine, identity)| {
                let share = old
                    .iter()
                    .find(|(player, _)| player == identity)
                    .map(|(_, share)| share.clone());
                Resharer {
                    engine,
                    identity: identity.clone(),
                    placed: first_epoch(),
                    delivered: Vec::new(),
                    registered: vec![(
                        Epoch::zero(),
                        SchemeInfo::new(
                            identity,
                            output.players().clone(),
                            output.public().clone(),
                            share.clone(),
                        ),
                    )],
                    shares: share
                        .map(|share| (Epoch::zero(), share))
                        .into_iter()
                        .collect(),
                    unplayed: Vec::new(),
                }
            })
            .collect();
        let (output, new) = reshared(2, &output, &old, &genesis.players);
        let info = Info {
            outcome: EpochOutcome::Success,
            epoch: Epoch::new(1),
            directory: directory_of(
                output.players(),
                &genesis.next_players,
                &schedule.players(Epoch::new(2)),
            ),
            output,
            players: genesis.next_players.clone(),
            next_players: schedule.players(Epoch::new(2)),
        };
        let mut fixture = Fixture {
            reshare: Reshare {
                genesis,
                schedule,
                nodes,
            },
            old,
            new: Vec::new(),
        };
        fixture.boundary(&info, &new);
        fixture
    }

    /// A run over a fixed committee whose first ceremony fails.
    fn failed() -> Fixture {
        let mut fixture = succeeded(Rotation::Stay);
        let mut info = fixture.info();
        info.outcome = EpochOutcome::Failure;
        info.output = fixture.reshare.genesis.output.clone();
        let carried = fixture.old.clone();
        fixture.boundary(&info, &carried);
        fixture
    }

    /// A run over a fixed committee whose first ceremony reshares the first
    /// output, dealt with a counter as evaluation points, to shares at roots
    /// of unity.
    ///
    /// The two sharings of a run interpolate alike: they are in the run's
    /// mode among four participants, so the two interpolations of I5 return
    /// the same signature. Here they do not. The ceremony keeps the group
    /// public key and assigns the new shares other evaluation points, so a
    /// set of shares reconstructs the key only under the sharing its shares
    /// belong to.
    fn remoded() -> Fixture {
        let mut fixture = succeeded(Rotation::Stay);
        let genesis = fixture.reshare.genesis.clone();
        let (output, shares) = reshared_in(
            Mode::RootsOfUnity,
            2,
            &genesis.output,
            &fixture.old,
            &genesis.players,
        );
        let mut info = fixture.info();
        info.output = output;
        fixture.boundary(&info, &shares);
        fixture
    }

    #[test]
    fn successful_reshare_passes_every_check() {
        let fixture = succeeded(Rotation::Stay);
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(
            counts,
            ReshareCounts {
                correct_nodes: 5,
                epochs: 1,
                boundaries: 5,
                successes: 1,
                failures: 0,
                agreements: 4,
                registrations: 10,
                shares: 8,
                players: 4,

                // Four holders and three required, in each of two epochs.
                reconstructions: 8,
                continuities: 1,

                // One old share with two new ones, and two old with one new.
                isolations: 48,
                carried: 0,
                kept: 0,
                blocks: 0,

                // Every block of epoch zero above the height-zero block, at
                // each of five engines.
                placements: 155,
                dealer_logs: 20,
                epoch_infos: 5,
                tolerated_panics: 0,
            }
        );
    }

    #[test]
    fn reshare_to_a_changed_committee_passes_every_check() {
        let fixture = succeeded(Rotation::Replace(1));
        assert_ne!(
            fixture.info().output.players(),
            fixture.reshare.genesis.output.players()
        );
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(counts.successes, 1);
        assert_eq!(counts.shares, 8);
        assert_eq!(counts.reconstructions, 8);
        assert_eq!(counts.isolations, 48);
    }

    #[test]
    fn failed_reshare_passes_every_check() {
        let counts = check_reshare(&failed().reshare, &[]);
        assert_eq!(counts.failures, 1);
        assert_eq!(counts.successes, 0);
        assert_eq!(counts.carried, 4);
        assert_eq!(counts.kept, 4);
        assert_eq!(counts.isolations, 0);
        assert_eq!(counts.shares, 8);
        assert_eq!(counts.reconstructions, 8);
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 1 reached epoch 1 through a failed reshare as a \
                               player of the output carried into it and does not hold, under \
                               that epoch, the share it held of that output"
    )]
    fn carried_share_that_is_not_held_under_the_new_epoch_is_rejected() {
        // The engine registers the second epoch as a signer, with the share
        // it holds for the first epoch, and holds none for the second. The
        // rule on registrations reads the shares by the epoch they are held
        // for, and accepts it.
        let mut fixture = failed();
        fixture.reshare.nodes[1].shares.truncate(1);
        assert_eq!(check_registered_shares(&fixture.reshare), 7);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    fn only_players_that_reached_the_epoch_must_hold_the_carried_share() {
        // The outside identity is no player of the carried output.
        assert_eq!(check_reshare(&failed().reshare, &[]).kept, 4);

        // An engine that has not registered the second epoch is not judged,
        // whether or not it stored the carried share for it.
        for stored in [1, 2] {
            let mut fixture = failed();
            fixture.reshare.nodes[1].registered.truncate(1);
            fixture.reshare.nodes[1].shares.truncate(stored);
            assert_eq!(check_reshare(&fixture.reshare, &[]).kept, 3);
        }

        // An engine that held no share of the output has none to carry.
        let mut fixture = failed();
        let info = fixture.info();
        let node = &mut fixture.reshare.nodes[1];
        node.shares.clear();
        for (_, registration) in &mut node.registered {
            *registration = SchemeInfo::new(
                &node.identity,
                info.output.players().clone(),
                info.output.public().clone(),
                None,
            );
        }
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!((counts.kept, counts.carried), (3, 3));

        // An engine that entered the second epoch through state sync did not
        // carry its share across the boundary.
        let mut fixture = failed();
        fixture.reshare.nodes[1].shares.truncate(1);
        fixture.reshare.nodes[1].unplayed = vec![Epoch::new(1)];
        assert_eq!(check_reshare(&fixture.reshare, &[]).kept, 3);

        // An epoch it entered through state sync excuses no other epoch.
        fixture.reshare.nodes[1].unplayed = vec![Epoch::zero(), Epoch::new(2)];
        let rejected = std::panic::catch_unwind(|| check_reshare(&fixture.reshare, &[]));
        let message = *rejected
            .expect_err("the engine does not hold the carried share")
            .downcast::<String>()
            .expect("a check panics with a message");
        assert!(
            message.starts_with(
                "I2 violated: engine 1 reached epoch 1 through a failed reshare as a player"
            ),
            "{message}"
        );
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 1 completed the successful reshare into \
                               epoch 1 as a player of its output and holds no share of it"
    )]
    fn player_without_a_share_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        fixture.reshare.nodes[1].shares.truncate(1);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    fn only_players_that_completed_must_hold_a_share() {
        // The outside identity holds no share and is not a player.
        let mut fixture = succeeded(Rotation::Stay);
        assert_eq!(check_reshare(&fixture.reshare, &[]).players, 4);

        // An engine that has not completed the ceremony is not judged.
        fixture.reshare.nodes[1].shares.truncate(1);
        fixture.reshare.nodes[1].registered.truncate(1);
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(counts.players, 3);
        assert_eq!(counts.shares, 7);

        // A failed ceremony obliges no engine to hold a new share.
        assert_eq!(check_reshare(&failed().reshare, &[]).players, 0);
    }

    #[test]
    fn engine_that_entered_an_epoch_through_state_sync_need_not_hold_its_share() {
        // The engine registers the second epoch as a player of its output
        // and holds no share of it.
        let mut fixture = succeeded(Rotation::Stay);
        let info = fixture.info();
        let node = &mut fixture.reshare.nodes[1];
        node.shares.truncate(1);
        node.registered[1].1 = SchemeInfo::new(
            &node.identity,
            info.output.players().clone(),
            info.output.public().clone(),
            None,
        );

        // It did not play the ceremony that leads into that epoch.
        node.unplayed = vec![Epoch::new(1)];
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(counts.players, 3);
        assert_eq!(counts.shares, 7);
        assert_eq!(check_registered_shares(&fixture.reshare), 7);

        // An epoch it entered through state sync excuses no other epoch.
        fixture.reshare.nodes[1].unplayed = vec![Epoch::zero(), Epoch::new(2)];
        let rejected = std::panic::catch_unwind(|| check_reshare(&fixture.reshare, &[]));
        let message = *rejected
            .expect_err("the engine holds no share of the second output")
            .downcast::<String>()
            .expect("a check panics with a message");
        assert!(
            message.starts_with(
                "I2 violated: engine 1 completed the successful reshare into epoch 1 as a player"
            ),
            "{message}"
        );
    }

    #[test]
    fn registrations_that_carry_the_held_share_are_counted() {
        // Four engines hold a share of each of two outputs and register
        // both epochs with it. The outside identity holds none.
        let mut fixture = succeeded(Rotation::Stay);
        assert_eq!(check_registered_shares(&fixture.reshare), 8);

        // An engine a restart brought back registers its epoch again.
        let again = fixture.reshare.nodes[1].registered[1].clone();
        fixture.reshare.nodes[1].registered.push(again);
        assert_eq!(check_registered_shares(&fixture.reshare), 9);

        // The member that leaves holds no share of the new output, and the
        // identity that joins holds none of the first.
        let rotated = succeeded(Rotation::Replace(1));
        assert_eq!(check_registered_shares(&rotated.reshare), 8);

        // A carried share is registered for the epoch it is carried into.
        assert_eq!(check_registered_shares(&failed().reshare), 8);
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 1 registered the scheme of epoch 1 without \
                               the share it holds for it"
    )]
    fn registration_that_drops_the_held_share_is_rejected() {
        // The engine registers the second epoch once more, as a member that
        // holds no share, which every other check accepts.
        let mut fixture = succeeded(Rotation::Stay);
        let info = fixture.info();
        let node = &mut fixture.reshare.nodes[1];
        node.registered.push((
            Epoch::new(1),
            SchemeInfo::new(
                &node.identity,
                info.output.players().clone(),
                info.output.public().clone(),
                None,
            ),
        ));
        assert_eq!(check_reshare(&fixture.reshare, &[]).registrations, 11);
        check_registered_shares(&fixture.reshare);
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 2 registered the scheme of epoch 0 without \
                               the share it holds for it"
    )]
    fn registration_of_a_share_the_engine_never_held_is_rejected() {
        // The engine registers the first epoch with its share of the second
        // output.
        let mut fixture = succeeded(Rotation::Stay);
        let genesis = fixture.reshare.genesis.clone();
        fixture.reshare.nodes[2].registered[0] = (
            Epoch::zero(),
            SchemeInfo::Signer {
                participants: genesis.output.players().clone(),
                sharing: genesis.output.public().clone(),
                share: fixture.new[2].1.clone(),
            },
        );
        check_registered_shares(&fixture.reshare);
    }

    #[test]
    fn engines_behind_are_not_compared() {
        let mut fixture = succeeded(Rotation::Stay);
        for node in &mut fixture.reshare.nodes[2..] {
            node.delivered.clear();
            node.registered.truncate(1);
            node.shares.truncate(1);
        }
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(counts.boundaries, 2);
        assert_eq!(counts.agreements, 1);
        assert_eq!(counts.registrations, 7);
        assert_eq!(counts.shares, 6);

        // Two engines hold a share of the new output: none reconstructs.
        assert_eq!(counts.reconstructions, 4);
    }

    #[test]
    fn run_without_a_boundary_checks_only_the_first_output() {
        let mut fixture = succeeded(Rotation::Stay);
        for node in &mut fixture.reshare.nodes {
            node.delivered.clear();
            node.registered.truncate(1);
            node.shares.truncate(1);
        }
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(counts.epochs, 0);
        assert_eq!(counts.boundaries, 0);
        assert_eq!(counts.continuities, 0);
        assert_eq!(counts.shares, 4);
        assert_eq!(counts.reconstructions, 4);
    }

    #[test]
    #[should_panic(
        expected = "I1 violated: engine 0 and engine 2 disagree on the description of \
                               epoch 1"
    )]
    fn differing_descriptions_are_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let mut other = fixture.info();
        other.outcome = EpochOutcome::Failure;
        fixture.reshare.nodes[2].delivered = vec![(Epoch::new(1), other)];
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I1 violated: engine 3 and engine 3 disagree on the description of \
                               epoch 1"
    )]
    fn two_descriptions_at_one_engine_are_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let mut other = fixture.info();
        other.outcome = EpochOutcome::Failure;
        for node in &mut fixture.reshare.nodes[..3] {
            node.delivered.clear();
            node.registered.truncate(1);
            node.shares.truncate(1);
        }
        fixture.reshare.nodes[3]
            .delivered
            .push((Epoch::new(1), other));
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: engine 1 holds a share of epoch 1 at index")]
    fn reshared_share_at_another_index_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let foreign = fixture.new[2].1.clone();
        fixture.reshare.nodes[1].shares[1] = (Epoch::new(1), foreign);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: the share engine 1 holds for epoch 1 does not match")]
    fn share_of_the_previous_output_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let stale = fixture.old[1].1.clone();
        fixture.reshare.nodes[1].shares[1] = (Epoch::new(1), stale);

        // With the stale share among the new ones, three shares of the
        // previous output form a mixed set and I5 fires first, so the check
        // is called directly.
        check_share_validity(
            &fixture.reshare.holders(Epoch::new(1), true),
            &fixture.info(),
        );
    }

    #[test]
    #[should_panic(expected = "I2 violated: the share engine 1 holds for epoch 1 does not match")]
    fn second_share_for_an_epoch_is_checked() {
        let mut fixture = succeeded(Rotation::Stay);
        let (_, other) = dealt(9, &fixture.reshare.schedule.committee());
        let valid = fixture.reshare.nodes[1].shares[1].clone();
        fixture.reshare.nodes[1].shares[1] = (Epoch::new(1), other[1].1.clone());
        fixture.reshare.nodes[1].shares.push(valid);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 4 holds a share for epoch 7, which no correct \
                               engine holds a description of"
    )]
    fn share_for_an_undescribed_epoch_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let share = fixture.new[0].1.clone();
        fixture.reshare.nodes[4].shares.push((Epoch::new(7), share));
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 3 registered a scheme for epoch 1 that does \
                               not carry the agreed public sharing"
    )]
    fn registration_of_another_sharing_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let previous = fixture.reshare.nodes[3].registered[0].1.clone();
        fixture.reshare.nodes[3].registered[1] = (Epoch::new(1), previous);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 4 registered a scheme for epoch 1 that does \
                               not carry the agreed public sharing"
    )]
    fn registration_among_other_participants_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let info = fixture.info();
        fixture.reshare.nodes[4].registered[1] = (
            Epoch::new(1),
            SchemeInfo::Verifier {
                participants: Set::from_iter_dedup(identities().into_iter().skip(1)),
                sharing: info.output.public().clone(),
            },
        );
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(expected = "I2 violated: the share engine 2 holds for epoch 1 does not match")]
    fn registered_share_of_another_sharing_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let info = fixture.info();
        fixture.reshare.nodes[2].registered[1] = (
            Epoch::new(1),
            SchemeInfo::Signer {
                participants: info.output.players().clone(),
                sharing: info.output.public().clone(),
                share: fixture.old[2].1.clone(),
            },
        );
        check_reshare(&fixture.reshare, &[]);
    }

    /// A player registers the epoch as a verifier, which the DKG module never
    /// does: it registers a player without a share as a member.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 1 registered the scheme of epoch 1 as a verifier, \
                               but it is one of the players of the agreed output"
    )]
    fn registration_of_a_player_as_a_verifier_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let info = fixture.info();
        let node = &mut fixture.reshare.nodes[1];
        node.shares.truncate(1);
        node.registered[1].1 = SchemeInfo::Verifier {
            participants: info.output.players().clone(),
            sharing: info.output.public().clone(),
        };
        node.unplayed = vec![Epoch::new(1)];
        check_reshare(&fixture.reshare, &[]);
    }

    /// The registrar would build a member's scheme at another player's place.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 1 registered the scheme of epoch 1 as the member"
    )]
    fn registration_as_another_member_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let info = fixture.info();
        let other = fixture.reshare.nodes[2].identity.clone();
        let node = &mut fixture.reshare.nodes[1];
        node.shares.truncate(1);
        node.registered[1].1 = SchemeInfo::Member {
            participants: info.output.players().clone(),
            sharing: info.output.public().clone(),
            public_key: other,
        };
        node.unplayed = vec![Epoch::new(1)];
        check_reshare(&fixture.reshare, &[]);
    }

    /// The outside identity registers as a member, which it is not.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 4 registered the scheme of epoch 1 as the member"
    )]
    fn registration_of_an_outsider_as_a_member_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let info = fixture.info();
        let node = &mut fixture.reshare.nodes[4];
        node.registered[1].1 = SchemeInfo::Member {
            participants: info.output.players().clone(),
            sharing: info.output.public().clone(),
            public_key: node.identity.clone(),
        };
        check_reshare(&fixture.reshare, &[]);
    }

    /// The engines agree on an output whose sharing needs more shares than
    /// the quorum of its players, and register it. No scheme can be built
    /// from it.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 0 registered a scheme for epoch 1 whose sharing is \
                               among 4 participants and needs 4 shares, but it names 4 players \
                               with a quorum of 3"
    )]
    fn registration_of_a_sharing_off_the_quorum_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let players = fixture.info().output.players().clone();
        let (output, shares) =
            deal::<MockGroup, _, N5f1>(TestRng::new(9), Mode::NonZeroCounter, players)
                .expect("a trusted deal must succeed");
        assert_eq!(output.public().required(), 4);
        let shares = fixture
            .new
            .iter()
            .map(|(player, _)| {
                let share = shares.get_value(player).expect("every player is dealt");
                (player.clone(), share.clone())
            })
            .collect();
        let mut info = fixture.info();
        info.output = output;
        fixture.boundary(&info, &shares);

        // The output does not keep the group key, which I4 reports before
        // the registrations are judged, so the registration is checked
        // directly.
        let node = &fixture.reshare.nodes[0];
        check_registration(node, Epoch::new(1), &node.registered[1].1, &info);
    }

    #[test]
    #[should_panic(
        expected = "I2 violated: engine 0 registered a scheme for epoch 3, which no \
                               correct engine holds a description of"
    )]
    fn registration_for_an_undescribed_epoch_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let registration = fixture.reshare.nodes[0].registered[1].1.clone();
        fixture.reshare.nodes[0]
            .registered
            .push((Epoch::new(3), registration));
        check_reshare(&fixture.reshare, &[]);
    }

    // A share that fails I3 also fails I2, which runs first, so this control
    // calls the check directly.
    #[test]
    #[should_panic(
        expected = "I3 violated: the shares of engines [0, 1, 2] do not reconstruct \
                               the key of epoch 1"
    )]
    fn reshared_shares_with_a_foreign_one_do_not_reconstruct() {
        let mut fixture = succeeded(Rotation::Stay);
        let (_, other) = dealt(9, &fixture.reshare.schedule.committee());
        fixture.reshare.nodes[1].shares[1] = (Epoch::new(1), other[1].1.clone());
        check_reconstruction(
            &fixture.reshare.holders(Epoch::new(1), false),
            &fixture.info(),
        );
    }

    #[test]
    #[should_panic(
        expected = "I4 violated: the boundary into epoch 1 carries the description of \
                               epoch 2"
    )]
    fn description_of_another_epoch_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let mut info = fixture.info();
        info.epoch = Epoch::new(2);
        fixture.describe(&info);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(expected = "I4 violated: the players of epoch 1 are")]
    fn players_that_were_not_announced_are_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let mut info = fixture.info();
        info.players = Set::from_iter_dedup(identities().into_iter().skip(1));
        fixture.describe(&info);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(expected = "I4 violated: the next players of epoch 1 are")]
    fn next_players_off_the_schedule_are_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let mut info = fixture.info();
        info.next_players = Set::from_iter_dedup(identities().into_iter().skip(1));
        fixture.describe(&info);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(expected = "I4 violated: the output reshared into epoch 1 is among")]
    fn output_among_players_other_than_the_ceremony_s_is_rejected() {
        // The schedule replaces a member before the first ceremony, but the
        // output is reshared to the first committee.
        let mut fixture = succeeded(Rotation::Replace(0));
        let genesis = fixture.reshare.genesis.clone();
        let (output, shares) = reshared(3, &genesis.output, &fixture.old, genesis.output.players());
        let mut info = fixture.info();
        info.output = output;
        fixture.boundary(&info, &shares);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(expected = "I4 violated: the reshare into epoch 1 changed the group public key")]
    fn changed_group_key_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        let (output, shares) = dealt(9, &fixture.reshare.genesis.players);
        let mut info = fixture.info();
        info.output = output;
        fixture.boundary(&info, &shares);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I5 violated: the shares engines [0] held before the reshare into \
                               epoch 1, mixed with the shares engines [1, 2] hold after it, \
                               reconstruct the key"
    )]
    fn reshare_that_keeps_the_shares_is_rejected() {
        // A ceremony reported as successful whose output and shares are the
        // previous ones: nothing was refreshed.
        let mut fixture = succeeded(Rotation::Stay);
        let mut info = fixture.info();
        info.output = fixture.reshare.genesis.output.clone();
        let kept = fixture.old.clone();
        fixture.boundary(&info, &kept);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(expected = "I5 violated")]
    fn one_kept_share_is_rejected() {
        // One engine's share survived the reshare, so it completes a quorum
        // of the new shares.
        let fixture = succeeded(Rotation::Stay);
        let mut old = fixture.reshare.holders(Epoch::zero(), true);
        old.nodes[0].share = Some(fixture.new[0].1.clone());
        check_isolation(
            Epoch::new(1),
            &fixture.reshare.genesis,
            &fixture.info(),
            &old,
            &fixture.reshare.holders(Epoch::new(1), true),
        );
    }

    #[test]
    fn reshare_into_another_sharing_mode_passes_every_check() {
        let fixture = remoded();
        let (genesis, info) = (&fixture.reshare.genesis, fixture.info());
        assert_ne!(genesis.output.public(), info.output.public());
        assert_eq!(
            genesis.output.public().public(),
            info.output.public().public()
        );
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(counts.successes, 1);
        assert_eq!(counts.shares, 8);
        assert_eq!(counts.reconstructions, 8);
        assert_eq!(counts.isolations, 48);
    }

    /// I5 under the previous sharing. An engine comes out of the reshare
    /// with the share it went in with, so two shares from before the reshare
    /// and that one are three shares of the previous output. They
    /// reconstruct the key at the previous sharing's evaluation points and
    /// not at the new one's, so only the interpolation under the previous
    /// sharing rejects them.
    #[test]
    #[should_panic(
        expected = "I5 violated: the shares engines [0, 2] held before the reshare \
                               into epoch 1, mixed with the shares engines [1] hold after it, \
                               reconstruct the key"
    )]
    fn share_kept_through_a_reshare_into_another_sharing_mode_is_rejected() {
        let mut fixture = remoded();
        let kept = fixture.old[1].1.clone();
        fixture.reshare.nodes[1].shares[1] = (Epoch::new(1), kept);
        check_reshare(&fixture.reshare, &[]);
    }

    /// I5 under the new sharing. An engine held its share of the new output
    /// before the reshare, so that share and two shares from after the
    /// reshare are three shares of the new output. They reconstruct the key
    /// at the new sharing's evaluation points and not at the previous one's,
    /// so only the interpolation under the new sharing rejects them.
    ///
    /// The share is not valid for the first epoch either, and I2 would report
    /// that first, so the check is called directly.
    #[test]
    #[should_panic(
        expected = "I5 violated: the shares engines [0] held before the reshare into \
                               epoch 1, mixed with the shares engines [1, 2] hold after it, \
                               reconstruct the key"
    )]
    fn share_of_another_sharing_mode_held_before_the_reshare_is_rejected() {
        let fixture = remoded();
        let mut old = fixture.reshare.holders(Epoch::zero(), true);
        old.nodes[0].share = Some(fixture.new[0].1.clone());
        check_isolation(
            Epoch::new(1),
            &fixture.reshare.genesis,
            &fixture.info(),
            &old,
            &fixture.reshare.holders(Epoch::new(1), true),
        );
    }

    #[test]
    #[should_panic(
        expected = "I6 violated: the share engine 0 held before the failed ceremony \
                               is not valid under the output carried into epoch 1"
    )]
    fn failed_reshare_with_another_sharing_is_rejected() {
        let mut fixture = failed();
        let (output, shares) = dealt(9, &fixture.reshare.schedule.committee());
        let mut info = fixture.info();
        info.output = output;
        fixture.boundary(&info, &shares);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I6 violated: the failed ceremony did not carry the previous \
                               output into epoch 1 unchanged"
    )]
    fn failed_reshare_with_a_changed_output_is_rejected() {
        let mut fixture = failed();
        let mut info = fixture.info();
        info.output = resummarized(&info.output);
        assert_eq!(
            info.output.public(),
            fixture.reshare.genesis.output.public()
        );
        fixture.describe(&info);

        // The registrations carry the unchanged sharing, so only the output
        // differs.
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(expected = "I9 violated: correct identity")]
    fn block_between_correct_identities_of_a_reshare_is_rejected() {
        let fixture = succeeded(Rotation::Stay);
        let identities = identities();
        check_reshare(
            &fixture.reshare,
            &[(identities[4].clone(), identities[0].clone())],
        );
    }

    #[test]
    fn fixture_heights_follow_the_schedule() {
        let epocher = FixedEpocher::new(EPOCH_LENGTH);
        assert_eq!(epocher.midpoint(Epoch::zero()), Some(Height::new(MIDPOINT)));
        assert_eq!(epocher.last(Epoch::zero()), Some(Height::new(FINAL)));
        assert_eq!(EARLY + 1, MIDPOINT);
    }

    #[test]
    fn placement_is_judged_by_the_schedule_in_every_epoch() {
        // A dealer log in the midpoint block and in the last block before
        // the final one, and the same places an epoch later.
        let mut fixture = succeeded(Rotation::Stay);
        let length = EPOCH_LENGTH.get();
        fixture.place(1, MIDPOINT, Carried::DealerLog);
        fixture.place(1, FINAL - 1, Carried::DealerLog);
        fixture.place(1, FINAL + 1, Carried::Nothing);
        fixture.place(1, length + EARLY, Carried::Nothing);
        fixture.place(1, length + MIDPOINT, Carried::DealerLog);
        fixture.place(1, length + FINAL - 1, Carried::DealerLog);
        fixture.place(1, length + FINAL, Carried::EpochInfo);
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(counts.placements, 160);
        assert_eq!(counts.dealer_logs, 23);
        assert_eq!(counts.epoch_infos, 6);
    }

    #[test]
    fn engine_behind_is_judged_on_what_it_was_delivered() {
        // One engine was delivered nothing, and one stopped short of the
        // midpoint: no block is owed a payload.
        let mut fixture = succeeded(Rotation::Stay);
        fixture.reshare.nodes[3].placed.clear();
        fixture.reshare.nodes[4].placed.truncate(10);
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(counts.placements, 3 * 31 + 9);
        assert_eq!(counts.dealer_logs, 12);
        assert_eq!(counts.epoch_infos, 3);
    }

    #[test]
    fn height_zero_block_is_not_judged() {
        // The block every engine starts from carries the description of
        // epoch zero and is not counted.
        let mut fixture = succeeded(Rotation::Stay);
        for node in &mut fixture.reshare.nodes {
            assert_eq!(node.placed[0], (Height::zero(), Carried::EpochInfo));
            node.placed.truncate(1);
        }
        let counts = check_reshare(&fixture.reshare, &[]);
        assert_eq!(counts.placements, 0);
        assert_eq!(counts.epoch_infos, 0);
    }

    #[test]
    #[should_panic(
        expected = "I18 violated: engine 2 was delivered a finalized block at height 15, \
                    before the midpoint of epoch 0, that carries a dealer log"
    )]
    fn dealer_log_before_the_midpoint_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        fixture.place(2, EARLY, Carried::DealerLog);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I18 violated: engine 1 was delivered a finalized block at height 3, \
                    before the midpoint of epoch 0, that carries an epoch description"
    )]
    fn epoch_description_before_the_midpoint_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        fixture.place(1, 3, Carried::EpochInfo);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I18 violated: engine 3 was delivered a finalized block at height 30, \
                    between the midpoint and the final block of epoch 0, that carries an \
                    epoch description"
    )]
    fn epoch_description_before_the_final_block_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        fixture.place(3, FINAL - 1, Carried::EpochInfo);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I18 violated: engine 0 was delivered a finalized block at height 31, the \
                    final block of epoch 0, that carries a dealer log"
    )]
    fn dealer_log_in_the_final_block_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        fixture.place(0, FINAL, Carried::DealerLog);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I18 violated: engine 4 was delivered a finalized block at height 31, the \
                    final block of epoch 0, that carries no payload"
    )]
    fn final_block_without_a_description_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        fixture.place(4, FINAL, Carried::Nothing);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I18 violated: engine 1 was delivered a finalized block at height 47, \
                    before the midpoint of epoch 1, that carries a dealer log"
    )]
    fn dealer_log_before_the_midpoint_of_a_later_epoch_is_rejected() {
        let mut fixture = succeeded(Rotation::Stay);
        fixture.place(1, EPOCH_LENGTH.get() + EARLY, Carried::DealerLog);
        check_reshare(&fixture.reshare, &[]);
    }

    #[test]
    #[should_panic(
        expected = "I18 violated: engine 0 was delivered a finalized block at height \
                    18446744073709551615, outside every epoch, that carries a dealer log"
    )]
    fn payload_outside_every_epoch_is_rejected() {
        // No schedule of 32 blocks leaves a height outside every epoch, so
        // the control runs under one of three, whose last epoch would end
        // past the largest height.
        let mut fixture = succeeded(Rotation::Stay);
        let epocher = FixedEpocher::new(NZU64!(3));
        fixture.reshare.nodes.truncate(1);
        fixture.reshare.nodes[0].placed = vec![(Height::new(u64::MAX), Carried::Nothing)];
        assert_eq!(check_placement(&epocher, &fixture.reshare).blocks, 1);
        fixture.reshare.nodes[0].placed = vec![(Height::new(u64::MAX), Carried::DealerLog)];
        check_placement(&epocher, &fixture.reshare);
    }

    #[test]
    fn records_keep_what_every_finalized_block_carries() {
        let fixture = succeeded(Rotation::Stay);
        let (dealer, share) = fixture.old[0].clone();
        let signer = keys()
            .into_iter()
            .find(|signer| signer.public_key() == dealer)
            .expect("every identity has a key");
        let log = spare_log(
            &mut FuzzRng::new(vec![1]),
            &fixture.reshare.genesis,
            &signer,
            Some(share),
            Mode::NonZeroCounter,
        )
        .expect("a dealer of the first ceremony signs a log");

        // A block delivered again is recorded once, and the blocks are
        // listed by height.
        let records = Records::default();
        records.placed(
            Height::new(FINAL),
            Some(&Payload::EpochInfo(fixture.info())),
        );
        records.placed(Height::new(MIDPOINT), Some(&Payload::DealerLog(log)));
        records.placed(Height::new(1), None);
        records.placed(Height::new(1), None);
        let placed = vec![
            (Height::new(1), Carried::Nothing),
            (Height::new(MIDPOINT), Carried::DealerLog),
            (Height::new(FINAL), Carried::EpochInfo),
        ];
        assert_eq!(records.placements(), placed);
        assert_eq!(
            Resharer::observed(0, dealer, &records, Vec::new()).placed,
            placed
        );
    }

    #[test]
    fn records_keep_what_an_engine_reports() {
        let fixture = succeeded(Rotation::Stay);
        let (info, registration) = (
            fixture.info(),
            fixture.reshare.nodes[0].registered[1].1.clone(),
        );
        let records = Records::default();
        let mut watched = records.watch();

        // A redelivered description is recorded once; registrations are all
        // kept and announced in order.
        records.delivered(Epoch::new(1), info.clone());
        records.delivered(Epoch::new(1), info.clone());
        records.registered(Epoch::zero(), registration.clone());
        records.registered(Epoch::new(1), registration.clone());
        assert_eq!(records.deliveries(), vec![(Epoch::new(1), info)]);
        assert_eq!(
            records.registrations(),
            vec![
                (Epoch::zero(), registration.clone()),
                (Epoch::new(1), registration)
            ]
        );
        assert_eq!(watched.try_recv().ok(), Some(Epoch::zero()));
        assert_eq!(watched.try_recv().ok(), Some(Epoch::new(1)));
        assert!(watched.try_recv().is_err());
    }
}

#[cfg(test)]
mod state_sync_tests {
    use super::*;
    use crate::dkg::{
        fixtures::{committee, described},
        signers,
    };
    use commonware_consensus::types::View;
    use commonware_cryptography::{Hasher as _, Sha256, Signer as _};

    /// The joiner's engine in every record below.
    const JOINER: usize = 4;

    /// With 32 blocks in an epoch, the first block after the midpoint of
    /// epoch one and the final block of that epoch.
    const LATE: u64 = 49;
    const FINAL: u64 = 63;

    /// The description of `epoch`, with an output a trusted dealer dealt.
    fn info(epoch: u64) -> Info {
        described(epoch + 1, Epoch::new(epoch)).0
    }

    /// The block of the one chain at `height`.
    fn block(height: u64) -> Digest {
        Sha256::hash(&[b"block", &height.to_be_bytes()])
    }

    /// The round the block at `height` is finalized in: one view a block.
    fn round(height: u64) -> Round {
        let epoch = height / EPOCH_LENGTH.get();
        Round::new(
            Epoch::new(epoch),
            View::new(height % EPOCH_LENGTH.get() + 1),
        )
    }

    /// The material of a floor at `height`, paired with the description of
    /// the floor's epoch.
    fn material(height: u64) -> Material {
        let floor = round(height);
        Material {
            round: floor,
            digest: block(height),
            info: Box::new(info(floor.epoch().get())),
            boundary: floor.epoch() != Epoch::zero(),
        }
    }

    /// A start that found `resumed` and `synced` on record, which chose
    /// state sync if `syncs`.
    fn start(resumed: Option<u64>, synced: Option<u64>, syncs: bool) -> Step {
        Step::Started(Startup {
            resumed: resumed.map(round),
            synced: synced.map(Height::new),
            syncs,
        })
    }

    /// The record of an engine that started at genesis and was delivered
    /// every block up to `tip`.
    fn source(engine: usize, tip: u64) -> Chain {
        Chain {
            engine,
            finalized: (1..=tip)
                .map(|height| (round(height), Height::new(height), block(height)))
                .collect(),
            committed: (0..=tip)
                .map(|height| (Height::new(height), block(height)))
                .collect(),
            endorsed: (1..=tip)
                .map(|height| (Height::new(height), block(height)))
                .collect(),
            delivered: (1..=(tip + 1) / EPOCH_LENGTH.get())
                .map(|epoch| (Epoch::new(epoch), info(epoch)))
                .collect(),
            steps: Vec::new(),
        }
    }

    /// A run in which four engines were delivered every block up to `tip`
    /// and the joiner entered from a floor at `floor`, completed its sync,
    /// and was delivered every block from its floor up to `tip`.
    fn synced(floor: u64, tip: u64) -> StateSync {
        let mut joiner = source(JOINER, tip);
        joiner
            .finalized
            .retain(|(_, height, _)| height.get() >= floor);
        joiner.committed.retain(|(height, _)| height.get() >= floor);
        joiner
            .delivered
            .retain(|(epoch, _)| epoch.get() * EPOCH_LENGTH.get() > floor);
        joiner.steps = vec![
            start(None, None, true),
            Step::Entered(material(floor)),
            Step::Synced(Height::new(floor)),
        ];
        let mut nodes: Vec<Chain> = (0..JOINER).map(|engine| source(engine, tip)).collect();
        nodes.push(joiner);
        StateSync {
            genesis: info(0),
            joiner: JOINER,
            nodes,
        }
    }

    /// The joiner's record with `steps` in place of its own.
    fn stepped(steps: Vec<Step>) -> Chain {
        let mut joiner = synced(LATE, FINAL).nodes.remove(JOINER);
        joiner.steps = steps;
        joiner
    }

    #[test]
    fn completed_sync_passes_every_check() {
        let counts = check_state_sync(&synced(LATE, FINAL + 10));
        assert_eq!(
            counts,
            SyncCounts {
                starts: 1,
                syncs: 1,
                resumptions: 0,
                entries: 1,
                boundaries: 1,
                completions: 1,
                later: 0,
                floors: 1,
                pairings: 1,

                // Twenty-five blocks from the floor to the tip and one
                // description, each compared with four engines.
                blocks: 100,
                descriptions: 4,
                floor: Some(Height::new(LATE)),
            }
        );
    }

    #[test]
    fn sync_in_the_first_epoch_is_paired_with_the_configured_description() {
        let counts = check_state_sync(&synced(5, 20));
        assert_eq!(counts.boundaries, 0);
        assert_eq!(counts.floors, 1);
        assert_eq!(counts.pairings, 1);
        assert_eq!(counts.blocks, 64);
        assert_eq!(counts.descriptions, 0);
    }

    #[test]
    fn joiner_that_never_enters_compares_nothing() {
        let mut sync = synced(LATE, FINAL);
        let joiner = &mut sync.nodes[JOINER];
        joiner.steps.truncate(1);
        joiner.committed.clear();
        joiner.delivered.clear();
        let counts = check_state_sync(&sync);
        assert_eq!(
            counts,
            SyncCounts {
                starts: 1,
                syncs: 1,
                ..SyncCounts::default()
            }
        );
    }

    #[test]
    fn interrupted_sync_resumes_and_completes_once() {
        // The first start is crashed before the probe answers, the second
        // after it recorded a floor, and the third resumes from that floor,
        // moves it forward, and completes. The fourth and the fifth do not
        // sync again; the fifth is the one that reports nothing but a start.
        let counts = check_single_sync(&stepped(vec![
            start(None, None, true),
            start(None, None, true),
            Step::Entered(material(40)),
            start(Some(40), None, true),
            Step::Entered(material(45)),
            Step::Synced(Height::new(45)),
            start(None, Some(45), false),
            start(None, Some(45), false),
        ]));
        assert_eq!(counts.starts, 5);
        assert_eq!(counts.syncs, 3);
        assert_eq!(counts.resumptions, 1);
        assert_eq!(counts.entries, 2);
        assert_eq!(counts.completions, 1);
        assert_eq!(counts.later, 2);
    }

    /// An engine crashed between recording its floor, or its completion,
    /// and reporting it shows the record at its next start.
    #[test]
    fn record_written_before_a_crash_is_found_by_the_next_start() {
        let counts = check_single_sync(&stepped(vec![
            start(None, None, true),
            start(Some(40), None, true),
            Step::Entered(material(40)),
            start(None, Some(40), false),
        ]));
        assert_eq!(counts.resumptions, 1);
        assert_eq!(counts.completions, 0);
        assert_eq!(counts.later, 1);
    }

    #[test]
    #[should_panic(
        expected = "I15 violated: engine 4 chose state sync after its sync completed at height \
                    40, at step 3"
    )]
    fn second_sync_is_rejected() {
        check_single_sync(&stepped(vec![
            start(None, None, true),
            Step::Entered(material(40)),
            Step::Synced(Height::new(40)),
            start(None, Some(40), true),
        ]));
    }

    #[test]
    #[should_panic(
        expected = "I15 violated: engine 4 lost the record of its state sync, which completed \
                    at height 40, by step 3"
    )]
    fn completion_that_does_not_survive_a_restart_is_rejected() {
        check_single_sync(&stepped(vec![
            start(None, None, true),
            Step::Entered(material(40)),
            Step::Synced(Height::new(40)),
            start(Some(40), None, true),
        ]));
    }

    #[test]
    #[should_panic(
        expected = "I15 violated: engine 4 lost the floor of round (1, 9) of its interrupted \
                    state sync by step 2"
    )]
    fn floor_that_does_not_survive_a_restart_is_rejected() {
        check_single_sync(&stepped(vec![
            start(None, None, true),
            Step::Entered(material(40)),
            start(None, None, true),
        ]));
    }

    #[test]
    #[should_panic(
        expected = "I15 violated: engine 4 lost the floor of round (1, 9) of its interrupted \
                    state sync by step 2"
    )]
    fn floor_that_a_restart_finds_earlier_is_rejected() {
        check_single_sync(&stepped(vec![
            start(None, None, true),
            Step::Entered(material(40)),
            start(Some(35), None, true),
        ]));
    }

    #[test]
    #[should_panic(
        expected = "I15 violated: engine 4 moved the floor of its state sync from round (1, 9) \
                    back to round (1, 4) at step 3"
    )]
    fn resumed_sync_that_moves_its_floor_back_is_rejected() {
        check_single_sync(&stepped(vec![
            start(None, None, true),
            Step::Entered(material(40)),
            start(Some(40), None, true),
            Step::Entered(material(35)),
        ]));
    }

    #[test]
    #[should_panic(
        expected = "I15 violated: engine 4 entered through state sync at step 3 in a start \
                    that did not choose it"
    )]
    fn entry_after_the_sync_completed_is_rejected() {
        check_single_sync(&stepped(vec![
            start(None, None, true),
            Step::Entered(material(40)),
            Step::Synced(Height::new(40)),
            Step::Entered(material(45)),
        ]));
    }

    #[test]
    #[should_panic(
        expected = "I15 violated: engine 4 completed a state sync at step 1 that its start did \
                    not enter"
    )]
    fn completion_without_an_entry_is_rejected() {
        check_single_sync(&stepped(vec![
            start(None, None, true),
            Step::Synced(Height::new(40)),
        ]));
    }

    #[test]
    #[should_panic(
        expected = "I16 violated: engine 4 started from a floor of round (1, 18) over block"
    )]
    fn floor_over_a_block_nobody_finalized_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        let Step::Entered(material) = &mut sync.nodes[JOINER].steps[1] else {
            unreachable!("the second step is the entry");
        };
        material.digest = block(1_000);
        check_floor_provenance(&sync);
    }

    #[test]
    #[should_panic(
        expected = "I16 violated: engine 4 started from a floor of round (1, 40) over block"
    )]
    fn floor_at_a_round_nobody_finalized_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        let Step::Entered(material) = &mut sync.nodes[JOINER].steps[1] else {
            unreachable!("the second step is the entry");
        };
        material.round = Round::new(Epoch::new(1), View::new(40));
        check_floor_provenance(&sync);
    }

    /// What the joiner itself reports as finalized vouches for nothing.
    #[test]
    #[should_panic(
        expected = "I16 violated: engine 4 started from a floor of round (1, 18) over block"
    )]
    fn floor_only_the_joiner_finalized_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[..JOINER] {
            node.finalized.retain(|(_, height, _)| height.get() != LATE);
        }
        assert!(sync.nodes[JOINER].finalized.contains(&(
            round(LATE),
            Height::new(LATE),
            block(LATE)
        )));
        check_floor_provenance(&sync);
    }

    /// One node that started at genesis and finalized the floor is enough.
    #[test]
    fn floor_one_source_finalized_is_accepted() {
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[1..JOINER] {
            node.finalized.clear();
            node.delivered.clear();
        }
        assert_eq!(check_floor_provenance(&sync), (1, 1));
    }

    #[test]
    #[should_panic(
        expected = "I16 violated: engine 4 paired its floor with a description of epoch 1 \
                    other than the one the nodes that started at genesis finalized"
    )]
    fn description_nobody_finalized_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        let Step::Entered(material) = &mut sync.nodes[JOINER].steps[1] else {
            unreachable!("the second step is the entry");
        };
        material.info.outcome = EpochOutcome::Failure;
        check_floor_provenance(&sync);
    }

    #[test]
    #[should_panic(
        expected = "I16 violated: engine 4 paired its floor with a description of epoch 0 \
                    other than the one the nodes that started at genesis finalized"
    )]
    fn description_of_the_first_epoch_other_than_the_configured_one_is_rejected() {
        let mut sync = synced(5, 20);
        sync.genesis = Info {
            epoch: Epoch::zero(),
            ..info(7)
        };
        check_floor_provenance(&sync);
    }

    #[test]
    #[should_panic(
        expected = "I16 violated: engine 4 paired its floor of round (1, 18) with the \
                    description of epoch 0"
    )]
    fn description_of_another_epoch_than_the_floor_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        let Step::Entered(material) = &mut sync.nodes[JOINER].steps[1] else {
            unreachable!("the second step is the entry");
        };
        *material.info = info(0);
        check_floor_provenance(&sync);
    }

    #[test]
    #[should_panic(
        expected = "I16 violated: engine 4 paired its floor with a description of epoch 1, \
                    which no node that started at genesis finalized"
    )]
    fn description_no_source_holds_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[..JOINER] {
            node.delivered.clear();
        }
        check_floor_provenance(&sync);
    }

    #[test]
    #[should_panic(expected = "I17 violated: engine 4 committed block")]
    fn block_the_others_did_not_commit_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        let committed = &mut sync.nodes[JOINER].committed;
        let last = committed.len() - 1;
        committed[last].1 = block(1_000);
        check_agreement_after_sync(&sync);
    }

    #[test]
    #[should_panic(expected = "I17 violated: engine 4 committed two blocks at height 50")]
    fn second_block_at_a_height_is_rejected() {
        // No other engine has been delivered the height yet.
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[..JOINER] {
            node.committed.retain(|(height, _)| height.get() < 50);
        }
        sync.nodes[JOINER]
            .committed
            .push((Height::new(50), block(1_000)));
        check_agreement_after_sync(&sync);
    }

    #[test]
    #[should_panic(
        expected = "I17 violated: engine 4 committed a description of epoch 2 above its floor \
                    other than the one engine 0 committed"
    )]
    fn description_the_others_did_not_commit_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        sync.nodes[JOINER].delivered[0].1.outcome = EpochOutcome::Failure;
        check_agreement_after_sync(&sync);
    }

    /// A joiner that is ahead of every other engine has nothing to be
    /// compared with at the heights only it was delivered, and the blocks
    /// there are the others' all the same: their marshals reported them
    /// finalized.
    #[test]
    fn heights_only_the_joiner_reached_are_not_compared() {
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[..JOINER] {
            node.committed.retain(|(height, _)| height.get() < 60);
            node.endorsed.clear();
            node.delivered.clear();
        }
        assert_eq!(check_agreement_after_sync(&sync), (44, 0));
    }

    /// A run can end, or the nodes that started at genesis can be down,
    /// before their marshals hold what the joiner was delivered. Their
    /// applications built or accepted those blocks before a finalization of
    /// them could exist, and one such record vouches for a block and for the
    /// description it carries.
    #[test]
    fn blocks_one_source_built_or_accepted_are_accepted() {
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[..JOINER] {
            node.committed.retain(|(height, _)| height.get() < 60);
            node.finalized.retain(|(_, height, _)| height.get() < 60);
            node.delivered.clear();
        }
        for node in &mut sync.nodes[1..JOINER] {
            node.endorsed.clear();
        }
        assert_eq!(check_agreement_after_sync(&sync), (44, 0));
    }

    /// A block no node that started at genesis has any record of is not
    /// theirs, whether or not any of them reached its height.
    #[test]
    #[should_panic(
        expected = "at height 50 above its floor, of which no node that started at genesis has \
                    a record"
    )]
    fn block_only_the_joiner_committed_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[..JOINER] {
            node.committed.retain(|(height, _)| height.get() != 50);
            node.finalized.retain(|(_, height, _)| height.get() != 50);
            node.endorsed.retain(|(height, _)| height.get() != 50);
        }
        check_agreement_after_sync(&sync);
    }

    /// The same at the top of the joiner's chain, where no node that started
    /// at genesis has been delivered anything.
    #[test]
    #[should_panic(expected = "of which no node that started at genesis has a record")]
    fn block_above_every_record_of_the_others_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[..JOINER] {
            node.committed.retain(|(height, _)| height.get() < 60);
            node.finalized.retain(|(_, height, _)| height.get() < 60);
            node.endorsed.retain(|(height, _)| height.get() < 60);
            node.delivered.clear();
        }
        sync.nodes[JOINER].delivered.clear();
        check_agreement_after_sync(&sync);
    }

    /// A description no node that started at genesis was delivered, carried
    /// by a block none of them has a record of, is not theirs.
    #[test]
    #[should_panic(
        expected = "I17 violated: engine 4 committed a description of epoch 2 above its floor \
                    that no node that started at genesis committed"
    )]
    fn description_only_the_joiner_committed_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[..JOINER] {
            node.delivered.clear();
            node.committed.retain(|(height, _)| height.get() != FINAL);
            node.finalized
                .retain(|(_, height, _)| height.get() != FINAL);
            node.endorsed.retain(|(height, _)| height.get() != FINAL);
        }
        check_agreement_after_sync(&sync);
    }

    /// A description the joiner holds without the block that carries it is
    /// not traced to anything.
    #[test]
    #[should_panic(
        expected = "I17 violated: engine 4 committed a description of epoch 3 above its floor \
                    that no node that started at genesis committed"
    )]
    fn description_without_the_block_that_carries_it_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        sync.nodes[JOINER].delivered.push((Epoch::new(3), info(3)));
        check_agreement_after_sync(&sync);
    }

    /// A block another engine's marshal reported finalized at a height is the
    /// block the joiner must have been delivered there.
    #[test]
    #[should_panic(expected = "and engine 0 finalized block")]
    fn block_other_than_the_one_another_engine_finalized_is_rejected() {
        let mut sync = synced(LATE, FINAL);
        for node in &mut sync.nodes[..JOINER] {
            node.committed.retain(|(height, _)| height.get() < 60);
        }
        let last = sync.nodes[0].finalized.len() - 1;
        sync.nodes[0].finalized[last].2 = block(1_000);
        check_agreement_after_sync(&sync);
    }

    #[test]
    fn records_keep_the_chain_and_the_steps_an_engine_reports() {
        let records = Records::default();
        let mut commits = records.watch_commits();
        records.finalized(round(3), Height::new(3), block(3));
        records.finalized(round(3), Height::new(3), block(3));
        records.committed(Height::new(2), block(2));
        records.committed(Height::new(1), block(1));
        records.committed(Height::new(2), block(2));
        records.endorsed(Height::new(4), block(4));
        records.endorsed(Height::new(3), block(3));
        records.endorsed(Height::new(4), block(4));
        records.stepped(start(None, None, true));
        records.stepped(Step::Entered(material(40)));

        // A tip or a block reported again is recorded once, and the blocks
        // are listed by height and announced as they are delivered. A block
        // the application built or accepted again is recorded once, and an
        // endorsement announces no delivery.
        assert_eq!(
            records.finalizations(),
            vec![(round(3), Height::new(3), block(3))]
        );
        assert_eq!(
            records.commits(),
            vec![(Height::new(1), block(1)), (Height::new(2), block(2))]
        );
        for height in [2, 1, 2] {
            assert_eq!(commits.try_recv().ok(), Some(Height::new(height)));
        }
        assert!(commits.try_recv().is_err());
        let chain = Chain::observed(JOINER, &records);
        assert_eq!(chain.engine, JOINER);
        assert_eq!(chain.finalized, records.finalizations());
        assert_eq!(chain.committed, records.commits());
        assert_eq!(
            chain.endorsed,
            vec![(Height::new(3), block(3)), (Height::new(4), block(4))]
        );
        assert_eq!(
            chain.steps,
            vec![start(None, None, true), Step::Entered(material(40))]
        );
    }

    #[test]
    fn unplayed_epochs_follow_the_floor() {
        let identity = signers(1)[0].public_key();
        let unplayed = |floor: u64, delivered: bool| {
            let records = Records::default();
            records.stepped(start(None, None, true));
            records.stepped(Step::Entered(material(floor)));
            if delivered {
                records.committed(Height::new(floor), block(floor));
            }
            Resharer::observed(JOINER, identity.clone(), &records, Vec::new()).unplayed
        };
        let (first, second, third) = (Epoch::zero(), Epoch::new(1), Epoch::new(2));

        // An engine that takes no step entered no epoch through state sync.
        assert!(Records::default().unplayed().is_empty());

        // The epoch of the floor is entered without its ceremony. A floor up
        // to the midpoint leaves the engine to play the next ceremony.
        assert_eq!(unplayed(5, true), vec![first]);
        assert_eq!(unplayed(16, true), vec![first]);
        assert_eq!(unplayed(40, true), vec![second]);
        assert_eq!(unplayed(48, true), vec![second]);

        // A floor past the midpoint makes the engine follow the rest of its
        // epoch, the final block included.
        assert_eq!(unplayed(17, true), vec![first, second]);
        assert_eq!(unplayed(LATE, true), vec![second, third]);
        assert_eq!(unplayed(FINAL, true), vec![second, third]);

        // An engine that was not delivered its floor has not followed.
        assert_eq!(unplayed(LATE, false), vec![second]);

        // Every floor an engine entered from counts.
        let records = Records::default();
        records.stepped(Step::Entered(material(20)));
        records.stepped(Step::Entered(material(70)));
        records.committed(Height::new(20), block(20));
        records.committed(Height::new(70), block(70));
        assert_eq!(records.unplayed(), vec![first, second, third]);
    }

    /// The scheme an engine registers of the epoch `epoch` as it enters it
    /// without a share.
    fn follower(epoch: u64) -> Registration {
        let info = info(epoch);
        SchemeInfo::Verifier {
            participants: info.output.players().clone(),
            sharing: info.output.public().clone(),
        }
    }

    /// An entry excuses an epoch only if the engine had not registered its
    /// scheme before: an engine that syncs a second time, into an epoch it
    /// had reached on its own, played the ceremony that leads into it.
    #[test]
    fn epoch_registered_before_an_entry_is_not_excused_by_it() {
        let (first, second) = (Epoch::zero(), Epoch::new(1));
        let registered = |records: &Records, epoch: u64| {
            records.registered(Epoch::new(epoch), follower(epoch));
        };
        let entered = |records: &Records, floor: u64| {
            records.stepped(Step::Entered(material(floor)));
            records.committed(Height::new(floor), block(floor));
        };

        // The engine enters the first epoch before its midpoint, plays the
        // ceremony, and registers the second epoch at its end. A crash finds
        // its sync without a completion on record, and it syncs again from a
        // floor in the second epoch, which that floor does not excuse.
        let records = Records::default();
        entered(&records, 5);
        registered(&records, 0);
        registered(&records, 1);
        entered(&records, 40);
        registered(&records, 1);
        assert_eq!(records.unplayed(), vec![first]);

        // Crashed before the end of the ceremony, it enters the second epoch
        // through the second floor alone.
        let records = Records::default();
        entered(&records, 5);
        registered(&records, 0);
        entered(&records, 40);
        registered(&records, 1);
        assert_eq!(records.unplayed(), vec![first, second]);

        // A second floor in an epoch the first floor excused changes nothing,
        // whatever the engine registered in between.
        let records = Records::default();
        entered(&records, 5);
        registered(&records, 0);
        entered(&records, 9);
        registered(&records, 0);
        assert_eq!(records.unplayed(), vec![first]);

        // The same holds of the epoch a floor past the midpoint makes the
        // engine follow into. Having ended the first ceremony itself, the
        // engine is not excused the second epoch by a later floor past the
        // midpoint of the first.
        let records = Records::default();
        entered(&records, 5);
        registered(&records, 0);
        registered(&records, 1);
        entered(&records, 20);
        registered(&records, 0);
        registered(&records, 1);
        assert_eq!(records.unplayed(), vec![first]);

        // Crashed before the end of the first ceremony, it follows the rest
        // of the first epoch from such a floor and is excused the second.
        let records = Records::default();
        entered(&records, 5);
        registered(&records, 0);
        entered(&records, 20);
        registered(&records, 0);
        registered(&records, 1);
        assert_eq!(records.unplayed(), vec![first, second]);

        // An engine that followed into the second epoch stays excused it
        // when it syncs again from a floor in it, and is not excused the
        // third epoch, whose ceremony it played.
        let records = Records::default();
        entered(&records, 20);
        registered(&records, 0);
        registered(&records, 1);
        registered(&records, 2);
        entered(&records, 70);
        registered(&records, 2);
        assert_eq!(records.unplayed(), vec![first, second]);
    }

    /// The engine played the first ceremony after entering through state
    /// sync, registered the second epoch, and synced again from a floor in
    /// it. With no share of the second output on record it is rejected, and
    /// with the second epoch first registered after the second entry it is
    /// excused.
    #[test]
    #[should_panic(
        expected = "I2 violated: engine 4 completed the successful reshare into epoch 1 as a \
                    player of its output and holds no share of it"
    )]
    fn second_sync_into_a_played_epoch_does_not_excuse_its_share() {
        // The engine runs as a player of the second output.
        let players = committee();
        let info = info(1);
        let node =
            |records: &Records| Resharer::observed(JOINER, players[0].clone(), records, Vec::new());
        let reshare = |node: Resharer| Reshare {
            genesis: self::info(0),
            schedule: Schedule::new(&players, 0, &[]),
            nodes: vec![node],
        };
        assert!(info.output.players().position(&players[0]).is_some());

        // Registered after the second entry only: excused.
        let records = Records::default();
        records.stepped(Step::Entered(material(5)));
        records.registered(Epoch::zero(), follower(0));
        records.stepped(Step::Entered(material(40)));
        records.registered(Epoch::new(1), follower(1));
        assert_eq!(
            check_players_hold_shares(&reshare(node(&records)), Epoch::new(1), &info),
            0
        );

        // Registered before the second entry: required.
        let records = Records::default();
        records.stepped(Step::Entered(material(5)));
        records.registered(Epoch::zero(), follower(0));
        records.registered(Epoch::new(1), follower(1));
        records.stepped(Step::Entered(material(40)));
        records.registered(Epoch::new(1), follower(1));
        check_players_hold_shares(&reshare(node(&records)), Epoch::new(1), &info);
    }
}
