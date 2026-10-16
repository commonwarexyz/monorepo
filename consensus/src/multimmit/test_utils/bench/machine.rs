//! Machine benchmarks: a validator's steady-state view cycle, its duplicate admission and idle
//! polls, and the replay of the journal the cycle wrote.
//!
//! Every scenario drives the production machine through the symbolic
//! [`Driver`](crate::multimmit::machine::testing::Driver), so the figures are pure state-machine
//! work: no I/O, signatures, or scheduling. Artifacts are signed once when a [`Script`] is built
//! and replayed against a fresh machine on every iteration.

use crate::{
    multimmit::{
        config::{Role, Tuning},
        machine::{
            BlockValidity,
            testing::{
                Drive as _, HeldVqc, Until, cohort,
                fixtures::{
                    Block, TestDriver, built_body, deliver, enter_next_view, receive, reference,
                    started_with, tuned, validate, vqc_above,
                },
            },
        },
        mocks::Committee,
        types::{Artifact, ChainSet, LeaderBlock, Lqc, Vqc},
    },
    types::Participant,
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};
use core::fmt;
use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

/// Views each view-cycle scenario runs.
pub const MACHINE_VIEWS: u64 = 16;

const SEED: u64 = 0xbe9c_4a11;

/// One fixed machine workload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineScenario {
    /// A validator of `participants` runs [`MACHINE_VIEWS`] views: per view it admits and
    /// validates one header per chain, enters the next view on a V-QC endorsing them, and
    /// finalizes the view's leader block with an L-QC.
    ViewCycle { participants: u32 },
    /// A validator replays the journal [`Self::ViewCycle`] wrote, from its start checkpoint.
    Replay { participants: u32 },
}

impl MachineScenario {
    /// Every scenario, at a small committee and a deployment-sized one.
    pub const ALL: [Self; 4] = [
        Self::ViewCycle { participants: 6 },
        Self::ViewCycle { participants: 31 },
        Self::Replay { participants: 6 },
        Self::Replay { participants: 31 },
    ];

    /// Returns the committee size the scenario runs.
    pub const fn participants(self) -> u32 {
        match self {
            Self::ViewCycle { participants } | Self::Replay { participants } => participants,
        }
    }
}

impl fmt::Display for MachineScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::ViewCycle { .. } => "view_cycle",
            Self::Replay { .. } => "replay",
        };
        write!(f, "{name}/n={} views={MACHINE_VIEWS}", self.participants())
    }
}

/// The signed artifacts of one view: a header per chain, the V-QC that endorses them, and the
/// L-QC of the view's leader block.
struct ViewScript {
    blocks: Vec<Block>,
    vqc: Vqc<MinPk, Digest>,
    lqc: Lqc<MinPk, Digest>,
}

/// A committee and the artifacts of [`MACHINE_VIEWS`] consecutive views from genesis.
pub struct Script {
    committee: Committee<MinPk>,
    views: Vec<ViewScript>,
}

impl Script {
    /// Signs the artifacts of [`MACHINE_VIEWS`] views for a committee of `participants`.
    ///
    /// Building runs the views once on a reference machine, which names each V-QC's parent.
    pub fn new(participants: u32) -> Self {
        let committee = Committee::<MinPk>::builder(SEED, participants).build();
        let mut driver = validator(&committee);
        let mut parent = HeldVqc::genesis(committee.genesis());
        let mut views = Vec::new();
        for _ in 0..MACHINE_VIEWS {
            let view = parent.view.next();
            let blocks = parent
                .tips
                .iter()
                .map(|tip| committee.sign_header(committee.header(tip, built_body(tip.digest()))))
                .collect::<Vec<_>>();
            let tips = blocks.iter().map(reference).collect();
            let vqc = vqc_above(&committee, &parent, true, tips, &blocks);
            let leader =
                LeaderBlock::new(committee.round(view), parent.id, parent.history).unwrap();
            let vote = committee.content(
                view,
                Some(leader.digest::<Sha256>()),
                false,
                committee.endorsement(
                    ChainSet::empty(committee.codec().chains()),
                    parent.tips.to_vec(),
                ),
            );
            let contents = (0..committee.codec().view_quorum())
                .map(|signer| (Participant::from_usize(signer), vote.clone()))
                .collect();
            let lqc = committee.lqc_from(leader, contents);
            let script = ViewScript { blocks, vqc, lqc };
            parent = script.run(&mut driver);
            views.push(script);
        }
        Self { committee, views }
    }

    /// Runs every view on `driver`.
    fn run(&self, driver: &mut TestDriver) {
        for view in &self.views {
            view.run(driver);
        }
    }
}

impl ViewScript {
    fn run(&self, driver: &mut TestDriver) -> HeldVqc<Digest> {
        receive(driver, &self.blocks);
        for block in &self.blocks {
            validate(driver, block, BlockValidity::Valid);
        }
        let held = enter_next_view(driver, self.vqc.clone());
        deliver(driver, vec![Artifact::Lqc(self.lqc.clone())]);
        held
    }
}

/// Returns a started driver for participant zero, retaining every scripted view.
fn validator(committee: &Committee<MinPk>) -> TestDriver {
    let tuning = Tuning::default();
    started_with(tuned(
        committee,
        Role::Validator(Participant::new(0)),
        tuning,
    ))
}

/// Runs `scenario` over `script` once and returns the host time of its measured region.
///
/// # Panics
///
/// Panics if `script` was built for another committee size or the machine leaves the script.
pub fn run_machine(scenario: MachineScenario, script: &Script) -> Duration {
    assert_eq!(
        script.committee.codec().participants(),
        scenario.participants() as usize
    );
    let mut driver = validator(&script.committee);
    match scenario {
        MachineScenario::ViewCycle { .. } => {
            let started = Instant::now();
            script.run(&mut driver);
            started.elapsed()
        }
        MachineScenario::Replay { .. } => {
            script.run(&mut driver);
            let started = Instant::now();
            driver.crash_and_restore().expect("the journal replays");
            started.elapsed()
        }
    }
}

/// Machine operations whose allocations are budgeted, on a validator that ran a script.
pub struct HotPathOperations {
    driver: TestDriver,
    header: Artifact<MinPk, Digest>,
    vqc: Artifact<MinPk, Digest>,
}

impl Default for HotPathOperations {
    fn default() -> Self {
        Self::new()
    }
}

impl HotPathOperations {
    /// Runs a six-validator script and keeps the last view's artifacts to observe again.
    pub fn new() -> Self {
        let script = Script::new(6);
        let mut driver = validator(&script.committee);
        script.run(&mut driver);
        let last = script.views.last().unwrap();
        Self {
            driver,
            header: Artifact::TransactionBlock(last.blocks[0].clone()),
            vqc: Artifact::Vqc(last.vqc.clone()),
        }
    }

    /// Observes an admitted header again.
    pub fn duplicate_header(&mut self) {
        self.observe(self.header.clone());
    }

    /// Observes an admitted V-QC again.
    pub fn duplicate_vqc(&mut self) {
        self.observe(self.vqc.clone());
    }

    fn observe(&mut self, artifact: Artifact<MinPk, Digest>) {
        let step = self
            .driver
            .submit(cohort::<Sha256, _>(vec![artifact]))
            .expect("a duplicate is classified");
        std::hint::black_box(self.driver.settle(step, Until::Quiesce));
    }

    /// Polls a machine that has no work, returning whether it stayed idle.
    pub fn idle_poll(&mut self) -> bool {
        let polled = self
            .driver
            .poll_with(NonZeroUsize::MIN)
            .expect("an idle poll succeeds");
        polled.capabilities().is_empty() && !self.driver.work_remaining()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn view_cycle_advances_every_scripted_view_and_replays() {
        let script = Script::new(6);
        let mut driver = validator(&script.committee);
        script.run(&mut driver);
        assert_eq!(driver.inspect().view().get(), MACHINE_VIEWS + 1);
        driver.crash_and_restore().unwrap();
        assert_eq!(driver.inspect().view().get(), MACHINE_VIEWS + 1);
        for scenario in MachineScenario::ALL.into_iter().take(1) {
            run_machine(scenario, &script);
        }
    }
}
