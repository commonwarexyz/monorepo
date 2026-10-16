//! View timing: the round-trip delay estimator, the production estimator, the timers derived
//! from their estimates, and the adaptive grace.

use crate::{
    multimmit::{
        config::{Role, Tuning},
        machine::{
            input::{BlockValidity, Input, Now},
            testing::{
                CapabilitiesExt as _, Drive as _, SymbolicPersistence, SymbolicSigner, Until,
                fixtures::{
                    committee, path, produce, profile, receive, started, tuned, validate, validator,
                },
            },
            view::timing::{Cadence, DeltaEstimator, RoundTrip, Timing, ViewTimers, millis},
        },
        types::{Artifact, ChainId, ChainSet},
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::Sha256;
use std::time::Duration;

fn at(millis: u64) -> Now {
    Now::from_millis(millis)
}

/// The production seed of the estimator tests.
const SEED: Duration = Duration::from_millis(50);

#[test]
fn the_estimate_halves_the_ninetieth_percentile_round_trip_less_the_vote_interval() {
    let mut estimator = RoundTrip::new(10, 32, 10);
    assert_eq!(estimator.estimate(), None);
    for height in 1..=10 {
        estimator.produced(Height::new(height), at(0));
    }
    for height in 1..=10 {
        estimator.confirmed(Height::new(height), at(10 * height));
    }
    // Round trips 10..=100: the nearest-rank 90th percentile is 90, less one vote interval.
    assert_eq!(estimator.estimate(), Some(40));

    // Newer samples push older ones out of the window.
    for height in 11..=20 {
        estimator.produced(Height::new(height), at(1_000));
    }
    estimator.confirmed(Height::new(20), at(1_200));
    assert_eq!(estimator.estimate(), Some(95));

    // A round trip within one vote interval measures no delay.
    let mut fast = RoundTrip::new(4, 4, 50);
    fast.produced(Height::new(1), at(0));
    fast.confirmed(Height::new(1), at(30));
    assert_eq!(fast.estimate(), Some(0));
}

#[test]
fn unconfirmed_blocks_beyond_the_bound_are_dropped_unsampled() {
    let mut estimator = RoundTrip::new(64, 2, 0);
    for height in 1..=4 {
        estimator.produced(Height::new(height), at(height * 100));
    }
    // Only heights three and four are still tracked: one confirmation samples both.
    estimator.confirmed(Height::new(4), at(500));
    assert_eq!(estimator.estimate(), Some(100));
    // A later confirmation of an already sampled height adds nothing.
    estimator.confirmed(Height::new(4), at(10_000));
    assert_eq!(estimator.estimate(), Some(100));
}

#[test]
fn a_chain_interval_is_the_median_of_its_recent_acceptance_gaps() {
    let chain = ChainId::new(0);
    let mut cadence = Cadence::new(1, 8, SEED);
    assert_eq!(cadence.chain_interval(chain), None);
    assert_eq!(cadence.estimate(), 50_000);

    // The first acceptance only starts the clock.
    cadence.accepted(chain, at(0));
    assert_eq!(cadence.chain_interval(chain), None);

    // Five blocks every 10 ms, then a pause for the next view's base: rarer than the blocks, the
    // pause does not count.
    for index in 1..=5 {
        cadence.accepted(chain, at(10 * index));
    }
    cadence.accepted(chain, at(550));
    assert_eq!(cadence.chain_interval(chain), Some(10_000));
    assert_eq!(cadence.estimate(), 10_000);

    // Only the most recent samples count.
    let mut cadence = Cadence::new(1, 2, SEED);
    for time in [0, 100, 200, 210, 220] {
        cadence.accepted(chain, at(time));
    }
    assert_eq!(cadence.chain_interval(chain), Some(10_000));
}

#[test]
fn heights_accepted_together_share_the_gap_since_the_previous_acceptance() {
    let chain = ChainId::new(0);
    let mut cadence = Cadence::new(1, 8, SEED);

    // Acceptances replayed at one instant, as on a restart, measure nothing.
    for _ in 0..4 {
        cadence.accepted(chain, at(100));
    }
    assert_eq!(cadence.chain_interval(chain), None);

    // Four heights accepted together 6 ms later took 1.5 ms each.
    for _ in 0..4 {
        cadence.accepted(chain, at(106));
    }
    assert_eq!(cadence.chain_interval(chain), Some(1_500));

    // The next gap is measured from that batch: samples 1.5 ms and 3 ms.
    cadence.accepted(chain, at(109));
    assert_eq!(cadence.chain_interval(chain), Some(3_000));
}

#[test]
fn the_production_estimate_is_the_median_across_chains() {
    let mut cadence = Cadence::new(5, 8, SEED);
    // Chains zero to two produce every 10, 20, and 30 ms; chain three's producer is faulty and
    // produces every millisecond; chain four has no sample yet and counts at the seed.
    for (chain, gap) in [(0, 10), (1, 20), (2, 30), (3, 1)] {
        for index in 0..=4 {
            cadence.accepted(ChainId::new(chain), at(index * gap));
        }
    }
    assert_eq!(cadence.estimate(), 20_000);

    // A second faulty producer, stalling for 10 s, moves the estimate only within the correct
    // chains' range.
    for index in 1..=4 {
        cadence.accepted(ChainId::new(4), at(index * 10_000));
    }
    assert_eq!(cadence.estimate(), 20_000);
}

/// A tuning whose seeds, floor, and ceiling differ from every measured value in the timer tests.
fn timing_tuning(ceiling: Duration) -> Tuning {
    Tuning {
        vote_interval: Duration::from_millis(20),
        delta_initial: Duration::from_millis(100),
        delta_min: Duration::from_millis(5),
        theta_initial: Duration::from_millis(40),
        timer_ceiling: ceiling,
        ..Tuning::default()
    }
}

#[test]
fn view_timers_derive_from_the_measured_delay_and_production_interval() {
    let committee = committee(130);
    let profile = tuned(
        &committee,
        validator(0),
        timing_tuning(Duration::from_secs(10)),
    );
    let cap = u64::from(committee.codec().window().cap());
    let mut timing = Timing::new(&profile);

    // Before any measurement the seeds apply.
    assert_eq!(
        timing.timers(),
        ViewTimers {
            delta: 100,
            production: 40,
            stop: 2 * 100 + 40 + 20,
            late: 40 + 100,
            max: cap * 40 + 2 * 100 + 20,
            quiet: 2 * 100 + 20,
            grace: 100 * 5 / 2,
        }
    );

    // Round trips of 60 ms are a delay of (60 - 20) / 2 ms; every chain accepts a height every
    // 7 ms. The grace keeps its value within its new range.
    timing.estimator().produced(Height::new(1), at(0));
    timing.estimator().confirmed(Height::new(1), at(60));
    for chain in committee.codec().chain_ids() {
        for index in 0..=3 {
            timing.cadence().accepted(chain, at(7 * index));
        }
    }
    assert_eq!(
        timing.timers(),
        ViewTimers {
            delta: 20,
            production: 7,
            stop: 2 * 20 + 7 + 20,
            late: 7 + 20,
            max: cap * 7 + 2 * 20 + 20,
            quiet: 2 * 20 + 20,
            grace: (100 * 5 / 2).min(2 * (cap * 7 + 2 * 20 + 20)),
        }
    );

    // A round trip within one vote interval is raised to the floor.
    let mut timing = Timing::new(&profile);
    timing.estimator().produced(Height::new(1), at(0));
    timing.estimator().confirmed(Height::new(1), at(10));
    assert_eq!(timing.timers().delta, 5);
}

#[test]
fn the_timer_ceiling_bounds_every_timer_and_estimate() {
    let committee = committee(134);
    let ceiling = Duration::from_secs(1);
    let profile = tuned(&committee, validator(0), timing_tuning(ceiling));
    let ceiling = millis(ceiling);
    let mut timing = Timing::new(&profile);

    // Faulty validators that delay their endorsements, and producers that stall, cannot stretch
    // the timers past the ceiling.
    timing.estimator().produced(Height::new(1), at(0));
    timing.estimator().confirmed(Height::new(1), at(60_000));
    for chain in committee.codec().chain_ids() {
        for index in 0..=3 {
            timing.cadence().accepted(chain, at(30_000 * index));
        }
    }
    for _ in 0..16 {
        timing.widen();
    }
    assert_eq!(
        timing.timers(),
        ViewTimers {
            delta: ceiling,
            production: ceiling,
            stop: ceiling,
            late: ceiling,
            max: ceiling,
            quiet: ceiling,
            grace: ceiling,
        }
    );
}

#[test]
fn the_grace_doubles_up_to_twice_t_max_and_halves_down_to_its_floor() {
    let committee = committee(131);
    let profile = profile(&committee, validator(0));
    let mut timing = Timing::new(&profile);
    let timers = timing.timers();
    let floor = timers.grace;
    assert_eq!(floor, timers.delta * 5 / 2);
    timing.widen();
    assert_eq!(timing.timers().grace, 2 * floor);
    for _ in 0..16 {
        timing.widen();
    }
    assert_eq!(timing.timers().grace, 2 * timers.max);
    timing.narrow();
    assert_eq!(timing.timers().grace, timers.max);
    for _ in 0..16 {
        timing.narrow();
    }
    assert_eq!(timing.timers().grace, floor);
}

#[test]
fn own_blocks_feed_the_estimator_when_n_minus_f_validators_endorse_them() {
    let committee = committee(132);
    let mut driver = started(&committee, validator(0));
    let reserved = produce(&mut driver);
    let mut signer = (
        SymbolicSigner::new(committee.signers[0].clone()),
        SymbolicPersistence,
    );
    driver.drain(&mut signer, reserved.into_capabilities());
    let block = driver.machine().chain_layer().tip(ChainId::new(0));
    assert_eq!(block.height(), Height::new(1));

    driver.advance(60).unwrap();
    let now = driver.now();
    let quorum = committee.codec().view_quorum() as u32;
    for signer in 1..quorum {
        driver.machine_mut().note_endorsement(
            Participant::new(signer),
            View::new(1),
            block,
            now,
            now,
        );
    }
    assert_eq!(driver.machine_mut().delay_estimator().estimate(), None);
    driver
        .machine_mut()
        .note_endorsement(Participant::new(quorum), View::new(1), block, now, now);
    let vote = millis(driver.machine().profile().tuning().vote_interval);
    assert_eq!(
        driver.machine_mut().delay_estimator().estimate(),
        Some((60 - vote) / 2)
    );
}

#[test]
fn a_saturated_local_queue_does_not_inflate_delta_hat() {
    let committee = committee(135);
    let mut driver = started(&committee, validator(0));
    let reserved = produce(&mut driver);
    let mut signer = (
        SymbolicSigner::new(committee.signers[0].clone()),
        SymbolicPersistence,
    );
    driver.drain(&mut signer, reserved.into_capabilities());
    let block = driver.machine().chain_layer().tip(ChainId::new(0));
    assert_eq!(block.height(), Height::new(1));

    // Votes of n - f validators endorsing the block arrive 60 ms after it was produced, but this
    // node's queues hold them, and its own deadlines, for 5 s before the machine reads them.
    let received = driver.now().saturating_add(60);
    driver.elapse(5_000);
    let mut tips = committee.genesis().tips().to_vec();
    tips[block.chain().index()] = block;
    let content = committee.content(
        View::new(1),
        None,
        false,
        committee.endorsement(ChainSet::empty(committee.codec().chains()), tips),
    );
    let votes = (1..=committee.codec().view_quorum() as u32)
        .map(|signer| {
            let update = committee.update(
                Participant::new(signer),
                &content,
                committee.genesis().tips(),
                1,
            );
            let mut vote = Artifact::Update(update).identify::<Sha256>(&mut Vec::new());
            vote.received = Some(received);
            vote
        })
        .collect();
    let observed = driver.submit(Input::Observe(votes)).unwrap();
    driver.verify(&observed.verify_job(), true, Until::Quiesce);

    // The sample is the 60 ms round trip to the votes' arrival, not the 5 s until they were read.
    let vote = millis(driver.machine().profile().tuning().vote_interval);
    assert_eq!(
        driver.machine_mut().delay_estimator().estimate(),
        Some(60u64.saturating_sub(vote) / 2)
    );
}

#[test]
fn accepted_headers_feed_the_production_estimator() {
    let committee = committee(133);
    let mut driver = started(&committee, Role::Observer);
    let chain = ChainId::new(1);
    let blocks = path(&committee, chain, 4);
    receive(&mut driver, &blocks);

    // The first acceptance starts the clock; three heights accepted together 30 ms later took
    // 10 ms each.
    validate(&mut driver, &blocks[0], BlockValidity::Valid);
    driver.advance(30).unwrap();
    validate(&mut driver, &blocks[3], BlockValidity::Valid);
    validate(&mut driver, &blocks[2], BlockValidity::Valid);
    assert_eq!(
        driver
            .machine_mut()
            .production_cadence()
            .chain_interval(chain),
        None
    );
    validate(&mut driver, &blocks[1], BlockValidity::Valid);
    assert_eq!(
        driver
            .machine_mut()
            .production_cadence()
            .chain_interval(chain),
        Some(10_000)
    );
}
