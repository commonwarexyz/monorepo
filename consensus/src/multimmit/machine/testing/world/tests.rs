//! World runs: fair, randomized, byte-scheduled, and crashing at every durable prefix, all under
//! the oracles.

use super::{Broadcast, Config, Cut, Seeded, World, exercise};
use crate::{multimmit::mocks::Committee, types::View};

/// Simulated time a run may take to reach its target.
const BUDGET: u64 = 60_000;

fn world(seed: u64) -> World {
    World::new(
        Config::correct(Committee::builder(seed, 6).build()),
        Broadcast,
    )
}

/// Runs the fair suffix until every node resolved `views` more views than the furthest node had,
/// with a leader block finalized in the last two of them.
fn progress(world: &mut World, views: u64) {
    let furthest = world.resolved_views().into_iter().max().unwrap_or_default();
    let target = View::new(furthest.get() + views);
    world.run_to(BUDGET, target, View::new(target.get() - 1));
}

#[test]
fn a_fair_world_resolves_and_finalizes_views_in_agreement() {
    let mut world = world(1);
    progress(&mut world, 6);
    assert!(world.oracle().delivered() > 0, "blocks are ordered");
    assert!(world.oracle().quarantines().is_empty());
    world.check_replay();
}

#[test]
fn randomized_schedules_keep_every_oracle_and_recover() {
    for seed in 0..8 {
        let mut world = world(100 + seed);
        world.adversarial(&mut Seeded::new(seed, 20_000));
        progress(&mut world, 3);
        assert!(world.oracle().quarantines().is_empty(), "seed {seed}");
        world.check_replay();
    }
}

#[test]
fn a_crash_at_every_durable_prefix_recovers_without_breaking_an_oracle() {
    for barrier in 1..=16 {
        for cut in [Cut::BeforeAppend, Cut::BeforeAcknowledge] {
            let mut world = world(200);
            world.crash_at(0, barrier, cut);
            progress(&mut world, 4);
            assert!(
                world.crash_pending().is_none(),
                "barrier {barrier} {cut:?} was reached"
            );
            world.check_replay();
        }
    }
}

#[test]
fn byte_schedules_keep_every_oracle() {
    let patterns: [&[u8]; 4] = [
        &[],
        &[0x13; 512],
        &[1, 15, 2, 3, 15, 0, 7, 4, 9, 15, 2, 1, 12, 5, 5, 0, 0, 3],
        &(0..=255).cycle().take(2_048).collect::<Vec<u8>>(),
    ];
    for data in patterns {
        exercise(data);
    }
}
