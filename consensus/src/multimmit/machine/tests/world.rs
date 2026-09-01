#[cfg(test)]
use proptest::prelude::*;

#[cfg(test)]
#[test]
fn canonical_fault_schedule_drains_all_locally_answerable_work() {
    exercise(&[]);
}

#[cfg(test)]
proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn honest_replicas_keep_compatible_finality_under_replayable_faults(
        blocks in 2usize..=6,
        proposal_first in any::<[bool; REPLICAS]>(),
        newest_verification in any::<[bool; REPLICAS]>(),
        reverse_votes in any::<[bool; REPLICAS]>(),
        byzantine_full in any::<[bool; REPLICAS]>(),
        reverse_blocks in any::<[bool; REPLICAS]>(),
        malformed_bits in any::<u8>(),
        crash_bits in any::<u8>(),
    ) {
        let (plan, durable) = run_scenario(
            blocks,
            proposal_first,
            newest_verification,
            reverse_votes,
            byzantine_full,
            reverse_blocks,
            malformed_completions(malformed_bits),
            crash_cuts(crash_bits),
        );

        let (_, canonical) = run_scenario(
            blocks,
            proposal_first,
            [false; REPLICAS],
            reverse_votes,
            byzantine_full,
            reverse_blocks,
            malformed_completions(malformed_bits),
            [CrashCut::None; REPLICAS],
        );
        prop_assert_eq!(&durable.finality, &canonical.finality);
        prop_assert_eq!(
            durable.inspections[0].finality_floor(),
            canonical.inspections[0].finality_floor(),
        );

        let replay_fixture = Fixture::new(plan.blocks);
        let replayed = World::replay(&replay_fixture, &plan.actions);
        for replica in 0..REPLICAS {
            replayed.assert_locally_drained(replica);
        }
        prop_assert_eq!(replayed.durable_outcome(), durable);
    }
}
