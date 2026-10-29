//! Auditor states of ordinary end-to-end runs, recorded before the drivers had a
//! prefix hook: a driver called without a prefix runs exactly what it ran.

use super::{
    FloorStart, HeightOffset, MarshalDisrupterInput, MarshalTwinsInput,
    app::{ApplicationChoice, FaultTable},
    block_disrupter,
    coding_stack::FaultScope,
    runner::{force_poison, run_coding_disrupter, run_standard_disrupter},
    twins::{
        run_coding_twins, run_split_header_twins, run_standard_twins,
        stack::{DeferredMarshal, InlineMarshal, MarshalChoice},
    },
};
use commonware_consensus::{
    Handoff,
    simplex::ForwardPolicy,
    types::{TermLength, ViewDelta},
};
use commonware_consensus_fuzz_core::{
    SimplexCertificateMock, SimplexCertificateMockByzantineFirstLeader,
    network::CertificatePoison,
    strategy::StrategyChoice,
    utils::{Partition, SetPartition},
};
use commonware_utils::{FuzzRng, NZU32};

fn disrupter_input(
    raw_bytes: Vec<u8>,
    required_containers: u64,
    partition: Partition,
    strategy: StrategyChoice,
) -> MarshalDisrupterInput {
    MarshalDisrupterInput {
        raw_bytes,
        required_containers,
        term_length: TermLength::ONE,
        optimistic_views: ViewDelta::zero(),
        handoff: Handoff::Wait,
        height_offset: HeightOffset::Zero,
        application: ApplicationChoice::AlwaysAccept,
        degraded_network: false,
        partition,
        strategy,
        forwarding: ForwardPolicy::Disabled,
    }
}

fn twins_input(raw_bytes: Vec<u8>, rounds: u8) -> MarshalTwinsInput {
    MarshalTwinsInput {
        raw_bytes,
        rounds,
        case_selector: 0,
        sustained: false,
        strategy: StrategyChoice::AnyScope,
        trailing_blocks: 1,
        forwarding: ForwardPolicy::Disabled,
        floor: None,
        term_length: TermLength::ONE,
        optimistic_views: ViewDelta::zero(),
        handoff: Handoff::Wait,
        fault_table: FaultTable::Sampled,
        fault_scope: FaultScope::Term,
    }
}

#[test]
fn ordinary_marshal_runs_are_unchanged() {
    let small = |rounds| StrategyChoice::SmallScope {
        fault_rounds: rounds,
        fault_rounds_bound: rounds,
    };
    let mut runs: Vec<(&str, String, &str)> = Vec::new();

    let (state, _, _) = run_standard_disrupter::<SimplexCertificateMock>(
        disrupter_input(vec![11], 2, Partition::Connected, StrategyChoice::AnyScope),
        None,
        None,
        None,
    );
    runs.push(("standard disrupter connected", state, "e5219942"));
    let (state, _, _) = run_standard_disrupter::<SimplexCertificateMock>(
        disrupter_input(
            vec![12, 34],
            3,
            Partition::Static(SetPartition::n4(5)),
            small(1),
        ),
        None,
        None,
        None,
    );
    runs.push(("standard disrupter static", state, "72f55964"));
    let mut poisoned = disrupter_input(vec![13], 4, Partition::Connected, StrategyChoice::AnyScope);
    force_poison(&mut poisoned);
    let (state, _, _) = run_standard_disrupter::<SimplexCertificateMock>(
        poisoned,
        Some(CertificatePoison::new()),
        None,
        None,
    );
    runs.push(("standard certificate poison", state, "f6ab7e51"));
    let mut dissemination =
        disrupter_input(vec![14], 2, Partition::Connected, StrategyChoice::AnyScope);
    dissemination.term_length = TermLength::new(NZU32!(2));
    let fault = block_disrupter::MarshalBroadcastFault::sample(&mut FuzzRng::new(
        dissemination.raw_bytes.clone(),
    ));
    let (state, _, _) = run_standard_disrupter::<SimplexCertificateMockByzantineFirstLeader>(
        dissemination,
        None,
        Some(fault),
        None,
    );
    runs.push(("standard block dissemination", state, "756728a2"));
    let (state, _) = run_coding_disrupter::<SimplexCertificateMock>(
        disrupter_input(vec![15], 2, Partition::Connected, small(1)),
        false,
        None,
    );
    runs.push(("coding disrupter", state, "6b030d49"));
    let mut poisoned = disrupter_input(vec![16], 4, Partition::Connected, StrategyChoice::AnyScope);
    force_poison(&mut poisoned);
    let (state, _) = run_coding_disrupter::<SimplexCertificateMock>(poisoned, true, None);
    runs.push(("coding block poison", state, "42c97709"));

    let (floor, state, _) = run_standard_twins(twins_input(vec![0, 0b11_0000], 2), None);
    assert_eq!(floor, None);
    runs.push(("standard twins", state, "eba46ef0"));
    // The faulty application (selector bit 0) over the deferred wrapper.
    let (floor, state, _) = run_standard_twins(twins_input(vec![0, 0b11_0001], 2), None);
    assert_eq!(floor, None);
    runs.push(("standard twins faulty", state, "723d3191"));
    // A floor node anchored at height 3 (the input of the floor-join test).
    let mut floored = twins_input(vec![0, 0b11_0000], 1);
    floored.strategy = small(1);
    floored.trailing_blocks = 2;
    floored.floor = Some(FloorStart { slot: 1, height: 3 });
    let (floor, state, _) = run_standard_twins(floored, None);
    assert!(floor.is_some(), "no node joined from the floor");
    runs.push(("standard twins floor", state, "4e2721f6"));
    let (_, state, _) = run_split_header_twins::<DeferredMarshal>(
        twins_input(vec![0; 4], 4),
        MarshalChoice::Deferred,
        None,
    );
    runs.push(("split header deferred", state, "5b95e9c6"));
    let (_, state, _) = run_split_header_twins::<InlineMarshal>(
        twins_input(vec![0; 4], 4),
        MarshalChoice::Inline,
        None,
    );
    runs.push(("split header inline", state, "11979dda"));
    let mut coding = twins_input(vec![0], 1);
    coding.strategy = small(1);
    let (state, _) = run_coding_twins::<SimplexCertificateMock>(coding, None);
    runs.push(("coding twins", state, "3658e7ac"));
    // The faulty application (selector bit 0).
    let mut coding_faulty = twins_input(vec![1], 1);
    coding_faulty.strategy = small(1);
    let (state, _) = run_coding_twins::<SimplexCertificateMock>(coding_faulty, None);
    runs.push(("coding twins faulty", state, "79d9f460"));

    let changed: Vec<String> = runs
        .iter()
        .filter(|(_, state, expected)| state != expected)
        .map(|(name, state, _)| format!("{name}: {state}"))
        .collect();
    assert!(changed.is_empty(), "changed runs:\n{}", changed.join("\n"));
}
