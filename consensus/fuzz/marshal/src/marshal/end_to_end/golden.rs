//! Auditor states of ordinary end-to-end runs, recorded before the drivers had a
//! prefix hook: a driver called without a prefix runs exactly what it ran.

use super::{
    FloorStart, MarshalDisrupterInput, MarshalTwinsInput, block_disrupter,
    runner::{force_poison, run_coding_disrupter, run_standard_disrupter},
    twins::{
        run_coding_twins, run_split_header_twins, run_standard_twins,
        stack::{DeferredMarshal, InlineMarshal, MarshalChoice},
    },
};
use commonware_consensus::{simplex::ForwardPolicy, types::TermLength};
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
    runs.push((
        "standard disrupter connected",
        state,
        "c44801a872e76c116131ab026b0c882ed659b47ebecb5cd6ec8ac04a70db482e",
    ));
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
    runs.push((
        "standard disrupter static",
        state,
        "871849e38cdf6f10274e67527c09bb88fce4c766cf28c2f09cb6f36733bcf0b2",
    ));
    let mut poisoned = disrupter_input(vec![13], 4, Partition::Connected, StrategyChoice::AnyScope);
    force_poison(&mut poisoned);
    let (state, _, _) = run_standard_disrupter::<SimplexCertificateMock>(
        poisoned,
        Some(CertificatePoison::new()),
        None,
        None,
    );
    runs.push((
        "standard certificate poison",
        state,
        "d3ab460dea5e0f698ee312a6729b9250fdc2fba809a0164a07ee5c903f33a07e",
    ));
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
    runs.push((
        "standard block dissemination",
        state,
        "bc3dea98eee8668b3bb5de3b2b8d5d8575920eb0f20bb19d62b7f83409489b30",
    ));
    let (state, _) = run_coding_disrupter::<SimplexCertificateMock>(
        disrupter_input(vec![15], 2, Partition::Connected, small(1)),
        false,
        None,
    );
    runs.push((
        "coding disrupter",
        state,
        "8643205625e7ea502a16562b211481772d5d11ec49cc7c8ec299043607d7f5bc",
    ));
    let mut poisoned = disrupter_input(vec![16], 4, Partition::Connected, StrategyChoice::AnyScope);
    force_poison(&mut poisoned);
    let (state, _) = run_coding_disrupter::<SimplexCertificateMock>(poisoned, true, None);
    runs.push((
        "coding block poison",
        state,
        "7499cffe13f38f90cb9f51f1d7684a5df368ffb2d522656237b33b1de7de6e33",
    ));

    let (floor, state, _) = run_standard_twins(twins_input(vec![0, 0b11_0000], 2), None);
    assert_eq!(floor, None);
    runs.push((
        "standard twins",
        state,
        "c7a9101f9e066dc9745e58eacb3b1accb5d2809d04017220fcb6d6abeeb30d69",
    ));
    // A floor node anchored at height 3 (the input of the floor-join test).
    let mut floored = twins_input(vec![0, 0b11_0000], 1);
    floored.strategy = small(1);
    floored.trailing_blocks = 2;
    floored.floor = Some(FloorStart { slot: 1, height: 3 });
    let (floor, state, _) = run_standard_twins(floored, None);
    assert!(floor.is_some(), "no node joined from the floor");
    runs.push((
        "standard twins floor",
        state,
        "aa91333aab70ebefa9fe5db1fc2b101197d6366b194816d391201950d5b4c240",
    ));
    let (_, state, _) = run_split_header_twins::<DeferredMarshal>(
        twins_input(vec![0; 4], 4),
        MarshalChoice::Deferred,
        None,
    );
    runs.push((
        "split header deferred",
        state,
        "aac8ae21dc5877dea801143cbbe529f8237972cd4a8179cab4c464643cbefbf4",
    ));
    let (_, state, _) = run_split_header_twins::<InlineMarshal>(
        twins_input(vec![0; 4], 4),
        MarshalChoice::Inline,
        None,
    );
    runs.push((
        "split header inline",
        state,
        "1871ec112c668be3b7871b198dd027ac1398eceb8d0e67f13cb869be82b0353c",
    ));
    let mut coding = twins_input(vec![0], 1);
    coding.strategy = small(1);
    let (state, _) = run_coding_twins::<SimplexCertificateMock>(coding, None);
    runs.push((
        "coding twins",
        state,
        "b6b477739eb261c362cbd2817f4d15ee9f2f702bd369d734b3f1ed493b39ef7e",
    ));

    let changed: Vec<String> = runs
        .iter()
        .filter(|(_, state, expected)| state != expected)
        .map(|(name, state, _)| format!("{name}: {state}"))
        .collect();
    assert!(changed.is_empty(), "changed runs:\n{}", changed.join("\n"));
}
