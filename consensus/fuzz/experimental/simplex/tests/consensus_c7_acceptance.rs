use commonware_consensus::types::{TermLength, View, ViewDelta};
use commonware_consensus_fuzz_simplex::blame::{
    Attack, Call, Outcome, Plant, Trace, attack_at, check_blocks, check_floors, fixed_scenarios,
    run, run_planted,
};
use commonware_utils::NZU32;
use std::{
    panic::{self, AssertUnwindSafe},
    sync::OnceLock,
    time::{Duration, Instant},
};

const RUNS_PER_ATTACK: usize = 12;
const REQUIRED_CONTAINERS: u64 = 60;
const SETTLE: Duration = Duration::from_secs(2);

struct AttackData {
    outcomes: Vec<Outcome>,
    host_time: Duration,
}

static CORRECT: OnceLock<AttackData> = OnceLock::new();
static SILENT: OnceLock<AttackData> = OnceLock::new();
static FLOOD: OnceLock<AttackData> = OnceLock::new();
static BAD_SIGNATURE: OnceLock<AttackData> = OnceLock::new();
static REPLAY: OnceLock<AttackData> = OnceLock::new();
static JUNK: OnceLock<AttackData> = OnceLock::new();
static RUSH_CERTIFICATES: OnceLock<AttackData> = OnceLock::new();
static BAD_CERTIFICATES: OnceLock<AttackData> = OnceLock::new();
static EQUIVOCATE: OnceLock<AttackData> = OnceLock::new();
static EQUIVOCATE_UNSIGNED: OnceLock<AttackData> = OnceLock::new();
static RESOLVER_LIES: OnceLock<AttackData> = OnceLock::new();
static MIXED: OnceLock<AttackData> = OnceLock::new();

fn cell(attack: Attack) -> &'static OnceLock<AttackData> {
    match attack {
        Attack::Correct => &CORRECT,
        Attack::Silent => &SILENT,
        Attack::Flood => &FLOOD,
        Attack::BadSignature => &BAD_SIGNATURE,
        Attack::Replay => &REPLAY,
        Attack::Junk => &JUNK,
        Attack::RushCertificates => &RUSH_CERTIFICATES,
        Attack::BadCertificates => &BAD_CERTIFICATES,
        Attack::Equivocate => &EQUIVOCATE,
        Attack::EquivocateUnsigned => &EQUIVOCATE_UNSIGNED,
        Attack::ResolverLies => &RESOLVER_LIES,
        Attack::Mixed => &MIXED,
    }
}

fn attack_position(attack: Attack) -> usize {
    Attack::ALL
        .iter()
        .position(|candidate| *candidate == attack)
        .expect("every attack is listed")
}

fn expected_window(index: usize) -> (usize, Vec<usize>, Duration, Duration) {
    let node = 3 - index;
    let from = (1..=3).filter(|candidate| *candidate != node).collect();
    let cut_at = Duration::from_millis(3_000 + 4_500 * index as u64);
    let restored_at = cut_at + Duration::from_millis(1_500);
    (node, from, cut_at, restored_at)
}

fn assert_clean_outcome(
    expected: &commonware_consensus_fuzz_simplex::blame::Scenario,
    outcome: &Outcome,
) {
    assert_eq!(&outcome.scenario, expected);
    assert_eq!(outcome.participants.len(), 4);
    assert_eq!(outcome.nodes.len(), 3);
    assert!(outcome.nodes.iter().map(|node| node.index).eq(1..=3));
    assert!(
        outcome
            .nodes
            .iter()
            .all(|node| node.finalized >= REQUIRED_CONTAINERS)
    );
    assert!(outcome.measured_at >= outcome.finalized_at + SETTLE);
    assert_eq!(outcome.windows.len(), 3);
    for (index, window) in outcome.windows.iter().enumerate() {
        let (node, from, cut_at, restored_at) = expected_window(index);
        assert_eq!(window.node, node);
        assert_eq!(window.from, from);
        assert_eq!(window.cut_at, cut_at);
        assert_eq!(window.restored_at, restored_at);
    }
    assert!(
        outcome
            .calls
            .iter()
            .all(|call| { (1..=3).contains(&call.blocker) && (0..=3).contains(&call.blocked) })
    );
    check_blocks(&outcome.blocked).expect("a clean run must not block an honest participant");
}

fn initialize(attack: Attack) -> AttackData {
    let first = attack_position(attack) * RUNS_PER_ATTACK;
    let scenarios: Vec<_> = fixed_scenarios()
        .into_iter()
        .skip(first)
        .take(RUNS_PER_ATTACK)
        .collect();
    let started = Instant::now();
    let outcomes: Vec<_> = scenarios
        .iter()
        .map(|scenario| {
            let outcome = run(scenario);
            assert_clean_outcome(scenario, &outcome);
            outcome
        })
        .collect();
    let host_time = started.elapsed();
    AttackData {
        outcomes,
        host_time,
    }
}

fn data(attack: Attack) -> &'static AttackData {
    cell(attack).get_or_init(|| initialize(attack))
}

fn outcomes(attack: Attack) -> &'static [Outcome] {
    &data(attack).outcomes
}

fn panic_text(f: impl FnOnce()) -> String {
    let payload = panic::catch_unwind(AssertUnwindSafe(f)).expect_err("the control must panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&'static str>()
                .map(|text| (*text).to_owned())
        })
        .unwrap_or_else(|| "<non-string panic>".to_owned())
}

fn calls_on_byzantine(outcome: &Outcome, node: usize) -> usize {
    outcome
        .calls
        .iter()
        .filter(|call| call.blocker == node && call.blocked == 0)
        .count()
}

fn min_calls(outcomes: &[Outcome]) -> [usize; 3] {
    [1, 2, 3].map(|node| {
        outcomes
            .iter()
            .map(|outcome| calls_on_byzantine(outcome, node))
            .min()
            .unwrap()
    })
}

fn range(outcomes: &[Outcome], value: impl Fn(&Outcome) -> u64) -> (u64, u64) {
    let mut values = outcomes.iter().map(value);
    let first = values.next().unwrap();
    values.fold((first, first), |(minimum, maximum), value| {
        (minimum.min(value), maximum.max(value))
    })
}

fn minimum_fallbacks(outcomes: &[Outcome]) -> [u64; 3] {
    [1, 2, 3].map(|node| {
        outcomes
            .iter()
            .map(|outcome| {
                outcome
                    .nodes
                    .iter()
                    .find(|measured| measured.index == node)
                    .unwrap()
                    .fallbacks
            })
            .min()
            .unwrap()
    })
}

fn floor_evidence(attack: Attack, outcomes: &[Outcome]) -> String {
    match attack {
        Attack::Correct => format!(
            "echoes={:?} proposals={:?} fetched_sum={}",
            range(outcomes, |outcome| outcome.trace.echoes),
            range(outcomes, |outcome| outcome.trace.proposals),
            outcomes
                .iter()
                .flat_map(|outcome| &outcome.nodes)
                .map(|node| node.fetched)
                .sum::<u64>()
        ),
        Attack::Silent => "calls=0 non_request_counters=0".to_owned(),
        Attack::Flood => format!(
            "flood_votes={:?} flood_certificates={:?} flood_requests={:?}",
            range(outcomes, |outcome| outcome.trace.flood_votes),
            range(outcomes, |outcome| outcome.trace.flood_certificates),
            range(outcomes, |outcome| outcome.trace.flood_requests)
        ),
        Attack::BadSignature => format!(
            "bad_signatures={:?} fallbacks_min={:?}",
            range(outcomes, |outcome| outcome.trace.bad_signatures),
            minimum_fallbacks(outcomes)
        ),
        Attack::Replay => format!(
            "replayed={:?} forged_signers={:?}",
            range(outcomes, |outcome| outcome.trace.replayed),
            range(outcomes, |outcome| outcome.trace.forged_signers)
        ),
        Attack::Junk => format!("junk={:?}", range(outcomes, |outcome| outcome.trace.junk)),
        Attack::RushCertificates => format!(
            "rushed={:?} relayed={:?} calls=0",
            range(outcomes, |outcome| outcome.trace.rushed),
            range(outcomes, |outcome| outcome.trace.relayed)
        ),
        Attack::BadCertificates => format!(
            "bad_certificates={:?}",
            range(outcomes, |outcome| outcome.trace.bad_certificates)
        ),
        Attack::Equivocate | Attack::EquivocateUnsigned => format!(
            "equivocations={:?} nodes_seen={:?}",
            range(outcomes, |outcome| outcome.trace.equivocations),
            [1, 2, 3].map(|node| {
                outcomes
                    .iter()
                    .filter(|outcome| calls_on_byzantine(outcome, node) > 0)
                    .count()
            })
        ),
        Attack::ResolverLies => format!(
            "stale_parents={:?} answers={:?} guesses={:?}",
            range(outcomes, |outcome| outcome.trace.stale_parents),
            range(outcomes, |outcome| outcome.trace.answers),
            range(outcomes, |outcome| outcome.trace.guesses)
        ),
        Attack::Mixed => format!(
            "flood_votes={:?} bad_signatures={:?} replayed={:?} junk={:?} rushed={:?} relayed={:?} bad_certificates={:?} equivocations={:?} fallbacks_min={:?}",
            range(outcomes, |outcome| outcome.trace.flood_votes),
            range(outcomes, |outcome| outcome.trace.bad_signatures),
            range(outcomes, |outcome| outcome.trace.replayed),
            range(outcomes, |outcome| outcome.trace.junk),
            range(outcomes, |outcome| outcome.trace.rushed),
            range(outcomes, |outcome| outcome.trace.relayed),
            range(outcomes, |outcome| outcome.trace.bad_certificates),
            range(outcomes, |outcome| outcome.trace.equivocations),
            minimum_fallbacks(outcomes)
        ),
    }
}

fn check_attack(attack: Attack) {
    let data = data(attack);
    check_floors(attack, &data.outcomes).unwrap();
    println!(
        "attack={attack:?} runs={} min_calls={:?} floors={} host_ms={}",
        data.outcomes.len(),
        min_calls(&data.outcomes),
        floor_evidence(attack, &data.outcomes),
        data.host_time.as_millis()
    );
}

macro_rules! attack_test {
    ($name:ident, $attack:expr) => {
        #[test]
        fn $name() {
            check_attack($attack);
        }
    };
}

attack_test!(blame_grid_correct, Attack::Correct);
attack_test!(blame_grid_silent, Attack::Silent);
attack_test!(blame_grid_flood, Attack::Flood);
attack_test!(blame_grid_bad_signature, Attack::BadSignature);
attack_test!(blame_grid_replay, Attack::Replay);
attack_test!(blame_grid_junk, Attack::Junk);
attack_test!(blame_grid_rush_certificates, Attack::RushCertificates);
attack_test!(blame_grid_bad_certificates, Attack::BadCertificates);
attack_test!(blame_grid_equivocate, Attack::Equivocate);
attack_test!(blame_grid_equivocate_unsigned, Attack::EquivocateUnsigned);
attack_test!(blame_grid_resolver_lies, Attack::ResolverLies);
attack_test!(blame_grid_mixed, Attack::Mixed);

#[test]
fn blame_attack_selection() {
    for view in 0..=17 {
        assert_eq!(
            attack_at(Attack::Mixed, View::new(view)),
            Attack::CYCLE[(view % 9) as usize]
        );
        assert_eq!(attack_at(Attack::Replay, View::new(view)), Attack::Replay);
    }
    assert_eq!(attack_at(Attack::Flood, View::new(8)), Attack::Flood);
    assert_eq!(attack_at(Attack::Flood, View::new(16)), Attack::Flood);
    assert_eq!(attack_at(Attack::Flood, View::new(9)), Attack::Correct);
}

#[test]
fn blame_fixed_scenarios() {
    let configurations = [(1, 0), (5, 0), (5, 5), (3, 1)];
    let scenarios = fixed_scenarios();
    assert_eq!(scenarios.len(), 144);
    for (index, scenario) in scenarios.iter().enumerate() {
        let attack = Attack::ALL[index / RUNS_PER_ATTACK];
        let configuration = configurations[(index % RUNS_PER_ATTACK) / 3];
        assert_eq!(scenario.attack, attack, "scenario {index}");
        assert_eq!(
            scenario.term_length,
            TermLength::new(NZU32!(configuration.0))
        );
        assert_eq!(scenario.optimistic_views, ViewDelta::new(configuration.1));
        assert_eq!(scenario.seed, (index % 3) as u64);
    }
    assert_eq!(scenarios[0].attack, Attack::Correct);
    assert_eq!(scenarios[36].attack, Attack::BadSignature);
    assert_eq!(scenarios[132].attack, Attack::Mixed);
}

fn assert_i1_error(blocked: &[(usize, usize)], blocker: usize, honest: usize) {
    let error = check_blocks(blocked).expect_err("an honest blocked identity must fail");
    assert!(error.starts_with("C7-I1"));
    assert!(error.contains(&blocker.to_string()));
    assert!(error.contains(&honest.to_string()));
}

#[test]
fn blame_block_oracle() {
    assert!(check_blocks(&[]).is_ok());
    assert!(check_blocks(&[(1, 0), (2, 0), (3, 0)]).is_ok());
    assert_i1_error(&[(1, 2)], 1, 2);
    assert_i1_error(&[(1, 0), (3, 2)], 3, 2);
    assert_i1_error(&[(0, 1)], 0, 1);
}

#[test]
fn blame_run_delegates_and_replays_deterministically() {
    let scenarios = fixed_scenarios();
    let s0_first = run(&scenarios[0]);
    let s0_second = run(&scenarios[0]);
    let s0_delegated = run_planted(&scenarios[0], None);
    assert_eq!(s0_first, s0_second);
    assert_eq!(s0_first, s0_delegated);

    let s132_first = run(&scenarios[132]);
    let s132_second = run(&scenarios[132]);
    assert_eq!(s132_first, s132_second);
}

#[test]
fn blame_direct_block_control() {
    let scenario = &fixed_scenarios()[0];
    let text = panic_text(|| {
        run_planted(scenario, Some(Plant::DirectBlock { from: 1, to: 2 }));
    });
    assert!(text.starts_with("C7-I1"), "{text}");
    assert!(text.contains('1') && text.contains('2'), "{text}");

    let outcome = run_planted(scenario, Some(Plant::DirectBlock { from: 3, to: 0 }));
    assert_eq!(outcome.blocked, vec![(3, 0)]);
}

#[test]
fn blame_corrupt_votes_control() {
    let scenario = &fixed_scenarios()[0];
    for node in 1..=3 {
        let text = panic_text(|| {
            run_planted(scenario, Some(Plant::CorruptVotes { node }));
        });
        assert!(text.starts_with("C7-I1"), "node {node}: {text}");
        assert!(text.contains(&format!("participant {node}")), "{text}");
    }
}

#[test]
fn blame_corrupt_certificates_control() {
    let scenario = &fixed_scenarios()[0];
    for node in 1..=3 {
        let text = panic_text(|| {
            run_planted(scenario, Some(Plant::CorruptCertificates { node }));
        });
        assert!(text.starts_with("C7-I1"), "node {node}: {text}");
        assert!(text.contains(&format!("participant {node}")), "{text}");
    }
}

#[test]
fn blame_corrupt_responses_control() {
    let clean = outcomes(Attack::Correct);
    let selected = clean
        .iter()
        .position(|outcome| outcome.nodes.iter().map(|node| node.fetched).sum::<u64>() >= 1)
        .expect("C7-I2 vacuous: F-0b: no Correct scenario fetched a response");
    assert_eq!(selected, 0, "the pinned resolver scenario drifted");
    let scenario = clean[selected].scenario.clone();
    let text = panic_text(|| {
        run_planted(&scenario, Some(Plant::CorruptResponses));
    });
    assert!(text.starts_with("C7-I1"), "{text}");
}

fn assert_floor_error(attack: Attack, outcomes: &[Outcome], floor: &str) {
    let error = check_floors(attack, outcomes).expect_err("the planted floor must fail");
    assert!(
        error.starts_with(&format!("C7-I2 vacuous: {floor}:")),
        "wrong floor: {error}"
    );
}

fn assert_input_error(attack: Attack, outcomes: &[Outcome]) {
    let error = check_floors(attack, outcomes).expect_err("malformed floor input must fail");
    assert!(error.starts_with("C7-I2 input:"), "{error}");
}

fn remove_calls(outcomes: &mut [Outcome], node: usize) {
    for outcome in outcomes {
        outcome.calls.retain(|call| call.blocker != node);
    }
}

fn set_counter(trace: &mut Trace, name: &str, value: u64) {
    match name {
        "echoes" => trace.echoes = value,
        "proposals" => trace.proposals = value,
        "flood_votes" => trace.flood_votes = value,
        "flood_certificates" => trace.flood_certificates = value,
        "flood_requests" => trace.flood_requests = value,
        "bad_signatures" => trace.bad_signatures = value,
        "replayed" => trace.replayed = value,
        "forged_signers" => trace.forged_signers = value,
        "junk" => trace.junk = value,
        "rushed" => trace.rushed = value,
        "relayed" => trace.relayed = value,
        "bad_certificates" => trace.bad_certificates = value,
        "equivocations" => trace.equivocations = value,
        "stale_parents" => trace.stale_parents = value,
        "requests_heard" => trace.requests_heard = value,
        "answers" => trace.answers = value,
        "guesses" => trace.guesses = value,
        _ => panic!("unknown trace counter {name}"),
    }
}

#[test]
fn blame_floor_input_validation() {
    let clean = outcomes(Attack::Correct);
    assert!(check_floors(Attack::Correct, clean).is_ok());
    assert_input_error(Attack::Correct, &[]);
    assert_input_error(Attack::Correct, &clean[..11]);

    let mut thirteen = clean.to_vec();
    thirteen.push(clean[0].clone());
    assert_input_error(Attack::Correct, &thirteen);

    let mut wrong_attack = clean.to_vec();
    wrong_attack[0].scenario.attack = Attack::Silent;
    assert_input_error(Attack::Correct, &wrong_attack);

    let mut swapped = clean.to_vec();
    swapped.swap(0, 1);
    assert_input_error(Attack::Correct, &swapped);

    let mut duplicated = clean.to_vec();
    duplicated[1] = duplicated[0].clone();
    assert_input_error(Attack::Correct, &duplicated);

    let mut wrong_configuration = clean.to_vec();
    wrong_configuration[0].scenario.seed = u64::MAX;
    assert_input_error(Attack::Correct, &wrong_configuration);
}

#[test]
fn blame_swallowed_block_control() {
    let mut planted = outcomes(Attack::BadSignature).to_vec();
    let scenario = fixed_scenarios()[36].clone();
    planted[0] = run_planted(&scenario, Some(Plant::SwallowBlocks { node: 1 }));
    check_blocks(&planted[0].blocked).unwrap();
    assert_floor_error(Attack::BadSignature, &planted, "F-3");
    let error = check_floors(Attack::BadSignature, &planted).unwrap_err();
    assert!(error.contains("scenario 36"), "{error}");
    assert!(error.contains("node 1"), "{error}");
}

#[test]
fn blame_floor_controls_correct() {
    let clean = outcomes(Attack::Correct);
    for counter in ["echoes", "proposals"] {
        let mut planted = clean.to_vec();
        set_counter(&mut planted[0].trace, counter, 0);
        assert_floor_error(Attack::Correct, &planted, "F-0a");
    }
    let mut call = clean.to_vec();
    call[0].calls.push(Call {
        blocker: 1,
        blocked: 0,
        at: Duration::ZERO,
    });
    assert_floor_error(Attack::Correct, &call, "F-0a");

    let mut no_fetch = clean.to_vec();
    for outcome in &mut no_fetch {
        for node in &mut outcome.nodes {
            node.fetched = 0;
        }
    }
    assert_floor_error(Attack::Correct, &no_fetch, "F-0b");
}

#[test]
fn blame_floor_controls_silent() {
    let clean = outcomes(Attack::Silent);
    let mut call = clean.to_vec();
    call[0].calls.push(Call {
        blocker: 1,
        blocked: 0,
        at: Duration::ZERO,
    });
    assert_floor_error(Attack::Silent, &call, "F-1");

    for counter in [
        "echoes",
        "proposals",
        "flood_votes",
        "flood_certificates",
        "flood_requests",
        "bad_signatures",
        "replayed",
        "forged_signers",
        "junk",
        "rushed",
        "relayed",
        "bad_certificates",
        "equivocations",
        "stale_parents",
        "answers",
        "guesses",
    ] {
        let mut planted = clean.to_vec();
        set_counter(&mut planted[0].trace, counter, 1);
        assert_floor_error(Attack::Silent, &planted, "F-1");
    }
}

#[test]
fn blame_floor_controls_flood() {
    let clean = outcomes(Attack::Flood);
    for counter in ["flood_votes", "flood_certificates", "flood_requests"] {
        let mut planted = clean.to_vec();
        set_counter(&mut planted[0].trace, counter, 0);
        assert_floor_error(Attack::Flood, &planted, "F-2");
    }
    let mut no_node_two = clean.to_vec();
    remove_calls(&mut no_node_two, 2);
    assert_floor_error(Attack::Flood, &no_node_two, "F-2");
}

#[test]
fn blame_floor_controls_bad_signature() {
    let clean = outcomes(Attack::BadSignature);
    let mut no_counter = clean.to_vec();
    no_counter[0].trace.bad_signatures = 0;
    assert_floor_error(Attack::BadSignature, &no_counter, "F-3");

    let mut no_node_two = clean.to_vec();
    remove_calls(&mut no_node_two, 2);
    assert_floor_error(Attack::BadSignature, &no_node_two, "F-3");

    let mut no_fallback = clean.to_vec();
    no_fallback[0]
        .nodes
        .iter_mut()
        .find(|node| node.index == 3)
        .unwrap()
        .fallbacks = 0;
    assert_floor_error(Attack::BadSignature, &no_fallback, "F-3");
}

#[test]
fn blame_floor_controls_replay() {
    let clean = outcomes(Attack::Replay);
    for counter in ["replayed", "forged_signers"] {
        let mut planted = clean.to_vec();
        set_counter(&mut planted[0].trace, counter, 0);
        assert_floor_error(Attack::Replay, &planted, "F-4");
    }
    let mut no_node_two = clean.to_vec();
    remove_calls(&mut no_node_two, 2);
    assert_floor_error(Attack::Replay, &no_node_two, "F-4");
}

#[test]
fn blame_floor_controls_junk() {
    let clean = outcomes(Attack::Junk);
    let mut no_counter = clean.to_vec();
    no_counter[0].trace.junk = 0;
    assert_floor_error(Attack::Junk, &no_counter, "F-5");
    let mut no_node_two = clean.to_vec();
    remove_calls(&mut no_node_two, 2);
    assert_floor_error(Attack::Junk, &no_node_two, "F-5");
}

#[test]
fn blame_floor_controls_rush_certificates() {
    let clean = outcomes(Attack::RushCertificates);
    for counter in ["rushed", "relayed"] {
        let mut planted = clean.to_vec();
        set_counter(&mut planted[0].trace, counter, 0);
        assert_floor_error(Attack::RushCertificates, &planted, "F-6");
    }
    let mut call = clean.to_vec();
    call[0].calls.push(Call {
        blocker: 1,
        blocked: 0,
        at: Duration::ZERO,
    });
    assert_floor_error(Attack::RushCertificates, &call, "F-6");
}

#[test]
fn blame_floor_controls_bad_certificates() {
    let clean = outcomes(Attack::BadCertificates);
    let mut no_counter = clean.to_vec();
    no_counter[0].trace.bad_certificates = 0;
    assert_floor_error(Attack::BadCertificates, &no_counter, "F-7");
    let mut no_node_two = clean.to_vec();
    remove_calls(&mut no_node_two, 2);
    assert_floor_error(Attack::BadCertificates, &no_node_two, "F-7");
}

fn check_equivocation_controls(attack: Attack, floor: &str) {
    let clean = outcomes(attack);
    let mut no_counter = clean.to_vec();
    no_counter[0].trace.equivocations = 0;
    assert_floor_error(attack, &no_counter, floor);

    let mut no_run_calls = clean.to_vec();
    no_run_calls[0].calls.clear();
    assert_floor_error(attack, &no_run_calls, floor);

    let mut no_node_three = clean.to_vec();
    remove_calls(&mut no_node_three, 3);
    assert_floor_error(attack, &no_node_three, floor);
}

#[test]
fn blame_floor_controls_equivocate() {
    check_equivocation_controls(Attack::Equivocate, "F-8");
}

#[test]
fn blame_floor_controls_equivocate_unsigned() {
    check_equivocation_controls(Attack::EquivocateUnsigned, "F-9");
}

#[test]
fn blame_floor_controls_resolver_lies() {
    let clean = outcomes(Attack::ResolverLies);
    for counter in ["stale_parents", "answers", "guesses"] {
        let mut planted = clean.to_vec();
        set_counter(&mut planted[0].trace, counter, 0);
        assert_floor_error(Attack::ResolverLies, &planted, "F-10");
    }
    let mut no_node_two = clean.to_vec();
    remove_calls(&mut no_node_two, 2);
    assert_floor_error(Attack::ResolverLies, &no_node_two, "F-10");
}

#[test]
fn blame_floor_controls_mixed() {
    let clean = outcomes(Attack::Mixed);
    for counter in [
        "flood_votes",
        "bad_signatures",
        "replayed",
        "junk",
        "rushed",
        "relayed",
        "bad_certificates",
        "equivocations",
    ] {
        let mut planted = clean.to_vec();
        set_counter(&mut planted[0].trace, counter, 0);
        assert_floor_error(Attack::Mixed, &planted, "F-11");
    }
    let mut no_node_two = clean.to_vec();
    remove_calls(&mut no_node_two, 2);
    assert_floor_error(Attack::Mixed, &no_node_two, "F-11");

    let mut no_fallback = clean.to_vec();
    no_fallback[0]
        .nodes
        .iter_mut()
        .find(|node| node.index == 3)
        .unwrap()
        .fallbacks = 0;
    assert_floor_error(Attack::Mixed, &no_fallback, "F-11");
}

#[test]
fn blame_windows_control() {
    let scenarios: Vec<_> = fixed_scenarios()
        .into_iter()
        .take(RUNS_PER_ATTACK)
        .collect();
    let without_windows: Vec<_> = scenarios
        .iter()
        .map(|scenario| run_planted(scenario, Some(Plant::NoWindows)))
        .collect();
    for outcome in &without_windows {
        check_blocks(&outcome.blocked).unwrap();
        assert!(outcome.windows.is_empty());
        assert_eq!(
            outcome.nodes.iter().map(|node| node.fetched).sum::<u64>(),
            0
        );
    }
    assert_floor_error(Attack::Correct, &without_windows, "F-0b");
}

#[test]
fn blame_plant_indices_fail_closed() {
    let scenario = &fixed_scenarios()[0];
    for plant in [
        Plant::DirectBlock { from: 0, to: 0 },
        Plant::DirectBlock { from: 4, to: 0 },
        Plant::DirectBlock { from: 1, to: 4 },
        Plant::CorruptVotes { node: 0 },
        Plant::CorruptVotes { node: 4 },
        Plant::CorruptCertificates { node: 0 },
        Plant::CorruptCertificates { node: 4 },
        Plant::SwallowBlocks { node: 0 },
        Plant::SwallowBlocks { node: 4 },
    ] {
        let text = panic_text(|| {
            run_planted(scenario, Some(plant));
        });
        assert!(text.contains("names participant"), "{plant:?}: {text}");
    }
}

#[test]
fn blame_public_trace_surface() {
    let trace = Trace {
        echoes: 1,
        proposals: 2,
        flood_votes: 3,
        flood_certificates: 4,
        flood_requests: 5,
        bad_signatures: 6,
        replayed: 7,
        forged_signers: 8,
        junk: 9,
        rushed: 10,
        relayed: 11,
        bad_certificates: 12,
        equivocations: 13,
        stale_parents: 14,
        requests_heard: 15,
        answers: 16,
        guesses: 17,
    };
    assert_eq!(trace.clone(), trace);
    assert!(format!("{trace:?}").contains("guesses: 17"));

    let mut outcome = outcomes(Attack::Correct)[0].clone();
    assert_ne!(outcome.trace, trace);
    outcome.trace = trace;
    outcome.calls.push(Call {
        blocker: 1,
        blocked: 0,
        at: Duration::from_millis(1),
    });
    assert_eq!(outcome.calls.last().unwrap().blocked, 0);
}
