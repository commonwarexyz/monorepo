//! Resource bounds of proof search (docs/fix1-reports.md, "prover resource
//! safety"): every prover call must finish — succeed or fail — within its
//! step budget (kernel and front-end work, `auto::meter`), its per-goal
//! deadline and the memory soft limit, even on goals whose facts are the
//! fully unfolded QMDB verifier; exhaustion is a failure, never a success.
//!
//! The reproductions are the refutation goals of the first version of the
//! non-vacuity audit (hypotheses evaluated with every function
//! transparent), which took 56 s (`auto`, lightest configuration, lemma
//! `inputs_accepted`) and 41 s (development prover, 50,000 steps, law
//! `verify_acceptance`), one run growing to 4.2 GB; before this fix, on this
//! machine: 8.2 s / 3 GiB and 19.4 s. The fully specified QMDB (§15 S5)
//! replaced both items; their successors here have the same kind of
//! hypotheses: [`LEMMA`] the unfolded decoder of the exec verifier
//! (`verifier::parse`, which `inputs_accepted`'s `verify_inputs` called),
//! [`LAW`] the unfolded verifier (the spec's `verify`, which the exec
//! `verify` refines; `verify_acceptance` assumed the exec one).
//!
//! The bounds asserted here are generous (the measured times are ~0.1 s and
//! a few ms, the heap growth under 64 MiB) so that a loaded machine does not
//! make the suite flaky. Two calls are the exception: `auto` and the chain
//! at the build's 20M steps on [`LAW`] use every budget they are given (the
//! search case splits the unfolded spec verifier, every step charged), and
//! `auto` is given two (`auto::search::prove_goal`: the retry in the other
//! order of plain search and simplifier has a fresh budget, which QMDB's
//! own proofs need; the pass without casts shares the one before it): those
//! calls are bounded by [`MAX_TIME`] per budget ([`per_budget`]; 6.5 s per
//! budget here, 13 s in all; 21 s when each of `auto`'s three passes had a
//! fresh budget), and the same configurations on a tenth of the budget by
//! [`MAX_TIME`] (1.4 s here: the time follows the charged steps). The tests
//! share process-wide state (the memory limits), so they are serialized.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sandblaster_front::auto::{meter, Auto, AutoConfig};
use sandblaster_front::driver::{self, Checked};
use sandblaster_front::elab::{self, basic::BasicProver, ProverChain};
use sandblaster_front::loader::RealFs;
use sandblaster_front::memguard;
use sandblaster_front::prover::{AutoFailure, Goal, Prover};
use sandblaster_front::target::TargetInfo;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::Tm;
use sandblaster_kernel::value::Budget;

/// Serializes the tests of this binary (memory limits are process-wide).
static SERIAL: Mutex<()> = Mutex::new(());

/// Time bound of one prover call in the assertions.
const MAX_TIME: Duration = Duration::from_secs(10);
/// Bound on the heap growth of one prover call in the assertions.
const MAX_HEAP: usize = 512 << 20;

/// Time bound of a call that uses every step budget it is given:
/// [`MAX_TIME`] per budget, `n` budgets (`auto`: its first pass and the
/// retry in the other order; the standard chain: `basic`'s and `auto`'s).
fn per_budget(n: u32) -> Duration {
    MAX_TIME * n
}

/// The lemma whose hypotheses are a refutation goal: the exec decoder's
/// result, `crate::verifier::parse(proof) == r`.
const LEMMA: &str = "crate::proof::parsed_split";
/// The law whose hypothesis is a refutation goal: the verifier accepts,
/// `verify(root, key, value, proof)`.
const LAW: &str = "crate::laws::verified_proofs_are_small";

fn qmdb_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/mod.rs")
}

fn check_qmdb() -> Checked {
    let c = driver::check(&qmdb_root(), &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    c
}

/// The refutation goal of the hypotheses of `path` (a law or lemma) with
/// every function transparent (the unbounded first audit).
fn transparent_goal(c: &Checked, out: &elab::Output, path: &str) -> (Goal, elab::basic::GoalTerms) {
    let k = c.krate.as_ref().unwrap();
    let id = k.find(path).unwrap_or_else(|| panic!("no item {path}"));
    let d = out.defs.iter().find(|d| d.item == Some(id) && d.global.is_some()).unwrap_or_else(|| panic!("no definition of {path}"));
    let ty = out.env.global_type(d.global.unwrap()).unwrap();
    let f = k.fn_def(id).unwrap();
    let nparams = f.generics.len() + f.params.len();
    let mut b = Budget { steps: 50_000_000 };
    driver::hypotheses_goal(&out.env, &ty, nparams, None, &mut b, 1_000_001, d.span).expect("refutation goal")
}

/// The lightest `auto` configuration.
fn lightest() -> AutoConfig {
    AutoConfig { max_split_depth: 0, max_rewrites: 4, max_deltas: 0, max_nodes: 64, enum_limit: 0, lin_rounds: 1, max_fact_rewrites: 4, max_instances: 4, ..AutoConfig::default() }
}

struct Run {
    elapsed: Duration,
    /// Upper bound of the heap growth during the call (bytes).
    heap: usize,
    ok: bool,
    tried: Vec<String>,
}

fn run(env: &Env, p: &mut dyn Prover, g: &Goal, terms: &elab::basic::GoalTerms, steps: u64) -> Run {
    let before = memguard::allocated();
    // the peak so far must not hide the call's own peak
    assert!(memguard::peak() < before + MAX_HEAP, "the process peak ({} MiB) is already above the bound", memguard::peak() >> 20);
    let t = Instant::now();
    elab::basic::set_goal_terms(Some(terms.clone()));
    let mut b = Budget { steps };
    let r = p.prove(env, g, &mut b);
    elab::basic::set_goal_terms(None);
    let elapsed = t.elapsed();
    let heap = memguard::peak().saturating_sub(before);
    let (ok, tried) = match r {
        Ok(_) => (true, vec![]),
        Err(f) => (false, f.tried),
    };
    Run { elapsed, heap, ok, tried }
}

#[track_caller]
fn assert_bounded(what: &str, r: &Run) {
    assert_bounded_by(what, r, MAX_TIME);
}

#[track_caller]
fn assert_bounded_by(what: &str, r: &Run, max_time: Duration) {
    eprintln!("{what}: ok={} in {:?}, heap growth ≤ {} MiB, last tried: {:?}", r.ok, r.elapsed, r.heap >> 20, r.tried.last());
    assert!(r.elapsed < max_time, "{what}: took {:?} (bound {max_time:?})", r.elapsed);
    assert!(r.heap < MAX_HEAP, "{what}: heap grew by {} MiB", r.heap >> 20);
    // the hypotheses are satisfiable: refuting them would be a bug
    assert!(!r.ok, "{what}: refuted satisfiable hypotheses");
}

/// Both reproductions, and the build's prover configurations, on one
/// elaboration of what the two items need from QMDB: the items they reach
/// (their statements, proofs and every lemma those use; the mutation
/// gate's item filter, `elab::order::filter_closure`), which must all
/// check. The whole of QMDB takes about ten minutes to elaborate, and its
/// verification is `qmdb_gates`' subject, not this test's.
#[test]
fn unfolded_qmdb_refutations_are_bounded() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    memguard::init_from_env();
    let c = check_qmdb();
    let k = c.krate.as_ref().unwrap();
    let seeds = [LEMMA, LAW].map(|p| k.find(p).unwrap_or_else(|| panic!("no item {p}")));
    let items = elab::order::filter_closure(k, seeds);
    let opts = elab::Options { items: Some(std::sync::Arc::new(items)), ..elab::Options::default() };
    let c2 = &c;
    elab::with_big_stack(move || {
        let t = Instant::now();
        let out = &elab::elaborate(k, &mut ProverChain::standard(), &opts);
        eprintln!("elaborated {} definitions in {:?}", out.defs.len(), t.elapsed());
        // everything elaborated checks; the one error is the filter's note
        // that a partial elaboration is not a verification of the crate
        let bad: Vec<&elab::DefRecord> = out.defs.iter().filter(|d| !matches!(d.status, elab::DefStatus::Checked | elab::DefStatus::Deferred(_))).collect();
        assert!(bad.is_empty() && out.obligations.iter().all(|o| o.proven()), "the items must verify: {bad:?}\n{}", out.diags.render(&c2.sm));
        let errors: Vec<&str> = out.diags.list.iter().filter(|d| d.severity == sandblaster_front::diag::Severity::Error).map(|d| d.msg.as_str()).collect();
        assert!(errors.len() == 1 && errors[0].starts_with("partial elaboration"), "{}", out.diags.render(&c2.sm));
        let (ia, ia_terms) = transparent_goal(c2, out, LEMMA);
        let (va, va_terms) = transparent_goal(c2, out, LAW);
        // the heap is measured from here: the elaboration's own peak (above
        // a GiB, freed again) is not the prover calls', and would hide theirs
        memguard::reset_peak();
        // (1) `auto`, lightest configuration, on the lemma (the audit's
        // budget and the elaborator's)
        for steps in [driver::VACUITY_BUDGET, 20_000_000] {
            let r = run(&out.env, &mut Auto::with_config(lightest()), &ia, &ia_terms, steps);
            assert_bounded(&format!("auto (lightest, {steps} steps) on {LEMMA}"), &r);
        }
        // (2) the development prover, 50,000 steps, on the law
        let r = run(&out.env, &mut BasicProver::default(), &va, &va_terms, 50_000);
        assert_bounded(&format!("basic (50k steps) on {LAW}"), &r);
        // (3) the build's configurations (20M steps per prover) on both:
        // within `MAX_TIME`, except `auto` and the chain on the law, whose
        // search uses every budget it is given, within `MAX_TIME` per budget
        for (name, g, t, law) in [(LEMMA, &ia, &ia_terms, false), (LAW, &va, &va_terms, true)] {
            let r = run(&out.env, &mut Auto::new(), g, t, 20_000_000);
            assert_bounded_by(&format!("auto (default, 20M steps) on {name}"), &r, if law { per_budget(2) } else { MAX_TIME });
            let r = run(&out.env, &mut BasicProver::default(), g, t, 20_000_000);
            assert_bounded(&format!("basic (default, 20M steps) on {name}"), &r);
            let r = run(&out.env, &mut ProverChain::standard(), g, t, 20_000_000);
            assert_bounded_by(&format!("standard chain (20M steps) on {name}"), &r, if law { per_budget(3) } else { MAX_TIME });
        }
        // … and on the law with a tenth of that budget, `auto` and the chain
        // within `MAX_TIME`: their time follows the steps they are given
        // (work the meter did not charge would not shrink with the budget)
        let r = run(&out.env, &mut Auto::new(), &va, &va_terms, 2_000_000);
        assert_bounded(&format!("auto (default, 2M steps) on {LAW}"), &r);
        let r = run(&out.env, &mut ProverChain::standard(), &va, &va_terms, 2_000_000);
        assert_bounded(&format!("standard chain (2M steps) on {LAW}"), &r);
        // (4) a tiny deadline stops `auto` even with an unbounded budget
        let cfg = AutoConfig { goal_timeout: Some(Duration::from_millis(1)), max_nodes: u64::MAX, ..AutoConfig::default() };
        let r = run(&out.env, &mut Auto::with_config(cfg), &va, &va_terms, u64::MAX / 4);
        assert_bounded(&format!("auto (1 ms deadline, unbounded budget) on {LAW}"), &r);
        assert!(r.elapsed < Duration::from_secs(5), "{:?}", r.elapsed);
    });
}

/// A prover that does nothing but charge front-end work (the shape of a
/// runaway quote/shift/scan loop) until its goal is exhausted.
struct Spinner {
    units: u64,
}

impl Prover for Spinner {
    fn prove(&mut self, _env: &Env, _g: &Goal, b: &mut Budget) -> Result<Tm, AutoFailure> {
        let _scope = meter::Scope::enter(None, b);
        let mut junk: Vec<Vec<u8>> = Vec::new();
        while meter::spend(self.units) {
            // allocate a little on every round (a growing search state)
            if self.units > 1 {
                junk.push(vec![1u8; 64 << 10]);
            }
        }
        // `settle` zeroes the budget of an exhausted goal
        assert!(!meter::settle(b));
        assert_eq!(b.steps, 0);
        Err(AutoFailure { tried: vec![meter::failure_note()], ..Default::default() })
    }
}

fn dummy_goal(env: &Env) -> Goal {
    use sandblaster_front::prover::{ObligationId, ObligationKind};
    let empty = sandblaster_kernel::util::mk::ind(env.empty_ind(), vec![]);
    let target = env.eval(&Default::default(), sandblaster_kernel::term::Lvl(0), &empty, &mut Budget { steps: 1000 }).unwrap();
    Goal { id: ObligationId(7), kind: ObligationKind::Assert, span: Default::default(), ctx: Default::default(), facts: vec![], target, hints: vec![] }
}

/// The per-goal deadline of the prover chain stops front-end work and is
/// reported in the failure; the step budget (charged front-end work) and
/// the memory soft limit stop it as well.
#[test]
fn deadline_budget_and_memory_limits_stop_front_end_work() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let env = Env::with_prelude();
    let g = dummy_goal(&env);
    // deadline
    let mut chain = ProverChain::new(vec![("spin".into(), Box::new(Spinner { units: 1 }))]);
    chain.timeout = Some(Duration::from_millis(100));
    let t = Instant::now();
    let f = chain.prove(&env, &g, &mut Budget { steps: u64::MAX / 2 }).expect_err("must fail");
    let dt = t.elapsed();
    assert!(dt >= Duration::from_millis(100) && dt < Duration::from_secs(5), "{dt:?}");
    assert!(f.tried.iter().any(|x| x.contains("deadline exceeded") && x.contains("per-goal limit 100 ms")), "{:?}", f.tried);
    // step budget: front-end work alone exhausts it
    let mut chain = ProverChain::new(vec![("spin".into(), Box::new(Spinner { units: 1 }))]);
    let t = Instant::now();
    let f = chain.prove(&env, &g, &mut Budget { steps: 1_000_000 }).expect_err("must fail");
    assert!(t.elapsed() < Duration::from_secs(5));
    assert!(f.tried.iter().any(|x| x.contains("budget exhausted")), "{:?}", f.tried);
    // memory soft limit (process-wide; restored afterwards)
    let (hard, soft) = memguard::limits();
    memguard::set_limits(hard, memguard::allocated() + (16 << 20));
    let mut chain = ProverChain::new(vec![("spin".into(), Box::new(Spinner { units: 4096 }))]);
    let r = chain.prove(&env, &g, &mut Budget { steps: u64::MAX / 2 });
    memguard::set_limits(hard, soft);
    let f = r.expect_err("must fail");
    assert!(f.tried.iter().any(|x| x.contains("memory soft limit exceeded")), "{:?}", f.tried);
}

/// The per-goal heap cap measures the goal's own thread (memguard's
/// per-thread count): another thread's allocations while the goal runs —
/// the mutation gate elaborates its batches on several threads — do not
/// trip it, although the process-wide heap grows past the cap. Negative
/// twin: [`a_goal_that_allocates_past_its_heap_cap_trips_it`].
#[test]
fn a_goals_heap_cap_counts_only_its_own_thread() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    const CAP: usize = 32 << 20;
    let (opened, grown) = (std::sync::Barrier::new(2), std::sync::Barrier::new(2));
    let (reason, process_growth) = std::thread::scope(|s| {
        let goal = s.spawn(|| {
            let _scope = meter::Scope::enter_capped(None, CAP, &Budget { steps: u64::MAX / 2 });
            let before = memguard::allocated();
            opened.wait();
            // the other thread now holds 4x the cap
            grown.wait();
            let process_growth = memguard::allocated().saturating_sub(before);
            let r = meter::check();
            opened.wait();
            (r, process_growth)
        });
        s.spawn(|| {
            opened.wait();
            let big: Vec<u8> = std::hint::black_box(vec![0u8; 4 * CAP]);
            grown.wait();
            // released only after the goal checked its cap
            opened.wait();
            drop(big);
        });
        goal.join().unwrap()
    });
    let trips = meter::take_trips();
    assert!(process_growth >= 4 * CAP, "the process-wide heap grew by {} MiB only", process_growth >> 20);
    assert_eq!(reason, None, "another thread's allocations tripped the goal's heap cap: {trips:?}");
    assert!(trips.is_empty(), "{trips:?}");
}

/// Negative twin of [`a_goals_heap_cap_counts_only_its_own_thread`]: a goal
/// whose own thread allocates past its cap trips it (a safety net, recorded
/// as a trip, never a result).
#[test]
fn a_goal_that_allocates_past_its_heap_cap_trips_it() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    const CAP: usize = 32 << 20;
    let (reason, note, trips) = std::thread::spawn(|| {
        let _scope = meter::Scope::enter_capped(None, CAP, &Budget { steps: u64::MAX / 2 });
        let big: Vec<u8> = std::hint::black_box(vec![0u8; 4 * CAP]);
        let r = meter::check();
        let note = meter::failure_note();
        drop(big);
        (r, note, meter::take_trips())
    })
    .join()
    .unwrap();
    assert_eq!(reason, Some(meter::Exhaustion::GoalHeap), "{note}");
    assert!(note.contains("per-goal heap cap exceeded") && note.contains("cap 32 MiB"), "{note}");
    assert!(trips.iter().any(|t| t.reason == meter::Exhaustion::GoalHeap), "{trips:?}");
}
