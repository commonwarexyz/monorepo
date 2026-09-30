//! Memory probe (resource control, not part of the TCB; AUDIT.md §14): the
//! kernel's step ticker polls the process-wide soft allocation limit of
//! `sandblaster-memguard` and fails with `OutOfFuel` — never success — once the
//! process holds more heap than that limit.
//!
//! This binary has exactly one test: the limits are process-wide, so no
//! other test may run concurrently with the lowered limit.

mod common;

use common::*;
use sandblaster_kernel::term::Lvl;
use sandblaster_kernel::value::{Budget, EvalError, VEnv};

/// A list of `n` elements built by the kernel (non-tail recursion over a
/// literal measure: each element is a separate heap node), then measured.
fn len_of_replicate(n: u64) -> String {
    format!("seq::len U8 (seq::replicate U8 {n}int 7u8)")
}

#[test]
fn soft_memory_limit_makes_large_evaluations_fail_gracefully() {
    // Everything runs on one thread with a large stack (the list is built by
    // non-tail recursion), so that only the memory probe can stop the
    // evaluation.
    std::thread::Builder::new().stack_size(512 << 20).spawn(probe).unwrap().join().unwrap();
}

fn probe() {
    const N: u64 = 50_000;
    sandblaster_kernel::util::set_stack_limit(448 << 20);
    let env = prelude();
    let big = tm(&env, &len_of_replicate(N));
    // `limits`: (hard, soft) limits relative to the heap in use just before.
    let run = |limits: Option<(usize, usize)>| {
        let (old_hard, old_soft) = sandblaster_memguard::limits();
        let before = sandblaster_memguard::allocated();
        if let Some((hard, soft)) = limits {
            sandblaster_memguard::set_limits(before + hard, before + soft);
        }
        let r = env.eval(&VEnv::default(), Lvl(0), &big, &mut Budget { steps: 1 << 40 });
        let peak = sandblaster_memguard::peak().saturating_sub(before);
        sandblaster_memguard::set_limits(old_hard, old_soft);
        let q = r.as_ref().ok().map(|v| env.print_term(&[], &env.quote(Lvl(0), v, false)));
        (r.map(|_| ()), q, peak)
    };
    // With the default limits the evaluation completes; it needs well over
    // the lowered limit below.
    let (r, q, grew) = run(None);
    eprintln!("unrestricted: {r:?}, heap grew by {grew} bytes");
    assert_eq!(r, Ok(()), "unrestricted evaluation");
    assert_eq!(q, Some(format!("{N}int")));
    assert!(grew > 8 << 20, "the evaluation should need more than 8 MiB (grew {grew} bytes)");
    // With a soft limit 1 MiB above the current heap it fails with OutOfFuel
    // shortly after crossing the limit. The hard limit is set 8 MiB above
    // the current heap: had the probe not stopped the evaluation (which
    // needs about 24 MiB), the next allocation would have aborted the test.
    let (r, q, _) = run(Some((8 << 20, 1 << 20)));
    eprintln!("soft limit +1 MiB, hard limit +8 MiB: {r:?}");
    assert_eq!(r, Err(EvalError::OutOfFuel), "lowered soft limit");
    assert_eq!(q, None);
    // A soft limit below the current heap stops any evaluation of more than
    // a handful of steps, including type checking.
    let (hard, soft) = sandblaster_memguard::limits();
    sandblaster_memguard::set_limits(hard, 0);
    let small = env.eval(&VEnv::default(), Lvl(0), &tm(&env, &len_of_replicate(100)), &mut budget()).map(|_| ());
    let checked = check(&env, &len_of_replicate(100), "Int").map_err(|e| e.kind);
    sandblaster_memguard::set_limits(hard, soft);
    assert_eq!(small, Err(EvalError::OutOfFuel));
    assert_eq!(checked, Err(sandblaster_kernel::api::KernelErrorKind::Eval(EvalError::OutOfFuel)));
    // Limits restored: the kernel works again.
    assert_eq!(norm(&env, &len_of_replicate(10)), "10int");
}
