#![no_main]

use commonware_cryptography::{Keccak256, fuzz::Plan};
use commonware_parallel::{Manual, Rayon, Strategy as _};
use commonware_utils::NZUsize;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

/// A strategy that splits every operation across four workers, built once and reused across
/// invocations because starting a thread pool is expensive.
static STRATEGY: LazyLock<Manual<Rayon>> =
    LazyLock::new(|| Rayon::new(NZUsize!(4)).unwrap().manual());

fuzz_target!(|plan: Plan<Keccak256>| plan.run(&*STRATEGY));
