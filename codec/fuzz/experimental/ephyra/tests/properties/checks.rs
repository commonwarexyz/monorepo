//! Checks of the generators, shrinkers and mutators behind the properties.
//!
//! `#[ephyra::generator]` marks a support predicate, or a generator together
//! with its predicate. For each marked generator the macro adds an ignored
//! test `__ephyra_check_<name>`: over 10,000 inputs, every generated value,
//! every shrink candidate, every step of the first-candidate shrink chain and
//! every mutant must satisfy the predicate, and shrink chains must settle.
//! `--include-ignored` runs them (see `codec/fuzz/experimental/README.md`).
//!
//! The two plain tests at the end use `check_shrinker` and `check_mutator` on
//! `wide()`, the one generator with a hand-written shrinker.

use crate::{config, generators::*};
use ephyra::prelude::*;
use std::ops::Bound;

// ---------------------------------------------------------------------------
// Support predicates
// ---------------------------------------------------------------------------

#[ephyra::generator]
fn any_u128(_value: &u128) -> bool {
    true
}

#[ephyra::generator]
fn varint_stream(bytes: &[u8]) -> bool {
    bytes.len() <= 24
}

#[ephyra::generator]
fn exactly_32(bytes: &[u8]) -> bool {
    bytes.len() == 32
}

#[ephyra::generator]
fn small_bound(bound: &Bound<usize>) -> bool {
    match bound {
        Bound::Unbounded => true,
        Bound::Included(v) | Bound::Excluded(v) => *v <= 45,
    }
}

#[ephyra::generator]
fn valid_sample(s: &Sample) -> bool {
    s.blob.len() <= 300
        && s.opts.len() <= 24
        && s.nested.len() <= 6
        && s.nested.iter().all(|inner| inner.len() <= 6)
        && s.pairs.len() <= 12
        && s.pairs.iter().all(|(_, value)| value.len() <= 5)
        && s.keys.len() <= 16
        && s.ip.len() == 16
        && s.modes.len() == 4
        && s.modes.iter().all(|m| *m <= 0x7F)
        && s.extra.len() <= 3
}

#[ephyra::generator]
fn valid_limits(l: &Limits) -> bool {
    l.n <= 40 && small_bound(&l.start) && small_bound(&l.end)
}

#[ephyra::generator]
fn valid_mutation(m: &Mutation) -> bool {
    match m {
        Mutation::Keep => true,
        Mutation::Truncate(n) => (1..=40).contains(n),
        Mutation::Flip(at, bit) => *at <= 4095 && *bit <= 7,
        Mutation::Set(at, _) | Mutation::Insert(at, _) | Mutation::Remove(at) => *at <= 4095,
        Mutation::Append(more) => (1..=6).contains(&more.len()),
    }
}

#[ephyra::generator]
fn valid_hostile(h: &Hostile) -> bool {
    h.opts.len() <= 8
        && h.pairs.len() <= 6
        && h.pairs.iter().all(|(_, value)| value.len() <= 4)
        && h.keys.len() <= 6
        && h.blob.len() <= 40
        && h.ip.len() == 16
        && h.count <= LIMIT
        && h.mutations.len() <= 4
        && h.mutations.iter().all(valid_mutation)
        && h.tail.len() <= 24
}

#[ephyra::generator]
fn valid_sized(s: &Sized) -> bool {
    valid_sample(&s.sample) && s.slack <= 300
}

// ---------------------------------------------------------------------------
// Generators, each with its predicate
// ---------------------------------------------------------------------------

#[ephyra::generator(any_u128)]
fn wide_values() -> impl Gen<Value = u128> {
    wide()
}

#[ephyra::generator(varint_stream)]
fn varint_streams() -> impl Gen<Value = Vec<u8>> {
    varint_like()
}

#[ephyra::generator(exactly_32)]
fn raw_32() -> impl Gen<Value = Vec<u8>> {
    raw(32)
}

#[ephyra::generator(small_bound)]
fn bounds() -> impl Gen<Value = Bound<usize>> {
    bound()
}

#[ephyra::generator(valid_sample)]
fn samples() -> impl Gen<Value = Sample> {
    any::<Sample>()
}

#[ephyra::generator(valid_limits)]
fn limits() -> impl Gen<Value = Limits> {
    any::<Limits>()
}

#[ephyra::generator(valid_mutation)]
fn mutations() -> impl Gen<Value = Mutation> {
    any::<Mutation>()
}

#[ephyra::generator(valid_hostile)]
fn hostiles() -> impl Gen<Value = Hostile> {
    any::<Hostile>()
}

#[ephyra::generator(valid_sized)]
fn sizeds() -> impl Gen<Value = Sized> {
    any::<Sized>()
}

// ---------------------------------------------------------------------------
// The hand-written shrinker of `wide()`
// ---------------------------------------------------------------------------

#[test]
fn wide_shrinker_candidates_are_strictly_smaller() {
    let config = config("wide_shrinker").tests(10_000);
    let report = check_shrinker(&config, wide(), |_| true, wide_size);
    println!("{report}");
    report.assert_passed();
}

#[test]
fn wide_mutants_stay_in_the_support() {
    let config = config("wide_mutator").tests(10_000);
    let report = check_mutator(&config, wide(), |_| true);
    println!("{report}");
    report.assert_passed();
}
