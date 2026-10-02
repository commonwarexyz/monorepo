//! Bounded differential checks of native NEON and its emulator.

use super::NativeNeon;
use crate::{Neon, Operation, Simd, emulated::EmulatedNeon};
use arbitrary::{Arbitrary, Unstructured};
use core::arch::aarch64::{uint64x2_t, vdupq_n_u64, vgetq_lane_u64, vsetq_lane_u64};
#[cfg(test)]
use std::panic::{AssertUnwindSafe, catch_unwind};

const BOUNDARIES: [u64; 8] = [
    0,
    1,
    u64::MAX,
    u64::MAX - 1,
    1 << 63,
    (1 << 63) - 1,
    0xaaaa_aaaa_aaaa_aaaa,
    0x5555_5555_5555_5555,
];

/// One native primitive or operation-dispatch check.
#[derive(Clone, Copy, Debug, Arbitrary)]
pub enum Plan {
    /// Loads lanes in order from a slice offset by one `u64`.
    Load,
    /// Stores lanes without changing the surrounding words.
    Store,
    /// Broadcasts an arbitrary or boundary word to both lanes.
    Splat,
    /// Adds arbitrary or boundary lanes modulo `2^64`.
    Add,
    /// Rejects short memory slices, leaving failed stores untouched.
    ///
    /// Available only in tests because libFuzzer aborts on expected panics.
    #[cfg(test)]
    ShortMemory,
    /// Selects NEON for direct and nested child operations.
    Execute,
}

fn word(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    if u.arbitrary()? {
        u.arbitrary()
    } else {
        Ok(BOUNDARIES[u.int_in_range(0..=BOUNDARIES.len() - 1)?])
    }
}

fn lanes(u: &mut Unstructured<'_>) -> arbitrary::Result<[u64; 2]> {
    Ok([word(u)?, word(u)?])
}

// Offset one is u64-aligned but deliberately not aligned to a NEON vector.
#[repr(align(16))]
struct Memory([u64; 5]);

#[target_feature(enable = "neon")]
unsafe fn extract_lanes(value: uint64x2_t) -> [u64; 2] {
    [vgetq_lane_u64::<0>(value), vgetq_lane_u64::<1>(value)]
}

fn native_lanes(_: NativeNeon, value: uint64x2_t) -> [u64; 2] {
    // SAFETY: Construction of the token established NEON support.
    unsafe { extract_lanes(value) }
}

#[target_feature(enable = "neon")]
unsafe fn construct_vector(value: [u64; 2]) -> uint64x2_t {
    vsetq_lane_u64::<1>(value[1], vdupq_n_u64(value[0]))
}

fn native_vector(_: NativeNeon, value: [u64; 2]) -> uint64x2_t {
    // SAFETY: Construction of the token established NEON support.
    unsafe { construct_vector(value) }
}

fn output<S: Simd>(s: S, value: S::U64, sentinel: u64) -> [u64; 5] {
    let mut memory = Memory([sentinel; 5]);
    s.u64_store(value, &mut memory.0[1..]);
    memory.0
}

fn check_load(native: NativeNeon, value: [u64; 2], sentinel: u64) {
    let input = Memory([sentinel, value[0], value[1], !sentinel, sentinel]);
    let emulated = EmulatedNeon.u64_load(&input.0[1..]);
    assert_eq!(emulated, value);
    assert_eq!(
        native_lanes(native, native.u64_load(&input.0[1..])),
        emulated
    );
}

fn check_store(native: NativeNeon, value: [u64; 2], sentinel: u64) {
    let expected = [sentinel, value[0], value[1], sentinel, sentinel];
    assert_eq!(
        output(native, native_vector(native, value), sentinel),
        expected
    );
    assert_eq!(output(EmulatedNeon, value, sentinel), expected);
}

fn check_splat(native: NativeNeon, value: u64, sentinel: u64) {
    let emulated = EmulatedNeon.u64_splat(value);
    assert_eq!(emulated, [value; 2]);
    assert_eq!(native_lanes(native, native.u64_splat(value)), emulated);
    assert_eq!(
        output(native, native.u64_splat(value), sentinel),
        [sentinel, value, value, sentinel, sentinel]
    );
}

fn check_add(native: NativeNeon, a: [u64; 2], b: [u64; 2], sentinel: u64) {
    let expected = [
        sentinel,
        a[0].wrapping_add(b[0]),
        a[1].wrapping_add(b[1]),
        sentinel,
        sentinel,
    ];
    let actual = native.u64_add(native_vector(native, a), native_vector(native, b));
    let emulated = EmulatedNeon.u64_add(a, b);
    assert_eq!(native_lanes(native, actual), emulated);
    assert_eq!(output(native, actual, sentinel), expected);
    assert_eq!(output(EmulatedNeon, emulated, sentinel), expected);
}

#[cfg(test)]
fn check_short<S: Simd>(s: S, value: u64, len: usize) {
    let mut memory = Memory([value; 5]);
    assert!(catch_unwind(AssertUnwindSafe(|| s.u64_load(&memory.0[1..1 + len]))).is_err());
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            s.u64_store(s.u64_splat(!value), &mut memory.0[1..1 + len]);
        }))
        .is_err()
    );
    assert_eq!(memory.0, [value; 5]);
}

#[derive(Clone, Copy)]
struct Child([u64; 2]);

impl Operation for Child {
    type Output = (bool, [u64; 2]);

    fn portable<S: Simd>(self, _: S) -> Self::Output {
        (false, self.0)
    }

    fn neon<S: Neon>(self, s: S) -> Self::Output {
        let value = s.u64_add(s.u64_load(&self.0), s.u64_splat(1));
        let mut result = [0; 2];
        s.u64_store(value, &mut result);
        (true, result)
    }
}

struct Parent<O>(O);

impl<O: Operation> Operation for Parent<O> {
    type Output = O::Output;

    fn portable<S: Simd>(self, s: S) -> Self::Output {
        execute_child(s, self.0)
    }
}

fn execute_child<S: Simd, O: Operation>(s: S, child: O) -> O::Output {
    s.execute(child)
}

fn check_execute(native: NativeNeon, value: [u64; 2]) {
    let expected = (true, value.map(|v| v.wrapping_add(1)));
    assert_eq!(native.execute(Child(value)), expected);
    assert_eq!(EmulatedNeon.execute(Child(value)), expected);
    assert_eq!(native.execute(Parent(Parent(Child(value)))), expected);
    assert_eq!(EmulatedNeon.execute(Parent(Parent(Child(value)))), expected);
}

impl Plan {
    /// Runs the check against native hardware and the emulator.
    ///
    /// Hosts without NEON support perform no hardware checks.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let Some(native) = NativeNeon::new() else {
            return Ok(());
        };
        assert_eq!(NativeNeon::U64_LANES, 2);
        assert_eq!(EmulatedNeon::U64_LANES, 2);
        match self {
            Self::Load => check_load(native, lanes(u)?, word(u)?),
            Self::Store => check_store(native, lanes(u)?, word(u)?),
            Self::Splat => check_splat(native, word(u)?, word(u)?),
            Self::Add => check_add(native, lanes(u)?, lanes(u)?, word(u)?),
            #[cfg(test)]
            Self::ShortMemory => {
                let value = word(u)?;
                let len = u.int_in_range(0..=1)?;
                check_short(native, value, len);
                check_short(EmulatedNeon, value, len);
            }
            Self::Execute => check_execute(native, lanes(u)?),
        }
        Ok(())
    }
}

#[cfg(test)]
fn test_plan(plan: Plan) {
    if !std::arch::is_aarch64_feature_detected!("neon") {
        eprintln!("skipping native NEON differential fuzz: NEON is unavailable");
        return;
    }
    assert!(
        NativeNeon::new().is_some(),
        "NEON hardware must yield a token"
    );
    commonware_invariants::minifuzz::test(|u| plan.run(u));
}

#[test]
fn test_fuzz_load() {
    test_plan(Plan::Load);
}

#[test]
fn test_fuzz_store() {
    test_plan(Plan::Store);
}

#[test]
fn test_fuzz_splat() {
    test_plan(Plan::Splat);
}

#[test]
fn test_fuzz_add() {
    test_plan(Plan::Add);
}

#[test]
fn test_fuzz_short_memory() {
    test_plan(Plan::ShortMemory);
}

#[test]
fn test_fuzz_execute() {
    test_plan(Plan::Execute);
}

#[test]
fn test_boundaries() {
    if !std::arch::is_aarch64_feature_detected!("neon") {
        eprintln!("skipping native NEON boundaries: NEON is unavailable");
        return;
    }
    let native = NativeNeon::new().expect("NEON hardware must yield a token");
    for a in BOUNDARIES {
        check_splat(native, a, !a);
        check_execute(native, [a, !a]);
        for b in BOUNDARIES {
            check_load(native, [a, b], !a);
            check_store(native, [a, b], !a);
            check_add(native, [a, b], [b, a], !a);
        }
        for len in 0..2 {
            check_short(native, a, len);
            check_short(EmulatedNeon, a, len);
        }
    }
}
