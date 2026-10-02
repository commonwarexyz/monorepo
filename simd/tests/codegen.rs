//! Cross-crate consumers used by `just check-simd-codegen`.
//!
//! Stable symbols allow the check to inspect optimized bodies without depending
//! on Rust symbol hashes. These operations intentionally have no inline hints.

#[cfg(target_arch = "aarch64")]
use commonware_simd::native::NativeNeon;
use commonware_simd::{
    Operation, Simd, dispatch,
    emulated::{EmulatedArmV9, EmulatedIceLake, EmulatedNeon, EmulatedScalar},
};

struct Add<'a> {
    a: &'a [u64; 8],
    b: &'a [u64; 8],
    output: &'a mut [u64; 8],
}

impl Operation for Add<'_> {
    type Output = ();

    fn portable<S: Simd>(self, s: S) {
        let bias = s.u64_splat(self.b[0]);
        for offset in (0..8).step_by(S::U64_LANES) {
            let value = s.u64_add(s.u64_load(&self.a[offset..]), s.u64_load(&self.b[offset..]));
            s.u64_store(s.u64_add(value, bias), &mut self.output[offset..]);
        }
    }
}

struct Parent<O>(O);

impl<O: Operation> Operation for Parent<O> {
    type Output = O::Output;

    fn portable<S: Simd>(self, s: S) -> Self::Output {
        s.execute(self.0)
    }
}

struct AddSlices<'a> {
    a: &'a [u64],
    b: &'a [u64],
    output: &'a mut [u64],
    bias: u64,
}

impl Operation for AddSlices<'_> {
    type Output = ();

    // Associated constants cannot be used as const generic chunk sizes.
    #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
    fn portable<S: Simd>(self, s: S) {
        let bias = s.u64_splat(self.bias);
        for ((a, b), output) in self
            .a
            .chunks_exact(S::U64_LANES)
            .zip(self.b.chunks_exact(S::U64_LANES))
            .zip(self.output.chunks_exact_mut(S::U64_LANES))
        {
            let value = s.u64_add(s.u64_load(a), s.u64_load(b));
            s.u64_store(s.u64_add(value, bias), output);
        }
    }
}

#[unsafe(no_mangle)]
pub fn probe_slice_scalar(a: &[u64], b: &[u64], output: &mut [u64], bias: u64) {
    EmulatedScalar.execute(AddSlices { a, b, output, bias });
}

#[unsafe(no_mangle)]
pub fn probe_slice_emulated_neon(a: &[u64], b: &[u64], output: &mut [u64], bias: u64) {
    EmulatedNeon.execute(AddSlices { a, b, output, bias });
}

#[unsafe(no_mangle)]
pub fn probe_slice_emulated_arm_v9(a: &[u64], b: &[u64], output: &mut [u64], bias: u64) {
    EmulatedArmV9.execute(AddSlices { a, b, output, bias });
}

#[unsafe(no_mangle)]
pub fn probe_slice_emulated_ice_lake(a: &[u64], b: &[u64], output: &mut [u64], bias: u64) {
    EmulatedIceLake.execute(AddSlices { a, b, output, bias });
}

#[unsafe(no_mangle)]
pub fn probe_slice_dispatch(a: &[u64], b: &[u64], output: &mut [u64], bias: u64) {
    dispatch(Parent(Parent(AddSlices { a, b, output, bias })));
}

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub fn probe_slice_native_neon(s: NativeNeon, a: &[u64], b: &[u64], output: &mut [u64], bias: u64) {
    s.execute(Parent(Parent(AddSlices { a, b, output, bias })));
}

#[unsafe(no_mangle)]
pub fn probe_scalar(a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    EmulatedScalar.execute(Add { a, b, output });
}

#[unsafe(no_mangle)]
pub fn probe_emulated_neon(a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    EmulatedNeon.execute(Add { a, b, output });
}

#[unsafe(no_mangle)]
pub fn probe_emulated_arm_v9(a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    EmulatedArmV9.execute(Add { a, b, output });
}

#[unsafe(no_mangle)]
pub fn probe_emulated_ice_lake(a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    EmulatedIceLake.execute(Add { a, b, output });
}

#[unsafe(no_mangle)]
pub fn probe_nested_scalar(a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    EmulatedScalar.execute(Parent(Parent(Add { a, b, output })));
}

#[unsafe(no_mangle)]
pub fn probe_nested_emulated_neon(a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    EmulatedNeon.execute(Parent(Parent(Add { a, b, output })));
}

#[unsafe(no_mangle)]
pub fn probe_nested_emulated_arm_v9(a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    EmulatedArmV9.execute(Parent(Parent(Add { a, b, output })));
}

#[unsafe(no_mangle)]
pub fn probe_nested_emulated_ice_lake(a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    EmulatedIceLake.execute(Parent(Parent(Add { a, b, output })));
}

#[unsafe(no_mangle)]
pub fn probe_dispatch(a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    dispatch(Parent(Parent(Add { a, b, output })));
}

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub fn probe_native_neon(s: NativeNeon, a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    s.execute(Add { a, b, output });
}

#[cfg(target_arch = "aarch64")]
#[unsafe(no_mangle)]
pub fn probe_nested_native_neon(s: NativeNeon, a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    s.execute(Parent(Parent(Add { a, b, output })));
}

// Keep a consumer frame outlined to check feature-scope reentry via execute.
#[cfg(target_arch = "aarch64")]
#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_outlined_neon(s: NativeNeon, a: &[u64; 8], b: &[u64; 8], output: &mut [u64; 8]) {
    s.execute(Parent(Parent(Add { a, b, output })));
}

#[test]
fn test_consumers() {
    commonware_invariants::minifuzz::test(|u| {
        let a: [u64; 8] = u.arbitrary()?;
        let b: [u64; 8] = u.arbitrary()?;
        let expected = core::array::from_fn(|i| a[i].wrapping_add(b[i]).wrapping_add(b[0]));
        for probe in [
            probe_scalar,
            probe_emulated_neon,
            probe_emulated_arm_v9,
            probe_emulated_ice_lake,
            probe_nested_scalar,
            probe_nested_emulated_neon,
            probe_nested_emulated_arm_v9,
            probe_nested_emulated_ice_lake,
            probe_dispatch,
        ] {
            let mut output = [0; 8];
            probe(&a, &b, &mut output);
            assert_eq!(output, expected);
        }
        let len = u.int_in_range(0..=8)?;
        #[cfg(target_arch = "aarch64")]
        let dispatch_lanes = if std::arch::is_aarch64_feature_detected!("neon") {
            2
        } else {
            1
        };
        #[cfg(not(target_arch = "aarch64"))]
        let dispatch_lanes = 1;
        for (probe, lanes) in [
            (probe_slice_scalar as fn(&[u64], &[u64], &mut [u64], u64), 1),
            (probe_slice_emulated_neon, 2),
            (probe_slice_emulated_arm_v9, 2),
            (probe_slice_emulated_ice_lake, 8),
            (probe_slice_dispatch, dispatch_lanes),
        ] {
            check_slices(probe, &a, &b, len, lanes);
        }
        #[cfg(target_arch = "aarch64")]
        if let Some(s) = NativeNeon::new() {
            for probe in [
                probe_native_neon,
                probe_nested_native_neon,
                probe_outlined_neon,
            ] {
                let mut output = [0; 8];
                probe(s, &a, &b, &mut output);
                assert_eq!(output, expected);
            }
            check_slices(
                |a, b, output, bias| probe_slice_native_neon(s, a, b, output, bias),
                &a,
                &b,
                len,
                2,
            );
        }
        Ok(())
    });
}

fn check_slices(
    mut probe: impl FnMut(&[u64], &[u64], &mut [u64], u64),
    a: &[u64; 8],
    b: &[u64; 8],
    len: usize,
    lanes: usize,
) {
    let mut output = [u64::MAX; 10];
    let mut expected = output;
    for i in 0..len / lanes * lanes {
        expected[i + 1] = a[i].wrapping_add(b[i]).wrapping_add(b[0]);
    }
    probe(&a[..len], &b[..len], &mut output[1..1 + len], b[0]);
    assert_eq!(output, expected);
}
