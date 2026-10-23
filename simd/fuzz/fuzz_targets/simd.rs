#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_simd::{ArmV9, Neon, Operation, Simd, X86V4C, dispatch};

struct Backend;

impl<S: Simd> Operation<S> for Backend {
    type Output = &'static str;

    // Native x86-64-v3 runs the portable path with four u64 lanes, and scalar with one.
    fn portable(self, _: S) -> Self::Output {
        if S::U64_LANES == 4 {
            "x86_v3"
        } else {
            "scalar"
        }
    }

    fn x86_v4c(self, _: S) -> Self::Output
    where
        S: X86V4C,
    {
        "x86_v4c"
    }

    fn neon(self, _: S) -> Self::Output
    where
        S: Neon,
    {
        "neon"
    }

    fn arm_v9(self, _: S) -> Self::Output
    where
        S: ArmV9,
    {
        "arm_v9"
    }
}

libfuzzer_sys::fuzz_target!(
    init: {
        let selected = dispatch(Backend);
        eprintln!("instruction differential backend: {selected}");
        if let Ok(expected) = std::env::var("COMMONWARE_SIMD_EXPECT_BACKEND")
            && !expected.is_empty()
        {
            assert_eq!(selected, expected, "unexpected SIMD dispatch backend");
        }
    },
    |input: &[u8]| {
        let mut u = Unstructured::new(input);
        if let Ok(plan) = commonware_simd::fuzz::Plan::arbitrary(&mut u) {
            let _ = plan.run(&mut u);
        }
    }
);
