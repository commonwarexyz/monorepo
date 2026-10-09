//! Backend-typed register composition.

use crate::{
    ArmV9, IceLake, Neon, Operation, Simd, check_consistent,
    emulated::{EmulatedArmV9, EmulatedIceLake, EmulatedNeon, EmulatedScalar},
};

#[derive(Debug, PartialEq)]
enum Path {
    Portable,
    IceLake,
    ArmV9,
    Neon,
}

fn leaf<S: Simd>(
    value: S::U32,
    path: &mut Option<(Path, usize)>,
) -> impl Operation<S, Output = S::U32> {
    struct Leaf<'a, S: Simd>(S::U32, &'a mut Option<(Path, usize)>);

    impl<S: Simd> Operation<S> for Leaf<'_, S> {
        type Output = S::U32;

        fn portable(self, simd: S) -> S::U32 {
            *self.1 = Some((Path::Portable, S::U32_LANES));
            simd.u32_rotate_right::<7>(simd.u32_xor(self.0, simd.u32_splat(0xa5a5_a5a5)))
        }

        fn ice_lake(self, simd: S) -> S::U32
        where
            S: IceLake,
        {
            *self.1 = Some((Path::IceLake, S::U32_LANES));
            let value =
                simd.u32_ternary::<0x96>(self.0, simd.u32_splat(0xa5a5_a5a5), simd.u32_splat(0));
            simd.u32_rotate_right::<7>(value)
        }

        fn arm_v9(self, simd: S) -> S::U32
        where
            S: ArmV9,
        {
            *self.1 = Some((Path::ArmV9, S::U32_LANES));
            simd.u32_xor_rotate_right::<7>(self.0, simd.u32_splat(0xa5a5_a5a5))
        }

        fn neon(self, simd: S) -> S::U32
        where
            S: Neon,
        {
            *self.1 = Some((Path::Neon, S::U32_LANES));
            simd.u32_rotate_right::<7>(simd.u32_xor(self.0, simd.u32_splat(0xa5a5_a5a5)))
        }
    }

    Leaf::<S>(value, path)
}

fn compose<S: Simd>(simd: S, input: u32, path: &mut Option<(Path, usize)>) -> S::U32 {
    let value = simd.execute(leaf::<S>(simd.u32_splat(input), path));
    simd.u32_add(value, simd.u32_splat(1))
}

fn expected(input: u32) -> u32 {
    (input ^ 0xa5a5_a5a5).rotate_right(7).wrapping_add(1)
}

fn check<S: Simd>(simd: S, expected_path: Path) {
    let input = 0xdead_beef;
    let mut path = None;
    let value = compose(simd, input, &mut path);
    assert_eq!(path, Some((expected_path, S::U32_LANES)));
    let mut lanes = [0; 16];
    simd.u32_store(value, &mut lanes);
    assert_eq!(
        &lanes[..S::U32_LANES],
        &[expected(input); 16][..S::U32_LANES]
    );
}

#[test]
fn typed_register_composition() {
    check(EmulatedScalar, Path::Portable);
    check(EmulatedIceLake, Path::IceLake);
    check(EmulatedArmV9, Path::ArmV9);
    check(EmulatedNeon, Path::Neon);

    #[cfg(target_arch = "x86_64")]
    if let Some(simd) = crate::native::NativeIceLake::new() {
        check(simd, Path::IceLake);
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(simd) = crate::native::NativeArmV9::new() {
            check(simd, Path::ArmV9);
        }
        if let Some(simd) = crate::native::NativeNeon::new() {
            check(simd, Path::Neon);
        }
    }
}

#[test]
fn normalize_at_outer_boundary() {
    // Runtime dispatch and consistency checks require a universal operation with scalar output.
    struct Root(u32);
    impl<S: Simd> Operation<S> for Root {
        type Output = u32;

        fn portable(self, simd: S) -> u32 {
            let value = compose(simd, self.0, &mut None);
            let mut output = [0; 16];
            simd.u32_store(value, &mut output);
            output[0]
        }
    }

    for input in [0, 1, u32::MAX, 0xdead_beef] {
        check_consistent(|| Root(input));
        assert_eq!(crate::dispatch(Root(input)), expected(input));
        assert_eq!(crate::test_dispatch(Root(input)), expected(input));
    }
}

#[test]
fn kernel_closure_owns_input_and_borrows_mutably() {
    fn check<S: Simd>(simd: S, expected_path: Path) {
        let mut inputs = std::vec![0, 1, u32::MAX, 0xdead_beef];
        let mut path = None;
        let path_ref = &mut path;
        let mut calls = 0;
        let calls_ref = &mut calls;
        let value = simd.execute(
            #[inline(always)]
            move |simd: S| {
                *calls_ref += 1;
                let mut value = simd.u32_splat(0);
                for input in inputs.drain(..) {
                    let child = simd.execute(leaf::<S>(simd.u32_splat(input), path_ref));
                    value = simd.u32_add(value, simd.u32_add(child, simd.u32_splat(1)));
                }
                value
            },
        );

        assert_eq!(calls, 1);
        assert_eq!(path, Some((expected_path, S::U32_LANES)));
        let expected = [0, 1, u32::MAX, 0xdead_beef]
            .into_iter()
            .map(expected)
            .fold(0, u32::wrapping_add);
        let mut lanes = [0; 16];
        simd.u32_store(value, &mut lanes);
        assert_eq!(&lanes[..S::U32_LANES], &[expected; 16][..S::U32_LANES]);
    }

    check(EmulatedScalar, Path::Portable);
    check(EmulatedIceLake, Path::IceLake);
    check(EmulatedArmV9, Path::ArmV9);
    check(EmulatedNeon, Path::Neon);

    #[cfg(target_arch = "x86_64")]
    if let Some(simd) = crate::native::NativeIceLake::new() {
        check(simd, Path::IceLake);
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(simd) = crate::native::NativeArmV9::new() {
            check(simd, Path::ArmV9);
        }
        if let Some(simd) = crate::native::NativeNeon::new() {
            check(simd, Path::Neon);
        }
    }
}
