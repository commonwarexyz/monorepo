//! Backend-typed register composition.

use commonware_simd::{
    ArmV9, Neon, Operation, Simd, X86V4C, check_consistent, dispatch,
    emulated::{EmulatedArmV9, EmulatedNeon, EmulatedScalar, EmulatedX86V3, EmulatedX86V4C},
    test_dispatch,
};

#[derive(Debug, PartialEq)]
enum Path {
    Portable,
    X86V4C,
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

        fn x86_v4c(self, simd: S) -> S::U32
        where
            S: X86V4C,
        {
            *self.1 = Some((Path::X86V4C, S::U32_LANES));
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

const fn expected(input: u32) -> u32 {
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
    check(EmulatedX86V3, Path::Portable);
    check(EmulatedX86V4C, Path::X86V4C);
    check(EmulatedArmV9, Path::ArmV9);
    check(EmulatedNeon, Path::Neon);

    #[cfg(target_arch = "x86_64")]
    {
        if let Some(simd) = commonware_simd::native::NativeX86V4C::new() {
            check(simd, Path::X86V4C);
        }
        if let Some(simd) = commonware_simd::native::NativeX86V3::new() {
            check(simd, Path::Portable);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(simd) = commonware_simd::native::NativeArmV9::new() {
            check(simd, Path::ArmV9);
        }
        if let Some(simd) = commonware_simd::native::NativeNeon::new() {
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
        assert_eq!(dispatch(Root(input)), expected(input));
        assert_eq!(test_dispatch(Root(input)), expected(input));
    }
}

#[test]
fn kernel_closure_owns_input_and_borrows_mutably() {
    fn check<S: Simd>(simd: S, expected_path: Path) {
        let mut inputs = vec![0, 1, u32::MAX, 0xdead_beef];
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
    check(EmulatedX86V3, Path::Portable);
    check(EmulatedX86V4C, Path::X86V4C);
    check(EmulatedArmV9, Path::ArmV9);
    check(EmulatedNeon, Path::Neon);

    #[cfg(target_arch = "x86_64")]
    {
        if let Some(simd) = commonware_simd::native::NativeX86V4C::new() {
            check(simd, Path::X86V4C);
        }
        if let Some(simd) = commonware_simd::native::NativeX86V3::new() {
            check(simd, Path::Portable);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(simd) = commonware_simd::native::NativeArmV9::new() {
            check(simd, Path::ArmV9);
        }
        if let Some(simd) = commonware_simd::native::NativeNeon::new() {
            check(simd, Path::Neon);
        }
    }
}

/// Rotates every aligned four-byte group left by one byte (a word rotation in little-endian
/// order), processing full vectors through a word operation and the tail with scalars.
#[inline(always)]
fn rotate_groups<S: Simd>(simd: S, data: &mut [u8]) {
    simd.execute(
        #[inline(always)]
        |simd: S| {
            let mut rest = &mut *data;
            while rest.len() >= S::U8_LANES {
                let (chunk, tail) = rest.split_at_mut(S::U8_LANES);
                let words = simd.u8_as_u32(simd.u8_load(chunk));
                let rotated = simd.u32_rotate_right::<8>(words);
                simd.u8_store(simd.u32_as_u8(rotated), chunk);
                rest = tail;
            }
            for group in rest.as_chunks_mut::<4>().0 {
                group.rotate_left(1);
            }
        },
    );
}

#[test]
fn cast_bytes_to_words_and_back() {
    fn check<S: Simd>(simd: S) {
        for len in [0, 3, 4, 16, 63, 64, 65, 130, 200] {
            let input: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(73) ^ 0x5a)
                .collect();
            let mut expected = input.clone();
            for group in expected.as_chunks_mut::<4>().0 {
                group.rotate_left(1);
            }
            let mut actual = input.clone();
            rotate_groups(simd, &mut actual);
            assert_eq!(actual, expected, "len {len}");
        }
    }

    check(EmulatedScalar);
    check(EmulatedX86V3);
    check(EmulatedX86V4C);
    check(EmulatedArmV9);
    check(EmulatedNeon);

    #[cfg(target_arch = "x86_64")]
    {
        if let Some(simd) = commonware_simd::native::NativeX86V4C::new() {
            check(simd);
        }
        if let Some(simd) = commonware_simd::native::NativeX86V3::new() {
            check(simd);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if let Some(simd) = commonware_simd::native::NativeArmV9::new() {
            check(simd);
        }
        if let Some(simd) = commonware_simd::native::NativeNeon::new() {
            check(simd);
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Hex-encodes 32 bytes with a nibble table lookup and a byte interleave.
struct HexEncode([u8; 32]);

impl<S: Simd> Operation<S> for HexEncode {
    type Output = [u8; 64];

    fn portable(self, simd: S) -> [u8; 64] {
        let lanes = S::U8_LANES;
        // Pad to whole vectors so every lane count processes full registers.
        let blocks = self.0.len().div_ceil(lanes);
        let mut input = vec![0; blocks * lanes];
        input[..self.0.len()].copy_from_slice(&self.0);
        let mut output = vec![0; 2 * input.len()];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                let table = simd.u8_table_load(HEX);
                let low = simd.u8_splat(0x0f);
                for (block, out) in input
                    .chunks_exact(lanes)
                    .zip(output.chunks_exact_mut(2 * lanes))
                {
                    let value = simd.u8_load(block);
                    let high = simd.u8_table_lookup(table, simd.u8_shr::<4>(value));
                    let low = simd.u8_table_lookup(table, simd.u8_and(value, low));
                    simd.u8_store(simd.u8_zip_lo(high, low), out);
                    simd.u8_store(simd.u8_zip_hi(high, low), &mut out[lanes..]);
                }
            },
        );
        output[..64].try_into().unwrap()
    }
}

/// Decodes 64 hex characters, returning the first invalid index on failure.
struct HexDecode([u8; 64]);

impl<S: Simd> Operation<S> for HexDecode {
    type Output = Result<[u8; 32], usize>;

    fn portable(self, simd: S) -> Self::Output {
        let lanes = S::U8_LANES;
        // Pad with a valid digit to whole pairs of vectors.
        let blocks = self.0.len().div_ceil(2 * lanes);
        let mut input = vec![b'0'; blocks * 2 * lanes];
        input[..self.0.len()].copy_from_slice(&self.0);
        let mut output = vec![0; input.len() / 2];
        simd.execute(
            #[inline(always)]
            |simd: S| {
                // Maps characters to nibble values, marking invalid lanes.
                #[inline(always)]
                fn nibbles<S: Simd>(simd: S, chars: S::U8) -> (S::U8, S::U8) {
                    let digit = simd.u8_sub(chars, simd.u8_splat(b'0'));
                    let letter =
                        simd.u8_sub(simd.u8_or(chars, simd.u8_splat(0x20)), simd.u8_splat(b'a'));
                    let invalid = simd.u8_and(
                        simd.u8_gt(digit, simd.u8_splat(9)),
                        simd.u8_gt(letter, simd.u8_splat(5)),
                    );
                    // Non-digits have digit >= 0x11 > letter + 10, and digits have
                    // letter + 10 saturating above 9.
                    let value =
                        simd.u8_min(digit, simd.u8_add_saturating(letter, simd.u8_splat(10)));
                    (value, invalid)
                }

                for (index, (block, out)) in input
                    .chunks_exact(2 * lanes)
                    .zip(output.chunks_exact_mut(lanes))
                    .enumerate()
                {
                    let (first, first_invalid) = nibbles(simd, simd.u8_load(block));
                    let (second, second_invalid) = nibbles(simd, simd.u8_load(&block[lanes..]));
                    if simd.u8_any(simd.u8_or(first_invalid, second_invalid)) {
                        let first_mask = simd.u8_movemask(first_invalid);
                        let lane = if first_mask != 0 {
                            first_mask.trailing_zeros() as usize
                        } else {
                            lanes + simd.u8_movemask(second_invalid).trailing_zeros() as usize
                        };
                        return Err(2 * lanes * index + lane);
                    }
                    let high = simd.u8_unzip_even(first, second);
                    let low = simd.u8_unzip_odd(first, second);
                    simd.u8_store(simd.u8_or(simd.u8_shl::<4>(high), low), out);
                }
                Ok(())
            },
        )?;
        Ok(output[..32].try_into().unwrap())
    }
}

fn hex_encode_reference(input: &[u8; 32]) -> [u8; 64] {
    core::array::from_fn(|i| HEX[usize::from(input[i / 2] >> (4 * (1 - i % 2))) & 15])
}

fn hex_decode_reference(input: &[u8; 64]) -> Result<[u8; 32], usize> {
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    let mut output = [0; 32];
    for (i, c) in input.iter().enumerate() {
        let value = nibble(*c).ok_or(i)?;
        output[i / 2] |= value << (4 * (1 - i % 2));
    }
    Ok(output)
}

#[test]
fn hex_byte_kernels() {
    // Dispatch selects native x86-64-v3 only on CPUs without x86v4c, so check it directly.
    #[cfg(target_arch = "x86_64")]
    let x86_v3 = commonware_simd::native::NativeX86V3::new();
    let inputs: Vec<[u8; 32]> = vec![
        [0; 32],
        [0xff; 32],
        core::array::from_fn(|i| i as u8),
        core::array::from_fn(|i| (i as u8).wrapping_mul(0x9d).wrapping_add(0x5b)),
    ];
    for input in inputs {
        let encoded = hex_encode_reference(&input);
        assert_eq!(test_dispatch(HexEncode(input)), encoded);
        assert_eq!(dispatch(HexEncode(input)), encoded);
        check_consistent(|| HexEncode(input));

        assert_eq!(test_dispatch(HexDecode(encoded)), Ok(input));
        assert_eq!(dispatch(HexDecode(encoded)), Ok(input));
        let upper = encoded.map(|c| c.to_ascii_uppercase());
        assert_eq!(test_dispatch(HexDecode(upper)), Ok(input));
        check_consistent(|| HexDecode(upper));

        #[cfg(target_arch = "x86_64")]
        if let Some(simd) = x86_v3 {
            assert_eq!(simd.execute(HexEncode(input)), encoded);
            assert_eq!(simd.execute(HexDecode(encoded)), Ok(input));
            assert_eq!(simd.execute(HexDecode(upper)), Ok(input));
        }
    }
    // Every byte value at every position, including characters adjacent to valid ranges.
    let valid = hex_encode_reference(&core::array::from_fn(|i| (i as u8).wrapping_mul(37)));
    for position in [0, 1, 15, 16, 31, 32, 63] {
        for c in 0..=255u8 {
            let mut input = valid;
            input[position] = c;
            let expected = hex_decode_reference(&input);
            assert_eq!(test_dispatch(HexDecode(input)), expected);
            assert_eq!(dispatch(HexDecode(input)), expected);
            check_consistent(|| HexDecode(input));
            #[cfg(target_arch = "x86_64")]
            if let Some(simd) = x86_v3 {
                assert_eq!(simd.execute(HexDecode(input)), expected);
            }
        }
    }
    // The first invalid character is reported when several are present.
    let mut input = valid;
    input[40] = b'g';
    input[17] = b'/';
    assert_eq!(test_dispatch(HexDecode(input)), Err(17));
    check_consistent(|| HexDecode(input));
}
