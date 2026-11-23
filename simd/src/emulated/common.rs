//! Shared array semantics for emulated backends.

macro_rules! impl_common {
    ($backend:ty, $u8_lanes:literal, $u32_lanes:literal, $u64_lanes:literal, $execute:ident) => {
        const _: () = $crate::core::assert_lane_relation::<$backend>();

        impl $crate::Simd for $backend {
            type U32x4 = [u32; 4];

            #[inline]
            fn u32x4_load(self, input: &[u32]) -> Self::U32x4 {
                input[..4].try_into().unwrap()
            }

            #[inline]
            fn u32x4_store(self, value: Self::U32x4, output: &mut [u32]) {
                output[..4].copy_from_slice(&value);
            }

            #[inline]
            fn u32x4_add(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
                core::array::from_fn(|i| a[i].wrapping_add(b[i]))
            }

            #[inline]
            fn u32x4_shuffle<const MASK: i32>(self, value: Self::U32x4) -> Self::U32x4 {
                assert!((0..256).contains(&MASK));
                core::array::from_fn(|i| value[((MASK >> (2 * i)) & 3) as usize])
            }

            #[inline]
            fn u32x4_load_be(self, input: &[u8]) -> Self::U32x4 {
                let input = &input[..16];
                core::array::from_fn(|i| {
                    u32::from_be_bytes(input[4 * i..4 * i + 4].try_into().unwrap())
                })
            }

            #[inline]
            fn u32x4_load_be2(self, input: &[u8]) -> Self::U32x4 {
                let input = &input[..8];
                [
                    u32::from_be_bytes(input[..4].try_into().unwrap()),
                    u32::from_be_bytes(input[4..8].try_into().unwrap()),
                    0,
                    0,
                ]
            }

            #[inline]
            fn u32x4_store_be(self, value: Self::U32x4, output: &mut [u8]) {
                let output = &mut output[..16];
                for (word, bytes) in value.into_iter().zip(output.as_chunks_mut::<4>().0) {
                    bytes.copy_from_slice(&word.to_be_bytes());
                }
            }

            #[inline]
            fn u32x4_align<const N: i32>(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
                assert!((0..=4).contains(&N));
                core::array::from_fn(|i| {
                    let j = N as usize + i;
                    if j < 4 { a[j] } else { b[j - 4] }
                })
            }

            #[inline]
            fn u32x4_blend<const MASK: i32>(self, a: Self::U32x4, b: Self::U32x4) -> Self::U32x4 {
                assert!((0..16).contains(&MASK));
                core::array::from_fn(|i| if MASK & (1 << i) != 0 { b[i] } else { a[i] })
            }

            type U8 = [u8; $u8_lanes];
            const U8_LANES: usize = $u8_lanes;

            #[inline]
            fn u8_load(self, input: &[u8]) -> Self::U8 {
                let mut value = [0; Self::U8_LANES];
                value.copy_from_slice(&input[..Self::U8_LANES]);
                value
            }

            #[inline]
            fn u8_store(self, value: Self::U8, output: &mut [u8]) {
                output[..Self::U8_LANES].copy_from_slice(&value);
            }

            #[inline]
            fn u8_splat(self, value: u8) -> Self::U8 {
                [value; $u8_lanes]
            }

            #[inline]
            fn u8_xor(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| a[i] ^ b[i])
            }

            #[inline]
            fn u8_load_partial(self, input: &[u8]) -> Self::U8 {
                assert!(input.len() <= Self::U8_LANES);
                let mut value = [0; Self::U8_LANES];
                value[..input.len()].copy_from_slice(input);
                value
            }

            #[inline]
            fn u8_store_partial(self, value: Self::U8, output: &mut [u8]) {
                assert!(output.len() <= Self::U8_LANES);
                output.copy_from_slice(&value[..output.len()]);
            }

            #[inline]
            fn u8_and(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| a[i] & b[i])
            }

            type U8Table = [u8; 16];

            #[inline]
            fn u8_table_load(self, table: &[u8; 16]) -> Self::U8Table {
                *table
            }

            #[inline]
            fn u8_table_lookup(self, table: Self::U8Table, indices: Self::U8) -> Self::U8 {
                indices.map(|index| table.get(usize::from(index)).copied().unwrap_or(0))
            }

            #[inline]
            fn u8_or(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| a[i] | b[i])
            }

            #[inline]
            fn u8_add(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| a[i].wrapping_add(b[i]))
            }

            #[inline]
            fn u8_sub(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| a[i].wrapping_sub(b[i]))
            }

            #[inline]
            fn u8_add_saturating(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| a[i].saturating_add(b[i]))
            }

            #[inline]
            fn u8_sub_saturating(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| a[i].saturating_sub(b[i]))
            }

            #[inline]
            fn u8_min(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| a[i].min(b[i]))
            }

            #[inline]
            fn u8_max(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| a[i].max(b[i]))
            }

            #[inline]
            fn u8_eq(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| if a[i] == b[i] { u8::MAX } else { 0 })
            }

            #[inline]
            fn u8_gt(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| if a[i] > b[i] { u8::MAX } else { 0 })
            }

            #[inline]
            fn u8_movemask(self, value: Self::U8) -> u64 {
                value
                    .iter()
                    .enumerate()
                    .fold(0, |mask, (i, v)| mask | (u64::from(v >> 7) << i))
            }

            #[inline]
            fn u8_any(self, value: Self::U8) -> bool {
                value.iter().any(|v| *v != 0)
            }

            #[inline]
            fn u8_all(self, value: Self::U8) -> bool {
                value.iter().all(|v| *v != 0)
            }

            #[inline]
            fn u8_zip_lo(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| if i % 2 == 0 { a[i / 2] } else { b[i / 2] })
            }

            #[inline]
            fn u8_zip_hi(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| {
                    let j = Self::U8_LANES + i;
                    if j % 2 == 0 { a[j / 2] } else { b[j / 2] }
                })
            }

            #[inline]
            fn u8_unzip_even(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| {
                    let j = 2 * i;
                    if j < Self::U8_LANES {
                        a[j]
                    } else {
                        b[j - Self::U8_LANES]
                    }
                })
            }

            #[inline]
            fn u8_unzip_odd(self, a: Self::U8, b: Self::U8) -> Self::U8 {
                core::array::from_fn(|i| {
                    let j = 2 * i + 1;
                    if j < Self::U8_LANES {
                        a[j]
                    } else {
                        b[j - Self::U8_LANES]
                    }
                })
            }

            #[inline]
            fn u8_shl<const N: u32>(self, value: Self::U8) -> Self::U8 {
                assert!(N < 8);
                value.map(|v| v << N)
            }

            #[inline]
            fn u8_shr<const N: u32>(self, value: Self::U8) -> Self::U8 {
                assert!(N < 8);
                value.map(|v| v >> N)
            }

            #[inline]
            fn u8_xor_fold(self, value: Self::U8) -> u8 {
                value.into_iter().fold(0, |acc, v| acc ^ v)
            }

            type U32 = [u32; $u32_lanes];
            const U32_LANES: usize = $u32_lanes;

            #[inline]
            fn u32_load(self, input: &[u32]) -> Self::U32 {
                let mut value = [0; Self::U32_LANES];
                value.copy_from_slice(&input[..Self::U32_LANES]);
                value
            }

            #[inline]
            fn u32_store(self, value: Self::U32, output: &mut [u32]) {
                output[..Self::U32_LANES].copy_from_slice(&value);
            }

            #[inline]
            fn u32_splat(self, value: u32) -> Self::U32 {
                [value; $u32_lanes]
            }

            #[inline]
            fn u32_xor(self, a: Self::U32, b: Self::U32) -> Self::U32 {
                core::array::from_fn(|i| a[i] ^ b[i])
            }

            #[inline]
            fn u32_add(self, a: Self::U32, b: Self::U32) -> Self::U32 {
                core::array::from_fn(|i| a[i].wrapping_add(b[i]))
            }

            #[inline]
            fn u32_rotate_right<const N: u32>(self, value: Self::U32) -> Self::U32 {
                assert!(N < 32);
                value.map(|v| v.rotate_right(N))
            }

            #[inline]
            fn u32_sub(self, a: Self::U32, b: Self::U32) -> Self::U32 {
                core::array::from_fn(|i| a[i].wrapping_sub(b[i]))
            }

            #[inline]
            fn u32_and(self, a: Self::U32, b: Self::U32) -> Self::U32 {
                core::array::from_fn(|i| a[i] & b[i])
            }

            #[inline]
            fn u32_or(self, a: Self::U32, b: Self::U32) -> Self::U32 {
                core::array::from_fn(|i| a[i] | b[i])
            }

            #[inline]
            fn u32_shl<const N: u32>(self, value: Self::U32) -> Self::U32 {
                assert!(N < 32);
                value.map(|v| v << N)
            }

            #[inline]
            fn u32_shr<const N: u32>(self, value: Self::U32) -> Self::U32 {
                assert!(N < 32);
                value.map(|v| v >> N)
            }

            #[inline]
            fn u32_select(self, mask: Self::U32, a: Self::U32, b: Self::U32) -> Self::U32 {
                core::array::from_fn(|i| (mask[i] & a[i]) | (!mask[i] & b[i]))
            }

            #[inline]
            fn u32_permute(self, value: Self::U32, indices: Self::U32) -> Self::U32 {
                core::array::from_fn(|i| value[indices[i] as usize % Self::U32_LANES])
            }

            #[inline]
            fn u32_permute2(self, a: Self::U32, b: Self::U32, indices: Self::U32) -> Self::U32 {
                core::array::from_fn(|i| {
                    let index = indices[i] as usize % (2 * Self::U32_LANES);
                    if index < Self::U32_LANES {
                        a[index]
                    } else {
                        b[index - Self::U32_LANES]
                    }
                })
            }

            #[inline]
            fn u64_and(self, a: Self::U64, b: Self::U64) -> Self::U64 {
                core::array::from_fn(|i| a[i] & b[i])
            }

            #[inline]
            fn u64_or(self, a: Self::U64, b: Self::U64) -> Self::U64 {
                core::array::from_fn(|i| a[i] | b[i])
            }

            #[inline]
            fn u64_shl<const N: u32>(self, value: Self::U64) -> Self::U64 {
                assert!(N < 64);
                value.map(|v| v << N)
            }

            #[inline]
            fn u64_shr<const N: u32>(self, value: Self::U64) -> Self::U64 {
                assert!(N < 64);
                value.map(|v| v >> N)
            }

            type U64 = [u64; $u64_lanes];

            const U64_LANES: usize = $u64_lanes;

            // Expose the body to downstream loops so vector bounds checks can be eliminated.
            #[inline]
            fn u64_load(self, input: &[u64]) -> Self::U64 {
                let input = &input[..Self::U64_LANES];
                let mut value = [0; Self::U64_LANES];
                for (i, lane) in value.iter_mut().enumerate() {
                    *lane = input[i];
                }
                value
            }

            // Expose the body to downstream loops so vector bounds checks can be eliminated.
            #[inline]
            fn u64_store(self, value: Self::U64, output: &mut [u64]) {
                let output = &mut output[..Self::U64_LANES];
                for (i, lane) in value.into_iter().enumerate() {
                    output[i] = lane;
                }
            }

            #[inline]
            fn u64_splat(self, value: u64) -> Self::U64 {
                [value; $u64_lanes]
            }

            // Inline lane arithmetic into downstream loops instead of calling once per vector.
            #[inline]
            fn u64_add(self, a: Self::U64, b: Self::U64) -> Self::U64 {
                core::array::from_fn(|i| a[i].wrapping_add(b[i]))
            }

            #[inline]
            fn u64_sub(self, a: Self::U64, b: Self::U64) -> Self::U64 {
                core::array::from_fn(|i| a[i].wrapping_sub(b[i]))
            }

            #[inline]
            fn u64_xor(self, a: Self::U64, b: Self::U64) -> Self::U64 {
                core::array::from_fn(|i| a[i] ^ b[i])
            }

            #[inline]
            fn u64_rotate_left<const N: u32>(self, value: Self::U64) -> Self::U64 {
                assert!(N < 64);
                value.map(|v| v.rotate_left(N))
            }

            #[inline]
            fn u64_rotate_right<const N: u32>(self, value: Self::U64) -> Self::U64 {
                assert!(N < 64);
                value.map(|v| v.rotate_right(N))
            }

            #[inline]
            fn u64_andnot(self, a: Self::U64, b: Self::U64) -> Self::U64 {
                core::array::from_fn(|i| a[i] & !b[i])
            }

            #[inline]
            fn u64_xor3(self, a: Self::U64, b: Self::U64, c: Self::U64) -> Self::U64 {
                core::array::from_fn(|i| a[i] ^ b[i] ^ c[i])
            }

            #[inline]
            fn u64_select(self, mask: Self::U64, a: Self::U64, b: Self::U64) -> Self::U64 {
                core::array::from_fn(|i| (mask[i] & a[i]) | (!mask[i] & b[i]))
            }

            #[inline]
            fn u64_extract<const N: usize>(self, value: Self::U64) -> u64 {
                assert!(N < Self::U64_LANES);
                value[N]
            }

            #[inline]
            fn u64_insert<const N: usize>(self, mut value: Self::U64, lane: u64) -> Self::U64 {
                assert!(N < Self::U64_LANES);
                value[N] = lane;
                value
            }

            #[inline]
            fn u8_as_u32(self, value: Self::U8) -> Self::U32 {
                core::array::from_fn(|i| {
                    u32::from_le_bytes(value[4 * i..4 * i + 4].try_into().unwrap())
                })
            }

            #[inline]
            fn u32_as_u8(self, value: Self::U32) -> Self::U8 {
                let mut bytes = [0; Self::U8_LANES];
                for (word, chunk) in value.into_iter().zip(bytes.as_chunks_mut::<4>().0) {
                    chunk.copy_from_slice(&word.to_le_bytes());
                }
                bytes
            }

            #[inline]
            fn u8_as_u64(self, value: Self::U8) -> Self::U64 {
                core::array::from_fn(|i| {
                    u64::from_le_bytes(value[8 * i..8 * i + 8].try_into().unwrap())
                })
            }

            #[inline]
            fn u64_as_u8(self, value: Self::U64) -> Self::U8 {
                let mut bytes = [0; Self::U8_LANES];
                for (lane, chunk) in value.into_iter().zip(bytes.as_chunks_mut::<8>().0) {
                    chunk.copy_from_slice(&lane.to_le_bytes());
                }
                bytes
            }

            #[inline]
            fn u32_as_u64(self, value: Self::U32) -> Self::U64 {
                core::array::from_fn(|i| {
                    u64::from(value[2 * i]) | u64::from(value[2 * i + 1]) << 32
                })
            }

            #[inline]
            fn u64_as_u32(self, value: Self::U64) -> Self::U32 {
                let mut words = [0; Self::U32_LANES];
                for (lane, pair) in value.into_iter().zip(words.as_chunks_mut::<2>().0) {
                    pair[0] = lane as u32;
                    pair[1] = (lane >> 32) as u32;
                }
                words
            }

            // Inline nested adapters across consumer code generation units.
            #[inline]
            fn execute<O: $crate::Operation<Self>>(self, operation: O) -> O::Output {
                operation.$execute(self)
            }
        }
    };
}

pub(super) use impl_common;
