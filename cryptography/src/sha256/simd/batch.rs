//! SHA-256 for sixteen equal-length messages using independent SIMD lanes.

use super::{X16_LANES as MESSAGES, constants::K};
use crate::sha256::{BLOCK_LENGTH, DIGEST_LENGTH, Digest, IV, pad_fresh, padding_length};
use commonware_simd::{IceLake, Operation, Simd};

const STATE_WORDS: usize = 8;

/// Hashes sixteen equal-length messages in input order.
///
/// Widths up to sixteen use fixed stack buffers, zero-filling unused lanes in the
/// final chunk. Wider backends use scalar lanes without larger buffers.
///
/// # Panics
///
/// Executing the operation panics if the messages have different lengths or the backend violates
/// `Simd`'s positive lane-count contract.
pub(super) fn hash<S: Simd>(
    messages: [&[u8]; MESSAGES],
) -> impl Operation<S, Output = [Digest; MESSAGES]> {
    #[inline(always)]
    move |simd: S| {
        let len = messages[0].len();
        assert!(
            messages.iter().all(|message| message.len() == len),
            "SHA-256 batch inputs must have equal lengths"
        );
        let full_len = len / BLOCK_LENGTH * BLOCK_LENGTH;
        let remainder = len - full_len;
        let padding_len = padding_length(remainder);
        let mut padding = [[0u8; 2 * BLOCK_LENGTH]; MESSAGES];
        for (message, padding) in messages.iter().zip(&mut padding) {
            padding[..remainder].copy_from_slice(&message[full_len..]);
            pad_fresh(padding, remainder, len);
        }
        let padding: [&[u8]; MESSAGES] = core::array::from_fn(|lane| padding[lane].as_slice());

        let state = compress_blocks(
            simd,
            messages,
            full_len,
            padding,
            padding_len,
            IV.map(|word| [word; MESSAGES]),
        );
        core::array::from_fn(|lane| {
            let mut digest = Digest([0; DIGEST_LENGTH]);
            for (word, values) in state.iter().enumerate() {
                digest.0[word * 4..word * 4 + 4].copy_from_slice(&values[lane].to_be_bytes());
            }
            digest
        })
    }
}

/// Compresses both input segments while keeping the chaining state in registers.
#[inline(always)]
fn compress_blocks<S: Simd>(
    simd: S,
    messages: [&[u8]; MESSAGES],
    full_len: usize,
    padding: [&[u8]; MESSAGES],
    padding_len: usize,
    initial: [[u32; MESSAGES]; STATE_WORDS],
) -> [[u32; MESSAGES]; STATE_WORDS] {
    /// Compresses one schedule in each active lane.
    #[inline(always)]
    fn compress<S: Simd>(simd: S, state: &mut [S::U32; STATE_WORDS], mut schedule: [S::U32; 16]) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        macro_rules! round {
            ($round:expr; $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident) => {{
                const ROUND: usize = $round;
                let round = ROUND;
                let k = K[ROUND];
                let index = round & 15;
                if round >= 16 {
                    let x = schedule[(round - 15) & 15];
                    let y = schedule[(round - 2) & 15];
                    let sigma0 = simd.execute(xor3::<S>(
                        simd.u32_rotate_right::<7>(x),
                        simd.u32_rotate_right::<18>(x),
                        simd.u32_shr::<3>(x),
                    ));
                    let sigma1 = simd.execute(xor3::<S>(
                        simd.u32_rotate_right::<17>(y),
                        simd.u32_rotate_right::<19>(y),
                        simd.u32_shr::<10>(y),
                    ));
                    schedule[index] = simd.u32_add(
                        simd.u32_add(schedule[index], schedule[(round - 7) & 15]),
                        simd.u32_add(sigma0, sigma1),
                    );
                }
                let hwk = simd.u32_add(simd.u32_add($h, schedule[index]), simd.u32_splat(k));
                let sum1 = simd.execute(xor3::<S>(
                    simd.u32_rotate_right::<6>($e),
                    simd.u32_rotate_right::<11>($e),
                    simd.u32_rotate_right::<25>($e),
                ));
                let t1 = simd.u32_add(simd.u32_add(hwk, sum1), simd.execute(choice::<S>($e, $f, $g)));
                let sum0 = simd.execute(xor3::<S>(
                    simd.u32_rotate_right::<2>($a),
                    simd.u32_rotate_right::<13>($a),
                    simd.u32_rotate_right::<22>($a),
                ));
                let t2 = simd.u32_add(sum0, simd.execute(majority::<S>($a, $b, $c)));
                $d = simd.u32_add($d, t1);
                $h = simd.u32_add(t1, t2);
            }};
        }

        // Rotate state names so each round updates only d and h.
        macro_rules! rounds8 {
            ($base:expr) => {{
                round!($base; a, b, c, d, e, f, g, h);
                round!($base + 1; h, a, b, c, d, e, f, g);
                round!($base + 2; g, h, a, b, c, d, e, f);
                round!($base + 3; f, g, h, a, b, c, d, e);
                round!($base + 4; e, f, g, h, a, b, c, d);
                round!($base + 5; d, e, f, g, h, a, b, c);
                round!($base + 6; c, d, e, f, g, h, a, b);
                round!($base + 7; b, c, d, e, f, g, h, a);
            }};
        }
        rounds8!(0);
        rounds8!(8);
        rounds8!(16);
        rounds8!(24);
        rounds8!(32);
        rounds8!(40);
        rounds8!(48);
        rounds8!(56);
        for (word, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = simd.u32_add(*word, value);
        }
    }

    assert!(S::U32_LANES > 0);
    if S::U32_LANES > MESSAGES {
        return compress_blocks(
            commonware_simd::emulated::EmulatedScalar,
            messages,
            full_len,
            padding,
            padding_len,
            initial,
        );
    }
    let mut output = [[0; MESSAGES]; STATE_WORDS];
    for start in (0..MESSAGES).step_by(S::U32_LANES) {
        let end = (start + S::U32_LANES).min(MESSAGES);
        let state_words = core::array::from_fn::<_, STATE_WORDS, _>(|word| {
            let mut lanes = [0; MESSAGES];
            lanes[..end - start].copy_from_slice(&initial[word][start..end]);
            simd.u32_load(&lanes[..S::U32_LANES])
        });
        let mut state = state_words;
        for (messages, len) in [(&messages, full_len), (&padding, padding_len)] {
            for offset in (0..len).step_by(BLOCK_LENGTH) {
                let schedule = simd.execute(load::<S>(&messages[start..end], offset));
                compress(simd, &mut state, schedule);
            }
        }
        let mut words = [0; MESSAGES];
        for (word, value) in state.into_iter().enumerate() {
            simd.u32_store(value, &mut words[..S::U32_LANES]);
            output[word][start..end].copy_from_slice(&words[..end - start]);
        }
    }
    output
}

#[inline(always)]
fn load<'a, S: Simd>(
    messages: &'a [&'a [u8]],
    offset: usize,
) -> impl Operation<S, Output = [S::U32; 16]> + 'a {
    struct Load<'a>(&'a [&'a [u8]], usize);

    impl<S: Simd> Operation<S> for Load<'_> {
        type Output = [S::U32; 16];

        #[inline(always)]
        fn portable(self, simd: S) -> Self::Output {
            let Self(messages, offset) = self;
            let mut schedule = [simd.u32_splat(0); 16];
            let mut words = [0; MESSAGES];
            for (word, value) in schedule.iter_mut().enumerate() {
                let offset = offset + word * 4;
                for (lane, message) in messages.iter().enumerate() {
                    words[lane] =
                        u32::from_be_bytes(message[offset..offset + 4].try_into().unwrap());
                }
                *value = simd.u32_load(&words[..S::U32_LANES]);
            }
            schedule
        }

        #[inline(always)]
        fn ice_lake(self, simd: S) -> Self::Output
        where
            S: IceLake,
        {
            let Self(messages, offset) = self;
            // Each checked block is loaded once before transposing messages into lanes.
            macro_rules! load_rows {
                ($($lane:expr),* $(,)?) => {
                    [$(simd.u32_load_be(&messages[$lane][offset..offset + BLOCK_LENGTH])),*]
                };
            }
            let mut words = load_rows!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
            macro_rules! pair {
                ($lo:expr, $hi:expr) => {{
                    let (a, b) = (words[$lo], words[$hi]);
                    words[$lo] = simd.u32_unpacklo32(a, b);
                    words[$hi] = simd.u32_unpackhi32(a, b);
                }};
            }
            pair!(0, 1);
            pair!(2, 3);
            pair!(4, 5);
            pair!(6, 7);
            pair!(8, 9);
            pair!(10, 11);
            pair!(12, 13);
            pair!(14, 15);

            macro_rules! quad {
                ($base:expr) => {{
                    let (a, b, c, d) = (
                        words[$base],
                        words[$base + 1],
                        words[$base + 2],
                        words[$base + 3],
                    );
                    words[$base] = simd.u32_unpacklo64(a, c);
                    words[$base + 1] = simd.u32_unpackhi64(a, c);
                    words[$base + 2] = simd.u32_unpacklo64(b, d);
                    words[$base + 3] = simd.u32_unpackhi64(b, d);
                }};
            }
            quad!(0);
            quad!(4);
            quad!(8);
            quad!(12);
            words.swap(4, 8);
            words.swap(5, 9);
            words.swap(6, 10);
            words.swap(7, 11);

            macro_rules! quarter {
                ($base:expr) => {{
                    let (v0, v4, v8, v12) = (
                        words[$base],
                        words[$base + 4],
                        words[$base + 8],
                        words[$base + 12],
                    );
                    let a = simd.u32_shuffle_groups::<0x44>(v0, v8);
                    let b = simd.u32_shuffle_groups::<0xee>(v0, v8);
                    let c = simd.u32_shuffle_groups::<0x44>(v4, v12);
                    let d = simd.u32_shuffle_groups::<0xee>(v4, v12);
                    words[$base] = simd.u32_shuffle_groups::<0x88>(a, c);
                    words[$base + 4] = simd.u32_shuffle_groups::<0xdd>(a, c);
                    words[$base + 8] = simd.u32_shuffle_groups::<0x88>(b, d);
                    words[$base + 12] = simd.u32_shuffle_groups::<0xdd>(b, d);
                }};
            }
            quarter!(0);
            quarter!(1);
            quarter!(2);
            quarter!(3);
            words
        }
    }

    Load(messages, offset)
}

#[inline(always)]
fn boolean<S: Simd, const MASK: i32>(
    a: S::U32,
    b: S::U32,
    c: S::U32,
) -> impl Operation<S, Output = S::U32> {
    const {
        assert!(matches!(MASK, 0x96 | 0xca | 0xe8));
    }
    struct Boolean<S: Simd, const MASK: i32>(S::U32, S::U32, S::U32);

    impl<S: Simd, const MASK: i32> Operation<S> for Boolean<S, MASK> {
        type Output = S::U32;

        #[inline(always)]
        fn portable(self, simd: S) -> Self::Output {
            let Self(a, b, c) = self;
            match MASK {
                0x96 => simd.u32_xor(simd.u32_xor(a, b), c),
                0xca => simd.u32_xor(c, simd.u32_and(a, simd.u32_xor(b, c))),
                0xe8 => simd.u32_or(simd.u32_and(a, b), simd.u32_and(c, simd.u32_or(a, b))),
                _ => unreachable!(),
            }
        }

        #[inline(always)]
        fn ice_lake(self, simd: S) -> Self::Output
        where
            S: IceLake,
        {
            let Self(a, b, c) = self;
            simd.u32_ternary::<MASK>(a, b, c)
        }
    }
    Boolean::<S, MASK>(a, b, c)
}

#[inline(always)]
fn xor3<S: Simd>(a: S::U32, b: S::U32, c: S::U32) -> impl Operation<S, Output = S::U32> {
    boolean::<S, 0x96>(a, b, c)
}

#[inline(always)]
fn choice<S: Simd>(a: S::U32, b: S::U32, c: S::U32) -> impl Operation<S, Output = S::U32> {
    boolean::<S, 0xca>(a, b, c)
}

#[inline(always)]
fn majority<S: Simd>(a: S::U32, b: S::U32, c: S::U32) -> impl Operation<S, Output = S::U32> {
    boolean::<S, 0xe8>(a, b, c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_simd::emulated::{EmulatedArmV9, EmulatedIceLake, EmulatedNeon, EmulatedScalar};
    use sha2::{Digest as _, Sha256, block_api::compress256};

    const BOUNDARY_LENGTHS: [usize; 14] =
        [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 256, 1024];

    fn messages(len: usize) -> [Vec<u8>; MESSAGES] {
        core::array::from_fn(|lane| {
            (0..len)
                .map(|offset| (lane * 37 + offset * 13 + offset / 7) as u8)
                .collect()
        })
    }

    fn check_hash(inputs: [&[u8]; MESSAGES]) {
        let expected = inputs.map(|message| Digest(Sha256::digest(message).into()));
        assert_eq!(EmulatedScalar.execute(hash::<_>(inputs)), expected);
        assert_eq!(EmulatedIceLake.execute(hash::<_>(inputs)), expected);
        assert_eq!(EmulatedArmV9.execute(hash::<_>(inputs)), expected);
        assert_eq!(EmulatedNeon.execute(hash::<_>(inputs)), expected);
    }

    #[test]
    fn test_batch_boundaries() {
        for len in BOUNDARY_LENGTHS {
            let messages = messages(len);
            let inputs = core::array::from_fn(|lane| messages[lane].as_slice());
            check_hash(inputs);
        }
    }

    #[test]
    fn test_compress_initial_state() {
        for (full_len, padding_len) in [(0, 0), (0, 64), (64, 0), (64, 128), (256, 64)] {
            let messages = messages(full_len);
            let padding = messages_for_padding(padding_len);
            let inputs = core::array::from_fn(|lane| messages[lane].as_slice());
            let tails = core::array::from_fn(|lane| padding[lane].as_slice());
            let initial = core::array::from_fn(|word| {
                core::array::from_fn(|lane| {
                    (word as u32 * 0x1020304).wrapping_add(lane as u32 * 0x718293a) ^ 0xa5a5a5a5
                })
            });
            let mut expected = initial;
            for lane in 0..MESSAGES {
                let mut state = initial.map(|word| word[lane]);
                for segment in [inputs[lane], tails[lane]] {
                    for block in segment.as_chunks::<BLOCK_LENGTH>().0 {
                        compress256(&mut state, &[*block]);
                    }
                }
                for word in 0..STATE_WORDS {
                    expected[word][lane] = state[word];
                }
            }
            fn check<S: Simd>(
                simd: S,
                inputs: [&[u8]; MESSAGES],
                full_len: usize,
                tails: [&[u8]; MESSAGES],
                padding_len: usize,
                initial: [[u32; MESSAGES]; STATE_WORDS],
                expected: [[u32; MESSAGES]; STATE_WORDS],
            ) {
                assert_eq!(
                    compress_blocks(simd, inputs, full_len, tails, padding_len, initial,),
                    expected,
                );
            }
            check(
                EmulatedScalar,
                inputs,
                full_len,
                tails,
                padding_len,
                initial,
                expected,
            );
            check(
                EmulatedIceLake,
                inputs,
                full_len,
                tails,
                padding_len,
                initial,
                expected,
            );
            check(
                EmulatedArmV9,
                inputs,
                full_len,
                tails,
                padding_len,
                initial,
                expected,
            );
            check(
                EmulatedNeon,
                inputs,
                full_len,
                tails,
                padding_len,
                initial,
                expected,
            );
        }
    }

    fn messages_for_padding(len: usize) -> [Vec<u8>; MESSAGES] {
        messages(len).map(|mut message| {
            message.iter_mut().for_each(|byte| *byte ^= 0x5a);
            message
        })
    }

    fn dispatched_hash(inputs: [&[u8]; MESSAGES]) -> [Digest; MESSAGES] {
        struct Hash<'a>([&'a [u8]; MESSAGES]);
        impl<S: Simd> Operation<S> for Hash<'_> {
            type Output = [Digest; MESSAGES];

            #[inline(always)]
            fn portable(self, simd: S) -> Self::Output {
                simd.execute(hash::<S>(self.0))
            }
        }
        commonware_simd::dispatch(Hash(inputs))
    }

    #[test]
    fn test_batch_dispatched() {
        for len in BOUNDARY_LENGTHS {
            let messages = messages(len);
            let inputs = core::array::from_fn(|lane| messages[lane].as_slice());
            let expected = inputs.map(|message| Digest(Sha256::digest(message).into()));
            assert_eq!(dispatched_hash(inputs), expected, "dispatched length {len}");
        }
    }

    #[test]
    fn test_instruction_leaves() {
        fn path<S: Simd, O: Operation<S>>(
            operation: O,
        ) -> impl Operation<S, Output = (O::Output, bool)> {
            struct Path<O>(O);

            impl<S: Simd, O: Operation<S>> Operation<S> for Path<O> {
                type Output = (O::Output, bool);

                fn portable(self, simd: S) -> Self::Output {
                    (self.0.portable(simd), false)
                }

                fn ice_lake(self, simd: S) -> Self::Output
                where
                    S: IceLake,
                {
                    (self.0.ice_lake(simd), true)
                }
            }

            Path(operation)
        }

        fn check<S: Simd>(simd: S, specialized: bool) {
            let a = core::array::from_fn::<_, MESSAGES, _>(|lane| {
                0x10203040u32.wrapping_mul(lane as u32)
            });
            let b = a.map(|word| word.rotate_left(13) ^ 0xa5a5a5a5);
            let c = a.map(|word| !word.rotate_right(7));
            let av = simd.u32_load(&a[..S::U32_LANES]);
            let bv = simd.u32_load(&b[..S::U32_LANES]);
            let cv = simd.u32_load(&c[..S::U32_LANES]);
            for ((value, selected), expected) in [
                (
                    simd.execute(path::<S, _>(xor3::<S>(av, bv, cv))),
                    core::array::from_fn::<_, MESSAGES, _>(|lane| a[lane] ^ b[lane] ^ c[lane]),
                ),
                (
                    simd.execute(path::<S, _>(choice::<S>(av, bv, cv))),
                    core::array::from_fn::<_, MESSAGES, _>(|lane| {
                        (a[lane] & b[lane]) ^ (!a[lane] & c[lane])
                    }),
                ),
                (
                    simd.execute(path::<S, _>(majority::<S>(av, bv, cv))),
                    core::array::from_fn::<_, MESSAGES, _>(|lane| {
                        (a[lane] & b[lane]) ^ (a[lane] & c[lane]) ^ (b[lane] & c[lane])
                    }),
                ),
            ] {
                assert_eq!(selected, specialized);
                let mut output = [0; MESSAGES];
                simd.u32_store(value, &mut output[..S::U32_LANES]);
                assert_eq!(output[..S::U32_LANES], expected[..S::U32_LANES]);
            }

            let messages = messages(2 * BLOCK_LENGTH + 3);
            let inputs = core::array::from_fn::<_, MESSAGES, _>(|lane| &messages[lane][3..]);
            let (schedule, selected) = simd.execute(path::<S, _>(load::<S>(&inputs, BLOCK_LENGTH)));
            assert_eq!(selected, specialized);
            for (word, value) in schedule.into_iter().enumerate() {
                let mut output = [0; MESSAGES];
                simd.u32_store(value, &mut output[..S::U32_LANES]);
                for lane in 0..S::U32_LANES {
                    let offset = BLOCK_LENGTH + word * 4;
                    assert_eq!(
                        output[lane],
                        u32::from_be_bytes(inputs[lane][offset..offset + 4].try_into().unwrap())
                    );
                }
            }
        }

        check(EmulatedScalar, false);
        check(EmulatedIceLake, true);
        check(EmulatedArmV9, false);
        check(EmulatedNeon, false);
    }

    #[test]
    fn test_batch_unaligned() {
        for len in BOUNDARY_LENGTHS {
            let messages = messages(len + 3);
            let inputs = core::array::from_fn(|lane| &messages[lane][3..]);
            check_hash(inputs);
            let expected = inputs.map(|message| Digest(Sha256::digest(message).into()));
            assert_eq!(dispatched_hash(inputs), expected);
        }
    }

    #[test]
    fn test_batch_bit_patterns() {
        for byte in [0, 0xff, 0x55, 0xaa] {
            let mut messages = [[byte; 128]; MESSAGES];
            for (lane, message) in messages.iter_mut().enumerate() {
                message[lane] ^= 1 << (lane % 8);
            }
            let inputs = core::array::from_fn(|lane| messages[lane].as_slice());
            check_hash(inputs);
        }
    }

    #[test]
    #[should_panic(expected = "SHA-256 batch inputs must have equal lengths")]
    fn test_batch_rejects_unequal_lengths() {
        let mut inputs: [&[u8]; MESSAGES] = [&[]; MESSAGES];
        inputs[15] = &[1];
        let _ = EmulatedScalar.execute(hash::<_>(inputs));
    }
}
