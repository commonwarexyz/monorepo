//! Interleaved SHA-256 compression for two merkle nodes.

use super::constants::K;
use crate::sha256::{Digest, IV};
use commonware_simd::{ArmV9, IceLake, Neon, Operation, Simd};

#[inline(always)]
const fn schedule_word(w: u32, x: u32, y: u32, z: u32) -> u32 {
    w.wrapping_add(x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3))
        .wrapping_add(y)
        .wrapping_add(z.rotate_right(17) ^ z.rotate_right(19) ^ (z >> 10))
}

/// Expanded schedule and round constants for the BMT padding block.
const PAD64_WK: [u32; 64] = {
    let mut w = [0u32; 64];
    w[0] = 0x8000_0000;
    w[15] = 512;
    let mut i = 16;
    while i < 64 {
        w[i] = schedule_word(w[i - 16], w[i - 15], w[i - 7], w[i - 2]);
        i += 1;
    }
    i = 0;
    while i < 64 {
        w[i] = w[i].wrapping_add(K[i]);
        i += 1;
    }
    w
};

/// Hashes two nodes directly from their optional positions and digest parts.
#[inline(always)]
pub(super) fn hash<'a, S: Simd, const PREFIX: usize>(
    left_pos: &'a [u8; PREFIX],
    left_a: &'a [u8; 32],
    left_b: &'a [u8; 32],
    right_pos: &'a [u8; PREFIX],
    right_a: &'a [u8; 32],
    right_b: &'a [u8; 32],
) -> impl Operation<S, Output = (Digest, Digest)> + 'a {
    const { assert!(PREFIX == 0 || PREFIX == 8) };
    #[inline(always)]
    move |simd: S| {
        let initial = simd.execute(initialize::<S>());
        let state = (initial.0, initial.1, initial.0, initial.1);
        let (left, tail_left) = load::<S, PREFIX>(simd, left_pos, left_a, left_b);
        let (right, tail_right) = load::<S, PREFIX>(simd, right_pos, right_a, right_b);
        let state = compress::<S, false>(simd, state, left, right);
        let zero = simd.u32x4_load(&[0; 4]);
        let state = if PREFIX == 0 {
            compress::<S, true>(
                simd,
                state,
                (zero, zero, zero, zero),
                (zero, zero, zero, zero),
            )
        } else {
            let len = simd.u32x4_load(&[0, 0, 0, 576]);
            compress::<S, false>(
                simd,
                state,
                (tail_left, zero, zero, len),
                (tail_right, zero, zero, len),
            )
        };
        finish(simd, state)
    }
}

type State<S> = (
    <S as Simd>::U32x4,
    <S as Simd>::U32x4,
    <S as Simd>::U32x4,
    <S as Simd>::U32x4,
);
type Words<S> = State<S>;

#[inline(always)]
fn load<S: Simd, const PREFIX: usize>(
    simd: S,
    pos: &[u8; PREFIX],
    left: &[u8; 32],
    right: &[u8; 32],
) -> (Words<S>, S::U32x4) {
    let l0 = simd.u32x4_load_be(left);
    let l1 = simd.u32x4_load_be(&left[16..]);
    let r0 = simd.u32x4_load_be(right);
    let r1 = simd.u32x4_load_be(&right[16..]);
    if PREFIX == 0 {
        ((l0, l1, r0, r1), simd.u32x4_load(&[0; 4]))
    } else {
        let pos = simd.u32x4_load_be2(pos);
        let pad = simd.u32x4_load(&[0x8000_0000, 0, 0, 0]);
        let first = simd.u32x4_blend::<12>(pos, simd.u32x4_shuffle::<0x44>(l0));
        (
            (
                first,
                simd.u32x4_align::<2>(l0, l1),
                simd.u32x4_align::<2>(l1, r0),
                simd.u32x4_align::<2>(r0, r1),
            ),
            simd.u32x4_align::<2>(r1, pad),
        )
    }
}

#[inline(always)]
fn add_state<S: Simd>(simd: S, a: State<S>, b: State<S>) -> State<S> {
    (
        simd.u32x4_add(a.0, b.0),
        simd.u32x4_add(a.1, b.1),
        simd.u32x4_add(a.2, b.2),
        simd.u32x4_add(a.3, b.3),
    )
}

#[inline(always)]
fn compress<S: Simd, const PRECOMPUTED: bool>(
    simd: S,
    mut state: State<S>,
    left: Words<S>,
    right: Words<S>,
) -> State<S> {
    let saved = state;
    let (mut a, mut b, mut c, mut d) = left;
    let (mut e, mut f, mut g, mut h) = right;
    macro_rules! group {
        ($i:literal, $a:ident, $e:ident) => {{
            let (left, right) = if PRECOMPUTED {
                let wk = simd.u32x4_load(&PAD64_WK[$i..]);
                (wk, wk)
            } else {
                let k = simd.u32x4_load(&K[$i..]);
                (simd.u32x4_add($a, k), simd.u32x4_add($e, k))
            };
            state = simd.execute(rounds4::<S>(state, left, right));
        }};
        ($i:literal, $a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident) => {{
            group!($i, $a, $e);
            if !PRECOMPUTED {
                $a = simd.execute(schedule4::<S>($a, $b, $c, $d));
                $e = simd.execute(schedule4::<S>($e, $f, $g, $h));
            }
        }};
    }
    // Prepare each successor sixteen rounds ahead to overlap expansion with rounds.
    group!(0, a, b, c, d, e, f, g, h);
    group!(4, b, c, d, a, f, g, h, e);
    group!(8, c, d, a, b, g, h, e, f);
    group!(12, d, a, b, c, h, e, f, g);
    group!(16, a, b, c, d, e, f, g, h);
    group!(20, b, c, d, a, f, g, h, e);
    group!(24, c, d, a, b, g, h, e, f);
    group!(28, d, a, b, c, h, e, f, g);
    group!(32, a, b, c, d, e, f, g, h);
    group!(36, b, c, d, a, f, g, h, e);
    group!(40, c, d, a, b, g, h, e, f);
    group!(44, d, a, b, c, h, e, f, g);
    group!(48, a, e);
    group!(52, b, f);
    group!(56, c, g);
    group!(60, d, h);
    add_state(simd, saved, state)
}

#[inline(always)]
fn initialize<S: Simd>() -> impl Operation<S, Output = (S::U32x4, S::U32x4)> {
    struct Initialize;
    impl<S: Simd> Operation<S> for Initialize {
        type Output = (S::U32x4, S::U32x4);
        #[inline(always)]
        fn portable(self, simd: S) -> Self::Output {
            (simd.u32x4_load(&IV[..4]), simd.u32x4_load(&IV[4..]))
        }
        #[inline(always)]
        fn ice_lake(self, simd: S) -> Self::Output
        where
            S: IceLake,
        {
            (
                simd.u32x4_load(&[IV[5], IV[4], IV[1], IV[0]]),
                simd.u32x4_load(&[IV[7], IV[6], IV[3], IV[2]]),
            )
        }
    }
    Initialize
}

#[inline(always)]
fn rounds4<S: Simd>(
    state: State<S>,
    left: S::U32x4,
    right: S::U32x4,
) -> impl Operation<S, Output = State<S>> {
    struct Rounds<S: Simd>(State<S>, S::U32x4, S::U32x4);
    impl<S: Simd> Operation<S> for Rounds<S> {
        type Output = State<S>;
        #[inline(always)]
        fn portable(self, simd: S) -> Self::Output {
            #[inline(always)]
            fn one<S: Simd>(
                simd: S,
                abcd: S::U32x4,
                efgh: S::U32x4,
                wk: S::U32x4,
            ) -> (S::U32x4, S::U32x4) {
                let mut x = [0; 4];
                let mut y = [0; 4];
                let mut k = [0; 4];
                simd.u32x4_store(abcd, &mut x);
                simd.u32x4_store(efgh, &mut y);
                simd.u32x4_store(wk, &mut k);
                let [mut a, mut b, mut c, mut d] = x;
                let [mut e, mut f, mut g, mut h] = y;
                macro_rules! round {
                    ($i:literal) => {{
                        let t = h
                            .wrapping_add(
                                e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25),
                            )
                            .wrapping_add((e & f) ^ (!e & g))
                            .wrapping_add(k[$i]);
                        let u = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
                            .wrapping_add((a & b) ^ (a & c) ^ (b & c));
                        (a, b, c, d, e, f, g, h) =
                            (t.wrapping_add(u), a, b, c, d.wrapping_add(t), e, f, g);
                    }};
                }
                round!(0);
                round!(1);
                round!(2);
                round!(3);
                (
                    simd.u32x4_load(&[a, b, c, d]),
                    simd.u32x4_load(&[e, f, g, h]),
                )
            }
            let (a, b, c, d) = self.0;
            let (a, b) = one(simd, a, b, self.1);
            let (c, d) = one(simd, c, d, self.2);
            (a, b, c, d)
        }
        #[inline(always)]
        fn ice_lake(self, simd: S) -> Self::Output
        where
            S: IceLake,
        {
            let (a, b, c, d) = self.0;
            let b = simd.sha256_rounds2(b, a, self.1);
            let d = simd.sha256_rounds2(d, c, self.2);
            let a = simd.sha256_rounds2(a, b, simd.u32x4_shuffle::<0xee>(self.1));
            let c = simd.sha256_rounds2(c, d, simd.u32x4_shuffle::<0xee>(self.2));
            (a, b, c, d)
        }
        #[inline(always)]
        fn arm_v9(self, simd: S) -> Self::Output
        where
            S: ArmV9,
        {
            self.neon(simd)
        }

        #[inline(always)]
        fn neon(self, simd: S) -> Self::Output
        where
            S: Neon,
        {
            let (a, b, c, d) = self.0;
            let next_a = simd.sha256_h(a, b, self.1);
            let next_c = simd.sha256_h(c, d, self.2);
            let b = simd.sha256_h2(b, a, self.1);
            let d = simd.sha256_h2(d, c, self.2);
            (next_a, b, next_c, d)
        }
    }
    Rounds::<S>(state, left, right)
}

#[inline(always)]
fn schedule4<S: Simd>(
    a: S::U32x4,
    b: S::U32x4,
    c: S::U32x4,
    d: S::U32x4,
) -> impl Operation<S, Output = S::U32x4> {
    struct Schedule<S: Simd>(S::U32x4, S::U32x4, S::U32x4, S::U32x4);
    impl<S: Simd> Operation<S> for Schedule<S> {
        type Output = S::U32x4;
        #[inline(always)]
        fn portable(self, simd: S) -> Self::Output {
            let mut a = [0; 4];
            let mut b = [0; 4];
            let mut c = [0; 4];
            let mut d = [0; 4];
            simd.u32x4_store(self.0, &mut a);
            simd.u32x4_store(self.1, &mut b);
            simd.u32x4_store(self.2, &mut c);
            simd.u32x4_store(self.3, &mut d);
            let w0 = schedule_word(a[0], a[1], c[1], d[2]);
            let w1 = schedule_word(a[1], a[2], c[2], d[3]);
            let w2 = schedule_word(a[2], a[3], c[3], w0);
            let w3 = schedule_word(a[3], b[0], d[0], w1);
            simd.u32x4_load(&[w0, w1, w2, w3])
        }
        #[inline(always)]
        fn ice_lake(self, simd: S) -> Self::Output
        where
            S: IceLake,
        {
            let partial = simd.sha256_msg1(self.0, self.1);
            let partial = simd.u32x4_add(partial, simd.u32x4_align::<1>(self.2, self.3));
            simd.sha256_msg2(partial, self.3)
        }
        #[inline(always)]
        fn arm_v9(self, simd: S) -> Self::Output
        where
            S: ArmV9,
        {
            self.neon(simd)
        }

        #[inline(always)]
        fn neon(self, simd: S) -> Self::Output
        where
            S: Neon,
        {
            simd.sha256_su1(simd.sha256_su0(self.0, self.1), self.2, self.3)
        }
    }
    Schedule::<S>(a, b, c, d)
}

#[inline(always)]
fn normalize<S: Simd>(
    a: S::U32x4,
    b: S::U32x4,
) -> impl Operation<S, Output = (S::U32x4, S::U32x4)> {
    struct Normalize<S: Simd>(S::U32x4, S::U32x4);
    impl<S: Simd> Operation<S> for Normalize<S> {
        type Output = (S::U32x4, S::U32x4);
        #[inline(always)]
        fn portable(self, _: S) -> Self::Output {
            (self.0, self.1)
        }
        #[inline(always)]
        fn ice_lake(self, simd: S) -> Self::Output
        where
            S: IceLake,
        {
            (
                simd.u32x4_blend::<12>(
                    simd.u32x4_shuffle::<0x1b>(self.0),
                    simd.u32x4_shuffle::<0xb1>(self.1),
                ),
                simd.u32x4_blend::<12>(
                    simd.u32x4_shuffle::<0xb1>(self.0),
                    simd.u32x4_shuffle::<0x1b>(self.1),
                ),
            )
        }
    }
    Normalize::<S>(a, b)
}

#[inline(always)]
fn finish<S: Simd>(simd: S, state: State<S>) -> (Digest, Digest) {
    let (a, b) = simd.execute(normalize::<S>(state.0, state.1));
    let (c, d) = simd.execute(normalize::<S>(state.2, state.3));
    let mut left = Digest([0; 32]);
    let mut right = Digest([0; 32]);
    simd.u32x4_store_be(a, &mut left.0);
    simd.u32x4_store_be(b, &mut left.0[16..]);
    simd.u32x4_store_be(c, &mut right.0);
    simd.u32x4_store_be(d, &mut right.0[16..]);
    (left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_simd::{check_consistent, dispatch, test_dispatch};
    use sha2::{Digest as _, Sha256};

    fn reference(parts: &[&[u8]]) -> Digest {
        let mut hash = Sha256::new();
        for part in parts {
            hash.update(part);
        }
        Digest(hash.finalize().into())
    }

    #[test]
    fn test_pair_parts() {
        struct Hash<'a>([&'a [u8; 8]; 2], [&'a [u8; 32]; 4]);

        impl<S: Simd> Operation<S> for Hash<'_> {
            type Output = ((Digest, Digest), (Digest, Digest));

            #[inline(always)]
            fn portable(self, simd: S) -> Self::Output {
                let [p, q] = self.0;
                let [a, b, c, d] = self.1;
                (
                    simd.execute(hash::<S, 0>(&[], a, b, &[], c, d)),
                    simd.execute(hash::<S, 8>(p, a, b, q, c, d)),
                )
            }
        }

        // Offset each part independently to exercise byte-aligned vector loads.
        for offset in 0..16 {
            for pattern in 0..4 {
                let bytes: [[u8; 48]; 4] = core::array::from_fn(|part| {
                    core::array::from_fn(|i| match pattern {
                        0 => 0,
                        1 => 255,
                        2 => (part * 79 + i * 13 + i / 4) as u8,
                        _ => (1u8 << (i % 8)) ^ (part * 63) as u8,
                    })
                });
                let positions: [[u8; 24]; 2] = core::array::from_fn(|part| {
                    core::array::from_fn(|i| (part * 117 + i * 29 + pattern) as u8)
                });
                let parts: [&[u8; 32]; 4] = core::array::from_fn(|part| {
                    bytes[part][offset..offset + 32].try_into().unwrap()
                });
                let positions: [&[u8; 8]; 2] = core::array::from_fn(|part| {
                    positions[part][offset..offset + 8].try_into().unwrap()
                });
                let [p, q] = positions;
                let [a, b, c, d] = parts;
                let expected = (
                    (reference(&[a, b]), reference(&[c, d])),
                    (reference(&[p, a, b]), reference(&[q, c, d])),
                );
                assert_eq!(test_dispatch(Hash(positions, parts)), expected);
                check_consistent(|| Hash(positions, parts));
                assert_eq!(dispatch(Hash(positions, parts)), expected);
            }
        }
    }
}
