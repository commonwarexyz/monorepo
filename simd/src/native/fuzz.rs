//! Private differential checks shared by native instruction profiles.

use crate::Simd;
#[cfg(not(miri))]
use crate::{ArmV9, IceLake, Neon};
#[cfg(not(miri))]
use arbitrary::Unstructured;

#[cfg(not(miri))]
fn bytes<S: Simd>(simd: S, value: S::U8) -> [u8; 66] {
    let mut output = [0xa5; 66];
    simd.u8_store(value, &mut output[1..]);
    output
}

#[cfg(not(miri))]
fn words<S: Simd>(simd: S, value: S::U32) -> [u32; 18] {
    let mut output = [0xa5a5_a5a5; 18];
    simd.u32_store(value, &mut output[1..]);
    output
}

pub fn longs<S: Simd>(simd: S, value: S::U64) -> [u64; 10] {
    let mut output = [0xa5a5_a5a5_a5a5_a5a5; 10];
    simd.u64_store(value, &mut output[1..]);
    output
}

#[cfg(not(miri))]
pub fn common<N: Simd, E: Simd>(n: N, e: E, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    assert_eq!(N::U8_LANES, E::U8_LANES);
    assert_eq!(N::U32_LANES, E::U32_LANES);
    assert_eq!(N::U64_LANES, E::U64_LANES);
    let a: [u32; 4] = u.arbitrary()?;
    let b: [u32; 4] = u.arbitrary()?;
    let input: [u8; 18] = u.arbitrary()?;
    let na = n.u32x4_load(&a);
    let nb = n.u32x4_load(&b);
    let ea = e.u32x4_load(&a);
    let eb = e.u32x4_load(&b);
    fn fixed<S: Simd>(simd: S, value: S::U32x4) -> [u32; 4] {
        let mut output = [0; 4];
        simd.u32x4_store(value, &mut output);
        output
    }
    assert_eq!(fixed(n, na), fixed(e, ea));
    assert_eq!(fixed(n, n.u32x4_add(na, nb)), fixed(e, e.u32x4_add(ea, eb)));
    assert_eq!(
        fixed(n, n.u32x4_load_be(&input[1..])),
        fixed(e, e.u32x4_load_be(&input[1..]))
    );
    assert_eq!(
        fixed(n, n.u32x4_load_be2(&input[1..])),
        fixed(e, e.u32x4_load_be2(&input[1..]))
    );
    let mut native = input;
    let mut emulated = input;
    n.u32x4_store_be(na, &mut native[1..]);
    e.u32x4_store_be(ea, &mut emulated[1..]);
    assert_eq!(native, emulated);
    macro_rules! align {
        ($($offset:literal),*) => { $(
            assert_eq!(fixed(n, n.u32x4_align::<$offset>(na, nb)), fixed(e, e.u32x4_align::<$offset>(ea, eb)));
        )* };
    }
    align!(0, 1, 2, 3, 4);
    macro_rules! blend {
        ($($mask:literal),*) => { $(
            assert_eq!(fixed(n, n.u32x4_blend::<$mask>(na, nb)), fixed(e, e.u32x4_blend::<$mask>(ea, eb)));
        )* };
    }
    blend!(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    let a: [u8; 65] = u.arbitrary()?;
    let b: [u8; 65] = u.arbitrary()?;
    let na = n.u8_load(&a[1..]);
    let nb = n.u8_load(&b[1..]);
    let ea = e.u8_load(&a[1..]);
    let eb = e.u8_load(&b[1..]);
    macro_rules! byte {
        ($method:ident $(::<$imm:literal>)? ($($arg:expr),*); ($($earg:expr),*)) => {
            assert_eq!(bytes(n, n.$method $(::<$imm>)? ($($arg),*)), bytes(e, e.$method $(::<$imm>)? ($($earg),*)));
        };
    }
    assert_eq!(bytes(n, na), bytes(e, ea));
    byte!(u8_splat(a[0]); (a[0]));
    byte!(u8_xor(na, nb); (ea, eb));
    byte!(u8_and(na, nb); (ea, eb));
    byte!(u8_shl::<0>(na); (ea));
    byte!(u8_shl::<1>(na); (ea));
    byte!(u8_shl::<7>(na); (ea));
    byte!(u8_shr::<0>(na); (ea));
    byte!(u8_shr::<1>(na); (ea));
    byte!(u8_shr::<7>(na); (ea));
    assert_eq!(n.u8_xor_fold(na), e.u8_xor_fold(ea));
    let len = u.int_in_range(0..=N::U8_LANES)?;
    byte!(u8_load_partial(&a[1..1 + len]); (&a[1..1 + len]));
    let mut native_output = [0xa5; 66];
    let mut emulated_output = native_output;
    n.u8_store_partial(na, &mut native_output[1..1 + len]);
    e.u8_store_partial(ea, &mut emulated_output[1..1 + len]);
    assert_eq!(native_output, emulated_output);
    let a: [u32; 17] = u.arbitrary()?;
    let b: [u32; 17] = u.arbitrary()?;
    let mask: [u32; 16] = u.arbitrary()?;
    let na = n.u32_load(&a[1..]);
    let nb = n.u32_load(&b[1..]);
    let ea = e.u32_load(&a[1..]);
    let eb = e.u32_load(&b[1..]);
    macro_rules! check {
        ($method:ident $(::<$imm:literal>)? ($($arg:expr),*); ($($earg:expr),*)) => {
            assert_eq!(words(n, n.$method $(::<$imm>)? ($($arg),*)), words(e, e.$method $(::<$imm>)? ($($earg),*)));
        };
    }
    assert_eq!(words(n, na), words(e, ea));
    check!(u32_splat(a[0]); (a[0]));
    check!(u32_add(na, nb); (ea, eb));
    check!(u32_sub(na, nb); (ea, eb));
    check!(u32_and(na, nb); (ea, eb));
    check!(u32_or(na, nb); (ea, eb));
    check!(u32_xor(na, nb); (ea, eb));
    check!(u32_select(n.u32_load(&mask), na, nb); (e.u32_load(&mask), ea, eb));
    check!(u32_shl::<0>(na); (ea));
    check!(u32_shl::<1>(na); (ea));
    check!(u32_shl::<31>(na); (ea));
    check!(u32_shr::<0>(na); (ea));
    check!(u32_shr::<1>(na); (ea));
    check!(u32_shr::<31>(na); (ea));
    check!(u32_rotate_right::<0>(na); (ea));
    check!(u32_rotate_right::<1>(na); (ea));
    check!(u32_rotate_right::<31>(na); (ea));
    let indices: [u8; 16] = u.arbitrary()?;
    let one = indices.map(|i| usize::from(i) % N::U32_LANES);
    let two = indices.map(|i| usize::from(i) % (2 * N::U32_LANES));
    check!(u32_permute(na, &one); (ea, &one));
    check!(u32_permute2(na, nb, &two); (ea, eb, &two));
    let a: [u64; 9] = u.arbitrary()?;
    let b: [u64; 9] = u.arbitrary()?;
    let mask: [u64; 8] = u.arbitrary()?;
    let na = n.u64_load(&a[1..]);
    let nb = n.u64_load(&b[1..]);
    let ea = e.u64_load(&a[1..]);
    let eb = e.u64_load(&b[1..]);
    macro_rules! check {
        ($method:ident $(::<$imm:literal>)? ($($arg:expr),*); ($($earg:expr),*)) => {
            assert_eq!(longs(n, n.$method $(::<$imm>)? ($($arg),*)), longs(e, e.$method $(::<$imm>)? ($($earg),*)));
        };
    }
    assert_eq!(longs(n, na), longs(e, ea));
    check!(u64_splat(a[0]); (a[0]));
    check!(u64_add(na, nb); (ea, eb));
    check!(u64_sub(na, nb); (ea, eb));
    check!(u64_and(na, nb); (ea, eb));
    check!(u64_or(na, nb); (ea, eb));
    check!(u64_xor(na, nb); (ea, eb));
    check!(u64_select(n.u64_load(&mask), na, nb); (e.u64_load(&mask), ea, eb));
    check!(u64_shl::<0>(na); (ea));
    check!(u64_shl::<1>(na); (ea));
    check!(u64_shl::<63>(na); (ea));
    check!(u64_shr::<0>(na); (ea));
    check!(u64_shr::<1>(na); (ea));
    check!(u64_shr::<63>(na); (ea));
    macro_rules! lanes { ($($lane:literal),*) => { $(
        if $lane < N::U64_LANES {
            assert_eq!(n.u64_extract::<$lane>(na), e.u64_extract::<$lane>(ea));
            check!(u64_insert::<$lane>(na, b[0]); (ea, b[0]));
        }
    )* }; }
    lanes!(0, 1, 2, 3, 4, 5, 6, 7);
    Ok(())
}

#[cfg(not(miri))]
fn halves<S: Neon>(simd: S, value: S::U32Half) -> [u64; 10] {
    longs(simd, simd.u32_widen_mul(value, simd.u32_half_splat(1)))
}

#[cfg(not(miri))]
fn shorts<S: Neon>(simd: S, value: S::U16) -> [u8; 66] {
    bytes(simd, simd.u16_narrow_pair(value, simd.u16_shr::<8>(value)))
}

#[cfg(not(miri))]
pub fn neon<N: Neon, E: Neon>(n: N, e: E, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let a: [u8; 16] = u.arbitrary()?;
    let b: [u8; 16] = u.arbitrary()?;
    let na = n.u8_load(&a);
    let nb = n.u8_load(&b);
    let ea = e.u8_load(&a);
    let eb = e.u8_load(&b);
    assert_eq!(
        bytes(n, n.u8_table_lookup(na, nb)),
        bytes(e, e.u8_table_lookup(ea, eb))
    );
    let nl = n.u8_clmul_lo(na, nb);
    let nh = n.u8_clmul_hi(na, nb);
    let el = e.u8_clmul_lo(ea, eb);
    let eh = e.u8_clmul_hi(ea, eb);
    assert_eq!(shorts(n, nl), shorts(e, el));
    assert_eq!(shorts(n, nh), shorts(e, eh));
    assert_eq!(shorts(n, n.u16_xor(nl, nh)), shorts(e, e.u16_xor(el, eh)));
    assert_eq!(
        bytes(n, n.u16_narrow_pair(nl, nh)),
        bytes(e, e.u16_narrow_pair(el, eh))
    );
    assert_eq!(shorts(n, n.u16_shl::<0>(nl)), shorts(e, e.u16_shl::<0>(el)));
    assert_eq!(shorts(n, n.u16_shl::<1>(nl)), shorts(e, e.u16_shl::<1>(el)));
    assert_eq!(
        shorts(n, n.u16_shl::<15>(nl)),
        shorts(e, e.u16_shl::<15>(el))
    );
    assert_eq!(shorts(n, n.u16_shr::<0>(nl)), shorts(e, e.u16_shr::<0>(el)));
    assert_eq!(shorts(n, n.u16_shr::<1>(nl)), shorts(e, e.u16_shr::<1>(el)));
    assert_eq!(
        shorts(n, n.u16_shr::<15>(nl)),
        shorts(e, e.u16_shr::<15>(el))
    );
    let a: [u64; 2] = u.arbitrary()?;
    let b: [u64; 2] = u.arbitrary()?;
    let acc: [u64; 2] = u.arbitrary()?;
    let na = n.u64_narrow(n.u64_load(&a));
    let nb = n.u64_narrow(n.u64_load(&b));
    let ea = e.u64_narrow(e.u64_load(&a));
    let eb = e.u64_narrow(e.u64_load(&b));
    assert_eq!(halves(n, na), halves(e, ea));
    assert_eq!(
        halves(n, n.u32_half_splat(a[0] as u32)),
        halves(e, e.u32_half_splat(a[0] as u32))
    );
    assert_eq!(
        halves(n, n.u32_half_add(na, nb)),
        halves(e, e.u32_half_add(ea, eb))
    );
    assert_eq!(
        halves(n, n.u32_half_shl::<0>(na)),
        halves(e, e.u32_half_shl::<0>(ea))
    );
    assert_eq!(
        halves(n, n.u32_half_shl::<1>(na)),
        halves(e, e.u32_half_shl::<1>(ea))
    );
    assert_eq!(
        halves(n, n.u32_half_shl::<31>(na)),
        halves(e, e.u32_half_shl::<31>(ea))
    );
    assert_eq!(
        longs(n, n.u32_widen_mul(na, nb)),
        longs(e, e.u32_widen_mul(ea, eb))
    );
    assert_eq!(
        longs(n, n.u32_widen_madd(n.u64_load(&acc), na, nb)),
        longs(e, e.u32_widen_madd(e.u64_load(&acc), ea, eb))
    );
    let a: [u32; 4] = u.arbitrary()?;
    let b: [u32; 4] = u.arbitrary()?;
    let c: [u32; 4] = u.arbitrary()?;
    let na = n.u32x4_load(&a);
    let nb = n.u32x4_load(&b);
    let nc = n.u32x4_load(&c);
    let ea = e.u32x4_load(&a);
    let eb = e.u32x4_load(&b);
    let ec = e.u32x4_load(&c);
    fn fixed<S: Simd>(simd: S, value: S::U32x4) -> [u32; 4] {
        let mut output = [0; 4];
        simd.u32x4_store(value, &mut output);
        output
    }
    assert_eq!(
        fixed(n, n.sha256_h(na, nb, nc)),
        fixed(e, e.sha256_h(ea, eb, ec))
    );
    assert_eq!(
        fixed(n, n.sha256_h2(na, nb, nc)),
        fixed(e, e.sha256_h2(ea, eb, ec))
    );
    assert_eq!(
        fixed(n, n.sha256_su0(na, nb)),
        fixed(e, e.sha256_su0(ea, eb))
    );
    assert_eq!(
        fixed(n, n.sha256_su1(na, nb, nc)),
        fixed(e, e.sha256_su1(ea, eb, ec))
    );

    Ok(())
}

#[cfg(not(miri))]
fn words128<S: IceLake>(simd: S, value: S::U32x4) -> [u32; 6] {
    let mut output = [0xa5a5_a5a5; 6];
    simd.u32x4_store(value, &mut output[1..]);
    output
}

#[cfg(not(miri))]
pub fn ice_lake<N: IceLake, E: IceLake>(
    n: N,
    e: E,
    u: &mut Unstructured<'_>,
) -> arbitrary::Result<()> {
    let input: [u8; 66] = u.arbitrary()?;
    assert_eq!(
        words(n, n.u32_load_be(&input[1..])),
        words(e, e.u32_load_be(&input[1..]))
    );
    let a: [u8; 64] = u.arbitrary()?;
    let b: [u8; 64] = u.arbitrary()?;
    assert_eq!(
        bytes(n, n.u8_gf_mul(n.u8_load(&a), n.u8_load(&b))),
        bytes(e, e.u8_gf_mul(e.u8_load(&a), e.u8_load(&b)))
    );
    assert_eq!(
        bytes(n, n.u8_shuffle128(n.u8_load(&a), n.u8_load(&b))),
        bytes(e, e.u8_shuffle128(e.u8_load(&a), e.u8_load(&b)))
    );
    let a: [u32; 5] = u.arbitrary()?;
    let b: [u32; 5] = u.arbitrary()?;
    let k: [u32; 5] = u.arbitrary()?;
    let na = n.u32x4_load(&a[1..]);
    let nb = n.u32x4_load(&b[1..]);
    let nk = n.u32x4_load(&k[1..]);
    let ea = e.u32x4_load(&a[1..]);
    let eb = e.u32x4_load(&b[1..]);
    let ek = e.u32x4_load(&k[1..]);
    macro_rules! narrow {
        ($method:ident($($arg:expr),*); ($($earg:expr),*)) => {
            assert_eq!(words128(n, n.$method($($arg),*)), words128(e, e.$method($($earg),*)));
        };
    }
    assert_eq!(words128(n, na), words128(e, ea));
    narrow!(u32x4_add(na, nb); (ea, eb));
    narrow!(sha256_rounds2(na, nb, nk); (ea, eb, ek));
    narrow!(sha256_msg1(na, nb); (ea, eb));
    narrow!(sha256_msg2(na, nb); (ea, eb));
    macro_rules! shuffles128 { ($($m:literal),*) => { $(
        assert_eq!(words128(n, n.u32x4_shuffle::<$m>(na)), words128(e, e.u32x4_shuffle::<$m>(ea)));
    )* }; }
    shuffles128!(0, 14, 27, 177, 255);
    let a: [u64; 8] = u.arbitrary()?;
    let b: [u64; 8] = u.arbitrary()?;
    let acc: [u64; 8] = u.arbitrary()?;
    assert_eq!(
        longs(
            n,
            n.u64_madd52lo(n.u64_load(&acc), n.u64_load(&a), n.u64_load(&b))
        ),
        longs(
            e,
            e.u64_madd52lo(e.u64_load(&acc), e.u64_load(&a), e.u64_load(&b))
        )
    );
    assert_eq!(
        longs(
            n,
            n.u64_madd52hi(n.u64_load(&acc), n.u64_load(&a), n.u64_load(&b))
        ),
        longs(
            e,
            e.u64_madd52hi(e.u64_load(&acc), e.u64_load(&a), e.u64_load(&b))
        )
    );
    let a: [u32; 16] = u.arbitrary()?;
    let b: [u32; 16] = u.arbitrary()?;
    let na = n.u32_load(&a);
    let nb = n.u32_load(&b);
    let ea = e.u32_load(&a);
    let eb = e.u32_load(&b);
    assert_eq!(
        words(n, n.u32_shuffle128::<0>(na)),
        words(e, e.u32_shuffle128::<0>(ea))
    );
    assert_eq!(
        words(n, n.u32_shuffle128::<27>(na)),
        words(e, e.u32_shuffle128::<27>(ea))
    );
    assert_eq!(
        words(n, n.u32_shuffle128::<177>(na)),
        words(e, e.u32_shuffle128::<177>(ea))
    );
    assert_eq!(
        words(n, n.u32_shuffle128::<255>(na)),
        words(e, e.u32_shuffle128::<255>(ea))
    );
    assert_eq!(
        words(n, n.u32_shuffle2_128::<0>(na, nb)),
        words(e, e.u32_shuffle2_128::<0>(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_shuffle2_128::<27>(na, nb)),
        words(e, e.u32_shuffle2_128::<27>(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_shuffle2_128::<177>(na, nb)),
        words(e, e.u32_shuffle2_128::<177>(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_shuffle2_128::<255>(na, nb)),
        words(e, e.u32_shuffle2_128::<255>(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_blend128::<0>(na, nb)),
        words(e, e.u32_blend128::<0>(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_blend128::<5>(na, nb)),
        words(e, e.u32_blend128::<5>(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_blend128::<10>(na, nb)),
        words(e, e.u32_blend128::<10>(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_blend128::<15>(na, nb)),
        words(e, e.u32_blend128::<15>(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_unpacklo32(na, nb)),
        words(e, e.u32_unpacklo32(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_unpackhi32(na, nb)),
        words(e, e.u32_unpackhi32(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_unpacklo64(na, nb)),
        words(e, e.u32_unpacklo64(ea, eb))
    );
    assert_eq!(
        words(n, n.u32_unpackhi64(na, nb)),
        words(e, e.u32_unpackhi64(ea, eb))
    );
    let c: [u32; 16] = u.arbitrary()?;
    let nc = n.u32_load(&c);
    let ec = e.u32_load(&c);
    macro_rules! ternary { ($($m:literal),*) => { $(
        assert_eq!(words(n, n.u32_ternary::<$m>(na, nb, nc)), words(e, e.u32_ternary::<$m>(ea, eb, ec)));
    )* }; }
    ternary!(0, 255, 0x96, 0xca, 0xe8, 0xf0, 0xcc, 0xaa);
    macro_rules! groups { ($($m:literal),*) => { $(
        assert_eq!(words(n, n.u32_shuffle_groups::<$m>(na, nb)), words(e, e.u32_shuffle_groups::<$m>(ea, eb)));
    )* }; }
    groups!(0, 255, 0x44, 0xee, 0x88, 0xdd);
    Ok(())
}

#[cfg(not(miri))]
pub fn arm_v9<N: ArmV9, E: ArmV9>(n: N, e: E, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let a: [u32; 4] = u.arbitrary()?;
    let b: [u32; 4] = u.arbitrary()?;
    let na = n.u32_load(&a);
    let nb = n.u32_load(&b);
    let ea = e.u32_load(&a);
    let eb = e.u32_load(&b);
    macro_rules! rotations { ($($rotation:literal),*) => { $(
        assert_eq!(
            words(n, n.u32_xor_rotate_right::<$rotation>(na, nb)),
            words(e, e.u32_xor_rotate_right::<$rotation>(ea, eb)),
        );
    )* }; }
    rotations!(
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31
    );
    Ok(())
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::{bytes, longs, words};
    use crate::Simd;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn memory_contracts<S: Simd>(simd: S) {
        for len in 0..S::U8_LANES {
            let mut output = [0xa5; 66];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u8_load(&output[1..1 + len]))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    simd.u8_store(simd.u8_splat(0), &mut output[1..1 + len]);
                }))
                .is_err()
            );
            assert_eq!(output, [0xa5; 66]);
        }
        for len in 0..S::U32_LANES {
            let mut output = [0xa5a5_a5a5; 18];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_load(&output[1..1 + len]))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    simd.u32_store(simd.u32_splat(0), &mut output[1..1 + len]);
                }))
                .is_err()
            );
            assert_eq!(output, [0xa5a5_a5a5; 18]);
        }
        for len in 0..S::U64_LANES {
            let mut output = [0xa5a5_a5a5_a5a5_a5a5; 10];
            assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_load(&output[1..1 + len]))).is_err());
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    simd.u64_store(simd.u64_splat(0), &mut output[1..1 + len]);
                }))
                .is_err()
            );
            assert_eq!(output, [0xa5a5_a5a5_a5a5_a5a5; 10]);
        }

        let input: [u8; 66] = core::array::from_fn(|i| (i as u8).wrapping_mul(73));
        let value = simd.u8_load(&input[1..]);
        for len in 0..=S::U8_LANES {
            let mut expected = [0xa5; 66];
            expected[1..1 + S::U8_LANES].fill(0);
            expected[1..1 + len].copy_from_slice(&input[1..1 + len]);
            assert_eq!(
                bytes(simd, simd.u8_load_partial(&input[1..1 + len])),
                expected
            );
            let mut output = [0xa5; 66];
            simd.u8_store_partial(value, &mut output[1..1 + len]);
            expected[1 + len..1 + S::U8_LANES].fill(0xa5);
            assert_eq!(output, expected);
        }
        for len in [S::U8_LANES + 1, 65] {
            let mut output = [0xa5; 66];
            assert!(
                catch_unwind(AssertUnwindSafe(
                    || simd.u8_load_partial(&output[1..1 + len])
                ))
                .is_err()
            );
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    simd.u8_store_partial(value, &mut output[1..1 + len]);
                }))
                .is_err()
            );
            assert_eq!(output, [0xa5; 66]);
        }
    }

    fn permutation_contracts<S: Simd>(simd: S) {
        let a: [u32; 16] = core::array::from_fn(|i| 0xa000_0000 + i as u32);
        let b: [u32; 16] = core::array::from_fn(|i| 0xb000_0000 + i as u32);
        let av = simd.u32_load(&a);
        let bv = simd.u32_load(&b);
        for source in 0..2 * S::U32_LANES {
            let mut indices = [usize::MAX; 17];
            let mut expected = [0xa5a5_a5a5; 18];
            for i in 0..S::U32_LANES {
                indices[i] = (source + i) % S::U32_LANES;
                expected[i + 1] = a[indices[i]];
            }
            assert_eq!(words(simd, simd.u32_permute(av, &indices)), expected);
            for i in 0..S::U32_LANES {
                indices[i] = (source + i) % (2 * S::U32_LANES);
                expected[i + 1] = if indices[i] < S::U32_LANES {
                    a[indices[i]]
                } else {
                    b[indices[i] - S::U32_LANES]
                };
            }
            assert_eq!(words(simd, simd.u32_permute2(av, bv, &indices)), expected);
        }
        for len in 0..S::U32_LANES {
            let indices = [0; 16];
            assert!(
                catch_unwind(AssertUnwindSafe(|| simd.u32_permute(av, &indices[..len]))).is_err()
            );
            assert!(
                catch_unwind(AssertUnwindSafe(|| simd.u32_permute2(
                    av,
                    bv,
                    &indices[..len]
                )))
                .is_err()
            );
        }
        for lane in 0..S::U32_LANES {
            for invalid in [S::U32_LANES, usize::MAX] {
                let mut indices = [0; 16];
                indices[lane] = invalid;
                assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_permute(av, &indices))).is_err());
                indices[lane] = invalid.saturating_mul(2);
                assert!(
                    catch_unwind(AssertUnwindSafe(|| simd.u32_permute2(av, bv, &indices))).is_err()
                );
            }
        }
    }

    fn register_contracts<S: Simd>(simd: S) {
        let input: [u8; 64] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(73).wrapping_add(0x81));
        let value = simd.u8_load(&input);
        macro_rules! byte_shifts { ($($n:literal),*) => { $(
            let mut expected = [0xa5; 66];
            for i in 0..S::U8_LANES { expected[i + 1] = input[i] << $n; }
            assert_eq!(bytes(simd, simd.u8_shl::<$n>(value)), expected);
            for i in 0..S::U8_LANES { expected[i + 1] = input[i] >> $n; }
            assert_eq!(bytes(simd, simd.u8_shr::<$n>(value)), expected);
        )* }; }
        byte_shifts!(0, 1, 2, 3, 4, 5, 6, 7);
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u8_shl::<8>(value))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u8_shr::<8>(value))).is_err());

        let input: [u32; 16] = core::array::from_fn(|i| 0xfedc_ba98u32.rotate_left(i as u32));
        let value = simd.u32_load(&input);
        macro_rules! word_shifts { ($($n:literal),*) => { $(
            let mut expected = [0xa5a5_a5a5; 18];
            for i in 0..S::U32_LANES { expected[i + 1] = input[i] << $n; }
            assert_eq!(words(simd, simd.u32_shl::<$n>(value)), expected);
            for i in 0..S::U32_LANES { expected[i + 1] = input[i] >> $n; }
            assert_eq!(words(simd, simd.u32_shr::<$n>(value)), expected);
            for i in 0..S::U32_LANES { expected[i + 1] = input[i].rotate_right($n); }
            assert_eq!(words(simd, simd.u32_rotate_right::<$n>(value)), expected);
        )* }; }
        word_shifts!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31
        );
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_shl::<32>(value))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_shr::<32>(value))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u32_rotate_right::<32>(value))).is_err());

        let input: [u64; 8] =
            core::array::from_fn(|i| 0xfedc_ba98_7654_3210u64.rotate_left(i as u32 * 7));
        let value = simd.u64_load(&input);
        macro_rules! long_shifts { ($($n:literal),*) => { $(
            let mut expected = [0xa5a5_a5a5_a5a5_a5a5; 10];
            for i in 0..S::U64_LANES { expected[i + 1] = input[i] << $n; }
            assert_eq!(longs(simd, simd.u64_shl::<$n>(value)), expected);
            for i in 0..S::U64_LANES { expected[i + 1] = input[i] >> $n; }
            assert_eq!(longs(simd, simd.u64_shr::<$n>(value)), expected);
        )* }; }
        long_shifts!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63
        );
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_shl::<64>(value))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_shr::<64>(value))).is_err());
        macro_rules! lanes { ($($n:literal),*) => { $(
            if $n < S::U64_LANES {
                assert_eq!(simd.u64_extract::<$n>(value), input[$n]);
                let mut expected = [0xa5a5_a5a5_a5a5_a5a5; 10];
                expected[1..1 + S::U64_LANES].copy_from_slice(&input[..S::U64_LANES]);
                expected[$n + 1] = !input[$n];
                assert_eq!(longs(simd, simd.u64_insert::<$n>(value, !input[$n])), expected);
            } else {
                assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_extract::<$n>(value))).is_err());
                assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_insert::<$n>(value, 0))).is_err());
            }
        )* }; }
        lanes!(0, 1, 2, 3, 4, 5, 6, 7);
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_extract::<8>(value))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| simd.u64_insert::<8>(value, 0))).is_err());
    }

    #[test]
    fn native_register_contracts() {
        #[cfg(target_arch = "x86_64")]
        if let Some(simd) = crate::native::NativeIceLake::new() {
            register_contracts(simd);
        }
        #[cfg(target_arch = "aarch64")]
        {
            if let Some(simd) = crate::native::NativeNeon::new() {
                register_contracts(simd);
            }
            if let Some(simd) = crate::native::NativeArmV9::new() {
                register_contracts(simd);
            }
        }
    }

    #[test]
    fn native_input_contracts() {
        fn check<S: Simd>(simd: S) {
            memory_contracts(simd);
            permutation_contracts(simd);
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(simd) = crate::native::NativeIceLake::new() {
            check(simd);
        }
        #[cfg(target_arch = "aarch64")]
        {
            if let Some(simd) = crate::native::NativeNeon::new() {
                check(simd);
            }
            if let Some(simd) = crate::native::NativeArmV9::new() {
                check(simd);
            }
        }
    }
}
