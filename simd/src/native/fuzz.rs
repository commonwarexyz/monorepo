//! Private differential checks shared by native instruction profiles.

use crate::Simd;
#[cfg(not(miri))]
use crate::{ArmV9, IceLake, Neon};
#[cfg(not(miri))]
use arbitrary::Unstructured;

#[cfg(not(miri))]
fn bytes<S: Simd>(s: S, value: S::U8) -> [u8; 66] {
    let mut output = [0xa5; 66];
    s.u8_store(value, &mut output[1..]);
    output
}

#[cfg(not(miri))]
fn words<S: Simd>(s: S, value: S::U32) -> [u32; 18] {
    let mut output = [0xa5a5_a5a5; 18];
    s.u32_store(value, &mut output[1..]);
    output
}

pub fn longs<S: Simd>(s: S, value: S::U64) -> [u64; 10] {
    let mut output = [0xa5a5_a5a5_a5a5_a5a5; 10];
    s.u64_store(value, &mut output[1..]);
    output
}

#[cfg(not(miri))]
pub fn common<N: Simd, E: Simd>(n: N, e: E, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    assert_eq!(N::U8_LANES, E::U8_LANES);
    assert_eq!(N::U32_LANES, E::U32_LANES);
    assert_eq!(N::U64_LANES, E::U64_LANES);
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
    assert_eq!(n.u64_extract::<0>(na), e.u64_extract::<0>(ea));
    check!(u64_insert::<0>(na, b[0]); (ea, b[0]));
    assert_eq!(n.u64_extract::<1>(na), e.u64_extract::<1>(ea));
    check!(u64_insert::<1>(na, b[0]); (ea, b[0]));
    Ok(())
}

#[cfg(not(miri))]
fn halves<S: Neon>(s: S, value: S::U32Half) -> [u64; 10] {
    longs(s, s.u32_widen_mul(value, s.u32_half_splat(1)))
}

#[cfg(not(miri))]
fn shorts<S: Neon>(s: S, value: S::U16) -> [u8; 66] {
    bytes(s, s.u16_narrow_pair(value, s.u16_shr::<8>(value)))
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
    Ok(())
}

#[cfg(not(miri))]
fn words128<S: IceLake>(s: S, value: S::U32x4) -> [u32; 6] {
    let mut output = [0xa5a5_a5a5; 6];
    s.u32x4_store(value, &mut output[1..]);
    output
}

#[cfg(not(miri))]
pub fn ice_lake<N: IceLake, E: IceLake>(
    n: N,
    e: E,
    u: &mut Unstructured<'_>,
) -> arbitrary::Result<()> {
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
    assert_eq!(words(n, n.u32_unpackhi64(na, nb)), words(e, e.u32_unpackhi64(ea, eb)));
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
    assert_eq!(
        words(
            n,
            n.u32_xor_rotate_right::<0>(n.u32_load(&a), n.u32_load(&b))
        ),
        words(
            e,
            e.u32_xor_rotate_right::<0>(e.u32_load(&a), e.u32_load(&b))
        )
    );
    assert_eq!(
        words(
            n,
            n.u32_xor_rotate_right::<1>(n.u32_load(&a), n.u32_load(&b))
        ),
        words(
            e,
            e.u32_xor_rotate_right::<1>(e.u32_load(&a), e.u32_load(&b))
        )
    );
    assert_eq!(
        words(
            n,
            n.u32_xor_rotate_right::<7>(n.u32_load(&a), n.u32_load(&b))
        ),
        words(
            e,
            e.u32_xor_rotate_right::<7>(e.u32_load(&a), e.u32_load(&b))
        )
    );
    assert_eq!(
        words(
            n,
            n.u32_xor_rotate_right::<31>(n.u32_load(&a), n.u32_load(&b))
        ),
        words(
            e,
            e.u32_xor_rotate_right::<31>(e.u32_load(&a), e.u32_load(&b))
        )
    );
    Ok(())
}
