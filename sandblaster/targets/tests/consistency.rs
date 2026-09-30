//! Portable consistency tests (any host): the SHA instruction models and the
//! compressions assembled from them agree with plain FIPS 180-4
//! (DESIGN.md §9.2, §9.3 `VariantEquiv` in executable form).
//!
//! For SHA-NI these are the only checks possible on this machine (hardware
//! validation pending); for Arm SHA2 they complement the hardware campaigns.

use sandblaster_targets::compress;
use sandblaster_targets::consistency;
use sandblaster_targets::diff::{self, Config, DEFAULT_SEED, assert_all_passed};
use sandblaster_targets::fips;
use sandblaster_targets::reference;
use sandblaster_targets::registry::{self, Arch};
use sandblaster_targets::x86_64 as x86;

#[test]
fn aarch64_sha2_models_agree_with_fips() {
    assert_all_passed(&consistency::aarch64_models(&Config::fast()));
}

#[test]
fn x86_sha_ni_models_agree_with_fips() {
    assert_all_passed(&consistency::x86_models(&Config::fast()));
}

#[test]
fn compositions_agree_with_fips() {
    let outcomes = consistency::compositions(&Config::fast());
    assert!(
        outcomes
            .iter()
            .any(|o| o.name == "compress_sha2_models_vs_fips")
    );
    assert!(
        outcomes
            .iter()
            .any(|o| o.name == "compress_shani_models_vs_fips")
    );
    assert_all_passed(&outcomes);
}

/// Hash whole messages (multi-block, both padding shapes) with the model
/// compressions and compare with the FIPS known answers.
#[test]
fn model_compressions_hash_known_answers() {
    fn sha256_with(msg: &[u8], compress_fn: fn([u32; 8], &[u8; 64]) -> [u32; 8]) -> String {
        let mut padded = msg.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
        let mut s = fips::H0;
        for c in padded.as_chunks::<64>().0 {
            s = compress_fn(s, c);
        }
        let mut d = [0u8; 32];
        for (i, w) in s.iter().enumerate() {
            d[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        fips::hex(&d)
    }
    let cases: [(&[u8], &str); 3] = [
        (
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ];
    for (msg, want) in cases {
        assert_eq!(sha256_with(msg, compress::compress_aarch64_models), want);
        assert_eq!(sha256_with(msg, compress::compress_x86_models), want);
        assert_eq!(sha256_with(msg, fips::compress), want);
    }
}

#[test]
#[ignore = "§9.2-size consistency campaign; run with --release -- --ignored"]
fn large_consistency_campaign() {
    assert_all_passed(&consistency::run_all(&Config::large()));
}

/// Every 256/512-bit x86 model agrees with its independent reference
/// implementation (MODELS.md §10.8) on corners, random inputs and every
/// immediate. (The §9.2-size run is `large_consistency_campaign`.)
#[test]
fn x86_wide_models_agree_with_their_references() {
    let cfg = Config { random_per_model: 20_000, seed: DEFAULT_SEED };
    let outcomes = consistency::x86_wide_models(&cfg);
    assert_eq!(outcomes.len(), reference::NAMES.len());
    for o in &outcomes {
        let m = registry::find(Arch::X86_64, &o.name).expect("registered");
        assert!(o.skipped.is_none() && o.corner > 0 && o.random >= cfg.random_per_model, "{}", o.summary());
        assert_eq!(o.immediates, m.immediates, "{}: every immediate", o.name);
    }
    assert_all_passed(&outcomes);
}

/// The reference comparison catches plausible transcription bugs of the
/// wide models: each "wrong model" below disagrees with the reference.
#[test]
fn reference_check_detects_plausible_wrong_models() {
    let n = 2_000;
    let caught = |o: diff::Outcome| assert!(o.mismatches > 0, "not caught: {}", o.summary());
    // VPSHUFB (EVEX) indexing across the whole vector instead of per 128-bit lane.
    caught(diff::diff2("pshufb512 without lanes", n, 1, |a: [u8; 64], b: [u8; 64]| -> [u8; 64] {
        core::array::from_fn(|j| if b[j] & 0x80 != 0 { 0 } else { a[(b[j] & 63) as usize] })
    }, reference::_mm512_shuffle_epi8));
    // VPERMI2Q selecting the table with bit 4 instead of bit 3.
    caught(diff::diff3("permutex2var bit 4", n, 2, |a: [u8; 64], idx: [u8; 64], b: [u8; 64]| {
        let sel: [u8; 64] = core::array::from_fn(|i| if i % 8 == 0 { (idx[i] & 7) | ((idx[i] >> 1) & 8) } else { idx[i] });
        x86::_mm512_permutex2var_epi64(a, sel, b)
    }, reference::_mm512_permutex2var_epi64));
    // IFMA using the low 64 bits of the product instead of bits 51:0.
    caught(diff::diff3("madd52lo mod 2^64", n, 3, |a: [u8; 64], b: [u8; 64], c: [u8; 64]| {
        let q = |v: &[u8; 64], j: usize| u64::from_le_bytes(v[8 * j..8 * j + 8].try_into().unwrap());
        let mut out = [0u8; 64];
        for j in 0..8 {
            let p = (q(&b, j) & ((1 << 52) - 1)).wrapping_mul(q(&c, j) & ((1 << 52) - 1));
            out[8 * j..8 * j + 8].copy_from_slice(&q(&a, j).wrapping_add(p).to_le_bytes());
        }
        out
    }, reference::_mm512_madd52lo_epu64));
    // GF2P8AFFINEQB reading matrix row i from byte i instead of byte 7 - i.
    caught(diff::diff_imm2("affine rows reversed", 0..=3, n, 4, |x: [u8; 16], a: [u8; 16], b: i32| {
        let mut rev = a;
        rev[..8].reverse();
        rev[8..].reverse();
        x86::_mm_gf2p8affine_epi64_epi8(x, rev, b)
    }, reference::_mm_gf2p8affine_epi64_epi8));
    // VPALIGNR (AVX2) as one 256-bit byte shift instead of two 128-bit lanes.
    caught(diff::diff_imm2("alignr256 unlaned", 1..=20, n, 5, |a: [u8; 32], b: [u8; 32], imm: i32| -> [u8; 32] {
        core::array::from_fn(|i| { let k = i + imm as usize; if k < 32 { b[k] } else if k < 64 { a[k - 32] } else { 0 } })
    }, reference::_mm256_alignr_epi8));
    // _mm256_permutevar8x32_epi32 with the operands in instruction order.
    caught(diff::diff2("permutevar8x32 swapped", n, 6, |a: [u8; 32], idx: [u8; 32]| x86::_mm256_permutevar8x32_epi32(idx, a),
        reference::_mm256_permutevar8x32_epi32));
    // VPSHRDVQ with the halves swapped (DEST as the high half).
    caught(diff::diff3("shrdv swapped", n, 7, |a: [u8; 64], b: [u8; 64], c: [u8; 64]| x86::_mm512_shrdv_epi64(b, a, c),
        reference::_mm512_shrdv_epi64));
    // VPSLLD by an immediate taken mod 32 (the hardware zeroes above 31).
    caught(diff::diff_imm1("slli mod 32", 30..=40, n, 8, |a: [u8; 64], imm: i32| x86::_mm512_slli_epi32(a, imm % 32),
        reference::_mm512_slli_epi32));
    // VPTERNLOG with the operand roles of the index permuted (b as the high bit).
    caught(diff::diff_imm3("ternlog roles", 0x80..=0x8f, 200, 9, |a: [u8; 64], b: [u8; 64], c: [u8; 64], imm: i32| {
        x86::_mm512_ternarylogic_epi32(b, a, c, imm)
    }, reference::_mm512_ternarylogic_epi32));
}
