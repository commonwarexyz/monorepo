//! Positive `BvRefl` demonstrations (DESIGN.md §9.8, §9.3; docs/review-1.md,
//! hardware lens "where the SHA proofs would actually get stuck"): every
//! equation below is closed by `bvrefl` in the kernel, with timings printed
//! (`--nocapture`).
//!
//! * Arm `SHAchoose` = FIPS `Ch`, `SHAmajority` = FIPS `Maj` (truth tables).
//! * Reassociated SHA round sums with `W + K` folding (canonical sums).
//! * `(x >> 2) | (x << 30)` = `rotr(x, 2)` (disjoint linear terms merge).
//! * `from_be_bytes` = `rev` then `from_le_bytes`, and the shift/or, shift/add
//!   and multiply spellings (bit-slice concatenation).
//! * A 4-round `SHA256H`/`SHA256H2` block (lane-level core text, intrinsics
//!   unfolded by `BvRefl` only) = 4 FIPS rounds.
//! * The whole ARMv8-shaped compress (`compress_sha2`'s structure: 16
//!   `SHA256H`/`H2` groups, `SU0`/`SU1` schedule, `vrev32` + reinterpret
//!   loads) = the FIPS compress with a sliding schedule, on a symbolic state
//!   and block.
//! * The same 4-round block with the sandblaster/targets transcription.

mod common;

use std::time::Instant;

use common::*;
use sandblaster_kernel::api::*;

const SHA: &str = include_str!("sha256.core");

fn sha_env() -> Env {
    let mut env = prelude();
    load(&mut env, SHA).unwrap_or_else(|e| panic!("sha256.core: {e}"));
    env
}

/// Check `bvrefl(ty, lhs, rhs)` under binders `vars` (each `(name, type)`),
/// returning the time taken; also check that plain `refl` does not suffice
/// when `needs_bv`.
fn prove(env: &Env, vars: &str, ty: &str, lhs: &str, rhs: &str, needs_bv: bool) -> std::time::Duration {
    let binders = if vars.is_empty() { String::new() } else { format!("fun {vars} => ") };
    let pis = if vars.is_empty() { String::new() } else { format!("{} -> ", vars.replace(") (", ") -> (")) };
    let goal = format!("{pis}Eq({ty}, {lhs}, {rhs})");
    let t0 = Instant::now();
    check(env, &format!("{binders}bvrefl({ty}, {lhs}, {rhs})"), &goal).unwrap_or_else(|e| panic!("bvrefl {lhs} == {rhs}: {e}"));
    let dt = t0.elapsed();
    if needs_bv {
        assert!(check(env, &format!("{binders}refl({ty}, {lhs})"), &goal).is_err(), "refl already proves {lhs} == {rhs}");
    }
    dt
}

#[test]
fn sha_functions_and_sums() {
    let env = sha_env();
    let xyz = "(x : U32) (y : U32) (z : U32)";
    let t = prove(&env, xyz, "U32", "arm::sha_choose x y z", "sha::ch x y z", true);
    eprintln!("SHAchoose == Ch: {t:?}");
    let t = prove(&env, xyz, "U32", "arm::sha_majority x y z", "sha::maj x y z", true);
    eprintln!("SHAmajority == Maj: {t:?}");
    let t = prove(&env, "(x : U32)", "U32", "arm::sigma1 x", "sha::bsig1 x", false);
    eprintln!("Σ1 (rotr) == Σ1 (rotate_right): {t:?}");
    // Σ0 written with shifts (the portable spelling) vs rotations.
    let t = prove(
        &env,
        "(x : U32)",
        "U32",
        "#xor_u32(#xor_u32(#or_u32(#wshr_u32(x, 2u32), #wshl_u32(x, 30u32)), #or_u32(#wshr_u32(x, 13u32), #wshl_u32(x, 19u32))), \
         #or_u32(#wshr_u32(x, 22u32), #wshl_u32(x, 10u32)))",
        "sha::bsig0 x",
        true,
    );
    eprintln!("Σ0 with shifts == Σ0 with rotations: {t:?}");
    // FIPS T1 ((((h + Σ1(e)) + Ch) + K) + W) vs Arm t (Y3 + Σ1(Y0) + chs) + (W + K)
    // with K a literal: the constant folds into the sum.
    let efgh = "(e : U32) (f : U32) (g : U32) (h : U32) (w : U32)";
    let t = prove(
        &env,
        efgh,
        "U32",
        "#wadd_u32(#wadd_u32(#wadd_u32(#wadd_u32(h, sha::bsig1 e), sha::ch e f g), 1116352408u32), w)",
        "#wadd_u32(#wadd_u32(#wadd_u32(h, arm::sigma1 e), arm::sha_choose e f g), #wadd_u32(w, 1116352408u32))",
        true,
    );
    eprintln!("T1 reassociated with W+K folded: {t:?}");
    // ... and new a / new e of a round in both spellings.
    let t = prove(
        &env,
        "(a : U32) (b : U32) (c : U32) (d : U32) (e : U32) (f : U32) (g : U32) (h : U32) (w : U32)",
        "U32",
        "#wadd_u32(#wadd_u32(#wadd_u32(#wadd_u32(#wadd_u32(h, sha::bsig1 e), sha::ch e f g), 1116352408u32), w), \
                   #wadd_u32(sha::bsig0 a, sha::maj a b c))",
        "#wadd_u32(#wadd_u32(#wadd_u32(#wadd_u32(#wadd_u32(h, arm::sigma1 e), arm::sha_choose e f g), #wadd_u32(w, 1116352408u32)), \
                   arm::sigma0 a), arm::sha_majority a b c)",
        true,
    );
    eprintln!("new a, reassociated: {t:?}");
}

#[test]
fn rotations_and_byte_order() {
    let env = sha_env();
    let t = prove(&env, "(x : U32)", "U32", "#or_u32(#wshr_u32(x, 2u32), #wshl_u32(x, 30u32))", "#rotr_u32(x, 2u32)", true);
    eprintln!("(x >> 2) | (x << 30) == rotr(x, 2): {t:?}");
    let b = "(b : Array U8 4usize)";
    let i = |k: u32| format!("#cast_u8_u32(array::index U8 4usize b {k}usize .refl(Bool, true))");
    // By definition (from_be_bytes := from_le_bytes ∘ rev): conversion suffices.
    let t = prove(&env, b, "U32", "u32::from_be_bytes b", "u32::from_le_bytes (array::rev U8 4usize b)", false);
    eprintln!("from_be_bytes == from_le_bytes ∘ rev: {t:?}");
    let t = prove(
        &env,
        b,
        "U32",
        "u32::from_be_bytes b",
        &format!("#or_u32(#or_u32(#or_u32(#wshl_u32({}, 24u32), #wshl_u32({}, 16u32)), #wshl_u32({}, 8u32)), {})", i(0), i(1), i(2), i(3)),
        true,
    );
    eprintln!("from_be_bytes == shifts and ors: {t:?}");
    let t = prove(
        &env,
        b,
        "U32",
        "u32::from_be_bytes b",
        &format!(
            "#wadd_u32(#xor_u32({}, #wmul_u32({}, 256u32)), #wadd_u32(#wmul_u32({}, 16777216u32), #wshl_u32({}, 16u32)))",
            i(3),
            i(2),
            i(0),
            i(1)
        ),
        true,
    );
    eprintln!("from_be_bytes == shifts, adds, xors and multiplies in another order: {t:?}");
    // Byte swap through the little-endian bytes of a word.
    let t = prove(
        &env,
        "(x : U32)",
        "U32",
        "u32::from_be_bytes (u32::to_le_bytes x)",
        "#or_u32(#or_u32(#wshl_u32(x, 24u32), #and_u32(#wshl_u32(x, 8u32), 16711680u32)), \
                 #or_u32(#and_u32(#wshr_u32(x, 8u32), 65280u32), #wshr_u32(x, 24u32)))",
        true,
    );
    eprintln!("from_be_bytes(to_le_bytes x) == byte swap by masks: {t:?}");
}

#[test]
fn fixture_computes_the_sha256_of_abc() {
    // Both compress formulations on concrete data (intrinsics unfold on
    // closed arguments): SHA-256("abc") = ba7816bf 8f01cfea 414140de 5dae2223
    // b00361a3 96177a9c b410ff61 f20015ad.
    big_stack(|| {
        let env = sha_env();
        let iv = "v8 1779033703u32 3144134277u32 1013904242u32 2773480762u32 1359893119u32 2600822924u32 528734635u32 1541459225u32";
        let mut bytes = vec![0x61u8, 0x62, 0x63, 0x80];
        bytes.resize(63, 0);
        bytes.push(0x18);
        let mut blk = "Nil[U8]".to_string();
        for b in bytes.iter().rev() {
            blk = format!("Cons[U8]({b}u8, {blk})");
        }
        let blk = format!("pair(Array U8 64usize, {blk}, refl(Int, 64int))");
        let want = "v8 3128432319u32 2399260650u32 1094795486u32 1571693091u32 2953011619u32 2518121116u32 3021012833u32 4060091821u32";
        for f in ["sha::compress", "arm::compress"] {
            let got = norm(&env, &format!("fst({f} ({iv}) ({blk}))"));
            let exp = norm(&env, &format!("fst({want})"));
            assert_eq!(got, exp, "{f}");
        }
    })
}

#[test]
fn four_round_sha256h_block() {
    let env = sha_env();
    let vars = "(a : U32) (b : U32) (c : U32) (d : U32) (e : U32) (f : U32) (g : U32) (h : U32) \
                (w0 : U32) (w1 : U32) (w2 : U32) (w3 : U32)";
    let wk = "arm::vaddq_u32 (v4 w0 w1 w2 w3) arm::K4_0";
    let fips = "sha::round (sha::round (sha::round (sha::round (st(a, b, c, d, e, f, g, h)) 1116352408u32 w0) \
                1899447441u32 w1) 3049323471u32 w2) 3921009573u32 w3";
    let abcd = format!("match {fips} : St as _ return Array U32 4usize with | st(a, b, c, d, e, f, g, h) => v4 a b c d end");
    let efgh = format!("match {fips} : St as _ return Array U32 4usize with | st(a, b, c, d, e, f, g, h) => v4 e f g h end");
    let t = prove(&env, vars, "Array U32 4usize", &format!("arm::vsha256hq_u32 (v4 a b c d) (v4 e f g h) ({wk})"), &abcd, true);
    eprintln!("SHA256H (4 rounds) == 4 FIPS rounds (abcd): {t:?}");
    let t = prove(&env, vars, "Array U32 4usize", &format!("arm::vsha256h2q_u32 (v4 e f g h) (v4 a b c d) ({wk})"), &efgh, true);
    eprintln!("SHA256H2 (4 rounds) == 4 FIPS rounds (efgh): {t:?}");
    // The wrong argument order of vsha256h2q_u32 (the classic transcription
    // bug) is rejected.
    let bad = format!("fun {vars} => bvrefl(Array U32 4usize, arm::vsha256h2q_u32 (v4 a b c d) (v4 e f g h) ({wk}), {efgh})");
    assert!(infer(&env, &bad).is_err(), "h2 with swapped arguments");
    // Four schedule steps: SU1(SU0(w0, w1), w2, w3) == W[16..20].
    let ws: Vec<String> = (0..16).map(|i| format!("(x{i} : U32)")).collect();
    let x = |i: usize| format!("x{i}");
    let w16 = |a: &str, b: &str, c: &str, d: &str| format!("#wadd_u32(#wadd_u32(#wadd_u32(sha::ssig1 {a}, {b}), sha::ssig0 {c}), {d})");
    let n16 = w16(&x(14), &x(9), &x(1), &x(0));
    let n17 = w16(&x(15), &x(10), &x(2), &x(1));
    let n18 = w16(&n16, &x(11), &x(3), &x(2));
    let n19 = w16(&n17, &x(12), &x(4), &x(3));
    let v = |a: usize| format!("(v4 x{} x{} x{} x{})", a, a + 1, a + 2, a + 3);
    let t = prove(
        &env,
        &ws.join(" "),
        "Array U32 4usize",
        &format!("arm::vsha256su1q_u32 (arm::vsha256su0q_u32 {} {}) {} {}", v(0), v(4), v(8), v(12)),
        &format!("v4 ({n16}) ({n17}) ({n18}) ({n19})"),
        true,
    );
    eprintln!("SU1(SU0(w0, w1), w2, w3) == W[16..20]: {t:?}");
}

#[test]
fn arm_compress_equals_fips_compress() {
    big_stack(|| {
        let env = sha_env();
        let vars = "(s : Array U32 8usize) (b : Array U8 64usize)";
        let t = prove(&env, vars, "Array U32 8usize", "arm::compress s b", "sha::compress s b", true);
        eprintln!("ARMv8-shaped compress == FIPS compress (symbolic state and block): {t:?}");
        // A single wrong constant is caught.
        let bad_src = SHA.replace(
            "def[spec] arm::K4_15 : Array U32 4usize := v4 0x90befffau32",
            "def[spec] arm::K4_15 : Array U32 4usize := v4 0x90befffbu32",
        );
        assert_ne!(bad_src, SHA);
        let mut bad = prelude();
        load(&mut bad, &bad_src).unwrap();
        let t0 = Instant::now();
        let r = infer(&bad, &format!("fun {vars} => bvrefl(Array U32 8usize, arm::compress s b, sha::compress s b)"));
        assert!(r.is_err(), "a wrong round constant must be rejected");
        eprintln!("... and with one wrong round constant it is rejected: {:?}", t0.elapsed());
    })
}

#[test]
fn targets_transcription_cross_check() {
    // sandblaster/targets/core/aarch64.core (phase-2 work of another
    // component): its SHA256H model must equal four FIPS rounds too. Skipped
    // (with a note) if that file does not load in this tree.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../targets/core/aarch64.core");
    let Ok(src) = std::fs::read_to_string(path) else {
        eprintln!("targets transcription not found; skipped");
        return;
    };
    let mut env = sha_env();
    if let Err(e) = load(&mut env, &src) {
        eprintln!("targets transcription does not load here ({e}); skipped");
        return;
    }
    let vars = "(a : U32) (b : U32) (c : U32) (d : U32) (e : U32) (f : U32) (g : U32) (h : U32) \
                (w0 : U32) (w1 : U32) (w2 : U32) (w3 : U32)";
    let wk = "aarch64::vaddq_u32 (aarch64::u32x4 w0 w1 w2 w3) arm::K4_0";
    let fips = "sha::round (sha::round (sha::round (sha::round (st(a, b, c, d, e, f, g, h)) 1116352408u32 w0) \
                1899447441u32 w1) 3049323471u32 w2) 3921009573u32 w3";
    for (f, args, proj) in [
        ("aarch64::vsha256hq_u32", "(aarch64::u32x4 a b c d) (aarch64::u32x4 e f g h)", "v4 a b c d"),
        ("aarch64::vsha256h2q_u32", "(aarch64::u32x4 e f g h) (aarch64::u32x4 a b c d)", "v4 e f g h"),
    ] {
        let rhs = format!("match {fips} : St as _ return Array U32 4usize with | st(a, b, c, d, e, f, g, h) => {proj} end");
        let t = prove(&env, vars, "Array U32 4usize", &format!("{f} {args} ({wk})"), &rhs, true);
        eprintln!("targets {f} == 4 FIPS rounds: {t:?}");
    }
}
