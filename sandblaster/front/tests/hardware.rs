//! Hardware code is first-class (DESIGN.md §9.2, §9.3): a `#[target_feature]`
//! function calling `core::arch` intrinsics elaborates onto the target
//! models (`sandblaster/targets/core/<arch>.core`, loaded for the build
//! target's architecture), its contract is proven over the models, and the
//! specification surface pins each model it uses (`target-model:` items:
//! the model's source and core hashes, its native evidence and verdict).
//! Negative twins: a contract the models refute is not proven, and a model
//! the elaborator cannot reach is never silently trusted.

mod common;

use sandblaster_front::driver::Checked;
use sandblaster_front::elab::{DefStatus, Options, ProverChain};
use sandblaster_front::surface::{self, SurfaceKind, SurfaceOptions};
use common::*;

struct Run {
    verified: bool,
    rendered: String,
    checked: Vec<String>,
    /// `(key, statement)` of every `target-model:` item.
    models: Vec<(String, String)>,
    target_model: [u8; 32],
}

#[track_caller]
fn run(c: Checked) -> Run {
    assert!(c.ok(), "front end rejected the crate:\n{}", c.render());
    let k = c.krate.clone().unwrap();
    let (kr, sm) = (&k, &c.sm);
    sandblaster_front::elab::with_big_stack(move || {
        let mut chain = ProverChain::standard();
        let out = sandblaster_front::elab::elaborate(kr, &mut chain, &Options::default());
        let s = surface::compute(&out, kr, sm, &SurfaceOptions::default());
        Run {
            verified: out.verified(),
            rendered: out.diags.render(sm),
            checked: out.defs.iter().filter(|d| d.status == DefStatus::Checked).map(|d| d.name.clone()).collect(),
            models: s.items.iter().filter(|i| i.kind == SurfaceKind::TargetModel).map(|i| (i.key.clone(), i.statement.join("\n"))).collect(),
            target_model: s.target_model,
        }
    })
}

/// A NEON function: lane 2 of `v + v` for `v` the splat of `x`.
const NEON: &str = "use core::arch::aarch64::*;\n\
#[target_feature(enable = \"neon\")]\n\
#[ensures(|r: u32| r == ENSURES)]\n\
pub fn lane_sum(x: u32) -> u32 { let v = vdupq_n_u32(x); vgetq_lane_u32::<2>(vaddq_u32(v, v)) }\n";

#[test]
fn a_neon_function_is_proven_over_the_models_and_the_lock_pins_them() {
    let r = run(check(&NEON.replace("ENSURES", "x.wrapping_add(x)")));
    assert!(r.verified, "not verified:\n{}", r.rendered);
    assert!(r.checked.iter().any(|d| d == "crate::lane_sum"), "{:?}", r.checked);
    let keys: Vec<&str> = r.models.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["target-model:aarch64:vaddq_u32", "target-model:aarch64:vdupq_n_u32", "target-model:aarch64:vgetq_lane_u32"]);
    for (k, st) in &r.models {
        // the registered model, its core transcription, and its native
        // evidence record (validated on a real CPU)
        assert!(st.contains("model ") && !st.contains("model unregistered"), "{k}: {st}");
        assert!(st.contains("core ") && !st.contains("core none"), "{k}: {st}");
        assert!(st.contains("record ") && !st.contains("record none"), "{k}: {st}");
        assert!(st.contains("verdict Validated"), "{k}: {st}");
    }
    // the header's `target aarch64` hash is the models' core files
    assert_ne!(r.target_model, [0; 32]);
    assert_eq!(r.target_model, surface::Toolchain::current().target["aarch64"]);
}

#[test]
fn a_contract_the_models_refute_is_not_proven() {
    let r = run(check(&NEON.replace("ENSURES", "x")));
    assert!(!r.verified, "a false contract verified:\n{}", r.rendered);
}

/// The same function on x86_64 (SSE2, the x86 models): the definition
/// elaborates onto `x86_64::_mm_add_epi32` and checks.
#[test]
fn an_sse2_function_elaborates_onto_the_x86_models() {
    let c = check_x86("use core::arch::x86_64::*;\n#[target_feature(enable = \"sse2\")]\npub fn add(a: __m128i, b: __m128i) -> __m128i { _mm_add_epi32(a, b) }\n");
    let r = run(c);
    assert!(r.verified, "not verified:\n{}", r.rendered);
    assert!(r.checked.iter().any(|d| d == "crate::add"), "{:?}", r.checked);
    assert_eq!(r.models.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["target-model:x86_64:_mm_add_epi32"]);
    assert_eq!(r.target_model, surface::Toolchain::current().target["x86_64"]);
}

/// Portable code uses no model: no `target-model:` item.
#[test]
fn portable_code_has_no_target_model_items() {
    let r = run(check("pub fn f(x: u32) -> u32 { x.wrapping_add(x) }\n"));
    assert!(r.verified, "{}", r.rendered);
    assert!(r.models.is_empty(), "{:?}", r.models);
}

/// In ghost code a vector is the array of its lanes, lane 0 first (and that
/// array the vector: the same kernel value; `docs/mir-lift.md` §20.9), so a
/// contract or law states a vector function lane by lane; exec code has no
/// such coercion (Rust has none).
#[test]
fn ghost_code_reads_a_vector_as_the_array_of_its_lanes() {
    let src = "use core::arch::aarch64::*;\n\
#[target_feature(enable = \"neon\")]\n\
#[ensures(|r: uint8x16_t| r == [x; 16])]\n\
pub fn splat(x: u8) -> uint8x16_t { vdupq_n_u8(x) }\n";
    let r = run(check(src));
    assert!(r.verified, "not verified:\n{}", r.rendered);
    assert!(r.checked.iter().any(|d| d == "crate::splat"), "{:?}", r.checked);
    // a wrong lane is refuted by the model
    let r = run(check(&src.replace("r == [x; 16]", "r == [x.wrapping_add(1u8); 16]")));
    assert!(!r.verified, "a false lane verified:\n{}", r.rendered);
    // exec code: no coercion between a vector and an array
    let c = check("use core::arch::aarch64::*;\n#[target_feature(enable = \"neon\")]\npub fn bytes(v: uint8x16_t) -> [u8; 16] { v }\n");
    assert!(!c.ok(), "an exec coercion of a vector to an array was accepted");
}

/// The lanes of a vector built by the models, in a contract: a vector is
/// indexed in ghost code (`v[i]`, lane `i` of its model's `Array(lane, n)`,
/// lane 0 first), a model read at a lane is its scalar lane operation
/// (`auto::lanes`: one `Delta` step of the model, whose body is the vector
/// of its lanes), and a symbolic lane is split into the literal ones. So
/// the nibble split of a byte vector (`x & 15`, `x >> 4`, Reed–Solomon's
/// table indices), a lane sum exact under bounds on the lanes, a lane's
/// carry split at bit 26 (curve25519's radix-2^26 limbs) and a lane-wise
/// relation over every lane are proven; negative twins: a bound one too
/// small, a sum without its bounds.
const NEON_LANES: &str = r#"
#[lemma]
fn low_nibble(x: uint8x16_t, i: usize) {
    requires(i < 16usize);
    ensures(vandq_u8(x, vdupq_n_u8(15))[i] < 16u8);
    follows();
}
#[lemma]
fn low_nibble_bad(x: uint8x16_t, i: usize) {
    requires(i < 16usize);
    ensures(vandq_u8(x, vdupq_n_u8(15))[i] < 15u8);
    follows();
}
#[lemma]
fn high_nibble(x: uint8x16_t, i: usize) {
    requires(i < 16usize);
    ensures(vshrq_n_u8::<4>(x)[i] < 16u8);
    follows();
}
#[lemma]
fn nibbles(x: uint8x16_t, i: usize) {
    requires(i < 16usize);
    ensures((x[i] as Int) == 16 * (vshrq_n_u8::<4>(x)[i] as Int) + (vandq_u8(x, vdupq_n_u8(15))[i] as Int));
    follows();
}
#[lemma]
fn exact_sum(a: uint32x4_t, b: uint32x4_t, i: usize) {
    requires(i < 4usize && a[i] < 1000u32 && b[i] < 1000u32);
    ensures((vaddq_u32(a, b)[i] as Int) == (a[i] as Int) + (b[i] as Int));
    follows();
}
#[lemma]
fn exact_sum_bad(a: uint32x4_t, b: uint32x4_t, i: usize) {
    requires(i < 4usize);
    ensures((vaddq_u32(a, b)[i] as Int) == (a[i] as Int) + (b[i] as Int));
    follows();
}
#[lemma]
fn carry_split(v: uint32x4_t, i: usize) {
    requires(i < 4usize);
    ensures((v[i] as Int) == pow2(26) * (vshrq_n_u32::<26>(v)[i] as Int) + (vandq_u32(v, vdupq_n_u32(67108863))[i] as Int));
    follows();
}
#[lemma]
fn lane_wise(a: uint32x4_t, b: uint32x4_t) {
    ensures(forall(|i: usize| implies(i < 4usize, vaddq_u32(a, b)[i] == a[i].wrapping_add(b[i]))));
    follows();
}
#[lemma]
fn nested(a: uint8x16_t, b: uint8x16_t, i: usize) {
    requires(i < 16usize);
    ensures(veorq_u8(vandq_u8(a, b), vandq_u8(a, b))[i] == 0u8);
    follows();
}
"#;

/// A probe crate: a stub boundary and `lanes` (ghost) on `target`.
fn run_lanes(arch_use: &str, lanes: &str, target: &sandblaster_front::target::TargetInfo) -> Run {
    let root = format!("{HEADER}#[cfg(sandblaster)]\nmod lanes;\n/// A stub.\npub fn probe(x: u8) -> u8 {{ x }}\n");
    let lanes = format!("//! Lane facts.\nuse sandblaster::prelude::*;\nuse {arch_use};\n{lanes}");
    run(check_files_target(&[("r/mod.rs", &root), ("r/lanes.rs", &lanes)], target))
}

#[track_caller]
fn lanes_proven(r: &Run, good: &[&str], bad: &[&str]) {
    for g in good {
        let full = format!("crate::lanes::{g}");
        assert!(r.checked.contains(&full), "`{full}` not proven:\n{}", r.rendered);
    }
    for b in bad {
        let full = format!("crate::lanes::{b}");
        assert!(!r.checked.contains(&full), "`{full}` was proven, but it does not hold:\n{}", r.rendered);
    }
    assert!(!r.rendered.contains("rejected by the kernel") && !r.rendered.contains("the kernel rejected"), "{}", r.rendered);
}

#[test]
fn the_lanes_of_the_neon_models_are_their_scalar_lane_operations() {
    let r = run_lanes("core::arch::aarch64::*", NEON_LANES, &sandblaster_front::target::TargetInfo::aarch64_apple_darwin());
    lanes_proven(&r, &["low_nibble", "high_nibble", "nibbles", "exact_sum", "carry_split", "lane_wise", "nested"], &["low_nibble_bad", "exact_sum_bad"]);
}

/// The x86 models read `__m128i` as sixteen little-endian bytes: a 32-bit
/// lane of `_mm_add_epi32` is the sum of the operands' 32-bit lanes (the
/// bytes recombined), a byte of `_mm_xor_si128` is the bytes' xor, and a
/// byte masked by a lane of 15 is a nibble. Negative twin: a mask of 31.
#[test]
fn the_byte_lanes_of_the_x86_models_are_their_scalar_lane_operations() {
    let lanes = r#"
#[lemma]
fn epi32_lane0(a: __m128i, b: __m128i) {
    ensures(u32::from_le_bytes([_mm_add_epi32(a, b)[0], _mm_add_epi32(a, b)[1], _mm_add_epi32(a, b)[2], _mm_add_epi32(a, b)[3]])
        == u32::from_le_bytes([a[0], a[1], a[2], a[3]]).wrapping_add(u32::from_le_bytes([b[0], b[1], b[2], b[3]])));
    follows();
}
#[lemma]
fn xor_byte(a: __m128i, b: __m128i, i: usize) {
    requires(i < 16usize);
    ensures(_mm_xor_si128(a, b)[i] == a[i] ^ b[i]);
    follows();
}
#[lemma]
fn masked_byte(a: __m128i, m: __m128i, i: usize) {
    requires(i < 16usize && m[i] == 15u8);
    ensures(_mm_and_si128(a, m)[i] < 16u8);
    follows();
}
#[lemma]
fn masked_byte_bad(a: __m128i, m: __m128i, i: usize) {
    requires(i < 16usize && m[i] == 31u8);
    ensures(_mm_and_si128(a, m)[i] < 16u8);
    follows();
}
"#;
    let r = run_lanes("core::arch::x86_64::*", lanes, &sandblaster_front::target::TargetInfo::x86_64_apple_darwin());
    lanes_proven(&r, &["epi32_lane0", "xor_byte", "masked_byte"], &["masked_byte_bad"]);
}

/// Lane indexing is ghost-only: exec code cannot index a vector (Rust
/// cannot either); it reads a lane with the lane intrinsic.
#[test]
fn exec_code_cannot_index_a_vector() {
    let c = check("use core::arch::aarch64::*;\n#[target_feature(enable = \"neon\")]\npub fn lane(a: uint32x4_t) -> u32 { a[0] }\n");
    assert!(errors(&c).iter().any(|(_, m)| m.contains("cannot index into a value of type `uint32x4_t`")), "{}", c.render());
}
