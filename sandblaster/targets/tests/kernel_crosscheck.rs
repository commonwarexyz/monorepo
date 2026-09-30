//! K-style cross-checks between the core-text target models (evaluated by
//! the sandblaster kernel) and the executable Rust models (DESIGN.md §9.2,
//! §10.3 "Target models"). Needs the `kernel` feature:
//!
//! ```text
//! CARGO_TARGET_DIR=target/targets cargo test -p sandblaster-targets --features kernel --test kernel_crosscheck
//! ```
//!
//! * the core files load after the prelude, each on its own and together;
//! * every registry model is a `def[intrinsic]` global whose kernel type is
//!   the registry signature, whose calls built by `Kit::apply` type-check at
//!   every immediate bound, and whose core items (hashed in the evidence) are
//!   exactly what the kernel's checked body references;
//! * intrinsic models stay neutral on symbolic arguments (§5.6);
//! * kernel evaluation == executable model on ≥ 1000 random inputs per model
//!   plus corners and every immediate value;
//! * the aarch64 (and x86) SHA-256 compressions assembled in core text from
//!   the core models == a core-text FIPS 180-4 compression == the executable
//!   models, by kernel evaluation on random concrete inputs.
#![cfg(feature = "kernel")]

use sandblaster_kernel::api::Ctx;
use sandblaster_kernel::term::{DefKind, Lvl, Rel};
use sandblaster_kernel::value::{Budget, Head, Value};
use sandblaster_targets::coretext::{self, CORE_HELPERS};
use sandblaster_targets::diff::assert_all_passed;
use sandblaster_targets::kernel::{self, Checker, CoreValue};
use sandblaster_targets::registry::Arch;

fn big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(move || {
            sandblaster_kernel::util::set_stack_limit(240 << 20);
            f()
        })
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn core_files_load_alone_and_together() {
    big_stack(|| {
        for archs in [&[Arch::Aarch64][..], &[Arch::X86_64][..], &[Arch::Aarch64, Arch::X86_64][..]] {
            let env = kernel::env_with_models(archs).unwrap_or_else(|e| panic!("{archs:?}: {e}"));
            for &arch in archs {
                for name in coretext::item_names(coretext::core_text(arch)) {
                    assert!(env.lookup_global(name).is_some(), "{name}");
                }
            }
        }
        Checker::new().expect("core models + fixtures load");
    });
}

#[test]
fn globals_match_the_registry() {
    big_stack(|| {
        let ck = Checker::new().unwrap();
        let env = &ck.env;
        for arch in [Arch::Aarch64, Arch::X86_64] {
            for m in coretext::models(arch) {
                let g = env.lookup_global(m.global).unwrap();
                assert_eq!(env.global_kind(g), Some(DefKind::Intrinsic), "{}", m.global);
                let tele = m.telescope();
                assert_eq!(env.global_arity(g), Some(tele.len() as u32), "{}", m.global);
                let rels: Vec<Rel> = tele.iter().map(|b| if b.relevant { Rel::Rel } else { Rel::Irr }).collect();
                assert_eq!(env.global_param_rels(g), Some(rels), "{}", m.global);
                assert_eq!(ck.type_matches(m.global, &m.type_text()), Ok(true), "{}: {}", m.global, m.type_text());
                // Kit::apply builds well-typed calls at both ends of each immediate range.
                let args = || -> Vec<_> {
                    m.params
                        .iter()
                        .map(|(_, ty)| match ty {
                            coretext::CoreTy::Word(l) => ck.kit.word(*l, 1),
                            coretext::CoreTy::Vector(l, n) => ck.kit.array(*l, &vec![1; *n as usize]),
                        })
                        .collect()
                };
                let bounds: Vec<Vec<u32>> = match m.imms.first() {
                    None => vec![vec![]],
                    Some(i) => vec![vec![i.lo], vec![i.hi]],
                };
                for imms in bounds {
                    ck.check_call(m, &imms, args()).unwrap_or_else(|e| panic!("{} {imms:?}: {e}", m.global));
                }
                if let Some(i) = m.imms.first() {
                    assert!(ck.kit.apply(env, m, &[i.hi + 1], args()).is_err());
                }
            }
            for h in CORE_HELPERS.iter().filter(|h| h.arch == arch) {
                assert_eq!(ck.type_matches(h.global, &h.type_text()), Ok(true), "{}", h.global);
            }
        }
    });
}

#[test]
fn out_of_range_immediates_are_ill_typed() {
    big_stack(|| {
        let ck = Checker::new().unwrap();
        let env = &ck.env;
        for (text, ok) in [
            ("aarch64::vshlq_n_u32 31u32 .refl(Bool, true) (aarch64::vdupq_n_u32 1u32)", true),
            ("aarch64::vshlq_n_u32 32u32 .refl(Bool, true) (aarch64::vdupq_n_u32 1u32)", false),
            ("aarch64::vshrq_n_u32 0u32 .refl(Bool, true) .refl(Bool, true) (aarch64::vdupq_n_u32 1u32)", false),
            ("aarch64::vextq_u32 4u32 .refl(Bool, true) (aarch64::vdupq_n_u32 1u32) (aarch64::vdupq_n_u32 2u32)", false),
            ("aarch64::vgetq_lane_u32 4u32 .refl(Bool, true) (aarch64::vdupq_n_u32 1u32)", false),
            ("x86_64::_mm_shuffle_epi32 256u32 .refl(Bool, true) (x86_64::_mm_set_epi32 1u32 2u32 3u32 4u32)", false),
        ] {
            let t = env.parse_term(&[], text).unwrap();
            let r = env.infer(&Ctx::default(), &t, &mut Budget { steps: 1 << 24 });
            assert_eq!(r.is_ok(), ok, "{text}: {:?}", r.err());
        }
    });
}

#[test]
fn core_items_are_what_the_kernel_references() {
    big_stack(|| {
        let ck = Checker::new().unwrap();
        for arch in [Arch::Aarch64, Arch::X86_64] {
            for m in coretext::models(arch) {
                // Transitive closure of the kernel-side references.
                let mut seen: Vec<String> = vec![m.global.to_string()];
                let mut todo = vec![m.global.to_string()];
                while let Some(g) = todo.pop() {
                    for r in ck.referenced_globals(arch, &g) {
                        if !seen.contains(&r) {
                            seen.push(r.clone());
                            todo.push(r);
                        }
                    }
                }
                let mut from_kernel = seen;
                from_kernel.sort();
                let mut from_text: Vec<String> = m.items().into_iter().map(str::to_string).collect();
                from_text.sort();
                assert_eq!(from_kernel, from_text, "{}", m.global);
            }
        }
    });
}

#[test]
fn intrinsic_models_are_neutral_on_symbolic_arguments() {
    big_stack(|| {
        let ck = Checker::new().unwrap();
        let env = &ck.env;
        let g = env.lookup_global("aarch64::vaddq_u32").unwrap();
        // λ x. vaddq_u32 x [1, 1, 1, 1] under a binder: stays a neutral head.
        let one = ck.kit.array(coretext::Lane::U32, &[1, 1, 1, 1]);
        let ty = env.parse_term(&[], "Array U32 4usize").unwrap();
        let tyv = kernel::eval_closed(env, &ty).unwrap();
        let ctx = Ctx::default().push(sandblaster_kernel::api::CtxEntry { name: "x".into(), rel: Rel::Rel, ty: tyv, def: None });
        let t = sandblaster_kernel::util::mk::apps(
            sandblaster_kernel::util::mk::global(g),
            [(Rel::Rel, sandblaster_kernel::util::mk::var(0)), (Rel::Rel, one.clone())],
        );
        let v = env.eval(&env.ctx_venv(&ctx), Lvl(1), &t, &mut Budget { steps: 1 << 24 }).unwrap();
        assert!(matches!(&*v, Value::Neu(n) if matches!(n.head, Head::Global { def, .. } if def == g)), "{v:?}");
        // On closed arguments it computes.
        let r: [u32; 4] = ck.call(coretext::find(Arch::Aarch64, "vaddq_u32").unwrap(), &[], vec![one.clone(), one]).unwrap();
        assert_eq!(r, [2; 4]);
    });
}

#[test]
fn known_answers() {
    big_stack(|| {
        let ck = Checker::new().unwrap();
        let a64 = |n: &str| coretext::find(Arch::Aarch64, n).unwrap();
        let x86 = |n: &str| coretext::find(Arch::X86_64, n).unwrap();
        let bytes: [u8; 16] = core::array::from_fn(|i| i as u8);
        let r: [u8; 16] = ck.call(a64("vrev32q_u8"), &[], vec![bytes.to_term(&ck.kit)]).unwrap();
        assert_eq!(r, [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]);
        let r: [u32; 4] = ck.call(a64("vextq_u32"), &[1], vec![[0u32, 1, 2, 3].to_term(&ck.kit), [4u32, 5, 6, 7].to_term(&ck.kit)]).unwrap();
        assert_eq!(r, [1, 2, 3, 4]);
        let r: [u32; 4] = ck.call(a64("vshrq_n_u32"), &[32], vec![[u32::MAX; 4].to_term(&ck.kit)]).unwrap();
        assert_eq!(r, [0; 4]);
        // FIPS 180-4 "abc", rounds 0..3 (MODELS.md §4 trap: H2 takes efgh first and the pre-update abcd).
        let abcd = [0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a];
        let efgh = [0x510e527fu32, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
        let wk = [0x6162_6380u32.wrapping_add(0x428a_2f98), 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5];
        let h: [u32; 4] =
            ck.call(a64("vsha256hq_u32"), &[], vec![abcd.to_term(&ck.kit), efgh.to_term(&ck.kit), wk.to_term(&ck.kit)]).unwrap();
        assert_eq!(h, [0xd550_f666, 0xc8c3_47a7, 0x5a6a_d9ad, 0x5d6a_ebcd]);
        let h2: [u32; 4] =
            ck.call(a64("vsha256h2q_u32"), &[], vec![efgh.to_term(&ck.kit), abcd.to_term(&ck.kit), wk.to_term(&ck.kit)]).unwrap();
        assert_eq!(h2, [0x24e0_0850, 0xf929_39eb, 0x78ce_7989, 0xfa2a_4622]);
        let r: [u8; 16] = ck.call(x86("_mm_alignr_epi8"), &[17], vec![[1u8; 16].to_term(&ck.kit), bytes.to_term(&ck.kit)]).unwrap();
        let mut want = [1u8; 16];
        want[15] = 0;
        assert_eq!(r, want);
        // The "abc" block through the core compressions.
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 24;
        let args = || vec![sandblaster_targets::fips::H0.to_term(&ck.kit), block.to_term(&ck.kit)];
        let want = sandblaster_targets::fips::compress(sandblaster_targets::fips::H0, &block);
        assert_eq!(want[0], 0xba78_16bf);
        for g in ["checks::fips::compress", "checks::aarch64::compress_sha2", "checks::x86_64::compress_shani"] {
            assert_eq!(ck.call_global::<[u32; 8]>(g, args()).unwrap(), want, "{g}");
        }
    });
}

/// Kernel evaluation of every core model == its executable model, the
/// campaign on `kernel::default_threads()` worker threads.
#[test]
fn every_core_model_equals_its_executable_model() {
    let cfg = kernel::config();
    let outcomes = kernel::crosscheck_all(&[Arch::Aarch64, Arch::X86_64], &cfg, kernel::default_threads());
    assert_all_passed(&outcomes);
    for (o, m) in outcomes.iter().zip(coretext::models(Arch::Aarch64).iter().chain(coretext::models(Arch::X86_64))) {
        assert_eq!(o.name, m.name);
        assert!(o.skipped.is_none(), "{}", o.name);
        assert!(o.random >= kernel::RANDOM_PER_MODEL, "{}: {} random cases", o.name, o.random);
        assert!(o.corner > 0, "{}", o.name);
        let want = m.imms.first().map(|i| i.lo as i32..=i.hi as i32);
        assert_eq!(o.immediates, want, "{}: every immediate", o.name);
    }
}

#[test]
fn core_compressions_equal_fips_and_the_executable_models() {
    let outcomes = kernel::compress_checks(&kernel::compress_config(), kernel::default_threads());
    assert_all_passed(&outcomes);
    assert_eq!(outcomes.len(), kernel::COMPRESS_CHECKS.len());
    for o in &outcomes {
        assert!(o.random >= kernel::RANDOM_PER_COMPRESSION && o.corner > 0, "{}", o.summary());
    }
}

/// The cross-checks catch the MODELS.md transcription traps: each mutated
/// core model (loaded in place of the committed text) disagrees with the
/// executable model.
#[test]
fn mutated_core_models_are_caught() {
    big_stack(|| {
        let a64 = coretext::AARCH64_CORE;
        let x86 = coretext::X86_64_CORE;
        let cfg = sandblaster_targets::diff::Config { random_per_model: 64, seed: 7 };
        for (arch, name, from, to) in [
            // SHA256H2: the first argument is efgh (reverse of the pseudocode).
            (Arch::Aarch64, "vsha256h2q_u32", "aarch64::sha256hash hash_abcd hash_efgh wk false", "aarch64::sha256hash hash_efgh hash_abcd wk false"),
            // SHA256SU1: the upper half depends on the lower half of the result.
            (Arch::Aarch64, "vsha256su1q_u32", "aarch64::sha256su1_sigma r0,", "aarch64::sha256su1_sigma (array::index U32 4usize w12_15 2usize .refl(Bool, true)),"),
            // EXT: the first argument is in the low lanes.
            (Arch::Aarch64, "vextq_u32", "aarch64::concat_u32x4 a b;", "aarch64::concat_u32x4 b a;"),
            // USHR #32 is 0, not a shift by 32 mod 32.
            (Arch::Aarch64, "vshrq_n_u32", "if #eq_u32(N, 32u32) return U32 then 0u32 else #wshr_u32(x, N)", "#wshr_u32(x, N)"),
            // _mm_set_epi32: the first argument is the highest lane.
            (Arch::X86_64, "_mm_set_epi32", "x86_64::u32x4 e0 e1 e2 e3", "x86_64::u32x4 e3 e2 e1 e0"),
            // PALIGNR: SRC (second argument) is the low half.
            (Arch::X86_64, "_mm_alignr_epi8", "x86_64::concat_u8x16 b a;", "x86_64::concat_u8x16 a b;"),
            // PSHUFB: bits 6..4 of the control byte are ignored (index mask 15, not 127).
            (Arch::X86_64, "_mm_shuffle_epi8", "#ne_u8(#and_u8(m, 128u8), 0u8)", "#ne_u8(#and_u8(m, 144u8), 0u8)"),
        ] {
            let (a, x) = match arch {
                Arch::Aarch64 => {
                    assert!(a64.contains(from), "{from}");
                    (a64.replacen(from, to, 1), x86.to_string())
                }
                Arch::X86_64 => {
                    assert!(x86.contains(from), "{from}");
                    (a64.to_string(), x86.replacen(from, to, 1))
                }
            };
            let ck = Checker::from_core_texts(&[&a, &x]).unwrap_or_else(|e| panic!("{name}: mutated text must still load: {e}"));
            let m = coretext::find(arch, name).unwrap();
            // A few immediates suffice (the full sweeps run in
            // `every_core_model_equals_its_executable_model`).
            // (vshrq_n_u32's trap is at N = 32, the others' at small immediates.)
            let part = m.imms.first().map(|i| {
                let (lo, hi) = if name == "vshrq_n_u32" { (29, 32) } else { (i.lo as i32, (i.lo as i32 + 7).min(i.hi as i32)) };
                kernel::Part { imms: lo..=hi, random: 64 }
            });
            let o = kernel::crosscheck_part(&ck, m, &cfg, part.as_ref());
            assert!(o.mismatches > 0, "mutation of {name} not caught: {}", o.summary());
        }
    });
}

/// The x86 load/store helper wrappers equal their executable meaning (the
/// NEON helpers and the x86 byte helpers are the intrinsic models themselves).
#[test]
fn helper_wrappers_equal_their_executable_meaning() {
    use sandblaster_targets::x86_64 as x86;
    big_stack(|| {
        let ck = Checker::new().unwrap();
        let cfg = kernel::config();
        let call = |g: &str, t| ck.call_global::<[u8; 16]>(g, vec![t]);
        let outcomes = vec![
            sandblaster_targets::diff::diff1(
                "x86_64::load_u32x4",
                cfg.random_per_model,
                cfg.seed_for("load_u32x4"),
                |a: [u32; 4]| call("x86_64::load_u32x4", a.to_term(&ck.kit)),
                |a: [u32; 4]| Ok::<[u8; 16], String>(x86::_mm_loadu_si128(&x86::from_u32x4(a))),
            ),
            sandblaster_targets::diff::diff1(
                "x86_64::m128i_from_u32x4",
                cfg.random_per_model,
                cfg.seed_for("m128i_from_u32x4"),
                |a: [u32; 4]| call("x86_64::m128i_from_u32x4", a.to_term(&ck.kit)),
                |a: [u32; 4]| Ok::<[u8; 16], String>(x86::from_u32x4(a)),
            ),
            sandblaster_targets::diff::diff1(
                "x86_64::store_u32x4",
                cfg.random_per_model,
                cfg.seed_for("store_u32x4"),
                |v: [u8; 16]| ck.call_global::<[u32; 4]>("x86_64::store_u32x4", vec![v.to_term(&ck.kit)]),
                |v: [u8; 16]| Ok::<[u32; 4], String>(x86::view_u32(x86::_mm_storeu_si128(v))),
            ),
            sandblaster_targets::diff::diff1(
                "x86_64::load_u32x8",
                cfg.random_per_model,
                cfg.seed_for("load_u32x8"),
                |a: [u32; 8]| ck.call_global::<[u8; 32]>("x86_64::load_u32x8", vec![a.to_term(&ck.kit)]),
                |a: [u32; 8]| Ok::<[u8; 32], String>(x86::_mm256_loadu_si256(&le_bytes::<8, 32>(a))),
            ),
            sandblaster_targets::diff::diff1(
                "x86_64::store_u32x8",
                cfg.random_per_model,
                cfg.seed_for("store_u32x8"),
                |v: [u8; 32]| ck.call_global::<[u32; 8]>("x86_64::store_u32x8", vec![v.to_term(&ck.kit)]),
                |v: [u8; 32]| Ok::<[u32; 8], String>(le_words::<32, 8>(x86::_mm256_storeu_si256(v))),
            ),
            sandblaster_targets::diff::diff1(
                "x86_64::load_u32x16",
                cfg.random_per_model / 4,
                cfg.seed_for("load_u32x16"),
                |a: [u32; 16]| ck.call_global::<[u8; 64]>("x86_64::load_u32x16", vec![a.to_term(&ck.kit)]),
                |a: [u32; 16]| Ok::<[u8; 64], String>(x86::_mm512_loadu_si512(&le_bytes::<16, 64>(a))),
            ),
            sandblaster_targets::diff::diff1(
                "x86_64::store_u32x16",
                cfg.random_per_model / 4,
                cfg.seed_for("store_u32x16"),
                |v: [u8; 64]| ck.call_global::<[u32; 16]>("x86_64::store_u32x16", vec![v.to_term(&ck.kit)]),
                |v: [u8; 64]| Ok::<[u32; 16], String>(le_words::<64, 16>(x86::_mm512_storeu_si512(v))),
            ),
        ];
        assert_all_passed(&outcomes);
        for h in CORE_HELPERS {
            assert_eq!(env_kind(&ck, h.global), Some(DefKind::Intrinsic), "{}", h.global);
        }
    });
}

/// The little-endian memory image of a `[u32; W]` (`B = 4W` bytes).
fn le_bytes<const W: usize, const B: usize>(a: [u32; W]) -> [u8; B] {
    core::array::from_fn(|i| a[i / 4].to_le_bytes()[i % 4])
}

/// The `[u32; W]` whose memory image is `v` (`B = 4W` bytes).
fn le_words<const B: usize, const W: usize>(v: [u8; B]) -> [u32; W] {
    core::array::from_fn(|i| u32::from_le_bytes([v[4 * i], v[4 * i + 1], v[4 * i + 2], v[4 * i + 3]]))
}

fn env_kind(ck: &Checker, global: &str) -> Option<DefKind> {
    ck.env.global_kind(ck.env.lookup_global(global)?)
}

/// The cross-checks catch transcription slips in the 256/512-bit core models
/// (MODELS.md §10): each mutation of `core/x86_64_avx.core` (loaded in place
/// of the committed text) disagrees with the executable model.
#[test]
fn mutated_wide_core_models_are_caught() {
    big_stack(|| {
        let x86 = coretext::X86_64_CORE;
        let cfg = sandblaster_targets::diff::Config { random_per_model: 64, seed: 11 };
        // (model, from, to, immediates to try)
        type Mutation = (&'static str, &'static str, &'static str, Option<(i32, i32)>);
        let cases: [Mutation; 14] = [
            // VPSHUFB: the lookup table is the destination byte's own 128-bit lane.
            ("_mm512_shuffle_epi8", "(x86_64::pshufb_byte t1 (array::index U8 64usize b 16usize", "(x86_64::pshufb_byte t0 (array::index U8 64usize b 16usize", None),
            // VPERMI2Q: bit 3 of the index selects the second table (bit id+1, id = 2 at 512 bits).
            ("_mm512_permutex2var_epi64", "#ne_u64(#and_u64(i, 8u64), 0u64)", "#ne_u64(#and_u64(i, 16u64), 0u64)", None),
            // GF2P8AFFINEQB: result bit i uses matrix byte 7 - i.
            ("_mm512_gf2p8affine_epi64_epi8", "#wshr_u64(tsrc2qw, 56u32)", "#wshr_u64(tsrc2qw, 0u32)", Some((0, 3))),
            // IFMA: bits 63:52 of the multiplicands are ignored (visible in the
            // high half; the low 52 bits of the product do not depend on them).
            (
                "_mm512_madd52hi_epu64",
                "x86_64::madd52hi : (acc : U64) -> (b : U64) -> (c : U64) -> U64 :=\n  fun (acc : U64) (b : U64) (c : U64) =>\n    let t : Int = #imul(#cast_u64_int(#and_u64(b, 4503599627370495u64))",
                "x86_64::madd52hi : (acc : U64) -> (b : U64) -> (c : U64) -> U64 :=\n  fun (acc : U64) (b : U64) (c : U64) =>\n    let t : Int = #imul(#cast_u64_int(b)",
                None,
            ),
            // IFMA: the product's low 52 bits are added, not the low 64.
            ("_mm512_madd52lo_epu64", "#wadd_u64(acc, #int_to_sat_u64(#imod(t, 4503599627370496int)))", "#wadd_u64(acc, #int_to_sat_u64(#imod(t, 18446744073709551616int)))", None),
            // VPTERNLOG: minterm 4 is x AND NOT y AND NOT z (the first source is the high index bit).
            ("_mm512_ternarylogic_epi32", "#and_u32(#and_u32(x, #not_u32(y)), #not_u32(z))", "#and_u32(#and_u32(#not_u32(x), y), #not_u32(z))", Some((0x10, 0x13))),
            // VPALIGNR (VEX.256): SRC2 (second argument) is the low half of each lane.
            ("_mm256_alignr_epi8", "x86_64::concat_u8x16 (array::index (Array U8 16usize) 2usize lb 0usize .refl(Bool, true)) (array::index (Array U8 16usize) 2usize la 0usize .refl(Bool, true))", "x86_64::concat_u8x16 (array::index (Array U8 16usize) 2usize la 0usize .refl(Bool, true)) (array::index (Array U8 16usize) 2usize lb 0usize .refl(Bool, true))", Some((1, 8))),
            // VPSHRDVQ: DEST is the low half, the count 0 returns DEST.
            ("_mm512_shrdv_epi64", "then lo else #or_u64(#wshr_u64(lo, s), #wshl_u64(hi, #wsub_u32(64u32, s)))", "then hi else #or_u64(#wshr_u64(lo, s), #wshl_u64(hi, #wsub_u32(64u32, s)))", None),
            // VPSLLD imm8: a count above 31 gives 0 (not a shift mod 32).
            ("_mm512_slli_epi32", "if #le_u32(IMM8, 31u32) return U32 then #wshl_u32(x, IMM8) else 0u32", "#wshl_u32(x, IMM8)", Some((32, 35))),
            // VPBLENDMD: a set mask bit takes the SECOND source.
            ("_mm512_mask_blend_epi32", "if x86_64::kbit16 k j return U32 then y else x", "if x86_64::kbit16 k j return U32 then x else y", None),
            // VPCMPUQ LT is strict.
            ("_mm512_cmplt_epu64_mask", "(#lt_u64(array::index U64 8usize x 0usize .refl(Bool, true), array::index U64 8usize y 0usize .refl(Bool, true)))", "(#le_u64(array::index U64 8usize x 0usize .refl(Bool, true), array::index U64 8usize y 0usize .refl(Bool, true)))", None),
            // VPMULTISHIFTQB: result bit k is tcur bit (ctrl + k) mod 64.
            ("_mm512_multishift_epi64_epi8", "#wshl_u8(b1, 1u32)", "#wshl_u8(b2, 1u32)", None),
            // VPERMB: SRC2 (second argument) is the table.
            ("_mm512_permutexvar_epi8", "let src : Array U8 64usize = a;", "let src : Array U8 64usize = idx;", None),
            // GF2P8MULB: bit 0 of src2byte adds src1byte unshifted.
            ("_mm512_gf2p8mul_epi8", "then #xor_u16(t0, #wshl_u16(s, 0u32)) else t0", "then #xor_u16(t0, #wshl_u16(s, 1u32)) else t0", None),
        ];
        for (name, from, to, imms) in cases {
            assert!(x86.contains(from), "{name}: {from}");
            let mutated = x86.replacen(from, to, 1);
            let ck = Checker::from_core_texts(&[coretext::AARCH64_CORE, &mutated]).unwrap_or_else(|e| panic!("{name}: mutated text must still load: {e}"));
            let m = coretext::find(Arch::X86_64, name).unwrap();
            let part = m.imms.first().map(|i| {
                let (lo, hi) = imms.unwrap_or((i.lo as i32, i.lo as i32 + 3));
                kernel::Part { imms: lo..=hi, random: 64 }
            });
            let o = kernel::crosscheck_part(&ck, m, &cfg, part.as_ref());
            assert!(o.mismatches > 0, "mutation of {name} not caught: {}", o.summary());
        }
    });
}

/// Known answers of the 256/512-bit core models, by kernel evaluation: the
/// AES S-box through GF2P8AFFINEINVQB (FIPS-197 §5.1.1), VPTERNLOGD 0x96 =
/// xor3, IFMA at its 52-bit edges, VPERMD as a lane reversal.
#[test]
fn wide_known_answers() {
    big_stack(|| {
        let ck = Checker::new().unwrap();
        let x86 = |n: &str| coretext::find(Arch::X86_64, n).unwrap();
        let aes = 0xf1e3_c78f_1f3e_7cf8u64.to_le_bytes();
        let mat: [u8; 16] = core::array::from_fn(|i| aes[i % 8]);
        let x: [u8; 16] = core::array::from_fn(|i| [0x00, 0x01, 0x53, 0xff, 0x10, 0x6e, 0xc9, 0x02][i % 8]);
        let r: [u8; 16] = ck.call(x86("_mm_gf2p8affineinv_epi64_epi8"), &[0x63], vec![x.to_term(&ck.kit), mat.to_term(&ck.kit)]).unwrap();
        assert_eq!(&r[..8], &[0x63, 0x7c, 0xed, 0x16, 0xca, 0x9f, 0xdd, 0x77]);
        let a: [u8; 64] = core::array::from_fn(|i| (i * 7) as u8);
        let b: [u8; 64] = core::array::from_fn(|i| (i * 13 + 1) as u8);
        let c: [u8; 64] = core::array::from_fn(|i| (i * 31 + 5) as u8);
        let r: [u8; 64] = ck
            .call(x86("_mm512_ternarylogic_epi32"), &[0x96], vec![a.to_term(&ck.kit), b.to_term(&ck.kit), c.to_term(&ck.kit)])
            .unwrap();
        assert_eq!(r, core::array::from_fn(|i| a[i] ^ b[i] ^ c[i]));
        let splat = |q: u64| -> [u8; 64] { core::array::from_fn(|i| q.to_le_bytes()[i % 8]) };
        let m52 = (1u64 << 52) - 1;
        let hi: [u8; 64] = ck
            .call(x86("_mm512_madd52hi_epu64"), &[], vec![splat(0).to_term(&ck.kit), splat(u64::MAX).to_term(&ck.kit), splat(m52).to_term(&ck.kit)])
            .unwrap();
        assert_eq!(hi, splat(m52 - 1));
        let mut idx = [0u8; 64];
        for j in 0..16 {
            idx[4 * j] = (15 - j) as u8 | 0xf0;
        }
        let r: [u8; 64] = ck.call(x86("_mm512_permutexvar_epi32"), &[], vec![idx.to_term(&ck.kit), a.to_term(&ck.kit)]).unwrap();
        for j in 0..16 {
            assert_eq!(&r[4 * j..4 * j + 4], &a[4 * (15 - j)..4 * (15 - j) + 4]);
        }
    });
}
