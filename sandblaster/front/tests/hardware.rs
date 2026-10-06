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
