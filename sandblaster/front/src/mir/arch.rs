//! `core::arch` in the literal reading (capability C8, first slice;
//! `docs/mir-lift.md` §20.9, DESIGN.md §16.4). TRUSTED: it decides which
//! intrinsic call of rustc's MIR is read as which target model, and when a
//! call is read at all.
//!
//! Nothing here is a table of its own. A vector type is read as the
//! representation the front end gives it (`intrinsics::VecTy`, hashed into
//! every lock's `builtins` line: `uint8x16_t` is `Array U8 16usize`,
//! `__m128i` its sixteen little-endian bytes); a call is read as the core
//! model whose registered `core::arch` path is the call's path
//! (`sandblaster_targets::coretext::find_by_path`: the model's global, its
//! immediates with their ranges and its parameter and result types, TCB
//! item 4), and only when that model is **validated** (the fail-closed
//! verdict of `sandblaster_targets::evidence`: current hardware evidence
//! for the model's source, a current kernel cross-check of its core text)
//! and its global is the one the target library loaded
//! (`elab::semantics::install`: a `def[intrinsic]` of the model's type).
//!
//! A call is refused (read as stuck: the function has no theorem) when:
//!
//! * the intrinsic is an `unsafe fn` or takes or returns a raw pointer (the
//!   loads and stores, `vld1q_u8(ptr)`, `_mm_loadu_si128(ptr)`): verified
//!   code is safe Rust (DESIGN.md §16.5), and whether shipped `unsafe`
//!   SIMD code may be split into safe vector arithmetic and unverified
//!   loads and stores is the user's open decision (§18, decision 9);
//! * the extraction records no target, or another architecture than the
//!   intrinsic's;
//! * no model has the call's path, or its model is not validated;
//! * the calling function's body is not compiled with every target feature
//!   the intrinsic needs (rustc's own rule for a safe call; the model's
//!   features too): the instruction is then not known to exist on the CPU;
//! * an immediate is outside the model's range, or an argument or the
//!   result does not have the model's type (rustc refuses both at compile
//!   time, so a well-formed extraction never has them).
//!
//! A runtime feature detection (`is_x86_feature_detected!` of a feature the
//! target does not enable statically: a call into `std_detect`, a cache in
//! a static) is refused too ([`detection`]); the detection of a statically
//! enabled feature is the constant `true` in the MIR already.

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::DefKind;
use sandblaster_targets::coretext::{self, CoreModel, CoreTy, Lane};
use sandblaster_targets::evidence::{self, Validation};

use super::ir::{ArchCall, Sbmir, Ty};
use crate::hir::UintTy;
use crate::intrinsics::VecTy;

/// The `target_arch` of a `core::arch` path (`core::arch::aarch64::vandq_u8`
/// → `aarch64`, `vandq_u8`).
fn split(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("core::arch::")?;
    let (arch, name) = rest.split_once("::")?;
    (!name.contains("::")).then_some((arch, name))
}

fn lane_of(u: UintTy) -> Option<Lane> {
    Some(match u {
        UintTy::U8 => Lane::U8,
        UintTy::U16 => Lane::U16,
        UintTy::U32 => Lane::U32,
        UintTy::U64 => Lane::U64,
        _ => return None,
    })
}

/// The front end's vector type of a `core::arch` vector path.
pub fn vec_ty(path: &str) -> Option<VecTy> {
    let (arch, name) = split(path)?;
    VecTy::from_name(&crate::target::Arch::parse(arch), name)
}

/// The model representation of a MIR vector type `(simd path lane n)`: the
/// front end's (`VecTy::lanes`, lane 0 first), when rustc lays the type out
/// in as many bits — lane for lane for a NEON type, whose lanes are typed;
/// in total for an x86 one, an untyped register rustc declares as `i64`s
/// and the models read as bytes.
pub fn vector(path: &str, lane: &Ty, n: u64) -> Result<CoreTy, String> {
    let v = vec_ty(path).ok_or_else(|| format!("the vector type `{path}`, which has no model representation"))?;
    let (ul, count) = v.lanes();
    let l = lane_of(ul).ok_or_else(|| format!("the lanes of `{path}`"))?;
    let bits = lane.bits().ok_or_else(|| format!("`{path}` with lanes of {lane:?}"))?;
    let same = match v.arch() {
        crate::target::Arch::X86_64 => bits as u64 * n == l.bits() as u64 * count,
        _ => !lane.signed() && bits == l.bits() && n == count,
    };
    if !same {
        return Err(format!("`{path}` laid out as {n} lanes of {lane:?}, which is not its model's {count} lanes of {}", l.core_name()));
    }
    Ok(CoreTy::Vector(l, count as u32))
}

/// The L type of a MIR type that is a model type (a vector, or a machine
/// word), as core text.
pub fn core_ty_text(t: CoreTy) -> String {
    match t {
        CoreTy::Word(_) => t.text(),
        CoreTy::Vector(..) => format!("({})", t.text()),
    }
}

/// The validated model of an intrinsic call made in a body compiled with
/// `body_features` (the calling function's, as rustc compiles it), or why
/// the call is not read.
pub fn model(m: &Sbmir, a: &ArchCall, body_features: &[String]) -> Result<&'static CoreModel, String> {
    if !a.safe || a.pointer {
        let what = if a.pointer { "takes or returns a raw pointer (a load or a store)" } else { "is an `unsafe fn`" };
        return Err(format!(
            "the intrinsic `{}` {what}: refused, verified code is safe Rust (DESIGN.md §16.5) and whether shipped `unsafe` SIMD code may be split into safe vector arithmetic and unverified loads and stores is the user's open decision (§18, decision 9); build the vectors with value intrinsics, and leave the loads and stores to unverified host code (DESIGN.md §16.4)",
            a.path
        ));
    }
    let (arch, _) = split(&a.path).ok_or_else(|| format!("`{}` is not a `core::arch` path", a.path))?;
    match &m.target {
        Some((_, t)) if t == arch => {}
        Some((triple, t)) => return Err(format!("the intrinsic `{}` in MIR extracted for `{triple}` ({t})", a.path)),
        None => return Err(format!("the intrinsic `{}` in an extraction that records no target (extract it again)", a.path)),
    }
    let cm = coretext::find_by_path(&a.path).filter(|cm| cm.rust_path() == a.path).ok_or_else(|| format!("the intrinsic `{}` has no model in the target library (sandblaster/targets): not read", a.path))?;
    match evidence::validation(cm.arch, cm.name) {
        Validation::Validated { .. } => {}
        other => return Err(format!("the model of `{}` is not validated ({other:?}): not read", a.path)),
    }
    let need: Vec<&str> = cm.model().features.iter().copied().chain(a.features.iter().map(String::as_str)).collect();
    let missing: Vec<&str> = need.iter().copied().filter(|f| !body_features.iter().any(|g| g == f)).collect();
    if !missing.is_empty() {
        let mut missing = missing;
        missing.sort();
        missing.dedup();
        return Err(format!("the intrinsic `{}` needs target feature(s) {}, which the calling function is not compiled with (`#[target_feature(enable = \"..\")]`)", a.path, missing.join(", ")));
    }
    Ok(cm)
}

/// The model's global as the target library loaded it into `env`
/// (`elab::semantics::install`): a `def[intrinsic]` with the model's type.
/// (A later definition may take over a name in the kernel; the global L
/// applies must be the model, never a stand-in.)
pub fn loaded(env: &Env, cm: &CoreModel) -> Result<(), String> {
    let g = env.lookup_global(cm.global).ok_or_else(|| format!("the model `{}` is not loaded (the build target's architecture loads its own models only)", cm.global))?;
    if env.global_kind(g) != Some(DefKind::Intrinsic) {
        return Err(format!("`{}` is not the target library's model", cm.global));
    }
    let want = env.parse_term(&[], &cm.type_text()).map_err(|e| format!("the model `{}`'s type: {e}", cm.global))?;
    let got = env.global_type(g).ok_or_else(|| format!("`{}` has no type", cm.global))?;
    if !env.alpha_eq_relevant(&got, &want, &|a, b| a == b) {
        return Err(format!("`{}` is not of its model's type", cm.global));
    }
    Ok(())
}

/// The immediates of a call as the model takes them: as many as it has,
/// each in its range (rustc's `static_assert` refuses any other value at
/// compile time).
pub fn immediates(cm: &CoreModel, a: &ArchCall) -> Result<Vec<u32>, String> {
    if a.imms.len() != cm.imms.len() {
        return Err(format!("`{}` with {} immediate(s); its model takes {}", a.path, a.imms.len(), cm.imms.len()));
    }
    a.imms
        .iter()
        .zip(cm.imms)
        .map(|(v, imm)| match u32::try_from(*v) {
            Ok(x) if imm.lo <= x && x <= imm.hi => Ok(x),
            _ => Err(format!("`{}`'s immediate `{}` = {v}, outside its model's range {}..={}", a.path, imm.name, imm.lo, imm.hi)),
        })
        .collect()
}

/// Whether the MIR type `t` is the model type `want`: a vector of the same
/// representation, or a machine word of the same width (a signed type by
/// its two's-complement bits: `_mm_set_epi64x` takes `i64`s).
pub fn same_ty(t: &Ty, want: CoreTy) -> bool {
    match (t, want) {
        (Ty::Simd(p, l, n), CoreTy::Vector(..)) => vector(p, l, *n).is_ok_and(|v| v == want),
        (Ty::Int(_, b), CoreTy::Word(l)) => *b != 0 && *b == l.bits(),
        _ => false,
    }
}

/// A call into `std_detect` (runtime CPU feature detection): why it is not
/// read. A detection is a read of a cache in a static, initialized by
/// `cpuid` or the operating system; the reading has no model of either, and
/// a function whose behavior depends on it would have to meet its laws on
/// both answers (docs/mir-lift.md §20.9, "Feature detection").
pub fn detection(path: &str) -> Option<String> {
    path.starts_with("std_detect::").then(|| {
        format!("runtime feature detection (`{path}`): not read (the feature is not enabled statically for the extraction's target, so the answer is a run-time value; a function reading it is refused: docs/mir-lift.md §20.9)")
    })
}
