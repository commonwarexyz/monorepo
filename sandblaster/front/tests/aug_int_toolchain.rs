//! Toolchain features added for the varint pilot (commonware-codec's
//! `varint.rs` lifted as-is, with ZigZag): each has a positive test and a
//! negative twin.
//!
//! * `auto`'s equality closure: a target `a == b` of any type joined to its
//!   sides by fact equations (`eq::trans`/`eq::sym`, kernel-checked);
//! * `use_hyp(i, args..)` in `#[proof(complete = ..)]` items: an explicit
//!   instance of the section hypothesis `h{i}`;
//! * `#[lift(host)]` modules: host models whose enum variants the emitted
//!   module checks against the host;
//! * signed integers in lifted code (SEMANTICS.md §19.3): an `iN` is its
//!   two's complement bits, every sign-dependent operation is translated,
//!   the others are refused; the translation agrees with rustc on many
//!   inputs (kernel evaluation against native code);
//! * LR5 compares code, not proofs.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::Path;

use sandblaster_front::diag::{DiagKind, Severity};
use sandblaster_front::driver::{self, Checked, ProverSet, Verification, VerifyOptions};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;
use util::{explain, unproven};

const ROOT: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// The MIR fixtures of this file (`mir_fixtures/ai_*`): a lifted module's
/// source and rustc's MIR of it (`mir_fixtures/extract.py`).
const FIXTURES: &[(&str, &str)] = &[
    (include_str!("mir_fixtures/ai_err/w.rs"), include_str!("mir_fixtures/ai_err/w.sbmir")),
    (include_str!("mir_fixtures/ai_signed/s.rs"), include_str!("mir_fixtures/ai_signed/s.sbmir")),
    (include_str!("mir_fixtures/ai_panics/s.rs"), include_str!("mir_fixtures/ai_panics/s.sbmir")),
    (include_str!("mir_fixtures/ai_lit/s.rs"), include_str!("mir_fixtures/ai_lit/s.sbmir")),
    (include_str!("mir_fixtures/ai_ref_add/s.rs"), include_str!("mir_fixtures/ai_ref_add/s.sbmir")),
    (include_str!("mir_fixtures/ai_ref_lt/s.rs"), include_str!("mir_fixtures/ai_ref_lt/s.sbmir")),
    (include_str!("mir_fixtures/ai_ref_widen/s.rs"), include_str!("mir_fixtures/ai_ref_widen/s.sbmir")),
    (include_str!("mir_fixtures/ai_ref_abs/s.rs"), include_str!("mir_fixtures/ai_ref_abs/s.sbmir")),
];

/// The files, and rustc's MIR of each lifted module's source next to it
/// (`r/w.rs` → `r/w.sbmir`).
fn check(files: &[(&str, &str)]) -> Checked {
    let mirs: Vec<(String, &str)> = files.iter().filter_map(|(p, c)| FIXTURES.iter().find(|(s, _)| s == c).map(|(_, m)| (p.replace(".rs", ".sbmir"), *m))).collect();
    let fs = MemFs::from_files(files.iter().map(|(p, c)| (*p, *c)).chain(mirs.iter().map(|(p, m)| (p.as_str(), *m))));
    driver::check(Path::new(files[0].0), &fs, &TargetInfo::aarch64_apple_darwin())
}

fn root(decls: &str) -> String {
    format!("{ROOT}{decls}")
}

fn errors(c: &Checked) -> Vec<(DiagKind, String)> {
    c.diags.list.iter().filter(|d| d.severity == Severity::Error).map(|d| (d.kind, d.msg.clone())).collect()
}

#[track_caller]
fn rejects(c: &Checked, kind: DiagKind, needle: &str) {
    assert!(errors(c).iter().any(|(k, m)| *k == kind && m.contains(needle)), "expected error[{}] containing {needle:?}; got:\n{}", kind.code(), c.render());
}

#[track_caller]
fn front_ok(files: &[(&str, &str)]) -> Checked {
    let c = check(files);
    assert!(c.ok(), "front end rejected the crate:\n{}", c.render());
    c
}

/// Verifies with ghost code (lemmas, proofs).
fn verify(c: &Checked) -> Verification {
    driver::stage::verify(c.krate.as_ref().unwrap(), &VerifyOptions { provers: ProverSet::Standard, exec_only: false })
}

// ---------------------------------------------------------------------
// auto: equality closure
// ---------------------------------------------------------------------

const CLOSURE: &str = r#"
#[cfg(sandblaster)]
#[lemma]
fn seq_chain(a: Seq<u8>, b: Seq<u8>, c: Seq<u8>, d: Seq<u8>) {
    requires(a == c && d == c && d == b);
    ensures(a == b);
    follows();
}

#[cfg(sandblaster)]
#[lemma]
fn option_chain(a: Option<u16>, b: Option<u16>, c: Option<u16>) {
    requires(a == c && b == c);
    ensures(b == a);
    follows();
}
"#;

#[test]
fn equations_of_any_type_chain() {
    let c = front_ok(&[("r/mod.rs", &root(CLOSURE))]);
    let v = verify(&c);
    util::assert_verified(&c, &v);
}

#[test]
fn an_equation_chain_needs_every_link() {
    // `d == b` dropped: `a` and `b` are not joined
    let c = front_ok(&[("r/mod.rs", &root(&CLOSURE.replace("requires(a == c && d == c && d == b);", "requires(a == c && d == c);")))]);
    let v = verify(&c);
    assert!(unproven(&v).iter().any(|(d, k)| d == "crate::seq_chain" && k == "ensures"), "{}", explain(&c, &v));
}

// ---------------------------------------------------------------------
// use_hyp in completeness proofs
// ---------------------------------------------------------------------

const IS_EVEN: &str = r#"
#[cfg(sandblaster)]
#[spec]
fn even(x: Nat) -> bool { x % 2 == 0 }

pub fn is_even(x: u32) -> bool { x % 2 == 0 }

#[cfg(sandblaster)]
#[path = "LAWS.rs"]
mod laws;

#[cfg(sandblaster)]
#[path = "PROOF.rs"]
mod proof;
"#;

const IS_EVEN_LAWS: &str = r#"use sandblaster::prelude::*;
use super::{is_even, even};

/// `is_even` holds only of even numbers.
#[law]
fn is_even_sound(x: u32) {
    requires(is_even(x));
    ensures(even(x as Nat));
}

/// `is_even` holds of every even number.
#[law]
fn is_even_complete(x: u32) {
    requires(even(x as Nat));
    ensures(is_even(x));
}
"#;

fn is_even_proof(body: &str) -> String {
    format!(
        "use sandblaster::prelude::*;\n#[allow(unused_imports)]\nuse super::{{is_even, even}};\n\n#[proof]\nfn is_even_sound(x: u32) {{\n    follows();\n}}\n\n#[proof]\nfn is_even_complete(x: u32) {{\n    follows();\n}}\n\n/// Pinned by its laws, with explicit instances of them.\n#[proof(complete = super::is_even)]\nfn is_even_determined(x: u32) {{\n{body}\n}}\n"
    )
}

/// A call of `is_even` in the proof item is the hypothetical `is_even'`:
/// `use_hyp(0, x)` is the soundness law for it at `x` (its `requires` proven
/// from the branch), `use_hyp(1, x)` the completeness law.
const USE_HYP: &str = "    if is_even(x) {\n        use_hyp(0, x);\n        follows();\n    } else if even(x as Nat) {\n        use_hyp(1, x);\n        by_contradiction();\n    } else {\n        follows();\n    }";

#[test]
fn use_hyp_instantiates_a_section_hypothesis() {
    let r = root(IS_EVEN);
    let p = is_even_proof(USE_HYP);
    let c = front_ok(&[("r/mod.rs", &r), ("r/LAWS.rs", IS_EVEN_LAWS), ("r/PROOF.rs", &p)]);
    let v = verify(&c);
    util::assert_verified(&c, &v);
}

#[test]
fn use_hyp_of_a_missing_hypothesis_or_with_extra_arguments_is_refused() {
    let r = root(IS_EVEN);
    for (body, needle) in [
        (USE_HYP.replace("use_hyp(1, x);", "use_hyp(7, x);"), "use_hyp"),
        (USE_HYP.replace("use_hyp(1, x);", "use_hyp(1, x, x);"), "too many"),
    ] {
        let p = is_even_proof(&body);
        let c = front_ok(&[("r/mod.rs", &r), ("r/LAWS.rs", IS_EVEN_LAWS), ("r/PROOF.rs", &p)]);
        let v = verify(&c);
        assert!(!v.proofs_ok, "{needle}: expected a failure\n{}", explain(&c, &v));
        let text = explain(&c, &v);
        assert!(text.contains(needle), "{needle}: {text}");
    }
}

#[test]
fn use_hyp_needs_the_hypothesis_requires() {
    let r = root(IS_EVEN);
    // the completeness instance where `even(x)` is false (and nothing
    // contradicts that)
    let p = is_even_proof(&USE_HYP.replace("    } else {\n        follows();\n    }", "    } else {\n        use_hyp(1, x);\n        follows();\n    }"));
    let c = front_ok(&[("r/mod.rs", &r), ("r/LAWS.rs", IS_EVEN_LAWS), ("r/PROOF.rs", &p)]);
    let v = verify(&c);
    assert!(!v.proofs_ok, "{}", explain(&c, &v));
}

// ---------------------------------------------------------------------
// #[lift(host)]
// ---------------------------------------------------------------------

const ERR_MODEL: &str = "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub enum Error {\n    EndOfBuffer,\n    InvalidVarint(usize),\n}\n";

const USES_ERR: &str = include_str!("mir_fixtures/ai_err/w.rs");

#[test]
fn a_host_model_is_checked_variant_by_variant() {
    let r = root("#[lift(mir = \"w.sbmir\")]\nmod w;\n#[lift(host)]\nmod error;\npub use error::Error;\npub use w::fail;\n");
    let c = front_ok(&[("r/mod.rs", &r), ("r/w.rs", USES_ERR), ("r/error.rs", ERR_MODEL)]);
    assert!(c.lifted.iter().any(|l| l.name == "error" && l.host), "{:?}", c.lifted);
    assert!(c.lifted.iter().any(|l| l.name == "w" && !l.host), "{:?}", c.lifted);
    assert_eq!(c.lift_facts.host_checks, vec!["const _: Error = Error::EndOfBuffer;".to_string(), "const _: fn(usize) -> Error = Error::InvalidVarint;".to_string()]);
    assert_eq!(driver::lifted::emitted_module(&c.lifted).unwrap().unwrap().name, "w");
    let v = verify(&c);
    util::assert_verified(&c, &v);
}

#[test]
fn a_host_model_holds_only_checkable_enums() {
    let r = root("#[lift(mir = \"w.sbmir\")]\nmod w;\n#[lift(host)]\nmod error;\npub use error::Error;\npub use w::fail;\n");
    let with_struct = format!("{ERR_MODEL}pub struct Extra(pub u8);\n");
    let c = check(&[("r/mod.rs", &r), ("r/w.rs", USES_ERR), ("r/error.rs", &with_struct)]);
    rejects(&c, DiagKind::Unsupported, "holds only non-generic enums");
    let named = ERR_MODEL.replace("InvalidVarint(usize),", "InvalidVarint { width: usize },");
    let c = check(&[("r/mod.rs", &r), ("r/w.rs", USES_ERR), ("r/error.rs", &named)]);
    rejects(&c, DiagKind::Unsupported, "has named fields");
    let c = check(&[("r/mod.rs", &root("#[lift(hosted)]\nmod w;\npub use w::fail;\n")), ("r/w.rs", USES_ERR)]);
    rejects(&c, DiagKind::Load, "expected `#[lift]`, `#[lift(host)]`");
}

// ---------------------------------------------------------------------
// signed integers in lifted code
// ---------------------------------------------------------------------

/// Signed operations on the bits a `u32` carries, as the codec writes them.
const SIGNED: &str = include_str!("mir_fixtures/ai_signed/s.rs");

const SIGNED_ROOT: &str = "#[lift(mir = \"s.sbmir\")]\nmod s;\npub use s::{shr_bits, shl_bits, neg_bits, zz, unzz, narrow, lit};\n";

fn native(f: &str, a: u32, k: u32) -> String {
    let v: u32 = match f {
        "shr_bits" => if k < 32 { ((a as i32) >> k) as u32 } else { 0 },
        "shl_bits" => if k < 32 { ((a as i32) << k) as u32 } else { 0 },
        "neg_bits" => if a == 0x8000_0000 { 0 } else { (-(a as i32)) as u32 },
        "zz" => (((a as i32) << 1) ^ ((a as i32) >> 31)) as u32,
        "unzz" => (((a >> 1) as i32) ^ (-((a & 1) as i32))) as u32,
        "narrow" => ((a as i32) as i16) as u16 as u32,
        _ => unreachable!(),
    };
    v.to_string()
}

#[test]
fn signed_operations_agree_with_rustc() {
    let r = root(SIGNED_ROOT);
    let c = front_ok(&[("r/mod.rs", &r), ("r/s.rs", SIGNED)]);
    let k = c.krate.clone().unwrap();
    let mut inputs: Vec<u32> = vec![0, 1, 2, 3, 0x7FFF_FFFF, 0x8000_0000, 0x8000_0001, 0xFFFF_FFFF, 0xFFFF_FFFE, 0x7FFF, 0x8000, 0xFFFF, 0x1_0000];
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..200 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        inputs.push(x as u32);
    }
    let amounts = [0u32, 1, 2, 7, 15, 16, 30, 31, 32, 40];
    let (ok, bad) = driver::stage::with_elaboration(&k, &VerifyOptions { provers: ProverSet::Standard, exec_only: true }, |out| {
        let ok = out.verified();
        let mut bad = Vec::new();
        for &a in &inputs {
            for f in ["neg_bits", "zz", "unzz", "narrow"] {
                let got = driver::stage::eval_in(out, &k, &format!("crate::s::{f}"), &format!("[{a}]"));
                if got.as_deref() != Ok(native(f, a, 0).as_str()) {
                    bad.push(format!("{f}({a}): kernel {got:?}, native {}", native(f, a, 0)));
                }
            }
            for &s in &amounts {
                for f in ["shr_bits", "shl_bits"] {
                    let got = driver::stage::eval_in(out, &k, &format!("crate::s::{f}"), &format!("[{a}, {s}]"));
                    if got.as_deref() != Ok(native(f, a, s).as_str()) {
                        bad.push(format!("{f}({a}, {s}): kernel {got:?}, native {}", native(f, a, s)));
                    }
                }
            }
        }
        let l = driver::stage::eval_in(out, &k, "crate::s::lit", "[]");
        if l.as_deref() != Ok(((-3i32 >> 1) as u32).to_string().as_str()) {
            bad.push(format!("lit(): kernel {l:?}"));
        }
        (ok, bad)
    });
    assert!(ok, "the signed operations do not verify");
    assert!(bad.is_empty(), "kernel evaluation disagrees with rustc:\n{}", bad[..bad.len().min(20)].join("\n"));
}

#[test]
fn sign_dependent_operations_the_lift_does_not_translate_are_refused() {
    let r = root("#[lift(mir = \"s.sbmir\")]\nmod s;\npub use s::f;\n");
    for (body, needle) in [
        // (rustc's MIR of each, `mir_fixtures/ai_ref_*`, read by `mir::read`)
        ("pub fn f(a: u32, b: u32) -> u32 { ((a as i32) + (b as i32)) as u32 }", "signed checked `add`"),
        ("pub fn f(a: u32, b: u32) -> bool { (a as i32) < (b as i32) }", "the signed operation `lt`"),
        ("pub fn f(a: u32) -> u64 { (a as i32) as u64 }", "sign extension is not read"),
        // `abs` is core's MIR, refused at its first sign-dependent operation
        ("pub fn f(a: u32) -> u32 { (a as i32).abs() as u32 }", "(in `core::num::<impl i32>::abs`): the signed operation `lt`"),
    ] {
        let c = check(&[("r/mod.rs", &r), ("r/s.rs", body)]);
        rejects(&c, DiagKind::Unsupported, needle);
    }
}

#[test]
fn rusts_signed_panics_are_obligations() {
    let r = root("#[lift(mir = \"s.sbmir\")]\nmod s;\npub use s::{neg, shr};\n");
    // `-x` panics on `i32::MIN`, `x >> k` for `k >= 32`
    let body = "pub fn neg(b: u32) -> u32 { (-(b as i32)) as u32 }\npub fn shr(b: u32, k: u32) -> u32 { ((b as i32) >> k) as u32 }\n";
    let c = front_ok(&[("r/mod.rs", &r), ("r/s.rs", body)]);
    let v = verify(&c);
    let bad = unproven(&v);
    assert!(bad.iter().any(|(d, k)| d == "crate::s::neg" && k == "callee-requires"), "{}", explain(&c, &v));
    assert!(bad.iter().any(|(d, k)| d == "crate::s::shr" && k == "callee-requires"), "{}", explain(&c, &v));
}

#[test]
fn a_signed_value_in_ghost_code_is_its_number() {
    let proof = "use sandblaster::prelude::*;\n\n#[lemma]\nfn minus_three() {\n    ensures(((4294967293u32 as i32) as Int) == -3);\n    by_unfolding(crate::__lift_model::int_of_i32);\n}\n";
    let r = root("#[lift(mir = \"s.sbmir\")]\nmod s;\n#[cfg(sandblaster)]\n#[lift]\n#[path = \"PROOF.rs\"]\nmod proof;\npub use s::lit;\n");
    let c = front_ok(&[("r/mod.rs", &r), ("r/s.rs", "pub fn lit() -> u32 { (-3i32 >> 1) as u32 }\n"), ("r/PROOF.rs", proof)]);
    let v = verify(&c);
    util::assert_verified(&c, &v);
    // negative twin: the bits read as a number is not the value
    let c = front_ok(&[("r/mod.rs", &r), ("r/s.rs", "pub fn lit() -> u32 { (-3i32 >> 1) as u32 }\n"), ("r/PROOF.rs", &proof.replace("== -3", "== 4294967293"))]);
    let v = verify(&c);
    assert!(unproven(&v).iter().any(|(d, _)| d.contains("minus_three")), "{}", explain(&c, &v));
}
