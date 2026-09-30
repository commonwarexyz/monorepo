//! Shared helpers of the elaboration tests (`tests/elab_*.rs` include this
//! file as `mod util`; built alone it is an empty test crate).
//!
//! * [`program!`] writes a test program **once**: it becomes a native Rust
//!   module (compiled by rustc into the test binary, `proof!` erased) and a
//!   DSL source string for the sandblaster front end and elaborator;
//! * [`calls!`] evaluates calls natively and records their arguments and
//!   results as JSON, so [`differential`] can compare the kernel evaluator
//!   (the reference semantics, DESIGN.md §10.3 "K-style" differential
//!   corpus) against the native results;
//! * [`verify_src`] / [`with_elab`] run the verified pipeline on a source.
#![allow(dead_code, unused_macros)]

use std::path::Path;

use sandblaster_front::driver::{self, Checked, ProverSet, Verification, VerifyOptions};
use sandblaster_front::elab::{self, value::J, DefStatus, OblStatus};
use sandblaster_front::loader::MemFs;
use sandblaster_front::target::TargetInfo;

/// The standard header of test roots.
pub const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// Checks a single-module crate made of [`HEADER`] + `body` (aarch64).
pub fn check_src(body: &str) -> Checked {
    let src = format!("{HEADER}{body}");
    let fs = MemFs::from_files([("r/mod.rs", src.as_str())]);
    driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin())
}

/// Checks an in-memory crate; `files[0]` is the root (its text gets
/// [`HEADER`] prepended).
pub fn check_files(files: &[(&str, &str)]) -> Checked {
    let mut owned: Vec<(String, String)> = files.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
    owned[0].1 = format!("{HEADER}{}", owned[0].1);
    let fs = MemFs::from_files(owned.iter().map(|(p, c)| (p.as_str(), c.as_str())));
    driver::check(Path::new(&owned[0].0), &fs, &TargetInfo::aarch64_apple_darwin())
}

/// Checks `body`, asserting the front end accepts it.
#[track_caller]
pub fn accepted(body: &str) -> Checked {
    let c = check_src(body);
    assert!(c.ok(), "front end rejected the program:\n{}\n--- source ---\n{body}", c.render());
    c
}

/// The options of the elaboration tests: exec code only (test-only), the
/// given provers.
pub fn opts(provers: ProverSet) -> VerifyOptions {
    // `ELAB_TEST_PROVERS=standard` runs every test with the build's chain
    let provers = if std::env::var("ELAB_TEST_PROVERS").as_deref() == Ok("standard") { ProverSet::Standard } else { provers };
    VerifyOptions { provers, exec_only: true }
}

/// Runs the verified pipeline (exec code) on `body`.
pub fn verify_src(body: &str, provers: ProverSet) -> (Checked, Verification) {
    let c = accepted(body);
    let v = driver::stage::verify(c.krate.as_ref().unwrap(), &opts(provers));
    (c, v)
}

/// Runs `f` on the elaboration of `body` (on the big-stack thread).
pub fn with_elab<T: Send>(body: &str, provers: ProverSet, f: impl FnOnce(&Checked, &elab::Output) -> T + Send) -> T {
    let c = accepted(body);
    let k = c.krate.as_ref().unwrap();
    let c2 = &c;
    driver::stage::with_elaboration(k, &opts(provers), move |out| f(c2, out))
}

/// Renders the diagnostics and the status of every definition that did not
/// check, for assertion messages.
pub fn explain(c: &Checked, v: &Verification) -> String {
    let mut s = String::new();
    for d in &v.defs {
        if d.status != DefStatus::Checked {
            s.push_str(&format!("def {}: {:?}\n", d.name, d.status));
        }
    }
    for o in &v.obligations {
        if !o.proven() {
            s.push_str(&format!("unproven {} [{}]: {}\n", o.def, elab::obl::kind_name(&o.kind), o.goal));
        }
    }
    s.push_str(&v.diags.render(&c.sm));
    s
}

/// Asserts every definition checked and every obligation proven.
#[track_caller]
pub fn assert_verified(c: &Checked, v: &Verification) {
    let ok = v.failed_defs().is_empty() && v.obligations.iter().all(|o| o.proven()) && !v.diags.has_errors();
    assert!(ok, "not verified:\n{}", explain(c, v));
}

/// Unproven obligations as `(def, kind)`.
pub fn unproven(v: &Verification) -> Vec<(String, String)> {
    v.obligations.iter().filter(|o| !matches!(o.status, OblStatus::Proven { .. })).map(|o| (o.def.clone(), elab::obl::kind_name(&o.kind).to_string())).collect()
}

/// Obligation kinds of a definition, in generation order.
pub fn kinds_of(v: &Verification, def: &str) -> Vec<String> {
    v.obligations.iter().filter(|o| o.def == def).map(|o| elab::obl::kind_name(&o.kind).to_string()).collect()
}

/// Status of a definition by kernel name.
pub fn status_of<'v>(v: &'v Verification, def: &str) -> &'v DefStatus {
    &v.defs.iter().find(|d| d.name == def).unwrap_or_else(|| panic!("no definition `{def}`; have {:?}", v.defs.iter().map(|d| &d.name).collect::<Vec<_>>())).status
}

/// Values printable in the JSON format of `elab::value` (for native
/// arguments and results).
pub trait ToJ {
    fn j(&self) -> String;
}

macro_rules! num_toj {
    ($($t:ty),*) => { $(impl ToJ for $t { fn j(&self) -> String { self.to_string() } })* };
}
num_toj!(u8, u16, u32, u64, usize);

impl ToJ for bool {
    fn j(&self) -> String {
        self.to_string()
    }
}
impl ToJ for () {
    fn j(&self) -> String {
        "null".into()
    }
}
impl<T: ToJ> ToJ for [T] {
    fn j(&self) -> String {
        format!("[{}]", self.iter().map(|x| x.j()).collect::<Vec<_>>().join(","))
    }
}
impl<T: ToJ, const N: usize> ToJ for [T; N] {
    fn j(&self) -> String {
        self[..].j()
    }
}
impl<T: ToJ + ?Sized> ToJ for &T {
    fn j(&self) -> String {
        (**self).j()
    }
}
impl<T: ToJ> ToJ for Option<T> {
    fn j(&self) -> String {
        match self {
            None => "null".into(),
            Some(x) => format!("{{\"Some\":{}}}", x.j()),
        }
    }
}
impl<A: ToJ, B: ToJ> ToJ for (A, B) {
    fn j(&self) -> String {
        format!("[{},{}]", self.0.j(), self.1.j())
    }
}
impl<A: ToJ, B: ToJ, C: ToJ> ToJ for (A, B, C) {
    fn j(&self) -> String {
        format!("[{},{},{}]", self.0.j(), self.1.j(), self.2.j())
    }
}

/// Native erasure of `proof!` blocks (used by [`program!`] modules).
macro_rules! proof {
    ($($t:tt)*) => {};
}

/// A test program: a native module `$name` (rustc) and `$name::SRC`, the
/// same tokens as DSL source. `proof!` blocks are erased natively.
macro_rules! program {
    ($name:ident { $($src:tt)* }) => {
        #[allow(dead_code, unused, clippy::all)]
        pub mod $name {
            $($src)*
            pub const SRC: &str = stringify!($($src)*);
        }
    };
}

/// Native calls: `calls!(m; f(a, b); g(c))` evaluates `m::f(a, b)` natively
/// and returns `(fn, args JSON, result JSON)` per call.
macro_rules! calls {
    ($m:ident; $( $f:ident ( $($a:expr),* $(,)? ) );* $(;)?) => {{
        #[allow(unused_imports)]
        use $crate::util::ToJ;
        let v: Vec<(String, String, String)> = vec![
            $( (stringify!($f).to_string(), format!("[{}]", { let xs: Vec<String> = vec![$( ToJ::j(&$a) ),*]; xs.join(",") }), ToJ::j(&$m::$f($($a),*))) ),*
        ];
        v
    }};
}

fn normalize(s: &str) -> String {
    J::parse(s).map(|j| j.render()).unwrap_or_else(|e| format!("<bad JSON {s}: {e}>"))
}

/// Verifies `src` (every obligation must be proven) and compares the kernel
/// evaluation of every call with its native result.
#[track_caller]
pub fn differential(src: &str, provers: ProverSet, cases: &[(String, String, String)]) {
    let results = with_elab(src, provers, |c, out| {
        let v = Verification {
            defs: out.defs.clone(),
            obligations: out.obligations.clone(),
            laws: out.laws.clone(),
            diags: out.diags.clone(),
            deferred: out.deferred.clone(),
            proofs_ok: out.verified(),
            elapsed: Default::default(),
            provers: vec![],
            exec_only: true,
        };
        let expl = explain(c, &v);
        let evals: Vec<Result<String, String>> = cases.iter().map(|(f, args, _)| driver::stage::eval_in(out, c.krate.as_ref().unwrap(), f, args)).collect();
        (out.verified(), expl, evals)
    });
    assert!(results.0, "program not verified:\n{}\n--- source ---\n{src}", results.1);
    let mut bad = Vec::new();
    for ((f, args, native), kernel) in cases.iter().zip(results.2) {
        match kernel {
            Ok(k) if normalize(&k) == normalize(native) => {}
            Ok(k) => bad.push(format!("{f}{args}: kernel {k}, native {native}")),
            Err(e) => bad.push(format!("{f}{args}: kernel error {e}, native {native}")),
        }
    }
    assert!(bad.is_empty(), "kernel evaluation disagrees with rustc:\n{}", bad.join("\n"));
}
