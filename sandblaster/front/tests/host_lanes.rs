//! Host runs of the lane kernels (plan O10): the harness of the host kit's
//! `lanes` stage (`tools/host-kit/run.sh --stages lanes`).
//!
//! A lane kernel (the lane functor's `s__<target>`, e.g. SHA-256 ×16 on
//! AVX-512) uses validated intrinsic models only, but it is dispatched only
//! when the evidence record says a host has run the kernel itself against
//! its lane site (`sandblaster_targets::evidence::SetRecord`, set name
//! `lanes:<target>:<hash>`, suite `lane-differential`; the hash covers the
//! kernel as printed, the helpers it calls and the compiler,
//! `sandblaster_front::opt::par::lane_fingerprint`). This harness produces
//! those runs: it emits `tests/samples/lanes` for the host's architecture
//! with the kernels' host runs granted by a test hook (the only way to get
//! them emitted before any host has run them), compiles it natively, and
//! runs every kernel directly against the portable site (`s__portable`) on
//! corner and pseudo-random inputs.
//!
//! * x86_64: the AVX-512 ×16 kernels (`compress_x16`, `hash64_x16`) and the
//!   AVX2 ×8 kernel (`compress_x8`), which the cost model picks.
//! * aarch64: the NEON ×4 kernel (`compress_x4`). The cost model rejects it
//!   on the M5 (the SHA2 instructions are cheaper), so the harness also
//!   forces its dispatch with a test hook; the run is recorded all the
//!   same, and the kernel is dispatched in a real build only where the cost
//!   model picks it.
//!
//! The emitted file is compiled by `rustc` from `PATH`, which must be the
//! compiler that built this harness (the set name includes it, and a run
//! compiled by another compiler would be recorded under a name no build
//! uses): the harness checks that first.
//!
//! Each kernel runs in its own process: on a CPU without the target's
//! features the process may die on an illegal instruction (`crashed`;
//! the kit records nothing for a CPU that does not report the features,
//! and a failure for one that does). The results go to `$HOST_LANES_OUT`
//! (JSON lines: set, features, suite, cases, mismatches, crashed), which the
//! kit records with `sandblaster-targets-evidence --record-set`.
//!
//! Environment: `HOST_LANES_OUT`, `HOST_LANES_TARGET` (rustc target, whose
//! architecture picks the kernels; default: the host's architecture,
//! `-unknown-linux-gnu` on Linux and `-apple-darwin` elsewhere),
//! `HOST_LANES_CASES` (random inputs per kernel, default 10^6).
//!
//! Run: `cargo test -p sandblaster-front --release --features opt-test-hooks --test host_lanes -- --ignored --nocapture`.

mod common;

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use common::tmp;
use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::OptOptions;
use sandblaster_front::opt::hooks::OptTestHooks;
use sandblaster_front::target::TargetInfo;

#[test]
#[ignore = "a host-kit harness: emits, compiles and runs the lane kernels on this CPU (minutes)"]
fn host_lane_runs() {
    // the kernels of the target's architecture (the kit passes its target:
    // on Apple silicon it defaults to x86_64-apple-darwin under Rosetta 2)
    let host_arch = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
    let target = std::env::var("HOST_LANES_TARGET").unwrap_or_else(|_| if cfg!(target_os = "linux") { format!("{host_arch}-unknown-linux-gnu") } else { format!("{host_arch}-apple-darwin") });
    let arm = target.starts_with("aarch64");
    // the compiler that builds the kernels is the one their set names
    let rustc_v = Command::new("rustc").arg("-V").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    assert_eq!(rustc_v, sandblaster_targets::evidence::BUILD_RUSTC, "`rustc` on PATH is not the compiler that built this harness: the lane runs would be recorded under set names no build of this toolchain uses");
    let out = std::env::var("HOST_LANES_OUT").map(std::path::PathBuf::from).unwrap_or_else(|_| tmp("host-lanes").join("results.jsonl"));
    let cases: u64 = std::env::var("HOST_LANES_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    let dir_src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/samples/lanes");
    let mut fs = MemFs::new();
    for f in ["mod.rs", "sha256.rs", "sites.rs"] {
        fs.insert(&format!("l/{f}"), &std::fs::read_to_string(dir_src.join(f)).unwrap());
    }
    let info = if arm { TargetInfo::aarch64_apple_darwin() } else { TargetInfo::x86_64_apple_darwin() };
    let c = driver::check(Path::new("l/mod.rs"), &fs, &info);
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let em = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let hooks = if arm {
            // the M5's cost model rejects the NEON ×4 kernel: forced, so it is emitted and run
            OptTestHooks { set_evidence: ["lanes:neon_x4".to_string()].into(), force_dispatch: ["crate::sites::compress_x4__neon_x4".to_string()].into(), ..Default::default() }
        } else {
            OptTestHooks { set_evidence: ["lanes:avx512_x16".to_string(), "lanes:avx2_x8".to_string()].into(), ..Default::default() }
        };
        driver::stage::optimize_emit_mode(&c, &mut out, "tests/samples/lanes/mod.rs", "", &OptOptions { strict: true, hooks: Some(Arc::new(hooks)), ..Default::default() }, true).unwrap()
    });
    assert!(em.opt.errors.is_empty() && em.roundtrip.is_empty(), "{:?} {:?}", em.opt.errors, em.roundtrip);
    let kernels: Vec<_> = em.opt.lanes.iter().filter(|l| l.dispatched).cloned().collect();
    assert!(!kernels.is_empty(), "no lane kernel dispatched: {:?}", em.opt.lanes.iter().map(|l| &l.note).collect::<Vec<_>>());
    let dir = tmp("host-lanes");
    std::fs::write(dir.join("sandblaster.rs"), &em.code).unwrap();
    // one function per kernel: the kernel against the portable site
    let mut runs = String::new();
    let mut arms = String::new();
    for (i, l) in kernels.iter().enumerate() {
        let site = l.site.rsplit("::").next().unwrap().to_string();
        let kern = l.kernel.rsplit("::").next().unwrap().to_string();
        let (arg_ty, call_k, call_p, input) = match site.as_str() {
            s if s.starts_with("compress_x") => {
                let n: usize = s["compress_x".len()..].parse().unwrap();
                (
                    format!("([[u32; 8]; {n}], [[u8; 64]; {n}])"),
                    format!("unsafe {{ crate::__sandblaster::sites::{kern}(&x.0, &x.1) }}"),
                    format!("crate::__sandblaster::sites::{site}__portable(&x.0, &x.1)"),
                    format!("(core::array::from_fn(|_| core::array::from_fn(|_| next(&mut s) as u32)), core::array::from_fn(|_| core::array::from_fn(|_| next(&mut s) as u8)))"),
                )
            }
            s if s.starts_with("hash64_x") => {
                let n: usize = s["hash64_x".len()..].parse().unwrap();
                (format!("[[u8; 64]; {n}]"), format!("unsafe {{ crate::__sandblaster::sites::{kern}(&x) }}"), format!("crate::__sandblaster::sites::{site}__portable(&x)"), "core::array::from_fn(|_| core::array::from_fn(|_| next(&mut s) as u8))".to_string())
            }
            other => panic!("unknown lane site {other}"),
        };
        runs.push_str(&format!(
            r#"
#[allow(unsafe_code)]
fn run_{i}(cases: u64) {{
    let mut s: u64 = 0x9e37_79b9_7f4a_7c15 ^ {i};
    fn next(s: &mut u64) -> u64 {{ *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; *s }}
    let (mut n, mut bad) = (0u64, 0u64);
    for c in 0..cases {{
        let mut x: {arg_ty} = {input};
        // corner inputs first: all-zero and all-ones lanes
        if c == 0 {{ x = unsafe {{ core::mem::zeroed() }}; }}
        let a = {call_k};
        let b = {call_p};
        n += 1;
        bad += u64::from(a != b);
    }}
    println!("suite lane-differential cases {{n}} mismatches {{bad}}");
}}
"#
        ));
        arms.push_str(&format!("        \"{i}\" => run_{i}(cases),\n"));
    }
    let main = format!(
        r#"include!({generated:?});
{runs}
fn main() {{
    let mut args = std::env::args().skip(1);
    let which = args.next().expect("a kernel index");
    let cases: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1_000_000);
    match which.as_str() {{
{arms}        other => panic!("unknown kernel {{other}}"),
    }}
}}
"#,
        generated = dir.join("sandblaster.rs"),
    );
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let bin = dir.join("host_lanes");
    let st = Command::new("rustc").args(["--edition", "2024", "--target", &target, "-O", "--cap-lints", "warn", "-o"]).arg(&bin).arg(dir.join("main.rs")).output().expect("rustc");
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stderr));
    let mut lines = Vec::new();
    for (i, l) in kernels.iter().enumerate() {
        let features: Vec<String> = em.opt.variants.iter().find(|v| v.variant == l.kernel).map(|v| v.features.clone()).unwrap_or_default();
        let feats = features.iter().map(|f| format!("\"{f}\"")).collect::<Vec<_>>().join(", ");
        let run = Command::new(&bin).arg(i.to_string()).arg(cases.to_string()).output();
        let (stdout, crashed) = match &run {
            Ok(r) if r.status.success() => (String::from_utf8_lossy(&r.stdout).to_string(), false),
            Ok(r) => (String::from_utf8_lossy(&r.stdout).to_string(), true),
            Err(e) => panic!("cannot run {}: {e}", bin.display()),
        };
        println!("{} ({}){}:\n{stdout}", l.kernel, l.lane_set, if crashed { " CRASHED" } else { "" });
        let mut seen = false;
        for line in stdout.lines() {
            let w: Vec<&str> = line.split_whitespace().collect();
            if let ["suite", suite, "cases", n, "mismatches", m] = w[..] {
                seen = true;
                lines.push(format!("{{\"set\": \"{}\", \"features\": [{feats}], \"suite\": \"{suite}\", \"cases\": {n}, \"mismatches\": {m}, \"crashed\": false}}", l.lane_set));
            }
        }
        if crashed || !seen {
            lines.push(format!("{{\"set\": \"{}\", \"features\": [{feats}], \"suite\": \"lane-differential\", \"cases\": 0, \"mismatches\": 0, \"crashed\": true}}", l.lane_set));
        }
    }
    if let Some(d) = out.parent() {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(&out, lines.join("\n") + "\n").unwrap();
    println!("results in {}", out.display());
}
