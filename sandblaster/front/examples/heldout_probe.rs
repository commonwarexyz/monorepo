//! `heldout_probe <root.rs> <prefix>...`: the reader and exec-only steps of
//! the held-out set H2's probe (`sandblaster/bench/heldout/h2/RULE.md` §5,
//! steps 3 and 4). For each DSL root it runs `driver::check` (the lift and
//! the MIR reading), then `elab::elaborate` with `exec_only` (no laws, as
//! `tests/opt_qmdb.rs` and `driver::stage::lower_in_place` run it), and
//! prints one JSON object: whether the front end accepted the root, its
//! first error diagnostics, and the status of every definition whose kernel
//! name is one of the prefixes or extends one by `__` or `::`.
//!
//! It stops before the optimizer: `opt::optimize` is never called, so the
//! sampling sees no optimizer output (the fairness audit's protocol, item 3).

use std::path::Path;
use std::process::ExitCode;

use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn main() -> ExitCode {
    sandblaster_front::memguard::init_from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: heldout_probe <root.rs> <kernel-name prefix>...");
        return ExitCode::from(2);
    }
    let root = &args[0];
    let prefixes = &args[1..];
    let c = driver::check(Path::new(root), &RealFs, &TargetInfo::aarch64_apple_darwin());
    if !c.ok() {
        let first: String = c.diags.list.iter().filter(|d| d.severity == sandblaster_front::diag::Severity::Error).take(8).map(|d| d.render(&c.sm)).collect::<Vec<_>>().join("\n");
        println!("{{\"root\":{},\"front_end\":false,\"errors\":{},\"defs\":[]}}", esc(root), esc(&first));
        return ExitCode::SUCCESS;
    }
    let k = c.krate.as_ref().expect("checked crate");
    let defs = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let errors: Vec<String> = out.diags.list.iter().filter(|d| d.severity == sandblaster_front::diag::Severity::Error).take(8).map(|d| d.render(&c.sm)).collect();
        let defs: Vec<(String, String)> = out
            .defs
            .iter()
            .filter(|d| prefixes.iter().any(|p| d.name == *p || d.name.starts_with(&format!("{p}__")) || d.name.starts_with(&format!("{p}::"))))
            .map(|d| (d.name.clone(), format!("{:?}", d.status)))
            .collect();
        let all: Vec<String> = out.defs.iter().map(|d| d.name.clone()).collect();
        (errors, defs, all)
    });
    let (errors, defs, all) = defs;
    let defs_json: Vec<String> = defs.iter().map(|(n, s)| format!("{{\"name\":{},\"status\":{}}}", esc(n), esc(s))).collect();
    let all_json: Vec<String> = all.iter().map(|n| esc(n)).collect();
    println!("{{\"root\":{},\"front_end\":true,\"errors\":{},\"defs\":[{}],\"all_defs\":[{}]}}", esc(root), esc(&errors.join("\n")), defs_json.join(","), all_json.join(","));
    ExitCode::SUCCESS
}
