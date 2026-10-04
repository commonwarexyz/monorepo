//! `heldout_eval <root.rs> <out_dir> <prefix>...`: the optimizer on one DSL
//! root of the held-out evaluation (`sandblaster/bench/heldout-harness`,
//! fairness audit plan step 8).
//!
//! It runs what `driver::stage::lower_in_place` runs, with the optimizer's
//! reports kept: `driver::check` (lift and MIR reading), `elab::elaborate`
//! with `exec_only` (no laws, as `tests/opt_qmdb.rs` runs it), the
//! always-on optimizer (`opt::optimize`) with
//! `OptOptions::exclude_user_rewrites` (the evaluation build: only the
//! optimizer's own output), and the in-place lowering with its lifted
//! round trip (`driver::lowered::lower_in_place`). It writes each lowered
//! copy to `<out_dir>/<file stem>.lowered.rs` (its leading `//!` lines,
//! then the lowered body: what rustc compiles where a host declares the
//! module by its lowered declaration) and prints one JSON object: the front
//! end's verdict, the status of every definition whose kernel name is one
//! of the prefixes or extends one by `__` or `::` (and the obligations of
//! those definitions that are not proven), the optimizer's report
//! for those functions (outcome, rung, link, every candidate with its
//! reason and cost) and every lowering record.
//!
//! Nothing here changes what the optimizer does: it is the production
//! optimizer and lowering, read out.

use std::path::Path;
use std::process::ExitCode;
use std::time::Instant;

use sandblaster_front::driver::{self, lowered::LowerOutcome};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::RealFs;
use sandblaster_front::opt::{self, OptOptions, Outcome};
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

fn opt_str(s: Option<String>) -> String {
    s.map(|s| esc(&s)).unwrap_or_else(|| "null".into())
}

fn main() -> ExitCode {
    sandblaster_front::memguard::init_from_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!("usage: heldout_eval <root.rs> <out_dir> <kernel-name prefix>...");
        return ExitCode::from(2);
    }
    let root = Path::new(&args[0]);
    let out_dir = Path::new(&args[1]);
    let prefixes = &args[2..];
    let wanted = |n: &str| prefixes.iter().any(|p| n == p || n.starts_with(&format!("{p}__")) || n.starts_with(&format!("{p}::")));
    let c = driver::check(root, &RealFs, &TargetInfo::aarch64_apple_darwin());
    if !c.ok() {
        let first: String = c.diags.list.iter().filter(|d| d.severity == sandblaster_front::diag::Severity::Error).take(8).map(|d| d.render(&c.sm)).collect::<Vec<_>>().join("\n");
        println!("{{\"root\":{},\"front_end\":false,\"errors\":{}}}", esc(&args[0]), esc(&first));
        return ExitCode::SUCCESS;
    }
    let k = c.krate.as_ref().expect("checked crate");
    let oopts = OptOptions { exclude_user_rewrites: true, ..Default::default() };
    let json = elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let errors: Vec<String> = out.diags.list.iter().filter(|d| d.severity == sandblaster_front::diag::Severity::Error).take(8).map(|d| d.render(&c.sm)).collect();
        let defs: Vec<String> = out.defs.iter().filter(|d| wanted(&d.name)).map(|d| format!("{{\"name\":{},\"status\":{}}}", esc(&d.name), esc(&format!("{:?}", d.status)))).collect();
        // the obligations of those definitions that are not proven (why a
        // definition is `Unproven`)
        let unproven: Vec<String> = out
            .obligations
            .iter()
            .filter(|ob| wanted(&ob.def) && !ob.proven())
            .take(24)
            .map(|ob| format!("{{\"def\":{},\"kind\":{},\"status\":{},\"goal\":{}}}", esc(&ob.def), esc(&format!("{:?}", ob.kind)), esc(&format!("{:?}", ob.status).chars().take(300).collect::<String>()), esc(&ob.goal.chars().take(400).collect::<String>())))
            .collect();
        let t = Instant::now();
        let o = opt::optimize(&mut out, k, &oopts);
        let opt_ms = t.elapsed().as_millis();
        let fns: Vec<String> = o
            .fns
            .iter()
            .filter(|f| wanted(&f.name))
            .map(|f| {
                let (outcome, reason, failure, nodes) = match &f.outcome {
                    Outcome::Specialized { nodes, .. } => ("Specialized", String::new(), false, *nodes),
                    Outcome::Unspecialized { reason, failure } => ("Unspecialized", reason.clone(), *failure, 0),
                };
                let cands: Vec<String> = f
                    .candidates
                    .iter()
                    .map(|cd| {
                        let cost: Vec<String> = cd.cost.iter().map(|(k, v)| format!("{}:{v}", esc(k))).collect();
                        format!("{{\"rung\":{},\"chosen\":{},\"reason\":{},\"rejected_by\":{},\"cost\":{{{}}}}}", esc(cd.rung.name()), cd.chosen, esc(&cd.reason), opt_str(cd.rejected_by.clone()), cost.join(","))
                    })
                    .collect();
                format!(
                    "{{\"name\":{},\"set\":{},\"outcome\":{},\"reason\":{},\"failure\":{},\"nodes\":{},\"rung\":{},\"link\":{},\"candidates\":[{}],\"loopsum_steps\":{},\"millis\":{}}}",
                    esc(&f.name),
                    opt_str(f.set.clone()),
                    esc(outcome),
                    esc(&reason),
                    failure,
                    nodes,
                    opt_str(f.rung.map(|r| r.name().to_string())),
                    opt_str(f.link.as_ref().map(|l| format!("{l:?}"))),
                    cands.join(","),
                    f.budgets_used.loopsum_steps,
                    f.millis
                )
            })
            .collect();
        // the panic-explicit readings (DESIGN.md §8.2 item 12) of the wanted
        // functions: the reading's name, or why there is none
        let panics: Vec<String> = o
            .panics
            .iter()
            .filter(|r| wanted(&k.item(r.source).path.to_string()))
            .map(|r| format!("{{\"source\":{},\"reading\":{},\"note\":{}}}", esc(&k.item(r.source).path.to_string()), opt_str(r.item.map(|i| o.print.item(i).path.to_string())), esc(&r.note)))
            .collect();
        let warnings: Vec<String> = o.warnings.iter().map(|w| esc(w)).collect();
        let opt_errors: Vec<String> = o.errors.iter().map(|e| esc(e)).collect();
        let t = Instant::now();
        let low = driver::lowered::lower_in_place(&c, root, &mut out, &o, &oopts);
        let low_ms = t.elapsed().as_millis();
        let mut mods = Vec::new();
        for m in &low {
            let stem = Path::new(&m.file).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "module".into());
            let dest = out_dir.join(format!("{stem}.lowered.rs"));
            if let Err(e) = std::fs::create_dir_all(out_dir).and_then(|_| std::fs::write(&dest, format!("{}{}", m.docs, m.body))) {
                eprintln!("cannot write {}: {e}", dest.display());
            }
            // the lifted round trip's copy (its MIR, extracted next to the
            // module's `.sbmir`, is what the round trip reads back) and that
            // MIR's path
            let (rt_copy, rt_mir) = match &m.roundtrip_copy {
                Some((flat, text)) => {
                    let p = out_dir.join(format!("{stem}.roundtrip__{flat}.rs"));
                    let _ = std::fs::write(&p, text);
                    let mir = c.lifted.iter().filter_map(|l| l.mir.as_ref()).find(|mir| c.lifted.iter().any(|l| l.in_place && !l.ghost && l.mir.as_ref() == Some(*mir))).map(|mir| {
                        let ms = mir.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                        mir.with_file_name(format!("{ms}.roundtrip__{flat}.sbmir")).display().to_string()
                    });
                    (Some(p.display().to_string()), mir)
                }
                None => (None, None),
            };
            let recs: Vec<String> = m
                .records
                .iter()
                .map(|r| match &r.outcome {
                    LowerOutcome::Lowered { origin, rung, cost_source, cost_residual, helpers, via } => format!(
                        "{{\"function\":{},\"lowered\":true,\"origin\":{},\"rung\":{},\"cost_source\":{cost_source},\"cost_residual\":{cost_residual},\"helpers\":{},\"via\":{}}}",
                        esc(&r.function),
                        esc(origin.name()),
                        esc(rung),
                        helpers.len(),
                        esc(via)
                    ),
                    LowerOutcome::Kept(why) => format!("{{\"function\":{},\"lowered\":false,\"reason\":{}}}", esc(&r.function), esc(why)),
                })
                .collect();
            mods.push(format!(
                "{{\"file\":{},\"written\":{},\"compared\":{},\"note\":{},\"user_rewrites_excluded\":{},\"roundtrip_copy\":{},\"roundtrip_mir\":{},\"records\":[{}]}}",
                esc(&m.file),
                esc(&dest.display().to_string()),
                m.compared,
                opt_str(m.note.clone()),
                m.user_rewrites_excluded,
                opt_str(rt_copy),
                opt_str(rt_mir),
                recs.join(",")
            ));
        }
        format!(
            "{{\"root\":{},\"front_end\":true,\"elab_errors\":{},\"defs\":[{}],\"unproven\":[{}],\"opt_ms\":{opt_ms},\"lowering_ms\":{low_ms},\"fns\":[{}],\"panics\":[{}],\"warnings\":[{}],\"opt_errors\":[{}],\"modules\":[{}]}}",
            esc(&args[0]),
            esc(&errors.join("\n")),
            defs.join(","),
            unproven.join(","),
            fns.join(","),
            panics.join(","),
            warnings.join(","),
            opt_errors.join(","),
            mods.join(",")
        )
    });
    println!("{json}");
    ExitCode::SUCCESS
}
