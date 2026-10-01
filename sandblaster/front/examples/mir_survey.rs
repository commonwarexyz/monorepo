//! `mir_survey <file.sbmir> <module-suffix> [sealed,..] [Trait=path::Instance,..]`: reads every root function of
//! an extraction with the MIR reader (parameters named as rustc names them,
//! `&mut` parameters as states) and prints, per function, `ok` or the first
//! construct the reader refuses — a development tool to see what a new
//! crate needs from the reader (`docs/mir-lift.md` §20). The sources the
//! extraction names are read relative to `SBMIR_CRATE_DIR`.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use sandblaster_front::mir::ir::Ty;
use sandblaster_front::mir::read::{self, Spec};
use sandblaster_front::mir::{self, ModuleNames};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let text = std::fs::read_to_string(&args[0]).expect("read .sbmir");
    let names = ModuleNames { module: String::new(), sealed: args.get(2).map(|s| s.split(',').map(str::to_string).collect()).unwrap_or_default(), host_enums: BTreeMap::new(), requires: BTreeSet::new(), open: args.get(3).map(|s| s.split(',').filter_map(|kv| kv.split_once('=')).map(|(a, b)| (a.to_string(), b.to_string())).collect()).unwrap_or_default(), dsl_modules: vec![], current: Default::default(), consts: BTreeMap::new(), invariant_types: BTreeSet::new(), host: Default::default() };
    // the sources the extraction names, relative to the crate directory
    // (`SBMIR_CRATE_DIR`, default: the current directory)
    let dir = std::path::PathBuf::from(std::env::var("SBMIR_CRATE_DIR").unwrap_or_else(|_| ".".into()));
    let l = match mir::load(&text, &|p| std::fs::read(dir.join(p)).ok(), names, &args[1]) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let (mut ok, mut bad) = (0, 0);
    let mut reasons: BTreeMap<String, usize> = BTreeMap::new();
    for key in &l.m.roots {
        let f = &l.m.fns[key];
        if !f.has_body {
            continue;
        }
        let params: Vec<String> = (1..=f.argc).map(|i| f.debug.iter().find(|(_, x)| *x == i).map(|(n, _)| n.clone()).unwrap_or_else(|| "_".into())).collect();
        let states: Vec<usize> = (0..f.argc).filter(|i| matches!(f.locals[i + 1].0, Ty::Ref(true, _))).collect();
        let has_ret = f.locals[0].0 != Ty::Unit;
        let spec = Spec { key, lifted_name: "f", params, states, has_ret, out_ty: syn::parse_quote!(()), loops: HashMap::new(), ref_params: vec![] };
        match read::read(&l.m, &l.names, &spec) {
            Ok(_) => {
                ok += 1;
                println!("ok    {key}");
            }
            Err(e) => {
                bad += 1;
                let short = e.split("): ").last().unwrap_or(&e).to_string();
                let short: String = short.chars().take(120).collect();
                *reasons.entry(short.clone()).or_default() += 1;
                println!("REFUSED {key}\n        {short}");
            }
        }
    }
    println!("\n{ok} read, {bad} refused; reasons:");
    for (r, n) in reasons {
        println!("  {n:3} {r}");
    }
}
