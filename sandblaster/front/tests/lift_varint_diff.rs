//! Differential harness for a lifted crate (scratch tool, `#[ignore]`d):
//! elaborates the crate at `LIFT_DIFF_CRATE` once (ghost code included, so
//! attachments check), evaluates every call of `LIFT_DIFF_CASES` (lines
//! `fn<TAB>args-json[<TAB>..]`) with the kernel evaluator, and writes
//! `fn<TAB>args<TAB>result-or-error` lines to `LIFT_DIFF_OUT`. A line
//! `CHAIN <Decoder path><TAB>[bytes]` runs `new()` and then `feed` byte by
//! byte (threading the decoder state) until a value or an error, and
//! prints the list of `feed` results. A line `ITER <ctor path><TAB><next
//! path><TAB>[args]` builds an iterator with the constructor and calls the
//! state-passing `next` until it returns `None` (at most 128 times),
//! printing the list of items.

use std::io::Write;
use std::path::Path;

use sandblaster_front::driver::{self, ProverSet, VerifyOptions};
use sandblaster_front::elab::value::J;
use sandblaster_front::loader::RealFs;
use sandblaster_front::target::TargetInfo;

#[test]
#[ignore]
fn lift_diff() {
    let root = std::env::var("LIFT_DIFF_CRATE").expect("LIFT_DIFF_CRATE");
    let cases = std::fs::read_to_string(std::env::var("LIFT_DIFF_CASES").expect("LIFT_DIFF_CASES")).unwrap();
    let out_path = std::env::var("LIFT_DIFF_OUT").expect("LIFT_DIFF_OUT");
    let c = driver::check(Path::new(&root), &RealFs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let lines: Vec<(String, String)> = cases.lines().filter(|l| !l.is_empty()).map(|l| {
        let (f, a) = l.rsplit_once('\t').unwrap();
        (f.to_string(), a.to_string())
    }).collect();
    let t0 = std::time::Instant::now();
    let results = driver::stage::with_elaboration(k, &opts, |out| {
        let t1 = std::time::Instant::now();
        let chain = |d: &str, a: &str| -> Result<String, String> {
            let J::Arr(bytes) = J::parse(a)? else { return Err("bytes".into()) };
            let mut state = driver::stage::eval_in(out, k, &format!("{d}::new"), "[]")?;
            let mut steps = Vec::new();
            for b in bytes {
                let r = driver::stage::eval_in(out, k, &format!("{d}::feed"), &format!("[{state},{}]", b.render()))?;
                let J::Arr(pair) = J::parse(&r)? else { return Err("feed result".into()) };
                state = pair[0].render();
                let res = pair[1].render();
                let done = res != "{\"Ok\":[null]}";
                steps.push(res);
                if done {
                    break;
                }
            }
            Ok(format!("[{}]", steps.join(",")))
        };
        let iter = |spec: &str, a: &str| -> Result<String, String> {
            let (ctor, next) = spec.split_once('\t').ok_or("ITER needs a constructor and a next function")?;
            let mut state = driver::stage::eval_in(out, k, ctor, a)?;
            let mut items = Vec::new();
            for _ in 0..128 {
                let r = driver::stage::eval_in(out, k, next, &format!("[{state}]"))?;
                let J::Arr(pair) = J::parse(&r)? else { return Err("next result".into()) };
                state = pair[0].render();
                let item = pair[1].render();
                if item == "null" {
                    return Ok(format!("[{}]", items.join(",")));
                }
                items.push(item);
            }
            Err("more than 128 items".into())
        };
        // time per function (the first tab-separated field)
        let mut per: std::collections::BTreeMap<String, (usize, std::time::Duration)> = std::collections::BTreeMap::new();
        let r: Vec<String> = lines.iter().map(|(f, a)| {
            let t = std::time::Instant::now();
            let v = if let Some(d) = f.strip_prefix("CHAIN ") {
                chain(d, a)
            } else if let Some(s) = f.strip_prefix("ITER ") {
                iter(s, a)
            } else {
                driver::stage::eval_in(out, k, f, a)
            };
            let e = per.entry(f.split('\t').next().unwrap_or("").to_string()).or_default();
            e.0 += 1;
            e.1 += t.elapsed();
            v.unwrap_or_else(|e| format!("ERROR {e}"))
        }).collect();
        eprintln!("eval of {} calls: {:?}", lines.len(), t1.elapsed());
        for (f, (n, d)) in &per {
            eprintln!("  {f}: {n} calls, {:?} per call", *d / (*n as u32).max(1));
        }
        r
    });
    eprintln!("total: {:?}", t0.elapsed());
    let mut f = std::fs::File::create(out_path).unwrap();
    for ((fname, a), r) in lines.iter().zip(results) {
        writeln!(f, "{fname}\t{a}\t{r}").unwrap();
    }
}
