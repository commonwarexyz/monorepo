use commonware_consensus_fuzz::tracing::static_honest::{
    generate_small_honest_traces, write_small_honest_traces, SmallHonestTraceConfig,
};
use std::{env, path::PathBuf, process};

fn usage() -> ! {
    eprintln!(
        "Usage: generate_small_honest_traces <output_dir> [--max-views N] [--max-containers N]"
    );
    process::exit(1);
}

fn main() {
    let mut output_dir: Option<PathBuf> = None;
    let mut cfg = SmallHonestTraceConfig::default();

    let args: Vec<String> = env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--max-views" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    usage();
                };
                cfg.max_views = value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --max-views value: {value}");
                    process::exit(1);
                });
            }
            "--max-containers" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    usage();
                };
                cfg.max_containers = value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --max-containers value: {value}");
                    process::exit(1);
                });
            }
            arg if output_dir.is_none() => {
                output_dir = Some(PathBuf::from(arg));
            }
            _ => usage(),
        }
        i += 1;
    }

    let Some(output_dir) = output_dir else {
        usage();
    };

    let traces = generate_small_honest_traces(cfg);
    let count = write_small_honest_traces(&traces, &output_dir).unwrap_or_else(|err| {
        eprintln!("failed to write traces to {}: {err}", output_dir.display());
        process::exit(1);
    });

    println!(
        "generated {} honest small-scope traces into {} (max_views={}, max_containers={}, epoch={})",
        count,
        output_dir.display(),
        cfg.max_views,
        cfg.max_containers,
        cfg.epoch,
    );
}
