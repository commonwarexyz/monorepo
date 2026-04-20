//! Watches a trace artifact directory, submits new traces to the controlled TLC
//! server, and promotes the original libFuzzer input bytes when TLC reports new
//! state fingerprints.
//!
//! Usage:
//!
//!   cargo run -p commonware-consensus-fuzz --bin tlc_watch -- \
//!       consensus/fuzz/artifacts/traces/simplex_ed25519_quint_honest_smallscope \
//!       consensus/fuzz/corpus/simplex_ed25519_quint_honest_tlc \
//!       consensus/fuzz/artifacts/tlc_rejected/simplex_ed25519_quint_honest_smallscope
//!
//! Environment:
//!
//!   * `TLC_URL` - oracle endpoint, default `http://localhost:2023/execute`
//!   * `TLC_WATCH_INTERVAL_SECS` - polling interval, default `2`
//!   * `TLC_ONCE=1` - process currently available traces once and exit

use commonware_consensus_fuzz::{
    tlc::{non_reset_action_count, verdict_for, TlcClient, TlcMapper, TlcVerdict, DEFAULT_TLC_URL},
    tracing::data::TraceData,
};
use std::{
    collections::HashSet,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process, thread,
    time::Duration,
};

struct Config {
    trace_dir: PathBuf,
    approved_dir: PathBuf,
    rejected_dir: PathBuf,
    url: String,
    interval: Duration,
    once: bool,
}

fn main() {
    let config = match parse_config() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            process::exit(2);
        }
    };

    if let Err(err) = prepare_dirs(&config) {
        eprintln!("{err}");
        process::exit(1);
    }

    let keys_path = config.rejected_dir.join(".tlc_keys");
    let mut fingerprints = load_fingerprints(&keys_path);
    let client = TlcClient::new(&config.url);

    println!(
        "[tlc-watch] watching {}",
        config.trace_dir.as_path().display()
    );
    println!(
        "[tlc-watch] approved corpus {}",
        config.approved_dir.as_path().display()
    );
    println!(
        "[tlc-watch] state directory {}",
        config.rejected_dir.as_path().display()
    );
    println!("[tlc-watch] loaded {} TLC fingerprints", fingerprints.len());

    loop {
        match process_available(&config, &client, &keys_path, &mut fingerprints) {
            Ok(processed) => {
                if config.once {
                    println!("[tlc-watch] processed {processed} trace(s)");
                    break;
                }
            }
            Err(err) => {
                eprintln!("[tlc-watch] {err}");
                if config.once {
                    process::exit(1);
                }
            }
        }

        thread::sleep(config.interval);
    }
}

fn parse_config() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 && args.len() != 4 {
        return Err(format!(
            "Usage: {} <trace_dir> <approved_corpus_dir> [rejected_dir]",
            args.first().map(String::as_str).unwrap_or("tlc_watch")
        ));
    }

    let interval_secs = env::var("TLC_WATCH_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2);
    let rejected_dir = args
        .get(3)
        .map(PathBuf::from)
        .unwrap_or_else(|| default_state_dir(Path::new(&args[2])));

    Ok(Config {
        trace_dir: PathBuf::from(&args[1]),
        approved_dir: PathBuf::from(&args[2]),
        rejected_dir,
        url: env::var("TLC_URL").unwrap_or_else(|_| DEFAULT_TLC_URL.to_string()),
        interval: Duration::from_secs(interval_secs),
        once: matches!(env::var("TLC_ONCE").as_deref(), Ok("1" | "true")),
    })
}

fn default_state_dir(approved_dir: &Path) -> PathBuf {
    let name = approved_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("approved");
    approved_dir.with_file_name(format!("{name}_tlc_state"))
}

fn prepare_dirs(config: &Config) -> Result<(), String> {
    fs::create_dir_all(&config.trace_dir)
        .map_err(|e| format!("create trace dir {}: {e}", config.trace_dir.display()))?;
    fs::create_dir_all(&config.approved_dir)
        .map_err(|e| format!("create approved dir {}: {e}", config.approved_dir.display()))?;
    fs::create_dir_all(accepted_traces_dir(config)).map_err(|e| {
        format!(
            "create accepted trace dir {}: {e}",
            accepted_traces_dir(config).display()
        )
    })?;
    fs::create_dir_all(&config.rejected_dir)
        .map_err(|e| format!("create rejected dir {}: {e}", config.rejected_dir.display()))?;
    fs::create_dir_all(seen_dir(config))
        .map_err(|e| format!("create seen dir {}: {e}", seen_dir(config).display()))?;
    Ok(())
}

fn process_available(
    config: &Config,
    client: &TlcClient,
    keys_path: &Path,
    fingerprints: &mut HashSet<i64>,
) -> Result<usize, String> {
    let mut files = trace_files(&config.trace_dir)?;
    files.sort();

    let mut processed = 0;
    for path in files {
        let Some(hash) = trace_hash(&path) else {
            continue;
        };
        if seen_path(config, &hash).exists() {
            continue;
        }

        match process_trace(config, client, keys_path, fingerprints, &path, &hash) {
            Ok(()) => {
                processed += 1;
            }
            Err(err) => {
                eprintln!("[tlc-watch] {}: {err}", path.display());
            }
        }
    }

    Ok(processed)
}

fn process_trace(
    config: &Config,
    client: &TlcClient,
    keys_path: &Path,
    fingerprints: &mut HashSet<i64>,
    path: &Path,
    hash: &str,
) -> Result<(), String> {
    let json = fs::read_to_string(path).map_err(|e| format!("read trace: {e}"))?;
    let trace: TraceData =
        serde_json::from_str(&json).map_err(|e| format!("parse trace JSON: {e}"))?;
    let actions = TlcMapper::map_trace(&trace);
    let sent = non_reset_action_count(&actions);
    if actions.is_empty() {
        reject(config, hash, "empty action list")?;
        mark_seen(config, hash, "rejected: empty action list")?;
        println!("[tlc-watch] skip {hash}: empty action list");
        return Ok(());
    }

    let response = client
        .execute_full(&actions)
        .map_err(|e| format!("tlc execute failed: {e}"))?;
    match verdict_for(&actions, &response) {
        TlcVerdict::Accepted => {}
        TlcVerdict::Rejected { sent, accepted } => {
            let reason = format!("model rejected: sent={sent} accepted={accepted}");
            reject(config, hash, &reason)?;
            mark_seen(config, hash, &format!("rejected: {reason}"))?;
            println!("[tlc-watch] skip {hash}: {reason}");
            return Ok(());
        }
    }

    let mut seen_new_keys = HashSet::new();
    let new_keys: Vec<i64> = response
        .keys
        .iter()
        .copied()
        .filter(|key| !fingerprints.contains(key) && seen_new_keys.insert(*key))
        .collect();
    if new_keys.is_empty() {
        let reason = format!(
            "no new TLC states: actions={sent} keys={}",
            response.keys.len()
        );
        reject(config, hash, &reason)?;
        mark_seen(config, hash, &format!("rejected: {reason}"))?;
        println!("[tlc-watch] skip {hash}: {reason}");
        return Ok(());
    }

    let bytes_path = path.with_extension("bytes");
    let corpus_bytes = match fs::read(&bytes_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            let reason = format!("missing corpus bytes {}: {e}", bytes_path.display());
            reject(config, hash, &reason)?;
            mark_seen(config, hash, &format!("rejected: {reason}"))?;
            println!("[tlc-watch] skip {hash}: {reason}");
            return Ok(());
        }
    };
    let corpus_path = config.approved_dir.join(hash);
    fs::write(&corpus_path, &corpus_bytes)
        .map_err(|e| format!("write approved corpus {}: {e}", corpus_path.display()))?;
    let trace_copy_path = accepted_traces_dir(config).join(format!("{hash}.json"));
    fs::write(&trace_copy_path, json)
        .map_err(|e| format!("write approved trace {}: {e}", trace_copy_path.display()))?;

    for key in &new_keys {
        fingerprints.insert(*key);
    }
    append_fingerprints(keys_path, &new_keys)?;
    mark_seen(
        config,
        hash,
        &format!(
            "accepted: actions={sent} keys={} new={}",
            response.keys.len(),
            new_keys.len()
        ),
    )?;
    println!(
        "[tlc-watch] accept {hash}: actions={sent} keys={} new={} -> {}",
        response.keys.len(),
        new_keys.len(),
        corpus_path.display()
    );
    Ok(())
}

fn trace_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries =
        fs::read_dir(dir).map_err(|e| format!("read trace dir {}: {e}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read trace dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) == Some("json") {
            files.push(path);
        }
    }
    Ok(files)
}

fn trace_hash(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .map(str::to_string)
}

fn seen_dir(config: &Config) -> PathBuf {
    config.trace_dir.join(".tlc_seen")
}

fn seen_path(config: &Config, hash: &str) -> PathBuf {
    seen_dir(config).join(hash)
}

fn accepted_traces_dir(config: &Config) -> PathBuf {
    config.rejected_dir.join("accepted_traces")
}

fn mark_seen(config: &Config, hash: &str, status: &str) -> Result<(), String> {
    fs::write(seen_path(config, hash), status)
        .map_err(|e| format!("write seen marker for {hash}: {e}"))
}

fn reject(config: &Config, hash: &str, reason: &str) -> Result<(), String> {
    fs::write(config.rejected_dir.join(format!("{hash}.txt")), reason)
        .map_err(|e| format!("write rejection marker for {hash}: {e}"))
}

fn load_fingerprints(path: &Path) -> HashSet<i64> {
    let Ok(contents) = fs::read_to_string(path) else {
        return HashSet::new();
    };
    contents
        .lines()
        .filter_map(|line| line.trim().parse::<i64>().ok())
        .collect()
}

fn append_fingerprints(path: &Path, keys: &[i64]) -> Result<(), String> {
    if keys.is_empty() {
        return Ok(());
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("open fingerprint file {}: {e}", path.display()))?;
    for key in keys {
        writeln!(file, "{key}")
            .map_err(|e| format!("append fingerprint file {}: {e}", path.display()))?;
    }
    Ok(())
}
