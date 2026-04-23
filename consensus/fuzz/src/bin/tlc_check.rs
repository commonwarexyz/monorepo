//! Posts a single TraceData JSON file to the controlled TLC server and
//! prints the action list, the raw response, and the verdict (sent vs
//! accepted) so we can see whether `tlc2.TLCServer.simulate` silently
//! skipped any actions.
//!
//! Usage:
//!
//!   cargo run -p commonware-consensus-fuzz --bin tlc_check -- \
//!       consensus/fuzz/artifacts/mutated_traces/<sha1>.json
//!
//! By default, `tlc_check` spawns its own tlc-controlled server on a
//! random free port (via `consensus/quint/scripts/free_port.sh` and
//! `scripts/tlc.sh run`) and tears it down on exit. Set `TLC_URL` to
//! skip the spawn and target an existing server.
//!
//! Environment:
//!
//!   * `TLC_URL` - existing `/execute` endpoint to target; skips spawn
//!   * `TLC_STARTUP_SECS` - server readiness timeout, default `60`

use commonware_consensus_fuzz::{
    tlc::{verdict_for, ExecuteResponse, TlcMapper, TlcVerdict},
    tracing::data::TraceData,
};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{self, Child, Command, Stdio},
    time::{Duration, Instant},
};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: tlc_check <trace.json>");
        process::exit(2);
    }
    let path = PathBuf::from(&args[1]);

    // Resolve the target URL: either an externally-provided server via
    // TLC_URL, or spin up our own on a free port. The guard keeps the
    // spawned JVM alive for the duration of this process and kills it on
    // drop (normal exit or panic unwind).
    let (_server, url) = match env::var("TLC_URL") {
        Ok(url) => (None, url),
        Err(_) => match spawn_server() {
            Ok((guard, url)) => (Some(guard), url),
            Err(e) => {
                eprintln!("failed to start tlc server: {e}");
                process::exit(1);
            }
        },
    };

    let json = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("read {}: {e}", path.display());
            process::exit(1);
        }
    };
    let trace: TraceData = match serde_json::from_str(&json) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("parse {}: {e}", path.display());
            process::exit(1);
        }
    };

    let actions = TlcMapper::map_trace(&trace);
    println!("trace        : {}", path.display());
    println!("entries      : {}", trace.entries.len());
    println!("actions      : {}", actions.len());
    println!("--- action list ---");
    for (i, a) in actions.iter().enumerate() {
        println!("  [{i:>3}] {a}");
    }

    if actions.is_empty() {
        println!("(empty action list, nothing to send)");
        return;
    }

    let body = serde_json::to_string(&actions).expect("serialize actions");
    let http = reqwest::blocking::Client::new();
    let http_response = match http
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tlc execute failed: request error: {e}");
            process::exit(1);
        }
    };
    let status = http_response.status();
    let response_text = match http_response.text() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tlc execute failed: response read error: {e}");
            process::exit(1);
        }
    };
    if !status.is_success() {
        eprintln!("tlc execute failed: HTTP {status}");
        eprintln!("--- tlc error body ---");
        eprintln!("{response_text}");
        process::exit(1);
    }
    let response: ExecuteResponse = match serde_json::from_str(&response_text) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tlc execute failed: bad JSON response: {e}");
            eprintln!("--- raw body ---");
            eprintln!("{response_text}");
            process::exit(1);
        }
    };

    println!("--- tlc response ---");
    println!("keys ({}):", response.keys.len());
    for (i, k) in response.keys.iter().enumerate() {
        println!("  [{i:>3}] {k}");
    }
    println!("states ({}):", response.states.len());
    for (i, s) in response.states.iter().enumerate() {
        let one_line = s.replace('\n', " | ");
        println!("  [{i:>3}] {one_line}");
    }
    if let Some(mapped) = response.mapped {
        println!("mapped       : {mapped}");
    }
    if let Some(accepted) = response.accepted {
        println!("accepted     : {accepted}");
    }
    if let Some(skipped) = response.skipped {
        println!("skipped      : {skipped}");
    }

    let verdict = verdict_for(&actions, &response);
    println!("--- verdict ---");
    match verdict {
        TlcVerdict::Accepted => {
            println!("ACCEPTED: every action fired");
        }
        TlcVerdict::Rejected { sent, accepted } => {
            println!(
                "REJECTED: sent={sent} accepted={accepted} skipped={}",
                sent - accepted
            );
            process::exit(3);
        }
    }
}

/// RAII guard for the spawned `scripts/tlc.sh run` child. The script does
/// `cd $TLC_BUILD_DIR && exec java ...`, so the shell is replaced in place
/// by the JVM and `Child::kill()` sends SIGKILL straight to the JVM.
struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs `scripts/free_port.sh` to pick a port, then launches
/// `scripts/tlc.sh run` with `TLC_PORT` pointing at it, polls `/health`
/// until ready, and returns the guard plus the `/execute` URL.
fn spawn_server() -> Result<(ServerGuard, String), String> {
    let quint_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("fuzz crate has no parent")
        .join("quint");

    let port = read_port(&quint_dir)?;
    eprintln!("[tlc_check] spawning tlc-controlled on port {port}");

    let child = Command::new("./scripts/tlc.sh")
        .arg("run")
        .env("TLC_PORT", port.to_string())
        .current_dir(&quint_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn scripts/tlc.sh run: {e}"))?;
    let guard = ServerGuard { child };

    let wait_secs = env::var("TLC_STARTUP_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);
    wait_ready(port, Duration::from_secs(wait_secs))?;

    Ok((guard, format!("http://localhost:{port}/execute")))
}

fn read_port(quint_dir: &Path) -> Result<u16, String> {
    let output = Command::new("./scripts/free_port.sh")
        .current_dir(quint_dir)
        .output()
        .map_err(|e| format!("spawn scripts/free_port.sh: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "scripts/free_port.sh failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .trim()
        .parse::<u16>()
        .map_err(|e| format!("parse port from `{}`: {e}", stdout.trim()))
}

fn wait_ready(port: u16, timeout: Duration) -> Result<(), String> {
    let url = format!("http://localhost:{port}/health");
    let client = reqwest::blocking::Client::new();
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() > deadline {
            return Err(format!(
                "tlc-controlled on port {port} did not become ready within {timeout:?}"
            ));
        }
        let ready = client
            .get(&url)
            .timeout(Duration::from_secs(2))
            .send()
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if ready {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}
