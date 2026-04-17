//! Rust-side driver for the controlled TLC HTTP server.
//!
//! Reuses the canonical honest recording pipeline
//! ([`crate::tracing::record::run_honest_pipeline`]) to produce a
//! [`Trace`], encodes it into the JSON action sequence accepted by the Java
//! `SimplexActionMapper` via [`tlc_encoder::encode_from_trace`], and POSTs
//! it to the controlled `tlc2.TLCServer` `/execute` endpoint. The server
//! returns a list of state fingerprints (`keys`); we keep a global
//! cumulative set of fingerprints across calls and report whether the most
//! recent run added any new ones, so the libfuzzer target can
//! `Corpus::Reject` uninteresting inputs.
//!
//! Spec actions exposed by `main_n4f1b0.qnt` (and the compiled `main.tla`):
//!
//!   * `correct_replica_step(id)` — pulls the next event for `id` (one of
//!     the inner `on_*`/`on_timeout` alternatives, picked non-deterministically)
//!   * `propose(id, payload, parent_view)` — leader of `parent_view + 1`
//!     proposes `payload` (must be in `VALID_PAYLOADS`)
//!   * `byzantine_step` — only enabled when `BYZANTINE` is non-empty

use crate::{
    tracing::{record::run_honest_pipeline, tlc_encoder},
    FuzzInput,
};
use commonware_consensus::simplex::replay::Trace;
use libfuzzer_sys::Corpus;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    sync::{Mutex, OnceLock},
};

/// Default URL of the controlled TLC server.
pub const DEFAULT_TLC_URL: &str = "http://localhost:2023/execute";

/// Response payload from `tlc2.TLCServer` `/execute`.
///
/// `states[i]` and `keys[i]` are parallel arrays. `states[0]` / `keys[0]`
/// are always the (random) init state picked by `tlc2.TLCServer.randomState`;
/// the rest are the trajectory after running each accepted action.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct ExecuteResponse {
    pub states: Vec<String>,
    pub keys: Vec<i64>,
    #[serde(default)]
    pub mapped: Option<usize>,
    #[serde(default)]
    pub accepted: Option<usize>,
    #[serde(default)]
    pub skipped: Option<usize>,
}

/// Blocking HTTP client for the controlled TLC server.
pub struct TlcClient {
    client: reqwest::blocking::Client,
    url: String,
}

impl TlcClient {
    pub fn new(url: &str) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            url: url.to_string(),
        }
    }

    /// Posts the action list to `/execute` and returns the fingerprints
    /// (state keys) reported by the server.
    pub fn execute(&self, actions: &[Value]) -> Result<Vec<i64>, reqwest::Error> {
        self.execute_full(actions).map(|r| r.keys)
    }

    /// Posts the action list to `/execute` and returns the full server
    /// response, including both the human-readable `states[i]` strings and
    /// the parallel `keys[i]` fingerprint list. Callers that need the
    /// rejection signal must use this (see [`accepted_action_count`]).
    pub fn execute_full(&self, actions: &[Value]) -> Result<ExecuteResponse, reqwest::Error> {
        let body = serde_json::to_string(actions).expect("serialize actions");
        let response: ExecuteResponse = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()?
            .error_for_status()?
            .json()?;
        Ok(response)
    }
}

/// Returns the number of non-reset actions in `actions`.
///
/// `tlc2.TLCServer.simulate` consumes one action per loop turn until it
/// hits a reset/quit/unknown marker. Counting non-reset actions gives the
/// number of actions the server *attempted* to fire.
pub fn non_reset_action_count(actions: &[Value]) -> usize {
    actions
        .iter()
        .filter(|a| {
            // The terminator appended in [`submit_trace`] is `{"reset": true}`.
            // Anything else (proposes, correct_replica_step, ...) is a real
            // action.
            !a.get("reset").and_then(|v| v.as_bool()).unwrap_or(false)
        })
        .count()
}

/// Returns the number of actions that actually fired in a server response.
///
/// Newer `tlc-controlled` builds return an explicit `accepted` count
/// from `simulate`, which is the correct value to use. When talking to
/// an older server, fall back to the historical `keys.len() - 1`
/// heuristic.
pub fn accepted_action_count(response: &ExecuteResponse) -> usize {
    response
        .accepted
        .unwrap_or_else(|| response.keys.len().saturating_sub(1))
}

/// Combined verdict for a `/execute` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlcVerdict {
    /// Every non-reset action sent to TLC fired.
    Accepted,
    /// At least one action was silently skipped by `simulate()`.
    Rejected {
        /// Number of non-reset actions sent.
        sent: usize,
        /// Number of actions that actually fired.
        accepted: usize,
    },
}

impl TlcVerdict {
    pub fn is_accepted(&self) -> bool {
        matches!(self, TlcVerdict::Accepted)
    }
}

/// Computes a [`TlcVerdict`] for a single `/execute` call.
pub fn verdict_for(actions: &[Value], response: &ExecuteResponse) -> TlcVerdict {
    let sent = non_reset_action_count(actions);
    let accepted = accepted_action_count(response);
    if accepted == sent {
        TlcVerdict::Accepted
    } else {
        TlcVerdict::Rejected { sent, accepted }
    }
}

/// Appends the `{"reset": true}` terminator the controlled TLC server's
/// `simulate(..., is_reset=true)` loop expects. Without it the server
/// calls `actionsToRun.remove()` on an empty queue, throws
/// NoSuchElementException, then NPEs in the catch block on
/// `e.getMessage()`, leaving the Rust client with only a transport
/// error ("error sending request"). Every caller that POSTs an action
/// list to `/execute` must call this (or push the terminator itself).
pub fn terminate_actions(actions: &mut Vec<Value>) {
    actions.push(json!({ "reset": true }));
}

/// Cumulative set of state fingerprints observed across all fuzz inputs in a
/// single libfuzzer process. Used as the coverage signal: a fuzz input is
/// `Keep` iff its TLC trace contributes at least one new fingerprint.
fn global_fingerprints() -> &'static Mutex<HashSet<i64>> {
    static GLOBAL: OnceLock<Mutex<HashSet<i64>>> = OnceLock::new();
    GLOBAL.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Outcome of feeding a trace to the controlled TLC server.
pub struct CoverageOutcome {
    /// Number of fingerprints returned by the server (after dedup).
    pub returned: usize,
    /// How many of those fingerprints were not previously seen.
    pub new_count: usize,
    /// Total cumulative coverage after merging this run.
    pub total: usize,
}

impl CoverageOutcome {
    pub fn is_interesting(&self) -> bool {
        self.new_count > 0
    }
}

/// Encodes the trace as TLC actions, posts the result to the controlled
/// TLC server, and merges the returned fingerprints into the global
/// coverage set. Returns the per-input outcome so the fuzz target can
/// decide whether to keep or reject the input.
pub fn submit_trace(client: &TlcClient, trace: &Trace) -> Result<CoverageOutcome, String> {
    let mut actions = tlc_encoder::encode_from_trace(trace);
    if actions.is_empty() {
        return Ok(CoverageOutcome {
            returned: 0,
            new_count: 0,
            total: global_fingerprints().lock().unwrap().len(),
        });
    }

    terminate_actions(&mut actions);

    let keys = client
        .execute(&actions)
        .map_err(|e| format!("tlc execute failed: {e}"))?;

    let mut set = global_fingerprints().lock().unwrap();
    let before = set.len();
    for k in &keys {
        set.insert(*k);
    }
    Ok(CoverageOutcome {
        returned: keys.len(),
        new_count: set.len() - before,
        total: set.len(),
    })
}

/// Full honest fuzz workflow with TLC coverage feedback:
///
///   1. Run the deterministic 4-node honest pipeline (same as the
///      `simplex_ed25519_quint_honest` target) and collect a canonical
///      [`Trace`].
///   2. Encode the resulting [`Trace`] into TLC actions via
///      [`tlc_encoder::encode_from_trace`].
///   3. POST the actions to the controlled `tlc2.TLCServer` `/execute`
///      endpoint and merge the returned state fingerprints into the global
///      cumulative coverage set.
///   4. Return [`Corpus::Reject`] **only** when TLC explicitly reports zero
///      new state fingerprints; every other outcome (pipeline failure,
///      empty trace, server unreachable, JSON error, ...) falls through to
///      [`Corpus::Keep`]. Coverage feedback from TLC is the *only* reason
///      to drop an input from the corpus.
///
/// The TLC server URL is read from the `TLC_URL` environment variable,
/// defaulting to [`DEFAULT_TLC_URL`].
pub fn run_quint_tlc_honest_model(input: FuzzInput, _corpus_bytes: &[u8]) -> Corpus {
    let Some(trace) = run_honest_pipeline(input) else {
        return Corpus::Keep;
    };

    let url = std::env::var("TLC_URL").unwrap_or_else(|_| DEFAULT_TLC_URL.to_string());
    let client = tlc_client(&url);

    match submit_trace(client, &trace) {
        Ok(outcome) if outcome.is_interesting() => Corpus::Keep,
        // The only path that drops an input from the corpus: TLC ran the
        // trace and reported no new fingerprints.
        Ok(_) => Corpus::Reject,
        Err(err) => {
            eprintln!("[tlc] {err}");
            Corpus::Keep
        }
    }
}

/// Returns a process-wide [`TlcClient`] keyed on the URL it was first
/// constructed for. Reusing the client lets `reqwest` reuse the underlying
/// HTTP connection across fuzz iterations.
fn tlc_client(url: &str) -> &'static TlcClient {
    static CLIENT: OnceLock<TlcClient> = OnceLock::new();
    CLIENT.get_or_init(|| TlcClient::new(url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    /// Finds a free high-numbered TCP port by binding to port 0.
    fn find_free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("failed to bind ephemeral port")
            .local_addr()
            .expect("failed to get local addr")
            .port()
    }

    fn fuzz_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn quint_dir() -> PathBuf {
        fuzz_dir().parent().unwrap().join("quint")
    }

    /// RAII guard that kills the spawned `tlc-controlled` server on drop so
    /// the test does not leave a stale JVM. We do not call
    /// `./scripts/tlc.sh kill`, which would `pkill` *every* tlc2.TLCServer
    /// process and clobber a fuzzer that may be running on a different port.
    struct TlcServerGuard {
        child: Child,
    }

    impl Drop for TlcServerGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn require_jar() {
        let jar = quint_dir().join("tlc-controlled/dist/tla2tools_server.jar");
        assert!(
            jar.exists(),
            "missing TLC jar at {}; build it with:\n  (cd {} && ant -f customBuild.xml compile && ant -f customBuild.xml dist)",
            jar.display(),
            quint_dir().join("tlc-controlled").display(),
        );
    }

    fn tla_build_dir() -> PathBuf {
        quint_dir().join("tla-build")
    }

    /// Asserts the manually-built `tla-build/main.tla` is in place. Unlike
    /// `ensure_compiled` (which builds the legacy `main_n4f1b0.qnt` via
    /// `scripts/tlc.sh compile`), the refactored `replica_tla.qnt` spec
    /// has no compile script yet, so this helper only checks for the file
    /// and prints a copy-pasteable build recipe on failure.
    fn require_tla_build() {
        let main_tla = tla_build_dir().join("main.tla");
        assert!(
            main_tla.exists(),
            "missing {}; build it with:\n  \
             cd {} && quint compile main_n4f1b0_tla.qnt --target=tlaplus 2>/dev/null \
             | awk '/^---/{{found=1}} found' > tla-build/main.tla\n  \
             then copy Apalache.tla and Variants.tla into tla-build/ from\n  \
             ~/.quint/apalache-dist-*/apalache/lib/apalache.jar (tla2sany/StandardModules/).",
            main_tla.display(),
            quint_dir().display(),
        );
        for std_mod in ["Apalache.tla", "Variants.tla"] {
            let p = tla_build_dir().join(std_mod);
            assert!(
                p.exists(),
                "missing {} (extract it from the apalache jar's StandardModules dir)",
                p.display(),
            );
        }
    }

    /// Returns the mtime of `path`, or `None` if the file does not exist.
    fn mtime(path: &std::path::Path) -> Option<std::time::SystemTime> {
        std::fs::metadata(path).and_then(|m| m.modified()).ok()
    }

    /// Returns true if any source mtime is strictly newer than `target`'s
    /// mtime, or if `target` does not exist.
    fn any_newer(target: &std::path::Path, sources: &[PathBuf]) -> bool {
        let Some(target_mtime) = mtime(target) else {
            return true;
        };
        sources
            .iter()
            .any(|src| mtime(src).map(|t| t > target_mtime).unwrap_or(false))
    }

    /// Rebuilds `tla-build/main.tla` via `quint compile` if any of the
    /// `.qnt` sources that feed into it are newer than the compiled file.
    /// Avoids the recurring footgun of editing `replica_tla.qnt` and
    /// forgetting to recompile before running the test.
    fn ensure_tla_build_fresh() {
        let main_tla = tla_build_dir().join("main.tla");
        let sources: Vec<PathBuf> = [
            "main_n4f1b0_tla.qnt",
            "replica_tla.qnt",
            "types.qnt",
            "defs.qnt",
            "option.qnt",
        ]
        .iter()
        .map(|n| quint_dir().join(n))
        .collect();
        if !any_newer(&main_tla, &sources) {
            return;
        }
        eprintln!("[tlc] rebuilding {} via quint compile", main_tla.display());
        let output = Command::new("sh")
            .arg("-c")
            .arg(
                "quint compile main_n4f1b0_tla.qnt --target=tlaplus 2>/dev/null \
                 | awk '/^---- MODULE/{p=1} p'",
            )
            .current_dir(quint_dir())
            .output()
            .expect("failed to run quint compile");
        assert!(
            output.status.success() && !output.stdout.is_empty(),
            "quint compile main_n4f1b0_tla.qnt failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        std::fs::write(&main_tla, &output.stdout).expect("write main.tla");
    }

    /// Rebuilds `tlc-controlled/dist/tla2tools_server.jar` via
    /// `ant compile && ant dist` if any `.java` source under
    /// `tlc-controlled/src/` is newer than the jar. `ant dist` alone does
    /// NOT recompile sources, so we always run `compile` first.
    fn ensure_jar_fresh() {
        let jar = quint_dir().join("tlc-controlled/dist/tla2tools_server.jar");
        let src_root = quint_dir().join("tlc-controlled/src");
        let sources = collect_java_sources(&src_root);
        if !any_newer(&jar, &sources) {
            return;
        }
        eprintln!("[tlc] rebuilding {} via ant", jar.display());
        for target in ["compile", "dist"] {
            let status = Command::new("ant")
                .args(["-f", "customBuild.xml", target])
                .current_dir(quint_dir().join("tlc-controlled"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("failed to run ant");
            assert!(status.success(), "ant {target} failed");
        }
    }

    /// Recursively collects every `.java` file under `root`. Used by
    /// [`ensure_jar_fresh`] so that edits to any TLC source (not just
    /// `SimplexActionMapper.java`) trigger a rebuild.
    fn collect_java_sources(root: &std::path::Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|s| s.to_str()) == Some("java") {
                    out.push(path);
                }
            }
        }
        out
    }

    /// Spawns a tlc-controlled server against `tla-build/main.tla` (the
    /// hand-built artifact for the refactored `replica_tla.qnt` spec).
    /// Bypasses `scripts/tlc.sh run`, which targets `tlc-build/` and the
    /// legacy spec layout.
    fn start_server_for_tla_build(port: u16) -> TlcServerGuard {
        ensure_tla_build_fresh();
        ensure_jar_fresh();
        let jar = quint_dir().join("tlc-controlled/dist/tla2tools_server.jar");
        let build = tla_build_dir();
        // Forward the JVM's stderr to the test harness so any Java
        // exception thrown inside `/execute` is visible (the /execute
        // handler writes stack traces to stderr). stdout is suppressed
        // because TLC's parser, semantic processor, and TLCServer.main
        // print noisy progress messages there that drown out the test
        // output. Without forwarding *something*, an exception that
        // aborts the HTTP response would surface in Rust as an opaque
        // `IncompleteMessage` with no signal about the root cause.
        let child = Command::new("java")
            .args([
                "-ea",
                // Quint compiles variant matches and sequences of
                // let-bindings into deeply nested TLA+ LET-INs, and TLC's
                // evaluator recurses into them with one JVM frame per
                // sub-expression. The default 512 KiB thread stack
                // overflows part-way through the trace; 64 MiB is plenty.
                "-Xss64m",
                "-cp",
                jar.to_str().expect("jar path utf-8"),
                "tlc2.TLCServer",
                "-mapperparams",
                &format!("name=simplex;port={port}"),
                "main.tla",
                "-config",
                "main.cfg",
            ])
            .current_dir(&build)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to spawn TLC server JVM");
        let guard = TlcServerGuard { child };

        // Poll /health until the JVM finishes parsing the spec.
        let url = format!("http://localhost:{port}/health");
        let client = reqwest::blocking::Client::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if Instant::now() > deadline {
                panic!("TLC server on port {port} did not become ready within 60s");
            }
            let ready = client
                .get(&url)
                .timeout(Duration::from_secs(2))
                .send()
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ready {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        guard
    }

    /// Sanity check: drives the controlled TLC server through the full
    /// `propose -> notarize quorum -> notarization broadcast -> finalize
    /// quorum -> finalization broadcast` happy path against the refactored
    /// `replica_tla.qnt` spec, using the JSON action shapes accepted by the
    /// current `SimplexActionMapper`.
    ///
    /// With the static round-robin leader schedule
    /// (`leader(v) = participants[(epoch + v) % n]`, epoch=0, n=4) the
    /// leader of view 1 is `n1`. The trace:
    ///
    ///   1. `propose(n1, val_b0, parent=0)` -- leader broadcasts and
    ///      auto-stores its own notarize vote.
    ///   2. Three peers (`n0, n2, n3`) deliver `n1`'s notarize vote so
    ///      every replica has at least one stored vote.
    ///   3. `n1` then receives notarize votes from `n0` and `n2`, giving
    ///      it Q=3 votes total -> notarization certificate -> finalize
    ///      vote broadcast (and self-stored).
    ///   4. `n1` delivers its own finalize vote.
    ///   5. `on_certificate` for the three peers -- each absorbs `n1`'s
    ///      notarization (the only cert in `sent_certificates` at this
    ///      point) and, via `notarize_effect`, broadcasts and self-stores
    ///      its own finalize vote. After this step
    ///      `sent_finalize_votes` contains finalize votes signed by every
    ///      replica.
    ///   6. `n1` then receives finalize votes from `n0` and `n2`, giving
    ///      it Q=3 stored finalize votes -> finalization certificate
    ///      broadcast.
    ///   7. `on_certificate` for the three peers -- each absorbs the
    ///      finalization certificate. (At this point `sent_certificates`
    ///      contains both the notarization and the finalization; TLC
    ///      picks one binding nondeterministically. The notarization is
    ///      already stored at every node so it would be a no-op duplicate;
    ///      the finalization completes the path. Either way the action
    ///      fires, which is what the verdict checks.)
    ///
    /// Every action must fire ([`TlcVerdict::Accepted`]). If any single
    /// step is silently dropped the test fails, which would indicate the
    /// spec preconditions, the action mapper, or the trace itself drifted.
    ///
    /// Run with:
    ///
    ///   cargo test -p commonware-consensus-fuzz --lib \
    ///       tlc::tests::test_finalize_path_sanity -- --nocapture
    #[test]
    fn test_finalize_path_sanity() {
        require_jar();
        require_tla_build();

        let port = find_free_port();
        let _server = start_server_for_tla_build(port);
        let url = format!("http://localhost:{port}/execute");
        let client = TlcClient::new(&url);

        let trace: Vec<Value> = vec![
            // 1. Leader of view 1 (n1) proposes.
            json!({
                "name": "propose",
                "params": { "id": "n1", "payload": "val_b0", "parent": 0 },
            }),
            // 2. Cross-deliver n1's notarize vote to the three peers.
            json!({
                "name": "on_notarize",
                "params": { "id": "n0", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n1" },
            }),
            json!({
                "name": "on_notarize",
                "params": { "id": "n2", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n1" },
            }),
            // 3. n1 receives two peer notarize votes -> Q=3 -> notarization
            //    cert -> finalize vote broadcast.
            json!({
                "name": "on_notarize",
                "params": { "id": "n1", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n0" },
            }),
            json!({
                "name": "on_notarize",
                "params": { "id": "n1", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n2" },
            }),
            // 4. n0 receives two peer notarize vote -> Q=3 -> notarization
            //    cert -> finalize vote broadcast.
            json!({
                "name": "on_notarize",
                "params": { "id": "n0", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n2" },
            }),
            // 5. n2 receives peer notarize votes -> Q=3 -> notarization
            //    cert -> finalize vote broadcast.
            json!({
                "name": "on_notarize",
                "params": { "id": "n2", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n0" },
            }),
            // 5. The three peers absorb the notarization broadcast from
            //    n1 (ghost_sender = "n1"). Each peer's on_certificate
            //    handler triggers notarize_effect, which broadcasts and
            //    self-stores a finalize vote. n1's own finalize vote is
            //    already auto-stored by notarize_effect when it reached
            //    Q on notarize votes above, so no explicit on_finalize
            //    for n1 sig=n1 is needed.
            json!({
                "name": "on_certificate",
                "params": {
                    "id": "n0",
                    "type": "notarization",
                    "proposal": { "view": 1, "parent": 0, "payload": "val_b0" },
                    "signatures": ["n0", "n1", "n2"],
                    "ghost_sender": "n1",
                },
            }),
            json!({
                "name": "on_finalize",
                "params": { "id": "n2", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n0" },
            }),
            json!({
                "name": "on_finalize",
                "params": { "id": "n2", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n1" },
            }),
            json!({
                "name": "on_finalize",
                "params": { "id": "n0", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n2" },
            }),
            json!({
                "name": "on_finalize",
                "params": { "id": "n0", "view": 1, "parent": 0, "payload": "val_b0", "sig": "n1" },
            }),
            json!({
                "name": "on_certificate",
                "params": {
                    "id": "n3",
                    "type": "finalization",
                    "proposal": { "view": 1, "parent": 0, "payload": "val_b0" },
                    "signatures": ["n0", "n1", "n2"],
                    "ghost_sender": "n2",
                },
            }),
            // 2. Leader of view 2 (n2) proposes.
            json!({
                "name": "propose",
                "params": { "id": "n2", "payload": "val_b1", "parent": 1 },
            }),
            // All other nodes inject nullify votes for view 2.
            json!({
                "name": "send_nullify_vote",
                "params": { "view": 2, "sig": "n0" },
            }),
            json!({
                "name": "send_nullify_vote",
                "params": { "view": 2, "sig": "n1" },
            }),
            json!({
                "name": "send_nullify_vote",
                "params": { "view": 2, "sig": "n3" },
            }),
            json!({
                "name": "on_nullify",
                "params": { "id": "n1", "view": 2, "sig": "n0" },
            }),
            json!({
                "name": "on_nullify",
                "params": { "id": "n1", "view": 2, "sig": "n3" },
            }),
            json!({
                "name": "on_nullify",
                "params": { "id": "n0", "view": 2, "sig": "n1" },
            }),
            json!({
                "name": "on_nullify",
                "params": { "id": "n0", "view": 2, "sig": "n3" },
            }),
            json!({
                "name": "send_certificate",
                "params": {
                    "type": "nullification",
                    "view": 2,
                    "signatures": ["n0", "n1", "n3"],
                    "ghost_sender": "n1",
                },
            }),
            json!({
                "name": "on_certificate",
                "params": {
                    "id": "n2",
                    "type": "nullification",
                    "view": 2,
                    "signatures": ["n0", "n1", "n3"],
                    "ghost_sender": "n1",
                },
            }),
            json!({ "reset": true }),
        ];

        let response = client.execute_full(&trace).expect("execute");
        let verdict = verdict_for(&trace, &response);
        // `response.keys` is the parallel fingerprint trace (one per
        // visited state, including the init state at index 0). Count the
        // distinct fingerprints: that is the number of distinct states
        // the trace exercised, and `new_states` excludes the init state
        // so it reflects how many states the trace *discovered* on top
        // of the starting point.
        let distinct_states: std::collections::HashSet<_> =
            response.keys.iter().copied().collect();
        let new_states = distinct_states.len().saturating_sub(1);
        println!(
            "[finalize_path] sent={} accepted={} keys={} distinct={} new_states={} verdict={:?}",
            non_reset_action_count(&trace),
            accepted_action_count(&response),
            response.keys.len(),
            distinct_states.len(),
            new_states,
            verdict,
        );
        assert_eq!(
            verdict,
            TlcVerdict::Accepted,
            "every action of the propose -> notarize quorum -> notarization \
             broadcast -> finalize quorum -> finalization broadcast path must fire",
        );
    }
}
