//! Interactive Symbolic Testing (IST) for Simplex consensus.
//!
//! Uses Apalache's SMT solver to generate transitions on-the-fly, then
//! immediately replays each step's messages into Rust engines and compares
//! observable state after every transition.
//!
//! # Interactive Architecture
//!
//! A single loop alternates between:
//! 1. Driving Apalache to pick an enabled transition (blocking HTTP)
//! 2. Extracting new messages from the state diff
//! 3. Injecting messages into Rust engines
//! 4. Comparing observable state against Apalache's expected state
//!
//! Divergences are detected immediately at the step where they occur,
//! following the TFTP interactive testing pattern.
//!
//! Blocking HTTP inside the deterministic runtime is safe because:
//! - The runtime is single-threaded; blocking HTTP blocks the thread
//! - The event loop does not check liveness while a task is polled
//! - Engines are idle during HTTP calls (nothing to process)
//! - Between HTTP calls, `context.sleep()` yields to let engines process

use crate::{
    apalache::{ApalacheClient, TransitionStatus},
    config::ForwardingPolicy,
    invariants,
    replayer::{
        compare,
        injected::{self, NullBlocker, NullSender, PendingReceiver},
        messages,
    },
    tracing::{
        decoder::{
            collect_store_certificate, collect_store_vote, compute_epoch, count_nodes,
            diff_store_certificate, diff_store_vote, extract_expected_state, extract_leader_map,
            identify_correct_nodes,
        },
        sniffer::TraceEntry,
    },
};
use commonware_consensus::{
    simplex::{
        config,
        elector::RoundRobin,
        mocks::{application, relay, reporter},
        scheme::ed25519,
        Engine,
    },
    types::{Delta, Epoch as EpochType},
};
use commonware_cryptography::{
    certificate::mocks::Fixture, sha256::Sha256 as Sha256Hasher, Sha256,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Clock, Metrics, Runner};
use commonware_utils::{NZUsize, NZU16};
use serde_json::Value;
use std::{
    collections::HashMap,
    num::{NonZeroU16, NonZeroUsize},
    process::Command,
    sync::Arc,
    time::Duration,
};

const NAMESPACE: &[u8] = b"consensus_fuzz";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

/// Errors from IST execution.
#[derive(Debug)]
pub enum Error {
    Apalache(crate::apalache::Error),
    Quint(String),
    Setup(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Apalache(e) => write!(f, "apalache: {e}"),
            Error::Quint(e) => write!(f, "quint compile: {e}"),
            Error::Setup(e) => write!(f, "setup: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::apalache::Error> for Error {
    fn from(e: crate::apalache::Error) -> Self {
        Error::Apalache(e)
    }
}

/// Compiles a Quint spec to TLA+ using `quint compile --target tlaplus`.
pub fn compile_quint_to_tla(spec_path: &str, main: &str) -> Result<String, Error> {
    let output = Command::new("quint")
        .args(["compile", "--target", "tlaplus", "--main", main, spec_path])
        .output()
        .map_err(|e| Error::Quint(format!("failed to run quint: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Quint(format!(
            "quint compile failed ({}): {stderr}",
            output.status
        )));
    }

    let tla = String::from_utf8_lossy(&output.stdout).to_string();
    if tla.trim().is_empty() {
        return Err(Error::Quint("quint compile produced empty output".into()));
    }

    Ok(tla)
}

/// Configuration for an IST run.
pub struct IstConfig {
    /// Apalache server URL.
    pub apalache_url: String,
    /// Maximum number of steps to execute.
    pub max_steps: usize,
    /// Path to the Quint spec file.
    pub spec_path: String,
    /// Quint main module name.
    pub main_module: String,
    /// Number of steps between compaction calls (0 = no compaction).
    pub compact_every: usize,
    /// Path to a pre-compiled TLA+ file (skips quint compile).
    pub tla_path: Option<String>,
}

impl Default for IstConfig {
    fn default() -> Self {
        Self {
            apalache_url: "http://localhost:8822/rpc".to_string(),
            max_steps: 100,
            spec_path: String::new(),
            main_module: "itf_main".to_string(),
            compact_every: 20,
            tla_path: None,
        }
    }
}

/// Fix operator precedence issues in Quint-generated TLA+.
///
/// Two issues:
/// 1. Quint uses `:=` (Apalache assignment) which has lower precedence than `/\`,
///    causing `x' := a /\ y' := b` to mis-parse. Replace with `=` (precedence 5 > 3).
/// 2. `LET ... IN body` extends body to end of expression, capturing subsequent
///    `/\` conjuncts. Wrap LET expressions in parentheses when they appear as
///    the right-hand side of a primed variable assignment.
fn fix_tla_precedence(tla: &str) -> String {
    // Step 1: Replace := with = for standard operator precedence
    let tla = tla.replace(" := ", " = ");

    // Step 2: Parenthesize LET bodies in primed variable assignments.
    // Pattern: line ending with "'" followed by line starting with "= LET".
    // The LET body contains an EXCEPT block ([...]) whose closing "]" should
    // end the LET scope. We add "(" before LET and ")" after the closing "]".
    let lines: Vec<&str> = tla.lines().collect();
    let mut output: Vec<String> = Vec::with_capacity(lines.len());
    let mut need_close = false;
    let mut bracket_depth: i32 = 0;
    let mut saw_bracket = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if !need_close && trimmed.starts_with("= LET") && i > 0 {
            if lines[i - 1].trim().ends_with('\'') {
                let ws = &line[..line.len() - trimmed.len()];
                output.push(format!("{ws}= (LET{}", &trimmed["= LET".len()..]));
                need_close = true;
                bracket_depth = 0;
                saw_bracket = false;
                continue;
            }
        }

        if need_close {
            for ch in line.chars() {
                if ch == '[' {
                    bracket_depth += 1;
                    saw_bracket = true;
                }
                if ch == ']' {
                    bracket_depth -= 1;
                }
            }

            if saw_bracket && bracket_depth == 0 {
                output.push(format!("{line})"));
                need_close = false;
                continue;
            }
        }

        output.push(line.to_string());
    }

    output.join("\n")
}

/// Strip TLA+ module prefix from state variable names.
///
/// Quint's TLA+ output mangles variable names (e.g. `leader` -> `itf_main_r_leader`).
/// The decoder functions expect the original Quint names, so we strip the prefix.
fn normalize_state(state: &Value) -> Value {
    let Some(obj) = state.as_object() else {
        return state.clone();
    };
    let mut normalized = serde_json::Map::new();
    for (key, val) in obj {
        // Strip known prefixes: "itf_main_r_", or any "module_r_" pattern
        let short = key.find("_r_").map(|pos| &key[pos + 3..]).unwrap_or(key);
        normalized.insert(short.to_string(), val.clone());
    }
    Value::Object(normalized)
}

/// Extract the last state from an ITF trace returned by `query`.
fn last_state_from_trace(trace: &Value) -> Result<(Value, Value), Error> {
    let states = trace["states"]
        .as_array()
        .ok_or(Error::Setup("trace has no states array".into()))?;
    let state = states
        .last()
        .ok_or(Error::Setup("trace states array is empty".into()))?;
    Ok((state.clone(), normalize_state(state)))
}

/// Extract the last two states from an ITF trace.
///
/// Returns (prev_normalized, last_normalized). Both states come from
/// the same Z3 model, ensuring consistency for diffing.
fn last_two_states_from_trace(trace: &Value) -> Result<(Value, Value), Error> {
    let states = trace["states"]
        .as_array()
        .ok_or(Error::Setup("trace has no states array".into()))?;
    if states.len() < 2 {
        return Err(Error::Setup(
            "trace needs at least 2 states for diffing".into(),
        ));
    }
    let prev = normalize_state(&states[states.len() - 2]);
    let last = normalize_state(&states[states.len() - 1]);
    Ok((prev, last))
}

/// Gets the TLA+ source from config (pre-compiled file or quint compile).
fn get_tla_source(cfg: &IstConfig) -> Result<String, Error> {
    let tla_source = if let Some(tla_path) = &cfg.tla_path {
        println!("reading pre-compiled TLA+ from {tla_path}...");
        std::fs::read_to_string(tla_path)
            .map_err(|e| Error::Setup(format!("failed to read TLA+ file {tla_path}: {e}")))?
    } else {
        println!("compiling {} to TLA+...", cfg.spec_path);
        compile_quint_to_tla(&cfg.spec_path, &cfg.main_module)?
    };
    let tla_source = fix_tla_precedence(&tla_source);
    println!(
        "TLA+ source: {} bytes (after precedence fixup)",
        tla_source.len()
    );
    Ok(tla_source)
}

/// Injects a single trace entry into the appropriate engine channel.
fn inject_entry(
    entry: &TraceEntry,
    faults: usize,
    vote_injectors: &[injected::Injector],
    cert_injectors: &[injected::Injector],
    schemes: &[ed25519::Scheme],
    participants: &[commonware_cryptography::ed25519::PublicKey],
    epoch: u64,
) {
    // Skip self-votes
    if let TraceEntry::Vote {
        sender, receiver, ..
    } = entry
    {
        if sender == receiver {
            return;
        }
    }

    let receiver_id = match entry {
        TraceEntry::Vote { receiver, .. } => receiver,
        TraceEntry::Certificate { receiver, .. } => receiver,
    };

    let receiver_idx = receiver_id
        .strip_prefix('n')
        .and_then(|s| s.parse::<usize>().ok())
        .expect("invalid receiver id");

    // Skip entries for Byzantine nodes
    if receiver_idx < faults {
        return;
    }

    let correct_idx = receiver_idx - faults;

    let msg = messages::construct_message(entry, schemes, participants, epoch);

    if msg.is_certificate {
        cert_injectors[correct_idx].inject(msg.sender_pk, msg.payload);
    } else {
        vote_injectors[correct_idx].inject(msg.sender_pk, msg.payload);
    }
}

/// Runs an IST session as a single interactive loop.
///
/// Alternates between driving Apalache and comparing Rust engine state
/// at every step, detecting divergences immediately.
pub fn run_ist(cfg: &IstConfig) -> Result<IstReport, Error> {
    // --- Outside runtime: Apalache setup ---
    let tla_source = get_tla_source(cfg)?;

    let client = ApalacheClient::new(&cfg.apalache_url);
    client.health().map_err(|e| {
        Error::Setup(format!(
            "cannot reach Apalache at {}: {e}\n\
             Start it with: docker run --rm -p 8822:8822 \
             ghcr.io/apalache-mc/apalache:latest server --server-type=explorer",
            cfg.apalache_url
        ))
    })?;
    println!("connected to Apalache");

    use base64::{engine::general_purpose::STANDARD, Engine as B64Engine};
    let source_b64 = STANDARD.encode(&tla_source);

    let session = client.load_spec(&[source_b64], Some("init"), Some("step"), &[])?;
    println!(
        "loaded spec: session={}, init transitions={}, next transitions={}",
        session.id,
        session.init_transitions.len(),
        session.next_transitions.len()
    );

    // Initialize: assume init transition and advance
    let init_id = session
        .init_transitions
        .first()
        .ok_or(Error::Setup("no init transitions".into()))?
        .index;

    let assume_result = client.assume_transition(&session.id, init_id, true)?;
    if assume_result.status != TransitionStatus::Enabled {
        let _ = client.dispose_spec(&session.id);
        return Err(Error::Setup("init transition not enabled".into()));
    }
    let next_result = client.next_step(&session.id)?;
    println!("initialized: step={}", next_result.step_no);

    // Query the initial state
    let query_result = client.query(&session.id, &["TRACE"], None)?;
    let trace = query_result
        .trace
        .as_ref()
        .ok_or(Error::Setup("no trace from query".into()))?;
    let (_, init_state) = last_state_from_trace(trace)?;

    // Extract configuration from the initial state
    let correct_nodes = identify_correct_nodes(&init_state);
    let n = count_nodes(&init_state);
    let faults = n - correct_nodes.len();
    let leader_map = extract_leader_map(&init_state);
    let epoch = compute_epoch(&leader_map, n)
        .map_err(|e| Error::Setup(format!("epoch computation: {e}")))?;

    println!("config: n={n}, faults={faults}, epoch={epoch}, correct={correct_nodes:?}");

    // --- Inside runtime: interactive loop ---
    let executor = deterministic::Runner::timed(Duration::from_secs(600));
    let max_steps = cfg.max_steps;

    let report: Result<IstReport, Error> = executor.start(|mut context| async move {
        // Set up engines
        let Fixture {
            participants,
            schemes,
            verifier: _,
            ..
        } = ed25519::fixture(&mut context, NAMESPACE, n as u32);

        let correct_start = faults;
        let mut vote_injectors = Vec::new();
        let mut cert_injectors = Vec::new();
        let mut reporters = Vec::new();

        let relay_inst = Arc::new(relay::Relay::new());
        let elector = RoundRobin::<Sha256Hasher>::default();

        for i in correct_start..n {
            let ctx = context.with_label(&format!("validator_n{i}"));

            let (vote_inj, vote_rx) = injected::channel();
            vote_injectors.push(vote_inj);

            let (cert_inj, cert_rx) = injected::channel();
            cert_injectors.push(cert_inj);

            let resolver_rx = PendingReceiver;

            let reporter_cfg = reporter::Config {
                participants: participants
                    .as_slice()
                    .try_into()
                    .expect("public keys are unique"),
                scheme: schemes[i].clone(),
                elector: elector.clone(),
            };
            let reporter_inst =
                reporter::Reporter::new(ctx.with_label("reporter"), reporter_cfg);
            reporters.push(reporter_inst.clone());

            let app_cfg = application::Config {
                hasher: Sha256::default(),
                relay: relay_inst.clone(),
                me: participants[i].clone(),
                propose_latency: (1.0, 0.1),
                verify_latency: (1.0, 0.1),
                certify_latency: (1.0, 0.1),
                should_certify: application::Certifier::Always,
            };
            let (actor, application) =
                application::Application::new(ctx.with_label("application"), app_cfg);
            actor.start();

            // Use generous timeouts so engines do not fire spuriously
            let engine_cfg = config::Config {
                blocker: NullBlocker,
                scheme: schemes[i].clone(),
                elector: elector.clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: reporter_inst.clone(),
                partition: format!("ist_n{i}"),
                mailbox_size: 1024,
                epoch: EpochType::new(epoch),
                leader_timeout: Duration::from_secs(3600),
                certification_timeout: Duration::from_secs(3600),
                timeout_retry: Duration::from_secs(3600),
                fetch_timeout: Duration::from_secs(3600),
                activity_timeout: Delta::new(100),
                skip_timeout: Delta::new(50),
                fetch_concurrent: 1,
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer: NZUsize!(1024 * 1024),
                page_cache: CacheRef::from_pooler(&ctx, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
                forwarding: ForwardingPolicy::Disabled,
            };
            let engine = Engine::new(ctx.with_label("engine"), engine_cfg);
            engine.start(
                (NullSender, vote_rx),
                (NullSender, cert_rx),
                (NullSender, resolver_rx),
            );
        }

        // Interactive loop state
        let mut current_snapshot = next_result.snapshot_id;
        let mut steps_completed = 0;
        let mut divergences: Vec<(usize, Vec<compare::Mismatch>)> = Vec::new();

        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let mut transition_indices: Vec<usize> =
            (0..session.next_transitions.len()).collect();

        let mut block_map: HashMap<String, String> = HashMap::new();

        for step in 0..max_steps {
            // 1. Find an enabled transition (blocking HTTP)
            let mut found_enabled = false;
            let pre_snapshot = current_snapshot;

            transition_indices.shuffle(&mut rng);

            for &ti in &transition_indices {
                let transition = &session.next_transitions[ti];
                let assume_result =
                    client.assume_transition(&session.id, transition.index, true)?;

                match assume_result.status {
                    TransitionStatus::Enabled => {
                        let step_result = client.next_step(&session.id)?;
                        current_snapshot = step_result.snapshot_id;

                        // 2. Query the concrete state.
                        // Extract both previous and current states from the
                        // SAME trace query. This guarantees consistency
                        // (both come from the same Z3 model), avoiding
                        // re-concretization issues across queries.
                        let query_result =
                            client.query(&session.id, &["TRACE"], None)?;
                        let trace_val = query_result
                            .trace
                            .as_ref()
                            .ok_or(Error::Setup("no trace from query".into()))?;
                        let (prev_state, new_state) =
                            last_two_states_from_trace(trace_val)?;

                        let action_name = new_state
                            .get("lastAction")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?");

                        // 3. Diff to extract new messages.
                        // Both states come from the same trace query, so
                        // the diff is consistent within this step.
                        let prev_votes = collect_store_vote(&prev_state);
                        let new_votes = collect_store_vote(&new_state);
                        let prev_certs =
                            collect_store_certificate(&prev_state);
                        let new_certs =
                            collect_store_certificate(&new_state);

                        let vote_entries =
                            diff_store_vote(&prev_votes, &new_votes, &mut block_map);
                        let cert_entries = diff_store_certificate(
                            &prev_certs,
                            &new_certs,
                            &mut block_map,
                        );

                        println!(
                            "step {step}: t{} [{action_name}] -> {} votes, {} certs",
                            transition.index,
                            vote_entries.len(),
                            cert_entries.len(),
                        );

                        let mut step_entries = Vec::new();
                        for (receiver, sender, vote) in vote_entries {
                            println!("  vote: {sender} -> {receiver}: {vote:?}");
                            step_entries.push(TraceEntry::Vote {
                                sender,
                                receiver,
                                vote,
                            });
                        }
                        for (receiver, sender, cert) in cert_entries {
                            println!("  cert: {sender} -> {receiver}: {cert:?}");
                            step_entries.push(TraceEntry::Certificate {
                                sender,
                                receiver,
                                cert,
                            });
                        }

                        // 4. Inject into engines (1ms per message, like MBT)
                        for entry in &step_entries {
                            inject_entry(
                                entry,
                                faults,
                                &vote_injectors,
                                &cert_injectors,
                                &schemes,
                                &participants,
                                epoch,
                            );
                            context.sleep(Duration::from_millis(1)).await;
                        }

                        // 5. Let engines settle (2s, like MBT)
                        context.sleep(Duration::from_secs(2)).await;

                        // 6. Compare observed vs expected
                        let observed = invariants::extract_replayed(&reporters, n);
                        let correct_nodes_now = identify_correct_nodes(&new_state);
                        let expected = extract_expected_state(
                            &new_state,
                            &correct_nodes_now,
                            &block_map,
                        );
                        let mismatches =
                            compare::compare(&expected, &observed, faults);

                        // 7. Report result - print both spec and impl state
                        for (ci, impl_state) in observed.iter().enumerate() {
                            let ni = ci + faults;
                            let nid = format!("n{ni}");

                            // Impl (Rust) state
                            let i_notar: Vec<u64> =
                                impl_state.notarizations.keys().copied().collect();
                            let i_nulls: Vec<u64> =
                                impl_state.nullifications.keys().copied().collect();
                            let i_finals: Vec<u64> =
                                impl_state.finalizations.keys().copied().collect();
                            let i_last_fin =
                                i_finals.last().copied().unwrap_or(0);

                            // Spec (Quint/Apalache) state
                            let spec_node = expected.nodes.get(&nid);
                            let s_notar: Vec<u64> = spec_node
                                .map(|s| s.notarizations.keys().copied().collect())
                                .unwrap_or_default();
                            let s_nulls: Vec<u64> = spec_node
                                .map(|s| s.nullifications.iter().copied().collect())
                                .unwrap_or_default();
                            let s_finals: Vec<u64> = spec_node
                                .map(|s| s.finalizations.keys().copied().collect())
                                .unwrap_or_default();
                            let s_last_fin = spec_node
                                .map(|s| s.last_finalized)
                                .unwrap_or(0);

                            let has_state = !i_notar.is_empty()
                                || !i_nulls.is_empty()
                                || !i_finals.is_empty()
                                || !s_notar.is_empty()
                                || !s_nulls.is_empty()
                                || !s_finals.is_empty();

                            if has_state {
                                println!(
                                    "  {nid} spec: notarization={s_notar:?} nullification={s_nulls:?} finalization={s_finals:?} last_finalized={s_last_fin}"
                                );
                                println!(
                                    "  {nid} impl: notarization={i_notar:?} nullification={i_nulls:?} finalization={i_finals:?} last_finalized={i_last_fin}"
                                );

                                // Print vote signers if any differ or are non-empty
                                let s_notar_v = spec_node
                                    .map(|s| &s.notarize_signers)
                                    .cloned()
                                    .unwrap_or_default();
                                let s_null_v = spec_node
                                    .map(|s| &s.nullify_signers)
                                    .cloned()
                                    .unwrap_or_default();
                                let s_fin_v = spec_node
                                    .map(|s| &s.finalize_signers)
                                    .cloned()
                                    .unwrap_or_default();

                                // Only print vote details for views > 1
                                // (view 1 is init, signers differ by design)
                                let all_views: std::collections::BTreeSet<u64> =
                                    s_notar_v
                                        .keys()
                                        .chain(impl_state.notarize_signers.keys())
                                        .chain(s_null_v.keys())
                                        .chain(impl_state.nullify_signers.keys())
                                        .chain(s_fin_v.keys())
                                        .chain(impl_state.finalize_signers.keys())
                                        .copied()
                                        .filter(|&v| v > 1)
                                        .collect();

                                let empty = std::collections::BTreeSet::new();
                                for view in all_views {
                                    let sn = s_notar_v.get(&view).unwrap_or(&empty);
                                    let in_ = impl_state
                                        .notarize_signers
                                        .get(&view)
                                        .unwrap_or(&empty);
                                    let snl = s_null_v.get(&view).unwrap_or(&empty);
                                    let inl = impl_state
                                        .nullify_signers
                                        .get(&view)
                                        .unwrap_or(&empty);
                                    let sf = s_fin_v.get(&view).unwrap_or(&empty);
                                    let if_ = impl_state
                                        .finalize_signers
                                        .get(&view)
                                        .unwrap_or(&empty);

                                    if !sn.is_empty() || !in_.is_empty() {
                                        println!(
                                            "    v{view} notarize: spec={sn:?} impl={in_:?}"
                                        );
                                    }
                                    if !snl.is_empty() || !inl.is_empty() {
                                        println!(
                                            "    v{view} nullify:  spec={snl:?} impl={inl:?}"
                                        );
                                    }
                                    if !sf.is_empty() || !if_.is_empty() {
                                        println!(
                                            "    v{view} finalize: spec={sf:?} impl={if_:?}"
                                        );
                                    }
                                }
                            }
                        }
                        if mismatches.is_empty() {
                            println!("  [OK]");
                        } else {
                            println!(
                                "  [DIVERGENCE] {} mismatches:",
                                mismatches.len()
                            );
                            for m in &mismatches {
                                println!("    {m}");
                            }
                            divergences.push((step, mismatches));
                            // Stop immediately on divergence
                            steps_completed = step + 1;
                            break;
                        }

                        // Compact solver state to prevent Z3
                        // re-concretization across steps.
                        current_snapshot =
                            client.compact(&session.id, current_snapshot)?;
                        steps_completed = step + 1;
                        found_enabled = true;
                        break;
                    }
                    TransitionStatus::Disabled => {
                        client.rollback(&session.id, pre_snapshot)?;
                        current_snapshot = pre_snapshot;
                    }
                    TransitionStatus::Unknown => {
                        println!(
                            "step {step}: t{} {:?} returned UNKNOWN, skipping",
                            transition.index, transition.labels
                        );
                        client.rollback(&session.id, pre_snapshot)?;
                        current_snapshot = pre_snapshot;
                    }
                }
            }

            if !divergences.is_empty() {
                break;
            }

            if !found_enabled {
                println!("step {step}: no enabled transitions, stopping");
                break;
            }

        }

        // Cleanup
        let _ = client.dispose_spec(&session.id);

        Ok(IstReport {
            steps_completed,
            divergences,
        })
    });

    report
}

/// Report from an IST run.
pub struct IstReport {
    /// Number of steps completed.
    pub steps_completed: usize,
    /// Divergences found: (step_number, mismatches).
    pub divergences: Vec<(usize, Vec<compare::Mismatch>)>,
}

impl IstReport {
    pub fn is_ok(&self) -> bool {
        self.divergences.is_empty()
    }
}

impl std::fmt::Display for IstReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IST: {} steps completed, {} divergences",
            self.steps_completed,
            self.divergences.len()
        )?;
        for (step, mismatches) in &self.divergences {
            write!(f, "\n  at step {step}: {} mismatches", mismatches.len())?;
        }
        Ok(())
    }
}
