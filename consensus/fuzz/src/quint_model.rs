use crate::tracing::{
    data::TraceData,
    encoder::{self, ActionItem, CertItem, EncoderConfig},
    sniffer::{TraceEntry, TracedCert, TracedVote},
};
use sha1::{Digest, Sha1};
use std::{
    collections::{BTreeSet, HashSet},
    error::Error,
    fmt::{self, Display},
    fs,
    path::PathBuf,
    process::{self, Command},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct ModelError {
    message: String,
}

impl ModelError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ModelError {}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn quint_dir() -> PathBuf {
    manifest_dir().join("../quint")
}

fn temp_dir() -> PathBuf {
    quint_dir().join(".mbf_model_tmp")
}

fn unique_stem(label: &str, suffix: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(label.as_bytes());
    hasher.update(suffix.as_bytes());
    hasher.update(process::id().to_string().as_bytes());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before epoch")
        .as_nanos()
        .to_string();
    hasher.update(now.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn normalized_model_trace(trace: &TraceData) -> TraceData {
    let mut model_trace = trace.clone();
    model_trace.required_containers = 0;
    model_trace.reporter_states.clear();
    model_trace
}

fn encoder_config(trace: &TraceData) -> EncoderConfig {
    EncoderConfig {
        n: trace.n,
        faults: trace.faults,
        epoch: trace.epoch,
        max_view: trace.max_view,
        required_containers: 0,
    }
}

fn run_quint_test_module(label: &str, suffix: &str, qnt_source: &str) -> Result<(), ModelError> {
    let temp_dir = temp_dir();
    fs::create_dir_all(&temp_dir)
        .map_err(|e| ModelError::new(format!("failed to create {}: {e}", temp_dir.display())))?;

    let stem = unique_stem(label, suffix);
    let qnt_path = temp_dir.join(format!("{stem}.qnt"));

    fs::write(&qnt_path, qnt_source)
        .map_err(|e| ModelError::new(format!("failed to write {}: {e}", qnt_path.display())))?;

    let mut command = Command::new("quint");
    command
        .current_dir(quint_dir())
        .env("NODE_OPTIONS", "--max-old-space-size=8192")
        .args([
            "test",
            "--main=tests",
            "--backend=rust",
            "--max-samples=1",
            "--match=traceTest",
        ]);
    command.arg(qnt_path.to_str().expect("utf8 qnt path"));

    let output = command.output().map_err(|e| {
        ModelError::new(format!(
            "failed to run quint for {} [{}]: {e}",
            label, suffix,
        ))
    })?;

    let _ = fs::remove_file(&qnt_path);
    let _ = fs::remove_dir(&temp_dir);

    if !output.status.success() {
        let mut message = format!(
            "quint test failed for {} [{}] (exit {})",
            label,
            suffix,
            output.status.code().unwrap_or(-1)
        );
        if !output.stdout.is_empty() {
            message.push_str("\n--- quint stdout ---\n");
            message.push_str(&String::from_utf8_lossy(&output.stdout));
        }
        if !output.stderr.is_empty() {
            message.push_str("\n--- quint stderr ---\n");
            message.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        return Err(ModelError::new(message));
    }
    Ok(())
}

fn collect_block_hashes(trace: &TraceData) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut seen = HashSet::new();
    let mut record = |block: &str| {
        if block == "GENESIS_PAYLOAD" || !seen.insert(block.to_string()) {
            return;
        }
        blocks.push(block.to_string());
    };

    for entry in &trace.entries {
        let maybe_block = match entry {
            TraceEntry::Vote {
                vote: TracedVote::Notarize { block, .. },
                ..
            }
            | TraceEntry::Vote {
                vote: TracedVote::Finalize { block, .. },
                ..
            }
            | TraceEntry::Certificate {
                cert: TracedCert::Notarization { block, .. },
                ..
            }
            | TraceEntry::Certificate {
                cert: TracedCert::Finalization { block, .. },
                ..
            } => Some(block.as_str()),
            _ => None,
        };

        if let Some(block) = maybe_block {
            record(block);
        }
    }

    blocks
}

fn is_certifiable(block_hash: &str) -> bool {
    if block_hash.len() >= 2 {
        let last_two = &block_hash[block_hash.len() - 2..];
        let last_byte = u8::from_str_radix(last_two, 16).unwrap_or(0);
        (last_byte % 11) < 9
    } else {
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ProposalKey {
    view: u64,
    parent: u64,
    payload: String,
}

fn proposal_var_name(key: &ProposalKey) -> String {
    format!("proposal_v{}_p{}_{}", key.view, key.parent, key.payload)
}

fn proposal_ref(view: u64, parent: u64, payload: &str) -> String {
    proposal_var_name(&ProposalKey {
        view,
        parent,
        payload: payload.to_string(),
    })
}

fn cert_to_quint(cert: &CertItem) -> String {
    match cert {
        CertItem::Notarization {
            view,
            parent_view,
            payload,
            signers,
            ghost_sender,
        } => {
            let sigs: Vec<String> = signers.iter().map(|s| format!("\"{}\"", s)).collect();
            format!(
                "notarization({}, Set({}), \"{}\")",
                proposal_ref(*view, *parent_view, payload),
                sigs.join(", "),
                ghost_sender
            )
        }
        CertItem::Nullification {
            view,
            signers,
            ghost_sender,
        } => {
            let sigs: Vec<String> = signers.iter().map(|s| format!("\"{}\"", s)).collect();
            format!(
                "nullification({}, Set({}), \"{}\")",
                view,
                sigs.join(", "),
                ghost_sender
            )
        }
        CertItem::Finalization {
            view,
            parent_view,
            payload,
            signers,
            ghost_sender,
        } => {
            let sigs: Vec<String> = signers.iter().map(|s| format!("\"{}\"", s)).collect();
            format!(
                "finalization({}, Set({}), \"{}\")",
                proposal_ref(*view, *parent_view, payload),
                sigs.join(", "),
                ghost_sender
            )
        }
    }
}

fn render_replica_tla_actions(items: &[ActionItem]) -> Vec<String> {
    let mut result = Vec::new();
    let mut delivery_seen: HashSet<(String, String)> = HashSet::new();

    for item in items {
        match item {
            ActionItem::Propose {
                leader,
                view,
                payload,
                parent_view,
            } => {
                let pref = proposal_ref(*view, *parent_view, payload);
                result.push(format!(
                    "propose(\"{}\", {}.payload, {}.parent)",
                    leader, pref, pref
                ));
            }
            ActionItem::SendNotarizeVote {
                view,
                parent_view,
                payload,
                sig,
            } => result.push(format!(
                "inject_notarize_vote({{ proposal: {}, sig: \"{}\" }})",
                proposal_ref(*view, *parent_view, payload),
                sig
            )),
            ActionItem::SendNullifyVote { view, sig } => result.push(format!(
                "inject_nullify_vote({{ view: {}, sig: \"{}\" }})",
                view, sig
            )),
            ActionItem::SendFinalizeVote {
                view,
                parent_view,
                payload,
                sig,
            } => result.push(format!(
                "inject_finalize_vote({{ proposal: {}, sig: \"{}\" }})",
                proposal_ref(*view, *parent_view, payload),
                sig
            )),
            ActionItem::SendCertificate { cert } => {
                result.push(format!("inject_certificate({})", cert_to_quint(cert)))
            }
            ActionItem::OnNotarize {
                receiver,
                view,
                parent_view,
                payload,
                sig,
            } => result.push(format!(
                "on_notarize(\"{}\", {{ proposal: {}, sig: \"{}\" }})",
                receiver,
                proposal_ref(*view, *parent_view, payload),
                sig
            )),
            ActionItem::OnNullify {
                receiver,
                view,
                sig,
            } => {
                let vote = format!("{{ view: {}, sig: \"{}\" }}", view, sig);
                if delivery_seen.insert((receiver.clone(), vote.clone())) {
                    result.push(format!("on_nullify(\"{}\", {})", receiver, vote));
                }
            }
            ActionItem::OnFinalize {
                receiver,
                view,
                parent_view,
                payload,
                sig,
            } => {
                let vote = format!(
                    "{{ proposal: {}, sig: \"{}\" }}",
                    proposal_ref(*view, *parent_view, payload),
                    sig
                );
                if delivery_seen.insert((receiver.clone(), vote.clone())) {
                    result.push(format!("on_finalize(\"{}\", {})", receiver, vote));
                }
            }
            ActionItem::OnCertificate { receiver, cert } => {
                result.push(format!(
                    "on_certificate(\"{}\", {})",
                    receiver,
                    cert_to_quint(cert)
                ));
            }
        }
    }

    result
}

fn write_replica_tla_helpers(out: &mut String) {
    use std::fmt::Write;

    writeln!(
        out,
        "    action inject_notarize_vote(vote: NotarizeVote): bool = all {{"
    )
    .unwrap();
    writeln!(
        out,
        "        sent_notarize_votes' = sent_notarize_votes.union(Set(vote)),"
    )
    .unwrap();
    writeln!(out, "        sent_nullify_votes' = sent_nullify_votes,").unwrap();
    writeln!(out, "        sent_finalize_votes' = sent_finalize_votes,").unwrap();
    writeln!(out, "        sent_certificates' = sent_certificates,").unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = \"inject_vote\",").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    action inject_nullify_vote(vote: NullifyVote): bool = all {{"
    )
    .unwrap();
    writeln!(out, "        sent_notarize_votes' = sent_notarize_votes,").unwrap();
    writeln!(
        out,
        "        sent_nullify_votes' = sent_nullify_votes.union(Set(vote)),"
    )
    .unwrap();
    writeln!(out, "        sent_finalize_votes' = sent_finalize_votes,").unwrap();
    writeln!(out, "        sent_certificates' = sent_certificates,").unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = \"inject_vote\",").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    action inject_finalize_vote(vote: FinalizeVote): bool = all {{"
    )
    .unwrap();
    writeln!(out, "        sent_notarize_votes' = sent_notarize_votes,").unwrap();
    writeln!(out, "        sent_nullify_votes' = sent_nullify_votes,").unwrap();
    writeln!(
        out,
        "        sent_finalize_votes' = sent_finalize_votes.union(Set(vote)),"
    )
    .unwrap();
    writeln!(out, "        sent_certificates' = sent_certificates,").unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = \"inject_vote\",").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    writeln!(
        out,
        "    action inject_certificate(cert: Certificate): bool = all {{"
    )
    .unwrap();
    writeln!(out, "        sent_notarize_votes' = sent_notarize_votes,").unwrap();
    writeln!(out, "        sent_nullify_votes' = sent_nullify_votes,").unwrap();
    writeln!(out, "        sent_finalize_votes' = sent_finalize_votes,").unwrap();
    writeln!(
        out,
        "        sent_certificates' = sent_certificates.union(Set(cert)),"
    )
    .unwrap();
    writeln!(out, "        store_notarize_votes' = store_notarize_votes,").unwrap();
    writeln!(out, "        store_nullify_votes' = store_nullify_votes,").unwrap();
    writeln!(out, "        store_finalize_votes' = store_finalize_votes,").unwrap();
    writeln!(out, "        store_certificates' = store_certificates,").unwrap();
    writeln!(
        out,
        "        ghost_committed_blocks' = ghost_committed_blocks,"
    )
    .unwrap();
    writeln!(out, "        leader' = leader,").unwrap();
    writeln!(out, "        replica_state' = replica_state,").unwrap();
    writeln!(out, "        certify_policy' = certify_policy,").unwrap();
    writeln!(out, "        lastAction' = \"inject_cert\",").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
}

fn collect_payload_aliases(trace: &TraceData) -> Vec<(String, String)> {
    collect_block_hashes(trace)
        .into_iter()
        .enumerate()
        .map(|(idx, original)| (original, format!("val_b{idx}")))
        .collect()
}

fn collect_proposals(items: &[ActionItem]) -> BTreeSet<ProposalKey> {
    let mut proposals = BTreeSet::new();
    for item in items {
        match item {
            ActionItem::Propose {
                view,
                parent_view,
                payload,
                ..
            }
            | ActionItem::SendNotarizeVote {
                view,
                parent_view,
                payload,
                ..
            }
            | ActionItem::SendFinalizeVote {
                view,
                parent_view,
                payload,
                ..
            }
            | ActionItem::OnNotarize {
                view,
                parent_view,
                payload,
                ..
            }
            | ActionItem::OnFinalize {
                view,
                parent_view,
                payload,
                ..
            } => {
                proposals.insert(ProposalKey {
                    view: *view,
                    parent: *parent_view,
                    payload: payload.clone(),
                });
            }
            ActionItem::SendCertificate { cert } | ActionItem::OnCertificate { cert, .. } => {
                match cert {
                    CertItem::Notarization {
                        view,
                        parent_view,
                        payload,
                        ..
                    }
                    | CertItem::Finalization {
                        view,
                        parent_view,
                        payload,
                        ..
                    } => {
                        proposals.insert(ProposalKey {
                            view: *view,
                            parent: *parent_view,
                            payload: payload.clone(),
                        });
                    }
                    CertItem::Nullification { .. } => {}
                }
            }
            ActionItem::SendNullifyVote { .. } | ActionItem::OnNullify { .. } => {}
        }
    }
    proposals
}

fn encode_replica_tla_model(trace_data: &TraceData, cfg: &EncoderConfig) -> String {
    use std::fmt::Write;

    let payload_aliases = collect_payload_aliases(trace_data);
    let action_items = encoder::build_action_items(trace_data, cfg);
    let actions = render_replica_tla_actions(&action_items);
    let proposals = collect_proposals(&action_items);
    let block_names: Vec<&str> = payload_aliases
        .iter()
        .map(|(_, alias)| alias.as_str())
        .collect();
    let f = (cfg.n - 1) / 3;
    let q = cfg.n - f;

    let mut out = String::new();
    writeln!(out, "module tests {{").unwrap();
    writeln!(out, "    import types.* from \"../types\"").unwrap();
    writeln!(out, "    import defs.* from \"../defs\"").unwrap();
    writeln!(out, "    import option.* from \"../option\"").unwrap();
    write!(out, "    import automaton(\n        CERTIFY_DOMAIN = Set(").unwrap();
    let all_blocks: Vec<String> = block_names.iter().map(|b| format!("\"{}\"", b)).collect();
    write!(out, "{}", all_blocks.join(", ")).unwrap();
    writeln!(out, "),").unwrap();
    writeln!(out, "    ) as app from \"../automaton\"").unwrap();
    writeln!(out, "    import replica(").unwrap();
    writeln!(out, "        N = {},", cfg.n).unwrap();
    writeln!(out, "        F = {},", f).unwrap();
    writeln!(out, "        Q = {},", q).unwrap();

    let correct: Vec<String> = (cfg.faults..cfg.n).map(|i| format!("\"n{}\"", i)).collect();
    writeln!(out, "        CORRECT = Set({}),", correct.join(", ")).unwrap();
    let byzantine: Vec<String> = (0..cfg.faults).map(|i| format!("\"n{}\"", i)).collect();
    if byzantine.is_empty() {
        writeln!(out, "        BYZANTINE = Set(),").unwrap();
    } else {
        writeln!(out, "        BYZANTINE = Set({}),", byzantine.join(", ")).unwrap();
    }
    let keys: Vec<String> = (0..cfg.n)
        .map(|i| format!("\"n{}\"->\"n{}\"", i, i))
        .collect();
    writeln!(out, "        REPLICA_KEYS = Map({}),", keys.join(", ")).unwrap();
    writeln!(out, "        VIEWS = 1.to({}),", cfg.max_view).unwrap();
    write!(out, "        VALID_PAYLOADS = Set(").unwrap();
    write!(out, "{}", all_blocks.join(", ")).unwrap();
    writeln!(out, "),").unwrap();
    writeln!(out, "        INVALID_PAYLOADS = Set(),").unwrap();
    writeln!(out, "        ACTIVITY_TIMEOUT = 10").unwrap();
    writeln!(out, "    ).* from \"../replica_tla\"").unwrap();
    writeln!(out).unwrap();

    let mut certifiable_payloads: Vec<String> = vec!["GENESIS_PAYLOAD".to_string()];
    for (hash, alias) in &payload_aliases {
        if is_certifiable(hash) {
            certifiable_payloads.push(format!("\"{}\"", alias));
        }
    }
    writeln!(
        out,
        "    pure val CERTIFY_POLICY = Set({})",
        certifiable_payloads.join(", ")
    )
    .unwrap();
    writeln!(
        out,
        "    pure val CERTIFY_CUSTOM = Replicas.mapBy(_ => CERTIFY_POLICY)"
    )
    .unwrap();
    writeln!(out).unwrap();

    for key in &proposals {
        let parent_str = if key.parent == 0 {
            "GENESIS_VIEW".to_string()
        } else {
            key.parent.to_string()
        };
        writeln!(
            out,
            "    pure val {} = {{ payload: \"{}\", view: {}, parent: {} }}",
            proposal_var_name(key),
            key.payload,
            key.view,
            parent_str
        )
        .unwrap();
    }
    writeln!(out).unwrap();

    const CHUNK_SIZE: usize = 25;
    let chunks: Vec<&[String]> = actions.chunks(CHUNK_SIZE).collect();
    let leader_entries: Vec<String> = (0..=cfg.max_view)
        .map(|view| {
            let leader_idx = ((cfg.epoch + view) as usize) % cfg.n;
            format!("{view} -> \"n{leader_idx}\"")
        })
        .collect();
    let leader_init = format!(
        "initWithLeaderAndCertify(\n            Map({}),\n            CERTIFY_CUSTOM\n        )",
        leader_entries.join(", ")
    );

    for (i, chunk) in chunks.iter().enumerate() {
        writeln!(out, "    action trace_part_{:02} =", i).unwrap();
        if i == 0 {
            writeln!(out, "        {}", leader_init).unwrap();
        } else {
            writeln!(out, "        trace_part_{:02}", i - 1).unwrap();
        }
        for action in *chunk {
            writeln!(out, "            .then({})", action).unwrap();
        }
        writeln!(out).unwrap();
    }

    writeln!(out, "    run traceTest =").unwrap();
    if chunks.is_empty() {
        writeln!(out, "        {}", leader_init).unwrap();
    } else {
        writeln!(out, "        trace_part_{:02}", chunks.len() - 1).unwrap();
    }
    writeln!(out).unwrap();
    write_replica_tla_helpers(&mut out);
    writeln!(out, "}}").unwrap();
    out
}

fn validate_replica_trace(trace: &TraceData, label: &str) -> Result<(), ModelError> {
    let cfg = encoder_config(trace);
    let qnt = encoder::encode(trace, &cfg);
    run_quint_test_module(label, "replica", &qnt)
}

fn validate_replica_tla_trace(trace: &TraceData, label: &str) -> Result<(), ModelError> {
    let cfg = encoder_config(trace);
    let qnt = encode_replica_tla_model(trace, &cfg);
    run_quint_test_module(label, "replica_tla", &qnt)
}

pub fn validate_trace_dual(trace: &TraceData, label: &str) -> Result<(), ModelError> {
    let model_trace = normalized_model_trace(trace);
    validate_replica_trace(&model_trace, label)?;
    validate_replica_tla_trace(&model_trace, label)?;
    Ok(())
}
