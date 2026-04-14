use super::{
    data::TraceData,
    sniffer::{TraceEntry, TracedCert, TracedVote},
};
use serde_json::to_string;
use sha1::{Digest, Sha1};
use std::{collections::BTreeMap, fs, path::Path};

const N: usize = 4;
const FAULTS: usize = 0;
const Q: usize = 3;
const REPLICAS: [&str; N] = ["n0", "n1", "n2", "n3"];
const PAYLOADS: [&str; 3] = ["val_b0", "val_b1", "val_b2"];

#[derive(Clone, Copy, Debug)]
pub struct SmallHonestTraceConfig {
    pub max_views: u64,
    pub max_containers: u64,
    pub epoch: u64,
}

impl Default for SmallHonestTraceConfig {
    fn default() -> Self {
        Self {
            max_views: 4,
            max_containers: 4,
            epoch: 0,
        }
    }
}

#[derive(Clone, Debug)]
struct SearchState {
    next_view: u64,
    latest_parent: u64,
    finalized_containers: u64,
    max_seen_view: u64,
    entries: Vec<TraceEntry>,
}

#[derive(Clone, Debug)]
struct ViewExtension {
    entries: Vec<TraceEntry>,
    next_parent: u64,
    finalized_delta: u64,
    advances_view: bool,
}

fn replica(id: usize) -> String {
    format!("n{id}")
}

fn all_replicas() -> Vec<String> {
    REPLICAS.iter().map(|id| (*id).to_string()).collect()
}

fn leader_for_view(epoch: u64, view: u64) -> String {
    replica(((epoch + view) as usize) % N)
}

fn payload_for_view(view: u64) -> String {
    PAYLOADS[((view - 1) as usize) % PAYLOADS.len()].to_string()
}

fn append_vote_broadcast(entries: &mut Vec<TraceEntry>, sender: &str, vote: TracedVote) {
    for receiver in REPLICAS {
        if receiver == sender {
            continue;
        }
        entries.push(TraceEntry::Vote {
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            vote: vote.clone(),
        });
    }
}

fn append_certificate_broadcast(entries: &mut Vec<TraceEntry>, sender: &str, cert: TracedCert) {
    for receiver in REPLICAS {
        if receiver == sender {
            continue;
        }
        entries.push(TraceEntry::Certificate {
            sender: sender.to_string(),
            receiver: receiver.to_string(),
            cert: cert.clone(),
        });
    }
}

fn make_notarize(view: u64, parent: u64, sig: &str, payload: &str) -> TracedVote {
    TracedVote::Notarize {
        view,
        parent,
        sig: sig.to_string(),
        block: payload.to_string(),
    }
}

fn make_finalize(view: u64, parent: u64, sig: &str, payload: &str) -> TracedVote {
    TracedVote::Finalize {
        view,
        parent,
        sig: sig.to_string(),
        block: payload.to_string(),
    }
}

fn make_nullify(view: u64, sig: &str) -> TracedVote {
    TracedVote::Nullify {
        view,
        sig: sig.to_string(),
    }
}

fn make_notarization_cert(
    view: u64,
    parent: u64,
    payload: &str,
    signers: &[String],
    ghost_sender: &str,
) -> TracedCert {
    TracedCert::Notarization {
        view,
        parent,
        block: payload.to_string(),
        signers: signers.to_vec(),
        ghost_sender: ghost_sender.to_string(),
    }
}

fn make_finalization_cert(
    view: u64,
    parent: u64,
    payload: &str,
    signers: &[String],
    ghost_sender: &str,
) -> TracedCert {
    TracedCert::Finalization {
        view,
        parent,
        block: payload.to_string(),
        signers: signers.to_vec(),
        ghost_sender: ghost_sender.to_string(),
    }
}

fn make_nullification_cert(view: u64, signers: &[String], ghost_sender: &str) -> TracedCert {
    TracedCert::Nullification {
        view,
        signers: signers.to_vec(),
        ghost_sender: ghost_sender.to_string(),
    }
}

fn cert_sender(signers: &[String]) -> String {
    signers
        .iter()
        .min()
        .cloned()
        .expect("certificate must have at least one signer")
}

fn leader_nullify_extension(view: u64, parent: u64) -> ViewExtension {
    let mut entries = Vec::new();
    let signers = all_replicas();
    for signer in &signers {
        append_vote_broadcast(&mut entries, signer, make_nullify(view, signer));
    }
    let sender = cert_sender(&signers);
    append_certificate_broadcast(
        &mut entries,
        &sender,
        make_nullification_cert(view, &signers, &sender),
    );
    ViewExtension {
        entries,
        next_parent: parent,
        finalized_delta: 0,
        advances_view: true,
    }
}

fn propose_extension(
    epoch: u64,
    view: u64,
    parent: u64,
    follower_notarizers_mask: u8,
) -> ViewExtension {
    let leader = leader_for_view(epoch, view);
    let payload = payload_for_view(view);
    let followers: Vec<String> = REPLICAS
        .iter()
        .filter(|id| **id != leader)
        .map(|id| (*id).to_string())
        .collect();
    let mut entries = Vec::new();
    let mut notarizers = vec![leader.clone()];
    let mut nullifiers = Vec::new();

    append_vote_broadcast(
        &mut entries,
        &leader,
        make_notarize(view, parent, &leader, &payload),
    );

    for (idx, follower) in followers.iter().enumerate() {
        if follower_notarizers_mask & (1 << idx) != 0 {
            notarizers.push(follower.clone());
            append_vote_broadcast(
                &mut entries,
                follower,
                make_notarize(view, parent, follower, &payload),
            );
        } else {
            nullifiers.push(follower.clone());
            append_vote_broadcast(&mut entries, follower, make_nullify(view, follower));
        }
    }

    if nullifiers.len() >= Q {
        let sender = cert_sender(&nullifiers);
        append_certificate_broadcast(
            &mut entries,
            &sender,
            make_nullification_cert(view, &nullifiers, &sender),
        );
        return ViewExtension {
            entries,
            next_parent: parent,
            finalized_delta: 0,
            advances_view: true,
        };
    }

    if notarizers.len() >= Q {
        let not_sender = cert_sender(&notarizers);
        append_certificate_broadcast(
            &mut entries,
            &not_sender,
            make_notarization_cert(view, parent, &payload, &notarizers, &not_sender),
        );
        for signer in &notarizers {
            append_vote_broadcast(
                &mut entries,
                signer,
                make_finalize(view, parent, signer, &payload),
            );
        }
        let fin_sender = cert_sender(&notarizers);
        append_certificate_broadcast(
            &mut entries,
            &fin_sender,
            make_finalization_cert(view, parent, &payload, &notarizers, &fin_sender),
        );
        return ViewExtension {
            entries,
            next_parent: view,
            finalized_delta: 1,
            advances_view: true,
        };
    }

    ViewExtension {
        entries,
        next_parent: parent,
        finalized_delta: 0,
        advances_view: false,
    }
}

fn view_extensions(cfg: &SmallHonestTraceConfig, state: &SearchState) -> Vec<ViewExtension> {
    let mut out = Vec::new();
    let view = state.next_view;
    let parent = state.latest_parent;

    out.push(leader_nullify_extension(view, parent));

    for follower_mask in 0u8..(1u8 << (N - 1)) {
        out.push(propose_extension(cfg.epoch, view, parent, follower_mask));
    }

    out
}

fn trace_data_for_state(state: &SearchState, cfg: &SmallHonestTraceConfig) -> TraceData {
    TraceData {
        n: N,
        faults: FAULTS,
        epoch: cfg.epoch,
        max_view: state.max_seen_view,
        entries: state.entries.clone(),
        required_containers: state.finalized_containers,
        reporter_states: BTreeMap::new(),
    }
}

fn canonical_json(trace: &TraceData) -> String {
    to_string(trace).expect("trace serialization must succeed")
}

fn explore(
    cfg: &SmallHonestTraceConfig,
    state: SearchState,
    seen: &mut BTreeMap<String, TraceData>,
) {
    if state.next_view > cfg.max_views || state.finalized_containers >= cfg.max_containers {
        return;
    }

    for extension in view_extensions(cfg, &state) {
        let finalized = state.finalized_containers + extension.finalized_delta;
        if finalized > cfg.max_containers {
            continue;
        }

        let max_seen_view = state.max_seen_view.max(state.next_view);
        let mut entries = state.entries.clone();
        entries.extend(extension.entries);

        let next = SearchState {
            next_view: state.next_view + 1,
            latest_parent: extension.next_parent,
            finalized_containers: finalized,
            max_seen_view,
            entries,
        };

        let trace = trace_data_for_state(&next, cfg);
        seen.entry(canonical_json(&trace)).or_insert(trace);

        if extension.advances_view
            && next.next_view <= cfg.max_views
            && next.finalized_containers < cfg.max_containers
        {
            explore(cfg, next, seen);
        }
    }
}

pub fn generate_small_honest_traces(cfg: SmallHonestTraceConfig) -> Vec<TraceData> {
    let mut seen = BTreeMap::new();
    let init = SearchState {
        next_view: 1,
        latest_parent: 0,
        finalized_containers: 0,
        max_seen_view: 0,
        entries: Vec::new(),
    };
    explore(&cfg, init, &mut seen);
    seen.into_values().collect()
}

pub fn write_small_honest_traces(
    traces: &[TraceData],
    output_dir: &Path,
) -> Result<usize, std::io::Error> {
    fs::create_dir_all(output_dir)?;
    for trace in traces {
        let json = serde_json::to_string_pretty(trace).expect("pretty trace serialization");
        let digest = Sha1::digest(json.as_bytes());
        let name = format!("{:x}.json", digest);
        fs::write(output_dir.join(name), json)?;
    }
    Ok(traces.len())
}

#[cfg(test)]
mod tests {
    use super::{generate_small_honest_traces, SmallHonestTraceConfig, N};
    use crate::tracing::{
        encoder::EncoderConfig,
        sniffer::{TraceEntry, TracedCert, TracedVote},
        tlc_encoder,
    };
    use std::collections::BTreeSet;

    #[test]
    fn generate_bounded_honest_traces() {
        let cfg = SmallHonestTraceConfig::default();
        let traces = generate_small_honest_traces(cfg);

        assert!(
            !traces.is_empty(),
            "generator must produce at least one trace"
        );

        let mut serialized = BTreeSet::new();
        for trace in &traces {
            assert_eq!(trace.n, N);
            assert_eq!(trace.faults, 0);
            assert_eq!(trace.epoch, 0);
            assert!(trace.max_view <= cfg.max_views);
            assert!(trace.required_containers <= cfg.max_containers);
            assert!(!trace.entries.is_empty());

            for entry in &trace.entries {
                match entry {
                    TraceEntry::Vote {
                        sender,
                        receiver,
                        vote,
                    } => {
                        assert_ne!(sender, receiver);
                        match vote {
                            TracedVote::Notarize { view, parent, .. }
                            | TracedVote::Finalize { view, parent, .. } => {
                                assert!(*view >= 1 && *view <= cfg.max_views);
                                assert!(*parent <= *view);
                            }
                            TracedVote::Nullify { view, .. } => {
                                assert!(*view >= 1 && *view <= cfg.max_views);
                            }
                        }
                    }
                    TraceEntry::Certificate {
                        sender,
                        receiver,
                        cert,
                    } => {
                        assert_ne!(sender, receiver);
                        match cert {
                            TracedCert::Notarization { view, parent, .. }
                            | TracedCert::Finalization { view, parent, .. } => {
                                assert!(*view >= 1 && *view <= cfg.max_views);
                                assert!(*parent <= *view);
                            }
                            TracedCert::Nullification { view, .. } => {
                                assert!(*view >= 1 && *view <= cfg.max_views);
                            }
                        }
                    }
                }
            }

            let enc_cfg = EncoderConfig {
                n: trace.n,
                faults: trace.faults,
                epoch: trace.epoch,
                max_view: trace.max_view,
                required_containers: trace.required_containers,
            };
            let actions = tlc_encoder::encode(trace, &enc_cfg);
            assert!(!actions.is_empty(), "encoded action list must be non-empty");

            let json = serde_json::to_string(trace).expect("serialize generated trace");
            assert!(serialized.insert(json), "generated traces must be unique");
        }
    }

    #[test]
    fn parent_survives_nullified_view_after_finalization() {
        let cfg = SmallHonestTraceConfig {
            max_views: 3,
            max_containers: 2,
            epoch: 0,
        };
        let traces = generate_small_honest_traces(cfg);
        let mut found = false;

        for trace in &traces {
            let finalized_v1 = trace.entries.iter().any(|entry| {
                matches!(
                    entry,
                    TraceEntry::Certificate {
                        cert: TracedCert::Finalization {
                            view: 1,
                            parent: 0,
                            ..
                        },
                        ..
                    }
                )
            });
            let nullified_v2 = trace.entries.iter().any(|entry| {
                matches!(
                    entry,
                    TraceEntry::Certificate {
                        cert: TracedCert::Nullification { view: 2, .. },
                        ..
                    }
                )
            });
            if !(finalized_v1 && nullified_v2) {
                continue;
            }

            let has_view3_activity = trace.entries.iter().any(|entry| {
                matches!(
                    entry,
                    TraceEntry::Vote {
                        vote: TracedVote::Notarize { view: 3, .. }
                            | TracedVote::Finalize { view: 3, .. },
                        ..
                    } | TraceEntry::Certificate {
                        cert: TracedCert::Notarization { view: 3, .. }
                            | TracedCert::Finalization { view: 3, .. },
                        ..
                    }
                )
            });
            if !has_view3_activity {
                continue;
            }
            found = true;

            for entry in &trace.entries {
                match entry {
                    TraceEntry::Vote { vote, .. } => match vote {
                        TracedVote::Notarize {
                            view: 3, parent, ..
                        }
                        | TracedVote::Finalize {
                            view: 3, parent, ..
                        } => {
                            assert_eq!(*parent, 1);
                        }
                        _ => {}
                    },
                    TraceEntry::Certificate { cert, .. } => match cert {
                        TracedCert::Notarization {
                            view: 3, parent, ..
                        }
                        | TracedCert::Finalization {
                            view: 3, parent, ..
                        } => {
                            assert_eq!(*parent, 1);
                        }
                        _ => {}
                    },
                }
            }
        }

        assert!(found);
    }
}
