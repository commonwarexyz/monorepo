//! The canonical state digest both sides take after `finish`.
//!
//! [`take`] reads only: every mailbox read is a `Get*` query, every other read
//! is a shared counter or map, or the runtime's durable storage read without
//! opening a blob. It first settles the cluster, so acknowledged deliveries
//! have advanced the processed position on both sides, then prints fixed
//! sections with every multiset sorted, so the two sides, which never share a
//! schedule, compare by state and never by interleaving.
//!
//! Besides what `finish` reads, the digest carries what the fuzzing phase
//! would inherit silently: a delivery left armed on a node's resolver and its
//! unconsumed verdicts, pending application acknowledgements, and the durable
//! storage of every node (the certificate and block caches, the finalized
//! archives and the application metadata, then one audit of the whole
//! runtime's storage), so a certificate reported to another node, which the
//! mailbox cannot be asked about, or an injection left armed tells the two
//! sides apart.

use crate::setup::Cluster;
use commonware_codec::Encode as _;
use commonware_consensus::{
    marshal::Identifier,
    simplex::Floor,
    types::{Epoch, Height, Round, View},
};
use commonware_consensus_fuzz_core::simplex::Simplex;
use commonware_consensus_fuzz_marshal::{
    marshal::end_to_end::twins::stack::TwinsMarshal,
    scenarios::{
        environment::ScenarioHandoff,
        harness::{App, FuzzScenarioStandardHarness},
    },
};
use commonware_cryptography::{
    Digestible as _, Hasher as _, Sha256, sha256::Digest as Sha256Digest,
};
use commonware_runtime::{Clock as _, Storage as _, deterministic};
use std::{
    fmt::{Display, Write as _},
    time::Duration,
};

/// Bound on the settle rounds, each a barrier plus one millisecond.
const SETTLE_ROUNDS: usize = 64;

/// Heights and views the per-node probes read.
const PROBE_RANGE: u64 = 4;

/// The archives of the marshal's per-epoch cache (`core/cache.rs`).
const CACHE_ARCHIVES: [&str; 5] = [
    "verified",
    "notarized",
    "certified",
    "notarizations",
    "finalizations",
];

/// The partitions of a prunable archive.
const PRUNABLE_PARTS: [&str; 3] = ["metadata", "key", "value"];

/// The immutable archives `setup_validator` builds.
const IMMUTABLE_ARCHIVES: [&str; 2] = ["finalizations-by-height", "finalized-blocks"];

/// The partitions of an immutable archive.
const IMMUTABLE_PARTS: [&str; 5] = [
    "metadata",
    "freezer-table",
    "freezer-key",
    "freezer-value",
    "ordinal",
];

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The sha256 of a digest text, for the table.
pub fn sha256(text: &str) -> String {
    Sha256::hash(&[text.as_bytes()]).to_string()
}

fn sorted(mut items: Vec<String>) -> String {
    items.sort();
    format!("[{}]", items.join(" "))
}

/// The marshal partitions of the node `validator`, without their
/// `validator-<key>-` prefix, as `twins::stack::setup_validator` and the
/// marshal actor name them (`consensus/src/marshal/core/{actor,cache}.rs`,
/// epoch 0). A renamed partition drops out of the per-node listing silently;
/// the `storage_audit` line still covers it.
fn partitions() -> Vec<String> {
    let mut out = vec![
        "application-metadata".to_string(),
        "cache-metadata".to_string(),
    ];
    for name in CACHE_ARCHIVES {
        for part in PRUNABLE_PARTS {
            out.push(format!("cache-cache-0-{name}-{part}"));
        }
    }
    for name in IMMUTABLE_ARCHIVES {
        for part in IMMUTABLE_PARTS {
            out.push(format!("{name}-{part}"));
        }
    }
    out
}

/// Waits until no application has a pending acknowledgement and every
/// processed position is unchanged across two rounds; whether it did.
async fn settle<P: Simplex, M: TwinsMarshal<P, App<P>>>(
    context: &deterministic::Context,
    cluster: &Cluster<P, M>,
    harness: &FuzzScenarioStandardHarness<P, M>,
) -> bool {
    let mut previous = None;
    for _ in 0..SETTLE_ROUNDS {
        harness.barrier_all().await;
        let mut processed = Vec::new();
        let mut pending = false;
        for node in cluster.nodes.iter().flatten() {
            processed.push(node.mailbox.get_processed().await);
            pending |= !node.application.pending_ack_heights().is_empty();
        }
        if !pending && previous.as_ref() == Some(&processed) {
            return true;
        }
        previous = Some(processed);
        context.sleep(Duration::from_millis(1)).await;
    }
    false
}

/// The blobs of the partition `suffix` of node `validator`, each as
/// `<name>:<sha256 of its logical contents>`, or `None` when the partition
/// does not exist.
async fn blobs(
    context: &deterministic::Context,
    validator: &impl Display,
    suffix: &str,
) -> Option<Vec<String>> {
    let partition = format!("validator-{validator}-{suffix}");
    let names = context.scan(&partition).await.ok()?;
    Some(
        names
            .iter()
            .map(|name| {
                let content = context.logical_blob(&partition, name).unwrap_or_default();
                format!("{}:{}", hex(name), Sha256::hash(&[content.as_slice()]))
            })
            .collect(),
    )
}

/// The digest of the cluster state after `finish`, as one canonical text.
///
/// # Panics
///
/// When the cluster does not settle within [`SETTLE_ROUNDS`].
pub async fn take<P: Simplex, M: TwinsMarshal<P, App<P>>>(
    context: &deterministic::Context,
    cluster: &Cluster<P, M>,
    harness: &FuzzScenarioStandardHarness<P, M>,
    handoff: &ScenarioHandoff<P>,
) -> String {
    assert!(
        settle(context, cluster, harness).await,
        "the cluster did not settle in {SETTLE_ROUNDS} rounds"
    );
    let mut out = String::new();

    // The digests every node is probed for: genesis, the reference chain, the
    // expected blocks and the canonical chain.
    let mut probes: Vec<Sha256Digest> = vec![cluster.genesis.digest()];
    probes.extend(handoff.reference_chain.iter().map(|block| block.digest()));
    for expectation in &handoff.expected_nodes {
        probes.extend(expectation.present.iter().copied());
        probes.extend(expectation.absent.iter().copied());
    }
    probes.extend(harness.canonical().iter().map(|block| block.digest()));
    probes.sort_by_key(ToString::to_string);
    probes.dedup_by_key(|digest| digest.to_string());

    for (idx, node) in cluster.nodes.iter().enumerate() {
        let Some(node) = node else {
            continue;
        };
        let _ = writeln!(out, "node[{idx}]:");
        let fetches = node
            .resolver
            .fetches()
            .iter()
            .map(|(key, annotation)| format!("{key:?}/{annotation:?}"))
            .collect();
        let _ = writeln!(out, "  fetches={}", sorted(fetches));
        let active = node
            .resolver
            .active_fetches()
            .iter()
            .map(|(key, annotation)| format!("{key:?}/{annotation:?}"))
            .collect();
        let _ = writeln!(out, "  active={}", sorted(active));
        let targeted = node
            .resolver
            .targeted()
            .iter()
            .map(|(key, peers)| {
                let mut peers: Vec<String> = peers.iter().map(ToString::to_string).collect();
                peers.sort();
                format!("{key:?}->{}", peers.join(","))
            })
            .collect();
        let _ = writeln!(out, "  targeted={}", sorted(targeted));
        let _ = writeln!(out, "  retains={}", node.resolver.retain_count());
        // The injection path, which the fuzzing phase inherits as it stands.
        let _ = writeln!(
            out,
            "  armed={}",
            node.resolver.auto_delivery.lock().is_some()
        );
        let _ = writeln!(
            out,
            "  pending_deliveries={}",
            node.resolver.delivery_responses.lock().len()
        );
        let _ = writeln!(
            out,
            "  subscriptions={}",
            node.subscriptions
                .load(std::sync::atomic::Ordering::Relaxed)
        );
        let sends = node
            .sends
            .lock()
            .iter()
            .map(|(round, digest, recipients)| format!("{round:?}/{digest}/{recipients:?}"))
            .collect();
        let _ = writeln!(out, "  sends={}", sorted(sends));
        let _ = writeln!(out, "  processed={:?}", node.mailbox.get_processed().await);
        for probe in &probes {
            let held = node
                .mailbox
                .get_block(Identifier::Digest(*probe))
                .await
                .is_some();
            let _ = writeln!(
                out,
                "  block[{probe}]={}",
                if held { "present" } else { "absent" }
            );
        }
        for view in 1..=PROBE_RANGE {
            let round = Round::new(Epoch::zero(), View::new(view));
            let verified = node
                .mailbox
                .get_verified(round)
                .await
                .map_or_else(|| "none".to_string(), |block| block.digest().to_string());
            let _ = writeln!(out, "  verified[{view}]={verified}");
        }
        for height in 1..=PROBE_RANGE {
            let height = Height::new(height);
            let finalization = node.mailbox.get_finalization(height).await.map_or_else(
                || "none".to_string(),
                |finalization| hex(&finalization.encode()),
            );
            let _ = writeln!(out, "  finalization[{}]={finalization}", height.get());
            let info = node
                .mailbox
                .get_info(Identifier::Height(height))
                .await
                .map_or_else(|| "none".to_string(), |(h, d)| format!("{}/{d}", h.get()));
            let _ = writeln!(out, "  info[{}]={info}", height.get());
        }
        let latest = node
            .mailbox
            .get_info(Identifier::Latest)
            .await
            .map_or_else(|| "none".to_string(), |(h, d)| format!("{}/{d}", h.get()));
        let _ = writeln!(out, "  info[latest]={latest}");
        let tip = node
            .application
            .tip()
            .map_or_else(|| "none".to_string(), |(h, d)| format!("{}/{d}", h.get()));
        let _ = writeln!(out, "  app.tip={tip}");
        let delivered = node
            .application
            .delivered()
            .iter()
            .map(|(h, d)| format!("{}/{d}", h.get()))
            .collect::<Vec<_>>();
        let _ = writeln!(out, "  app.delivered=[{}]", delivered.join(" "));
        let blocks = node
            .application
            .blocks()
            .iter()
            .map(|(h, block)| format!("{}/{}", h.get(), block.digest()))
            .collect::<Vec<_>>();
        let _ = writeln!(out, "  app.blocks=[{}]", blocks.join(" "));
        let mut acks = node.application.pending_ack_heights();
        acks.sort();
        let acks: Vec<String> = acks.iter().map(|h| h.get().to_string()).collect();
        let _ = writeln!(out, "  app.pending_acks=[{}]", acks.join(" "));
        // The node's durable storage, partition by partition.
        let mut found = 0;
        for suffix in partitions() {
            let Some(blobs) = blobs(context, &cluster.participants[idx], &suffix).await else {
                continue;
            };
            found += 1;
            let _ = writeln!(out, "  storage[{suffix}]={}", sorted(blobs));
        }
        // Every node has its metadata partitions from its start.
        assert!(
            found > 0,
            "no marshal partition of node {idx} found: the names in `partitions` are stale"
        );
        let _ = writeln!(out, "  storage_partitions={found}");
    }

    let _ = writeln!(out, "handoff:");
    let floor = match &handoff.engine_floor {
        Floor::Genesis(digest) => format!("Genesis({digest})"),
        Floor::Finalized(finalization) => format!("Finalized({})", hex(&finalization.encode())),
    };
    let _ = writeln!(out, "  floor={floor}");
    let journal: Vec<String> = handoff
        .engine_journal
        .iter()
        .map(|notarization| hex(&notarization.encode()))
        .collect();
    let _ = writeln!(out, "  journal=[{}]", journal.join(" "));
    let anchor = &handoff.attack_anchor;
    let _ = writeln!(
        out,
        "  anchor={},{},{}",
        anchor.height.get(),
        anchor.view.get(),
        anchor.digest
    );
    let reference: Vec<String> = handoff
        .reference_chain
        .iter()
        .map(|block| block.digest().to_string())
        .collect();
    let _ = writeln!(out, "  reference=[{}]", reference.join(" "));
    let _ = writeln!(out, "  node_fetches={:?}", handoff.node_fetches);
    let _ = writeln!(
        out,
        "  node_active_fetches={:?}",
        handoff.node_active_fetches
    );
    for expectation in &handoff.expected_nodes {
        let present: Vec<String> = expectation
            .present
            .iter()
            .map(ToString::to_string)
            .collect();
        let absent: Vec<String> = expectation.absent.iter().map(ToString::to_string).collect();
        let _ = writeln!(
            out,
            "  expected[{:?}]=present{} absent{}",
            expectation.node,
            sorted(present),
            sorted(absent)
        );
    }
    let _ = writeln!(
        out,
        "  expectation.all_floor_rooted={:?}",
        handoff.expectation.all_floor_rooted
    );

    let ledger: Vec<String> = harness
        .ledger()
        .iter()
        .map(|certificate| {
            format!(
                "{:?}/{:?}/{}/{}/{:?}/{}",
                certificate.kind,
                certificate.round,
                certificate.parent_view.get(),
                certificate.payload,
                certificate.signers,
                hex(&certificate.encoded)
            )
        })
        .collect();
    let _ = writeln!(out, "ledger=[{}]", ledger.join(" "));
    let canonical: Vec<String> = harness
        .canonical()
        .iter()
        .map(|block| block.digest().to_string())
        .collect();
    let _ = writeln!(out, "canonical=[{}]", canonical.join(" "));
    // Every blob of every partition of the runtime, whatever its name.
    let _ = writeln!(out, "storage_audit={}", hex(&context.storage_audit()));
    out
}
