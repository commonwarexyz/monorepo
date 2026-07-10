//! Happens-before coverage for the Simplex harness (Mallory-style, model-free).
//!
//! Turns a node-attributed, ordered stream of protocol [Event]s into a per-node
//! happens-before [Summary]. The summary's distinct happens-before pairs are the
//! coverage tokens fed to libFuzzer (novelty over interleavings), and its per-node
//! structure supports inter-replica dispersion.
//!
//! This module is source-independent: it consumes [Event]s regardless of whether
//! they were captured from the p2p boundary or from node-attributed tracing
//! (dispatch propagation). Capture and libFuzzer wiring live elsewhere.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

/// Consensus-aware protocol event kinds. Kinds carry protocol meaning so
/// the summary discriminates concurrency; blunt kinds would not.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum EventKind {
    Propose,
    ReceiveProposal,
    SendNotarize,
    SendNullify,
    SendFinalize,
    SendNotarization,
    SendNullification,
    SendFinalization,
    ReceiveNotarize,
    ReceiveNullify,
    ReceiveFinalize,
    ReceiveNotarization,
    ReceiveNullification,
    ReceiveFinalization,
    ProcessNotarization,
    ProcessNullification,
    ProcessFinalization,
    QuorumNotarization,
    QuorumNullification,
    QuorumFinalization,
    TimeoutFired,
    EnterView,
}

impl EventKind {
    /// Stable short tag used to build coverage tokens.
    const fn tag(self) -> &'static str {
        match self {
            Self::Propose => "propose",
            Self::ReceiveProposal => "recv_proposal",
            Self::SendNotarize => "send_notarize",
            Self::SendNullify => "send_nullify",
            Self::SendFinalize => "send_finalize",
            Self::SendNotarization => "send_notarization",
            Self::SendNullification => "send_nullification",
            Self::SendFinalization => "send_finalization",
            Self::ReceiveNotarize => "recv_notarize",
            Self::ReceiveNullify => "recv_nullify",
            Self::ReceiveFinalize => "recv_finalize",
            Self::ReceiveNotarization => "recv_notarization",
            Self::ReceiveNullification => "recv_nullification",
            Self::ReceiveFinalization => "recv_finalization",
            Self::ProcessNotarization => "proc_notarization",
            Self::ProcessNullification => "proc_nullification",
            Self::ProcessFinalization => "proc_finalization",
            Self::QuorumNotarization => "quorum_notarization",
            Self::QuorumNullification => "quorum_nullification",
            Self::QuorumFinalization => "quorum_finalization",
            Self::TimeoutFired => "timeout",
            Self::EnterView => "enter_view",
        }
    }

    /// True when the kind is the node's own forward action (it advances the node's
    /// view position); receives do not, so a message from a future view stays
    /// `Ahead` rather than moving the node forward.
    const fn is_local_action(self) -> bool {
        matches!(
            self,
            Self::Propose
                | Self::SendNotarize
                | Self::SendNullify
                | Self::SendFinalize
                | Self::SendNotarization
                | Self::SendNullification
                | Self::SendFinalization
                | Self::QuorumNotarization
                | Self::QuorumNullification
                | Self::QuorumFinalization
                | Self::TimeoutFired
                | Self::EnterView
        )
    }

    /// For a receive kind, the send kind that causally precedes it
    /// (send-before-receive). `None` for kinds that are not receives of a
    /// broadcast we also observe as a send.
    const fn matching_send(self) -> Option<Self> {
        Some(match self {
            Self::ReceiveNotarize => Self::SendNotarize,
            Self::ReceiveNullify => Self::SendNullify,
            Self::ReceiveFinalize => Self::SendFinalize,
            Self::ReceiveNotarization => Self::SendNotarization,
            Self::ReceiveNullification => Self::SendNullification,
            Self::ReceiveFinalization => Self::SendFinalization,
            Self::ReceiveProposal => Self::Propose,
            _ => return None,
        })
    }

    /// True when this kind can be matched as the send half of a send-before-receive
    /// edge (the effect a peer later observes as a receive).
    const fn is_matchable_send(self) -> bool {
        matches!(
            self,
            Self::SendNotarize
                | Self::SendNullify
                | Self::SendFinalize
                | Self::SendNotarization
                | Self::SendNullification
                | Self::SendFinalization
                | Self::Propose
        )
    }

    /// Classify a tracing event by its target + human message. Returns
    /// `None` for events outside the simplex module or without a modeled kind.
    pub fn classify(target: &str, message: &str) -> Option<Self> {
        if !target.contains("commonware_consensus::simplex") {
            return None;
        }
        Some(match message {
            "broadcasting notarize" => Self::SendNotarize,
            "broadcasting nullify" => Self::SendNullify,
            "broadcasting finalize" => Self::SendFinalize,
            "broadcasting notarization" => Self::SendNotarization,
            "broadcasting nullification" | "broadcasting nullification floor" => {
                Self::SendNullification
            }
            "broadcasting finalization" => Self::SendFinalization,
            "received proposal" => Self::ReceiveProposal,
            "received notarization" | "received notarization for request" => {
                Self::ProcessNotarization
            }
            "received nullification" | "received nullification for request" => {
                Self::ProcessNullification
            }
            "received finalization" | "received finalization for request" => {
                Self::ProcessFinalization
            }
            "constructed notarization, forwarding to voter" => Self::QuorumNotarization,
            "constructed nullification, forwarding to voter" => Self::QuorumNullification,
            "constructed finalization, forwarding to voter" => Self::QuorumFinalization,
            "timing out view" => Self::TimeoutFired,
            "leader elected" => Self::EnterView,
            "requested proposal from automaton" => Self::Propose,
            _ => return None,
        })
    }
}

/// A node-attributed, view-tagged protocol event.
#[derive(Clone, Copy, Debug)]
pub struct Event {
    pub node: u32,
    pub view: u64,
    pub kind: EventKind,
    /// Wire sender resolved at the p2p boundary; `None` for local events and
    /// receives whose sender is unknown (such receives skip the cross-node merge
    /// rather than guessing).
    pub sender: Option<u32>,
}

/// View position relative to a node's current (max local-action) view.
/// This is what makes the fork-bug pair discriminating: receiving a notarization
/// for a view the node already left renders as `Behind`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Rel {
    Behind,
    Current,
    Ahead,
}

impl Rel {
    const fn tag(self) -> &'static str {
        match self {
            Self::Behind => "old",
            Self::Current => "cur",
            Self::Ahead => "new",
        }
    }
}

/// A view-relative event token: the unit of a happens-before pair.
type Token = (EventKind, Rel);

fn token_tag(t: Token) -> String {
    format!("{}@{}", t.0.tag(), t.1.tag())
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
struct NodeHistory {
    /// The node's current view = highest view it has taken a local action in.
    current_view: u64,
    /// Distinct tokens seen at this node.
    seen: BTreeSet<Token>,
    /// Distinct local happens-before pairs (A occurred-before B at this node).
    pairs: BTreeSet<(Token, Token)>,
}

/// Per-node happens-before summary. Accumulates, for each node, the set of
/// happens-before pairs of view-relative event tokens witnessed at that node.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    nodes: BTreeMap<u32, NodeHistory>,
}

impl Summary {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct nodes that contributed at least one event.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Fold one event into the summary.
    pub fn observe(&mut self, ev: Event) {
        let h = self.nodes.entry(ev.node).or_default();

        // Relative position is measured against the node's view *before* this
        // event, so a local action in a new view is `Ahead` (it advances) and a
        // receive for an already-left view is `Behind`.
        let rel = match ev.view.cmp(&h.current_view) {
            Ordering::Less => Rel::Behind,
            Ordering::Equal => Rel::Current,
            Ordering::Greater => Rel::Ahead,
        };
        if ev.kind.is_local_action() && ev.view > h.current_view {
            h.current_view = ev.view;
        }

        let token = (ev.kind, rel);
        for &prev in &h.seen {
            h.pairs.insert((prev, token));
        }
        h.seen.insert(token);
    }

    /// Merge a frozen sender history into the receiver: a receive inherits what
    /// the sender had witnessed by the matching send, so the receiver's
    /// subsequent events form happens-before pairs with the sender's inherited
    /// events, propagating causality across the node boundary. The receiver's
    /// own view is unchanged.
    fn merge_history(&mut self, receiver: u32, history: &NodeHistory) {
        let dst = self.nodes.entry(receiver).or_default();
        dst.seen.extend(history.seen.iter().copied());
        dst.pairs.extend(history.pairs.iter().copied());
    }

    /// Node-agnostic happens-before pair tokens (symmetry reduction over node
    /// identity). Each distinct pair is one coverage point for libFuzzer.
    pub fn tokens(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for h in self.nodes.values() {
            for &(a, b) in &h.pairs {
                out.insert(format!("hb:{}->{}", token_tag(a), token_tag(b)));
            }
        }
        out
    }

    /// MinHash + LSH band tokens (saturation control): a similarity-collapsing
    /// whole-run descriptor. Runs whose node-agnostic pair-sets are Jaccard-similar
    /// collide in most bands and light the same tokens; dissimilar runs light
    /// different ones. This is the discretized behaviour-descriptor cell libFuzzer
    /// chases (MAP-Elites bridge), additive to the fine per-pair tokens.
    /// Deterministic in the pair-set alone.
    ///
    /// Calibration path: the similarity threshold is set by the band
    /// geometry, ~ (1 / LSH_BANDS)^(1 / LSH_ROWS); widen bands to demand more
    /// similarity before collision, narrow them to collapse more aggressively.
    pub fn lsh_tokens(&self) -> Vec<String> {
        let tokens = self.tokens();
        if tokens.is_empty() {
            return Vec::new();
        }
        let mut sig = [u64::MAX; MINHASH_K];
        for t in &tokens {
            let base = fnv1a_bytes(t.as_bytes());
            for (k, s) in sig.iter_mut().enumerate() {
                *s = (*s).min(mix(base, k as u64));
            }
        }
        (0..LSH_BANDS)
            .map(|b| {
                let rows = &sig[b * LSH_ROWS..(b + 1) * LSH_ROWS];
                let mut h = 0xcbf2_9ce4_8422_2325u64;
                for &r in rows {
                    h = mix(h, r);
                }
                format!("hb:lsh:b{b}={}", h % LSH_BUCKETS)
            })
            .collect()
    }

    /// Stable per-run fingerprint of the whole summary (novelty descriptor).
    pub fn fingerprint(&self) -> u64 {
        // FNV-1a over the sorted, node-agnostic token set: stable across runs of
        // the same binary, order-independent by construction.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for tok in self.tokens() {
            for b in tok.as_bytes() {
                hash ^= u64::from(*b);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
            hash ^= 0xff;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash
    }

    /// Inter-replica dispersion: mean pairwise Jaccard distance between
    /// nodes' pair-sets. ~0 when replicas share a causal history (benign,
    /// synchronous); high when they diverge (partition / reorder / Byzantine).
    pub fn dispersion(&self) -> f64 {
        let sets: Vec<_> = self.nodes.values().map(|h| &h.pairs).collect();
        mean_pairwise_jaccard_distance(&sets)
    }

    /// Discretized inter-replica dispersion for coverage feedback, computed only
    /// over replicas that advanced past genesis. Anti-gaming: an idle or
    /// partitioned-and-stuck network is maximal raw dispersion yet bug-free, so
    /// replicas that never took a local action are excluded; `None` when fewer
    /// than two made progress.
    pub fn dispersion_bucket(&self) -> Option<u8> {
        let sets: Vec<_> = self
            .nodes
            .values()
            .filter(|h| h.current_view >= 1)
            .map(|h| &h.pairs)
            .collect();
        if sets.len() < 2 {
            return None;
        }
        let d = mean_pairwise_jaccard_distance(&sets);
        Some(((d * f64::from(DISPERSION_BUCKETS)) as u8).min(DISPERSION_BUCKETS - 1))
    }
}

/// Number of discrete dispersion levels libFuzzer can chase.
const DISPERSION_BUCKETS: u8 = 8;

/// MinHash signature width; must equal `LSH_BANDS * LSH_ROWS`.
const MINHASH_K: usize = 32;
/// LSH band count and rows-per-band: the two tunables that set the similarity
/// threshold (calibration path). Fewer rows / more bands collapse more.
const LSH_BANDS: usize = 8;
const LSH_ROWS: usize = 4;
/// Per-band bucket count: bounds the band token space so it saturates.
const LSH_BUCKETS: u64 = 64;

const _: () = assert!(MINHASH_K == LSH_BANDS * LSH_ROWS);

/// FNV-1a over bytes.
fn fnv1a_bytes(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// SplitMix64-style avalanche of a value combined with a salt (independent hash
/// family for MinHash / band folding).
fn mix(value: u64, salt: u64) -> u64 {
    let mut x = value ^ salt.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Mean pairwise Jaccard distance over a set of per-replica pair-sets. Returns
/// 0 for fewer than two replicas.
fn mean_pairwise_jaccard_distance(sets: &[&BTreeSet<(Token, Token)>]) -> f64 {
    if sets.len() < 2 {
        return 0.0;
    }
    let (mut sum, mut count) = (0.0, 0u32);
    for i in 0..sets.len() {
        for j in (i + 1)..sets.len() {
            let inter = sets[i].intersection(sets[j]).count();
            let union = sets[i].union(sets[j]).count();
            let jaccard = if union == 0 {
                0.0
            } else {
                inter as f64 / union as f64
            };
            sum += 1.0 - jaccard;
            count += 1;
        }
    }
    sum / f64::from(count)
}

/// Tracing capture: per-node subscribers that classify simplex tracing events
/// into an ordered, node-attributed [Event] log. Relies on the runtime's
/// dispatch propagation so each validator's whole task tree reports to its own
/// subscriber. Stores no spans of its own (the view is read from each event's
/// fields), avoiding the sharded-registry cross-scope span-drop panic: spans
/// are either dummies (stand-alone) or forwarded to one shared inner registry
/// (teed).
pub mod capture {
    use super::{Event, EventKind, NodeHistory, Summary};
    use std::{
        collections::BTreeMap,
        fmt::Write as _,
        sync::{Arc, Mutex},
    };

    /// Shared, ordered, node-attributed event log.
    #[derive(Clone, Default)]
    pub struct EventLog(Arc<Mutex<Vec<Event>>>);

    impl EventLog {
        pub fn new() -> Self {
            Self::default()
        }

        /// Fold the captured events into a happens-before summary. Events are
        /// processed in the deterministic runtime's exact global order: a wire
        /// receive with a known sender merges that sender's history as frozen at
        /// its first matching send (send-before-receive). Retries of the same
        /// (kind, view) do not refresh the snapshot: which copy a receive
        /// corresponds to is unknowable, and the first send's history is a
        /// subset of the sender's causal past at every copy, so the merge never
        /// imports post-send history. A receive with no known sender forms only
        /// local pairs.
        pub fn summary(&self) -> Summary {
            let mut s = Summary::new();
            let mut snapshots: BTreeMap<(u32, EventKind, u64), NodeHistory> = BTreeMap::new();
            for &ev in self.0.lock().unwrap().iter() {
                if let Some(send) = ev.kind.matching_send() {
                    if let Some(sender) = ev.sender.filter(|&sender| sender != ev.node) {
                        if let Some(history) = snapshots.get(&(sender, send, ev.view)) {
                            s.merge_history(ev.node, history);
                        }
                    }
                }
                s.observe(ev);
                if ev.kind.is_matchable_send() {
                    snapshots
                        .entry((ev.node, ev.kind, ev.view))
                        .or_insert_with(|| s.nodes.get(&ev.node).cloned().unwrap_or_default());
                }
            }
            s
        }

        /// Record an externally-captured event (e.g. from the p2p-boundary
        /// sniffer) into the shared ordered log.
        pub fn record(&self, ev: Event) {
            self.push(ev);
        }

        fn push(&self, ev: Event) {
            self.0.lock().unwrap().push(ev);
        }
    }

    /// A per-node subscriber. Wire per validator with
    /// `dispatcher::with_default(&Dispatch::new(NodeSubscriber::new(node, log)), || start_node())`.
    /// Installing it shadows the ambient default for the node's whole task tree;
    /// [Self::with_inner] tees to that shadowed collector so it still observes
    /// validator tasks.
    pub struct NodeSubscriber {
        node: u32,
        log: EventLog,
        inner: Option<tracing::Dispatch>,
    }

    impl NodeSubscriber {
        pub fn new(node: u32, log: EventLog) -> Self {
            Self {
                node,
                log,
                inner: None,
            }
        }

        /// Tee spans and events to `inner`, gated by its own interest. Span
        /// bookkeeping is forwarded there wholesale (one shared registry issues
        /// every id), never stored per node.
        pub fn with_inner(mut self, inner: tracing::Dispatch) -> Self {
            self.inner = Some(inner);
            self
        }
    }

    impl tracing::Subscriber for NodeSubscriber {
        fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
            let Some(inner) = &self.inner else {
                return true;
            };
            (m.is_event() && m.target().contains("commonware_consensus::simplex"))
                || inner.enabled(m)
        }
        fn new_span(&self, a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            match &self.inner {
                // Only reached when `enabled` passed, i.e. `inner` wants this
                // span; register it there so guard calls resolve against the one
                // shared registry.
                Some(inner) => inner.new_span(a),
                None => tracing::span::Id::from_u64(1),
            }
        }
        fn record(&self, s: &tracing::span::Id, r: &tracing::span::Record<'_>) {
            if let Some(inner) = &self.inner {
                inner.record(s, r);
            }
        }
        fn record_follows_from(&self, s: &tracing::span::Id, f: &tracing::span::Id) {
            if let Some(inner) = &self.inner {
                inner.record_follows_from(s, f);
            }
        }
        fn enter(&self, s: &tracing::span::Id) {
            if let Some(inner) = &self.inner {
                inner.enter(s);
            }
        }
        fn exit(&self, s: &tracing::span::Id) {
            if let Some(inner) = &self.inner {
                inner.exit(s);
            }
        }
        fn clone_span(&self, id: &tracing::span::Id) -> tracing::span::Id {
            match &self.inner {
                Some(inner) => inner.clone_span(id),
                None => id.clone(),
            }
        }
        fn try_close(&self, id: tracing::span::Id) -> bool {
            match &self.inner {
                Some(inner) => inner.try_close(id),
                None => false,
            }
        }
        fn event(&self, event: &tracing::Event<'_>) {
            if let Some(inner) = &self.inner {
                if inner.enabled(event.metadata()) {
                    inner.event(event);
                }
            }
            let target = event.metadata().target();
            if !target.contains("commonware_consensus::simplex") {
                return;
            }
            let mut v = Visitor::default();
            event.record(&mut v);
            let Some(kind) = EventKind::classify(target, &v.message) else {
                return;
            };
            let Some(view) = v.view() else {
                return;
            };
            self.log.push(Event {
                node: self.node,
                view,
                kind,
                sender: None,
            });
        }
    }

    #[derive(Default)]
    struct Visitor {
        message: String,
        view: Option<u64>,
        received: Option<u64>,
        blob: String,
    }

    impl Visitor {
        /// The event's protocol view. Resolver backfill logs pair the request
        /// `view` with the delivered certificate's `received` view (which may be
        /// ahead of the request); the certificate is what the node processes, so
        /// `received` wins when present.
        fn view(&self) -> Option<u64> {
            self.received
                .or(self.view)
                .or_else(|| parse_view_paren(&self.blob))
        }
    }

    fn is_view_field(name: &str) -> bool {
        name == "view" || name == "updated_view"
    }

    /// Recover a view from a `View(N)` fragment inside a Debug-formatted field
    /// (e.g. `proposal=Proposal { round: Round { view: View(2) } }`).
    fn parse_view_paren(blob: &str) -> Option<u64> {
        let start = blob.find("View(")? + "View(".len();
        let rest = &blob[start..];
        let end = rest.find(')')?;
        rest[..end].trim().parse().ok()
    }

    impl tracing::field::Visit for Visitor {
        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            if is_view_field(field.name()) {
                self.view.get_or_insert(value);
            } else if field.name() == "received" {
                self.received.get_or_insert(value);
            }
        }
        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            if value >= 0 {
                self.record_u64(field, value as u64);
            }
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            let s = format!("{value:?}");
            if field.name() == "message" {
                self.message = s;
            } else {
                if is_view_field(field.name()) && self.view.is_none() {
                    self.view = s.trim().parse().ok();
                } else if field.name() == "received" && self.received.is_none() {
                    self.received = s.trim().parse().ok();
                }
                let _ = write!(self.blob, "{s} ");
            }
        }
    }
}

#[cfg(test)]
mod capture_tests {
    use super::{
        capture::{EventLog, NodeSubscriber},
        Event, EventKind,
    };
    use tracing::{dispatcher, Dispatch};

    const T: &str = "commonware_consensus::simplex::actors::voter::actor";

    #[test]
    fn capture_classifies_attributes_and_extracts_view() {
        let log = EventLog::new();
        let d0 = Dispatch::new(NodeSubscriber::new(0, log.clone()));
        let d1 = Dispatch::new(NodeSubscriber::new(1, log.clone()));

        dispatcher::with_default(&d0, || {
            tracing::info!(target: T, view = 1u64, "received proposal");
            // view nested inside a Debug-rendered field
            tracing::info!(
                target: T,
                proposal = "Proposal { round: Round { view: View(2) } }",
                "broadcasting notarize"
            );
        });
        dispatcher::with_default(&d1, || {
            tracing::info!(target: T, view = 1u64, reason = "LeaderTimeout", "timing out view");
            // non-simplex and non-modeled events are dropped
            tracing::info!(target: "commonware_runtime::storage", view = 1u64, "write_at");
            tracing::info!(target: T, "no verifier ready");
        });

        let summary = log.summary();
        let toks = summary.tokens();
        // node 0's recv-proposal -> send-notarize pair is present (view extracted
        // from both the plain field and the nested `View(2)`).
        assert!(toks
            .iter()
            .any(|t| t.contains("recv_proposal") && t.contains("send_notarize")));
        // node 0 (recv/send) diverges from node 1 (timeout only) -> dispersion > 0.
        assert!(summary.dispersion() > 0.0);
    }

    #[test]
    fn backfill_processing_uses_received_certificate_view() {
        // The resolver's backfill log pairs the request `view` with the
        // delivered certificate's `received` view, which may be ahead of the
        // request; the event's view is the certificate's, not the request key.
        let log = EventLog::new();
        let d = Dispatch::new(NodeSubscriber::new(0, log.clone()));
        dispatcher::with_default(&d, || {
            tracing::info!(target: T, view = 2u64, "timing out view");
            tracing::info!(
                target: "commonware_consensus::simplex::actors::resolver::actor",
                view = %1u64,
                received = %3u64,
                "received notarization for request"
            );
        });

        let toks = log.summary().tokens();
        // Current view is 2 after the timeout; the view-3 certificate is ahead.
        assert!(
            toks.contains("hb:timeout@new->proc_notarization@new"),
            "expected processing at the received view, got {toks:?}"
        );
        // The stale request view would render the processing as behind.
        assert!(!toks.iter().any(|t| t.contains("proc_notarization@old")));
    }

    fn rec(log: &EventLog, node: u32, view: u64, kind: EventKind, sender: Option<u32>) {
        log.record(Event {
            node,
            view,
            kind,
            sender,
        });
    }

    #[test]
    fn merge_inherits_sender_history_across_nodes() {
        // Global-ordered log: node 0 sends a notarization, node 1 receives it off
        // the wire (real sender resolved at the p2p boundary), then finalizes.
        let log = EventLog::new();
        rec(&log, 0, 1, EventKind::SendNotarization, None);
        rec(&log, 1, 1, EventKind::ReceiveNotarization, Some(0));
        rec(&log, 1, 2, EventKind::SendFinalization, None);

        let toks = log.summary().tokens();
        // Cross-node causal pair: node 0's sent notarization happens-before node 1's
        // receipt of it. A purely local (unmerged) summary never forms this pair.
        assert!(
            toks.iter()
                .any(|t| t.contains("send_notarization") && t.contains("recv_notarization")),
            "expected a cross-node send->receive pair from merge, got {toks:?}"
        );
    }

    #[test]
    fn merge_uses_real_sender_not_a_kind_view_guess() {
        // Nodes 0 and 2 both send a notarization at view 1; node 2's is the most
        // recent when node 1's receive arrives, but the wire says node 0 sent it.
        let log = EventLog::new();
        rec(&log, 0, 1, EventKind::TimeoutFired, None);
        rec(&log, 0, 1, EventKind::SendNotarization, None);
        rec(&log, 2, 1, EventKind::Propose, None);
        rec(&log, 2, 1, EventKind::SendNotarization, None);
        rec(&log, 1, 1, EventKind::ReceiveNotarization, Some(0));

        let toks = log.summary().tokens();
        // Node 0's timeout is inherited across the causal edge...
        assert!(
            toks.contains("hb:timeout@new->recv_notarization@new"),
            "expected the real sender's history, got {toks:?}"
        );
        // ...node 2's propose is not, despite being the latest (kind, view) match.
        assert!(!toks
            .iter()
            .any(|t| t.starts_with("hb:propose") && t.contains("->recv_notarization")));
    }

    #[test]
    fn merge_freezes_sender_history_at_the_send() {
        // The sender keeps acting after the send; those later events are not part
        // of the receive's causal past and must not be imported.
        let log = EventLog::new();
        rec(&log, 0, 1, EventKind::SendNotarization, None);
        rec(&log, 0, 2, EventKind::SendFinalization, None);
        rec(&log, 1, 1, EventKind::ReceiveNotarization, Some(0));

        let toks = log.summary().tokens();
        assert!(toks.contains("hb:send_notarization@new->recv_notarization@new"));
        assert!(!toks
            .iter()
            .any(|t| t.contains("send_finalization") && t.contains("->recv_notarization")));
    }

    #[test]
    fn merge_uses_first_send_snapshot_for_retries() {
        // Node 0 broadcasts nullify, keeps acting, then retries the same nullify
        // (the voter rebroadcasts until it leaves the view). Node 1's receive may
        // be either copy; merging the first-send snapshot is sound for both, so
        // events between the copies must not be imported.
        let log = EventLog::new();
        rec(&log, 0, 1, EventKind::SendNullify, None);
        rec(&log, 0, 1, EventKind::TimeoutFired, None);
        rec(&log, 0, 1, EventKind::SendNullify, None);
        rec(&log, 1, 1, EventKind::ReceiveNullify, Some(0));

        let toks = log.summary().tokens();
        assert!(toks.contains("hb:send_nullify@new->recv_nullify@new"));
        assert!(!toks
            .iter()
            .any(|t| t.contains("timeout") && t.contains("->recv_nullify")));
    }

    #[test]
    fn receive_without_known_sender_does_not_merge() {
        let log = EventLog::new();
        rec(&log, 0, 1, EventKind::SendNotarization, None);
        rec(&log, 1, 1, EventKind::ReceiveNotarization, None);

        let toks = log.summary().tokens();
        assert!(!toks
            .iter()
            .any(|t| t.contains("send_notarization") && t.contains("->recv_notarization")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "commonware_consensus::simplex::actors::voter::actor";

    #[test]
    fn classify_maps_real_messages() {
        assert_eq!(
            EventKind::classify(T, "broadcasting notarize"),
            Some(EventKind::SendNotarize)
        );
        // The tracing "received X" events mark the node PROCESSING a certificate
        // (it passed the interesting-check); wire arrival is captured from p2p.
        assert_eq!(
            EventKind::classify(T, "received notarization"),
            Some(EventKind::ProcessNotarization)
        );
        assert_eq!(
            EventKind::classify(T, "timing out view"),
            Some(EventKind::TimeoutFired)
        );
        assert_eq!(
            EventKind::classify(T, "constructed nullification, forwarding to voter"),
            Some(EventKind::QuorumNullification)
        );
        assert_eq!(
            EventKind::classify(T, "constructed finalization, forwarding to voter"),
            Some(EventKind::QuorumFinalization)
        );
        // Resolver backfill is also a processing event (the voter handles it).
        assert_eq!(
            EventKind::classify(T, "received finalization for request"),
            Some(EventKind::ProcessFinalization)
        );
        // Non-modeled and non-simplex events are dropped.
        assert_eq!(EventKind::classify(T, "no verifier ready"), None);
        assert_eq!(
            EventKind::classify("commonware_runtime::storage", "broadcasting notarize"),
            None
        );
    }

    fn ev(node: u32, view: u64, kind: EventKind) -> Event {
        Event {
            node,
            view,
            kind,
            sender: None,
        }
    }

    #[test]
    fn accumulates_local_happens_before_pairs() {
        let mut s = Summary::new();
        s.observe(ev(0, 1, EventKind::EnterView));
        s.observe(ev(0, 1, EventKind::SendNotarize));
        s.observe(ev(0, 1, EventKind::SendFinalize));
        let toks = s.tokens();
        // Entering view 1 from genesis is an advance (@new); the votes it then
        // casts are @cur. Pairs: enter->notarize, enter->finalize, notarize->finalize.
        assert!(toks.contains("hb:enter_view@new->send_notarize@cur"));
        assert!(toks.contains("hb:send_notarize@cur->send_finalize@cur"));
        assert_eq!(toks.len(), 3);
    }

    #[test]
    fn fork_window_is_a_distinct_pair() {
        // Node advances to view 2 (local action), then receives a notarization for
        // the already-left view 1 -> the discriminating "receive-of-an-old-view"
        // pair the fork bug lives in.
        let mut safe = Summary::new();
        safe.observe(ev(0, 1, EventKind::ReceiveNotarization)); // received while still in view 1
        safe.observe(ev(0, 2, EventKind::SendNotarize)); // then advanced

        let mut buggy = Summary::new();
        buggy.observe(ev(0, 2, EventKind::SendNotarize)); // advanced to view 2 first
        buggy.observe(ev(0, 1, EventKind::ReceiveNotarization)); // THEN received view-1 notarization

        // The buggy interleaving produces a pair with a `Behind` receive that the
        // safe one does not.
        let buggy_toks = buggy.tokens();
        assert!(buggy_toks
            .iter()
            .any(|t| t.contains("->recv_notarization@old")));
        assert!(!safe
            .tokens()
            .iter()
            .any(|t| t.contains("recv_notarization@old")));
        // ...so the two interleavings have different coverage.
        assert_ne!(safe.fingerprint(), buggy.fingerprint());
    }

    #[test]
    fn symmetry_reduced_over_nodes_and_order_independent() {
        // Same causal shape on two different node ids -> identical tokens.
        let mut a = Summary::new();
        a.observe(ev(0, 1, EventKind::EnterView));
        a.observe(ev(0, 1, EventKind::SendNotarize));
        let mut b = Summary::new();
        b.observe(ev(3, 1, EventKind::EnterView));
        b.observe(ev(3, 1, EventKind::SendNotarize));
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn dispersion_rises_with_divergence() {
        // Two nodes with identical histories -> 0 dispersion.
        let mut agree = Summary::new();
        for n in [0, 1] {
            agree.observe(ev(n, 1, EventKind::EnterView));
            agree.observe(ev(n, 1, EventKind::SendNotarize));
        }
        assert_eq!(agree.dispersion(), 0.0);

        // Divergent local histories -> positive dispersion.
        let mut diverge = Summary::new();
        diverge.observe(ev(0, 1, EventKind::EnterView));
        diverge.observe(ev(0, 1, EventKind::SendNotarize));
        diverge.observe(ev(1, 1, EventKind::EnterView));
        diverge.observe(ev(1, 1, EventKind::TimeoutFired));
        diverge.observe(ev(1, 1, EventKind::SendNullify));
        assert!(diverge.dispersion() > 0.0);
    }

    #[test]
    fn token_universe_is_bounded_and_saturates() {
        use EventKind::*;
        let kinds = [
            Propose,
            ReceiveProposal,
            SendNotarize,
            SendNullify,
            SendFinalize,
            SendNotarization,
            SendNullification,
            SendFinalization,
            ReceiveNotarize,
            ReceiveNullify,
            ReceiveFinalize,
            ReceiveNotarization,
            ReceiveNullification,
            ReceiveFinalization,
            ProcessNotarization,
            ProcessNullification,
            ProcessFinalization,
            QuorumNotarization,
            QuorumNullification,
            QuorumFinalization,
            TimeoutFired,
            EnterView,
        ];
        // Exhaustiveness guard: a new EventKind variant breaks this match, forcing
        // `kinds` (and the counts below) to be updated in lockstep.
        for k in kinds {
            match k {
                Propose | ReceiveProposal | SendNotarize | SendNullify | SendFinalize
                | SendNotarization | SendNullification | SendFinalization | ReceiveNotarize
                | ReceiveNullify | ReceiveFinalize | ReceiveNotarization | ReceiveNullification
                | ReceiveFinalization | ProcessNotarization | ProcessNullification
                | ProcessFinalization | QuorumNotarization | QuorumNullification
                | QuorumFinalization | TimeoutFired | EnterView => {}
            }
        }

        // Every token comes from a fixed family: pairs of view-relative tags
        // (kind x {behind,current,ahead}), the discrete dispersion buckets, and the
        // LSH band buckets. A small, fixed universe.
        let tags = kinds.len() * 3;
        let pairs = tags * tags;
        let dispersion = DISPERSION_BUCKETS as usize;
        let lsh = LSH_BANDS * LSH_BUCKETS as usize;
        let universe = pairs + dispersion + lsh;
        assert_eq!(tags, 66);
        assert_eq!(pairs, 4356);
        assert_eq!(universe, 4356 + 8 + 512);

        // The whole signal fits the 2^16 coverage table with < 10% occupancy, so it
        // saturates by construction, unlike state_cov's unbounded state:/local:
        // fingerprints.
        assert!(universe * 10 < (1 << 16));
    }

    #[test]
    fn lsh_bands_collapse_similar_runs() {
        let seq = |kinds: &[(u64, EventKind)]| {
            let mut s = Summary::new();
            for &(v, k) in kinds {
                s.observe(ev(0, v, k));
            }
            s
        };
        let shared = |x: &Summary, y: &Summary| {
            x.lsh_tokens()
                .iter()
                .zip(y.lsh_tokens())
                .filter(|(p, q)| **p == *q)
                .count()
        };

        let a = seq(&[
            (1, EventKind::EnterView),
            (1, EventKind::SendNotarize),
            (1, EventKind::SendFinalize),
            (2, EventKind::SendNullify),
        ]);
        let a_copy = seq(&[
            (1, EventKind::EnterView),
            (1, EventKind::SendNotarize),
            (1, EventKind::SendFinalize),
            (2, EventKind::SendNullify),
        ]);
        let b = seq(&[
            (1, EventKind::ReceiveProposal),
            (1, EventKind::ReceiveNullification),
        ]);

        // Identical pair-sets collide in every band; a disjoint run collides in
        // strictly fewer (the saturation-control collapse).
        assert_eq!(shared(&a, &a_copy), LSH_BANDS);
        assert!(shared(&a, &b) < shared(&a, &a_copy));
    }

    #[test]
    fn dispersion_bucket_gates_on_activity() {
        // Idle: no node advanced past genesis (only receives) -> no signal.
        let mut idle = Summary::new();
        idle.observe(ev(0, 0, EventKind::ReceiveNotarization));
        idle.observe(ev(1, 0, EventKind::ReceiveNotarization));
        assert_eq!(idle.dispersion_bucket(), None);

        // Only one replica made progress -> nothing to compare against.
        let mut lonely = Summary::new();
        lonely.observe(ev(0, 1, EventKind::EnterView));
        lonely.observe(ev(0, 1, EventKind::SendNotarize));
        lonely.observe(ev(1, 0, EventKind::ReceiveNotarization));
        assert_eq!(lonely.dispersion_bucket(), None);

        // Two advanced replicas that agree -> lowest bucket.
        let mut agree = Summary::new();
        for n in [0, 1] {
            agree.observe(ev(n, 1, EventKind::EnterView));
            agree.observe(ev(n, 1, EventKind::SendNotarize));
        }
        assert_eq!(agree.dispersion_bucket(), Some(0));

        // Two advanced replicas that diverge -> a higher bucket.
        let mut diverge = Summary::new();
        diverge.observe(ev(0, 1, EventKind::EnterView));
        diverge.observe(ev(0, 1, EventKind::SendNotarize));
        diverge.observe(ev(1, 1, EventKind::EnterView));
        diverge.observe(ev(1, 1, EventKind::TimeoutFired));
        diverge.observe(ev(1, 1, EventKind::SendNullify));
        assert!(diverge.dispersion_bucket().unwrap() > 0);
    }
}
