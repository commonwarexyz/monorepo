//! Oracles over what a world's machines sign and report.
//!
//! Every check reads only signed statements, published headers, and reported activity, never
//! machine internals: the delivered order of each node is rebuilt from its `ViewResolved` and
//! `ViewSweep` reports with [`algebra::Horiz`] and [`algebra::Sweep`], and statements are compared
//! under the per-(signer, tag) partial order of
//! [`accountability`](crate::multimmit::machine::accountability).

use crate::{
    Viewable as _,
    multimmit::{
        algebra::{self, Horiz, Step, Sweep},
        machine::durability::SignRequest,
        scheme::bls12381::Scheme,
        types::{
            Activity, Artifact, ArtifactId, BlockRef, ChainId, ChainSet, CodecConfig,
            HistoryRecord, Lqc, TransactionBlockHeader, VoteContent,
        },
    },
    types::{Epoch, Height, Participant, View},
};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, ed25519, sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::TestRng;
use std::collections::{BTreeMap, BTreeSet, HashMap, btree_map::Entry};

/// One view's agreement facts as a `ViewResolved` report carries them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Resolved {
    base: Vec<BlockRef<Digest>>,
    tips: Vec<BlockRef<Digest>>,
    commitment: Digest,
}

/// The report a delivered order was rebuilt from: the views resolved through a view, or a sweep
/// of a view.
type Source = (&'static str, View);

/// What the oracle remembers about one node's reports.
#[derive(Debug)]
struct Reports {
    participant: Participant,
    /// Every view the node resolved, across restarts.
    resolved: BTreeMap<View, Resolved>,
    /// The node's delivered order through its highest contiguously resolved view.
    committed: Vec<BlockRef<Digest>>,
    /// `ends[u]` is the length of `committed` after view `u` (`ends[0] = 0`).
    ends: Vec<usize>,
    /// The latest sweep per view reported since the last restart.
    sweeps: BTreeMap<View, (Vec<BlockRef<Digest>>, ChainSet)>,
    /// The latest floor index reported since the last restart.
    floor: Option<u64>,
    /// The highest view whose leader block the node reported finalized.
    finalized: View,
    /// The header the node reported accepted at each (chain, height).
    accepted: BTreeMap<(ChainId, Height), Digest>,
}

/// Checks the safety properties of a world's runs as statements and reports arrive.
///
/// # Panics
///
/// Every method panics on the first violated property.
pub(crate) struct Oracle {
    epoch: Epoch,
    codec: CodecConfig,
    verifier: Scheme<ed25519::PublicKey, MinPk>,
    genesis: Vec<BlockRef<Digest>>,
    byzantine: BTreeSet<Participant>,
    /// Every header signed, published, or accepted anywhere, by reference, mapped to its parent.
    parents: HashMap<BlockRef<Digest>, BlockRef<Digest>>,
    /// Correct producers' published header per (chain, height).
    headers: BTreeMap<(ChainId, Height), Digest>,
    /// Correct leaders' published block per view.
    leaders: BTreeMap<View, Digest>,
    /// The content of every update signed in the world, by artifact.
    contents: HashMap<ArtifactId<Digest>, VoteContent<Digest>>,
    /// Correct voters' published contents per (signer, tag), by sequence number.
    votes: BTreeMap<(Participant, View), BTreeMap<u32, VoteContent<Digest>>>,
    /// The facts every node reported for each view.
    resolved: BTreeMap<View, Resolved>,
    /// The commitment each floor opened, by the view it pins.
    pinned: BTreeMap<View, Digest>,
    /// The longest delivered order any node reported; every other one is a prefix of it.
    longest: Vec<BlockRef<Digest>>,
    /// The node and report that last extended [`Self::longest`].
    longest_from: (usize, Source),
    /// Every quarantine, as (node, participant).
    quarantines: Vec<(usize, Participant)>,
    nodes: Vec<Reports>,
}

impl Oracle {
    /// Creates an oracle for nodes acting for `participants`, in node order, of which the
    /// `byzantine` participants may equivocate.
    pub(crate) fn new(
        epoch: Epoch,
        codec: CodecConfig,
        verifier: Scheme<ed25519::PublicKey, MinPk>,
        genesis: Vec<BlockRef<Digest>>,
        byzantine: BTreeSet<Participant>,
        participants: impl IntoIterator<Item = Participant>,
    ) -> Self {
        Self {
            epoch,
            codec,
            verifier,
            genesis,
            byzantine,
            parents: HashMap::new(),
            headers: BTreeMap::new(),
            leaders: BTreeMap::new(),
            contents: HashMap::new(),
            votes: BTreeMap::new(),
            resolved: BTreeMap::new(),
            pinned: BTreeMap::new(),
            longest: Vec::new(),
            longest_from: (0, ("resolved", View::zero())),
            quarantines: Vec::new(),
            nodes: participants
                .into_iter()
                .map(|participant| Reports {
                    participant,
                    resolved: BTreeMap::new(),
                    committed: Vec::new(),
                    ends: vec![0],
                    sweeps: BTreeMap::new(),
                    floor: None,
                    finalized: View::zero(),
                    accepted: BTreeMap::new(),
                })
                .collect(),
        }
    }

    /// Returns whether `participant` is correct.
    pub(crate) fn is_correct(&self, participant: Participant) -> bool {
        !self.byzantine.contains(&participant)
    }

    /// Returns the highest view `node` resolved contiguously from genesis.
    pub(crate) fn resolved(&self, node: usize) -> View {
        View::new((self.nodes[node].ends.len() - 1) as u64)
    }

    /// Returns the highest view whose leader block `node` reported finalized.
    pub(crate) fn finalized(&self, node: usize) -> View {
        self.nodes[node].finalized
    }

    /// Returns the digest of the header `node` reported accepted at `height` of `chain`.
    pub(crate) fn accepted(&self, node: usize, chain: ChainId, height: Height) -> Option<Digest> {
        self.nodes[node].accepted.get(&(chain, height)).copied()
    }

    /// Returns the length of the longest delivered order any node reported.
    pub(crate) const fn delivered(&self) -> usize {
        self.longest.len()
    }

    /// Returns every quarantine, as (node, participant), in report order.
    pub(crate) fn quarantines(&self) -> &[(usize, Participant)] {
        &self.quarantines
    }

    /// Records a header so later statements naming it or its descendants can be ordered.
    pub(crate) fn header(&mut self, header: &TransactionBlockHeader<Digest>) {
        self.parents
            .insert(header.block_ref::<Sha256>(), header.parent_ref());
    }

    /// Records the content `signer` signed as `artifact` so its publication can be checked.
    pub(crate) fn signed(
        &mut self,
        request: &SignRequest<MinPk, Digest>,
        artifact: &Artifact<MinPk, Digest>,
    ) {
        match request {
            SignRequest::TransactionBlock(header) => self.header(header),
            SignRequest::Update(request) => {
                self.contents
                    .insert(artifact.id::<Sha256>(), request.content().clone());
            }
            SignRequest::LeaderBlock(_) => {}
        }
    }

    /// Checks one statement a node publishes.
    ///
    /// A machine may sign before its reservation is durable, so what must hold is that a correct
    /// participant publishes at most one header per height and one leader block per view, and
    /// that its votes of one tag form a chain under the accountability partial order in sequence
    /// order, with one content per sequence number and nothing after a final vote.
    pub(crate) fn published(&mut self, artifact: &Artifact<MinPk, Digest>) {
        let Some(signer) = artifact.signer() else {
            return;
        };
        if let Artifact::TransactionBlock(block) = artifact {
            self.header(block.header());
        }
        if !self.is_correct(signer) {
            return;
        }
        match artifact {
            Artifact::TransactionBlock(block) => {
                let header = block.header();
                let slot = (header.chain(), header.height());
                let digest = header.digest::<Sha256>();
                assert_eq!(
                    *self.headers.entry(slot).or_insert(digest),
                    digest,
                    "{signer} published two headers at {slot:?}"
                );
            }
            Artifact::LeaderBlock(block) => {
                let digest = block.block().digest::<Sha256>();
                assert_eq!(
                    *self.leaders.entry(block.view()).or_insert(digest),
                    digest,
                    "{signer} published two leader blocks for view {}",
                    block.view()
                );
            }
            Artifact::Update(update) => {
                let content = self
                    .contents
                    .get(&artifact.id::<Sha256>())
                    .cloned()
                    .expect("published updates were signed in this world");
                let seq = update.seq();
                let tag = (signer, content.view());
                let published = self.votes.entry(tag).or_default();
                if let Some(earlier) = published.get(&seq) {
                    assert_eq!(
                        *earlier, content,
                        "{signer} published {tag:?} seq {seq} twice differently"
                    );
                    return;
                }
                let published = published.clone();
                for (other, previous) in &published {
                    let (lower, upper) = if *other < seq {
                        (previous, &content)
                    } else {
                        (&content, previous)
                    };
                    assert!(
                        !lower.is_final(),
                        "{signer} published {tag:?} after its final vote: {lower:?} then {upper:?}"
                    );
                    assert!(
                        self.precedes(lower, upper),
                        "{signer}'s votes of {tag:?} are not ordered by sequence number: \
                         {lower:?} then {upper:?}"
                    );
                }
                self.votes.entry(tag).or_default().insert(seq, content);
            }
            Artifact::Vqc(_) | Artifact::Lqc(_) | Artifact::Floor(_) => {}
        }
    }

    /// Checks one quarantine: a correct node quarantines only Byzantine participants.
    pub(crate) fn quarantined(&mut self, node: usize, participants: &[Participant]) {
        for participant in participants {
            if self.is_correct(self.nodes[node].participant) {
                assert!(
                    !self.is_correct(*participant),
                    "node {node} quarantined correct participant {participant}"
                );
            }
            self.quarantines.push((node, *participant));
        }
    }

    /// Forgets what `node` reported since its last restart that need not survive one.
    pub(crate) fn restarted(&mut self, node: usize) {
        let reports = &mut self.nodes[node];
        reports.sweeps.clear();
        reports.floor = None;
    }

    /// Checks one activity `node` reported.
    pub(crate) fn report(&mut self, node: usize, activity: &Activity<MinPk, Digest>) {
        if let Activity::HeaderAccepted { header, .. } = activity {
            if self.is_correct(self.nodes[node].participant) {
                self.nodes[node]
                    .accepted
                    .insert((header.chain(), header.height()), header.digest::<Sha256>());
            }
            return self.header(header);
        }
        // A twin half runs correct code for an equivocating identity: what it reports is not a
        // correct node's log.
        if !self.is_correct(self.nodes[node].participant) {
            return;
        }
        match activity {
            Activity::ViewResolved {
                view,
                base,
                tips,
                commitment,
                parent_commitment,
                ..
            } => {
                let record = HistoryRecord::new(*parent_commitment, tips.to_vec())
                    .expect("reported tips are one per chain");
                assert_eq!(
                    record.commitment::<Sha256>(),
                    *commitment,
                    "node {node}'s view {view} commitment does not open to its tips"
                );
                let resolved = Resolved {
                    base: base.to_vec(),
                    tips: tips.to_vec(),
                    commitment: *commitment,
                };
                self.resolve(node, *view, resolved);
            }
            Activity::ViewSweep {
                view,
                finals,
                settled,
            } => self.sweep(node, *view, finals, settled),
            Activity::LeaderFinalized { lqc, opening } => self.finalize(node, lqc, opening),
            Activity::TransactionProposed { .. } | Activity::HeaderAccepted { .. } => {}
        }
    }

    fn resolve(&mut self, node: usize, view: View, resolved: Resolved) {
        let reports = &mut self.nodes[node];
        let newest = reports.resolved.last_key_value().map(|(newest, _)| *newest);
        match reports.resolved.entry(view) {
            Entry::Occupied(entry) => {
                assert_eq!(
                    *entry.get(),
                    resolved,
                    "node {node} resolved view {view} twice differently"
                );
                return;
            }
            Entry::Vacant(entry) => {
                assert!(
                    newest.is_none_or(|newest| newest < view),
                    "node {node} resolved view {view} after view {newest:?}"
                );
                entry.insert(resolved.clone());
            }
        }
        match self.resolved.entry(view) {
            Entry::Occupied(entry) => assert_eq!(
                *entry.get(),
                resolved,
                "node {node} disagrees on view {view}"
            ),
            Entry::Vacant(entry) => {
                entry.insert(resolved.clone());
            }
        }
        if let Some(pinned) = self.pinned.get(&view) {
            assert_eq!(
                *pinned, resolved.commitment,
                "view {view} contradicts its floor"
            );
        }
        loop {
            let reports = &self.nodes[node];
            let next = View::new(reports.ends.len() as u64);
            let Some(resolved) = reports.resolved.get(&next).cloned() else {
                break;
            };
            let frontier = self.frontier(node, next);
            assert_eq!(
                resolved.base, frontier,
                "node {node}'s view {next} does not extend the previous view's tips"
            );
            let segment = Horiz::new(&resolved.base, &resolved.tips)
                .expect("reported tips extend their base")
                .map(|append| self.ancestor(&append.tip, append.height))
                .collect::<Vec<_>>();
            let reports = &mut self.nodes[node];
            reports.committed.extend(segment);
            reports.ends.push(reports.committed.len());
            let index = resolved
                .tips
                .iter()
                .map(|tip| tip.height().get())
                .sum::<u64>();
            assert_eq!(
                reports.committed.len() as u64,
                index,
                "node {node}'s order after view {next} is not indexed by its tip heights"
            );
        }
        let committed = std::mem::take(&mut self.nodes[node].committed);
        let through = View::new((self.nodes[node].ends.len() - 1) as u64);
        self.extend(node, ("resolved", through), &committed);
        self.nodes[node].committed = committed;
    }

    fn sweep(&mut self, node: usize, view: View, finals: &[BlockRef<Digest>], settled: &ChainSet) {
        if let Some((previous, was)) = self.nodes[node].sweeps.get(&view) {
            for (before, after) in previous.iter().zip(finals) {
                assert!(
                    self.extends(after, before),
                    "node {node}'s sweep of view {view} retreated on {}",
                    before.chain()
                );
            }
            assert!(
                was.is_subset(settled),
                "node {node}'s sweep of view {view} unsettled a chain"
            );
        }
        self.nodes[node]
            .sweeps
            .insert(view, (finals.to_vec(), settled.clone()));
        // A sweep is checked once the node has resolved every earlier view.
        let reports = &self.nodes[node];
        let Some(&end) = reports.ends.get(view.get() as usize - 1) else {
            return;
        };
        let base = self.frontier(node, view);
        let settled = (0..base.len())
            .map(|chain| settled.contains(ChainId::new(chain as u32)))
            .collect::<Vec<_>>();
        let mut order = self.nodes[node].committed[..end].to_vec();
        for step in Sweep::new(&base, finals, &settled).expect("sweeps extend their base") {
            if let Step::Append(append) = step {
                order.push(self.ancestor(&append.tip, append.height));
            }
        }
        self.extend(node, ("sweep", view), &order);
    }

    fn finalize(&mut self, node: usize, lqc: &Lqc<MinPk, Digest>, opening: &HistoryRecord<Digest>) {
        let index = algebra::validate_floor::<Sha256, MinPk>(lqc, opening, self.epoch, self.codec)
            .unwrap_or_else(|error| panic!("node {node} reported an invalid floor: {error}"));
        assert!(
            self.verifier
                .verify_lqc::<_, Sha256, _>(&mut TestRng::new(0), lqc, &Sequential),
            "node {node} reported an L-QC whose aggregate fails"
        );
        let pinned = lqc.view().previous().expect("an L-QC pins a view");
        let commitment = opening.commitment::<Sha256>();
        assert_eq!(
            *self.pinned.entry(pinned).or_insert(commitment),
            commitment,
            "two floors pin view {pinned} differently"
        );
        if let Some(resolved) = self.resolved.get(&pinned) {
            assert_eq!(
                resolved.commitment, commitment,
                "a floor contradicts view {pinned}"
            );
        }
        let reports = &mut self.nodes[node];
        assert!(
            reports.floor.is_none_or(|floor| floor <= index),
            "node {node}'s floor regressed"
        );
        reports.floor = Some(index);
        reports.finalized = reports.finalized.max(lqc.view());
    }

    /// Returns the tips `node` resolved for the view before `view` (genesis for view one).
    fn frontier(&self, node: usize, view: View) -> Vec<BlockRef<Digest>> {
        view.previous()
            .filter(|previous| !previous.is_zero())
            .map_or_else(
                || self.genesis.clone(),
                |previous| self.nodes[node].resolved[&previous].tips.clone(),
            )
    }

    /// Checks that `order` and the longest reported order are prefix-compatible.
    fn extend(&mut self, node: usize, source: Source, order: &[BlockRef<Digest>]) {
        let common = order.len().min(self.longest.len());
        if let Some(position) = (0..common).find(|&index| order[index] != self.longest[index]) {
            panic!(
                "node {node}'s order from {source:?} diverges at position {position}: {:?} vs {:?} \
                 from {:?}",
                order[position], self.longest[position], self.longest_from
            );
        }
        if order.len() > self.longest.len() {
            self.longest.extend_from_slice(&order[common..]);
            self.longest_from = (node, source);
        }
    }

    /// Returns whether `a` precedes or equals `b`: every tip of `a` is an ancestor-or-equal of
    /// `b`'s, `a` declares a subset of `b`'s chains, and `a` votes for no leader block or for
    /// `b`'s.
    fn precedes(&self, a: &VoteContent<Digest>, b: &VoteContent<Digest>) -> bool {
        a.tips()
            .iter()
            .zip(b.tips())
            .all(|(a, b)| self.extends(b, a))
            && a.declared().is_subset(b.declared())
            && a.leader().is_none_or(|leader| b.leader() == Some(leader))
    }

    /// Returns whether `descendant` is `ancestor` or extends it.
    fn extends(&self, descendant: &BlockRef<Digest>, ancestor: &BlockRef<Digest>) -> bool {
        descendant.height() >= ancestor.height()
            && self.ancestor(descendant, ancestor.height()) == *ancestor
    }

    /// Returns the block at `height` on `tip`'s path.
    ///
    /// # Panics
    ///
    /// Panics unless every header between them was signed or published.
    fn ancestor(&self, tip: &BlockRef<Digest>, height: Height) -> BlockRef<Digest> {
        let mut current = *tip;
        while current.height() > height {
            current = *self
                .parents
                .get(&current)
                .unwrap_or_else(|| panic!("no header for {current:?}"));
        }
        current
    }
}
