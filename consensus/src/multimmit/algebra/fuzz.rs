//! Random producer forests and differential campaigns of the extraction and ordering algebra
//! against the naive [`mod@reference`] model, the body of the `fuzz_algebra` target.
//!
//! The generators draw every choice from one RNG, so a seeded RNG gives a unit-test campaign and
//! a [`FuzzRng`] over fuzzer input gives a coverage-guided one.

use super::{
    reference::{self, Tree},
    tips::determined,
    *,
};
use crate::{
    multimmit::types::{
        BlockRef, CertificateId, ChainSet, CodecConfig, DEFAULT_DELTA_MAX, Endorsement,
        EpochGenesis, FinalTally, ResolutionPath, VoteContent, Vqc, Window,
    },
    types::{Epoch, Height, Participant, Round, View},
};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::primitives::{ops::aggregate, variant::MinSig},
    sha256::Digest as Sha256Digest,
};
use commonware_utils::FuzzRng;
use rand::{Rng, RngExt as _};
use std::{collections::BTreeSet, ops::RangeInclusive};

pub(super) type D = Sha256Digest;

pub(super) const EPOCH: Epoch = Epoch::new(3);
pub(super) const ROUND: Round = Round::new(EPOCH, View::new(5));

/// Runs every differential campaign with choices drawn from `input`.
pub(crate) fn exercise(input: &[u8]) {
    let mut rng = FuzzRng::new(input.to_vec());
    extraction(&mut rng);
    vqc_resolution(&mut rng);
    order(&mut rng);
}

/// Returns a codec configuration with window cap `cap` and flow bound `4 cap`, whose tip lead
/// `6 cap` covers every block of a [`Forest::random`] forest above any base it picks.
pub(super) fn config(participants: usize, chains: usize, cap: u32) -> CodecConfig {
    let window = Window::with_bounds(cap, 4 * cap, DEFAULT_DELTA_MAX).unwrap();
    CodecConfig::new(participants, chains, window).unwrap()
}

pub(super) fn hash(bytes: &[u8]) -> D {
    Sha256::hash(&[bytes])
}

pub(super) fn signer(index: usize) -> Participant {
    Participant::from_usize(index)
}

/// Random producer trees: a trunk per chain from its genesis object plus short forks.
pub(super) struct Forest {
    pub(super) tree: Tree<D>,
    pub(super) genesis: Vec<BlockRef<D>>,
    trunks: Vec<Vec<BlockRef<D>>>,
    blocks: Vec<Vec<BlockRef<D>>>,
    payloads: u64,
}

impl Forest {
    pub(super) fn new(chains: usize) -> Self {
        let genesis = EpochGenesis::new::<Sha256>(EPOCH, chains)
            .unwrap()
            .tips()
            .to_vec();
        Self {
            tree: Tree::new(EPOCH),
            trunks: genesis.iter().map(|block| vec![*block]).collect(),
            blocks: genesis.iter().map(|block| vec![*block]).collect(),
            genesis,
            payloads: 0,
        }
    }

    fn random(rng: &mut impl Rng, chains: usize, trunk: usize, forks: usize) -> Self {
        let mut forest = Self::new(chains);
        for chain in 0..chains {
            for _ in 0..trunk {
                let top = *forest.trunks[chain].last().unwrap();
                let block = forest.extend(&top);
                forest.trunks[chain].push(block);
            }
            for _ in 0..forks {
                let index = rng.random_range(0..forest.trunks[chain].len() - 1);
                let mut parent = forest.trunks[chain][index];
                for _ in 0..rng.random_range(1..=3) {
                    parent = forest.extend(&parent);
                }
            }
        }
        forest
    }

    pub(super) fn extend(&mut self, parent: &BlockRef<D>) -> BlockRef<D> {
        self.payloads += 1;
        let payload = hash(&self.payloads.to_le_bytes());
        let block = self.tree.extend::<Sha256>(parent, payload);
        self.blocks[parent.chain().index()].push(block);
        block
    }

    /// Picks a tip on `base`'s chain, mostly near the window on the trunk.
    fn pick(&self, rng: &mut impl Rng, base: &BlockRef<D>, cap: u32) -> BlockRef<D> {
        let chain = base.chain().index();
        if rng.random_bool(0.7) {
            let low = base.height().get().saturating_sub(1);
            let high = base.height().get() + u64::from(cap) + 2;
            let near: Vec<_> = self.trunks[chain]
                .iter()
                .filter(|block| (low..=high).contains(&block.height().get()))
                .collect();
            if !near.is_empty() {
                return *near[rng.random_range(0..near.len())];
            }
        }
        self.blocks[chain][rng.random_range(0..self.blocks[chain].len())]
    }

    /// Picks a base vector, mostly on the trunks.
    fn base(&self, rng: &mut impl Rng) -> Vec<BlockRef<D>> {
        (0..self.trunks.len())
            .map(|chain| {
                if rng.random_bool(0.9) {
                    self.trunks[chain][rng.random_range(0..3)]
                } else {
                    self.blocks[chain][rng.random_range(0..self.blocks[chain].len())]
                }
            })
            .collect()
    }

    /// Picks a block extending `from` (or `from` itself) at most `lead` above it.
    fn descendant(&self, rng: &mut impl Rng, from: &BlockRef<D>, lead: u64) -> BlockRef<D> {
        let candidates: Vec<_> = self.blocks[from.chain().index()]
            .iter()
            .filter(|block| {
                block.height().get() <= from.height().get() + lead
                    && self.tree.endorses(block, from)
            })
            .collect();
        *candidates[rng.random_range(0..candidates.len())]
    }
}

pub(super) fn content(
    tips: Vec<BlockRef<D>>,
    leader: Option<D>,
    config: CodecConfig,
) -> VoteContent<D> {
    let endorsement = Endorsement::new(ChainSet::empty(config.chains()), tips, config).unwrap();
    VoteContent::new(ROUND, leader, true, endorsement).unwrap()
}

/// Returns the canonical resolution paths of `contents` above `base`: one per recorded tip above
/// the base that is not an ancestor of another.
pub(super) fn resolution_paths(
    tree: &Tree<D>,
    base: &[BlockRef<D>],
    contents: &[(Participant, VoteContent<D>)],
    config: CodecConfig,
) -> Vec<ResolutionPath<D>> {
    let mut paths = Vec::new();
    for base in base {
        let above: BTreeSet<_> = contents
            .iter()
            .map(|(_, content)| content.tips()[base.chain().index()])
            .filter(|tip| tip.height() > base.height())
            .collect();
        for tip in &above {
            if above
                .iter()
                .any(|other| other != tip && tree.endorses(other, tip))
            {
                continue;
            }
            let from = tree.ancestor(tip, base.height()).unwrap();
            let payloads = tree.payloads(&from, tip).unwrap();
            paths.push(ResolutionPath::new(from, payloads, config).unwrap());
        }
    }
    paths
}

pub(super) fn vqc(
    parent: CertificateId<D>,
    contents: &[(Participant, VoteContent<D>)],
    paths: Vec<ResolutionPath<D>>,
    config: CodecConfig,
) -> Vqc<MinSig, D> {
    let tally = FinalTally::from_contents(contents.iter().cloned(), paths, config).unwrap();
    Vqc::new(ROUND, parent, tally, aggregate::Signature::zero(), config).unwrap()
}

fn chain_votes(
    contents: &[(Participant, VoteContent<D>)],
    chain: usize,
) -> Vec<(Participant, BlockRef<D>)> {
    contents
        .iter()
        .map(|(signer, content)| (*signer, content.tips()[chain]))
        .collect()
}

/// Random final votes, one per signer of a V-QC, with tips near `base`.
fn random_contents(
    rng: &mut impl Rng,
    forest: &Forest,
    base: &[BlockRef<D>],
    config: CodecConfig,
) -> Vec<(Participant, VoteContent<D>)> {
    let cap = config.window().cap();
    (0..config.view_quorum())
        .map(|index| {
            let tips = base
                .iter()
                .map(|base| forest.pick(rng, base, cap))
                .collect();
            (signer(index), content(tips, None, config))
        })
        .collect()
}

/// Random votes on `base`'s chain: each processor, present with probability `present`, casts a
/// number of tips drawn from `votes`.
fn random_pool(
    rng: &mut impl Rng,
    forest: &Forest,
    base: &BlockRef<D>,
    cap: u32,
    participants: usize,
    present: f64,
    votes: RangeInclusive<usize>,
) -> Vec<(Participant, BlockRef<D>)> {
    let mut pool = Vec::new();
    for index in 0..participants {
        if !rng.random_bool(present) {
            continue;
        }
        for _ in 0..rng.random_range(votes.clone()) {
            pool.push((signer(index), forest.pick(rng, base, cap)));
        }
    }
    pool
}

/// Returns the reference `Tips(Q)` of `contents` above `base`.
fn reference_tips(
    tree: &Tree<D>,
    base: &[BlockRef<D>],
    contents: &[(Participant, VoteContent<D>)],
    config: CodecConfig,
) -> Vec<BlockRef<D>> {
    base.iter()
        .enumerate()
        .map(|(chain, base)| {
            let votes = chain_votes(contents, chain);
            reference::tip(
                tree,
                base,
                config.window().cap(),
                config.tip_quorum(),
                &votes,
            )
        })
        .collect()
}

/// Checks `Tips(Q)`, `Det(G)`, the pool's final tip `b*`, and settledness over one random forest
/// against the reference.
pub(super) fn extraction(rng: &mut impl Rng) {
    let participants = [6, 11, 16][rng.random_range(0..3)];
    let chains = rng.random_range(1..=3);
    let cap = rng.random_range(2..=4u32);
    let config = config(participants, chains, cap);
    let forest = Forest::random(rng, chains, 8, 4);
    let tree = &forest.tree;
    let base = forest.base(rng);

    // Tips(Q) and Det(G) over n - f final votes, one per signer.
    let contents = random_contents(rng, &forest, &base, config);
    let expected = reference_tips(tree, &base, &contents, config);
    assert_eq!(tips(&base, &contents, config, tree).unwrap(), expected);
    let expected: Option<Vec<_>> = base
        .iter()
        .enumerate()
        .map(|(chain, base)| {
            let votes = chain_votes(&contents, chain);
            let expected = reference::determined(tree, base, cap, config.view_quorum(), &votes);
            // With exactly n - f votes, determination means every vote reaches alike.
            let reaches: BTreeSet<_> = votes
                .iter()
                .map(|(_, tip)| format!("{:?}", reach(base, cap, tip, tree)))
                .collect();
            assert_eq!(expected.is_some(), reaches.len() == 1);
            assert_eq!(determined(base, config, votes, tree), expected);
            expected
        })
        .collect();
    assert_eq!(det(&base, &contents, config, tree).unwrap(), expected);

    // Det(G) agrees with the V-QC recording G (the specification's Lemma det).
    if let Some(determined) = &expected {
        let paths = resolution_paths(tree, &base, &contents, config);
        let certificate = vqc(
            CertificateId::new(hash(b"parent")),
            &contents,
            paths,
            config,
        );
        let valid =
            validate_vqc::<Sha256, MinSig>(&certificate, hash(b"history"), &base, config).unwrap();
        assert_eq!(valid.record.tips(), determined.as_slice());
    }

    // TipsF and settledness over a pool with several votes per processor.
    for base in &base {
        let pool = random_pool(rng, &forest, base, cap, participants, 1.0, 0..=3);
        let expected = reference::tip(tree, base, cap, config.view_quorum(), &pool);
        let final_tip = final_tip(base, config, pool.iter().copied(), tree);
        assert_eq!(final_tip, expected);

        let mut first_binding = random_pool(rng, &forest, base, cap, participants, 0.9, 1..=2);
        if rng.random_bool(0.5) {
            // Most first binding votes stop at the final tip.
            for entry in first_binding.iter_mut() {
                if rng.random_bool(0.8) {
                    entry.1 = final_tip;
                }
            }
        }
        let expected = reference::settled(
            tree,
            base,
            &final_tip,
            cap,
            participants,
            config.settled_bound(),
            &first_binding,
        );
        let actual = settled(
            base,
            &final_tip,
            config,
            first_binding.iter().copied(),
            tree,
        );
        assert_eq!(actual.settled, expected);
        incremental_settledness(rng, &forest, base, final_tip, config, &first_binding);
    }
}

/// The forest with some blocks withheld: ancestry walks parents through held blocks only.
struct Withheld<'a> {
    tree: &'a Tree<D>,
    withheld: BTreeSet<BlockRef<D>>,
}

impl Ancestry<D> for Withheld<'_> {
    fn ancestor(&self, tip: &BlockRef<D>, height: Height) -> Option<BlockRef<D>> {
        for block in self.tree.lineage(tip) {
            if block.height() == height {
                return Some(block);
            }
            if self.withheld.contains(&block) {
                return None;
            }
        }
        None
    }
}

/// Checks that [`Bindings`], fed `first_binding` one vote at a time through an ancestry missing
/// some blocks and then retried on the whole forest, agrees with [`settled`] and the reference
/// on every prefix, against the base, `final_tip`, and another window block.
fn incremental_settledness(
    rng: &mut impl Rng,
    forest: &Forest,
    base: &BlockRef<D>,
    final_tip: BlockRef<D>,
    config: CodecConfig,
    first_binding: &[(Participant, BlockRef<D>)],
) {
    let tree = &forest.tree;
    let cap = config.window().cap();
    let partial = Withheld {
        tree,
        withheld: tree.blocks().filter(|_| rng.random_bool(0.1)).collect(),
    };
    let candidates = [*base, final_tip, forest.pick(rng, base, cap)];
    let mut tally = Bindings::new(*base, cap);
    let mut seen = BTreeSet::new();
    for (index, (signer, tip)) in first_binding.iter().enumerate() {
        if seen.insert(*signer) {
            tally.add(*tip, &partial);
        }
        let prefix = &first_binding[..=index];
        for candidate in &candidates {
            let expected = settled(base, candidate, config, prefix.iter().copied(), &partial);
            assert_eq!(tally.settledness(candidate, config, &partial), expected);
        }
    }
    let unresolved = tally.has_unresolved();
    assert_eq!(tally.retry(tree), unresolved);
    assert!(!tally.has_unresolved());
    for candidate in &candidates {
        let expected = reference::settled(
            tree,
            base,
            candidate,
            cap,
            config.participants(),
            config.settled_bound(),
            first_binding,
        );
        assert_eq!(tally.settledness(candidate, config, tree).settled, expected);
    }
}

/// Checks that a V-QC over random final votes with canonical resolution paths validates to the
/// reference `Tips(Q)`, and that its rebuilt paths answer ancestry like the forest.
pub(super) fn vqc_resolution(rng: &mut impl Rng) {
    let participants = [6, 11, 16][rng.random_range(0..3)];
    let chains = rng.random_range(1..=3);
    let cap = rng.random_range(2..=4u32);
    let config = config(participants, chains, cap);
    let forest = Forest::random(rng, chains, 8, 4);
    let tree = &forest.tree;
    let base = forest.base(rng);
    let contents = random_contents(rng, &forest, &base, config);
    let paths = resolution_paths(tree, &base, &contents, config);
    let certificate = vqc(
        CertificateId::new(hash(b"parent")),
        &contents,
        paths,
        config,
    );
    let parent_history = hash(b"history");
    let valid = validate_vqc::<Sha256, MinSig>(&certificate, parent_history, &base, config)
        .unwrap_or_else(|error| panic!("canonical V-QC is invalid: {error}"));
    let expected = reference_tips(tree, &base, &contents, config);
    assert_eq!(valid.record.tips(), expected.as_slice());
    assert_eq!(valid.record.parent(), parent_history);
    assert_eq!(valid.commitment, valid.record.commitment::<Sha256>());
    assert_eq!(valid.contents, certificate.contents());
    assert_eq!(valid.designated, None);

    for (_, content) in &contents {
        for (tip, base) in content.tips().iter().zip(&base) {
            if tip.height() <= base.height() {
                continue;
            }
            for height in base.height().get()..=tip.height().get() {
                let height = Height::new(height);
                assert_eq!(
                    valid.ancestry.ancestor(tip, height),
                    tree.ancestor(tip, height)
                );
            }
        }
    }
}

/// Checks `Horiz` over a random V-QC chain against the reference `Ord`, its length against the
/// output index, and the open view's `Sweep` against the reference sweep.
pub(super) fn order(rng: &mut impl Rng) {
    let chains = rng.random_range(1..=4);
    let cap = rng.random_range(1..=4u32);
    let forest = Forest::random(rng, chains, 12, 3);
    let tree = &forest.tree;

    // Ord over a V-QC chain: each view's tips extend the previous within the cap.
    let mut history = vec![forest.genesis.clone()];
    for _ in 0..rng.random_range(1..=4) {
        let last = history.last().unwrap();
        let next = last
            .iter()
            .map(|tip| forest.descendant(rng, tip, u64::from(cap)))
            .collect();
        history.push(next);
    }
    let mut ordered = Vec::new();
    for pair in history.windows(2) {
        for step in Horiz::new(&pair[0], &pair[1]).unwrap() {
            assert_eq!(step.chain, step.tip.chain());
            ordered.push(tree.ancestor(&step.tip, step.height).unwrap());
        }
    }
    assert_eq!(ordered, reference::ord(tree, &history));
    let output_index: u64 = history
        .last()
        .unwrap()
        .iter()
        .map(|tip| tip.height().get())
        .sum();
    assert_eq!(ordered.len() as u64, output_index);

    // The sweep of an open view.
    let base = history.last().unwrap();
    let finals: Vec<_> = base
        .iter()
        .map(|tip| forest.descendant(rng, tip, u64::from(cap)))
        .collect();
    let flags: Vec<_> = (0..chains).map(|_| rng.random_bool(0.5)).collect();
    let mut placed = Vec::new();
    let mut halted = false;
    for step in Sweep::new(base, &finals, &flags).unwrap() {
        assert!(!halted, "a sweep ends at its halt");
        match step {
            Step::Append(step) => placed.push(tree.ancestor(&step.tip, step.height).unwrap()),
            Step::Halt => halted = true,
        }
    }
    assert_eq!(
        (placed, halted),
        reference::sweep(tree, base, &finals, &flags)
    );
}

#[cfg(test)]
mod tests {
    use super::exercise;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn algebra_matches_reference(input in proptest::collection::vec(any::<u8>(), 0..256)) {
            exercise(&input);
        }
    }
}
