//! Differential tests of the extraction and ordering algebra against the naive reference, and
//! examples from the specification's extraction section.

use super::{
    fuzz::{self, D, EPOCH, Forest, ROUND, config, content, hash, signer, vqc},
    path::PathAncestry,
    reference,
    tips::determined,
    validate::ValidVqc,
    *,
};
use crate::{
    multimmit::types::{
        BlockRef, CertificateId, ChainId, ChainSet, CodecConfig, Endorsement, EpochGenesis,
        HistoryRecord, LeaderBlock, Lqc, ResolutionPath, VoteContent, VoteTally, Window,
    },
    types::{Epoch, Height, Participant, Round, View},
};
use commonware_cryptography::{
    Sha256,
    bls12381::primitives::{ops::aggregate, variant::MinSig},
};
use commonware_utils::TestRng;

const ITERATIONS: u64 = 300;

#[test]
fn quorum_extraction_matches_reference() {
    for seed in 0..ITERATIONS {
        fuzz::extraction(&mut TestRng::new(seed));
    }
}

#[test]
fn vqc_tips_match_reference() {
    for seed in 0..ITERATIONS {
        fuzz::vqc_resolution(&mut TestRng::new(seed));
    }
}

#[test]
fn order_matches_reference() {
    for seed in 0..ITERATIONS {
        fuzz::order(&mut TestRng::new(seed));
    }
}

// Paths.

#[test]
fn paths_rebuild_headers_and_resolve_targets() {
    let mut forest = Forest::new(2);
    let genesis = forest.genesis[1];
    let first = forest.extend(&genesis);
    let second = forest.extend(&first);
    let payloads = forest.tree.payloads(&genesis, &second).unwrap();

    let path = Path::rebuild::<Sha256>(EPOCH, genesis, &payloads).unwrap();
    assert_eq!(path.from(), genesis);
    assert_eq!(path.refs(), &[first, second]);
    assert_eq!(path.top(), second);
    assert_eq!(path.headers()[1].parent(), first.digest());
    assert_eq!(path.headers()[1].block_ref::<Sha256>(), second);
    assert_eq!(
        Path::rebuild::<Sha256>(EPOCH, genesis, &[]).unwrap().top(),
        genesis
    );

    assert_eq!(
        Path::resolve::<Sha256>(EPOCH, genesis, &payloads, &second).unwrap(),
        path
    );
    assert_eq!(
        Path::resolve::<Sha256>(EPOCH, genesis, &payloads, &first),
        Err(Error::PathTarget)
    );
    let elsewhere = BlockRef::new(ChainId::new(0), second.height(), second.digest());
    assert_eq!(
        Path::resolve::<Sha256>(EPOCH, genesis, &payloads, &elsewhere),
        Err(Error::PathTarget)
    );
    // Another epoch rebuilds other headers.
    assert_eq!(
        Path::resolve::<Sha256>(Epoch::new(4), genesis, &payloads, &second),
        Err(Error::PathTarget)
    );
    let highest = BlockRef::new(genesis.chain(), Height::new(u64::MAX), genesis.digest());
    assert_eq!(
        Path::rebuild::<Sha256>(EPOCH, highest, &payloads),
        Err(Error::HeightOverflow)
    );
}

#[test]
fn path_ancestry_walks_across_paths() {
    let mut forest = Forest::new(1);
    let genesis = forest.genesis[0];
    let mut lineage = vec![genesis];
    for _ in 0..5 {
        let top = *lineage.last().unwrap();
        lineage.push(forest.extend(&top));
    }
    let tree = &forest.tree;
    let rebuild = |from: BlockRef<D>, to: BlockRef<D>| {
        Path::rebuild::<Sha256>(EPOCH, from, &tree.payloads(&from, &to).unwrap()).unwrap()
    };
    let lower = rebuild(genesis, lineage[2]);
    let upper = rebuild(lineage[2], lineage[5]);
    let ancestry = PathAncestry::new(vec![upper.clone(), lower]);
    for (height, block) in lineage.iter().enumerate() {
        assert_eq!(
            ancestry.ancestor(&lineage[5], Height::new(height as u64)),
            Some(*block)
        );
    }
    assert!(ancestry.contains(&lineage[1]));
    assert!(!ancestry.contains(&genesis));
    assert_eq!(ancestry.ancestor(&lineage[3], Height::new(6)), None);
    let unknown = BlockRef::new(genesis.chain(), Height::new(3), hash(b"unknown"));
    assert_eq!(ancestry.ancestor(&unknown, Height::new(3)), Some(unknown));
    assert_eq!(ancestry.ancestor(&unknown, Height::new(2)), None);

    // Without the lower path the walk stops at the upper path's start.
    let ancestry = PathAncestry::new(vec![upper]);
    assert_eq!(
        ancestry.ancestor(&lineage[5], Height::new(2)),
        Some(lineage[2])
    );
    assert_eq!(ancestry.ancestor(&lineage[5], Height::new(1)), None);
}

#[test]
fn path_ancestry_tells_forks_apart() {
    let (forest, main, side) = branches(4, 1, 3);
    let genesis = main[0];
    let rebuild = |to: BlockRef<D>| {
        Path::rebuild::<Sha256>(
            EPOCH,
            genesis,
            &forest.tree.payloads(&genesis, &to).unwrap(),
        )
        .unwrap()
    };
    // The forks share main[1], which both paths rebuild.
    let ancestry = PathAncestry::new(vec![rebuild(main[4]), rebuild(side[4])]);
    assert_eq!(ancestry.holders(&main[1]), 2);
    for (fork, other) in [(&main, &side), (&side, &main)] {
        for height in 2..=4 {
            assert!(ancestry.contains(&fork[height]));
            assert_eq!(ancestry.holders(&fork[height]), 1);
            assert_ne!(fork[height], other[height]);
        }
        for height in 0..=4 {
            assert_eq!(
                ancestry.ancestor(&fork[4], Height::new(height as u64)),
                Some(fork[height])
            );
        }
    }
    let unknown = BlockRef::new(main[2].chain(), main[2].height(), hash(b"unknown"));
    assert!(!ancestry.contains(&unknown));
    assert_eq!(ancestry.holders(&unknown), 0);
    assert_eq!(ancestry.ancestor(&unknown, Height::new(1)), None);
}

// Examples of the specification's extraction section.

/// One chain with a trunk of `trunk` blocks and a fork of `fork` blocks above trunk height `at`.
fn branches(trunk: usize, at: usize, fork: usize) -> (Forest, Vec<BlockRef<D>>, Vec<BlockRef<D>>) {
    let mut forest = Forest::new(1);
    let mut main = vec![forest.genesis[0]];
    for _ in 0..trunk {
        let top = *main.last().unwrap();
        main.push(forest.extend(&top));
    }
    let mut side = main[..=at].to_vec();
    for _ in 0..fork {
        let top = *side.last().unwrap();
        side.push(forest.extend(&top));
    }
    (forest, main, side)
}

/// Assigns consecutive signers to `count` copies of each tip, in order.
fn votes(groups: &[(usize, BlockRef<D>)]) -> Vec<(Participant, BlockRef<D>)> {
    groups
        .iter()
        .flat_map(|(count, tip)| std::iter::repeat_n(*tip, *count))
        .enumerate()
        .map(|(index, tip)| (signer(index), tip))
        .collect()
}

/// Single-chain final votes with the given tips.
fn contents_of(
    votes: &[(Participant, BlockRef<D>)],
    config: CodecConfig,
) -> Vec<(Participant, VoteContent<D>)> {
    votes
        .iter()
        .map(|(signer, tip)| (*signer, content(vec![*tip], None, config)))
        .collect()
}

#[test]
fn incompatible_blocks_split_the_tip_quorum() {
    // n = 11, f = 2: a V-QC holds 9 votes and a tip needs 5.
    let config = config(11, 1, 4);
    let (forest, main, side) = branches(4, 1, 3);
    let tree = &forest.tree;
    let base = [main[0]];

    let majority = contents_of(&votes(&[(5, main[3]), (4, side[3])]), config);
    assert_eq!(tips(&base, &majority, config, tree).unwrap(), vec![main[3]]);

    // Neither branch reaches 5: the tip is their common ancestor, which 8 endorse.
    let split = contents_of(&votes(&[(4, main[3]), (4, side[3]), (1, main[0])]), config);
    assert_eq!(tips(&base, &split, config, tree).unwrap(), vec![main[1]]);

    // Votes on a branch that leaves below the base endorse nothing in its window.
    let (forest, main, side) = branches(4, 0, 3);
    let tree = &forest.tree;
    let base = [main[1]];
    let off = contents_of(&votes(&[(4, main[3]), (5, side[3])]), config);
    assert_eq!(tips(&base, &off, config, tree).unwrap(), vec![main[1]]);
    assert_eq!(reach(&main[1], 4, &side[3], tree), Reach::Outside);
    assert_eq!(reach(&main[1], 4, &main[1], tree), Reach::Outside);
    assert_eq!(reach(&main[1], 1, &main[3], tree), Reach::Top(main[2]));
    let unknown = BlockRef::new(main[0].chain(), Height::new(3), hash(b"unknown"));
    assert_eq!(reach(&main[1], 4, &unknown, tree), Reach::Unresolved);
}

#[test]
fn determination_requires_no_final_beyond() {
    // n = 6, f = 1: G holds 5 final votes and the target needs all 5.
    let config = config(6, 1, 3);
    let (forest, main, side) = branches(5, 2, 2);
    let tree = &forest.tree;
    let base = main[0];

    // Every vote endorses the N-th block: determined there under the cap, even with tips beyond.
    let capped = votes(&[(3, main[3]), (2, main[5])]);
    assert_eq!(determined(&base, config, capped, tree), Some(main[3]));

    // A chain declared short of the cap is determined at the common tip...
    let short = votes(&[(5, main[1])]);
    assert_eq!(determined(&base, config, short, tree), Some(main[1]));

    // ...but one final vote beyond it, even a faulty one, leaves the chain undetermined.
    let beyond = votes(&[(4, main[1]), (1, main[2])]);
    assert_eq!(determined(&base, config, beyond.clone(), tree), None);
    let beyond = contents_of(&beyond, config);
    assert_eq!(tips(&[base], &beyond, config, tree).unwrap(), vec![main[1]]);

    // A vote on a conflicting branch above the target also leaves it undetermined.
    let conflicting = votes(&[(4, main[3]), (1, side[4])]);
    assert_eq!(determined(&base, config, conflicting, tree), None);

    // Nothing above the base: determined at the base.
    assert_eq!(
        determined(&base, config, votes(&[(5, base)]), tree),
        Some(base)
    );

    // An unresolvable vote leaves the chain undetermined.
    let unknown = BlockRef::new(base.chain(), Height::new(2), hash(b"unknown"));
    let unresolved = votes(&[(4, main[1]), (1, unknown)]);
    assert_eq!(determined(&base, config, unresolved, tree), None);
}

#[test]
fn final_tip_counts_processors_once() {
    // n = 6, f = 1: b* needs 5 distinct processors.
    let config = config(6, 1, 3);
    let (forest, main, side) = branches(4, 1, 2);
    let tree = &forest.tree;
    let base = main[0];

    // Four processors on the trunk; a fifth endorses the trunk through one of its two votes.
    let mut pool = votes(&[(4, main[3])]);
    pool.push((signer(4), side[3]));
    pool.push((signer(4), main[2]));
    pool.push((signer(0), side[3]));
    assert_eq!(final_tip(&base, config, pool, tree), main[2]);

    // Repeating a processor's votes adds nothing.
    let mut repeated = votes(&[(4, main[3])]);
    repeated.extend([(signer(0), main[3]), (signer(1), main[3])]);
    assert_eq!(final_tip(&base, config, repeated, tree), base);
}

#[test]
fn settledness_bound_at_the_fault_limit() {
    // The bound n - 4f - 1 is f at n = 5f + 1 and 13 at n = 50, f = 9.
    for (participants, bound) in [(6, 1), (11, 2), (50, 13)] {
        let config = config(participants, 1, 4);
        assert_eq!(config.settled_bound(), bound);
        let (forest, main, _) = branches(5, 0, 0);
        let tree = &forest.tree;
        let base = main[0];
        let final_tip = main[2];

        // `stopped` processors bind at b*, `beyond` endorse above it, the rest are unseen.
        let check = |stopped: usize, beyond: usize| {
            let first_binding = votes(&[(stopped, final_tip), (beyond, main[4])]);
            let counts = settled(&base, &final_tip, config, first_binding.clone(), tree);
            let expected = reference::settled(
                tree,
                &base,
                &final_tip,
                4,
                participants,
                bound,
                &first_binding,
            );
            assert_eq!(counts.settled, expected);
            assert_eq!(counts.bound, stopped + beyond);
            assert_eq!(counts.beyond, beyond);
            counts.settled
        };
        // Everyone bound: at most `bound` may still endorse beyond b*.
        assert!(check(participants - bound, bound));
        assert!(!check(participants - bound - 1, bound + 1));
        // An unseen processor counts like one that endorses beyond.
        assert!(check(participants - bound, 0));
        assert!(!check(participants - bound - 1, 0));
        assert!(check(participants - bound, bound - 1));
        assert!(!check(participants - bound - 1, bound));
    }
}

#[test]
fn settledness_reads_first_binding_votes_conservatively() {
    let config = config(6, 1, 4);
    let (forest, main, side) = branches(5, 1, 3);
    let tree = &forest.tree;
    let base = main[0];
    let final_tip = main[2];

    // A later entry of a signer is ignored: only its first binding vote counts.
    let mut first_binding = votes(&[(6, final_tip)]);
    first_binding.push((signer(0), main[4]));
    first_binding.push((signer(1), main[4]));
    assert!(settled(&base, &final_tip, config, first_binding, tree).settled);

    // A branch forking below b* does not extend it, even above b*'s height.
    let conflicting = votes(&[(4, final_tip), (2, side[4])]);
    let counts = settled(&base, &final_tip, config, conflicting, tree);
    assert_eq!(counts.beyond, 0);
    assert!(counts.settled);

    // A vote the ancestry cannot place counts as endorsing beyond.
    let unknown = BlockRef::new(base.chain(), Height::new(3), hash(b"unknown"));
    let unresolved = votes(&[(4, final_tip), (2, unknown)]);
    let counts = settled(&base, &final_tip, config, unresolved, tree);
    assert_eq!(counts.beyond, 2);
    assert!(!counts.settled);
}

#[test]
fn binding_votes() {
    let config = config(6, 2, 3);
    let (_, main, _) = branches(4, 0, 0);
    let base = main[0];
    let other = EpochGenesis::<D>::new::<Sha256>(EPOCH, 2).unwrap().tips()[1];
    let chain = ChainId::new(0);
    let vote = |tip: BlockRef<D>, final_: bool, declared: bool| {
        let declared = ChainSet::from_chains(2, declared.then_some(chain)).unwrap();
        let endorsement = Endorsement::new(declared, vec![tip, other], config).unwrap();
        VoteContent::new(ROUND, None, final_, endorsement).unwrap()
    };
    assert!(!binding(
        &vote(main[2], false, false),
        chain,
        Some(&base),
        3
    ));
    assert!(binding(&vote(main[2], true, false), chain, Some(&base), 3));
    assert!(binding(&vote(main[2], false, true), chain, Some(&base), 3));
    assert!(binding(&vote(main[3], false, false), chain, Some(&base), 3));
    assert!(!binding(
        &vote(main[2], false, true),
        ChainId::new(1),
        Some(&other),
        3
    ));
    // Before the base is resolved, a capped tip does not bind; finality and declaration do.
    assert!(!binding(&vote(main[3], false, false), chain, None, 3));
    assert!(binding(&vote(main[3], true, false), chain, None, 3));
    assert!(binding(&vote(main[3], false, true), chain, None, 3));
}

#[test]
fn horizontal_order_examples() {
    let mut forest = Forest::new(3);
    let mut lines = Vec::new();
    for chain in 0..3 {
        let mut line = vec![forest.genesis[chain]];
        for _ in 0..3 {
            let top = *line.last().unwrap();
            line.push(forest.extend(&top));
        }
        lines.push(line);
    }
    let from = vec![lines[0][0], lines[1][1], lines[2][0]];
    let to = vec![lines[0][2], lines[1][1], lines[2][1]];
    let order: Vec<_> = Horiz::new(&from, &to)
        .unwrap()
        .map(|step| (step.chain.get(), step.height.get()))
        .collect();
    assert_eq!(order, vec![(0, 1), (2, 1), (0, 2)]);
    assert_eq!(Horiz::new(&from, &from).unwrap().count(), 0);
    assert_eq!(
        Horiz::new(&to, &from).err(),
        Some(Error::Regression(ChainId::new(0)))
    );
    assert_eq!(Horiz::new(&from, &to[..2]).err(), Some(Error::ChainOrder));
    let swapped = vec![to[1], to[0], to[2]];
    assert_eq!(Horiz::new(&from, &swapped).err(), Some(Error::ChainOrder));

    // The sweep places chain 0 up to offset 3, skips settled chain 1, and halts at chain 2.
    let finals = vec![lines[0][3], lines[1][1], lines[2][1]];
    let steps: Vec<_> = Sweep::new(&from, &finals, &[false, true, false])
        .unwrap()
        .map(|step| match step {
            Step::Append(step) => Some((step.chain.get(), step.height.get())),
            Step::Halt => None,
        })
        .collect();
    assert_eq!(steps, vec![Some((0, 1)), Some((2, 1)), Some((0, 2)), None]);
    // With chain 2 settled the sweep runs to the last final offset without halting.
    let steps: Vec<_> = Sweep::new(&from, &finals, &[false, true, true])
        .unwrap()
        .map(|step| match step {
            Step::Append(step) => (step.chain.get(), step.height.get()),
            Step::Halt => panic!("settled chains never halt"),
        })
        .collect();
    assert_eq!(steps, vec![(0, 1), (2, 1), (0, 2), (0, 3)]);
    assert_eq!(
        Sweep::new(&from, &finals, &[true]).err(),
        Some(Error::ChainOrder)
    );
}

// V-QC validation.

/// A two-chain V-QC fixture over n = 6 (5 votes, tip quorum 3) with its base at genesis, a trunk
/// `main` on chain 0, and a branch `side` forking at `main[1]`.
struct Fixture {
    config: CodecConfig,
    forest: Forest,
    base: Vec<BlockRef<D>>,
    main: Vec<BlockRef<D>>,
    side: Vec<BlockRef<D>>,
    parent: CertificateId<D>,
    history: D,
}

impl Fixture {
    fn new() -> Self {
        let mut forest = Forest::new(2);
        let base = forest.genesis.clone();
        let mut main = vec![base[0]];
        for _ in 0..4 {
            let top = *main.last().unwrap();
            main.push(forest.extend(&top));
        }
        let mut side = main[..=1].to_vec();
        for _ in 0..2 {
            let top = *side.last().unwrap();
            side.push(forest.extend(&top));
        }
        Self {
            config: config(6, 2, 3),
            forest,
            base,
            main,
            side,
            parent: CertificateId::new(hash(b"parent")),
            history: hash(b"history"),
        }
    }

    /// Five final votes with chain-0 tips `tips`, chain 1 at genesis, and leaders by signer.
    fn contents(
        &self,
        tips: [BlockRef<D>; 5],
        leader: impl Fn(usize) -> Option<D>,
    ) -> Vec<(Participant, VoteContent<D>)> {
        tips.iter()
            .enumerate()
            .map(|(index, tip)| {
                let content = content(vec![*tip, self.base[1]], leader(index), self.config);
                (signer(index), content)
            })
            .collect()
    }

    fn path(&self, from: BlockRef<D>, tip: BlockRef<D>) -> ResolutionPath<D> {
        let payloads = self.forest.tree.payloads(&from, &tip).unwrap();
        ResolutionPath::new(from, payloads, self.config).unwrap()
    }

    fn validate(
        &self,
        contents: &[(Participant, VoteContent<D>)],
        paths: Vec<ResolutionPath<D>>,
    ) -> Result<ValidVqc<D>, Error> {
        let certificate = vqc(self.parent, contents, paths, self.config);
        validate_vqc::<Sha256, MinSig>(&certificate, self.history, &self.base, self.config)
    }
}

#[test]
fn vqc_validation_accepts_canonical_paths() {
    let fixture = Fixture::new();
    let (main, side, base) = (&fixture.main, &fixture.side, fixture.base[0]);
    let contents = fixture.contents([main[3], main[3], main[2], side[3], main[4]], |_| None);
    let paths = vec![fixture.path(base, main[4]), fixture.path(base, side[3])];
    let valid = fixture.validate(&contents, paths).unwrap();
    let tips = vec![main[3], fixture.base[1]];
    let record = HistoryRecord::new(fixture.history, tips).unwrap();
    assert_eq!(valid.commitment, record.commitment::<Sha256>());
    assert_eq!(valid.record, record);
}

#[test]
fn vqc_validation_rejects_malformed_paths() {
    let fixture = Fixture::new();
    let (main, side, base) = (&fixture.main, &fixture.side, fixture.base[0]);
    let contents = fixture.contents([main[3], main[3], main[3], side[3], main[2]], |_| None);
    let canonical = || vec![fixture.path(base, main[3]), fixture.path(base, side[3])];
    assert!(fixture.validate(&contents, canonical()).is_ok());

    // A recorded tip above the base without a path.
    assert_eq!(
        fixture
            .validate(&contents, vec![fixture.path(base, main[3])])
            .err(),
        Some(Error::Unresolved(ChainId::new(0)))
    );
    // A path that does not start at the base height.
    let shifted = vec![fixture.path(main[1], main[3]), fixture.path(base, side[3])];
    assert_eq!(
        fixture.validate(&contents, shifted).err(),
        Some(Error::PathHeight(ChainId::new(0)))
    );
    // A path whose top lies on another path.
    let mut redundant = canonical();
    redundant.push(fixture.path(base, main[2]));
    assert_eq!(
        fixture.validate(&contents, redundant).err(),
        Some(Error::RedundantPath(ChainId::new(0)))
    );
    // A path that ends at no recorded tip.
    let mut unused = canonical();
    let payload = hash(b"payload");
    unused.push(ResolutionPath::new(base, vec![payload], fixture.config).unwrap());
    assert_eq!(
        fixture.validate(&contents, unused).err(),
        Some(Error::UnusedPath(ChainId::new(0)))
    );
    let mut other_chain = canonical();
    other_chain.push(ResolutionPath::new(fixture.base[1], vec![payload], fixture.config).unwrap());
    assert_eq!(
        fixture.validate(&contents, other_chain).err(),
        Some(Error::UnusedPath(ChainId::new(1)))
    );
}

#[test]
fn vqc_paths_from_other_objects_endorse_nothing() {
    // With the base at main[2], votes on the side branch (forked at main[1]) resolve to side[2],
    // not the base, at the base height.
    let mut fixture = Fixture::new();
    let (main, side) = (fixture.main.clone(), fixture.side.clone());
    fixture.base[0] = main[2];
    let contents = fixture.contents([side[3], side[3], side[3], main[3], main[4]], |_| None);
    let paths = vec![
        fixture.path(side[2], side[3]),
        fixture.path(main[2], main[4]),
    ];
    let valid = fixture.validate(&contents, paths).unwrap();
    assert_eq!(valid.record.tips()[0], main[2]);

    // A tip on the side branch at the base height endorses nothing either and needs no path.
    let contents = fixture.contents([side[2], side[2], main[3], main[3], main[3]], |_| None);
    let valid = fixture
        .validate(&contents, vec![fixture.path(main[2], main[3])])
        .unwrap();
    assert_eq!(valid.record.tips()[0], main[3]);
}

#[test]
fn vqc_designation_forces_the_parent() {
    let fixture = Fixture::new();
    let main = &fixture.main;
    let leader = LeaderBlock::new(ROUND, fixture.parent, fixture.history)
        .unwrap()
        .digest::<Sha256>();
    let tips = [main[1]; 5];
    let paths = || vec![fixture.path(fixture.base[0], main[1])];

    // Three of five votes (n - 3f) for the leader block designate it.
    let designating = fixture.contents(tips, |index| (index < 3).then_some(leader));
    let valid = fixture.validate(&designating, paths()).unwrap();
    assert_eq!(valid.designated, Some(leader));

    // Two votes designate nothing, whatever they name.
    let other = hash(b"other leader");
    let undesignated = fixture.contents(tips, |index| (index < 2).then_some(other));
    assert_eq!(
        fixture.validate(&undesignated, paths()).unwrap().designated,
        None
    );

    // A designated block naming another parent, history, or round is malformed.
    for wrong in [
        LeaderBlock::new(ROUND, CertificateId::new(other), fixture.history).unwrap(),
        LeaderBlock::new(ROUND, fixture.parent, other).unwrap(),
        LeaderBlock::new(
            Round::new(EPOCH, View::new(6)),
            fixture.parent,
            fixture.history,
        )
        .unwrap(),
    ] {
        let wrong = wrong.digest::<Sha256>();
        let contents = fixture.contents(tips, |index| (index < 3).then_some(wrong));
        assert_eq!(
            fixture.validate(&contents, paths()).err(),
            Some(Error::Designation)
        );
    }
}

#[test]
fn vqc_validation_checks_the_base_vector() {
    let fixture = Fixture::new();
    let contents = fixture.contents([fixture.base[0]; 5], |_| None);
    let certificate = vqc(fixture.parent, &contents, Vec::new(), fixture.config);
    let validate = |base: &[BlockRef<D>]| {
        validate_vqc::<Sha256, MinSig>(&certificate, fixture.history, base, fixture.config).err()
    };
    assert_eq!(validate(&fixture.base[..1]), Some(Error::ChainOrder));
    assert_eq!(
        validate(&[fixture.base[1], fixture.base[0]]),
        Some(Error::ChainOrder)
    );
    assert_eq!(validate(&fixture.base), None);
}

// Finalization certificates.

fn lqc(history: D, config: CodecConfig) -> Lqc<MinSig, D> {
    let parent = CertificateId::new(hash(b"parent"));
    let leader = LeaderBlock::new(ROUND, parent, history).unwrap();
    let digest = leader.digest::<Sha256>();
    let genesis = EpochGenesis::<D>::new::<Sha256>(EPOCH, config.chains()).unwrap();
    let endorsement = Endorsement::new(
        ChainSet::empty(config.chains()),
        genesis.tips().to_vec(),
        config,
    )
    .unwrap();
    let contents = (0..config.view_quorum()).map(|index| {
        let content = VoteContent::new(ROUND, Some(digest), index == 0, endorsement.clone());
        (signer(index), content.unwrap())
    });
    let tally = VoteTally::from_contents(digest, contents, config).unwrap();
    Lqc::new(leader, tally, aggregate::Signature::zero())
}

fn opening(heights: [u64; 2]) -> HistoryRecord<D> {
    let tips = heights
        .iter()
        .enumerate()
        .map(|(chain, height)| {
            let digest = hash(&chain.to_le_bytes());
            BlockRef::new(ChainId::new(chain as u32), Height::new(*height), digest)
        })
        .collect();
    HistoryRecord::new(hash(b"grandparent"), tips).unwrap()
}

#[test]
fn floor_validation() {
    let config = config(6, 2, 3);
    let opening = opening([7, 5]);
    let certificate = lqc(opening.commitment::<Sha256>(), config);
    let validate = |opening: &HistoryRecord<D>, epoch: Epoch, config: CodecConfig| {
        validate_floor::<Sha256, MinSig>(&certificate, opening, epoch, config)
    };
    assert_eq!(validate(&opening, EPOCH, config), Ok(12));

    // The opening must hash to the leader block's history.
    let other = HistoryRecord::new(hash(b"other"), opening.tips().to_vec()).unwrap();
    assert_eq!(validate(&other, EPOCH, config), Err(Error::History));
    // The leader block must belong to the expected epoch.
    assert_eq!(validate(&opening, Epoch::new(4), config), Err(Error::Epoch));
    // The opening must cover every chain of the epoch.
    let wider = CodecConfig::new(6, 3, Window::new(3).unwrap()).unwrap();
    assert_eq!(validate(&opening, EPOCH, wider), Err(Error::ChainOrder));
    // The certificate must hold n - f signers of the epoch's committee.
    let larger = CodecConfig::new(7, 2, Window::new(3).unwrap()).unwrap();
    assert_eq!(validate(&opening, EPOCH, larger), Err(Error::Quorum));

    // The resume index must fit a u64.
    let huge = self::opening([u64::MAX, 1]);
    let certificate = lqc(huge.commitment::<Sha256>(), config);
    assert_eq!(
        validate_floor::<Sha256, MinSig>(&certificate, &huge, EPOCH, config),
        Err(Error::IndexOverflow)
    );
}
