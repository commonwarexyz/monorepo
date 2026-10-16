//! One view's votes over real producer headers, measured by the signature and algebra benchmarks.

use crate::{
    multimmit::{
        algebra::{self, Ancestry as _, Horiz, Sweep},
        mocks::{Certified, Committee, Scenario},
        scheme::bls12381::{Scheme, SignatureVerification},
        types::{
            Attestation, BlockRef, CertificateId, LeaderBlock, Lqc, ResolutionPath, VoteContent,
            Vqc,
        },
    },
    types::{Height, Participant},
};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::Variant, ed25519, sha256::Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::test_rng;
use core::fmt;

/// Namespace the benchmark committee signs under.
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_BENCH";

/// The benchmark committee seed.
const SEED: u64 = 9;

/// Heights each chain's main branch runs past the window above the base.
const LEAD: u64 = 2;

/// Heights of each chain's fork above the base.
const FORK: u64 = 2;

/// One final vote with its signer's attestation, as certificate assembly consumes it.
pub type AttestedVote<V> = (VoteContent<Digest>, Attestation<V>);

/// How the votes of a [`ViewScenario`] spread over the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoteShape {
    /// Every vote endorses the top of the window on every chain: one distinct content, and every
    /// chain is determined.
    Agreeing,
    /// Votes endorse staggered heights of each chain's main branch, except that each voter
    /// endorses the base on its own chain and the last `f` voters endorse a fork on every other
    /// chain: every content is distinct, and no chain is determined.
    Staggered,
}

impl VoteShape {
    /// Every shape, in benchmark order.
    pub const ALL: [Self; 2] = [Self::Agreeing, Self::Staggered];
}

impl fmt::Display for VoteShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Agreeing => "agreeing",
            Self::Staggered => "staggered",
        })
    }
}

/// The second view of an epoch in which every validator produces one chain.
///
/// The first view's V-QC fixes a base `N` blocks above genesis on every chain. Above it each chain
/// has a main branch running past the window and a short fork, and `n - f` validators vote for the
/// second view's leader block, finally and not, endorsing tips placed by a [`VoteShape`]. The
/// scenario holds the certificates those votes form and every input the extraction algebra reads.
pub struct ViewScenario<V: Variant> {
    scenario: Scenario<V>,
    parent: Certified<V>,
    leader: LeaderBlock<Digest>,
    finals: Vec<AttestedVote<V>>,
    votes: Vec<AttestedVote<V>>,
    contents: Vec<(Participant, VoteContent<Digest>)>,
    paths: Vec<ResolutionPath<Digest>>,
    vqc: Vqc<V, Digest>,
    lqc: Lqc<V, Digest>,
    /// `Tips(Q)` of [`Self::vqc`], the target of [`Self::horiz`].
    resolved: Vec<BlockRef<Digest>>,
    /// The pool's final tips and settledness, the inputs of [`Self::sweep`].
    pool_finals: Vec<BlockRef<Digest>>,
    pool_settled: Vec<bool>,
}

impl<V: Variant> ViewScenario<V> {
    /// Builds the scenario for a committee of `participants` with votes shaped by `shape`.
    pub fn new(participants: u32, shape: VoteShape) -> Self {
        let committee = Committee::<V>::builder(SEED, participants)
            .namespace(NAMESPACE)
            .build();
        let config = committee.codec();
        let cap = u64::from(config.window().cap());
        let mut scenario = Scenario::new(committee);
        let genesis = scenario.genesis();
        let base = scenario.extend_all(genesis.tips(), cap);
        let parent = scenario.advance(&genesis, &base);
        let main = scenario.extend_all(&base, cap + LEAD);
        let forks = scenario.extend_all(&base, FORK);

        let voters = config.view_quorum();
        let honest = voters - config.max_faults();
        let tips = |signer: usize| -> Vec<BlockRef<Digest>> {
            base.iter()
                .zip(&main)
                .zip(&forks)
                .enumerate()
                .map(|(chain, ((base, main), fork))| {
                    let offset = match shape {
                        VoteShape::Agreeing => cap,
                        VoteShape::Staggered if chain == signer => return *base,
                        VoteShape::Staggered if signer >= honest && chain % 2 == 0 => {
                            return *fork;
                        }
                        VoteShape::Staggered => 1 + (signer + chain) as u64 % (cap + LEAD),
                    };
                    let height = Height::new(base.height().get() + offset);
                    scenario
                        .ancestor(main, height)
                        .expect("main branch is held")
                })
                .collect()
        };
        let ballot = |final_: bool| -> Vec<(Participant, VoteContent<Digest>)> {
            (0..voters)
                .map(|signer| {
                    let content = scenario.vote(&parent, final_, &tips(signer));
                    (Participant::from_usize(signer), content)
                })
                .collect()
        };
        let contents = ballot(true);
        let committee = scenario.committee();
        let finals = committee.attested(contents.clone());
        let votes = committee.attested(ballot(false));
        let paths = scenario.resolution_paths(parent.tips(), &contents);
        let leader = scenario.leader_block(&parent).block().clone();
        let vqc = committee
            .verifier
            .assemble_vqc(
                &mut test_rng(),
                parent.id(),
                &finals,
                paths.clone(),
                SignatureVerification::Preverified,
                &Sequential,
            )
            .expect("final votes form a V-QC");
        let lqc = committee
            .verifier
            .assemble_lqc::<_, Sha256, _>(
                &mut test_rng(),
                leader.clone(),
                &votes,
                SignatureVerification::Preverified,
                &Sequential,
            )
            .expect("votes form an L-QC");

        let resolved = vqc_tips(&scenario, parent.tips(), &contents);
        let pool_finals = final_tips(&scenario, parent.tips(), &contents);
        let pool_settled = settled(&scenario, parent.tips(), &pool_finals, &contents);
        Self {
            scenario,
            parent,
            leader,
            finals,
            votes,
            contents,
            paths,
            vqc,
            lqc,
            resolved,
            pool_finals,
            pool_settled,
        }
    }

    /// Returns the committee.
    pub const fn committee(&self) -> &Committee<V> {
        self.scenario.committee()
    }

    /// Returns the committee's keyless verifier.
    pub const fn verifier(&self) -> &Scheme<ed25519::PublicKey, V> {
        &self.committee().verifier
    }

    /// Returns the identifier of the first view's V-QC, which the view's V-QC extends.
    pub const fn parent(&self) -> CertificateId<Digest> {
        self.parent.id()
    }

    /// Returns the view's leader block.
    pub const fn leader(&self) -> &LeaderBlock<Digest> {
        &self.leader
    }

    /// Returns the `n - f` attested final votes for the leader block.
    pub fn finals(&self) -> &[AttestedVote<V>] {
        &self.finals
    }

    /// Returns the `n - f` attested non-final votes for the leader block.
    pub fn votes(&self) -> &[AttestedVote<V>] {
        &self.votes
    }

    /// Returns the final votes' contents with their signers, in signer order.
    pub fn contents(&self) -> &[(Participant, VoteContent<Digest>)] {
        &self.contents
    }

    /// Returns the resolution paths of the final votes' tips above the base.
    pub fn paths(&self) -> &[ResolutionPath<Digest>] {
        &self.paths
    }

    /// Returns the V-QC of the final votes.
    pub const fn vqc(&self) -> &Vqc<V, Digest> {
        &self.vqc
    }

    /// Returns the L-QC of the non-final votes.
    pub const fn lqc(&self) -> &Lqc<V, Digest> {
        &self.lqc
    }

    /// Computes `Tips(Q)` of the view's V-QC from the held headers.
    pub fn tips(&self) -> Vec<BlockRef<Digest>> {
        vqc_tips(&self.scenario, self.parent.tips(), &self.contents)
    }

    /// Computes the pool's final tip `b*` on every chain, the pool holding the final votes.
    pub fn final_tips(&self) -> Vec<BlockRef<Digest>> {
        final_tips(&self.scenario, self.parent.tips(), &self.contents)
    }

    /// Computes whether every chain is settled given the pool's final tips, each final vote being
    /// its signer's first binding vote.
    pub fn settled(&self) -> Vec<bool> {
        settled(
            &self.scenario,
            self.parent.tips(),
            &self.pool_finals,
            &self.contents,
        )
    }

    /// Computes `Det(G)` of the final votes.
    pub fn det(&self) -> Option<Vec<BlockRef<Digest>>> {
        algebra::det(
            self.parent.tips(),
            &self.contents,
            self.committee().codec(),
            &self.scenario,
        )
        .expect("base is one tip per chain")
    }

    /// Checks the view's V-QC against its parent and returns its tips-history commitment.
    pub fn validate(&self) -> Digest {
        algebra::validate_vqc::<Sha256, V>(
            &self.vqc,
            self.parent.commitment(),
            self.parent.tips(),
            self.committee().codec(),
        )
        .expect("V-QC is well formed")
        .commitment
    }

    /// Returns the number of blocks `Horiz(base, Tips(Q))` places.
    pub fn horiz(&self) -> usize {
        Horiz::new(self.parent.tips(), &self.resolved)
            .expect("tips extend the base")
            .count()
    }

    /// Returns the number of steps the view's sweep over `b*` takes.
    pub fn sweep(&self) -> usize {
        Sweep::new(self.parent.tips(), &self.pool_finals, &self.pool_settled)
            .expect("final tips extend the base")
            .count()
    }
}

/// Computes `Tips(Q)` of the V-QC recording `contents` above `base`.
fn vqc_tips<V: Variant>(
    scenario: &Scenario<V>,
    base: &[BlockRef<Digest>],
    contents: &[(Participant, VoteContent<Digest>)],
) -> Vec<BlockRef<Digest>> {
    algebra::tips(base, contents, scenario.committee().codec(), scenario)
        .expect("base is one tip per chain")
}

/// Computes the pool's final tip `b*` above every chain of `base` for a pool holding `contents`.
fn final_tips<V: Variant>(
    scenario: &Scenario<V>,
    base: &[BlockRef<Digest>],
    contents: &[(Participant, VoteContent<Digest>)],
) -> Vec<BlockRef<Digest>> {
    let config = scenario.committee().codec();
    base.iter()
        .map(|base| algebra::final_tip(base, config, chain_tips(base, contents), scenario))
        .collect()
}

/// Computes the settledness of every chain of `base` given its final tip `finals`, each of
/// `contents` being its signer's first binding vote.
fn settled<V: Variant>(
    scenario: &Scenario<V>,
    base: &[BlockRef<Digest>],
    finals: &[BlockRef<Digest>],
    contents: &[(Participant, VoteContent<Digest>)],
) -> Vec<bool> {
    let config = scenario.committee().codec();
    base.iter()
        .zip(finals)
        .map(|(base, final_tip)| {
            algebra::settled(
                base,
                final_tip,
                config,
                chain_tips(base, contents),
                scenario,
            )
            .settled
        })
        .collect()
}

/// Returns every content's tip on `base`'s chain with its signer.
fn chain_tips<'a>(
    base: &BlockRef<Digest>,
    contents: &'a [(Participant, VoteContent<Digest>)],
) -> impl Iterator<Item = (Participant, BlockRef<Digest>)> + 'a {
    let chain = base.chain().index();
    contents
        .iter()
        .map(move |(signer, content)| (*signer, content.tips()[chain]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use std::collections::HashSet;

    #[test]
    fn agreeing_votes_determine_and_settle_every_chain() {
        let view = ViewScenario::<MinPk>::new(6, VoteShape::Agreeing);
        let top = view.contents()[0].1.tips().to_vec();
        assert_eq!(view.tips(), top);
        assert_eq!(view.det(), Some(top.clone()));
        assert_eq!(view.final_tips(), top);
        assert!(view.settled().iter().all(|settled| *settled));
        assert_eq!(view.vqc().tally().deviations().len(), 0);
        assert_eq!(view.horiz(), 4 * 6);
        check_certificates(&view);
    }

    /// The benchmarked sizes must see one distinct content per voter.
    #[test]
    fn staggered_votes_are_distinct_and_undetermined() {
        for participants in [6, 31, 50] {
            let view = ViewScenario::<MinPk>::new(participants, VoteShape::Staggered);
            let voters = view.committee().codec().view_quorum();
            let distinct: HashSet<_> = view.contents().iter().map(|(_, content)| content).collect();
            assert_eq!(distinct.len(), voters);
            assert_eq!(view.vqc().tally().deviations().len(), voters - 1);
            assert_eq!(view.det(), None);

            let base = view.parent.tips();
            let above = |tips: &[BlockRef<Digest>]| {
                tips.iter()
                    .zip(base)
                    .filter(|(tip, base)| tip.height() > base.height())
                    .count()
            };
            assert_eq!(above(&view.tips()), base.len());
            assert!(above(&view.final_tips()) > 0);
            assert!(view.horiz() > view.sweep());
            check_certificates(&view);
        }
    }

    fn check_certificates(view: &ViewScenario<MinPk>) {
        let verifier = view.verifier();
        assert!(verifier.verify_vqc(&mut test_rng(), view.vqc(), &Sequential));
        assert!(verifier.verify_lqc::<_, Sha256, _>(&mut test_rng(), view.lqc(), &Sequential));
        let certified = view.scenario.certify(&view.parent, view.contents.clone());
        assert_eq!(view.validate(), certified.commitment());
        assert_eq!(view.tips(), certified.tips());
    }
}
