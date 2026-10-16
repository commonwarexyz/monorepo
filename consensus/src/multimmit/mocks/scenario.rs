//! Producer chains and V-QC lineages built on a [`Committee`].
//!
//! A [`Scenario`] holds every producer-signed header it creates and certifies V-QCs over them the
//! way a correct assembler does: each certificate carries the canonical resolution paths of its
//! recorded tips and is checked for well-formedness against its parent before it is returned, so
//! every [`Certified`] fixture is one a correct validator admits.

use super::Committee;
use crate::{
    multimmit::{
        algebra::{self, Ancestry},
        marshal::Floor,
        types::{
            Activity, BlockRef, CertificateId, ChainChange, ChainSet, HistoryRecord, Lqc,
            Resolution, ResolutionPath, SignedLeaderBlock, SignedTransactionBlock, VoteContent,
            VoteUpdate, Vqc,
        },
    },
    types::{Height, Participant, View},
};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::Variant, sha256::Digest,
};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

/// Namespace for the body digests of scenario blocks.
const BODY_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MOCK_SCENARIO_BODY";

/// Payload hashes an update carries beyond a chain's advance since the earlier updates (the
/// sender rule's sigma).
const UPDATE_SLACK: u64 = 2;

/// A V-QC certified by a [`Scenario`], or the epoch's genesis V-QC, with the facts it fixes.
#[derive(Clone, Debug)]
pub struct Certified<V: Variant> {
    view: View,
    id: CertificateId<Digest>,
    vqc: Option<Arc<Vqc<V, Digest>>>,
    base: Arc<[BlockRef<Digest>]>,
    record: Option<Arc<HistoryRecord<Digest>>>,
    tips: Arc<[BlockRef<Digest>]>,
    commitment: Digest,
}

impl<V: Variant> Certified<V> {
    /// Returns the certified view; the genesis V-QC certifies view zero.
    pub const fn view(&self) -> View {
        self.view
    }

    /// Returns the V-QC's identifier.
    pub const fn id(&self) -> CertificateId<Digest> {
        self.id
    }

    /// Returns the V-QC, or `None` for the genesis V-QC, which has no transcript.
    pub const fn vqc(&self) -> Option<&Arc<Vqc<V, Digest>>> {
        self.vqc.as_ref()
    }

    /// Returns the parent's tips, which this V-QC's tips extend; genesis is its own base.
    pub fn base(&self) -> &[BlockRef<Digest>] {
        &self.base
    }

    /// Returns `Tips(Q)`, one per chain in chain order.
    pub fn tips(&self) -> &[BlockRef<Digest>] {
        &self.tips
    }

    /// Returns the record `(C(parent), Tips(Q))` opening [`Self::commitment`], or `None` for the
    /// genesis V-QC, whose commitment has no parent.
    pub const fn record(&self) -> Option<&Arc<HistoryRecord<Digest>>> {
        self.record.as_ref()
    }

    /// Returns `C(Q)`, the tips-history commitment a child leader block carries.
    pub const fn commitment(&self) -> Digest {
        self.commitment
    }

    /// Returns the fact consensus reports once this V-QC's view is resolved by `by`.
    ///
    /// # Panics
    ///
    /// Panics for the genesis V-QC, whose view is never reported.
    pub fn resolved(&self, by: Resolution<Digest>) -> Activity<V, Digest> {
        let record = self.record.as_ref().expect("genesis is never resolved");
        Activity::ViewResolved {
            view: self.view,
            base: Arc::clone(&self.base),
            tips: Arc::clone(&self.tips),
            commitment: self.commitment,
            parent_commitment: record.parent(),
            by,
        }
    }
}

/// A committee with the producer headers and V-QC lineage tests build on it.
///
/// Block bodies are synthetic digests unique to each created block, so extending one parent twice
/// forks its chain.
pub struct Scenario<V: Variant> {
    committee: Committee<V>,
    blocks: HashMap<BlockRef<Digest>, SignedTransactionBlock<V, Digest>>,
}

impl<V: Variant> Scenario<V> {
    /// Creates a scenario holding only the genesis objects of `committee`'s epoch.
    pub fn new(committee: Committee<V>) -> Self {
        Self {
            committee,
            blocks: HashMap::new(),
        }
    }

    /// Returns the committee.
    pub const fn committee(&self) -> &Committee<V> {
        &self.committee
    }

    /// Returns the genesis V-QC, the parent of every view-one V-QC.
    pub fn genesis(&self) -> Certified<V> {
        let genesis = self.committee.genesis();
        let tips: Arc<[BlockRef<Digest>]> = genesis.tips().into();
        Certified {
            view: View::zero(),
            id: genesis.vqc(),
            vqc: None,
            base: Arc::clone(&tips),
            record: None,
            tips,
            commitment: genesis.history(),
        }
    }

    /// Appends `count` producer-signed blocks above `parent` and returns the highest (`parent`
    /// itself when `count` is zero).
    ///
    /// # Panics
    ///
    /// Panics if `parent` is neither a genesis object nor a block of this scenario.
    pub fn extend(&mut self, parent: &BlockRef<Digest>, count: u64) -> BlockRef<Digest> {
        assert!(self.holds(parent), "parent is held");
        let mut tip = *parent;
        for _ in 0..count {
            let nonce = self.blocks.len() as u64;
            let body = Sha256::hash(&[
                BODY_NAMESPACE,
                &tip.chain().get().to_be_bytes(),
                &tip.height().get().to_be_bytes(),
                &nonce.to_be_bytes(),
            ]);
            let block = self
                .committee
                .sign_header(self.committee.header(&tip, body));
            tip = block.header().block_ref::<Sha256>();
            self.blocks.insert(tip, block);
        }
        tip
    }

    /// Extends every tip of `tips` by `count` blocks and returns the new tips.
    pub fn extend_all(&mut self, tips: &[BlockRef<Digest>], count: u64) -> Vec<BlockRef<Digest>> {
        tips.iter().map(|tip| self.extend(tip, count)).collect()
    }

    /// Returns the signed header of `block`, if this scenario created it.
    pub fn block(&self, block: &BlockRef<Digest>) -> Option<&SignedTransactionBlock<V, Digest>> {
        self.blocks.get(block)
    }

    /// Returns the signed headers on `tip`'s path above height `from`, lowest first.
    ///
    /// # Panics
    ///
    /// Panics if a header in between was not created by this scenario.
    pub fn path(
        &self,
        from: Height,
        tip: &BlockRef<Digest>,
    ) -> Vec<&SignedTransactionBlock<V, Digest>> {
        let mut path = Vec::new();
        let mut current = *tip;
        while current.height() > from {
            let block = self.blocks.get(&current).expect("path headers are held");
            current = block.header().parent_ref();
            path.push(block);
        }
        path.reverse();
        path
    }

    /// Returns the body digests of the headers on `tip`'s path above height `from`, lowest first.
    pub fn payloads(&self, from: Height, tip: &BlockRef<Digest>) -> Vec<Digest> {
        self.path(from, tip)
            .into_iter()
            .map(|block| block.header().body_digest())
            .collect()
    }

    /// Returns `signer`'s update number `seq` carrying `content`, as a correct sender builds it.
    ///
    /// `prior` holds the tips of the sender's updates `seq - 1` and `seq - 2` of the same view; an
    /// update that does not exist counts as the sender's final tips of the previous view. The
    /// update names every chain whose tip differs from either, so a reader holding only one of
    /// them rebuilds the content. Each named chain carries the payload hashes of the blocks the
    /// tip advanced above the lower of the two plus two more, capped at the window's `delta_max`
    /// and the tip's height.
    pub fn update(
        &self,
        signer: Participant,
        content: &VoteContent<Digest>,
        prior: [&[BlockRef<Digest>]; 2],
        seq: u32,
    ) -> VoteUpdate<V, Digest> {
        let config = self.committee.codec();
        let [last, before] = prior;
        let changes = content
            .tips()
            .iter()
            .zip(last.iter().zip(before))
            .filter(|(tip, (last, before))| tip != last || tip != before)
            .map(|(tip, (last, before))| {
                let lowest = last.height().min(before.height()).get();
                let advance = tip.height().get().saturating_sub(lowest);
                let hints = (advance + UPDATE_SLACK)
                    .min(u64::from(config.window().delta_max()))
                    .min(tip.height().get());
                let payloads = self.payloads(Height::new(tip.height().get() - hints), tip);
                ChainChange::new(*tip, payloads, config).expect("change is within the window")
            })
            .collect();
        self.committee.update_with(signer, content, changes, seq)
    }

    /// Returns the scheduled leader's block for the view after `parent`, naming `parent` and its
    /// commitment.
    pub fn leader_block(&self, parent: &Certified<V>) -> SignedLeaderBlock<V, Digest> {
        self.committee
            .leader_block_with(parent.view.next(), parent.id, parent.commitment)
    }

    /// Returns the canonical resolution paths a V-QC above `base` recording `contents` carries.
    ///
    /// On each chain, every recorded tip above the base height that is not an ancestor of another
    /// recorded tip gets one path from its ancestor at the base height.
    ///
    /// # Panics
    ///
    /// Panics if a recorded tip's headers down to the base height are not held.
    pub fn resolution_paths(
        &self,
        base: &[BlockRef<Digest>],
        contents: &[(Participant, VoteContent<Digest>)],
    ) -> Vec<ResolutionPath<Digest>> {
        let config = self.committee.codec();
        let mut paths = Vec::new();
        for base in base {
            let recorded: BTreeSet<_> = contents
                .iter()
                .filter_map(|(_, content)| content.tips().get(base.chain().index()))
                .filter(|tip| tip.height() > base.height())
                .copied()
                .collect();
            for tip in &recorded {
                let covered = recorded
                    .iter()
                    .any(|other| other != tip && self.ancestor(other, tip.height()) == Some(*tip));
                if covered {
                    continue;
                }
                let from = self
                    .ancestor(tip, base.height())
                    .expect("recorded tips are held down to the base");
                let payloads = self.payloads(base.height(), tip);
                paths.push(
                    ResolutionPath::new(from, payloads, config)
                        .expect("recorded tip is within the tip lead"),
                );
            }
        }
        paths
    }

    /// Assembles the V-QC of the view after `parent` from the final votes `contents`, with their
    /// resolution paths, and returns its facts.
    ///
    /// # Panics
    ///
    /// Panics unless `contents` are `n - f` final votes of that view forming a V-QC well formed
    /// above `parent`.
    pub fn certify(
        &self,
        parent: &Certified<V>,
        contents: Vec<(Participant, VoteContent<Digest>)>,
    ) -> Certified<V> {
        let config = self.committee.codec();
        let paths = self.resolution_paths(&parent.tips, &contents);
        let vqc = self.committee.vqc_from(parent.id, contents, paths);
        assert_eq!(
            vqc.round().view(),
            parent.view.next(),
            "V-QC extends its parent"
        );
        let valid =
            algebra::validate_vqc::<Sha256, V>(&vqc, parent.commitment, &parent.tips, config)
                .expect("V-QC is well formed above its parent");
        Certified {
            view: parent.view.next(),
            id: vqc.id::<Sha256>(),
            vqc: Some(Arc::new(vqc)),
            base: Arc::clone(&parent.tips),
            tips: valid.record.tips().into(),
            record: Some(Arc::new(valid.record)),
            commitment: valid.commitment,
        }
    }

    /// Certifies the view after `parent` with `n - f` identical final votes for its leader block
    /// endorsing `tips`.
    ///
    /// The V-QC designates the leader block, and its tips are `tips` clipped to the window above
    /// `parent`'s tips.
    pub fn advance(&self, parent: &Certified<V>, tips: &[BlockRef<Digest>]) -> Certified<V> {
        let content = self.vote(parent, true, tips);
        self.certify(parent, self.committee.quorum(&content))
    }

    /// Returns the L-QC for the leader block of the view after `parent`, whose `n - f` votes
    /// endorse `parent`'s tips without finalizing the view.
    pub fn lqc(&self, parent: &Certified<V>) -> Lqc<V, Digest> {
        let leader = self.leader_block(parent).block().clone();
        let content = self.vote(parent, false, &parent.tips);
        self.committee
            .lqc_from(leader, self.committee.quorum(&content))
    }

    /// Returns the finalization certificate pinning `parent`'s tips: the L-QC of the next view's
    /// leader block with the record opening its history commitment.
    ///
    /// # Panics
    ///
    /// Panics if `parent` is the genesis V-QC, whose commitment has no opening record.
    pub fn floor(&self, parent: &Certified<V>) -> Floor<V, Digest> {
        let opening = parent
            .record
            .clone()
            .expect("genesis has no opening record");
        Floor::new(Arc::new(self.lqc(parent)), opening)
    }

    /// Returns a vote in the view after `parent` for its leader block, endorsing `tips` and
    /// declaring no chain.
    pub fn vote(
        &self,
        parent: &Certified<V>,
        final_: bool,
        tips: &[BlockRef<Digest>],
    ) -> VoteContent<Digest> {
        let leader = self.leader_block(parent).block().digest::<Sha256>();
        let declared = ChainSet::empty(self.committee.codec().chains());
        self.committee.content(
            parent.view.next(),
            Some(leader),
            final_,
            self.committee.endorsement(declared, tips.to_vec()),
        )
    }

    /// Returns whether `block` is a genesis object or a block of this scenario.
    fn holds(&self, block: &BlockRef<Digest>) -> bool {
        self.blocks.contains_key(block)
            || self.committee.genesis().tip(block.chain()) == Some(block)
    }
}

impl<V: Variant> Ancestry<Digest> for Scenario<V> {
    fn ancestor(&self, tip: &BlockRef<Digest>, height: Height) -> Option<BlockRef<Digest>> {
        if height > tip.height() {
            return None;
        }
        let mut current = *tip;
        while current.height() > height {
            current = self.blocks.get(&current)?.header().parent_ref();
        }
        (current == *tip || self.holds(&current)).then_some(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Epochable as _, multimmit::algebra::Path};
    use commonware_cryptography::bls12381::primitives::variant::MinPk;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    /// Six validators tolerate one fault: V-QCs hold five votes and three make a tip.
    fn scenario() -> Scenario<MinPk> {
        Scenario::new(Committee::builder(41, 6).build())
    }

    #[test]
    fn lineage_resolves_forks_and_clips_tips_to_the_window() {
        let mut scenario = scenario();
        let genesis = scenario.genesis();
        let raised = scenario.extend_all(genesis.tips(), 2);
        let first = scenario.advance(&genesis, &raised);
        assert_eq!(first.view(), View::new(1));
        assert_eq!(first.tips(), raised.as_slice());
        assert_eq!(first.base(), genesis.tips());
        let record = HistoryRecord::new(genesis.commitment(), raised.clone()).unwrap();
        assert_eq!(first.commitment(), record.commitment::<Sha256>());
        assert_eq!(first.vqc().unwrap().parent(), genesis.id());

        // Chain 0 forks above the base: three votes make the left branch the tip. Chain 1 runs
        // two blocks past the window cap of four. On chain 2 one voter records a tip above the
        // base height on a branch that forks below the base, which still needs a path.
        let left = scenario.extend(&raised[0], 1);
        let right = scenario.extend(&raised[0], 1);
        assert_ne!(left, right);
        let long = scenario.extend(&raised[1], 6);
        let below = scenario.ancestor(&raised[2], Height::new(1)).unwrap();
        let stranded = scenario.extend(&below, 3);
        let contents = (0..5)
            .map(|signer| {
                let mut tips = raised.clone();
                tips[0] = if signer < 3 { left } else { right };
                tips[1] = long;
                if signer == 4 {
                    tips[2] = stranded;
                }
                (Participant::new(signer), scenario.vote(&first, true, &tips))
            })
            .collect();
        let second = scenario.certify(&first, contents);
        let vqc = second.vqc().unwrap();
        assert_eq!(vqc.tally().paths().len(), 4);
        let off_base = vqc
            .tally()
            .paths()
            .iter()
            .find(|path| path.from().chain() == raised[2].chain())
            .unwrap();
        assert_eq!(off_base.from().height(), raised[2].height());
        assert_ne!(off_base.from(), raised[2]);
        assert_eq!(second.tips()[0], left);
        assert_eq!(
            second.tips()[1],
            scenario.ancestor(&long, Height::new(6)).unwrap()
        );
        assert_eq!(&second.tips()[2..], &raised[2..]);
        assert!(
            scenario
                .committee()
                .verifier
                .verify_vqc(&mut test_rng(), vqc, &Sequential)
        );
    }

    #[test]
    fn updates_relist_recent_changes_with_payloads_that_rebuild_their_tips() {
        let mut scenario = scenario();
        let genesis = scenario.genesis();
        let signer = Participant::new(4);
        let initial = genesis.tips();
        let mut first = initial.to_vec();
        first[2] = scenario.extend(&first[2], 3);
        let mut second = first.clone();
        second[3] = scenario.extend(&second[3], 1);
        let updates = [
            (scenario.vote(&genesis, false, &first), [initial, initial]),
            (
                scenario.vote(&genesis, false, &second),
                [&first[..], initial],
            ),
        ]
        .into_iter()
        .zip(1..)
        .map(|((content, prior), seq)| (scenario.update(signer, &content, prior, seq), content))
        .collect::<Vec<_>>();

        // Update 2 relists chain 2, which changed only in update 1, so a reader holding just the
        // genesis tips rebuilds it as well as one holding update 1.
        let changed = |index: usize| -> Vec<_> {
            updates[index]
                .0
                .changes()
                .iter()
                .map(|change| change.chain())
                .collect()
        };
        assert_eq!(changed(0), [first[2].chain()]);
        assert_eq!(changed(1), [first[2].chain(), second[3].chain()]);
        let config = scenario.committee().codec();
        let (update, content) = &updates[1];
        assert_eq!(update.content(&first, config).unwrap(), *content);
        assert_eq!(update.content(initial, config).unwrap(), *content);
        assert!(
            scenario
                .committee()
                .verifier
                .verify_vote(content, update.attestation())
        );

        let epoch = scenario.committee().config.epoch();
        for change in update.changes() {
            let tip = change.tip();
            let depth = change.payloads().len() as u64;
            assert_eq!(depth, tip.height().get());
            let from = scenario
                .ancestor(&tip, Height::new(tip.height().get() - depth))
                .unwrap();
            Path::resolve::<Sha256>(epoch, from, change.payloads(), &tip).unwrap();
        }
    }

    #[test]
    fn floors_open_the_pinned_tips() {
        let mut scenario = scenario();
        let genesis = scenario.genesis();
        let raised = scenario.extend_all(genesis.tips(), 3);
        let first = scenario.advance(&genesis, &raised);
        let floor = scenario.floor(&first);
        let committee = scenario.committee();
        assert_eq!(floor.lqc().leader(), scenario.leader_block(&first).block());
        let index = algebra::validate_floor::<Sha256, MinPk>(
            floor.lqc(),
            floor.opening(),
            committee.config.epoch(),
            committee.codec(),
        )
        .unwrap();
        assert_eq!(index, 3 * 6);
        assert!(committee.verifier.verify_lqc::<_, Sha256, _>(
            &mut test_rng(),
            floor.lqc(),
            &Sequential
        ));

        let Activity::ViewResolved {
            view,
            base,
            tips,
            commitment,
            parent_commitment,
            ..
        } = first.resolved(Resolution::Determined)
        else {
            panic!("a resolved view is reported as such");
        };
        assert_eq!(view, View::new(1));
        assert_eq!(&*base, genesis.tips());
        assert_eq!(parent_commitment, genesis.commitment());
        let record = HistoryRecord::new(parent_commitment, tips.to_vec()).unwrap();
        assert_eq!(record.commitment::<Sha256>(), commitment);
    }
}
