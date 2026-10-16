//! A complete epoch committee with real cryptographic material.

use super::{
    NAMESPACE,
    keys::{keys, test_config},
};
use crate::{
    Epochable as _,
    multimmit::{
        config::{LeaderSchedule, Protocol},
        scheme::bls12381::{Roster, Scheme, SignatureVerification},
        types::{
            Attestation, BlockRef, CertificateId, ChainChange, ChainId, ChainSet, CodecConfig,
            Endorsement, EpochGenesis, LeaderBlock, Lqc, ResolutionPath, SignedLeaderBlock,
            SignedTransactionBlock, TransactionBlockHeader, VoteContent, VoteUpdate, Vqc, Window,
        },
    },
    types::{Round, View},
};
use commonware_cryptography::{
    Hasher as _, Sha256, Signer as _,
    bls12381::primitives::{group::Private, variant::Variant},
    ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_math::algebra::Random as _;
use commonware_parallel::Sequential;
use commonware_utils::{Participant, TestRng, ordered::Set};
use std::marker::PhantomData;

/// Mixed into a committee's seed to derive its network keys apart from its BLS keys.
const NETWORK_KEY_SEED: u64 = 0x6e65_7477_6f72_6b00;

/// One complete epoch committee with real cryptographic material.
pub struct Committee<V: Variant> {
    /// The validated immutable epoch configuration.
    pub config: Protocol<Sha256Digest>,
    /// Authenticated network identities in participant order.
    pub identities: Vec<ed25519::PublicKey>,
    /// The proof-of-possession checked ordinary-key roster.
    pub roster: Roster<ed25519::PublicKey, V>,
    /// Ordinary BLS private keys in participant order.
    pub privates: Vec<Private>,
    /// One signing scheme per participant, in participant order.
    pub signers: Vec<Scheme<ed25519::PublicKey, V>>,
    /// A keyless verification scheme for observers.
    pub verifier: Scheme<ed25519::PublicKey, V>,
}

/// Builds a [`Committee`] with deterministic keys derived from a seed.
///
/// Unless set otherwise, the committee runs epoch `seed` under the mock namespace, every
/// participant produces the chain at its own index, the window has cap four, and leaders rotate
/// round-robin.
pub struct CommitteeBuilder<V: Variant> {
    seed: u64,
    participants: u32,
    namespace: Vec<u8>,
    producers: Option<Vec<Participant>>,
    window: Window,
    leaders: Option<LeaderSchedule>,
    _variant: PhantomData<V>,
}

impl<V: Variant> CommitteeBuilder<V> {
    /// Signs under `namespace`.
    pub fn namespace(mut self, namespace: &[u8]) -> Self {
        self.namespace = namespace.to_vec();
        self
    }

    /// Assigns one producer chain to each entry of `producers`, in chain order.
    pub fn producers(mut self, producers: Vec<Participant>) -> Self {
        self.producers = Some(producers);
        self
    }

    /// Uses `window` for the epoch.
    pub const fn window(mut self, window: Window) -> Self {
        self.window = window;
        self
    }

    /// Elects leaders by `leaders`.
    pub fn leaders(mut self, leaders: LeaderSchedule) -> Self {
        self.leaders = Some(leaders);
        self
    }

    /// Generates the committee's keys and builds it.
    ///
    /// # Panics
    ///
    /// Panics if the settings do not describe a valid epoch configuration.
    pub fn build(self) -> Committee<V> {
        let producers = self
            .producers
            .unwrap_or_else(|| (0..self.participants).map(Participant::new).collect());
        let mut config = test_config(
            self.seed,
            &self.namespace,
            self.participants,
            producers,
            self.window,
        );
        if let Some(leaders) = self.leaders {
            config = config
                .with_leaders(leaders)
                .expect("schedule matches the committee");
        }
        // One stream per seed, so committees built from different seeds never share identities.
        let mut network_rng = TestRng::new(self.seed ^ NETWORK_KEY_SEED);
        let mut identities = (0..self.participants)
            .map(|_| ed25519::PrivateKey::random(&mut network_rng).public_key())
            .collect::<Vec<_>>();
        identities.sort();
        let identity_set = Set::try_from(identities.clone()).expect("identities are unique");
        let keys = keys::<V>(
            &mut TestRng::new(self.seed),
            config.parameters(),
            &identity_set,
        );
        Committee {
            config,
            identities,
            roster: keys.roster,
            privates: keys.privates,
            signers: keys.signers,
            verifier: keys.verifier,
        }
    }
}

impl<V: Variant> Committee<V> {
    /// Starts building a committee of `participants` with deterministic keys derived from `seed`.
    pub fn builder(seed: u64, participants: u32) -> CommitteeBuilder<V> {
        CommitteeBuilder {
            seed,
            participants,
            namespace: NAMESPACE.to_vec(),
            producers: None,
            window: Window::new(4).expect("default window is valid"),
            leaders: None,
            _variant: PhantomData,
        }
    }

    /// Returns the bounded codec configuration for the epoch.
    pub const fn codec(&self) -> CodecConfig {
        self.config.codec_config()
    }

    /// Returns the epoch's genesis facts.
    pub const fn genesis(&self) -> &EpochGenesis<Sha256Digest> {
        self.config.genesis()
    }

    /// Returns the round of `view` in the committee's epoch.
    pub fn round(&self, view: View) -> Round {
        Round::new(self.config.epoch(), view)
    }

    /// Returns the header of the block above `parent` committing to `body`.
    pub fn header(
        &self,
        parent: &BlockRef<Sha256Digest>,
        body: Sha256Digest,
    ) -> TransactionBlockHeader<Sha256Digest> {
        TransactionBlockHeader::new(
            self.config.epoch(),
            parent.chain(),
            parent.height().next(),
            parent.digest(),
            body,
        )
        .expect("a child is above height zero")
    }

    /// Returns `header` signed by its chain's producer.
    pub fn sign_header(
        &self,
        header: TransactionBlockHeader<Sha256Digest>,
    ) -> SignedTransactionBlock<V, Sha256Digest> {
        let producer = self
            .config
            .producer(header.chain())
            .expect("producer chain is configured");
        self.signer(producer)
            .sign_transaction_block(header)
            .expect("producer owns its chain")
    }

    /// Returns the producer-signed header at height one on `chain` committing to the hash of
    /// `body`.
    pub fn genesis_child(
        &self,
        chain: ChainId,
        body: &[u8],
    ) -> SignedTransactionBlock<V, Sha256Digest> {
        let parent = self.genesis().tips()[chain.get() as usize];
        self.sign_header(self.header(&parent, Sha256::hash(&[body])))
    }

    /// Returns the scheduled leader's signed leader block for `view` above the V-QC `parent`
    /// whose tips-history commitment is `history`.
    pub fn leader_block_with(
        &self,
        view: View,
        parent: CertificateId<Sha256Digest>,
        history: Sha256Digest,
    ) -> SignedLeaderBlock<V, Sha256Digest> {
        let block =
            LeaderBlock::new(self.round(view), parent, history).expect("view is above genesis");
        self.signer(self.config.leader(view))
            .sign_leader_block(block)
            .expect("scheduled leader signs its block")
    }

    /// Returns the scheduled leader's signed leader block for `view` above the genesis V-QC.
    pub fn leader_block(&self, view: View) -> SignedLeaderBlock<V, Sha256Digest> {
        let genesis = self.genesis();
        self.leader_block_with(view, genesis.vqc(), genesis.history())
    }

    /// Returns an endorsement of `tips`, one per chain in chain order, declaring `declared`.
    pub fn endorsement(
        &self,
        declared: ChainSet,
        tips: Vec<BlockRef<Sha256Digest>>,
    ) -> Endorsement<Sha256Digest> {
        Endorsement::new(declared, tips, self.codec()).expect("one tip per chain")
    }

    /// Returns an endorsement of every genesis object, declaring no chain.
    pub fn genesis_endorsement(&self) -> Endorsement<Sha256Digest> {
        self.endorsement(
            ChainSet::empty(self.codec().chains()),
            self.genesis().tips().to_vec(),
        )
    }

    /// Returns the content of a vote in `view`.
    pub fn content(
        &self,
        view: View,
        leader: Option<Sha256Digest>,
        final_: bool,
        endorsement: Endorsement<Sha256Digest>,
    ) -> VoteContent<Sha256Digest> {
        VoteContent::new(self.round(view), leader, final_, endorsement)
            .expect("view is above genesis")
    }

    /// Returns the content of a pre-vote in `view` endorsing every genesis object.
    pub fn genesis_content(&self, view: View) -> VoteContent<Sha256Digest> {
        self.content(view, None, false, self.genesis_endorsement())
    }

    /// Returns `signer`'s first update in `view`, carrying [`Self::genesis_content`].
    pub fn genesis_update(&self, signer: Participant, view: View) -> VoteUpdate<V, Sha256Digest> {
        self.update(
            signer,
            &self.genesis_content(view),
            self.genesis().tips(),
            1,
        )
    }

    /// Returns `signer`'s attestation over `content`.
    pub fn sign_vote(
        &self,
        signer: Participant,
        content: &VoteContent<Sha256Digest>,
    ) -> Attestation<V> {
        self.signer(signer)
            .sign_vote(content)
            .expect("content belongs to the epoch")
    }

    /// Returns `signer`'s update number `seq` carrying `content`, naming the chains whose tips
    /// differ from `previous` without payload hashes.
    pub fn update(
        &self,
        signer: Participant,
        content: &VoteContent<Sha256Digest>,
        previous: &[BlockRef<Sha256Digest>],
        seq: u32,
    ) -> VoteUpdate<V, Sha256Digest> {
        let changes = content
            .tips()
            .iter()
            .zip(previous)
            .filter(|(tip, previous)| tip != previous)
            .map(|(tip, _)| {
                ChainChange::new(*tip, Vec::new(), self.codec()).expect("tip is on a chain")
            })
            .collect();
        self.update_with(signer, content, changes, seq)
    }

    /// Returns `signer`'s update number `seq` carrying `content` with the given `changes`.
    pub fn update_with(
        &self,
        signer: Participant,
        content: &VoteContent<Sha256Digest>,
        changes: Vec<ChainChange<Sha256Digest>>,
        seq: u32,
    ) -> VoteUpdate<V, Sha256Digest> {
        VoteUpdate::new(
            content.round(),
            content.leader(),
            content.is_final(),
            content.declared().clone(),
            seq,
            changes,
            self.sign_vote(signer, content),
            self.codec(),
        )
        .expect("update is well formed")
    }

    /// Signs each content by its participant and assembles a V-QC above `parent`.
    pub fn vqc_from(
        &self,
        parent: CertificateId<Sha256Digest>,
        contents: Vec<(Participant, VoteContent<Sha256Digest>)>,
        paths: Vec<ResolutionPath<Sha256Digest>>,
    ) -> Vqc<V, Sha256Digest> {
        self.verifier
            .assemble_vqc(
                &mut TestRng::new(0),
                parent,
                &self.attested(contents),
                paths,
                SignatureVerification::Preverified,
                &Sequential,
            )
            .expect("contents form a V-QC")
    }

    /// Signs each content by its participant and assembles an L-QC for `leader`.
    pub fn lqc_from(
        &self,
        leader: LeaderBlock<Sha256Digest>,
        contents: Vec<(Participant, VoteContent<Sha256Digest>)>,
    ) -> Lqc<V, Sha256Digest> {
        self.verifier
            .assemble_lqc::<_, Sha256, _>(
                &mut TestRng::new(0),
                leader,
                &self.attested(contents),
                SignatureVerification::Preverified,
                &Sequential,
            )
            .expect("contents form an L-QC")
    }

    /// Returns a V-QC for `view` above the genesis V-QC in which the first `n - f` participants
    /// vote finally for the view's genesis-anchored leader block and endorse every genesis object.
    pub fn vqc(&self, view: View) -> Vqc<V, Sha256Digest> {
        let leader = self.leader_block(view).block().digest::<Sha256>();
        let content = self.content(view, Some(leader), true, self.genesis_endorsement());
        self.vqc_from(self.genesis().vqc(), self.quorum(&content), Vec::new())
    }

    /// Returns an L-QC for the genesis-anchored leader block of `view` in which the first
    /// `n - f` participants endorse every genesis object.
    pub fn lqc(&self, view: View) -> Lqc<V, Sha256Digest> {
        let genesis = self.genesis();
        self.lqc_with(view, genesis.vqc(), genesis.history())
    }

    /// Returns an L-QC for the leader block of `view` above the V-QC `parent` whose tips-history
    /// commitment is `history`, in which the first `n - f` participants endorse every genesis
    /// object.
    pub fn lqc_with(
        &self,
        view: View,
        parent: CertificateId<Sha256Digest>,
        history: Sha256Digest,
    ) -> Lqc<V, Sha256Digest> {
        let leader = self
            .leader_block_with(view, parent, history)
            .block()
            .clone();
        let content = self.content(
            view,
            Some(leader.digest::<Sha256>()),
            false,
            self.genesis_endorsement(),
        );
        self.lqc_from(leader, self.quorum(&content))
    }

    fn signer(&self, participant: Participant) -> &Scheme<ed25519::PublicKey, V> {
        &self.signers[usize::from(participant)]
    }

    /// Pairs `content` with each of the first `n - f` participants.
    pub fn quorum(
        &self,
        content: &VoteContent<Sha256Digest>,
    ) -> Vec<(Participant, VoteContent<Sha256Digest>)> {
        (0..self.codec().view_quorum())
            .map(|signer| (Participant::from_usize(signer), content.clone()))
            .collect()
    }

    /// Signs each content by its participant, keeping the input order.
    pub fn attested(
        &self,
        contents: Vec<(Participant, VoteContent<Sha256Digest>)>,
    ) -> Vec<(VoteContent<Sha256Digest>, Attestation<V>)> {
        contents
            .into_iter()
            .map(|(signer, content)| {
                let attestation = self.sign_vote(signer, &content);
                (content, attestation)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::Committee;
    use crate::{
        multimmit::config::LeaderSchedule,
        types::{Attributable as _, Participant, View},
    };
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    #[test]
    fn leader_block_follows_the_configured_schedule() {
        let participants = 6u32;
        let reversed = LeaderSchedule::from_order(
            (0..participants).rev().map(Participant::new).collect(),
            participants as usize,
        )
        .unwrap();
        let committee = Committee::<MinPk>::builder(78, participants)
            .leaders(reversed)
            .build();
        for view in (1..=u64::from(participants)).map(View::new) {
            let block = committee.leader_block(view);
            assert_eq!(block.signer(), committee.config.leader(view));
            assert!(committee.verifier.verify_leader_block(&block));
        }
    }

    #[test]
    fn default_certificates_verify() {
        let committee = Committee::<MinPk>::builder(7, 6).build();
        let vqc = committee.vqc(View::new(2));
        let lqc = committee.lqc(View::new(3));
        assert!(
            committee
                .verifier
                .verify_vqc(&mut test_rng(), &vqc, &Sequential)
        );
        assert!(
            committee
                .verifier
                .verify_lqc::<_, Sha256, _>(&mut test_rng(), &lqc, &Sequential)
        );
    }
}
