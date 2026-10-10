//! A complete epoch committee with real cryptographic material.

use super::{
    NAMESPACE,
    keys::{keys, test_config},
};
use crate::{
    Epochable as _,
    multimmit::{
        algebra::VqcExtraction,
        config::{LeaderSchedule, Protocol},
        scheme::bls12381_threshold::{Roster, Scheme},
        types::{
            Anchor, CertificateId, ChainId, ChainProposal, CodecConfig, DaVote, DigestedLeader,
            Extension, LeaderBlock, Lqc, NoVote, Nullification, Nullify, PathLimits, Position,
            SignedLeaderBlock, SignedTransactionBlock, TipRecord, TransactionBlockHeader,
            ViewMessage, Vote, VoteBody, Vqc, genesis_tip_commitment,
        },
    },
    types::{Height, Round, View},
};
use commonware_cryptography::{
    Sha256, Signer as _,
    bls12381::primitives::{sharing::Sharing, variant::Variant},
    ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_parallel::Sequential;
use commonware_utils::{Participant, TestRng, ordered::Set};
use std::{marker::PhantomData, sync::Arc};

/// One complete epoch committee with real cryptographic material.
pub struct Committee<V: Variant> {
    /// The validated immutable epoch configuration.
    pub config: Protocol<Sha256Digest>,
    /// Authenticated network identities in participant order.
    pub identities: Vec<ed25519::PublicKey>,
    /// Network private keys in participant order.
    pub network_keys: Vec<ed25519::PrivateKey>,
    /// The proof-of-possession checked ordinary-key roster.
    pub roster: Roster<ed25519::PublicKey, V>,
    /// The public `n-2f` DA sharing.
    pub da: Sharing<V>,
    /// The public `2f+1` nullification sharing.
    pub nullification: Sharing<V>,
    /// One signing scheme per participant, in participant order.
    pub signers: Vec<Scheme<ed25519::PublicKey, V>>,
    /// A keyless verification scheme for observers.
    pub verifier: Scheme<ed25519::PublicKey, V>,
}

/// Builds a [`Committee`] with deterministic keys derived from a seed.
///
/// Unless set otherwise, the committee signs under the mock namespace, every participant produces
/// the chain at its own index, pipelines at depth two with extension bound one, and elects leaders
/// round-robin.
pub struct CommitteeBuilder<V: Variant> {
    seed: u64,
    participants: u32,
    namespace: Vec<u8>,
    producers: Option<Vec<Participant>>,
    limits: PathLimits,
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

    /// Bounds proposal pipelines and vote extensions by `limits`.
    pub const fn limits(mut self, limits: PathLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Elects leaders by `leaders`.
    pub fn leaders(mut self, leaders: LeaderSchedule) -> Self {
        self.leaders = Some(leaders);
        self
    }

    /// Deals the committee's keys and builds it.
    ///
    /// # Panics
    ///
    /// Panics if the settings do not describe a valid epoch configuration.
    pub fn build(self) -> Committee<V> {
        let producers = self
            .producers
            .unwrap_or_else(|| (0..self.participants).map(Participant::new).collect());
        let config = test_config(
            self.seed,
            &self.namespace,
            self.participants,
            producers,
            self.limits,
        );
        let mut network_keys = (0..self.participants)
            .map(|index| ed25519::PrivateKey::from_seed(self.seed ^ (u64::from(index) + 1)))
            .collect::<Vec<_>>();
        network_keys.sort_by_key(|key| key.public_key());
        let identities = network_keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>();
        let identity_set = Set::try_from(identities.clone()).expect("identities are unique");
        let keys = keys::<V>(&mut TestRng::new(self.seed), &config, &identity_set);

        let committee = Committee {
            config,
            identities,
            network_keys,
            roster: keys.roster,
            da: keys.da,
            nullification: keys.nullification,
            signers: keys.signers,
            verifier: keys.verifier,
        };
        match self.leaders {
            Some(leaders) => committee.with_leaders(leaders),
            None => committee,
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
            limits: PathLimits::new(2, 1).expect("default limits are valid"),
            leaders: None,
            _variant: PhantomData,
        }
    }

    /// Returns this committee with an explicit leader schedule.
    ///
    /// Schemes are rebuilt so the leader each scheme signs and verifies matches the machine's.
    fn with_leaders(self, leaders: LeaderSchedule) -> Self {
        let config = self
            .config
            .with_leaders(leaders)
            .expect("schedule matches the committee");
        let parameters = config.parameters();
        let signers = self
            .signers
            .into_iter()
            .map(|scheme| scheme.with_parameters(Arc::clone(parameters)))
            .collect();
        let verifier = self.verifier.with_parameters(Arc::clone(parameters));
        Self {
            config,
            signers,
            verifier,
            ..self
        }
    }

    /// Returns the bounded codec configuration for the epoch.
    pub const fn codec(&self) -> CodecConfig {
        self.config.codec_config()
    }

    /// Returns a height-one transaction-block header for `chain`.
    pub fn transaction_header(
        &self,
        chain: ChainId,
        commitment: Sha256Digest,
    ) -> TransactionBlockHeader<Sha256Digest> {
        let parent = self.config.genesis().tips()[chain.get() as usize];
        TransactionBlockHeader::new(
            self.config.epoch(),
            chain,
            Height::new(1),
            parent.digest(),
            commitment,
        )
        .expect("height one is a live header")
    }

    /// Returns a producer-signed height-one transaction block for `chain`.
    pub fn signed_block(
        &self,
        chain: ChainId,
        commitment: Sha256Digest,
    ) -> SignedTransactionBlock<V, Sha256Digest> {
        let producer = self
            .config
            .producer(chain)
            .expect("producer chain is configured");
        self.signers[producer.get() as usize]
            .sign_transaction_block(self.transaction_header(chain, commitment))
            .expect("producer owns its chain")
    }

    /// Returns `signer`'s data-availability share for `header`.
    pub fn da_vote(
        &self,
        signer: Participant,
        header: TransactionBlockHeader<Sha256Digest>,
    ) -> DaVote<V, Sha256Digest> {
        self.signers[signer.get() as usize]
            .sign_da_vote(header)
            .expect("signer holds a DA share")
    }

    /// Returns `signer`'s abstention for `view`.
    pub fn novote(&self, signer: Participant, view: View) -> NoVote<V> {
        self.signers[signer.get() as usize]
            .sign_novote(Round::new(self.config.epoch(), view))
            .expect("signer holds an ordinary key")
    }

    /// Returns `signer`'s nullification share for `view`.
    pub fn nullify(&self, signer: Participant, view: View) -> Nullify<V> {
        self.signers[signer.get() as usize]
            .sign_nullify(Round::new(self.config.epoch(), view))
            .expect("signer holds a nullification share")
    }

    /// Recovers a complete nullification for `view` from the first `2f+1` signers.
    pub fn nullification(&self, view: View) -> Nullification<V> {
        let shares = (0..self.codec().nullification_quorum())
            .map(|signer| self.nullify(Participant::from_usize(signer), view))
            .collect::<Vec<_>>();
        self.verifier
            .assemble_nullification(&shares, &Sequential)
            .expect("quorum of valid shares recovers")
    }

    /// Returns the scheduled leader's signed empty proposal for `view` above `parent`.
    pub fn leader_block_with_parent(
        &self,
        view: View,
        parent: &Vqc<V, Sha256Digest>,
    ) -> SignedLeaderBlock<V, Sha256Digest> {
        let (tips, _) = VqcExtraction::new::<Sha256, V>(parent, self.codec())
            .expect("fixture parent V-QC extracts")
            .into_parts();
        let history = TipRecord::new(
            parent.leader().history(),
            tips.blocks().to_vec(),
            parent.leader().proposed_heights(),
        )
        .expect("fixture tips are canonical")
        .commitment::<Sha256>();
        self.empty_leader_block(view, parent.id::<Sha256>(), history)
    }

    /// Returns the scheduled leader's signed empty proposal for `view`, anchored at genesis.
    pub fn leader_block(&self, view: View) -> SignedLeaderBlock<V, Sha256Digest> {
        let genesis = self.config.genesis();
        let history = genesis_tip_commitment::<Sha256>(genesis);
        self.empty_leader_block(view, genesis.vqc(), history)
    }

    /// Returns the scheduled leader's signed empty proposal for `view` above `parent`.
    fn empty_leader_block(
        &self,
        view: View,
        parent: CertificateId<Sha256Digest>,
        history: Sha256Digest,
    ) -> SignedLeaderBlock<V, Sha256Digest> {
        let codec = self.codec();
        let proposals = self
            .config
            .genesis()
            .tips()
            .iter()
            .enumerate()
            .map(|(chain, tip)| {
                ChainProposal::new(
                    ChainId::new(chain as u32),
                    Anchor::Tip(*tip),
                    Vec::new(),
                    codec.pipeline_depth(),
                )
                .expect("empty proposal is valid")
            })
            .collect();
        let block = LeaderBlock::new(
            Round::new(self.config.epoch(), view),
            parent,
            history,
            proposals,
            codec,
        )
        .expect("anchored proposal is valid");
        let leader = self.config.leader(view);
        self.signers[leader.get() as usize]
            .sign_leader_block(block)
            .expect("scheduled leader signs its proposal")
    }

    /// Returns `signer`'s complete zero-position vote for `block`.
    pub fn vote(
        &self,
        signer: Participant,
        block: &SignedLeaderBlock<V, Sha256Digest>,
    ) -> Vote<V, Sha256Digest> {
        let codec = self.codec();
        let body = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(block.block()),
            vec![Position::new(0); codec.chains()],
            vec![Extension::empty(); codec.chains()],
            codec,
        )
        .expect("zero positions are valid for an empty proposal");
        self.signers[signer.get() as usize]
            .sign_vote(body)
            .expect("signer holds an ordinary key")
    }

    /// Assembles a real V-QC for `view` from the first `n-f` signers' votes.
    pub fn vqc(&self, view: View) -> Vqc<V, Sha256Digest> {
        let block = self.leader_block(view);
        let messages = (0..self.codec().view_quorum())
            .map(|signer| ViewMessage::Vote(self.vote(Participant::from_usize(signer), &block)))
            .collect::<Vec<_>>();
        self.verifier
            .assemble_vqc::<Sha256, _>(block.block().clone(), &messages, &Sequential)
            .expect("quorum of valid votes aggregates")
    }

    /// Assembles a real L-QC for `view` from the first `n-f` signers' votes.
    pub fn lqc(&self, view: View) -> Lqc<V, Sha256Digest> {
        let block = self.leader_block(view);
        let votes = (0..self.codec().view_quorum())
            .map(|signer| self.vote(Participant::from_usize(signer), &block))
            .collect::<Vec<_>>();
        self.verifier
            .assemble_lqc::<Sha256, _>(block.block().clone(), &votes, &Sequential)
            .expect("quorum of valid votes aggregates")
    }
}

#[cfg(test)]
mod tests {
    use super::Committee;
    use crate::{
        multimmit::config::LeaderSchedule,
        types::{Attributable as _, Participant, View},
    };
    use commonware_cryptography::bls12381::primitives::variant::MinPk;

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
        }
    }
}
