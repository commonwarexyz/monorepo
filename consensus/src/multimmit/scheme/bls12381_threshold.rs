//! BLS12-381 signatures and threshold certificates without a VRF.
//!
//! Multimmit uses three independent key roles:
//!
//! - ordinary BLS keys authenticate transaction blocks, leader blocks, votes, and novotes;
//! - an `n-2f` threshold sharing produces constant-size data-availability certificates; and
//! - a `2f+1` threshold sharing produces constant-size nullifications.
//!
//! V-QCs and L-QCs aggregate the exact ordinary signatures represented by their compact
//! signer-to-message transcripts. They are not recovered threshold signatures.

use super::{Namespace, Subject, Unverified};
use crate::{
    Epochable, Viewable,
    multimmit::{
        config::{CodecConfig, Config, LeaderSchedule},
        types::{
            Anchor, Attestation, CertificateId, ConflictingVote, DaCertificate, DaVote,
            LeaderBlock, Lqc, NoVote, Nullification, Nullify, SignedLeaderBlock,
            SignedTransactionBlock, Tally, ThresholdShare, TransactionBlockHeader, ViewMessage,
            Vote, VoteBody, Vqc,
        },
    },
    types::{Attributable, Epoch, Round},
};
use bytes::Bytes;
use commonware_cryptography::{
    Digest, Hasher, PublicKey,
    bls12381::{
        certificate::threshold as certificate_threshold,
        primitives::{
            group::{Private, Share},
            ops::{self, aggregate, batch, threshold},
            sharing::{Mode, Sharing},
            variant::{PartialSignature, Variant},
        },
    },
    certificate::Signers,
};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
use commonware_utils::{
    N5f1, Participant, TryFromIterator,
    ordered::{BiMap, Set},
};
use core::{convert::identity, fmt};
use rand_core::CryptoRng;
use std::{collections::HashSet, sync::Arc};

/// An error while constructing or verifying a Multimmit cryptographic artifact.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The scheme has no local signing material.
    #[error("scheme is verifier-only")]
    VerifierOnly,
    /// The scheme has only certificate-verification material.
    #[error("threshold sharing is unavailable")]
    SharingUnavailable,
    /// The local key does not own the producer or leader role.
    #[error("unexpected signer")]
    Signer,
    /// A signature, aggregate, share, or recovered certificate is invalid.
    #[error("invalid signature")]
    Signature,
    /// The supplied messages do not form the required certificate quorum.
    #[error("invalid quorum")]
    Quorum,
    /// A compact transcript does not reconstruct the supplied messages.
    #[error("invalid vote transcript")]
    Transcript,
    /// The object belongs to another epoch.
    #[error("epoch mismatch")]
    Context,
}

#[derive(Clone)]
struct Signer {
    participant: Participant,
    ordinary: Private,
    da: Share,
    nullification: Share,
}

#[derive(Clone, Copy)]
enum SignatureVerification {
    Checked,
    Preverified,
}

/// An ordinary BLS key roster whose proofs of possession have been verified.
///
/// Multimmit aggregates ordinary signatures into V-QCs and L-QCs. Accepting an unproven public
/// key would make those certificates vulnerable to rogue-key attacks, so [`Scheme`] can only be
/// constructed from this validated type.
#[derive(Clone)]
pub struct Roster<P: PublicKey, V: Variant> {
    participants: BiMap<P, V::Public>,
    proof_namespace: Vec<u8>,
}

impl<P: PublicKey, V: Variant> fmt::Debug for Roster<P, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Roster")
            .field("participants", &self.participants.len())
            .finish()
    }
}

impl<P: PublicKey, V: Variant> Roster<P, V> {
    /// Verifies participant proofs of possession and constructs an ordered roster.
    ///
    /// Each tuple binds an identity key to an ordinary BLS public key and its proof. Identity and
    /// BLS keys must both be unique. Verification may be parallelized by `strategy`.
    pub fn verify(
        namespace: &[u8],
        expected: usize,
        mut participants: Vec<(P, V::Public, V::Signature)>,
        strategy: &impl Strategy,
    ) -> Option<Self> {
        if expected == 0 || participants.len() != expected {
            return None;
        }

        participants.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        if participants.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return None;
        }
        let mut public_keys = HashSet::with_capacity(expected);
        if participants
            .iter()
            .any(|(_, public, _)| !public_keys.insert(*public))
        {
            return None;
        }

        let namespace = Namespace::new(namespace);
        strategy
            .try_map_collect_vec(&participants, |(_, public, proof)| {
                if public == &V::Public::zero() || proof == &V::Signature::zero() {
                    return Err(());
                }
                ops::verify_proof_of_possession::<V>(public, &namespace.proof_of_possession, proof)
                    .map_err(|_| ())
            })
            .ok()?;

        let participants = BiMap::try_from_iter(
            participants
                .into_iter()
                .map(|(identity, public, _)| (identity, public)),
        )
        .ok()?;
        Some(Self {
            participants,
            proof_namespace: namespace.proof_of_possession,
        })
    }

    /// Generates the proof of possession required by [`Self::verify`].
    pub fn proof_of_possession(namespace: &[u8], private: &Private) -> V::Signature {
        let namespace = Namespace::new(namespace);
        ops::sign_proof_of_possession::<V>(private, &namespace.proof_of_possession)
    }

    /// Returns identity keys in participant-index order.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns ordinary BLS public keys in participant-index order.
    pub const fn public_keys(&self) -> &BiMap<P, V::Public> {
        &self.participants
    }

    fn matches_namespace(&self, namespace: &[u8]) -> bool {
        self.proof_namespace == Namespace::new(namespace).proof_of_possession
    }
}

/// Multimmit's concrete BLS12-381 scheme.
///
/// `V` may be either [`commonware_cryptography::bls12381::primitives::variant::MinPk`] or
/// [`commonware_cryptography::bls12381::primitives::variant::MinSig`].
///
/// The ordinary signing roster is proof-of-possession checked by [`Roster`]. The DA and
/// nullification sharings must be generated independently. The constructor checks their public
/// structure, thresholds, and distinct group identities, but cannot prove how key material was
/// generated.
#[derive(Clone)]
pub struct Scheme<P: PublicKey, V: Variant> {
    epoch: Epoch,
    namespace: Namespace,
    codec: CodecConfig,
    leaders: LeaderSchedule,
    producers: Arc<[Participant]>,
    participants: BiMap<P, V::Public>,
    da: Option<Sharing<V>>,
    nullification: Option<Sharing<V>>,
    da_identity: V::Public,
    nullification_identity: V::Public,
    signer: Option<Signer>,
}

impl<P: PublicKey, V: Variant> fmt::Debug for Scheme<P, V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Scheme")
            .field("epoch", &self.epoch)
            .field("participants", &self.participants.len())
            .field("me", &self.me())
            .finish()
    }
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Creates a signer with ordinary, DA-share, and nullification-share key material.
    ///
    /// See the type-level security requirements. Returns `None` when any key, share, sharing, or
    /// participant index is inconsistent with the epoch configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn signer<D: Digest>(
        config: &Config<D>,
        roster: Roster<P, V>,
        ordinary: Private,
        da: Sharing<V>,
        da_share: Share,
        nullification: Sharing<V>,
        nullification_share: Share,
    ) -> Option<Self> {
        if !roster.matches_namespace(config.namespace()) {
            return None;
        }
        validate_public_material(config, roster.public_keys(), &da, &nullification)?;

        let ordinary_public = ops::compute_public::<V>(&ordinary);
        let participant = Participant::from_usize(
            roster
                .public_keys()
                .values()
                .iter()
                .position(|public| public == &ordinary_public)?,
        );
        if da_share.index != participant
            || nullification_share.index != participant
            || da.partial_public(participant).ok()? != da_share.public::<V>()
            || nullification.partial_public(participant).ok()? != nullification_share.public::<V>()
        {
            return None;
        }

        Some(Self::new_full(
            config,
            roster.participants,
            da,
            nullification,
            Some(Signer {
                participant,
                ordinary,
                da: da_share,
                nullification: nullification_share,
            }),
        ))
    }

    /// Creates a verifier with the ordinary key roster and both public threshold sharings.
    ///
    /// See the type-level security requirements. Returns `None` when the public material is
    /// inconsistent with the epoch configuration.
    pub fn verifier<D: Digest>(
        config: &Config<D>,
        roster: Roster<P, V>,
        da: Sharing<V>,
        nullification: Sharing<V>,
    ) -> Option<Self> {
        if !roster.matches_namespace(config.namespace()) {
            return None;
        }
        validate_public_material(config, roster.public_keys(), &da, &nullification)?;
        Some(Self::new_full(
            config,
            roster.participants,
            da,
            nullification,
            None,
        ))
    }

    /// Creates a verifier for complete certificates without retaining public threshold sharings.
    ///
    /// This role verifies ordinary signatures, V-QCs, L-QCs, recovered DA certificates, and
    /// recovered nullifications. It cannot verify or recover threshold shares.
    pub fn certificate_verifier<D: Digest>(
        config: &Config<D>,
        roster: Roster<P, V>,
        da_identity: V::Public,
        nullification_identity: V::Public,
    ) -> Option<Self> {
        if !roster.matches_namespace(config.namespace()) {
            return None;
        }
        validate_certificate_material::<P, V, D>(
            config,
            roster.public_keys(),
            &da_identity,
            &nullification_identity,
        )?;
        Some(Self {
            epoch: config.epoch(),
            namespace: Namespace::new(config.namespace()),
            codec: config.codec_config(),
            leaders: config.leaders().clone(),
            producers: config.producers().into(),
            participants: roster.participants,
            da: None,
            nullification: None,
            da_identity,
            nullification_identity,
            signer: None,
        })
    }

    fn new_full<D: Digest>(
        config: &Config<D>,
        participants: BiMap<P, V::Public>,
        da: Sharing<V>,
        nullification: Sharing<V>,
        signer: Option<Signer>,
    ) -> Self {
        da.precompute_partial_publics();
        nullification.precompute_partial_publics();
        let da_identity = *da.public();
        let nullification_identity = *nullification.public();
        Self {
            epoch: config.epoch(),
            namespace: Namespace::new(config.namespace()),
            codec: config.codec_config(),
            leaders: config.leaders().clone(),
            producers: config.producers().into(),
            participants,
            da: Some(da),
            nullification: Some(nullification),
            da_identity,
            nullification_identity,
            signer,
        }
    }

    /// Returns this scheme with `config`'s leader schedule.
    ///
    /// # Panics
    ///
    /// Panics if any protocol fact other than the leader schedule differs.
    pub(crate) fn with_leaders<D: Digest>(mut self, config: &Config<D>) -> Self {
        assert_eq!(self.epoch, config.epoch(), "scheme and config epoch differ");
        assert_eq!(
            self.namespace,
            Namespace::new(config.namespace()),
            "scheme and config namespace differ"
        );
        assert_eq!(
            self.codec,
            config.codec_config(),
            "scheme and config protocol limits differ"
        );
        assert!(
            self.matches_producers(config.producers()),
            "scheme and config producer ownership differ"
        );
        self.leaders = config.leaders().clone();
        self
    }

    /// Returns the ordered identity-key committee.
    pub const fn participants(&self) -> &Set<P> {
        self.participants.keys()
    }

    /// Returns the ordinary BLS public-key roster in identity-key order.
    pub const fn public_keys(&self) -> &BiMap<P, V::Public> {
        &self.participants
    }

    /// Returns this instance's participant index when it can sign.
    pub fn me(&self) -> Option<Participant> {
        self.signer.as_ref().map(|signer| signer.participant)
    }

    /// Returns the immutable decoding and quorum limits for this epoch.
    pub const fn codec_config(&self) -> CodecConfig {
        self.codec
    }

    /// Returns whether this scheme is bound to `namespace`.
    pub(crate) fn matches_namespace(&self, namespace: &[u8]) -> bool {
        self.namespace == Namespace::new(namespace)
    }

    /// Returns whether this scheme uses the supplied chain-owner order.
    pub(crate) fn matches_producers(&self, producers: &[Participant]) -> bool {
        self.producers.as_ref() == producers
    }

    /// Returns the public `n-2f` DA sharing when this is a full verifier.
    pub const fn da_sharing(&self) -> Option<&Sharing<V>> {
        self.da.as_ref()
    }

    /// Returns the public `2f+1` nullification sharing when this is a full verifier.
    pub const fn nullification_sharing(&self) -> Option<&Sharing<V>> {
        self.nullification.as_ref()
    }

    /// Returns the DA threshold group identity.
    pub const fn da_identity(&self) -> &V::Public {
        &self.da_identity
    }

    /// Returns the nullification threshold group identity.
    pub const fn nullification_identity(&self) -> &V::Public {
        &self.nullification_identity
    }

    /// Signs a transaction-block header for the local participant's producer chain.
    pub(crate) fn sign_transaction_block<D: Digest>(
        &self,
        header: TransactionBlockHeader<D>,
    ) -> Result<SignedTransactionBlock<V, D>, Error> {
        let expected = self.producer(header.chain().get())?;
        let attestation = self.sign_expected(Subject::transaction_block(&header), expected)?;
        Ok(SignedTransactionBlock::new(header, attestation))
    }

    /// Verifies a producer's transaction-block attestation.
    pub fn verify_transaction_block<D: Digest>(
        &self,
        block: &SignedTransactionBlock<V, D>,
    ) -> bool {
        self.producer(block.header().chain().get())
            .is_ok_and(|producer| block.signer() == producer)
            && self.verify_attestation(
                Subject::transaction_block(block.header()),
                block.attestation(),
            )
    }

    /// Signs a data-availability threshold share over one complete header.
    pub(crate) fn sign_da_vote<D: Digest>(
        &self,
        header: TransactionBlockHeader<D>,
    ) -> Result<DaVote<V, D>, Error> {
        self.ensure_chain(header.chain().get())?;
        let share = self.sign_da(Subject::da_vote(&header))?;
        Ok(DaVote::new(header, share))
    }

    /// Verifies one data-availability threshold share.
    pub fn verify_da_vote<D: Digest>(&self, vote: &DaVote<V, D>) -> bool {
        (vote.header().chain().get() as usize) < self.codec.chains()
            && self.da.as_ref().is_some_and(|da| {
                self.verify_threshold_share(da, Subject::da_vote(vote.header()), vote.share())
            })
    }

    /// Signs a complete leader block as the round's scheduled leader.
    pub(crate) fn sign_leader_block<D: Digest>(
        &self,
        block: LeaderBlock<V, D>,
    ) -> Result<SignedLeaderBlock<V, D>, Error> {
        self.ensure_leader(&block)?;
        let expected = self.leaders.leader(block.view());
        let attestation = self.sign_expected(Subject::leader_block(&block), expected)?;
        Ok(SignedLeaderBlock::new(block, attestation))
    }

    /// Verifies the scheduled leader's signature and every embedded DA certificate.
    pub fn verify_leader_block<D: Digest>(
        &self,
        block: &SignedLeaderBlock<V, D>,
        strategy: &impl Strategy,
    ) -> bool {
        if self.ensure_leader(block.block()).is_err() {
            return false;
        }
        let expected = self.leaders.leader(block.view());
        if block.signer() != expected
            || !self.verify_attestation(Subject::leader_block(block.block()), block.attestation())
        {
            return false;
        }

        strategy
            .map_collect_vec(block.block().proposals(), |proposal| {
                let Anchor::Certificate(certificate) = proposal.anchor() else {
                    return true;
                };
                self.verify_da_certificate(certificate)
            })
            .into_iter()
            .all(identity)
    }

    /// Signs one complete consensus vote with the local ordinary key.
    pub(crate) fn sign_vote<D: Digest>(&self, body: VoteBody<D>) -> Result<Vote<V, D>, Error> {
        self.ensure_vote_body(&body)?;
        let attestation = self.sign_attestation(Subject::vote(&body))?;
        Ok(Vote::new(body, attestation))
    }

    /// Verifies a complete consensus vote.
    pub fn verify_vote<D: Digest>(&self, vote: &Vote<V, D>) -> bool {
        self.ensure_vote_body(vote.body()).is_ok()
            && self.verify_attestation(Subject::vote(vote.body()), vote.attestation())
    }

    /// Signs an attributed abstention for a round.
    pub(crate) fn sign_novote(&self, round: Round) -> Result<NoVote<V>, Error> {
        let attestation = self.sign_attestation(Subject::NoVote(round))?;
        NoVote::new(round, attestation).map_err(|_| Error::Transcript)
    }

    /// Verifies an attributed abstention.
    pub fn verify_novote(&self, novote: &NoVote<V>) -> bool {
        self.verify_attestation(Subject::NoVote(novote.round()), novote.attestation())
    }

    /// Signs a threshold share authorizing a round to be nullified.
    pub(crate) fn sign_nullify(&self, round: Round) -> Result<Nullify<V>, Error> {
        let share = self.sign_nullification(Subject::Nullify(round))?;
        Nullify::new(round, share).map_err(|_| Error::Transcript)
    }

    /// Verifies one nullification threshold share.
    pub fn verify_nullify(&self, nullify: &Nullify<V>) -> bool {
        self.nullification.as_ref().is_some_and(|sharing| {
            self.verify_threshold_share(sharing, Subject::Nullify(nullify.round()), nullify.share())
        })
    }

    /// Recovers a DA certificate from exactly `n-2f` shares for one header.
    pub fn assemble_da_certificate<D: Digest>(
        &self,
        votes: &[DaVote<V, D>],
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<V, D>, Error> {
        self.assemble_da_certificate_with(votes, SignatureVerification::Checked, strategy)
    }

    pub(crate) fn assemble_da_certificate_preverified<D: Digest>(
        &self,
        votes: &[DaVote<V, D>],
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<V, D>, Error> {
        self.assemble_da_certificate_with(votes, SignatureVerification::Preverified, strategy)
    }

    fn assemble_da_certificate_with<D: Digest>(
        &self,
        votes: &[DaVote<V, D>],
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<V, D>, Error> {
        if votes.len() != self.codec.da_quorum() || votes.is_empty() {
            return Err(Error::Quorum);
        }
        let header = votes[0].header().clone();
        self.ensure_chain(header.chain().get())?;
        self.ensure_epoch(header.epoch())?;
        if votes.iter().any(|vote| vote.header() != &header) {
            return Err(Error::Transcript);
        }

        let da = self.da.as_ref().ok_or(Error::SharingUnavailable)?;
        let subject = Subject::da_vote(&header);
        let certificate = recover(
            da,
            votes.iter().map(DaVote::share),
            subject.namespace(&self.namespace),
            &subject.message(),
            verification,
            strategy,
        )?;
        Ok(DaCertificate::new(header, certificate))
    }

    /// Verifies a recovered data-availability certificate.
    pub fn verify_da_certificate<D: Digest>(&self, certificate: &DaCertificate<V, D>) -> bool {
        let header = certificate.header();
        if header.chain().get() as usize >= self.codec.chains()
            || self.ensure_epoch(header.epoch()).is_err()
        {
            return false;
        }
        verify_recovered(
            &self.da_identity,
            Subject::da_vote(header),
            certificate.certificate(),
            &self.namespace,
        )
    }

    /// Recovers a nullification from exactly `2f+1` shares for one round.
    pub fn assemble_nullification(
        &self,
        shares: &[Nullify<V>],
        strategy: &impl Strategy,
    ) -> Result<Nullification<V>, Error> {
        self.assemble_nullification_with(shares, SignatureVerification::Checked, strategy)
    }

    pub(crate) fn assemble_nullification_preverified(
        &self,
        shares: &[Nullify<V>],
        strategy: &impl Strategy,
    ) -> Result<Nullification<V>, Error> {
        self.assemble_nullification_with(shares, SignatureVerification::Preverified, strategy)
    }

    fn assemble_nullification_with(
        &self,
        shares: &[Nullify<V>],
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<Nullification<V>, Error> {
        if shares.len() != self.codec.nullification_quorum() || shares.is_empty() {
            return Err(Error::Quorum);
        }
        let round = shares[0].round();
        self.ensure_epoch(round.epoch())?;
        if shares.iter().any(|share| share.round() != round) {
            return Err(Error::Transcript);
        }

        let nullification = self
            .nullification
            .as_ref()
            .ok_or(Error::SharingUnavailable)?;
        let subject = Subject::Nullify(round);
        let certificate = recover(
            nullification,
            shares.iter().map(Nullify::share),
            subject.namespace(&self.namespace),
            &subject.message(),
            verification,
            strategy,
        )?;
        Nullification::new(round, certificate).map_err(|_| Error::Transcript)
    }

    /// Verifies a recovered nullification certificate.
    pub fn verify_nullification(&self, certificate: &Nullification<V>) -> bool {
        if self.ensure_epoch(certificate.epoch()).is_err() {
            return false;
        }
        verify_recovered(
            &self.nullification_identity,
            Subject::Nullify(certificate.round()),
            certificate.certificate(),
            &self.namespace,
        )
    }

    /// Assembles a V-QC from `n-f..=n` complete view messages.
    pub fn assemble_vqc<H: Hasher<Digest = D>, D: Digest>(
        &self,
        leader: LeaderBlock<V, D>,
        messages: &[ViewMessage<V, D>],
        strategy: &impl Strategy,
    ) -> Result<Vqc<V, D>, Error> {
        self.assemble_vqc_with::<H, D>(leader, messages, SignatureVerification::Checked, strategy)
    }

    pub(crate) fn assemble_vqc_preverified<H: Hasher<Digest = D>, D: Digest>(
        &self,
        leader: LeaderBlock<V, D>,
        messages: &[ViewMessage<V, D>],
        strategy: &impl Strategy,
    ) -> Result<Vqc<V, D>, Error> {
        self.assemble_vqc_with::<H, D>(
            leader,
            messages,
            SignatureVerification::Preverified,
            strategy,
        )
    }

    fn assemble_vqc_with<H: Hasher<Digest = D>, D: Digest>(
        &self,
        leader: LeaderBlock<V, D>,
        messages: &[ViewMessage<V, D>],
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<Vqc<V, D>, Error> {
        self.ensure_leader(&leader)?;
        if !(self.codec.view_quorum()..=self.codec.vqc_max_messages()).contains(&messages.len()) {
            return Err(Error::Quorum);
        }

        let leader_digest = leader.digest::<H>();
        let mut target = Vec::new();
        let mut conflicting = Vec::new();
        let mut novoters = Vec::new();
        let mut transcript = Vec::with_capacity(messages.len());
        let mut signatures = Vec::with_capacity(messages.len());

        for message in messages {
            match message {
                ViewMessage::Vote(vote) => {
                    self.ensure_vote_body(vote.body())?;
                    if vote.body().round() != leader.round() {
                        return Err(Error::Transcript);
                    }
                    let signature = decoded(vote.attestation())?;
                    transcript.push((
                        vote.signer(),
                        Subject::vote(vote.body()).namespace(&self.namespace),
                        Subject::vote(vote.body()).message(),
                    ));
                    signatures.push(signature);

                    if vote.body().leader() == leader_digest {
                        if !vote.body().valid_for::<H, V>(&leader) {
                            return Err(Error::Transcript);
                        }
                        target.push((vote.signer(), vote.body().clone()));
                    } else {
                        conflicting.push(
                            ConflictingVote::new(
                                vote.signer(),
                                vote.body().leader(),
                                vote.body().positions().to_vec(),
                                vote.body().extensions().to_vec(),
                                self.codec,
                            )
                            .map_err(|_| Error::Transcript)?,
                        );
                    }
                }
                ViewMessage::NoVote(novote) => {
                    if novote.round() != leader.round() {
                        return Err(Error::Transcript);
                    }
                    let signature = decoded(novote.attestation())?;
                    let subject = Subject::NoVote(novote.round());
                    transcript.push((
                        novote.signer(),
                        subject.namespace(&self.namespace),
                        subject.message(),
                    ));
                    signatures.push(signature);
                    novoters.push(novote.signer());
                }
            }
        }
        if target.len() < self.codec.designation_quorum() {
            return Err(Error::Quorum);
        }

        let signature = self.aggregate(&transcript, &signatures, verification, strategy)?;
        conflicting.sort_by_key(ConflictingVote::signer);
        novoters.sort_unstable();
        let tally = Tally::from_votes::<V, H, _>(&leader, target, self.codec)
            .map_err(|_| Error::Transcript)?;
        let novoters = Signers::from(self.participants.len(), novoters);
        Vqc::new(leader, tally, novoters, conflicting, signature, self.codec)
            .map_err(|_| Error::Quorum)
    }

    /// Verifies every ordinary signature represented by a V-QC's compact transcript.
    pub fn verify_vqc<H: Hasher<Digest = D>, D: Digest>(
        &self,
        certificate: &Vqc<V, D>,
        strategy: &impl Strategy,
    ) -> Option<CertificateId<D>> {
        if self.ensure_epoch(certificate.epoch()).is_err()
            || certificate.validate(self.codec).is_err()
        {
            return None;
        }
        let transcript =
            vqc_transcript::<V, D, H>(certificate, self.codec, &self.namespace).ok()?;
        let signature = certificate.signature()?;
        self.verify_aggregate(&transcript, signature, strategy)
            .then(|| certificate.id::<H>())
    }

    /// Assembles an L-QC from exactly `n-f` ordinary votes for one leader.
    pub fn assemble_lqc<H: Hasher<Digest = D>, D: Digest>(
        &self,
        leader: LeaderBlock<V, D>,
        votes: &[Vote<V, D>],
        strategy: &impl Strategy,
    ) -> Result<Lqc<V, D>, Error> {
        self.assemble_lqc_with::<H, D>(leader, votes, SignatureVerification::Checked, strategy)
    }

    pub(crate) fn assemble_lqc_preverified<H: Hasher<Digest = D>, D: Digest>(
        &self,
        leader: LeaderBlock<V, D>,
        votes: &[Vote<V, D>],
        strategy: &impl Strategy,
    ) -> Result<Lqc<V, D>, Error> {
        self.assemble_lqc_with::<H, D>(leader, votes, SignatureVerification::Preverified, strategy)
    }

    fn assemble_lqc_with<H: Hasher<Digest = D>, D: Digest>(
        &self,
        leader: LeaderBlock<V, D>,
        votes: &[Vote<V, D>],
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<Lqc<V, D>, Error> {
        self.ensure_leader(&leader)?;
        if votes.len() != self.codec.view_quorum() {
            return Err(Error::Quorum);
        }

        let leader_digest = leader.digest::<H>();
        let mut tally_votes = Vec::with_capacity(votes.len());
        let mut transcript = Vec::with_capacity(votes.len());
        let mut signatures = Vec::with_capacity(votes.len());
        for vote in votes {
            self.ensure_vote_body(vote.body())?;
            if vote.body().leader() != leader_digest || !vote.body().valid_for::<H, V>(&leader) {
                return Err(Error::Transcript);
            }
            tally_votes.push((vote.signer(), vote.body().clone()));
            let subject = Subject::vote(vote.body());
            transcript.push((
                vote.signer(),
                subject.namespace(&self.namespace),
                subject.message(),
            ));
            signatures.push(decoded(vote.attestation())?);
        }

        let signature = self.aggregate(&transcript, &signatures, verification, strategy)?;
        let tally = Tally::from_votes::<V, H, _>(&leader, tally_votes, self.codec)
            .map_err(|_| Error::Transcript)?;
        Lqc::new(leader, tally, signature, self.codec).map_err(|error| {
            if matches!(error, crate::multimmit::types::Error::Quorum) {
                Error::Quorum
            } else {
                Error::Transcript
            }
        })
    }

    /// Verifies every ordinary vote signature represented by an L-QC's tally.
    pub fn verify_lqc<H: Hasher<Digest = D>, D: Digest>(
        &self,
        certificate: &Lqc<V, D>,
        strategy: &impl Strategy,
    ) -> Option<CertificateId<D>> {
        if self.ensure_epoch(certificate.epoch()).is_err()
            || certificate.validate(self.codec).is_err()
        {
            return None;
        }

        let mut transcript = Vec::with_capacity(self.codec.view_quorum());
        for signer in certificate.tally().signers().iter() {
            let body = certificate
                .tally()
                .vote::<V, H>(certificate.leader(), signer, self.codec)
                .ok()?;
            let subject = Subject::vote(&body);
            transcript.push((
                signer,
                subject.namespace(&self.namespace),
                subject.message(),
            ));
        }
        let signature = certificate.signature()?;
        self.verify_aggregate(&transcript, signature, strategy)
            .then(|| certificate.id::<H>())
    }

    /// Verifies a heterogeneous artifact batch and returns one verdict per input item.
    ///
    /// Items are independent: an invalid artifact cannot poison a valid neighbor. Executors remain
    /// responsible for returning each verdict under the local machine's exact verification ticket.
    ///
    /// Every artifact decomposes into pairing claims, and the whole batch is checked as one
    /// randomly scaled pairing product costing one pairing per distinct message instead of one
    /// per signature. On failure, bisection isolates the invalid artifacts; an invalid
    /// signature is attributable evidence of misbehavior, so the optimistic path is the
    /// common case.
    pub fn verify_artifacts<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        artifacts: &[Unverified<'_, V, D>],
        strategy: &impl Strategy,
    ) -> Vec<bool> {
        // Structural checks and claim extraction run per artifact; message construction and
        // transcript reconstruction dominate, so they parallelize.
        let claims: Vec<Option<Vec<Claim<'_, V>>>> =
            strategy.map_collect_vec(artifacts, |artifact| self.artifact_claims::<H, D>(artifact));

        let mut verdicts: Vec<bool> = claims.iter().map(Option::is_some).collect();
        let mut owners = Vec::new();
        let mut transcripts = Vec::new();
        for (index, set) in claims.iter().enumerate() {
            let Some(set) = set else {
                continue;
            };
            for claim in set {
                owners.push(index);
                transcripts.push(batch::Transcript {
                    signature: claim.signature,
                    terms: claim
                        .terms
                        .iter()
                        .map(|(public, namespace, message)| (*public, *namespace, message.as_ref()))
                        .collect(),
                });
            }
        }
        for invalid in batch::verify_transcripts::<R, V>(rng, &transcripts, strategy) {
            verdicts[owners[invalid]] = false;
        }
        verdicts
    }

    /// Decomposes one artifact into its pairing claims, running every structural check.
    ///
    /// Returns `None` when the artifact fails a non-cryptographic check; otherwise the
    /// artifact is valid exactly when every returned claim's pairing product holds. Claims
    /// mirror the individual verifiers: the equivalence is pinned by the crypto conformance
    /// tests, which compare batched verdicts against per-artifact verification for every kind.
    fn artifact_claims<'a, H: Hasher<Digest = D>, D: Digest>(
        &'a self,
        artifact: &Unverified<'_, V, D>,
    ) -> Option<Vec<Claim<'a, V>>> {
        match artifact {
            Unverified::TransactionBlock(block) => self
                .producer(block.header().chain().get())
                .is_ok_and(|producer| block.signer() == producer)
                .then(|| {
                    self.attestation_claim(
                        Subject::transaction_block(block.header()),
                        block.attestation(),
                    )
                })?
                .map(|claim| vec![claim]),
            Unverified::DaVote(vote) => {
                if (vote.header().chain().get() as usize) >= self.codec.chains() {
                    return None;
                }
                let sharing = self.da.as_ref()?;
                self.share_claim(sharing, Subject::da_vote(vote.header()), vote.share())
                    .map(|claim| vec![claim])
            }
            Unverified::DaCertificate(certificate) => self
                .da_certificate_claim(certificate)
                .map(|claim| vec![claim]),
            Unverified::LeaderBlock(block) => {
                if self.ensure_leader(block.block()).is_err()
                    || block.signer() != self.leaders.leader(block.view())
                {
                    return None;
                }
                let mut claims = vec![self.attestation_claim(
                    Subject::leader_block(block.block()),
                    block.attestation(),
                )?];
                for proposal in block.block().proposals() {
                    let Anchor::Certificate(certificate) = proposal.anchor() else {
                        continue;
                    };
                    claims.push(self.da_certificate_claim(certificate)?);
                }
                Some(claims)
            }
            Unverified::Vote(vote) => {
                if self.ensure_vote_body(vote.body()).is_err() {
                    return None;
                }
                self.attestation_claim(Subject::vote(vote.body()), vote.attestation())
                    .map(|claim| vec![claim])
            }
            Unverified::NoVote(vote) => self
                .attestation_claim(Subject::NoVote(vote.round()), vote.attestation())
                .map(|claim| vec![claim]),
            Unverified::Nullify(nullify) => {
                let sharing = self.nullification.as_ref()?;
                self.share_claim(sharing, Subject::Nullify(nullify.round()), nullify.share())
                    .map(|claim| vec![claim])
            }
            Unverified::Nullification(certificate) => {
                if self.ensure_epoch(certificate.epoch()).is_err() {
                    return None;
                }
                self.recovered_claim(
                    &self.nullification_identity,
                    Subject::Nullify(certificate.round()),
                    certificate.certificate(),
                )
                .map(|claim| vec![claim])
            }
            Unverified::Vqc(certificate) => {
                if self.ensure_epoch(certificate.epoch()).is_err()
                    || certificate.validate(self.codec).is_err()
                {
                    return None;
                }
                let transcript =
                    vqc_transcript::<V, D, H>(certificate, self.codec, &self.namespace).ok()?;
                self.aggregate_claim(&transcript, certificate.signature()?)
                    .map(|claim| vec![claim])
            }
            Unverified::Lqc(certificate) => {
                if self.ensure_epoch(certificate.epoch()).is_err()
                    || certificate.validate(self.codec).is_err()
                {
                    return None;
                }
                let mut transcript = Vec::with_capacity(self.codec.view_quorum());
                for signer in certificate.tally().signers().iter() {
                    let body = certificate
                        .tally()
                        .vote::<V, H>(certificate.leader(), signer, self.codec)
                        .ok()?;
                    let subject = Subject::vote(&body);
                    transcript.push((
                        signer,
                        subject.namespace(&self.namespace),
                        subject.message(),
                    ));
                }
                self.aggregate_claim(&transcript, certificate.signature()?)
                    .map(|claim| vec![claim])
            }
        }
    }

    /// Builds the claim for one attributed ordinary signature.
    fn attestation_claim(
        &self,
        subject: Subject,
        attestation: &Attestation<V>,
    ) -> Option<Claim<'_, V>> {
        self.ensure_epoch(subject.epoch()).ok()?;
        let public = self.public(attestation.signer())?;
        let signature = decoded(attestation).ok()?;
        Some(Claim {
            signature,
            terms: vec![(
                *public,
                subject.namespace(&self.namespace),
                subject.message(),
            )],
        })
    }

    /// Builds the claim for one threshold share, against its partial public key.
    fn share_claim(
        &self,
        sharing: &Sharing<V>,
        subject: Subject,
        share: &ThresholdShare<V>,
    ) -> Option<Claim<'_, V>> {
        self.ensure_epoch(subject.epoch()).ok()?;
        let partial = partial(share).ok()?;
        let public = sharing.partial_public(partial.index).ok()?;
        Some(Claim {
            signature: partial.value,
            terms: vec![(
                public,
                subject.namespace(&self.namespace),
                subject.message(),
            )],
        })
    }

    /// Builds the claim for one recovered threshold certificate, against a group identity.
    fn recovered_claim(
        &self,
        identity: &V::Public,
        subject: Subject,
        certificate: &certificate_threshold::Certificate<V>,
    ) -> Option<Claim<'_, V>> {
        let signature = certificate.get()?;
        if signature == &V::Signature::zero() {
            return None;
        }
        Some(Claim {
            signature: *signature,
            terms: vec![(
                *identity,
                subject.namespace(&self.namespace),
                subject.message(),
            )],
        })
    }

    /// Builds the claim for one data-availability certificate, including its header checks.
    fn da_certificate_claim<D: Digest>(
        &self,
        certificate: &DaCertificate<V, D>,
    ) -> Option<Claim<'_, V>> {
        let header = certificate.header();
        if header.chain().get() as usize >= self.codec.chains()
            || self.ensure_epoch(header.epoch()).is_err()
        {
            return None;
        }
        self.recovered_claim(
            &self.da_identity,
            Subject::da_vote(header),
            certificate.certificate(),
        )
    }

    /// Builds the atomic claim for one aggregate transcript (a V-QC or L-QC).
    ///
    /// Mirrors [`aggregate::verify_transcript`]'s validation: the transcript must be
    /// non-empty, every signer must resolve to a distinct non-zero public key, and the
    /// signature must be non-zero.
    fn aggregate_claim<'a>(
        &'a self,
        transcript: &[TranscriptEntry<'a>],
        signature: &aggregate::Signature<V>,
    ) -> Option<Claim<'a, V>> {
        if transcript.is_empty() || signature.element() == &V::Signature::zero() {
            return None;
        }
        let mut publics = HashSet::with_capacity(transcript.len());
        let terms = transcript
            .iter()
            .map(|(signer, namespace, message)| {
                let public = self.public(*signer)?;
                publics
                    .insert(*public)
                    .then_some((*public, *namespace, message.clone()))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Claim {
            signature: *signature.element(),
            terms,
        })
    }

    fn sign_attestation(&self, subject: Subject) -> Result<Attestation<V>, Error> {
        self.ensure_epoch(subject.epoch())?;
        let signer = self.signer.as_ref().ok_or(Error::VerifierOnly)?;
        let signature = ops::sign_message::<V>(
            &signer.ordinary,
            subject.namespace(&self.namespace),
            &subject.message(),
        );
        Ok(Attestation::new(signer.participant, signature.into()))
    }

    fn sign_expected(
        &self,
        subject: Subject,
        expected: Participant,
    ) -> Result<Attestation<V>, Error> {
        let attestation = self.sign_attestation(subject)?;
        if attestation.signer() != expected {
            return Err(Error::Signer);
        }
        Ok(attestation)
    }

    fn sign_da(&self, subject: Subject) -> Result<ThresholdShare<V>, Error> {
        self.ensure_epoch(subject.epoch())?;
        let signer = self.signer.as_ref().ok_or(Error::VerifierOnly)?;
        let share = threshold::sign_message::<V>(
            &signer.da,
            subject.namespace(&self.namespace),
            &subject.message(),
        );
        Ok(ThresholdShare::new(share.index, share.value.into()))
    }

    fn sign_nullification(&self, subject: Subject) -> Result<ThresholdShare<V>, Error> {
        self.ensure_epoch(subject.epoch())?;
        let signer = self.signer.as_ref().ok_or(Error::VerifierOnly)?;
        let share = threshold::sign_message::<V>(
            &signer.nullification,
            subject.namespace(&self.namespace),
            &subject.message(),
        );
        Ok(ThresholdShare::new(share.index, share.value.into()))
    }

    fn verify_attestation(&self, subject: Subject, attestation: &Attestation<V>) -> bool {
        if self.ensure_epoch(subject.epoch()).is_err() {
            return false;
        }
        let Some(public) = self.public(attestation.signer()) else {
            return false;
        };
        let Some(signature) = attestation.signature() else {
            return false;
        };
        signature != &V::Signature::zero()
            && ops::verify_message::<V>(
                public,
                subject.namespace(&self.namespace),
                &subject.message(),
                signature,
            )
            .is_ok()
    }

    fn verify_threshold_share(
        &self,
        sharing: &Sharing<V>,
        subject: Subject,
        share: &ThresholdShare<V>,
    ) -> bool {
        if self.ensure_epoch(subject.epoch()).is_err() {
            return false;
        }
        let Ok(share) = partial(share) else {
            return false;
        };
        threshold::verify_message(
            sharing,
            subject.namespace(&self.namespace),
            &subject.message(),
            &share,
        )
        .is_ok()
    }

    fn aggregate(
        &self,
        transcript: &[TranscriptEntry<'_>],
        signatures: &[V::Signature],
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<aggregate::Signature<V>, Error> {
        if transcript.len() != signatures.len() {
            return Err(Error::Transcript);
        }
        if matches!(verification, SignatureVerification::Preverified) {
            let signature = aggregate::combine_signatures::<V, _>(signatures);
            return self
                .verify_aggregate(transcript, &signature, strategy)
                .then_some(signature)
                .ok_or(Error::Signature);
        }

        let entries = transcript
            .iter()
            .zip(signatures)
            .map(|((signer, namespace, message), signature)| {
                let public = self.public(*signer).ok_or(Error::Transcript)?;
                Ok((public, *namespace, message.as_ref(), signature))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        aggregate::aggregate_signatures::<V>(entries, strategy).map_err(|_| Error::Signature)
    }

    fn verify_aggregate(
        &self,
        transcript: &[TranscriptEntry<'_>],
        signature: &aggregate::Signature<V>,
        strategy: &impl Strategy,
    ) -> bool {
        let entries = transcript
            .iter()
            .map(|(signer, namespace, message)| {
                self.public(*signer)
                    .map(|public| (public, *namespace, message.as_ref()))
            })
            .collect::<Option<Vec<_>>>();
        let Some(entries) = entries else {
            return false;
        };
        aggregate::verify_transcript::<V>(entries, signature, strategy).is_ok()
    }

    fn public(&self, participant: Participant) -> Option<&V::Public> {
        self.participants.value(usize::from(participant))
    }

    fn ensure_epoch(&self, epoch: Epoch) -> Result<(), Error> {
        if epoch != self.epoch {
            return Err(Error::Context);
        }
        Ok(())
    }

    fn ensure_leader<D: Digest>(&self, leader: &LeaderBlock<V, D>) -> Result<(), Error> {
        self.ensure_epoch(leader.epoch())?;
        leader.validate(self.codec).map_err(|_| Error::Transcript)
    }

    fn ensure_vote_body<D: Digest>(&self, body: &VoteBody<D>) -> Result<(), Error> {
        self.ensure_epoch(body.epoch())?;
        body.validate(self.codec).map_err(|_| Error::Transcript)
    }

    const fn ensure_chain(&self, chain: u32) -> Result<(), Error> {
        if chain as usize >= self.codec.chains() {
            return Err(Error::Signer);
        }
        Ok(())
    }

    fn producer(&self, chain: u32) -> Result<Participant, Error> {
        self.producers
            .get(chain as usize)
            .copied()
            .ok_or(Error::Signer)
    }
}

impl<P: PublicKey, V: Variant> Epochable for Scheme<P, V> {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

type TranscriptEntry<'a> = (Participant, &'a [u8], Bytes);

/// One pairing claim extracted from an artifact: `signature` covers every term.
///
/// A claim builder performs all of its artifact's structural checks, so the artifact is valid
/// exactly when every one of its claims' pairing products holds. Single-term claims are
/// ordinary signatures or threshold material; multi-term claims are aggregate transcripts.
struct Claim<'a, V: Variant> {
    signature: V::Signature,
    terms: Vec<(V::Public, &'a [u8], Bytes)>,
}

fn validate_public_material<P: PublicKey, V: Variant, D: Digest>(
    config: &Config<D>,
    participants: &BiMap<P, V::Public>,
    da: &Sharing<V>,
    nullification: &Sharing<V>,
) -> Option<()> {
    let total = config.codec_config().participants();
    if participants.len() != total
        || participants.is_empty()
        || participants
            .values()
            .iter()
            .any(|public| public == &V::Public::zero())
        || !valid_sharing(da, total, N5f1::n_minus_two_f(total))
        || !valid_sharing(nullification, total, N5f1::m_quorum(total))
        || da.public() == nullification.public()
    {
        return None;
    }
    Some(())
}

fn validate_certificate_material<P: PublicKey, V: Variant, D: Digest>(
    config: &Config<D>,
    participants: &BiMap<P, V::Public>,
    da: &V::Public,
    nullification: &V::Public,
) -> Option<()> {
    if participants.len() != config.codec_config().participants()
        || participants.is_empty()
        || da == &V::Public::zero()
        || nullification == &V::Public::zero()
        || da == nullification
    {
        return None;
    }
    Some(())
}

fn valid_sharing<V: Variant>(sharing: &Sharing<V>, total: usize, required: u32) -> bool {
    if sharing.evaluation_mode() != Mode::NonZeroCounter
        || sharing.total().get() as usize != total
        || sharing.required() != required
        || sharing.public() == &V::Public::zero()
    {
        return false;
    }

    let mut publics = HashSet::with_capacity(total);
    (0..total).all(|index| {
        let Ok(public) = sharing.partial_public(Participant::from_usize(index)) else {
            return false;
        };
        public != V::Public::zero() && publics.insert(public)
    })
}

fn decoded<V: Variant>(attestation: &Attestation<V>) -> Result<V::Signature, Error> {
    let signature = attestation.signature().ok_or(Error::Signature)?;
    if signature == &V::Signature::zero() {
        return Err(Error::Signature);
    }
    Ok(*signature)
}

fn partial<V: Variant>(share: &ThresholdShare<V>) -> Result<PartialSignature<V>, Error> {
    let value = share.signature().ok_or(Error::Signature)?;
    if value == &V::Signature::zero() {
        return Err(Error::Signature);
    }
    Ok(PartialSignature {
        index: share.signer(),
        value: *value,
    })
}

fn recover<'a, V: Variant>(
    sharing: &Sharing<V>,
    shares: impl IntoIterator<Item = &'a ThresholdShare<V>>,
    namespace: &[u8],
    message: &[u8],
    verification: SignatureVerification,
    strategy: &impl Strategy,
) -> Result<certificate_threshold::Certificate<V>, Error> {
    let partials = shares
        .into_iter()
        .map(partial)
        .collect::<Result<Vec<_>, _>>()?;
    if matches!(verification, SignatureVerification::Checked) {
        strategy
            .try_map_collect_vec(&partials, |share| {
                threshold::verify_message(sharing, namespace, message, share)
            })
            .map_err(|_| Error::Signature)?;
    }
    let signature =
        threshold::recover(sharing, &partials, strategy).map_err(|_| Error::Signature)?;
    if signature == V::Signature::zero()
        || matches!(verification, SignatureVerification::Preverified)
            && ops::verify_message::<V>(sharing.public(), namespace, message, &signature).is_err()
    {
        return Err(Error::Signature);
    }
    Ok(certificate_threshold::Certificate::new(signature))
}

fn verify_recovered<V: Variant>(
    public: &V::Public,
    subject: Subject,
    certificate: &certificate_threshold::Certificate<V>,
    namespace: &Namespace,
) -> bool {
    let Some(signature) = certificate.get() else {
        return false;
    };
    signature != &V::Signature::zero()
        && ops::verify_message::<V>(
            public,
            subject.namespace(namespace),
            &subject.message(),
            signature,
        )
        .is_ok()
}

fn vqc_transcript<'a, V, D, H>(
    certificate: &Vqc<V, D>,
    config: CodecConfig,
    namespace: &'a Namespace,
) -> Result<Vec<TranscriptEntry<'a>>, Error>
where
    V: Variant,
    D: Digest,
    H: Hasher<Digest = D>,
{
    let leader = certificate.leader();
    let leader_digest = leader.digest::<H>();
    let mut transcript = Vec::with_capacity(config.vqc_max_messages());
    for signer in certificate.tally().signers().iter() {
        let body = certificate
            .tally()
            .vote::<V, H>(leader, signer, config)
            .map_err(|_| Error::Transcript)?;
        let subject = Subject::vote(&body);
        transcript.push((signer, subject.namespace(namespace), subject.message()));
    }
    for signer in certificate.novoters().iter() {
        let subject = Subject::NoVote(leader.round());
        transcript.push((signer, subject.namespace(namespace), subject.message()));
    }
    for vote in certificate.conflicting_votes() {
        if vote.leader() == leader_digest {
            return Err(Error::Transcript);
        }
        let body = vote
            .vote_body(leader.round(), config)
            .map_err(|_| Error::Transcript)?;
        let subject = Subject::vote(&body);
        transcript.push((
            vote.signer(),
            subject.namespace(namespace),
            subject.message(),
        ));
    }
    transcript.sort_by_key(|(signer, _, _)| *signer);
    if !(config.view_quorum()..=config.vqc_max_messages()).contains(&transcript.len())
        || transcript.windows(2).any(|pair| pair[0].0 == pair[1].0)
    {
        return Err(Error::Transcript);
    }
    Ok(transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Viewable,
        multimmit::{
            config::{CodecConfig, Config, Limits},
            types::{
                Anchor, BlockRef, ChainId, ChainProposal, EpochGenesis, Extension, Height,
                Position, TipRecord,
            },
        },
        types::{Epoch, Round, View},
    };
    use bytes::BytesMut;
    use commonware_codec::{Decode, Encode, Read, Write, types::lazy::Lazy};
    use commonware_cryptography::{
        Hasher, Sha256, Signer,
        bls12381::primitives::{
            group::{Private, Scalar, Share},
            ops::{self, aggregate},
            sharing::{Mode, ModeVersion, Sharing},
            variant::{MinPk, MinSig, Variant},
        },
        ed25519::{PrivateKey as Ed25519PrivateKey, PublicKey as Ed25519PublicKey},
        sha256::Digest,
    };
    use commonware_math::{
        algebra::{CryptoGroup, Random},
        poly::Poly,
    };
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{NZUsize, Participant, TestRng, ordered::Set, test_rng};
    use core::num::NonZeroU32;

    const PARTICIPANTS: u32 = 6;
    const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST";

    struct Fixture<V: Variant> {
        codec: CodecConfig,
        epoch_config: Config<Digest>,
        roster: Roster<Ed25519PublicKey, V>,
        da: Sharing<V>,
        nullification: Sharing<V>,
        round: Round,
        tips: Vec<BlockRef<Digest>>,
        signers: Vec<Scheme<Ed25519PublicKey, V>>,
        verifier: Scheme<Ed25519PublicKey, V>,
    }

    impl<V: Variant> Fixture<V> {
        fn new() -> Self {
            Self::with_producers((0..PARTICIPANTS).map(Participant::new).collect())
        }

        fn with_producers(producers: Vec<Participant>) -> Self {
            let epoch_config = test_config_with_producers(PARTICIPANTS, producers, 9);
            let codec = epoch_config.codec_config();
            let identities = Set::try_from(
                (0..PARTICIPANTS)
                    .map(|index| Ed25519PrivateKey::from_seed(u64::from(index) + 100).public_key())
                    .collect::<Vec<_>>(),
            )
            .unwrap();

            let mut rng = TestRng::new(1_234);
            let mut ordinary = Vec::with_capacity(PARTICIPANTS as usize);
            let participants = identities
                .iter()
                .map(|identity| {
                    let (private, public) = ops::keypair::<_, V>(&mut rng);
                    let proof =
                        Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &private);
                    ordinary.push(private);
                    (identity.clone(), public, proof)
                })
                .collect();
            let roster =
                Roster::verify(NAMESPACE, codec.participants(), participants, &Sequential).unwrap();
            let (da, da_shares) = sharing::<V>(
                &mut rng,
                PARTICIPANTS,
                u32::try_from(codec.da_quorum()).unwrap(),
            );
            let (nullification, nullification_shares) = sharing::<V>(
                &mut rng,
                PARTICIPANTS,
                u32::try_from(codec.nullification_quorum()).unwrap(),
            );

            let signers = ordinary
                .into_iter()
                .zip(da_shares)
                .zip(nullification_shares)
                .map(|((ordinary, da_share), nullification_share)| {
                    Scheme::signer(
                        &epoch_config,
                        roster.clone(),
                        ordinary,
                        da.clone(),
                        da_share,
                        nullification.clone(),
                        nullification_share,
                    )
                    .unwrap()
                })
                .collect();
            let verifier = Scheme::verifier(
                &epoch_config,
                roster.clone(),
                da.clone(),
                nullification.clone(),
            )
            .unwrap();

            Self {
                codec,
                round: Round::new(epoch_config.epoch(), View::new(7)),
                tips: epoch_config.genesis().tips().to_vec(),
                epoch_config,
                roster,
                da,
                nullification,
                signers,
                verifier,
            }
        }

        fn header(&self, chain: u32, marker: u64) -> TransactionBlockHeader<Digest> {
            TransactionBlockHeader::new(
                self.round.epoch(),
                ChainId::new(chain),
                Height::new(1),
                digest(b"parent", marker),
                digest(b"commitment", marker),
            )
            .unwrap()
        }

        fn leader(&self, marker: u64) -> LeaderBlock<V, Digest> {
            let proposals = self
                .tips
                .iter()
                .enumerate()
                .map(|(index, tip)| {
                    ChainProposal::new(
                        ChainId::new(index as u32),
                        Anchor::Tip(*tip),
                        vec![digest(b"proposal", marker * 100 + index as u64)],
                        self.codec.pipeline_depth(),
                    )
                    .unwrap()
                })
                .collect();
            LeaderBlock::new(
                self.round,
                CertificateId::new(digest(b"parent vqc", marker)),
                self.parent_history(marker).commitment::<Sha256>(),
                proposals,
                self.codec,
            )
            .unwrap()
        }

        fn parent_history(&self, marker: u64) -> TipRecord<Digest> {
            TipRecord::new(digest(b"history parent", marker), self.tips.clone()).unwrap()
        }

        fn body(
            &self,
            leader: &LeaderBlock<V, Digest>,
            positions: Vec<u32>,
            extensions: Vec<Vec<Digest>>,
        ) -> VoteBody<Digest> {
            VoteBody::for_leader::<Sha256, V>(
                leader,
                positions.into_iter().map(Position::new).collect(),
                extensions
                    .into_iter()
                    .map(|payloads| Extension::new(payloads, self.codec.extension_bound()).unwrap())
                    .collect(),
                self.codec,
            )
            .unwrap()
        }

        fn standard_body(&self, leader: &LeaderBlock<V, Digest>) -> VoteBody<Digest> {
            self.body(
                leader,
                vec![1; self.codec.chains()],
                vec![Vec::new(); self.codec.chains()],
            )
        }

        fn certificate_verifier(&self) -> Scheme<Ed25519PublicKey, V> {
            Scheme::certificate_verifier(
                &self.epoch_config,
                self.roster.clone(),
                *self.da.public(),
                *self.nullification.public(),
            )
            .unwrap()
        }
    }

    fn sharing<V: Variant>(
        rng: &mut TestRng,
        total: u32,
        required: u32,
    ) -> (Sharing<V>, Vec<Share>) {
        let private = Poly::<Scalar>::new(rng, required - 1);
        let shares = (0..total)
            .map(|index| {
                let point = Scalar::from_u64(u64::from(index) + 1);
                Share::new(Participant::new(index), Private::new(private.eval(&point)))
            })
            .collect();
        let public = Poly::<V::Public>::commit(private);
        let mut encoded = BytesMut::new();
        Mode::NonZeroCounter.write(&mut encoded);
        total.write(&mut encoded);
        public.write(&mut encoded);
        let mut encoded = encoded.freeze();
        let total = NonZeroU32::new(total).unwrap();
        let sharing = Sharing::read_cfg(&mut encoded, &(total, ModeVersion::v0())).unwrap();
        (sharing, shares)
    }

    fn digest(label: &[u8], marker: u64) -> Digest {
        Sha256::hash(&[label, &marker.to_be_bytes()])
    }

    fn test_config(participants: u32, marker: u64) -> Config<Digest> {
        test_config_with_producers(
            participants,
            (0..participants).map(Participant::new).collect(),
            marker,
        )
    }

    fn test_config_with_producers(
        participants: u32,
        producers: Vec<Participant>,
        marker: u64,
    ) -> Config<Digest> {
        let epoch = Epoch::new(marker);
        let limits = Limits::new(2, 2).unwrap();
        let chains = u32::try_from(producers.len()).unwrap();
        let tips = (0..chains)
            .map(|chain| {
                BlockRef::new(
                    ChainId::new(chain),
                    Height::zero(),
                    digest(b"genesis", marker + u64::from(chain)),
                )
            })
            .collect();
        let genesis = EpochGenesis::new(
            epoch,
            digest(b"leader genesis", marker),
            CertificateId::new(digest(b"vqc genesis", marker)),
            CertificateId::new(digest(b"lqc genesis", marker)),
            tips,
        )
        .unwrap();
        Config::new(
            epoch,
            NAMESPACE,
            participants as usize,
            producers,
            limits,
            genesis,
        )
        .unwrap()
    }

    fn roster_rejects_rogue_keys<V: Variant>() {
        let mut rng = TestRng::new(4_242);
        let (honest_private, honest_public) = ops::keypair::<_, V>(&mut rng);
        let (attacker_private, attacker_public) = ops::keypair::<_, V>(&mut rng);
        let rogue_public = attacker_public - &honest_public;
        let namespace = b"rogue-key-vector";
        let message = b"same vote";
        let forged = ops::sign_message::<V>(&attacker_private, namespace, message);
        let mut forged = forged.encode();
        let forged = aggregate::Signature::<V>::read_cfg(&mut forged, &()).unwrap();

        assert!(
            aggregate::verify_transcript::<V>(
                [
                    (&honest_public, namespace.as_slice(), message.as_slice()),
                    (&rogue_public, namespace.as_slice(), message.as_slice()),
                ],
                &forged,
                &Sequential,
            )
            .is_ok()
        );

        let participants = vec![
            (
                Ed25519PrivateKey::from_seed(1).public_key(),
                honest_public,
                Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &honest_private),
            ),
            (
                Ed25519PrivateKey::from_seed(2).public_key(),
                rogue_public,
                Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &attacker_private),
            ),
        ];
        assert!(
            Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 2, participants, &Sequential)
                .is_none()
        );
    }

    #[test]
    fn roster_rejects_rogue_keys_for_both_variants() {
        roster_rejects_rogue_keys::<MinPk>();
        roster_rejects_rogue_keys::<MinSig>();
    }

    fn roster_bounds_and_deduplicates_manifests<V: Variant>() {
        let mut rng = TestRng::new(4_243);
        let (first_private, first_public) = ops::keypair::<_, V>(&mut rng);
        let (second_private, second_public) = ops::keypair::<_, V>(&mut rng);
        let first_identity = Ed25519PrivateKey::from_seed(1).public_key();
        let second_identity = Ed25519PrivateKey::from_seed(2).public_key();
        let first_proof =
            Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &first_private);
        let second_proof =
            Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &second_private);
        let valid = vec![
            (first_identity.clone(), first_public, first_proof),
            (second_identity.clone(), second_public, second_proof),
        ];

        assert!(
            Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 2, valid.clone(), &Sequential)
                .is_some()
        );
        assert!(Roster::<Ed25519PublicKey, V>::verify(NAMESPACE, 1, valid, &Sequential).is_none());
        assert!(
            Roster::<Ed25519PublicKey, V>::verify(
                NAMESPACE,
                2,
                vec![
                    (first_identity.clone(), first_public, first_proof),
                    (first_identity.clone(), second_public, second_proof),
                ],
                &Sequential,
            )
            .is_none()
        );
        assert!(
            Roster::<Ed25519PublicKey, V>::verify(
                NAMESPACE,
                2,
                vec![
                    (first_identity, first_public, first_proof),
                    (second_identity, first_public, first_proof),
                ],
                &Sequential,
            )
            .is_none()
        );
    }

    #[test]
    fn roster_bounds_and_deduplicates_manifests_for_both_variants() {
        roster_bounds_and_deduplicates_manifests::<MinPk>();
        roster_bounds_and_deduplicates_manifests::<MinSig>();
    }

    fn artifact_batch_returns_per_item_verdicts<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let header = fixture.header(0, 90);
        let valid = fixture.signers[0]
            .sign_transaction_block(header.clone())
            .unwrap();
        let invalid = SignedTransactionBlock::new(
            header,
            Attestation::new(Participant::new(0), Lazy::from(V::Signature::zero())),
        );
        let artifacts = [
            Unverified::TransactionBlock(&valid),
            Unverified::TransactionBlock(&invalid),
        ];

        assert_eq!(
            fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
                &mut test_rng(),
                &artifacts,
                &Sequential
            ),
            vec![true, false],
        );
        let parallel = Rayon::new(NZUsize!(4)).unwrap();
        assert_eq!(
            fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
                &mut test_rng(),
                &artifacts,
                &parallel
            ),
            vec![true, false],
        );
    }

    #[test]
    fn artifact_batches_isolate_invalid_items_for_both_variants() {
        artifact_batch_returns_per_item_verdicts::<MinPk>();
        artifact_batch_returns_per_item_verdicts::<MinSig>();
    }

    /// Batched verification must agree with per-artifact verification for every artifact
    /// kind: the claim builders re-state each verifier's structural checks, and this is the
    /// test that pins the two paths together.
    fn batched_verdicts_match_individual_verification<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let verifier = &fixture.verifier;

        let transaction = fixture.signers[0]
            .sign_transaction_block(fixture.header(0, 90))
            .unwrap();
        let bad_transaction = SignedTransactionBlock::new(
            fixture.header(0, 91),
            Attestation::new(Participant::new(0), Lazy::from(V::Signature::zero())),
        );

        let da_header = fixture.header(1, 92);
        let da_votes = fixture
            .signers
            .iter()
            .map(|signer| signer.sign_da_vote(da_header.clone()).unwrap())
            .collect::<Vec<_>>();
        let da_vote = da_votes[0].clone();
        // A share moved under a different header signs the wrong message.
        let bad_da_vote = DaVote::new(fixture.header(1, 93), da_votes[1].share().clone());
        let da_certificate = verifier
            .assemble_da_certificate(&da_votes[..fixture.codec.da_quorum()], &Sequential)
            .unwrap();
        let bad_da_certificate =
            DaCertificate::new(fixture.header(1, 94), da_certificate.certificate().clone());

        let leader = fixture.leader(95);
        let scheduled = usize::from(
            LeaderSchedule::round_robin(fixture.codec.participants()).leader(leader.view()),
        );
        let signed_leader = fixture.signers[scheduled]
            .sign_leader_block(leader.clone())
            .unwrap();
        let bad_leader = SignedLeaderBlock::new(
            leader.clone(),
            Attestation::new(
                Participant::new(scheduled as u32),
                Lazy::from(V::Signature::zero()),
            ),
        );

        let vote = fixture.signers[0]
            .sign_vote(fixture.standard_body(&leader))
            .unwrap();
        // A valid attestation over a different body no longer matches its message.
        let bad_vote = Vote::new(
            fixture.body(
                &leader,
                vec![0; PARTICIPANTS as usize],
                vec![Vec::new(); PARTICIPANTS as usize],
            ),
            fixture.signers[1]
                .sign_vote(fixture.standard_body(&leader))
                .unwrap()
                .attestation()
                .clone(),
        );

        let novote = fixture.signers[1].sign_novote(fixture.round).unwrap();
        let nullify = fixture.signers[2].sign_nullify(fixture.round).unwrap();
        let wrong_round = Round::new(
            fixture.round.epoch(),
            View::new(fixture.round.view().get() + 1),
        );
        let bad_nullify = Nullify::new(wrong_round, nullify.share().clone()).unwrap();

        let nullifies = fixture
            .signers
            .iter()
            .map(|signer| signer.sign_nullify(fixture.round).unwrap())
            .collect::<Vec<_>>();
        let nullification = verifier
            .assemble_nullification(
                &nullifies[..fixture.codec.nullification_quorum()],
                &Sequential,
            )
            .unwrap();
        let bad_nullification =
            Nullification::new(wrong_round, nullification.certificate().clone()).unwrap();

        // Assembly does not verify inputs, so a vote attributed to the wrong signer yields a
        // structurally well-formed QC whose aggregate cannot hold.
        let quorum_votes = (0..fixture.codec.view_quorum())
            .map(|index| {
                fixture.signers[index]
                    .sign_vote(fixture.standard_body(&leader))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let lqc = verifier
            .assemble_lqc::<Sha256, _>(leader.clone(), &quorum_votes, &Sequential)
            .unwrap();
        let vqc = verifier
            .assemble_vqc::<Sha256, _>(
                leader,
                &quorum_votes
                    .iter()
                    .cloned()
                    .map(ViewMessage::Vote)
                    .collect::<Vec<_>>(),
                &Sequential,
            )
            .unwrap();
        // Aggregate signatures decode lazily, so a certificate with a corrupted signature
        // round-trips the codec and fails only at verification.
        let bad_vqc = {
            let mut encoded = vqc.encode().to_vec();
            *encoded.last_mut().unwrap() ^= 0x01;
            Vqc::<V, Digest>::decode_cfg(encoded.as_slice(), &fixture.codec)
                .expect("a tampered aggregate signature still decodes")
        };
        let bad_lqc = {
            let mut encoded = lqc.encode().to_vec();
            *encoded.last_mut().unwrap() ^= 0x01;
            Lqc::<V, Digest>::decode_cfg(encoded.as_slice(), &fixture.codec)
                .expect("a tampered aggregate signature still decodes")
        };
        let artifacts = vec![
            Unverified::TransactionBlock(&transaction),
            Unverified::TransactionBlock(&bad_transaction),
            Unverified::DaVote(&da_vote),
            Unverified::DaVote(&bad_da_vote),
            Unverified::DaCertificate(&da_certificate),
            Unverified::DaCertificate(&bad_da_certificate),
            Unverified::LeaderBlock(&signed_leader),
            Unverified::LeaderBlock(&bad_leader),
            Unverified::Vote(&vote),
            Unverified::Vote(&bad_vote),
            Unverified::NoVote(&novote),
            Unverified::Nullify(&nullify),
            Unverified::Nullify(&bad_nullify),
            Unverified::Nullification(&nullification),
            Unverified::Nullification(&bad_nullification),
            Unverified::Vqc(&vqc),
            Unverified::Vqc(&bad_vqc),
            Unverified::Lqc(&lqc),
            Unverified::Lqc(&bad_lqc),
        ];
        let individual = vec![
            verifier.verify_transaction_block(&transaction),
            verifier.verify_transaction_block(&bad_transaction),
            verifier.verify_da_vote(&da_vote),
            verifier.verify_da_vote(&bad_da_vote),
            verifier.verify_da_certificate(&da_certificate),
            verifier.verify_da_certificate(&bad_da_certificate),
            verifier.verify_leader_block(&signed_leader, &Sequential),
            verifier.verify_leader_block(&bad_leader, &Sequential),
            verifier.verify_vote(&vote),
            verifier.verify_vote(&bad_vote),
            verifier.verify_novote(&novote),
            verifier.verify_nullify(&nullify),
            verifier.verify_nullify(&bad_nullify),
            verifier.verify_nullification(&nullification),
            verifier.verify_nullification(&bad_nullification),
            verifier
                .verify_vqc::<Sha256, _>(&vqc, &Sequential)
                .is_some(),
            verifier
                .verify_vqc::<Sha256, _>(&bad_vqc, &Sequential)
                .is_some(),
            verifier
                .verify_lqc::<Sha256, _>(&lqc, &Sequential)
                .is_some(),
            verifier
                .verify_lqc::<Sha256, _>(&bad_lqc, &Sequential)
                .is_some(),
        ];
        // The cohort must actually exercise both outcomes for every kind that has a forgery.
        let expected = vec![
            true, false, true, false, true, false, true, false, true, false, true, true, false,
            true, false, true, false, true, false,
        ];
        assert_eq!(individual, expected, "individual verdicts changed");
        assert_eq!(
            verifier.verify_artifacts::<_, Sha256, Digest>(
                &mut test_rng(),
                &artifacts,
                &Sequential
            ),
            expected,
            "batched verdicts diverge from individual verification"
        );
        let parallel = Rayon::new(NZUsize!(4)).unwrap();
        assert_eq!(
            verifier.verify_artifacts::<_, Sha256, Digest>(&mut test_rng(), &artifacts, &parallel),
            expected,
            "parallel batched verdicts diverge from individual verification"
        );
    }

    #[test]
    fn batched_verdicts_match_individual_verification_for_both_variants() {
        batched_verdicts_match_individual_verification::<MinPk>();
        batched_verdicts_match_individual_verification::<MinSig>();
    }

    fn ordinary_signatures_are_role_and_domain_bound<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let header = fixture.header(2, 1);
        assert_eq!(
            fixture.signers[0]
                .sign_transaction_block(header.clone())
                .unwrap_err(),
            Error::Signer
        );
        let block = fixture.signers[2]
            .sign_transaction_block(header.clone())
            .unwrap();
        assert!(fixture.verifier.verify_transaction_block(&block));

        let da_vote = fixture.signers[2].sign_da_vote(header.clone()).unwrap();
        let wrong_key_and_domain = SignedTransactionBlock::new(
            header,
            Attestation::new(da_vote.signer(), da_vote.share().lazy_signature().clone()),
        );
        assert!(
            !fixture
                .verifier
                .verify_transaction_block(&wrong_key_and_domain)
        );

        let leader = fixture.leader(1);
        let scheduled = usize::from(
            LeaderSchedule::round_robin(fixture.codec.participants()).leader(leader.view()),
        );
        assert_eq!(
            fixture.signers[(scheduled + 1) % fixture.signers.len()]
                .sign_leader_block(leader.clone())
                .unwrap_err(),
            Error::Signer
        );
        let signed = fixture.signers[scheduled]
            .sign_leader_block(leader.clone())
            .unwrap();
        assert!(fixture.verifier.verify_leader_block(&signed, &Sequential));

        let vote = fixture.signers[0]
            .sign_vote(fixture.standard_body(&leader))
            .unwrap();
        let novote = fixture.signers[1].sign_novote(fixture.round).unwrap();
        assert!(fixture.verifier.verify_vote(&vote));
        assert!(fixture.verifier.verify_novote(&novote));
    }

    #[test]
    fn ordinary_signatures_are_role_and_domain_bound_for_both_variants() {
        ordinary_signatures_are_role_and_domain_bound::<MinPk>();
        ordinary_signatures_are_role_and_domain_bound::<MinSig>();
    }

    fn producer_ownership_is_independent_of_participant_index<V: Variant>() {
        let producers = vec![Participant::new(1), Participant::new(4)];
        let fixture = Fixture::<V>::with_producers(producers);

        let first = fixture.header(0, 401);
        assert_eq!(
            fixture.signers[0]
                .sign_transaction_block(first.clone())
                .unwrap_err(),
            Error::Signer
        );
        let first = fixture.signers[1].sign_transaction_block(first).unwrap();
        assert!(fixture.verifier.verify_transaction_block(&first));

        let second = fixture.header(1, 402);
        assert_eq!(
            fixture.signers[1]
                .sign_transaction_block(second.clone())
                .unwrap_err(),
            Error::Signer
        );
        let second = fixture.signers[4].sign_transaction_block(second).unwrap();
        assert!(fixture.verifier.verify_transaction_block(&second));

        let identity = Fixture::<V>::new();
        let wrong_owner = identity.signers[0]
            .sign_transaction_block(fixture.header(0, 403))
            .unwrap();
        assert!(!fixture.verifier.verify_transaction_block(&wrong_owner));
        let artifacts = [
            Unverified::TransactionBlock(&first),
            Unverified::TransactionBlock(&wrong_owner),
        ];
        assert_eq!(
            fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
                &mut test_rng(),
                &artifacts,
                &Sequential,
            ),
            vec![true, false]
        );

        let validator_vote = fixture.signers[5]
            .sign_da_vote(fixture.header(1, 404))
            .unwrap();
        assert!(fixture.verifier.verify_da_vote(&validator_vote));
        assert_eq!(
            fixture.signers[4]
                .sign_da_vote(fixture.header(2, 405))
                .unwrap_err(),
            Error::Signer
        );
    }

    #[test]
    fn producer_ownership_is_independent_for_both_variants() {
        producer_ownership_is_independent_of_participant_index::<MinPk>();
        producer_ownership_is_independent_of_participant_index::<MinSig>();
    }

    fn signatures_are_namespace_bound<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let mut wrong_namespace = fixture.verifier.clone();
        wrong_namespace.namespace = Namespace::new(b"wrong namespace");

        let header = fixture.header(0, 301);
        let transaction = fixture.signers[0]
            .sign_transaction_block(header.clone())
            .unwrap();
        let da_vote = fixture.signers[0].sign_da_vote(header).unwrap();

        let leader = fixture.leader(302);
        let scheduled = usize::from(
            LeaderSchedule::round_robin(fixture.codec.participants()).leader(leader.view()),
        );
        let signed_leader = fixture.signers[scheduled]
            .sign_leader_block(leader.clone())
            .unwrap();
        let vote = fixture.signers[0]
            .sign_vote(fixture.standard_body(&leader))
            .unwrap();
        let novote = fixture.signers[0].sign_novote(fixture.round).unwrap();
        let nullify = fixture.signers[0].sign_nullify(fixture.round).unwrap();

        assert!(!wrong_namespace.verify_transaction_block(&transaction));
        assert!(!wrong_namespace.verify_da_vote(&da_vote));
        assert!(!wrong_namespace.verify_leader_block(&signed_leader, &Sequential));
        assert!(!wrong_namespace.verify_vote(&vote));
        assert!(!wrong_namespace.verify_novote(&novote));
        assert!(!wrong_namespace.verify_nullify(&nullify));
    }

    #[test]
    fn signatures_are_namespace_bound_for_every_subject_kind() {
        signatures_are_namespace_bound::<MinPk>();
        signatures_are_namespace_bound::<MinSig>();
    }

    fn threshold_certificates_use_independent_exact_quorums<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let header = fixture.header(0, 4);
        let da_votes = fixture
            .signers
            .iter()
            .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
            .collect::<Vec<_>>();
        let da_quorum = fixture.codec.da_quorum();
        assert_eq!(
            fixture
                .verifier
                .assemble_da_certificate(&da_votes[..da_quorum - 1], &Sequential)
                .unwrap_err(),
            Error::Quorum
        );
        assert_eq!(
            fixture
                .verifier
                .assemble_da_certificate(&da_votes[..=da_quorum], &Sequential)
                .unwrap_err(),
            Error::Quorum
        );
        let da_certificate = fixture
            .verifier
            .assemble_da_certificate(&da_votes[..da_quorum], &Sequential)
            .unwrap();
        assert_eq!(
            fixture
                .verifier
                .assemble_da_certificate_preverified(&da_votes[..da_quorum], &Sequential)
                .unwrap(),
            da_certificate
        );
        assert!(fixture.verifier.verify_da_certificate(&da_certificate));

        let mut duplicate = da_votes[..da_quorum].to_vec();
        duplicate[1] = duplicate[0].clone();
        assert_eq!(
            fixture
                .verifier
                .assemble_da_certificate(&duplicate, &Sequential)
                .unwrap_err(),
            Error::Signature
        );
        assert_eq!(
            fixture
                .verifier
                .assemble_da_certificate_preverified(&duplicate, &Sequential)
                .unwrap_err(),
            Error::Signature
        );
        let mut invalid = da_votes[..da_quorum].to_vec();
        invalid[0] = DaVote::new(
            header,
            ThresholdShare::new(Participant::new(0), Lazy::from(V::Signature::zero())),
        );
        assert_eq!(
            fixture
                .verifier
                .assemble_da_certificate(&invalid, &Sequential)
                .unwrap_err(),
            Error::Signature
        );
        assert_eq!(
            fixture
                .verifier
                .assemble_da_certificate_preverified(&invalid, &Sequential)
                .unwrap_err(),
            Error::Signature
        );

        let nullify = fixture
            .signers
            .iter()
            .map(|signer| signer.sign_nullify(fixture.round).unwrap())
            .collect::<Vec<_>>();
        let nullification_quorum = fixture.codec.nullification_quorum();
        assert_eq!(
            fixture
                .verifier
                .assemble_nullification(&nullify[..nullification_quorum - 1], &Sequential,)
                .unwrap_err(),
            Error::Quorum
        );
        assert_eq!(
            fixture
                .verifier
                .assemble_nullification(&nullify[..=nullification_quorum], &Sequential,)
                .unwrap_err(),
            Error::Quorum
        );
        let nullification = fixture
            .verifier
            .assemble_nullification(&nullify[..nullification_quorum], &Sequential)
            .unwrap();
        assert_eq!(
            fixture
                .verifier
                .assemble_nullification_preverified(&nullify[..nullification_quorum], &Sequential,)
                .unwrap(),
            nullification
        );
        assert!(fixture.verifier.verify_nullification(&nullification));

        let wrong_nullification =
            Nullification::new(fixture.round, da_certificate.certificate().clone()).unwrap();
        assert!(!fixture.verifier.verify_nullification(&wrong_nullification));
        let wrong_da = DaCertificate::new(
            da_certificate.header().clone(),
            nullification.certificate().clone(),
        );
        assert!(!fixture.verifier.verify_da_certificate(&wrong_da));

        let certificate_verifier = fixture.certificate_verifier();
        assert!(certificate_verifier.da_sharing().is_none());
        assert!(certificate_verifier.nullification_sharing().is_none());
        assert!(certificate_verifier.verify_da_certificate(&da_certificate));
        assert!(certificate_verifier.verify_nullification(&nullification));
        assert!(!certificate_verifier.verify_da_vote(&da_votes[0]));
        assert!(!certificate_verifier.verify_nullify(&nullify[0]));
        assert_eq!(
            certificate_verifier
                .assemble_da_certificate(&da_votes[..da_quorum], &Sequential)
                .unwrap_err(),
            Error::SharingUnavailable
        );

        let mut other_rng = TestRng::new(9_999);
        let (other_da, _) = sharing::<V>(
            &mut other_rng,
            PARTICIPANTS,
            fixture.codec.da_quorum() as u32,
        );
        let (other_nullification, _) = sharing::<V>(
            &mut other_rng,
            PARTICIPANTS,
            fixture.codec.nullification_quorum() as u32,
        );
        let other = Scheme::verifier(
            &fixture.epoch_config,
            fixture.roster.clone(),
            other_da,
            other_nullification,
        )
        .unwrap();
        assert!(!other.verify_da_certificate(&da_certificate));
        assert!(!other.verify_nullification(&nullification));
    }

    #[test]
    fn threshold_certificates_use_independent_exact_quorums_for_both_variants() {
        threshold_certificates_use_independent_exact_quorums::<MinPk>();
        threshold_certificates_use_independent_exact_quorums::<MinSig>();
    }

    fn leader_verification_checks_embedded_da_certificates<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let header = fixture.header(0, 501);
        let votes = fixture
            .signers
            .iter()
            .take(fixture.codec.da_quorum())
            .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
            .collect::<Vec<_>>();
        let certificate = fixture
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .unwrap();
        let proposals = fixture
            .tips
            .iter()
            .enumerate()
            .map(|(index, tip)| {
                let anchor = if index == 0 {
                    Anchor::Certificate(certificate.clone())
                } else {
                    Anchor::Tip(*tip)
                };
                ChainProposal::new(
                    ChainId::new(index as u32),
                    anchor,
                    Vec::new(),
                    fixture.codec.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        let leader = LeaderBlock::new(
            fixture.round,
            CertificateId::new(digest(b"parent vqc", 700)),
            digest(b"history", 700),
            proposals,
            fixture.codec,
        )
        .unwrap();
        let scheduled = usize::from(
            LeaderSchedule::round_robin(fixture.codec.participants()).leader(leader.view()),
        );
        let signed = fixture.signers[scheduled]
            .sign_leader_block(leader)
            .unwrap();
        assert!(fixture.verifier.verify_leader_block(&signed, &Sequential));

        let mut other_rng = TestRng::new(7_777);
        let (other_da, _) = sharing::<V>(
            &mut other_rng,
            PARTICIPANTS,
            fixture.codec.da_quorum() as u32,
        );
        let (other_nullification, _) = sharing::<V>(
            &mut other_rng,
            PARTICIPANTS,
            fixture.codec.nullification_quorum() as u32,
        );
        let other = Scheme::verifier(
            &fixture.epoch_config,
            fixture.roster.clone(),
            other_da,
            other_nullification,
        )
        .unwrap();
        assert!(!other.verify_leader_block(&signed, &Sequential));
    }

    #[test]
    fn leader_verification_checks_embedded_da_certificates_for_both_variants() {
        leader_verification_checks_embedded_da_certificates::<MinPk>();
        leader_verification_checks_embedded_da_certificates::<MinSig>();
    }

    fn vqc_exact_transcript<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let leader = fixture.leader(1);
        let other = fixture.leader(2);
        let target_bodies = [
            fixture.standard_body(&leader),
            fixture.body(
                &leader,
                vec![0, 1, 1, 1, 1, 1],
                vec![Vec::new(); PARTICIPANTS as usize],
            ),
            fixture.body(
                &leader,
                vec![1; PARTICIPANTS as usize],
                vec![
                    vec![digest(b"extension", 1)],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ],
            ),
        ];
        let mut messages = target_bodies
            .iter()
            .enumerate()
            .map(|(index, body)| {
                ViewMessage::Vote(fixture.signers[index].sign_vote(body.clone()).unwrap())
            })
            .collect::<Vec<_>>();
        let conflict = VoteBody::new(
            fixture.round,
            other.digest::<Sha256>(),
            vec![Position::new(0); PARTICIPANTS as usize],
            vec![Extension::empty(); PARTICIPANTS as usize],
            fixture.codec,
        )
        .unwrap();
        messages.push(ViewMessage::Vote(
            fixture.signers[3].sign_vote(conflict).unwrap(),
        ));
        messages.push(ViewMessage::NoVote(
            fixture.signers[4].sign_novote(fixture.round).unwrap(),
        ));

        let certificate = fixture
            .verifier
            .assemble_vqc::<Sha256, _>(leader.clone(), &messages, &Sequential)
            .unwrap();
        let preverified = fixture
            .verifier
            .assemble_vqc_preverified::<Sha256, _>(leader.clone(), &messages, &Sequential)
            .unwrap();
        assert_eq!(preverified, certificate);
        assert_eq!(certificate.tally().signers().count(), 3);
        assert_eq!(certificate.novoters().count(), 1);
        assert_eq!(certificate.conflicting_votes().len(), 1);
        let id = fixture
            .verifier
            .verify_vqc::<Sha256, _>(&certificate, &Sequential)
            .unwrap();
        assert!(
            fixture
                .certificate_verifier()
                .verify_vqc::<Sha256, _>(&certificate, &Sequential)
                .is_some()
        );
        assert_eq!(
            id,
            CertificateId::new(Sha256::hash(&[certificate.encode().as_ref()]))
        );

        let mut overlapping = messages.clone();
        *overlapping.last_mut().unwrap() =
            ViewMessage::NoVote(fixture.signers[0].sign_novote(fixture.round).unwrap());
        assert_eq!(
            fixture
                .verifier
                .assemble_vqc::<Sha256, _>(leader.clone(), &overlapping, &Sequential)
                .unwrap_err(),
            Error::Signature
        );

        let wrong_round = Round::new(
            fixture.round.epoch(),
            View::new(fixture.round.view().get() + 1),
        );
        let wrong_round_conflict = VoteBody::new(
            wrong_round,
            other.digest::<Sha256>(),
            vec![Position::new(0); PARTICIPANTS as usize],
            vec![Extension::empty(); PARTICIPANTS as usize],
            fixture.codec,
        )
        .unwrap();
        let mut wrong_round_messages = messages.clone();
        wrong_round_messages[3] =
            ViewMessage::Vote(fixture.signers[3].sign_vote(wrong_round_conflict).unwrap());
        assert_eq!(
            fixture
                .verifier
                .assemble_vqc::<Sha256, _>(leader.clone(), &wrong_round_messages, &Sequential)
                .unwrap_err(),
            Error::Transcript
        );

        let mut mutated = target_bodies.to_vec();
        mutated[0] = fixture.body(
            &leader,
            vec![0, 1, 1, 1, 1, 1],
            vec![Vec::new(); PARTICIPANTS as usize],
        );
        let tally = Tally::from_votes::<V, Sha256, _>(
            &leader,
            mutated
                .into_iter()
                .enumerate()
                .map(|(index, body)| (Participant::from_usize(index), body)),
            fixture.codec,
        )
        .unwrap();
        let mutated = Vqc::new(
            leader,
            tally,
            certificate.novoters().clone(),
            certificate.conflicting_votes().to_vec(),
            certificate.signature().unwrap().clone(),
            fixture.codec,
        )
        .unwrap();
        assert!(
            fixture
                .verifier
                .verify_vqc::<Sha256, _>(&mutated, &Sequential)
                .is_none()
        );
    }

    #[test]
    fn vqc_authenticates_every_compact_transcript_field_for_both_variants() {
        vqc_exact_transcript::<MinPk>();
        vqc_exact_transcript::<MinSig>();
    }

    fn vqc_accepts_more_than_n_minus_f_messages<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let leader = fixture.leader(1);
        let messages = fixture
            .signers
            .iter()
            .map(|signer| {
                ViewMessage::Vote(signer.sign_vote(fixture.standard_body(&leader)).unwrap())
            })
            .collect::<Vec<_>>();
        assert!(messages.len() > fixture.codec.view_quorum());

        let certificate = fixture
            .verifier
            .assemble_vqc::<Sha256, _>(leader, &messages, &Sequential)
            .unwrap();
        assert_eq!(certificate.tally().signers().count(), messages.len());
        assert!(
            fixture
                .verifier
                .verify_vqc::<Sha256, _>(&certificate, &Sequential)
                .is_some()
        );

        let encoded = certificate.encode();
        let bounds = fixture
            .codec
            .encoded_bounds::<V, Digest>()
            .expect("fixture bounds are representable");
        assert!(encoded.len() <= bounds.max_artifact_bytes());
        let decoded = Vqc::<V, Digest>::decode_cfg(encoded.as_ref(), &fixture.codec).unwrap();
        assert_eq!(decoded, certificate);
    }

    #[test]
    fn vqc_accepts_more_than_n_minus_f_messages_for_both_variants() {
        vqc_accepts_more_than_n_minus_f_messages::<MinPk>();
        vqc_accepts_more_than_n_minus_f_messages::<MinSig>();
    }

    fn lqc_uses_only_the_exact_vote_aggregate<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let leader = fixture.leader(1);
        let votes = fixture
            .signers
            .iter()
            .take(fixture.codec.view_quorum())
            .enumerate()
            .map(|(index, signer)| {
                let positions = if index == 0 {
                    vec![0, 1, 1, 1, 1, 1]
                } else {
                    vec![1; PARTICIPANTS as usize]
                };
                signer
                    .sign_vote(fixture.body(
                        &leader,
                        positions,
                        vec![Vec::new(); PARTICIPANTS as usize],
                    ))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            fixture
                .verifier
                .assemble_lqc::<Sha256, _>(leader.clone(), &votes[..votes.len() - 1], &Sequential,)
                .unwrap_err(),
            Error::Quorum
        );
        let certificate = fixture
            .verifier
            .assemble_lqc::<Sha256, _>(leader.clone(), &votes, &Sequential)
            .unwrap();
        let preverified = fixture
            .verifier
            .assemble_lqc_preverified::<Sha256, _>(leader.clone(), &votes, &Sequential)
            .unwrap();
        assert_eq!(preverified, certificate);
        let mut forged = votes.clone();
        let delta = V::Signature::generator() * &Scalar::random(test_rng());
        let first = *forged[0].attestation().signature().unwrap() + &delta;
        let second = *forged[1].attestation().signature().unwrap() - &delta;
        forged[0] = Vote::new(
            forged[0].body().clone(),
            Attestation::new(forged[0].signer(), Lazy::from(first)),
        );
        forged[1] = Vote::new(
            forged[1].body().clone(),
            Attestation::new(forged[1].signer(), Lazy::from(second)),
        );
        assert_eq!(
            fixture
                .verifier
                .assemble_lqc::<Sha256, _>(leader.clone(), &forged, &Sequential,),
            Err(Error::Signature)
        );
        assert_eq!(
            fixture
                .verifier
                .assemble_lqc_preverified::<Sha256, _>(leader.clone(), &forged, &Sequential,)
                .unwrap(),
            certificate
        );
        let id = fixture
            .verifier
            .verify_lqc::<Sha256, _>(&certificate, &Sequential)
            .unwrap();
        assert!(
            fixture
                .certificate_verifier()
                .verify_lqc::<Sha256, _>(&certificate, &Sequential)
                .is_some()
        );
        assert_eq!(
            id,
            CertificateId::new(Sha256::hash(&[certificate.encode().as_ref()]))
        );

        let derived = certificate.derive_vqc(fixture.codec).unwrap();
        assert_eq!(derived.leader(), certificate.leader());
        assert_eq!(derived.tally(), certificate.tally());
        assert_eq!(derived.novoters().count(), 0);
        assert!(derived.conflicting_votes().is_empty());
        assert!(certificate.equivalent_vqc(&derived));
        assert!(
            fixture
                .verifier
                .verify_vqc::<Sha256, _>(&derived, &Sequential)
                .is_some()
        );

        let mutated_bodies = votes.iter().enumerate().map(|(index, vote)| {
            let body = if index == 0 {
                fixture.standard_body(&leader)
            } else {
                vote.body().clone()
            };
            (vote.signer(), body)
        });
        let tally =
            Tally::from_votes::<V, Sha256, _>(&leader, mutated_bodies, fixture.codec).unwrap();
        let mutated = Lqc::new(
            leader,
            tally,
            certificate.signature().unwrap().clone(),
            fixture.codec,
        )
        .unwrap();
        assert!(
            fixture
                .verifier
                .verify_lqc::<Sha256, _>(&mutated, &Sequential)
                .is_none()
        );
    }

    #[test]
    fn lqc_uses_only_the_exact_vote_aggregate_for_both_variants() {
        lqc_uses_only_the_exact_vote_aggregate::<MinPk>();
        lqc_uses_only_the_exact_vote_aggregate::<MinSig>();
    }

    fn scheme_rejects_context_and_key_material_mismatches<V: Variant>() {
        let fixture = Fixture::<V>::new();
        let block = fixture.signers[0]
            .sign_transaction_block(fixture.header(0, 1))
            .unwrap();
        let other_config = test_config(PARTICIPANTS, 10);
        let other_context = Scheme::verifier(
            &other_config,
            fixture.roster.clone(),
            fixture.da.clone(),
            fixture.nullification.clone(),
        )
        .unwrap();
        assert!(!other_context.verify_transaction_block(&block));

        let mut rng = TestRng::new(8_888);
        let (unlisted, _) = ops::keypair::<_, V>(&mut rng);
        let (fresh_da, fresh_da_shares) =
            sharing::<V>(&mut rng, PARTICIPANTS, fixture.codec.da_quorum() as u32);
        let (fresh_nullification, fresh_nullification_shares) = sharing::<V>(
            &mut rng,
            PARTICIPANTS,
            fixture.codec.nullification_quorum() as u32,
        );
        assert!(
            Scheme::signer(
                &fixture.epoch_config,
                fixture.roster.clone(),
                unlisted,
                fresh_da,
                fresh_da_shares[0].clone(),
                fresh_nullification,
                fresh_nullification_shares[0].clone(),
            )
            .is_none()
        );

        let (wrong_da, _) =
            sharing::<V>(&mut rng, PARTICIPANTS, fixture.codec.view_quorum() as u32);
        assert!(
            Scheme::verifier(
                &fixture.epoch_config,
                fixture.roster.clone(),
                wrong_da,
                fixture.nullification.clone(),
            )
            .is_none()
        );

        let one = test_config(1, 20);
        let identity = Ed25519PrivateKey::from_seed(1).public_key();
        let (ordinary, public) = ops::keypair::<_, V>(&mut rng);
        let proof = Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, &ordinary);
        let roster =
            Roster::verify(NAMESPACE, 1, vec![(identity, public, proof)], &Sequential).unwrap();
        let (same, shares) = sharing::<V>(&mut rng, 1, 1);
        assert!(
            Scheme::signer(
                &one,
                roster,
                ordinary,
                same.clone(),
                shares[0].clone(),
                same,
                shares[0].clone(),
            )
            .is_none()
        );
    }

    #[test]
    fn scheme_rejects_context_and_key_material_mismatches_for_both_variants() {
        scheme_rejects_context_and_key_material_mismatches::<MinPk>();
        scheme_rejects_context_and_key_material_mismatches::<MinSig>();
    }
}
