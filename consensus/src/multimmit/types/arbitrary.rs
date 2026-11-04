//! [`Arbitrary`] implementations for the protocol types.
//!
//! Every generated value is structurally valid under one fixed codec profile: 6 participants,
//! 6 producer chains, a pipeline depth of 2 and an extension bound of 2. Decode generated values
//! with [`codec_config`].

use super::*;
use crate::{
    multimmit::{
        scheme::{
            AggregateOf, DaCertificateOf, NullificationOf, Scheme, bls12381, bls12381_sas,
            ed25519 as ed25519_suite,
        },
        types::{CodecConfig, PathLimits},
    },
    types::{Epoch, Height, Round, View},
};
use ::arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{
    Digest, Hasher, PublicKey, Sha256,
    bls12381::{
        certificate::threshold,
        primitives::{
            ops::aggregate,
            variant::{MinSig, Variant},
        },
    },
    certificate::{self, Signers},
    ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_utils::Participant;
use core::num::NonZeroUsize;

/// A suite whose attestations, certificates, and aggregates can be generated arbitrarily.
///
/// Generated signatures are arbitrary bytes of the right shape, not valid signatures.
pub trait ArbitraryScheme: Scheme {
    /// Generates an ordinary attestation.
    fn attestation(u: &mut Unstructured<'_>) -> ArbitraryResult<Attestation<Self>>;

    /// Generates a data-availability attestation.
    fn da_attestation(u: &mut Unstructured<'_>) -> ArbitraryResult<DaAttestation<Self>>;

    /// Generates a nullification attestation.
    fn nullify_attestation(u: &mut Unstructured<'_>) -> ArbitraryResult<NullifyAttestation<Self>>;

    /// Generates a data-availability certificate.
    fn da_certificate(u: &mut Unstructured<'_>) -> ArbitraryResult<DaCertificateOf<Self>>;

    /// Generates a nullification certificate.
    fn nullification(u: &mut Unstructured<'_>) -> ArbitraryResult<NullificationOf<Self>>;

    /// Generates an aggregate over `terms` transcript terms.
    fn aggregate(u: &mut Unstructured<'_>, terms: usize) -> ArbitraryResult<AggregateOf<Self>>;
}

fn arbitrary_attestation<R>(
    u: &mut Unstructured<'_>,
) -> ArbitraryResult<certificate::Attestation<R>>
where
    R: certificate::Scheme,
    R::Signature: for<'a> Arbitrary<'a>,
{
    Ok(certificate::Attestation {
        signer: u.arbitrary()?,
        signature: Lazy::from(u.arbitrary::<R::Signature>()?),
    })
}

macro_rules! impl_arbitrary_bls12381 {
    ($suite:ident) => {
        impl<P, V, Q> ArbitraryScheme for $suite::Scheme<P, V, Q>
        where
            P: PublicKey,
            V: Variant,
            V::Signature: for<'a> Arbitrary<'a>,
            Q: bls12381::Quorum,
        {
            fn attestation(u: &mut Unstructured<'_>) -> ArbitraryResult<Attestation<Self>> {
                arbitrary_attestation(u)
            }

            fn da_attestation(u: &mut Unstructured<'_>) -> ArbitraryResult<DaAttestation<Self>> {
                arbitrary_attestation(u)
            }

            fn nullify_attestation(
                u: &mut Unstructured<'_>,
            ) -> ArbitraryResult<NullifyAttestation<Self>> {
                arbitrary_attestation(u)
            }

            fn da_certificate(u: &mut Unstructured<'_>) -> ArbitraryResult<DaCertificateOf<Self>> {
                u.arbitrary::<threshold::Certificate<V>>()
            }

            fn nullification(u: &mut Unstructured<'_>) -> ArbitraryResult<NullificationOf<Self>> {
                u.arbitrary::<threshold::Certificate<V>>()
            }

            fn aggregate(u: &mut Unstructured<'_>, _: usize) -> ArbitraryResult<AggregateOf<Self>> {
                Ok(Lazy::from(u.arbitrary::<aggregate::Signature<V>>()?))
            }
        }
    };
}

impl_arbitrary_bls12381!(bls12381);
impl_arbitrary_bls12381!(bls12381_sas);

/// Generates an Ed25519 certificate whose signers fit the fixed codec profile.
fn arbitrary_listed_certificate(
    u: &mut Unstructured<'_>,
) -> ArbitraryResult<ed25519::certificate::Certificate> {
    let mut indices = Vec::new();
    for index in 0..PARTICIPANTS {
        if u.arbitrary()? {
            indices.push(index);
        }
    }
    // A certificate names at least one signer.
    if indices.is_empty() {
        indices.push(0);
    }
    let signatures = indices
        .iter()
        .map(|_| Ok(Lazy::from(u.arbitrary::<ed25519::Signature>()?)))
        .collect::<ArbitraryResult<_>>()?;
    Ok(ed25519::certificate::Certificate {
        signers: signers(PARTICIPANTS, indices),
        signatures,
    })
}

impl<Q: ed25519_suite::Quorum> ArbitraryScheme for ed25519_suite::Scheme<Q> {
    fn attestation(u: &mut Unstructured<'_>) -> ArbitraryResult<Attestation<Self>> {
        arbitrary_attestation(u)
    }

    fn da_attestation(u: &mut Unstructured<'_>) -> ArbitraryResult<DaAttestation<Self>> {
        arbitrary_attestation(u)
    }

    fn nullify_attestation(u: &mut Unstructured<'_>) -> ArbitraryResult<NullifyAttestation<Self>> {
        arbitrary_attestation(u)
    }

    fn da_certificate(u: &mut Unstructured<'_>) -> ArbitraryResult<DaCertificateOf<Self>> {
        arbitrary_listed_certificate(u)
    }

    fn nullification(u: &mut Unstructured<'_>) -> ArbitraryResult<NullificationOf<Self>> {
        arbitrary_listed_certificate(u)
    }

    fn aggregate(u: &mut Unstructured<'_>, terms: usize) -> ArbitraryResult<AggregateOf<Self>> {
        (0..terms)
            .map(|_| Ok(Lazy::from(u.arbitrary::<ed25519::Signature>()?)))
            .collect()
    }
}

const PARTICIPANTS: usize = 6;
const PIPELINE_DEPTH: u32 = 2;
const EXTENSION_BOUND: u32 = 2;

/// Returns the codec profile every generated value satisfies.
pub(crate) fn codec_config() -> CodecConfig {
    let limits = PathLimits::new(PIPELINE_DEPTH, EXTENSION_BOUND);
    CodecConfig::new(PARTICIPANTS, PARTICIPANTS, limits).expect("arbitrary codec config is valid")
}

fn arbitrary_live_round(u: &mut Unstructured<'_>) -> ArbitraryResult<Round> {
    Ok(Round::new(
        u.arbitrary()?,
        View::new(u.int_in_range(1..=u64::MAX)?),
    ))
}

fn arbitrary_vec<'a, T: Arbitrary<'a>>(
    u: &mut Unstructured<'a>,
    max_len: usize,
) -> ArbitraryResult<Vec<T>> {
    let len = u.int_in_range(0..=max_len)?;
    (0..len).map(|_| u.arbitrary()).collect()
}

fn arbitrary_extension<D>(
    u: &mut Unstructured<'_>,
    config: CodecConfig,
) -> ArbitraryResult<Extension<D>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    Ok(Extension::new(
        arbitrary_vec(u, config.extension_bound())?,
        config.extension_bound(),
    )
    .expect("generated extension respects codec limits"))
}

fn arbitrary_extensions<D>(
    u: &mut Unstructured<'_>,
    config: CodecConfig,
) -> ArbitraryResult<Vec<Extension<D>>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    (0..config.chains())
        .map(|_| arbitrary_extension(u, config))
        .collect()
}

fn signers(participants: usize, indices: impl IntoIterator<Item = usize>) -> Signers {
    Signers::new(
        participants
            .try_into()
            .expect("participant count exceeds u32::MAX"),
        indices.into_iter().map(Participant::from_usize),
    )
    .expect("generated signer indices are unique and in range")
}

fn arbitrary_live_header<D>(
    u: &mut Unstructured<'_>,
    epoch: Epoch,
    chain: ChainId,
) -> ArbitraryResult<TransactionBlockHeader<D>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    Ok(TransactionBlockHeader::new(
        epoch,
        chain,
        Height::new(u.int_in_range(1..=u64::MAX)?),
        u.arbitrary()?,
        u.arbitrary()?,
    )
    .expect("generated transaction block header is live"))
}

fn arbitrary_da_certificate_for<S, D>(
    u: &mut Unstructured<'_>,
    header: TransactionBlockHeader<D>,
) -> ArbitraryResult<DaCertificate<S, D>>
where
    S: ArbitraryScheme,
    D: Digest,
{
    Ok(DaCertificate::new(header, S::da_certificate(u)?))
}

fn arbitrary_anchor_for<S, D>(
    u: &mut Unstructured<'_>,
    round: Round,
    chain: ChainId,
) -> ArbitraryResult<Anchor<S, D>>
where
    S: ArbitraryScheme,
    D: Digest + for<'a> Arbitrary<'a>,
{
    if u.arbitrary()? {
        return Ok(Anchor::Tip(BlockRef::new(
            chain,
            u.arbitrary()?,
            u.arbitrary()?,
        )));
    }

    let header = arbitrary_live_header(u, round.epoch(), chain)?;
    Ok(Anchor::Certificate(arbitrary_da_certificate_for(
        u, header,
    )?))
}

fn arbitrary_chain_proposal_for<S, D>(
    u: &mut Unstructured<'_>,
    round: Round,
    chain: ChainId,
    config: CodecConfig,
) -> ArbitraryResult<ChainProposal<S, D>>
where
    S: ArbitraryScheme,
    D: Digest + for<'a> Arbitrary<'a>,
{
    let anchor = arbitrary_anchor_for(u, round, chain)?;
    let payloads = arbitrary_vec(u, config.pipeline_depth())?;

    ChainProposal::new(chain, anchor, payloads, config.pipeline_depth())
        .map_err(|_| ::arbitrary::Error::IncorrectFormat)
}

fn arbitrary_leader_block<S, D>(u: &mut Unstructured<'_>) -> ArbitraryResult<LeaderBlock<S, D>>
where
    S: ArbitraryScheme,
    D: Digest + for<'a> Arbitrary<'a>,
{
    let config = codec_config();
    let round = arbitrary_live_round(u)?;
    let proposals = (0..config.chains())
        .map(|chain| arbitrary_chain_proposal_for(u, round, ChainId::new(chain as u32), config))
        .collect::<ArbitraryResult<_>>()?;

    Ok(LeaderBlock::new(
        round,
        CertificateId::new(u.arbitrary()?),
        u.arbitrary()?,
        proposals,
        config,
    )
    .expect("generated leader block is canonical"))
}

fn arbitrary_vote_body<D>(
    u: &mut Unstructured<'_>,
    round: Round,
    config: CodecConfig,
) -> ArbitraryResult<VoteBody<D>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    Ok(VoteBody::from_ballot(round, arbitrary_ballot(u, config)?)
        .expect("generated vote body has a live view"))
}

fn arbitrary_vote_body_for_leader<S, D, H>(
    u: &mut Unstructured<'_>,
    leader: &LeaderBlock<S, D>,
    config: CodecConfig,
) -> ArbitraryResult<VoteBody<D>>
where
    S: ArbitraryScheme,
    D: Digest + for<'a> Arbitrary<'a>,
    H: Hasher<Digest = D>,
{
    let positions = leader
        .proposals()
        .iter()
        .map(|proposal| u.int_in_range(0..=proposal.len() as u32).map(Position::new))
        .collect::<ArbitraryResult<_>>()?;

    VoteBody::for_leader(
        DigestedLeader::new::<H>(leader),
        positions,
        arbitrary_extensions(u, config)?,
        config,
    )
    .map_err(|_| ::arbitrary::Error::IncorrectFormat)
}

fn arbitrary_tally_for<S, D, H>(
    u: &mut Unstructured<'_>,
    leader: &LeaderBlock<S, D>,
    signer_count: usize,
    config: CodecConfig,
) -> ArbitraryResult<Tally<D>>
where
    S: ArbitraryScheme,
    D: Digest + for<'a> Arbitrary<'a>,
    H: Hasher<Digest = D>,
{
    let votes = (0..signer_count)
        .map(|signer| {
            Ok((
                Participant::from_usize(signer),
                arbitrary_vote_body_for_leader::<S, D, H>(u, leader, config)?,
            ))
        })
        .collect::<ArbitraryResult<Vec<_>>>()?;

    Ok(
        Tally::from_votes(DigestedLeader::new::<H>(leader), votes, config)
            .expect("generated tally contains canonical votes"),
    )
}

fn arbitrary_ballot<D>(u: &mut Unstructured<'_>, config: CodecConfig) -> ArbitraryResult<Ballot<D>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    let positions = (0..config.chains())
        .map(|_| {
            u.int_in_range(0..=config.pipeline_depth() as u32)
                .map(Position::new)
        })
        .collect::<ArbitraryResult<_>>()?;

    Ok(Ballot::new(
        u.arbitrary()?,
        positions,
        arbitrary_extensions(u, config)?,
        config,
    )
    .expect("generated ballot respects codec limits"))
}

fn arbitrary_conflicting_vote_for<D>(
    u: &mut Unstructured<'_>,
    signer: Participant,
    config: CodecConfig,
) -> ArbitraryResult<ConflictingVote<D>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    Ok(
        ConflictingVote::new(signer, arbitrary_ballot(u, config)?, config)
            .expect("generated conflicting vote names a committee member"),
    )
}

impl<'a, D> Arbitrary<'a> for EpochGenesis<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let tips = (0..config.chains())
            .map(|chain| {
                Ok(BlockRef::new(
                    ChainId::new(chain as u32),
                    Height::zero(),
                    u.arbitrary()?,
                ))
            })
            .collect::<ArbitraryResult<_>>()?;

        Ok(Self::new(
            u.arbitrary()?,
            u.arbitrary()?,
            CertificateId::new(u.arbitrary()?),
            CertificateId::new(u.arbitrary()?),
            tips,
        )
        .expect("generated genesis tips are canonical"))
    }
}

impl<'a, D> Arbitrary<'a> for TipRecord<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let tips = (0..codec_config().chains())
            .map(|chain| {
                Ok(BlockRef::new(
                    ChainId::new(chain as u32),
                    u.arbitrary()?,
                    u.arbitrary()?,
                ))
            })
            .collect::<ArbitraryResult<_>>()?;

        let proposed = (0..codec_config().chains())
            .map(|_| u.arbitrary())
            .collect::<ArbitraryResult<_>>()?;

        Ok(Self::new(u.arbitrary()?, tips, proposed).expect("generated tip record is canonical"))
    }
}

impl<'a, D> Arbitrary<'a> for TransactionBlockHeader<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let epoch = u.arbitrary()?;
        let chain = ChainId::new(u.int_in_range(0..=(PARTICIPANTS - 1) as u32)?);
        arbitrary_live_header(u, epoch, chain)
    }
}

impl<'a, H, B> Arbitrary<'a> for TransactionBlock<H, B>
where
    H: Hasher,
    H::Digest: for<'b> Arbitrary<'b>,
    B: Body<H> + Arbitrary<'a>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let epoch = u.arbitrary()?;
        let chain = ChainId::new(u.int_in_range(0..=(PARTICIPANTS - 1) as u32)?);
        let height = Height::new(u.int_in_range(1..=u64::MAX)?);
        let parent = u.arbitrary()?;
        let body: B = u.arbitrary()?;
        let header = TransactionBlockHeader::new(epoch, chain, height, parent, body.digest())
            .expect("generated transaction block header is live");
        Ok(Self::new(header, body).expect("generated body matches its commitment"))
    }
}

impl<'a, S, D> Arbitrary<'a> for SignedTransactionBlock<S, D>
where
    S: ArbitraryScheme,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(u.arbitrary()?, S::attestation(u)?))
    }
}

impl<'a, S, D> Arbitrary<'a> for DaVote<S, D>
where
    S: ArbitraryScheme,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(u.arbitrary()?, S::da_attestation(u)?))
    }
}

impl<'a, S, D> Arbitrary<'a> for DaCertificate<S, D>
where
    S: ArbitraryScheme,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let header = u.arbitrary()?;
        arbitrary_da_certificate_for(u, header)
    }
}

impl<'a, S, D> Arbitrary<'a> for Anchor<S, D>
where
    S: ArbitraryScheme,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let round = arbitrary_live_round(u)?;
        let chain = ChainId::new(u.int_in_range(0..=(config.chains() - 1) as u32)?);
        arbitrary_anchor_for(u, round, chain)
    }
}

impl<'a, S, D> Arbitrary<'a> for ChainProposal<S, D>
where
    S: ArbitraryScheme,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let round = arbitrary_live_round(u)?;
        arbitrary_chain_proposal_for(u, round, ChainId::new(0), config)
    }
}

impl<'a, S, D> Arbitrary<'a> for LeaderBlock<S, D>
where
    S: ArbitraryScheme,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        arbitrary_leader_block(u)
    }
}

impl<'a, S, D> Arbitrary<'a> for SignedLeaderBlock<S, D>
where
    S: ArbitraryScheme,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(u.arbitrary()?, S::attestation(u)?))
    }
}

impl<'a, D> Arbitrary<'a> for Extension<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        arbitrary_extension(u, codec_config())
    }
}

impl<'a, D> Arbitrary<'a> for Ballot<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        arbitrary_ballot(u, codec_config())
    }
}

impl<'a, D> Arbitrary<'a> for VoteBody<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let round = arbitrary_live_round(u)?;
        arbitrary_vote_body(u, round, codec_config())
    }
}

impl<'a, S, D> Arbitrary<'a> for Vote<S, D>
where
    S: ArbitraryScheme,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(u.arbitrary()?, S::attestation(u)?))
    }
}

impl<'a, S> Arbitrary<'a> for NoVote<S>
where
    S: ArbitraryScheme,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(arbitrary_live_round(u)?, S::attestation(u)?)
            .expect("generated novote has a live view"))
    }
}

impl<'a, S> Arbitrary<'a> for Nullify<S>
where
    S: ArbitraryScheme,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(
            Self::new(arbitrary_live_round(u)?, S::nullify_attestation(u)?)
                .expect("generated nullification request has a live view"),
        )
    }
}

impl<'a, S, D> Arbitrary<'a> for ViewMessage<S, D>
where
    S: ArbitraryScheme,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        if u.arbitrary()? {
            return Ok(Self::Vote(u.arbitrary()?));
        }
        Ok(Self::NoVote(u.arbitrary()?))
    }
}

impl<'a> Arbitrary<'a> for ExtensionDeviation {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(
            u.arbitrary()?,
            NonZeroUsize::new(u.int_in_range(0..=128)?),
        ))
    }
}

impl<'a> Arbitrary<'a> for Deviation {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let position_count = u.int_in_range(0..=config.chains())?;
        let positions = (0..position_count)
            .map(|chain| {
                Ok(PositionDeviation::new(
                    ChainId::new(chain as u32),
                    u.arbitrary()?,
                ))
            })
            .collect::<ArbitraryResult<_>>()?;
        let extension_count = u.int_in_range(0..=config.chains())?;
        let extensions = (0..extension_count)
            .map(|chain| {
                Ok(ExtensionDeviation::new(
                    ChainId::new(chain as u32),
                    NonZeroUsize::new(u.int_in_range(0..=128)?),
                ))
            })
            .collect::<ArbitraryResult<_>>()?;

        Ok(Self::new(
            Participant::from_usize(u.int_in_range(0..=config.participants() - 1)?),
            positions,
            extensions,
        ))
    }
}

impl<'a> Arbitrary<'a> for Tally<Sha256Digest> {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let leader = arbitrary_leader_block::<
            bls12381::Scheme<ed25519::PublicKey, MinSig>,
            Sha256Digest,
        >(u)?;
        let signer_count = u.int_in_range(1..=config.participants())?;
        arbitrary_tally_for::<bls12381::Scheme<ed25519::PublicKey, MinSig>, Sha256Digest, Sha256>(
            u,
            &leader,
            signer_count,
            config,
        )
    }
}

impl<'a, D> Arbitrary<'a> for ConflictingVote<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let signer = Participant::from_usize(u.int_in_range(0..=config.participants() - 1)?);
        arbitrary_conflicting_vote_for(u, signer, config)
    }
}

impl<'a, S> Arbitrary<'a> for Nullification<S>
where
    S: ArbitraryScheme,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(arbitrary_live_round(u)?, S::nullification(u)?)
            .expect("generated nullification has a live view"))
    }
}

impl<'a, S> Arbitrary<'a> for Vqc<S, Sha256Digest>
where
    S: ArbitraryScheme,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let leader = arbitrary_leader_block::<S, Sha256Digest>(u)?;
        let signer_count = u.int_in_range(config.designation_quorum()..=config.view_quorum())?;
        let tally =
            arbitrary_tally_for::<S, Sha256Digest, Sha256>(u, &leader, signer_count, config)?;
        let mut novoters = Vec::new();
        let mut conflicting = Vec::new();

        for signer in signer_count..config.view_quorum() {
            if u.arbitrary()? {
                novoters.push(signer);
                continue;
            }
            conflicting.push(arbitrary_conflicting_vote_for(
                u,
                Participant::from_usize(signer),
                config,
            )?);
        }

        Ok(Self::new(
            leader,
            tally,
            signers(config.participants(), novoters),
            conflicting,
            S::aggregate(u, config.view_quorum())?,
            config,
        )
        .expect("generated V-QC has a canonical transcript"))
    }
}

impl<'a, S> Arbitrary<'a> for Lqc<S, Sha256Digest>
where
    S: ArbitraryScheme,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let leader = arbitrary_leader_block::<S, Sha256Digest>(u)?;
        let tally = arbitrary_tally_for::<S, Sha256Digest, Sha256>(
            u,
            &leader,
            config.view_quorum(),
            config,
        )?;

        Ok(Self::new(
            leader,
            tally,
            S::aggregate(u, config.view_quorum())?,
            config,
        )
        .expect("generated L-QC has a canonical transcript"))
    }
}
