//! [`Arbitrary`] implementations for the protocol types.
//!
//! Every generated value is structurally valid under one fixed codec profile: 6 participants,
//! 6 producer chains, a pipeline depth of 2 and an extension bound of 2. Decode generated values
//! with [`codec_config`].

use super::*;
use crate::{
    multimmit::types::{CodecConfig, PathLimits},
    types::{Epoch, Height, Round, View},
};
use ::arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use commonware_cryptography::{
    Digest, Hasher, Sha256,
    bls12381::{
        certificate::threshold,
        primitives::{
            ops::aggregate,
            variant::{MinSig, Variant},
        },
    },
    certificate::Signers,
    sha256::Digest as Sha256Digest,
};
use commonware_utils::Participant;
use core::num::NonZeroUsize;

const PARTICIPANTS: usize = 6;
const PIPELINE_DEPTH: u32 = 2;
const EXTENSION_BOUND: u32 = 2;

/// Returns the codec profile every generated value satisfies.
pub(super) fn codec_config() -> CodecConfig {
    let limits =
        PathLimits::new(PIPELINE_DEPTH, EXTENSION_BOUND).expect("arbitrary codec limits are valid");
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

fn arbitrary_da_certificate_for<V, D>(
    u: &mut Unstructured<'_>,
    header: TransactionBlockHeader<D>,
) -> ArbitraryResult<DaCertificate<V, D>>
where
    V: Variant,
    V::Signature: for<'a> Arbitrary<'a>,
    D: Digest,
{
    Ok(DaCertificate::new(
        header,
        u.arbitrary::<threshold::Certificate<V>>()?,
    ))
}

fn arbitrary_anchor_for<V, D>(
    u: &mut Unstructured<'_>,
    round: Round,
    chain: ChainId,
) -> ArbitraryResult<Anchor<V, D>>
where
    V: Variant,
    V::Signature: for<'a> Arbitrary<'a>,
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

fn arbitrary_chain_proposal_for<V, D>(
    u: &mut Unstructured<'_>,
    round: Round,
    chain: ChainId,
    config: CodecConfig,
) -> ArbitraryResult<ChainProposal<V, D>>
where
    V: Variant,
    V::Signature: for<'a> Arbitrary<'a>,
    D: Digest + for<'a> Arbitrary<'a>,
{
    let anchor = arbitrary_anchor_for(u, round, chain)?;
    let payloads = arbitrary_vec(u, config.pipeline_depth())?;

    ChainProposal::new(chain, anchor, payloads, config.pipeline_depth())
        .map_err(|_| ::arbitrary::Error::IncorrectFormat)
}

fn arbitrary_leader_block<V, D>(u: &mut Unstructured<'_>) -> ArbitraryResult<LeaderBlock<V, D>>
where
    V: Variant,
    V::Signature: for<'a> Arbitrary<'a>,
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

fn arbitrary_vote_body_for_leader<V, D, H>(
    u: &mut Unstructured<'_>,
    leader: &LeaderBlock<V, D>,
    config: CodecConfig,
) -> ArbitraryResult<VoteBody<D>>
where
    V: Variant,
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

fn arbitrary_tally_for<V, D, H>(
    u: &mut Unstructured<'_>,
    leader: &LeaderBlock<V, D>,
    signer_count: usize,
    config: CodecConfig,
) -> ArbitraryResult<Tally<D>>
where
    V: Variant,
    D: Digest + for<'a> Arbitrary<'a>,
    H: Hasher<Digest = D>,
{
    let votes = (0..signer_count)
        .map(|signer| {
            Ok((
                Participant::from_usize(signer),
                arbitrary_vote_body_for_leader::<V, D, H>(u, leader, config)?,
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

impl<'a, V> Arbitrary<'a> for Attestation<V>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(
            u.arbitrary()?,
            u.arbitrary::<V::Signature>()?.into(),
        ))
    }
}

impl<'a, V> Arbitrary<'a> for ThresholdShare<V>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(
            u.arbitrary()?,
            u.arbitrary::<V::Signature>()?.into(),
        ))
    }
}

impl<'a, V, D> Arbitrary<'a> for SignedTransactionBlock<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

impl<'a, V, D> Arbitrary<'a> for DaVote<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

impl<'a, V, D> Arbitrary<'a> for DaCertificate<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let header = u.arbitrary()?;
        arbitrary_da_certificate_for(u, header)
    }
}

impl<'a, V, D> Arbitrary<'a> for Anchor<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let round = arbitrary_live_round(u)?;
        let chain = ChainId::new(u.int_in_range(0..=(config.chains() - 1) as u32)?);
        arbitrary_anchor_for(u, round, chain)
    }
}

impl<'a, V, D> Arbitrary<'a> for ChainProposal<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let round = arbitrary_live_round(u)?;
        arbitrary_chain_proposal_for(u, round, ChainId::new(0), config)
    }
}

impl<'a, V, D> Arbitrary<'a> for LeaderBlock<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        arbitrary_leader_block(u)
    }
}

impl<'a, V, D> Arbitrary<'a> for SignedLeaderBlock<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
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

impl<'a, V, D> Arbitrary<'a> for Vote<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(u.arbitrary()?, u.arbitrary()?))
    }
}

impl<'a, V> Arbitrary<'a> for NoVote<V>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(arbitrary_live_round(u)?, u.arbitrary()?)
            .expect("generated novote has a live view"))
    }
}

impl<'a, V> Arbitrary<'a> for Nullify<V>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(arbitrary_live_round(u)?, u.arbitrary()?)
            .expect("generated nullification request has a live view"))
    }
}

impl<'a, V, D> Arbitrary<'a> for ViewMessage<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
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
        let leader = arbitrary_leader_block::<MinSig, Sha256Digest>(u)?;
        let signer_count = u.int_in_range(1..=config.participants())?;
        arbitrary_tally_for::<MinSig, Sha256Digest, Sha256>(u, &leader, signer_count, config)
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

impl<'a, V> Arbitrary<'a> for Nullification<V>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(
            arbitrary_live_round(u)?,
            u.arbitrary::<threshold::Certificate<V>>()?,
        )
        .expect("generated nullification has a live view"))
    }
}

impl<'a, V> Arbitrary<'a> for Vqc<V, Sha256Digest>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let leader = arbitrary_leader_block::<V, Sha256Digest>(u)?;
        let signer_count = u.int_in_range(config.designation_quorum()..=config.view_quorum())?;
        let tally =
            arbitrary_tally_for::<V, Sha256Digest, Sha256>(u, &leader, signer_count, config)?;
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
            u.arbitrary::<aggregate::Signature<V>>()?,
            config,
        )
        .expect("generated V-QC has a canonical transcript"))
    }
}

impl<'a, V> Arbitrary<'a> for Lqc<V, Sha256Digest>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let leader = arbitrary_leader_block::<V, Sha256Digest>(u)?;
        let tally = arbitrary_tally_for::<V, Sha256Digest, Sha256>(
            u,
            &leader,
            config.view_quorum(),
            config,
        )?;

        Ok(Self::new(
            leader,
            tally,
            u.arbitrary::<aggregate::Signature<V>>()?,
            config,
        )
        .expect("generated L-QC has a canonical transcript"))
    }
}
