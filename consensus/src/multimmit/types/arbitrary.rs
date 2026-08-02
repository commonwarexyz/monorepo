use super::*;
use crate::{
    multimmit::config::{CodecConfig, Limits},
    types::{Epoch, Round, View},
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
};
use commonware_utils::Participant;

const PARTICIPANTS: usize = 6;
const PIPELINE_DEPTH: u32 = 2;
const EXTENSION_BOUND: u32 = 2;

fn codec_config() -> CodecConfig {
    let limits =
        Limits::new(PIPELINE_DEPTH, EXTENSION_BOUND).expect("arbitrary codec limits are valid");
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
    Signers::from(
        participants,
        indices.into_iter().map(Participant::from_usize),
    )
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
    let positions = (0..config.chains())
        .map(|_| {
            u.int_in_range(0..=config.pipeline_depth() as u32)
                .map(Position::new)
        })
        .collect::<ArbitraryResult<_>>()?;

    Ok(VoteBody::new(
        round,
        u.arbitrary()?,
        positions,
        arbitrary_extensions(u, config)?,
        config,
    )
    .expect("generated vote body respects codec limits"))
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

    VoteBody::for_leader::<H, V>(leader, positions, arbitrary_extensions(u, config)?, config)
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

    Ok(Tally::from_votes::<V, H, _>(leader, votes, config)
        .expect("generated tally contains canonical votes"))
}

fn arbitrary_conflicting_vote_for<D>(
    u: &mut Unstructured<'_>,
    signer: Participant,
    config: CodecConfig,
) -> ArbitraryResult<ConflictingVote<D>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    let positions = (0..config.chains())
        .map(|_| {
            u.int_in_range(0..=config.pipeline_depth() as u32)
                .map(Position::new)
        })
        .collect::<ArbitraryResult<_>>()?;

    Ok(ConflictingVote::new(
        signer,
        u.arbitrary()?,
        positions,
        arbitrary_extensions(u, config)?,
        config,
    )
    .expect("generated conflicting vote respects codec limits"))
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

        Ok(Self::new(u.arbitrary()?, tips).expect("generated tip record is canonical"))
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

impl<'a, D> Arbitrary<'a> for Deviation<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
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
        let extensions = if u.arbitrary()? {
            Some(arbitrary_extensions(u, config)?)
        } else {
            None
        };

        Ok(Self::new(
            Participant::from_usize(u.int_in_range(0..=config.participants() - 1)?),
            positions,
            extensions,
        ))
    }
}

impl<'a, D> Arbitrary<'a> for Tally<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
    Sha256: Hasher<Digest = D>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let leader = arbitrary_leader_block::<MinSig, D>(u)?;
        let signer_count = u.int_in_range(1..=config.participants())?;
        arbitrary_tally_for::<MinSig, D, Sha256>(u, &leader, signer_count, config)
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

impl<'a, V, D> Arbitrary<'a> for Vqc<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
    Sha256: Hasher<Digest = D>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let leader = arbitrary_leader_block::<V, D>(u)?;
        let signer_count = u.int_in_range(config.designation_quorum()..=config.view_quorum())?;
        let tally = arbitrary_tally_for::<V, D, Sha256>(u, &leader, signer_count, config)?;
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

impl<'a, V, D> Arbitrary<'a> for Lqc<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
    Sha256: Hasher<Digest = D>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let leader = arbitrary_leader_block::<V, D>(u)?;
        let tally = arbitrary_tally_for::<V, D, Sha256>(u, &leader, config.view_quorum(), config)?;

        Ok(Self::new(
            leader,
            tally,
            u.arbitrary::<aggregate::Signature<V>>()?,
            config,
        )
        .expect("generated L-QC has a canonical transcript"))
    }
}

#[cfg(test)]
mod conformance {
    use super::*;
    use commonware_codec::{
        Decode, Encode, Read,
        conformance::{CodecConformance, generate_value},
    };
    use commonware_conformance::Conformance;
    use commonware_cryptography::{
        bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use core::fmt::Debug;

    fn assert_round_trip<T>(cfg: T::Cfg, n_cases: u64)
    where
        T: Read + Encode + Eq + Debug + for<'a> Arbitrary<'a>,
    {
        for seed in 0..n_cases {
            let value = generate_value::<T>(seed);
            let encoded = value.encode();
            let decoded = T::decode_cfg(encoded.clone(), &cfg)
                .expect("generated value should decode under its codec config");
            assert_eq!(decoded, value);
            assert!(T::decode_cfg(encoded.slice(..encoded.len() - 1), &cfg).is_err());
        }
    }

    #[test]
    fn generated_values_round_trip() {
        let config = codec_config();

        assert_round_trip::<ChainId>((), 1024);
        assert_round_trip::<Position>((), 1024);
        assert_round_trip::<PositionDeviation>((), 1024);
        assert_round_trip::<CertificateId<Sha256Digest>>((), 1024);
        assert_round_trip::<BlockRef<Sha256Digest>>((), 1024);
        assert_round_trip::<TipRecord<Sha256Digest>>(config.chains(), 128);
        assert_round_trip::<EpochGenesis<Sha256Digest>>(config, 128);
        assert_round_trip::<TransactionBlockHeader<Sha256Digest>>((), 128);
        assert_round_trip::<Attestation<MinSig>>((), 128);
        assert_round_trip::<ThresholdShare<MinSig>>((), 128);
        assert_round_trip::<SignedTransactionBlock<MinSig, Sha256Digest>>((), 128);
        assert_round_trip::<DaVote<MinSig, Sha256Digest>>((), 128);
        assert_round_trip::<DaCertificate<MinSig, Sha256Digest>>((), 128);
        assert_round_trip::<Anchor<MinSig, Sha256Digest>>(config, 128);
        assert_round_trip::<ChainProposal<MinSig, Sha256Digest>>((ChainId::new(0), config), 128);
        assert_round_trip::<LeaderBlock<MinSig, Sha256Digest>>(config, 128);
        assert_round_trip::<SignedLeaderBlock<MinSig, Sha256Digest>>(config, 128);
        assert_round_trip::<Extension<Sha256Digest>>(config.extension_bound(), 128);
        assert_round_trip::<VoteBody<Sha256Digest>>(config, 128);
        assert_round_trip::<Vote<MinSig, Sha256Digest>>(config, 128);
        assert_round_trip::<NoVote<MinSig>>((), 128);
        assert_round_trip::<Nullify<MinSig>>((), 128);
        assert_round_trip::<ViewMessage<MinSig, Sha256Digest>>(config, 128);
        assert_round_trip::<ConflictingVote<Sha256Digest>>(config, 128);
        assert_round_trip::<Nullification<MinSig>>((), 128);
        assert_round_trip::<Vqc<MinSig, Sha256Digest>>(config, 128);
        assert_round_trip::<Lqc<MinSig, Sha256Digest>>(config, 128);

        assert_round_trip::<Attestation<MinPk>>((), 128);
        assert_round_trip::<ThresholdShare<MinPk>>((), 128);
        assert_round_trip::<SignedTransactionBlock<MinPk, Sha256Digest>>((), 128);
        assert_round_trip::<DaVote<MinPk, Sha256Digest>>((), 128);
        assert_round_trip::<DaCertificate<MinPk, Sha256Digest>>((), 128);
        assert_round_trip::<Anchor<MinPk, Sha256Digest>>(config, 128);
        assert_round_trip::<ChainProposal<MinPk, Sha256Digest>>((ChainId::new(0), config), 128);
        assert_round_trip::<LeaderBlock<MinPk, Sha256Digest>>(config, 128);
        assert_round_trip::<SignedLeaderBlock<MinPk, Sha256Digest>>(config, 128);
        assert_round_trip::<Vote<MinPk, Sha256Digest>>(config, 128);
        assert_round_trip::<NoVote<MinPk>>((), 128);
        assert_round_trip::<Nullify<MinPk>>((), 128);
        assert_round_trip::<ViewMessage<MinPk, Sha256Digest>>(config, 128);
        assert_round_trip::<Nullification<MinPk>>((), 128);
        assert_round_trip::<Vqc<MinPk, Sha256Digest>>(config, 128);
        assert_round_trip::<Lqc<MinPk, Sha256Digest>>(config, 128);
    }

    struct TipRecordConformance;

    impl Conformance for TipRecordConformance {
        async fn commit(seed: u64) -> Vec<u8> {
            let value = generate_value::<TipRecord<Sha256Digest>>(seed);
            let encoded = value.encode();
            let decoded = TipRecord::decode_cfg(encoded.clone(), &codec_config().chains())
                .expect("generated tip record decodes with its canonical chain count");
            assert_eq!(decoded, value);
            encoded.to_vec()
        }
    }

    commonware_conformance::conformance_tests! {
        CodecConformance<ChainId> => 1024,
        CodecConformance<Position> => 1024,
        CodecConformance<PositionDeviation> => 1024,
        CodecConformance<CertificateId<Sha256Digest>> => 1024,
        CodecConformance<BlockRef<Sha256Digest>> => 1024,
        TipRecordConformance => 128,
        CodecConformance<EpochGenesis<Sha256Digest>> => 128,
        CodecConformance<TransactionBlockHeader<Sha256Digest>> => 128,
        CodecConformance<Attestation<MinSig>> => 128,
        CodecConformance<ThresholdShare<MinSig>> => 128,
        CodecConformance<SignedTransactionBlock<MinSig, Sha256Digest>> => 128,
        CodecConformance<DaVote<MinSig, Sha256Digest>> => 128,
        CodecConformance<DaCertificate<MinSig, Sha256Digest>> => 128,
        CodecConformance<Anchor<MinSig, Sha256Digest>> => 128,
        CodecConformance<ChainProposal<MinSig, Sha256Digest>> => 128,
        CodecConformance<LeaderBlock<MinSig, Sha256Digest>> => 128,
        CodecConformance<SignedLeaderBlock<MinSig, Sha256Digest>> => 128,
        CodecConformance<Extension<Sha256Digest>> => 128,
        CodecConformance<VoteBody<Sha256Digest>> => 128,
        CodecConformance<Vote<MinSig, Sha256Digest>> => 128,
        CodecConformance<NoVote<MinSig>> => 128,
        CodecConformance<Nullify<MinSig>> => 128,
        CodecConformance<ViewMessage<MinSig, Sha256Digest>> => 128,
        CodecConformance<ConflictingVote<Sha256Digest>> => 128,
        CodecConformance<Nullification<MinSig>> => 128,
        CodecConformance<Vqc<MinSig, Sha256Digest>> => 128,
        CodecConformance<Lqc<MinSig, Sha256Digest>> => 128,
        CodecConformance<Attestation<MinPk>> => 128,
        CodecConformance<ThresholdShare<MinPk>> => 128,
        CodecConformance<SignedTransactionBlock<MinPk, Sha256Digest>> => 128,
        CodecConformance<DaVote<MinPk, Sha256Digest>> => 128,
        CodecConformance<DaCertificate<MinPk, Sha256Digest>> => 128,
        CodecConformance<Anchor<MinPk, Sha256Digest>> => 128,
        CodecConformance<ChainProposal<MinPk, Sha256Digest>> => 128,
        CodecConformance<LeaderBlock<MinPk, Sha256Digest>> => 128,
        CodecConformance<SignedLeaderBlock<MinPk, Sha256Digest>> => 128,
        CodecConformance<Vote<MinPk, Sha256Digest>> => 128,
        CodecConformance<NoVote<MinPk>> => 128,
        CodecConformance<Nullify<MinPk>> => 128,
        CodecConformance<ViewMessage<MinPk, Sha256Digest>> => 128,
        CodecConformance<Nullification<MinPk>> => 128,
        CodecConformance<Vqc<MinPk, Sha256Digest>> => 128,
        CodecConformance<Lqc<MinPk, Sha256Digest>> => 128,
    }
}
