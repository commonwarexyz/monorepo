//! [`Arbitrary`] implementations for the protocol types.
//!
//! Every generated value is structurally valid under one fixed codec profile: 6 participants,
//! 6 producer chains, a window cap of 2, a flow bound of 4, and at most 2 payload hashes per
//! update chain. Decode generated values with [`codec_config`].

use super::*;
use crate::types::{Height, Participant, Round, View};
use ::arbitrary::{Arbitrary, Result as ArbitraryResult, Unstructured};
use commonware_cryptography::{
    Digest, Hasher, Sha256,
    bls12381::primitives::{ops::aggregate, variant::Variant},
    sha256::Digest as Sha256Digest,
};

const PARTICIPANTS: usize = 6;
const CHAINS: usize = 6;

/// Returns the codec profile every generated value satisfies.
pub(crate) fn codec_config() -> CodecConfig {
    let window = Window::with_bounds(2, 4, 2).expect("arbitrary window is valid");
    CodecConfig::new(PARTICIPANTS, CHAINS, window).expect("arbitrary codec config is valid")
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

fn arbitrary_chain(u: &mut Unstructured<'_>) -> ArbitraryResult<ChainId> {
    Ok(ChainId::new(u.int_in_range(0..=(CHAINS - 1) as u32)?))
}

fn arbitrary_ref<D>(u: &mut Unstructured<'_>, chain: ChainId) -> ArbitraryResult<BlockRef<D>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    Ok(BlockRef::new(
        chain,
        Height::new(u.arbitrary()?),
        u.arbitrary()?,
    ))
}

fn arbitrary_endorsement<D>(u: &mut Unstructured<'_>) -> ArbitraryResult<Endorsement<D>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    let tips = codec_config()
        .chain_ids()
        .map(|chain| arbitrary_ref(u, chain))
        .collect::<ArbitraryResult<Vec<_>>>()?;
    Ok(Endorsement::new(u.arbitrary()?, tips, codec_config())
        .expect("generated endorsement spans every chain"))
}

/// Generates `n - f` contents of one round drawn from a small pool, so tallies mix shared
/// references with deviations.
fn arbitrary_contents<D>(
    u: &mut Unstructured<'_>,
    round: Round,
    leader: impl Fn(&mut Unstructured<'_>) -> ArbitraryResult<Option<D>>,
    final_: impl Fn(&mut Unstructured<'_>) -> ArbitraryResult<bool>,
) -> ArbitraryResult<Vec<(Participant, VoteContent<D>)>>
where
    D: Digest + for<'a> Arbitrary<'a>,
{
    let config = codec_config();
    let pool = (0..u.int_in_range(1..=3)?)
        .map(|_| arbitrary_endorsement(u))
        .collect::<ArbitraryResult<Vec<_>>>()?;
    let skipped = u.int_in_range(0..=config.participants() - 1)?;
    (0..config.participants())
        .filter(|index| *index != skipped)
        .map(|index| {
            let endorsement = pool[u.int_in_range(0..=pool.len() - 1)?].clone();
            let content = VoteContent::new(round, leader(u)?, final_(u)?, endorsement)
                .expect("generated round is live");
            Ok((Participant::from_usize(index), content))
        })
        .collect()
}

impl<'a> Arbitrary<'a> for ChainSet {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let mut set = Self::empty(CHAINS);
        for chain in codec_config().chain_ids() {
            if u.arbitrary()? {
                set.insert(chain);
            }
        }
        Ok(set)
    }
}

impl<'a, D> Arbitrary<'a> for HistoryRecord<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let tips = codec_config()
            .chain_ids()
            .map(|chain| arbitrary_ref(u, chain))
            .collect::<ArbitraryResult<Vec<_>>>()?;
        Ok(Self::new(u.arbitrary()?, tips).expect("generated history record is canonical"))
    }
}

impl<'a, D> Arbitrary<'a> for TransactionBlockHeader<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(
            u.arbitrary()?,
            arbitrary_chain(u)?,
            Height::new(u.int_in_range(1..=u64::MAX)?),
            u.arbitrary()?,
            u.arbitrary()?,
        )
        .expect("generated transaction block header is live"))
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
        let chain = arbitrary_chain(u)?;
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

impl<'a, D> Arbitrary<'a> for LeaderBlock<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(
            arbitrary_live_round(u)?,
            CertificateId::new(u.arbitrary()?),
            u.arbitrary()?,
        )
        .expect("generated leader block has a live view"))
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

impl<'a, D> Arbitrary<'a> for Endorsement<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        arbitrary_endorsement(u)
    }
}

impl<'a, D> Arbitrary<'a> for VoteContent<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(
            arbitrary_live_round(u)?,
            u.arbitrary()?,
            u.arbitrary()?,
            arbitrary_endorsement(u)?,
        )
        .expect("generated vote has a live view"))
    }
}

impl<'a, D> Arbitrary<'a> for ChainChange<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let chain = arbitrary_chain(u)?;
        let height = Height::new(u.int_in_range(config.window().delta_max() as u64..=u64::MAX)?);
        let payloads = arbitrary_vec(u, config.window().delta_max() as usize)?;
        Ok(Self::new(
            BlockRef::new(chain, height, u.arbitrary()?),
            payloads,
            config,
        )
        .expect("generated chain change respects codec limits"))
    }
}

impl<'a, V, D> Arbitrary<'a> for VoteUpdate<V, D>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let mut changes: Vec<ChainChange<D>> = arbitrary_vec(u, CHAINS)?;
        changes.sort_by_key(ChainChange::chain);
        changes.dedup_by_key(|change| change.chain());
        Ok(Self::new(
            arbitrary_live_round(u)?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.arbitrary()?,
            u.int_in_range(1..=u32::MAX)?,
            changes,
            u.arbitrary()?,
            config,
        )
        .expect("generated update respects codec limits"))
    }
}

impl<'a, D> Arbitrary<'a> for ResolutionPath<D>
where
    D: Digest + for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let config = codec_config();
        let chain = arbitrary_chain(u)?;
        let from = BlockRef::new(
            chain,
            Height::new(u.int_in_range(0..=u32::MAX as u64)?),
            u.arbitrary()?,
        );
        let len = u.int_in_range(1..=config.window().max_tip_lead() as usize)?;
        let payloads = (0..len)
            .map(|_| u.arbitrary())
            .collect::<ArbitraryResult<_>>()?;
        Ok(Self::new(from, payloads, config).expect("generated path respects codec limits"))
    }
}

impl<'a> Arbitrary<'a> for VoteTally<Sha256Digest> {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let leader: Sha256Digest = u.arbitrary()?;
        let round = arbitrary_live_round(u)?;
        let contents = arbitrary_contents(u, round, |_| Ok(Some(leader)), |u| u.arbitrary())?;
        Ok(Self::from_contents(leader, contents, codec_config())
            .expect("generated votes form a quorum"))
    }
}

impl<'a> Arbitrary<'a> for FinalTally<Sha256Digest> {
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let leader: Option<Sha256Digest> = u.arbitrary()?;
        let round = arbitrary_live_round(u)?;
        let contents = arbitrary_contents(
            u,
            round,
            |u| Ok(if u.arbitrary()? { leader } else { None }),
            |_| Ok(true),
        )?;
        let paths = arbitrary_vec(u, 3)?;
        Ok(Self::from_contents(contents, paths, codec_config())
            .expect("generated final votes form a quorum"))
    }
}

impl<'a, V> Arbitrary<'a> for Vqc<V, Sha256Digest>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        Ok(Self::new(
            arbitrary_live_round(u)?,
            CertificateId::new(u.arbitrary()?),
            u.arbitrary()?,
            u.arbitrary::<aggregate::Signature<V>>()?,
            codec_config(),
        )
        .expect("generated V-QC fits the byte ceiling"))
    }
}

impl<'a, V> Arbitrary<'a> for Lqc<V, Sha256Digest>
where
    V: Variant,
    V::Signature: for<'b> Arbitrary<'b>,
{
    fn arbitrary(u: &mut Unstructured<'a>) -> ArbitraryResult<Self> {
        let leader: LeaderBlock<Sha256Digest> = u.arbitrary()?;
        let contents = arbitrary_contents(
            u,
            leader.round(),
            |_| Ok(Some(leader.digest::<Sha256>())),
            |u| u.arbitrary(),
        )?;
        let tally = VoteTally::from_contents(leader.digest::<Sha256>(), contents, codec_config())
            .expect("generated votes form a quorum");
        Ok(Self::new(
            leader,
            tally,
            u.arbitrary::<aggregate::Signature<V>>()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multimmit::mocks::MockBody;
    use commonware_codec::conformance::CodecConformance;
    use commonware_cryptography::bls12381::primitives::variant::{MinPk, MinSig};

    commonware_conformance::conformance_tests! {
        CodecConformance<VoteUpdate<MinPk, Sha256Digest>> => 128,
        CodecConformance<VoteContent<Sha256Digest>> => 128,
        CodecConformance<SignedLeaderBlock<MinSig, Sha256Digest>> => 64,
        CodecConformance<FinalTally<Sha256Digest>> => 128,
        CodecConformance<VoteTally<Sha256Digest>> => 128,
        CodecConformance<Vqc<MinSig, Sha256Digest>> => 64,
        CodecConformance<Lqc<MinPk, Sha256Digest>> => 64,
        CodecConformance<HistoryRecord<Sha256Digest>> => 64,
        CodecConformance<VoteUpdate<MinSig, Sha256Digest>> => 128,
        CodecConformance<SignedLeaderBlock<MinPk, Sha256Digest>> => 64,
        CodecConformance<Vqc<MinPk, Sha256Digest>> => 64,
        CodecConformance<Lqc<MinSig, Sha256Digest>> => 64,
        CodecConformance<Floor<MinPk, Sha256Digest>> => 64,
        CodecConformance<Floor<MinSig, Sha256Digest>> => 64,
        CodecConformance<ChainId> => 64,
        CodecConformance<ChainSet> => 64,
        CodecConformance<CertificateId<Sha256Digest>> => 64,
        CodecConformance<BlockRef<Sha256Digest>> => 64,
        CodecConformance<Attestation<MinPk>> => 64,
        CodecConformance<Attestation<MinSig>> => 64,
        CodecConformance<TransactionBlockHeader<Sha256Digest>> => 128,
        CodecConformance<TransactionBlock<Sha256, MockBody>> => 64,
        CodecConformance<SignedTransactionBlock<MinPk, Sha256Digest>> => 64,
        CodecConformance<SignedTransactionBlock<MinSig, Sha256Digest>> => 64,
        CodecConformance<LeaderBlock<Sha256Digest>> => 128,
        CodecConformance<Endorsement<Sha256Digest>> => 128,
        CodecConformance<ChainChange<Sha256Digest>> => 128,
        CodecConformance<ResolutionPath<Sha256Digest>> => 128,
    }
}
