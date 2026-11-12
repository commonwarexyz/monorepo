//! Peer-visible resolver keys and the responses that answer them.
//!
//! A key names only the object requested; every response is authenticated by the requester
//! against the key before anything is stored:
//!
//! - [`Key::Blocks`]: complete blocks, newest first, starting at the exact head and following
//!   parent links. Each decoded block's body matches its header, and each header's digest is the
//!   reference that names it.
//! - [`Key::Records`]: tip-history records, newest first, starting at the record whose commitment
//!   is `before` and following parent links, or [`Records::Pruned`] when the server no longer
//!   retains that part of the history.
//! - [`Key::Proofs`]: an L-QC with the history record its leader commits to. The requester
//!   verifies the certificate before using it.
//! - [`Key::Lqc`]: the L-QC with exactly that identifier.

use super::store::blocks::Block;
use crate::multimmit::types::{
    BlockRef, Body, CertificateId, CodecConfig, Lqc, TipRecord, TransactionBlock,
};
use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, EncodeSize, Error, RangeCfg, Read, ReadExt as _, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_utils::Span;
use core::{fmt, num::NonZeroU16};
use std::sync::Arc;

const BLOCKS: u8 = 0;
const RECORDS: u8 = 1;
const PROOFS: u8 = 2;
const LQC: u8 = 3;

/// Most blocks one request names.
pub(crate) const MAX_BLOCKS: u16 = 1024;

/// Most records one response carries.
pub(crate) const MAX_RECORDS: usize = 4096;

/// A peer-visible request for marshal data.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Key<D: Digest> {
    /// Complete blocks: `head` and up to `len - 1` of its ancestors, newest first.
    Blocks {
        /// The newest block requested.
        head: BlockRef<D>,
        /// Most blocks requested.
        len: NonZeroU16,
    },
    /// Tip-history records: the record whose commitment is `before`, then its ancestors.
    Records {
        /// Commitment of the newest record requested.
        before: D,
    },
    /// An L-QC with its leader's history record: the server's strongest, or with `after`, the
    /// first the server retains whose leader history is `after` or descends from it.
    Proofs {
        /// The history the proof must not precede.
        after: Option<D>,
    },
    /// The L-QC with exactly this identifier.
    Lqc {
        /// The certificate's identifier.
        id: CertificateId<D>,
    },
}

impl<D: Digest> Write for Key<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Blocks { head, len } => {
                BLOCKS.write(buf);
                head.write(buf);
                len.write(buf);
            }
            Self::Records { before } => {
                RECORDS.write(buf);
                before.write(buf);
            }
            Self::Proofs { after } => {
                PROOFS.write(buf);
                after.write(buf);
            }
            Self::Lqc { id } => {
                LQC.write(buf);
                id.write(buf);
            }
        }
    }
}

impl<D: Digest> EncodeSize for Key<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Blocks { head, len } => head.encode_size() + len.encode_size(),
            Self::Records { before } => before.encode_size(),
            Self::Proofs { after } => after.encode_size(),
            Self::Lqc { id } => id.encode_size(),
        }
    }
}

impl<D: Digest> Read for Key<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(buf)? {
            BLOCKS => {
                let head = BlockRef::read(buf)?;
                let len = NonZeroU16::read(buf)?;
                if len.get() > MAX_BLOCKS {
                    return Err(Error::InvalidLength(usize::from(len.get())));
                }
                Ok(Self::Blocks { head, len })
            }
            RECORDS => Ok(Self::Records {
                before: D::read(buf)?,
            }),
            PROOFS => Ok(Self::Proofs {
                after: Option::<D>::read(buf)?,
            }),
            LQC => Ok(Self::Lqc {
                id: CertificateId::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl<D: Digest> Span for Key<D> {}

impl<D: Digest> fmt::Display for Key<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocks { head, len } => write!(formatter, "Blocks({head:?}, {len})"),
            Self::Records { before } => write!(formatter, "Records({before:?})"),
            Self::Proofs { after } => write!(formatter, "Proofs({after:?})"),
            Self::Lqc { id } => write!(formatter, "Lqc({id:?})"),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, D> arbitrary::Arbitrary<'a> for Key<D>
where
    D: Digest + arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=3u8)? {
            BLOCKS => Self::Blocks {
                head: u.arbitrary()?,
                len: NonZeroU16::new(u.int_in_range(1..=MAX_BLOCKS)?).expect("nonzero"),
            },
            RECORDS => Self::Records {
                before: u.arbitrary()?,
            },
            PROOFS => Self::Proofs {
                after: u.arbitrary()?,
            },
            _ => Self::Lqc {
                id: CertificateId::new(u.arbitrary()?),
            },
        })
    }
}

/// A history record with its commitment.
pub(crate) type Committed<D> = (D, Arc<TipRecord<D>>);

/// Encodes blocks answering a [`Key::Blocks`] request.
pub(crate) fn encode_blocks<H: Hasher, B: Body<H>>(blocks: &[Block<H, B>]) -> Bytes {
    let mut buf = Vec::with_capacity(
        blocks.len().encode_size()
            + blocks
                .iter()
                .map(|block| block.encode_size())
                .sum::<usize>(),
    );
    blocks.len().write(&mut buf);
    for block in blocks {
        block.write(&mut buf);
    }
    buf.into()
}

/// Decodes and authenticates blocks answering a request for `len` blocks from `head`.
///
/// Returns the blocks newest first: a non-empty, parent-linked prefix ending at `head`.
pub(crate) fn decode_blocks<H: Hasher, B: Body<H>>(
    mut bytes: Bytes,
    head: BlockRef<H::Digest>,
    len: NonZeroU16,
    codec: &B::Cfg,
) -> Option<Vec<Block<H, B>>> {
    let count = usize::read_cfg(&mut bytes, &RangeCfg::from(1..=usize::from(len.get()))).ok()?;
    let mut blocks: Vec<Block<H, B>> = Vec::with_capacity(count);
    let mut expected = head;
    for _ in 0..count {
        let block = Arc::new(TransactionBlock::<H, B>::read_cfg(&mut bytes, codec).ok()?);
        if block.reference() != expected {
            return None;
        }
        expected = block.header().parent_ref();
        blocks.push(block);
    }
    bytes.is_empty().then_some(blocks)
}

/// A response to a [`Key::Records`] request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Records<D: Digest> {
    /// Records newest first.
    Records(Vec<Arc<TipRecord<D>>>),
    /// The server no longer retains the requested part of the history.
    Pruned,
}

impl<D: Digest> Write for Records<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Records(records) => {
                0u8.write(buf);
                records.len().write(buf);
                for record in records {
                    record.write(buf);
                }
            }
            Self::Pruned => 1u8.write(buf),
        }
    }
}

impl<D: Digest> EncodeSize for Records<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Records(records) => {
                records.len().encode_size()
                    + records
                        .iter()
                        .map(|record| record.encode_size())
                        .sum::<usize>()
            }
            Self::Pruned => 0,
        }
    }
}

impl<D: Digest> Read for Records<D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &CodecConfig) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => {
                let count = usize::read_cfg(buf, &RangeCfg::from(1..=MAX_RECORDS))?;
                let records = (0..count)
                    .map(|_| TipRecord::read_cfg(buf, config).map(Arc::new))
                    .collect::<Result<_, _>>()?;
                Ok(Self::Records(records))
            }
            1 => Ok(Self::Pruned),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

/// Authenticates records answering a [`Key::Records`] request for `before`.
///
/// Returns the records newest first with their commitments: the first is `before`, and each
/// next one is the parent of the one before it.
pub(crate) fn authenticate_records<H: Hasher>(
    records: Vec<Arc<TipRecord<H::Digest>>>,
    before: H::Digest,
) -> Option<Vec<Committed<H::Digest>>> {
    let mut expected = before;
    let mut authenticated = Vec::with_capacity(records.len());
    for record in records {
        let commitment = record.commitment::<H>();
        if commitment != expected {
            return None;
        }
        expected = record.parent();
        authenticated.push((commitment, record));
    }
    Some(authenticated)
}

/// An L-QC and the history record its leader commits to, answering a [`Key::Proofs`] request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Proof<S: crate::multimmit::scheme::Scheme, D: Digest> {
    pub(crate) lqc: Arc<Lqc<S, D>>,
    pub(crate) record: Arc<TipRecord<D>>,
}

impl<S: crate::multimmit::scheme::Scheme, D: Digest> Write for Proof<S, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.lqc.write(buf);
        self.record.write(buf);
    }
}

impl<S: crate::multimmit::scheme::Scheme, D: Digest> EncodeSize for Proof<S, D> {
    fn encode_size(&self) -> usize {
        self.lqc.encode_size() + self.record.encode_size()
    }
}

impl<S: crate::multimmit::scheme::Scheme, D: Digest> Read for Proof<S, D> {
    type Cfg = CodecConfig;

    fn read_cfg(buf: &mut impl Buf, config: &CodecConfig) -> Result<Self, Error> {
        Ok(Self {
            lqc: Arc::new(Lqc::read_cfg(buf, config)?),
            record: Arc::new(TipRecord::read_cfg(buf, config)?),
        })
    }
}

/// Encodes a value for the wire.
pub(crate) fn encode(value: &impl commonware_codec::Encode) -> Bytes {
    value.encode()
}

/// Malformed-response campaign over every marshal request and response, the body of the
/// `fuzz_marshal_wire` target.
#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz {
    use super::{
        Key, MAX_BLOCKS, Proof, Records, authenticate_records, decode_blocks, encode_blocks,
    };
    use crate::multimmit::{
        mocks::Bls,
        types::{CodecConfig, PathLimits, TransactionBlock},
    };
    use bytes::{BufMut, Bytes};
    use commonware_codec::{
        Buf, Codec, Copying, Decode as _, EncodeSize, Error, RangeCfg, Read, Write,
    };
    use commonware_cryptography::{
        Digestible, Hasher as _, Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as D,
    };
    use core::{fmt::Debug, num::NonZeroU16};

    /// A small opaque body.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Body(Vec<u8>);

    impl Write for Body {
        fn write(&self, buf: &mut impl BufMut) {
            self.0.write(buf);
        }
    }

    impl EncodeSize for Body {
        fn encode_size(&self) -> usize {
            self.0.encode_size()
        }
    }

    impl Read for Body {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
            Vec::<u8>::read_cfg(buf, &(RangeCfg::from(..=64), ())).map(Self)
        }
    }

    impl Digestible for Body {
        type Digest = D;

        fn digest(&self) -> D {
            Sha256::hash(&[&self.0])
        }
    }

    /// Decodes `input` as every request and response a peer may send, checking that accepted
    /// values re-encode canonically and that authenticated responses keep their linkage.
    pub(crate) fn exercise(input: &[u8]) {
        let config = CodecConfig::new(6, 2, PathLimits::new(2, 1)).unwrap();
        roundtrip::<Key<D>>(input, &());
        roundtrip::<Records<D>>(input, &config);
        roundtrip::<Proof<Bls<MinPk>, D>>(input, &config);
        if let Ok(Records::Records(records)) = Records::<D>::decode_cfg(Copying(input), &config) {
            // A walk asks for the newest record's commitment; records that do not chain from it
            // are rejected, and accepted ones keep their linkage.
            let before = records[0].commitment::<Sha256>();
            if let Some(authenticated) = authenticate_records::<Sha256>(records, before) {
                for pair in authenticated.windows(2) {
                    assert_eq!(pair[0].1.parent(), pair[1].0);
                }
            }
        }
        blocks(input);
    }

    /// Decodes `input` as a block response for the head its first block names.
    fn blocks(input: &[u8]) {
        let mut peek = Bytes::copy_from_slice(input);
        let Ok(count) = usize::read_cfg(&mut peek, &RangeCfg::from(1..=usize::from(MAX_BLOCKS)))
        else {
            return;
        };
        let Ok(first) = TransactionBlock::<Sha256, Body>::read_cfg(&mut peek, &()) else {
            return;
        };
        let head = first.reference();
        let lens = [count, usize::from(MAX_BLOCKS)];
        for len in lens {
            let len = NonZeroU16::new(len as u16).expect("lengths are positive and bounded");
            let Some(blocks) =
                decode_blocks::<Sha256, Body>(Bytes::copy_from_slice(input), head, len, &())
            else {
                continue;
            };
            assert!(!blocks.is_empty() && blocks.len() <= usize::from(len.get()));
            assert_eq!(blocks[0].reference(), head);
            for pair in blocks.windows(2) {
                assert_eq!(pair[0].header().parent_ref(), pair[1].reference());
            }
            assert_eq!(encode_blocks(&blocks).as_ref(), input);
        }
    }

    fn roundtrip<M>(input: &[u8], config: &M::Cfg)
    where
        M: Codec + PartialEq + Debug,
    {
        if let Ok(value) = M::decode_cfg(Copying(input), config) {
            assert_eq!(commonware_codec::Encode::encode(&value).as_ref(), input);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{CodecConfig, D, PathLimits, Records, exercise};
        use crate::{
            multimmit::types::{BlockRef, ChainId, TipRecord},
            types::Height,
        };
        use commonware_codec::{Decode as _, Encode as _};
        use commonware_cryptography::{Hasher as _, Sha256};
        use proptest::prelude::*;
        use std::sync::Arc;

        #[test]
        fn records_that_do_not_chain_are_rejected() {
            let record = |seed: u8| {
                let tips = (0..2u32)
                    .map(|chain| {
                        BlockRef::<D>::new(
                            ChainId::new(chain),
                            Height::new(1),
                            Sha256::hash(&[&[seed], &chain.to_be_bytes()]),
                        )
                    })
                    .collect();
                Arc::new(TipRecord::at_tips(Sha256::hash(&[&[seed]]), tips).unwrap())
            };
            // Both records decode, but the second is not the first's parent.
            let input = Records::Records(vec![record(1), record(2)]).encode();
            let config = CodecConfig::new(6, 2, PathLimits::new(2, 1)).unwrap();
            assert!(Records::<D>::decode_cfg(input.clone(), &config).is_ok());
            exercise(&input);
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]
            #[test]
            fn accepted_responses_reencode_and_keep_their_linkage(
                input in proptest::collection::vec(any::<u8>(), 0..2048),
            ) {
                exercise(&input);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            testing::TestBody,
            types::{ChainId, PathLimits, TransactionBlockHeader},
        },
        types::{Epoch, Height},
    };
    use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
    use commonware_cryptography::{Digestible as _, Sha256, sha256::Digest as D};

    fn chain(len: u64) -> Vec<Block<Sha256, TestBody>> {
        let mut parent = Sha256::hash(&[b"genesis"]);
        (1..=len)
            .map(|height| {
                let body = TestBody::new(Sha256::hash(&[b"app"]), Height::new(height), 0);
                let header = TransactionBlockHeader::new(
                    Epoch::new(1),
                    ChainId::new(2),
                    Height::new(height),
                    parent,
                    body.digest(),
                )
                .unwrap();
                let block = Arc::new(TransactionBlock::new(header, body).unwrap());
                parent = block.reference().digest();
                block
            })
            .collect()
    }

    #[test]
    fn keys_round_trip_and_bound_their_lengths() {
        let head = BlockRef::new(ChainId::new(1), Height::new(9), Sha256::hash(&[b"head"]));
        let keys = [
            Key::Blocks {
                head,
                len: NonZeroU16::new(MAX_BLOCKS).unwrap(),
            },
            Key::Records {
                before: Sha256::hash(&[b"before"]),
            },
            Key::Proofs { after: None },
            Key::Proofs {
                after: Some(Sha256::hash(&[b"after"])),
            },
            Key::Lqc {
                id: CertificateId::new(Sha256::hash(&[b"lqc"])),
            },
        ];
        for key in keys {
            let encoded = key.encode();
            assert_eq!(encoded.len(), key.encode_size());
            assert_eq!(Key::<D>::decode(encoded).unwrap(), key);
        }
        let mut too_long = Vec::new();
        BLOCKS.write(&mut too_long);
        head.write(&mut too_long);
        (MAX_BLOCKS + 1).write(&mut too_long);
        assert!(Key::<D>::decode(Bytes::from(too_long)).is_err());
        assert!(Key::<D>::decode(Bytes::from_static(&[9])).is_err());
    }

    #[test]
    fn blocks_authenticate_against_the_head() {
        let blocks = chain(4);
        let newest_first = blocks.iter().rev().cloned().collect::<Vec<_>>();
        let head = newest_first[0].reference();
        let len = NonZeroU16::new(4).unwrap();
        let encoded = encode_blocks::<Sha256, TestBody>(&newest_first);
        assert_eq!(
            decode_blocks::<Sha256, TestBody>(encoded.clone(), head, len, &()),
            Some(newest_first.clone())
        );
        // A prefix is accepted; more blocks than requested are not.
        let prefix = encode_blocks::<Sha256, TestBody>(&newest_first[..2]);
        assert_eq!(
            decode_blocks::<Sha256, TestBody>(prefix, head, len, &()).map(|b| b.len()),
            Some(2)
        );
        assert!(
            decode_blocks::<Sha256, TestBody>(
                encoded.clone(),
                head,
                NonZeroU16::new(3).unwrap(),
                &()
            )
            .is_none()
        );
        // Another head, a gap, or trailing bytes are rejected.
        assert!(
            decode_blocks::<Sha256, TestBody>(
                encoded.clone(),
                newest_first[1].reference(),
                len,
                &()
            )
            .is_none()
        );
        let gapped =
            encode_blocks::<Sha256, TestBody>(&[newest_first[0].clone(), newest_first[2].clone()]);
        assert!(decode_blocks::<Sha256, TestBody>(gapped, head, len, &()).is_none());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(decode_blocks::<Sha256, TestBody>(trailing.into(), head, len, &()).is_none());
        assert!(
            decode_blocks::<Sha256, TestBody>(
                encode_blocks::<Sha256, TestBody>(&[]),
                head,
                len,
                &()
            )
            .is_none()
        );
    }

    #[test]
    fn records_authenticate_newest_first() {
        let config = CodecConfig::new(4, 1, PathLimits::new(2, 1)).unwrap();
        let mut parent = Sha256::hash(&[b"base"]);
        let mut records = Vec::new();
        for height in 1..=3u64 {
            let record = TipRecord::at_tips(
                parent,
                vec![BlockRef::new(
                    ChainId::new(0),
                    Height::new(height),
                    Sha256::hash(&[&height.to_be_bytes()]),
                )],
            )
            .unwrap();
            parent = record.commitment::<Sha256>();
            records.push(Arc::new(record));
        }
        records.reverse();
        let response = Records::Records(records.clone());
        let decoded = Records::<D>::decode_cfg(response.encode(), &config).unwrap();
        assert_eq!(decoded, response);
        assert_eq!(
            Records::<D>::decode_cfg(Records::<D>::Pruned.encode(), &config).unwrap(),
            Records::Pruned
        );
        let authenticated = authenticate_records::<Sha256>(records.clone(), parent).unwrap();
        assert_eq!(authenticated.len(), 3);
        assert_eq!(authenticated[0].0, parent);
        // Any other starting commitment, or a gap, is rejected.
        assert!(authenticate_records::<Sha256>(records.clone(), records[1].parent()).is_none());
        assert!(
            authenticate_records::<Sha256>(vec![records[0].clone(), records[2].clone()], parent)
                .is_none()
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::multimmit::{mocks::Bls, types::arbitrary_codec_config};
        use arbitrary::{Arbitrary, Unstructured};
        use commonware_codec::conformance::{CodecConformance, generate_value};
        use commonware_conformance::Conformance;
        use commonware_cryptography::bls12381::primitives::variant::MinSig;

        type TestProof = Proof<Bls<MinSig>, D>;

        impl<'a> Arbitrary<'a> for Records<D> {
            fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
                if u.arbitrary()? {
                    return Ok(Self::Pruned);
                }
                let count = u.int_in_range(1..=4usize)?;
                let records = (0..count)
                    .map(|_| u.arbitrary().map(Arc::new))
                    .collect::<arbitrary::Result<_>>()?;
                Ok(Self::Records(records))
            }
        }

        impl<'a> Arbitrary<'a> for TestProof {
            fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
                Ok(Self {
                    lqc: Arc::new(u.arbitrary()?),
                    record: Arc::new(u.arbitrary()?),
                })
            }
        }

        struct RecordsConformance;

        impl Conformance for RecordsConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let records = generate_value::<Records<D>>(seed);
                let encoded = records.encode();
                assert_eq!(
                    Records::decode_cfg(encoded.clone(), &arbitrary_codec_config()).unwrap(),
                    records
                );
                encoded.to_vec()
            }
        }

        struct ProofConformance;

        impl Conformance for ProofConformance {
            async fn commit(seed: u64) -> Vec<u8> {
                let proof = generate_value::<TestProof>(seed);
                let encoded = proof.encode();
                assert_eq!(
                    TestProof::decode_cfg(encoded.clone(), &arbitrary_codec_config()).unwrap(),
                    proof
                );
                encoded.to_vec()
            }
        }

        commonware_conformance::conformance_tests! {
            CodecConformance<Key<D>> => 128,
            RecordsConformance => 128,
            ProofConformance => 128,
        }
    }
}
