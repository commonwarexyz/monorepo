//! The wire encoding of the retrieval keys peers request from each other.

use crate::{
    multimmit::{
        machine::RetrievalKey,
        types::{CertificateId, ChainId},
    },
    types::{Participant, View},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, FixedSize as _, Read, ReadExt as _, Write};
use commonware_cryptography::Digest;
use commonware_utils::Span;
use core::fmt;

const UPDATE: u8 = 0;
const HEADER: u8 = 1;
const VQC: u8 = 2;
const VQC_VIEW: u8 = 3;
const LEADER_BLOCK: u8 = 4;
const LQC: u8 = 5;
const LATEST_FLOOR: u8 = 6;

impl<D: Digest> Write for RetrievalKey<D> {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Update { signer, view } => {
                UPDATE.write(buf);
                signer.write(buf);
                view.write(buf);
            }
            Self::Header { chain, digest } => {
                HEADER.write(buf);
                chain.write(buf);
                digest.write(buf);
            }
            Self::Vqc(id) => {
                VQC.write(buf);
                id.write(buf);
            }
            Self::VqcView(view) => {
                VQC_VIEW.write(buf);
                view.write(buf);
            }
            Self::LeaderBlock(view) => {
                LEADER_BLOCK.write(buf);
                view.write(buf);
            }
            Self::Lqc(id) => {
                LQC.write(buf);
                id.write(buf);
            }
            Self::LatestFloor => LATEST_FLOOR.write(buf),
        }
    }
}

impl<D: Digest> EncodeSize for RetrievalKey<D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Update { signer, view } => signer.encode_size() + view.encode_size(),
            Self::Header { chain, .. } => chain.encode_size() + D::SIZE,
            Self::Vqc(_) | Self::Lqc(_) => CertificateId::<D>::SIZE,
            Self::VqcView(view) | Self::LeaderBlock(view) => view.encode_size(),
            Self::LatestFloor => 0,
        }
    }
}

impl<D: Digest> Read for RetrievalKey<D> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(match u8::read(buf)? {
            UPDATE => Self::Update {
                signer: Participant::read(buf)?,
                view: View::read(buf)?,
            },
            HEADER => Self::Header {
                chain: ChainId::read(buf)?,
                digest: D::read(buf)?,
            },
            VQC => Self::Vqc(CertificateId::read(buf)?),
            VQC_VIEW => Self::VqcView(View::read(buf)?),
            LEADER_BLOCK => Self::LeaderBlock(View::read(buf)?),
            LQC => Self::Lqc(CertificateId::read(buf)?),
            LATEST_FLOOR => Self::LatestFloor,
            tag => return Err(Error::InvalidEnum(tag)),
        })
    }
}

impl<D: Digest> fmt::Display for RetrievalKey<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

impl<D: Digest> Span for RetrievalKey<D> {}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

    #[test]
    fn every_key_round_trips() {
        let digest = Sha256::hash(&[b"key"]);
        let keys: [RetrievalKey<Sha256Digest>; 7] = [
            RetrievalKey::Update {
                signer: Participant::new(300),
                view: View::new(u64::MAX),
            },
            RetrievalKey::Header {
                chain: ChainId::new(7),
                digest,
            },
            RetrievalKey::Vqc(CertificateId::new(digest)),
            RetrievalKey::VqcView(View::new(9)),
            RetrievalKey::LeaderBlock(View::new(10)),
            RetrievalKey::Lqc(CertificateId::new(digest)),
            RetrievalKey::LatestFloor,
        ];
        for key in keys {
            let encoded = key.encode();
            assert_eq!(encoded.len(), key.encode_size());
            assert_eq!(RetrievalKey::decode(encoded).unwrap(), key);
        }
        assert!(matches!(
            RetrievalKey::<Sha256Digest>::decode(bytes::Bytes::from_static(&[7u8])),
            Err(Error::InvalidEnum(7))
        ));
    }

    #[test]
    fn an_update_key_names_a_sender_and_tag_only() {
        let (signer, view) = (Participant::new(3), View::new(9));
        let key = RetrievalKey::<Sha256Digest>::Update { signer, view };
        let mut expected = vec![UPDATE];
        signer.write(&mut expected);
        view.write(&mut expected);
        assert_eq!(key.encode().as_ref(), expected.as_slice());

        // An update key is exactly a signer and view; trailing bytes are rejected.
        expected.push(1);
        assert!(matches!(
            RetrievalKey::<Sha256Digest>::decode(bytes::Bytes::from(expected)),
            Err(Error::ExtraData(1))
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<RetrievalKey<Sha256Digest>> => 128,
        }
    }
}
