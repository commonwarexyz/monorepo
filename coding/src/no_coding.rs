use crate::Config;
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("data does not match commitment")]
    BadData,
    #[error("checked shard commitment does not match decode commitment")]
    CommitmentMismatch,
}

/// A trivial scheme which performs no coding at all.
///
/// Instead, each shard contains all of the data.
///
/// The commitment is simply a hash of that data. This struct is generic
/// over the choice of [commonware_cryptography::Hasher].
#[derive(Clone, Copy)]
pub struct NoCoding<H> {
    _marker: PhantomData<H>,
}

impl<H> std::fmt::Debug for NoCoding<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoCoding").finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Shard(Vec<u8>);

impl EncodeSize for Shard {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Write for Shard {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf)
    }
}

impl Read for Shard {
    type Cfg = crate::CodecConfig;

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Vec::read_cfg(buf, &(RangeCfg::new(0..=cfg.maximum_shard_size), ())).map(Self)
    }
}

/// A shard that has been checked against a specific commitment.
#[derive(Clone)]
pub struct CheckedShard<D: Digest> {
    data: Vec<u8>,
    commitment: D,
}

impl<H: Hasher> crate::Scheme for NoCoding<H> {
    type Commitment = H::Digest;
    type Shard = Shard;
    type CheckingData = ();
    type CheckedShard = CheckedShard<H::Digest>;
    type Error = Error;

    fn encode(
        config: &crate::Config,
        mut data: impl bytes::Buf,
        _strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        let data: Vec<u8> = data.copy_to_bytes(data.remaining()).to_vec();
        let commitment = H::new().update(&data).finalize();
        let shards = (0..config.total_shards())
            .map(|_| Shard(data.clone()))
            .collect();
        Ok((commitment, shards))
    }

    fn check(
        _config: &Config,
        commitment: &Self::Commitment,
        _index: u16,
        shard: &Self::Shard,
        _checking_data: Option<Self::CheckingData>,
    ) -> Result<(Self::CheckedShard, Self::CheckingData), Self::Error> {
        let shard_commitment = H::new().update(shard.0.as_slice()).finalize();
        if &shard_commitment != commitment {
            return Err(Error::BadData);
        }
        Ok((
            CheckedShard {
                data: shard.0.clone(),
                commitment: *commitment,
            },
            (),
        ))
    }

    fn decode(
        _config: &Config,
        commitment: &Self::Commitment,
        _checking_data: &Self::CheckingData,
        shards: &[Self::CheckedShard],
        _strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        let first = shards.first().ok_or(Error::BadData)?;
        if !shards.iter().all(|s| &s.commitment == commitment) {
            return Err(Error::CommitmentMismatch);
        }
        Ok(first.data.clone())
    }
}

impl<H: Hasher> crate::ValidatingScheme for NoCoding<H> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Scheme;
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_utils::NZU16;

    const STRATEGY: Sequential = Sequential;

    #[test]
    fn test_invalid_shard_rejected() {
        let config = crate::Config {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(1),
        };
        let (commitment, mut shards) =
            NoCoding::<Sha256>::encode(&config, &b"commonware"[..], &STRATEGY).unwrap();
        let mut shard = shards.pop().expect("missing shard");
        shard.0[0] ^= 0x01;

        let result = NoCoding::<Sha256>::check(&config, &commitment, 0, &shard, None);
        assert!(matches!(result, Err(Error::BadData)));
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<Shard>,
    }
}
