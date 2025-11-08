use crate::Config;
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("data does not match commitment")]
    BadData,
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

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct WeakShard(());

impl EncodeSize for WeakShard {
    fn encode_size(&self) -> usize {
        0
    }
}

impl Write for WeakShard {
    fn write(&self, _buf: &mut impl bytes::BufMut) {}
}

impl Read for WeakShard {
    type Cfg = crate::CodecConfig;

    fn read_cfg(
        _buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        Ok(Self(()))
    }
}

impl<H: Hasher> crate::Scheme for NoCoding<H> {
    type Commitment = H::Digest;

    type StrongShard = Shard;

    type WeakShard = WeakShard;

    type CheckedShard = ();

    type CheckingData = Vec<u8>;

    type Error = Error;

    fn encode(
        config: &crate::Config,
        mut data: impl bytes::Buf,
        _strategy: &impl Strategy,
    ) -> Result<(Self::Commitment, Vec<Self::StrongShard>), Self::Error> {
        let data: Vec<u8> = data.copy_to_bytes(data.remaining()).to_vec();
        let commitment = H::new().update(&data).finalize();
        let shards = (0..config.total_shards())
            .map(|_| Shard(data.clone()))
            .collect();
        Ok((commitment, shards))
    }

    fn weaken(
        _config: &Config,
        commitment: &Self::Commitment,
        _index: u16,
        shard: Self::StrongShard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::WeakShard), Self::Error> {
        let my_commitment = H::new().update(shard.0.as_slice()).finalize();
        if &my_commitment != commitment {
            return Err(Error::BadData);
        }
        Ok((shard.0, (), WeakShard(())))
    }

    fn check(
        _config: &Config,
        _commitment: &Self::Commitment,
        _checking_data: &Self::CheckingData,
        _index: u16,
        _weak_shard: Self::WeakShard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        Ok(())
    }

    fn decode(
        _config: &Config,
        _commitment: &Self::Commitment,
        checking_data: Self::CheckingData,
        _shards: &[Self::CheckedShard],
        _strategy: &impl Strategy,
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(checking_data)
    }
}

impl<H: Hasher> crate::ValidatingScheme for NoCoding<H> {}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<Shard>,
        CodecConformance<WeakShard>
    }
}
