use crate::Config;
use commonware_cryptography::Hasher;
use std::marker::PhantomData;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NoCodingError {
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

impl<H: Hasher> crate::Scheme for NoCoding<H> {
    type Commitment = H::Digest;

    type Shard = Vec<u8>;

    type ReShard = ();

    type CheckedShard = ();

    type CheckingData = Vec<u8>;

    type Error = NoCodingError;

    fn encode(
        config: &crate::Config,
        mut data: impl bytes::Buf,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        let data: Vec<u8> = data.copy_to_bytes(data.remaining()).to_vec();
        let commitment = H::new().update(&data).finalize();
        let shards = (0..config.minimum_shards + config.extra_shards)
            .map(|_| data.clone())
            .collect();
        Ok((commitment, shards))
    }

    fn reshard(
        _config: &Config,
        commitment: &Self::Commitment,
        _index: u16,
        shard: Self::Shard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::ReShard), Self::Error> {
        let my_commitment = H::new().update(shard.as_slice()).finalize();
        if &my_commitment != commitment {
            return Err(NoCodingError::BadData);
        }
        Ok((shard, (), ()))
    }

    fn check(
        _config: &Config,
        _commitment: &Self::Commitment,
        _checking_data: &Self::CheckingData,
        _index: u16,
        _reshard: Self::ReShard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        Ok(())
    }

    fn decode(
        _config: &Config,
        _commitment: &Self::Commitment,
        checking_data: Self::CheckingData,
        _shards: &[Self::CheckedShard],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(checking_data)
    }
}

impl<H: Hasher> crate::ValidatingScheme for NoCoding<H> {}
