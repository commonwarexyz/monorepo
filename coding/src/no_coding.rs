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
pub struct NoCoding<H> {
    _marker: PhantomData<H>,
}

impl<H: Hasher> crate::Scheme for NoCoding<H> {
    type Commitment = H::Digest;

    type Shard = Vec<u8>;

    type ReShard = ();

    type Proof = ();

    type Error = NoCodingError;

    fn encode(
        config: &crate::Config,
        mut data: impl bytes::Buf,
    ) -> Result<(Self::Commitment, Vec<(Self::Shard, Self::Proof)>), Self::Error> {
        let data: Vec<u8> = data.copy_to_bytes(data.remaining()).to_vec();
        let commitment = H::new().update(&data).finalize();
        let shards = (0..config.minimum_shards + config.extra_shards)
            .map(|_| (data.clone(), ()))
            .collect();
        Ok((commitment, shards))
    }

    fn check(
        commitment: &Self::Commitment,
        _proof: &Self::Proof,
        shard: &Self::Shard,
    ) -> Result<Self::ReShard, Self::Error> {
        let my_commitment = H::new().update(shard.as_slice()).finalize();
        if &my_commitment != commitment {
            return Err(NoCodingError::BadData);
        }
        Ok(())
    }

    fn decode(
        _config: &crate::Config,
        _commitment: &Self::Commitment,
        my_shard: Self::Shard,
        _shards: &[Self::ReShard],
    ) -> Result<Vec<u8>, Self::Error> {
        Ok(my_shard)
    }
}

impl<H: Hasher> crate::ValidatingScheme for NoCoding<H> {}
