use std::marker::PhantomData;

use commonware_cryptography::Hasher;
use thiserror::Error;

use crate::{Config, Scheme};

pub struct Zoda<H> {
    _marker: PhantomData<H>,
}

#[derive(Debug, Error)]
pub enum ZodaError {}

impl<H: Hasher> Scheme for Zoda<H> {
    type Commitment = H::Digest;

    type Shard = ();

    type ReShard = ();

    type CheckingData = ();

    type CheckedShard = ();

    type Error = ();

    fn encode(
        _config: &Config,
        _data: impl bytes::Buf,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        todo!()
    }

    fn reshard(
        _config: &Config,
        _commitment: &Self::Commitment,
        _shard: Self::Shard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::ReShard), Self::Error> {
        todo!()
    }

    fn check(
        _config: &Config,
        _commitment: &Self::Commitment,
        _checking_data: &Self::CheckingData,
        _index: u16,
        _reshard: Self::ReShard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        todo!()
    }

    fn decode(
        _config: &Config,
        _commitment: &Self::Commitment,
        _checking_data: Self::CheckingData,
        _shards: &[Self::CheckedShard],
    ) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }
}
