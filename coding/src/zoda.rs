use std::marker::PhantomData;

use commonware_cryptography::Hasher;
use thiserror::Error;

use crate::{Config, Scheme};

#[derive(Clone, Copy)]
pub struct Zoda<H> {
    _marker: PhantomData<H>,
}

impl<H> std::fmt::Debug for Zoda<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Zoda")
    }
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
        config: &Config,
        data: impl bytes::Buf,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
        todo!()
    }

    fn reshard(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: Self::Shard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::ReShard), Self::Error> {
        todo!()
    }

    fn check(
        config: &Config,
        commitment: &Self::Commitment,
        checking_data: &Self::CheckingData,
        index: u16,
        reshard: Self::ReShard,
    ) -> Result<Self::CheckedShard, Self::Error> {
        todo!()
    }

    fn decode(
        config: &Config,
        commitment: &Self::Commitment,
        checking_data: Self::CheckingData,
        shards: &[Self::CheckedShard],
    ) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }
}
