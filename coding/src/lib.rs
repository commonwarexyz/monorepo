//! Encode data to enable recovery from a subset of fragments.
//!
//! # Status
//!
//! `commonware-coding` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use bytes::Buf;
use rand_core::CryptoRngCore;

pub mod reed_solomon;

pub struct Config {
    pub minimum_shards: usize,
    pub extra_shards: usize,
}

trait Scheme {
    type Commitment;
    type Shard;
    type Proof;
    type Error;

    fn encode(
        rng: impl CryptoRngCore,
        config: Config,
        data: impl Buf,
    ) -> (Self::Commitment, Vec<(Self::Shard, Self::Proof)>);
    fn check(
        commitment: &Self::Commitment,
        shard: &Self::Shard,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error>;
    fn decode(
        commitment: &Self::Commitment,
        shards: &[Self::Shard],
    ) -> Result<Vec<u8>, Self::Error>;
}
