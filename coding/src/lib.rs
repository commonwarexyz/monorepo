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
    pub minimum_shards: u16,
    pub extra_shards: u16,
}

pub trait Scheme {
    type Commitment;
    type Shard: Clone;
    type Proof;
    type Error;

    #[allow(clippy::type_complexity)]
    fn encode(
        rng: impl CryptoRngCore,
        config: &Config,
        data: impl Buf,
    ) -> Result<(Self::Commitment, Vec<(Self::Shard, Self::Proof)>), Self::Error>;
    fn check(
        commitment: &Self::Commitment,
        shard: &Self::Shard,
        proof: &Self::Proof,
    ) -> Result<(), Self::Error>;
    fn decode(
        config: &Config,
        commitment: &Self::Commitment,
        shards: &[Self::Shard],
    ) -> Result<Vec<u8>, Self::Error>;
}
