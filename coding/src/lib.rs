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
use commonware_codec::Codec;
use rand_core::CryptoRngCore;

pub mod reed_solomon;

/// Configuration common to all encoding schemes.
pub struct Config {
    /// The minimum number of shards needed to encode the data.
    pub minimum_shards: u16,
    /// Extra shards beyond the minimum number.
    ///
    /// Alternatively, one can think of the configuration as having a total number
    /// `N = extra_shards + minimum_shards`, but by specifying the `extra_shards`
    /// rather than `N`, we avoid needing to check that `minimum_shards <= N`.
    pub extra_shards: u16,
}

pub trait Scheme {
    /// A commitment attesting to the shards of data.
    type Commitment: Codec;
    /// A shard of data, to be received by a participant.
    type Shard: Codec;
    /// A shard shared with other participants, to aid them in reconstruction.
    ///
    /// In most cases, this will be the same as `Shard`, but some schemes might
    /// have extra information in `Shard` that may not be necessary to reconstruct
    /// the data.
    type ReShard: Clone + Codec;
    /// A proof that the shard is well-formed.
    type Proof: Codec;
    type Error;

    /// Encode a piece of data, returning a commitment, along with shards, and proofs.
    ///
    /// Each shard and proof is intended for exactly one participant. The number of shards returned
    /// should equal `config.minimum_shards + config.extra_shards`.
    #[allow(clippy::type_complexity)]
    fn encode(
        rng: impl CryptoRngCore,
        config: &Config,
        data: impl Buf,
    ) -> Result<(Self::Commitment, Vec<(Self::Shard, Self::Proof)>), Self::Error>;
    /// Check that integrity of a shard.
    ///
    /// At a minimum, this checks that the shard is included in the data attested
    /// to by the commitment.
    ///
    /// This might have a stronger guarantee, in the case of [ValidatingScheme].
    fn check(
        commitment: &Self::Commitment,
        proof: &Self::Proof,
        shard: &Self::Shard,
    ) -> Result<Self::ReShard, Self::Error>;
    /// Decode the data from shards received from other participants.
    ///
    /// The data must be decodeable with as few as `config.minimum_shards`,
    /// including your own shard.
    ///
    /// Calls to this function with the same commitment, but with different shards,
    /// or shards in a different should also result in the same output data, or in failure.
    /// In other words, when using the decoding function in a broader system, you
    /// get a guarantee that every participant decoding will see the same final
    /// data, even if they receive different shards, or receive them in a different order.
    fn decode(
        config: &Config,
        commitment: &Self::Commitment,
        my_shard: Self::Shard,
        shards: &[Self::ReShard],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// A marker trait indicating that [Scheme::check] proves validity of the encoding.
///
/// In more detail, this means that upon a successful call to [Scheme::check],
/// guarantees that the shard results from a valid encoding of the data, and thus,
/// if other participants also call check, then the data is guaranteed to be reconstructable.
pub trait ValidatingScheme: Scheme {}
