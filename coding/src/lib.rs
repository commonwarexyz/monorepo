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
use commonware_codec::{Codec, FixedSize, Read, Write};
use std::fmt::Debug;

mod reed_solomon;
use commonware_cryptography::Digest;
pub use reed_solomon::{Error as ReedSolomonError, ReedSolomon};

mod no_coding;
pub use no_coding::{NoCoding, NoCodingError};

/// Configuration common to all encoding schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

impl Config {
    /// Returns the total number of shards produced by this configuration.
    pub fn total_shards(&self) -> u16 {
        self.minimum_shards + self.extra_shards
    }
}

impl FixedSize for Config {
    const SIZE: usize = 2 * <u16 as FixedSize>::SIZE;
}

impl Write for Config {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.minimum_shards.write(buf);
        self.extra_shards.write(buf);
    }
}

impl Read for Config {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        Ok(Self {
            minimum_shards: u16::read_cfg(buf, cfg)?,
            extra_shards: u16::read_cfg(buf, cfg)?,
        })
    }
}

/// A scheme for encoding data into pieces, and recovering the data from those pieces.
///
/// # Example
/// ```
/// use commonware_coding::{Config, ReedSolomon, Scheme as _};
/// use commonware_cryptography::Sha256;
///
/// type RS = ReedSolomon<Sha256>;
///
/// let config = Config { minimum_shards: 2, extra_shards: 1 };
/// let data = b"Hello!";
/// // Turn the data into shards, and a commitment to those shards.
/// let (commitment, shards) =
///      RS::encode(&config, data.as_slice()).unwrap();
///
/// // Each person produces reshards, their own checked shard, and checking data
/// // to check other peoples reshards.
/// let (mut checking_data_w_shard, reshards): (Vec<_>, Vec<_>) = shards
///         .into_iter()
///         .enumerate()
///         .map(|(i, shard)| {
///             let (checking_data, checked_shard, reshard) = RS::reshard(&config, &commitment, i as u16, shard).unwrap();
///             ((checking_data, checked_shard), reshard)
///         })
///         .collect();
/// // Let's pretend that the last item is "ours"
/// let (checking_data, checked_shard) = checking_data_w_shard.pop().unwrap();
/// // We can use this checking_data to check the other shards.
/// let mut checked_shards = Vec::new();
/// checked_shards.push(checked_shard);
/// for (i, reshard) in reshards.into_iter().enumerate().skip(1) {
///   checked_shards.push(RS::check(&config, &commitment, &checking_data, i as u16, reshard).unwrap())
/// }
///
/// let data2 = RS::decode(&config, &commitment, checking_data, &checked_shards[..2]).unwrap();
/// assert_eq!(&data[..], &data2[..]);
///
/// // Decoding works with different shards, with a guarantee to get the same result.
/// let data3 = RS::decode(&config, &commitment, checking_data, &checked_shards[1..]).unwrap();
/// assert_eq!(&data[..], &data3[..]);
/// ```
pub trait Scheme: Debug + Clone + Send + Sync + 'static {
    /// A commitment attesting to the shards of data.
    type Commitment: Digest;
    /// A shard of data, to be received by a participant.
    type Shard: Clone + Eq + Codec + Send + Sync + 'static;
    /// A shard shared with other participants, to aid them in reconstruction.
    ///
    /// In most cases, this will be the same as `Shard`, but some schemes might
    /// have extra information in `Shard` that may not be necessary to reconstruct
    /// the data.
    type ReShard: Clone + Eq + Codec + Send + Sync + 'static;
    /// Data which can assist in checking shards.
    type CheckingData: Clone + Send;
    /// A shard that has been checked for inclusion in the commitment.
    ///
    /// This allows excluding [Scheme::ReShard]s which are invalid, and shouldn't
    /// be considered as progress towards meeting the minimum number of shards.
    type CheckedShard;
    type Error: std::fmt::Debug;

    /// Encode a piece of data, returning a commitment, along with shards, and proofs.
    ///
    /// Each shard and proof is intended for exactly one participant. The number of shards returned
    /// should equal `config.minimum_shards + config.extra_shards`.
    #[allow(clippy::type_complexity)]
    fn encode(
        config: &Config,
        data: impl Buf,
    ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error>;

    /// Take your own shard, check it, and produce a [Scheme::ReShard] to forward to others.
    ///
    /// This takes in an index, which is the index you expect the shard to be.
    ///
    /// This will produce a [Scheme::CheckedShard] which counts towards the minimum
    /// number of shards you need to reconstruct the data, in [Scheme::decode].
    ///
    /// You also get [Scheme::CheckingData], which has information you can use to check
    /// the shards you receive from others.
    #[allow(clippy::type_complexity)]
    fn reshard(
        config: &Config,
        commitment: &Self::Commitment,
        index: u16,
        shard: Self::Shard,
    ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::ReShard), Self::Error>;

    /// Check the integrity of a reshard, producing a checked shard.
    ///
    /// This requires the [Scheme::CheckingData] produced by [Scheme::reshard].
    ///
    /// This takes in an index, to make sure that the reshard you're checking
    /// is associated with the participant you expect it to be.
    fn check(
        config: &Config,
        commitment: &Self::Commitment,
        checking_data: &Self::CheckingData,
        index: u16,
        reshard: Self::ReShard,
    ) -> Result<Self::CheckedShard, Self::Error>;

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
        checking_data: Self::CheckingData,
        shards: &[Self::CheckedShard],
    ) -> Result<Vec<u8>, Self::Error>;
}

/// A marker trait indicating that [Scheme::check] proves validity of the encoding.
///
/// In more detail, this means that upon a successful call to [Scheme::check],
/// guarantees that the shard results from a valid encoding of the data, and thus,
/// if other participants also call check, then the data is guaranteed to be reconstructable.
pub trait ValidatingScheme: Scheme {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::reed_solomon::ReedSolomon;
    use commonware_cryptography::Sha256;

    fn test_basic<S: Scheme>() {
        let data = b"Hello, Reed-Solomon!";
        let config = Config {
            minimum_shards: 4,
            extra_shards: 3,
        };

        // Encode the data
        let (commitment, shards) = S::encode(&config, data.as_slice()).unwrap();

        let (mut checking_data, checked_shards): (Vec<_>, Vec<_>) = shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                let (checking_data, checked_shard, _) =
                    S::reshard(&config, &commitment, i as u16, shard).unwrap();
                (checking_data, checked_shard)
            })
            .collect();

        let decoded = S::decode(
            &config,
            &commitment,
            checking_data.pop().unwrap(),
            &checked_shards[..config.minimum_shards as usize],
        )
        .unwrap();
        assert_eq!(decoded, data, "test_basic_failed");
    }

    fn test_moderate<S: Scheme>() {
        let data = b"Testing with more pieces than minimum";
        let config = Config {
            minimum_shards: 4,
            extra_shards: 6,
        };

        // Encode the data
        let (commitment, shards) = S::encode(&config, data.as_slice()).unwrap();

        let (mut checking_data, mut checked_shards): (Vec<_>, Vec<_>) = shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                let (checking_data, checked_shard, _) =
                    S::reshard(&config, &commitment, i as u16, shard).unwrap();
                (checking_data, checked_shard)
            })
            .collect();

        // Try to decode with a mix of original and recovery pieces
        {
            let (part1, part2) = checked_shards.split_at_mut(config.minimum_shards as usize);
            std::mem::swap(&mut part1[0], &mut part2[0]);
        }
        let decoded = S::decode(
            &config,
            &commitment,
            checking_data.pop().unwrap(),
            &checked_shards[..config.minimum_shards as usize],
        )
        .unwrap();
        assert_eq!(decoded, data, "test_moderate_failed");
    }

    fn test_odd_shard_len<S: Scheme>() {
        let data = b"a";
        let config = Config {
            minimum_shards: 2,
            extra_shards: 1,
        };

        // Encode the data
        let (commitment, shards) = S::encode(&config, data.as_slice()).unwrap();

        let (mut checking_data, checked_shards): (Vec<_>, Vec<_>) = shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                let (checking_data, checked_shard, _) =
                    S::reshard(&config, &commitment, i as u16, shard).unwrap();
                (checking_data, checked_shard)
            })
            .collect();

        let decoded = S::decode(
            &config,
            &commitment,
            checking_data.pop().unwrap(),
            &checked_shards[..config.minimum_shards as usize],
        )
        .unwrap();
        assert_eq!(decoded, data, "test_odd_shard_len_failed");
    }

    fn test_recovery<S: Scheme>() {
        let data = b"Testing recovery pieces";
        let config = Config {
            minimum_shards: 3,
            extra_shards: 5,
        };

        // Encode the data
        let (commitment, shards) = S::encode(&config, data.as_slice()).unwrap();

        let (mut checking_data, checked_shards): (Vec<_>, Vec<_>) = shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                let (checking_data, checked_shard, _) =
                    S::reshard(&config, &commitment, i as u16, shard).unwrap();
                (checking_data, checked_shard)
            })
            .collect();

        let decoded = S::decode(
            &config,
            &commitment,
            checking_data.pop().unwrap(),
            &checked_shards[checked_shards.len() - config.minimum_shards as usize..],
        )
        .unwrap();
        assert_eq!(decoded, data, "test_recovery_failed");
    }

    fn test_empty_data<S: Scheme>() {
        let data = b"";
        let config = Config {
            minimum_shards: 30,
            extra_shards: 100,
        };

        // Encode the data
        let (commitment, shards) = S::encode(&config, data.as_slice()).unwrap();

        let (mut checking_data, checked_shards): (Vec<_>, Vec<_>) = shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                let (checking_data, checked_shard, _) =
                    S::reshard(&config, &commitment, i as u16, shard).unwrap();
                (checking_data, checked_shard)
            })
            .collect();

        let decoded = S::decode(
            &config,
            &commitment,
            checking_data.pop().unwrap(),
            &checked_shards[..config.minimum_shards as usize],
        )
        .unwrap();
        assert_eq!(decoded, data, "test_empty_data_failed");
    }

    fn test_large_data<S: Scheme>() {
        let data = vec![42u8; 1000]; // 1KB of data
        let config = Config {
            minimum_shards: 4,
            extra_shards: 3,
        };

        // Encode the data
        let (commitment, shards) = S::encode(&config, data.as_slice()).unwrap();

        let (mut checking_data, checked_shards): (Vec<_>, Vec<_>) = shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                let (checking_data, checked_shard, _) =
                    S::reshard(&config, &commitment, i as u16, shard).unwrap();
                (checking_data, checked_shard)
            })
            .collect();

        let decoded = S::decode(
            &config,
            &commitment,
            checking_data.pop().unwrap(),
            &checked_shards[..config.minimum_shards as usize],
        )
        .unwrap();
        assert_eq!(decoded, data, "test_large_data_failed");
    }

    fn test_suite<S: Scheme>() {
        test_basic::<S>();
        test_moderate::<S>();
        test_odd_shard_len::<S>();
        test_recovery::<S>();
        test_empty_data::<S>();
        test_large_data::<S>();
    }

    #[test]
    fn test_suite_reed_solomon() {
        test_suite::<ReedSolomon<Sha256>>();
    }

    #[test]
    fn test_suite_no_coding() {
        test_suite::<NoCoding<Sha256>>();
    }
}
