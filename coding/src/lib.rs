//! Encode data to enable recovery from a subset of fragments.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(ALPHA {
    use bytes::Buf;
    use commonware_codec::{Codec, FixedSize, Read, Write};
    use commonware_cryptography::Digest;
    use commonware_parallel::Strategy;
    use std::{fmt::Debug, num::NonZeroU16};

    mod no_coding;
    pub use no_coding::{Error as NoCodingError, NoCoding};

    mod reed_solomon;
    pub use reed_solomon::{Error as ReedSolomonError, ReedSolomon};

    mod zoda;
    pub use zoda::{Error as ZodaError, Zoda};

    /// Configuration common to all encoding schemes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Config {
        /// The minimum number of shards needed to encode the data.
        pub minimum_shards: NonZeroU16,
        /// Extra shards beyond the minimum number.
        ///
        /// Alternatively, one can think of the configuration as having a total number
        /// `N = extra_shards + minimum_shards`, but by specifying the `extra_shards`
        /// rather than `N`, we avoid needing to check that `minimum_shards <= N`.
        pub extra_shards: NonZeroU16,
    }

    impl Config {
        /// Returns the total number of shards produced by this configuration.
        pub fn total_shards(&self) -> u32 {
            u32::from(self.minimum_shards.get()) + u32::from(self.extra_shards.get())
        }
    }

    impl FixedSize for Config {
        const SIZE: usize = 2 * <NonZeroU16 as FixedSize>::SIZE;
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
                minimum_shards: NonZeroU16::read_cfg(buf, cfg)?,
                extra_shards: NonZeroU16::read_cfg(buf, cfg)?,
            })
        }
    }

    #[cfg(feature = "arbitrary")]
    impl<'a> arbitrary::Arbitrary<'a> for Config {
        fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
            let minimum_shards = commonware_utils::NZU16!(u.int_in_range(1..=u16::MAX)?);
            let extra_shards = commonware_utils::NZU16!(u.int_in_range(1..=u16::MAX)?);
            Ok(Self {
                minimum_shards,
                extra_shards,
            })
        }
    }

    /// The configuration for decoding shard data.
    #[derive(Clone, Debug)]
    pub struct CodecConfig {
        /// The maximum number of bytes a shard is expected to contain.
        ///
        /// This can be an upper bound, and only constrains the non-fixed-size portion
        /// of shard data.
        pub maximum_shard_size: usize,
    }

    /// A scheme for encoding data into pieces, and recovering the data from those pieces.
    ///
    /// # Example
    /// ```
    /// use commonware_coding::{Config, ReedSolomon, Scheme as _};
    /// use commonware_cryptography::Sha256;
    /// use commonware_parallel::Sequential;
    /// use commonware_utils::NZU16;
    ///
    /// const STRATEGY: Sequential = Sequential;
    ///
    /// type RS = ReedSolomon<Sha256>;
    ///
    /// let config = Config {
    ///     minimum_shards: NZU16!(2),
    ///     extra_shards: NZU16!(1),
    /// };
    /// let data = b"Hello!";
    /// // Turn the data into shards, and a commitment to those shards.
    /// let (commitment, shards) =
    ///      RS::encode(&config, data.as_slice(), &STRATEGY).unwrap();
    ///
    /// // Each participant checks their shard against the commitment.
    /// let checked_shards: Vec<_> = shards
    ///         .into_iter()
    ///         .enumerate()
    ///         .map(|(i, shard)| {
    ///             RS::check(&config, &commitment, i as u16, shard).unwrap()
    ///         })
    ///         .collect();
    ///
    /// // Decode from any minimum_shards-sized subset.
    /// let data2 = RS::decode(&config, &commitment, &checked_shards[..2], &STRATEGY).unwrap();
    /// assert_eq!(&data[..], &data2[..]);
    ///
    /// // Decoding works with different shards, with a guarantee to get the same result.
    /// let data3 = RS::decode(&config, &commitment, &checked_shards[1..], &STRATEGY).unwrap();
    /// assert_eq!(&data[..], &data3[..]);
    /// ```
    pub trait Scheme: Debug + Clone + Send + Sync + 'static {
        /// A commitment attesting to the shards of data.
        type Commitment: Digest;
        /// A shard of data, to be received by a participant.
        type Shard: Clone + Debug + Eq + Codec<Cfg = CodecConfig> + Send + Sync + 'static;
        /// A shard that has been checked for inclusion in the commitment.
        ///
        /// This allows excluding invalid shards from the function signature of [Self::decode].
        type CheckedShard: Clone + Send + Sync;
        /// The type of errors that can occur during encoding, checking, and decoding.
        type Error: std::fmt::Debug + Send;

        /// Encode a piece of data, returning a commitment, along with shards, and proofs.
        ///
        /// Each shard and proof is intended for exactly one participant. The number of shards returned
        /// should equal `config.minimum_shards + config.extra_shards`.
        #[allow(clippy::type_complexity)]
        fn encode(
            config: &Config,
            data: impl Buf,
            strategy: &impl Strategy,
        ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error>;

        /// Check the integrity of a shard, producing a checked shard.
        ///
        /// This takes in an index, to make sure that the shard you're checking
        /// is associated with the participant you expect it to be.
        fn check(
            config: &Config,
            commitment: &Self::Commitment,
            index: u16,
            shard: Self::Shard,
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
            shards: &[Self::CheckedShard],
            strategy: &impl Strategy,
        ) -> Result<Vec<u8>, Self::Error>;
    }

    /// A marker trait indicating that [Scheme::check] proves validity of the encoding.
    ///
    /// In more detail, this means that upon a successful call to [Scheme::check],
    /// guarantees that the shard results from a valid encoding of the data, and thus,
    /// if other participants also call check, then the data is guaranteed to be reconstructable.
    pub trait ValidatingScheme: Scheme {}
});

#[cfg(test)]
mod test {
    use super::*;
    use crate::reed_solomon::ReedSolomon;
    use arbitrary::Unstructured;
    use commonware_codec::Encode;
    use commonware_cryptography::Sha256;
    use commonware_invariants::minifuzz;
    use commonware_macros::test_group;
    use commonware_parallel::Sequential;
    use commonware_utils::NZU16;

    const MAX_SHARD_SIZE: usize = 1 << 31;
    const MAX_SHARDS: u16 = 32;
    const MAX_DATA: usize = 1024;
    const MIN_EXTRA_SHARDS: u16 = 1;

    fn roundtrip<S: Scheme>(config: &Config, data: &[u8], selected: &[u16]) {
        // Encode data into shards.
        let (commitment, shards) = S::encode(config, data, &Sequential).unwrap();
        let read_cfg = CodecConfig {
            maximum_shard_size: MAX_SHARD_SIZE,
        };
        for shard in shards.iter() {
            // Shard codec roundtrip.
            let decoded_shard = S::Shard::read_cfg(&mut shard.encode(), &read_cfg).unwrap();
            assert_eq!(decoded_shard, *shard);
        }

        // Collect selected shards for decoding.
        let mut checked_shards = Vec::new();
        for (i, shard) in shards.into_iter().enumerate() {
            if !selected.contains(&(i as u16)) {
                continue;
            }
            let checked = S::check(config, &commitment, i as u16, shard.clone()).unwrap();
            checked_shards.push(checked);
        }

        // Shuffle the checked shards to verify decode is order-independent.
        checked_shards.reverse();

        // Decode from the selected shards and verify data integrity.
        let decoded = S::decode(config, &commitment, &checked_shards, &Sequential).unwrap();
        assert_eq!(decoded, data);
    }

    fn generate_case(u: &mut Unstructured<'_>) -> arbitrary::Result<(Config, Vec<u8>, Vec<u16>)> {
        let minimum_shards = (u.arbitrary::<u16>()? % MAX_SHARDS) + 1;
        let extra_shards =
            MIN_EXTRA_SHARDS + (u.arbitrary::<u16>()? % (MAX_SHARDS - MIN_EXTRA_SHARDS + 1));
        let total_shards = minimum_shards + extra_shards;

        let data_len = usize::from(u.arbitrary::<u16>()?) % (MAX_DATA + 1);
        let data = u.bytes(data_len)?.to_vec();

        let selected_len = usize::from(minimum_shards)
            + (usize::from(u.arbitrary::<u16>()?) % (usize::from(extra_shards) + 1));
        let mut selected: Vec<u16> = (0..total_shards).collect();
        for i in 0..selected_len {
            let remaining = usize::from(total_shards) - i;
            let j = i + (usize::from(u.arbitrary::<u16>()?) % remaining);
            selected.swap(i, j);
        }
        selected.truncate(selected_len);

        Ok((
            Config {
                minimum_shards: NZU16!(minimum_shards),
                extra_shards: NZU16!(extra_shards),
            },
            data,
            selected,
        ))
    }

    #[test]
    fn roundtrip_empty_data() {
        let config = Config {
            minimum_shards: NZU16!(30),
            extra_shards: NZU16!(70),
        };
        let selected: Vec<u16> = (0..30).collect();

        roundtrip::<ReedSolomon<Sha256>>(&config, b"", &selected);
        roundtrip::<NoCoding<Sha256>>(&config, b"", &selected);
        roundtrip::<Zoda<Sha256>>(&config, b"", &selected);
    }

    // This exercises an edge case in ZODA, but is also useful for other schemes.
    #[test]
    fn roundtrip_2_pow_16_25_total_shards() {
        let config = Config {
            minimum_shards: NZU16!(8),
            extra_shards: NZU16!(17),
        };
        let data = vec![0x67; 1 << 16];
        let selected: Vec<u16> = (0..8).collect();

        roundtrip::<ReedSolomon<Sha256>>(&config, &data, &selected);
        roundtrip::<NoCoding<Sha256>>(&config, &data, &selected);
        roundtrip::<Zoda<Sha256>>(&config, &data, &selected);
    }

    #[test]
    fn minifuzz_roundtrip_reed_solomon() {
        minifuzz::test(|u| {
            let (config, data, selected) = generate_case(u)?;
            roundtrip::<ReedSolomon<Sha256>>(&config, &data, &selected);
            Ok(())
        });
    }

    #[test]
    fn minifuzz_roundtrip_no_coding() {
        minifuzz::test(|u| {
            let (config, data, selected) = generate_case(u)?;
            roundtrip::<NoCoding<Sha256>>(&config, &data, &selected);
            Ok(())
        });
    }

    #[test_group("slow")]
    #[test]
    fn minifuzz_roundtrip_zoda() {
        minifuzz::Builder::default()
            .with_search_limit(64)
            .test(|u| {
                let (config, data, selected) = generate_case(u)?;
                roundtrip::<Zoda<Sha256>>(&config, &data, &selected);
                Ok(())
            });
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Config>,
        }
    }
}
