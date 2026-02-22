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

    mod raptor;
    pub use raptor::{Error as RaptorError, Raptor};

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
    /// // Each person produces weak shards, their own checked shard, and checking data
    /// // to check other peoples weak shards.
    /// let (mut checking_data_w_shard, weak_shards): (Vec<_>, Vec<_>) = shards
    ///         .into_iter()
    ///         .enumerate()
    ///         .map(|(i, shard)| {
    ///             let (checking_data, checked_shard, weak_shard) = RS::weaken(&config, &commitment, i as u16, shard).unwrap();
    ///             ((checking_data, checked_shard), weak_shard)
    ///         })
    ///         .collect();
    /// // Let's pretend that the last item is "ours"
    /// let (checking_data, checked_shard) = checking_data_w_shard.pop().unwrap();
    /// // We can use this checking_data to check the other shards.
    /// let mut checked_shards = Vec::new();
    /// checked_shards.push(checked_shard);
    /// for (i, weak_shard) in weak_shards.into_iter().enumerate().skip(1) {
    ///   checked_shards.push(RS::check(&config, &commitment, &checking_data, i as u16, weak_shard).unwrap())
    /// }
    ///
    /// let data2 = RS::decode(&config, &commitment, checking_data, &checked_shards[..2], &STRATEGY).unwrap();
    /// assert_eq!(&data[..], &data2[..]);
    ///
    /// // Decoding works with different shards, with a guarantee to get the same result.
    /// let data3 = RS::decode(&config, &commitment, checking_data, &checked_shards[1..], &STRATEGY).unwrap();
    /// assert_eq!(&data[..], &data3[..]);
    /// ```
    ///
    /// # Guarantees
    ///
    /// Here are additional properties that implementors of this trait need to
    /// consider, and that users of this trait can rely on.
    ///
    /// ## Weaken vs Check
    ///
    /// [`Scheme::weaken`] and [`Scheme::check`] should agree, even for malicious encoders.
    ///
    /// It should not be possible for parties A and B to call `weaken` successfully,
    /// but then have either of them fail on the other's shard when calling `check`.
    ///
    /// In other words, if an honest party considers their shard to be correctly
    /// formed, then other honest parties which have successfully constructed their
    /// checking data will also agree with the shard being correct.
    ///
    /// A violation of this property would be, for example, if a malicious payload
    /// could convince two parties that they both have valid shards, but then the
    /// checking data they produce from the malicious payload reports issues with
    /// those shards.
    pub trait Scheme: Debug + Clone + Send + Sync + 'static {
        /// A commitment attesting to the shards of data.
        type Commitment: Digest;
        /// A strong shard of data, to be received by a participant.
        type StrongShard: Clone + Debug + Eq + Codec<Cfg = CodecConfig> + Send + Sync + 'static;
        /// A weak shard shared with other participants, to aid them in reconstruction.
        ///
        /// In most cases, this will be the same as `StrongShard`, but some schemes might
        /// have extra information in `StrongShard` that may not be necessary to reconstruct
        /// the data.
        type WeakShard: Clone + Debug + Eq + Codec<Cfg = CodecConfig> + Send + Sync + 'static;
        /// Data which can assist in checking shards.
        type CheckingData: Clone + Send + Sync;
        /// A shard that has been checked for inclusion in the commitment.
        ///
        /// This allows excluding [Scheme::WeakShard]s which are invalid, and shouldn't
        /// be considered as progress towards meeting the minimum number of shards.
        type CheckedShard: Clone + Send + Sync;
        /// The type of errors that can occur during encoding, weakening, checking, and decoding.
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
        ) -> Result<(Self::Commitment, Vec<Self::StrongShard>), Self::Error>;

        /// Take your own shard, check it, and produce a [Scheme::WeakShard] to forward to others.
        ///
        /// This takes in an index, which is the index you expect the shard to be.
        ///
        /// This will produce a [Scheme::CheckedShard] which counts towards the minimum
        /// number of shards you need to reconstruct the data, in [Scheme::decode].
        ///
        /// You also get [Scheme::CheckingData], which has information you can use to check
        /// the shards you receive from others.
        #[allow(clippy::type_complexity)]
        fn weaken(
            config: &Config,
            commitment: &Self::Commitment,
            index: u16,
            shard: Self::StrongShard,
        ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::WeakShard), Self::Error>;

        /// Check the integrity of a weak shard, producing a checked shard.
        ///
        /// This requires the [Scheme::CheckingData] produced by [Scheme::weaken].
        ///
        /// This takes in an index, to make sure that the weak shard you're checking
        /// is associated with the participant you expect it to be.
        fn check(
            config: &Config,
            commitment: &Self::Commitment,
            checking_data: &Self::CheckingData,
            index: u16,
            weak_shard: Self::WeakShard,
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
        for (i, shard) in shards.iter().enumerate() {
            // Strong shard codec roundtrip.
            let decoded_shard = S::StrongShard::read_cfg(&mut shard.encode(), &read_cfg).unwrap();
            assert_eq!(decoded_shard, *shard);

            // Weak shard codec roundtrip.
            let (_, _, weak_shard) =
                S::weaken(config, &commitment, i as u16, shard.clone()).unwrap();
            let decoded_weak_shard =
                S::WeakShard::read_cfg(&mut weak_shard.encode(), &read_cfg).unwrap();
            assert_eq!(decoded_weak_shard, weak_shard);
        }

        // Collect selected shards for decoding. The first selected shard
        // goes through `weaken`, the rest go through `check`.
        let mut checked_shards = Vec::new();
        let mut checking_data = None;
        for (i, shard) in shards.into_iter().enumerate() {
            if !selected.contains(&(i as u16)) {
                continue;
            }
            let (cd, checked, weak_shard) =
                S::weaken(config, &commitment, i as u16, shard).unwrap();
            if let Some(cd) = &checking_data {
                let checked = S::check(config, &commitment, cd, i as u16, weak_shard).unwrap();
                checked_shards.push(checked);
            } else {
                checking_data = Some(cd);
                checked_shards.push(checked);
            }
        }

        // Shuffle the checked shards to verify decode is order-independent.
        checked_shards.reverse();

        // Decode from the selected shards and verify data integrity.
        let decoded = S::decode(
            config,
            &commitment,
            checking_data.unwrap(),
            &checked_shards,
            &Sequential,
        )
        .unwrap();
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
        roundtrip::<Raptor<Sha256>>(&config, b"", &selected);
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
        roundtrip::<Raptor<Sha256>>(&config, &data, &selected);
    }

    #[test]
    fn minifuzz_roundtrip_reed_solomon() {
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(64)
            .test(|u| {
                let (config, data, selected) = generate_case(u)?;
                roundtrip::<ReedSolomon<Sha256>>(&config, &data, &selected);
                Ok(())
            });
    }

    #[test]
    fn minifuzz_roundtrip_no_coding() {
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(64)
            .test(|u| {
                let (config, data, selected) = generate_case(u)?;
                roundtrip::<NoCoding<Sha256>>(&config, &data, &selected);
                Ok(())
            });
    }

    #[test]
    fn minifuzz_roundtrip_zoda() {
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(64)
            .test(|u| {
                let (config, data, selected) = generate_case(u)?;
                roundtrip::<Zoda<Sha256>>(&config, &data, &selected);
                Ok(())
            });
    }

    /// Generate a test case with Raptor constraints: k in [4, 32].
    ///
    /// Raptor codes are probabilistic fountain codes, not MDS codes. Unlike
    /// Reed-Solomon, decoding with exactly k symbols may fail with non-trivial
    /// probability (especially for small k). We therefore always select at
    /// least k + 2 shards to account for the Raptor overhead.
    fn generate_case_raptor(
        u: &mut Unstructured<'_>,
    ) -> arbitrary::Result<(Config, Vec<u8>, Vec<u16>)> {
        const MIN_RAPTOR_SHARDS: u16 = 8;
        // Raptor codes need a small overhead beyond k for reliable decoding.
        // The overhead is more significant for small k values.
        const RAPTOR_OVERHEAD: u16 = 4;
        const MIN_RAPTOR_EXTRA: u16 = RAPTOR_OVERHEAD + MIN_EXTRA_SHARDS;
        let minimum_shards =
            MIN_RAPTOR_SHARDS + (u.arbitrary::<u16>()? % (MAX_SHARDS - MIN_RAPTOR_SHARDS + 1));
        let extra_shards =
            MIN_RAPTOR_EXTRA + (u.arbitrary::<u16>()? % (MAX_SHARDS - MIN_RAPTOR_EXTRA + 1));
        let total_shards = minimum_shards + extra_shards;

        let data_len = usize::from(u.arbitrary::<u16>()?) % (MAX_DATA + 1);
        let data = u.bytes(data_len)?.to_vec();

        // Always select at least minimum_shards + RAPTOR_OVERHEAD
        let min_selected = usize::from(minimum_shards + RAPTOR_OVERHEAD);
        let max_extra = usize::from(total_shards) - min_selected;
        let selected_len = min_selected + (usize::from(u.arbitrary::<u16>()?) % (max_extra + 1));
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
    fn minifuzz_roundtrip_raptor() {
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(64)
            .test(|u| {
                let (config, data, selected) = generate_case_raptor(u)?;
                roundtrip::<Raptor<Sha256>>(&config, &data, &selected);
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
