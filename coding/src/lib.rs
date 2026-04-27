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
    use thiserror::Error;

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
    ///         .iter()
    ///         .enumerate()
    ///         .map(|(i, shard)| {
    ///             RS::check(&config, &commitment, i as u16, shard).unwrap()
    ///         })
    ///         .collect();
    ///
    /// // Decode from any minimum_shards-sized subset.
    /// let data2 = RS::decode(&config, &commitment, checked_shards[..2].iter(), &STRATEGY).unwrap();
    /// assert_eq!(&data[..], &data2[..]);
    ///
    /// // Decoding works with different shards, with a guarantee to get the same result.
    /// let data3 = RS::decode(&config, &commitment, checked_shards[1..].iter(), &STRATEGY).unwrap();
    /// assert_eq!(&data[..], &data3[..]);
    /// ```
    ///
    /// # Guarantees
    ///
    /// Here are additional properties that implementors of this trait need to
    /// consider, and that users of this trait can rely on.
    ///
    /// ## Check Agreement
    ///
    /// [`Scheme::check`] should agree across honest parties, even for malicious
    /// encoders.
    ///
    /// It should not be possible for parties A and B to both call `check`
    /// successfully on their own shards, but then have either of them fail
    /// when calling `check` on the other's shard.
    ///
    /// In other words, if an honest party considers their shard to be correctly
    /// formed, then other honest parties which have also successfully checked
    /// their own shards will agree with that shard being correct.
    ///
    /// A violation of this property would be, for example, if a malicious
    /// payload could convince two parties that they both have valid shards, but
    /// then checking each other's shards reports issues with those shards.
    ///
    /// ## Unique Commitments
    ///
    /// [`Scheme::encode`] MUST be deterministic.
    ///
    /// For a given [`Config`] and `data`, the only [`Scheme::Commitment`] which
    /// should pass [`Scheme::decode`] MUST be that produced by [`Scheme::encode`].
    ///
    /// In other words, a data has a unique valid commitment associated with it.
    pub trait Scheme: Debug + Clone + Send + Sync + 'static {
        /// A commitment attesting to the shards of data.
        type Commitment: Digest;
        /// A shard of data, to be received by a participant.
        type Shard: Clone + Debug + Eq + Codec<Cfg = CodecConfig> + Send + Sync + 'static;
        /// A shard that has been checked for inclusion in the commitment.
        ///
        /// This allows excluding invalid shards from the function signature of [`Self::decode`].
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
            shard: &Self::Shard,
        ) -> Result<Self::CheckedShard, Self::Error>;

        /// Decode the data from shards received from other participants.
        ///
        /// The data must be decodeable with as few as `config.minimum_shards`,
        /// including your own shard.
        ///
        /// Calls to this function with the same commitment, but with different shards,
        /// or shards in a different order should also result in the same output data,
        /// or in failure. In other words, when using the decoding function in a broader
        /// system, you get a guarantee that every participant decoding will see the same
        /// final data, even if they receive different shards, or receive them in a
        /// different order.
        ///
        /// ## Commitment Binding
        ///
        /// Implementations must reject shards that were checked against a different
        /// commitment than the one passed to `decode`. Mixing checked shards from
        /// separate `encode` calls (and thus different commitments) must return an
        /// error.
        fn decode<'a>(
            config: &Config,
            commitment: &Self::Commitment,
            shards: impl Iterator<Item = &'a Self::CheckedShard>,
            strategy: &impl Strategy,
        ) -> Result<Vec<u8>, Self::Error>;
    }

    /// A phased coding interface with separate local and forwarded shard handling.
    ///
    /// This trait models schemes where the initial distributor attaches extra
    /// verification material to each participant's strong shard. Participants
    /// derive checking data from that strong shard, then use it to validate
    /// weaker forwarded shards received from others before reconstruction.
    ///
    /// The tradeoff compared to [`Scheme`] is that weak shards cannot be
    /// verified independently. A participant must first derive
    /// [`PhasedScheme::CheckingData`] from a strong shard via
    /// [`PhasedScheme::weaken`].
    ///
    /// # Example
    /// ```
    /// use commonware_coding::{Config, PhasedScheme as _, Zoda};
    /// use commonware_cryptography::Sha256;
    /// use commonware_parallel::Sequential;
    /// use commonware_utils::NZU16;
    ///
    /// const STRATEGY: Sequential = Sequential;
    ///
    /// type Z = Zoda<Sha256>;
    ///
    /// let namespace = b"my-application";
    /// let config = Config {
    ///     minimum_shards: NZU16!(2),
    ///     extra_shards: NZU16!(1),
    /// };
    /// let data = b"Hello!";
    /// let (commitment, mut shards) = Z::encode(namespace, &config, data.as_slice(), &STRATEGY).unwrap();
    ///
    /// let (checking_data, checked_0, _) =
    ///     Z::weaken(namespace, &config, &commitment, 0, shards.remove(0)).unwrap();
    /// let (_, _, weak_1) = Z::weaken(namespace, &config, &commitment, 1, shards.remove(0)).unwrap();
    /// let checked_1 = Z::check(&config, &commitment, &checking_data, 1, weak_1).unwrap();
    ///
    /// let data2 = Z::decode(
    ///     &config,
    ///     &commitment,
    ///     checking_data,
    ///     [checked_0, checked_1].iter(),
    ///     &STRATEGY,
    /// )
    /// .unwrap();
    /// assert_eq!(&data[..], &data2[..]);
    /// ```
    ///
    /// # Guarantees
    ///
    /// Here are additional properties that implementors of this trait need to
    /// consider, and that users of this trait can rely on.
    ///
    /// ## Weaken vs Check
    ///
    /// [`PhasedScheme::weaken`] and [`PhasedScheme::check`] should agree, even for malicious encoders.
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
    pub trait PhasedScheme: Debug + Clone + Send + Sync + 'static {
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
        type CheckingData: Clone + Eq + Send + Sync;
        /// A shard that has been checked for inclusion in the commitment.
        ///
        /// This allows excluding [`PhasedScheme::WeakShard`]s which are invalid, and shouldn't
        /// be considered as progress towards meeting the minimum number of shards.
        type CheckedShard: Clone + Send + Sync;
        /// The type of errors that can occur during encoding, weakening, checking, and decoding.
        type Error: std::fmt::Debug + Send;

        /// Encode a piece of data, returning a commitment, along with shards, and proofs.
        ///
        /// Each shard and proof is intended for exactly one participant. The number of shards returned
        /// should equal `config.minimum_shards + config.extra_shards`.
        ///
        /// `namespace` is a caller-provided byte string used for domain separation. All parties
        /// participating in the same session must use the same `namespace` when calling `encode`
        /// and `weaken`. Using `b""` produces the default behavior with no caller-specific context.
        #[allow(clippy::type_complexity)]
        fn encode(
            namespace: &[u8],
            config: &Config,
            data: impl Buf,
            strategy: &impl Strategy,
        ) -> Result<(Self::Commitment, Vec<Self::StrongShard>), Self::Error>;

        /// Take your own shard, check it, and produce a [`PhasedScheme::WeakShard`] to forward to others.
        ///
        /// This takes in an index, which is the index you expect the shard to be.
        ///
        /// This will produce a [`PhasedScheme::CheckedShard`] which counts towards the minimum
        /// number of shards you need to reconstruct the data, in [`PhasedScheme::decode`].
        ///
        /// You also get [`PhasedScheme::CheckingData`], which has information you can use to check
        /// the shards you receive from others.
        ///
        /// `namespace` must match the one used in the corresponding `encode` call.
        #[allow(clippy::type_complexity)]
        fn weaken(
            namespace: &[u8],
            config: &Config,
            commitment: &Self::Commitment,
            index: u16,
            shard: Self::StrongShard,
        ) -> Result<(Self::CheckingData, Self::CheckedShard, Self::WeakShard), Self::Error>;

        /// Check the integrity of a weak shard, producing a checked shard.
        ///
        /// This requires the [`PhasedScheme::CheckingData`] produced by [`PhasedScheme::weaken`].
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
        ///
        /// ## Commitment Binding
        ///
        /// Implementations must reject shards that were checked against a different
        /// commitment than the one passed to `decode`. Mixing checked shards from
        /// separate `encode` calls (and thus different commitments) must return an
        /// error.
        fn decode<'a>(
            config: &Config,
            commitment: &Self::Commitment,
            checking_data: Self::CheckingData,
            shards: impl Iterator<Item = &'a Self::CheckedShard>,
            strategy: &impl Strategy,
        ) -> Result<Vec<u8>, Self::Error>;
    }

    /// An adapter that exposes a [`PhasedScheme`] through the [`Scheme`] trait.
    ///
    /// In most cases, this is not the most optimal way to use a [`PhasedScheme`],
    /// or to expose a [`PhasedScheme`] as a [`Scheme`] for that matter. However,
    /// it can be useful for testing or for usecases where the phased scheme
    /// cannot be used directly.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct PhasedAsScheme<P>(core::marker::PhantomData<P>);

    /// A checked shard produced by adapting a phased scheme into [`Scheme`].
    #[derive(Clone)]
    pub struct PhasedCheckedShard<P: PhasedScheme> {
        checking_data: P::CheckingData,
        checked_shard: P::CheckedShard,
    }

    /// Errors returned by the [`PhasedAsScheme`] adapter.
    #[derive(Debug, Error)]
    pub enum PhasedAsSchemeError<E> {
        #[error(transparent)]
        Scheme(E),
        #[error("checked shards do not agree on checking data")]
        InconsistentCheckingData,
        #[error("insufficient shards {0} < {1}")]
        InsufficientShards(usize, usize),
    }

    impl<P: PhasedScheme> Debug for PhasedCheckedShard<P> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("PhasedCheckedShard").finish_non_exhaustive()
        }
    }

    impl<P: PhasedScheme> Scheme for PhasedAsScheme<P> {
        type Commitment = P::Commitment;
        type Shard = P::StrongShard;
        type CheckedShard = PhasedCheckedShard<P>;
        type Error = PhasedAsSchemeError<P::Error>;

        fn encode(
            config: &Config,
            data: impl Buf,
            strategy: &impl Strategy,
        ) -> Result<(Self::Commitment, Vec<Self::Shard>), Self::Error> {
            P::encode(b"", config, data, strategy).map_err(PhasedAsSchemeError::Scheme)
        }

        fn check(
            config: &Config,
            commitment: &Self::Commitment,
            index: u16,
            shard: &Self::Shard,
        ) -> Result<Self::CheckedShard, Self::Error> {
            let (checking_data, checked_shard, _) =
                P::weaken(b"", config, commitment, index, shard.clone())
                    .map_err(PhasedAsSchemeError::Scheme)?;
            Ok(PhasedCheckedShard {
                checking_data,
                checked_shard,
            })
        }

        fn decode<'a>(
            config: &Config,
            commitment: &Self::Commitment,
            shards: impl Iterator<Item = &'a Self::CheckedShard>,
            strategy: &impl Strategy,
        ) -> Result<Vec<u8>, Self::Error> {
            let mut shards = shards.peekable();
            let Some(first) = shards.peek() else {
                return Err(PhasedAsSchemeError::InsufficientShards(
                    0,
                    usize::from(config.minimum_shards.get()),
                ));
            };
            let checking_data = first.checking_data.clone();
            P::decode(
                config,
                commitment,
                checking_data.clone(),
                shards
                    .map(|shard| {
                        if shard.checking_data != checking_data {
                            return Err(PhasedAsSchemeError::InconsistentCheckingData);
                        }
                        Ok(&shard.checked_shard)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter(),
                strategy,
            )
            .map_err(PhasedAsSchemeError::Scheme)
        }
    }

    /// A marker trait indicating that [`Scheme::check`] or [`PhasedScheme::check`] proves validity of the encoding.
    ///
    /// In more detail, this means that upon a successful call to [`Scheme::check`],
    /// guarantees that the shard results from a valid encoding of the data, and thus,
    /// if other participants also call check, then the data is guaranteed to be reconstructable.
    pub trait ValidatingScheme {}
});

#[cfg(test)]
mod test {
    use super::*;
    use arbitrary::Unstructured;
    use commonware_cryptography::Sha256;
    use commonware_invariants::minifuzz;
    use commonware_macros::test_group;
    use commonware_utils::NZU16;

    const MAX_SHARD_SIZE: usize = 1 << 31;
    const MAX_SHARDS: u16 = 32;
    const MAX_DATA: usize = 1024;
    const MIN_EXTRA_SHARDS: u16 = 1;

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

    mod scheme {
        use super::*;
        use crate::{reed_solomon::ReedSolomon, PhasedAsScheme, Scheme, Zoda};
        use commonware_codec::Encode;
        use commonware_parallel::Sequential;

        fn roundtrip<S: Scheme>(config: &Config, data: &[u8], selected: &[u16]) {
            let (commitment, shards) = S::encode(config, data, &Sequential).unwrap();
            let read_cfg = CodecConfig {
                maximum_shard_size: MAX_SHARD_SIZE,
            };
            for shard in &shards {
                let decoded_shard = S::Shard::read_cfg(&mut shard.encode(), &read_cfg).unwrap();
                assert_eq!(decoded_shard, *shard);
            }

            let mut checked_shards = Vec::new();
            for (i, shard) in shards.into_iter().enumerate() {
                if !selected.contains(&(i as u16)) {
                    continue;
                }
                let checked = S::check(config, &commitment, i as u16, &shard).unwrap();
                checked_shards.push(checked);
            }

            checked_shards.reverse();
            let decoded =
                S::decode(config, &commitment, checked_shards.iter(), &Sequential).unwrap();
            assert_eq!(decoded, data);
        }

        fn decode_rejects_mixed_commitments<S: Scheme>(
            config: &Config,
            data_a: &[u8],
            data_b: &[u8],
        ) {
            let (commitment_a, shards_a) = S::encode(config, data_a, &Sequential).unwrap();
            let (commitment_b, shards_b) = S::encode(config, data_b, &Sequential).unwrap();

            let checked_a = S::check(config, &commitment_a, 0, &shards_a[0]).unwrap();
            let checked_b = S::check(config, &commitment_b, 1, &shards_b[1]).unwrap();

            let result = S::decode(
                config,
                &commitment_a,
                [checked_a, checked_b].iter(),
                &Sequential,
            );
            assert!(
                result.is_err(),
                "decode must reject shards checked against different commitments"
            );
        }

        fn decode_rejects_empty_checked_shards<S: Scheme>(config: &Config, data: &[u8]) {
            let (commitment, _) = S::encode(config, data, &Sequential).unwrap();
            let result = S::decode(config, &commitment, core::iter::empty(), &Sequential);
            assert!(
                result.is_err(),
                "decode must reject empty checked shard sets"
            );
        }

        #[test]
        fn decode_rejects_mixed_commitment_shards() {
            let config = Config {
                minimum_shards: NZU16!(2),
                extra_shards: NZU16!(1),
            };

            decode_rejects_mixed_commitments::<ReedSolomon<Sha256>>(
                &config,
                b"alpha payload",
                b"bravo payload",
            );
            decode_rejects_mixed_commitments::<PhasedAsScheme<Zoda<Sha256>>>(
                &config,
                b"alpha payload",
                b"bravo payload",
            );
            decode_rejects_empty_checked_shards::<ReedSolomon<Sha256>>(&config, b"alpha payload");
            decode_rejects_empty_checked_shards::<PhasedAsScheme<Zoda<Sha256>>>(
                &config,
                b"alpha payload",
            );
        }

        #[test]
        fn roundtrip_empty_data() {
            let config = Config {
                minimum_shards: NZU16!(30),
                extra_shards: NZU16!(70),
            };
            let selected: Vec<u16> = (0..30).collect();

            roundtrip::<ReedSolomon<Sha256>>(&config, b"", &selected);
            roundtrip::<PhasedAsScheme<Zoda<Sha256>>>(&config, b"", &selected);
        }

        #[test]
        fn roundtrip_2_pow_16_25_total_shards() {
            let config = Config {
                minimum_shards: NZU16!(8),
                extra_shards: NZU16!(17),
            };
            let data = vec![0x67; 1 << 16];
            let selected: Vec<u16> = (0..8).collect();

            roundtrip::<ReedSolomon<Sha256>>(&config, &data, &selected);
            roundtrip::<PhasedAsScheme<Zoda<Sha256>>>(&config, &data, &selected);
        }

        #[test]
        fn minifuzz_roundtrip_reed_solomon() {
            minifuzz::test(|u| {
                let (config, data, selected) = generate_case(u)?;
                roundtrip::<ReedSolomon<Sha256>>(&config, &data, &selected);
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
                    roundtrip::<PhasedAsScheme<Zoda<Sha256>>>(&config, &data, &selected);
                    Ok(())
                });
        }
    }

    mod phased_scheme {
        use super::*;
        use crate::{PhasedScheme, Zoda};
        use commonware_codec::Encode;
        use commonware_parallel::Sequential;

        fn roundtrip<S: PhasedScheme>(config: &Config, data: &[u8], selected: &[u16]) {
            let owner = *selected.first().expect("selected must not be empty");
            let (commitment, shards) = S::encode(b"", config, data, &Sequential).unwrap();
            let read_cfg = CodecConfig {
                maximum_shard_size: MAX_SHARD_SIZE,
            };
            for shard in &shards {
                let decoded_shard =
                    S::StrongShard::read_cfg(&mut shard.encode(), &read_cfg).unwrap();
                assert_eq!(decoded_shard, *shard);
            }

            let (checking_data, own_checked, _) = S::weaken(
                b"",
                config,
                &commitment,
                owner,
                shards[owner as usize].clone(),
            )
            .unwrap();
            let mut checked_shards = vec![own_checked];
            for &index in selected {
                if index == owner {
                    continue;
                }
                let (_, _, weak_shard) = S::weaken(
                    b"",
                    config,
                    &commitment,
                    index,
                    shards[index as usize].clone(),
                )
                .unwrap();
                let decoded_weak =
                    S::WeakShard::read_cfg(&mut weak_shard.encode(), &read_cfg).unwrap();
                assert_eq!(decoded_weak, weak_shard);
                let checked =
                    S::check(config, &commitment, &checking_data, index, decoded_weak).unwrap();
                checked_shards.push(checked);
            }

            checked_shards.reverse();
            let decoded = S::decode(
                config,
                &commitment,
                checking_data,
                checked_shards.iter(),
                &Sequential,
            )
            .unwrap();
            assert_eq!(decoded, data);
        }

        fn check_rejects_mixed_commitments<S: PhasedScheme>(
            config: &Config,
            data_a: &[u8],
            data_b: &[u8],
        ) {
            let (commitment_a, shards_a) = S::encode(b"", config, data_a, &Sequential).unwrap();
            let (commitment_b, shards_b) = S::encode(b"", config, data_b, &Sequential).unwrap();

            let (checking_data_a, checked_a, _) =
                S::weaken(b"", config, &commitment_a, 0, shards_a[0].clone()).unwrap();
            let (checking_data_b, checked_b, weak_b) =
                S::weaken(b"", config, &commitment_b, 1, shards_b[1].clone()).unwrap();

            let check_result = S::check(config, &commitment_a, &checking_data_a, 1, weak_b);
            assert!(
                check_result.is_err(),
                "check must reject weak shards derived from a different commitment"
            );

            let decode_result = S::decode(
                config,
                &commitment_a,
                checking_data_a,
                [checked_a, checked_b].iter(),
                &Sequential,
            );
            assert!(
                decode_result.is_err(),
                "decode must reject checked shards derived from a different commitment"
            );

            let decode_result = S::decode(
                config,
                &commitment_b,
                checking_data_b,
                core::iter::empty::<&S::CheckedShard>(),
                &Sequential,
            );
            assert!(
                decode_result.is_err(),
                "decode must reject insufficient checked shards"
            );
        }

        #[test]
        fn check_rejects_mixed_commitment_weak_shards() {
            let config = Config {
                minimum_shards: NZU16!(2),
                extra_shards: NZU16!(1),
            };

            check_rejects_mixed_commitments::<Zoda<Sha256>>(
                &config,
                b"alpha payload",
                b"bravo payload",
            );
        }

        #[test]
        fn roundtrip_empty_data() {
            let config = Config {
                minimum_shards: NZU16!(30),
                extra_shards: NZU16!(70),
            };
            let selected: Vec<u16> = (0..30).collect();

            roundtrip::<Zoda<Sha256>>(&config, b"", &selected);
        }

        #[test]
        fn roundtrip_2_pow_16_25_total_shards() {
            let config = Config {
                minimum_shards: NZU16!(8),
                extra_shards: NZU16!(17),
            };
            let data = vec![0x67; 1 << 16];
            let selected: Vec<u16> = (0..8).collect();

            roundtrip::<Zoda<Sha256>>(&config, &data, &selected);
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
