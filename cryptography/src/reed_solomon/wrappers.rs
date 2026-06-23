use crate::reed_solomon::{
    engine::DefaultEngine,
    rate::{DefaultRate, DefaultRateDecoder, DefaultRateEncoder, Rate, RateDecoder, RateEncoder},
    DecoderResult, EncoderResult, Error, RecoveryDecoderResult,
};

// ======================================================================
// Encoder - PUBLIC

/// Reed-Solomon encoder using [`DefaultEngine`] and [`DefaultRate`].
///
/// [`DefaultEngine`]: crate::reed_solomon::engine::DefaultEngine
pub struct Encoder(DefaultRateEncoder<DefaultEngine>);

impl Encoder {
    /// Adds one original shard to the encoder.
    ///
    /// Original shards have indexes `0..original_count` corresponding to the order
    /// in which they are added and these same indexes must be used when decoding.
    ///
    /// See [basic usage](crate::reed_solomon#basic-usage) for an example.
    pub fn add_original_shard<T: AsRef<[u8]>>(&mut self, original_shard: T) -> Result<(), Error> {
        self.0.add_original_shard(original_shard)
    }

    /// Encodes the added original shards returning [`EncoderResult`]
    /// which contains the generated recovery shards.
    ///
    /// When returned [`EncoderResult`] is dropped the encoder is
    /// automatically [`reset`] and ready for new round of encoding.
    ///
    /// See [basic usage](crate::reed_solomon#basic-usage) for an example.
    ///
    /// [`reset`]: Encoder::reset
    pub fn encode(&mut self) -> Result<EncoderResult<'_>, Error> {
        self.0.encode()
    }

    /// Creates new encoder with given configuration
    /// and allocates required working space.
    ///
    /// See [basic usage](crate::reed_solomon#basic-usage) for an example.
    pub fn new(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<Self, Error> {
        Ok(Self(DefaultRateEncoder::new(
            original_count,
            recovery_count,
            shard_bytes,
            DefaultEngine::new(),
            None,
        )?))
    }

    /// Resets encoder to given configuration.
    ///
    /// - Added original shards are forgotten.
    /// - Existing working space is re-used if it's large enough
    ///   or re-allocated otherwise.
    pub fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error> {
        self.0.reset(original_count, recovery_count, shard_bytes)
    }

    /// Returns `true` if given `original_count` / `recovery_count`
    /// combination is supported.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use commonware_cryptography::reed_solomon::Encoder;
    ///
    /// assert_eq!(Encoder::supports(60_000, 4_000), true);
    /// assert_eq!(Encoder::supports(60_000, 5_000), false);
    /// ```
    pub fn supports(original_count: usize, recovery_count: usize) -> bool {
        DefaultRate::<DefaultEngine>::supports(original_count, recovery_count)
    }
}

// ======================================================================
// Decoder - PUBLIC

/// Reed-Solomon decoder using [`DefaultEngine`] and [`DefaultRate`].
///
/// [`DefaultEngine`]: crate::reed_solomon::engine::DefaultEngine
pub struct Decoder(DefaultRateDecoder<DefaultEngine>);

impl Decoder {
    /// Adds one original shard to the decoder.
    ///
    /// - Shards can be added in any order.
    /// - Index must be the same that was used in encoding.
    ///
    /// See [basic usage](crate::reed_solomon#basic-usage) for an example.
    pub fn add_original_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        original_shard: T,
    ) -> Result<(), Error> {
        self.0.add_original_shard(index, original_shard)
    }

    /// Adds one recovery shard to the decoder.
    ///
    /// - Shards can be added in any order.
    /// - Index must be the same that was used in encoding.
    ///
    /// See [basic usage](crate::reed_solomon#basic-usage) for an example.
    pub fn add_recovery_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        recovery_shard: T,
    ) -> Result<(), Error> {
        self.0.add_recovery_shard(index, recovery_shard)
    }

    /// Decodes the added shards returning [`DecoderResult`]
    /// which contains the restored original shards.
    ///
    /// When returned [`DecoderResult`] is dropped the decoder is
    /// automatically [`reset`] and ready for new round of decoding.
    ///
    /// See [basic usage](crate::reed_solomon#basic-usage) for an example.
    ///
    /// [`reset`]: Decoder::reset
    pub fn decode(&mut self) -> Result<DecoderResult<'_>, Error> {
        self.0.decode(false)
    }

    /// Like [`decode`](Decoder::decode), but also reconstructs the missing recovery shards,
    /// returning a [`RecoveryDecoderResult`] that additionally exposes them via
    /// [`RecoveryDecoderResult::restored_recovery`] / [`restored_recovery_iter`]. This costs up to
    /// `recovery_count` extra field multiplications, so prefer [`decode`](Decoder::decode) when only
    /// the original data is needed.
    ///
    /// [`restored_recovery_iter`]: RecoveryDecoderResult::restored_recovery_iter
    pub fn decode_with_recovery(&mut self) -> Result<RecoveryDecoderResult<'_>, Error> {
        Ok(RecoveryDecoderResult::new(self.0.decode(true)?))
    }

    /// Creates new decoder with given configuration
    /// and allocates required working space.
    ///
    /// See [basic usage](crate::reed_solomon#basic-usage) for an example.
    pub fn new(
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<Self, Error> {
        Ok(Self(DefaultRateDecoder::new(
            original_count,
            recovery_count,
            shard_bytes,
            DefaultEngine::new(),
            None,
        )?))
    }

    /// Resets decoder to given configuration.
    ///
    /// - Added shards are forgotten.
    /// - Existing working space is re-used if it's large enough
    ///   or re-allocated otherwise.
    pub fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) -> Result<(), Error> {
        self.0.reset(original_count, recovery_count, shard_bytes)
    }

    /// Returns `true` if given `original_count` / `recovery_count`
    /// combination is supported.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use commonware_cryptography::reed_solomon::Decoder;
    ///
    /// assert_eq!(Decoder::supports(60_000, 4_000), true);
    /// assert_eq!(Decoder::supports(60_000, 5_000), false);
    /// ```
    pub fn supports(original_count: usize, recovery_count: usize) -> bool {
        DefaultRate::<DefaultEngine>::supports(original_count, recovery_count)
    }
}

// ======================================================================
// TESTS

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::test_util;
    use fixedbitset::FixedBitSet;
    use std::collections::BTreeMap;

    // ============================================================
    // HELPERS

    fn roundtrip(
        encoder: &mut Encoder,
        decoder: &mut Decoder,
        original_count: usize,
        recovery_hash: &str,
        decoder_original: &[usize],
        decoder_recovery: &[usize],
        seed: u8,
    ) {
        let original = test_util::generate_original(original_count, 1024, seed);

        for original in &original {
            encoder.add_original_shard(original).unwrap();
        }

        let result = encoder.encode().unwrap();
        let recovery: Vec<_> = result.recovery_iter().collect();

        test_util::assert_hash(&recovery, recovery_hash);

        let mut original_received = FixedBitSet::with_capacity(original_count);

        for i in decoder_original {
            decoder.add_original_shard(*i, &original[*i]).unwrap();
            original_received.set(*i, true);
        }

        for i in decoder_recovery {
            decoder.add_recovery_shard(*i, recovery[*i]).unwrap();
        }

        let result = decoder.decode().unwrap();
        let restored: BTreeMap<_, _> = result.restored_original_iter().collect();

        for i in 0..original_count {
            if !original_received[i] {
                assert_eq!(restored[&i], original[i]);
            }
        }
    }

    // ============================================================
    // ROUNDTRIP - TWO ROUNDS

    #[test]
    fn roundtrip_two_rounds_reset_low_to_high() {
        let mut encoder = Encoder::new(2, 3, 1024).unwrap();
        let mut decoder = Decoder::new(2, 3, 1024).unwrap();

        roundtrip(
            &mut encoder,
            &mut decoder,
            2,
            test_util::LOW_2_3,
            &[],
            &[0, 1],
            123,
        );

        encoder.reset(3, 2, 1024).unwrap();
        decoder.reset(3, 2, 1024).unwrap();

        roundtrip(
            &mut encoder,
            &mut decoder,
            3,
            test_util::HIGH_3_2,
            &[1],
            &[0, 1],
            132,
        );
    }

    #[test]
    fn failed_encoder_reset_preserves_state() {
        let original = test_util::generate_original(2, 1024, 123);
        let mut encoder = Encoder::new(2, 3, 1024).unwrap();

        assert_eq!(
            encoder.reset(3, 2, 3),
            Err(Error::InvalidShardSize { shard_bytes: 3 })
        );

        for shard in &original {
            encoder.add_original_shard(shard).unwrap();
        }
        let result = encoder.encode().unwrap();
        let recovery: Vec<_> = result.recovery_iter().collect();

        test_util::assert_hash(&recovery, test_util::LOW_2_3);
    }

    #[test]
    fn failed_decoder_reset_preserves_state() {
        let original = test_util::generate_original(2, 1024, 123);
        let mut encoder = Encoder::new(2, 3, 1024).unwrap();
        for shard in &original {
            encoder.add_original_shard(shard).unwrap();
        }
        let result = encoder.encode().unwrap();
        let recovery: Vec<_> = result.recovery_iter().map(<[u8]>::to_vec).collect();

        let mut decoder = Decoder::new(2, 3, 1024).unwrap();

        assert_eq!(
            decoder.reset(3, 2, 3),
            Err(Error::InvalidShardSize { shard_bytes: 3 })
        );

        decoder.add_recovery_shard(0, &recovery[0]).unwrap();
        decoder.add_recovery_shard(1, &recovery[1]).unwrap();
        let result = decoder.decode().unwrap();
        let restored: BTreeMap<_, _> = result.restored_original_iter().collect();

        assert_eq!(restored[&0], original[0]);
        assert_eq!(restored[&1], original[1]);
    }

    // ==================================================
    // supports

    #[test]
    fn supports() {
        assert!(Encoder::supports(4096, 61440));
        assert!(Encoder::supports(61440, 4096));

        assert!(Decoder::supports(4096, 61440));
        assert!(Decoder::supports(61440, 4096));
    }
}
