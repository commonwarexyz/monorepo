use super::Error;
use crate::Config;
use commonware_math::fields::goldilocks::F;
use commonware_utils::{BigRationalExt as _, Bounded};
use num_rational::BigRational;
use std::num::{NonZeroU16, NonZeroUsize};

const SECURITY_BITS: usize = 126;
// Fractional precision for log2 calculations when computing required samples.
// We use the next power of 2 above SECURITY_BITS (128 = 2^7), which provides
// 1/128 fractional precision, sufficient for these security calculations.
const LOG2_PRECISION: usize = SECURITY_BITS.next_power_of_two().trailing_zeros() as usize;
const MAX_ENCODED_ROWS: u32 = 1 << 31;
const MAX_TOTAL_SHARDS: u32 = 65_536;

/// Encoded row count supported by row shuffling.
type EncodedRows = Bounded<NonZeroUsize, 1, MAX_ENCODED_ROWS>;
/// Shard count addressable by `u16` shard indices.
type TotalShards = Bounded<NonZeroUsize, 1, MAX_TOTAL_SHARDS>;

/// Contains the sizes of various objects in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topology {
    /// Size of the data, in bytes.
    pub data_bytes: usize,
    /// Non-zero number of columns in the data matrix.
    pub data_cols: usize,
    /// Non-zero number of rows in the data matrix.
    pub data_rows: usize,
    /// Non-zero number of rows in the encoded data.
    pub encoded_rows: usize,
    /// Non-zero number of samples in each shard.
    pub samples: usize,
    /// How many column samples we need.
    pub column_samples: usize,
    /// Non-zero number of shards needed for recovery.
    pub min_shards: usize,
    /// Non-zero total shard count (each shard contains multiple rows).
    pub total_shards: usize,
}

impl Topology {
    fn with_cols(
        data_bytes: NonZeroUsize,
        min_shards: NonZeroU16,
        total_shards: TotalShards,
        data_cols: NonZeroUsize,
    ) -> Result<Self, Error> {
        let data_bytes = data_bytes.get();
        let min_shards = usize::from(min_shards.get());
        let total_shards = total_shards.get();
        let data_cols = data_cols.get();
        let data_bits = data_bytes.checked_mul(8).ok_or(Error::TopologyOverflow)?;
        let data_els = F::bits_to_elements(data_bits);
        let data_rows = data_els.div_ceil(data_cols);
        let samples = data_rows.div_ceil(min_shards);
        let encoded_rows = total_shards
            .checked_mul(samples)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::TooManyEncodedRows)?;
        let encoded_rows = EncodedRows::try_from(encoded_rows)
            .map_err(|_| Error::TooManyEncodedRows)?
            .get();
        Ok(Self {
            data_bytes,
            data_cols,
            data_rows,
            encoded_rows,
            samples,
            column_samples: 0,
            min_shards,
            total_shards,
        })
    }

    pub(crate) fn required_samples(&self) -> usize {
        let encoded_rows = self.encoded_rows;
        let k = BigRational::from_usize(encoded_rows - self.data_rows);
        let m = BigRational::from_usize(encoded_rows);
        let fraction = (&k + BigRational::from_u64(1)) / (BigRational::from_usize(2) * &m);

        // Compute log2(one_minus). When m is close to n, one_minus is close to 1, making log2(one_minus)
        // a small negative value that requires sufficient precision to correctly capture the sign.
        let one_minus = BigRational::from_usize(1) - &fraction;
        let log_term = one_minus.log2_ceil(LOG2_PRECISION);
        if log_term >= BigRational::from_u64(0) {
            return usize::MAX;
        }

        let required = BigRational::from_usize(SECURITY_BITS) / -log_term;
        required.ceil_to_u128().unwrap_or(u128::MAX) as usize
    }

    fn correct_column_samples(&mut self) -> Result<(), Error> {
        // We make sure we have enough column samples to get 126 bits of security.
        //
        // This effectively does two elements per column. To get strictly greater
        // than 128 bits, we would need to add another column per column_sample.
        // We also have less than 128 bits in other places because of the bounds
        // on the messages encoded size.
        self.column_samples = F::bits_to_elements(SECURITY_BITS)
            .checked_mul(self.required_samples().div_ceil(self.samples))
            .ok_or(Error::TopologyOverflow)?;
        Ok(())
    }

    /// Computes protocol dimensions for the data.
    ///
    /// Empty data occupies one zero-padded field element so matrix dimensions remain non-zero.
    pub(super) fn reckon(config: &Config, data_bytes: usize) -> Result<Self, Error> {
        let matrix_data_bytes = NonZeroUsize::new(data_bytes).unwrap_or(NonZeroUsize::MIN);
        let minimum_shards = config.minimum_shards;
        let min_shards = usize::from(minimum_shards.get());
        let extra_shards = usize::from(config.extra_shards.get());
        let total_shards = min_shards
            .checked_add(extra_shards)
            .ok_or(Error::TopologyOverflow)?;
        let total_shards = TotalShards::try_from(total_shards)
            .map_err(|_| Error::TooManyTotalShards(config.total_shards()))?;
        // The goal here is to try and maximize the number of columns in the
        // data. ZODA is more efficient the more columns there are. However,
        // we need to make sure that every shard has enough samples to guarantee
        // correct encoding, and that the number of encoded rows can contain
        // all of the samples in each shard, without overlap.
        //
        // To determine if a column configuration is good, we need to choose
        // the number of encoded rows. To do this, we pick a number of samples
        // `S` such that `S * n >= data_rows`. Then, our encoded rows will
        // equal `((n + k) * S).next_power_of_two()`. If the number of required
        // samples `R` for this configuration satisfies `(n + k) * R <= encoded_rows`,
        // then this configuration is valid, using `R` as the necessary number
        // of samples.
        //
        // We try increasing column counts, picking the configuration that's good.
        // It's possible that the first configuration, with one column, is not good.
        // To correct for that, we need to add extra checksum columns to guarantee
        // security.
        let data_bits = matrix_data_bytes
            .get()
            .checked_mul(8)
            .ok_or(Error::TopologyOverflow)?;
        let max_samples = (MAX_ENCODED_ROWS as usize) / total_shards.get();
        let first_cols = F::bits_to_elements(data_bits)
            .div_ceil(min_shards)
            .div_ceil(max_samples);
        let mut data_cols = NonZeroUsize::new(first_cols).ok_or(Error::TopologyOverflow)?;
        let mut out = Self::with_cols(matrix_data_bytes, minimum_shards, total_shards, data_cols)?;
        loop {
            data_cols = data_cols.checked_add(1).ok_or(Error::TopologyOverflow)?;
            let attempt =
                Self::with_cols(matrix_data_bytes, minimum_shards, total_shards, data_cols)?;
            let required_samples = attempt.required_samples();
            if required_samples <= attempt.encoded_rows / total_shards.get() {
                out = Self {
                    samples: required_samples.max(attempt.samples),
                    ..attempt
                };
            } else {
                break;
            }
        }
        out.correct_column_samples()?;
        out.data_bytes = data_bytes;
        Ok(out)
    }

    pub fn check_index(&self, i: u16) -> Result<(), Error> {
        if (0..self.total_shards).contains(&usize::from(i)) {
            return Ok(());
        }
        Err(Error::InvalidIndex(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{NZU16, NZUsize};

    #[test]
    fn reckon_defines_empty_data() {
        let config = Config {
            minimum_shards: NZU16!(3),
            extra_shards: NZU16!(1),
        };
        let topology = Topology::reckon(&config, 0).unwrap();

        assert_eq!(topology.data_bytes, 0);
        assert_eq!(topology.data_cols, 1);
        assert_eq!(topology.data_rows, 1);
        assert_eq!(topology.samples, 1);
    }

    #[test]
    fn reckon_handles_small_extra_shards() {
        let config = Config {
            minimum_shards: NZU16!(3),
            extra_shards: NZU16!(1),
        };
        let topology = Topology::reckon(&config, 16).unwrap();
        assert_eq!(topology.min_shards, 3);
        assert_eq!(topology.total_shards, 4);

        // Verify we hit the 1-column fallback and the security invariant holds.
        // When the loop in reckon() exits without finding a multi-column config,
        // correct_column_samples() must compensate by adding column samples.
        assert_eq!(topology.data_cols, 1);
        let required = topology.required_samples();
        let provided = topology.samples * (topology.column_samples / 2);
        assert!(
            provided >= required,
            "security invariant violated: provided {provided} < required {required}"
        );
    }

    #[test]
    fn with_cols_rejects_unshufflable_encoded_rows() {
        let total_shards = TotalShards::try_from(usize::from(u16::MAX) + 1).unwrap();
        let result = Topology::with_cols(NZUsize!(258_049), NZU16!(1), total_shards, NZUsize!(1));

        // A power-of-two row count larger than 2^31 cannot be represented by
        // the u32 indices used to shuffle encoded rows.
        assert!(matches!(result, Err(Error::TooManyEncodedRows)));
    }

    #[test]
    fn reckon_rejects_unaddressable_total_shards() {
        let config = Config {
            minimum_shards: NZU16!(u16::MAX),
            extra_shards: NZU16!(2),
        };

        // A u16 index can address every shard only when the count is at most
        // one more than the largest index.
        assert!(matches!(
            Topology::reckon(&config, 1),
            Err(Error::TooManyTotalShards(65_537))
        ));
    }
}
