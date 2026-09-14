use super::Error;
use crate::Config;
use commonware_math::fields::goldilocks::F;
use commonware_utils::BigRationalExt as _;
use num_rational::BigRational;

// Target security for row and column sampling. Using 126 bits requires two
// Goldilocks checksum elements; F::bits_to_elements counts 63 bits per element.
const SECURITY_BITS: usize = 126;
// Fractional precision (in binary digits) for the fixed-precision log2 bound
// in `required_samples`. We use the next power of 2 above SECURITY_BITS
// (128 = 2^7), which provides 1/128 fractional precision. Computing log2 costs
// exponentially more with each digit, so this cannot be raised much.
const LOG2_PRECISION: usize = SECURITY_BITS.next_power_of_two().trailing_zeros() as usize;
// The fixed-precision bound in `required_samples` has an absolute error of at
// most 2^-LOG2_PRECISION. Below this threshold its relative error exceeds 1/16,
// so we refine it with the (more expensive) series bound.
const SERIES_THRESHOLD_LOG2: usize = LOG2_PRECISION - 4;
// Number of terms of the Taylor series of -ln(1 - f) used for the series bound
// in `required_samples`. Every term is positive, so truncating the series gives
// a lower bound on the log term. With f <= 1/2, the relative error of this
// bound is below 0.1%.
const LN_TERMS: usize = 8;
// A rational upper bound on ln(2), as (numerator, denominator).
const LN2_UPPER: (u64, u64) = (6_931_471_806, 10_000_000_000);

/// Contains the sizes of various objects in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topology {
    /// How many bytes the data has.
    pub data_bytes: usize,
    /// How many columns the data has.
    pub data_cols: usize,
    /// How many rows the data has.
    pub data_rows: usize,
    /// How many rows the encoded data has.
    pub encoded_rows: usize,
    /// How many samples each shard has.
    pub samples: usize,
    /// How many column samples we need.
    pub column_samples: usize,
    /// How many shards we need to recover.
    pub min_shards: usize,
    /// How many shards there are in total (each shard containing multiple rows).
    pub total_shards: usize,
}

impl Topology {
    const fn with_cols(data_bytes: usize, n: usize, k: usize, cols: usize) -> Self {
        let data_els = F::bits_to_elements(8 * data_bytes);
        let data_rows = data_els.div_ceil(cols);
        let samples = data_rows.div_ceil(n);
        Self {
            data_bytes,
            data_cols: cols,
            data_rows,
            encoded_rows: ((n + k) * samples).next_power_of_two(),
            samples,
            column_samples: 0,
            min_shards: n,
            total_shards: n + k,
        }
    }

    /// Compute how many row samples are needed for [SECURITY_BITS] of security.
    ///
    /// Returns `None` if the encoding provides no security at all, which
    /// cannot happen for a topology with more encoded rows than data rows.
    pub(crate) fn required_samples(&self) -> Option<usize> {
        // A single sample of an incorrectly encoded matrix passes with
        // probability at most 1 - f, where f = (m - n + 1) / (2 m) is half the
        // relative distance of a code with n data rows and m encoded rows.
        // We need s samples such that (1 - f)^s <= 2^-SECURITY_BITS, i.e.
        // s >= SECURITY_BITS / -log2(1 - f).
        let distance = self.encoded_rows.checked_sub(self.data_rows)?;
        let fraction = (BigRational::from_usize(distance) + BigRational::from_u64(1))
            / (BigRational::from_usize(2) * BigRational::from_usize(self.encoded_rows));

        // We lower bound -log2(1 - f), which over-estimates the required
        // samples. The fixed-precision ceiling of log2(1 - f), negated, is
        // cheap and tight when f is not small, and exact when 1 - f is a power
        // of two. When m is close to n, f is small, and this bound loses all
        // precision and can even round to zero. In that case, we take the
        // larger of it and a truncation of -ln(1 - f) = sum_{i >= 1} f^i / i,
        // divided by an upper bound on ln(2), which stays tight for small f.
        let one_minus = BigRational::from_usize(1) - &fraction;
        let mut log_term = -one_minus.log2_ceil(LOG2_PRECISION);
        if log_term < BigRational::from_frac_u64(1, 1 << SERIES_THRESHOLD_LOG2) {
            let mut series_bound = BigRational::from_u64(0);
            let mut power = BigRational::from_u64(1);
            for i in 1..=LN_TERMS {
                power *= &fraction;
                series_bound += &power / BigRational::from_usize(i);
            }
            series_bound /= BigRational::from_frac_u64(LN2_UPPER.0, LN2_UPPER.1);
            log_term = log_term.max(series_bound);
        }
        if log_term <= BigRational::from_u64(0) {
            return None;
        }

        let required = BigRational::from_usize(SECURITY_BITS) / log_term;
        usize::try_from(required.ceil_to_u128()?).ok()
    }

    /// Set the number of column samples so that the topology provides
    /// [SECURITY_BITS] of security, even if the row samples alone do not.
    fn correct_column_samples(&mut self) -> Option<()> {
        // We make sure we have enough column samples to get 126 bits of security.
        //
        // This effectively does two elements per column. To get strictly greater
        // than 128 bits, we would need to add another column per column_sample.
        // We also have less than 128 bits in other places because of the bounds
        // on the messages encoded size.
        self.column_samples = F::bits_to_elements(SECURITY_BITS)
            .checked_mul(self.required_samples()?.div_ceil(self.samples))?;
        Some(())
    }

    /// Figure out what size different values will have, based on the config and the data.
    ///
    /// Returns [Error::InvalidConfig] if no secure topology exists for this
    /// configuration and data size.
    pub fn reckon(config: &Config, data_bytes: usize) -> Result<Self, Error> {
        let n = config.minimum_shards.get() as usize;
        let k = config.extra_shards.get() as usize;
        // The following calculations don't tolerate data_bytes = 0, so we
        // temporarily correct that to be at least 1, then make sure to adjust
        // it back again to 0.
        let corrected_data_bytes = data_bytes.max(1);
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
        let mut out = Self::with_cols(corrected_data_bytes, n, k, 1);
        loop {
            let attempt = Self::with_cols(corrected_data_bytes, n, k, out.data_cols + 1);
            let Some(required_samples) = attempt.required_samples() else {
                break;
            };
            if required_samples.saturating_mul(n + k) <= attempt.encoded_rows {
                out = Self {
                    samples: required_samples.max(attempt.samples),
                    ..attempt
                };
            } else {
                break;
            }
        }
        out.correct_column_samples().ok_or(Error::InvalidConfig)?;
        out.data_bytes = data_bytes;
        Ok(out)
    }

    pub fn check_index(&self, i: u16) -> Result<(), Error> {
        if (0..self.total_shards).contains(&(i as usize)) {
            return Ok(());
        }
        Err(Error::InvalidIndex(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::NZU16;

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
        let required = topology.required_samples().unwrap();
        let provided = topology.samples * (topology.column_samples / 2);
        assert!(
            provided >= required,
            "security invariant violated: provided {provided} < required {required}"
        );
    }

    #[test]
    fn reckon_small_extra_shards_exact_power_of_two() {
        // With k = 1 and (n + k) * samples an exact power of two, the encoded
        // rows barely exceed the data rows, so the log2 term in
        // `required_samples` is tiny. With insufficient precision it rounds
        // to zero, which used to overflow when computing `column_samples`.
        // See https://github.com/commonwarexyz/monorepo/issues/4681.
        let config = Config {
            minimum_shards: NZU16!(511),
            extra_shards: NZU16!(1),
        };
        let topology = Topology::reckon(&config, 4000).unwrap();
        assert_eq!(topology.data_rows, 508);
        assert_eq!(topology.encoded_rows, 512);
        assert_eq!(topology.samples, 1);
        let required = topology.required_samples().unwrap();
        // The exact value is 126 / -log2(1019 / 1024), which is about 17842.9.
        assert!(
            (17_843..17_860).contains(&required),
            "required = {required}"
        );
        let provided = topology.samples * (topology.column_samples / 2);
        assert!(
            provided >= required,
            "security invariant violated: provided {provided} < required {required}"
        );
    }

    #[test]
    fn required_samples_is_close_to_exact() {
        // Check that the precision used for the log2 term keeps the rounding
        // error on the required samples small, across a range of encoded
        // row counts approaching the data row count.
        for lg in 3..=20 {
            let encoded_rows = 1usize << lg;
            for data_rows in [1, encoded_rows / 2, encoded_rows - 4, encoded_rows - 1] {
                let topology = Topology {
                    data_bytes: 0,
                    data_cols: 1,
                    data_rows,
                    encoded_rows,
                    samples: 1,
                    column_samples: 0,
                    min_shards: 1,
                    total_shards: 2,
                };
                let required = topology.required_samples().unwrap();
                let fraction = (encoded_rows - data_rows + 1) as f64 / (2.0 * encoded_rows as f64);
                let exact = SECURITY_BITS as f64 / -(1.0 - fraction).log2();
                assert!(
                    required as f64 >= exact,
                    "required {required} below exact {exact} for m={encoded_rows} n={data_rows}"
                );
                // Above the series threshold, only the fixed-precision bound
                // applies, with a relative error of up to 1/16.
                let tolerance =
                    if exact > SECURITY_BITS as f64 * (1 << SERIES_THRESHOLD_LOG2) as f64 {
                        1.001
                    } else {
                        1.0625
                    };
                assert!(
                    required as f64 <= exact * tolerance + 1.0,
                    "required {required} too far above exact {exact} for m={encoded_rows} n={data_rows}"
                );
            }
        }
    }
}
