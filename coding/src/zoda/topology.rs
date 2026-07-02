use super::Error;
use crate::Config;
use commonware_math::fields::goldilocks::F;
use commonware_utils::BigRationalExt as _;
use num_rational::BigRational;

const SECURITY_BITS: usize = 126;
// Fractional precision for log2 calculations when computing required samples.
// We use the next power of 2 above SECURITY_BITS (128 = 2^7), which provides
// 1/128 fractional precision, sufficient for these security calculations.
const LOG2_PRECISION: usize = SECURITY_BITS.next_power_of_two().trailing_zeros() as usize;

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

    pub(crate) fn required_samples(&self) -> usize {
        let k = BigRational::from_usize(self.encoded_rows - self.data_rows);
        let m = BigRational::from_usize(self.encoded_rows);
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

    fn correct_column_samples(&mut self) {
        // We make sure we have enough column samples to get 126 bits of security.
        //
        // This effectively does two elements per column. To get strictly greater
        // than 128 bits, we would need to add another column per column_sample.
        // We also have less than 128 bits in other places because of the bounds
        // on the messages encoded size.
        self.column_samples =
            F::bits_to_elements(SECURITY_BITS) * self.required_samples().div_ceil(self.samples);
    }

    /// Figure out what size different values will have, based on the config and the data.
    pub fn reckon(config: &Config, data_bytes: usize) -> Self {
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
        // encoded_rows = next_power_of_two((n+k)*samples) takes only O(log(data_els))
        // distinct values as cols varies. Each distinct value defines a "band" of cols.
        // Within a band, encoded_rows is fixed and required_samples decreases as cols
        // increases, so the validity condition is non-decreasing within a band (valid
        // configs form a contiguous suffix). This means the best col in a band is always
        // its right endpoint (band_hi).
        //
        // Across band boundaries, encoded_rows drops sharply, so the condition can go
        // valid -> invalid -> valid as cols increases. A binary search would incorrectly
        // discard valid cols to the right of an invalid gap.
        //
        // Instead, we enumerate the O(log(data_els)) bands and check each band's right
        // endpoint. For band P, the right endpoint is the largest cols where
        // (n+k)*samples > P/2, i.e., band_hi = floor((data_els-1)/(n*(s_min-1)))
        // where s_min = P/(2*(n+k))+1. If encoded_rows(band_hi) != P, the band is
        // empty (samples skips that value) and we skip it. This gives O(log(data_els))
        // BigRational calls instead of O(data_els).
        //
        // It's possible that even cols=1 is not good. To correct for that, we
        // need to add extra checksum columns to guarantee security.
        let data_els = F::bits_to_elements(8 * corrected_data_bytes);
        let is_valid = |cols: usize| -> bool {
            let t = Self::with_cols(corrected_data_bytes, n, k, cols);
            t.required_samples().saturating_mul(n + k) <= t.encoded_rows
        };
        let mut out = if !is_valid(1) || !is_valid(2) {
            // cols=1 is the best we can do. Return it without applying the
            // required_samples adjustment; correct_column_samples handles the
            // security requirement via column_samples instead.
            Self::with_cols(corrected_data_bytes, n, k, 1)
        } else {
            // Enumerate bands from smallest encoded_rows (largest cols) to largest.
            // band_hi is non-increasing as p grows, so the first valid band_hi
            // found is the globally largest valid col.
            let min_er = Self::with_cols(corrected_data_bytes, n, k, data_els).encoded_rows;
            let max_er = Self::with_cols(corrected_data_bytes, n, k, 2).encoded_rows;
            let mut result: Option<Self> = None;
            let mut p = min_er;
            loop {
                let s_min = p / (2 * (n + k)) + 1;
                let band_hi = if s_min <= 1 {
                    data_els
                } else {
                    ((data_els - 1) / (n * (s_min - 1))).max(2)
                };
                let t = Self::with_cols(corrected_data_bytes, n, k, band_hi);
                // If t.encoded_rows != p, the band is empty (samples skips s_min).
                if t.encoded_rows == p {
                    let req = t.required_samples();
                    if req.saturating_mul(n + k) <= t.encoded_rows {
                        result = Some(Self {
                            samples: req.max(t.samples),
                            ..t
                        });
                        break;
                    }
                }
                if p >= max_er {
                    break;
                }
                p *= 2;
            }
            // is_valid(2) was true, so at least one band has a valid col.
            result.expect("is_valid(2) ensures at least one valid multi-column config")
        };
        out.correct_column_samples();
        out.data_bytes = data_bytes;
        out
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
        let topology = Topology::reckon(&config, 16);
        assert_eq!(topology.min_shards, 3);
        assert_eq!(topology.total_shards, 4);

        // Verify we hit the 1-column fallback and the security invariant holds.
        // When reckon() cannot find a valid multi-column config, correct_column_samples()
        // must compensate by adding column samples.
        assert_eq!(topology.data_cols, 1);
        let required = topology.required_samples();
        let provided = topology.samples * (topology.column_samples / 2);
        assert!(
            provided >= required,
            "security invariant violated: provided {provided} < required {required}"
        );
    }

    // Fast oracle: stops at the first invalid col (original loop behavior).
    // Used for the exhaustive small-input test because non-monotone patterns
    // do not arise for small data sizes, so this agrees with the full scan.
    fn reckon_initial_run(config: &Config, data_bytes: usize) -> Topology {
        let n = config.minimum_shards.get() as usize;
        let k = config.extra_shards.get() as usize;
        let corrected_data_bytes = data_bytes.max(1);
        let mut out = Topology::with_cols(corrected_data_bytes, n, k, 1);
        loop {
            let attempt = Topology::with_cols(corrected_data_bytes, n, k, out.data_cols + 1);
            let required_samples = attempt.required_samples();
            if required_samples.saturating_mul(n + k) <= attempt.encoded_rows {
                out = Topology {
                    samples: required_samples.max(attempt.samples),
                    ..attempt
                };
            } else {
                break;
            }
        }
        out.correct_column_samples();
        out.data_bytes = data_bytes;
        out
    }

    // Slow oracle: scans all column counts to find the globally largest valid one.
    // Used for the large-input spot-check test where non-monotone patterns can
    // arise, so stopping at the first invalid col would miss better configs.
    fn reckon_full_scan(config: &Config, data_bytes: usize) -> Topology {
        let n = config.minimum_shards.get() as usize;
        let k = config.extra_shards.get() as usize;
        let corrected_data_bytes = data_bytes.max(1);
        let data_els = F::bits_to_elements(8 * corrected_data_bytes);
        let mut best: Option<Topology> = None;
        for cols in 2..=data_els {
            let attempt = Topology::with_cols(corrected_data_bytes, n, k, cols);
            let required_samples = attempt.required_samples();
            if required_samples.saturating_mul(n + k) <= attempt.encoded_rows {
                best = Some(Topology {
                    samples: required_samples.max(attempt.samples),
                    ..attempt
                });
            }
        }
        // If no valid multi-column config was found, fall back to cols=1 without
        // applying the required_samples adjustment, matching the binary search
        // fallback path.
        let mut out = best.unwrap_or_else(|| Topology::with_cols(corrected_data_bytes, n, k, 1));
        out.correct_column_samples();
        out.data_bytes = data_bytes;
        out
    }

    fn check_security_invariant(t: &Topology) {
        let required = t.required_samples();
        // When a multi-column config was found, samples must satisfy the security
        // requirement on its own, without relying on column_samples to compensate.
        if t.data_cols > 1 {
            assert!(
                required.saturating_mul(t.total_shards) <= t.encoded_rows,
                "multi-column security invariant violated: required={required} total_shards={} encoded_rows={}",
                t.total_shards,
                t.encoded_rows,
            );
        }
        // column_samples must always cover the security requirement, whether or
        // not a multi-column config was found.
        let provided = t.samples * (t.column_samples / 2).max(1);
        assert!(
            provided >= required,
            "column_samples security invariant violated: provided={provided} required={required}"
        );
    }

    // Exhaustively verify the binary search matches the initial-run oracle for
    // all small inputs and check the security invariant on every result.
    // Non-monotone patterns do not arise for these small data sizes, so the
    // fast initial-run oracle is correct here.
    #[test]
    fn reckon_matches_linear_scan() {
        for data_bytes in 0..=1024usize {
            for n in 1..=16u16 {
                for k in 1..=16u16 {
                    let config = Config {
                        minimum_shards: n.try_into().unwrap(),
                        extra_shards: k.try_into().unwrap(),
                    };
                    let got = Topology::reckon(&config, data_bytes);
                    let expected = reckon_initial_run(&config, data_bytes);
                    assert_eq!(
                        got, expected,
                        "mismatch at data_bytes={data_bytes} n={n} k={k}: got {got:?}, expected {expected:?}"
                    );
                    check_security_invariant(&got);
                }
            }
        }
    }

    // Spot-check the binary search against the full-scan oracle at larger inputs
    // where non-monotone patterns can arise, to verify the binary search finds
    // the globally optimal col count in those cases.
    #[test]
    fn reckon_matches_full_scan_large() {
        let configs: &[(u16, u16)] = &[(4, 2), (8, 4), (10, 5), (16, 16)];
        for &data_bytes in &[10_000usize, 100_000] {
            for &(n, k) in configs {
                let config = Config {
                    minimum_shards: n.try_into().unwrap(),
                    extra_shards: k.try_into().unwrap(),
                };
                let got = Topology::reckon(&config, data_bytes);
                let expected = reckon_full_scan(&config, data_bytes);
                assert_eq!(
                    got, expected,
                    "mismatch at data_bytes={data_bytes} n={n} k={k}: got {got:?}, expected {expected:?}"
                );
                check_security_invariant(&got);
            }
        }
    }
}
