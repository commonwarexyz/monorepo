use super::Error;
use crate::Config;
use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_math::fields::goldilocks::F;
use commonware_utils::BigRationalExt as _;
use num_rational::BigRational;

const SECURITY_BITS: usize = 126;
// Fractional precision for log2 calculations when computing required samples.
// We use the next power of 2 above SECURITY_BITS (128 = 2^7), which provides
// 1/128 fractional precision, sufficient for these security calculations.
const LOG2_PRECISION: usize = SECURITY_BITS.next_power_of_two().trailing_zeros() as usize;

/// Expensive-to-search portion of a ZODA topology.
///
/// A hint carries the structural choices that determine the full topology, but
/// it does not itself prove that those choices meet ZODA's sampling-security
/// bound. Call [`Topology::reckon`] to derive and validate a full topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopologyHint {
    pub(crate) data_cols: usize,
}

impl TopologyHint {
    const fn new(data_cols: usize) -> Self {
        Self { data_cols }
    }

    /// Search for an efficient topology shape for this configuration and data size.
    pub fn search(config: &Config, data_bytes: usize) -> Self {
        let min_shards = usize::from(config.minimum_shards.get());
        let total_shards = config.total_shards() as usize;
        let data_els = Topology::effective_data_elements(data_bytes);

        // The goal here is to try and maximize the number of columns in the
        // data. ZODA is more efficient the more columns there are. However,
        // we need to make sure that every shard has enough samples to guarantee
        // correct encoding, and that the number of encoded rows can contain
        // all of the samples in each shard, without overlap.
        //
        // To determine if a column configuration is good, we need to choose
        // the number of encoded rows. To do this, we pick a number of samples
        // `S` such that `S * n >= data_rows`. Then, our encoded rows will
        // equal `(N * S).next_power_of_two()`. If the number of required
        // samples `R` for this configuration satisfies `N * R <= encoded_rows`,
        // then this configuration is valid, using `R` as the necessary number
        // of samples.
        //
        // We cannot stop at the first invalid column count.
        //
        // `data_rows = ceil(data_els / cols)` is a staircase: many adjacent
        // `cols` values map to the same row count. Everything that matters for
        // the row-sampling security check depends only on that row count:
        //
        // - `samples = ceil(data_rows / n)`
        // - `encoded_rows = next_power_of_two(N * samples)`
        // - `required_samples(...)`
        //
        // so every `cols` in the same staircase interval has the same validity.
        //
        // Write `q = ceil(data_els / cols)`. The interval of column counts that
        // produce exactly this `q` is:
        //
        //   ceil(data_els / q) <= cols <= floor((data_els - 1) / (q - 1))
        //
        // for `q > 1`. We are already inside such an interval at the current
        // `cols`, so we only need its right endpoint:
        //
        //   interval_end = floor((data_els - 1) / (q - 1))
        //
        // This lets us jump directly from one distinct `data_rows` value to the
        // next, yielding an exact search over all candidates in about
        // `O(sqrt(data_els))` intervals instead of `O(data_els)` individual
        // column counts.
        //
        // We cap the search at `data_els`. Beyond that, `data_rows = 1`
        // forever, meaning we would only be adding guaranteed zero padding to a
        // single row. That region can never satisfy the 126-bit row-sampling
        // bound, so it is never an optimal choice.
        let mut out = Self::new(1);
        let mut cols = 1usize;
        while cols <= data_els {
            let attempt = Topology::with_cols(data_bytes, min_shards, total_shards, cols);
            let interval_end = if attempt.data_rows == 1 {
                data_els
            } else {
                (data_els - 1) / (attempt.data_rows - 1)
            };
            let required_samples = attempt.required_samples();
            if required_samples.saturating_mul(total_shards) <= attempt.encoded_rows {
                out = Self::new(interval_end);
            }
            cols = interval_end + 1;
        }
        out
    }
}

impl EncodeSize for TopologyHint {
    fn encode_size(&self) -> usize {
        self.data_cols.encode_size()
    }
}

impl Write for TopologyHint {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.data_cols.write(buf);
    }
}

impl Read for TopologyHint {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        let range = RangeCfg::from(..);
        Ok(Self {
            data_cols: usize::read_cfg(buf, &range)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for TopologyHint {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            data_cols: u.arbitrary::<u32>()? as usize,
        })
    }
}

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
    const fn effective_data_elements(data_bytes: usize) -> usize {
        // Model empty input as a single zero-padded row so the sampling and
        // security calculations still have a non-empty domain.
        let effective_data_bytes = if data_bytes == 0 { 1 } else { data_bytes };
        F::bits_to_elements(8 * effective_data_bytes)
    }

    const fn with_cols(
        data_bytes: usize,
        min_shards: usize,
        total_shards: usize,
        data_cols: usize,
    ) -> Self {
        let data_els = Self::effective_data_elements(data_bytes);
        let data_rows = data_els.div_ceil(data_cols);
        let samples = data_rows.div_ceil(min_shards);
        Self {
            data_bytes,
            data_cols,
            data_rows,
            encoded_rows: (total_shards * samples).next_power_of_two(),
            samples,
            column_samples: 0,
            min_shards,
            total_shards,
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

    pub const fn hint(&self) -> TopologyHint {
        TopologyHint::new(self.data_cols)
    }

    /// Figure out what size different values will have, based on a searched hint
    /// and the data size. The hint does not need to be optimal, but it must
    /// still satisfy ZODA's sampling-security bound.
    pub fn reckon(hint: TopologyHint, config: &Config, data_bytes: usize) -> Option<Self> {
        if hint.data_cols == 0 || hint.data_cols > Self::effective_data_elements(data_bytes) {
            return None;
        }

        let mut topology = Self::with_cols(
            data_bytes,
            usize::from(config.minimum_shards.get()),
            config.total_shards() as usize,
            hint.data_cols,
        );

        let required_samples = topology.required_samples();
        if required_samples.saturating_mul(topology.total_shards) <= topology.encoded_rows {
            // We might need more samples than required for being able to recover the data,
            // but if we can fit the required samples, we might as well do that.
            topology.samples = required_samples.max(topology.samples);
        }

        // Now we make sure we have enough columns to get the desired security.
        topology.correct_column_samples();
        Some(topology)
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
    fn reckon_handles_empty_input() {
        let config = Config {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(1),
        };
        let data_bytes = 0;
        let hint = TopologyHint::search(&config, data_bytes);
        let topology = Topology::reckon(hint, &config, data_bytes)
            .expect("searched topology hint must be valid");
        assert_eq!(hint.data_cols, 1);
        assert_eq!(topology.data_bytes, 0);
        assert_eq!(topology.data_cols, 1);
        assert_eq!(topology.data_rows, 1);
        assert_eq!(topology.samples, 1);
        assert_eq!(topology.encoded_rows, 4);

        let required = topology.required_samples();
        let provided = topology.samples * (topology.column_samples / 2);
        assert!(
            provided >= required,
            "security invariant violated: provided {provided} < required {required}"
        );
    }

    #[test]
    fn reckon_handles_small_extra_shards() {
        let config = Config {
            minimum_shards: NZU16!(3),
            extra_shards: NZU16!(1),
        };
        let data_bytes = 16;
        let hint = TopologyHint::search(&config, data_bytes);
        let topology = Topology::reckon(hint, &config, data_bytes)
            .expect("searched topology hint must be valid");
        assert_eq!(topology.min_shards, 3);
        assert_eq!(topology.total_shards, 4);

        // Verify we hit the 1-column fallback and the security invariant holds.
        // When the search finds no better multi-column configuration,
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
    fn reckon_searches_past_invalid_intervals() {
        let config = Config {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(1),
        };
        let hint = TopologyHint::search(&config, 65_536);
        let topology =
            Topology::reckon(hint, &config, 65_536).expect("searched topology hint must be valid");

        // For this payload size, cols=13 and cols=14 are invalid, but
        // cols=15..24 are valid again. A "stop at first invalid candidate"
        // search would therefore get stuck at 12, while the exact interval
        // search should recover the true optimum at 24.
        assert_eq!(topology.data_cols, 24);
        assert_eq!(hint.data_cols, 24);
    }

    #[test]
    fn reckon_accepts_hints_that_need_extra_column_samples() {
        let config = Config {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(1),
        };
        let hint = TopologyHint::new(13);
        let topology =
            Topology::reckon(hint, &config, 65_536).expect("hint should still be secure");
        assert_eq!(topology.data_cols, 13);
        assert!(topology.column_samples > 2);
    }

    #[test]
    fn reckon_rejects_malformed_hints() {
        let config = Config {
            minimum_shards: NZU16!(2),
            extra_shards: NZU16!(1),
        };
        assert!(Topology::reckon(TopologyHint::new(0), &config, 65_536).is_none());
        let too_many_cols = Topology::effective_data_elements(65_536) + 1;
        assert!(Topology::reckon(TopologyHint::new(too_many_cols), &config, 65_536).is_none());
    }
}
