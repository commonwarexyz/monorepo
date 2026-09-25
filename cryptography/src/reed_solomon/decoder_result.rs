use crate::reed_solomon::rate::DecoderWork;

/// The restored original shards from a decode that ran (an original was missing).
///
/// [`Decoder::decode`] returns `None` instead when every original shard was already provided, since
/// there is nothing to reconstruct.
///
/// [`Decoder::decode`]: crate::reed_solomon::Decoder::decode
pub struct DecoderResult<'a> {
    work: &'a mut DecoderWork,
}

impl DecoderResult<'_> {
    /// Returns the restored original shard with the given `index`, or `None` if `index` does not
    /// correspond to a missing original shard.
    pub fn original(&self, index: usize) -> Option<&[u8]> {
        self.work.original(index)
    }

    /// Returns an iterator over all restored original shards and their indexes, ordered by index.
    pub const fn original_iter(&self) -> Originals<'_> {
        Originals::new(self.work)
    }
}

impl<'a> DecoderResult<'a> {
    pub(crate) const fn new(work: &'a mut DecoderWork) -> Self {
        Self { work }
    }
}

impl Drop for DecoderResult<'_> {
    fn drop(&mut self) {
        self.work.reset_received();
    }
}

/// The restored shards from a successful [`Decoder::decode_with_recovery`] or
/// [`Decoder::decode_with_recovery_plan`], exposing both the restored original shards (like
/// [`DecoderResult`]) and the reconstructed recovery shards.
///
/// [`Decoder::decode_with_recovery`]: crate::reed_solomon::Decoder::decode_with_recovery
/// [`Decoder::decode_with_recovery_plan`]: crate::reed_solomon::Decoder::decode_with_recovery_plan
pub struct RecoveryDecoderResult<'a> {
    inner: DecoderResult<'a>,
}

impl RecoveryDecoderResult<'_> {
    /// Returns the restored original shard with the given `index`, or `None` if it was provided or
    /// `index` is out of range. See [`DecoderResult::original`].
    pub fn original(&self, index: usize) -> Option<&[u8]> {
        self.inner.original(index)
    }

    /// Returns an iterator over the restored original shards and their indexes, ordered by index.
    /// See [`DecoderResult::original_iter`].
    pub const fn original_iter(&self) -> Originals<'_> {
        self.inner.original_iter()
    }

    /// Returns the reconstructed recovery shard with the given `index`, or `None` if it was
    /// provided or `index` is out of range.
    pub fn recovery(&self, index: usize) -> Option<&[u8]> {
        self.inner.work.recovery(index)
    }

    /// Returns an iterator over the reconstructed recovery shards and their indexes, ordered by
    /// index.
    pub const fn recovery_iter(&self) -> Recoveries<'_> {
        Recoveries::new(self.inner.work)
    }
}

impl<'a> RecoveryDecoderResult<'a> {
    pub(crate) const fn new(inner: DecoderResult<'a>) -> Self {
        Self { inner }
    }
}

/// Iterator over restored original shards and their indexes.
///
/// This struct is created by [`DecoderResult::original_iter`].
pub struct Originals<'a> {
    remaining: usize,
    next_index: usize,
    work: &'a DecoderWork,
}

impl<'a> Iterator for Originals<'a> {
    type Item = (usize, &'a [u8]);
    fn next(&mut self) -> Option<(usize, &'a [u8])> {
        if self.remaining == 0 {
            return None;
        }

        let mut index = self.next_index;
        while index < self.work.original_count() {
            if let Some(original) = self.work.original(index) {
                self.next_index = index + 1;
                self.remaining -= 1;
                return Some((index, original));
            }
            index += 1;
        }

        unreachable!("Inconsistency in internal data structures. Please report.");
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Originals<'_> {}

impl<'a> Originals<'a> {
    pub(crate) const fn new(work: &'a DecoderWork) -> Self {
        Self {
            remaining: work.missing_original_count(),
            next_index: 0,
            work,
        }
    }
}

/// Iterator over restored recovery shards and their indexes.
///
/// This struct is created by [`RecoveryDecoderResult::recovery_iter`].
pub struct Recoveries<'a> {
    remaining: usize,
    next_index: usize,
    work: &'a DecoderWork,
}

impl<'a> Iterator for Recoveries<'a> {
    type Item = (usize, &'a [u8]);
    fn next(&mut self) -> Option<(usize, &'a [u8])> {
        if self.remaining == 0 {
            return None;
        }

        let mut index = self.next_index;
        while index < self.work.recovery_count() {
            if let Some(recovery) = self.work.recovery(index) {
                self.next_index = index + 1;
                self.remaining -= 1;
                return Some((index, recovery));
            }
            index += 1;
        }

        unreachable!("Inconsistency in internal data structures. Please report.");
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Recoveries<'_> {}

impl<'a> Recoveries<'a> {
    pub(crate) const fn new(work: &'a DecoderWork) -> Self {
        Self {
            remaining: work.missing_recovery_count(),
            next_index: 0,
            work,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::{Decoder, Encoder, SHARD_CHUNK_BYTES, test_util};
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;
    use commonware_utils::test_rng;
    use rand::seq::SliceRandom as _;

    fn simple_roundtrip(shard_size: usize) {
        let original = test_util::generate_original(3, shard_size, 0);

        let mut encoder = Encoder::new(3, 2, shard_size).unwrap();
        let mut decoder = Decoder::new(3, 2, shard_size).unwrap();

        for original in &original {
            encoder.add_original_shard(original).unwrap();
        }

        let result = encoder.encode().unwrap();
        let recovery: Vec<_> = result.recovery_iter().collect();

        assert!(recovery.iter().all(|slice| slice.len() == shard_size));

        decoder.add_original_shard(1, &original[1]).unwrap();
        decoder.add_recovery_shard(0, recovery[0]).unwrap();
        decoder.add_recovery_shard(1, recovery[1]).unwrap();

        let result = decoder.decode().unwrap().unwrap();

        assert_eq!(result.original(0).unwrap(), original[0]);
        assert!(result.original(1).is_none());
        assert_eq!(result.original(2).unwrap(), original[2]);
        assert!(result.original(3).is_none());

        let mut iter: Originals<'_> = result.original_iter();
        assert_eq!(iter.next(), Some((0, original[0].as_slice())));
        assert_eq!(iter.next(), Some((2, original[2].as_slice())));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    /// Covers `DecoderResult::original`, `DecoderResult::original_iter`, and `Originals`.
    #[test]
    fn decoder_result() {
        simple_roundtrip(1024);
    }

    #[test]
    fn shard_size_not_divisible_by_chunk_size() {
        for shard_size in [
            2,
            4,
            6,
            30,
            32,
            34,
            62,
            SHARD_CHUNK_BYTES,
            66,
            126,
            128,
            130,
        ] {
            simple_roundtrip(shard_size);
        }
    }

    #[test]
    fn decoder_result_size_hint() {
        let shard_size = SHARD_CHUNK_BYTES;
        let original = test_util::generate_original(3, shard_size, 0);

        let mut encoder = Encoder::new(3, 2, shard_size).unwrap();
        let mut decoder = Decoder::new(3, 2, shard_size).unwrap();

        for original in &original {
            encoder.add_original_shard(original).unwrap();
        }

        let result = encoder.encode().unwrap();
        let recovery: Vec<_> = result.recovery_iter().collect();

        decoder.add_original_shard(1, &original[1]).unwrap();
        decoder.add_recovery_shard(0, recovery[0]).unwrap();
        decoder.add_recovery_shard(1, recovery[1]).unwrap();

        let result = decoder.decode().unwrap().unwrap();

        let mut iter: Originals<'_> = result.original_iter();

        assert_eq!(iter.len(), 2);

        assert!(iter.next().is_some());
        assert_eq!(iter.len(), 1);

        assert!(iter.next().is_some());
        assert_eq!(iter.len(), 0);

        assert!(iter.next().is_none());
        assert_eq!(iter.len(), 0);
    }

    /// Decodes from exactly `original_count` shards (dropping original 0 and every recovery
    /// except index 1) and asserts the reconstructed recovery shards are byte-identical to the
    /// encoder's output. This is the load-bearing check for `recovery`. The reveal and
    /// last-chunk undo on the recovery positions must reproduce `encoding.recovery(i)` exactly,
    /// including the partial-final-chunk path (shard sizes not divisible by `SHARD_CHUNK_BYTES`).
    fn recovery_roundtrip(original_count: usize, recovery_count: usize, shard_size: usize) {
        let original = test_util::generate_original(original_count, shard_size, 0);

        let mut encoder = Encoder::new(original_count, recovery_count, shard_size).unwrap();
        for original in &original {
            encoder.add_original_shard(original).unwrap();
        }
        let encoding = encoder.encode().unwrap();
        let recovery: Vec<Vec<u8>> = encoding.recovery_iter().map(<[u8]>::to_vec).collect();

        // Provide originals `1..original_count` plus recovery 1 (exactly `original_count`
        // shards), so original 0 and every recovery except index 1 are reconstructed.
        let mut decoder = Decoder::new(original_count, recovery_count, shard_size).unwrap();
        for (i, original) in original.iter().enumerate().skip(1) {
            decoder.add_original_shard(i, original).unwrap();
        }
        decoder.add_recovery_shard(1, &recovery[1]).unwrap();
        let decoding = decoder.decode_with_recovery().unwrap().unwrap();

        assert_eq!(decoding.original(0).unwrap(), original[0].as_slice());
        for (i, recovery) in recovery.iter().enumerate() {
            let label = format!("oc={original_count} rc={recovery_count} ss={shard_size} rec={i}");
            if i == 1 {
                assert!(decoding.recovery(i).is_none(), "provided recovery: {label}");
            } else {
                assert_eq!(
                    decoding.recovery(i).unwrap(),
                    recovery.as_slice(),
                    "restored recovery mismatch: {label}"
                );
            }
        }

        let via_iter: Vec<(usize, Vec<u8>)> = decoding
            .recovery_iter()
            .map(|(i, s)| (i, s.to_vec()))
            .collect();
        let expected: Vec<(usize, Vec<u8>)> = (0..recovery_count)
            .filter(|&i| i != 1)
            .map(|i| (i, recovery[i].clone()))
            .collect();
        assert_eq!(via_iter, expected);
    }

    #[test]
    fn recovery_matches_encoder() {
        // Shard sizes span the partial-final-chunk boundary (`SHARD_CHUNK_BYTES` = 64).
        for shard_size in [2, 34, 62, SHARD_CHUNK_BYTES, 66, 130, 1024] {
            // HighRate selections (original_count_pow2 >= recovery_count_pow2).
            recovery_roundtrip(3, 2, shard_size);
            recovery_roundtrip(16, 4, shard_size);

            // LowRate selections (original_count_pow2 < recovery_count_pow2), including the
            // 250-shard / k=83 / m=167 shape used by the coding crate.
            recovery_roundtrip(4, 8, shard_size);
            recovery_roundtrip(83, 167, shard_size);
        }
    }

    #[test]
    fn direct_recovery_matches_encoder() {
        // The last two `(k, m)` cases straddle the direct-evaluation limit.
        let mut rng = test_rng();
        for (k, m) in [(7, 13), (84, 166), (128, 384), (128, 385)] {
            for shard_size in [2, 66, 1024] {
                let originals = test_util::generate_original(k, shard_size, 0);
                let mut encoder = Encoder::new(k, m, shard_size).unwrap();
                for shard in &originals {
                    encoder.add_original_shard(shard).unwrap();
                }
                let encoding = encoder.encode().unwrap();
                let recoveries: Vec<_> = encoding.recovery_iter().collect();
                let mut decoder = Decoder::new(k, m, shard_size).unwrap();

                // Always omit original 0 so recovery runs, even with surplus shards.
                let mut indices: Vec<_> = (1..k + m).collect();
                for provided in [k, k + 3, k + m - 1] {
                    indices.shuffle(&mut rng);
                    let selected = &indices[..provided];
                    for &i in selected {
                        if i < k {
                            decoder.add_original_shard(i, &originals[i]).unwrap();
                        } else {
                            decoder
                                .add_recovery_shard(i - k, recoveries[i - k])
                                .unwrap();
                        }
                    }
                    let result = decoder.decode_with_recovery().unwrap().unwrap();
                    for (i, shard) in originals.iter().enumerate() {
                        if !selected.contains(&i) {
                            assert_eq!(result.original(i).unwrap(), shard.as_slice());
                        }
                    }
                    for (i, shard) in recoveries.iter().enumerate() {
                        if !selected.contains(&(k + i)) {
                            assert_eq!(result.recovery(i).unwrap(), *shard);
                        }
                    }
                }
            }
        }
    }

    /// Provides every original, so there is nothing to reconstruct, and asserts both decode entry
    /// points return `None`.
    fn assert_decode_none(original_count: usize, recovery_count: usize) {
        let shard_size = SHARD_CHUNK_BYTES;
        let original = test_util::generate_original(original_count, shard_size, 0);

        let mut decoder = Decoder::new(original_count, recovery_count, shard_size).unwrap();
        for (i, shard) in original.iter().enumerate() {
            decoder.add_original_shard(i, shard).unwrap();
        }
        assert!(decoder.decode().unwrap().is_none());

        let mut decoder = Decoder::new(original_count, recovery_count, shard_size).unwrap();
        for (i, shard) in original.iter().enumerate() {
            decoder.add_original_shard(i, shard).unwrap();
        }
        assert!(decoder.decode_with_recovery().unwrap().is_none());
    }

    #[test]
    fn decode_none_when_all_originals_present() {
        assert_decode_none(3, 2); // HighRate (original_count_pow2 >= recovery_count_pow2)
        assert_decode_none(4, 8); // LowRate (original_count_pow2 < recovery_count_pow2)
    }
}
