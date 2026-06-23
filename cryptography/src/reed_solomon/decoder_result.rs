use crate::reed_solomon::rate::DecoderWork;

// ======================================================================
// DecoderResult - PUBLIC

/// The reconstructed shards from a decode that ran, held by [`Decoded::Reconstructed`].
///
/// Always exposes the restored original shards. The reconstructed recovery shards are also available
/// when [`decode`](crate::reed_solomon::Decoder::decode) was called with `compute_recovery = true`;
/// otherwise the recovery accessors return nothing.
pub struct DecoderResult<'a> {
    work: &'a mut DecoderWork,
}

impl DecoderResult<'_> {
    /// Returns restored original shard with given `index`
    /// or `None` if given `index` doesn't correspond to
    /// a missing original shard.
    pub fn original(&self, index: usize) -> Option<&[u8]> {
        self.work.original(index)
    }

    /// Returns iterator over all restored original shards
    /// and their indexes, ordered by indexes.
    pub const fn original_iter(&self) -> Originals<'_> {
        Originals::new(self.work)
    }

    /// Returns the reconstructed recovery shard with the given `index`, or `None` if it was
    /// provided, `index` is out of range, or recovery was not attempted (`decode` was called with
    /// `compute_recovery = false`).
    pub fn recovery(&self, index: usize) -> Option<&[u8]> {
        self.work.recovery(index)
    }

    /// Returns an iterator over the reconstructed recovery shards and their indexes, ordered by
    /// index. Empty unless `decode` was called with `compute_recovery = true`.
    pub const fn recovery_iter(&self) -> Recoveries<'_> {
        Recoveries::new(self.work)
    }
}

// ======================================================================
// DecoderResult - CRATE

impl<'a> DecoderResult<'a> {
    pub(crate) const fn new(work: &'a mut DecoderWork) -> Self {
        Self { work }
    }
}

// ======================================================================
// DecoderResult - IMPL DROP

impl Drop for DecoderResult<'_> {
    fn drop(&mut self) {
        self.work.reset_received();
    }
}

// ======================================================================
// Decoded - PUBLIC

/// Outcome of [`Decoder::decode`](crate::reed_solomon::Decoder::decode).
///
/// Distinguishes the two cases at the type level: when every original shard was provided there is
/// nothing to reconstruct (and no recovery to reveal), so the restored-shard accessors only exist on
/// the [`Reconstructed`](Decoded::Reconstructed) variant.
pub enum Decoded<'a> {
    /// Every original shard was provided, so no Reed-Solomon decode ran. The original data is
    /// already complete from the inputs; nothing was reconstructed.
    Complete,
    /// At least one original shard was missing, so a decode reconstructed the missing shards. Access
    /// the restored originals (and, if `compute_recovery` was set, the recovery shards) through the
    /// [`DecoderResult`].
    Reconstructed(DecoderResult<'a>),
}

// ======================================================================
// Originals - PUBLIC

/// Iterator over restored original shards and their indexes.
///
/// This struct is created by [`DecoderResult::original_iter`].
pub struct Originals<'a> {
    remaining: usize,
    next_index: usize,
    work: &'a DecoderWork,
}

// ======================================================================
// Originals - IMPL Iterator

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

// ======================================================================
// Originals - IMPL ExactSizeIterator

impl ExactSizeIterator for Originals<'_> {}

// ======================================================================
// Originals - CRATE

impl<'a> Originals<'a> {
    pub(crate) const fn new(work: &'a DecoderWork) -> Self {
        Self {
            remaining: work.missing_original_count(),
            next_index: 0,
            work,
        }
    }
}

// ======================================================================
// Recoveries - PUBLIC

/// Iterator over restored recovery shards and their indexes.
///
/// This struct is created by [`DecoderResult::recovery_iter`].
pub struct Recoveries<'a> {
    remaining: usize,
    next_index: usize,
    work: &'a DecoderWork,
}

// ======================================================================
// Recoveries - IMPL Iterator

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

// ======================================================================
// Recoveries - IMPL ExactSizeIterator

impl ExactSizeIterator for Recoveries<'_> {}

// ======================================================================
// Recoveries - CRATE

impl<'a> Recoveries<'a> {
    pub(crate) const fn new(work: &'a DecoderWork) -> Self {
        Self {
            remaining: work.recovery_computed_count(),
            next_index: 0,
            work,
        }
    }
}

// ======================================================================
// TESTS

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reed_solomon::{test_util, Decoder, Encoder, SHARD_CHUNK_BYTES};
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

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

        let Decoded::Reconstructed(result) = decoder.decode(false).unwrap() else {
            unreachable!("an original is missing");
        };

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

    #[test]
    // DecoderResult::original
    // DecoderResult::original_iter
    // Originals
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

        let Decoded::Reconstructed(result) = decoder.decode(false).unwrap() else {
            unreachable!("an original is missing");
        };

        let mut iter: Originals<'_> = result.original_iter();

        assert_eq!(iter.len(), 2);

        assert!(iter.next().is_some());
        assert_eq!(iter.len(), 1);

        assert!(iter.next().is_some());
        assert_eq!(iter.len(), 0);

        assert!(iter.next().is_none());
        assert_eq!(iter.len(), 0);
    }

    // Decode from exactly `original_count` shards (dropping original 0 and every recovery
    // except index 1) and assert the reconstructed recovery shards are byte-identical to the
    // encoder's output. This is the load-bearing check for `recovery`: the reveal +
    // last-chunk-undo on the recovery positions must reproduce `encoding.recovery(i)` exactly,
    // including the partial-final-chunk path (shard sizes not divisible by SHARD_CHUNK_BYTES).
    fn recovery_roundtrip(original_count: usize, recovery_count: usize, shard_size: usize) {
        let original = test_util::generate_original(original_count, shard_size, 0);

        let mut encoder = Encoder::new(original_count, recovery_count, shard_size).unwrap();
        for original in &original {
            encoder.add_original_shard(original).unwrap();
        }
        let encoding = encoder.encode().unwrap();
        let recovery: Vec<Vec<u8>> = encoding.recovery_iter().map(<[u8]>::to_vec).collect();

        // Provide originals 1..original_count plus recovery 1 == exactly `original_count` shards,
        // so original 0 and every recovery except index 1 are reconstructed.
        let mut decoder = Decoder::new(original_count, recovery_count, shard_size).unwrap();
        for (i, original) in original.iter().enumerate().skip(1) {
            decoder.add_original_shard(i, original).unwrap();
        }
        decoder.add_recovery_shard(1, &recovery[1]).unwrap();
        let Decoded::Reconstructed(decoding) = decoder.decode(true).unwrap() else {
            unreachable!("original 0 is missing");
        };

        assert_eq!(
            decoding.original(0).unwrap(),
            original[0].as_slice()
        );
        for (i, recovery) in recovery.iter().enumerate() {
            let label = format!("oc={original_count} rc={recovery_count} ss={shard_size} rec={i}");
            if i == 1 {
                assert!(
                    decoding.recovery(i).is_none(),
                    "provided recovery: {label}"
                );
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
        // Shard sizes spanning the partial-final-chunk boundary (SHARD_CHUNK_BYTES = 64).
        for shard_size in [2, 34, 62, SHARD_CHUNK_BYTES, 66, 130, 1024] {
            // HighRate selections (original_count_pow2 >= recovery_count_pow2).
            recovery_roundtrip(3, 2, shard_size);
            recovery_roundtrip(16, 4, shard_size);
            // LowRate selections (original_count_pow2 < recovery_count_pow2), incl. the
            // 250-shard / k=83 / m=167 shape used by the coding crate.
            recovery_roundtrip(4, 8, shard_size);
            recovery_roundtrip(83, 167, shard_size);
        }
    }

    #[test]
    fn decode_complete_when_all_originals_present() {
        let shard_size = SHARD_CHUNK_BYTES;
        let original = test_util::generate_original(3, shard_size, 0);

        // Every original is provided, so there is nothing to reconstruct. `decode` reports
        // `Complete` regardless of `compute_recovery`, and the recovery accessors are unreachable by
        // construction (they live only on `Decoded::Reconstructed`).
        for compute_recovery in [false, true] {
            let mut decoder = Decoder::new(3, 2, shard_size).unwrap();
            decoder.add_original_shard(0, &original[0]).unwrap();
            decoder.add_original_shard(1, &original[1]).unwrap();
            decoder.add_original_shard(2, &original[2]).unwrap();
            assert!(matches!(
                decoder.decode(compute_recovery).unwrap(),
                Decoded::Complete
            ));
        }
    }
}
