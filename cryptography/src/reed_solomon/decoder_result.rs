use crate::reed_solomon::rate::DecoderWork;

// ======================================================================
// DecoderResult - PUBLIC

/// Result of decoding. Contains the restored original shards.
///
/// This struct is created by [`Decoder::decode`]
/// and [`RateDecoder::decode`].
///
/// [`RateDecoder::decode`]: crate::reed_solomon::rate::RateDecoder::decode
/// [`Decoder::decode`]: crate::reed_solomon::Decoder::decode
pub struct DecoderResult<'a> {
    work: &'a mut DecoderWork,
}

impl DecoderResult<'_> {
    /// Returns restored original shard with given `index`
    /// or `None` if given `index` doesn't correspond to
    /// a missing original shard.
    pub fn restored_original(&self, index: usize) -> Option<&[u8]> {
        self.work.restored_original(index)
    }

    /// Copies restored original shard with given `index` into `dst`.
    ///
    /// Returns `None` if `index` does not correspond to a restored original or
    /// if `dst` does not have the configured shard length.
    pub fn copy_restored_original(&self, index: usize, dst: &mut [u8]) -> Option<()> {
        let shard = self.work.restored_original(index)?;
        if dst.len() != shard.len() {
            return None;
        }
        dst.copy_from_slice(shard);
        Some(())
    }

    /// Returns iterator over all restored original shards
    /// and their indexes, ordered by indexes.
    pub const fn restored_original_iter(&self) -> RestoredOriginal<'_> {
        RestoredOriginal::new(self.work)
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
// RestoredOriginal - PUBLIC

/// Iterator over restored original shards and their indexes.
///
/// This struct is created by [`DecoderResult::restored_original_iter`].
pub struct RestoredOriginal<'a> {
    remaining: usize,
    next_index: usize,
    work: &'a DecoderWork,
}

// ======================================================================
// RestoredOriginal - IMPL Iterator

impl<'a> Iterator for RestoredOriginal<'a> {
    type Item = (usize, &'a [u8]);
    fn next(&mut self) -> Option<(usize, &'a [u8])> {
        if self.remaining == 0 {
            return None;
        }

        let mut index = self.next_index;
        while index < self.work.original_count() {
            if let Some(original) = self.work.restored_original(index) {
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
// RestoredOriginal - IMPL ExactSizeIterator

impl ExactSizeIterator for RestoredOriginal<'_> {}

// ======================================================================
// RestoredOriginal - CRATE

impl<'a> RestoredOriginal<'a> {
    pub(crate) const fn new(work: &'a DecoderWork) -> Self {
        Self {
            remaining: work.missing_original_count(),
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

        let result: DecoderResult<'_> = decoder.decode().unwrap();

        assert_eq!(result.restored_original(0).unwrap(), original[0]);
        assert!(result.restored_original(1).is_none());
        assert_eq!(result.restored_original(2).unwrap(), original[2]);
        assert!(result.restored_original(3).is_none());

        let mut copied = vec![0u8; shard_size];
        assert_eq!(result.copy_restored_original(0, &mut copied), Some(()));
        assert_eq!(copied.as_slice(), original[0].as_slice());
        assert!(result.copy_restored_original(1, &mut copied).is_none());
        let mut short = vec![0u8; shard_size - 1];
        assert!(result.copy_restored_original(2, &mut short).is_none());

        let mut iter: RestoredOriginal<'_> = result.restored_original_iter();
        assert_eq!(iter.next(), Some((0, original[0].as_slice())));
        assert_eq!(iter.next(), Some((2, original[2].as_slice())));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    // DecoderResult::restored_original
    // DecoderResult::restored_original_iter
    // RestoredOriginal
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

        let result: DecoderResult<'_> = decoder.decode().unwrap();

        let mut iter: RestoredOriginal<'_> = result.restored_original_iter();

        assert_eq!(iter.len(), 2);

        assert!(iter.next().is_some());
        assert_eq!(iter.len(), 1);

        assert!(iter.next().is_some());
        assert_eq!(iter.len(), 0);

        assert!(iter.next().is_none());
        assert_eq!(iter.len(), 0);
    }

    #[test]
    fn decoder_result_size_hint_no_missing() {
        let shard_size = SHARD_CHUNK_BYTES;
        let original = test_util::generate_original(3, shard_size, 0);

        let mut encoder = Encoder::new(3, 2, shard_size).unwrap();
        let mut decoder = Decoder::new(3, 2, shard_size).unwrap();

        for original in &original {
            encoder.add_original_shard(original).unwrap();
        }

        let result = encoder.encode().unwrap();
        let _recovery: Vec<_> = result.recovery_iter().collect();

        // Add all the original shards
        decoder.add_original_shard(0, &original[0]).unwrap();
        decoder.add_original_shard(1, &original[1]).unwrap();
        decoder.add_original_shard(2, &original[2]).unwrap();

        let result: DecoderResult<'_> = decoder.decode().unwrap();

        let mut iter: RestoredOriginal<'_> = result.restored_original_iter();

        assert_eq!(iter.len(), 0);

        assert!(iter.next().is_none());
        assert_eq!(iter.len(), 0);

        assert!(iter.next().is_none());
        assert_eq!(iter.len(), 0);
    }
}
