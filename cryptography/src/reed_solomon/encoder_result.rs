use crate::reed_solomon::rate::EncoderWork;

// ======================================================================
// EncoderResult - PUBLIC

/// Result of encoding. Contains the generated recovery shards.
///
/// This struct is created by [`Encoder::encode`]
/// and [`RateEncoder::encode`].
///
/// [`RateEncoder::encode`]: crate::reed_solomon::rate::RateEncoder::encode
/// [`Encoder::encode`]: crate::reed_solomon::Encoder::encode
pub struct EncoderResult<'a> {
    work: &'a mut EncoderWork,
}

impl EncoderResult<'_> {
    /// Returns recovery shard with given `index`
    /// or `None` if `index >= recovery_count`.
    ///
    /// Recovery shards have indexes `0..recovery_count`
    /// and these same indexes must be used when decoding.
    pub fn recovery(&self, index: usize) -> Option<&[u8]> {
        self.work.recovery(index)
    }

    /// Returns iterator over all recovery shards ordered by their indexes.
    ///
    /// Recovery shards have indexes `0..recovery_count`
    /// and these same indexes must be used when decoding.
    pub const fn recovery_iter(&self) -> Recovery<'_> {
        Recovery::new(self.work)
    }
}

// ======================================================================
// EncoderResult - CRATE

impl<'a> EncoderResult<'a> {
    pub(crate) const fn new(work: &'a mut EncoderWork) -> Self {
        Self { work }
    }
}

// ======================================================================
// EncoderResult - IMPL DROP

impl Drop for EncoderResult<'_> {
    fn drop(&mut self) {
        self.work.reset_received();
    }
}

// ======================================================================
// Recovery - PUBLIC

/// Iterator over generated recovery shards.
///
/// This struct is created by [`EncoderResult::recovery_iter`].
pub struct Recovery<'a> {
    ended: bool,
    next_index: usize,
    work: &'a EncoderWork,
}

// ======================================================================
// Recovery - IMPL Iterator

impl<'a> Iterator for Recovery<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.ended {
            None
        } else if let Some(next) = self.work.recovery(self.next_index) {
            self.next_index += 1;
            Some(next)
        } else {
            self.ended = true;
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.work.recovery_count() - self.next_index;
        (remaining, Some(remaining))
    }
}

// ======================================================================
// Recovery - IMPL ExactSizeIterator

impl ExactSizeIterator for Recovery<'_> {}

// ======================================================================
// Recovery - CRATE

impl<'a> Recovery<'a> {
    pub(crate) const fn new(work: &'a EncoderWork) -> Self {
        Self {
            ended: false,
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
    use crate::reed_solomon::{test_util, Encoder};
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    #[test]
    // EncoderResult::recovery
    // EncoderResult::recovery_iter
    // Recovery
    fn encoder_result() {
        let original = test_util::generate_original(2, 1024, 123);
        let mut encoder = Encoder::new(2, 3, 1024).unwrap();

        for original in &original {
            encoder.add_original_shard(original).unwrap();
        }

        let result: EncoderResult<'_> = encoder.encode().unwrap();

        let all = vec![
            result.recovery(0).unwrap(),
            result.recovery(1).unwrap(),
            result.recovery(2).unwrap(),
        ];
        assert!(result.recovery(3).is_none());
        test_util::assert_hash(all, test_util::LOW_2_3);

        let mut iter: Recovery<'_> = result.recovery_iter();
        let all = vec![
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
        ];
        assert!(iter.next().is_none());
        test_util::assert_hash(all, test_util::LOW_2_3);
    }

    #[test]
    fn encoder_result_size_hint() {
        let original = test_util::generate_original(2, 1024, 123);
        let mut encoder = Encoder::new(2, 3, 1024).unwrap();

        for original in &original {
            encoder.add_original_shard(original).unwrap();
        }

        let result: EncoderResult<'_> = encoder.encode().unwrap();

        let mut iter: Recovery<'_> = result.recovery_iter();

        assert_eq!(iter.len(), 3);

        assert!(iter.next().is_some());
        assert!(iter.next().is_some());
        assert_eq!(iter.len(), 1);

        assert!(iter.next().is_some());
        assert_eq!(iter.len(), 0);

        assert!(iter.next().is_none());
        assert_eq!(iter.len(), 0);
    }
}
