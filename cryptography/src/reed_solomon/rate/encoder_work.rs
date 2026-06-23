use crate::reed_solomon::{
    engine::{Shards, ShardsRefMut, SHARD_CHUNK_BYTES},
    Error,
};

// ======================================================================
// EncoderWork - PUBLIC

/// Working space for [`RateEncoder`].
///
/// [`RateEncoder`]: crate::reed_solomon::rate::RateEncoder
pub struct EncoderWork {
    original_count: usize,
    recovery_count: usize,

    pub(crate) shard_bytes: usize,

    original_received_count: usize,
    shards: Shards,
}

impl EncoderWork {
    /// Creates new [`EncoderWork`] which initially
    /// has no working space allocated.
    pub const fn new() -> Self {
        Self {
            original_count: 0,
            recovery_count: 0,
            shard_bytes: 0,

            original_received_count: 0,
            shards: Shards::new(),
        }
    }
}

// ======================================================================
// EncoderWork - IMPL Default

impl Default for EncoderWork {
    fn default() -> Self {
        Self::new()
    }
}

// ======================================================================
// EncoderWork - CRATE

impl EncoderWork {
    pub(crate) fn add_original_shard<T: AsRef<[u8]>>(
        &mut self,
        original_shard: T,
    ) -> Result<(), Error> {
        let original_shard = original_shard.as_ref();

        if self.original_received_count == self.original_count {
            Err(Error::TooManyOriginalShards {
                original_count: self.original_count,
            })
        } else if original_shard.len() != self.shard_bytes {
            Err(Error::DifferentShardSize {
                shard_bytes: self.shard_bytes,
                got: original_shard.len(),
            })
        } else {
            self.shards
                .insert(self.original_received_count, original_shard);

            self.original_received_count += 1;
            Ok(())
        }
    }

    pub(crate) fn encode_begin(&mut self) -> Result<(ShardsRefMut<'_>, usize, usize), Error> {
        if self.original_received_count == self.original_count {
            Ok((
                self.shards.as_ref_mut(),
                self.original_count,
                self.recovery_count,
            ))
        } else {
            Err(Error::TooFewOriginalShards {
                original_count: self.original_count,
                original_received_count: self.original_received_count,
            })
        }
    }

    // This must only be called by `EncoderResult`.
    pub(crate) fn recovery(&self, index: usize) -> Option<&[u8]> {
        if index < self.recovery_count {
            Some(&self.shards[index].as_flattened()[..self.shard_bytes])
        } else {
            None
        }
    }

    pub(crate) fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
        work_count: usize,
    ) {
        assert!(shard_bytes.is_multiple_of(2));

        self.original_count = original_count;
        self.recovery_count = recovery_count;
        self.shard_bytes = shard_bytes;

        self.original_received_count = 0;
        self.shards
            .resize(work_count, shard_bytes.div_ceil(SHARD_CHUNK_BYTES));
    }

    pub(crate) const fn reset_received(&mut self) {
        self.original_received_count = 0;
    }

    pub(crate) fn undo_last_chunk_encoding(&mut self) {
        self.shards
            .undo_last_chunk_encoding(self.shard_bytes, 0..self.recovery_count);
    }

    pub(crate) const fn recovery_count(&self) -> usize {
        self.recovery_count
    }
}
