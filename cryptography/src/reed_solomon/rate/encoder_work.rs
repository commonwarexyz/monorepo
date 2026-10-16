use crate::reed_solomon::{
    Error,
    engine::{SHARD_CHUNK_BYTES, Shards, ShardsRefMut},
};

/// Working space for [`RateEncoder`].
///
/// [`RateEncoder`]: crate::reed_solomon::rate::RateEncoder
pub struct EncoderWork {
    original_count: usize,
    recovery_count: usize,

    pub(crate) shard_bytes: usize,

    /// Number of originals added, which is also the position of the next one.
    original_received_count: usize,

    /// Encoding workspace. Originals are stored at `0..original_count`, and an encode leaves the
    /// recovery shards at `0..recovery_count`.
    shards: Shards,
}

impl EncoderWork {
    /// Creates a new [`EncoderWork`] with no working space allocated.
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

impl Default for EncoderWork {
    fn default() -> Self {
        Self::new()
    }
}

impl EncoderWork {
    /// Stores the next original shard at position `original_received_count`.
    ///
    /// Returns an error if `original_count` shards were already added or if the shard is not
    /// `shard_bytes` long.
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

    /// Returns the work shards and the original and recovery counts for an encode.
    ///
    /// Returns [`Error::TooFewOriginalShards`] unless all `original_count` originals were added.
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

    /// Returns recovery shard `index`, or `None` if `index >= recovery_count`.
    ///
    /// This must only be called by `EncoderResult`.
    pub(crate) fn recovery(&self, index: usize) -> Option<&[u8]> {
        if index < self.recovery_count {
            Some(&self.shards[index].as_flattened()[..self.shard_bytes])
        } else {
            None
        }
    }

    /// Configures this work for new shard counts, clears the received originals, and resizes
    /// `shards` to `work_count` shards.
    ///
    /// # Panics
    ///
    /// Panics if `shard_bytes` is odd.
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

    /// Clears the received originals so new ones can be added under the same configuration.
    pub(crate) const fn reset_received(&mut self) {
        self.original_received_count = 0;
    }

    /// Undoes the last-chunk encoding of the recovery shards at `0..recovery_count`.
    pub(crate) fn undo_last_chunk_encoding(&mut self) {
        self.shards
            .undo_last_chunk_encoding(self.shard_bytes, 0..self.recovery_count);
    }

    /// Returns the number of recovery shards.
    pub(crate) const fn recovery_count(&self) -> usize {
        self.recovery_count
    }
}
