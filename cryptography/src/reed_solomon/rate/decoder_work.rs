use crate::reed_solomon::{
    Error, Plan,
    engine::{SHARD_CHUNK_BYTES, Shards, ShardsRefMut},
};
use fixedbitset::FixedBitSet;

/// Working space for [`RateDecoder`].
///
/// [`RateDecoder`]: crate::reed_solomon::rate::RateDecoder
pub struct DecoderWork {
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,

    /// Index in `shards` of original shard 0.
    original_base_pos: usize,

    /// Index in `shards` of recovery shard 0.
    recovery_base_pos: usize,

    original_received_count: usize,
    recovery_received_count: usize,

    /// Received flags indexed by position in `shards`, not by shard index.
    ///
    /// May contain extra zero bits.
    received: FixedBitSet,

    /// Decoding workspace. Original and recovery shard `i` sit at their base position plus `i`.
    shards: Shards,
}

impl DecoderWork {
    /// Creates a new [`DecoderWork`] with no working space allocated.
    pub const fn new() -> Self {
        Self {
            original_count: 0,
            recovery_count: 0,
            shard_bytes: 0,

            original_base_pos: 0,
            recovery_base_pos: 0,

            original_received_count: 0,
            recovery_received_count: 0,
            received: FixedBitSet::new(),
            shards: Shards::new(),
        }
    }
}

impl Default for DecoderWork {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderWork {
    /// Returns [`Error::PlanMismatch`] unless `plan` was built for these shard counts,
    /// this rate, and these received shard indices.
    pub(crate) fn validate_plan(&self, plan: &Plan, high_rate: bool) -> Result<(), Error> {
        if plan.matches(
            self.original_count,
            self.recovery_count,
            high_rate,
            &self.received,
        ) {
            Ok(())
        } else {
            Err(Error::PlanMismatch)
        }
    }

    /// Stores original shard `index` at `original_base_pos + index` and marks it received.
    ///
    /// Returns an error if `index` is out of range or already received, or if the shard is not
    /// `shard_bytes` long.
    pub(crate) fn add_original_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        original_shard: T,
    ) -> Result<(), Error> {
        if index >= self.original_count {
            return Err(Error::InvalidOriginalShardIndex {
                original_count: self.original_count,
                index,
            });
        }

        let pos = self.original_base_pos + index;
        let original_shard = original_shard.as_ref();

        if self.received[pos] {
            Err(Error::DuplicateOriginalShardIndex { index })
        } else if original_shard.len() != self.shard_bytes {
            Err(Error::DifferentShardSize {
                shard_bytes: self.shard_bytes,
                got: original_shard.len(),
            })
        } else {
            self.shards.insert(pos, original_shard);

            self.original_received_count += 1;
            self.received.set(pos, true);
            Ok(())
        }
    }

    /// Stores recovery shard `index` at `recovery_base_pos + index` and marks it received.
    ///
    /// Returns an error if `index` is out of range or already received, or if the shard is not
    /// `shard_bytes` long.
    pub(crate) fn add_recovery_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        recovery_shard: T,
    ) -> Result<(), Error> {
        if index >= self.recovery_count {
            return Err(Error::InvalidRecoveryShardIndex {
                recovery_count: self.recovery_count,
                index,
            });
        }

        let pos = self.recovery_base_pos + index;
        let recovery_shard = recovery_shard.as_ref();

        if self.received[pos] {
            Err(Error::DuplicateRecoveryShardIndex { index })
        } else if recovery_shard.len() != self.shard_bytes {
            Err(Error::DifferentShardSize {
                shard_bytes: self.shard_bytes,
                got: recovery_shard.len(),
            })
        } else {
            self.shards.insert(pos, recovery_shard);

            self.recovery_received_count += 1;
            self.received.set(pos, true);
            Ok(())
        }
    }

    /// Begins a decode.
    ///
    /// Returns the work shards, the original and recovery counts, and the received flags. Returns
    /// `Ok(None)` if every original was received, or [`Error::NotEnoughShards`] if fewer than
    /// `original_count` shards were received.
    ///
    /// The returned `FixedBitSet` may contain extra zero bits.
    pub(crate) fn decode_begin(
        &mut self,
    ) -> Result<Option<(ShardsRefMut<'_>, usize, usize, &FixedBitSet)>, Error> {
        if self.original_received_count + self.recovery_received_count < self.original_count {
            Err(Error::NotEnoughShards {
                original_count: self.original_count,
                original_received_count: self.original_received_count,
                recovery_received_count: self.recovery_received_count,
            })
        } else if self.original_received_count == self.original_count {
            Ok(None)
        } else {
            Ok(Some((
                self.shards.as_ref_mut(),
                self.original_count,
                self.recovery_count,
                &self.received,
            )))
        }
    }

    /// Returns the number of original shards.
    pub(crate) const fn original_count(&self) -> usize {
        self.original_count
    }

    /// Configures this work for new shard counts, clears the received state, and resizes
    /// `shards` to `work_count` shards.
    ///
    /// Original shard `i` is stored at `original_base_pos + i` and recovery shard `i` at
    /// `recovery_base_pos + i`. Retained shard contents are not zeroed.
    ///
    /// # Panics
    ///
    /// Panics if `shard_bytes` is odd.
    pub(crate) fn reset(
        &mut self,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,

        original_base_pos: usize,
        recovery_base_pos: usize,
        work_count: usize,
    ) {
        assert!(shard_bytes.is_multiple_of(2));

        self.original_count = original_count;
        self.recovery_count = recovery_count;
        self.shard_bytes = shard_bytes;

        self.original_base_pos = original_base_pos;
        self.recovery_base_pos = recovery_base_pos;

        self.original_received_count = 0;
        self.recovery_received_count = 0;

        let max_received_pos = core::cmp::max(
            original_base_pos + original_count,
            recovery_base_pos + recovery_count,
        );

        self.received.clear();
        if self.received.len() < max_received_pos {
            self.received.grow(max_received_pos);
        }

        self.shards
            .resize(work_count, shard_bytes.div_ceil(SHARD_CHUNK_BYTES));
    }

    /// Clears the received shards so new ones can be added under the same configuration.
    pub(crate) fn reset_received(&mut self) {
        self.original_received_count = 0;
        self.recovery_received_count = 0;
        self.received.clear();
    }

    /// Returns a restored original shard, or `None` if `index` is out of range or the shard was
    /// received.
    ///
    /// This must only be called by `DecoderResult`.
    pub(crate) fn original(&self, index: usize) -> Option<&[u8]> {
        if index >= self.original_count {
            return None;
        }
        let pos = self.original_base_pos + index;

        if !self.received[pos] {
            Some(&self.shards[pos].as_flattened()[..self.shard_bytes])
        } else {
            None
        }
    }

    /// Returns a reconstructed recovery shard, or `None` if `index` is not a missing recovery
    /// shard.
    ///
    /// This must only be called by `RecoveryDecoderResult`, which is produced only by a
    /// recovery-computing decode (an original was missing and `compute_recovery` was set), so the
    /// recovery work buffers hold canonical values.
    pub(crate) fn recovery(&self, index: usize) -> Option<&[u8]> {
        if index >= self.recovery_count {
            return None;
        }
        let pos = self.recovery_base_pos + index;

        if self.missing_original_count() > 0 && !self.received[pos] {
            Some(&self.shards[pos].as_flattened()[..self.shard_bytes])
        } else {
            None
        }
    }

    /// Undoes the last-chunk encoding of every original shard position.
    pub(crate) fn undo_last_chunk_encoding(&mut self) {
        self.shards.undo_last_chunk_encoding(
            self.shard_bytes,
            self.original_base_pos..self.original_base_pos + self.original_count,
        );
    }

    /// Undoes the last-chunk encoding of every recovery shard position.
    ///
    /// Call only after a decode that reconstructed the recovery shards.
    pub(crate) fn undo_last_chunk_encoding_recovery(&mut self) {
        self.shards.undo_last_chunk_encoding(
            self.shard_bytes,
            self.recovery_base_pos..self.recovery_base_pos + self.recovery_count,
        );
    }

    /// Returns the number of original shards not received.
    pub(crate) const fn missing_original_count(&self) -> usize {
        self.original_count - self.original_received_count
    }

    /// Returns the number of recovery shards.
    pub(crate) const fn recovery_count(&self) -> usize {
        self.recovery_count
    }

    /// Returns the number of recovery shards not received.
    pub(crate) const fn missing_recovery_count(&self) -> usize {
        self.recovery_count - self.recovery_received_count
    }
}
