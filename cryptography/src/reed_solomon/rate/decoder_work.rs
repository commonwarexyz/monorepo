use crate::reed_solomon::{
    engine::{Shards, ShardsRefMut, SHARD_CHUNK_BYTES},
    Error,
};
use fixedbitset::FixedBitSet;

// ======================================================================
// DecoderWork - PUBLIC

/// Working space for [`RateDecoder`].
///
/// [`RateDecoder`]: crate::reed_solomon::rate::RateDecoder
pub struct DecoderWork {
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,

    original_base_pos: usize,
    recovery_base_pos: usize,

    original_received_count: usize,
    recovery_received_count: usize,
    // May contain extra zero bits.
    received: FixedBitSet,
    shards: Shards,
    recovery_computed: bool,
}

impl DecoderWork {
    /// Creates new [`DecoderWork`] which initially
    /// has no working space allocated.
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
            recovery_computed: false,
        }
    }
}

// ======================================================================
// DecoderWork - IMPL Default

impl Default for DecoderWork {
    fn default() -> Self {
        Self::new()
    }
}

// ======================================================================
// DecoderWork - CRATE

impl DecoderWork {
    pub(crate) fn add_original_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        original_shard: T,
    ) -> Result<(), Error> {
        let pos = self.original_base_pos + index;
        let original_shard = original_shard.as_ref();

        if index >= self.original_count {
            Err(Error::InvalidOriginalShardIndex {
                original_count: self.original_count,
                index,
            })
        } else if self.received[pos] {
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

    pub(crate) fn add_recovery_shard<T: AsRef<[u8]>>(
        &mut self,
        index: usize,
        recovery_shard: T,
    ) -> Result<(), Error> {
        let pos = self.recovery_base_pos + index;
        let recovery_shard = recovery_shard.as_ref();

        if index >= self.recovery_count {
            Err(Error::InvalidRecoveryShardIndex {
                recovery_count: self.recovery_count,
                index,
            })
        } else if self.received[pos] {
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

    // Begin decode.
    // - Returned `FixedBitSet` may contain extra zero bits.
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

    pub(crate) const fn original_count(&self) -> usize {
        self.original_count
    }

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
        self.recovery_computed = false;

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

    pub(crate) fn reset_received(&mut self) {
        self.original_received_count = 0;
        self.recovery_received_count = 0;
        self.recovery_computed = false;
        self.received.clear();
    }

    // This must only be called by `DecoderResult`.
    pub(crate) fn original(&self, index: usize) -> Option<&[u8]> {
        let pos = self.original_base_pos + index;

        if index < self.original_count && !self.received[pos] {
            Some(&self.shards[pos].as_flattened()[..self.shard_bytes])
        } else {
            None
        }
    }

    // This must only be called by `DecoderResult`. Returns a reconstructed recovery shard, or `None`
    // when `index` is not a missing recovery shard or recovery was not computed. Recovery is computed
    // only when `decode` ran with `compute_recovery` set; otherwise the recovery work buffers hold
    // scaled/stale contents and must not be returned.
    pub(crate) fn recovery(&self, index: usize) -> Option<&[u8]> {
        let pos = self.recovery_base_pos + index;

        if self.recovery_computed && index < self.recovery_count && !self.received[pos] {
            Some(&self.shards[pos].as_flattened()[..self.shard_bytes])
        } else {
            None
        }
    }

    pub(crate) fn undo_last_chunk_encoding(&mut self) {
        self.shards.undo_last_chunk_encoding(
            self.shard_bytes,
            self.original_base_pos..self.original_base_pos + self.original_count,
        );
    }

    pub(crate) fn undo_last_chunk_encoding_recovery(&mut self) {
        self.shards.undo_last_chunk_encoding(
            self.shard_bytes,
            self.recovery_base_pos..self.recovery_base_pos + self.recovery_count,
        );
    }

    // Records that `decode` computed the missing recovery shards, so `recovery` may return
    // them. Reset by `reset` / `reset_received`.
    pub(crate) const fn set_recovery_computed(&mut self) {
        self.recovery_computed = true;
    }

    pub(crate) const fn missing_original_count(&self) -> usize {
        self.original_count - self.original_received_count
    }

    pub(crate) const fn recovery_count(&self) -> usize {
        self.recovery_count
    }

    pub(crate) const fn missing_recovery_count(&self) -> usize {
        self.recovery_count - self.recovery_received_count
    }

    // Number of computed recovery shards: zero unless `decode` ran with `compute_recovery`;
    // otherwise the missing recovery count. Matches what `recovery` returns.
    pub(crate) const fn recovery_computed_count(&self) -> usize {
        if self.recovery_computed {
            self.missing_recovery_count()
        } else {
            0
        }
    }
}
