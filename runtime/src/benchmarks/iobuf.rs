//! Hidden support for iobuf microbenchmarks.

use crate::iobuf::{AlignedBuffer, Freelist};

const BENCH_BUFFER_CAPACITY: usize = 64;
const BENCH_BUFFER_ALIGNMENT: usize = 64;
const BENCH_PREFERRED_WORDS: usize = 8;

/// Opaque owned freelist entry for Freelist microbenchmarks.
pub struct FreelistEntry {
    slot: u32,
    buffer: AlignedBuffer,
}

// SAFETY: this entry uniquely owns its AlignedBuffer and slot id, so moving it
// across threads is equivalent to moving a uniquely-owned heap allocation.
unsafe impl Send for FreelistEntry {}

/// Hidden wrapper that drives the production Freelist from benchmark code
/// without exposing it as part of the normal public API.
pub struct FreelistBench {
    inner: Freelist,
}

impl FreelistBench {
    /// Creates a prefilled Freelist benchmark harness.
    pub fn with_capacity(capacity: usize) -> Self {
        let inner = Freelist::new(capacity, BENCH_PREFERRED_WORDS);
        for slot in 0..capacity {
            inner.put(
                slot as u32,
                AlignedBuffer::new(BENCH_BUFFER_CAPACITY, BENCH_BUFFER_ALIGNMENT),
            );
        }
        Self { inner }
    }

    /// Takes one entry from the underlying Freelist.
    #[inline]
    pub fn take(&self) -> Option<FreelistEntry> {
        self.inner
            .take()
            .map(|(slot, buffer)| FreelistEntry { slot, buffer })
    }

    /// Puts one entry into the underlying Freelist.
    #[inline]
    pub fn put(&self, entry: FreelistEntry) {
        self.inner.put(entry.slot, entry.buffer);
    }

    /// Batch take wrapper around Freelist.
    pub fn take_batch(&self, out: &mut Vec<FreelistEntry>, max: usize) {
        let remaining = max.saturating_sub(out.len());
        if remaining == 1 {
            if let Some(entry) = self.take() {
                out.push(entry);
            }
            return;
        }

        self.inner.take_batch(remaining, |slot, buffer| {
            out.push(FreelistEntry { slot, buffer });
        });
    }

    /// Batch put wrapper around Freelist.
    pub fn put_batch(&self, entries: &mut Vec<FreelistEntry>) {
        if entries.len() == 1 {
            let entry = entries.pop().expect("single-entry batch must exist");
            self.put(entry);
            return;
        }

        self.inner
            .put_batch(entries.drain(..).map(|entry| (entry.slot, entry.buffer)));
    }
}
