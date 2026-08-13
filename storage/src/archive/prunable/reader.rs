//! Read half of the prunable archive.
//!
//! The writer keeps where each item lives, plus a handle on each section's value blob bounded by
//! the bytes flushed when it was taken, in a [State] behind a lock. A read holds the lock long
//! enough to copy one [Location] and clone one [Capture], then does its I/O with nothing held.
//!
//! Reads see what the last publish installed, so a put is invisible until then. Publishing follows
//! the flush, not the fsync, so a reader can serve a value a crash would lose.

use crate::{archive::Error, journal::segmented::glob::Capture};
use commonware_codec::CodecShared;
use commonware_runtime::{Blob, telemetry::metrics::Counter};
use commonware_utils::sync::RwLock;
use std::{collections::BTreeMap, sync::Arc};

/// The section holding `index`.
pub(super) const fn section(index: u64, items_per_section: u64) -> u64 {
    (index / items_per_section) * items_per_section
}

/// Where one stored item lives.
#[derive(Clone, Copy)]
pub(super) struct Location {
    /// Byte offset of the item's value frame in its section's value blob.
    pub value_offset: u64,
    /// The record's position within its section of the index journal. Only key lookups read it.
    pub position: u32,
    /// Byte length of the value frame, including the trailing checksum.
    pub value_size: u32,
}

/// State the writer shares with its readers.
pub(super) struct State<B: Blob, V: CodecShared> {
    /// Where each index's first item lives.
    pub locations: BTreeMap<u64, Location>,

    /// Each section's value blob, bounded by the bytes flushed at the last publish.
    pub captures: BTreeMap<u64, Capture<B, V>>,
}

/// A cloneable handle serving reads by index from the archive's last published state.
pub struct Reader<B: Blob, V: CodecShared> {
    state: Arc<RwLock<State<B, V>>>,
    items_per_section: u64,
    gets: Counter,
}

impl<B: Blob, V: CodecShared> Clone for Reader<B, V> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            items_per_section: self.items_per_section,
            gets: self.gets.clone(),
        }
    }
}

impl<B: Blob, V: CodecShared> Reader<B, V> {
    pub(super) const fn new(
        state: Arc<RwLock<State<B, V>>>,
        items_per_section: u64,
        gets: Counter,
    ) -> Self {
        Self {
            state,
            items_per_section,
            gets,
        }
    }

    /// Where `index` can be read, or `None` if it is absent, pruned, or not yet published.
    fn locate(&self, index: u64) -> Option<(Capture<B, V>, Location)> {
        let state = self.state.read();
        let location = *state.locations.get(&index)?;
        let capture = state
            .captures
            .get(&section(index, self.items_per_section))?;
        capture
            .covers(location.value_offset, location.value_size)
            .then(|| (capture.clone(), location))
    }

    /// See [crate::archive::Archive::get] for [crate::archive::Identifier::Index].
    ///
    /// Returns `None` when the index is absent, pruned, or not yet published. A value that is
    /// published but unreadable is an error, so corruption is not mistaken for absence.
    pub async fn get(&self, index: u64) -> Result<Option<V>, Error> {
        self.gets.inc();
        let Some((capture, location)) = self.locate(index) else {
            return Ok(None);
        };
        Ok(Some(
            capture
                .get(location.value_offset, location.value_size)
                .await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::segmented::glob::{Config as GlobConfig, Glob};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Runner, Supervisor as _, deterministic, telemetry::metrics::MetricsExt as _,
    };
    use commonware_utils::NZUsize;

    /// A reader over one section holding one value frame at `(offset, size)`.
    fn reader_over<B: Blob>(
        capture: Capture<B, i32>,
        offset: u64,
        size: u32,
        gets: Counter,
    ) -> Reader<B, i32> {
        let location = Location {
            value_offset: offset,
            position: 0,
            value_size: size,
        };
        let state = State {
            locations: BTreeMap::from([(0, location)]),
            captures: BTreeMap::from([(0, capture)]),
        };
        Reader::new(Arc::new(RwLock::new(state)), 1, gets)
    }

    #[test_traced]
    fn test_reader_reports_an_unreadable_value_as_an_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let glob = Glob::<_, i32>::init(
                context.child("glob"),
                GlobConfig {
                    partition: "values".into(),
                    compression: None,
                    codec_config: (),
                    write_buffer: NZUsize!(64),
                },
            )
            .await
            .expect("Failed to init glob");
            let (glob, offset, size) = glob.append(0, &7).await.expect("Failed to append");
            let (_, capture) = glob.capture_section(0).await.expect("Failed to capture");
            let capture = capture.expect("section must exist");

            // The frame reads back as written.
            let gets = context.counter("gets", "gets");
            let reader = reader_over(capture.clone(), offset, size, gets.clone());
            assert_eq!(reader.get(0).await.unwrap(), Some(7));

            // A location one byte into the frame stays inside the capture but fails its checksum.
            // Corruption must not read as absence, or a peer would retry a hole forever.
            let reader = reader_over(capture, offset + 1, size - 1, gets);
            assert!(reader.get(0).await.is_err());
        });
    }
}
