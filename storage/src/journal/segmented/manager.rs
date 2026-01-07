//! Common blob management for segmented journals.
//!
//! This module provides `Manager`, a reusable component that handles
//! section-based blob storage, pruning, syncing, and metrics.

use crate::journal::Error;
use commonware_runtime::{
    buffer::{Append, PoolRef, Write},
    telemetry::metrics::status::GaugeExt,
    Blob, Error as RError, Metrics, Storage,
};
use commonware_utils::hex;
use futures::future::try_join_all;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{collections::BTreeMap, future::Future, num::NonZeroUsize};
use tracing::debug;

/// A buffer that wraps a blob and provides size information.
///
/// Both [`Append`] and [`Write`] implement this trait.
pub trait SectionBuffer: Blob + Clone + Send + Sync {
    /// Returns the current logical size of the buffer including any buffered data.
    fn size(&self) -> impl Future<Output = u64> + Send;
}

impl<B: Blob> SectionBuffer for Append<B> {
    async fn size(&self) -> u64 {
        Self::size(self).await
    }
}

impl<B: Blob> SectionBuffer for Write<B> {
    async fn size(&self) -> u64 {
        Self::size(self).await
    }
}

/// Factory for creating section buffers from raw blobs.
pub trait BufferFactory<B: Blob>: Clone + Send + Sync {
    /// The buffer type produced by this factory.
    type Buffer: SectionBuffer;

    /// Create a new buffer wrapping the given blob with the specified size.
    fn create(
        &self,
        blob: B,
        size: u64,
    ) -> impl Future<Output = Result<Self::Buffer, RError>> + Send;
}

/// Factory for creating [`Append`] buffers with pool caching.
#[derive(Clone)]
pub struct AppendFactory {
    /// The size of the write buffer.
    pub write_buffer: NonZeroUsize,
    /// The buffer pool for read caching.
    pub pool_ref: PoolRef,
}

impl<B: Blob> BufferFactory<B> for AppendFactory {
    type Buffer = Append<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        Append::new(blob, size, self.write_buffer, self.pool_ref.clone()).await
    }
}

/// Factory for creating [`Write`] buffers without caching.
#[derive(Clone)]
pub struct WriteFactory {
    /// The capacity of the write buffer.
    pub capacity: NonZeroUsize,
}

impl<B: Blob> BufferFactory<B> for WriteFactory {
    type Buffer = Write<B>;

    async fn create(&self, blob: B, size: u64) -> Result<Self::Buffer, RError> {
        Ok(Write::new(blob, size, self.capacity))
    }
}

/// Configuration for blob management.
#[derive(Clone)]
pub struct Config<F> {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// The factory for creating section buffers.
    pub factory: F,
}

/// Manages a collection of section-based blobs.
///
/// Each section is stored in a separate blob, named by its section number
/// (big-endian u64). This component handles initialization, pruning, syncing,
/// and metrics.
pub struct Manager<E: Storage + Metrics, F: BufferFactory<E::Blob>> {
    context: E,
    partition: String,
    factory: F,

    /// One blob per section.
    pub(crate) blobs: BTreeMap<u64, F::Buffer>,

    /// A section number before which all sections have been pruned during
    /// the current execution. Not persisted across restarts.
    oldest_retained_section: u64,

    tracked: Gauge,
    synced: Counter,
    pruned: Counter,
}

impl<E: Storage + Metrics, F: BufferFactory<E::Blob>> Manager<E, F> {
    /// Initialize a new `Manager`.
    ///
    /// Scans the partition for existing blobs and opens them.
    pub async fn init(context: E, cfg: Config<F>) -> Result<Self, Error> {
        // Iterate over blobs in partition
        let mut blobs = BTreeMap::new();
        let stored_blobs = match context.scan(&cfg.partition).await {
            Ok(blobs) => blobs,
            Err(RError::PartitionMissing(_)) => Vec::new(),
            Err(err) => return Err(Error::Runtime(err)),
        };

        for name in stored_blobs {
            let (blob, size) = context.open(&cfg.partition, &name).await?;
            let hex_name = hex(&name);
            let section = match name.try_into() {
                Ok(section) => u64::from_be_bytes(section),
                Err(_) => return Err(Error::InvalidBlobName(hex_name)),
            };
            debug!(section, blob = hex_name, size, "loaded section");
            let buffer = cfg.factory.create(blob, size).await?;
            blobs.insert(section, buffer);
        }

        // Initialize metrics
        let tracked = Gauge::default();
        let synced = Counter::default();
        let pruned = Counter::default();
        context.register("tracked", "Number of blobs", tracked.clone());
        context.register("synced", "Number of syncs", synced.clone());
        context.register("pruned", "Number of blobs pruned", pruned.clone());
        let _ = tracked.try_set(blobs.len());

        Ok(Self {
            context,
            partition: cfg.partition,
            factory: cfg.factory,
            blobs,
            oldest_retained_section: 0,
            tracked,
            synced,
            pruned,
        })
    }

    /// Ensures that a section pruned during the current execution is not accessed.
    pub const fn prune_guard(&self, section: u64) -> Result<(), Error> {
        if section < self.oldest_retained_section {
            Err(Error::AlreadyPrunedToSection(self.oldest_retained_section))
        } else {
            Ok(())
        }
    }

    /// Get a reference to a blob for a section, if it exists.
    pub fn get(&self, section: u64) -> Result<Option<&F::Buffer>, Error> {
        self.prune_guard(section)?;
        Ok(self.blobs.get(&section))
    }

    /// Get a mutable reference to a blob, creating it if it doesn't exist.
    pub async fn get_or_create(&mut self, section: u64) -> Result<&mut F::Buffer, Error> {
        self.prune_guard(section)?;

        if !self.blobs.contains_key(&section) {
            let name = section.to_be_bytes();
            let (blob, size) = self.context.open(&self.partition, &name).await?;
            let buffer = self.factory.create(blob, size).await?;
            self.tracked.inc();
            self.blobs.insert(section, buffer);
        }

        Ok(self.blobs.get_mut(&section).unwrap())
    }

    /// Sync the given section to storage.
    pub async fn sync(&self, section: u64) -> Result<(), Error> {
        self.prune_guard(section)?;
        if let Some(blob) = self.blobs.get(&section) {
            self.synced.inc();
            blob.sync().await.map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Sync all sections to storage.
    pub async fn sync_all(&self) -> Result<(), Error> {
        let futures: Vec<_> = self.blobs.values().map(|blob| blob.sync()).collect();
        let results = try_join_all(futures).await.map_err(Error::Runtime)?;
        self.synced.inc_by(results.len() as u64);
        Ok(())
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        // Prune any blobs that are smaller than the minimum
        let mut pruned = false;
        while let Some((&section, _)) = self.blobs.first_key_value() {
            // Stop pruning if we reach the minimum
            if section >= min {
                break;
            }

            // Remove blob from map
            let blob = self.blobs.remove(&section).unwrap();
            let size = blob.size().await;
            drop(blob);

            // Remove blob from storage
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            pruned = true;

            debug!(section, size, "pruned blob");
            self.tracked.dec();
            self.pruned.inc();
        }

        if pruned {
            self.oldest_retained_section = min;
        }

        Ok(pruned)
    }

    /// Returns the oldest section number, if any blobs exist.
    pub fn oldest_section(&self) -> Option<u64> {
        self.blobs.first_key_value().map(|(&s, _)| s)
    }

    /// Returns the newest section number, if any blobs exist.
    pub fn newest_section(&self) -> Option<u64> {
        self.blobs.last_key_value().map(|(&s, _)| s)
    }

    /// Returns true if no blobs exist.
    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }

    /// Returns the number of sections (blobs).
    pub fn num_sections(&self) -> usize {
        self.blobs.len()
    }

    /// Returns an iterator over all sections starting from `start_section`.
    pub fn sections_from(&self, start_section: u64) -> impl Iterator<Item = (&u64, &F::Buffer)> {
        self.blobs.range(start_section..)
    }

    /// Returns an iterator over all section numbers.
    pub fn sections(&self) -> impl Iterator<Item = u64> + '_ {
        self.blobs.keys().copied()
    }

    /// Remove a specific section. Returns true if the section existed and was removed.
    pub async fn remove_section(&mut self, section: u64) -> Result<bool, Error> {
        self.prune_guard(section)?;

        if let Some(blob) = self.blobs.remove(&section) {
            let size = blob.size().await;
            drop(blob);
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
            self.tracked.dec();
            debug!(section, size, "removed section");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Remove all underlying blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        for (section, blob) in self.blobs.into_iter() {
            let size = blob.size().await;
            drop(blob);
            debug!(section, size, "destroyed blob");
            self.context
                .remove(&self.partition, Some(&section.to_be_bytes()))
                .await?;
        }
        match self.context.remove(&self.partition, None).await {
            Ok(()) => {}
            // Partition already removed or never existed.
            Err(RError::PartitionMissing(_)) => {}
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }

    /// Rewind by removing all sections after `section` and resizing the target section.
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Remove sections in descending order (newest first) to maintain a contiguous record
        // if a crash occurs during rewind.
        let sections_to_remove: Vec<u64> = self
            .blobs
            .range((section + 1)..)
            .rev()
            .map(|(&s, _)| s)
            .collect();

        for s in sections_to_remove {
            // Remove the underlying blob from storage
            let blob = self.blobs.remove(&s).unwrap();
            drop(blob);
            self.context
                .remove(&self.partition, Some(&s.to_be_bytes()))
                .await?;
            self.tracked.dec();
            debug!(section = s, "removed blob during rewind");
        }

        // If the section exists, truncate it to the given size
        if let Some(blob) = self.blobs.get(&section) {
            let current_size = blob.size().await;
            if size < current_size {
                blob.resize(size).await?;
                debug!(
                    section,
                    old_size = current_size,
                    new_size = size,
                    "rewound blob"
                );
            }
        }

        Ok(())
    }

    /// Resize only the given section without affecting other sections.
    pub async fn rewind_section(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Get the blob at the given section
        if let Some(blob) = self.blobs.get(&section) {
            // Truncate the blob to the given size
            let current = blob.size().await;
            if size < current {
                blob.resize(size).await?;
                debug!(section, from = current, to = size, "rewound section");
            }
        }

        Ok(())
    }

    /// Returns the byte size of the given section.
    pub async fn size(&self, section: u64) -> Result<u64, Error> {
        self.prune_guard(section)?;
        match self.blobs.get(&section) {
            Some(blob) => Ok(blob.size().await),
            None => Ok(0),
        }
    }
}
