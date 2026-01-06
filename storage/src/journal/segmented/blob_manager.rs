//! Common blob management for segmented journals.
//!
//! This module provides `BlobManager`, a reusable component that handles
//! section-based blob storage, pruning, syncing, and metrics.

use crate::journal::Error;
use commonware_runtime::{
    buffer::{Append, PoolRef},
    telemetry::metrics::status::GaugeExt,
    Blob, Error as RError, Metrics, Storage,
};
use commonware_utils::hex;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use std::{collections::BTreeMap, num::NonZeroUsize};
use tracing::debug;

/// Configuration for blob management.
#[derive(Clone)]
pub struct Config {
    /// The partition to use for storing blobs.
    pub partition: String,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// Manages a collection of section-based blobs.
///
/// Each section is stored in a separate blob, named by its section number
/// (big-endian u64). This component handles initialization, pruning, syncing,
/// and metrics.
pub struct BlobManager<E: Storage + Metrics> {
    pub(crate) context: E,
    pub(crate) cfg: Config,

    /// One blob per section.
    pub(crate) blobs: BTreeMap<u64, Append<E::Blob>>,

    /// A section number before which all sections have been pruned during
    /// the current execution. Not persisted across restarts.
    pub(crate) oldest_retained_section: u64,

    pub(crate) tracked: Gauge,
    pub(crate) synced: Counter,
    pub(crate) pruned: Counter,
}

impl<E: Storage + Metrics> BlobManager<E> {
    /// Initialize a new `BlobManager`.
    ///
    /// Scans the partition for existing blobs and opens them.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
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
            let blob = Append::new(blob, size, cfg.write_buffer, cfg.buffer_pool.clone()).await?;
            blobs.insert(section, blob);
        }

        let tracked = Gauge::default();
        let synced = Counter::default();
        let pruned = Counter::default();
        context.register("tracked", "Number of blobs", tracked.clone());
        context.register("synced", "Number of syncs", synced.clone());
        context.register("pruned", "Number of blobs pruned", pruned.clone());
        let _ = tracked.try_set(blobs.len());

        Ok(Self {
            context,
            cfg,
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
    pub fn get(&self, section: u64) -> Result<Option<&Append<E::Blob>>, Error> {
        self.prune_guard(section)?;
        Ok(self.blobs.get(&section))
    }

    /// Get a mutable reference to a blob, creating it if it doesn't exist.
    pub async fn get_or_create(&mut self, section: u64) -> Result<&mut Append<E::Blob>, Error> {
        self.prune_guard(section)?;

        if !self.blobs.contains_key(&section) {
            let name = section.to_be_bytes();
            let (blob, size) = self.context.open(&self.cfg.partition, &name).await?;
            let blob = Append::new(
                blob,
                size,
                self.cfg.write_buffer,
                self.cfg.buffer_pool.clone(),
            )
            .await?;
            self.tracked.inc();
            self.blobs.insert(section, blob);
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
        for blob in self.blobs.values() {
            self.synced.inc();
            blob.sync().await.map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Prune all sections less than `min`. Returns true if any were pruned.
    pub async fn prune(&mut self, min: u64) -> Result<bool, Error> {
        let mut pruned = false;
        while let Some((&section, _)) = self.blobs.first_key_value() {
            if section >= min {
                break;
            }

            let blob = self.blobs.remove(&section).unwrap();
            let size = blob.size().await;
            drop(blob);

            self.context
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
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
    pub fn sections_from(
        &self,
        start_section: u64,
    ) -> impl Iterator<Item = (&u64, &Append<E::Blob>)> {
        self.blobs.range(start_section..)
    }

    /// Remove all underlying blobs.
    pub async fn destroy(self) -> Result<(), Error> {
        for (section, blob) in self.blobs.into_iter() {
            let size = blob.size().await;
            drop(blob);
            debug!(section, size, "destroyed blob");
            self.context
                .remove(&self.cfg.partition, Some(&section.to_be_bytes()))
                .await?;
        }
        match self.context.remove(&self.cfg.partition, None).await {
            Ok(()) => {}
            Err(RError::PartitionMissing(_)) => {}
            Err(err) => return Err(Error::Runtime(err)),
        }
        Ok(())
    }

    /// Rewind by removing all sections after `section` and resizing the target section.
    pub async fn rewind(&mut self, section: u64, size: u64) -> Result<(), Error> {
        self.prune_guard(section)?;

        // Remove all sections after this one
        let sections_to_remove: Vec<u64> =
            self.blobs.range((section + 1)..).map(|(&s, _)| s).collect();

        for s in sections_to_remove {
            let blob = self.blobs.remove(&s).unwrap();
            drop(blob);
            self.context
                .remove(&self.cfg.partition, Some(&s.to_be_bytes()))
                .await?;
            self.tracked.dec();
            debug!(section = s, "removed blob during rewind");
        }

        // Resize the target section if it exists
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

        if let Some(blob) = self.blobs.get(&section) {
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

    /// Returns a reference to the underlying blobs map.
    ///
    /// This is primarily intended for conformance testing where raw access
    /// to blob data is needed.
    pub const fn blobs(&self) -> &BTreeMap<u64, Append<E::Blob>> {
        &self.blobs
    }
}
