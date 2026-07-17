use super::{Config, Error};
use crate::Context;
use commonware_codec::Codec;
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, GaugeExt, MetricsExt as _},
    Blob, Buf as _, WriteBatch,
};
use commonware_utils::Span;
use std::collections::BTreeMap;

/// Name of the blob holding the encoded key-value pairs.
const BLOB_NAME: &[u8] = b"data";

/// Implementation of [Metadata] storage.
pub struct Metadata<E: Context, K: Span, V: Codec> {
    context: E,

    partition: String,
    blob: E::Blob,
    map: BTreeMap<K, V>,
    /// Whether the in-memory map has diverged from the last written state.
    modified: bool,

    syncs: Counter,
    keys: Gauge,
}

impl<E: Context, K: Span, V: Codec> Metadata<E, K, V> {
    /// Initialize a new [Metadata] instance.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let (blob, len) = context.open(&cfg.partition, BLOB_NAME).await?;

        // An empty blob is an empty store. Anything else is a whole record: the backend
        // restores the blob to exactly its last-synced state, so a decode failure is
        // corruption.
        let mut map = BTreeMap::new();
        if len != 0 {
            let len: usize = len.try_into().expect("blob too large for platform");
            let mut buf = blob.read_at(0, len).await?.coalesce();
            while buf.remaining() > 0 {
                let key = K::read_cfg(&mut buf, &()).map_err(Error::Corruption)?;
                let value = V::read_cfg(&mut buf, &cfg.codec_config).map_err(Error::Corruption)?;
                map.insert(key, value);
            }
        }

        // Create metrics
        let syncs = context.counter("syncs", "number of syncs that wrote data");
        let keys = context.gauge("keys", "number of tracked keys");
        let _ = keys.try_set(map.len());

        Ok(Self {
            context,

            partition: cfg.partition,
            blob,
            map,
            modified: false,

            syncs,
            keys,
        })
    }

    /// Get a value from [Metadata] (if it exists).
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Get a mutable reference to a value from [Metadata] (if it exists).
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let value = self.map.get_mut(key)?;
        self.modified = true;
        Some(value)
    }

    /// Clear all values from [Metadata]. The new state will not be persisted until [Self::sync] is
    /// called.
    pub fn clear(&mut self) {
        if !self.map.is_empty() {
            self.map.clear();
            self.modified = true;
        }
        self.keys.set(0);
    }

    /// Put a value into [Metadata].
    ///
    /// If the key already exists, the value will be overwritten and the previous
    /// value is returned. The value stored will not be persisted until [Self::sync]
    /// is called.
    pub fn put(&mut self, key: K, value: V) -> Option<V> {
        let previous = self.map.insert(key, value);
        self.modified = true;
        let _ = self.keys.try_set(self.map.len());
        previous
    }

    /// Perform a [Self::put] and [Self::sync] in a single operation.
    ///
    /// Like calling [Self::sync] directly, this commits all pending metadata
    /// changes, not just the provided key.
    pub async fn put_sync(&mut self, key: K, value: V) -> Result<(), Error> {
        self.put(key, value);
        self.sync().await
    }

    /// Update (or insert) a value in [Metadata] using a closure.
    pub fn upsert(&mut self, key: K, f: impl FnOnce(&mut V))
    where
        V: Default,
    {
        if let Some(value) = self.get_mut(&key) {
            // Update existing value
            f(value);
        } else {
            // Insert new value
            let mut value = V::default();
            f(&mut value);
            self.put(key, value);
        }
    }

    /// Update (or insert) a value in [Metadata] using a closure and sync immediately.
    pub async fn upsert_sync(&mut self, key: K, f: impl FnOnce(&mut V)) -> Result<(), Error>
    where
        V: Default,
    {
        self.upsert(key, f);
        self.sync().await
    }

    /// Remove a value from [Metadata] (if it exists).
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let past = self.map.remove(key);
        if past.is_some() {
            self.modified = true;
        }
        let _ = self.keys.try_set(self.map.len());
        past
    }

    /// Iterate over all keys in metadata.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    /// Retain only the keys that satisfy the predicate.
    pub fn retain(&mut self, mut f: impl FnMut(&K, &V) -> bool) {
        let old_len = self.map.len();
        self.map.retain(|k, v| f(k, v));
        if self.map.len() != old_len {
            self.modified = true;
            let _ = self.keys.try_set(self.map.len());
        }
    }

    /// Encode the current state wholesale as key-value pairs in key order.
    fn encode(&self) -> Vec<u8> {
        let mut size = 0;
        for (key, value) in &self.map {
            size += key.encode_size() + value.encode_size();
        }
        let mut bytes = Vec::with_capacity(size);
        for (key, value) in &self.map {
            key.write(&mut bytes);
            value.write(&mut bytes);
        }
        bytes
    }

    /// Atomically commit the current state of [Metadata], in ONE atomic commit. Does
    /// nothing if the state has not been modified since the last commit.
    pub async fn sync(&mut self) -> Result<(), Error> {
        if !self.modified {
            return Ok(());
        }
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.sync_into(&mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// [Self::sync], staged with `batch`: the wholesale rewrite lands when the caller
    /// applies the batch with `apply_sync`, atomically with everything else it stages.
    pub async fn sync_into<T: WriteBatch<Blob = E::Blob>>(
        &mut self,
        batch: &mut T,
    ) -> Result<(), Error> {
        if !self.modified {
            return Ok(());
        }
        let bytes = self.encode();
        batch.resize(&self.blob, bytes.len() as u64).await?;
        batch.write_at(&self.blob, 0, bytes).await?;
        self.modified = false;
        self.syncs.inc();
        Ok(())
    }

    /// Remove the underlying partition for this [Metadata], in ONE atomic commit.
    pub async fn destroy(self) -> Result<(), Error> {
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.destroy_into(&mut batch);
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// [Self::destroy], staged with `batch`: the partition's removal lands when the caller
    /// applies the batch with `apply_sync`, atomically with everything else it stages.
    ///
    /// The partition always exists: the blob is created at initialization.
    pub(crate) fn destroy_into<T: WriteBatch<Blob = E::Blob>>(self, batch: &mut T) {
        drop(self.blob);
        batch.remove(&self.partition, None);
    }
}
