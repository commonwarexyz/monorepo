use super::{Config, Error};
use crate::{
    identifier::Identifier,
    store::{immutable, ordinal},
};
use commonware_codec::Codec;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use prometheus_client::metrics::counter::Counter;

/// Implementation of `Archive` storage using immutable and ordinal stores.
pub struct Archive<E: Storage + Metrics + Clock, K: Array, V: Codec> {
    // Immutable store for key->value storage
    keys: immutable::Store<E, K, V>,

    // Ordinal store for index->key mapping and interval tracking
    indices: ordinal::Store<E, K>,

    // Metrics
    gets: Counter,
    puts: Counter,
}

impl<E: Storage + Metrics + Clock, K: Array + Codec<Cfg = ()>, V: Codec> Archive<E, K, V> {
    /// Initialize a new `Archive` instance.
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        // Initialize immutable store for key->value storage
        let keys = immutable::Store::init(context.with_label("keys"), cfg.immutable).await?;
        let indices = ordinal::Store::init(context.with_label("indices"), cfg.ordinal).await?;

        // Initialize metrics
        let gets = Counter::default();
        let puts = Counter::default();
        context.register("gets", "Number of gets performed", gets.clone());
        context.register("puts", "Number of puts performed", puts.clone());

        Ok(Self {
            keys,
            indices,
            gets,
            puts,
        })
    }

    /// Store an item in `Archive`. Both indices and keys are assumed to be globally unique.
    ///
    /// If the index already exists, put does nothing and returns. If the same key is stored multiple times
    /// at different indices (not recommended), any value associated with the key may be returned.
    pub async fn put(&mut self, index: u64, key: K, data: V) -> Result<(), Error> {
        self.puts.inc();

        // Check if index already exists
        if self.indices.has(index) {
            return Ok(());
        }

        // Store key -> value mapping
        self.keys.put(key.clone(), data).await?;

        // Store index -> key mapping
        self.indices.put(index, key)?;

        Ok(())
    }

    /// Retrieve an item from `Archive`.
    pub async fn get(&self, identifier: Identifier<'_, u64, K>) -> Result<Option<V>, Error> {
        self.gets.inc();
        match identifier {
            Identifier::Index(index) => self.get_index(index).await,
            Identifier::Key(key) => self.get_key(key).await,
        }
    }

    async fn get_index(&self, index: u64) -> Result<Option<V>, Error> {
        // Get key from index->key mapping
        let key = match self.indices.get(index).await? {
            Some(key) => key,
            None => return Ok(None),
        };

        // Get value from key->value mapping
        self.keys.get(&key).await.map_err(Error::Immutable)
    }

    async fn get_key(&self, key: &K) -> Result<Option<V>, Error> {
        // Get value directly from key->value mapping
        self.keys.get(key).await.map_err(Error::Immutable)
    }

    /// Check if an item exists in the `Archive`.
    pub async fn has(&self, identifier: Identifier<'_, u64, K>) -> Result<bool, Error> {
        match identifier {
            Identifier::Index(index) => Ok(self.indices.has(index)),
            Identifier::Key(key) => self.has_key(key).await,
        }
    }

    async fn has_key(&self, key: &K) -> Result<bool, Error> {
        Ok(self.keys.has(key).await?)
    }

    /// Forcibly sync all pending writes.
    pub async fn sync(&mut self) -> Result<(), Error> {
        // Sync immutable store
        self.keys.sync().await?;

        // Sync ordinal store
        self.indices.sync().await?;

        Ok(())
    }

    /// Retrieve the end of the current range including `index` (inclusive) and
    /// the start of the next range after `index` (if it exists).
    ///
    /// This is useful for driving backfill operations over the archive.
    pub fn next_gap(&self, index: u64) -> (Option<u64>, Option<u64>) {
        self.indices.next_gap(index)
    }

    /// Close `Archive` (and underlying storage).
    ///
    /// Any pending writes will be synced prior to closing.
    pub async fn close(mut self) -> Result<(), Error> {
        // Sync before closing
        self.sync().await?;

        // Close underlying storage
        self.keys.close().await?;
        self.indices.close().await?;

        Ok(())
    }

    /// Remove all on-disk data created by this `Archive`.
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy underlying storage
        self.keys.destroy().await?;
        self.indices.destroy().await?;

        Ok(())
    }
}
