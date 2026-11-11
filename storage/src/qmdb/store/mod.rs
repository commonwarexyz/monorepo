//! A mutable key-value database that supports variable-sized values, but without authentication.
//!
//! # Example
//!
//! ```rust
//! use commonware_storage::{
//!     journal::contiguous::variable::Config as JournalConfig,
//!     qmdb::store::{Config, Db},
//!     translator::TwoCap,
//! };
//! use commonware_utils::{NZUsize, NZU16, NZU64};
//! use commonware_cryptography::{blake3::Digest, Digest as _};
//! use commonware_math::algebra::Random;
//! use commonware_parallel::Sequential;
//! use commonware_runtime::{
//!     buffer::paged::CacheRef, deterministic::Runner, Metrics, Runner as _, Supervisor as _,
//! };
//!
//! use std::num::NonZeroU16;
//! const PAGE_SIZE: NonZeroU16 = NZU16!(8192);
//! const PAGE_CACHE_SIZE: usize = 100;
//!
//! let executor = Runner::default();
//! executor.start(|mut ctx| async move {
//!     let config = Config {
//!         log: JournalConfig {
//!             partition: "test-partition".into(),
//!             write_buffer: NZUsize!(64 * 1024),
//!             replay_buffer: NZUsize!(64 * 1024),
//!             compression: None,
//!             codec_config: ((), ()),
//!             items_per_section: NZU64!(4),
//!             page_cache: CacheRef::new(PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
//!         },
//!         translator: TwoCap,
//!         init_cache: Some(NZUsize!(1 << 16)),
//!         init_buffer: NZUsize!(1 << 21),
//!         strategy: Sequential,
//!         init_concurrency: (),
//!     };
//!     let db =
//!         Db::<_, Digest, Digest, TwoCap, _>::init(ctx.child("store"), config, None)
//!             .await
//!             .unwrap();
//!
//!     // Insert a key-value pair
//!     let k = Digest::random(&mut ctx);
//!     let v = Digest::random(&mut ctx);
//!     let metadata = Some(Digest::random(&mut ctx));
//!     let batch = db.new_batch().write(k, Some(v)).with_metadata(metadata).finalize();
//!     let db = db.apply_batch(batch).await.unwrap().commit().await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = db.get(&k).await.unwrap();
//!     assert_eq!(fetched_value.unwrap(), v);
//!
//!     // Delete the key's value
//!     let batch = db.new_batch().write(k, None).finalize();
//!     let db = db.apply_batch(batch).await.unwrap().commit().await.unwrap();
//!
//!     // Fetch the value
//!     let fetched_value = db.get(&k).await.unwrap();
//!     assert!(fetched_value.is_none());
//!
//!     // Destroy the store
//!     db.destroy().await.unwrap();
//! });
//! ```
//!
//! ```ignore
//! // Apply a batch and commit it, then build a child batch from the newly published state
//! // and apply it. Each mutation takes the database and returns it, so committing and
//! // building run in sequence on the threaded handle.
//! let batch = db.new_batch().write(key_a, Some(value_a)).finalize();
//! let db = db.apply_batch(batch).await?.commit().await?;
//!
//! let child = db.new_batch().write(key_b, Some(value_b)).finalize();
//! let db = db.apply_batch(child).await?.commit().await?;
//! ```

use crate::{index::unordered::Index, merkle::mmr::Location};

mod db;
pub use db::{Batch, Changeset, Config};

/// An unauthenticated key-value database based off of an append-only journal of operations.
pub type Db<E, K, V, T, S> = db::Db<E, K, V, Index<T, Location>, S>;

/// Partitioned index variants that divide the key space into `2^(P*8)` partitions and build the
/// snapshot in parallel at startup.
pub mod partitioned {
    use super::db;
    use crate::{index::partitioned::unordered::Index, merkle::mmr::Location};
    use core::num::NonZeroUsize;

    /// An unauthenticated key-value database with a partitioned snapshot index.
    ///
    /// This is the partitioned variant of [super::Db]. The const generic `P` specifies the
    /// number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    /// - `P = 3`: ~16 million partitions
    ///
    /// Use partitioned indices when you have a large number of keys (>> 2^(P*8)) and memory
    /// efficiency is important. Keys should be uniformly distributed across the prefix space.
    pub type Db<E, K, V, T, const P: usize, S> = db::Db<E, K, V, Index<T, Location, P>, S>;

    /// Configuration for a [Db], whose `init_concurrency` is the number of snapshot-build tasks.
    pub type Config<T, C, S> = db::Config<T, C, S, NonZeroUsize>;
}

#[cfg(test)]
pub(crate) mod tests {
    use commonware_codec::Codec;
    use commonware_cryptography::{Hasher as _, sha256};
    use commonware_utils::Array;
    use core::fmt::Debug;

    pub trait TestKey: Array + Copy {
        fn from_seed(seed: u64) -> Self;
    }

    pub trait TestValue: Codec + Eq + Debug + Send + Sync {
        fn from_seed(seed: u64) -> Self;
    }

    impl TestKey for sha256::Digest {
        fn from_seed(seed: u64) -> Self {
            commonware_cryptography::Sha256::hash(&[&seed.to_be_bytes()])
        }
    }

    impl<D: TestKey> TestValue for D {
        fn from_seed(seed: u64) -> Self {
            D::from_seed(seed)
        }
    }

    impl TestValue for Vec<u8> {
        fn from_seed(seed: u64) -> Self {
            vec![seed as u8; 32]
        }
    }
}
