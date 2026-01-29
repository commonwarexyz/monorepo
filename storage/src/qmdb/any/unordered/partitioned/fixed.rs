//! A partitioned variant of [crate::qmdb::any::unordered::fixed] that uses a partitioned index for the snapshot.
//!
//! The partitioned index divides the key space into `2^(P*8)` partitions based on the first `P`
//! bytes of the key. This reduces memory overhead when indexing large datasets, as the
//! partition prefix is not stored in the index. For example, with `P=2`, there are 64K partitions
//! and each key saves 2 bytes on average.
//!
//! # When to Use
//!
//! Use this variant when:
//! - You have a large number of keys (>> 2^(P*8))
//! - Memory efficiency is important
//! - Keys are uniformly distributed across the prefix space
//!
//! For smaller datasets, the regular [crate::qmdb::any::unordered::fixed::Db] may be more appropriate as the
//! partitioned index has upfront memory costs from pre-allocating all partitions.

use crate::{
    index::partitioned::unordered::Index,
    journal::contiguous::fixed::Journal,
    mmr::Location,
    qmdb::{
        any::{
            init_fixed_authenticated_log, unordered, value::FixedEncoding, FixedConfig as Config,
            FixedValue,
        },
        Durable, Error, Merkleized,
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

pub type Update<K, V> = unordered::Update<K, FixedEncoding<V>>;
pub type Operation<K, V> = unordered::Operation<K, FixedEncoding<V>>;

/// A key-value QMDB with a partitioned snapshot index.
///
/// This is the partitioned variant of [crate::qmdb::any::unordered::fixed::Db]. The const generic `P` specifies
/// the number of prefix bytes used for partitioning:
/// - `P = 1`: 256 partitions
/// - `P = 2`: 65,536 partitions
/// - `P = 3`: ~16 million partitions
///
/// See the [module documentation](self) for guidance on when to use this variant.
pub type Db<E, K, V, H, T, const P: usize, S = Merkleized<H>, D = Durable> =
    crate::qmdb::any::unordered::Db<E, Journal<E, Operation<K, V>>, Index<T, Location, P>, H, Update<K, V>, S, D>;

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const P: usize,
    > Db<E, K, V, H, T, P, Merkleized<H>, Durable>
{
    /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error> {
        Self::init_with_callback(context, cfg, None, |_, _| {}).await
    }

    /// Initialize the DB, invoking `callback` for each operation processed during recovery.
    ///
    /// If `known_inactivity_floor` is provided and is less than the log's actual inactivity floor,
    /// `callback` is invoked with `(false, None)` for each location in the gap. Then, as the snapshot
    /// is built from the log, `callback` is invoked for each operation with its activity status and
    /// previous location (if any).
    pub(crate) async fn init_with_callback(
        context: E,
        cfg: Config<T>,
        known_inactivity_floor: Option<Location>,
        callback: impl FnMut(bool, Option<Location>),
    ) -> Result<Self, Error> {
        let translator = cfg.translator.clone();
        let mut log = init_fixed_authenticated_log(context.clone(), cfg).await?;
        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            log.append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await?;
            log.sync().await?;
        }

        let log = Self::init_from_log(
            Index::new(context.clone(), translator),
            log,
            known_inactivity_floor,
            callback,
        )
        .await?;

        Ok(log)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        qmdb::{any::test::fixed_db_config, Durable, Merkleized},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};

    /// Type alias with 256 partitions (P=1).
    type AnyTestP1 =
        Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 1, Merkleized<Sha256>, Durable>;

    /// Type alias with 64K partitions (P=2).
    type AnyTestP2 =
        Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 2, Merkleized<Sha256>, Durable>;

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    async fn open_db_p1(context: deterministic::Context) -> AnyTestP1 {
        AnyTestP1::init(context, fixed_db_config("unordered_partitioned_p1"))
            .await
            .unwrap()
    }

    async fn open_db_p2(context: deterministic::Context) -> AnyTestP2 {
        AnyTestP2::init(context, fixed_db_config("unordered_partitioned_p2"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_partitioned_p1_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p1(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_build_and_authenticate(
                db_context,
                db,
                |ctx| Box::pin(open_db_p1(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_partitioned_p2_build_and_authenticate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p2(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_build_and_authenticate(
                db_context,
                db,
                |ctx| Box::pin(open_db_p2(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_partitioned_p1_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db_p1(context.with_label("db_0")).await;
            let ctx = context.clone();
            crate::qmdb::any::unordered::test::test_any_db_basic(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_db_p1(ctx))
            })
            .await;
        });
    }

    #[test_traced("INFO")]
    fn test_partitioned_p1_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db_p1(context.with_label("db_0")).await;
            let ctx = context.clone();
            crate::qmdb::any::unordered::test::test_any_db_empty(db, move |idx| {
                let ctx = ctx.with_label(&format!("db_{}", idx + 1));
                Box::pin(open_db_p1(ctx))
            })
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_partitioned_p1_non_empty_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p1(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_non_empty_recovery(
                db_context,
                db,
                |ctx| Box::pin(open_db_p1(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_partitioned_p1_empty_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p1(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_empty_recovery(
                db_context,
                db,
                |ctx| Box::pin(open_db_p1(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_partitioned_p1_multiple_commits_delete_replayed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p1(db_context.clone()).await;
            crate::qmdb::any::unordered::test::test_any_db_multiple_commits_delete_replayed(
                db_context,
                db,
                |ctx| Box::pin(open_db_p1(ctx)),
                to_digest,
            )
            .await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_partitioned_p1_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db_p1(context).await;
            crate::qmdb::any::test::test_any_db_steps_not_reset(db).await;
        });
    }
}
