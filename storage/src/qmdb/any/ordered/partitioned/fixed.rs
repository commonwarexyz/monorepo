//! A partitioned variant of [crate::qmdb::any::ordered::fixed] that uses a partitioned index for the snapshot.
//!
//! See [crate::qmdb::any::unordered::partitioned::fixed] for details on partitioned indices and
//! when to use them.

use crate::{
    index::partitioned::ordered::Index,
    journal::contiguous::fixed::Journal,
    mmr::Location,
    qmdb::{
        any::{
            init_fixed_authenticated_log, ordered, value::FixedEncoding, FixedConfig as Config,
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

pub type Update<K, V> = ordered::Update<K, FixedEncoding<V>>;
pub type Operation<K, V> = ordered::Operation<K, FixedEncoding<V>>;

/// An ordered key-value QMDB with a partitioned snapshot index.
///
/// This is the partitioned variant of [crate::qmdb::any::ordered::fixed::Db]. The const generic `P` specifies
/// the number of prefix bytes used for partitioning:
/// - `P = 1`: 256 partitions
/// - `P = 2`: 65,536 partitions
/// - `P = 3`: ~16 million partitions
pub type Db<E, K, V, H, T, const P: usize, S = Merkleized<H>, D = Durable> =
    crate::qmdb::any::ordered::Db<E, Journal<E, Operation<K, V>>, Index<T, Location, P>, H, Update<K, V>, S, D>;

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
    /// `callback` is invoked with `(false, None)` for each location in the gap. Then, as the
    /// snapshot is built from the log, `callback` is invoked for each operation with its activity
    /// status and previous location (if any).
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
            Index::new(context.with_label("index"), translator),
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
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};

    /// Type alias with 256 partitions (P=1).
    type AnyTestP1 =
        Db<deterministic::Context, Digest, Digest, Sha256, TwoCap, 1, Merkleized<Sha256>, Durable>;

    async fn open_db_p1(context: deterministic::Context) -> AnyTestP1 {
        AnyTestP1::init(context, fixed_db_config("ordered_partitioned_p1"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_ordered_partitioned_p1_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p1(db_context.clone()).await;
            crate::qmdb::any::ordered::test::test_digest_ordered_any_db_empty(
                db_context,
                db,
                |ctx| Box::pin(open_db_p1(ctx)),
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_partitioned_p1_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db_context = context.with_label("db");
            let db = open_db_p1(db_context.clone()).await;
            crate::qmdb::any::ordered::test::test_digest_ordered_any_db_basic(
                db_context,
                db,
                |ctx| Box::pin(open_db_p1(ctx)),
            )
            .await;
        });
    }

    #[test_traced("DEBUG")]
    fn test_ordered_partitioned_p1_steps_not_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_db_p1(context).await;
            crate::qmdb::any::test::test_any_db_steps_not_reset(db).await;
        });
    }
}
