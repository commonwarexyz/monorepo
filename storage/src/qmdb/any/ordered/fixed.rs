use crate::{
    index::ordered::Index as OrderedIndex,
    journal::contiguous::fixed::Journal as FixedJournal,
    mmr::Location,
    qmdb::{
        any::{
            init_fixed_authenticated_log, Db, FixedConfig, FixedEncoding, FixedValue,
            OrderedOperation, OrderedUpdate,
        },
        Error,
    },
    translator::Translator,
};
use commonware_codec::CodecFixed;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

/// A QMDB implementation with ordered keys and fixed-length values.
pub type Fixed<E, K, V, H, T> = Db<
    E,
    K,
    FixedEncoding<V>,
    OrderedUpdate<K, FixedEncoding<V>>,
    FixedJournal<E, OrderedOperation<K, FixedEncoding<V>>>,
    OrderedIndex<T, Location>,
    H,
>;

impl<E: Storage + Clock + Metrics, K: Array, V: FixedValue, H: Hasher, T: Translator>
    Fixed<E, K, V, H, T>
where
    OrderedOperation<K, FixedEncoding<V>>: CodecFixed<Cfg = ()>,
{
    /// Returns a [Fixed] qmdb initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: FixedConfig<T>) -> Result<Self, Error> {
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
        cfg: FixedConfig<T>,
        known_inactivity_floor: Option<Location>,
        callback: impl FnMut(bool, Option<Location>),
    ) -> Result<Self, Error> {
        let translator = cfg.translator.clone();
        let mut log = init_fixed_authenticated_log(context.clone(), cfg).await?;
        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            log.append(OrderedOperation::CommitFloor(
                None,
                Location::new_unchecked(0),
            ))
            .await?;
            log.sync().await?;
        }
        let index = OrderedIndex::new(context.with_label("index"), translator);
        let log = Self::init_from_log(index, log, known_inactivity_floor, callback).await?;

        Ok(log)
    }
}
