use crate::{
    index::ordered::Index as OrderedIndex,
    journal::contiguous::variable::Journal as VariableJournal,
    mmr::Location,
    qmdb::{
        any::{
            init_variable_authenticated_log, Db, OrderedOperation, OrderedUpdate, VariableConfig,
            VariableEncoding, VariableValue,
        },
        Error,
    },
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

/// A QMDB implementation with ordered keys and variable-length values.
pub type Variable<E, K, V, H, T> = Db<
    E,
    K,
    VariableEncoding<V>,
    OrderedUpdate<K, VariableEncoding<V>>,
    VariableJournal<E, OrderedOperation<K, VariableEncoding<V>>>,
    OrderedIndex<T, Location>,
    H,
>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    Variable<E, K, V, H, T>
where
    OrderedOperation<K, VariableEncoding<V>>: Codec,
{
    /// Returns a [Variable] QMDB initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <OrderedOperation<K, VariableEncoding<V>> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let translator = cfg.translator.clone();
        let mut log = init_variable_authenticated_log(context.clone(), cfg).await?;

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
        Self::init_from_log(index, log, None, |_, _| {}).await
    }
}
