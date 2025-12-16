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

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{
        index::ordered::Index, mmr::Location, qmdb::any::test::variable_db_config,
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::deterministic::{Context, Runner};
    use commonware_runtime::Runner as _;
    use commonware_utils::sequence::FixedBytes;

    // Import generic test functions from parent test module
    use super::super::test::{test_ordered_any_db_basic, test_ordered_any_db_empty};

    /// A type alias for the concrete database type used in these unit tests.
    type VariableDb = Db<
        Context,
        FixedBytes<4>,
        VariableEncoding<Digest>,
        OrderedUpdate<FixedBytes<4>, VariableEncoding<Digest>>,
        VariableJournal<Context, OrderedOperation<FixedBytes<4>, VariableEncoding<Digest>>>,
        Index<TwoCap, Location>,
        Sha256,
    >;

    /// Return a database initialized with a variable config.
    pub(crate) async fn open_variable_db(context: Context) -> VariableDb {
        VariableDb::init(context, variable_db_config("partition"))
            .await
            .unwrap()
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_empty() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_db_empty(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }

    #[test_traced("WARN")]
    fn test_ordered_any_variable_db_basic() {
        let executor = Runner::default();
        executor.start(|context| async move {
            let db = open_variable_db(context.clone()).await;
            test_ordered_any_db_basic(context, db, |ctx| Box::pin(open_variable_db(ctx))).await;
        });
    }
}
