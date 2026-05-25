use crate::stateful::{
    db::{Anchor, DatabaseSet},
    Application,
};
use commonware_consensus::{
    marshal::{
        core::{Mailbox as MarshalMailbox, Variant},
        Identifier,
    },
    types::Height,
    CertifiableBlock, Heightable, Roundable,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_runtime::{Clock, Metrics, Spawner, Storage, Supervisor};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{fixed_bytes, sequence::FixedBytes};
use rand::Rng;

mod actor;
pub(crate) use actor::{Config, Syncer};

mod mailbox;
pub(crate) use mailbox::Mailbox;

mod plan;
pub use plan::SyncPlan;

const SYNC_METADATA_SUFFIX: &str = "state_sync_metadata";
const SYNC_HEIGHT_KEY: FixedBytes<1> = fixed_bytes!("C0");

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;

/// The result of a state sync operation.
pub struct SyncResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The database handle set.
    pub databases: A::Databases,
    /// The anchor at which state sync completed.
    pub anchor: Anchor<BlockDigest<A, E>>,
}

impl<E, A> Clone for SyncResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    fn clone(&self) -> Self {
        Self {
            databases: self.databases.clone(),
            anchor: self.anchor,
        }
    }
}

/// Loads the sync metadata from storage, initializing it if it does not already
/// exist.
async fn load_metadata<E>(context: &E, partition_prefix: &str) -> Metadata<E, FixedBytes<1>, Height>
where
    E: Storage + Supervisor + Clock + Metrics,
{
    Metadata::init(
        context.child("metadata"),
        metadata::Config {
            partition: format!("{partition_prefix}{SYNC_METADATA_SUFFIX}"),
            codec_config: (),
        },
    )
    .await
    .expect("failed to load sync metadata")
}

/// Loads the durable startup-sync height from storage.
///
/// When this returns [`Some`], the node has already completed its one-time
/// state sync for this partition and must recover from the later of that
/// height and marshal's processed height on future startups instead of
/// running peer state sync again.
pub(crate) async fn sync_height<E>(context: &E, partition_prefix: &str) -> Option<Height>
where
    E: Storage + Supervisor + Clock + Metrics,
{
    let metadata = load_metadata(context, partition_prefix).await;
    metadata.get(&SYNC_HEIGHT_KEY).copied()
}

/// Records the height reached by one-time startup sync for this partition.
///
/// Once this height is set, future startups skip peer state sync and initialize
/// from the later of this height and marshal's processed height instead. This
/// action is irreversible.
pub(crate) async fn set_sync_height<E>(context: &E, partition_prefix: &str, height: Height)
where
    E: Storage + Supervisor + Clock + Metrics,
{
    let mut metadata = load_metadata(context, partition_prefix).await;
    metadata
        .put_sync(SYNC_HEIGHT_KEY, height)
        .await
        .expect("failed to set sync height");
}

/// The result of initializing state from marshal on startup.
pub(crate) struct StartupResult<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The initialized database set and anchor.
    pub sync: SyncResult<E, A>,

    /// Finalized marshal blocks at or below this height are already reflected
    /// in the initialized database set and should be acknowledged without
    /// applying them again.
    pub skip_finalized_until: Option<Height>,
}

/// Initializes databases at marshal's current startup anchor.
///
/// This initialization route is used when startup should recover from marshal
/// instead of running peer state sync. If marshal has not yet recorded a
/// processed height, this falls back to marshal's genesis block so fresh boots
/// and post-sync restarts share the same path.
///
/// If the databases are found to be inconsistent with the marshal floor, this
/// function will attempt to repair by rewinding the databases which are ahead. If the
/// databases are entirely inconsistent, this function will panic.
pub(crate) async fn init_databases_from_marshal<E, A, S, V>(
    context: &E,
    marshal: &MarshalMailbox<S, V>,
    db_config: <A::Databases as DatabaseSet<E>>::Config,
    partition_prefix: &str,
    sync_height: Option<Height>,
) -> StartupResult<E, A>
where
    E: Rng + Storage + Spawner + Clock + Metrics,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    let processed_height = marshal.get_processed_height().await;
    let skip_finalized_until = match (sync_height, processed_height) {
        (Some(sync_height), Some(processed_height)) if processed_height < sync_height => {
            Some(sync_height)
        }
        (Some(sync_height), None) => Some(sync_height),
        _ => None,
    };
    let marshal_floor = sync_height
        .into_iter()
        .chain(processed_height)
        .max()
        .unwrap_or_else(Height::zero);
    let floor_block = {
        let marshal_block = marshal
            .get_block(Identifier::Height(marshal_floor))
            .await
            .expect("marshal must return floor block");
        V::into_inner(marshal_block)
    };

    let databases = A::Databases::init(context.child("db_set"), db_config).await;
    let processed_targets = A::sync_targets(&floor_block);

    // In the case that the committed targets do not match the marshal floor, we may
    // have suffered a crash that left the set in an inconsistent state. In this case,
    // we attempt to repair by rewinding the databases back to the marshal floor. If
    // the rewind fails to produce a consistent state, we must crash. This can occur
    // if the databases were corrupted or pruned to aggressively.
    if databases.committed_targets().await != processed_targets {
        databases.rewind_to_targets(processed_targets.clone()).await;
        let rewound_targets = databases.committed_targets().await;
        assert!(
            rewound_targets == processed_targets,
            "databases must be consistent with marshal floor after rewind"
        );
    }

    // Once startup has aligned databases with marshal, future boots should skip peer
    // state sync and recover from the later of this anchor and marshal's durable
    // processed height.
    set_sync_height(context, partition_prefix, floor_block.height()).await;

    let anchor = Anchor {
        height: floor_block.height(),
        round: floor_block.context().round(),
        digest: floor_block.digest(),
    };
    StartupResult {
        sync: SyncResult { databases, anchor },
        skip_finalized_until,
    }
}
