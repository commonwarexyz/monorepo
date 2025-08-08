use crate::{
    adb::{
        immutable::{Config, Immutable},
        operation::Variable,
        sync::{self, Journal as _},
    },
    journal::variable,
    mmr::hasher::Standard,
    translator::Translator,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use futures::{pin_mut, StreamExt};

mod journal;
mod verifier;

#[cfg(test)]
mod tests;

pub type Error = crate::adb::Error;

impl<E, K, V, H, T> sync::Database for Immutable<E, K, V, H, T>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: Codec,
    H: Hasher,
    T: Translator,
{
    type Op = Variable<K, V>;
    type Journal = journal::ImmutableSyncJournal<E, K, V>;
    type Verifier = verifier::Verifier<H>;
    type Error = crate::adb::Error;
    type Config = Config<T, V::Cfg>;
    type Digest = H::Digest;
    type Context = E;

    async fn create_journal(
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, <Self::Journal as sync::Journal>::Error> {
        let journal_config = variable::Config {
            partition: config.log_journal_partition.clone(),
            compression: config.log_compression,
            codec_config: config.log_codec_config.clone(),
            write_buffer: config.log_write_buffer,
        };

        // Create the Variable journal using init_sync
        let variable_journal = variable::Journal::init_sync(
            context.with_label("log"),
            journal_config,
            lower_bound,
            upper_bound,
            std::num::NonZeroU64::new(config.log_items_per_section).unwrap(),
        )
        .await?;

        // Count existing operations in the retained range to continue from the correct location
        let mut existing_ops: u64 = 0;
        {
            let stream = variable_journal.replay(1024).await?;
            pin_mut!(stream);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(_) => existing_ops += 1,
                    Err(e) => return Err(<Self::Journal as sync::Journal>::Error::from(e)),
                }
            }
        }

        // Wrap it in our sync journal wrapper
        // The current_size should be lower_bound + existing_ops so we advance sections correctly
        let sync_journal = journal::ImmutableSyncJournal::new(
            variable_journal,
            config.log_items_per_section,
            lower_bound,
            upper_bound,
            lower_bound.saturating_add(existing_ops),
        );

        Ok(sync_journal)
    }

    fn create_verifier() -> Self::Verifier {
        verifier::Verifier::new(Standard::<H>::new())
    }

    async fn from_sync_result(
        context: Self::Context,
        db_config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        target: sync::Target<Self::Digest>,
        apply_batch_size: usize,
    ) -> Result<Self, Self::Error> {
        // Extract the Variable journal from the wrapper
        let variable_journal = journal.into_inner();

        // Create a SyncConfig-like structure for init_synced
        let sync_config = ImmutableSyncConfig {
            db_config,
            log: variable_journal,
            lower_bound: target.lower_bound_ops,
            upper_bound: target.upper_bound_ops,
            pinned_nodes,
            apply_batch_size,
        };

        Self::init_synced(context, sync_config).await
    }

    fn root(&self) -> Self::Digest {
        let mut hasher = Standard::<H>::new();
        self.root(&mut hasher)
    }

    async fn resize_journal(
        journal: Self::Journal,
        context: Self::Context,
        config: &Self::Config,
        lower_bound: u64,
        upper_bound: u64,
    ) -> Result<Self::Journal, Self::Error> {
        // Check if there are operations at or after lower_bound
        let has_operations = journal
            .has_operations_from(lower_bound)
            .await
            .map_err(crate::adb::Error::from)?;

        if !has_operations {
            // Close existing journal and create new one
            journal.close().await.map_err(crate::adb::Error::from)?;
            Self::create_journal(context, config, lower_bound, upper_bound)
                .await
                .map_err(crate::adb::Error::from)
        } else {
            // Extract the Variable journal to perform section-based pruning
            let mut variable_journal = journal.into_inner();

            // Use Variable journal's section-based pruning
            let items_per_section =
                std::num::NonZeroU64::new(config.log_items_per_section).unwrap();
            let lower_section = lower_bound / items_per_section.get();
            variable_journal
                .prune(lower_section)
                .await
                .map_err(crate::adb::Error::from)?;

            // Count existing operations after pruning to set the correct current_size
            let mut existing_ops: u64 = 0;
            {
                let stream = variable_journal.replay(1024).await?;
                pin_mut!(stream);
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(_) => existing_ops += 1,
                        Err(e) => return Err(e.into()),
                    }
                }
            }

            // Wrap the pruned journal back in our sync wrapper
            let sync_journal = journal::ImmutableSyncJournal::new(
                variable_journal,
                config.log_items_per_section,
                lower_bound,
                upper_bound,
                lower_bound.saturating_add(existing_ops),
            );

            Ok(sync_journal)
        }
    }
}

/// Configuration for syncing an [Immutable] to a pruned target state.
pub struct ImmutableSyncConfig<E, K, V, T, D, C>
where
    E: Storage + Metrics,
    K: Array,
    V: Codec,
    T: Translator,
    D: commonware_cryptography::Digest,
{
    /// Database configuration.
    pub db_config: Config<T, C>,

    /// The [Immutable]'s log of operations. It has elements from `lower_bound` to `upper_bound`, inclusive.
    /// Reports `lower_bound` as its pruning boundary (oldest retained operation index).
    pub log: variable::Journal<E, Variable<K, V>>,

    /// Sync lower boundary (inclusive) - operations below this index are pruned.
    pub lower_bound: u64,

    /// Sync upper boundary (inclusive) - operations above this index are not synced.
    pub upper_bound: u64,

    /// The pinned nodes the MMR needs at the pruning boundary given by
    /// `lower_bound`, in the order specified by `Proof::nodes_to_pin`.
    /// If `None`, the pinned nodes will be computed from the MMR's journal and metadata,
    /// which are expected to have the necessary pinned nodes.
    pub pinned_nodes: Option<Vec<D>>,

    /// The maximum number of operations to keep in memory
    /// before committing the database while applying operations.
    /// Higher value will cause more memory usage during sync.
    pub apply_batch_size: usize,
}
