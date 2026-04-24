use crate::{
    journal::{
        authenticated,
        contiguous::{Contiguous as _, Mutable, Reader as _},
        Error as JournalError,
    },
    merkle::{
        hasher::Standard as StandardHasher,
        journaled::{self, Journaled},
        Family, Location,
    },
    qmdb::{
        self,
        any::value::ValueEncoding,
        keyless::{operation::Codec, Keyless, Operation},
        sync,
    },
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_utils::range::NonEmptyRange;

impl<F, E, V, C, H> sync::Database for Keyless<F, E, V, C, H>
where
    F: Family,
    E: Context,
    V: ValueEncoding + Codec,
    C: Mutable<Item = Operation<F, V>>
        + Persistable<Error = JournalError>
        + sync::Journal<F, Context = E, Op = Operation<F, V>>,
    C::Config: Clone + Send,
    H: Hasher,
    Operation<F, V>: EncodeShared,
{
    type Family = F;
    type Op = Operation<F, V>;
    type Journal = C;
    type Hasher = H;
    type Config = super::Config<C::Config>;
    type Digest = H::Digest;
    type Context = E;

    /// Returns a [Keyless] db initialized from data collected in the sync process.
    ///
    /// # Behavior
    ///
    /// This method handles different initialization scenarios based on existing data:
    /// - If the Merkle journal is empty or the last item is before the range start, it creates
    ///   a fresh Merkle structure from the provided `pinned_nodes`
    /// - If the Merkle journal has data but is incomplete (has length < range end), missing
    ///   operations from the log are applied to bring it up to the target state
    /// - If the Merkle journal has data beyond the range end, it is rewound to match the sync
    ///   target
    ///
    /// # Returns
    ///
    /// A [Keyless] db populated with the state from the given range.
    async fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        log: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: NonEmptyRange<Location<F>>,
        apply_batch_size: usize,
    ) -> Result<Self, qmdb::Error<F>> {
        let hasher = StandardHasher::<H>::new();

        let merkle = Journaled::init_sync(
            context.with_label("merkle"),
            journaled::SyncConfig {
                config: config.merkle.clone(),
                range,
                pinned_nodes,
            },
            &hasher,
        )
        .await?;

        let journal = authenticated::Journal::<F, _, _, _>::from_components(
            merkle,
            log,
            hasher,
            apply_batch_size as u64,
        )
        .await?;

        let (last_commit_loc, inactivity_floor_loc) = {
            let reader = journal.reader().await;
            let loc = reader
                .bounds()
                .end
                .checked_sub(1)
                .expect("journal should not be empty");
            let op = reader.read(loc).await?;
            let floor = op
                .has_floor()
                .expect("last operation should be a commit with floor");
            (Location::new(loc), floor)
        };

        let db = Self {
            journal,
            last_commit_loc,
            inactivity_floor_loc,
        };

        db.sync().await?;
        Ok(db)
    }

    fn root(&self) -> Self::Digest {
        self.root()
    }
}

#[cfg(test)]
mod tests;
