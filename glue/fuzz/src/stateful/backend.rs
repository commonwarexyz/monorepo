//! Statically dispatched database backends for the database-adapter matrix.
//!
//! A backend owns only what differs between adapter classes: the concrete
//! database type and its configuration, the valid workload one block applies
//! to a batch, the extraction of a block's [`StateCommitment`] from a
//! merkleized batch, its conversion to the adapter's exact sync target, and
//! the canonical root of the applied database. The commitment itself is one
//! type for every backend, so the block consensus carries does not vary with
//! the backend. Everything else (runtime setup, networking, scheduling,
//! waiters, reporting, and the invariants) is shared, and the stateful actor
//! and its adapter are monomorphized per backend, so no trait object sits on
//! the path through the system under test.
//!
//! Every backend uses a fixed-size QMDB variant, which covers the adapter
//! class without multiplying the search space.

use super::{Digest, IO_BUFFER_SIZE, QMDB_INIT_BUFFER, QMDB_INIT_CACHE};
#[cfg(any(
    test,
    feature = "stateful-cert-mock-restarts",
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-cert-mock-state-sync",
    feature = "stateful-cert-mock-twins",
    feature = "stateful-cert-mock-twins-coding",
    feature = "stateful-db-sync",
    feature = "stateful-probe"
))]
pub(super) use any_backend::Any;
use commonware_codec::{Buf, Codec, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_consensus::types::{Height, View};
use commonware_cryptography::{Hasher, Sha256};
use commonware_glue::stateful::db::{
    ManagedDb, Merkleized as _, Reader, Shared, StateSyncDb, Unmerkleized as _,
    p2p as qmdb_resolver,
};
use commonware_parallel::Sequential;
use commonware_runtime::{BufMut, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FixedLogConfig, variable::Config as VariableLogConfig},
    merkle::Location,
    mmr::{self, full::Config as MmrJournalConfig},
    qmdb::{
        self,
        sync::{CompactTarget, Source, Target},
    },
};
use commonware_utils::{NZU64, non_empty_range, range::NonEmptyRange};
#[cfg(any(
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-db-sync"
))]
pub(super) use current_backend::Current;
#[cfg(any(
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-db-sync"
))]
pub(super) use immutable_backend::{ImmutableCompact, ImmutableStandard};
#[cfg(any(
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-db-sync"
))]
pub(super) use keyless_backend::{KeylessCompact, KeylessStandard};
use std::{fmt::Debug, future::Future, num::NonZeroU64};

/// Items per storage blob of the standard adapters' journals.
const MERKLE_BLOB_ITEMS: NonZeroU64 = NZU64!(11);
const LOG_BLOB_ITEMS: NonZeroU64 = NZU64!(7);

/// Witness entries per journal section of the compact adapters.
const WITNESS_SECTION_ITEMS: NonZeroU64 = NZU64!(7);

/// The runtime every database runs under.
type Runtime = deterministic::Context;

/// The resolver mailbox the stateful actor hands a backend's database.
pub(super) type Resolver<B> =
    qmdb_resolver::Mailbox<<B as Backend>::Db, mmr::Family, <B as Backend>::Op, Digest>;

/// Unmerkleized batches handed to the application.
pub(super) type Batches<B> = <<B as Backend>::Db as ManagedDb<Runtime>>::Unmerkleized;

/// Merkleized batches produced by the application.
pub(super) type MerkleizedBatches<B> = <<B as Backend>::Db as ManagedDb<Runtime>>::Merkleized;

/// The adapter's exact sync target.
pub(super) type SyncTarget<B> = <<B as Backend>::Db as ManagedDb<Runtime>>::SyncTarget;

/// The database configuration.
pub(super) type Config<B> = <<B as Backend>::Db as ManagedDb<Runtime>>::Config;

/// The single-database set every node manages.
pub(super) type Databases<B> = Shared<<B as Backend>::Db>;

/// Read-only database handles handed to `finalized`.
pub(super) type Readers<B> = Reader<<B as Backend>::Db>;

/// What a block commits to: the canonical state its execution produced and
/// the exact sync target the stateful actor checks it against, in one shape
/// every backend fills. The canonical root and the sync target's root may
/// coincide, as they do for `any`, or be distinct, as they are for `current`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StateCommitment {
    /// The canonical root of the state, the observable I2 compares.
    pub(super) root: Digest,
    /// The root the sync target names. The operations root for `current`;
    /// the canonical root everywhere else.
    pub(super) sync_root: Digest,
    /// The operation range the sync target covers, ending at the database
    /// size. The compact adapters, whose target is a size alone, cover the
    /// whole database.
    pub(super) range: NonEmptyRange<Location<mmr::Family>>,
}

impl StateCommitment {
    /// A commitment over a journaled adapter's sync target, whose canonical
    /// root is the target's root.
    fn journaled(target: Target<mmr::Family, Digest>) -> Self {
        Self {
            root: target.root,
            sync_root: target.root,
            range: target.range,
        }
    }

    /// A commitment over a compact adapter's sync target, whose canonical
    /// root is the target's root. A compact database always holds at least
    /// its initial commit, so the range is never empty.
    fn compact(target: CompactTarget<mmr::Family, Digest>) -> Self {
        Self {
            root: target.root,
            sync_root: target.root,
            range: NonEmptyRange::new(Location::new(0)..target.size)
                .expect("compact database size is never zero"),
        }
    }

    /// The journaled sync target this commitment names.
    fn journaled_target(&self) -> Target<mmr::Family, Digest> {
        Target::new(self.sync_root, self.range.clone())
    }

    /// The compact sync target this commitment names.
    fn compact_target(&self) -> CompactTarget<mmr::Family, Digest> {
        CompactTarget {
            root: self.sync_root,
            size: self.range.end(),
        }
    }
}

impl Write for StateCommitment {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.sync_root.write(buf);
        self.range.write(buf);
    }
}

impl EncodeSize for StateCommitment {
    fn encode_size(&self) -> usize {
        self.root.encode_size() + self.sync_root.encode_size() + self.range.encode_size()
    }
}

impl Read for StateCommitment {
    type Cfg = ();

    /// Decoding enforces what construction guarantees: a non-empty range of
    /// valid locations, so a commitment off the wire always names a target.
    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let root = Digest::read(buf)?;
        let sync_root = Digest::read(buf)?;
        let range = NonEmptyRange::<Location<mmr::Family>>::read(buf)?;
        if !range.start().is_valid() || !range.end().is_valid() {
            return Err(CodecError::Invalid(
                "StateCommitment",
                "range exceeds the maximum location",
            ));
        }
        Ok(Self {
            root,
            sync_root,
            range,
        })
    }
}

/// The inputs one block's execution is a pure function of.
#[derive(Clone, Debug)]
pub(super) struct Transition {
    /// The view of the block being executed.
    pub(super) view: View,
    /// The parent block's digest.
    pub(super) parent: Digest,
    /// The height of the block being executed.
    pub(super) height: Height,
    /// The state transition to apply. The correct application and the
    /// faulty one differ only here.
    pub(super) bump: u64,
}

impl Transition {
    /// The same block under a different state transition.
    pub(super) fn with_bump(&self, bump: u64) -> Self {
        Self {
            bump,
            ..self.clone()
        }
    }

    /// A key no valid finalized history writes twice: it names the block's
    /// view, parent, and height, all of which are unique along a chain.
    fn fresh_key(&self) -> Digest {
        Sha256::hash(&[
            b"fresh",
            self.parent.as_ref(),
            &self.height.get().to_be_bytes(),
            &self.view.get().to_be_bytes(),
        ])
    }

    /// The value one block records under an append-only workload.
    fn value(&self) -> Digest {
        u64_to_digest(self.height.get().wrapping_add(self.bump))
    }
}

/// One database-adapter class.
pub(super) trait Backend: Clone + Send + Sync + 'static {
    /// Label this backend reports under.
    const NAME: &'static str;

    /// The operation the database serves to state-syncing peers.
    type Op: Codec<Cfg = ()> + Send + Sync + Clone + 'static;

    /// The concrete database.
    type Db: ManagedDb<Runtime>
        + StateSyncDb<Runtime, Resolver<Self>>
        + Source<
            Family = mmr::Family,
            Digest = Digest,
            Op = Self::Op,
            Error = qmdb::Error<mmr::Family>,
        > + Send
        + Sync
        + 'static;

    /// The database configuration for one engine's storage partitions.
    fn config(prefix: &str, page_cache: CacheRef) -> Config<Self>;

    /// The commitment the genesis block carries, matching a freshly
    /// initialized database.
    fn initial() -> StateCommitment;

    /// Execute one block against its batches and merkleize the result.
    fn execute(
        transition: Transition,
        batches: Batches<Self>,
    ) -> impl Future<Output = MerkleizedBatches<Self>> + Send;

    /// The commitment a merkleized batch produces.
    fn commitment(merkleized: &MerkleizedBatches<Self>) -> StateCommitment;

    /// The exact sync target a block commitment names.
    fn sync_target(commitment: &StateCommitment) -> SyncTarget<Self>;

    /// The canonical root of the applied database, the observable I2 compares.
    fn canonical_root(db: &Self::Db) -> Digest;

    /// The oldest operation location the applied database still retains, or
    /// `None` for an adapter that keeps no operation history to observe.
    fn oldest_retained(db: &Self::Db) -> Option<u64>;

    /// The location pruning to this commitment's sync target retains from,
    /// or `None` for an adapter whose retention is not observable.
    fn prune_floor(commitment: &StateCommitment) -> Option<u64>;
}

/// The retention observables of a journaled adapter: its operation log's
/// lower bound, and the sync target's range start pruning retains from.
macro_rules! journaled_retention {
    () => {
        fn oldest_retained(db: &Self::Db) -> Option<u64> {
            Some(db.bounds().start.as_u64())
        }

        fn prune_floor(commitment: &StateCommitment) -> Option<u64> {
            Some(commitment.range.start().as_u64())
        }
    };
}

/// The retention observables of a compact adapter, which keeps only Merkle
/// peaks and witnesses and exposes no operation history.
#[cfg(any(
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-db-sync"
))]
macro_rules! compact_retention {
    () => {
        fn oldest_retained(_db: &Self::Db) -> Option<u64> {
            None
        }

        fn prune_floor(_commitment: &StateCommitment) -> Option<u64> {
            None
        }
    };
}

pub(super) fn u64_to_digest(value: u64) -> Digest {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    Digest::from(bytes)
}

fn digest_to_u64(digest: &Digest) -> u64 {
    let bytes: &[u8] = digest.as_ref();
    u64::from_be_bytes(bytes[..8].try_into().expect("digest is 32 bytes"))
}

/// Configuration of the authenticated journal every standard adapter keeps.
fn merkle_config(prefix: &str, page_cache: CacheRef) -> MmrJournalConfig<Sequential> {
    MmrJournalConfig {
        journal_partition: format!("{prefix}-qmdb-mmr-journal"),
        metadata_partition: format!("{prefix}-qmdb-mmr-metadata"),
        items_per_blob: MERKLE_BLOB_ITEMS,
        write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
        strategy: Sequential,
        page_cache,
    }
}

/// Configuration of the fixed-size operation log every standard adapter keeps.
fn log_config(prefix: &str, page_cache: CacheRef) -> FixedLogConfig {
    FixedLogConfig {
        partition: format!("{prefix}-qmdb-log-journal"),
        items_per_blob: LOG_BLOB_ITEMS,
        page_cache,
        write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    }
}

/// Configuration of the witness journal every compact adapter keeps in place
/// of an operation log.
fn witness_config(prefix: &str, page_cache: CacheRef) -> VariableLogConfig<()> {
    VariableLogConfig {
        partition: format!("{prefix}-qmdb-witness"),
        items_per_section: WITNESS_SECTION_ITEMS,
        compression: None,
        codec_config: (),
        page_cache,
        write_buffer: IO_BUFFER_SIZE,
        replay_buffer: IO_BUFFER_SIZE,
    }
}

mod any_backend {
    //! The `any` adapter: keyed reads and writes over an unordered fixed-value QMDB.

    use super::*;
    use commonware_storage::{qmdb::any, translator::TwoCap};

    /// The `any` adapter.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct Any;

    type Db =
        any::unordered::fixed::Db<mmr::Family, Runtime, Digest, Digest, Sha256, TwoCap, Sequential>;

    impl Backend for Any {
        const NAME: &'static str = "any";
        type Op = any::unordered::fixed::Operation<mmr::Family, Digest, Digest>;
        type Db = Db;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            any::FixedConfig {
                merkle_config: merkle_config(prefix, page_cache.clone()),
                journal_config: log_config(prefix, page_cache),
                translator: TwoCap,
                init_cache: Some(QMDB_INIT_CACHE),
                init_buffer: QMDB_INIT_BUFFER,
                init_concurrency: (),
            }
        }

        fn initial() -> StateCommitment {
            StateCommitment::journaled(<Db as ManagedDb<Runtime>>::initial_sync_target())
        }

        /// Bump a counter and record the height.
        async fn execute(
            transition: Transition,
            mut batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            let counter = Sha256::hash(&[b"counter"]);
            let current = batches
                .get(&counter)
                .await
                .expect("counter read must succeed")
                .map_or(0, |value| digest_to_u64(&value));
            batches = batches.write(counter, Some(u64_to_digest(current + transition.bump)));
            batches = batches.write(
                Sha256::hash(&[&transition.height.get().to_be_bytes()]),
                Some(u64_to_digest(transition.height.get())),
            );
            batches.merkleize().await.expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> StateCommitment {
            let bounds = merkleized.bounds();
            StateCommitment::journaled(Target::new(
                merkleized.root(),
                non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
            ))
        }

        fn sync_target(commitment: &StateCommitment) -> SyncTarget<Self> {
            commitment.journaled_target()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }

        journaled_retention!();
    }
}

#[cfg(any(
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-db-sync"
))]
mod current_backend {
    //! The `current` adapter: the keyed workload over a grafted QMDB whose
    //! canonical root is distinct from the operations root state sync uses.

    use super::*;
    use commonware_cryptography::Digest as _;
    use commonware_storage::{
        qmdb::{any, current},
        translator::TwoCap,
    };

    /// Bitmap chunk size, in bytes.
    const CHUNK_BYTES: usize = 64;

    /// The `current` adapter. The canonical root is what the database-state
    /// invariant compares; the operations root and range are the sync target
    /// the stateful actor checks. They differ, so a block carries and the
    /// application verifies both.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct Current;

    type Db = current::unordered::fixed::Db<
        mmr::Family,
        Runtime,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        CHUNK_BYTES,
        Sequential,
    >;

    impl Backend for Current {
        const NAME: &'static str = "current";
        type Op = any::unordered::fixed::Operation<mmr::Family, Digest, Digest>;
        type Db = Db;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            current::FixedConfig {
                merkle_config: merkle_config(prefix, page_cache.clone()),
                journal_config: log_config(prefix, page_cache),
                grafted_metadata_partition: format!("{prefix}-qmdb-grafted-metadata"),
                translator: TwoCap,
                init_cache: Some(QMDB_INIT_CACHE),
                init_buffer: QMDB_INIT_BUFFER,
                init_concurrency: (),
            }
        }

        /// The genesis block is never verified against its canonical root,
        /// which has no static form for a grafted database, so it carries a
        /// placeholder there and the real initial sync target.
        fn initial() -> StateCommitment {
            let ops = <Db as ManagedDb<Runtime>>::initial_sync_target();
            StateCommitment {
                root: Digest::EMPTY,
                sync_root: ops.root,
                range: ops.range,
            }
        }

        /// Bump a counter and record the height.
        async fn execute(
            transition: Transition,
            mut batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            let counter = Sha256::hash(&[b"counter"]);
            let current = batches
                .get(&counter)
                .await
                .expect("counter read must succeed")
                .map_or(0, |value| digest_to_u64(&value));
            batches = batches.write(counter, Some(u64_to_digest(current + transition.bump)));
            batches = batches.write(
                Sha256::hash(&[&transition.height.get().to_be_bytes()]),
                Some(u64_to_digest(transition.height.get())),
            );
            batches.merkleize().await.expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> StateCommitment {
            StateCommitment {
                root: merkleized.root(),
                sync_root: merkleized.ops_root(),
                range: non_empty_range!(merkleized.sync_boundary(), merkleized.bounds().tip.size),
            }
        }

        fn sync_target(commitment: &StateCommitment) -> SyncTarget<Self> {
            commitment.journaled_target()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }

        journaled_retention!();
    }
}

#[cfg(any(
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-db-sync"
))]
mod immutable_backend {
    //! The immutable adapters: fresh-key inserts only, over the journaled and
    //! the compact database.

    use super::*;
    use commonware_storage::{qmdb::immutable, translator::TwoCap};

    /// The journaled immutable adapter.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct ImmutableStandard;

    type StandardDb =
        immutable::fixed::Db<mmr::Family, Runtime, Digest, Digest, Sha256, TwoCap, Sequential>;

    impl Backend for ImmutableStandard {
        const NAME: &'static str = "immutable-standard";
        type Op = immutable::fixed::Operation<mmr::Family, Digest, Digest>;
        type Db = StandardDb;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            immutable::fixed::Config {
                merkle_config: merkle_config(prefix, page_cache.clone()),
                log: log_config(prefix, page_cache),
                translator: TwoCap,
                init_buffer: QMDB_INIT_BUFFER,
            }
        }

        fn initial() -> StateCommitment {
            StateCommitment::journaled(<StandardDb as ManagedDb<Runtime>>::initial_sync_target())
        }

        /// Insert one key the block is the only writer of. Nothing is read:
        /// the workload must also fit the compact adapter.
        async fn execute(
            transition: Transition,
            batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            batches
                .set(transition.fresh_key(), transition.value())
                .merkleize()
                .await
                .expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> StateCommitment {
            let bounds = merkleized.bounds();
            StateCommitment::journaled(Target::new(
                merkleized.root(),
                non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
            ))
        }

        fn sync_target(commitment: &StateCommitment) -> SyncTarget<Self> {
            commitment.journaled_target()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }

        journaled_retention!();
    }

    /// The compact immutable adapter, which retains only the current Merkle
    /// peaks and supports no historical reads.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct ImmutableCompact;

    type CompactDb =
        immutable::fixed::CompactDb<mmr::Family, Runtime, Digest, Digest, Sha256, Sequential>;

    impl Backend for ImmutableCompact {
        const NAME: &'static str = "immutable-compact";
        type Op = immutable::fixed::Operation<mmr::Family, Digest, Digest>;
        type Db = CompactDb;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            immutable::fixed::CompactConfig {
                strategy: Sequential,
                witness: witness_config(prefix, page_cache),
                commit_codec_config: (),
            }
        }

        fn initial() -> StateCommitment {
            StateCommitment::compact(<CompactDb as ManagedDb<Runtime>>::initial_sync_target())
        }

        /// Insert one key the block is the only writer of.
        async fn execute(
            transition: Transition,
            batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            batches
                .set(transition.fresh_key(), transition.value())
                .merkleize()
                .await
                .expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> StateCommitment {
            StateCommitment::compact(CompactTarget {
                root: merkleized.root(),
                size: merkleized.bounds().tip.size,
            })
        }

        fn sync_target(commitment: &StateCommitment) -> SyncTarget<Self> {
            commitment.compact_target()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }

        compact_retention!();
    }
}

#[cfg(any(
    feature = "stateful-cert-mock-restarts-db",
    feature = "stateful-db-sync"
))]
mod keyless_backend {
    //! The keyless adapters: appends only, over the journaled and the compact
    //! database.

    use super::*;
    use commonware_storage::qmdb::keyless;

    /// The journaled keyless adapter.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct KeylessStandard;

    type StandardDb = keyless::fixed::Db<mmr::Family, Runtime, Digest, Sha256, Sequential>;

    impl Backend for KeylessStandard {
        const NAME: &'static str = "keyless-standard";
        type Op = keyless::fixed::Operation<mmr::Family, Digest>;
        type Db = StandardDb;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            keyless::fixed::Config {
                merkle: merkle_config(prefix, page_cache.clone()),
                log: log_config(prefix, page_cache),
            }
        }

        fn initial() -> StateCommitment {
            StateCommitment::journaled(<StandardDb as ManagedDb<Runtime>>::initial_sync_target())
        }

        /// Append the block's value.
        async fn execute(
            transition: Transition,
            batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            batches
                .append(transition.value())
                .merkleize()
                .await
                .expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> StateCommitment {
            let bounds = merkleized.bounds();
            StateCommitment::journaled(Target::new(
                merkleized.root(),
                non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
            ))
        }

        fn sync_target(commitment: &StateCommitment) -> SyncTarget<Self> {
            commitment.journaled_target()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }

        journaled_retention!();
    }

    /// The compact keyless adapter, which retains only the current Merkle
    /// peaks and supports no historical reads.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct KeylessCompact;

    type CompactDb = keyless::fixed::CompactDb<mmr::Family, Runtime, Digest, Sha256, Sequential>;

    impl Backend for KeylessCompact {
        const NAME: &'static str = "keyless-compact";
        type Op = keyless::fixed::Operation<mmr::Family, Digest>;
        type Db = CompactDb;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            keyless::fixed::CompactConfig {
                strategy: Sequential,
                witness: witness_config(prefix, page_cache),
                commit_codec_config: (),
            }
        }

        fn initial() -> StateCommitment {
            StateCommitment::compact(<CompactDb as ManagedDb<Runtime>>::initial_sync_target())
        }

        /// Append the block's value.
        async fn execute(
            transition: Transition,
            batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            batches
                .append(transition.value())
                .merkleize()
                .await
                .expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> StateCommitment {
            StateCommitment::compact(CompactTarget {
                root: merkleized.root(),
                size: merkleized.bounds().tip.size,
            })
        }

        fn sync_target(commitment: &StateCommitment) -> SyncTarget<Self> {
            commitment.compact_target()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }

        compact_retention!();
    }
}

#[cfg(all(
    test,
    any(
        feature = "stateful-cert-mock-restarts-db",
        feature = "stateful-db-sync"
    )
))]
mod tests {
    use super::*;
    use crate::stateful::{PAGE_CACHE_SIZE, PAGE_SIZE};
    use commonware_codec::{DecodeExt as _, Encode as _};
    use commonware_cryptography::Digest as _;
    use commonware_glue::stateful::db::DatabaseSet;
    use commonware_runtime::{Runner as _, Supervisor as _};

    /// Execute one block against a fresh database of backend `B` through the
    /// same batch, merkleize, and apply path the stateful actor drives, and
    /// return the commitment alongside the applied database's canonical root.
    async fn one_block<B: Backend>(
        context: &deterministic::Context,
    ) -> (StateCommitment, Digest, bool) {
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let databases = Databases::<B>::init(
            context.child("db"),
            B::config(&format!("backend-test-{}", B::NAME), page_cache),
        )
        .await;
        let batches = databases.new_batches().await;
        let merkleized = B::execute(
            Transition {
                view: View::new(1),
                parent: Digest::EMPTY,
                height: Height::new(1),
                bump: 1,
            },
            batches,
        )
        .await;
        let commitment = B::commitment(&merkleized);
        let matches =
            Databases::<B>::matches_sync_targets(&merkleized, &B::sync_target(&commitment));
        databases.apply(merkleized).await;
        let root = B::canonical_root(&*databases.read().await);
        (commitment, root, matches)
    }

    /// `current` commits to two distinct values: the canonical root the
    /// database-state invariant compares, and the operations root and range
    /// the stateful actor checks as the sync target.
    #[test]
    fn current_commits_canonical_and_ops_roots_separately() {
        deterministic::Runner::default().start(|context| async move {
            let (commitment, root, matches) = one_block::<Current>(&context).await;
            assert!(matches, "the ops target must match the merkleized batch");
            assert_ne!(
                commitment.root, commitment.sync_root,
                "the canonical root must differ from the operations root"
            );
            assert_eq!(
                root, commitment.root,
                "the applied database exposes the canonical root"
            );
            assert_ne!(
                <Current as Backend>::sync_target(&commitment).root,
                root,
                "the sync target must not be the canonical root"
            );
        });
    }

    /// For every other backend the canonical root is the sync target's root,
    /// and both survive apply.
    #[test]
    fn other_backends_commit_to_their_sync_target_root() {
        deterministic::Runner::default().start(|context| async move {
            async fn check<B: Backend>(context: &deterministic::Context) {
                let (commitment, root, matches) = one_block::<B>(context).await;
                assert!(matches, "{}", B::NAME);
                assert_eq!(commitment.root, root, "{}", B::NAME);
                assert_eq!(commitment.sync_root, root, "{}", B::NAME);
            }
            check::<Any>(&context).await;
            check::<ImmutableStandard>(&context).await;
            check::<ImmutableCompact>(&context).await;
            check::<KeylessStandard>(&context).await;
            check::<KeylessCompact>(&context).await;
        });
    }

    /// The shared commitment survives the wire: a block decoded off the
    /// network names the same exact sync target the proposer computed.
    #[test]
    fn commitment_round_trips_through_the_codec() {
        deterministic::Runner::default().start(|context| async move {
            async fn check<B: Backend>(context: &deterministic::Context) {
                let (commitment, _, _) = one_block::<B>(context).await;
                let decoded =
                    StateCommitment::decode(commitment.encode()).expect("commitment must decode");
                assert_eq!(decoded, commitment, "{}", B::NAME);
                assert!(
                    B::sync_target(&decoded) == B::sync_target(&commitment),
                    "{}: the decoded commitment must name the same target",
                    B::NAME
                );
            }
            check::<Any>(&context).await;
            check::<Current>(&context).await;
            check::<ImmutableStandard>(&context).await;
            check::<ImmutableCompact>(&context).await;
            check::<KeylessStandard>(&context).await;
            check::<KeylessCompact>(&context).await;
        });
    }

    /// A commitment off the wire never names an empty or out-of-range target,
    /// so converting it to a sync target cannot fail later.
    #[test]
    fn decoding_rejects_invalid_ranges() {
        fn decoded(start: u64, end: u64) -> Result<StateCommitment, CodecError> {
            let mut bytes = Vec::new();
            Digest::EMPTY.write(&mut bytes);
            Digest::EMPTY.write(&mut bytes);
            Location::<mmr::Family>::new(start).write(&mut bytes);
            Location::<mmr::Family>::new(end).write(&mut bytes);
            StateCommitment::decode(bytes)
        }
        assert!(decoded(0, 1).is_ok());
        assert!(decoded(1, 1).is_err());
        assert!(decoded(2, 1).is_err());
        assert!(decoded(0, u64::MAX).is_err());
    }

    /// The genesis commitment matches a freshly initialized database, which is
    /// what lets startup reconciliation accept genesis without a rewind.
    #[test]
    fn initial_commitment_matches_a_fresh_database() {
        deterministic::Runner::default().start(|context| async move {
            async fn check<B: Backend>(context: &deterministic::Context) {
                let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
                let databases = Databases::<B>::init(
                    context.child("db"),
                    B::config(&format!("initial-{}", B::NAME), page_cache),
                )
                .await;
                assert!(
                    databases.committed_targets().await == B::sync_target(&B::initial()),
                    "{}: a fresh database must match the genesis sync target",
                    B::NAME
                );
            }
            check::<Any>(&context).await;
            check::<Current>(&context).await;
            check::<ImmutableStandard>(&context).await;
            check::<ImmutableCompact>(&context).await;
            check::<KeylessStandard>(&context).await;
            check::<KeylessCompact>(&context).await;
        });
    }
}
