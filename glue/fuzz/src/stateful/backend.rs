//! Statically dispatched database backends for the database-adapter matrix.
//!
//! A backend owns only what differs between adapter classes: the concrete
//! database type and its configuration, the commitment a block carries, the
//! valid workload one block applies to a batch, the extraction of that
//! commitment from a merkleized batch, its conversion to the adapter's exact
//! sync target, and the canonical root of the applied database. Everything
//! else (runtime setup, networking, scheduling, waiters, reporting, and the
//! invariants) is shared and monomorphized per backend, so no trait object
//! sits on the exercised path.
//!
//! Every backend uses a fixed-size QMDB variant, which covers the adapter
//! class without multiplying the search space.

use super::{Ctx, Digest, IO_BUFFER_SIZE, QMDB_INIT_BUFFER, QMDB_INIT_CACHE};
pub(super) use any_backend::Any;
#[cfg(any(test, feature = "stateful-probe"))]
pub(super) use any_backend::AnyCommitment;
use commonware_codec::{Codec, EncodeSize, Read, Write};
use commonware_consensus::types::Height;
use commonware_cryptography::{Hasher, Sha256};
use commonware_glue::stateful::db::{
    ManagedDb, Merkleized as _, Reader, Shared, StateSyncDb, Unmerkleized as _,
    p2p as qmdb_resolver,
};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::{fixed::Config as FixedLogConfig, variable::Config as VariableLogConfig},
    mmr::{self, full::Config as MmrJournalConfig},
    qmdb::{self, sync::Source},
};
use commonware_utils::NZU64;
#[cfg(feature = "stateful-cert-mock-restarts-db")]
pub(super) use current_backend::Current;
#[cfg(feature = "stateful-cert-mock-restarts-db")]
pub(super) use immutable_backend::{ImmutableCompact, ImmutableStandard};
#[cfg(feature = "stateful-cert-mock-restarts-db")]
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
/// the exact sync target the stateful actor checks it against. The two may
/// coincide, as they do for `any`, or be distinct, as they are for `current`.
pub(super) trait Commitment:
    Clone + Debug + PartialEq + Eq + Send + Sync + Write + EncodeSize + Read<Cfg = ()> + 'static
{
}

impl<T> Commitment for T where
    T: Clone + Debug + PartialEq + Eq + Send + Sync + Write + EncodeSize + Read<Cfg = ()> + 'static
{
}

/// The inputs one block's execution is a pure function of.
pub(super) struct Transition<'a> {
    /// The consensus context of the block being executed.
    pub(super) context: &'a Ctx,
    /// The parent block's digest.
    pub(super) parent: Digest,
    /// The height of the block being executed.
    pub(super) height: Height,
    /// The state transition to apply. The correct application and the
    /// faulty one differ only here.
    pub(super) bump: u64,
}

impl Transition<'_> {
    /// A key no valid finalized history writes twice: it names the block's
    /// context, parent, and height, all of which are unique along a chain.
    fn fresh_key(&self) -> Digest {
        Sha256::hash(&[
            b"fresh",
            self.parent.as_ref(),
            &self.height.get().to_be_bytes(),
            &self.context.round.view().get().to_be_bytes(),
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

    /// What a block commits to.
    type Commitment: Commitment;

    /// The database configuration for one engine's storage partitions.
    fn config(prefix: &str, page_cache: CacheRef) -> Config<Self>;

    /// The commitment the genesis block carries, matching a freshly
    /// initialized database.
    fn initial() -> Self::Commitment;

    /// Execute one block against its batches and merkleize the result.
    fn execute(
        transition: Transition<'_>,
        batches: Batches<Self>,
    ) -> impl Future<Output = MerkleizedBatches<Self>> + Send;

    /// The commitment a merkleized batch produces.
    fn commitment(merkleized: &MerkleizedBatches<Self>) -> Self::Commitment;

    /// The exact sync target a block commitment names.
    fn sync_target(commitment: &Self::Commitment) -> SyncTarget<Self>;

    /// The canonical root of the applied database, the observable I2 compares.
    fn canonical_root(db: &Self::Db) -> Digest;
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
    use commonware_storage::{
        qmdb::{any, sync::Target},
        translator::TwoCap,
    };
    use commonware_utils::non_empty_range;

    /// The canonical root and the sync range, which for `any` is the sync
    /// target itself.
    pub(in super::super) type AnyCommitment = Target<mmr::Family, Digest>;

    /// The `any` adapter.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct Any;

    type Db =
        any::unordered::fixed::Db<mmr::Family, Runtime, Digest, Digest, Sha256, TwoCap, Sequential>;

    impl Backend for Any {
        const NAME: &'static str = "any";
        type Op = any::unordered::fixed::Operation<mmr::Family, Digest, Digest>;
        type Db = Db;
        type Commitment = AnyCommitment;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            any::FixedConfig {
                merkle_config: merkle_config(prefix, page_cache.clone()),
                journal_config: log_config(prefix, page_cache),
                translator: TwoCap,
                init_cache_size: Some(QMDB_INIT_CACHE),
                init_buffer: QMDB_INIT_BUFFER,
                init_concurrency: (),
            }
        }

        fn initial() -> Self::Commitment {
            <Db as ManagedDb<Runtime>>::initial_sync_target()
        }

        /// Bump a counter and record the height.
        async fn execute(
            transition: Transition<'_>,
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

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> Self::Commitment {
            let bounds = merkleized.bounds();
            Target::new(
                merkleized.root(),
                non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
            )
        }

        fn sync_target(commitment: &Self::Commitment) -> SyncTarget<Self> {
            commitment.clone()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }
    }
}

#[cfg(feature = "stateful-cert-mock-restarts-db")]
mod current_backend {
    //! The `current` adapter: the keyed workload over a grafted QMDB whose
    //! canonical root is distinct from the operations root state sync uses.

    use super::*;
    use commonware_codec::{Buf, Error as CodecError, ReadExt as _};
    use commonware_cryptography::Digest as _;
    use commonware_runtime::BufMut;
    use commonware_storage::{
        qmdb::{any, current, sync::Target},
        translator::TwoCap,
    };
    use commonware_utils::non_empty_range;

    /// Bitmap chunk size, in bytes.
    const CHUNK_BYTES: usize = 64;

    /// What a `current` block commits to. The canonical root is what the
    /// database-state invariant compares; the operations root and range are
    /// the sync target the stateful actor checks. They differ, so a block
    /// carries and the application verifies both.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(in super::super) struct CurrentCommitment {
        pub(in super::super) root: Digest,
        pub(in super::super) ops: Target<mmr::Family, Digest>,
    }

    impl Write for CurrentCommitment {
        fn write(&self, buf: &mut impl BufMut) {
            self.root.write(buf);
            self.ops.write(buf);
        }
    }

    impl EncodeSize for CurrentCommitment {
        fn encode_size(&self) -> usize {
            self.root.encode_size() + self.ops.encode_size()
        }
    }

    impl Read for CurrentCommitment {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
            Ok(Self {
                root: Digest::read(buf)?,
                ops: Target::read(buf)?,
            })
        }
    }

    /// The `current` adapter.
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
        type Commitment = CurrentCommitment;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            current::FixedConfig {
                merkle_config: merkle_config(prefix, page_cache.clone()),
                journal_config: log_config(prefix, page_cache),
                grafted_metadata_partition: format!("{prefix}-qmdb-grafted-metadata"),
                translator: TwoCap,
                init_cache_size: Some(QMDB_INIT_CACHE),
                init_buffer: QMDB_INIT_BUFFER,
                init_concurrency: (),
            }
        }

        /// The genesis block is never verified against its canonical root,
        /// which has no static form for a grafted database, so it carries a
        /// placeholder there and the real initial sync target.
        fn initial() -> Self::Commitment {
            CurrentCommitment {
                root: Digest::EMPTY,
                ops: <Db as ManagedDb<Runtime>>::initial_sync_target(),
            }
        }

        /// Bump a counter and record the height.
        async fn execute(
            transition: Transition<'_>,
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

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> Self::Commitment {
            CurrentCommitment {
                root: merkleized.root(),
                ops: Target::new(
                    merkleized.ops_root(),
                    non_empty_range!(merkleized.sync_boundary(), merkleized.bounds().tip.size),
                ),
            }
        }

        fn sync_target(commitment: &Self::Commitment) -> SyncTarget<Self> {
            commitment.ops.clone()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }
    }
}

#[cfg(feature = "stateful-cert-mock-restarts-db")]
mod immutable_backend {
    //! The immutable adapters: fresh-key inserts only, over the journaled and
    //! the compact database.

    use super::*;
    use commonware_storage::{
        qmdb::{
            immutable,
            sync::{CompactTarget, Target},
        },
        translator::TwoCap,
    };
    use commonware_utils::non_empty_range;

    /// The journaled immutable adapter.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct ImmutableStandard;

    type StandardDb =
        immutable::fixed::Db<mmr::Family, Runtime, Digest, Digest, Sha256, TwoCap, Sequential>;

    impl Backend for ImmutableStandard {
        const NAME: &'static str = "immutable-standard";
        type Op = immutable::fixed::Operation<mmr::Family, Digest, Digest>;
        type Db = StandardDb;
        type Commitment = Target<mmr::Family, Digest>;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            immutable::fixed::Config {
                merkle_config: merkle_config(prefix, page_cache.clone()),
                log: log_config(prefix, page_cache),
                translator: TwoCap,
                init_buffer: QMDB_INIT_BUFFER,
            }
        }

        fn initial() -> Self::Commitment {
            <StandardDb as ManagedDb<Runtime>>::initial_sync_target()
        }

        /// Insert one key the block is the only writer of. Nothing is read:
        /// the workload must also fit the compact adapter.
        async fn execute(
            transition: Transition<'_>,
            batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            batches
                .set(transition.fresh_key(), transition.value())
                .merkleize()
                .await
                .expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> Self::Commitment {
            let bounds = merkleized.bounds();
            Target::new(
                merkleized.root(),
                non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
            )
        }

        fn sync_target(commitment: &Self::Commitment) -> SyncTarget<Self> {
            commitment.clone()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }
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
        type Commitment = CompactTarget<mmr::Family, Digest>;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            immutable::fixed::CompactConfig {
                strategy: Sequential,
                witness: witness_config(prefix, page_cache),
                commit_codec_config: (),
            }
        }

        fn initial() -> Self::Commitment {
            <CompactDb as ManagedDb<Runtime>>::initial_sync_target()
        }

        /// Insert one key the block is the only writer of.
        async fn execute(
            transition: Transition<'_>,
            batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            batches
                .set(transition.fresh_key(), transition.value())
                .merkleize()
                .await
                .expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> Self::Commitment {
            CompactTarget {
                root: merkleized.root(),
                size: merkleized.bounds().tip.size,
            }
        }

        fn sync_target(commitment: &Self::Commitment) -> SyncTarget<Self> {
            commitment.clone()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }
    }
}

#[cfg(feature = "stateful-cert-mock-restarts-db")]
mod keyless_backend {
    //! The keyless adapters: appends only, over the journaled and the compact
    //! database.

    use super::*;
    use commonware_storage::qmdb::{
        keyless,
        sync::{CompactTarget, Target},
    };
    use commonware_utils::non_empty_range;

    /// The journaled keyless adapter.
    #[derive(Clone, Copy, Debug, Default)]
    pub(in super::super) struct KeylessStandard;

    type StandardDb = keyless::fixed::Db<mmr::Family, Runtime, Digest, Sha256, Sequential>;

    impl Backend for KeylessStandard {
        const NAME: &'static str = "keyless-standard";
        type Op = keyless::fixed::Operation<mmr::Family, Digest>;
        type Db = StandardDb;
        type Commitment = Target<mmr::Family, Digest>;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            keyless::fixed::Config {
                merkle: merkle_config(prefix, page_cache.clone()),
                log: log_config(prefix, page_cache),
            }
        }

        fn initial() -> Self::Commitment {
            <StandardDb as ManagedDb<Runtime>>::initial_sync_target()
        }

        /// Append the block's value.
        async fn execute(
            transition: Transition<'_>,
            batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            batches
                .append(transition.value())
                .merkleize()
                .await
                .expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> Self::Commitment {
            let bounds = merkleized.bounds();
            Target::new(
                merkleized.root(),
                non_empty_range!(bounds.inactivity_floor, bounds.tip.size),
            )
        }

        fn sync_target(commitment: &Self::Commitment) -> SyncTarget<Self> {
            commitment.clone()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }
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
        type Commitment = CompactTarget<mmr::Family, Digest>;

        fn config(prefix: &str, page_cache: CacheRef) -> Config<Self> {
            keyless::fixed::CompactConfig {
                strategy: Sequential,
                witness: witness_config(prefix, page_cache),
                commit_codec_config: (),
            }
        }

        fn initial() -> Self::Commitment {
            <CompactDb as ManagedDb<Runtime>>::initial_sync_target()
        }

        /// Append the block's value.
        async fn execute(
            transition: Transition<'_>,
            batches: Batches<Self>,
        ) -> MerkleizedBatches<Self> {
            batches
                .append(transition.value())
                .merkleize()
                .await
                .expect("merkleize must succeed")
        }

        fn commitment(merkleized: &MerkleizedBatches<Self>) -> Self::Commitment {
            CompactTarget {
                root: merkleized.root(),
                size: merkleized.bounds().tip.size,
            }
        }

        fn sync_target(commitment: &Self::Commitment) -> SyncTarget<Self> {
            commitment.clone()
        }

        fn canonical_root(db: &Self::Db) -> Digest {
            db.root()
        }
    }
}

#[cfg(all(test, feature = "stateful-cert-mock-restarts-db"))]
mod tests {
    use super::*;
    use crate::stateful::{PAGE_CACHE_SIZE, PAGE_SIZE, PublicKey};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{Digest as _, Signer as _, ed25519};
    use commonware_glue::stateful::db::DatabaseSet;
    use commonware_runtime::{Runner as _, Supervisor as _};

    fn context_at(view: u64) -> Ctx {
        Context {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader: ed25519::PrivateKey::from_seed(0).public_key(),
            parent: (View::new(view.saturating_sub(1)), Digest::EMPTY),
        }
    }

    /// Execute one block against a fresh database of backend `B` through the
    /// same batch, merkleize, and apply path the stateful actor drives, and
    /// return the commitment alongside the applied database's canonical root.
    async fn one_block<B: Backend>(
        context: &deterministic::Context,
    ) -> (B::Commitment, Digest, bool) {
        let page_cache = CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE);
        let databases = Databases::<B>::init(
            context.child("db"),
            B::config(&format!("backend-test-{}", B::NAME), page_cache),
        )
        .await;
        let batches = databases.new_batches().await;
        let ctx = context_at(1);
        let merkleized = B::execute(
            Transition {
                context: &ctx,
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
                commitment.root, commitment.ops.root,
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
            let (commitment, root, matches) = one_block::<Any>(&context).await;
            assert!(matches);
            assert_eq!(commitment.root, root);
            let (commitment, root, matches) = one_block::<ImmutableStandard>(&context).await;
            assert!(matches);
            assert_eq!(commitment.root, root);
            let (commitment, root, matches) = one_block::<ImmutableCompact>(&context).await;
            assert!(matches);
            assert_eq!(commitment.root, root);
            let (commitment, root, matches) = one_block::<KeylessStandard>(&context).await;
            assert!(matches);
            assert_eq!(commitment.root, root);
            let (commitment, root, matches) = one_block::<KeylessCompact>(&context).await;
            assert!(matches);
            assert_eq!(commitment.root, root);
        });
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

    /// The genesis leader is what the cluster's genesis block names.
    const _: fn() -> PublicKey = || ed25519::PrivateKey::from_seed(0).public_key();
}
