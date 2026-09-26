//! Proof fixtures from committed, pruned, and reopened ordered Current databases.

use super::{Hash, Operation, OperationOutput, TreeKind, Uint256, key, leaf};
use alloy_sol_macro::sol;
use alloy_sol_types::SolValue;
use clap::Args;
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher, Keccak256, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic};
use commonware_storage::{
    journal::contiguous::fixed::Config as JournalConfig,
    merkle::{Graftable, PendingChunk as _, full::Config as MerkleConfig, mmb, mmr},
    qmdb::{
        self,
        any::{ordered::fixed::Update, value::FixedEncoding},
        current::{
            FixedConfig,
            ordered::{fixed::Db, proof::ExclusionProof},
            proof::constant::OperationProof,
        },
    },
    translator::OneCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize, bitmap::Readable as _, sequence::FixedBytes};
use std::time::Duration;

type Database<F, H> =
    Db<F, deterministic::Context, FixedBytes<32>, FixedBytes<32>, H, OneCap, 32, Sequential>;

sol! {
    struct LifecycleOutput {
        OperationOutput before;
        OperationOutput after;
        OperationOutput excluded;
        OperationOutput empty;
        bytes32 excludedKey;
        bytes32 emptyKey;
        uint256 retainedStart;
    }
}

#[derive(Args)]
pub(crate) struct LifecycleArgs {
    #[arg(long)]
    seed: u64,
    #[arg(long, value_enum)]
    family: TreeKind,
}

impl LifecycleArgs {
    pub(super) fn execute(self, hash: Hash) -> Result<Vec<u8>, String> {
        match (self.family, hash) {
            (TreeKind::Mmr, Hash::Keccak256) => generate::<mmr::Family, Keccak256>(self.seed),
            (TreeKind::Mmr, Hash::Sha256) => generate::<mmr::Family, Sha256>(self.seed),
            (TreeKind::Mmb, Hash::Keccak256) => generate::<mmb::Family, Keccak256>(self.seed),
            (TreeKind::Mmb, Hash::Sha256) => generate::<mmb::Family, Sha256>(self.seed),
        }
    }
}

fn config(context: &deterministic::Context) -> FixedConfig<OneCap, Sequential> {
    let page_cache = CacheRef::from_pooler(context, NZU16!(4096), NZUsize!(8));
    FixedConfig {
        merkle_config: MerkleConfig {
            journal_partition: "lifecycle-merkle-journal".into(),
            metadata_partition: "lifecycle-merkle-metadata".into(),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
            node_cache_size: None,
        },
        journal_config: JournalConfig {
            partition: "lifecycle-operations".into(),
            items_per_blob: NZU64!(7),
            page_cache,
            write_buffer: NZUsize!(1024),
            replay_buffer: NZUsize!(1024),
        },
        grafted_metadata_partition: "lifecycle-grafted-metadata".into(),
        translator: OneCap,
        init_cache: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(4096),
        init_concurrency: (),
    }
}

/// Export the production proof's fields without reconstructing its root or activity bitmap.
fn output<F: Graftable, D: Digest>(
    root: D,
    proof: &OperationProof<F, D, 32>,
    operation: Operation<F>,
) -> OperationOutput {
    let bytes32 = |digest: D| -> [u8; 32] { digest.as_ref().try_into().unwrap() };
    let range = &proof.range_proof;
    OperationOutput {
        root: bytes32(root).into(),
        leaves: Uint256::from(*range.proof.leaves),
        location: Uint256::from(*proof.loc),
        inactivePeaks: Uint256::from(range.proof.inactive_peaks),
        chunk: proof.chunk.to_vec().into(),
        opsRoot: bytes32(range.ops_root).into(),
        pending: range
            .pending_chunk_digest
            .as_ref()
            .map_or([0; 32], |d| bytes32(*d))
            .into(),
        partial: range.partial_chunk_digest.map_or([0; 32], bytes32).into(),
        digests: range
            .proof
            .digests
            .iter()
            .map(|d| bytes32(*d).into())
            .collect(),
        operation: operation.encode().to_vec().into(),
    }
}

async fn membership<F: Graftable, H: Hasher>(
    db: &Database<F, H>,
    value: FixedBytes<32>,
) -> Result<OperationOutput, qmdb::Error<F>> {
    assert_eq!(db.get(&key(2)).await?.as_ref(), Some(&value));
    let proof = db.key_value_proof(key(2)).await?;
    assert!(proof.verify::<H, FixedEncoding<FixedBytes<32>>>(key(2), value.clone(), &db.root()));
    Ok(output(
        db.root(),
        &proof.proof,
        Operation::Update(Update {
            key: key(2),
            value,
            next_key: proof.next_key,
        }),
    ))
}

async fn exclusion<F: Graftable, H: Hasher>(
    db: &Database<F, H>,
    query: FixedBytes<32>,
) -> Result<OperationOutput, qmdb::Error<F>> {
    assert_eq!(db.get(&query).await?, None);
    let proof = db.exclusion_proof(&query).await?;
    assert!(proof.verify::<H>(&query, &db.root()));
    let (proof, operation) = match proof {
        ExclusionProof::KeyValue(proof, update) => (proof, Operation::Update(update)),
        ExclusionProof::Commit(proof, metadata) => {
            let operation = Operation::CommitFloor(metadata, proof.loc);
            (proof, operation)
        }
    };
    Ok(output(db.root(), &proof, operation))
}

/// Advance the inactive prefix beyond a settled bitmap chunk before pruning and reopening.
fn generate<F: Graftable, H: Hasher>(seed: u64) -> Result<Vec<u8>, String> {
    const OVERWRITES: u64 = 384;
    deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30))),
    )
    .start(|context| async move {
        let initial = FixedBytes::new(leaf(seed, 0));
        let db = Database::<F, H>::init(context.child("initial"), config(&context), None).await?;
        let batch = db
            .new_batch()
            .write(key(2), Some(initial.clone()))
            .write(key(4), Some(FixedBytes::new(leaf(seed, 1))))
            .write(key(6), Some(FixedBytes::new(leaf(seed, 2))))
            .merkleize(&db, None)
            .await?;
        let (db, _) = db.apply_batch(batch).await?;
        let db = db.commit().await?;
        let before = membership(&db, initial).await?;
        let root = db.root();
        drop(db);

        let mut db =
            Database::<F, H>::init(context.child("overwrite"), config(&context), None).await?;
        assert_eq!(db.root(), root);
        for round in 0..OVERWRITES {
            let batch = db
                .new_batch()
                .write(key(2), Some(FixedBytes::new(leaf(seed, round + 3))))
                .write(key(4), None)
                .merkleize(&db, None)
                .await?;
            (db, _) = db.apply_batch(batch).await?;
        }
        let db = db.commit().await?;
        let root = db.root();
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await?;
        assert_eq!(db.root(), root);
        assert!(db.bitmap().pruned_chunks() > 0);
        let retained_start = *db.bounds().start;
        assert!(retained_start > 0);
        drop(db);

        let db = Database::<F, H>::init(context.child("pruned"), config(&context), None).await?;
        assert_eq!(db.root(), root);
        assert_eq!(*db.bounds().start, retained_start);
        assert_eq!(db.get(&key(6)).await?, Some(FixedBytes::new(leaf(seed, 2))));
        let after = membership(&db, FixedBytes::new(leaf(seed, OVERWRITES + 2))).await?;
        let excluded = exclusion(&db, key(4)).await?;
        let batch = db
            .new_batch()
            .write(key(2), None)
            .write(key(6), None)
            .merkleize(&db, Some(FixedBytes::new(leaf(seed, OVERWRITES + 3))))
            .await?;
        let (db, _) = db.apply_batch(batch).await?;
        let db = db.commit().await?;
        assert!(db.is_empty());
        let root = db.root();
        drop(db);

        let db = Database::<F, H>::init(context.child("empty"), config(&context), None).await?;
        assert_eq!(db.root(), root);
        assert!(db.is_empty());
        assert_eq!(
            db.get_metadata().await?,
            Some(FixedBytes::new(leaf(seed, OVERWRITES + 3)))
        );
        let empty = exclusion(&db, key(2)).await?;
        db.destroy().await?;
        Ok::<_, qmdb::Error<F>>(
            LifecycleOutput {
                before,
                after,
                excluded,
                empty,
                excludedKey: <[u8; 32]>::try_from(key(4).as_ref()).unwrap().into(),
                emptyKey: <[u8; 32]>::try_from(key(2).as_ref()).unwrap().into(),
                retainedStart: Uint256::from(retained_start),
            }
            .abi_encode(),
        )
    })
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_lifecycle_is_deterministic() {
        for family in [TreeKind::Mmr, TreeKind::Mmb] {
            for hash in [Hash::Keccak256, Hash::Sha256] {
                let run = || LifecycleArgs { seed: 71, family }.execute(hash).unwrap();
                let encoded = run();
                assert_eq!(encoded, run());
                let fixture = LifecycleOutput::abi_decode_validate(&encoded).unwrap();
                assert_ne!(fixture.before.root, fixture.after.root);
                assert_eq!(fixture.after.root, fixture.excluded.root);
                assert_ne!(fixture.after.root, fixture.empty.root);
                assert!(fixture.retainedStart > Uint256::ZERO);
                assert_eq!(fixture.before.operation[0], 0xd2);
                assert_eq!(fixture.empty.operation[0], 0xd3);
            }
        }
    }
}
