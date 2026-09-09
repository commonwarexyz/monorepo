use super::{OperationProof, RangeProof, RuntimeOperationProof, required_chunks};
use crate::{
    merkle::{self, Graftable, Location, conformance::build_test_mem, mem::Mem},
    mmb, mmr,
    qmdb::{
        self, Error,
        current::{db, grafting},
    },
};
use commonware_codec::{Decode as _, Encode as _};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_macros::test_async;
use commonware_parallel::Sequential;
use commonware_utils::{
    Widen,
    bitmap::{Prunable as BitMap, Readable},
    sync::Mutex,
};
use std::collections::{BTreeMap, BTreeSet};

struct PreloadedBitmap<'a> {
    bitmap: &'a BitMap<1>,
    chunks: BTreeMap<usize, [u8; 1]>,
    reads: Mutex<BTreeSet<usize>>,
}

impl Readable<1> for PreloadedBitmap<'_> {
    fn complete_chunks(&self) -> usize {
        self.bitmap.complete_chunks()
    }

    fn get_chunk(&self, chunk: usize) -> [u8; 1] {
        self.reads.lock().insert(chunk);
        self.chunks[&chunk]
    }

    fn last_chunk(&self) -> ([u8; 1], u64) {
        let (_, bits) = self.bitmap.last_chunk();
        let chunk = BitMap::<1>::to_chunk_index(self.len() - 1);
        (self.get_chunk(chunk), bits)
    }

    fn pruned_chunks(&self) -> usize {
        self.bitmap.pruned_chunks()
    }

    fn len(&self) -> u64 {
        self.bitmap.len()
    }
}

async fn fixture<F: Graftable>(
    leaves: u64,
    pruned: u64,
) -> (BitMap<1>, Mem<F, Digest>, Mem<F, Digest>) {
    let hasher = qmdb::hasher::<Sha256>();
    let height = grafting::height::<1>();
    let ops = build_test_mem(&hasher, Mem::<F, Digest>::new(), leaves);
    let mut bitmap = BitMap::<1>::new();
    for loc in 0..leaves {
        bitmap.push(loc >= pruned * 8);
    }
    let chunks = (0..grafting::graftable_chunks::<F>(leaves, height))
        .map(|chunk| (chunk as usize, *bitmap.get_chunk(chunk as usize)));
    let mut digests =
        db::compute_grafted_leaves::<F, Sha256, Sequential, 1>(&ops, chunks, &Sequential)
            .await
            .unwrap();
    digests.sort_unstable_by_key(|(chunk, _)| *chunk);
    let mut grafted = Mem::<F, Digest>::new();
    if !digests.is_empty() {
        let mut batch = grafted.new_batch();
        for (_, digest) in digests {
            batch = batch.add_leaf_digest(digest);
        }
        let hasher = grafting::GraftedHasher::<F, _>::new(hasher, height);
        let batch = batch.merkleize(&grafted, &hasher);
        grafted.apply_batch(&batch).unwrap();
    }
    bitmap.prune_to_bit(pruned * 8);
    (bitmap, ops, grafted)
}

async fn check_constructor_reads<F: Graftable>() {
    for leaves in [1, 7, 8, 9, 10, 11, 16, 17, 18, 24, 25] {
        let graftable = grafting::graftable_chunks::<F>(leaves, grafting::height::<1>());
        for pruned in 0..=graftable {
            let floor = Location::<F>::new(pruned * 8);
            if *floor == leaves {
                continue;
            }
            let (bitmap, ops, grafted) = fixture::<F>(leaves, pruned).await;
            let hasher = qmdb::hasher::<Sha256>();
            let ops_root = ops.root(&hasher, 0).unwrap();
            let storage =
                grafting::Storage::<F, Sha256, _, _>::new(&grafted, grafting::height::<1>(), &ops);
            let root = db::compute_db_root::<F, Sha256, _, _, 1>(
                &bitmap,
                &storage,
                Location::new(leaves),
                db::partial_chunk::<_, 1>(&bitmap),
                floor,
                &ops_root,
            )
            .await
            .unwrap();
            for location in
                core::iter::once(None).chain((*floor..leaves).map(|loc| Some(Location::new(loc))))
            {
                let required =
                    required_chunks::<F, 1>(Location::new(leaves), bitmap.len(), pruned, location)
                        .unwrap()
                        .collect::<Vec<_>>();
                assert!(required.windows(2).all(|pair| pair[0] < pair[1]));
                let preloaded = PreloadedBitmap {
                    bitmap: &bitmap,
                    chunks: required
                        .iter()
                        .map(|&chunk| (chunk as usize, *bitmap.get_chunk(chunk as usize)))
                        .collect(),
                    reads: Mutex::new(BTreeSet::new()),
                };
                if let Some(loc) = location {
                    let proof = OperationProof::<F, Digest, 1>::new::<Sha256, _>(
                        &preloaded, &storage, floor, loc, ops_root,
                    )
                    .await
                    .unwrap();
                    assert!(
                        proof.verify::<Sha256, _>(hasher.digest(&(*loc).to_be_bytes()), &root,)
                    );
                    let proof =
                        RuntimeOperationProof::<F, Digest>::decode_cfg(proof.encode(), &(1, 64))
                            .unwrap();
                    assert!(proof.verify::<Sha256, _>(hasher.digest(&(*loc).to_be_bytes()), &root));
                } else {
                    let proof = RangeProof::new::<Sha256, _, 1>(
                        &preloaded,
                        &storage,
                        floor,
                        floor..Location::new(leaves),
                        ops_root,
                    )
                    .await
                    .unwrap();
                    let elements = (*floor..leaves)
                        .map(|loc| hasher.digest(&loc.to_be_bytes()))
                        .collect::<Vec<_>>();
                    let chunks = (pruned..leaves.div_ceil(8))
                        .map(|chunk| *bitmap.get_chunk(chunk as usize))
                        .collect::<Vec<_>>();
                    assert!(proof.verify::<Sha256, _, 1>(floor, &elements, &chunks, &root));
                    assert!(
                        proof.verify_with_chunk_size::<Sha256, _>(
                            floor, &elements, &chunks, 1, &root,
                        )
                    );
                }
                let read_chunks = preloaded
                    .reads
                    .into_inner()
                    .into_iter()
                    .map(Widen::widen)
                    .collect::<Vec<_>>();
                assert_eq!(
                    read_chunks, required,
                    "leaves={leaves}, pruned={pruned}, location={location:?}",
                );
            }
        }
    }
}

#[test_async]
async fn required_chunks_match_constructor_reads() {
    check_constructor_reads::<mmr::Family>().await;
    check_constructor_reads::<mmb::Family>().await;
}

#[test]
fn required_chunks_boundary_sets() {
    for (leaves, mmr, mmb) in [
        (0, vec![], vec![]),
        (1, vec![0], vec![0]),
        (7, vec![0], vec![0]),
        (8, vec![], vec![0]),
        (9, vec![1], vec![0, 1]),
        (10, vec![1], vec![0, 1]),
        (11, vec![1], vec![1]),
        (16, vec![], vec![1]),
        (17, vec![2], vec![1, 2]),
        (18, vec![2], vec![1, 2]),
        (24, vec![], vec![2]),
        (25, vec![3], vec![2, 3]),
    ] {
        assert_eq!(
            required_chunks::<mmr::Family, 1>(Location::new(leaves), leaves, 0, None)
                .unwrap()
                .collect::<Vec<_>>(),
            mmr
        );
        assert_eq!(
            required_chunks::<mmb::Family, 1>(Location::new(leaves), leaves, 0, None)
                .unwrap()
                .collect::<Vec<_>>(),
            mmb
        );
    }
    assert!(
        required_chunks::<mmr::Family, 1>(Location::new(16), 16, 2, None)
            .unwrap()
            .next()
            .is_none()
    );
}

fn check_invalid_metadata<F: Graftable>() {
    for (ops_leaves, bitmap_len, loc) in [(0, 0, 0), (16, 16, 16), (8, 9, 8), (9, 8, 8)] {
        assert!(matches!(
            required_chunks::<F, 1>(Location::new(ops_leaves), bitmap_len, 0, Some(Location::new(loc))),
            Err(Error::Merkle(merkle::Error::RangeOutOfBounds(found))) if *found == loc
        ));
    }
    assert!(matches!(
        required_chunks::<F, 1>(Location::new(16), 16, 1, Some(Location::new(7))),
        Err(Error::OperationPruned(loc)) if *loc == 7
    ));
    assert!(matches!(
        required_chunks::<F, 1>(Location::new(0), 24, 0, None),
        Err(Error::DataCorrupted("multiple pending bitmap chunks"))
    ));
    assert!(matches!(
        required_chunks::<F, 1>(Location::new(8), 8, 2, None),
        Err(Error::DataCorrupted(
            "pruned chunks exceed graftable chunks"
        ))
    ));
}

#[test]
fn required_chunks_reject_invalid_metadata() {
    check_invalid_metadata::<mmr::Family>();
    check_invalid_metadata::<mmb::Family>();
    assert!(matches!(
        required_chunks::<mmb::Family, 1>(Location::new(8), 8, 1, None),
        Err(Error::DataCorrupted(
            "pruned chunks exceed graftable chunks"
        ))
    ));
}
