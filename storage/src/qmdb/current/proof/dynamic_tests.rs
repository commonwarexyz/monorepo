use super::{constant, dynamic, tests::current_range_proof_fixture};
use crate::{
    merkle::{Graftable, Location},
    mmb, mmr,
};
use bytes::Bytes;
use commonware_codec::{Decode as _, Encode as _, EncodeSize as _};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_macros::test_async;

fn invalid_chunk_sizes() -> impl Iterator<Item = usize> {
    [0, 3, usize::MAX, 1 << (usize::BITS - 1)]
        .into_iter()
        .chain(usize::try_from(1u64 << 60).ok())
}

async fn check_dynamic_proofs<F: Graftable, const N: usize>() {
    let chunk_bits = (N * 8) as u64;
    let height = chunk_bits.trailing_zeros() as u64;
    for leaves in [
        chunk_bits - 1,
        chunk_bits,
        chunk_bits + 1,
        chunk_bits + height,
        chunk_bits * 2,
        chunk_bits * 2 + 2,
    ] {
        let start = Location::<F>::new(chunk_bits - 2);
        let (_, proof, operations, chunks, root, _) =
            current_range_proof_fixture::<F, N>(leaves, start..Location::new(leaves)).await;
        assert!(proof.verify::<Sha256, _, N>(start, &operations, &chunks, &root));
        let slices = chunks.iter().map(<[u8; N]>::as_slice).collect::<Vec<_>>();
        assert!(proof.verify_with_chunk_size::<Sha256, _>(start, &operations, &slices, N, &root));
        assert!(!proof.verify_with_chunk_size::<Sha256, _>(
            start,
            &operations,
            &slices,
            N,
            &Sha256::hash(&[b"wrong root"]),
        ));

        for loc in [start, Location::new(leaves - 1)] {
            let (_, range_proof, operations, chunks, root, _) =
                current_range_proof_fixture::<F, N>(leaves, loc..loc + 1).await;
            let native = constant::OperationProof::<F, Digest, N> {
                loc,
                chunk: chunks[0],
                range_proof,
            };
            assert!(native.verify::<Sha256, _>(operations[0], &root));
            let encoded = native.encode();
            let max_digests = native.range_proof.proof.digests.len();
            let dynamic = dynamic::OperationProof::<F, Digest>::decode_cfg(
                encoded.clone(),
                &(N, max_digests),
            )
            .unwrap();
            assert_eq!(dynamic.encode(), encoded);
            assert_eq!(dynamic.encode_size(), encoded.len());
            assert_eq!(dynamic.loc, loc);
            assert_eq!(dynamic.chunk.as_ref(), native.chunk.as_slice());
            assert!(dynamic.verify::<Sha256, _>(operations[0], &root));
            assert!(!dynamic.verify::<Sha256, _>(Sha256::hash(&[b"wrong operation"]), &root,));
            assert!(!dynamic.verify::<Sha256, _>(operations[0], &Sha256::hash(&[b"wrong root"]),));

            let mut inactive = dynamic;
            let mut chunk = inactive.chunk.to_vec();
            let bit = (*loc % chunk_bits) as usize;
            chunk[bit / 8] &= !(1 << (bit % 8));
            inactive.chunk = Bytes::from(chunk);
            assert!(!inactive.verify::<Sha256, _>(operations[0], &root));
        }
    }
}

#[test_async]
async fn dynamic_proofs_match_native_mmr() {
    check_dynamic_proofs::<mmr::Family, 1>().await;
    check_dynamic_proofs::<mmr::Family, 32>().await;
    check_dynamic_proofs::<mmr::Family, 64>().await;
}

#[test_async]
async fn dynamic_proofs_match_native_mmb() {
    check_dynamic_proofs::<mmb::Family, 1>().await;
    check_dynamic_proofs::<mmb::Family, 32>().await;
    check_dynamic_proofs::<mmb::Family, 64>().await;
}

async fn check_dynamic_range_rejections<F: Graftable>() {
    const N: usize = 1;
    let start = Location::<F>::new(6);
    let (_, proof, operations, chunks, root, _) =
        current_range_proof_fixture::<F, N>(18, start..Location::new(18)).await;
    let chunks = chunks
        .iter()
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();
    for chunk_size in invalid_chunk_sizes() {
        assert!(!proof.verify_with_chunk_size::<Sha256, _>(
            start,
            &operations,
            &chunks,
            chunk_size,
            &root,
        ));
    }
    assert!(!proof.verify_with_chunk_size::<Sha256, _>(start, &operations, &chunks, 2, &root));
    assert!(!proof.verify_with_chunk_size::<Sha256, _>(start, &operations[..0], &chunks, N, &root));
    assert!(!proof.verify_with_chunk_size::<Sha256, _>(start, &operations, &chunks[..0], N, &root));
    assert!(!proof.verify_with_chunk_size::<Sha256, _>(
        start,
        &operations,
        &chunks[..chunks.len() - 1],
        N,
        &root,
    ));
    assert!(!proof.verify_with_chunk_size::<Sha256, _>(
        proof.proof.leaves,
        &operations,
        &chunks,
        N,
        &root,
    ));
    assert!(!proof.verify_with_chunk_size::<Sha256, _>(
        F::MAX_LEAVES,
        &operations,
        &chunks,
        N,
        &root,
    ));

    let mut extra = chunks.clone();
    extra.push(chunks[0].clone());
    assert!(!proof.verify_with_chunk_size::<Sha256, _>(start, &operations, &extra, N, &root));
    for chunk_len in [0, 2, 3] {
        let mut malformed = chunks.clone();
        malformed[1].resize(chunk_len, 0);
        assert!(!proof.verify_with_chunk_size::<Sha256, _>(
            start,
            &operations,
            &malformed,
            N,
            &root,
        ));
    }

    let mut tampered = chunks.clone();
    tampered.last_mut().unwrap()[0] ^= 1;
    assert!(!proof.verify_with_chunk_size::<Sha256, _>(start, &operations, &tampered, N, &root));
    let mut missing_partial = proof.clone();
    assert!(missing_partial.partial_chunk_digest.take().is_some());
    assert!(!missing_partial.verify_with_chunk_size::<Sha256, _>(
        start,
        &operations,
        &chunks,
        N,
        &root,
    ));
    let mut wrong_operations = operations;
    wrong_operations[0] = Sha256::hash(&[b"wrong operation"]);
    assert!(!proof.verify_with_chunk_size::<Sha256, _>(
        start,
        &wrong_operations,
        &chunks,
        N,
        &root,
    ));
}

#[test_async]
async fn dynamic_range_rejects_malformed_inputs() {
    check_dynamic_range_rejections::<mmr::Family>().await;
    check_dynamic_range_rejections::<mmb::Family>().await;
}

async fn check_dynamic_operation_codec_rejections<F: Graftable>() {
    const N: usize = 32;
    let loc = Location::<F>::new(14);
    let (_, range_proof, operations, chunks, root, _) =
        current_range_proof_fixture::<F, N>(18, loc..loc + 1).await;
    let native = constant::OperationProof::<F, Digest, N> {
        loc,
        chunk: chunks[0],
        range_proof,
    };
    let encoded = native.encode();
    let max_digests = native.range_proof.proof.digests.len();
    assert!(max_digests > 0);
    assert!(
        dynamic::OperationProof::<F, Digest>::decode_cfg(encoded.clone(), &(N, max_digests - 1),)
            .is_err()
    );
    for end in 0..encoded.len() {
        assert!(
            dynamic::OperationProof::<F, Digest>::decode_cfg(
                encoded.slice(..end),
                &(N, max_digests),
            )
            .is_err(),
            "truncated proof decoded at {end}"
        );
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(
        dynamic::OperationProof::<F, Digest>::decode_cfg(trailing, &(N, max_digests),).is_err()
    );
    for chunk_size in invalid_chunk_sizes() {
        assert!(matches!(
            dynamic::OperationProof::<F, Digest>::decode_cfg(
                encoded.clone(),
                &(chunk_size, max_digests),
            ),
            Err(commonware_codec::Error::Invalid(_, _)),
        ));
    }
    for chunk_size in [1, N / 2, N * 2] {
        if let Ok(dynamic) = dynamic::OperationProof::<F, Digest>::decode_cfg(
            encoded.clone(),
            &(chunk_size, max_digests),
        ) {
            assert!(!dynamic.verify::<Sha256, _>(operations[0], &root));
        }
    }
    let dynamic =
        dynamic::OperationProof::<F, Digest>::decode_cfg(encoded, &(N, max_digests)).unwrap();
    for chunk in [Bytes::new(), Bytes::from_static(&[0; 3])] {
        let mut malformed = dynamic.clone();
        malformed.chunk = chunk;
        assert!(!malformed.verify::<Sha256, _>(operations[0], &root));
    }
}

#[test_async]
async fn dynamic_operation_codec_rejects_malformed_inputs() {
    check_dynamic_operation_codec_rejections::<mmr::Family>().await;
    check_dynamic_operation_codec_rejections::<mmb::Family>().await;
}
