//! Performs batch Ed25519 signature verification.
//!
//! Batch verification asks whether *all* signatures in some set are valid,
//! rather than asking whether *each* of them is valid. This allows sharing
//! computations among all signature verifications, performing less work overall
//! at the cost of higher latency (the entire batch must complete), complexity of
//! caller code (which must assemble a batch of signatures across work-items),
//! and loss of the ability to easily pinpoint failing signatures.
//!
//! In addition to these general tradeoffs, design flaws in Ed25519 specifically
//! mean that batched verification may not agree with individual verification.
//! Some signatures may verify as part of a batch but not on their own.
//! This problem is fixed by [ZIP215], a precise specification for edge cases
//! in Ed25519 signature validation that ensures that batch verification agrees
//! with individual verification in all cases.
//!
//! This crate implements ZIP215, so batch verification always agrees with
//! individual verification, but this is not guaranteed by other implementations.
//! **Be extremely careful when using Ed25519 in a consensus-critical context
//! like a blockchain.**
//!
//! This batch verification implementation is adaptive in the sense that it
//! detects multiple signatures created with the same verification key and
//! automatically coalesces terms in the final verification equation. Signatures
//! are sharded for parallel verification, so coalescing applies to signatures
//! that land in the same shard. Sharding groups signatures by verification
//! key on a best-effort basis, regardless of input order. In the
//! limiting case where all signatures in the batch are made with the same
//! verification key, coalesced batch verification runs twice as fast as
//! ordinary batch verification.
//!
//! ![benchmark](https://www.zfnd.org/images/coalesced-batch-graph.png)
//!
//! This optimization doesn't help much when public keys are random,
//! but could be useful in proof-of-stake systems where signatures come from a
//! set of validators (provided that system uses the ZIP215 rules).
//!
//! [ZIP215]: https://github.com/zcash/zips/blob/master/zip-0215.rst

use super::{Error, Signature, VerificationKey, VerificationKeyBytes};
use crate::transcript::{Summary, Transcript, Version};
use ahash::RandomState;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_codec::{EncodeSize, Write, varint::UInt};
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use core::iter::once;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as B,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use hashbrown::HashMap;
use rand_core::CryptoRng;
use sha2::{Sha512, digest::Update};

const NOISE_BATCH_VERIFY: &[u8] = b"batch_verify";

// Shim to generate a u128 without importing `rand`.
fn gen_u128<R: CryptoRng>(mut rng: R) -> u128 {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes[..]);
    u128::from_le_bytes(bytes)
}

/// Verify a batch of projected signatures.
///
/// With a namespace, the signed payload is the namespace's byte length encoded
/// as an unsigned varint, followed by the namespace and message. `None` verifies
/// the raw message. Rejects empty batches, invalid signatures, and namespace
/// lengths that cannot be represented as a `u32`.
///
/// The projection receives the item's original slice index. It must return the
/// same entry each time it is called for that index and item, and may be called
/// concurrently.
pub fn verify_projected<'a, R, T, F>(
    rng: &mut R,
    items: &'a [T],
    project: F,
    strategy: &impl Strategy,
) -> Result<(), Error>
where
    R: CryptoRng,
    T: Sync,
    F: Fn(usize, &'a T) -> (&'a VerificationKey, Signature, Option<&'a [u8]>, &'a [u8]) + Sync,
{
    if items.is_empty() {
        return Err(Error::InvalidSignature);
    }

    // Seeds are drawn before an execution path is chosen so both paths
    // can borrow them.
    let manual = strategy.manual();
    let total = items.len();
    let shard_count = manual.parallelism().min(total);
    let seeds: Vec<Summary> = (0..shard_count)
        .map(|_| Summary::random(&mut *rng))
        .collect();

    strategy.try_run(
        total,
        // Serial verification checks the whole batch as one equation, so
        // coalescing is global and no partition is needed.
        || {
            verify_shard(
                items.iter().enumerate().map(|(i, item)| project(i, item)),
                total,
                seeds[0],
            )
        },
        // Parallel verification partitions the batch so signatures
        // sharing a verification key coalesce within their shard, then
        // checks one equation per shard.
        || {
            let order = partition(items, |i, item| project(i, item).0);
            let shard_size = total.div_ceil(shard_count);
            let shards: Vec<_> = order
                .chunks(shard_size)
                .zip(seeds.iter().copied())
                .collect();
            manual.try_fold(
                shards,
                || (),
                |_, (shard, seed)| {
                    verify_shard(
                        shard.iter().map(|&idx| project(idx, &items[idx])),
                        shard.len(),
                        seed,
                    )
                },
                |_, _| (),
            )
        },
    )
}

/// Build an iteration order that groups signatures by the first byte of
/// their verification key, using a counting sort. Chunking the order into
/// equal-size shards then keeps signatures sharing a key in the same
/// shard, except where a shard boundary cuts through a byte group.
/// Grouping is best-effort: skewed batches (like a single signer) still
/// split evenly across shards, and keys crafted to share a first byte
/// just forfeit the grouping, costing no more than the unpartitioned
/// order.
fn partition<'a, T>(
    signatures: &'a [T],
    key: impl Fn(usize, &'a T) -> &'a VerificationKey,
) -> Vec<usize> {
    let mut counts = [0; 256];
    for (i, item) in signatures.iter().enumerate() {
        let vk = key(i, item);
        counts[vk.as_bytes()[0] as usize] += 1;
    }
    let mut offsets = [0; 256];
    let mut acc = 0;
    for (offset, count) in offsets.iter_mut().zip(counts) {
        *offset = acc;
        acc += count;
    }
    let mut order = vec![0; signatures.len()];
    for (i, item) in signatures.iter().enumerate() {
        let vk = key(i, item);
        let bucket = vk.as_bytes()[0] as usize;
        order[offsets[bucket]] = i;
        offsets[bucket] += 1;
    }
    order
}

/// Verify `n` signatures as a single verification equation, drawing a
/// randomizer for each signature from `seed`.
#[allow(non_snake_case)]
fn verify_shard<'a>(
    items: impl Iterator<Item = (&'a VerificationKey, Signature, Option<&'a [u8]>, &'a [u8])>,
    n: usize,
    seed: Summary,
) -> Result<(), Error> {
    let mut rng = Transcript::resume(seed, Version::V1).noise(NOISE_BATCH_VERIFY);

    // The batch verification equation is
    //
    // [-sum(z_i * s_i)]B + sum([z_i]R_i) + sum([z_i * k_i]A_i) = 0.
    //
    // where for each signature i,
    // - A_i is the verification key;
    // - R_i is the signature's R value;
    // - s_i is the signature's s value;
    // - k_i is the hash of the message and other data, computed
    //   here so the per-signature SHA-512 work runs under the
    //   caller's strategy;
    // - z_i is a random 128-bit Scalar.
    //
    // Normally n signatures would require a multiscalar multiplication of
    // size 2*n + 1, together with 2*n point decompressions (to obtain A_i
    // and R_i). However, by grouping the entries by verification key, we
    // can "coalesce" all z_i * k_i terms for each distinct verification
    // key into a single coefficient.
    //
    // For n signatures from m verification keys, this approach instead
    // requires a multiscalar multiplication of size n + m + 1 together with
    // only n point decompressions because verification keys cache their
    // decompressed points. When m = n, so all signatures are from
    // distinct verification keys, this saves n decompressions relative to
    // the usual method. However, when m = 1 and all signatures are from a
    // single verification key, this is nearly twice as fast.

    // Group coefficients by the original key encoding, retaining borrowed
    // cached points with them in first-seen order. hashbrown with ahash
    // supports no_std builds.
    let mut key_indices: HashMap<&VerificationKeyBytes, usize, RandomState> =
        HashMap::with_capacity_and_hasher(n, RandomState::default());
    let mut A_terms: Vec<(Scalar, &EdwardsPoint)> = Vec::with_capacity(n);
    let mut R_coeffs = Vec::with_capacity(n);
    let mut Rs = Vec::with_capacity(n);
    let mut B_coeff = Scalar::ZERO;

    for (vk, sig, namespace, message) in items {
        let mut hash = Sha512::default()
            .chain(&sig.R_bytes[..])
            .chain(vk.as_bytes());
        if let Some(namespace) = namespace {
            let len = UInt(u32::try_from(namespace.len()).map_err(|_| Error::InvalidSignature)?);
            let mut prefix = [0u8; 5];
            len.write(&mut prefix.as_mut_slice());
            hash.update(&prefix[..len.encode_size()]);
            hash.update(namespace);
        }
        hash.update(message);
        let k = Scalar::from_hash(hash);
        let R = CompressedEdwardsY(sig.R_bytes)
            .decompress()
            .ok_or(Error::InvalidSignature)?;
        let s = Scalar::from_canonical_bytes(sig.s_bytes)
            .into_option()
            .ok_or(Error::InvalidSignature)?;
        let z = Scalar::from(gen_u128(&mut rng));
        B_coeff -= z * s;
        Rs.push(R);
        R_coeffs.push(z);
        let index = *key_indices.entry(&vk.A_bytes).or_insert_with(|| {
            A_terms.push((Scalar::ZERO, &vk.minus_A));
            A_terms.len() - 1
        });
        A_terms[index].0 += z * k;
    }

    let check = EdwardsPoint::vartime_multiscalar_mul(
        once(&B_coeff)
            .chain(A_terms.iter().map(|(coeff, _)| coeff))
            .chain(R_coeffs.iter()),
        once(B)
            .chain(A_terms.iter().map(|(_, point)| -*point))
            .chain(Rs.iter().copied()),
    );

    if check.mul_by_cofactor().is_identity() {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::{super::SigningKey, *};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{NZUsize, test_rng};
    use rand::RngExt as _;

    /// Generate `signers` keys with `per_signer` signed messages each.
    fn signatures(
        signers: usize,
        per_signer: usize,
    ) -> Vec<(VerificationKey, Signature, [u8; 32])> {
        let mut rng = test_rng();
        let mut items = Vec::with_capacity(signers * per_signer);
        for _ in 0..signers {
            let sk = SigningKey::new(&mut rng);
            let vk = sk.verification_key();
            for _ in 0..per_signer {
                let mut msg = [0u8; 32];
                rng.fill(&mut msg);
                items.push((vk, sk.sign(&msg), msg));
            }
        }
        items
    }

    /// Verify the batch and require sequential and parallel strategies to agree.
    fn verify(items: &[(VerificationKey, Signature, [u8; 32])]) -> bool {
        let sequential = verify_projected(
            &mut test_rng(),
            items,
            |_, (vk, sig, message)| (vk, *sig, None, message.as_slice()),
            &Sequential,
        )
        .is_ok();
        let parallel = Rayon::new(NZUsize!(4)).unwrap();
        assert_eq!(
            sequential,
            verify_projected(
                &mut test_rng(),
                items,
                |_, (vk, sig, message)| (vk, *sig, None, message.as_slice()),
                &parallel.manual(),
            )
            .is_ok()
        );
        sequential
    }

    #[test]
    fn test_verify_deferred_hashing() {
        let mut items = signatures(4, 3);
        assert!(verify(&items));

        // Altering any message must fail the whole batch.
        items[7].2[0] ^= 1;
        assert!(!verify(&items));
    }

    #[test]
    fn test_verify_interleaved_duplicate_keys() {
        // Interleaved input scatters each signer's signatures across the batch,
        // exercising key grouping and coalescing within each shard.
        let grouped = signatures(2, 6);
        let mut items = Vec::with_capacity(grouped.len());
        for i in 0..6 {
            items.push(grouped[i]);
            items.push(grouped[6 + i]);
        }
        assert!(verify(&items));

        items[5].2[0] ^= 1;
        assert!(!verify(&items));
    }
}
