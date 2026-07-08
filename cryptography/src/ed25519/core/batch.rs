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
//! key on a best-effort basis, no matter how the batch was queued. In the
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
use crate::transcript::{Summary, Transcript};
use ahash::RandomState;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use commonware_utils::union_unique;
use core::iter::once;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT as B,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::{IsIdentity, VartimeMultiscalarMul},
};
use hashbrown::HashMap;
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::Update, Sha512};

const NOISE_BATCH_VERIFY: &[u8] = b"batch_verify";

// Shim to generate a u128 without importing `rand`.
fn gen_u128<R: RngCore + CryptoRng>(mut rng: R) -> u128 {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes[..]);
    u128::from_le_bytes(bytes)
}

/// A batch verification context.
#[derive(Default)]
pub struct Verifier {
    /// Signature data queued for verification, in insertion order. Payloads
    /// are copied (instead of hashed at queue time) so the SHA-512 challenge
    /// computation for every signature is deferred to [`Verifier::verify`],
    /// where it runs under the caller's [`Strategy`] instead of serially at
    /// queue time.
    signatures: Vec<(VerificationKey, Vec<u8>, Signature)>,
}

impl Verifier {
    /// Construct a batch verifier with space for `capacity` queued signatures.
    pub fn new(capacity: usize) -> Self {
        Self {
            signatures: Vec::with_capacity(capacity),
        }
    }

    /// Queue a `(key, signature)` pair for verification of `message` under
    /// `namespace`.
    pub fn queue(
        &mut self,
        vk: VerificationKey,
        sig: Signature,
        namespace: Option<&[u8]>,
        message: &[u8],
    ) {
        let payload = namespace.map_or_else(
            || message.to_vec(),
            |namespace| union_unique(namespace, message),
        );

        self.signatures.push((vk, payload, sig));
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// # Warning
    ///
    /// Ed25519 has different verification rules for batched and non-batched
    /// verifications. This function does not have the same verification criteria
    /// as individual verification, which may reject some signatures this method
    /// accepts.
    pub fn verify<R: RngCore + CryptoRng>(
        self,
        mut rng: R,
        strategy: &impl Strategy,
    ) -> Result<(), Error> {
        // Seeds are drawn before an execution path is chosen so both paths
        // can borrow them.
        let manual = strategy.manual();
        let total = self.signatures.len();
        let shard_count = manual.parallelism_hint().min(total.max(1));
        let seeds: Vec<Summary> = (0..shard_count)
            .map(|_| Summary::random(&mut rng))
            .collect();

        strategy.try_run(
            total,
            // Serial verification checks the whole batch as one equation, so
            // coalescing is global and no partition is needed.
            || Self::verify_shard(self.signatures.iter(), total, seeds[0]),
            // Parallel verification partitions the batch so signatures
            // sharing a verification key coalesce within their shard, then
            // checks one equation per shard.
            || {
                let order = Self::partition(&self.signatures);
                let shard_size = total.div_ceil(shard_count).max(1);
                let shards: Vec<_> = order
                    .chunks(shard_size)
                    .zip(seeds.iter().copied())
                    .collect();
                manual.try_fold(
                    shards,
                    || (),
                    |_, (shard, seed)| {
                        Self::verify_shard(
                            shard.iter().map(|&idx| &self.signatures[idx]),
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
    fn partition(signatures: &[(VerificationKey, Vec<u8>, Signature)]) -> Vec<usize> {
        let mut counts = [0; 256];
        for (vk, _, _) in signatures {
            counts[vk.as_bytes()[0] as usize] += 1;
        }
        let mut offsets = [0; 256];
        let mut acc = 0;
        for (offset, count) in offsets.iter_mut().zip(counts) {
            *offset = acc;
            acc += count;
        }
        let mut order = vec![0; signatures.len()];
        for (i, (vk, _, _)) in signatures.iter().enumerate() {
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
        items: impl Iterator<Item = &'a (VerificationKey, Vec<u8>, Signature)>,
        n: usize,
        seed: Summary,
    ) -> Result<(), Error> {
        let mut rng = Transcript::resume(seed).noise(NOISE_BATCH_VERIFY);

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
        // only n point decompressions because verification keys are decompressed
        // before they are queued. When m = n, so all signatures are from
        // distinct verification keys, this saves n decompressions relative to
        // the usual method. However, when m = 1 and all signatures are from a
        // single verification key, this is nearly twice as fast.

        // Group the signatures by verification key. hashbrown's map with the
        // ahash hasher stands in for ahash::AHashMap, which wraps
        // std::collections::HashMap and is unavailable in no_std builds.
        let mut key_indices: HashMap<&VerificationKeyBytes, usize, RandomState> =
            HashMap::with_capacity_and_hasher(n, RandomState::default());
        let mut A_coeffs: Vec<Scalar> = Vec::with_capacity(n);
        let mut As = Vec::with_capacity(n);
        let mut R_coeffs = Vec::with_capacity(n);
        let mut Rs = Vec::with_capacity(n);
        let mut B_coeff = Scalar::ZERO;

        for (vk, payload, sig) in items {
            let k = super::scalar_from_hash(
                Sha512::default()
                    .chain(&sig.R_bytes[..])
                    .chain(vk.as_bytes())
                    .chain(payload),
            );
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
                As.push(-vk.minus_A);
                A_coeffs.push(Scalar::ZERO);
                As.len() - 1
            });
            A_coeffs[index] += z * k;
        }

        let check = EdwardsPoint::vartime_multiscalar_mul(
            once(&B_coeff).chain(A_coeffs.iter()).chain(R_coeffs.iter()),
            once(&B).chain(As.iter()).chain(Rs.iter()),
        );

        if check.mul_by_cofactor().is_identity() {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::SigningKey, *};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{test_rng, NZUsize};
    use rand::Rng;

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

    /// Queue `items` and verify them with `strategy`.
    fn verify_with(
        items: &[(VerificationKey, Signature, [u8; 32])],
        strategy: &impl Strategy,
    ) -> bool {
        let mut verifier = Verifier::default();
        for (vk, sig, msg) in items {
            verifier.queue(*vk, *sig, None, msg);
        }
        verifier.verify(test_rng(), strategy).is_ok()
    }

    /// Verify `items` with both the sequential and a parallel strategy,
    /// asserting the outcomes agree, and return the outcome.
    fn verify(items: &[(VerificationKey, Signature, [u8; 32])]) -> bool {
        let sequential = verify_with(items, &Sequential);
        let parallel = verify_with(items, &Rayon::new(NZUsize!(4)).unwrap());
        assert_eq!(sequential, parallel);
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
        // Round-robin queueing scatters each signer's signatures across the
        // queue, exercising the partition that regroups them into shards and
        // coalescing of duplicate keys within and across shard boundaries.
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

    #[test]
    fn test_deferred_framing_matches_union_unique() {
        // A signature over union_unique(ns, msg) must verify when queued as
        // (ns, msg), pinning the deferred framing to union_unique's format.
        let mut rng = test_rng();
        let sk = SigningKey::new(&mut rng);
        let namespace = b"namespace";
        let msg = b"message";
        let sig = sk.sign(&union_unique(namespace, msg));
        let mut verifier = Verifier::default();
        verifier.queue(sk.verification_key(), sig, Some(namespace), msg);
        assert!(verifier.verify(test_rng(), &Sequential).is_ok());

        // A different namespace must fail.
        let mut verifier = Verifier::default();
        verifier.queue(sk.verification_key(), sig, Some(b"other"), msg);
        assert!(verifier.verify(test_rng(), &Sequential).is_err());
    }
}
