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
//! automatically coalesces terms in the final verification equation. Large
//! batches are prepared in chunks for parallel verification, so coalescing
//! applies to signatures that land in the same chunk. Chunking groups
//! signatures by verification key on a best-effort basis, no matter how the
//! batch was queued. In the limiting case where all signatures in the batch
//! are made with the same verification key, coalesced batch verification
//! runs twice as fast as ordinary batch verification.
//!
//! ![benchmark](https://www.zfnd.org/images/coalesced-batch-graph.png)
//!
//! This optimization doesn't help much when public keys are random,
//! but could be useful in proof-of-stake systems where signatures come from a
//! set of validators (provided that system uses the ZIP215 rules).
//!
//! [ZIP215]: https://github.com/zcash/zips/blob/master/zip-0215.rst

use super::{msm, point, Error, Signature, VerificationKey, VerificationKeyBytes};
use crate::transcript::{Summary, Transcript};
use ahash::RandomState;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use commonware_math::algebra::Random;
use commonware_parallel::{Manual, Sequential, Strategy};
use commonware_utils::union_unique;
use curve25519_dalek::scalar::Scalar;
use hashbrown::HashMap;
use rand_core::{CryptoRng, Rng};
use sha2::{digest::Update, Sha512};

const NOISE_BATCH_VERIFY: &[u8] = b"batch_verify";

/// One chunk's contribution to the global verification equation.
struct Prepared {
    /// Partial coefficient of the basepoint: `-sum(z_i * s_i)`.
    b_coeff: Scalar,
    /// Per-signature 128-bit randomizers, in chunk order.
    zs: Vec<u128>,
    /// Decompressed R points, in chunk order.
    rs: Vec<point::Affine>,
    /// Coalesced verification-key terms: one `(sum(z_i * k_i), A)` per
    /// distinct key in the chunk.
    wide: Vec<(Scalar, point::Affine)>,
}

// Shim to generate a u128 without importing `rand`.
fn gen_u128<R: Rng + CryptoRng>(mut rng: R) -> u128 {
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
    pub fn verify<R: Rng + CryptoRng>(
        self,
        mut rng: R,
        strategy: &impl Strategy,
    ) -> Result<(), Error> {
        // Seeds are drawn before an execution path is chosen so both paths
        // can borrow them.
        let manual = strategy.manual();
        let total = self.signatures.len();
        let chunk_count = (manual.parallelism() * Self::CHUNKS_PER_THREAD).min(total.max(1));
        let seeds: Vec<Summary> = (0..chunk_count)
            .map(|_| Summary::random(&mut rng))
            .collect();

        strategy.try_run_n(
            total,
            2,
            // Serial verification prepares the whole batch as one chunk (so
            // coalescing is global and no partition is needed) and runs the
            // multiscalar multiplication inline.
            || {
                let prepared = Self::prepare_chunk(self.signatures.iter(), total, seeds[0])?;
                Self::finish(&Sequential.manual(), vec![prepared], total)
            },
            // The parallel arms trade fixed costs against parallelism
            // inside the final multiplication: arm 0 checks one owned
            // equation per thread (cheapest for small batches), and arm 1
            // prepares chunks and runs a single global equation with
            // per-window multiscalar tasks (cheapest for large batches).
            // The strategy's policy learns which arm wins per input size.
            |arm| {
                if arm == 0 {
                    let order = Self::partition(&self.signatures);
                    let shard_count = manual.parallelism().min(total.max(1));
                    let shard_size = total.div_ceil(shard_count).max(1);
                    let shards: Vec<_> = order
                        .chunks(shard_size)
                        .zip(seeds.iter().copied())
                        .collect();
                    return manual.try_fold(
                        shards,
                        || (),
                        |_, (shard, seed)| {
                            let prepared = Self::prepare_chunk(
                                shard.iter().map(|&idx| &self.signatures[idx]),
                                shard.len(),
                                seed,
                            )?;
                            Self::finish(&Sequential.manual(), vec![prepared], shard.len())
                        },
                        |_, _| (),
                    );
                }
                let order = Self::partition(&self.signatures);
                let chunk_size = total.div_ceil(chunk_count).max(1);
                let chunks: Vec<_> = order
                    .chunks(chunk_size)
                    .zip(seeds.iter().copied())
                    .collect();
                let outputs = manual.try_map_collect_vec(chunks, |(chunk, seed)| {
                    Self::prepare_chunk(
                        chunk.iter().map(|&idx| &self.signatures[idx]),
                        chunk.len(),
                        seed,
                    )
                })?;
                Self::finish(&manual, outputs, total)
            },
        )
    }

    /// Chunks of work per pool thread in the parallel path. Finer chunks let
    /// faster cores absorb more of the batch at the cost of coalescing (which
    /// applies within a chunk); window-level parallelism in the final
    /// multiplication keeps multiscalar amortization off this constant.
    const CHUNKS_PER_THREAD: usize = 4;

    /// Merge prepared chunks and check the global verification equation.
    fn finish<S: Strategy>(
        manual: &Manual<S>,
        outputs: Vec<Prepared>,
        total: usize,
    ) -> Result<(), Error> {
        let mut b_coeff = Scalar::ZERO;
        let mut zs = Vec::with_capacity(total);
        let mut rs = Vec::with_capacity(total);
        let mut wide = Vec::with_capacity(total + 1);
        for output in outputs {
            b_coeff += output.b_coeff;
            zs.extend(output.zs);
            rs.extend(output.rs);
            wide.extend(output.wide);
        }
        wide.push((b_coeff, msm::basepoint().0));

        let check = msm::msm_global(manual, &wide, &zs, &rs);
        let mut identity = [0u8; 32];
        identity[0] = 1;
        if check.mul_by_pow_2(3).compress() == identity {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// Prepare one chunk of the global verification equation: check the s
    /// values, draw randomizers, hash the payloads, coalesce coefficients per
    /// distinct verification key, and batch-decompress the R points together
    /// with the chunk's distinct verification keys.
    #[allow(non_snake_case)]
    fn prepare_chunk<'a>(
        items: impl Iterator<Item = &'a (VerificationKey, Vec<u8>, Signature)>,
        n: usize,
        seed: Summary,
    ) -> Result<Prepared, Error> {
        let mut rng = Transcript::resume(seed).noise(NOISE_BATCH_VERIFY);
        let items: Vec<_> = items.collect();

        // Check the s values and draw the randomizers.
        let mut zs: Vec<u128> = Vec::with_capacity(n);
        let mut b_coeff = Scalar::ZERO;
        for (_, _, sig) in &items {
            let s = Scalar::from_canonical_bytes(sig.s_bytes)
                .into_option()
                .ok_or(Error::InvalidSignature)?;
            let z = gen_u128(&mut rng);
            b_coeff -= Scalar::from(z) * s;
            zs.push(z);
        }

        // Hash the payloads and coalesce the A coefficients per distinct
        // verification key.
        let mut key_indices: HashMap<&VerificationKeyBytes, usize, RandomState> =
            HashMap::with_capacity_and_hasher(n, RandomState::default());
        let mut wide: Vec<(Scalar, point::Affine)> = Vec::with_capacity(n);
        for ((vk, payload, sig), z) in items.iter().zip(zs.iter()) {
            let k = Scalar::from_hash(
                Sha512::default()
                    .chain(&sig.R_bytes[..])
                    .chain(vk.as_bytes())
                    .chain(payload),
            );
            let index = *key_indices.entry(&vk.A_bytes).or_insert_with(|| {
                wide.push((Scalar::ZERO, vk.A_own));
                wide.len() - 1
            });
            wide[index].0 += Scalar::from(*z) * k;
        }

        // Batch-decompress the chunk's R points through the interleaved
        // kernel (the verification keys are decompressed at parse).
        let rs = point::decompress_batch(items.iter().map(|(_, _, sig)| sig.R_bytes))
            .ok_or(Error::InvalidSignature)?;

        Ok(Prepared {
            b_coeff,
            zs,
            rs,
            wide,
        })
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
}

#[cfg(test)]
mod tests {
    use super::{super::SigningKey, *};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::{test_rng, NZUsize};
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
    fn test_verify_large_batch_split_path() {
        // 60 signers x 10 messages exceeds PHASED_THRESHOLD, exercising the
        // batched decompression and the phased global equation in both arms.
        let mut items = signatures(60, 10);
        assert!(verify(&items));

        items[137].2[0] ^= 1;
        assert!(!verify(&items));
    }

    #[test]
    fn test_verify_mid_batch_sharded_path() {
        // 25 signers x 4 messages sits between SPLIT_THRESHOLD and
        // PHASED_THRESHOLD: the serial arm takes the global equation while
        // the parallel arm folds combined per-thread equations.
        let mut items = signatures(25, 4);
        assert!(verify(&items));

        items[57].2[0] ^= 1;
        assert!(!verify(&items));
    }

    #[test]
    fn test_verify_large_batch_rejects_invalid_r() {
        // An off-curve R encoding must fail the whole batch on the split path.
        let mut items = signatures(40, 4);
        let mut raw: [u8; 64] = items[100].1.into();
        raw[0] ^= 3;
        raw[5] ^= 0xaa;
        let bad_r: [u8; 32] = raw[..32].try_into().unwrap();
        assert!(point::decompress(&bad_r).is_none());
        items[100].1 = Signature::from(raw);
        assert!(!verify(&items));
    }

    #[test]
    fn test_verify_rejects_non_canonical_s() {
        // A malleated signature (R, s + l) satisfies the group equation but
        // must be rejected on every routing path, exactly like individual
        // verification (ZIP215 requires s < l).
        let mut rng = test_rng();
        let sk = SigningKey::new(&mut rng);
        let msg = [7u8; 32];
        let mut raw: [u8; 64] = sk.sign(&msg).into();
        // Add the group order l to the canonical s half, little-endian.
        const ORDER: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut carry = 0u16;
        for (byte, order) in raw[32..].iter_mut().zip(ORDER) {
            let v = *byte as u16 + order as u16 + carry;
            *byte = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
        let malleated = Signature::from(raw);

        // Batch sizes routing through the combined path, the mid-band
        // sharded parallel path, and the phased path.
        for pad in [0usize, 99, 599] {
            let honest = signatures(pad.max(1), 1);
            for parallel in [false, true] {
                let mut verifier = Verifier::new(pad + 1);
                for (hvk, hsig, hmsg) in honest.iter().take(pad) {
                    verifier.queue(*hvk, *hsig, None, hmsg);
                }
                verifier.queue(sk.verification_key(), malleated, None, &msg);
                let result = if parallel {
                    verifier.verify(test_rng(), &Rayon::new(NZUsize!(4)).unwrap())
                } else {
                    verifier.verify(test_rng(), &Sequential)
                };
                assert!(result.is_err(), "pad={pad} parallel={parallel}");
            }
        }
    }

    #[test]
    fn test_verify_small_order_zip215() {
        // A small-order verification key and R with s = 0 satisfy the
        // cofactored equation for any message (a ZIP215 acceptance), and must
        // verify identically on the combined and split paths.
        let torsion = curve25519_dalek::constants::EIGHT_TORSION[1];
        let bytes = torsion.compress().0;
        let vk = VerificationKey::try_from(VerificationKeyBytes(bytes)).unwrap();
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&bytes);
        let forged = Signature::from(raw);

        // Combined path (small batch).
        let mut verifier = Verifier::default();
        verifier.queue(vk, forged, None, b"zip215");
        assert!(verifier.verify(test_rng(), &Sequential).is_ok());

        // Split path (padded past SPLIT_THRESHOLD).
        let honest = signatures(40, 4);
        let mut verifier = Verifier::new(honest.len() + 1);
        for (hvk, hsig, msg) in &honest {
            verifier.queue(*hvk, *hsig, None, msg);
        }
        verifier.queue(vk, forged, None, b"zip215");
        assert!(verifier.verify(test_rng(), &Sequential).is_ok());

        // A nonzero s with a small-order key must still be rejected.
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&bytes);
        raw[32] = 1;
        let invalid = Signature::from(raw);
        let mut verifier = Verifier::new(honest.len() + 1);
        for (hvk, hsig, msg) in &honest {
            verifier.queue(*hvk, *hsig, None, msg);
        }
        verifier.queue(vk, invalid, None, b"zip215");
        assert!(verifier.verify(test_rng(), &Sequential).is_err());
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
