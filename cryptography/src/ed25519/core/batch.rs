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
//! automatically coalesces terms in the final verification equation. In the
//! limiting case where all signatures in the batch are made with the same
//! verification key, coalesced batch verification runs twice as fast as ordinary
//! batch verification.
//!
//! ![benchmark](https://www.zfnd.org/images/coalesced-batch-graph.png)
//!
//! This optimization doesn't help much when public keys are random,
//! but could be useful in proof-of-stake systems where signatures come from a
//! set of validators (provided that system uses the ZIP215 rules).
//!
//! [ZIP215]: https://github.com/zcash/zips/blob/master/zip-0215.rst

use super::{Error, Signature, VerificationKey};
use crate::transcript::{Summary, Transcript};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap as Map, vec::Vec};
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
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::Update, Sha512};
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
type Map<K, V> = HashMap<K, V>;

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
    /// Signature data queued for verification. Payloads are copied (instead
    /// of hashed at queue time) so the SHA-512 challenge computation for
    /// every signature is deferred to [`Verifier::verify`], where it runs
    /// under the caller's [`Strategy`] instead of serially at queue time.
    signatures: Map<VerificationKey, Vec<(Vec<u8>, Signature)>>,
    /// Caching this count avoids a map traversal to figure out
    /// how much to preallocate.
    batch_size: usize,
}

impl Verifier {
    /// Construct a new batch verifier.
    pub fn new() -> Self {
        Self::default()
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

        self.signatures
            .entry(vk)
            // The common case is 1 signature per public key.
            // We could also consider using a smallvec here.
            .or_insert_with(|| Vec::with_capacity(1))
            .push((payload, sig));
        self.batch_size += 1;
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
    #[allow(non_snake_case)]
    pub fn verify<R: RngCore + CryptoRng>(
        self,
        mut rng: R,
        strategy: &impl Strategy,
    ) -> Result<(), Error> {
        // Split all signatures into shards for parallel processing. Each shard is roughly
        // `n_signatures / cores` in size. Random seeds are generated for each shard, derived
        // from the provided RNG, to compute a random scalar for each signature in the shard.
        let manual = strategy.manual();
        let groups: Vec<_> = self.signatures.into_iter().collect();
        let shard_count = manual.parallelism_hint().min(groups.len().max(1));
        let shard_size = groups.len().div_ceil(shard_count).max(1);
        let mut shards = Vec::with_capacity(shard_count);
        for shard in groups.chunks(shard_size) {
            let seed = Summary::random(&mut rng);
            shards.push((shard, seed));
        }

        manual.fold(
            shards,
            || Ok(()),
            |result, (shard, seed)| {
                result?;
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
                // and R_i). However, because we store batch entries in a map
                // indexed by the verification key, we can "coalesce" all z_i * k_i
                // terms for each distinct verification key into a single coefficient.
                //
                // For n signatures from m verification keys, this approach instead
                // requires a multiscalar multiplication of size n + m + 1 together with
                // only n point decompressions because verification keys are decompressed
                // before they are queued. When m = n, so all signatures are from
                // distinct verification keys, this saves n decompressions relative to
                // the usual method. However, when m = 1 and all signatures are from a
                // single verification key, this is nearly twice as fast.

                let m = shard.len();
                let batch_size = shard.iter().map(|(_, sigs)| sigs.len()).sum();

                let mut A_coeffs = Vec::with_capacity(m);
                let mut As = Vec::with_capacity(m);
                let mut R_coeffs = Vec::with_capacity(batch_size);
                let mut Rs = Vec::with_capacity(batch_size);
                let mut B_coeff = Scalar::ZERO;

                for (vk, sigs) in shard {
                    let A = -vk.minus_A;
                    let mut A_coeff = Scalar::ZERO;

                    for (payload, sig) in sigs.iter() {
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
                        A_coeff += z * k;
                    }

                    As.push(A);
                    A_coeffs.push(A_coeff);
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
            },
            |left, right| left.and(right),
        )
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
        let mut verifier = Verifier::new();
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
    fn test_deferred_framing_matches_union_unique() {
        // A signature over union_unique(ns, msg) must verify when queued as
        // (ns, msg), pinning the deferred framing to union_unique's format.
        let mut rng = test_rng();
        let sk = SigningKey::new(&mut rng);
        let namespace = b"namespace";
        let msg = b"message";
        let sig = sk.sign(&union_unique(namespace, msg));
        let mut verifier = Verifier::new();
        verifier.queue(sk.verification_key(), sig, Some(namespace), msg);
        assert!(verifier.verify(test_rng(), &Sequential).is_ok());

        // A different namespace must fail.
        let mut verifier = Verifier::new();
        verifier.queue(sk.verification_key(), sig, Some(b"other"), msg);
        assert!(verifier.verify(test_rng(), &Sequential).is_err());
    }
}
