//! Ed25519 signing (public) keys, signatures, and (batch) verification.

mod error;
mod msm;
mod point;
mod scalar;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_parallel::Strategy;
pub use error::Error;
use point::EdwardsPoint;
use rand_core::CryptoRng;
use scalar::Scalar;
use sha2::{Digest, Sha512};

/// Computes `SHA-512(parts[0] || parts[1] || ...)`, the Ed25519 challenge hash `H(R || A || M)`.
fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

commonware_macros::stability_scope!(ALPHA {
    /// An Ed25519 verification (public) key.
    #[derive(Copy, Clone, Debug)]
    pub struct VerifyingKey {
        bytes: [u8; 32],
        point: EdwardsPoint,
    }

    impl VerifyingKey {
        /// Decodes and validates a 32-byte verification key encoding.
        ///
        /// Following [ZIP215](https://github.com/zcash/zips/blob/master/zip-0215.rst),
        /// non-canonical `y` encodings (`y >= p`) are accepted; only encodings with no
        /// corresponding curve point are rejected.
        pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
            let point = EdwardsPoint::decompress(&bytes).ok_or(Error::InvalidVerificationKey)?;
            Ok(Self { bytes, point })
        }

        /// Returns the byte encoding of this verification key.
        pub const fn to_bytes(&self) -> [u8; 32] {
            self.bytes
        }

        /// Verifies `signature` over `message`.
        ///
        /// This uses the cofactored, ZIP215-style verification equation `[8](sB - kA - R) = 0`
        /// (rather than the cofactorless `sB = kA + R`), so this agrees with [`verify_batch`] on
        /// every input, including small-order `A`/`R` components.
        pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
            let s = Scalar::from_canonical_bytes(&signature.s).ok_or(Error::NonCanonicalScalar)?;
            let r = EdwardsPoint::decompress(&signature.r).ok_or(Error::InvalidSignature)?;

            let digest = sha512(&[&signature.r, &self.bytes, message]);
            let k = Scalar::from_bytes_mod_order_wide(&digest);

            let sb = EdwardsPoint::basepoint().scalar_mul(&s);
            let ka = self.point.scalar_mul(&k);
            let check = sb.add(&ka.negate()).add(&r.negate());
            if check.mul_by_cofactor().is_identity() {
                Ok(())
            } else {
                Err(Error::VerificationFailed)
            }
        }
    }
});

commonware_macros::stability_scope!(ALPHA {
    /// An Ed25519 signature.
    #[derive(Copy, Clone, Debug)]
    pub struct Signature {
        r: [u8; 32],
        s: [u8; 32],
    }

    impl Signature {
        /// Constructs a signature from its 64-byte wire encoding (`R || s`).
        pub fn from_bytes(bytes: [u8; 64]) -> Self {
            let mut r = [0u8; 32];
            let mut s = [0u8; 32];
            r.copy_from_slice(&bytes[..32]);
            s.copy_from_slice(&bytes[32..]);
            Self { r, s }
        }

        /// Returns the 64-byte wire encoding of this signature (`R || s`).
        pub fn to_bytes(&self) -> [u8; 64] {
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(&self.r);
            out[32..].copy_from_slice(&self.s);
            out
        }
    }
});

/// Per-signature scalar-layer output. Computed purely from wire bytes -- the challenge hash only
/// touches `R`'s and `A`'s *encodings* and the message, never a decompressed point -- so this is
/// entirely independent of decompression and safe to compute for every signature in parallel.
struct ScalarLayer {
    /// `A`'s 32-byte encoding, the key `A`-term coalescing groups by.
    a_bytes: [u8; 32],
    /// This signature's random batch coefficient `z`, `R`'s own MSM scalar.
    z: Scalar,
    /// `z * h mod L`, this signature's contribution to its `A`'s (possibly shared) MSM term.
    a_contribution: Scalar,
    /// `z * s mod L`, this signature's contribution to the coalesced basepoint term.
    zs: Scalar,
}

/// Computes one signature's [`ScalarLayer`], or `None` if `s` is not `L`'s canonical
/// representative (a structurally invalid signature, rejected the same way [`VerifyingKey::verify`]
/// rejects it).
fn scalar_layer(a_bytes: [u8; 32], sig: &Signature, msg: &[u8], z: Scalar) -> Option<ScalarLayer> {
    let s = Scalar::from_canonical_bytes(&sig.s)?;
    let digest = sha512(&[&sig.r, &a_bytes, msg]);
    let h = Scalar::from_bytes_mod_order_wide(&digest);
    Some(ScalarLayer {
        a_bytes,
        z,
        a_contribution: z.mul_mod_l(&h),
        zs: z.mul_mod_l(&s),
    })
}

/// Pre-generates `n` random 128-bit batch coefficients in order, serially: an `RngCore`
/// implementation is not `Sync`, so this cannot run inside the parallel pass over
/// [`scalar_layer`] below, but it is cheap relative to everything else in the batch (`16n` bytes
/// of RNG output, no hashing or curve arithmetic) and preserves the exact sequence of `rng` calls
/// a single-threaded loop would make.
fn generate_zs(rng: &mut impl CryptoRng, n: usize) -> Vec<Scalar> {
    (0..n)
        .map(|_| {
            let mut z_bytes = [0u8; 16];
            rng.fill_bytes(&mut z_bytes);
            Scalar::from_u128(u128::from_le_bytes(z_bytes))
        })
        .collect()
}

/// Groups `sorted` (pre-sorted by `.0`) `(key, payload, scalar)` triples by adjacent equal `key`,
/// summing `scalar`s within each group and keeping the first `payload` encountered (every
/// occurrence of the same key carries an identical payload, so it does not matter which one). This
/// is [`verify_batch`]/[`verify_batch_bytes`]'s `A`-term coalescing: a signer reused across the
/// batch contributes one MSM term instead of one per signature, shrinking the MSM by up to a
/// factor of however reuse-heavy the batch is. Operating on raw `[u8; 32]` keys (rather than
/// decompressed points) means a repeated `A` is only ever decompressed once, not once per
/// occurrence.
///
/// A parallel sort (see [`commonware_parallel::Strategy::sort_by`]) plus this linear scan replaces
/// what used to be a `BTreeMap`: sorting needs no shared/locked map, so it composes with the fused
/// decompress-and-MSM pass below without introducing contention.
fn coalesce<T: Copy>(sorted: &[([u8; 32], T, Scalar)]) -> Vec<([u8; 32], T, Scalar)> {
    let mut out: Vec<([u8; 32], T, Scalar)> = Vec::new();
    for &(key, payload, scalar) in sorted {
        if let Some(last) = out.last_mut()
            && last.0 == key
        {
            last.2 = last.2.add_mod_l(&scalar);
            continue;
        }
        out.push((key, payload, scalar));
    }
    out
}

/// Verifies a batch of `(verifying_key, signature, message)` triples, returning `true` only if
/// every item is valid.
///
/// This checks one random linear combination of the batch's individual cofactored verification
/// equations (see [`VerifyingKey::verify`]) rather than each one independently, via a single
/// multi-scalar multiplication over the batch's `R` and `A` points. `rng` must be a
/// cryptographically secure source of randomness: a predictable `zᵢ` coefficient lets an attacker
/// construct a batch that passes here despite containing a forged signature. Given a strong
/// `rng`, a false positive (an invalid batch passing) happens with probability at most `2⁻¹²⁸`.
/// `strategy` controls whether the batch's stages run serially or spread across a thread pool (see
/// [`commonware_parallel::Strategy`]); `A` is already decompressed once per [`VerifyingKey`], so
/// only `R` needs decompressing here. Use [`verify_batch_bytes`] instead if `A` has not been
/// decompressed yet either (e.g. a batch of raw wire bytes with no cached keys).
///
/// A `false` result means *some* item in the batch is invalid, but not which one; check items
/// individually with [`VerifyingKey::verify`] to find it.
#[commonware_macros::stability(ALPHA)]
pub fn verify_batch<'a>(
    rng: &mut impl CryptoRng,
    items: impl IntoIterator<Item = (&'a VerifyingKey, &'a Signature, &'a [u8])>,
    strategy: &impl Strategy,
) -> bool {
    let items: Vec<_> = items.into_iter().collect();

    let zs = generate_zs(rng, items.len());
    let layers = strategy.map_collect_vec(items.iter().zip(zs), |((vk, sig, msg), z)| {
        scalar_layer(vk.bytes, sig, msg, z)
    });
    let Some(layers): Option<Vec<ScalarLayer>> = layers.into_iter().collect() else {
        return false;
    };

    // `A` needs no decompression here (every `VerifyingKey` already carries its decompressed
    // point), so coalescing carries the point straight through as the sort/scan's payload.
    let mut keyed: Vec<([u8; 32], EdwardsPoint, Scalar)> = items
        .iter()
        .zip(&layers)
        .map(|((vk, _, _), layer)| (vk.bytes, vk.point, layer.a_contribution))
        .collect();
    strategy.sort_by(&mut keyed, |a, b| a.0.cmp(&b.0));
    let a_terms = coalesce(&keyed);
    let a_points: Vec<EdwardsPoint> = a_terms.iter().map(|(_, p, _)| *p).collect();
    let a_scalars: Vec<Scalar> = a_terms.iter().map(|(_, _, s)| *s).collect();

    let s_sum = layers
        .iter()
        .fold(Scalar::ZERO, |acc, layer| acc.add_mod_l(&layer.zs));
    let r_bytes: Vec<[u8; 32]> = items.iter().map(|(_, sig, _)| sig.r).collect();
    let r_scalars: Vec<Scalar> = layers.iter().map(|layer| layer.z).collect();

    // The coalesced basepoint term: `sum(zᵢsᵢ)·B` moved to the equation's other side as
    // `sum(zᵢsᵢ)·(-B)`, folded into `R`'s fused decompress-and-MSM pass so it shares that pass's
    // window doublings instead of needing a separate scalar multiplication.
    let basepoint_term = (EdwardsPoint::basepoint().negate(), s_sum);
    let Some(r_total) = msm::multiscalar_mul_from_bytes_parallel(
        &[(&r_bytes, &r_scalars)],
        Some(basepoint_term),
        strategy,
    ) else {
        return false;
    };
    let a_total = msm::multiscalar_mul_parallel(&a_points, &a_scalars, strategy);

    r_total.add(&a_total).mul_by_cofactor().is_identity()
}

/// Verifies a batch of `(verifying_key_bytes, signature, message)` triples, returning `true` only
/// if every item is valid.
///
/// Identical to [`verify_batch`], except it takes raw 32-byte verification key encodings directly
/// rather than requiring the caller to have already constructed a [`VerifyingKey`]. `A` is
/// coalesced by its raw encoding before ever being decompressed (see [`coalesce`]), so a signer
/// reused across the batch is decompressed once, not once per signature; both `A`'s deduplicated
/// encodings and `R`'s per-signature encodings are then decompressed and fed into the batch's MSM
/// within the very same parallel pass (see
/// [`msm::multiscalar_mul_from_bytes_parallel`]), rather than as two separate decompression passes
/// followed by a third, separate MSM pass. Use this starting from raw wire bytes with no cached
/// keys; use [`verify_batch`] when keys are reused across many batches and worth decompressing
/// once up front (e.g. a stable validator set).
#[commonware_macros::stability(ALPHA)]
pub fn verify_batch_bytes<'a>(
    rng: &mut impl CryptoRng,
    items: impl IntoIterator<Item = (&'a [u8; 32], &'a Signature, &'a [u8])>,
    strategy: &impl Strategy,
) -> bool {
    let items: Vec<_> = items.into_iter().collect();

    let zs = generate_zs(rng, items.len());
    let layers = strategy.map_collect_vec(items.iter().zip(zs), |((a, sig, msg), z)| {
        scalar_layer(**a, sig, msg, z)
    });
    let Some(layers): Option<Vec<ScalarLayer>> = layers.into_iter().collect() else {
        return false;
    };

    let mut keyed: Vec<([u8; 32], (), Scalar)> = layers
        .iter()
        .map(|layer| (layer.a_bytes, (), layer.a_contribution))
        .collect();
    strategy.sort_by(&mut keyed, |a, b| a.0.cmp(&b.0));
    let a_terms = coalesce(&keyed);
    let a_bytes: Vec<[u8; 32]> = a_terms.iter().map(|(key, (), _)| *key).collect();
    let a_scalars: Vec<Scalar> = a_terms.iter().map(|(_, (), s)| *s).collect();

    let s_sum = layers
        .iter()
        .fold(Scalar::ZERO, |acc, layer| acc.add_mod_l(&layer.zs));
    let r_bytes: Vec<[u8; 32]> = items.iter().map(|(_, sig, _)| sig.r).collect();
    let r_scalars: Vec<Scalar> = layers.iter().map(|layer| layer.z).collect();

    let basepoint_term = (EdwardsPoint::basepoint().negate(), s_sum);
    let Some(total) = msm::multiscalar_mul_from_bytes_parallel(
        &[(&a_bytes, &a_scalars), (&r_bytes, &r_scalars)],
        Some(basepoint_term),
        strategy,
    ) else {
        return false;
    };

    total.mul_by_cofactor().is_identity()
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use ed25519_consensus::SigningKey as RefSigningKey;
    use rand_core::Rng;

    #[test]
    fn coalesce_sums_adjacent_equal_keys_and_keeps_first_payload() {
        let sorted = vec![
            ([1u8; 32], "a", Scalar::from_u128(1)),
            ([1u8; 32], "a-repeat", Scalar::from_u128(2)),
            ([2u8; 32], "b", Scalar::from_u128(10)),
            ([3u8; 32], "c", Scalar::from_u128(100)),
            ([3u8; 32], "c-repeat", Scalar::from_u128(200)),
            ([3u8; 32], "c-repeat-again", Scalar::from_u128(300)),
        ];
        let out = coalesce(&sorted);
        let simplified: Vec<([u8; 32], &str, [u64; 4])> =
            out.iter().map(|(k, p, s)| (*k, *p, s.0)).collect();
        assert_eq!(
            simplified,
            vec![
                ([1u8; 32], "a", Scalar::from_u128(3).0),
                ([2u8; 32], "b", Scalar::from_u128(10).0),
                ([3u8; 32], "c", Scalar::from_u128(600).0),
            ]
        );
    }

    #[test]
    fn coalesce_handles_empty_and_no_duplicates() {
        assert!(coalesce::<()>(&[]).is_empty());

        let sorted = vec![
            ([1u8; 32], (), Scalar::from_u128(1)),
            ([2u8; 32], (), Scalar::from_u128(2)),
        ];
        let out = coalesce(&sorted);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, sorted[0].0);
        assert_eq!(out[0].2.0, sorted[0].2.0);
        assert_eq!(out[1].0, sorted[1].0);
        assert_eq!(out[1].2.0, sorted[1].2.0);
    }

    /// Generates `n` valid `(VerifyingKey, Signature, message)` triples, signed by independent
    /// keys over independent messages using the `ed25519-consensus` reference implementation.
    fn valid_batch(n: usize) -> Vec<(VerifyingKey, Signature, Vec<u8>)> {
        let mut rng = test_rng();
        (0..n)
            .map(|i| {
                let mut seed = [0u8; 32];
                rng.fill_bytes(&mut seed);
                let signing_key = RefSigningKey::from(seed);
                let verifying_key =
                    VerifyingKey::from_bytes(signing_key.verification_key().to_bytes()).unwrap();

                let message = format!("message {i}").into_bytes();
                let signature = signing_key.sign(&message);
                let signature = Signature::from_bytes(signature.to_bytes());

                (verifying_key, signature, message)
            })
            .collect()
    }

    #[test]
    fn verify_accepts_reference_signature() {
        for (vk, sig, msg) in valid_batch(5) {
            assert!(vk.verify(&msg, &sig).is_ok());
        }
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (vk, sig, _) = valid_batch(1).pop().unwrap();
        assert!(vk.verify(b"not the signed message", &sig).is_err());
    }

    #[test]
    fn verify_batch_accepts_valid_batch() {
        let mut rng = test_rng();
        for n in [0, 1, 2, 5, 64] {
            let batch = valid_batch(n);
            let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
            assert!(verify_batch(&mut rng, items, &Sequential));
        }
    }

    #[test]
    fn verify_batch_bytes_accepts_valid_batch() {
        let mut rng = test_rng();
        for n in [0, 1, 2, 5, 64] {
            let batch = valid_batch(n);
            let items = batch
                .iter()
                .map(|(vk, sig, msg)| (&vk.bytes, sig, msg.as_slice()));
            assert!(verify_batch_bytes(&mut rng, items, &Sequential));
        }
    }

    #[test]
    fn verify_batch_bytes_rejects_one_corrupted_signature() {
        let mut rng = test_rng();
        let mut batch = valid_batch(16);
        batch[9].1.s[0] ^= 1;
        let items = batch
            .iter()
            .map(|(vk, sig, msg)| (&vk.bytes, sig, msg.as_slice()));
        assert!(!verify_batch_bytes(&mut rng, items, &Sequential));
    }

    #[test]
    fn verify_batch_rejects_one_corrupted_signature() {
        let mut rng = test_rng();
        let mut batch = valid_batch(16);
        batch[9].1.s[0] ^= 1;
        let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
        assert!(!verify_batch(&mut rng, items, &Sequential));
    }

    #[test]
    fn verify_batch_rejects_wrong_message() {
        let mut rng = test_rng();
        let mut batch = valid_batch(16);
        batch[3].2 = b"a different message".to_vec();
        let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
        assert!(!verify_batch(&mut rng, items, &Sequential));
    }

    /// Generates `n` valid signatures from a single signer over `n` independent messages, the
    /// workload key coalescing (see `verify_batch`) targets.
    fn repeated_signer_batch(n: usize) -> Vec<(VerifyingKey, Signature, Vec<u8>)> {
        let mut rng = test_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signing_key = RefSigningKey::from(seed);
        let verifying_key =
            VerifyingKey::from_bytes(signing_key.verification_key().to_bytes()).unwrap();

        (0..n)
            .map(|i| {
                let message = format!("message {i}").into_bytes();
                let signature = signing_key.sign(&message);
                let signature = Signature::from_bytes(signature.to_bytes());
                (verifying_key, signature, message)
            })
            .collect()
    }

    #[test]
    fn verify_batch_accepts_repeated_signer() {
        let mut rng = test_rng();
        for n in [1, 2, 5, 16, 64] {
            let batch = repeated_signer_batch(n);
            let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
            assert!(verify_batch(&mut rng, items, &Sequential));
        }
    }

    #[test]
    fn verify_batch_rejects_one_corrupted_signature_from_repeated_signer() {
        let mut rng = test_rng();
        let mut batch = repeated_signer_batch(16);
        batch[9].1.s[0] ^= 1;
        let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
        assert!(!verify_batch(&mut rng, items, &Sequential));
    }

    /// A batch of both independent signers and a repeated signer, spanning multiple parallel MSM
    /// chunks (`msm::PARALLEL_CHUNK_SIZE` is 256), verified under `Manual` -- which disables the
    /// adaptive serial/parallel policy so every `strategy` call in this test genuinely dispatches
    /// across the thread pool, rather than the policy falling back to serial for a size it judges
    /// too small. Every other test in this module uses `Sequential`, so this is the only one
    /// exercising real concurrent execution of the coalescing sort and the fused decompress-and-MSM
    /// pass end to end.
    fn mixed_batch_with_repeats(n: usize) -> Vec<(VerifyingKey, Signature, Vec<u8>)> {
        let mut rng = test_rng();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let repeated_signer = RefSigningKey::from(seed);
        let repeated_key =
            VerifyingKey::from_bytes(repeated_signer.verification_key().to_bytes()).unwrap();

        (0..n)
            .map(|i| {
                let message = format!("message {i}").into_bytes();
                // Every third signature reuses `repeated_signer`, exercising `A`-term coalescing
                // alongside the independent-signer common case.
                if i % 3 == 0 {
                    let signature = repeated_signer.sign(&message);
                    (
                        repeated_key,
                        Signature::from_bytes(signature.to_bytes()),
                        message,
                    )
                } else {
                    let mut seed = [0u8; 32];
                    rng.fill_bytes(&mut seed);
                    let signing_key = RefSigningKey::from(seed);
                    let verifying_key =
                        VerifyingKey::from_bytes(signing_key.verification_key().to_bytes())
                            .unwrap();
                    let signature = signing_key.sign(&message);
                    (
                        verifying_key,
                        Signature::from_bytes(signature.to_bytes()),
                        message,
                    )
                }
            })
            .collect()
    }

    #[test]
    fn verify_batch_and_verify_batch_bytes_accept_valid_batch_under_real_parallelism() {
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();
        let mut rng = test_rng();
        let batch = mixed_batch_with_repeats(600);

        let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
        assert!(verify_batch(&mut rng, items, &strategy));

        let items = batch
            .iter()
            .map(|(vk, sig, msg)| (&vk.bytes, sig, msg.as_slice()));
        assert!(verify_batch_bytes(&mut rng, items, &strategy));
    }

    #[test]
    fn verify_batch_and_verify_batch_bytes_reject_corrupted_signature_under_real_parallelism() {
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();
        let mut rng = test_rng();
        let mut batch = mixed_batch_with_repeats(600);
        batch[400].1.s[0] ^= 1;

        let items = batch.iter().map(|(vk, sig, msg)| (vk, sig, msg.as_slice()));
        assert!(!verify_batch(&mut rng, items, &strategy));

        let items = batch
            .iter()
            .map(|(vk, sig, msg)| (&vk.bytes, sig, msg.as_slice()));
        assert!(!verify_batch_bytes(&mut rng, items, &strategy));
    }
}
