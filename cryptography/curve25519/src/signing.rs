//! Ed25519 signing (public) keys, signatures, and (batch) verification.

mod error;
mod msm;
mod point;
mod scalar;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use crate::field_vec::LANES;
use commonware_parallel::Strategy;
pub use error::Error;
use msm::Term;
use point::{EdwardsPoint, MixedPoint};
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

/// Derives four consecutive 128-bit batch coefficients `z_{4*block} .. z_{4*block + 3}` from
/// `seed` as one SHA-512 output, in counter mode.
///
/// The batch equation's soundness needs each `z_i` to be uniform, independent, and unpredictable
/// to whoever assembled the batch; PRF outputs under a seed drawn freshly from the caller's
/// CSPRNG (and never revealed) are indistinguishable from exactly that. Deriving each signature's
/// coefficient from its *position* rather than drawing all of them from the shared `rng` up
/// front lets every thread compute its own signatures' coefficients locally -- and makes the
/// batch's entire execution a deterministic function of `(items, seed)`, identical at every
/// thread count.
fn batch_coefficients(seed: &[u8; 32], block: u64) -> [Scalar; 4] {
    let digest = sha512(&[seed, &block.to_le_bytes()]);
    core::array::from_fn(|k| {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[k * 16..(k + 1) * 16]);
        Scalar::from_u128(u128::from_le_bytes(bytes))
    })
}

/// Groups `sorted` (pre-sorted `(key, original index)` pairs) into runs of equal keys, returned
/// as `(start, end)` positions into `sorted`. This is batch verification's `A`-term coalescing:
/// a signer reused across the batch contributes one MSM term instead of one per signature, and
/// operating on raw `[u8; 32]` keys (rather than decompressed points) means a repeated `A` is
/// only ever decompressed once, not once per occurrence.
fn group_ranges(sorted: &[([u8; 32], u32)]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let mut start = 0;
    for i in 1..=sorted.len() {
        if i == sorted.len() || sorted[i].0 != sorted[start].0 {
            out.push((start as u32, i as u32));
            start = i;
        }
    }
    out
}

/// The per-signature scalar phase, parallel over contiguous runs of the sorted batch: for sorted
/// position `i`, derives `z_i` (see [`batch_coefficients`]), rejects a non-canonical `s`,
/// computes the challenge `h = H(R || A || M)`, and writes `z*h` into `zh[i]` (this signature's
/// contribution to its signer's coalesced term) and `z` into `zr[i]` (its `R` point's own MSM
/// scalar). Returns `sum(z*s) mod L` -- the coalesced basepoint scalar -- or `None` if any `s`
/// was non-canonical (a structurally invalid signature, rejected the same way
/// [`VerifyingKey::verify`] rejects it).
///
/// This phase touches no curve points: it is uniform per signature regardless of how the batch's
/// signers are distributed, so a batch dominated by one key parallelizes exactly as well as a
/// batch of all-distinct keys.
fn scalar_phase(
    items: &[(&[u8; 32], &Signature, &[u8])],
    order: &[([u8; 32], u32)],
    seed: &[u8; 32],
    zh: &mut [Scalar],
    zr: &mut [Scalar],
    strategy: &impl Strategy,
) -> Option<Scalar> {
    // A multiple of 4 keeps every chunk aligned to whole `batch_coefficients` blocks, so no
    // block is ever derived twice; the floor keeps per-chunk dispatch overhead amortized.
    let chunk = items
        .len()
        .div_ceil(4 * strategy.manual().parallelism())
        .next_multiple_of(4)
        .max(32);

    let partials: Result<Vec<Scalar>, ()> = strategy.try_map_collect_vec(
        zh.chunks_mut(chunk).zip(zr.chunks_mut(chunk)).enumerate(),
        |(index, (zh_chunk, zr_chunk))| {
            let start = index * chunk;
            let mut coefficients = [Scalar::ZERO; 4];
            let mut zs_sum = Scalar::ZERO;
            for (j, (zh_slot, zr_slot)) in zh_chunk.iter_mut().zip(zr_chunk).enumerate() {
                let i = start + j;
                if i.is_multiple_of(4) {
                    coefficients = batch_coefficients(seed, (i / 4) as u64);
                }
                let z = coefficients[i % 4];
                let (a_bytes, sig, msg) = items[order[i].1 as usize];
                let s = Scalar::from_canonical_bytes(&sig.s).ok_or(())?;
                let digest = sha512(&[&sig.r, a_bytes, msg]);
                let h = Scalar::from_bytes_mod_order_wide(&digest);
                *zh_slot = z.mul_mod_l(&h);
                *zr_slot = z;
                zs_sum = zs_sum.add_mod_l(&z.mul_mod_l(&s));
            }
            Ok(zs_sum)
        },
    );

    let partials = partials.ok()?;
    Some(
        partials
            .iter()
            .fold(Scalar::ZERO, |acc, partial| acc.add_mod_l(partial)),
    )
}

/// Floor on worklist entries per decompression chunk (a multiple of [`LANES`], so whole chunks
/// feed [`EdwardsPoint::decompress_batch`]): below this, per-chunk dispatch overhead stops being
/// amortized against the chunk's modular exponentiations.
const MIN_DECOMPRESS_CHUNK: usize = 64;

/// The decompression phase: turns a flat worklist of `count` point encodings (resolved by index
/// via `resolve`, which returns an encoding and its already-final MSM scalar) into [`Term`]
/// chunks, in one parallel pass. Every worklist entry costs the same (one decompression), so the
/// pass stays uniform however the batch's signers are distributed, and the arithmetic-heavy part
/// batches [`LANES`]-wide (see [`EdwardsPoint::decompress_batch`]). The per-chunk output vectors
/// are handed to the MSM as-is, never flattened into one allocation (see [`msm`]'s module docs).
///
/// Returns `None` if any encoding fails to decompress.
fn decompress_phase<F>(count: usize, resolve: F, strategy: &impl Strategy) -> Option<Vec<Vec<Term>>>
where
    F: Fn(usize) -> ([u8; 32], Scalar) + Send + Sync,
{
    if count == 0 {
        return Some(Vec::new());
    }
    let chunk = count
        .div_ceil(2 * strategy.manual().parallelism())
        .next_multiple_of(LANES)
        .max(MIN_DECOMPRESS_CHUNK);
    let starts: Vec<usize> = (0..count).step_by(chunk).collect();

    let chunks: Result<Vec<Vec<Term>>, ()> = strategy
        .try_map_collect_vec(starts, |start| {
            let end = (start + chunk).min(count);
            let mut terms = Vec::with_capacity(end - start);
            let mut i = start;
            while i < end {
                if end - i >= LANES {
                    let resolved: [([u8; 32], Scalar); LANES] =
                        core::array::from_fn(|k| resolve(i + k));
                    let bytes = resolved.map(|(bytes, _)| bytes);
                    let points = EdwardsPoint::decompress_batch(&bytes);
                    for (point, (_, scalar)) in points.into_iter().zip(&resolved) {
                        terms.push(Term::new(MixedPoint::new(&point.ok_or(())?), scalar));
                    }
                    i += LANES;
                } else {
                    let (bytes, scalar) = resolve(i);
                    let point = EdwardsPoint::decompress(&bytes).ok_or(())?;
                    terms.push(Term::new(MixedPoint::new(&point), &scalar));
                    i += 1;
                }
            }
            Ok(terms)
        });
    chunks.ok()
}

/// The shared batch-verification pipeline (see [`verify_batch`] for the equation and its
/// security argument): a short sequence of data-parallel phases over flat arrays, with `A`
/// coalescing falling out of a sort.
///
/// 1. Parallel sort of `(A encoding, original index)` pairs, so every signer's signatures sit
///    adjacent and grouping becomes local information ([`group_ranges`]).
/// 2. [`scalar_phase`]: coefficient derivation, hashing, and scalar arithmetic -- uniform per
///    signature, no curve points.
/// 3. Group sums: each distinct signer's coalesced scalar is a sum over a contiguous `zh` run.
///    Serial: even one signer covering a 16k batch is ~16k additions mod L, far below the cost
///    of the point work either side of it.
/// 4. [`decompress_phase`] over a flat worklist -- every `R`, plus every distinct `A` when
///    `a_points` is `None` -- into [`Term`] chunks, written where they're produced. When the
///    caller already holds decompressed `A` points ([`verify_batch`]), `a_points` supplies them
///    (indexed by *original* item position) and the coalesced `A` terms are built directly
///    instead.
/// 5. One tile-parallel MSM over the term chunks (with the coalesced basepoint term
///    `sum(z*s)·(-B)` riding along as one final term), then the cofactored identity check.
fn verify_batch_inner(
    rng: &mut impl CryptoRng,
    items: &[(&[u8; 32], &Signature, &[u8])],
    a_points: Option<&[&EdwardsPoint]>,
    strategy: &impl Strategy,
) -> bool {
    let n = items.len();
    if n == 0 {
        return true;
    }

    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // Including the original index in the sort key makes the order (and therefore the
    // position-derived coefficients) a deterministic function of the input, independent of the
    // sort algorithm.
    let mut order: Vec<([u8; 32], u32)> = items
        .iter()
        .enumerate()
        .map(|(i, (a_bytes, _, _))| (**a_bytes, i as u32))
        .collect();
    strategy.sort_by(&mut order, |x, y| x.cmp(y));

    let mut zh = vec![Scalar::ZERO; n];
    let mut zr = vec![Scalar::ZERO; n];
    let Some(s_sum) = scalar_phase(items, &order, &seed, &mut zh, &mut zr, strategy) else {
        return false;
    };

    let groups = group_ranges(&order);
    let a_scalars: Vec<Scalar> = groups
        .iter()
        .map(|&(start, end)| {
            zh[start as usize..end as usize]
                .iter()
                .fold(Scalar::ZERO, |acc, zh_i| acc.add_mod_l(zh_i))
        })
        .collect();

    let resolve_r = |i: usize| {
        let (_, sig, _) = items[order[i].1 as usize];
        (sig.r, zr[i])
    };
    let term_chunks = if let Some(points) = a_points {
        let mut chunks = match decompress_phase(n, resolve_r, strategy) {
            Some(chunks) => chunks,
            None => return false,
        };
        chunks.push(strategy.map_collect_vec(
            groups.iter().zip(&a_scalars),
            |(&(start, _), scalar)| {
                let point = points[order[start as usize].1 as usize];
                Term::new(MixedPoint::new(point), scalar)
            },
        ));
        chunks
    } else {
        let resolve = |i: usize| {
            if i < n {
                resolve_r(i)
            } else {
                let (start, _) = groups[i - n];
                (order[start as usize].0, a_scalars[i - n])
            }
        };
        match decompress_phase(n + groups.len(), resolve, strategy) {
            Some(chunks) => chunks,
            None => return false,
        }
    };

    // The coalesced basepoint term: `sum(z*s)·B` moved to the equation's other side as
    // `sum(z*s)·(-B)`, one more ordinary MSM term.
    let mut term_chunks = term_chunks;
    term_chunks.push(vec![Term::new(
        MixedPoint::new(&EdwardsPoint::basepoint().negate()),
        &s_sum,
    )]);

    msm::multiscalar_mul_terms_parallel(&term_chunks, strategy)
        .mul_by_cofactor()
        .is_identity()
}

/// Verifies a batch of `(verifying_key, signature, message)` triples, returning `true` only if
/// every item is valid.
///
/// This checks one random linear combination of the batch's individual cofactored verification
/// equations (see [`VerifyingKey::verify`]) rather than each one independently, via a single
/// multi-scalar multiplication over the batch's `R` and `A` points. `rng` must be a
/// cryptographically secure source of randomness: it seeds the per-signature combination
/// coefficients (see [`batch_coefficients`]), and predictable coefficients let an attacker
/// construct a batch that passes here despite containing a forged signature. Given a strong
/// `rng`, a false positive (an invalid batch passing) happens with probability at most `2⁻¹²⁸`.
/// `strategy` controls whether the batch's stages run serially or spread across a thread pool
/// (see [`commonware_parallel::Strategy`]); `A` is already decompressed once per
/// [`VerifyingKey`], so only `R` needs decompressing here. Use [`verify_batch_bytes`] instead if
/// `A` has not been decompressed yet either (e.g. a batch of raw wire bytes with no cached
/// keys).
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
    let byte_items: Vec<(&[u8; 32], &Signature, &[u8])> = items
        .iter()
        .map(|(vk, sig, msg)| (&vk.bytes, *sig, *msg))
        .collect();
    let a_points: Vec<&EdwardsPoint> = items.iter().map(|(vk, _, _)| &vk.point).collect();
    verify_batch_inner(rng, &byte_items, Some(&a_points), strategy)
}

/// Verifies a batch of `(verifying_key_bytes, signature, message)` triples, returning `true`
/// only if every item is valid.
///
/// Identical to [`verify_batch`], except it takes raw 32-byte verification key encodings
/// directly rather than requiring the caller to have already constructed a [`VerifyingKey`]: `A`
/// is coalesced by its raw encoding before ever being decompressed (see [`group_ranges`]), so a
/// signer reused across the batch is decompressed once, not once per signature, and the
/// deduplicated `A` encodings join `R`'s per-signature encodings in the same uniform
/// decompression pass. Use this starting from raw wire bytes with no cached keys; use
/// [`verify_batch`] when keys are reused across many batches and worth decompressing once up
/// front (e.g. a stable validator set).
#[commonware_macros::stability(ALPHA)]
pub fn verify_batch_bytes<'a>(
    rng: &mut impl CryptoRng,
    items: impl IntoIterator<Item = (&'a [u8; 32], &'a Signature, &'a [u8])>,
    strategy: &impl Strategy,
) -> bool {
    let items: Vec<_> = items.into_iter().collect();
    verify_batch_inner(rng, &items, None, strategy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use ed25519_consensus::SigningKey as RefSigningKey;
    use rand_core::Rng;

    #[test]
    fn group_ranges_groups_adjacent_equal_keys() {
        let sorted = vec![
            ([1u8; 32], 4),
            ([1u8; 32], 0),
            ([2u8; 32], 3),
            ([3u8; 32], 1),
            ([3u8; 32], 2),
            ([3u8; 32], 5),
        ];
        assert_eq!(group_ranges(&sorted), vec![(0, 2), (2, 3), (3, 6)]);
    }

    #[test]
    fn group_ranges_handles_empty_and_no_duplicates() {
        assert!(group_ranges(&[]).is_empty());

        let sorted = vec![([1u8; 32], 0), ([2u8; 32], 1)];
        assert_eq!(group_ranges(&sorted), vec![(0, 1), (1, 2)]);
    }

    #[test]
    fn batch_coefficients_are_deterministic_and_block_dependent() {
        let seed = [7u8; 32];
        let a = batch_coefficients(&seed, 0);
        let b = batch_coefficients(&seed, 0);
        for k in 0..4 {
            assert_eq!(a[k].0, b[k].0);
        }
        assert_ne!(
            batch_coefficients(&seed, 0)[0].0,
            batch_coefficients(&seed, 1)[0].0
        );
        assert_ne!(
            batch_coefficients(&seed, 0)[0].0,
            batch_coefficients(&[8u8; 32], 0)[0].0
        );
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

    #[test]
    fn verify_batch_bytes_rejects_invalid_key_encoding() {
        // `y = 2` has no corresponding curve point, so decompression must fail and reject the
        // batch.
        let mut rng = test_rng();
        let batch = valid_batch(4);
        let mut invalid = [0u8; 32];
        invalid[0] = 2;
        let items = batch
            .iter()
            .enumerate()
            .map(|(i, (vk, sig, msg))| (if i == 2 { &invalid } else { &vk.bytes }, sig, msg.as_slice()));
        assert!(!verify_batch_bytes(&mut rng, items, &Sequential));
    }

    /// Generates `n` valid signatures from a single signer over `n` independent messages, the
    /// workload key coalescing (see [`group_ranges`]) targets.
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
    fn verify_batch_bytes_accepts_repeated_signer() {
        let mut rng = test_rng();
        for n in [1, 2, 5, 16, 64] {
            let batch = repeated_signer_batch(n);
            let items = batch
                .iter()
                .map(|(vk, sig, msg)| (&vk.bytes, sig, msg.as_slice()));
            assert!(verify_batch_bytes(&mut rng, items, &Sequential));
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

    /// A batch of both independent signers and a repeated signer, spanning multiple scalar-phase
    /// chunks and decompression chunks, verified under `Manual` -- which disables the adaptive
    /// serial/parallel policy so every `strategy` call in this test genuinely dispatches across
    /// the thread pool, rather than the policy falling back to serial for a size it judges too
    /// small. Every other test in this module uses `Sequential`, so these are the only ones
    /// exercising real concurrent execution of the sort, the scalar phase, the fused
    /// decompression pass, and the tile-parallel MSM end to end.
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

    /// Batch verification's execution is a deterministic function of `(items, seed)` (see
    /// [`batch_coefficients`]), so serial and parallel strategies must agree on every batch --
    /// including invalid ones, where the accept/reject outcome depends on the derived
    /// coefficients.
    #[test]
    fn verify_batch_bytes_agrees_across_strategies_on_invalid_batch() {
        let strategy = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4))
            .unwrap()
            .manual();
        let mut batch = mixed_batch_with_repeats(300);
        batch[123].1.s[0] ^= 1;

        let items = batch
            .iter()
            .map(|(vk, sig, msg)| (&vk.bytes, sig, msg.as_slice()));
        let serial = verify_batch_bytes(&mut test_rng(), items, &Sequential);

        let items = batch
            .iter()
            .map(|(vk, sig, msg)| (&vk.bytes, sig, msg.as_slice()));
        let parallel = verify_batch_bytes(&mut test_rng(), items, &strategy);

        assert!(!serial);
        assert_eq!(serial, parallel);
    }
}
