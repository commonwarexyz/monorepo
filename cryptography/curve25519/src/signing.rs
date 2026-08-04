//! Ed25519 signing (public) keys, signatures, and (batch) verification.

mod error;
mod msm;
mod scalar;

use crate::simplified::{Backend, GAffine, LANES, WithBackend, with_backend};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use commonware_parallel::Strategy;
pub use error::Error;
use msm::Term;
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
        point: GAffine,
    }

    impl VerifyingKey {
        /// Decodes and validates a 32-byte verification key encoding.
        ///
        /// Following [ZIP215](https://github.com/zcash/zips/blob/master/zip-0215.rst),
        /// non-canonical `y` encodings (`y >= p`) are accepted; only encodings with no
        /// corresponding curve point are rejected.
        pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
            let point = GAffine::decompress(&bytes).ok_or(Error::InvalidVerificationKey)?;
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
            self.verify_with(message, signature)
        }

        fn verify_with(
            &self,
            message: &[u8],
            signature: &Signature,
        ) -> Result<(), Error> {
            let s = Scalar::from_canonical_bytes(&signature.s).ok_or(Error::NonCanonicalScalar)?;
            let r = GAffine::decompress(&signature.r).ok_or(Error::InvalidSignature)?;

            let digest = sha512(&[&signature.r, &self.bytes, message]);
            let k = Scalar::from_bytes_mod_order_wide(&digest);

            let sb = GAffine::BASEPOINT.to_extended().scalar_mul(s.bits_be());
            let ka = self.point.to_extended().scalar_mul(k.bits_be());
            let check = sb.add(ka.add_mixed(r).negate());
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

/// One [`scalar_phase`] output block: the `z*h` scalars (each signature's contribution to its
/// signer's coalesced `A` term) and `z` scalars (each `R` point's own MSM scalar) for the four
/// consecutive sorted positions covered by one [`batch_coefficients`] block, plus the block's
/// `sum(z*s)` contribution to the coalesced basepoint scalar.
struct ScalarBlock {
    zh: [Scalar; 4],
    zr: [Scalar; 4],
    zs_sum: Scalar,
    valid: bool,
}

/// The per-signature scalar phase, parallel over the sorted batch's coefficient blocks: for each
/// sorted position, derives `z` (see [`batch_coefficients`]), rejects a non-canonical `s`,
/// computes the challenge `h = H(R || A || M)`, and packs `z*h`/`z` into that position's
/// [`ScalarBlock`] slot. Returns the blocks together with `sum(z*s) mod L` -- the coalesced
/// basepoint scalar -- or `None` if any `s` was non-canonical (a structurally invalid signature,
/// rejected the same way [`VerifyingKey::verify`] rejects it).
///
/// The parallel unit is one 4-signature block -- the finest split that never derives a
/// coefficient block twice -- produced as a value and collected, so there is no output array to
/// pre-zero or scatter into, and the pool's demand-driven splitting balances the pass at block
/// granularity: a late-waking worker simply takes fewer blocks (see [`decompress_phase`] for the
/// same principle). This phase touches no curve points: it is uniform per signature regardless
/// of how the batch's signers are distributed.
fn scalar_phase(
    items: &[(&[u8; 32], &Signature, &[u8])],
    order: &[([u8; 32], u32)],
    seed: &[u8; 32],
    strategy: &impl Strategy,
) -> Option<(Vec<ScalarBlock>, Scalar)> {
    let n = items.len();
    let body = |block: usize| {
        let coefficients = batch_coefficients(seed, block as u64);
        let mut zh = [Scalar::ZERO; 4];
        let mut zr = [Scalar::ZERO; 4];
        let mut zs_sum = Scalar::ZERO;
        let mut valid = true;
        for (j, z) in coefficients.into_iter().enumerate() {
            let i = 4 * block + j;
            if i >= n {
                break;
            }
            let (a_bytes, sig, msg) = items[order[i].1 as usize];
            let Some(s) = Scalar::from_canonical_bytes(&sig.s) else {
                valid = false;
                continue;
            };
            let digest = sha512(&[&sig.r, a_bytes, msg]);
            let h = Scalar::from_bytes_mod_order_wide(&digest);
            zh[j] = z.mul_mod_l(&h);
            zr[j] = z;
            zs_sum = zs_sum.add_mod_l(&z.mul_mod_l(&s));
        }
        ScalarBlock {
            zh,
            zr,
            zs_sum,
            valid,
        }
    };

    let blocks: Vec<ScalarBlock> = strategy.map_collect_vec(0..n.div_ceil(4), body);
    let mut s_sum = Scalar::ZERO;
    for block in &blocks {
        if !block.valid {
            return None;
        }
        s_sum = s_sum.add_mod_l(&block.zs_sum);
    }
    Some((blocks, s_sum))
}

/// The decompression phase: turns a flat worklist of `count` point encodings (resolved by index
/// via `resolve`, which returns an encoding and its already-final MSM scalar) into MSM terms, in
/// one parallel pass over [`LANES`]-sized units -- the finest split that keeps the sqrt kernel
/// running 8-wide (see [`GAffine::decompress_batch`]), so the pool's demand-driven
/// splitting balances the pass at ~7us granularity and a late-waking worker simply takes fewer
/// units. Each fixed partition builds one exactly sized term vector, then the parallel fold joins
/// validity and vectors of those buffers without shared state or copying point data. The final
/// unit is padded with identity/zero terms, keeping decompression SIMD-wide without changing the
/// MSM.
///
/// Returns `None` if any encoding fails to decompress.
fn decompress_phase<B, F>(
    backend: B,
    count: usize,
    resolve: F,
    width: u32,
    strategy: &impl Strategy,
) -> Option<Vec<Vec<[Term; LANES]>>>
where
    B: Backend,
    F: Fn(usize) -> ([u8; 32], Scalar) + Send + Sync,
{
    let units = count.div_ceil(LANES);
    if units == 0 {
        return Some(Vec::new());
    }

    const PARTITIONS_PER_WORKER: usize = 4;
    const MIN_UNITS_PER_PARTITION: usize = 8;
    let target_partitions = strategy
        .manual()
        .parallelism()
        .saturating_mul(PARTITIONS_PER_WORKER);
    let max_partitions = (units / MIN_UNITS_PER_PARTITION).max(1);
    let partition_count = target_partitions.min(max_partitions).min(units);
    let partition_len = units / partition_count;
    let remainder = units % partition_count;
    let mut ranges = Vec::with_capacity(partition_count);
    let mut start = 0;
    for partition in 0..partition_count {
        let len = partition_len + usize::from(partition < remainder);
        ranges.push(start..start + len);
        start += len;
    }

    let placeholder = Term::new(GAffine::IDENTITY, &Scalar::ZERO, width);
    let mut identity_encoding = [0u8; 32];
    identity_encoding[0] = 1;

    let (valid, chunks) = strategy.fold(
        ranges,
        || (true, Vec::new()),
        |(valid, mut chunks), range| {
            let mut chunk_valid = true;
            let mut terms = Vec::with_capacity(range.len());
            for unit in range {
                let base = unit * LANES;
                let mut resolved = [(identity_encoding, Scalar::ZERO); LANES];
                for (lane, item) in resolved.iter_mut().enumerate() {
                    if base + lane < count {
                        *item = resolve(base + lane);
                    }
                }
                let bytes = resolved.map(|(bytes, _)| bytes);
                let points = GAffine::decompress_batch(backend, &bytes);
                terms.push(core::array::from_fn(|lane| {
                    if base + lane >= count {
                        return placeholder;
                    }
                    points[lane].map_or_else(
                        || {
                            chunk_valid = false;
                            placeholder
                        },
                        |point| Term::new(point, &resolved[lane].1, width),
                    )
                }));
            }
            chunks.push(terms);
            (valid && chunk_valid, chunks)
        },
        |(left_valid, mut left_chunks), (right_valid, right_chunks)| {
            left_chunks.extend(right_chunks);
            (left_valid && right_valid, left_chunks)
        },
    );
    valid.then_some(chunks)
}

/// The shared batch-verification pipeline (see [`verify_batch`] for the equation and its
/// security argument): a short sequence of data-parallel phases over flat arrays, with `A`
/// coalescing falling out of a sort.
///
/// 1. Sort of `(A encoding, original index)` pairs, so every signer's signatures sit adjacent
///    and grouping becomes local information ([`group_ranges`]).
/// 2. [`scalar_phase`]: coefficient derivation, hashing, and scalar arithmetic -- uniform per
///    signature, no curve points.
/// 3. [`decompress_phase`] over a flat worklist -- every `R`, plus every distinct `A` when
///    `a_points` is `None` -- into contiguous term chunks. A signer's coalesced scalar (the sum of
///    its signatures' `z*h` over a contiguous [`ScalarBlock`] run) is computed lazily by
///    whichever unit resolves its `A` entry, so there is no separate group-sum pass. When the
///    caller already holds decompressed `A` points ([`verify_batch`]), `a_points` supplies them
///    (indexed by *original* item position) and the coalesced `A` terms are built directly
///    instead, in a parallel map of their own.
/// 4. One tile-parallel MSM over the term slices (with the coalesced basepoint term
///    `sum(z*s)·(-B)` riding along as one final term), then the cofactored identity check.
fn verify_batch_inner<B: Backend>(
    backend: B,
    rng: &mut impl CryptoRng,
    items: &[(&[u8; 32], &Signature, &[u8])],
    a_points: Option<&[&GAffine]>,
    strategy: &impl Strategy,
) -> bool {
    let n = items.len();
    if n == 0 {
        return true;
    }

    // Every phase has a fixed work shape derived from the available parallelism. Disable adaptive
    // policy decisions and let the supplied strategy execute that shape directly.
    let strategy = &strategy.manual();

    // Sorting and grouping use compact indices.
    if u32::try_from(n).is_err() {
        return false;
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

    let Some((blocks, s_sum)) = scalar_phase(items, &order, &seed, strategy) else {
        return false;
    };
    let zr = |i: usize| blocks[i / 4].zr[i % 4];
    // A signer's coalesced scalar: the sum of its contiguous sorted run's `z*h` scalars. Cheap
    // mod-L additions, computed lazily (each group is resolved exactly once, by the worklist
    // entry for its `A` term), so the summing itself rides inside a parallel phase. A batch
    // dominated by one signer folds its whole run in that signer's single resolve call --
    // acceptable, since even a 16k-signature run is far cheaper than one decompression unit's
    // point arithmetic.
    let group_scalar = |(start, end): (u32, u32)| {
        (start as usize..end as usize).fold(Scalar::ZERO, |acc, i| {
            acc.add_mod_l(&blocks[i / 4].zh[i % 4])
        })
    };

    let groups = group_ranges(&order);
    // The MSM window width is a per-batch choice (see [`msm::width_for`]) and every term must
    // be recoded at the same width, so it is fixed here, before any term is built: the term
    // count is every `R`, every distinct `A`, and the basepoint.
    let width = msm::width_for(n + groups.len() + 1, strategy.parallelism());
    let resolve_r = |i: usize| {
        let (_, sig, _) = items[order[i].1 as usize];
        (sig.r, zr(i))
    };

    // The coalesced basepoint term: `sum(z*s)·B` moved to the equation's other side by negating
    // its scalar, one more ordinary MSM term.
    let basepoint = [Term::new(GAffine::BASEPOINT, &s_sum.neg_mod_l(), width)];

    let result = if let Some(points) = a_points {
        let Some(terms) = decompress_phase(backend, n, resolve_r, width, strategy) else {
            return false;
        };
        // `A` needs no decompression here, so its coalesced terms are built directly and gated
        // like the other phases.
        let a_body = |&(start, end): &(u32, u32)| {
            let point = points[order[start as usize].1 as usize];
            Term::new(*point, &group_scalar((start, end)), width)
        };
        let a_terms: Vec<Term> = strategy.map_collect_vec(groups.iter(), a_body);
        let mut chunks: Vec<&[Term]> = terms.iter().map(|chunk| chunk.as_flattened()).collect();
        chunks.push(a_terms.as_slice());
        chunks.push(basepoint.as_slice());
        msm::multiscalar_mul(backend, &chunks, width, strategy)
    } else {
        let resolve = |i: usize| {
            if i < n {
                resolve_r(i)
            } else {
                let group = groups[i - n];
                (order[group.0 as usize].0, group_scalar(group))
            }
        };
        let Some(terms) = decompress_phase(backend, n + groups.len(), resolve, width, strategy)
        else {
            return false;
        };
        let mut chunks: Vec<&[Term]> = terms.iter().map(|chunk| chunk.as_flattened()).collect();
        chunks.push(basepoint.as_slice());
        msm::multiscalar_mul(backend, &chunks, width, strategy)
    };
    result.mul_by_cofactor().is_identity()
}

struct VerifyBatchCall<'a, 'b, R, S> {
    rng: &'a mut R,
    items: &'a [(&'b [u8; 32], &'b Signature, &'b [u8])],
    a_points: Option<&'a [&'b GAffine]>,
    strategy: &'a S,
}

impl<R: CryptoRng, S: Strategy> WithBackend for VerifyBatchCall<'_, '_, R, S> {
    type Output = bool;

    fn call<B: Backend>(self, backend: B) -> Self::Output {
        verify_batch_inner(backend, self.rng, self.items, self.a_points, self.strategy)
    }
}

fn verify_batch_dispatch<'a, R: CryptoRng, S: Strategy>(
    rng: &mut R,
    items: &[(&'a [u8; 32], &'a Signature, &'a [u8])],
    a_points: Option<&[&'a GAffine]>,
    strategy: &S,
) -> bool {
    with_backend(VerifyBatchCall {
        rng,
        items,
        a_points,
        strategy,
    })
}

/// Verifies a batch of `(verifying_key, signature, message)` triples, returning `true` only if
/// every item is valid.
///
/// This checks one random linear combination of the batch's individual cofactored verification
/// equations (see [`VerifyingKey::verify`]) rather than each one independently, via a single
/// multi-scalar multiplication over the batch's `R` and `A` points. `rng` must be a
/// cryptographically secure source of randomness: it seeds the per-signature combination
/// coefficients (see `batch_coefficients`), and predictable coefficients let an attacker
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
    let a_points: Vec<&GAffine> = items.iter().map(|(vk, _, _)| &vk.point).collect();
    verify_batch_dispatch(rng, &byte_items, Some(&a_points), strategy)
}

/// Verifies a batch of `(verifying_key_bytes, signature, message)` triples, returning `true`
/// only if every item is valid.
///
/// Identical to [`verify_batch`], except it takes raw 32-byte verification key encodings
/// directly rather than requiring the caller to have already constructed a [`VerifyingKey`]: `A`
/// is coalesced by its raw encoding before ever being decompressed (see `group_ranges`), so a
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
    verify_batch_dispatch(rng, &items, None, strategy)
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
    fn verifying_key_from_bytes_follows_zip215_encoding_rules() {
        // y = p + 1 is a non-canonical encoding of the identity's y-coordinate and is accepted.
        let mut noncanonical_identity = [0xff; 32];
        noncanonical_identity[0] = 0xee;
        noncanonical_identity[31] = 0x7f;
        assert!(VerifyingKey::from_bytes(noncanonical_identity).is_ok());

        // The identity has x = 0, which has no negative encoding.
        let mut negative_zero = [0u8; 32];
        negative_zero[0] = 1;
        negative_zero[31] = 0x80;
        assert_eq!(
            VerifyingKey::from_bytes(negative_zero).unwrap_err(),
            Error::InvalidVerificationKey
        );
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
        let items = batch.iter().enumerate().map(|(i, (vk, sig, msg))| {
            (
                if i == 2 { &invalid } else { &vk.bytes },
                sig,
                msg.as_slice(),
            )
        });
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
