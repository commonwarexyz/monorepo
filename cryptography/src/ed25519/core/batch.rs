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

use super::{native, Error, Signature, VerificationKey};
use crate::transcript::{Summary, Transcript};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap as Map, vec::Vec};
use commonware_math::algebra::Random;
use commonware_parallel::Strategy;
use core::mem;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use sha2::{digest::Update, Sha512};
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
type Map<K, V> = HashMap<K, V>;

const NOISE_BATCH_VERIFY: &[u8] = b"batch_verify";

/// A slice of signatures sharing one verification key.
type GroupSlice<'a> = (&'a VerificationKey, &'a [QueuedSignature]);

#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
struct QueuedSignature {
    k: Scalar,
    R_bytes: [u8; 32],
    s_bytes: [u8; 32],
    /// Committed decompression hint for `R` (the affine `x`), if this is a hinted
    /// signature. When present, `R` is recovered without a square root.
    R_x: Option<[u8; 32]>,
}

// Shim to generate a u128 without importing `rand`.
fn gen_u128<R: RngCore + CryptoRng>(mut rng: R) -> u128 {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes[..]);
    u128::from_le_bytes(bytes)
}

// Recover `R` for a queued signature: validate the committed hint without a
// square root when present, otherwise decompress.
fn decompress_signature(sig: &QueuedSignature) -> Option<native::Point> {
    sig.R_x.map_or_else(
        || native::Point::decompress(&sig.R_bytes),
        |x| native::Point::decompress_with_hint(&sig.R_bytes, &x),
    )
}

/// A batch verification item.
///
/// This struct exists to allow batch processing to be decoupled from the
/// lifetime of the message. This is useful when using the batch verification API
/// in an async context.
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Item {
    vk: VerificationKey,
    k: Scalar,
    R_bytes: [u8; 32],
    s_bytes: [u8; 32],
    R_x: Option<[u8; 32]>,
}

impl<'msg, M: AsRef<[u8]> + ?Sized> From<(VerificationKey, Signature, &'msg M)> for Item {
    fn from(tup: (VerificationKey, Signature, &'msg M)) -> Self {
        let (vk, sig, msg) = tup;
        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&sig.R_bytes[..])
                .chain(vk.as_bytes())
                .chain(msg),
        );
        Self {
            vk,
            k,
            R_bytes: sig.R_bytes,
            s_bytes: sig.s_bytes,
            R_x: None,
        }
    }
}

/// A batch verification context.
#[derive(Default)]
pub struct Verifier {
    /// Signature data queued for verification.
    signatures: Map<VerificationKey, Vec<QueuedSignature>>,
    /// Caching this count avoids a map traversal to figure out
    /// how much to preallocate.
    batch_size: usize,
}

impl Verifier {
    /// Construct a new batch verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a `(key, signature, message)` tuple for verification.
    pub fn queue<I: Into<Item>>(&mut self, item: I) {
        let Item {
            vk,
            k,
            R_bytes,
            s_bytes,
            R_x,
        } = item.into();

        self.signatures
            .entry(vk)
            // The common case is 1 signature per public key.
            // We could also consider using a smallvec here.
            .or_insert_with(|| Vec::with_capacity(1))
            .push(QueuedSignature {
                k,
                R_bytes,
                s_bytes,
                R_x,
            });
        self.batch_size += 1;
    }

    /// Queue a hinted signature for verification. `vk` is the already-decompressed
    /// verification key, and `R_x` is the committed decompression hint for `R`.
    /// `R` is recovered via [`native::Point::decompress_with_hint`] (no square
    /// root); an invalid hint makes the signature invalid, with no fallback.
    #[allow(non_snake_case)]
    pub fn queue_hinted<M: AsRef<[u8]> + ?Sized>(
        &mut self,
        vk: VerificationKey,
        R_bytes: [u8; 32],
        s_bytes: [u8; 32],
        R_x: [u8; 32],
        msg: &M,
    ) {
        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&R_bytes[..])
                .chain(vk.as_bytes())
                .chain(msg),
        );
        self.signatures
            .entry(vk)
            .or_insert_with(|| Vec::with_capacity(1))
            .push(QueuedSignature {
                k,
                R_bytes,
                s_bytes,
                R_x: Some(R_x),
            });
        self.batch_size += 1;
    }

    /// Perform batch verification, returning `Ok(())` if all signatures were
    /// valid and `Err` otherwise.
    ///
    /// Both this method and [`VerificationKey::verify`](super::VerificationKey::verify)
    /// implement the ZIP215 rules, so batch verification agrees with individual
    /// verification (up to the negligible failure probability of the random
    /// linear combination).
    #[allow(non_snake_case)]
    pub fn verify<R: RngCore + CryptoRng>(
        self,
        mut rng: R,
        strategy: &impl Strategy,
    ) -> Result<(), Error> {
        // A batch of one is the single-signature cofactored check. Verifying it directly skips
        // the random multiplier, transcript, and multiscalar setup.
        if self.batch_size == 1 {
            let (vk, sigs) = self.signatures.into_iter().next().expect("batch size is 1");
            let sig = sigs.into_iter().next().expect("batch size is 1");
            let R = decompress_signature(&sig).ok_or(Error::InvalidSignature)?;
            let s = Scalar::from_canonical_bytes(sig.s_bytes)
                .into_option()
                .ok_or(Error::InvalidSignature)?;
            return vk.verify_prehashed_parts(R, s, sig.k);
        }

        let batch_size = self.batch_size;
        let groups: Vec<_> = self.signatures.into_iter().collect();

        // Split all signatures into shards of roughly `batch_size / cores` signatures
        // for parallel processing, each with an independently seeded randomizer stream.
        let parallelism = strategy.parallelism_hint().max(1);
        let shards = chunk_groups(&groups, batch_size, parallelism, &mut rng);

        strategy.fold(
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
                // - k_i is the hash of the message and other data;
                // - z_i is a random 128-bit Scalar.
                //
                // Normally n signatures would require a multiscalar multiplication of
                // size 2*n + 1, together with 2*n point decompressions (to obtain A_i
                // and R_i). However, because we store batch entries in a map
                // indexed by the verification key, we can "coalesce" all z_i * k_i
                // terms for each distinct verification key into a single coefficient.
                //
                // For n signatures from m verification keys, this approach instead
                // requires a multiscalar multiplication of size n + m + 1. Verification
                // keys and signature R values are decoded before the multiscalar
                // multiplication, so this path reuses the already-decoded points. When
                // m = n, so all signatures are from distinct verification keys, this
                // saves n decompressions relative to the usual method. However, when
                // m = 1 and all signatures are from a single verification key, this is
                // nearly twice as fast.

                let m = shard.len();
                let batch_size: usize = shard.iter().map(|(_, sigs)| sigs.len()).sum();
                let mut signatures = Vec::with_capacity(batch_size);
                let mut A_coeffs = vec![Scalar::ZERO; m];
                for (i, (_, sigs)) in shard.iter().enumerate() {
                    for sig in *sigs {
                        signatures.push((i, *sig));
                    }
                }

                let mut scalars = Vec::with_capacity(m + batch_size + 1);
                let mut points = Vec::with_capacity(m + batch_size + 1);
                let mut B_coeff = Scalar::ZERO;

                for (group, sig) in signatures.iter().copied() {
                    let R = decompress_signature(&sig).ok_or(Error::InvalidSignature)?;
                    let s = Scalar::from_canonical_bytes(sig.s_bytes)
                        .into_option()
                        .ok_or(Error::InvalidSignature)?;
                    let z = Scalar::from(gen_u128(&mut rng));
                    B_coeff -= z * s;
                    points.push(R);
                    scalars.push(z);
                    A_coeffs[group] += z * sig.k;
                }

                for ((vk, _), A_coeff) in shard.iter().zip(A_coeffs) {
                    points.push(vk.A);
                    scalars.push(A_coeff);
                }

                points.push(native::Point::basepoint());
                scalars.push(B_coeff);

                let check = native::vartime_multiscalar_mul(&scalars, &points);

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

/// Split per-key signature groups into `count` chunks of roughly equal signature
/// counts, splitting large groups across chunks (which only loses key coalescing
/// at the split boundaries). Each chunk is paired with an independent randomizer
/// seed drawn from `rng`.
fn chunk_groups<'a, R: RngCore + CryptoRng>(
    groups: &'a [(VerificationKey, Vec<QueuedSignature>)],
    batch_size: usize,
    count: usize,
    mut rng: R,
) -> Vec<(Vec<GroupSlice<'a>>, Summary)> {
    let chunk_size = batch_size.div_ceil(count).max(1);
    let mut chunks = Vec::with_capacity(count);
    let mut current: Vec<GroupSlice<'a>> = Vec::new();
    let mut remaining = chunk_size;
    for (vk, sigs) in groups {
        let mut rest: &[QueuedSignature] = sigs;
        while !rest.is_empty() {
            let take = remaining.min(rest.len());
            let (head, tail) = rest.split_at(take);
            current.push((vk, head));
            rest = tail;
            remaining -= take;
            if remaining == 0 {
                chunks.push((mem::take(&mut current), Summary::random(&mut rng)));
                remaining = chunk_size;
            }
        }
    }
    if !current.is_empty() {
        chunks.push((current, Summary::random(&mut rng)));
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::core::VerificationKey;
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;
    use curve25519_dalek::{
        constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION},
        edwards::CompressedEdwardsY,
        traits::IsIdentity,
    };
    use rand_core::RngCore;

    fn random_scalar(rng: &mut impl RngCore) -> Scalar {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    fn challenge(r_bytes: &[u8; 32], a_bytes: &[u8; 32], msg: &[u8]) -> Scalar {
        Scalar::from_hash(Sha512::default().chain(r_bytes).chain(a_bytes).chain(msg))
    }

    fn signature(r_bytes: [u8; 32], s: Scalar) -> Signature {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&r_bytes);
        bytes[32..].copy_from_slice(s.as_bytes());
        Signature::from(bytes)
    }

    /// Asserts single verification and batch verification (alone and alongside an
    /// honest signature) agree on `expected` for the given signature.
    fn assert_agreement(vk: &VerificationKey, sig: &Signature, msg: &[u8], expected: bool) {
        let mut rng = test_rng();
        assert_eq!(vk.verify(sig, msg).is_ok(), expected);

        // Batch of one exercises the single-signature delegation.
        let mut verifier = Verifier::new();
        verifier.queue((*vk, *sig, msg));
        assert_eq!(verifier.verify(&mut rng, &Sequential).is_ok(), expected);

        // Batch of two exercises the multiscalar path.
        let honest = honest_signer(&mut rng);
        let mut verifier = Verifier::new();
        verifier.queue((*vk, *sig, msg));
        verifier.queue((honest.0, honest.1, &honest.2[..]));
        assert_eq!(verifier.verify(&mut rng, &Sequential).is_ok(), expected);
    }

    fn honest_signer(rng: &mut impl RngCore) -> (VerificationKey, Signature, [u8; 32]) {
        let a = random_scalar(rng);
        let big_a = a * ED25519_BASEPOINT_POINT;
        let a_bytes = big_a.compress().to_bytes();
        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);
        let r = random_scalar(rng);
        let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let k = challenge(&r_bytes, &a_bytes, &msg);
        let vk = VerificationKey::try_from(a_bytes).unwrap();
        (vk, signature(r_bytes, r + k * a), msg)
    }

    /// All decodable encodings of small order points, including the non-canonical
    /// encodings ZIP215 requires accepting.
    fn small_order_encodings() -> Vec<[u8; 32]> {
        // Field prime p = 2^255 - 19.
        let mut p_bytes = [0xffu8; 32];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;

        let mut encodings = Vec::new();
        for point in EIGHT_TORSION.iter() {
            let canonical = point.compress().to_bytes();
            let mut candidates = vec![canonical];
            // Sign-flipped variant (meaningful when x == 0).
            let mut flipped = canonical;
            flipped[31] ^= 0x80;
            candidates.push(flipped);
            // Non-canonical variant: y + p still fits in 255 bits when y < 19.
            let y_small = canonical[1..31].iter().all(|&b| b == 0)
                && canonical[0] < 19
                && (canonical[31] & 0x7f) == 0;
            if y_small {
                let mut shifted = canonical;
                let mut carry = u16::from(p_bytes[0]) + u16::from(canonical[0]);
                shifted[0] = carry as u8;
                for i in 1..32 {
                    carry = u16::from(p_bytes[i]) + u16::from(canonical[i] & 0x7f) + (carry >> 8);
                    shifted[i] = carry as u8;
                }
                shifted[31] |= canonical[31] & 0x80;
                candidates.push(shifted);
                let mut shifted_flipped = shifted;
                shifted_flipped[31] ^= 0x80;
                candidates.push(shifted_flipped);
            }
            for candidate in candidates {
                let Some(decoded) = CompressedEdwardsY(candidate).decompress() else {
                    continue;
                };
                assert!(decoded.mul_by_cofactor().is_identity());
                encodings.push(candidate);
            }
        }
        encodings.sort();
        encodings.dedup();
        encodings
    }

    /// Signatures with small order `A` and `R` and `s = 0` satisfy the cofactored
    /// equation for any message, including via non-canonical encodings. ZIP215
    /// requires accepting them, and single and batch verification must agree.
    #[test]
    fn test_zip215_small_order() {
        let encodings = small_order_encodings();
        // 8 canonical + sign-flips and non-canonical variants of x == 0 points
        assert!(encodings.len() >= 14, "found {}", encodings.len());
        for a_bytes in &encodings {
            let vk = VerificationKey::try_from(*a_bytes).unwrap();
            for r_bytes in &encodings {
                let sig = signature(*r_bytes, Scalar::ZERO);
                assert_agreement(&vk, &sig, b"zip215", true);
            }
        }
    }

    /// A public key with a torsion component satisfies the cofactored equation
    /// but not the cofactorless one. Single and batch verification must agree.
    #[test]
    fn test_zip215_torsioned_key() {
        let mut rng = test_rng();
        let a = random_scalar(&mut rng);
        let msg = b"torsioned key";
        for torsion in EIGHT_TORSION.iter().skip(1) {
            let big_a = a * ED25519_BASEPOINT_POINT + torsion;
            let a_bytes = big_a.compress().to_bytes();
            let vk = VerificationKey::try_from(a_bytes).unwrap();
            let r = random_scalar(&mut rng);
            let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();
            let k = challenge(&r_bytes, &a_bytes, msg);
            assert_agreement(&vk, &signature(r_bytes, r + k * a), msg, true);
        }
    }

    /// An `R` with a torsion component satisfies the cofactored equation but not
    /// the cofactorless one. Single and batch verification must agree.
    #[test]
    fn test_zip215_torsioned_r() {
        let mut rng = test_rng();
        let a = random_scalar(&mut rng);
        let a_bytes = (a * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let vk = VerificationKey::try_from(a_bytes).unwrap();
        let msg = b"torsioned R";
        for torsion in EIGHT_TORSION.iter().skip(1) {
            let r = random_scalar(&mut rng);
            let r_bytes = (r * ED25519_BASEPOINT_POINT + torsion)
                .compress()
                .to_bytes();
            let k = challenge(&r_bytes, &a_bytes, msg);
            assert_agreement(&vk, &signature(r_bytes, r + k * a), msg, true);
        }
    }

    /// Multiple signatures from the same torsioned key exercise the coalesced
    /// terms in the batch equation.
    #[test]
    fn test_zip215_torsioned_key_coalesced() {
        let mut rng = test_rng();
        let a = random_scalar(&mut rng);
        let big_a = a * ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        let a_bytes = big_a.compress().to_bytes();
        let vk = VerificationKey::try_from(a_bytes).unwrap();

        let mut verifier = Verifier::new();
        for msg in [&b"first"[..], &b"second"[..], &b"third"[..]] {
            let r = random_scalar(&mut rng);
            let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();
            let k = challenge(&r_bytes, &a_bytes, msg);
            let sig = signature(r_bytes, r + k * a);
            assert!(vk.verify(&sig, msg).is_ok());
            verifier.queue((vk, sig, msg));
        }
        assert!(verifier.verify(test_rng(), &Sequential).is_ok());
    }

    /// A non-canonical `s` must be rejected by single and batch verification.
    #[test]
    fn test_non_canonical_s_rejected() {
        let mut rng = test_rng();
        let (vk, sig, msg) = honest_signer(&mut rng);
        let mut bytes = sig.to_bytes();
        // Add the group order to s, exceeding the canonical range.
        let order_wide = {
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&[
                0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10,
            ]);
            wide
        };
        let mut carry = 0u16;
        for i in 0..32 {
            carry = u16::from(bytes[32 + i]) + u16::from(order_wide[i]) + (carry >> 8);
            bytes[32 + i] = carry as u8;
        }
        assert_eq!(
            carry >> 8,
            0,
            "s + L must still fit in 32 bytes for this vector"
        );
        assert_agreement(&vk, &Signature::from(bytes), &msg, false);
    }

    /// A corrupted signature must be rejected by single and batch verification.
    #[test]
    fn test_corrupted_signature_rejected() {
        let mut rng = test_rng();
        let (vk, sig, msg) = honest_signer(&mut rng);
        let mut bytes = sig.to_bytes();
        bytes[40] ^= 0x01;
        assert_agreement(&vk, &Signature::from(bytes), &msg, false);
    }

    /// Builds a batch covering distinct-signer, repeated-signer, and ZIP215 edge
    /// signatures (torsioned key, torsioned R).
    fn mixed_batch(rng: &mut impl RngCore, n: usize) -> Verifier {
        let mut verifier = Verifier::new();
        for i in 0..n.saturating_sub(4) {
            let (vk, sig, msg) = honest_signer(rng);
            verifier.queue((vk, sig, &msg[..]));
            // Occasionally pile a second signature onto the same key.
            if i % 7 == 0 {
                let a = random_scalar(rng);
                let big_a = a * ED25519_BASEPOINT_POINT;
                let a_bytes = big_a.compress().to_bytes();
                let vk = VerificationKey::try_from(a_bytes).unwrap();
                for msg in [&b"one"[..], &b"two"[..]] {
                    let r = random_scalar(rng);
                    let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();
                    let k = challenge(&r_bytes, &a_bytes, msg);
                    verifier.queue((vk, signature(r_bytes, r + k * a), msg));
                }
            }
        }
        // Torsioned key.
        let a = random_scalar(rng);
        let big_a = a * ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        let a_bytes = big_a.compress().to_bytes();
        let vk = VerificationKey::try_from(a_bytes).unwrap();
        let r = random_scalar(rng);
        let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let k = challenge(&r_bytes, &a_bytes, b"torsion A");
        verifier.queue((vk, signature(r_bytes, r + k * a), &b"torsion A"[..]));
        // Torsioned R.
        let a = random_scalar(rng);
        let a_bytes = (a * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let vk = VerificationKey::try_from(a_bytes).unwrap();
        let r = random_scalar(rng);
        let r_bytes = (r * ED25519_BASEPOINT_POINT + EIGHT_TORSION[3])
            .compress()
            .to_bytes();
        let k = challenge(&r_bytes, &a_bytes, b"torsion R");
        verifier.queue((vk, signature(r_bytes, r + k * a), &b"torsion R"[..]));
        // Small order key and R with s = 0.
        let vk = VerificationKey::try_from(EIGHT_TORSION[2].compress().to_bytes()).unwrap();
        let sig = signature(EIGHT_TORSION[5].compress().to_bytes(), Scalar::ZERO);
        verifier.queue((vk, sig, &b"small order"[..]));
        // Same-signer run that straddles chunk boundaries.
        let a = random_scalar(rng);
        let a_bytes = (a * ED25519_BASEPOINT_POINT).compress().to_bytes();
        let vk = VerificationKey::try_from(a_bytes).unwrap();
        for i in 0..16u8 {
            let r = random_scalar(rng);
            let r_bytes = (r * ED25519_BASEPOINT_POINT).compress().to_bytes();
            let msg = [i; 4];
            let k = challenge(&r_bytes, &a_bytes, &msg);
            verifier.queue((vk, signature(r_bytes, r + k * a), &msg[..]));
        }
        verifier
    }

    /// Parallel and sequential verification must agree on valid and invalid
    /// batches, including batches whose per-key groups straddle shard boundaries.
    #[test]
    fn test_parallel_agreement() {
        let rayon = commonware_parallel::Rayon::new(commonware_utils::NZUsize!(4)).unwrap();
        for n in [120usize, 300, 500] {
            let mut rng = test_rng();
            assert!(mixed_batch(&mut rng, n).verify(&mut rng, &rayon).is_ok());
            assert!(mixed_batch(&mut rng, n)
                .verify(&mut rng, &Sequential)
                .is_ok());

            // Corrupt one signature: both strategies must reject.
            let corrupted = || {
                let mut rng = test_rng();
                let mut verifier = mixed_batch(&mut rng, n);
                let (vk, sig, msg) = honest_signer(&mut rng);
                let mut bytes = sig.to_bytes();
                bytes[2] ^= 0x04;
                verifier.queue((vk, Signature::from(bytes), &msg[..]));
                verifier
            };
            assert!(corrupted().verify(test_rng(), &rayon).is_err());
            assert!(corrupted().verify(test_rng(), &Sequential).is_err());
        }
    }
}
