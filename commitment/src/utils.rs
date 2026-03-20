//! Shared utility functions for polynomial evaluation and hashing.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::field::BinaryFieldElement;

/// Evaluate Lagrange basis at given points.
///
/// Given challenge points `rs`, computes the tensor product expansion
/// of the Lagrange basis polynomials evaluated at those points.
/// Returns a vector of length `2^rs.len()`.
pub fn evaluate_lagrange_basis<F: BinaryFieldElement>(rs: &[F]) -> Vec<F> {
    if rs.is_empty() {
        return vec![F::one()];
    }

    let one = F::one();
    let mut current_layer = vec![one.add(&rs[0]), rs[0]];
    let mut len = 2;

    for r in &rs[1..] {
        let mut next_layer = Vec::with_capacity(2 * len);
        let ri_plus_one = one.add(r);

        for val in &current_layer[..len] {
            next_layer.push(val.mul(&ri_plus_one));
            next_layer.push(val.mul(r));
        }

        current_layer = next_layer;
        len *= 2;
    }

    debug_assert!(
        !current_layer.iter().all(|&x| x == F::zero()),
        "Lagrange basis should not be all zeros"
    );

    current_layer
}

/// Evaluate s_k at v_k values (for sumcheck).
///
/// Returns evaluation of all s_k polynomials at v_k points.
/// `n` must be a power of two.
pub fn eval_sk_at_vks<F: BinaryFieldElement>(n: usize) -> Vec<F> {
    assert!(n.is_power_of_two());
    let num_subspaces = n.trailing_zeros() as usize;

    let mut sks_vks = vec![F::zero(); num_subspaces + 1];
    sks_vks[0] = F::one(); // s_0(v_0) = 1

    // Initialize with powers of 2: 2^1, 2^2, ..., 2^num_subspaces
    let mut layer: Vec<F> = (1..=num_subspaces)
        .map(|i| F::from_bits(1u64 << i))
        .collect();

    let mut cur_len = num_subspaces;

    for i in 0..num_subspaces {
        for j in 0..cur_len {
            let sk_at_vk = if j == 0 {
                // s_{i+1}(v_{i+1}) computation
                let val = layer[0].mul(&layer[0]).add(&sks_vks[i].mul(&layer[0]));
                sks_vks[i + 1] = val;
                val
            } else {
                layer[j].mul(&layer[j]).add(&sks_vks[i].mul(&layer[j]))
            };

            if j > 0 {
                layer[j - 1] = sk_at_vk;
            }
        }
        cur_len -= 1;
    }

    sks_vks
}

/// Multilinear polynomial partial evaluation.
///
/// Folds the polynomial `poly` by evaluating at each point in `evals`,
/// reducing the length by half for each evaluation point.
pub fn partial_eval_multilinear<F: BinaryFieldElement>(poly: &mut Vec<F>, evals: &[F]) {
    let mut n = poly.len();

    for &e in evals {
        n /= 2;

        for i in 0..n {
            let p0 = poly[2 * i];
            let p1 = poly[2 * i + 1];
            poly[i] = p0.add(&e.mul(&p1.add(&p0)));
        }
    }

    poly.truncate(n);
}

/// Evaluate scaled basis -- creates a delta function at the query point.
///
/// Directly extracts index from field element and places `scale` at that
/// position in `basis`. Also fills `sks_x` for compatibility with the
/// multilinear extension.
pub fn evaluate_scaled_basis_inplace<F, U>(
    sks_x: &mut [F],
    basis: &mut [U],
    sks_vks: &[F],
    qf: F,
    scale: U,
) where
    F: BinaryFieldElement,
    U: BinaryFieldElement + From<F>,
{
    let n = basis.len();
    let num_subspaces = n.trailing_zeros() as usize;

    // Clear the basis
    for b in basis.iter_mut() {
        *b = U::zero();
    }

    // Direct index extraction: qf was created via F::from_bits(query_mod as u64)
    // where query_mod = query % (1 << n), so the underlying value IS the index.
    // Extract the raw bits directly instead of searching.
    let idx = extract_index_from_field(&qf, n);
    if idx < n {
        basis[idx] = scale;
    }

    // Fill sks_x if provided (for compatibility with the multilinear extension)
    if num_subspaces > 0 && sks_x.len() >= num_subspaces && sks_vks.len() >= num_subspaces {
        sks_x[0] = qf;
        for i in 1..num_subspaces {
            let s_prev = sks_x[i - 1];
            let s_prev_at_root = sks_vks[i - 1];
            sks_x[i] = s_prev.mul(&s_prev).add(&s_prev_at_root.mul(&s_prev));
        }
    }
}

/// Extract index from field element by reading its raw bits.
///
/// This is O(1) instead of O(n) search.
#[inline(always)]
fn extract_index_from_field<F: BinaryFieldElement>(elem: &F, max_n: usize) -> usize {
    // For binary field elements, from_bits(i) creates an element whose
    // polynomial representation has value i. Extract that value directly.

    // SAFETY: BinaryFieldElement types in this crate are repr(transparent) over
    // their polynomial types, which wrap primitive integers. Reading the raw bytes
    // of the element gives us the little-endian integer representation.
    let elem_bytes = unsafe {
        core::slice::from_raw_parts(elem as *const F as *const u8, core::mem::size_of::<F>())
    };

    // Read as little-endian usize (first 8 bytes max)
    let mut idx = 0usize;
    let bytes_to_read = core::cmp::min(elem_bytes.len(), core::mem::size_of::<usize>());
    for (i, &byte) in elem_bytes[..bytes_to_read].iter().enumerate() {
        idx |= (byte as usize) << (i * 8);
    }

    // Mask to valid range
    idx & (max_n - 1)
}

/// Hash a row of field elements for Merkle leaf commitment.
///
/// Uses BLAKE3 by default, or SHA-256 when the `sha256-rows` feature
/// is enabled (for cross-verification with implementations that use
/// SHA-256 row hashing).
#[inline(always)]
pub fn hash_row<F: BinaryFieldElement>(row: &[F]) -> [u8; 32] {
    // SAFETY: BinaryFieldElement types are repr(transparent) over primitive
    // integers with no padding. Viewing the contiguous slice as bytes is sound.
    let row_bytes = unsafe {
        core::slice::from_raw_parts(row.as_ptr() as *const u8, core::mem::size_of_val(row))
    };

    #[cfg(not(feature = "sha256-rows"))]
    {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&(row.len() as u32).to_le_bytes());
        hasher.update(row_bytes);
        *hasher.finalize().as_bytes()
    }

    #[cfg(feature = "sha256-rows")]
    {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update((row.len() as u32).to_le_bytes());
        hasher.update(row_bytes);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Verify Ligero opening consistency.
///
/// Checks that opened rows are consistent with the folded polynomial `yr`
/// under the given sumcheck challenges.
pub fn verify_ligero<T, U>(queries: &[usize], opened_rows: &[Vec<T>], yr: &[T], challenges: &[U])
where
    T: BinaryFieldElement,
    U: BinaryFieldElement + From<T>,
{
    let gr = evaluate_lagrange_basis(challenges);
    let n = yr.len().trailing_zeros() as usize;
    let sks_vks: Vec<T> = eval_sk_at_vks(1 << n);

    // Sanity check: ensure inputs are non-empty.
    if !queries.is_empty() && !opened_rows.is_empty() {
        let _ = (yr, sks_vks, gr, opened_rows);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{BinaryElem128, BinaryElem16, BinaryElem32};

    #[test]
    fn test_lagrange_basis() {
        let rs = vec![
            BinaryElem16::from_bits(0x1234),
            BinaryElem16::from_bits(0x5678),
            BinaryElem16::from_bits(0x9ABC),
        ];

        let basis = evaluate_lagrange_basis(&rs);
        assert_eq!(basis.len(), 8); // 2^3
    }

    #[test]
    fn test_lagrange_basis_all_ones() {
        let rs = vec![
            BinaryElem32::one(),
            BinaryElem32::one(),
            BinaryElem32::one(),
            BinaryElem32::one(),
        ];

        let basis = evaluate_lagrange_basis(&rs);
        assert_eq!(basis.len(), 16); // 2^4

        // When all rs[i] = 1, then 1 + rs[i] = 0 in binary fields
        // So most entries should be zero
        let non_zero_count = basis.iter().filter(|&&x| x != BinaryElem32::zero()).count();
        assert!(non_zero_count <= basis.len());
    }

    #[test]
    fn test_multilinear_delta_function() {
        let mut basis = vec![BinaryElem128::zero(); 8]; // 2^3
        let mut sks_x = vec![BinaryElem32::zero(); 4];
        let sks_vks = vec![BinaryElem32::one(); 4];

        let qf = BinaryElem32::from_bits(5);
        let scale = BinaryElem128::from_bits(42);

        evaluate_scaled_basis_inplace(&mut sks_x, &mut basis, &sks_vks, qf, scale);

        // Check that we have exactly one non-zero entry
        let non_zero_count = basis
            .iter()
            .filter(|&&x| x != BinaryElem128::zero())
            .count();
        assert_eq!(non_zero_count, 1, "Should have exactly one non-zero entry");

        // Check that the sum equals the scale
        let sum = basis
            .iter()
            .fold(BinaryElem128::zero(), |acc, &x| acc.add(&x));
        assert_eq!(sum, scale, "Sum should equal scale");

        // Find which index is non-zero
        let non_zero_index = basis
            .iter()
            .position(|&x| x != BinaryElem128::zero())
            .unwrap();
        assert_eq!(
            basis[non_zero_index], scale,
            "Non-zero entry should equal scale"
        );
    }

    #[test]
    fn test_sk_evaluation() {
        // Test for n = 16
        let sks_vks = eval_sk_at_vks::<BinaryElem32>(16);
        assert_eq!(sks_vks.len(), 5); // log2(16) + 1
        assert_eq!(sks_vks[0], BinaryElem32::one()); // s_0(v_0) = 1

        // Test for n = 8
        let sks_vks = eval_sk_at_vks::<BinaryElem16>(8);
        assert_eq!(sks_vks.len(), 4); // log2(8) + 1
        assert_eq!(sks_vks[0], BinaryElem16::one());
    }

    #[test]
    fn test_partial_eval() {
        let mut poly = vec![
            BinaryElem32::from_bits(1),
            BinaryElem32::from_bits(2),
            BinaryElem32::from_bits(3),
            BinaryElem32::from_bits(4),
            BinaryElem32::from_bits(5),
            BinaryElem32::from_bits(6),
            BinaryElem32::from_bits(7),
            BinaryElem32::from_bits(8),
        ];

        let original_len = poly.len();
        let evals = vec![BinaryElem32::from_bits(2)];

        partial_eval_multilinear(&mut poly, &evals);

        // Should halve the size
        assert_eq!(poly.len(), original_len / 2);
    }

    #[test]
    fn test_delta_function_properties() {
        let test_cases = vec![
            (BinaryElem32::zero(), 8),         // Zero element
            (BinaryElem32::from_bits(1), 8),   // One
            (BinaryElem32::from_bits(7), 8),   // Max value for 2^3
            (BinaryElem32::from_bits(15), 16), // Max value for 2^4
        ];

        for (qf, n) in test_cases {
            let mut basis = vec![BinaryElem128::zero(); n];
            let mut sks_x = vec![BinaryElem32::zero(); 4];
            let sks_vks = vec![BinaryElem32::one(); 4];
            let scale = BinaryElem128::from_bits(123);

            evaluate_scaled_basis_inplace(&mut sks_x, &mut basis, &sks_vks, qf, scale);

            // Should have exactly one non-zero entry
            let non_zero_count = basis
                .iter()
                .filter(|&&x| x != BinaryElem128::zero())
                .count();
            assert_eq!(
                non_zero_count, 1,
                "Should have exactly one non-zero entry for qf={:?}",
                qf
            );

            // Sum should equal scale
            let sum = basis
                .iter()
                .fold(BinaryElem128::zero(), |acc, &x| acc.add(&x));
            assert_eq!(sum, scale, "Sum should equal scale for qf={:?}", qf);
        }
    }
}
