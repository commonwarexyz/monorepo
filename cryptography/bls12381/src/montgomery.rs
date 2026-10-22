//! Montgomery arithmetic on canonical multi-word integers, shared by the prime fields.
//!
//! Every function takes little-endian words below the modulus and returns the same; the
//! functions are `const fn` so field constants can be derived at compile time.

/// Computes `-m^(-1) mod 2^64` for an odd modulus word `m` by Newton iteration.
pub(crate) const fn negated_inverse(m: u64) -> u64 {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// Returns whether `value < modulus`.
pub(crate) const fn is_below<const N: usize>(value: &[u64; N], modulus: &[u64; N]) -> bool {
    let mut borrow = 0;
    let mut i = 0;
    while i < N {
        let wide = (value[i] as u128)
            .wrapping_sub(modulus[i] as u128)
            .wrapping_sub(borrow as u128);
        borrow = (wide >> 127) as u64;
        i += 1;
    }
    borrow == 1
}

/// Returns `value - modulus` when `value >= modulus`, where `carry` extends `value` with one
/// more word.
pub(crate) const fn subtract_modulus<const N: usize>(
    value: [u64; N],
    carry: u64,
    modulus: &[u64; N],
) -> [u64; N] {
    let mut reduced = [0; N];
    let mut borrow = 0;
    let mut i = 0;
    while i < N {
        let wide = (value[i] as u128)
            .wrapping_sub(modulus[i] as u128)
            .wrapping_sub(borrow as u128);
        reduced[i] = wide as u64;
        borrow = (wide >> 127) as u64;
        i += 1;
    }
    // Keep the subtraction exactly when it did not underflow the extended value.
    let underflow = carry.wrapping_sub(borrow) >> 63;
    let mask = underflow.wrapping_neg();
    let mut i = 0;
    while i < N {
        reduced[i] = (reduced[i] & !mask) | (value[i] & mask);
        i += 1;
    }
    reduced
}

/// Returns `a + b mod modulus`.
pub(crate) const fn add<const N: usize>(a: &[u64; N], b: &[u64; N], modulus: &[u64; N]) -> [u64; N] {
    let mut sum = [0; N];
    let mut carry = 0;
    let mut i = 0;
    while i < N {
        let wide = a[i] as u128 + b[i] as u128 + carry as u128;
        sum[i] = wide as u64;
        carry = (wide >> 64) as u64;
        i += 1;
    }
    subtract_modulus(sum, carry, modulus)
}

/// Returns `modulus - a`, mapping zero to zero.
pub(crate) const fn neg<const N: usize>(a: &[u64; N], modulus: &[u64; N]) -> [u64; N] {
    let mut value = [0; N];
    let mut borrow = 0;
    let mut nonzero = 0;
    let mut i = 0;
    while i < N {
        let wide = (modulus[i] as u128)
            .wrapping_sub(a[i] as u128)
            .wrapping_sub(borrow as u128);
        value[i] = wide as u64;
        borrow = (wide >> 127) as u64;
        nonzero |= a[i];
        i += 1;
    }
    // A zero input yields the modulus; mask it back to zero.
    let mask = ((nonzero | nonzero.wrapping_neg()) >> 63).wrapping_neg();
    let mut i = 0;
    while i < N {
        value[i] &= mask;
        i += 1;
    }
    value
}

/// Returns `2^k mod modulus` by repeated doubling.
pub(crate) const fn power_of_two<const N: usize>(k: u32, modulus: &[u64; N]) -> [u64; N] {
    let mut value = [0; N];
    value[0] = 1;
    let mut i = 0;
    while i < k {
        value = add(&value, &value, modulus);
        i += 1;
    }
    value
}

/// Returns `a * b / 2^(64 N) mod modulus` (CIOS Montgomery multiplication) for an odd modulus
/// below `2^(64 N - 1)`, given `inv = -modulus^(-1) mod 2^64`.
pub(crate) const fn mul<const N: usize>(
    a: &[u64; N],
    b: &[u64; N],
    modulus: &[u64; N],
    inv: u64,
) -> [u64; N] {
    let mut t = [0u64; N];
    let mut high = 0u64;
    let mut i = 0;
    while i < N {
        // t += a * b[i], with the carry out going to high.
        let mut carry = 0u64;
        let mut j = 0;
        while j < N {
            let wide = t[j] as u128 + a[j] as u128 * b[i] as u128 + carry as u128;
            t[j] = wide as u64;
            carry = (wide >> 64) as u64;
            j += 1;
        }
        let wide = high as u128 + carry as u128;
        high = wide as u64;
        let top = (wide >> 64) as u64;

        // t += m * modulus, then drop the low word, which is now zero.
        let m = t[0].wrapping_mul(inv);
        let wide = t[0] as u128 + m as u128 * modulus[0] as u128;
        let mut carry = (wide >> 64) as u64;
        let mut j = 1;
        while j < N {
            let wide = t[j] as u128 + m as u128 * modulus[j] as u128 + carry as u128;
            t[j - 1] = wide as u64;
            carry = (wide >> 64) as u64;
            j += 1;
        }
        let wide = high as u128 + carry as u128;
        t[N - 1] = wide as u64;
        high = top + (wide >> 64) as u64;
        i += 1;
    }
    subtract_modulus(t, high, modulus)
}
