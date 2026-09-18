//! Checked bitmap geometry shared by proof decoding and verification.

#[cfg(verus_keep_ghost)]
use vstd::{
    arithmetic::div_mod::{
        lemma_basic_div, lemma_div_by_self, lemma_mod_multiples_basic, lemma_mod_pos_bound,
        lemma_multiply_divide_lt,
    },
    arithmetic::mul::{
        lemma_mul_equality_converse, lemma_mul_inequality, lemma_mul_is_commutative,
    },
    arithmetic::power2::{
        lemma_pow2_adds, lemma_pow2_pos, lemma_pow2_strictly_increases, lemma_pow2_subtracts,
        lemma_pow2_unfold, lemma2_to64, lemma2_to64_rest, pow2,
    },
    bits::{
        lemma_low_bits_mask_values, lemma_u8_shr_is_div, lemma_u64_low_bits_mask_is_mod,
        lemma_u64_pow2_no_overflow, lemma_u64_shl_is_mul, lemma_u64_shr_is_div, low_bits_mask,
    },
    prelude::*,
    std_specs::bits::{axiom_u64_trailing_zeros, u64_trailing_zeros},
};

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(result =>
        ensures
            result.is_some() <==> valid_chunk_size(chunk_size as int),
            result.is_some() ==> result.unwrap() as int == (chunk_size as int) * 8,
            result.is_some() ==> 8 <= result.unwrap() <= (1u64 << 62),
            result.is_some() ==> exists|e: nat| e <= 59 && chunk_size as int == pow2(e),
            result.is_some() ==> exists|h: nat|
                3 <= h <= 62 && result.unwrap() as int == pow2(h),
            result.is_some() ==> u64_trailing_zeros(result.unwrap()) < 63,
    )
)]
#[inline]
pub(crate) const fn chunk_bits(chunk_size: usize) -> Option<u64> {
    let Some(bits) = chunk_size.checked_mul(8) else {
        return None;
    };
    let bits = bits as u64;
    let height = bits.trailing_zeros();

    #[cfg(verus_keep_ghost)]
    proof! {
        if valid_chunk_size(chunk_size as int) {
            let e = choose|e: nat| e <= 59 && chunk_size as int == pow2(e)
                && (chunk_size as int) * 8 <= usize::MAX;
            assert(e <= 59 && chunk_size as int == pow2(e)
                && (chunk_size as int) * 8 <= usize::MAX);
            lemma_pow2_adds(e, 3);
            lemma2_to64();
            assert(bits as int == (chunk_size as int) * 8);
            assert(bits as int == pow2(e + 3));
            lemma_u64_pow2_no_overflow(e + 3);
            lemma_u64_shl_is_mul(1u64, (e + 3) as u64);
            assert(bits == 1u64 << ((e + 3) as u64));
            lemma_single_bit_trailing_zeros((e + 3) as u64);
            assert(height as int == e + 3);
        }
    }

    if height >= 63 {
        return None;
    }

    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_u64_pow2_no_overflow(height as nat);
        lemma_u64_shl_is_mul(1u64, height as u64);
    }

    if bits != 1u64 << height {
        return None;
    }

    #[cfg(verus_keep_ghost)]
    proof! {
        assert(bits as int == (chunk_size as int) * 8);
        assert(bits as int == pow2(height as nat));
        lemma_pow2_pos(height as nat);
        assert(0 <= chunk_size as int);
        assert(0 < bits as int);
        if chunk_size == 0 {
            assert(bits as int == 0);
            assert(false);
        }
        assert(0 < chunk_size as int);
        assert(1 <= chunk_size as int);
        lemma_mul_inequality(1, chunk_size as int, 8);
        assert(8 <= (chunk_size as int) * 8);
        assert(8 <= bits as int);
        lemma2_to64();
        if height < 3 {
            lemma_pow2_strictly_increases(height as nat, 3);
            assert(pow2(3) == 8);
            assert(bits < 8);
        }
        assert(3 <= height <= 62);
        let e = (height - 3) as nat;
        lemma_pow2_adds(e, 3);
        assert(pow2(3) == 8);
        assert(e <= 59);
        assert(pow2(height as nat) == pow2(e) * 8);
        assert((chunk_size as int) * 8 == pow2(e) * 8);
        lemma_mul_is_commutative(chunk_size as int, 8);
        lemma_mul_is_commutative(pow2(e) as int, 8);
        assert(8 * (chunk_size as int) == 8 * pow2(e));
        lemma_mul_equality_converse(8, chunk_size as int, pow2(e) as int);
        lemma2_to64_rest();
        if height < 62 {
            lemma_pow2_strictly_increases(height as nat, 62);
        }
        lemma_u64_pow2_no_overflow(62);
        lemma_u64_shl_is_mul(1u64, 62);
        assert((1u64 << 62) as int == pow2(62));
        assert(bits <= 1u64 << 62);
    }

    Some(bits)
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(result =>
        ensures
            result.is_some() <==> valid_chunk_size(chunk@.len() as int),
            result.is_some() ==> result.unwrap() == selected_bit(chunk@, loc as int),
    )
)]
#[inline]
pub(crate) const fn active_bit(chunk: &[u8], loc: u64) -> Option<bool> {
    let Some(bits) = chunk_bits(chunk.len()) else {
        return None;
    };
    let bit = loc % bits;

    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_mod_pos_bound(loc as int, bits as int);
        assert(0 <= bit as int && (bit as int) < bits as int);
        assert(bits as int == (chunk@.len() as int) * 8);
        lemma_multiply_divide_lt(bit as int, 8, chunk@.len() as int);
        assert(((bit / 8) as int) < chunk@.len());
    }

    let byte_index = (bit / 8) as usize;
    let shift = (bit % 8) as u8;

    #[cfg(verus_keep_ghost)]
    proof! {
        lemma_mod_pos_bound(bit as int, 8);
        assert(shift < 8);
        assert(byte_index < chunk@.len());
        lemma_u8_shr_is_div(chunk@[byte_index as int], shift);
    }

    Some((chunk[byte_index] >> shift) % 2 == 1)
}

#[cfg(verus_keep_ghost)]
verus! {

spec fn valid_chunk_size(size: int) -> bool {
    exists|e: nat| e <= 59 && size == pow2(e) && size * 8 <= usize::MAX
}

spec fn selected_bit(chunk: Seq<u8>, loc: int) -> bool {
    let bits = (chunk.len() as int) * 8;
    let bit = loc % bits;
    let byte_index = bit / 8;
    let shift = bit % 8;
    (chunk[byte_index] as nat / pow2(shift as nat)) % 2 == 1
}

proof fn lemma_power_bit(e: u64, j: u64)
    requires
        e < 64,
        j < 64,
    ensures
        ((1u64 << e) >> j) & 1u64 == if e == j { 1u64 } else { 0u64 },
{
    lemma_u64_pow2_no_overflow(e as nat);
    lemma_u64_pow2_no_overflow(j as nat);
    lemma_u64_shl_is_mul(1u64, e);
    lemma_u64_shr_is_div(1u64 << e, j);
    let q = (1u64 << e) >> j;
    lemma_u64_low_bits_mask_is_mod(q, 1);
    lemma_low_bits_mask_values();
    assert(low_bits_mask(1) == 1);
    lemma2_to64();
    assert(pow2(1) == 2);

    if j < e {
        lemma_pow2_subtracts(j as nat, e as nat);
        let d = (e - j) as nat;
        assert(0 < d);
        lemma_pow2_unfold(d);
        assert(q as int == pow2(d));
        lemma_mod_multiples_basic(pow2((d - 1) as nat) as int, 2);
        assert(q % 2 == 0);
    } else if e < j {
        lemma_pow2_strictly_increases(e as nat, j as nat);
        assert(((1u64 << e) as int) < pow2(j as nat));
        lemma_basic_div((1u64 << e) as int, pow2(j as nat) as int);
        assert(q == 0);
    } else {
        lemma_div_by_self(pow2(e as nat) as int);
        assert(q == 1);
    }
}

proof fn lemma_single_bit_trailing_zeros(e: u64)
    requires
        e < 64,
    ensures
        u64_trailing_zeros(1u64 << e) == e,
{
    let x = 1u64 << e;
    let tz = u64_trailing_zeros(x);
    lemma_u64_pow2_no_overflow(e as nat);
    lemma_u64_shl_is_mul(1u64, e);
    lemma_pow2_pos(e as nat);
    assert(x != 0);
    axiom_u64_trailing_zeros(x);
    assert(tz < 64);

    if tz < e {
        lemma_power_bit(e, tz as u64);
        assert((x >> (tz as u64)) & 1u64 == 0u64);
        assert((x >> (tz as u64)) & 1u64 == 1u64);
    } else if e < tz {
        lemma_power_bit(e, e);
        assert((x >> e) & 1u64 == 0u64);
        assert((x >> e) & 1u64 == 1u64);
    }
}

}

#[cfg(test)]
mod tests {
    use super::{active_bit, chunk_bits};

    #[test]
    fn chunk_width_boundaries() {
        let max_exponent = (usize::BITS - 4).min(59);
        let largest = 1usize << max_exponent;
        assert_eq!(chunk_bits(largest), Some((largest * 8) as u64));

        let next = largest << 1;
        assert_eq!(chunk_bits(next), None);
        assert_eq!(chunk_bits(0), None);
        assert_eq!(chunk_bits(3), None);
        assert_eq!(chunk_bits(usize::MAX), None);
    }

    #[test]
    fn selects_activity_bits_for_all_location_extremes() {
        let chunk = [0b1000_0001, 0b0000_0010, 0b0000_0100, 0b0000_1000];
        for loc in 0..128u64 {
            let bit = loc % 32;
            let expected = chunk[(bit / 8) as usize] & (1 << (bit % 8)) != 0;
            assert_eq!(active_bit(&chunk, loc), Some(expected));
        }

        let bit = u64::MAX % 32;
        let expected = chunk[(bit / 8) as usize] & (1 << (bit % 8)) != 0;
        assert_eq!(active_bit(&chunk, u64::MAX), Some(expected));
        assert_eq!(active_bit(&[], 0), None);
        assert_eq!(active_bit(&[0; 3], u64::MAX), None);
    }
}
