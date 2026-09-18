//! Count bitmap chunks whose operations-tree ancestors have been born.

#[cfg(verus_keep_ghost)]
use vstd::{
    arithmetic::{
        div_mod::{
            lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse_div, lemma_remainder,
        },
        mul::{
            group_mul_properties, lemma_mul_basics, lemma_mul_inequality, lemma_mul_is_commutative,
            lemma_mul_is_distributive_add, lemma_mul_is_distributive_sub, lemma_mul_nonnegative,
        },
        power2::{lemma_pow2_pos, pow2},
    },
    bits::{lemma_u64_pow2_no_overflow, lemma_u64_shl_is_mul},
    prelude::*,
};

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(
    verus_keep_ghost,
    verus_spec(result: u64 =>
        requires
            1 <= grafting_height <= 62,
            pow2(grafting_height as nat) <= (birth_chunk_0 as int),
            (birth_chunk_0 as int) < 2 * pow2(grafting_height as nat),
        ensures
            (result as int) == grafted_count(
                ops_leaves as int,
                birth_chunk_0 as int,
                pow2(grafting_height as nat) as int,
            ),
            result == 0 || (birth_chunk_0 as int)
                + ((result as int) - 1) * (pow2(grafting_height as nat) as int)
                <= (ops_leaves as int),
            (ops_leaves as int) < (birth_chunk_0 as int)
                + (result as int) * (pow2(grafting_height as nat) as int),
            (result as int) == if delayed(
                ops_leaves as int,
                birth_chunk_0 as int,
                pow2(grafting_height as nat) as int,
            ) {
                (ops_leaves as int) / (pow2(grafting_height as nat) as int) - 1
            } else {
                (ops_leaves as int) / (pow2(grafting_height as nat) as int)
            },
            0 <= (ops_leaves as int) / (pow2(grafting_height as nat) as int) - (result as int) <= 1,
            (birth_chunk_0 as int) == (pow2(grafting_height as nat) as int) ==>
                (result as int) == (ops_leaves as int) / (pow2(grafting_height as nat) as int),
            grafting_height <= 61
                && (birth_chunk_0 as int) == (pow2(grafting_height as nat) as int)
                    + (pow2(grafting_height as nat) as int) / 2 - 1 ==>
                (result as int) == if (ops_leaves as int) / (pow2(grafting_height as nat) as int) > 0
                    && (ops_leaves as int) % (pow2(grafting_height as nat) as int)
                        < (pow2(grafting_height as nat) as int) / 2 - 1
                {
                    (ops_leaves as int) / (pow2(grafting_height as nat) as int) - 1
                } else {
                    (ops_leaves as int) / (pow2(grafting_height as nat) as int)
                },
            forall|k: int| 0 <= k ==> (k < (result as int) <==>
                #[trigger] ((birth_chunk_0 as int) + k * (pow2(grafting_height as nat) as int))
                    <= (ops_leaves as int)),
            forall|m: int| (ops_leaves as int) <= m ==>
                (result as int) <= #[trigger] grafted_count(
                    m,
                    birth_chunk_0 as int,
                    pow2(grafting_height as nat) as int,
                ),
            ops_leaves < u64::MAX ==> grafted_count(
                ops_leaves as int + 1,
                birth_chunk_0 as int,
                pow2(grafting_height as nat) as int,
            ) <= (result as int) + 1,
    )
)]
#[inline]
pub(crate) const fn graftable_chunks(
    ops_leaves: u64,
    grafting_height: u32,
    birth_chunk_0: u64,
) -> u64 {
    #[cfg(verus_keep_ghost)]
    proof! {
        let c = pow2(grafting_height as nat) as int;
        lemma_u64_pow2_no_overflow(grafting_height as nat);
        lemma_u64_shl_is_mul(1u64, grafting_height as u64);
        assert((1u64 << grafting_height) as int == c);
        assert(2 <= c) by {
            vstd::arithmetic::power2::lemma_pow2_strictly_increases(
                0,
                grafting_height as nat,
            );
            lemma_pow2_pos(0);
        }
        lemma_count_bounds(ops_leaves as int, birth_chunk_0 as int, c);
        lemma_kth_birth(ops_leaves as int, birth_chunk_0 as int, c);
        lemma_pending_characterization(ops_leaves as int, birth_chunk_0 as int, c);
        lemma_monotone(ops_leaves as int, birth_chunk_0 as int, c);
        lemma_next_leaf(ops_leaves as int, birth_chunk_0 as int, c);
        lemma_family_cases(ops_leaves as int, birth_chunk_0 as int, c);
    }
    if ops_leaves < birth_chunk_0 {
        return 0;
    }
    let chunk_size = 1u64 << grafting_height;
    (ops_leaves - birth_chunk_0) / chunk_size + 1
}

#[cfg(verus_keep_ghost)]
verus! {

spec fn grafted_count(n: int, birth: int, chunk: int) -> int {
    if n < birth { 0 } else { (n - birth) / chunk + 1 }
}

spec fn delayed(n: int, birth: int, chunk: int) -> bool {
    n / chunk > 0 && n % chunk < birth - chunk
}

proof fn lemma_count_bounds(n: int, birth: int, chunk: int)
    requires
        0 <= n,
        0 < chunk <= birth < 2 * chunk,
    ensures
        0 <= grafted_count(n, birth, chunk),
        grafted_count(n, birth, chunk) == 0
            || birth + (grafted_count(n, birth, chunk) - 1) * chunk <= n,
        n < birth + grafted_count(n, birth, chunk) * chunk,
{
    broadcast use group_mul_properties;

    if n < birth {
    } else {
        let x = n - birth;
        let q = x / chunk;
        lemma_remainder(x, chunk);
        assert(0 <= x - q * chunk < chunk);
        assert(birth + q * chunk <= n);
        assert(n < birth + (q + 1) * chunk);
    }
}

proof fn lemma_kth_birth(n: int, birth: int, chunk: int)
    requires
        0 <= n,
        0 < chunk <= birth < 2 * chunk,
    ensures
        forall|k: int| 0 <= k ==>
            (k < grafted_count(n, birth, chunk) <==> #[trigger] (birth + k * chunk) <= n),
{
    broadcast use group_mul_properties;

    if n < birth {
        assert forall|k: int| 0 <= k implies
            !(#[trigger] (birth + k * chunk) <= n) by {
            lemma_mul_nonnegative(k, chunk);
        }
    } else {
        let x = n - birth;
        let q = x / chunk;
        lemma_remainder(x, chunk);
        assert(0 <= x - q * chunk < chunk);
        assert forall|k: int| 0 <= k implies
            (k < q + 1 <==> #[trigger] (birth + k * chunk) <= n) by {
            if k < q + 1 {
                assert(k <= q);
                lemma_mul_inequality(k, q, chunk);
            } else {
                assert(q + 1 <= k);
                lemma_mul_inequality(q + 1, k, chunk);
                assert(x < (q + 1) * chunk);
            }
        }
    }
}

#[verifier::spinoff_prover]
proof fn lemma_pending_characterization(n: int, birth: int, chunk: int)
    requires
        0 <= n,
        0 < chunk <= birth < 2 * chunk,
    ensures
        grafted_count(n, birth, chunk)
            == if delayed(n, birth, chunk) { n / chunk - 1 } else { n / chunk },
        0 <= n / chunk - grafted_count(n, birth, chunk) <= 1,
{
    let complete = n / chunk;
    let rem = n % chunk;
    let delay = birth - chunk;
    lemma_fundamental_div_mod(n, chunk);
    assert(n == chunk * complete + rem);
    assert(0 <= rem < chunk) by {
        lemma_remainder(n, chunk);
        assert(n - complete * chunk == rem);
    }
    if complete == 0 {
        lemma_mul_basics(chunk);
        assert(n == rem);
        assert(n < birth);
    } else if rem < delay {
        if complete == 1 {
            lemma_mul_basics(chunk);
            assert(n == chunk + rem);
            assert(birth == chunk + delay);
            assert(n < birth);
        } else {
            let x = n - birth;
            let q = complete - 2;
            let r = chunk + rem - delay;
            assert(0 <= r < chunk);
            lemma_mul_is_commutative(chunk, complete);
            lemma_mul_is_commutative(q, chunk);
            lemma_mul_is_distributive_sub(chunk, complete, 2);
            assert(x == q * chunk + r);
            lemma_fundamental_div_mod_converse_div(x, chunk, q, r);
            assert(x / chunk == q);
        }
    } else {
        let x = n - birth;
        let q = complete - 1;
        let r = rem - delay;
        assert(0 <= r < chunk);
        lemma_mul_is_commutative(chunk, complete);
        lemma_mul_is_commutative(q, chunk);
        lemma_mul_is_distributive_sub(chunk, complete, 1);
        assert(x == q * chunk + r);
        lemma_fundamental_div_mod_converse_div(x, chunk, q, r);
        assert(x / chunk == q);
    }
}

proof fn lemma_monotone(n: int, birth: int, chunk: int)
    requires
        0 <= n,
        0 < chunk <= birth < 2 * chunk,
    ensures
        forall|m: int| n <= m ==>
            grafted_count(n, birth, chunk) <= #[trigger] grafted_count(m, birth, chunk),
{
    broadcast use group_mul_properties;

    lemma_count_bounds(n, birth, chunk);
    lemma_kth_birth(n, birth, chunk);
    assert forall|m: int| n <= m implies
        grafted_count(n, birth, chunk) <= #[trigger] grafted_count(m, birth, chunk) by {
        lemma_count_bounds(m, birth, chunk);
        lemma_kth_birth(m, birth, chunk);
        let r = grafted_count(n, birth, chunk);
        if r > 0 {
            assert(0 <= r - 1);
            assert(r - 1 < r);
            assert(birth + (r - 1) * chunk <= n);
            assert(birth + (r - 1) * chunk <= m);
            assert(r - 1 < grafted_count(m, birth, chunk));
        }
    }
}

proof fn lemma_next_leaf(n: int, birth: int, chunk: int)
    requires
        0 <= n,
        2 <= chunk <= birth < 2 * chunk,
    ensures
        grafted_count(n, birth, chunk)
            <= grafted_count(n + 1, birth, chunk)
            <= grafted_count(n, birth, chunk) + 1,
{
    lemma_count_bounds(n, birth, chunk);
    lemma_count_bounds(n + 1, birth, chunk);
    lemma_kth_birth(n, birth, chunk);
    lemma_kth_birth(n + 1, birth, chunk);
    let r = grafted_count(n, birth, chunk);
    let next = grafted_count(n + 1, birth, chunk);
    if r > 0 {
        assert(birth + (r - 1) * chunk <= n);
        assert(birth + (r - 1) * chunk <= n + 1);
        assert(r - 1 < next);
    } else {
        assert(0 <= next);
    }
    assert(r <= next);
    if next > r + 1 {
        assert(r + 1 < next);
        assert(birth + (r + 1) * chunk <= n + 1);
        assert(n < birth + r * chunk);
        lemma_mul_is_distributive_add(chunk, r, 1);
        lemma_mul_is_commutative(chunk, r + 1);
        lemma_mul_is_commutative(chunk, r);
        assert((r + 1) * chunk == r * chunk + chunk);
        assert(false);
    }
}

proof fn lemma_family_cases(n: int, birth: int, chunk: int)
    requires
        0 <= n,
        2 <= chunk <= birth < 2 * chunk,
    ensures
        birth == chunk ==> grafted_count(n, birth, chunk) == n / chunk,
        birth == chunk + chunk / 2 - 1 ==>
            (grafted_count(n, birth, chunk)
                == if n / chunk > 0 && n % chunk < chunk / 2 - 1 {
                    n / chunk - 1
                } else {
                    n / chunk
                }),
{
    broadcast use group_mul_properties;

    lemma_pending_characterization(n, birth, chunk);
}

}
