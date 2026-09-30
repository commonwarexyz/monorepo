//! Performance smoke test (DESIGN.md §5.9): a 64-round mixing loop over a
//! 64-element list-backed array with symbolic inputs, written twice
//! independently (array methods counting up with measure recursion on the
//! index; list functions counting down with preconditions), evaluated and
//! compared by memoized conversion. Timings are printed (`--nocapture`).

mod common;

use std::time::Instant;

use common::*;
use sandblaster_kernel::api::*;

const SRC: &str = r#"
-- Version A: array methods, index counting up, measure 64 − i.
def[loop_helper] perf::mix_a : (i : U64) -> (s : Array U32 64usize) -> Array U32 64usize :=
  fun (i : U64) (s : Array U32 64usize) =>
    if #lt_u64(i, 64u64) as .c return Array U32 64usize then
      let .q : Eq(Bool, #le_u64(i, 63u64), true) =
        linarith([c : Eq(Bool, #lt_u64(i, 64u64), true)]; Eq(Bool, #le_u64(i, 63u64), true); [1, 1, 0, 0]);
      let .p1 : Eq(Bool, #lt_usize(#cast_u64_usize(i), 64usize), true) =
        linarith([c : Eq(Bool, #lt_u64(i, 64u64), true)]; Eq(Bool, #lt_usize(#cast_u64_usize(i), 64usize), true); [1, 1, 0, 0]);
      let .p2 : Eq(Bool, #lt_usize(#cast_u64_usize(#sub_u64(63u64, i; q)), 64usize), true) =
        linarith([]; Eq(Bool, #lt_usize(#cast_u64_usize(#sub_u64(63u64, i; q)), 64usize), true); [1, 1, 0]);
      let .p3 : Eq(Bool, #le_int(#iadd(#cast_u64_int(i), 1int), 18446744073709551615int), true) =
        linarith([c : Eq(Bool, #lt_u64(i, 64u64), true)]; Eq(Bool, #le_int(#iadd(#cast_u64_int(i), 1int), 18446744073709551615int), true); [1, 1, 0, 0]);
      let a : U32 = array::index U32 64usize s (#cast_u64_usize(i)) .p1;
      let b : U32 = array::index U32 64usize s (#cast_u64_usize(#sub_u64(63u64, i; q))) .p2;
      let v : U32 = #wadd_u32(#rotr_u32(a, 7u32), #xor_u32(b, #wshl_u32(a, 3u32)));
      rec(#add_u64(i, 1u64; p3), array::set U32 64usize s (#cast_u64_usize(i)) v .p1;
        pair(Sigma (_ : Eq(Bool, #le_int(0int, #isub(64int, #cast_u64_int(#add_u64(i, 1u64; p3)))), true)),
               Eq(Bool, #lt_int(#isub(64int, #cast_u64_int(#add_u64(i, 1u64; p3))), #isub(64int, #cast_u64_int(i))), true),
             linarith([c : Eq(Bool, #lt_u64(i, 64u64), true)];
                      Eq(Bool, #le_int(0int, #isub(64int, #cast_u64_int(#add_u64(i, 1u64; p3)))), true); [1, 1, 0, 0]),
             linarith([]; Eq(Bool, #lt_int(#isub(64int, #cast_u64_int(#add_u64(i, 1u64; p3))), #isub(64int, #cast_u64_int(i))), true); [1, 0, 0])))
    else s
  measure (#isub(64int, #cast_u64_int(i)))

-- Version B: list functions, the mixing function passed as an argument
-- (written with the integer methods), counter counting down, preconditions
-- carried along.
def[spec] perf::mix : (a : U32) -> (b : U32) -> U32 :=
  fun (a : U32) (b : U32) => #wadd_u32(u32::rotate_right a 7u32, #xor_u32(b, u32::wrapping_shl a 3u32))

def[loop_helper] perf::mix_b : (f : U32 -> U32 -> U32) -> (j : U64) -> (l : List(U32))
    -> (.hj : Eq(Bool, #le_u64(j, 64u64), true)) -> (.hl : Eq(Int, seq::len U32 l, 64int)) -> List(U32) :=
  fun (f : U32 -> U32 -> U32) (j : U64) (l : List(U32)) (.hj : Eq(Bool, #le_u64(j, 64u64), true)) (.hl : Eq(Int, seq::len U32 l, 64int)) =>
    if #lt_u64(0u64, j) as .c return List(U32) then
      let i : Int = #isub(64int, #cast_u64_int(j));
      let .pj : Eq(Bool, #le_u64(1u64, j), true) =
        linarith([c : Eq(Bool, #lt_u64(0u64, j), true)]; Eq(Bool, #le_u64(1u64, j), true); [1, 1, 0, 0]);
      let x : U32 = seq::index U32 l i
        .linarith([hj : Eq(Bool, #le_u64(j, 64u64), true)]; Eq(Bool, #le_int(0int, i), true); [1, 1, 0, 0])
        .linarith([c : Eq(Bool, #lt_u64(0u64, j), true), hl : Eq(Int, seq::len U32 l, 64int)]; Eq(Bool, #lt_int(i, seq::len U32 l), true); [1, -1, 1, 0, 0, 0]);
      let y : U32 = seq::index U32 l (#isub(63int, i))
        .linarith([c : Eq(Bool, #lt_u64(0u64, j), true)]; Eq(Bool, #le_int(0int, #isub(63int, i)), true); [1, 1, 0, 0])
        .linarith([hj : Eq(Bool, #le_u64(j, 64u64), true), hl : Eq(Int, seq::len U32 l, 64int)]; Eq(Bool, #lt_int(#isub(63int, i), seq::len U32 l), true); [1, -1, 1, 0, 0, 0]);
      rec(f, #sub_u64(j, 1u64; pj), seq::update U32 l i (f x y),
          .linarith([hj : Eq(Bool, #le_u64(j, 64u64), true)]; Eq(Bool, #le_u64(#sub_u64(j, 1u64; pj), 64u64), true); [1, 1, 0, 0]),
          .eq::trans Int (seq::len U32 (seq::update U32 l i (f x y))) (seq::len U32 l) 64int (seq::len_update U32 l i (f x y)) hl;
          linarith([]; Eq(Bool, #lt_u64(#sub_u64(j, 1u64; pj), j), true); [1, 0, 0]))
    else l
  measure (j)

-- Version C: version A with one rotation amount changed (not equivalent).
def[spec] perf::mix_c : (a : U32) -> (b : U32) -> U32 :=
  fun (a : U32) (b : U32) => #wadd_u32(u32::rotate_right a 8u32, #xor_u32(b, u32::wrapping_shl a 3u32))
"#;

#[test]
fn sixty_four_rounds_two_ways() {
    big_stack(|| {
        let mut env = prelude();
        let t0 = Instant::now();
        load(&mut env, SRC).unwrap_or_else(|e| panic!("{e}"));
        let t_load = t0.elapsed();

        let goal = |mix: &str| {
            format!(
                "(x : Array U32 64usize) -> Eq(List(U32), fst(perf::mix_a 0u64 x), \
                    perf::mix_b {mix} 64u64 fst(x) .refl(Bool, true) .(array::ok_len U32 64usize x))"
            )
        };
        let proof = "fun (x : Array U32 64usize) => refl(List(U32), fst(perf::mix_a 0u64 x))";
        let t1 = Instant::now();
        let mut b = budget();
        let steps0 = b.steps;
        let gv = ev(&env, &tm(&env, &goal("perf::mix")));
        env.check(&Ctx::default(), &tm(&env, proof), &gv, &mut b).unwrap_or_else(|e| panic!("{e}"));
        let t_check = t1.elapsed();
        let used = steps0 - b.steps;
        // The same loop with a different mixing function is not equivalent.
        let t4 = Instant::now();
        let gv = ev(&env, &tm(&env, &goal("perf::mix_c")));
        assert!(env.check(&Ctx::default(), &tm(&env, proof), &gv, &mut budget()).is_err());
        let t_check_bad = t4.elapsed();

        // Evaluate each side alone under a fresh array variable (timing).
        let t2 = Instant::now();
        let a = ev(&env, &tm(&env, "fun (x : Array U32 64usize) => fst(perf::mix_a 0u64 x)"));
        let _ = env.quote(sandblaster_kernel::term::Lvl(0), &a, true);
        let t_eval_quote = t2.elapsed();

        // A non-equivalent version is rejected (quickly).
        let bad_goal = "(x : Array U32 64usize) -> Eq(U32, perf::mix (array::index U32 64usize x 0usize .refl(Bool, true)) 5u32, \
                        perf::mix_c (array::index U32 64usize x 0usize .refl(Bool, true)) 5u32)";
        let bad_proof = "fun (x : Array U32 64usize) => refl(U32, perf::mix (array::index U32 64usize x 0usize .refl(Bool, true)) 5u32)";
        let t3 = Instant::now();
        let bgv = ev(&env, &tm(&env, bad_goal));
        assert!(env.check(&Ctx::default(), &tm(&env, bad_proof), &bgv, &mut budget()).is_err());
        let t_bad = t3.elapsed();

        eprintln!(
            "perf: load A/B/C {:?}; check A ≡ B (eval both + memoized conv) {:?} using {} steps; \
             reject A ≡ B[mix_c] {:?}; eval+shared quote of A {:?}; reject small C {:?}",
            t_load, t_check, used, t_check_bad, t_eval_quote, t_bad
        );
        assert!(t_check.as_secs_f64() < 20.0, "conversion too slow: {t_check:?}");
    })
}
