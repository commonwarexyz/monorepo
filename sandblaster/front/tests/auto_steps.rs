//! The individual steps of DESIGN.md §8.1 (connectives, saturation,
//! contradictions, rewriting, axioms, case splits, enumeration, hints,
//! ∀-facts), plus determinism and budget behaviour. Every produced term is
//! re-checked by the kernel.

#[path = "auto_support.rs"]
mod support;

use num_bigint::BigInt;
use sandblaster_front::auto::AutoConfig;
use sandblaster_front::prover::Hint;
use support::*;

// ---------------------------------------------------------------------------
// Step 2–3: connectives.
// ---------------------------------------------------------------------------

#[test]
fn connectives() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("x", "U32"), (".h", "Eq(Bool, #lt_u32(x, 10u32), true)")]);
        // Unit
        assert_proves(env, &b.goal("Unit"));
        // ∧ (non-dependent) and dependent ∧
        assert_proves(env, &b.goal("And (Eq(Bool, #lt_u32(x, 11u32), true)) (Eq(Bool, #le_u32(x, 9u32), true))"));
        assert_proves(
            env,
            &b.goal("Sigma (p : Eq(Bool, #le_u32(1u32, #add_u32(x, 1u32; refl(Bool, true))), true)), Eq(Bool, #lt_u32(x, 12u32), true)"),
        );
        // → and ∀
        assert_proves(env, &b.goal("(y : U32) -> (.k : Eq(Bool, #lt_u32(y, x), true)) -> Eq(Bool, #lt_u32(y, 9u32), true)"));
        assert_proves(env, &b.goal("(y : U32) -> (k : Eq(Bool, #lt_u32(y, x), true)) -> Eq(Bool, #lt_u32(y, 9u32), true)"));
        // ∨: the provable side
        assert_proves(env, &b.goal("Or (Eq(Bool, #lt_u32(20u32, x), true)) (Eq(Bool, #lt_u32(x, 20u32), true))"));
        // ¬: Not P = P -> Empty
        assert_proves(env, &b.goal("Not (Eq(Bool, #lt_u32(10u32, x), true))"));
        // Iff
        assert_proves(env, &b.goal("Iff (Eq(Bool, #lt_u32(x, 10u32), true)) (Eq(Bool, #le_u32(x, 9u32), true))"));
        // negatives
        assert_fails(env, &b.goal("Or (Eq(Bool, #lt_u32(20u32, x), true)) (Eq(Bool, #lt_u32(x, 5u32), true))"));
        assert_fails(env, &b.goal("Eq(Bool, #lt_u32(x, 5u32), true)"));
        assert_fails(env, &b.goal("Empty"));
    });
}

#[test]
fn exists_by_unification_and_witness_hint() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("o", "Option(U32)"), ("v", "U32"), (".e", "Eq(Option(U32), o, Some[U32](v))")]);
        // exists w. o == Some(w)
        assert_proves(env, &b.goal("Exists U32 (fun (w : U32) => Eq(Option(U32), o, Some[U32](w)))"));
        // exists w. w < 5 — needs a witness hint.
        let g = b.goal("Exists U32 (fun (w : U32) => Eq(Bool, #lt_u32(w, 5u32), true))");
        assert_fails(env, &g);
        let bh = GoalBuilder::new(env).binds(&[("o", "Option(U32)"), ("v", "U32"), (".e", "Eq(Option(U32), o, Some[U32](v))")]);
        let w = bh.parse("3u32");
        let bh = bh.hint(Hint::Witness(vec![w]));
        assert_proves(env, &bh.goal("Exists U32 (fun (w : U32) => Eq(Bool, #lt_u32(w, 5u32), true))"));
    });
}

// ---------------------------------------------------------------------------
// Step 4–5: saturation and contradictions.
// ---------------------------------------------------------------------------

#[test]
fn short_circuit_and_facts() {
    run(|env| {
        // `a && b == true` in the plain and the dependent-match shape.
        let b = GoalBuilder::new(env).binds(&[
            ("x", "U32"),
            ("y", "U32"),
            (".h", "Eq(Bool, bool::and (#lt_u32(x, 4u32)) (#lt_u32(y, 5u32)), true)"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(x, 4u32), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(y, 6u32), true)"));
        let b = GoalBuilder::new(env).binds(&[
            ("x", "U32"),
            ("s", "Slice U8"),
            (
                ".h",
                "Eq(Bool, if #lt_usize(0usize, fst(s)) as .c return Bool then #eq_u8(slice::index U8 s 0usize .c, 7u8) else false, true)",
            ),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(0usize, fst(s)), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(1usize, fst(s)), true)"));
        // `!b == true` ⇒ `b == false`; `a || b == false` ⇒ both false
        let b = GoalBuilder::new(env).binds(&[("x", "U32"), (".h", "Eq(Bool, bool::not (#lt_u32(x, 4u32)), true)")]);
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(4u32, x), true)"));
        let b = GoalBuilder::new(env).binds(&[("x", "U32"), (".h", "Eq(Bool, bool::or (#lt_u32(x, 4u32)) (#lt_u32(9u32, x)), false)")]);
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(x, 9u32), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(4u32, x), true)"));
    });
}

#[test]
fn contradictions() {
    run(|env| {
        let t = "Eq(Bool, #lt_u32(x, 0u32), true)"; // false target, provable only from absurd facts
        for fact in [
            "Eq(Bool, true, false)",
            "Eq(Bool, false, true)",
            "Empty",
            "Eq(Option(U32), None[U32], Some[U32](x))",
            "Eq(U32, 3u32, 4u32)",
            "Eq(Bool, #lt_u32(x, x), true)",
            "Not (Eq(U32, x, x))",
            "Eq(Bool, #eq_u32(x, x), false)",
            "Eq(Bool, #ne_u32(x, x), true)",
            "Eq(Bool, bool::and (#lt_u32(x, 4u32)) (#lt_u32(10u32, x)), true)",
        ] {
            let b = GoalBuilder::new(env).binds(&[("x", "U32"), (".h", fact)]);
            let g = b.goal(t);
            if let Err(f) = prove(env, &g) {
                panic!("contradiction from `{fact}` not found: {:?}", f.tried);
            }
        }
        // Constructor injectivity.
        let b = GoalBuilder::new(env).binds(&[("x", "U32"), ("y", "U32"), (".h", "Eq(Option(U32), Some[U32](x), Some[U32](y))")]);
        assert_proves(env, &b.goal("Eq(U32, x, y)"));
        let b = GoalBuilder::new(env).binds(&[
            ("x", "U32"),
            ("y", "U8"),
            (".h", "Eq(Tuple2(U32, U8), tuple2[U32, U8](x, y), tuple2[U32, U8](5u32, 6u8))"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(x, 6u32), true)"));
        assert_proves(env, &b.goal("Eq(U8, y, 6u8)"));
    });
}

#[test]
fn disequality_splits() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[
            ("x", "U32"),
            (".h1", "Eq(Bool, #eq_u32(x, 3u32), false)"),
            (".h2", "Eq(Bool, #le_u32(3u32, x), true)"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(3u32, x), true)"));
        let b = GoalBuilder::new(env).binds(&[
            ("x", "U32"),
            ("y", "U32"),
            (".h1", "Eq(Bool, #ne_u32(x, y), true)"),
            (".h2", "Eq(Bool, #le_u32(x, y), true)"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(x, y), true)"));
        // negative: x ≠ 3 does not give x > 3
        let b = GoalBuilder::new(env).binds(&[("x", "U32"), (".h1", "Eq(Bool, #eq_u32(x, 3u32), false)")]);
        assert_fails(env, &b.goal("Eq(Bool, #lt_u32(3u32, x), true)"));
    });
}

// ---------------------------------------------------------------------------
// Step 6–10: rewriting, axioms, decision, congruence, unfolding.
// ---------------------------------------------------------------------------

#[test]
fn rewriting_with_stuck_equations() {
    run(|env| {
        // inactive_decoded_rejected-shaped: rewrite the stuck `active` test.
        let b = GoalBuilder::new(env).binds(&[
            ("chunk", "U8"),
            ("location", "U32"),
            ("r", "Bool"),
            (".h", "Eq(Bool, #ne_u8(#and_u8(#wshr_u8(chunk, #rem_u32(location, 8u32; refl(Bool, true))), 1u8), 0u8), false)"),
        ]);
        assert_proves(
            env,
            &b.goal(
                "Eq(Bool, bool::and (#ne_u8(#and_u8(#wshr_u8(chunk, #rem_u32(location, 8u32; refl(Bool, true))), 1u8), 0u8)) r, false)",
            ),
        );
        // Rewriting an option-valued stuck call with a fact.
        let b =
            GoalBuilder::new(env).binds(&[("s", "Slice U8"), ("v", "U8"), (".h", "Eq(Option(U8), slice::get U8 s 3usize, Some[U8](v))")]);
        assert_proves(env, &b.goal("Eq(Bool, option::is_some U8 (slice::get U8 s 3usize), true)"));
        assert_proves(env, &b.goal("Eq(U8, option::unwrap_or U8 (slice::get U8 s 3usize) 0u8, v)"));
    });
}

#[test]
fn axiom_instances() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("a", "U32"), ("b", "U32")]);
        for g in [
            "Eq(Bool, #le_u32(#min_u32(a, b), a), true)",
            "Eq(Bool, #le_u32(#min_u32(a, b), b), true)",
            "Eq(Bool, #le_u32(a, #max_u32(a, b)), true)",
            "Eq(Bool, #le_u32(#sat_sub_u32(a, b), a), true)",
            "Eq(Bool, #le_u32(#and_u32(a, b), b), true)",
            "Eq(Bool, #le_u32(a, #or_u32(a, b)), true)",
            "Eq(Bool, #le_int(#cast_u32_int(#or_u32(a, b)), #iadd(#cast_u32_int(a), #cast_u32_int(b))), true)",
            "Eq(Bool, #le_u32(#xor_u32(a, b), #or_u32(a, b)), true)",
            "Eq(Bool, #le_u32(#wshr_u32(a, b), a), true)",
            "Eq(Bool, #le_u32(#count_ones_u32(a), 32u32), true)",
            "Eq(Bool, #le_int(#cast_u32_int(#sat_add_u32(a, b)), #iadd(#cast_u32_int(a), #cast_u32_int(b))), true)",
        ] {
            let goal = b.goal(g);
            if let Err(f) = prove(env, &goal) {
                panic!("axiom goal `{g}` failed: {:?}", f.tried);
            }
        }
        let b = GoalBuilder::new(env).binds(&[("a", "U32"), ("b", "U32"), (".nz", "Eq(Bool, #ne_u32(b, 0u32), true)")]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(#rem_u32(a, b; nz), b), true)"));
        // Products of bounded factors (`mul_mono`): `(a as u64) * (b as u64)`
        // cannot overflow, and a product of bounded values stays bounded.
        let b = GoalBuilder::new(env).binds(&[("a", "U32"), ("b", "U32")]);
        assert_proves(
            env,
            &b.goal(
                "Eq(Bool, #le_int(#imul(#cast_u64_int(#cast_u32_u64(a)), #cast_u64_int(#cast_u32_u64(b))), 18446744073709551615int), true)",
            ),
        );
        let b = GoalBuilder::new(env).binds(&[
            ("a", "U32"),
            ("b", "U32"),
            (".ha", "Eq(Bool, #lt_u32(a, 10u32), true)"),
            (".hb", "Eq(Bool, #le_u32(b, 5u32), true)"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#imul(#cast_u32_int(a), #cast_u32_int(b)), 45int), true)"));
        assert_fails(env, &b.goal("Eq(Bool, #le_int(#imul(#cast_u32_int(a), #cast_u32_int(b)), 44int), true)"));
        // negatives
        let b = GoalBuilder::new(env).binds(&[("a", "U32"), ("b", "U32")]);
        assert_fails(env, &b.goal("Eq(Bool, #le_u32(a, #min_u32(a, b)), true)"));
        assert_fails(env, &b.goal("Eq(Bool, #le_u32(#or_u32(a, b), a), true)"));
    });
}

#[test]
fn arithmetic_decision_of_stuck_matches() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("i", "Usize"), ("s", "Slice U8"), (".h", "Eq(Bool, #lt_usize(i, fst(s)), true)")]);
        // `s.get(i)` is `Some(..)` when `i < s.len()`
        assert_proves(env, &b.goal("Eq(Bool, option::is_some U8 (slice::get U8 s i), true)"));
        assert_proves(env, &b.goal("Eq(Bool, option::is_none U8 (slice::get U8 s (#add_usize(fst(s), 0usize; refl(Bool, true)))), true)"));
    });
}

#[test]
fn congruence() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[
            ("s", "Slice U8"),
            ("a", "Usize"),
            ("b", "Usize"),
            (".pab", "Eq(Bool, #le_int(#iadd(#cast_usize_int(a), #cast_usize_int(b)), 18446744073709551615int), true)"),
            (".pba", "Eq(Bool, #le_int(#iadd(#cast_usize_int(b), #cast_usize_int(a)), 18446744073709551615int), true)"),
        ]);
        // get(s, a + b) = get(s, b + a): the sides differ only in an integer
        // argument (commutativity is not definitional).
        assert_proves(env, &b.goal("Eq(Option(U8), slice::get U8 s (#add_usize(a, b; pab)), slice::get U8 s (#add_usize(b, a; pba)))"));
        // A stuck recursive application with permuted integer arguments.
        let b = GoalBuilder::new(env).binds(&[("l", "List(U8)"), ("n", "Int"), ("m", "Int")]);
        assert_proves(env, &b.goal("Eq(List(U8), seq::take U8 l (#iadd(n, m)), seq::take U8 l (#iadd(m, n)))"));
        assert_fails(env, &b.goal("Eq(List(U8), seq::take U8 l (#iadd(n, m)), seq::take U8 l (#iadd(n, n)))"));
    });
}

#[test]
fn case_splits() {
    run(|env| {
        // Bool variable
        let b = GoalBuilder::new(env).bind("c", "Bool");
        assert_proves(env, &b.goal("Eq(Bool, bool::or c (bool::not c), true)"));
        assert_fails(env, &b.goal("Eq(Bool, bool::and c (bool::not c), true)"));
        // Option variable
        let b = GoalBuilder::new(env).bind("o", "Option(U8)");
        assert_proves(env, &b.goal("Eq(Bool, bool::or (option::is_some U8 o) (option::is_none U8 o), true)"));
        // Bool from a comparison inside an arithmetic atom
        let b = GoalBuilder::new(env).bind("x", "U32");
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(bool::as_u32 (#lt_u32(x, 5u32)), 1u32), true)"));
        // negative
        assert_fails(env, &b.goal("Eq(Bool, #le_u32(bool::as_u32 (#lt_u32(x, 5u32)), 0u32), true)"));
    });
}

#[test]
fn struct_eta_and_tuples() {
    run(|env| {
        let b = GoalBuilder::new(env).bind("p", "Tuple2(U32, U32)");
        // match p { (a, b) => (a, b) } == p   (struct eta by conversion or split)
        assert_proves(env, &b.goal("Eq(Tuple2(U32, U32), match p : Tuple2(U32, U32) as _ return Tuple2(U32, U32) with | tuple2(a, c) => tuple2[U32, U32](a, c) end, p)"));
    });
}

#[test]
fn slice_case_analysis() {
    run(|env| {
        // A slice is empty or its first element exists.
        let b = GoalBuilder::new(env).bind("s", "Slice U8");
        assert_proves(env, &b.goal("Eq(Bool, bool::or (slice::is_empty U8 s) (option::is_some U8 (slice::first U8 s)), true)"));
        // split_first on a nonempty slice
        let b = GoalBuilder::new(env).binds(&[("s", "Slice U8"), (".h", "Eq(Bool, #lt_usize(0usize, fst(s)), true)")]);
        assert_proves(env, &b.goal("Eq(Bool, option::is_some (Tuple2(U8, Slice U8)) (slice::split_first U8 s), true)"));
    });
}

#[test]
fn finite_enumeration() {
    run(|env| {
        // A property of a small table that only computes on literals.
        let b = GoalBuilder::new(env).binds(&[("k", "U32"), (".h", "Eq(Bool, #lt_u32(k, 5u32), true)")]);
        let g = "Eq(Bool, #lt_u32(#count_ones_u32(#wshl_u32(1u32, k)), 2u32), true)";
        assert_proves(env, &b.goal(g));
        // With an explicit cases hint.
        let bh = GoalBuilder::new(env).binds(&[("k", "U32"), (".h", "Eq(Bool, #lt_u32(k, 5u32), true)")]);
        let lk = lvl(&bh, "k");
        let bh = bh.hint(Hint::Cases { var: lk, lo: BigInt::from(0), hi: BigInt::from(5) });
        assert_proves(env, &bh.goal("Eq(Bool, #lt_u32(#count_ones_u32(#wshl_u32(3u32, k)), 3u32), true)"));
    });
}

#[test]
fn forall_facts_by_matching() {
    run(|env| {
        // ∀-fact instantiated backward (its conclusion matches the target).
        let b = GoalBuilder::new(env).binds(&[
            ("s", "Slice U8"),
            (".inv", "(i : Usize) -> (.h : Eq(Bool, #lt_usize(i, fst(s)), true)) -> Eq(Bool, #lt_u8(slice::index U8 s i .h, 128u8), true)"),
            ("j", "Usize"),
            (".hj", "Eq(Bool, #lt_usize(j, fst(s)), true)"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_u8(slice::index U8 s j .hj, 128u8), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #le_u8(slice::index U8 s j .hj, 200u8), true)"));
    });
}

#[test]
fn hints() {
    run(|env| {
        // Exact
        let b = GoalBuilder::new(env).binds(&[("x", "U32"), (".h", "Eq(Bool, #lt_u32(x, 3u32), true)")]);
        let h = b.parse("h");
        let bh = GoalBuilder::new(env).binds(&[("x", "U32"), (".h", "Eq(Bool, #lt_u32(x, 3u32), true)")]).hint(Hint::Exact(h));
        assert_proves(env, &bh.goal("Eq(Bool, #lt_u32(x, 3u32), true)"));
        // Lemma: an instance used as a fact
        let bl = GoalBuilder::new(env).bind("s", "Slice U8");
        let lem = bl.parse("slice::ok_bound U8 s");
        let bl = bl.hint(Hint::Lemma(lem));
        assert_proves(env, &bl.goal("Eq(Bool, #le_int(#cast_usize_int(fst(s)), ISIZE_MAX), true)"));
        let _ = b;
        // Rewrite (both directions)
        let br = GoalBuilder::new(env).binds(&[
            ("x", "U32"),
            ("y", "U32"),
            ("f", "U32 -> Bool"),
            (".e", "Eq(U32, x, y)"),
            (".h", "Eq(Bool, f y, true)"),
        ]);
        let e = br.parse("e");
        let br2 = GoalBuilder::new(env)
            .binds(&[("x", "U32"), ("y", "U32"), ("f", "U32 -> Bool"), (".e", "Eq(U32, x, y)"), (".h", "Eq(Bool, f y, true)")])
            .hint(Hint::Rewrite { eq: e.clone(), rev: false, motive: None });
        assert_proves(env, &br2.goal("Eq(Bool, f x, true)"));
        let br3 = GoalBuilder::new(env)
            .binds(&[("x", "U32"), ("y", "U32"), ("f", "U32 -> Bool"), (".e", "Eq(U32, x, y)"), (".h", "Eq(Bool, f x, true)")])
            .hint(Hint::Rewrite { eq: e, rev: true, motive: None });
        assert_proves(env, &br3.goal("Eq(Bool, f y, true)"));
        let _ = br;
        // Unfold: an opaque-by-recursion list length on a literal list computes;
        // on a symbolic list the unfold hint exposes the definition.
        let bu = GoalBuilder::new(env).binds(&[("h", "U8"), ("t", "List(U8)")]);
        let len = env.lookup_global("seq::len").unwrap();
        let bu = bu.hint(Hint::Unfold(len));
        assert_proves(env, &bu.goal("Eq(Int, seq::len U8 (Cons[U8](h, t)), #iadd(1int, seq::len U8 t))"));
        // Bv (BvRefl accepts what conversion accepts)
        let bv = GoalBuilder::new(env).bind("x", "U32").hint(Hint::Bv);
        assert_proves(env, &bv.goal("Eq(U32, #xor_u32(x, 0u32), #xor_u32(x, 0u32))"));
    });
}

// ---------------------------------------------------------------------------
// Determinism and budget.
// ---------------------------------------------------------------------------

#[test]
fn determinism() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("before", "U32"), ("inactive", "U32")]).def("folded", "U32", "#min_u32(before, inactive)");
        let g = b.goal("Eq(Bool, #le_int(#iadd(#cast_u64_int(#sat_sub_u64(#cast_u32_u64(before), #cast_u32_u64(folded))), #cast_u64_int(bool::as_u64 (#ne_u32(folded, 0u32)))), 18446744073709551615int), true)");
        let names = ctx_names(&g.ctx);
        let t1 = env.print_term(&names, &prove(env, &g).expect("proof"));
        for _ in 0..3 {
            let t2 = env.print_term(&names, &prove(env, &g).expect("proof"));
            assert_eq!(t1, t2, "auto is not deterministic");
        }
    });
}

#[test]
fn budget_exhaustion_is_a_failure() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("before", "U32"), ("inactive", "U32")]).def("folded", "U32", "#min_u32(before, inactive)");
        let g = b.goal("Eq(Bool, #le_int(#iadd(#cast_u64_int(#sat_sub_u64(#cast_u32_u64(before), #cast_u32_u64(folded))), #cast_u64_int(bool::as_u64 (#ne_u32(folded, 0u32)))), 18446744073709551615int), true)");
        // Tiny kernel budget.
        let mut auto = sandblaster_front::auto::Auto::new();
        let mut small = sandblaster_kernel::value::Budget { steps: 200 };
        use sandblaster_front::prover::Prover;
        let r = auto.prove(env, &g, &mut small);
        let f = r.expect_err("must fail with a tiny budget");
        assert!(f.tried.iter().any(|t| t.contains("budget")), "{:?}", f.tried);
        // Tiny node limit.
        let cfg = AutoConfig { max_nodes: 3, ..AutoConfig::default() };
        let f = prove_with(env, &g, cfg).expect_err("must fail with a tiny node limit");
        assert!(f.tried.iter().any(|t| t.contains("budget")), "{:?}", f.tried);
        // And the goal is provable with the default limits.
        assert_proves(env, &g);
    });
}

#[test]
fn failure_reports() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("x", "U32"), (".h", "Eq(Bool, #lt_u32(x, 10u32), true)")]);
        let f = assert_fails(env, &b.goal("Eq(Bool, #lt_u32(x, 5u32), true)"));
        assert!(f.goal.contains("#lt_u32"));
        assert_eq!(f.facts.len(), 1, "{:?}", f.facts);
        assert!(!f.tried.is_empty() || f.goal.contains("x"));
    });
}

#[test]
fn array_literals_with_symbolic_index() {
    run(|env| {
        // `TABLE[i]` for a literal table and `i < 3`: the index proof of the
        // unfolded `array::index` refers to the literal (quoted with
        // placeholders in proof closures, re-proved by `repair`).
        let lit = "pair(Array U8 3usize, Cons[U8](1u8, Cons[U8](2u8, Cons[U8](3u8, Nil[U8]))), refl(Int, 3int))";
        let b = GoalBuilder::new(env).binds(&[("i", "Usize"), (".h", "Eq(Bool, #lt_usize(i, 3usize), true)")]);
        assert_proves(env, &b.goal(&format!("Eq(Bool, #le_u8(array::index U8 3usize {lit} i .h, 3u8), true)")));
        assert_proves(env, &b.goal(&format!("Eq(Bool, #lt_u8(0u8, array::index U8 3usize {lit} i .h), true)")));
        assert_fails(env, &b.goal(&format!("Eq(Bool, #le_u8(array::index U8 3usize {lit} i .h, 2u8), true)")));
    });
}

// ---------------------------------------------------------------------------
// Plan O3: bit-count lemmas (step 7), wrapping exactness, integer cuts, fact
// normalization.
// ---------------------------------------------------------------------------

#[test]
fn bit_count_bounds_are_lemmas() {
    run(|env| {
        // The retired bound axioms are the lemmas of `lemmas/bits.core`.
        let b = GoalBuilder::new(env).bind("a", "U64");
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(#leading_zeros_u64(a), 64u32), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(#trailing_zeros_u64(a), 64u32), true)"));
        assert_proves(
            env,
            &b.goal("Eq(Bool, #le_int(#iadd(#cast_u32_int(#count_ones_u64(a)), #cast_u32_int(#leading_zeros_u64(a))), 128int), true)"),
        );
        // The strict bounds when `a ≠ 0` is decidable.
        let b = GoalBuilder::new(env).binds(&[("a", "U64"), (".h", "Eq(Bool, #lt_u64(0u64, a), true)")]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(#trailing_zeros_u64(a), 64u32), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(#leading_zeros_u64(a), 63u32), true)"));
        let b = GoalBuilder::new(env).bind("a", "U64");
        assert_fails(env, &b.goal("Eq(Bool, #lt_u32(#trailing_zeros_u64(a), 64u32), true)"));
    });
}

#[test]
fn wrapping_operations_that_do_not_wrap_are_exact() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("a", "U64"), (".h", "Eq(Bool, #le_u64(a, 1000u64), true)")]);
        assert_proves(env, &b.goal("Eq(Int, #cast_u64_int(#wadd_u64(a, 5u64)), #iadd(#cast_u64_int(a), 5int))"));
        assert_proves(env, &b.goal("Eq(Int, #cast_u64_int(#wmul_u64(a, 3u64)), #imul(3int, #cast_u64_int(a)))"));
        let b = GoalBuilder::new(env).binds(&[("a", "U64"), (".h", "Eq(Bool, #le_u64(8u64, a), true)")]);
        assert_proves(env, &b.goal("Eq(Int, #cast_u64_int(#wsub_u64(a, 8u64)), #isub(#cast_u64_int(a), 8int))"));
        // without the bound the sum may wrap
        let b = GoalBuilder::new(env).bind("a", "U64");
        assert_fails(env, &b.goal("Eq(Int, #cast_u64_int(#wadd_u64(a, 5u64)), #iadd(#cast_u64_int(a), 5int))"));
    });
}

#[test]
fn integer_cut_on_a_bit_atom() {
    run(|env| {
        // a = c + 4·bit with bit = (x >> 2) & 1 ∈ {0, 1} and a ≤ 3: rationally
        // bit ∈ [1/4, 3/4] is possible, so `a = c` needs the cut `bit < 1`.
        let bit = "#and_u64(#wshr_u64(x, 2u32), 1u64)";
        let b = GoalBuilder::new(env).binds(&[
            ("x", "U64"),
            ("a", "U64"),
            ("c", "U64"),
            (".h", &format!("Eq(Int, #cast_u64_int(a), #iadd(#cast_u64_int(c), #imul(4int, #cast_u64_int({bit}))))")),
            (".k", "Eq(Bool, #le_u64(a, 3u64), true)"),
        ]);
        let g = b.goal("Eq(U64, a, c)");
        assert_proves(env, &g);
        let no_cuts = AutoConfig { int_cuts: 0, ..AutoConfig::default() };
        assert!(prove_with(env, &g, no_cuts).is_err(), "linarith alone is rational");
        // a false variant stays unproven
        assert_fails(env, &b.goal("Eq(U64, a, 0u64)"));
    });
}

/// Quotient/remainder atoms that no word operation produces: a division by
/// the literal 0 (the cut used to panic building the word operation) and a
/// ghost `Int` division of a cast (the kernel keeps its own pair for it, so
/// a cut through the word operation constrained a different atom). The
/// context `0 < 2q < 2` has no integer solution; only a cut on `q` itself
/// refutes it.
#[test]
fn integer_cuts_on_int_divisions_of_casts() {
    run(|env| {
        // (type of x, q, goal, whether linarith without cuts fails)
        let cases = [
            ("U64", "#idiv(#cast_u64_int(x), 0int)", "#lt_u64(x, 0u64)", true),
            ("U64", "#imod(#cast_u64_int(x), 0int)", "#lt_u64(x, 0u64)", true),
            ("U64", "#idiv(#cast_u64_int(x), 3int)", "#lt_u64(x, 0u64)", true),
            ("U64", "#idiv(#cast_u64_int(x), 4int)", "#lt_u64(x, 0u64)", true),
            ("U64", "#imod(#cast_u64_int(x), 3int)", "#lt_u64(x, 0u64)", true),
            // a divisor beyond the word's range: only the `Int` pair exists
            // (q ∈ {0}: other steps may decide it without a cut)
            ("U8", "#idiv(#cast_u8_int(x), 1000int)", "#lt_u8(x, 0u8)", false),
        ];
        for (ty, q, goal, needs_cut) in cases {
            let b = GoalBuilder::new(env).binds(&[
                ("x", ty),
                (".h", &format!("Eq(Bool, #lt_int(0int, #imul(2int, {q})), true)")),
                (".k", &format!("Eq(Bool, #lt_int(#imul(2int, {q}), 2int), true)")),
            ]);
            let g = b.goal(&format!("Eq(Bool, {goal}, true)"));
            if let Err(f) = prove(env, &g) {
                panic!("{q}: not proved: {:#?}", f.tried);
            }
            if needs_cut {
                let no_cuts = AutoConfig { int_cuts: 0, ..AutoConfig::default() };
                assert!(prove_with(env, &g, no_cuts).is_err(), "{q}: linarith alone is rational");
            }
        }
        // satisfiable contexts (q = 1 at x = 3, r = 1 at x = 1) stay unproven
        for q in ["#idiv(#cast_u64_int(x), 3int)", "#imod(#cast_u64_int(x), 3int)"] {
            let b = GoalBuilder::new(env).binds(&[
                ("x", "U64"),
                (".h", &format!("Eq(Bool, #lt_int(0int, {q}), true)")),
                (".k", &format!("Eq(Bool, #lt_int({q}, 2int), true)")),
            ]);
            assert_fails(env, &b.goal("Eq(Bool, #lt_u64(x, 0u64), true)"));
        }
    });
}

#[test]
fn disequalities_are_normalized_or_split_on_demand() {
    run(|env| {
        // unsigned `x ≠ 0` is `0 < x` (a fact linarith can use)
        let b = GoalBuilder::new(env).binds(&[
            ("x", "U32"),
            (".h", "Eq(Bool, #ne_u32(x, 0u32), true)"),
            (".k", "Eq(Bool, #lt_u32(x, 2u32), true)"),
        ]);
        assert_proves(env, &b.goal("Eq(U32, x, 1u32)"));
        let b = GoalBuilder::new(env).binds(&[("x", "U64"), (".h", "Eq(Bool, #eq_u64(x, 0u64), false)")]);
        assert_proves(env, &b.goal("Eq(Bool, #le_u64(1u64, x), true)"));
        // a general disequality is split inside linear arithmetic — also in
        // a restricted (`by_arithmetic`) goal, which allows no case analysis
        // on program values but is complete linear integer arithmetic
        // (DESIGN.md §4.4)
        let b = GoalBuilder::new(env)
            .binds(&[("a", "U32"), ("c", "U32"), (".h", "Eq(Bool, #le_u32(a, c), true)"), (".k", "Eq(Bool, #ne_u32(a, c), true)")])
            .hint(Hint::Only(sandblaster_front::prover::Reasoning::Arithmetic));
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(a, c), true)"));
        let b = GoalBuilder::new(env).binds(&[("a", "U32"), ("c", "U32"), (".k", "Eq(Bool, #ne_u32(a, c), true)")]);
        assert_fails(env, &b.goal("Eq(Bool, #lt_u32(a, c), true)"));
    });
}
