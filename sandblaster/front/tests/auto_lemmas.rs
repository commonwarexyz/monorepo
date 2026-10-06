//! The prelude lemmas (DESIGN.md §6; `sandblaster/front/lemmas/*.core`)
//! load and check, and `auto` uses them (rules by role, §3.4 method facts).

#[path = "auto_support.rs"]
mod support;

use support::*;

#[test]
fn lemma_files_load() {
    run(|env| {
        for name in [
            "bool::and_left",
            "bool::eq_sound",
            "u8::eq_sound",
            "usize::ne_sound",
            "seq::take_drop_append",
            "seq::eq_sound",
            "seq::eq_refl",
            "seq::index_cons_zero",
            "seq::index_cons_succ",
            "seq::index_update_same",
            "seq::index_update_other",
            "seq::list_ext",
            "slice::ext",
            "slice::is_empty_nil",
            "slice::len_cons",
            "slice::len_nil",
            "array::ext",
            "array::eq_sound_u8",
            "array::eq_complete_usize",
            "seq::take_len",
            "option::if_some",
            "slice::split_at_checked_some",
            "slice::split_first_some",
            "slice::split_last_some",
            "slice::get_some",
            "slice::first_chunk_exact",
            "slice::split_first_chunk_some",
            "slice::split_first_chunk_none",
            "seq::chunks_c_small",
            "seq::chunks_rest_c_step",
            "seq::chunks_len_16",
            "slice::as_chunks_len_64",
            "slice::as_chunks_len_256",
            "bool::and_true_left",
            "word::byte7",
            "word::eq8",
            "word::xor_or_eq0",
            "word::xor_eq0",
            "word::eq8_or",
            "word::eq8_last",
        ] {
            assert!(env.lookup_global(name).is_some(), "lemma `{name}` is not loaded");
        }
    });
}

use sandblaster_front::auto::lemmas::{FactShape, fact_prop, method_facts};
use sandblaster_front::builtins::{Builtin, SliceMethod};

/// Bind the method fact `lemma args..` as an irrelevant fact binder
/// `name`, the way the elaborator does at a call site.
#[allow(clippy::too_many_arguments)]
fn with_method_fact<'e>(
    b: GoalBuilder<'e>,
    name: &str,
    builtin: Builtin,
    elem: &str,
    args: &[&str],
    payload: &[&str],
    eq: Option<&str>,
    which: usize,
) -> GoalBuilder<'e> {
    let env = b.env;
    let facts = method_facts(&builtin);
    let mf = &facts[which];
    let parse = |s: &str| b.parse(s);
    let args: Vec<_> = args.iter().map(|a| parse(a)).collect();
    let payload: Vec<_> = payload.iter().map(|a| parse(a)).collect();
    let eq = eq.map(parse);
    let proof =
        mf.apply(env, &parse(elem), &args, &payload, eq.as_ref()).unwrap_or_else(|| panic!("method fact {} did not apply", mf.lemma));
    let prop = fact_prop(env, &b.ctx, &proof, &mut budget()).expect("fact proposition");
    let ty = env.quote_typed(&b.ctx, &prop, None, false);
    let names = b.names();
    let text = env.print_term(&names, &ty);
    b.bind(&format!(".{name}"), &text)
}

#[test]
fn method_facts_split_at_checked() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[
            ("s", "Slice U8"),
            ("mid", "Usize"),
            ("a", "Slice U8"),
            ("c", "Slice U8"),
            (".e", "Eq(Option(Tuple2(Slice U8, Slice U8)), slice::split_at_checked U8 s mid, Some[Tuple2(Slice U8, Slice U8)](tuple2[Slice U8, Slice U8](a, c)))"),
        ]);
        let facts = method_facts(&Builtin::Slice(SliceMethod::SplitAtChecked));
        assert!(matches!(facts[0].shape, FactShape::OnSome { payload: 2 }));
        let b = with_method_fact(b, "mf", Builtin::Slice(SliceMethod::SplitAtChecked), "U8", &["s", "mid"], &["a", "c"], Some("e"), 0);
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(mid, fst(s)), true)"));
        assert_proves(env, &b.goal("Eq(Usize, fst(a), mid)"));
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(fst(c), fst(s)), true)"));
        assert_proves(env, &b.goal("Eq(List(U8), seq::append U8 fst(snd(a)) fst(snd(c)), fst(snd(s)))"));
        assert_fails(env, &b.goal("Eq(Bool, #lt_usize(fst(c), fst(s)), true)"));
    });
}

#[test]
fn forward_rules_without_the_elaborator() {
    run(|env| {
        // Only the path equation; the method fact is found by a forward rule.
        let b = GoalBuilder::new(env).binds(&[
            ("s", "Slice U8"),
            ("mid", "Usize"),
            ("a", "Slice U8"),
            ("c", "Slice U8"),
            (".e", "Eq(Option(Tuple2(Slice U8, Slice U8)), slice::split_at_checked U8 s mid, Some[Tuple2(Slice U8, Slice U8)](tuple2[Slice U8, Slice U8](a, c)))"),
        ]);
        assert_proves(env, &b.goal("Eq(Usize, fst(a), mid)"));
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(fst(c), fst(s)), true)"));
        // get(i) == None ⇒ len ≤ i
        let b = GoalBuilder::new(env).binds(&[("s", "Slice U8"), ("i", "Usize"), (".e", "Eq(Option(U8), slice::get U8 s i, None[U8])")]);
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(fst(s), i), true)"));
        // split_first_chunk::<32> == Some((k, rest)) ⇒ rest.len() == s.len() − 32
        let b = GoalBuilder::new(env).binds(&[
            ("s", "Slice U8"),
            ("k", "Array U8 32usize"),
            ("rest", "Slice U8"),
            (".e", "Eq(Option(Tuple2(Array U8 32usize, Slice U8)), slice::split_first_chunk U8 s 32usize, Some[Tuple2(Array U8 32usize, Slice U8)](tuple2[Array U8 32usize, Slice U8](k, rest)))"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(32usize, fst(s)), true)"));
        assert_proves(env, &b.goal("Eq(Int, #iadd(#cast_usize_int(fst(rest)), 32int), #cast_usize_int(fst(s)))"));
    });
}

/// Forward rules fire on a path equation whose payload is a tuple variable
/// (`split_first(s) == Some(p)`, `p` projected later — the pattern
/// compiler projects tuples, so `let Some((h, t)) = s.split_first() else
/// ..` and `let (h, t) = s.split_first()?` never produce `Some(tuple2(h,
/// t))`): the rule's `tuple2(x, rest)` matches `p` through struct η, with
/// `x := π₀ p`, `rest := π₁ p` (the elaborator's projections).
/// Regression: `redteam_fidelity::tail_recursion_differential`, the
/// termination of `early` / `opt_tail` (`decreases(xs.len())`).
#[test]
fn forward_rules_through_struct_eta() {
    run(|env| {
        let t1 = "match p : Tuple2(U8, Slice U8) as _ return Slice U8 with | tuple2(x, r) => r end";
        let b = GoalBuilder::new(env).binds(&[
            ("s", "Slice U8"),
            ("p", "Tuple2(U8, Slice U8)"),
            (".e", "Eq(Option(Tuple2(U8, Slice U8)), slice::split_first U8 s, Some[Tuple2(U8, Slice U8)](p))"),
        ]);
        // termination of the recursive call on the tail: `t.len() < s.len()`
        assert_proves(env, &b.goal(&format!("Eq(Bool, #lt_usize(fst({t1}), fst(s)), true)")));
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(0usize, fst(s)), true)"));
        assert_proves(env, &b.goal(&format!("Eq(Int, #iadd(#cast_usize_int(fst({t1})), 1int), #cast_usize_int(fst(s)))")));
        // still only what the lemma says
        assert_fails(env, &b.goal(&format!("Eq(Bool, #lt_usize(fst(s), fst({t1})), true)")));
        assert_fails(env, &b.goal(&format!("Eq(Bool, #lt_usize(1usize, fst({t1})), true)")));
        // `split_at_checked(mid) == Some(q)`, both halves projected
        let (qa, qc) = (
            "match q : Tuple2(Slice U8, Slice U8) as _ return Slice U8 with | tuple2(a, c) => a end",
            "match q : Tuple2(Slice U8, Slice U8) as _ return Slice U8 with | tuple2(a, c) => c end",
        );
        let b = GoalBuilder::new(env).binds(&[
            ("s", "Slice U8"),
            ("mid", "Usize"),
            ("q", "Tuple2(Slice U8, Slice U8)"),
            (".e", "Eq(Option(Tuple2(Slice U8, Slice U8)), slice::split_at_checked U8 s mid, Some[Tuple2(Slice U8, Slice U8)](q))"),
        ]);
        assert_proves(env, &b.goal(&format!("Eq(Usize, fst({qa}), mid)")));
        assert_proves(env, &b.goal(&format!("Eq(Bool, #le_usize(fst({qc}), fst(s)), true)")));
        assert_fails(env, &b.goal(&format!("Eq(Bool, #lt_usize(fst({qc}), fst(s)), true)")));
    });
}

#[test]
fn method_facts_as_chunks() {
    run(|env| {
        let b = GoalBuilder::new(env).bind("s", "Slice U8");
        let b = with_method_fact(b, "mf", Builtin::Slice(SliceMethod::AsChunks(64)), "U8", &["s", "refl(Bool, true)"], &[], None, 0);
        let tail = "match slice::as_chunks U8 s 64usize .refl(Bool, true) : Tuple2(Slice (Array U8 64usize), Slice U8) as _ return Slice U8 with | tuple2(cs, rs) => rs end";
        let chunks = "match slice::as_chunks U8 s 64usize .refl(Bool, true) : Tuple2(Slice (Array U8 64usize), Slice U8) as _ return Slice (Array U8 64usize) with | tuple2(cs, rs) => cs end";
        assert_proves(env, &b.goal(&format!("Eq(Bool, #lt_usize(fst({tail}), 64usize), true)")));
        assert_proves(env, &b.goal(&format!("Eq(Bool, #le_usize(fst({tail}), fst(s)), true)")));
        // compress_sha2-shaped: a 64-byte block has 4 chunks of 16.
        let b = GoalBuilder::new(env).binds(&[("s", "Slice U8"), (".len", "Eq(Usize, fst(s), 64usize)")]);
        let b = with_method_fact(b, "mf", Builtin::Slice(SliceMethod::AsChunks(16)), "U8", &["s", "refl(Bool, true)"], &[], None, 0);
        let chunks16 = "match slice::as_chunks U8 s 16usize .refl(Bool, true) : Tuple2(Slice (Array U8 16usize), Slice U8) as _ return Slice (Array U8 16usize) with | tuple2(cs, rs) => cs end";
        assert_proves(env, &b.goal(&format!("Eq(Bool, #lt_usize(3usize, fst({chunks16})), true)")));
        assert_fails(env, &b.goal(&format!("Eq(Bool, #lt_usize(4usize, fst({chunks16})), true)")));
        let _ = chunks;
        // Sizes outside CHUNK_SIZES: only the remainder bound, from the
        // generic lemma (its arguments include `N`).
        let f3 = method_facts(&Builtin::Slice(SliceMethod::AsChunks(3)));
        assert_eq!(f3.len(), 1);
        assert_eq!(f3[0].lemma, "slice::as_chunks_rest_lt");
        let b = GoalBuilder::new(env).bind("s", "Slice U8");
        let b = with_method_fact(b, "mf", Builtin::Slice(SliceMethod::AsChunks(3)), "U8", &["s", "3usize", "refl(Bool, true)"], &[], None, 0);
        let tail3 = "match slice::as_chunks U8 s 3usize .refl(Bool, true) : Tuple2(Slice (Array U8 3usize), Slice U8) as _ return Slice U8 with | tuple2(cs, rs) => rs end";
        assert_proves(env, &b.goal(&format!("Eq(Bool, #lt_usize(fst({tail3}), 3usize), true)")));
    });
}

#[test]
fn backward_rules_array_equality() {
    run(|env| {
        // digest_equal_sound: `sha256::equal(&left, &right)` is array `==`.
        let b = GoalBuilder::new(env).binds(&[
            ("left", "Array U8 32usize"),
            ("right", "Array U8 32usize"),
            (".h", "Eq(Bool, array::eq U8 32usize (fun (x : U8) (y : U8) => #eq_u8(x, y)) left right, true)"),
        ]);
        assert_proves(env, &b.goal("Eq(Array U8 32usize, left, right)"));
        // Negative: without the fact.
        let b = GoalBuilder::new(env).binds(&[("left", "Array U8 4usize"), ("right", "Array U8 4usize")]);
        assert_fails(env, &b.goal("Eq(Array U8 4usize, left, right)"));
    });
}

#[test]
fn rewrite_and_linarith_rules() {
    run(|env| {
        // take ++ drop (rewrite rule), drop 0 (rewrite rule)
        let b = GoalBuilder::new(env).binds(&[("l", "List(U8)"), ("n", "Int"), ("f", "List(U8) -> Bool"), (".h", "Eq(Bool, f l, true)")]);
        assert_proves(env, &b.goal("Eq(Bool, f (seq::append U8 (seq::take U8 l n) (seq::drop U8 l n)), true)"));
        assert_proves(env, &b.goal("Eq(Bool, f (seq::drop U8 l 0int), true)"));
        // index/update (conditional rewrite rules)
        let b = GoalBuilder::new(env).binds(&[
            ("l", "List(U8)"),
            ("i", "Int"),
            ("j", "Int"),
            ("v", "U8"),
            (".h0", "Eq(Bool, #le_int(0int, j), true)"),
            (".h1", "Eq(Bool, #lt_int(j, seq::len U8 l), true)"),
            (".h1u", "Eq(Bool, #lt_int(j, seq::len U8 (seq::update U8 l i v)), true)"),
            (".ne", "Eq(Bool, #eq_int(i, j), false)"),
        ]);
        assert_proves(env, &b.goal("Eq(U8, seq::index U8 (seq::update U8 l i v) j .h0 .h1u, seq::index U8 l j .h0 .h1)"));
        // length lemmas as linarith rules
        let b = GoalBuilder::new(env).binds(&[
            ("l", "List(U8)"),
            ("n", "Int"),
            (".h0", "Eq(Bool, #le_int(0int, n), true)"),
            (".h1", "Eq(Bool, #le_int(n, seq::len U8 l), true)"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #le_int(seq::len U8 (seq::take U8 l n), seq::len U8 l), true)"));
        assert_proves(env, &b.goal("Eq(Int, #iadd(seq::len U8 (seq::take U8 l n), seq::len U8 (seq::drop U8 l n)), seq::len U8 l)"));
    });
}

#[test]
fn slice_lemmas_in_use() {
    run(|env| {
        // is_empty ⇒ s == &[]
        let b = GoalBuilder::new(env).binds(&[("s", "Slice U8"), (".h", "Eq(Bool, slice::is_empty U8 s, true)")]);
        assert_proves(env, &b.goal("Eq(Slice U8, s, slice::empty U8)"));
        // first_chunk_exact (PROOF.rs): s.len() == 32 ∧ first_chunk == Some(k) ⇒ list(s) == list(k)
        let b = GoalBuilder::new(env).binds(&[
            ("s", "Slice U8"),
            ("k", "Array U8 32usize"),
            (".hn", "Eq(Usize, fst(s), 32usize)"),
            (".e", "Eq(Option(Array U8 32usize), slice::first_chunk U8 s 32usize, Some[Array U8 32usize](k))"),
        ]);
        assert_proves(env, &b.goal("Eq(List(U8), fst(snd(s)), fst(k))"));
    });
}

// ---------------------------------------------------------------------------
// The bit-count library (`lemmas/bits.core` and the on-demand per-literal
// families of `auto::bitlib`).
// ---------------------------------------------------------------------------

use sandblaster_front::auto::bitlib::{self, Family};
use sandblaster_kernel::term::Width;

/// Run `f` on a big-stack thread with the prelude and the lemma files that
/// precede `bits.core` (the environment `bits.core` is generated in).
fn before_bits<T: Send + 'static>(f: impl FnOnce(&mut sandblaster_kernel::api::Env) -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || {
            sandblaster_kernel::util::set_stack_limit(900 << 20);
            let mut env = sandblaster_kernel::api::Env::with_prelude();
            for (file, src) in sandblaster_front::auto::lemmas::FILES {
                if *file == "bits.core" {
                    break;
                }
                let text =
                    sandblaster_front::auto::lemmas::expand_n_templates(src).and_then(|t| sandblaster_kernel::expand_templates(&t)).unwrap();
                env.load_core(&text, &mut budget()).unwrap_or_else(|e| panic!("{file}: {e}"));
            }
            f(&mut env)
        })
        .expect("spawn")
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e))
}

/// `lemmas/bits.core` is the generator's output, certificates included
/// (`SANDBLASTER_REGEN_BITS=1` rewrites it).
#[test]
fn bits_core_is_generated() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("lemmas/bits.core");
    let text = before_bits(|env| bitlib::bits_core_text(env, &mut budget()).unwrap_or_else(|e| panic!("{e}")));
    if std::env::var_os("SANDBLASTER_REGEN_BITS").is_some() {
        std::fs::write(&path, &text).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk == text, "lemmas/bits.core is stale: rerun with SANDBLASTER_REGEN_BITS=1");
}

#[test]
fn bits_core_lemmas_load() {
    run(|env| {
        for w in ["u8", "u16", "u32", "u64", "usize"] {
            for stem in [
                "count_ones_le",
                "leading_zeros_le",
                "leading_zeros_lt",
                "trailing_zeros_le",
                "trailing_zeros_lt",
                "ne_zero_pos",
                "eq_zero_false_pos",
                "lz_ge_one",
                "popcnt_shr1",
                "bit1_flip",
                "not_val",
                "wadd_exact",
                "wsub_exact",
                "wmul_exact",
            ] {
                let name = format!("bits::{stem}_{w}");
                assert!(env.lookup_global(&name).is_some(), "lemma `{name}` is not loaded");
            }
        }
    });
}

/// Every per-literal family member checks: exhaustively at U8/U16/U32,
/// and at U64/Usize for `k ∈ {0, 1, 2, 31, 61, 62, 63}` (all `k` with
/// `SANDBLASTER_BITS_ALL=1`).
#[test]
fn bits_families_check() {
    let all = std::env::var_os("SANDBLASTER_BITS_ALL").is_some();
    run(move |env| {
        let mut b = budget();
        for w in bitlib::WIDTHS {
            let n = w.bits().unwrap();
            let ks: Vec<u32> = if n <= 32 || all { (0..n).collect() } else { vec![0, 1, 2, 31, 61, 62, 63] };
            for f in Family::ALL {
                for &k in &ks {
                    if !f.valid(w, k) {
                        assert!(bitlib::family_item(f, w, k).is_none());
                        continue;
                    }
                    let t = std::time::Instant::now();
                    bitlib::ensure(env, f, w, k, &mut b).unwrap_or_else(|e| panic!("{}: {e}", bitlib::lemma_name(f, w, k)));
                    if t.elapsed().as_millis() > 200 {
                        eprintln!("{} took {:?}", bitlib::lemma_name(f, w, k), t.elapsed());
                    }
                }
            }
        }
        let _ = Width::U8;
    });
}
