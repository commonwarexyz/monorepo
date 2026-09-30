//! Law-shaped goals (DESIGN.md §11.3; `sandblaster/fixtures/qmdb/sandblaster/LAWS.rs` and the
//! proof sketches of `sandblaster/fixtures/qmdb/sandblaster/PROOF.rs`), on miniature core-text
//! versions of the QMDB definitions written the way the elaborator
//! produces them (DESIGN.md §7: short-circuit `&&` as a Bool match,
//! `if n == 0` with a dependent equation, struct matches, let-bound
//! intermediate values, hashes as opaque definitions).
//!
//! The proof slots of the miniature definitions (overflow and range
//! obligations) are themselves discharged by `auto` and printed into the
//! definition text, as the elaborator would. Every goal's term is
//! re-checked by the kernel (`support::prove`).
//!
//! Differences from the real laws (recorded in the report): `bag_prefix`
//! recurses over a `List` of digests instead of a slice (the slice version
//! needs measure proofs over `SliceOk` that the elaborator generates), and
//! the Merkle arithmetic is a reduced version of `required_digests` with
//! the same operations (`min`, `saturating_sub`, `bool as u64`, widening
//! casts, checked adds).

#[path = "auto_support.rs"]
mod support;

use sandblaster_front::prover::Hint;
use sandblaster_kernel::api::Env;
use support::*;

/// The digest type.
const DIG: &str = "(Array U8 32usize)";

/// A proof by `auto` of `goal` in the context `binds` (plus let-bound
/// `defs`), printed as core text for a definition's proof slot.
fn auto_proof(env: &Env, binds: &[(&str, &str)], defs: &[(&str, &str, &str)], goal: &str) -> String {
    let mut b = GoalBuilder::new(env).binds(binds);
    for (n, t, v) in defs {
        b = b.def(n, t, v);
    }
    let t = assert_proves(env, &b.goal(goal));
    env.print_term(&b.names(), &t)
}

fn dig(s: &str) -> String {
    s.replace("DIG", DIG)
}

/// Load the miniature QMDB definitions.
fn load_mini(env: &mut Env) {
    // `n - 1` under `n == 0` being false (the elaborator's `if n == 0 {
    // return .. }` shape; `eq .. false` is not a linarith hypothesis, so
    // `auto` splits the disequality).
    let sub_pf =
        auto_proof(env, &[("n", "Usize"), (".hz", "Eq(Bool, #eq_usize(n, 0usize), false)")], &[], "Eq(Bool, #le_usize(1usize, n), true)");
    // `required_digests`-shaped arithmetic: overflow obligations.
    let u32s = [("height", "U32"), ("before", "U32"), ("after", "U32"), ("inactive", "U32")];
    let folded = [("folded", "U32", "#min_u32(before, inactive)")];
    let bc_sum = "#iadd(#cast_u64_int(#sat_sub_u64(#cast_u32_u64(before), #cast_u32_u64(folded))), #cast_u64_int(bool::as_u64 (#ne_u32(folded, 0u32))))";
    let p1 = auto_proof(env, &u32s, &folded, &format!("Eq(Bool, #le_int({bc_sum}, 18446744073709551615int), true)"));
    let before_count =
        format!("#add_u64(#sat_sub_u64(#cast_u32_u64(before), #cast_u32_u64(folded)), bool::as_u64 (#ne_u32(folded, 0u32)); {p1})");
    let folded_bc = [folded[0], ("before_count", "U64", before_count.as_str())];
    let p2 = auto_proof(
        env,
        &u32s,
        &folded_bc,
        "Eq(Bool, #le_int(#iadd(#cast_u64_int(#cast_u32_u64(height)), #cast_u64_int(before_count)), 18446744073709551615int), true)",
    );
    let p3 = auto_proof(
        env,
        &u32s,
        &[],
        "Eq(Bool, #le_int(#iadd(#cast_u64_int(#cast_u32_u64(before)), #cast_u64_int(#cast_u32_u64(after))), 18446744073709551615int), true)",
    );

    let src = dig(&format!(
        r#"
inductive MiniProof {{ | mini_proof(location : U32, chunk : U8, width : U64) }}
inductive MiniShape {{ | mini_shape(height : U32, before : U32, after : U32) }}

-- Hashes: opaque, never unfolded by automation.
def[spec, opaque] mini::fold : (a : DIG) -> (b : DIG) -> DIG :=
  fun (a : DIG) (b : DIG) => a

def[exec] mini::join : (head : DIG) -> (tail : Option(DIG)) -> Option(DIG) :=
  fun (head : DIG) (tail : Option(DIG)) =>
    match tail : Option(DIG) as _ return Option(DIG) with
    | None => Some[DIG](head)
    | Some(d) => Some[DIG](mini::fold head d)
    end

def[exec] mini::fold_back : (xs : List(DIG)) -> Option(DIG) :=
  fun (xs : List(DIG)) =>
    match xs : List(DIG) as _ return Option(DIG) with
    | Nil => None[DIG]
    | Cons(h, t) => mini::join h (rec(t))
    end
  structural 0

-- merkle::bag_prefix (over a list of digests).
def[exec] mini::bag_prefix : (n : Usize) -> (xs : List(DIG)) -> (acc : DIG) -> Option(DIG) :=
  fun (n : Usize) (xs : List(DIG)) (acc : DIG) =>
    if #eq_usize(n, 0usize) as .hz return Option(DIG)
    then mini::join acc (mini::fold_back xs)
    else match xs : List(DIG) as _ return Option(DIG) with
         | Nil => None[DIG]
         | Cons(head, tail) => rec(#sub_usize(n, 1usize; {sub_pf}), tail, mini::fold acc head)
         end
  structural 1

-- verifier::active / root_matches / verify_decoded / verify_parsed / exact.
def[exec] mini::active : (p : MiniProof) -> Bool :=
  fun (p : MiniProof) =>
    match p : MiniProof as _ return Bool with
    | mini_proof(location, chunk, width) => #ne_u8(#and_u8(#wshr_u8(chunk, #rem_u32(location, 8u32; refl(Bool, true))), 1u8), 0u8)
    end

def[spec, opaque] mini::reconstruct : (p : MiniProof) -> (k : DIG) -> (v : DIG) -> Option(DIG) :=
  fun (p : MiniProof) (k : DIG) (v : DIG) => Some[DIG](mini::fold k v)

def[exec] mini::equal : (a : DIG) -> (b : DIG) -> Bool :=
  fun (a : DIG) (b : DIG) => array::eq U8 32usize (fun (x : U8) (y : U8) => #eq_u8(x, y)) a b

def[exec] mini::root_matches : (root : DIG) -> (c : Option(DIG)) -> Bool :=
  fun (root : DIG) (c : Option(DIG)) =>
    match c : Option(DIG) as _ return Bool with
    | None => false
    | Some(found) => mini::equal root found
    end

def[exec] mini::verify_decoded : (root : DIG) -> (p : MiniProof) -> (k : DIG) -> (v : DIG) -> Bool :=
  fun (root : DIG) (p : MiniProof) (k : DIG) (v : DIG) =>
    match (mini::active p) : Bool as _ return Bool with
    | false => false
    | true => mini::root_matches root (mini::reconstruct p k v)
    end

def[exec] mini::verify_parsed : (root : Option(DIG)) -> (proof : Option(MiniProof)) -> (k : DIG) -> (v : DIG) -> Bool :=
  fun (root : Option(DIG)) (proof : Option(MiniProof)) (k : DIG) (v : DIG) =>
    match root : Option(DIG) as _ return Bool with
    | None => false
    | Some(r) =>
      match proof : Option(MiniProof) as _ return Bool with
      | None => false
      | Some(p) => mini::verify_decoded r p k v
      end
    end

def[spec, opaque] mini::parse : (bytes : Slice U8) -> Option(Tuple2(MiniProof, Slice U8)) :=
  fun (bytes : Slice U8) => None[Tuple2(MiniProof, Slice U8)]

def[exec] mini::exact : (o : Option(Tuple2(MiniProof, Slice U8))) -> Option(MiniProof) :=
  fun (o : Option(Tuple2(MiniProof, Slice U8))) =>
    match o : Option(Tuple2(MiniProof, Slice U8)) as _ return Option(MiniProof) with
    | None => None[MiniProof]
    | Some(x) =>
      match x : Tuple2(MiniProof, Slice U8) as _ return Option(MiniProof) with
      | tuple2(d, rest) => if slice::is_empty U8 rest return Option(MiniProof) then Some[MiniProof](d) else None[MiniProof]
      end
    end

-- merkle::required_digests / reconstruct_checked / reconstruct_shape.
def[spec] mini::required : (t : MiniShape) -> (inactive : U32) -> U64 :=
  fun (t : MiniShape) (inactive : U32) =>
    match t : MiniShape as _ return U64 with
    | mini_shape(height, before, after) =>
      let folded : U32 = #min_u32(before, inactive);
      let before_count : U64 = {before_count};
      #add_u64(#cast_u32_u64(height), before_count; {p2})
    end

def[spec, opaque] mini::reconstruct_inner : (digests : Slice DIG) -> Option(DIG) :=
  fun (digests : Slice DIG) => None[DIG]

def[exec] mini::reconstruct_checked : (ok : Bool) -> (digests : Slice DIG) -> Option(DIG) :=
  fun (ok : Bool) (digests : Slice DIG) => if ok return Option(DIG) then mini::reconstruct_inner digests else None[DIG]

def[exec] mini::reconstruct_shape : (inactive : U32) -> (digests : Slice DIG) -> (target : Option(MiniShape)) -> Option(DIG) :=
  fun (inactive : U32) (digests : Slice DIG) (target : Option(MiniShape)) =>
    match target : Option(MiniShape) as _ return Option(DIG) with
    | None => None[DIG]
    | Some(t) =>
      let range : Bool = match t : MiniShape as _ return Bool with
        | mini_shape(height, before, after) => #le_u64(#cast_u32_u64(inactive), #add_u64(#cast_u32_u64(before), #cast_u32_u64(after); {p3}))
        end;
      let count : Bool = #eq_u64(#cast_usize_u64(fst(digests)), mini::required t inactive);
      mini::reconstruct_checked (match range : Bool as _ return Bool with | false => false | true => count end) digests
    end
"#
    ));
    if let Err(e) = env.load_core(&src, &mut budget()) {
        panic!("miniature QMDB definitions failed to load: {e}\n{src}");
    }
}

/// A goal builder over `binds` (with `DIG` expanded in the types).
fn base<'e>(env: &'e Env, binds: &[(&str, &str)]) -> GoalBuilder<'e> {
    let mut b = GoalBuilder::new(env);
    for (n, t) in binds {
        b = b.bind(n, &dig(t));
    }
    b
}

// ---------------------------------------------------------------------------
// bag_prefix_order, bag_prefix_partition (induction step)
// ---------------------------------------------------------------------------

#[test]
fn bag_prefix_order() {
    run(|env| {
        load_mini(env);
        let b = base(
            env,
            &[
                ("n", "Usize"),
                ("head", "DIG"),
                ("tail", "List(DIG)"),
                ("acc", "DIG"),
                (".h", "Eq(Bool, #lt_usize(n, 18446744073709551615usize), true)"),
            ],
        );
        let add = b.lin(&["h"], "Eq(Bool, #le_int(#iadd(#cast_usize_int(n), 1int), 18446744073709551615int), true)");
        let lhs = format!("mini::bag_prefix (#add_usize(n, 1usize; {add})) (Cons[DIG](head, tail)) acc");
        assert_proves(env, &b.goal(&dig(&format!("Eq(Option(DIG), {lhs}, mini::bag_prefix n tail (mini::fold acc head))"))));
        // Negative: the accumulator is folded, not kept.
        assert_fails(env, &b.goal(&dig(&format!("Eq(Option(DIG), {lhs}, mini::bag_prefix n tail acc)"))));
    });
}

#[test]
fn bag_prefix_partition_step() {
    run(|env| {
        load_mini(env);
        // xs = Cons(head, tail), k = tail.len(); the induction hypothesis
        // (the recursive `bag_prefix_partition(tail, ys, n, fold(acc, head))`
        // call) as a fact.
        let b0 = base(
            env,
            &[
                ("head", "DIG"),
                ("tail", "List(DIG)"),
                ("ys", "List(DIG)"),
                ("n", "Usize"),
                ("acc", "DIG"),
                ("k", "Usize"),
                (".hk", "Eq(Int, seq::len DIG tail, #cast_usize_int(k))"),
                (".hb", "Eq(Bool, #le_int(#iadd(#iadd(#cast_usize_int(k), 1int), #cast_usize_int(n)), 18446744073709551615int), true)"),
            ],
        );
        let p1 = b0.lin(&["hb"], "Eq(Bool, #le_int(#iadd(#cast_usize_int(k), 1int), 18446744073709551615int), true)");
        let k1 = format!("#add_usize(k, 1usize; {p1})");
        let p2 =
            b0.lin(&["hb"], &format!("Eq(Bool, #le_int(#iadd(#cast_usize_int({k1}), #cast_usize_int(n)), 18446744073709551615int), true)"));
        let p3 = b0.lin(&["hb"], "Eq(Bool, #le_int(#iadd(#cast_usize_int(k), #cast_usize_int(n)), 18446744073709551615int), true)");
        let rhs_of = |len: &str, xs: &str, acc: &str| {
            format!(
                "match mini::bag_prefix ({len}) ({xs}) ({acc}) : Option(DIG) as _ return Option(DIG) with | None => None[DIG] | Some(next) => mini::bag_prefix n ys next end"
            )
        };
        let ih = format!(
            "Eq(Option(DIG), mini::bag_prefix (#add_usize(k, n; {p3})) (seq::append DIG tail ys) (mini::fold acc head), {})",
            rhs_of("k", "tail", "mini::fold acc head")
        );
        let b = b0.clone().bind(".ih", &dig(&ih));
        let goal = format!(
            "Eq(Option(DIG), mini::bag_prefix (#add_usize({k1}, n; {p2})) (seq::append DIG (Cons[DIG](head, tail)) ys) acc, {})",
            rhs_of(&k1, "Cons[DIG](head, tail)", "acc")
        );
        assert_proves(env, &b.goal(&dig(&goal)));
        // Negative: without the induction hypothesis.
        assert_fails(env, &b0.goal(&dig(&goal)));
    });
}

// ---------------------------------------------------------------------------
// digest_equal_sound, root_matches_sound, decoded_activity, decoded_root
// ---------------------------------------------------------------------------

#[test]
fn digest_equal_sound() {
    run(|env| {
        load_mini(env);
        let b = base(env, &[("left", "DIG"), ("right", "DIG"), (".h", "Eq(Bool, mini::equal left right, true)")]);
        assert_proves(env, &b.goal(&dig("Eq(DIG, left, right)")));
    });
}

#[test]
fn root_matches_sound() {
    run(|env| {
        load_mini(env);
        let b = base(env, &[("root", "DIG"), ("candidate", "Option(DIG)"), (".h", "Eq(Bool, mini::root_matches root candidate, true)")]);
        assert_proves(env, &b.goal(&dig("Eq(Option(DIG), candidate, Some[DIG](root))")));
        // Negative: `false` does not identify the candidate.
        let b = base(env, &[("root", "DIG"), ("candidate", "Option(DIG)"), (".h", "Eq(Bool, mini::root_matches root candidate, false)")]);
        assert_fails(env, &b.goal(&dig("Eq(Option(DIG), candidate, Some[DIG](root))")));
    });
}

#[test]
fn decoded_activity_and_root() {
    run(|env| {
        load_mini(env);
        let binds = [
            ("root", "DIG"),
            ("proof", "MiniProof"),
            ("key", "DIG"),
            ("value", "DIG"),
            (".h", "Eq(Bool, mini::verify_decoded root proof key value, true)"),
        ];
        let b = base(env, &binds);
        // decoded_activity: the short-circuit `&&` fact splits.
        assert_proves(env, &b.goal("Eq(Bool, mini::active proof, true)"));
        // decoded_root: case analysis on the (opaque) reconstruction and
        // array equality soundness.
        assert_proves(env, &b.goal(&dig("Eq(Option(DIG), mini::reconstruct proof key value, Some[DIG](root))")));
    });
}

#[test]
fn decoded_root_with_a_lemma_hint() {
    run(|env| {
        load_mini(env);
        // Prove `root_matches_sound` with `auto`, install it as a lemma, and
        // use it through a `Lemma` hint (PROOF.rs: `decoded_root` calls
        // `root_matches_sound`).
        let pf = auto_proof(
            env,
            &[("root", DIG), ("candidate", &dig("Option(DIG)")), (".h", "Eq(Bool, mini::root_matches root candidate, true)")],
            &[],
            &dig("Eq(Option(DIG), candidate, Some[DIG](root))"),
        );
        let src = dig(&format!(
            "def[lemma] mini::root_matches_sound : (root : DIG) -> (candidate : Option(DIG)) -> (.h : Eq(Bool, mini::root_matches root candidate, true)) -> Eq(Option(DIG), candidate, Some[DIG](root)) :=
               fun (root : DIG) (candidate : Option(DIG)) (.h : Eq(Bool, mini::root_matches root candidate, true)) => {pf}"
        ));
        if let Err(e) = env.load_core(&src, &mut budget()) {
            panic!("lemma failed to load: {e}\n{src}");
        }
        let b = base(
            env,
            &[
                ("root", "DIG"),
                ("proof", "MiniProof"),
                ("key", "DIG"),
                ("value", "DIG"),
                (".h", "Eq(Bool, mini::verify_decoded root proof key value, true)"),
            ],
        );
        let lemma = b.parse("mini::root_matches_sound root (mini::reconstruct proof key value)");
        let b = b.hint(Hint::Lemma(lemma));
        assert_proves(env, &b.goal(&dig("Eq(Option(DIG), mini::reconstruct proof key value, Some[DIG](root))")));
    });
}

// ---------------------------------------------------------------------------
// inactive_decoded_rejected, inactive_parsed, trailing_bytes_rejected
// ---------------------------------------------------------------------------

#[test]
fn inactive_decoded_rejected() {
    run(|env| {
        load_mini(env);
        let b = base(
            env,
            &[("root", "DIG"), ("proof", "MiniProof"), ("key", "DIG"), ("value", "DIG"), (".h", "Eq(Bool, mini::active proof, false)")],
        );
        assert_proves(env, &b.goal("Eq(Bool, mini::verify_decoded root proof key value, false)"));
        // Negative: without the hypothesis.
        let b = base(env, &[("root", "DIG"), ("proof", "MiniProof"), ("key", "DIG"), ("value", "DIG")]);
        assert_fails(env, &b.goal("Eq(Bool, mini::verify_decoded root proof key value, false)"));
    });
}

#[test]
fn inactive_parsed() {
    run(|env| {
        load_mini(env);
        // Case analysis on the decoded root (PROOF.rs `inactive_parsed`).
        let b = base(
            env,
            &[
                ("root", "Option(DIG)"),
                ("proof", "MiniProof"),
                ("key", "DIG"),
                ("value", "DIG"),
                (".h", "Eq(Bool, mini::active proof, false)"),
            ],
        );
        assert_proves(env, &b.goal("Eq(Bool, mini::verify_parsed root (Some[MiniProof](proof)) key value, false)"));
    });
}

#[test]
fn trailing_bytes_rejected() {
    run(|env| {
        load_mini(env);
        // `parse(bytes) == Some((decoded, cons(head, tail)))`: the rest is a
        // nonempty slice built with its well-formedness proof.
        let b0 = base(
            env,
            &[
                ("root", "Option(DIG)"),
                ("key", "DIG"),
                ("value", "DIG"),
                ("bytes", "Slice U8"),
                ("decoded", "MiniProof"),
                ("head", "U8"),
                ("tail", "Slice U8"),
                (".ol", "Eq(Int, seq::len U8 fst(snd(tail)), #cast_usize_int(fst(tail)))"),
                (".hb", "Eq(Bool, #lt_int(#cast_usize_int(fst(tail)), ISIZE_MAX), true)"),
            ],
        );
        let p = b0.lin(&["hb"], "Eq(Bool, #le_int(#iadd(#cast_usize_int(fst(tail)), 1int), 18446744073709551615int), true)");
        let n1 = format!("#add_usize(fst(tail), 1usize; {p})");
        let l1 = "Cons[U8](head, fst(snd(tail)))";
        let q0 = b0.lin(&["ol"], &format!("Eq(Int, seq::len U8 ({l1}), #cast_usize_int({n1}))"));
        let q1 = b0.lin(&["hb"], &format!("Eq(Bool, #le_int(#cast_usize_int({n1}), ISIZE_MAX), true)"));
        let rest = format!("slice::mk U8 ({n1}) ({l1}) .pair(SliceOk U8 ({n1}) ({l1}), {q0}, {q1})");
        let b = b0.bind(".hp", &format!("Eq(Option(Tuple2(MiniProof, Slice U8)), mini::parse bytes, Some[Tuple2(MiniProof, Slice U8)](tuple2[MiniProof, Slice U8](decoded, {rest})))"));
        assert_proves(env, &b.goal("Eq(Bool, mini::verify_parsed root (mini::exact (mini::parse bytes)) key value, false)"));
    });
}

#[test]
fn exhausted_rest_slice() {
    run(|env| {
        load_mini(env);
        // verify_acceptance's `match root_rest { [_, ..] => .., [] => .. }`:
        // an accepted `exact` means the rest slice is empty, i.e. `&[]`.
        let b = base(
            env,
            &[
                ("d", "MiniProof"),
                ("e", "MiniProof"),
                ("rest", "Slice U8"),
                (
                    ".h",
                    "Eq(Option(MiniProof), mini::exact (Some[Tuple2(MiniProof, Slice U8)](tuple2[MiniProof, Slice U8](d, rest))), Some[MiniProof](e))",
                ),
            ],
        );
        assert_proves(env, &b.goal("Eq(Bool, slice::is_empty U8 rest, true)"));
        assert_proves(env, &b.goal("Eq(Slice U8, rest, slice::empty U8)"));
        assert_proves(env, &b.goal("Eq(MiniProof, d, e)"));
    });
}

// ---------------------------------------------------------------------------
// reconstruction_gate, merkle_wrong_count_rejected, merkle_digest_count
// ---------------------------------------------------------------------------

#[test]
fn reconstruction_gate() {
    run(|env| {
        load_mini(env);
        let b = base(
            env,
            &[
                ("ok", "Bool"),
                ("digests", "Slice DIG"),
                ("root", "DIG"),
                (".h", "Eq(Option(DIG), mini::reconstruct_checked ok digests, Some[DIG](root))"),
            ],
        );
        assert_proves(env, &b.goal("Eq(Bool, ok, true)"));
    });
}

#[test]
fn merkle_wrong_count_rejected() {
    run(|env| {
        load_mini(env);
        let b = base(
            env,
            &[
                ("target", "MiniShape"),
                ("inactive", "U32"),
                ("digests", "Slice DIG"),
                (".h", "Eq(Bool, #eq_u64(#cast_usize_u64(fst(digests)), mini::required target inactive), false)"),
            ],
        );
        assert_proves(env, &b.goal(&dig("Eq(Option(DIG), mini::reconstruct_shape inactive digests (Some[MiniShape](target)), None[DIG])")));
        // Negative: a matching count is not rejected by this argument.
        let b = base(env, &[("target", "MiniShape"), ("inactive", "U32"), ("digests", "Slice DIG")]);
        assert_fails(env, &b.goal(&dig("Eq(Option(DIG), mini::reconstruct_shape inactive digests (Some[MiniShape](target)), None[DIG])")));
    });
}

#[test]
fn merkle_digest_count() {
    run(|env| {
        load_mini(env);
        let b = base(
            env,
            &[
                ("target", "Option(MiniShape)"),
                ("inactive", "U32"),
                ("digests", "Slice DIG"),
                ("root", "DIG"),
                (".h", "Eq(Option(DIG), mini::reconstruct_shape inactive digests target, Some[DIG](root))"),
            ],
        );
        let shape_count = "Exists MiniShape (fun (sel : MiniShape) => And (Eq(Option(MiniShape), target, Some[MiniShape](sel))) (Eq(U64, #cast_usize_u64(fst(digests)), mini::required sel inactive)))";
        assert_proves(env, &b.goal(shape_count));
    });
}
