//! The prelude (DESIGN.md §6): it loads and checks, its definitions compute
//! with Rust's meaning on concrete data, and its lemmas are usable in proofs.

mod common;

use common::*;

fn list(xs: &[u64], w: &str) -> String {
    let t = w.to_uppercase();
    xs.iter().rev().fold(format!("Nil[{t}]"), |acc, x| format!("Cons[{t}]({x}{w}, {acc})"))
}

fn array(xs: &[u64], w: &str) -> String {
    let t = w.to_uppercase();
    format!("pair(Array {t} {n}usize, {l}, refl(Int, {n}int))", n = xs.len(), l = list(xs, w))
}

fn slice(xs: &[u64], w: &str) -> String {
    let t = w.to_uppercase();
    format!("array::as_slice {t} {n}usize ({a}) .refl(Bool, true)", n = xs.len(), a = array(xs, w))
}

#[test]
fn prelude_loads_and_every_item_checked() {
    let env = prelude();
    for name in ["Unit", "Option", "Either", "Tuple2", "Tuple12", "List", "Bool", "Empty"] {
        assert!(env.lookup_ind(name).is_some(), "{name}");
    }
    for name in [
        "Not",
        "And",
        "Or",
        "Iff",
        "Exists",
        "seq::len",
        "seq::index",
        "seq::update",
        "seq::take",
        "seq::drop",
        "seq::append",
        "seq::rev",
        "seq::replicate",
        "seq::eq",
        "seq::chunks",
        "SliceOk",
        "Slice",
        "Array",
        "slice::len",
        "slice::is_empty",
        "slice::get",
        "slice::index",
        "slice::range",
        "slice::split_at",
        "slice::split_at_checked",
        "slice::split_first",
        "slice::split_first_chunk",
        "slice::first_chunk",
        "slice::as_chunks",
        "array::index",
        "array::set",
        "array::as_slice",
        "array::eq",
        "seq::split_first_chunk",
        "seq::as_chunks",
        "slice::first",
        "slice::last",
        "slice::split_last",
        "u32::from_le_bytes",
        "u64::from_be_bytes",
        "u16::to_be_bytes",
        "u32::rotate_right",
        "u8::count_ones",
        "usize::checked_add",
        "u64::saturating_sub",
        "u32::min",
        "seq::len_append",
        "seq::len_take",
        "seq::len_drop",
    ] {
        assert!(env.lookup_global(name).is_some(), "{name}");
    }
}

#[test]
fn slice_methods_compute() {
    let env = prelude();
    let s = slice(&[10, 20, 30, 40, 50], "u8");
    assert_eq!(norm(&env, &format!("slice::len U8 ({s})")), "5usize");
    assert_eq!(norm(&env, &format!("slice::is_empty U8 ({s})")), "false");
    assert_eq!(norm(&env, &format!("slice::get U8 ({s}) 3usize")), "Some[U8](40u8)");
    assert_eq!(norm(&env, &format!("slice::get U8 ({s}) 5usize")), "None[U8]");
    assert_eq!(norm(&env, &format!("slice::index U8 ({s}) 0usize .refl(Bool, true)")), "10u8");
    let r = format!("slice::range U8 ({s}) 1usize 4usize .refl(Bool, true) .refl(Bool, true)");
    assert_eq!(norm(&env, &format!("slice::len U8 ({r})")), "3usize");
    assert_eq!(norm(&env, &format!("slice::list U8 ({r})")), list(&[20, 30, 40], "u8"));
    let sp = format!("slice::split_at U8 ({s}) 2usize .refl(Bool, true)");
    assert_eq!(
        norm(&env, &format!("match {sp} : Tuple2(Slice U8, Slice U8) as _ return List(U8) with | tuple2(a, b) => slice::list U8 b end")),
        list(&[30, 40, 50], "u8")
    );
    assert_eq!(norm(&env, &format!("option::is_some (Tuple2(Slice U8, Slice U8)) (slice::split_at_checked U8 ({s}) 6usize)")), "false");
    assert_eq!(norm(&env, &format!("option::is_some (Tuple2(Slice U8, Slice U8)) (slice::split_at_checked U8 ({s}) 5usize)")), "true");
    // split_first, first_chunk, split_first_chunk.
    let sf = format!("slice::split_first U8 ({s})");
    assert_eq!(
        norm(
            &env,
            &format!(
                "match {sf} : Option(Tuple2(U8, Slice U8)) as _ return U8 with | None => 0u8 | Some(p) => match p : Tuple2(U8, Slice U8) as _ return U8 with | tuple2(h, t) => h end end"
            )
        ),
        "10u8"
    );
    let fc = format!("slice::first_chunk U8 ({s}) 2usize");
    assert_eq!(
        norm(&env, &format!("match {fc} : Option(Array U8 2usize) as _ return List(U8) with | None => Nil[U8] | Some(a) => fst(a) end")),
        list(&[10, 20], "u8")
    );
    let sfc = format!("slice::split_first_chunk U8 ({s}) 4usize");
    assert_eq!(
        norm(
            &env,
            &format!(
                "match {sfc} : Option(Tuple2(Array U8 4usize, Slice U8)) as _ return Usize with | None => 99usize | Some(p) => match p : Tuple2(Array U8 4usize, Slice U8) as _ return Usize with | tuple2(a, rest) => slice::len U8 rest end end"
            )
        ),
        "1usize"
    );
    // as_chunks: 5 bytes in chunks of 2 → 2 chunks and a remainder of 1.
    let ac = format!("slice::as_chunks U8 ({s}) 2usize .refl(Bool, true)");
    assert_eq!(
        norm(
            &env,
            &format!(
                "match {ac} : Tuple2(Slice (Array U8 2usize), Slice U8) as _ return Usize with | tuple2(c, r) => slice::len (Array U8 2usize) c end"
            )
        ),
        "2usize"
    );
    assert_eq!(
        norm(
            &env,
            &format!(
                "match {ac} : Tuple2(Slice (Array U8 2usize), Slice U8) as _ return List(U8) with | tuple2(c, r) => slice::list U8 r end"
            )
        ),
        list(&[50], "u8")
    );
    assert_eq!(norm(&env, &format!("slice::first U8 ({s})")), "Some[U8](10u8)");
    assert_eq!(norm(&env, &format!("slice::last U8 ({s})")), "Some[U8](50u8)");
    let sl = format!("slice::split_last U8 ({s})");
    assert_eq!(
        norm(
            &env,
            &format!(
                "match {sl} : Option(Tuple2(U8, Slice U8)) as _ return Usize with | None => 0usize | Some(p) => match p : Tuple2(U8, Slice U8) as _ return Usize with | tuple2(h, t) => slice::len U8 t end end"
            )
        ),
        "4usize"
    );
    assert_eq!(
        norm(&env, &format!("option::is_some (Tuple2(List(U8), List(U8))) (seq::split_first_chunk U8 6int ({}))", list(&[1, 2, 3], "u8"))),
        "false"
    );
    // The empty slice.
    let e = slice(&[], "u8");
    assert_eq!(norm(&env, &format!("slice::is_empty U8 ({e})")), "true");
    assert_eq!(norm(&env, &format!("slice::last U8 ({e})")), "None[U8]");
}

#[test]
fn array_methods_compute() {
    let env = prelude();
    let a = array(&[1, 2, 3, 4], "u32");
    assert_eq!(norm(&env, &format!("array::index U32 4usize ({a}) 2usize .refl(Bool, true)")), "3u32");
    let set = format!("array::set U32 4usize ({a}) 1usize 9u32 .refl(Bool, true)");
    assert_eq!(norm(&env, &format!("fst({set})")), list(&[1, 9, 3, 4], "u32"));
    assert_eq!(norm(&env, &format!("fst(array::rev U32 4usize ({a}))")), list(&[4, 3, 2, 1], "u32"));
    let eq = "fun (x : U32) (y : U32) => #eq_u32(x, y)";
    assert_eq!(norm(&env, &format!("array::eq U32 4usize ({eq}) ({a}) ({a})")), "true");
    assert_eq!(norm(&env, &format!("array::eq U32 4usize ({eq}) ({a}) ({set})")), "false");
    assert_eq!(norm(&env, "fst(array::repeat U8 3usize 7u8 .refl(Int, 3int))"), list(&[7, 7, 7], "u8"));
    // [v; N] needs the length proof, which computes for a literal N.
    assert!(check(&env, "array::repeat U8 3usize 7u8 .refl(Int, 3int)", "Array U8 3usize").is_ok());
    assert!(check(&env, "array::repeat U8 3usize 7u8 .refl(Int, 4int)", "Array U8 3usize").is_err());
}

#[test]
fn integer_methods_compute() {
    let env = prelude();
    assert_eq!(norm(&env, "u8::checked_add 200u8 55u8"), "Some[U8](255u8)");
    assert_eq!(norm(&env, "u8::checked_add 200u8 56u8"), "None[U8]");
    assert_eq!(norm(&env, "u8::checked_sub 3u8 4u8"), "None[U8]");
    assert_eq!(norm(&env, "u16::checked_mul 256u16 255u16"), "Some[U16](65280u16)");
    assert_eq!(norm(&env, "u32::checked_div 7u32 0u32"), "None[U32]");
    assert_eq!(norm(&env, "u32::checked_rem 7u32 3u32"), "Some[U32](1u32)");
    assert_eq!(norm(&env, "u32::rotate_right 1u32 1u32"), "2147483648u32");
    assert_eq!(norm(&env, "u64::rotate_left 1u64 65u32"), "2u64");
    assert_eq!(norm(&env, "u8::count_ones 255u8"), "8u32");
    assert_eq!(norm(&env, "u64::saturating_sub 3u64 5u64"), "0u64");
    assert_eq!(norm(&env, "usize::saturating_add 18446744073709551615usize 1usize"), "18446744073709551615usize");
    assert_eq!(norm(&env, "u32::min 3u32 5u32"), "3u32");
    assert_eq!(norm(&env, "u8::abs_diff 3u8 250u8"), "247u8");
    assert_eq!(norm(&env, "u8::is_power_of_two 64u8"), "true");
    assert_eq!(norm(&env, "u32::MAX"), "4294967295u32");
    assert_eq!(norm(&env, "bool::as_u8 true"), "1u8");
    assert_eq!(norm(&env, "u32::swap_bytes 305419896u32"), "2018915346u32");
}

#[test]
fn byte_conversions_compute() {
    let env = prelude();
    assert_eq!(norm(&env, &format!("u32::from_le_bytes ({})", array(&[0x78, 0x56, 0x34, 0x12], "u8"))), "305419896u32");
    assert_eq!(norm(&env, &format!("u32::from_be_bytes ({})", array(&[0x12, 0x34, 0x56, 0x78], "u8"))), "305419896u32");
    assert_eq!(norm(&env, "fst(u16::to_be_bytes 4660u16)"), list(&[0x12, 0x34], "u8"));
    assert_eq!(norm(&env, "fst(u64::to_le_bytes 1u64)"), list(&[1, 0, 0, 0, 0, 0, 0, 0], "u8"));
}

#[test]
fn lemmas_are_usable() {
    let mut env = prelude();
    load(&mut env, r#"
-- len (xs ++ ys ++ zs) by two uses of len_append and linarith.
def[lemma] len_append3 : (xs : List(U8)) -> (ys : List(U8)) -> (zs : List(U8))
    -> Eq(Int, seq::len U8 (seq::append U8 xs (seq::append U8 ys zs)), #iadd(#iadd(seq::len U8 xs, seq::len U8 ys), seq::len U8 zs)) :=
  fun (xs : List(U8)) (ys : List(U8)) (zs : List(U8)) =>
    linarith([seq::len_append U8 xs (seq::append U8 ys zs)
                : Eq(Int, seq::len U8 (seq::append U8 xs (seq::append U8 ys zs)), #iadd(seq::len U8 xs, seq::len U8 (seq::append U8 ys zs))),
              seq::len_append U8 ys zs : Eq(Int, seq::len U8 (seq::append U8 ys zs), #iadd(seq::len U8 ys, seq::len U8 zs))];
             Eq(Int, seq::len U8 (seq::append U8 xs (seq::append U8 ys zs)), #iadd(#iadd(seq::len U8 xs, seq::len U8 ys), seq::len U8 zs));
             [-1, -1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0])
-- array eta for N = 2 is refl (fixed-length array eta, DESIGN.md §5.9).
def[lemma] array_eta_2 : (a : Array U16 2usize)
    -> Eq(Array U16 2usize, a, pair(Array U16 2usize,
         Cons[U16](array::index U16 2usize a 0usize .refl(Bool, true), Cons[U16](array::index U16 2usize a 1usize .refl(Bool, true), Nil[U16])),
         refl(Int, 2int))) :=
  fun (a : Array U16 2usize) => refl(Array U16 2usize, a)
-- A slice's length is its list's length (promotion of an irrelevant fact).
def[lemma] slice_len_list : (s : Slice U8) -> Eq(Int, seq::len U8 (slice::list U8 s), #cast_usize_int(slice::len U8 s)) :=
  fun (s : Slice U8) => slice::ok_len U8 s
-- Induction: reversing twice preserves length.
def[lemma] len_rev_rev : (xs : List(U8)) -> Eq(Int, seq::len U8 (seq::rev U8 (seq::rev U8 xs)), seq::len U8 xs) :=
  fun (xs : List(U8)) =>
    eq::trans Int (seq::len U8 (seq::rev U8 (seq::rev U8 xs))) (seq::len U8 (seq::rev U8 xs)) (seq::len U8 xs)
      (seq::len_rev U8 (seq::rev U8 xs)) (seq::len_rev U8 xs)
"#).unwrap_or_else(|e| panic!("{e}"));
}
