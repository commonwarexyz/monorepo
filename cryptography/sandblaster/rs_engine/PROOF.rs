//! The proofs of LAWS.rs: per vector by the lane closer, per chunk by the
//! loop body's contract on one chunk, then the slice by the loop's.
use sandblaster::prelude::*;
use core::arch::aarch64::*;
#[allow(unused_imports)]
use crate::reed_solomon::engine::engine_neon::Neon;
#[allow(unused_imports)]
use crate::reed_solomon::engine::tables::Multiply128lutT;
#[allow(unused_imports)]
use crate::reed_solomon::engine::engine_scalar::Scalar;

/// A chunk multiplied, opaque: the loop's facts name a chunk's product
/// whole (`chunk_mul_is` says what it is).
#[spec]
#[opaque]
#[example(chunk_mul(crate::laws::LUT_ONE, [7u8; 64]) == [7u8; 64])]
pub fn chunk_mul(lut: Multiply128lutT, c: [u8; 64]) -> [u8; 64] {
    crate::laws::mul_chunk(lut, c)
}

#[lemma]
fn chunk_mul_is(lut: Multiply128lutT, c: [u8; 64]) {
    ensures(chunk_mul(lut, c) == crate::laws::mul_chunk(lut, c));
    unfold(chunk_mul);
    follows();
}

/// `mul_neon`'s loop body on one chunk: its four quarters loaded, multiplied
/// by `mul_128` and stored back multiply each of its elements (the lane
/// closer, through `mul_128`'s lanes).
#[lift_attach(crate::reed_solomon::engine::engine_neon::Neon::mul_neon, loop_nr = 0, element)]
fn mul_neon_chunk() {
    ensures(|ret: [u8; 64]| ret == crate::proof::chunk_mul(*lut, chunk));
    at_start! {
        crate::proof::chunk_mul_is(*lut, chunk);
    }
}

/// `x` with every chunk from `i` on multiplied, one chunk at a time as the
/// loop multiplies them.
#[spec]
#[decreases((x.len() as Int) - (i as Int))]
#[example(muls_from(crate::laws::LUT_ONE, seq![[7u8; 64], [9u8; 64]], 0) == seq![[7u8; 64], [9u8; 64]])]
pub fn muls_from(lut: Multiply128lutT, x: Seq<[u8; 64]>, i: Nat) -> Seq<[u8; 64]> {
    if i < x.len() { muls_from(lut, x.update(i, chunk_mul(lut, x[i])), i + 1) } else { x }
}

/// One chunk: `muls_from` from `i` is `muls_from` from `i + 1` of the slice
/// with chunk `i` multiplied (its definition, one step).
#[lemma]
fn muls_from_step(lut: Multiply128lutT, x: Seq<[u8; 64]>, i: Nat) {
    ensures(implies(i < x.len(), muls_from(lut, x, i) == muls_from(lut, x.update(i, chunk_mul(lut, x[i])), i + 1)));
    follows();
}

/// The end: `muls_from` from the length on is the slice itself.
#[lemma]
fn muls_from_end(lut: Multiply128lutT, x: Seq<[u8; 64]>, i: Nat) {
    ensures(implies(x.len() <= i, muls_from(lut, x, i) == x));
    follows();
}

/// `muls_from` keeps the length.
#[lemma]
#[decreases((x.len() as Int) - (i as Int))]
fn muls_from_len(lut: Multiply128lutT, x: Seq<[u8; 64]>, i: Nat) {
    ensures(muls_from(lut, x, i).len() == x.len());
    muls_from_step(lut, x, i);
    muls_from_end(lut, x, i);
    if i < x.len() {
        muls_from_len(lut, x.update(i, chunk_mul(lut, x[i])), i + 1);
        follows();
    } else {
        follows();
    }
}

/// A slice's chunks, as a sequence.
#[spec]
#[example(chunks_of(seq![[7u8; 64]]) == seq![[7u8; 64]])]
pub fn chunks_of(s: Seq<[u8; 64]>) -> Seq<[u8; 64]> {
    s
}

/// The loop's step as the iterator takes it: below the length, `muls_from`
/// from `iter` is `muls_from` from the iterator's next index, of the slice
/// with chunk `iter` multiplied.
#[lemma]
fn loop_step(lut: Multiply128lutT, x: &[[u8; 64]], iter: usize) {
    ensures(implies(iter < x.len(), muls_from(lut, x, iter as Nat) == muls_from(lut, chunks_of(x).update(iter as Nat, chunk_mul(lut, x[iter])), iter.wrapping_add(1usize) as Nat)));
    muls_from_step(lut, x, iter as Nat);
    follows();
}

/// The loop's end: at the length, `muls_from` is the slice itself.
#[lemma]
fn loop_end(lut: Multiply128lutT, x: &[[u8; 64]], iter: usize) {
    ensures(implies((iter < x.len()) == false, muls_from(lut, x, iter as Nat) == chunks_of(x)));
    muls_from_end(lut, x, iter as Nat);
    follows();
}

/// `mul_neon`'s loop from chunk `iter` on: the chunks from `iter` on
/// multiplied, one at a time.
#[lift_attach(crate::reed_solomon::engine::engine_neon::Neon::mul_neon, loop_nr = 0)]
fn mul_neon_loop() {
    invariant(iter <= x.len());
    decreases((x.len() as Int) - (iter as Int));
    ensures(|ret: &[[u8; 64]]| ret == crate::proof::muls_from(*lut, x, iter as Nat));
    at_start! {
        crate::proof::loop_step(*lut, x, iter);
        crate::proof::loop_end(*lut, x, iter);
    }
}

/// `mul_neon`'s summary: every chunk multiplied by the table row of `log_m`.
#[lift_attach(crate::reed_solomon::engine::engine_neon::Neon::mul_neon)]
fn mul_neon_summary() {
    ensures(|ret: &[[u8; 64]]| ret == crate::proof::muls_from(self.mul128[log_m as usize], x, 0));
}

/// Every chunk multiplied, as `mul_all` with the chunk product opaque.
#[spec]
#[example(muls(crate::laws::LUT_ONE, seq![[7u8; 64]]) == seq![[7u8; 64]])]
pub fn muls(lut: Multiply128lutT, s: Seq<[u8; 64]>) -> Seq<[u8; 64]> {
    match s {
        [] => Seq::empty(),
        [c, rest @ ..] => Seq::cons(chunk_mul(lut, c), muls(lut, rest)),
    }
}

/// `muls` is `mul_all` (chunk by chunk).
#[lemma]
#[induction(s)]
fn muls_is_mul_all(lut: Multiply128lutT, s: Seq<[u8; 64]>) {
    ensures(muls(lut, s) == crate::laws::mul_all(lut, s));
    match s {
        [] => follows(),
        [c, rest @ ..] => {
            ih(lut, rest);
            unfold(muls);
            unfold(crate::laws::mul_all);
            rewrite(chunk_mul_is(lut, c));
            rewrite(muls(lut, rest) == crate::laws::mul_all(lut, rest));
            follows();
        }
    }
}

/// Updating element `i` is cutting the sequence there.
#[lemma]
#[induction(x)]
fn update_split(x: Seq<[u8; 64]>, i: Nat, v: [u8; 64]) {
    requires(i < x.len());
    ensures(x.update(i, v) == seq![..x.take(i), v, ..x.skip(i + 1)]);
    match x {
        [] => follows(),
        [c, rest @ ..] => {
            if i == 0 {
                assert(i == 0);
                sandblaster::lemmas::seq::update_neg(rest, -1, v);
                follows();
            } else {
                ih(rest, i - 1, v);
                crate::stdlib::seqs::take_cons(c, rest, i);
                crate::stdlib::seqs::skip_cons(c, rest, i + 1);
                follows();
            }
        }
    }
}

/// The rest from `i` is element `i` and the rest from `i + 1`.
#[lemma]
#[induction(x)]
fn skip_at(x: Seq<[u8; 64]>, i: Nat) {
    requires(i < x.len());
    ensures(x.skip(i) == seq![x[i], ..x.skip(i + 1)]);
    match x {
        [] => follows(),
        [c, rest @ ..] => {
            if i == 0 {
                assert(i == 0);
                follows();
            } else {
                ih(rest, i - 1);
                crate::stdlib::seqs::skip_cons(c, rest, i);
                crate::stdlib::seqs::skip_cons(c, rest, i + 1);
                follows();
            }
        }
    }
}

/// `muls_from` from `i`: the chunks before `i` as they are, the rest
/// multiplied.
#[lemma]
#[decreases((x.len() as Int) - (i as Int))]
fn muls_from_split(lut: Multiply128lutT, x: Seq<[u8; 64]>, i: Nat) {
    requires(i <= x.len());
    ensures(muls_from(lut, x, i) == seq![..x.take(i), ..muls(lut, x.skip(i))]);
    muls_from_step(lut, x, i);
    muls_from_end(lut, x, i);
    if i < x.len() {
        let v = chunk_mul(lut, x[i]);
        let y = x.update(i, v);
        muls_from_split(lut, y, i + 1);
        update_split(x, i, v);
        crate::stdlib::seqs::append_snoc(x.take(i), v, x.skip(i + 1));
        assert(y == seq![..seq![..x.take(i), v], ..x.skip(i + 1)]);
        crate::stdlib::seqs::take_len_le(x, i as Int);
        crate::stdlib::seqs::len_app(x.take(i), seq![v]);
        crate::stdlib::seqs::take_skip_at(seq![..x.take(i), v], x.skip(i + 1), i + 1);
        assert(y.take(i + 1) == seq![..x.take(i), v]);
        assert(y.skip(i + 1) == x.skip(i + 1));
        assert(muls_from(lut, x, i) == seq![..seq![..x.take(i), v], ..muls(lut, x.skip(i + 1))]);
        crate::stdlib::seqs::append_snoc(x.take(i), v, muls(lut, x.skip(i + 1)));
        skip_at(x, i);
        assert(muls(lut, x.skip(i)) == seq![v, ..muls(lut, x.skip(i + 1))]);
        follows();
    } else {
        crate::stdlib::seqs::take_all(x, i);
        crate::stdlib::seqs::skip_len(x, i);
        crate::stdlib::seqs::len_zero(x.skip(i));
        follows();
    }
}

/// From the start: every chunk multiplied.
#[lemma]
fn muls_from_zero(lut: Multiply128lutT, x: Seq<[u8; 64]>) {
    ensures(muls_from(lut, x, 0) == crate::laws::mul_all(lut, x));
    muls_from_split(lut, x, 0);
    crate::stdlib::seqs::take_zero(x);
    crate::stdlib::seqs::skip_zero(x);
    muls_is_mul_all(lut, x);
    follows();
}

#[proof]
fn neon_mul_multiplies_every_chunk(n: Neon, x: &[[u8; 64]], log_m: u16) {
    unfold(Neon::mul);
    muls_from_zero(n.mul128[log_m as usize], x);
    follows();
}

/// `muladd_128` is opaque to its callers (the transforms, host code): its
/// contract is what they get.
#[lift_attach(crate::reed_solomon::engine::engine_neon::Neon::muladd_128)]
fn muladd_128_summary() {
    opaque();
}

/// `muladd_128` is pinned by its contract.
#[proof(complete = crate::reed_solomon::engine::engine_neon::Neon::muladd_128)]
fn muladd_128_determined(x_lo: uint8x16_t, x_hi: uint8x16_t, y_lo: uint8x16_t, y_hi: uint8x16_t, lut: &Multiply128lutT) {
    use_hyp(0, x_lo, x_hi, y_lo, y_hi, lut);
    use_real(0, x_lo, x_hi, y_lo, y_hi, lut);
    follows();
}

// ---------------------------------------------------------------------------
// The scalar engine
// ---------------------------------------------------------------------------

/// Element `i` of chunk `c` multiplied in place (its low byte at `i`, its
/// high byte at `32 + i`), as one iteration of `Scalar::mul`'s inner loop.
#[spec]
#[example(elem16_at(crate::laws::LUT16_ONE, [7u8; 64], 3usize) == [7u8; 64])]
pub fn elem16_at(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) -> [u8; 64] {
    if i < 32usize {
        let p = crate::laws::mul16(lut16, c[i], c[32usize.wrapping_add(i)]);
        let mut d = c;
        d[i] = p as u8;
        d[32usize.wrapping_add(i)] = (p >> 8u32) as u8;
        d
    } else {
        c
    }
}

/// The same, opaque: the loops' facts name an element's product whole
/// (`elem16_is` says what it is).
#[spec]
#[opaque]
#[example(elem16(crate::laws::LUT16_ONE, [7u8; 64], 3usize) == [7u8; 64])]
pub fn elem16(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) -> [u8; 64] {
    elem16_at(lut16, c, i)
}

#[lemma]
fn elem16_is(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) {
    ensures(elem16(lut16, c, i) == elem16_at(lut16, c, i));
    unfold(elem16);
    follows();
}

/// Chunk `c` with its elements from `i` on multiplied, one at a time as the
/// inner loop multiplies them.
#[spec]
#[decreases(32 - (i as Int))]
#[example(elems16_from(crate::laws::LUT16_ONE, [7u8; 64], 30usize) == [7u8; 64])]
pub fn elems16_from(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) -> [u8; 64] {
    if i < 32usize { elems16_from(lut16, elem16(lut16, c, i), i + 1usize) } else { c }
}

/// The same with the element's product written out, for evaluation.
#[spec]
#[decreases(32 - (i as Int))]
#[example(elems16_eval(crate::laws::LUT16_ONE, [7u8; 64], 30usize) == [7u8; 64])]
pub fn elems16_eval(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) -> [u8; 64] {
    if i < 32usize { elems16_eval(lut16, elem16_at(lut16, c, i), i + 1usize) } else { c }
}

/// One element: from `i` is from `i + 1` of the chunk with element `i`
/// multiplied (the definition, one step).
#[lemma]
fn elems16_step(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) {
    ensures(implies(i < 32usize, elems16_from(lut16, c, i) == elems16_from(lut16, elem16(lut16, c, i), i + 1usize)));
    unfold(elems16_from);
    follows();
}

/// The same step, written out.
#[lemma]
fn elems16_eval_step(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) {
    ensures(implies(i < 32usize, elems16_eval(lut16, c, i) == elems16_eval(lut16, elem16_at(lut16, c, i), i + 1usize)));
    unfold(elems16_eval);
    follows();
}

/// The end: from the last element on, nothing is left to multiply.
#[lemma]
fn elems16_end(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) {
    ensures(implies(32usize <= i, elems16_from(lut16, c, i) == c));
    follows();
}

#[lemma]
fn elems16_eval_end(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) {
    ensures(implies(32usize <= i, elems16_eval(lut16, c, i) == c));
    follows();
}

/// The two are the same.
#[lemma]
#[decreases(32 - (i as Int))]
fn elems16_is_eval(lut16: [[u16; 16]; 4], c: [u8; 64], i: usize) {
    ensures(elems16_from(lut16, c, i) == elems16_eval(lut16, c, i));
    if i < 32usize {
        let h1 = elems16_step(lut16, c, i);
        let h2 = elems16_eval_step(lut16, c, i);
        assert(elems16_from(lut16, c, i) == elems16_from(lut16, elem16(lut16, c, i), i + 1usize));
        assert(elems16_eval(lut16, c, i) == elems16_eval(lut16, elem16_at(lut16, c, i), i + 1usize));
        elem16_is(lut16, c, i);
        elems16_is_eval(lut16, elem16(lut16, c, i), i + 1usize);
        by_arithmetic();
    } else {
        elems16_end(lut16, c, i);
        elems16_eval_end(lut16, c, i);
        assert(elems16_from(lut16, c, i) == c);
        assert(elems16_eval(lut16, c, i) == c);
        by_arithmetic();
    }
}

/// From the first element: every element multiplied.
#[lemma]
fn elems16_eval_zero(lut16: [[u16; 16]; 4], c: [u8; 64]) {
    ensures(elems16_eval(lut16, c, 0usize) == crate::laws::mul_chunk16(lut16, c));
    by_computation();
}

#[lemma]
fn elems16_from_zero(lut16: [[u16; 16]; 4], c: [u8; 64]) {
    ensures(elems16_from(lut16, c, 0usize) == crate::laws::mul_chunk16(lut16, c));
    elems16_is_eval(lut16, c, 0usize);
    elems16_eval_zero(lut16, c);
    follows();
}

/// Writing element `i` back unchanged leaves the sequence as it is.
#[lemma]
#[induction(x)]
fn update_at_self(x: Seq<[u8; 64]>, i: Nat) {
    requires(i < x.len());
    ensures(x.update(i, x[i]) == x);
    match x {
        [] => follows(),
        [c, rest @ ..] => {
            if i == 0 {
                assert(i == 0);
                sandblaster::lemmas::seq::update_neg(rest, -1, c);
                follows();
            } else {
                ih(rest, i - 1);
                follows();
            }
        }
    }
}

/// `Scalar::mul`'s inner loop from element `iter.start` of chunk
/// `x_chunk_index` on: that chunk with those elements multiplied.
#[lift_attach(crate::reed_solomon::engine::engine_scalar::Scalar::mul, loop_nr = 1)]
fn scalar_mul_elements() {
    invariant(iter.end == 32usize);
    invariant(iter.start <= 32usize);
    invariant(x_chunk_index < x.len());
    decreases((iter.end as Int) - (iter.start as Int));
    ensures(|ret: &[[u8; 64]]| ret == crate::proof::chunks_of(x).update(x_chunk_index as Nat, crate::proof::elems16_from(*lut, x[x_chunk_index], iter.start)));
    at_start! {
        crate::proof::elems16_step(*lut, x[x_chunk_index], iter.start);
        crate::proof::elems16_end(*lut, x[x_chunk_index], iter.start);
        crate::proof::update_at_self(x, x_chunk_index as Nat);
    }
}

/// One iteration of `Scalar::mul`'s inner loop, on its chunk: element `i`
/// multiplied in place.
#[lift_attach(crate::reed_solomon::engine::engine_scalar::Scalar::mul, loop_nr = 1, element)]
fn scalar_mul_element() {
    requires(i < 32usize);
    ensures(|ret: [u8; 64]| ret == crate::proof::elem16(*lut, x_chunk, i));
    at_start! {
        crate::proof::elem16_is(*lut, x_chunk, i);
    }
}

/// A chunk multiplied with Scalar's row, opaque: the loop's facts name a
/// chunk's product whole (`chunk_mul16_is` says what it is).
#[spec]
#[opaque]
#[example(chunk_mul16(crate::laws::LUT16_ONE, [7u8; 64]) == [7u8; 64])]
pub fn chunk_mul16(lut16: [[u16; 16]; 4], c: [u8; 64]) -> [u8; 64] {
    crate::laws::mul_chunk16(lut16, c)
}

#[lemma]
fn chunk_mul16_is(lut16: [[u16; 16]; 4], c: [u8; 64]) {
    ensures(chunk_mul16(lut16, c) == crate::laws::mul_chunk16(lut16, c));
    unfold(chunk_mul16);
    follows();
}

/// `x` with every chunk from `i` on multiplied with Scalar's row, one chunk
/// at a time as the loop multiplies them.
#[spec]
#[decreases((x.len() as Int) - (i as Int))]
#[example(muls16_from(crate::laws::LUT16_ONE, seq![[7u8; 64], [9u8; 64]], 0) == seq![[7u8; 64], [9u8; 64]])]
pub fn muls16_from(lut16: [[u16; 16]; 4], x: Seq<[u8; 64]>, i: Nat) -> Seq<[u8; 64]> {
    if i < x.len() { muls16_from(lut16, x.update(i, chunk_mul16(lut16, x[i])), i + 1) } else { x }
}

#[lemma]
fn muls16_from_step(lut16: [[u16; 16]; 4], x: Seq<[u8; 64]>, i: Nat) {
    ensures(implies(i < x.len(), muls16_from(lut16, x, i) == muls16_from(lut16, x.update(i, chunk_mul16(lut16, x[i])), i + 1)));
    follows();
}

#[lemma]
fn muls16_from_end(lut16: [[u16; 16]; 4], x: Seq<[u8; 64]>, i: Nat) {
    ensures(implies(x.len() <= i, muls16_from(lut16, x, i) == x));
    follows();
}

/// The outer loop's step as the iterator takes it: below the length,
/// `muls16_from` from `iter` is `muls16_from` from the iterator's next
/// index, of the slice with chunk `iter` multiplied element by element (the
/// inner loop's result).
#[lemma]
fn loop16_step(lut16: [[u16; 16]; 4], x: &[[u8; 64]], iter: usize) {
    ensures(implies(iter < x.len(), muls16_from(lut16, x, iter as Nat) == muls16_from(lut16, chunks_of(x).update(iter as Nat, elems16_from(lut16, x[iter], 0usize)), iter.wrapping_add(1usize) as Nat)));
    muls16_from_step(lut16, x, iter as Nat);
    if iter < x.len() {
        elems16_from_zero(lut16, x[iter]);
        chunk_mul16_is(lut16, x[iter]);
        follows();
    } else {
        follows();
    }
}

/// The outer loop's end: at the length, `muls16_from` is the slice itself.
#[lemma]
fn loop16_end(lut16: [[u16; 16]; 4], x: &[[u8; 64]], iter: usize) {
    ensures(implies((iter < x.len()) == false, muls16_from(lut16, x, iter as Nat) == chunks_of(x)));
    muls16_from_end(lut16, x, iter as Nat);
    follows();
}

/// `Scalar::mul`'s loop from chunk `iter` on: the chunks from `iter` on
/// multiplied, one at a time.
#[lift_attach(crate::reed_solomon::engine::engine_scalar::Scalar::mul, loop_nr = 0)]
fn scalar_mul_loop() {
    invariant(iter <= x.len());
    decreases((x.len() as Int) - (iter as Int));
    ensures(|ret: &[[u8; 64]]| ret == crate::proof::muls16_from(*lut, x, iter as Nat));
    at_start! {
        crate::proof::loop16_step(*lut, x, iter);
        crate::proof::loop16_end(*lut, x, iter);
    }
}

/// Every chunk multiplied with Scalar's row, as `mul_all16` with the chunk
/// product opaque.
#[spec]
#[example(muls16(crate::laws::LUT16_ONE, seq![[7u8; 64]]) == seq![[7u8; 64]])]
pub fn muls16(lut16: [[u16; 16]; 4], s: Seq<[u8; 64]>) -> Seq<[u8; 64]> {
    match s {
        [] => Seq::empty(),
        [c, rest @ ..] => Seq::cons(chunk_mul16(lut16, c), muls16(lut16, rest)),
    }
}

#[lemma]
#[induction(s)]
fn muls16_is_mul_all16(lut16: [[u16; 16]; 4], s: Seq<[u8; 64]>) {
    ensures(muls16(lut16, s) == crate::laws::mul_all16(lut16, s));
    match s {
        [] => follows(),
        [c, rest @ ..] => {
            ih(lut16, rest);
            unfold(muls16);
            unfold(crate::laws::mul_all16);
            rewrite(chunk_mul16_is(lut16, c));
            rewrite(muls16(lut16, rest) == crate::laws::mul_all16(lut16, rest));
            follows();
        }
    }
}

#[lemma]
#[decreases((x.len() as Int) - (i as Int))]
fn muls16_from_split(lut16: [[u16; 16]; 4], x: Seq<[u8; 64]>, i: Nat) {
    requires(i <= x.len());
    ensures(muls16_from(lut16, x, i) == seq![..x.take(i), ..muls16(lut16, x.skip(i))]);
    muls16_from_step(lut16, x, i);
    muls16_from_end(lut16, x, i);
    if i < x.len() {
        let v = chunk_mul16(lut16, x[i]);
        let y = x.update(i, v);
        muls16_from_split(lut16, y, i + 1);
        update_split(x, i, v);
        crate::stdlib::seqs::append_snoc(x.take(i), v, x.skip(i + 1));
        assert(y == seq![..seq![..x.take(i), v], ..x.skip(i + 1)]);
        crate::stdlib::seqs::take_len_le(x, i as Int);
        crate::stdlib::seqs::len_app(x.take(i), seq![v]);
        crate::stdlib::seqs::take_skip_at(seq![..x.take(i), v], x.skip(i + 1), i + 1);
        assert(y.take(i + 1) == seq![..x.take(i), v]);
        assert(y.skip(i + 1) == x.skip(i + 1));
        assert(muls16_from(lut16, x, i) == seq![..seq![..x.take(i), v], ..muls16(lut16, x.skip(i + 1))]);
        crate::stdlib::seqs::append_snoc(x.take(i), v, muls16(lut16, x.skip(i + 1)));
        skip_at(x, i);
        assert(muls16(lut16, x.skip(i)) == seq![v, ..muls16(lut16, x.skip(i + 1))]);
        follows();
    } else {
        crate::stdlib::seqs::take_all(x, i);
        crate::stdlib::seqs::skip_len(x, i);
        crate::stdlib::seqs::len_zero(x.skip(i));
        follows();
    }
}

#[lemma]
fn muls16_from_zero(lut16: [[u16; 16]; 4], x: Seq<[u8; 64]>) {
    ensures(muls16_from(lut16, x, 0) == crate::laws::mul_all16(lut16, x));
    muls16_from_split(lut16, x, 0);
    crate::stdlib::seqs::take_zero(x);
    crate::stdlib::seqs::skip_zero(x);
    muls16_is_mul_all16(lut16, x);
    follows();
}

/// `Scalar::mul`'s summary: every chunk multiplied by the table row of
/// `log_m`, one at a time.
#[lift_attach(crate::reed_solomon::engine::engine_scalar::Scalar::mul)]
fn scalar_mul_summary() {
    ensures(|ret: &[[u8; 64]]| ret == crate::proof::muls16_from(self.mul16[log_m as usize], x, 0));
}

#[proof]
fn scalar_mul_multiplies_every_chunk(s: Scalar, x: &[[u8; 64]], log_m: u16) {
    // the call's summary becomes a fact
    let b = { let mut b = x; s.mul(&mut b, log_m); b };
    muls16_from_zero(s.mul16[log_m as usize], x);
    follows();
}

// ---------------------------------------------------------------------------
// The two engines
// ---------------------------------------------------------------------------

/// Byte `n` of the low bytes of sixteen 16-bit entries is the low byte of
/// entry `n`.
#[lemma]
fn lo_bytes_at(r: [u16; 16], n: usize) {
    requires(n < 16usize);
    ensures(crate::laws::lo_bytes(r)[n] == r[n] as u8);
    by_cases(n, 0..16);
}

/// Likewise the high bytes.
#[lemma]
fn hi_bytes_at(r: [u16; 16], n: usize) {
    requires(n < 16usize);
    ensures(crate::laws::hi_bytes(r)[n] == (r[n] >> 8u32) as u8);
    by_cases(n, 0..16);
}

/// The low bytes of four entries, xored, are the low byte of their xor.
#[lemma]
fn lo_byte_of(r0: [u16; 16], r1: [u16; 16], r2: [u16; 16], r3: [u16; 16], a: u8, b: u8) {
    ensures(crate::laws::lo_bytes(r0)[(a & 15u8) as usize] ^ crate::laws::lo_bytes(r1)[(a >> 4u32) as usize]
            ^ crate::laws::lo_bytes(r2)[(b & 15u8) as usize] ^ crate::laws::lo_bytes(r3)[(b >> 4u32) as usize]
        == (r0[(a & 15u8) as usize] ^ r1[(a >> 4u32) as usize] ^ r2[(b & 15u8) as usize] ^ r3[(b >> 4u32) as usize]) as u8);
    lo_bytes_at(r0, (a & 15u8) as usize);
    lo_bytes_at(r1, (a >> 4u32) as usize);
    lo_bytes_at(r2, (b & 15u8) as usize);
    lo_bytes_at(r3, (b >> 4u32) as usize);
    rewrite(crate::laws::lo_bytes(r0)[(a & 15u8) as usize] == r0[(a & 15u8) as usize] as u8);
    rewrite(crate::laws::lo_bytes(r1)[(a >> 4u32) as usize] == r1[(a >> 4u32) as usize] as u8);
    rewrite(crate::laws::lo_bytes(r2)[(b & 15u8) as usize] == r2[(b & 15u8) as usize] as u8);
    rewrite(crate::laws::lo_bytes(r3)[(b >> 4u32) as usize] == r3[(b >> 4u32) as usize] as u8);
    bv();
}

/// Likewise the high bytes.
#[lemma]
fn hi_byte_of(r0: [u16; 16], r1: [u16; 16], r2: [u16; 16], r3: [u16; 16], a: u8, b: u8) {
    ensures(crate::laws::hi_bytes(r0)[(a & 15u8) as usize] ^ crate::laws::hi_bytes(r1)[(a >> 4u32) as usize]
            ^ crate::laws::hi_bytes(r2)[(b & 15u8) as usize] ^ crate::laws::hi_bytes(r3)[(b >> 4u32) as usize]
        == ((r0[(a & 15u8) as usize] ^ r1[(a >> 4u32) as usize] ^ r2[(b & 15u8) as usize] ^ r3[(b >> 4u32) as usize]) >> 8u32) as u8);
    hi_bytes_at(r0, (a & 15u8) as usize);
    hi_bytes_at(r1, (a >> 4u32) as usize);
    hi_bytes_at(r2, (b & 15u8) as usize);
    hi_bytes_at(r3, (b >> 4u32) as usize);
    rewrite(crate::laws::hi_bytes(r0)[(a & 15u8) as usize] == (r0[(a & 15u8) as usize] >> 8u32) as u8);
    rewrite(crate::laws::hi_bytes(r1)[(a >> 4u32) as usize] == (r1[(a >> 4u32) as usize] >> 8u32) as u8);
    rewrite(crate::laws::hi_bytes(r2)[(b & 15u8) as usize] == (r2[(b & 15u8) as usize] >> 8u32) as u8);
    rewrite(crate::laws::hi_bytes(r3)[(b >> 4u32) as usize] == (r3[(b >> 4u32) as usize] >> 8u32) as u8);
    bv();
}

/// One element's low product byte through the NEON row is the low byte of
/// its product through the scalar row, when the one row is the byte split of
/// the other.
#[lemma]
fn lo_byte_split(lut: Multiply128lutT, lut16: [[u16; 16]; 4], a: u8, b: u8) {
    requires(crate::laws::is_split_of(lut, lut16));
    ensures(crate::laws::mul_lo_byte(lut, a, b) == crate::laws::mul16(lut16, a, b) as u8);
    unfold(crate::laws::mul_lo_byte);
    unfold(crate::laws::mul16);
    // each NEON row read as the scalar row it splits (`is_split_of`)
    lo_byte_of(lut16[0], lut16[1], lut16[2], lut16[3], a, b);
    follows();
}

/// Likewise the high product byte.
#[lemma]
fn hi_byte_split(lut: Multiply128lutT, lut16: [[u16; 16]; 4], a: u8, b: u8) {
    requires(crate::laws::is_split_of(lut, lut16));
    ensures(crate::laws::mul_hi_byte(lut, a, b) == (crate::laws::mul16(lut16, a, b) >> 8u32) as u8);
    unfold(crate::laws::mul_hi_byte);
    unfold(crate::laws::mul16);
    // each NEON row read as the scalar row it splits (`is_split_of`)
    hi_byte_of(lut16[0], lut16[1], lut16[2], lut16[3], a, b);
    follows();
}

/// A chunk multiplied through the NEON row is the chunk multiplied through
/// the scalar row, element by element.
#[lemma]
fn chunk_split(lut: Multiply128lutT, lut16: [[u16; 16]; 4], c: [u8; 64]) {
    requires(crate::laws::is_split_of(lut, lut16));
    ensures(crate::laws::mul_chunk(lut, c) == crate::laws::mul_chunk16(lut16, c));
    // element by element: each byte of the product by the row split
    using(lo_byte_split, hi_byte_split);
    follows();
}

/// Every chunk, likewise.
#[lemma]
#[induction(x)]
fn all_split(lut: Multiply128lutT, lut16: [[u16; 16]; 4], x: Seq<[u8; 64]>) {
    requires(crate::laws::is_split_of(lut, lut16));
    ensures(crate::laws::mul_all(lut, x) == crate::laws::mul_all16(lut16, x));
    match x {
        [] => follows(),
        [c, rest @ ..] => {
            ih(lut, lut16, rest);
            unfold(crate::laws::mul_all);
            unfold(crate::laws::mul_all16);
            rewrite(chunk_split(lut, lut16, c));
            rewrite(crate::laws::mul_all(lut, rest) == crate::laws::mul_all16(lut16, rest));
            follows();
        }
    }
}

#[proof]
fn neon_mul_is_scalar_mul(n: Neon, s: Scalar, x: &[[u8; 64]], log_m: u16) {
    let a = { let mut a = x; n.mul(&mut a, log_m); a };
    let b = { let mut b = x; s.mul(&mut b, log_m); b };
    calc! {
        a
            // the NEON engine multiplies every chunk through its row
            == crate::laws::mul_all(n.mul128[log_m as usize], x) by { neon_mul_multiplies_every_chunk(n, x, log_m); };
            // its row is the byte split of the scalar engine's row
            == crate::laws::mul_all16(s.mul16[log_m as usize], x) by { all_split(n.mul128[log_m as usize], s.mul16[log_m as usize], x); };
            // the scalar engine multiplies every chunk through its row
            == b by { scalar_mul_multiplies_every_chunk(s, x, log_m); follows(); };
    }
}
