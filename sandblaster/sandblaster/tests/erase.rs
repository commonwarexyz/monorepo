//! The erasing macros (baseline builds, DESIGN.md §2): contract and variant
//! attributes vanish and stack in any order, ghost items vanish entirely
//! (their bodies are Rust syntax but not well typed: `Int`, `forall`,
//! `requires(..)` do not exist for rustc), `proof!`
//! statements expand to nothing, and `#[refines]` keeps its exec type.

use sandblaster::prelude::*;

#[requires(off <= msg.len() && msg.len() - off >= 4)]
#[ensures(|ret: u32| true)]
#[decreases(msg.len(), max = 64)]
#[specialize]
fn read4(msg: &[u8], off: usize) -> u32 {
    proof! { assert(off + 4 <= msg.len()); }
    u32::from_be_bytes([msg[off], msg[off + 1], msg[off + 2], msg[off + 3]])
}

#[ensures(|ret: u64| ret == n as u64 * 2)]
#[inline]
#[requires(true)]
fn double(n: u32) -> u64 {
    let mut acc = 0u64;
    for _ in 0..2 {
        proof! {
            invariant(acc <= 2 * (n as Int));
            decreases(k);
        }
        acc += n as u64;
    }
    acc
}

#[implements(crate::double)]
#[must_use]
fn double_variant(n: u32) -> u64 {
    (n as u64) << 1u32
}

/// A ghost law: its body is script syntax, never Rust.
#[law]
fn double_is_even(n: u32) {
    requires(n < u32::MAX);
    ensures(double(n) % 2 == 0 && forall(|m: Int| m == m));
}

#[spec]
fn spec_only(x: Int) -> Prop {
    exists(|y: Int| y * 2 == x)
}

#[lemma]
fn helper(a: bool) {
    requires(a);
    ensures(a);
    todo();
}

#[rewrite]
#[law]
fn rewritten(x: u32) {
    ensures(x == x);
}

/// `refines` is erased like a contract: the repr type itself stays.
#[refines(spec_only, decode, inv)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Limbs {
    limbs: [u64; 5],
}

mod ghost_proofs {
    use sandblaster::ghost::*;

    #[proof]
    fn double_is_even(n: u32) {
        unfold(double);
        bv();
    }
}

#[test]
fn contracts_are_erased_and_code_runs() {
    assert_eq!(read4(&[0, 0, 1, 2, 3], 1), 0x0001_0203);
    assert_eq!(double(21), 42);
    assert_eq!(double_variant(21), 42);
    let l = Limbs { limbs: [1, 2, 3, 4, 5] };
    assert_eq!(l, l.clone());
    sandblaster::proof! { anything goes here; even(nonsense) }
}
