//! Iterators as step functions (a plain ghost module: its definitions are
//! generic over the state, so they are not lifted).

use sandblaster::prelude::*;

/// The items a step function yields from the state `s`, until it yields
/// nothing (at most `k` of them): what an iterator yields.
#[spec]
#[decreases(k)]
#[example(yields(0 as Int, 9, |s: Int| if s < 2 { (s + 1, Some((s, 7 as Int))) } else { (s, None) }) == seq![(0 as Int, 7 as Int), (1 as Int, 7 as Int)])]
#[example(yields(0 as Int, 1, |s: Int| (s + 1, Some((s, 0 as Int)))) == seq![(0 as Int, 0 as Int)] && yields(0 as Int, 0, |s: Int| (s, None)) == seq![])]
pub fn yields<S: Copy>(s: S, k: Int, step: fn(S) -> (S, Option<(Int, Int)>)) -> Seq<(Int, Int)> {
    if k <= 0 {
        seq![]
    } else {
        match step(s).1 {
            None => seq![],
            Some(x) => seq![x, ..yields(step(s).0, k - 1, step)],
        }
    }
}
