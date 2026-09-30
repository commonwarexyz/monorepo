//! The source of the pe P3 prelude lemmas: `lemmas/seq_lib.core` (the generic
//! `Seq` library, `seq.rs`, slice views, `view.rs`, and
//! constructor congruence, `option.rs`), the second part of `lemmas/nat.core`
//! (`nat.rs`) and `lemmas/bits_pow2.core` (`shift.rs`). The kernel terms the
//! front end produces for these lemmas are the proofs in those files
//! (generator `gen.py`); `prover_ergonomics_p3::p3_lemmas_match_their_source`
//! checks that this crate still proves exactly their statements.
#![forbid(unsafe_code)]
use sandblaster::prelude::*;

#[cfg(sandblaster)]
#[path = "seq.rs"]
mod seq;

#[cfg(sandblaster)]
#[path = "view.rs"]
mod view;

#[cfg(sandblaster)]
#[path = "option.rs"]
mod option;

#[cfg(sandblaster)]
#[path = "nat.rs"]
mod nat;

#[cfg(sandblaster)]
#[path = "shift.rs"]
mod shift;

pub fn api(x: u8) -> u8 { x }
