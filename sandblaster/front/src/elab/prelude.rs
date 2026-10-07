//! Kernel prelude names used by elaboration (DESIGN.md §6), looked up once
//! per environment, plus the handful of elaboration-semantics definitions
//! the kernel prelude does not provide ([`crate::elab::semantics`]).
//!
//! The meaning of every exec construct is given either by a primitive, by a
//! prelude definition named here, or by the elaboration rules of
//! `SEMANTICS.md`. A missing prelude name is an internal error (the prelude
//! is part of the TCB and fixed).

use std::collections::HashMap;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId};

/// Cached prelude ids.
pub struct Prelude {
    pub bool_: IndId,
    pub empty: IndId,
    pub unit: IndId,
    pub option: IndId,
    pub list: IndId,
    pub either: IndId,
    /// `tuples[n]` is `TupleN` (n = 1..=12; `Tuple1` comes from the
    /// elaboration semantics).
    pub tuples: Vec<Option<IndId>>,
    globals: HashMap<&'static str, GlobalId>,
}

/// Every prelude global the elaborator may refer to.
const GLOBALS: &[&str] = &[
    "ISIZE_MAX",
    "SliceOk",
    "Slice",
    "Array",
    "slice::mk",
    "slice::ok_len",
    "slice::ok_bound",
    "array::ok_len",
    "array::len",
    "array::index",
    "array::set",
    "array::as_slice",
    "array::eq",
    "array::rev",
    "array::repeat",
    "slice::len",
    "slice::list",
    "slice::is_empty",
    "slice::index",
    "slice::get",
    "slice::prefix",
    "slice::suffix",
    "slice::range",
    "slice::split_at",
    "slice::split_at_checked",
    "slice::split_first",
    "slice::first",
    "slice::last",
    "slice::split_last",
    "slice::prefix_array",
    "slice::split_first_chunk",
    "slice::first_chunk",
    "slice::as_chunks",
    "seq::len",
    "seq::cons",
    "seq::index",
    "seq::update",
    "seq::take",
    "seq::drop",
    "seq::append",
    "seq::rev",
    "seq::replicate",
    "seq::eq",
    "seq::len_append",
    "seq::len_update",
    "seq::len_take",
    "seq::len_drop",
    "Not",
    "And",
    "Or",
    "Iff",
    "Exists",
    "eq::sym",
    "eq::trans",
    "eq::cong",
    "eq::promote",
    "bool::false_ne_true",
    "bool::not",
    "bool::and",
    "bool::or",
    "bool::xor",
    "bool::eq",
    "bool::ne",
    "bool::as_u8",
    "bool::as_u16",
    "bool::as_u32",
    "bool::as_u64",
    "bool::as_usize",
    "option::is_some",
    "option::is_none",
    "option::unwrap_or",
];

impl Prelude {
    /// Looks every name up; `Err` names the missing items.
    pub fn new(env: &Env) -> Result<Prelude, String> {
        let mut missing = Vec::new();
        let mut ind = |n: &str| match env.lookup_ind(n) {
            Some(i) => i,
            None => {
                missing.push(n.to_string());
                IndId(u32::MAX)
            }
        };
        let unit = ind("Unit");
        let option = ind("Option");
        let list = ind("List");
        let either = ind("Either");
        let mut tuples = vec![None; 13];
        tuples[1] = env.lookup_ind("Tuple1");
        for (n, slot) in tuples.iter_mut().enumerate().skip(2) {
            *slot = Some(ind(&format!("Tuple{n}")));
        }
        let mut globals = HashMap::new();
        for g in GLOBALS {
            match env.lookup_global(g) {
                Some(id) => {
                    globals.insert(*g, id);
                }
                None => missing.push((*g).to_string()),
            }
        }
        if !missing.is_empty() {
            return Err(format!("the kernel prelude lacks: {}", missing.join(", ")));
        }
        Ok(Prelude { bool_: env.bool_ind(), empty: env.empty_ind(), unit, option, list, either, tuples, globals })
    }

    /// A prelude global by name (must be in [`GLOBALS`]).
    pub fn g(&self, name: &str) -> GlobalId {
        *self.globals.get(name).unwrap_or_else(|| panic!("prelude global `{name}` is not in the elaborator's table"))
    }

    /// `TupleN` for `n ≥ 1`.
    pub fn tuple(&self, n: usize) -> Option<IndId> {
        self.tuples.get(n).copied().flatten()
    }
}
