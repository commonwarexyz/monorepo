//! Prelude (and prelude-lemma) items `auto` builds proofs with, looked up
//! by name in the kernel environment (DESIGN.md §6). Everything is optional:
//! in an environment without the prelude the corresponding proof steps are
//! simply unavailable.

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{GlobalId, IndId};

/// Globals and inductives used by the automation.
#[derive(Clone, Debug)]
pub struct Names {
    pub bool_ind: IndId,
    pub empty_ind: IndId,
    pub unit: Option<IndId>,
    pub either: Option<IndId>,
    pub list: Option<IndId>,
    pub option: Option<IndId>,
    pub tuple2: Option<IndId>,
    pub eq_sym: Option<GlobalId>,
    pub eq_trans: Option<GlobalId>,
    pub eq_cong: Option<GlobalId>,
    pub eq_promote: Option<GlobalId>,
    pub false_ne_true: Option<GlobalId>,
    pub seq_len: Option<GlobalId>,
    pub seq_index: Option<GlobalId>,
    pub slice: Option<GlobalId>,
    pub array: Option<GlobalId>,
    pub slice_ok_len: Option<GlobalId>,
    pub slice_ok_bound: Option<GlobalId>,
    pub array_ok_len: Option<GlobalId>,
    pub isize_max: Option<GlobalId>,
    pub slice_mk: Option<GlobalId>,
}

impl Names {
    pub fn new(env: &Env) -> Names {
        let g = |n: &str| env.lookup_global(n);
        let i = |n: &str| env.lookup_ind(n);
        Names {
            bool_ind: env.bool_ind(),
            empty_ind: env.empty_ind(),
            unit: i("Unit"),
            either: i("Either"),
            list: i("List"),
            option: i("Option"),
            tuple2: i("Tuple2"),
            eq_sym: g("eq::sym"),
            eq_trans: g("eq::trans"),
            eq_cong: g("eq::cong"),
            eq_promote: g("eq::promote"),
            false_ne_true: g("bool::false_ne_true"),
            seq_len: g("seq::len"),
            seq_index: g("seq::index"),
            slice: g("Slice"),
            array: g("Array"),
            slice_ok_len: g("slice::ok_len"),
            slice_ok_bound: g("slice::ok_bound"),
            array_ok_len: g("array::ok_len"),
            isize_max: g("ISIZE_MAX"),
            slice_mk: g("slice::mk"),
        }
    }
}
