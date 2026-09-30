//! Basic `auto` behaviour (DESIGN.md §8.1 steps 1–3, 13): conversion,
//! assumption, connectives, linarith.

#[path = "auto_support.rs"]
mod support;

use support::*;

#[test]
fn refl_and_linarith() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("t", "Usize"), (".h", "Eq(Bool, #lt_usize(t, 16usize), true)")]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(3usize, 8usize), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(t, 64usize), true)"));
        assert_fails(env, &b.goal("Eq(Bool, #lt_usize(t, 15usize), true)"));
    });
}
