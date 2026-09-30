//! Every obligation shape of `qmdb/OBLIGATIONS.md`, written as core-text
//! goals the way the elaborator produces them (DESIGN.md §7.2: facts are
//! irrelevant binders — path conditions, loop ranges, requires, invariants,
//! let definitions, method facts), proved by `auto` and re-checked by the
//! kernel.

#[path = "auto_support.rs"]
mod support;

use support::*;

// ---------------------------------------------------------------------------
// sha256.rs
// ---------------------------------------------------------------------------

#[test]
fn sha256_literal_shifts_and_indices() {
    run(|env| {
        let b = GoalBuilder::new(env).bind("x", "U32");
        // `x >> 3u32`, `x >> 10u32`: shift < 32 (eval).
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(3u32, 32u32), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(10u32, 32u32), true)"));
        // `work[7]`: index < 8 (eval).
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(7usize, 8usize), true)"));
        // `(73u64 * 8)`: no overflow (eval).
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#imul(#cast_u64_int(73u64), #cast_u64_int(8u64)), 18446744073709551615int), true)"));
    });
}

#[test]
fn sha256_compress_loop1() {
    run(|env| {
        // for t in 0..16 { for j in 0..4 { .. block[4 * t + j] .. } }
        let b = GoalBuilder::new(env).binds(&[
            ("t", "Usize"),
            (".t0", "Eq(Bool, #le_usize(0usize, t), true)"),
            (".t1", "Eq(Bool, #lt_usize(t, 16usize), true)"),
            ("j", "Usize"),
            (".j0", "Eq(Bool, #le_usize(0usize, j), true)"),
            (".j1", "Eq(Bool, #lt_usize(j, 4usize), true)"),
        ]);
        // w[t] = ..: t < 64
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(t, 64usize), true)"));
        // 4 * t: no overflow
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#imul(#cast_usize_int(4usize), #cast_usize_int(t)), 18446744073709551615int), true)"));
        let pm = b.lin(&["t1"], "Eq(Bool, #le_int(#imul(#cast_usize_int(4usize), #cast_usize_int(t)), 18446744073709551615int), true)");
        let b = b.bind(".pm", "Eq(Bool, #le_int(#imul(#cast_usize_int(4usize), #cast_usize_int(t)), 18446744073709551615int), true)");
        // 4 * t + j: no overflow
        let add_ok =
            "Eq(Bool, #le_int(#iadd(#cast_usize_int(#mul_usize(4usize, t; pm)), #cast_usize_int(j)), 18446744073709551615int), true)";
        assert_proves(env, &b.goal(add_ok));
        let _ = pm;
        let b = b.bind(".pa", add_ok);
        // block[4 * t + j]: 4 * t + j < 64
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(#add_usize(#mul_usize(4usize, t; pm), j; pa), 64usize), true)"));
        // Negative: 4 * t + j < 60 does not follow.
        assert_fails(env, &b.goal("Eq(Bool, #lt_usize(#add_usize(#mul_usize(4usize, t; pm), j; pa), 60usize), true)"));
    });
}

#[test]
fn sha256_compress_loop2_and_3() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[
            ("t", "Usize"),
            (".t0", "Eq(Bool, #le_usize(16usize, t), true)"),
            (".t1", "Eq(Bool, #lt_usize(t, 64usize), true)"),
        ]);
        for k in [2, 7, 15, 16] {
            // t − k: no underflow
            assert_proves(env, &b.goal(&format!("Eq(Bool, #le_usize({k}usize, t), true)")));
        }
        let b = b.bind(".p2", "Eq(Bool, #le_usize(2usize, t), true)").bind(".p16", "Eq(Bool, #le_usize(16usize, t), true)");
        // w[t − 2] < 64, w[t − 16] < 64
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(#sub_usize(t, 2usize; p2), 64usize), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(#sub_usize(t, 16usize; p16), 64usize), true)"));
        // Negative: t − 16 < 47 is false for t = 63.
        assert_fails(env, &b.goal("Eq(Bool, #lt_usize(#sub_usize(t, 16usize; p16), 47usize), true)"));
        // loop 3 (t in 0..64): K[t], w[t]
        let b3 = GoalBuilder::new(env).binds(&[
            ("t", "Usize"),
            (".t0", "Eq(Bool, #le_usize(0usize, t), true)"),
            (".t1", "Eq(Bool, #lt_usize(t, 64usize), true)"),
        ]);
        assert_proves(env, &b3.goal("Eq(Bool, #lt_usize(t, 64usize), true)"));
    });
}

#[test]
fn sha256_blocks_and_to_bytes() {
    run(|env| {
        // blocks: for i in 0..full.len() { full[i] }
        let b = GoalBuilder::new(env).binds(&[
            ("full", "Slice (Array U8 64usize)"),
            ("i", "Usize"),
            (".i0", "Eq(Bool, #le_usize(0usize, i), true)"),
            (".i1", "Eq(Bool, #lt_usize(i, fst(full)), true)"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(i, fst(full)), true)"));
        // to_bytes: for i in 0..8 { out[4i..4i+4].copy_from_slice(&state[i].to_be_bytes()) }
        let b = GoalBuilder::new(env).binds(&[
            ("i", "Usize"),
            (".i0", "Eq(Bool, #le_usize(0usize, i), true)"),
            (".i1", "Eq(Bool, #lt_usize(i, 8usize), true)"),
        ]);
        let m = "Eq(Bool, #le_int(#imul(#cast_usize_int(4usize), #cast_usize_int(i)), 18446744073709551615int), true)";
        assert_proves(env, &b.goal(m));
        let b = b.bind(".pm", m);
        let a =
            "Eq(Bool, #le_int(#iadd(#cast_usize_int(#mul_usize(4usize, i; pm)), #cast_usize_int(4usize)), 18446744073709551615int), true)";
        assert_proves(env, &b.goal(a));
        let b = b.bind(".pa", a);
        // 4i ≤ 4i + 4 ≤ 32
        assert_proves(
            env,
            &b.goal("Eq(Bool, #le_usize(#mul_usize(4usize, i; pm), #add_usize(#mul_usize(4usize, i; pm), 4usize; pa)), true)"),
        );
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(#add_usize(#mul_usize(4usize, i; pm), 4usize; pa), 32usize), true)"));
        let b = b.bind(".ps", "Eq(Bool, #le_usize(#mul_usize(4usize, i; pm), #add_usize(#mul_usize(4usize, i; pm), 4usize; pa)), true)");
        // (4i + 4) − 4i == 4 == src.len()
        assert_proves(
            env,
            &b.goal("Eq(Usize, #sub_usize(#add_usize(#mul_usize(4usize, i; pm), 4usize; pa), #mul_usize(4usize, i; pm); ps), 4usize)"),
        );
        assert_proves(env, &b.goal("Eq(Bool, #eq_usize(#sub_usize(#add_usize(#mul_usize(4usize, i; pm), 4usize; pa), #mul_usize(4usize, i; pm); ps), 4usize), true)"));
        // state[i] (array of 8)
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(i, 8usize), true)"));
    });
}

#[test]
fn sha256_hash_as_chunks_facts() {
    run(|env| {
        // let (chunks, tail) = msg.as_chunks::<64>(); let n = tail.len();
        // last[0..n].copy_from_slice(tail); last[n] = 0x80;
        let b = GoalBuilder::new(env)
            .binds(&[
                ("msg", "Slice U8"),
                ("chunks", "Slice (Array U8 64usize)"),
                ("tail", "Slice U8"),
                // method facts (as_chunks, §3.4)
                (".c0", "Eq(Int, #iadd(#imul(#cast_usize_int(fst(chunks)), #cast_usize_int(64usize)), #cast_usize_int(fst(tail))), #cast_usize_int(fst(msg)))"),
                (".c1", "Eq(Bool, #lt_usize(fst(tail), 64usize), true)"),
            ])
            .def("n", "Usize", "fst(tail)");
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(0usize, n), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(n, 64usize), true)"));
        let b = b.bind(".p0", "Eq(Bool, #le_usize(0usize, n), true)");
        assert_proves(env, &b.goal("Eq(Usize, #sub_usize(n, 0usize; p0), fst(tail))"));
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(n, 64usize), true)"));
        assert_fails(env, &b.goal("Eq(Bool, #lt_usize(n, 63usize), true)"));
    });
}

#[test]
fn sha256_compress_sha2_chunks() {
    run(|env| {
        // let (chunks, _) = block.as_chunks::<16>();  chunks[3]: 3 < chunks.len()
        let b = GoalBuilder::new(env).binds(&[
            ("chunks", "Slice (Array U8 16usize)"),
            ("rest", "Slice U8"),
            (".c0", "Eq(Int, #iadd(#imul(#cast_usize_int(fst(chunks)), #cast_usize_int(16usize)), #cast_usize_int(fst(rest))), #cast_usize_int(64usize))"),
            (".c1", "Eq(Bool, #lt_usize(fst(rest), 16usize), true)"),
        ]);
        for k in 0..4 {
            assert_proves(env, &b.goal(&format!("Eq(Bool, #lt_usize({k}usize, fst(chunks)), true)")));
        }
        assert_fails(env, &b.goal("Eq(Bool, #lt_usize(4usize, fst(chunks)), true)"));
    });
}

// ---------------------------------------------------------------------------
// codec.rs
// ---------------------------------------------------------------------------

/// The `uint_go` context: `requires(fuel <= 5 && shift == 35 - 7 * fuel)`
/// as a dependent conjunction fact, and the path condition `fuel != 0`.
fn uint_go_ctx(env: &sandblaster_kernel::api::Env) -> GoalBuilder<'_> {
    let pre = GoalBuilder::new(env).binds(&[("fuel", "U32"), ("shift", "U32"), ("h", "Eq(Bool, #le_u32(fuel, 5u32), true)")]);
    let p1 = pre.lin(&["h"], "Eq(Bool, #le_int(#imul(#cast_u32_int(7u32), #cast_u32_int(fuel)), 4294967295int), true)");
    let pre = pre.bind(".q1", "Eq(Bool, #le_int(#imul(#cast_u32_int(7u32), #cast_u32_int(fuel)), 4294967295int), true)");
    let p2 = pre.lin(&["h"], "Eq(Bool, #le_u32(#mul_u32(7u32, fuel; q1), 35u32), true)");
    let p2 = p2.replace("q1", &format!("({p1})"));
    let req = format!(
        "Sigma (h : Eq(Bool, #le_u32(fuel, 5u32), true)), Eq(Bool, #eq_u32(shift, #sub_u32(35u32, #mul_u32(7u32, fuel; {p1}); {p2})), true)"
    );
    GoalBuilder::new(env).binds(&[
        ("fuel", "U32"),
        ("xs", "Slice U8"),
        ("shift", "U32"),
        ("acc", "U32"),
        (".req", &req),
        (".nz", "Eq(Bool, #eq_u32(fuel, 0u32), false)"),
    ])
}

#[test]
fn codec_uint_go_requires_itself() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("fuel", "U32"), ("shift", "U32"), (".h", "Eq(Bool, #le_u32(fuel, 5u32), true)")]);
        // 7 * fuel: no overflow, 35 − 7 * fuel: no underflow (left conjunct).
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#imul(#cast_u32_int(7u32), #cast_u32_int(fuel)), 4294967295int), true)"));
        let b = b.bind(".q1", "Eq(Bool, #le_int(#imul(#cast_u32_int(7u32), #cast_u32_int(fuel)), 4294967295int), true)");
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(#mul_u32(7u32, fuel; q1), 35u32), true)"));
    });
}

#[test]
fn codec_uint_go_body() {
    run(|env| {
        let b = uint_go_ctx(env);
        // `.. << shift`: shift < 32 (needs fuel ≥ 1 from `fuel != 0`).
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(shift, 32u32), true)"));
        // fuel − 1: no underflow
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(1u32, fuel), true)"));
        // shift + 7: no overflow
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#iadd(#cast_u32_int(shift), #cast_u32_int(7u32)), 4294967295int), true)"));
        // termination (measure fuel, u32): fuel − 1 < fuel
        let b = b.bind(".p1", "Eq(Bool, #le_u32(1u32, fuel), true)");
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(#sub_u32(fuel, 1u32; p1), fuel), true)"));
        // Negative: without `fuel != 0`, shift < 32 is not provable
        // (fuel = 0 gives shift = 35).
        let b2 = GoalBuilder::new(env).binds(&[
            ("fuel", "U32"),
            ("shift", "U32"),
            (".h", "Eq(Bool, #le_u32(fuel, 5u32), true)"),
            (".e", "Eq(U32, shift, #wsub_u32(35u32, #wmul_u32(7u32, fuel)))"),
        ]);
        assert_fails(env, &b2.goal("Eq(Bool, #lt_u32(shift, 32u32), true)"));
    });
}

#[test]
fn codec_uint_go_recursive_call() {
    run(|env| {
        let b = uint_go_ctx(env);
        let b = b
            .bind(".p1", "Eq(Bool, #le_u32(1u32, fuel), true)")
            .bind(".p7", "Eq(Bool, #le_int(#iadd(#cast_u32_int(shift), #cast_u32_int(7u32)), 4294967295int), true)");
        // callee requires: (fuel − 1) ≤ 5 && shift + 7 == 35 − 7·(fuel − 1)
        let pre = GoalBuilder::new(env).binds(&[
            ("fuel", "U32"),
            (".p1", "Eq(Bool, #le_u32(1u32, fuel), true)"),
            ("h", "Eq(Bool, #le_u32(#sub_u32(fuel, 1u32; p1), 5u32), true)"),
        ]);
        let m = "Eq(Bool, #le_int(#imul(#cast_u32_int(7u32), #cast_u32_int(#sub_u32(fuel, 1u32; p1))), 4294967295int), true)";
        let q1 = pre.lin(&["h"], m);
        let pre = pre.bind(".q1", m);
        let q2 = pre
            .lin(&["h"], "Eq(Bool, #le_u32(#mul_u32(7u32, #sub_u32(fuel, 1u32; p1); q1), 35u32), true)")
            .replace("q1", &format!("({q1})"));
        let target = format!(
            "Sigma (h : Eq(Bool, #le_u32(#sub_u32(fuel, 1u32; p1), 5u32), true)), \
             Eq(Bool, #eq_u32(#add_u32(shift, 7u32; p7), #sub_u32(35u32, #mul_u32(7u32, #sub_u32(fuel, 1u32; p1); {q1}); {q2})), true)"
        );
        assert_proves(env, &b.goal(&target));
        // uint: uint_go(5, xs, 0, 0) requires 5 ≤ 5 && 0 == 35 − 35 (eval).
        let u = GoalBuilder::new(env).bind("xs", "Slice U8");
        assert_proves(
            env,
            &u.goal("Sigma (h : Eq(Bool, #le_u32(5u32, 5u32), true)), Eq(Bool, #eq_u32(0u32, #sub_u32(35u32, #mul_u32(7u32, 5u32; refl(Bool, true)); refl(Bool, true))), true)"),
        );
    });
}

// ---------------------------------------------------------------------------
// merkle.rs
// ---------------------------------------------------------------------------

fn shape_loop_ctx(env: &sandblaster_kernel::api::Env) -> GoalBuilder<'_> {
    GoalBuilder::new(env).binds(&[
        ("leaves", "U32"),
        ("k", "U32"),
        (".k0", "Eq(Bool, #le_u32(0u32, k), true)"),
        (".k1", "Eq(Bool, #lt_u32(k, 32u32), true)"),
        ("remaining", "U64"),
        ("width", "U64"),
        ("position", "U64"),
        ("start", "U64"),
        ("before", "U32"),
        // invariants (over Int)
        (".i1", "Eq(Bool, #eq_int(#iadd(#cast_u64_int(start), #cast_u64_int(remaining)), #cast_u32_int(leaves)), true)"),
        (".i2", "Eq(Bool, #le_int(#cast_u64_int(position), #imul(2int, #cast_u64_int(start))), true)"),
        (".i3", "Eq(Bool, #le_u32(before, k), true)"),
        // branch `remaining >= width`
        (".g", "Eq(Bool, #ge_u64(remaining, width), true)"),
    ])
}

#[test]
fn merkle_shape_loop() {
    run(|env| {
        // invariant entry: start = position = before = 0, remaining = leaves
        let e = GoalBuilder::new(env).bind("leaves", "U32");
        assert_proves(
            env,
            &e.goal("Eq(Bool, #eq_int(#iadd(#cast_u64_int(0u64), #cast_u64_int(#cast_u32_u64(leaves))), #cast_u32_int(leaves)), true)"),
        );
        let b = shape_loop_ctx(env);
        // start + width: no overflow
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#iadd(#cast_u64_int(start), #cast_u64_int(width)), 18446744073709551615int), true)"));
        // 31 − k: no underflow
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(k, 31u32), true)"));
        // 2 * width, position + 2 * width: no overflow
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#imul(#cast_u64_int(2u64), #cast_u64_int(width)), 18446744073709551615int), true)"));
        let b = b.bind(".m2", "Eq(Bool, #le_int(#imul(#cast_u64_int(2u64), #cast_u64_int(width)), 18446744073709551615int), true)");
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#iadd(#cast_u64_int(position), #cast_u64_int(#mul_u64(2u64, width; m2))), 18446744073709551615int), true)"));
        // remaining − width: no underflow
        assert_proves(env, &b.goal("Eq(Bool, #le_u64(width, remaining), true)"));
        // before + 1: no overflow
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#iadd(#cast_u32_int(before), #cast_u32_int(1u32)), 4294967295int), true)"));
        // width / 2: divisor ≠ 0 (eval)
        assert_proves(env, &b.goal("Eq(Bool, #ne_u64(2u64, 0u64), true)"));
        // target − start with the guard target ≥ start
        let t = b.binds(&[("target", "U64"), (".gt", "Eq(Bool, #ge_u64(target, start), true)")]);
        assert_proves(env, &t.goal("Eq(Bool, #le_u64(start, target), true)"));
    });
}

#[test]
fn merkle_shape_invariant_preservation() {
    run(|env| {
        let b = shape_loop_ctx(env);
        let b = b
            .bind(".m2", "Eq(Bool, #le_int(#imul(#cast_u64_int(2u64), #cast_u64_int(width)), 18446744073709551615int), true)")
            .bind(".pa", "Eq(Bool, #le_int(#iadd(#cast_u64_int(position), #cast_u64_int(#mul_u64(2u64, width; m2))), 18446744073709551615int), true)")
            .bind(".sa", "Eq(Bool, #le_int(#iadd(#cast_u64_int(start), #cast_u64_int(width)), 18446744073709551615int), true)")
            .bind(".sw", "Eq(Bool, #le_u64(width, remaining), true)")
            .bind(".b1", "Eq(Bool, #le_int(#iadd(#cast_u32_int(before), #cast_u32_int(1u32)), 4294967295int), true)");
        // I2: sat_sub(position + 2w, 1) ≤ 2·(start + w)   (needs sat_sub_def)
        assert_proves(
            env,
            &b.goal("Eq(Bool, #le_int(#cast_u64_int(#sat_sub_u64(#add_u64(position, #mul_u64(2u64, width; m2); pa), 1u64)), #imul(2int, #cast_u64_int(#add_u64(start, width; sa)))), true)"),
        );
        // I1: (start + w) + (remaining − w) = leaves
        assert_proves(
            env,
            &b.goal("Eq(Bool, #eq_int(#iadd(#cast_u64_int(#add_u64(start, width; sa)), #cast_u64_int(#sub_u64(remaining, width; sw))), #cast_u32_int(leaves)), true)"),
        );
        // I3: before + 1 ≤ k + 1
        let b = b.bind(".k31", "Eq(Bool, #le_int(#iadd(#cast_u32_int(k), #cast_u32_int(1u32)), 4294967295int), true)");
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(#add_u32(before, 1u32; b1), #add_u32(k, 1u32; k31)), true)"));
        // Negative: sat_sub(position + 2w, 1) ≤ 2·start is false in general.
        assert_fails(env, &b.goal("Eq(Bool, #le_int(#cast_u64_int(#sat_sub_u64(#add_u64(position, #mul_u64(2u64, width; m2); pa), 1u64)), #imul(2int, #cast_u64_int(start))), true)"));
    });
}

#[test]
fn merkle_path_bag_prefix_list_ops() {
    run(|env| {
        // path: height − 1 with `height == 0` false; index − half with `index < half` false
        let b = GoalBuilder::new(env).binds(&[
            ("height", "U32"),
            (".hmax", "Eq(Bool, #le_u32(height, 64u32), true)"),
            (".hz", "Eq(Bool, #eq_u32(height, 0u32), false)"),
            ("index", "U64"),
            ("width", "U64"),
            (".hl", "Eq(Bool, #lt_u64(index, #div_u64(width, 2u64; refl(Bool, true))), false)"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(1u32, height), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #le_u64(#div_u64(width, 2u64; refl(Bool, true)), index), true)"));
        let b = b.bind(".p1", "Eq(Bool, #le_u32(1u32, height), true)");
        // recursive call: requires p ≤ 64, measure p < height (u32), stack depth
        assert_proves(env, &b.goal("Eq(Bool, #le_u32(#sub_u32(height, 1u32; p1), 64u32), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(#sub_u32(height, 1u32; p1), height), true)"));
        // reconstruct_checked: `height > MAX_HEIGHT` false ⇒ height ≤ 64
        let r = GoalBuilder::new(env).binds(&[("height", "U32"), (".g", "Eq(Bool, #gt_u32(height, 64u32), false)")]);
        assert_proves(env, &r.goal("Eq(Bool, #le_u32(height, 64u32), true)"));
        // bag_prefix: n − 1 with `n == 0` false
        let n = GoalBuilder::new(env).binds(&[("n", "Usize"), (".nz", "Eq(Bool, #eq_usize(n, 0usize), false)")]);
        assert_proves(env, &n.goal("Eq(Bool, #le_usize(1usize, n), true)"));
        let n = n.bind(".p", "Eq(Bool, #le_usize(1usize, n), true)");
        assert_proves(env, &n.goal("Eq(Bool, #lt_usize(#sub_usize(n, 1usize; p), n), true)"));
        // list_drop: &xs[xs.len()..]: xs.len() ≤ xs.len()
        let x = GoalBuilder::new(env).bind("xs", "Slice (Array U8 32usize)");
        assert_proves(env, &x.goal("Eq(Bool, #le_usize(fst(xs), fst(xs)), true)"));
    });
}

#[test]
fn merkle_fold_back_go_termination() {
    run(|env| {
        // [init @ .., last]: init = prefix(xs, len − 1); measure xs.len()
        let b = GoalBuilder::new(env).binds(&[
            ("xs", "Slice (Array U8 32usize)"),
            (".ne", "Eq(Bool, #lt_usize(0usize, fst(xs)), true)"),
            (".p1", "Eq(Bool, #le_usize(1usize, fst(xs)), true)"),
        ]);
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(#sub_usize(fst(xs), 1usize; p1), fst(xs)), true)"));
    });
}

#[test]
fn merkle_root_sum_with_bool_casts() {
    run(|env| {
        // root: inactive.saturating_sub(folded) as usize + (folded != 0) as usize
        let b = GoalBuilder::new(env).binds(&[("inactive", "U32"), ("folded", "U32")]);
        assert_proves(
            env,
            &b.goal("Eq(Bool, #le_int(#iadd(#cast_usize_int(#cast_u32_usize(#sat_sub_u32(inactive, folded))), #cast_usize_int(bool::as_usize (#ne_u32(folded, 0u32)))), 18446744073709551615int), true)"),
        );
    });
}

#[test]
fn merkle_reconstruct_finish() {
    run(|env| {
        let b = GoalBuilder::new(env)
            .binds(&[("before", "Slice (Array U8 32usize)"), ("after", "Slice (Array U8 32usize)")])
            .def("nb", "Usize", "fst(before)")
            .def("na", "Usize", "fst(after)");
        // nb + na: no overflow (SliceOk bounds)
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#iadd(#cast_usize_int(nb), #cast_usize_int(na)), 18446744073709551615int), true)"));
        let b = b
            .bind(".s", "Eq(Bool, #le_int(#iadd(#cast_usize_int(nb), #cast_usize_int(na)), 18446744073709551615int), true)")
            .bind(".g", "Eq(Bool, #ge_usize(#add_usize(nb, na; s), 32usize), false)");
        // xs[0..nb]: nb ≤ 32; xs[nb] = ..: nb < 32
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(nb, 32usize), true)"));
        assert_proves(env, &b.goal("Eq(Bool, #lt_usize(nb, 32usize), true)"));
        // nb + 1 + na ≤ 32
        assert_proves(
            env,
            &b.goal("Eq(Bool, #le_int(#iadd(#cast_usize_int(nb), #cast_usize_int(1usize)), 18446744073709551615int), true)"),
        );
        let b = b.bind(".n1", "Eq(Bool, #le_int(#iadd(#cast_usize_int(nb), #cast_usize_int(1usize)), 18446744073709551615int), true)");
        let b = b.bind(
            ".n2",
            "Eq(Bool, #le_int(#iadd(#cast_usize_int(#add_usize(nb, 1usize; n1)), #cast_usize_int(na)), 18446744073709551615int), true)",
        );
        assert_proves(env, &b.goal("Eq(Bool, #le_usize(#add_usize(#add_usize(nb, 1usize; n1), na; n2), 32usize), true)"));
        assert_proves(
            env,
            &b.goal("Eq(Bool, #le_usize(#add_usize(nb, 1usize; n1), #add_usize(#add_usize(nb, 1usize; n1), na; n2)), true)"),
        );
    });
}

#[test]
fn merkle_reconstruct_shape_counts() {
    run(|env| {
        // folded = min(before, inactive); before_count = sat_sub(before, folded) + (folded != 0)
        let b = GoalBuilder::new(env).binds(&[("before", "U32"), ("after", "U32"), ("inactive", "U32"), ("height", "U32")]).def(
            "folded",
            "U32",
            "#min_u32(before, inactive)",
        );
        let bc_ok = "Eq(Bool, #le_int(#iadd(#cast_u64_int(#sat_sub_u64(#cast_u32_u64(before), #cast_u32_u64(folded))), #cast_u64_int(bool::as_u64 (#ne_u32(folded, 0u32)))), 18446744073709551615int), true)";
        assert_proves(env, &b.goal(bc_ok));
        // before as u64 + 1
        let b1 = "Eq(Bool, #le_int(#iadd(#cast_u64_int(#cast_u32_u64(before)), #cast_u64_int(1u64)), 18446744073709551615int), true)";
        assert_proves(env, &b.goal(b1));
        let b = b.bind(".bc", bc_ok).bind(".b1", b1);
        let b = b
            .def(
                "before_count",
                "U64",
                "#add_u64(#sat_sub_u64(#cast_u32_u64(before), #cast_u32_u64(folded)), bool::as_u64 (#ne_u32(folded, 0u32)); bc)",
            )
            .def(
                "inactive_after",
                "U64",
                "#min_u64(#cast_u32_u64(after), #sat_sub_u64(#cast_u32_u64(inactive), #add_u64(#cast_u32_u64(before), 1u64; b1)))",
            );
        // inactive_after + (after > inactive_after) as u64
        let ac_ok = "Eq(Bool, #le_int(#iadd(#cast_u64_int(inactive_after), #cast_u64_int(bool::as_u64 (#gt_u64(#cast_u32_u64(after), inactive_after)))), 18446744073709551615int), true)";
        assert_proves(env, &b.goal(ac_ok));
        let b = b.bind(".ac", ac_ok).def(
            "after_count",
            "U64",
            "#add_u64(inactive_after, bool::as_u64 (#gt_u64(#cast_u32_u64(after), inactive_after)); ac)",
        );
        // height as u64 + before_count (+ after_count)
        let s1 =
            "Eq(Bool, #le_int(#iadd(#cast_u64_int(#cast_u32_u64(height)), #cast_u64_int(before_count)), 18446744073709551615int), true)";
        assert_proves(env, &b.goal(s1));
        let b = b.bind(".s1", s1);
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#iadd(#cast_u64_int(#add_u64(#cast_u32_u64(height), before_count; s1)), #cast_u64_int(after_count)), 18446744073709551615int), true)"));
        // before as u64 + after as u64 + 1
        let s2 = "Eq(Bool, #le_int(#iadd(#cast_u64_int(#cast_u32_u64(before)), #cast_u64_int(#cast_u32_u64(after))), 18446744073709551615int), true)";
        assert_proves(env, &b.goal(s2));
    });
}

// ---------------------------------------------------------------------------
// verifier.rs
// ---------------------------------------------------------------------------

#[test]
fn verifier_obligations() {
    run(|env| {
        let b = GoalBuilder::new(env).binds(&[("count", "U32"), ("location", "U32"), ("chunk", "U8")]);
        // count as usize * 32: no overflow
        assert_proves(env, &b.goal("Eq(Bool, #le_int(#imul(#cast_usize_int(#cast_u32_usize(count)), #cast_usize_int(32usize)), 18446744073709551615int), true)"));
        // location % 8: divisor ≠ 0 (eval)
        assert_proves(env, &b.goal("Eq(Bool, #ne_u32(8u32, 0u32), true)"));
        // chunk >> (location % 8): shift < 8 (rem by a literal)
        assert_proves(env, &b.goal("Eq(Bool, #lt_u32(#rem_u32(location, 8u32; refl(Bool, true)), 8u32), true)"));
        // Negative: location % 8 < 7 does not hold.
        assert_fails(env, &b.goal("Eq(Bool, #lt_u32(#rem_u32(location, 8u32; refl(Bool, true)), 7u32), true)"));
    });
}
