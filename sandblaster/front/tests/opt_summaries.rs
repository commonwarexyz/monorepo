//! Compositional summaries (docs/optimizer-plan.md O5; optimizer design
//! §6.4–§6.6, §7.7): callee summaries at call sites (instantiated with
//! case-of-case, inlined as values, kept), merged splits, polyvariant
//! call-site specialization, folding into loop helpers with carried
//! (Houdini) invariants, and fact-lemma export and import — each on a
//! small program, checked for the residual it prints and for its
//! kernel-checked admission (the round trip is part of every build).
//!
//! `cargo test --release -p sandblaster-front --test opt_summaries -- --test-threads=1`

use std::path::Path;
use std::sync::Arc;

use sandblaster_front::driver::{self, Checked, OptimizedEmit};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::hooks::OptTestHooks;
use sandblaster_front::opt::{Link, OptOptions, Outcome, Rung};
use sandblaster_front::target::TargetInfo;

fn check_src(src: &str) -> Checked {
    let fs = MemFs::from_files([("r/mod.rs", src)]);
    let c = driver::check(Path::new("r/mod.rs"), &fs, &TargetInfo::aarch64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    c
}

/// Elaborates (exec code), optimizes (strict) and prints `src`.
fn optimize(src: &str) -> OptimizedEmit {
    let c = check_src(src);
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        assert!(out.obligations.iter().all(|o| o.proven()), "the sample must verify");
        let em = driver::stage::optimize_emit_mode(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, hooks: Some(Arc::new(OptTestHooks::default())), ..Default::default() }, true).unwrap();
        assert!(em.opt.errors.is_empty(), "optimizer errors: {:?}", em.opt.errors);
        assert!(em.roundtrip.is_empty(), "round trip: {:?}", em.roundtrip);
        em
    })
}

fn report<'a>(em: &'a OptimizedEmit, name: &str) -> &'a sandblaster_front::opt::FnReport {
    em.opt.fns.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no report for {name}"))
}

/// The printed body of `fn name(` (up to the next item at the same indent).
fn body_of(code: &str, name: &str) -> String {
    let head = format!("fn {name}(");
    let mut out = String::new();
    let mut on = false;
    let mut indent = 0usize;
    for line in code.lines() {
        if !on && line.contains(&head) {
            on = true;
            indent = line.len() - line.trim_start().len();
        }
        if on {
            out.push_str(line);
            out.push('\n');
            if line.trim_start().starts_with('}') && line.len() - line.trim_start().len() == indent {
                break;
            }
        }
    }
    out
}

fn show(em: &OptimizedEmit) {
    for f in &em.opt.fns {
        match &f.outcome {
            Outcome::Specialized { nodes, .. } => println!("  {}: Specialized {nodes} nodes {:?} {:?}", f.name, f.link, f.rung),
            Outcome::Unspecialized { reason, .. } => println!("  {}: Unspecialized: {}", f.name, reason.chars().take(200).collect::<String>()),
        }
        for c in &f.candidates {
            if !c.chosen {
                println!("      {:?}: {} ({:?})", c.rung, c.reason.chars().take(300).collect::<String>(), c.rejected_by);
            }
        }
    }
}

fn driven(em: &OptimizedEmit, name: &str) -> bool {
    let f = report(em, name);
    matches!(f.outcome, Outcome::Specialized { .. }) && f.rung == Some(Rung::Driven) && matches!(f.link, Some(Link::Lemma(_)))
}

const HEADER: &str = "#![forbid(unsafe_code)]\nuse sandblaster::prelude::*;\n";

/// A decision on a masked, shifted byte (the level-1 leaf of a varint
/// reader followed by a range check): linear arithmetic decides it.
#[test]
fn masked_byte_bound_is_pruned() {
    let src = format!(
        "{HEADER}
pub fn small(h: u8, t: bool) -> Option<u64> {{
    let v = (((h & 0x7f) as u64) << 0u32) | 0u64;
    if t {{ if v <= 4611686018427387904 {{ Some(v) }} else {{ None }} }} else {{ None }}
}}
"
    );
    let em = optimize(&src);
    show(&em);
    let b = body_of(&em.code, "small");
    println!("{b}");
    assert!(driven(&em, "crate::small"));
    assert!(!b.contains("4611686018427387904"), "the range check is decided: {b}");
}

/// The same on a slice element (the reader's byte).
#[test]
fn masked_slice_byte_bound_is_pruned() {
    let src = format!(
        "{HEADER}
pub fn small2(xs: &[u8]) -> Option<u64> {{
    let [h, t @ ..] = xs else {{ return None; }};
    let v = (((*h & 0x7f) as u64) << 0u32) | 0u64;
    if v <= 4611686018427387904 {{ Some(v) }} else {{ None }}
}}
"
    );
    let em = optimize(&src);
    show(&em);
    let b = body_of(&em.code, "small2");
    println!("{b}");
    assert!(driven(&em, "crate::small2"));
    assert!(!b.contains("4611686018427387904"), "the range check is decided: {b}");
}

/// The QMDB varint readers (`sandblaster/fixtures/qmdb/sandblaster/codec.rs`, verbatim): a
/// `u64` LEB128 reader over a static recursion (fuel 10) and `location`,
/// its range-checked use.
const VARINT: &str = r#"
pub const MAX_LEAVES: u64 = 1u64 << 62u32;

fn uint64_finish(ok: bool, value: u64, rest: &[u8]) -> Option<(u64, &[u8])> {
    if ok { Some((value, rest)) } else { None }
}

#[requires(fuel <= 10 && shift == 70 - 7 * fuel)]
#[decreases(fuel)]
fn uint64_go(fuel: u32, xs: &[u8], shift: u32, acc: u64) -> Option<(u64, &[u8])> {
    if fuel == 0 {
        return None;
    }
    let [h, t @ ..] = xs else {
        return None;
    };
    let h = *h;
    let value = acc | (((h & 0x7f) as u64) << shift);
    if h < 0x80 {
        let ok = (fuel != 1 || h < 2) && (shift == 0 || h != 0);
        uint64_finish(ok, value, t)
    } else {
        uint64_go(fuel - 1, t, shift + 7, value)
    }
}

pub fn uint64(xs: &[u8]) -> Option<(u64, &[u8])> {
    uint64_go(10, xs, 0, 0)
}

pub fn location(xs: &[u8]) -> Option<(u64, &[u8])> {
    let (value, rest) = uint64(xs)?;
    if value <= MAX_LEAVES { Some((value, rest)) } else { None }
}
"#;

/// Design §12.3: `location` instantiates the driven `uint64` through its
/// link (case-of-case), the range check is decided in the leaves of the
/// first eight bytes, and both outcomes after nine continuation bytes are
/// `None`: the split merges and the tenth byte is never read.
#[test]
fn location_never_reads_the_tenth_byte() {
    let em = optimize(&format!("{HEADER}{VARINT}"));
    show(&em);
    let b = body_of(&em.code, "location");
    println!("{b}");
    assert!(driven(&em, "crate::uint64") && driven(&em, "crate::location"));
    // byte reads: `xs[k]` at literal indices (the kernel reads the
    // sub-slices' first elements as elements of `xs`)
    let reads = byte_reads(&b, "l0_xs");
    println!("bytes read by `location`: {reads:?}");
    assert_eq!(reads, (0..9).collect::<Vec<u64>>(), "location reads bytes 0..=8 and never the tenth");
}

/// The literal indices `k` of the element reads `get_unchecked(&(*xs), k)`
/// of the slice parameter `xs` in a printed body (sorted, distinct).
fn byte_reads(body: &str, xs: &str) -> Vec<u64> {
    let pat = format!("get_unchecked(&(*{xs}), ");
    let mut out: Vec<u64> = body
        .match_indices(&pat)
        .filter_map(|(i, _)| {
            let rest = &body[i + pat.len()..];
            let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            (!n.is_empty() && rest[n.len()..].starts_with("usize)")).then(|| n.parse().ok()).flatten()
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Linear arithmetic on an accumulated varint value (`acc | (h & 0x7f) <<
/// 7k`, `k` levels): the bound `v ≤ 2^62` for up to eight groups.
#[test]
fn varint_value_bounds() {
    for levels in [2usize, 5, 8] {
        let mut v = "0u64".to_string();
        let mut params = Vec::new();
        for k in 0..levels {
            params.push(format!("h{k}: u8"));
            v = format!("({v} | (((h{k} & 0x7f) as u64) << {}u32))", 7 * k);
        }
        let src = format!("{HEADER}\npub fn bound(t: bool, {}) -> u8 {{\n    let v = {v};\n    if t {{ if v <= 4611686018427387904 {{ 1u8 }} else {{ 2u8 }} }} else {{ 0u8 }}\n}}\n", params.join(", "));
        let t = std::time::Instant::now();
        let em = optimize(&src);
        let b = body_of(&em.code, "bound");
        println!("{levels} levels ({:?}):\n{b}", t.elapsed());
        assert!(!b.contains("4611686018427387904"), "{levels} levels: decided");
    }
}

/// The same bounds over the elements of a slice (the reader's bytes are
/// `index(xs, k)` atoms).
#[test]
fn varint_value_bounds_on_slice_elements() {
    for levels in [2usize, 5, 8] {
        let mut v = "0u64".to_string();
        for k in 0..levels {
            v = format!("({v} | (((xs[{k}] & 0x7f) as u64) << {}u32))", 7 * k);
        }
        let src = format!("{HEADER}\npub fn bound(t: bool, xs: &[u8]) -> u8 {{\n    if xs.len() < 10 {{ return 0u8; }}\n    let v = {v};\n    if t {{ if v <= 4611686018427387904 {{ 1u8 }} else {{ 2u8 }} }} else {{ 0u8 }}\n}}\n");
        let t = std::time::Instant::now();
        let em = optimize(&src);
        let b = body_of(&em.code, "bound");
        println!("{levels} levels ({:?})", t.elapsed());
        assert!(!b.contains("4611686018427387904"), "{levels} levels: decided\n{b}");
    }
}

/// The tenth byte of a `u64` varint: `h < 2 ∧ h ≠ 0` sets bit 63, so the
/// accumulated value exceeds `2^62` whatever the other groups are.
#[test]
fn tenth_group_exceeds_the_range() {
    let src = format!(
        "{HEADER}
pub fn tenth(h: u8, acc: u64) -> u8 {{
    if h < 2 && h != 0 {{
        let v = acc | (((h & 0x7f) as u64) << 63u32);
        if v <= 4611686018427387904 {{ 1u8 }} else {{ 2u8 }}
    }} else {{ 0u8 }}
}}
"
    );
    let em = optimize(&src);
    let b = body_of(&em.code, "tenth");
    println!("{b}");
    assert!(!b.contains("4611686018427387904"), "decided false:\n{b}");
}

/// The same with the byte an element read (a generalized leaf with facts).
#[test]
fn tenth_group_of_an_element_exceeds_the_range() {
    let src = format!(
        "{HEADER}
pub fn tenth2(xs: &[u8; 10], acc: u64) -> u8 {{
    let h = xs[9];
    if h < 128 {{
        if h < 2 && h != 0 {{
            let v = acc | (((h & 0x7f) as u64) << 63u32);
            if v <= 4611686018427387904 {{ 1u8 }} else {{ 2u8 }}
        }} else {{ 0u8 }}
    }} else {{ 3u8 }}
}}
"
    );
    let em = optimize(&src);
    let b = body_of(&em.code, "tenth2");
    println!("{b}");
    assert!(!b.contains("4611686018427387904"), "decided false:\n{b}");
}


/// Decided checked arithmetic (`Step::Checked`): under `a < 100`,
/// `a.checked_add(1)` is `Some(a + 1)` by the lemma `u64::checked_add_some`
/// and `b.checked_sub(1)` under `b >= 1` is `Some(b - 1)`; the residual has
/// no overflow test left.
#[test]
fn decided_checked_arithmetic_is_rewritten_by_its_lemma() {
    let src = format!(
        "{HEADER}
pub fn bump(a: u64, b: u32, t: bool) -> Option<u64> {{
    if a < 100 && b >= 1 && t {{
        match a.checked_add(1) {{
            Some(x) => match b.checked_sub(1) {{ Some(y) => Some(x ^ (y as u64)), None => None }},
            None => None,
        }}
    }} else {{
        None
    }}
}}
"
    );
    let em = optimize(&src);
    show(&em);
    let b = body_of(&em.code, "bump");
    println!("{b}");
    assert!(driven(&em, "crate::bump"));
    assert!(!b.contains("checked_add") && !b.contains("checked_sub"), "decided: {b}");
}

/// An undecided checked call inside a value (not at the head of a match)
/// stays a call and prints as the method.
#[test]
fn undecided_checked_call_in_a_value_prints() {
    let src = format!(
        "{HEADER}
pub fn pair(a: u64, b: u64, t: bool) -> (Option<u64>, u64) {{
    if t {{ (a.checked_add(b), 1u64) }} else {{ (None, 0u64) }}
}}
"
    );
    let em = optimize(&src);
    show(&em);
    let b = body_of(&em.code, "pair");
    println!("{b}");
    assert!(b.contains("checked_add"), "{b}");
}

/// An undecided checked call at the head of a match, in a function that
/// branches anyway (a test on whether an argument's arithmetic overflows):
/// the driver keeps the call and splits on its result, so the residual
/// prints `match a.checked_add(1u64) { .. }`. (Before, the split was on the
/// call's unfolded overflow test over `Int`, which no exec expression
/// prints, and the function was not specialized.) The same for the other
/// checked operations (`checked_mul`, `checked_div`, ..).
#[test]
fn undecided_checked_call_at_a_match_prints() {
    let src = format!(
        "{HEADER}
pub fn bump_if(a: u64, t: bool) -> Option<u64> {{
    if t {{ match a.checked_add(1) {{ Some(x) => Some(x ^ 1u64), None => None }} }} else {{ None }}
}}

pub fn scale_if(a: u32, b: u32, t: bool) -> Option<u32> {{
    if t {{ match a.checked_mul(b) {{ Some(x) => x.checked_div(b), None => None }} }} else {{ None }}
}}
"
    );
    let em = optimize(&src);
    show(&em);
    let b = body_of(&em.code, "bump_if");
    println!("{b}");
    assert!(driven(&em, "crate::bump_if"));
    assert!(b.contains("checked_add"), "{b}");
    let b = body_of(&em.code, "scale_if");
    println!("{b}");
    assert!(driven(&em, "crate::scale_if"));
    assert!(b.contains("checked_mul"), "{b}");
}

/// A checked sum whose checks never fail (corpus P10): folded into a loop
/// helper with the bound invariant `acc <= (65536 - xs.len()) * (2^32 - 1)`
/// (plan O5, design §6.6); the helper's `checked_add` is decided by the
/// invariant, the caller calls the helper.
#[test]
fn checked_sum_is_folded_with_a_bound_invariant() {
    let src = format!(
        "{HEADER}
#[requires(xs.len() <= 65536)]
#[decreases(xs.len())]
fn sum_checked_go(xs: &[u32], acc: u64) -> Option<u64> {{
    match xs {{
        [] => Some(acc),
        [h, t @ ..] => match acc.checked_add(*h as u64) {{
            None => None,
            Some(a) => sum_checked_go(t, a),
        }},
    }}
}}

pub fn sum_small(xs: &[u32]) -> Option<u64> {{
    if xs.len() > 65536 {{
        return None;
    }}
    sum_checked_go(xs, 0)
}}
"
    );
    let em = optimize(&src);
    show(&em);
    let caller = body_of(&em.code, "sum_small");
    let helper = body_of(&em.code, "sum_checked_go__fold");
    println!("{caller}\n{helper}");
    assert!(driven(&em, "crate::sum_small"));
    assert!(caller.contains("sum_checked_go__fold(l0_xs, 0u64)"), "{caller}");
    assert!(helper.contains("loop") && !helper.contains("checked_add"), "{helper}");
}
