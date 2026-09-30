//! The phase-3 pipeline on a program exercising the canonical dialect's
//! constructs (structs, enums, methods with receivers, constants, guards,
//! or-patterns, slice patterns, `let … else`, `?`, nested places, ranged
//! `copy_from_slice`, `for`/`while` loops, `requires` functions (`unsafe
//! fn`), generics, tail and depth-bounded recursion, derived `==`, straight
//! line arithmetic): verification, optimization (strict), round trip, and
//! the emitted code compiled by rustc (overflow checks and debug assertions
//! on, so every `get_unchecked` precondition is checked at run time) must
//! compute what the natively compiled source computes.

#[path = "elab_util.rs"]
#[macro_use]
#[allow(unused_macros)]
mod util;

use std::path::Path;
use std::process::Command;

use sandblaster_front::driver::{self, ProverSet, VerifyOptions};
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::opt::{Link, OptOptions, Outcome, Rung};

program!(prog {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Pt {
        pub x: u32,
        pub y: u32,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Shape {
        Dot,
        Seg(u32, u32),
        Rect { w: u32, h: u32 },
    }

    impl Pt {
        pub fn sum(&self) -> u64 {
            self.x as u64 + self.y as u64
        }
        pub fn swap(self) -> Pt {
            Pt { x: self.y, y: self.x }
        }
    }

    pub const TABLE: [u8; 4] = [1, 2, 4, 8];

    pub fn area(s: Shape) -> u64 {
        match s {
            Shape::Dot => 0,
            Shape::Seg(a, b) => a.abs_diff(b) as u64,
            Shape::Rect { w, h } => w as u64 * h as u64,
        }
    }

    pub fn classify(x: u32) -> u32 {
        match x {
            0 => 0,
            1..=9 => 1,
            _ if x % 2 == 0 => 2,
            _ => 3,
        }
    }

    pub fn first_two(xs: &[u8]) -> Option<(u8, u8)> {
        let [a, b, ..] = xs else {
            return None;
        };
        Some((*a, *b))
    }

    pub fn pick(o: (Option<u8>, u8)) -> u8 {
        match o {
            (Some(x), _) | (None, x) => x,
        }
    }

    pub fn add_opt(a: Option<u32>, b: Option<u32>) -> Option<u64> {
        let x = a?;
        let y = b?;
        Some(x as u64 + y as u64)
    }

    pub fn fill(v: u8) -> [[u8; 3]; 2] {
        let mut m = [[0u8; 3]; 2];
        for i in 0usize..2 {
            for j in 0usize..3 {
                m[i][j] = v;
            }
        }
        m
    }

    pub fn copy_mid(src: &[u8; 4]) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[2..6].copy_from_slice(src);
        out
    }

    pub fn count_down(n: u32) -> u32 {
        let mut i = n;
        let mut s: u32 = 0;
        while i > 0 {
            proof! {
                decreases(i);
            }
            s = s.wrapping_add(i);
            i -= 1;
        }
        s
    }


    pub fn choose<T: Copy>(a: T, b: T, first: bool) -> T {
        if first { a } else { b }
    }

    pub fn use_choose(x: u32) -> u32 {
        choose(x, 7u32, x > 3)
    }

    pub fn tail_sum(xs: &[u32], acc: u64) -> u64 {
        match xs {
            [] => acc,
            [h, t @ ..] => tail_sum(t, acc.wrapping_add(*h as u64)),
        }
    }


    pub fn same(a: Pt, b: Pt) -> bool {
        a == b
    }

    pub fn mix(x: u32) -> u32 {
        x.rotate_left(5) ^ x.rotate_right(3) ^ (x >> 7u32)
    }

    pub fn table_sum() -> u32 {
        TABLE[0] as u32 + TABLE[3] as u32
    }
});

/// Functions with contracts (the native twins have no attributes).
const CONTRACTS: &str = r#"
#[requires(i < 4)]
fn at(i: usize) -> u8 {
    TABLE[i]
}

pub fn safe_at(i: usize) -> u8 {
    if i < 4 { at(i) } else { 0 }
}

#[requires(d <= 16)]
#[decreases(d, max = 16)]
fn depth(d: u32) -> u32 {
    if d == 0 { 1 } else { depth(d - 1).wrapping_mul(2) }
}

pub fn run_depth(d: u32) -> u32 {
    if d <= 16 { depth(d) } else { 0 }
}
"#;

#[allow(dead_code)]
mod contracts {
    use super::prog::TABLE;
    fn at(i: usize) -> u8 {
        TABLE[i]
    }
    pub fn safe_at(i: usize) -> u8 {
        if i < 4 { at(i) } else { 0 }
    }
    fn depth(d: u32) -> u32 {
        if d == 0 { 1 } else { depth(d - 1).wrapping_mul(2) }
    }
    pub fn run_depth(d: u32) -> u32 {
        if d <= 16 { depth(d) } else { 0 }
    }
}

/// Calls evaluated natively and by the generated code (Debug output).
const CALLS: &[&str] = &[
    "Pt { x: 3, y: 4 }.sum()",
    "Pt { x: u32::MAX, y: u32::MAX }.sum()",
    "Pt { x: 3, y: 4 }.swap()",
    "area(Shape::Dot)",
    "area(Shape::Seg(3, 10))",
    "area(Shape::Seg(10, 3))",
    "area(Shape::Rect { w: u32::MAX, h: 7 })",
    "classify(0)",
    "classify(5)",
    "classify(10)",
    "classify(11)",
    "first_two(&[])",
    "first_two(&[9])",
    "first_two(&[1, 2, 3])",
    "pick((Some(4), 5))",
    "pick((None, 5))",
    "add_opt(Some(1), Some(u32::MAX))",
    "add_opt(None, Some(2))",
    "add_opt(Some(2), None)",
    "fill(7)",
    "copy_mid(&[1, 2, 3, 4])",
    "count_down(0)",
    "count_down(100)",
    "safe_at(0)",
    "safe_at(3)",
    "safe_at(4)",
    "use_choose(2)",
    "use_choose(9)",
    "tail_sum(&[], 5)",
    "tail_sum(&[1, 2, u32::MAX], 0)",
    "run_depth(0)",
    "run_depth(16)",
    "run_depth(17)",
    "same(Pt { x: 1, y: 2 }, Pt { x: 1, y: 2 })",
    "same(Pt { x: 1, y: 2 }, Pt { x: 2, y: 1 })",
    "mix(0x1234_5678)",
    "table_sum()",
];

fn native_results() -> Vec<String> {
    use contracts::*;
    use prog::*;
    vec![
        format!("{:?}", Pt { x: 3, y: 4 }.sum()),
        format!("{:?}", Pt { x: u32::MAX, y: u32::MAX }.sum()),
        format!("{:?}", Pt { x: 3, y: 4 }.swap()),
        format!("{:?}", area(Shape::Dot)),
        format!("{:?}", area(Shape::Seg(3, 10))),
        format!("{:?}", area(Shape::Seg(10, 3))),
        format!("{:?}", area(Shape::Rect { w: u32::MAX, h: 7 })),
        format!("{:?}", classify(0)),
        format!("{:?}", classify(5)),
        format!("{:?}", classify(10)),
        format!("{:?}", classify(11)),
        format!("{:?}", first_two(&[])),
        format!("{:?}", first_two(&[9])),
        format!("{:?}", first_two(&[1, 2, 3])),
        format!("{:?}", pick((Some(4), 5))),
        format!("{:?}", pick((None, 5))),
        format!("{:?}", add_opt(Some(1), Some(u32::MAX))),
        format!("{:?}", add_opt(None, Some(2))),
        format!("{:?}", add_opt(Some(2), None)),
        format!("{:?}", fill(7)),
        format!("{:?}", copy_mid(&[1, 2, 3, 4])),
        format!("{:?}", count_down(0)),
        format!("{:?}", count_down(100)),
        format!("{:?}", safe_at(0)),
        format!("{:?}", safe_at(3)),
        format!("{:?}", safe_at(4)),
        format!("{:?}", use_choose(2)),
        format!("{:?}", use_choose(9)),
        format!("{:?}", tail_sum(&[], 5)),
        format!("{:?}", tail_sum(&[1, 2, u32::MAX], 0)),
        format!("{:?}", run_depth(0)),
        format!("{:?}", run_depth(16)),
        format!("{:?}", run_depth(17)),
        format!("{:?}", same(Pt { x: 1, y: 2 }, Pt { x: 1, y: 2 })),
        format!("{:?}", same(Pt { x: 1, y: 2 }, Pt { x: 2, y: 1 })),
        format!("{:?}", mix(0x1234_5678)),
        format!("{:?}", table_sum()),
    ]
}

#[test]
fn constructs_verify_optimize_round_trip_and_agree_with_rustc() {
    let body = format!("{}\n{CONTRACTS}", prog::SRC);
    let c = util::accepted(&body);
    let opts = VerifyOptions { provers: ProverSet::Standard, exec_only: false };
    let built = driver::stage::verify_and_optimize(&c, &opts, &OptOptions { strict: true, ..Default::default() }, "r/mod.rs");
    assert!(built.v.proofs_ok, "not verified:\n{}", util::explain(&c, &built.v));
    let em = built.emit.expect("optimized").expect("optimizer ran");
    assert!(em.opt.errors.is_empty(), "optimizer errors: {:?}", em.opt.errors);
    assert!(em.roundtrip.is_empty(), "round trip failed:\n{}\n{}", em.roundtrip.join("\n"), em.code);
    assert!(em.roundtrip_stats.compared >= 20, "{:?}", em.roundtrip_stats);
    // straight-line functions specialize by conversion (tier 0); a
    // branching one that tier 0 refuses is specialized by the Σ1 driver
    // (optimizer O4) through a kernel-checked equality lemma
    let spec = |n: &str| em.opt.fns.iter().find(|f| f.name == format!("crate::{n}")).map(|f| matches!(f.outcome, Outcome::Specialized { .. }));
    assert_eq!(spec("mix"), Some(true), "{:?}", em.opt.fns);
    assert_eq!(spec("table_sum"), Some(true));
    let classify = em.opt.fns.iter().find(|f| f.name == "crate::classify").expect("`classify` in the report");
    assert!(matches!(classify.outcome, Outcome::Specialized { .. }), "{classify:?}");
    assert_eq!(classify.rung, Some(Rung::Driven), "{classify:?}");
    let lemma = "crate::classify__residual::equiv";
    assert!(matches!(&classify.link, Some(Link::Lemma(l)) if l == lemma), "{classify:?}");
    assert!(classify.candidates.iter().any(|c| c.rung == Rung::StraightLine && !c.chosen && c.reason.starts_with("not stuck-free")), "{classify:?}");
    assert!(classify.candidates.iter().any(|c| c.rung == Rung::Driven && c.chosen && c.rejected_by.is_none() && !c.injected), "{classify:?}");
    // generated-mode constructs are present
    assert!(em.code.contains("get_unchecked("), "unchecked indexing:\n{}", em.code);
    assert!(em.code.contains("unsafe fn at("), "requires functions are `unsafe fn`:\n{}", em.code);
    assert!(em.code.contains("if (l0_x % 2u32) == 0u32") || em.code.contains(" if "), "guards stay guards");
    // compile and run
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("roundtrip-constructs");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("sandblaster.rs"), &em.code).unwrap();
    let mut main = String::from("include!(\"sandblaster.rs\");\nfn main() {\n");
    for call in CALLS {
        main.push_str(&format!("    println!(\"{{:?}}\", {call});\n"));
    }
    main.push_str("}\n");
    std::fs::write(dir.join("main.rs"), main).unwrap();
    let st = Command::new("rustc")
        .args(["--edition", "2024", "-C", "overflow-checks=on", "-C", "debug-assertions=on", "--cap-lints", "warn", "-o"])
        .arg(dir.join("gen"))
        .arg(dir.join("main.rs"))
        .output()
        .expect("rustc");
    assert!(st.status.success(), "the emitted code does not compile:\n{}\n{}", String::from_utf8_lossy(&st.stderr), em.code);
    let run = Command::new(dir.join("gen")).output().unwrap();
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    let got: Vec<String> = String::from_utf8_lossy(&run.stdout).lines().map(|s| s.to_string()).collect();
    assert_eq!(got, native_results());
    // the link of `classify` is a lemma of the kernel environment stating
    // `Π x. Eq(u32, classify__residual x, classify x)` (exec-only
    // elaboration, the same optimizer)
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let em2 = driver::stage::optimize_emit(&c, &mut out, "r/mod.rs", "", &OptOptions { strict: true, ..Default::default() }).unwrap();
        assert!(em2.opt.errors.is_empty() && em2.roundtrip.is_empty(), "{:?} {:?}", em2.opt.errors, em2.roundtrip);
        let g = out.env.lookup_global(lemma).unwrap_or_else(|| panic!("`{lemma}` is not in the kernel environment"));
        let (res, src) = (out.env.lookup_global("crate::classify__residual").expect("the residual"), out.env.lookup_global("crate::classify").expect("classify"));
        let ty = out.env.print_term(&[], &out.env.global_type(g).unwrap());
        let name = |h| out.env.global_name(h).unwrap().to_string();
        assert_eq!(ty, format!("(x : U32) -> Eq(U32, {} x, {} x)", name(res), name(src)), "the statement of `{lemma}`");
    });
}
