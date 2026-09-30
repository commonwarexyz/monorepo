//! Lane targets and the tile table of the lane functor (optimizer design
//! §13.3; plan O10).
//!
//! A **lane target** is a vector register of `lanes` × `u32` lanes, its
//! typed view, lane constructors and maps (core helpers of
//! `sandblaster-targets/core`), and the load/store helpers the lifted
//! kernel packs and unpacks its lanes with.
//!
//! A **tile** maps a scalar pattern over at most three holes — one word
//! operation, or a bitwise expression over at most three inputs — to a
//! vector expression. Each tile has a **lanewise lemma**
//!
//! ```text
//! lanes::<target>::<key> : Π (a b c : V). Eq(Array U32 N, view(E(a, b, c)),
//!                                            mapK (λ x y z. pat) (view a) (view b) (view c))
//! ```
//!
//! proven once by a small `bvrefl` on symbolic vectors (the intrinsic models
//! unfold on symbolic data in the BvRefl mode). This module only produces
//! the text; `super::lift` loads it (the kernel checks it) and uses it.

use std::fmt::Write as _;

/// A lane target.
#[derive(Debug)]
pub struct LaneTarget {
    /// Short name, used in item and lemma names (`avx512_x16`).
    pub name: &'static str,
    /// `x86_64` / `aarch64`.
    pub arch: &'static str,
    /// Lanes per vector.
    pub lanes: usize,
    /// `#[target_feature(enable = ..)]` of the lifted function.
    pub features: &'static [&'static str],
    /// Core type of a vector (`Array U8 64usize`).
    pub vty: &'static str,
    /// The view `V → Array U32 N`, or `None` when the vector is the lane
    /// array itself (NEON `uint32x4_t`).
    pub view: Option<&'static str>,
    /// Its inverse `Array U32 N → V` (with the view).
    pub from: Option<&'static str>,
    /// Lane-array constructor (`x86_64::u32x16 x0 .. x15`).
    pub ctor: &'static str,
    /// `map`, `map2`, `map3` over the lane arrays.
    pub maps: [&'static str; 3],
    /// Core global of the load helper (`[u32; N]` → vector).
    pub load: &'static str,
    /// Core global of the store helper (vector → `[u32; N]`).
    pub store: &'static str,
    /// Instruction family of the operations.
    pub isa: Isa,
}

/// The instruction family of a target's tiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isa {
    Avx512,
    Avx2,
    Neon,
}

/// AVX-512F, 16 lanes (`__m512i`): `vpaddd`, `vpxord`, `vprord`,
/// `vpternlogd` (design §13.3).
pub static AVX512_X16: LaneTarget = LaneTarget {
    name: "avx512_x16",
    arch: "x86_64",
    lanes: 16,
    features: &["avx512f"],
    vty: "Array U8 64usize",
    view: Some("x86_64::view_u32x16"),
    from: Some("x86_64::from_u32x16"),
    ctor: "x86_64::u32x16",
    maps: ["x86_64::map_u32x16", "x86_64::map2_u32x16", "x86_64::map3_u32x16"],
    load: "x86_64::load_u32x16",
    store: "x86_64::store_u32x16",
    isa: Isa::Avx512,
};

/// AVX2, 8 lanes (`__m256i`): rotates as two shifts and an `or`.
pub static AVX2_X8: LaneTarget = LaneTarget {
    name: "avx2_x8",
    arch: "x86_64",
    lanes: 8,
    features: &["avx2"],
    vty: "Array U8 32usize",
    view: Some("x86_64::view_u32x8"),
    from: Some("x86_64::from_u32x8"),
    ctor: "x86_64::u32x8",
    maps: ["x86_64::map_u32x8", "x86_64::map2_u32x8", "x86_64::map3_u32x8"],
    load: "x86_64::load_u32x8",
    store: "x86_64::store_u32x8",
    isa: Isa::Avx2,
};

/// NEON, 4 lanes (`uint32x4_t`): `vbslq_u32` for Ch and Maj.
pub static NEON_X4: LaneTarget = LaneTarget {
    name: "neon_x4",
    arch: "aarch64",
    lanes: 4,
    features: &["neon"],
    vty: "Array U32 4usize",
    view: None,
    from: None,
    ctor: "aarch64::u32x4",
    maps: ["aarch64::map_u32x4", "aarch64::map2_u32x4", "aarch64::map3_u32x4"],
    load: "aarch64::vld1q_u32",
    store: "aarch64::vst1q_u32",
    isa: Isa::Neon,
};

/// All targets, widest first.
pub static TARGETS: [&LaneTarget; 3] = [&AVX512_X16, &AVX2_X8, &NEON_X4];

/// The lane targets of an architecture (`x86_64` / `aarch64`).
pub fn targets_for(arch: &str) -> Vec<&'static LaneTarget> {
    TARGETS.iter().copied().filter(|t| t.arch == arch).collect()
}

/// A target by name.
pub fn target(name: &str) -> Option<&'static LaneTarget> {
    TARGETS.iter().copied().find(|t| t.name == name)
}

/// A liftable `u32` operation (literal amounts are part of the operation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Op {
    Add,
    Sub,
    Xor,
    And,
    Or,
    Not,
    Rotr(u32),
    Rotl(u32),
    Shr(u32),
    Shl(u32),
}

impl Op {
    pub fn arity(self) -> usize {
        match self {
            Op::Add | Op::Sub | Op::Xor | Op::And | Op::Or => 2,
            _ => 1,
        }
    }

    /// Whether the operation is bitwise (a truth table of its inputs).
    pub fn bitwise(self) -> bool {
        matches!(self, Op::Xor | Op::And | Op::Or | Op::Not)
    }

    /// Whether `isa` has this operation (every lifted node needs one).
    pub fn available(self, isa: Isa) -> bool {
        match self {
            Op::Sub => isa == Isa::Avx512,
            Op::Rotr(k) | Op::Rotl(k) => k < 32,
            Op::Shr(k) | Op::Shl(k) => k < 32,
            _ => true,
        }
    }

    /// A short key (`rotr7`).
    pub fn key(self) -> String {
        match self {
            Op::Add => "add".into(),
            Op::Sub => "sub".into(),
            Op::Xor => "xor".into(),
            Op::And => "and".into(),
            Op::Or => "or".into(),
            Op::Not => "not".into(),
            Op::Rotr(k) => format!("rotr{k}"),
            Op::Rotl(k) => format!("rotl{k}"),
            Op::Shr(k) => format!("shr{k}"),
            Op::Shl(k) => format!("shl{k}"),
        }
    }

    /// The scalar primitive in core text, on argument texts.
    pub fn scalar(self, a: &str, b: &str) -> String {
        match self {
            Op::Add => format!("#wadd_u32({a}, {b})"),
            Op::Sub => format!("#wsub_u32({a}, {b})"),
            Op::Xor => format!("#xor_u32({a}, {b})"),
            Op::And => format!("#and_u32({a}, {b})"),
            Op::Or => format!("#or_u32({a}, {b})"),
            Op::Not => format!("#not_u32({a})"),
            Op::Rotr(k) => format!("#rotr_u32({a}, {k}u32)"),
            Op::Rotl(k) => format!("#rotl_u32({a}, {k}u32)"),
            Op::Shr(k) => format!("#wshr_u32({a}, {k}u32)"),
            Op::Shl(k) => format!("#wshl_u32({a}, {k}u32)"),
        }
    }

    /// Evaluates the operation on concrete words (truth tables).
    pub fn eval(self, a: u32, b: u32) -> u32 {
        match self {
            Op::Add => a.wrapping_add(b),
            Op::Sub => a.wrapping_sub(b),
            Op::Xor => a ^ b,
            Op::And => a & b,
            Op::Or => a | b,
            Op::Not => !a,
            Op::Rotr(k) => a.rotate_right(k),
            Op::Rotl(k) => a.rotate_left(k),
            Op::Shr(k) => a >> k,
            Op::Shl(k) => a << k,
        }
    }
}

/// A scalar expression over tile inputs `In(0..3)`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SExpr {
    In(usize),
    Op(Op, Vec<SExpr>),
}

impl SExpr {
    /// Core text with inputs named `x0`, `x1`, `x2`.
    pub fn text(&self) -> String {
        match self {
            SExpr::In(i) => format!("x{i}"),
            SExpr::Op(op, args) => {
                let a = args.first().map(|e| e.text()).unwrap_or_default();
                let b = args.get(1).map(|e| e.text()).unwrap_or_default();
                op.scalar(&a, &b)
            }
        }
    }

    /// Evaluates the expression with input `i` = `ins[i]`.
    pub fn eval(&self, ins: &[u32]) -> u32 {
        match self {
            SExpr::In(i) => ins[*i],
            SExpr::Op(op, args) => {
                let a = args.first().map(|e| e.eval(ins)).unwrap_or(0);
                let b = args.get(1).map(|e| e.eval(ins)).unwrap_or(0);
                op.eval(a, b)
            }
        }
    }

    /// The number of operations.
    pub fn ops(&self) -> usize {
        match self {
            SExpr::In(_) => 0,
            SExpr::Op(_, args) => 1 + args.iter().map(|a| a.ops()).sum::<usize>(),
        }
    }

    /// A compact key (`xor(and(x0,x1),x2)`), for tile names.
    pub fn key(&self) -> String {
        match self {
            SExpr::In(i) => format!("x{i}"),
            SExpr::Op(op, args) => format!("{}({})", op.key(), args.iter().map(|a| a.key()).collect::<Vec<_>>().join(",")),
        }
    }

    /// The truth table of a bitwise expression: bit `k` is the value for
    /// inputs `(k >> 2) & 1`, `(k >> 1) & 1`, `k & 1` (the `vpternlogd`
    /// immediate, input 0 = its first source).
    pub fn truth_table(&self) -> u8 {
        (self.eval(&[0xf0, 0xcc, 0xaa]) & 0xff) as u8
    }
}

/// A tile: a scalar pattern over `arity` inputs, lowered on one target.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tile {
    pub pat: SExpr,
    pub arity: usize,
}

impl Tile {
    /// A one-operation tile.
    pub fn op(op: Op) -> Tile {
        Tile { pat: SExpr::Op(op, (0..op.arity()).map(SExpr::In).collect()), arity: op.arity() }
    }

    /// The lemma key on `t`: the operation, or a bitwise expression's
    /// truth table and shape.
    pub fn key(&self, t: &LaneTarget) -> String {
        match &self.pat {
            SExpr::Op(op, args) if args.iter().enumerate().all(|(i, a)| *a == SExpr::In(i)) && args.len() == op.arity() => op.key(),
            p if t.isa == Isa::Avx512 => format!("tt{:02x}_{}", p.truth_table(), sanitize(&p.key())),
            p => format!("f_{}", sanitize(&p.key())),
        }
    }

    /// The lanewise lemma's global name.
    pub fn lemma_name(&self, t: &LaneTarget) -> String {
        format!("lanes::{}::{}", t.name, self.key(t))
    }

    /// `fun (x0 : U32) .. => pat`.
    pub fn pat_text(&self) -> String {
        let mut s = String::from("fun");
        for i in 0..self.arity {
            let _ = write!(s, " (x{i} : U32)");
        }
        let _ = write!(s, " => {}", self.pat.text());
        s
    }

    /// The vector expression on argument texts (`a`, `b`, `c`).
    pub fn vexpr(&self, t: &LaneTarget, args: &[String]) -> String {
        match &self.pat {
            SExpr::Op(op, xs) if xs.iter().enumerate().all(|(i, a)| *a == SExpr::In(i)) && xs.len() == op.arity() => vop(t, *op, args),
            p => {
                if t.isa == Isa::Avx512 {
                    let a = |i: usize| args.get(i).or(args.first()).cloned().unwrap_or_default();
                    format!("x86_64::_mm512_ternarylogic_epi32 {}u32 .refl(Bool, true) ({}) ({}) ({})", p.truth_table(), a(0), a(1), a(2))
                } else if let Some(s) = formula(t, p.truth_table(), args) {
                    s
                } else {
                    vexpr_of(t, p, args)
                }
            }
        }
    }

    /// Vector instructions the tile costs on `t` (for reports).
    pub fn vector_ops(&self, t: &LaneTarget) -> usize {
        match &self.pat {
            SExpr::Op(op, _) if self.pat.ops() == 1 => op_cost(t, *op),
            p if t.isa == Isa::Avx512 => {
                let _ = p;
                1
            }
            p => match p.truth_table() {
                0xca if t.isa == Isa::Neon => 1,
                0xe8 if t.isa == Isa::Neon => 2,
                0xca if t.isa == Isa::Avx2 => 3,
                0xe8 if t.isa == Isa::Avx2 => 4,
                0x96 => 2,
                _ => expr_cost(t, p),
            },
        }
    }

    /// The lemma text: a `def[lemma]` proven by `bvrefl`. With a byte
    /// view (x86), `bvrefl` runs on the **lane words**: the word lemma
    /// `<name>::w : Π x̄ : Array U32 N. Eq(view(E(from x̄)), mapK pat x̄)`
    /// (its atoms are the words, so the truth tables of `vpternlogd` and of
    /// the pattern meet in bvnorm's rule 5), and the vector lemma is its
    /// instance at `x̄ = view ā` (`from (view a)` is `a` by conversion: the
    /// §5.7 byte rules on the η-expanded bytes of `a`).
    pub fn lemma_text(&self, t: &LaneTarget) -> String {
        let names = ["a", "b", "c"];
        let args: Vec<String> = names[..self.arity].iter().map(|s| s.to_string()).collect();
        let view = |x: &str| match t.view {
            Some(v) => format!("{v} ({x})"),
            None => x.to_string(),
        };
        let lt = format!("Array U32 {}usize", t.lanes);
        let map = t.maps[self.arity - 1];
        let name = self.lemma_name(t);
        let header = format!("-- {}: view({}) = lanewise {}\n", self.key(t), self.vexpr(t, &args), self.pat.text());
        match t.from {
            None => {
                let lhs = self.vexpr(t, &args);
                let rhs = format!("{map} ({}) {}", self.pat_text(), args.iter().map(|a| format!("({a})")).collect::<Vec<_>>().join(" "));
                let binders: String = args.iter().map(|a| format!("({a} : {}) ", t.vty)).collect();
                let pi: String = args.iter().map(|a| format!("({a} : {}) -> ", t.vty)).collect();
                format!("{header}def[lemma] {name} : {pi}Eq({lt}, {lhs}, {rhs}) :=\n  fun {binders}=> bvrefl({lt}, {lhs}, {rhs})\n")
            }
            Some(from) => {
                let ws: Vec<String> = (0..self.arity).map(|i| format!("w{i}")).collect();
                let froms: Vec<String> = ws.iter().map(|w| format!("{from} {w}")).collect();
                let wl = view(&self.vexpr(t, &froms));
                let wr = format!("{map} ({}) {}", self.pat_text(), ws.iter().map(|w| format!("({w})")).collect::<Vec<_>>().join(" "));
                let wb: String = ws.iter().map(|w| format!("({w} : {lt}) ")).collect();
                let wp: String = ws.iter().map(|w| format!("({w} : {lt}) -> ")).collect();
                let lhs = view(&self.vexpr(t, &args));
                let rhs = format!("{map} ({}) {}", self.pat_text(), args.iter().map(|a| format!("({})", view(a))).collect::<Vec<_>>().join(" "));
                let binders: String = args.iter().map(|a| format!("({a} : {}) ", t.vty)).collect();
                let pi: String = args.iter().map(|a| format!("({a} : {}) -> ", t.vty)).collect();
                let inst: String = args.iter().map(|a| format!(" ({})", view(a))).collect();
                format!(
                    "{header}def[lemma] {name}::w : {wp}Eq({lt}, {wl}, {wr}) :=\n  fun {wb}=> bvrefl({lt}, {wl}, {wr})\n\n\
                     def[lemma] {name} : {pi}Eq({lt}, {lhs}, {rhs}) :=\n  fun {binders}=> {name}::w{inst}\n"
                )
            }
        }
    }
}

/// The boundary lemmas of a target: `view(load a) = a` and
/// `store v = view v`.
pub fn boundary_lemmas(t: &LaneTarget) -> String {
    let lt = format!("Array U32 {}usize", t.lanes);
    let view = |x: &str| match t.view {
        Some(v) => format!("{v} ({x})"),
        None => x.to_string(),
    };
    format!(
        "-- load: view(load a) = a\ndef[lemma, opaque] lanes::{n}::load : (a : {lt}) -> Eq({lt}, {vl}, a) :=\n  fun (a : {lt}) => bvrefl({lt}, {vl}, a)\n\n\
         -- store: store v = view v\ndef[lemma, opaque] lanes::{n}::store : (v : {vt}) -> Eq({lt}, {st} v, {vv}) :=\n  fun (v : {vt}) => bvrefl({lt}, {st} v, {vv})\n\n\
         -- a node of the lane proof: a vector, its lanes and the fact relating them\n\
         def[prelude] lanes::{n}::node : Type :=\n  Sigma (v : {vt}), Sigma (l : {lt}), .Eq({lt}, {vw}, l)\n",
        n = t.name,
        vl = view(&format!("{} a", t.load)),
        vt = t.vty,
        st = t.store,
        vv = view("v"),
        vw = view("v"),
    )
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect::<String>().trim_matches('_').to_string()
}

/// One operation on `t`.
fn vop(t: &LaneTarget, op: Op, a: &[String]) -> String {
    let x = |i: usize| a.get(i).cloned().unwrap_or_default();
    match t.isa {
        Isa::Avx512 => match op {
            Op::Add => format!("x86_64::_mm512_add_epi32 ({}) ({})", x(0), x(1)),
            Op::Sub => format!("x86_64::_mm512_sub_epi32 ({}) ({})", x(0), x(1)),
            Op::Xor => format!("x86_64::_mm512_xor_si512 ({}) ({})", x(0), x(1)),
            Op::And => format!("x86_64::_mm512_and_si512 ({}) ({})", x(0), x(1)),
            Op::Or => format!("x86_64::_mm512_or_si512 ({}) ({})", x(0), x(1)),
            Op::Not => format!("x86_64::_mm512_ternarylogic_epi32 85u32 .refl(Bool, true) ({0}) ({0}) ({0})", x(0)),
            Op::Rotr(k) => format!("x86_64::_mm512_ror_epi32 {k}u32 .refl(Bool, true) ({})", x(0)),
            Op::Rotl(k) => format!("x86_64::_mm512_rol_epi32 {k}u32 .refl(Bool, true) ({})", x(0)),
            Op::Shr(k) => format!("x86_64::_mm512_srli_epi32 {k}u32 .refl(Bool, true) ({})", x(0)),
            Op::Shl(k) => format!("x86_64::_mm512_slli_epi32 {k}u32 .refl(Bool, true) ({})", x(0)),
        },
        Isa::Avx2 => match op {
            Op::Add => format!("x86_64::_mm256_add_epi32 ({}) ({})", x(0), x(1)),
            Op::Sub => unreachable!("no AVX2 sub tile"),
            Op::Xor => format!("x86_64::_mm256_xor_si256 ({}) ({})", x(0), x(1)),
            Op::And => format!("x86_64::_mm256_and_si256 ({}) ({})", x(0), x(1)),
            Op::Or => format!("x86_64::_mm256_or_si256 ({}) ({})", x(0), x(1)),
            Op::Not => format!("x86_64::_mm256_xor_si256 ({}) ({})", x(0), ones(t)),
            Op::Rotr(k) => avx2_rotr(k, &x(0)),
            Op::Rotl(k) => avx2_rotr((32 - k) % 32, &x(0)),
            Op::Shr(k) => format!("x86_64::_mm256_srli_epi32 {k}u32 .refl(Bool, true) ({})", x(0)),
            Op::Shl(k) => format!("x86_64::_mm256_slli_epi32 {k}u32 .refl(Bool, true) ({})", x(0)),
        },
        Isa::Neon => match op {
            Op::Add => format!("aarch64::vaddq_u32 ({}) ({})", x(0), x(1)),
            Op::Sub => unreachable!("no NEON sub tile"),
            Op::Xor => format!("aarch64::veorq_u32 ({}) ({})", x(0), x(1)),
            Op::And => format!("aarch64::vandq_u32 ({}) ({})", x(0), x(1)),
            Op::Or => format!("aarch64::vorrq_u32 ({}) ({})", x(0), x(1)),
            Op::Not => format!("aarch64::veorq_u32 ({}) ({})", x(0), ones(t)),
            Op::Rotr(k) => neon_rotr(k, &x(0)),
            Op::Rotl(k) => neon_rotr((32 - k) % 32, &x(0)),
            Op::Shr(k) if k == 0 => x(0),
            Op::Shr(k) => format!("aarch64::vshrq_n_u32 {k}u32 .refl(Bool, true) .refl(Bool, true) ({})", x(0)),
            Op::Shl(k) => format!("aarch64::vshlq_n_u32 {k}u32 .refl(Bool, true) ({})", x(0)),
        },
    }
}

/// All-ones as a vector constant of `t`.
fn ones(t: &LaneTarget) -> String {
    format!("{} ({} {})", t.load, t.ctor, vec!["4294967295u32"; t.lanes].join(" "))
}

fn avx2_rotr(k: u32, a: &str) -> String {
    if k == 0 {
        return a.to_string();
    }
    format!("x86_64::_mm256_or_si256 (x86_64::_mm256_srli_epi32 {k}u32 .refl(Bool, true) ({a})) (x86_64::_mm256_slli_epi32 {}u32 .refl(Bool, true) ({a}))", 32 - k)
}

fn neon_rotr(k: u32, a: &str) -> String {
    if k == 0 {
        return a.to_string();
    }
    format!("aarch64::vorrq_u32 (aarch64::vshrq_n_u32 {k}u32 .refl(Bool, true) .refl(Bool, true) ({a})) (aarch64::vshlq_n_u32 {}u32 .refl(Bool, true) ({a}))", 32 - k)
}

/// A known short lowering of a 3-input truth table on AVX2 / NEON.
fn formula(t: &LaneTarget, tt: u8, a: &[String]) -> Option<String> {
    if a.len() != 3 {
        return None;
    }
    let (x, y, z) = (&a[0], &a[1], &a[2]);
    Some(match (t.isa, tt) {
        // Ch: x ? y : z
        (Isa::Neon, 0xca) => format!("aarch64::vbslq_u32 ({x}) ({y}) ({z})"),
        (Isa::Avx2, 0xca) => format!("x86_64::_mm256_xor_si256 (x86_64::_mm256_and_si256 (x86_64::_mm256_xor_si256 ({y}) ({z})) ({x})) ({z})"),
        // Maj: x = y ? x : z
        (Isa::Neon, 0xe8) => format!("aarch64::vbslq_u32 (aarch64::veorq_u32 ({x}) ({y})) ({z}) ({x})"),
        (Isa::Avx2, 0xe8) => format!("x86_64::_mm256_or_si256 (x86_64::_mm256_and_si256 ({x}) ({y})) (x86_64::_mm256_and_si256 (x86_64::_mm256_or_si256 ({x}) ({y})) ({z}))"),
        // xor3
        (Isa::Neon, 0x96) => format!("aarch64::veorq_u32 (aarch64::veorq_u32 ({x}) ({y})) ({z})"),
        (Isa::Avx2, 0x96) => format!("x86_64::_mm256_xor_si256 (x86_64::_mm256_xor_si256 ({x}) ({y})) ({z})"),
        _ => return None,
    })
}

/// The direct lowering of an expression (one vector operation per scalar
/// operation).
fn vexpr_of(t: &LaneTarget, e: &SExpr, a: &[String]) -> String {
    match e {
        SExpr::In(i) => a[*i].clone(),
        SExpr::Op(op, xs) => {
            let args: Vec<String> = xs.iter().map(|x| vexpr_of(t, x, a)).collect();
            vop(t, *op, &args)
        }
    }
}

fn op_cost(t: &LaneTarget, op: Op) -> usize {
    match (t.isa, op) {
        (Isa::Avx512, _) => 1,
        (_, Op::Rotr(k) | Op::Rotl(k)) if k % 32 != 0 => 3,
        (_, Op::Not) => 1,
        _ => 1,
    }
}

fn expr_cost(t: &LaneTarget, e: &SExpr) -> usize {
    match e {
        SExpr::In(_) => 0,
        SExpr::Op(op, xs) => op_cost(t, *op) + xs.iter().map(|x| expr_cost(t, x)).sum::<usize>(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truth_tables_of_the_sha_functions() {
        use SExpr::*;
        let ch = Op(super::Op::Xor, vec![Op(super::Op::And, vec![In(0), In(1)]), Op(super::Op::And, vec![Op(super::Op::Not, vec![In(0)]), In(2)])]);
        let maj = Op(super::Op::Xor, vec![Op(super::Op::Xor, vec![Op(super::Op::And, vec![In(0), In(1)]), Op(super::Op::And, vec![In(0), In(2)])]), Op(super::Op::And, vec![In(1), In(2)])]);
        let xor3 = Op(super::Op::Xor, vec![Op(super::Op::Xor, vec![In(0), In(1)]), In(2)]);
        assert_eq!(ch.truth_table(), 0xca);
        assert_eq!(maj.truth_table(), 0xe8);
        assert_eq!(xor3.truth_table(), 0x96);
    }
}
