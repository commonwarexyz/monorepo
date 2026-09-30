//! Cost tables per variant set and microarchitecture (optimizer design
//! §10.2; plan O8).
//!
//! A [`Table`] gives, for one *(architecture, lowering level,
//! microarchitecture)*, the latency and reciprocal throughput of every
//! abstract operation class ([`Op`]) the cost model counts, of every
//! intrinsic model it knows by name, and of 128-bit vector operations (the
//! lane candidates' costs). Values are **fixed point**: milli-cycles
//! ([`MC`] per cycle), so every cost and every comparison is an integer and
//! deterministic.
//!
//! The **lowering level** is what the variant set's features let rustc emit
//! for a primitive: on x86-64 without `lzcnt`/`popcnt`/`bmi1` (level
//! [`Level::X86V1`]) `leading_zeros` is `bsr` plus a fixup, `count_ones` a
//! 12-instruction SWAR sequence and `trailing_zeros` `bsf` plus a fixup; with
//! the feature-only set `v3_scalar` ([`Level::X86V3`]) and in `v4`
//! ([`Level::X86V4`]) each is one instruction. On aarch64 `count_ones` is a
//! transfer to a vector register, `cnt`, `addv` and a transfer back.
//!
//! Every entry carries a [`Status`]: `Measured` when a committed tuning
//! file (`opt::cost::tuning`) supplied it, `Hypothesis` for the seeded
//! values. The seeds: the M5 from the design's measurements (`$O/par`,
//! `$O/run_*`), Zen 5 from host round 0 (overridden by its tuning file), and
//! Sapphire Rapids and Zen 4 from published instruction tables — the last
//! two stay hypotheses until a host round measures them (design §19, plan
//! O20). A wrong constant costs speed, never correctness: tables only rank
//! candidates that are each kernel-checked.

use std::collections::BTreeMap;

/// Milli-cycles per cycle (the fixed-point unit of every cost).
pub const MC: u64 = 1000;

/// An abstract operation class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// add, sub, and, or, xor, not, neg (one ALU operation).
    Alu,
    /// A comparison producing a flag or a boolean.
    Cmp,
    /// A conditional select (`cmov`, `csel`).
    Select,
    /// A shift by a literal amount.
    ShiftImm,
    /// A shift by a variable amount (`shl r, cl` on x86 v1; `shlx` with BMI2).
    ShiftVar,
    Rotate,
    Mul,
    /// The high half of a product.
    MulWide,
    Div,
    Popcnt,
    Lzcnt,
    Tzcnt,
    /// `bzhi` (BMI2): only the x86 v3/v4 levels have it as one instruction.
    Bzhi,
    /// `pext`/`pdep` (BMI2): slow microcode on the Zen 2/3 parts that
    /// `v3_scalar` also covers, so only `v4` prices it as one instruction
    /// ("`pext` is tied to v4", plan O8).
    Pext,
    Bswap,
    /// A width change (zero extension, truncation, bool to integer).
    Cast,
    Load,
    Store,
    /// A (predicted) conditional branch.
    Branch,
    /// A call that is not inlined (call, return, argument moves).
    Call,
}

/// Every operation class, in order.
pub const OPS: &[Op] = &[
    Op::Alu,
    Op::Cmp,
    Op::Select,
    Op::ShiftImm,
    Op::ShiftVar,
    Op::Rotate,
    Op::Mul,
    Op::MulWide,
    Op::Div,
    Op::Popcnt,
    Op::Lzcnt,
    Op::Tzcnt,
    Op::Bzhi,
    Op::Pext,
    Op::Bswap,
    Op::Cast,
    Op::Load,
    Op::Store,
    Op::Branch,
    Op::Call,
];

/// Latency and reciprocal throughput, in milli-cycles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cost {
    pub lat: u64,
    pub tp: u64,
}

const fn c(lat: u64, tp: u64) -> Cost {
    Cost { lat, tp }
}

/// Where an entry comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    /// Supplied by a committed tuning file (measured on that
    /// microarchitecture).
    Measured,
    /// Seeded (design measurements of other machines, published tables).
    Hypothesis,
}

/// What the variant set's features let rustc emit for a primitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// x86-64 baseline (no `popcnt`, `lzcnt`, BMI).
    X86V1,
    /// x86-64 with `popcnt, lzcnt, bmi1, bmi2` (the feature-only set
    /// `v3_scalar`; also every set that includes those features).
    X86V3,
    /// x86-64-v4 (AVX-512 plus the scalar extensions).
    X86V4,
    /// aarch64 (NEON, SHA2 where the set has it).
    Aarch64,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Level::X86V1 => "x86-64-v1",
            Level::X86V3 => "x86-64-v3-scalar",
            Level::X86V4 => "x86-64-v4",
            Level::Aarch64 => "aarch64",
        }
    }

    /// The level of a variant set with the (implication-closed) features
    /// `features` on `arch` (`"x86_64"` or `"aarch64"`).
    pub fn of(arch: &str, features: &[String]) -> Level {
        if arch != "x86_64" {
            return Level::Aarch64;
        }
        let has = |f: &str| features.iter().any(|x| x == f);
        if has("avx512f") {
            Level::X86V4
        } else if has("lzcnt") && has("popcnt") && has("bmi1") && has("bmi2") {
            Level::X86V3
        } else {
            Level::X86V1
        }
    }
}

/// The microarchitectures a level's tables cover.
pub fn uarchs(level: Level) -> &'static [&'static str] {
    match level {
        Level::Aarch64 => &["m5"],
        _ => &["spr", "zen4", "zen5"],
    }
}

/// One cost table (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub arch: &'static str,
    pub level: Level,
    pub uarch: &'static str,
    /// Picoseconds per cycle (to express a cost in time for reports).
    pub cycle_ps: u64,
    pub ops: BTreeMap<Op, (Cost, Status)>,
    /// Intrinsic models and load/store helpers by name.
    pub intrinsics: BTreeMap<String, (Cost, Status)>,
    /// 128-bit vector operations (NEON / SSE), for lane candidates.
    pub vector: BTreeMap<Op, (Cost, Status)>,
    /// The penalty of a mispredicted branch.
    pub branch_miss: (u64, Status),
    /// Where the non-measured entries come from.
    pub seed: &'static str,
}

impl Table {
    /// The cost of an operation class.
    pub fn op(&self, op: Op) -> Cost {
        self.ops.get(&op).map(|e| e.0).unwrap_or(c(MC, MC))
    }

    /// The cost of a 128-bit vector operation (a scalar one when the table
    /// has none).
    pub fn vec_op(&self, op: Op) -> Cost {
        self.vector.get(&op).map(|e| e.0).unwrap_or_else(|| self.op(op))
    }

    /// The cost of an intrinsic model or helper (a conservative default
    /// for names the table does not know).
    pub fn intrinsic(&self, name: &str) -> Cost {
        if let Some(e) = self.intrinsics.get(name) {
            return e.0;
        }
        if name.starts_with("load_") {
            return self.vec_op(Op::Load);
        }
        if name.starts_with("store_") {
            return self.vec_op(Op::Store);
        }
        if name.starts_with("view_") || name.starts_with("m128i_from_") {
            return c(0, 0);
        }
        c(3 * MC, MC)
    }

    /// `true` when every entry is measured.
    pub fn measured(&self) -> bool {
        self.ops.values().chain(self.intrinsics.values()).chain(self.vector.values()).all(|e| e.1 == Status::Measured) && self.branch_miss.1 == Status::Measured
    }

    /// Number of measured entries (reports).
    pub fn measured_entries(&self) -> usize {
        self.ops.values().chain(self.intrinsics.values()).chain(self.vector.values()).filter(|e| e.1 == Status::Measured).count()
    }

    /// Sets an entry (tuning).
    pub fn set_op(&mut self, op: Op, cost: Cost) {
        self.ops.insert(op, (cost, Status::Measured));
    }

    pub fn set_vec(&mut self, op: Op, cost: Cost) {
        self.vector.insert(op, (cost, Status::Measured));
    }

    pub fn set_intrinsic(&mut self, name: &str, cost: Cost) {
        self.intrinsics.insert(name.to_string(), (cost, Status::Measured));
    }
}

fn hyp(entries: &[(Op, Cost)]) -> BTreeMap<Op, (Cost, Status)> {
    entries.iter().map(|(o, c)| (*o, (*c, Status::Hypothesis))).collect()
}

fn hyp_named(entries: &[(&str, Cost)]) -> BTreeMap<String, (Cost, Status)> {
    entries.iter().map(|(o, c)| (o.to_string(), (*c, Status::Hypothesis))).collect()
}

/// The seeded table (every entry a hypothesis; tuning overrides entries).
pub fn seed(level: Level, uarch: &'static str) -> Table {
    use Op::*;
    match (level, uarch) {
        (Level::Aarch64, _) => Table {
            arch: "aarch64",
            level,
            uarch: "m5",
            cycle_ps: 236,
            // Apple M5 (design measurements, `$O/par`, `$O/run_*`): six
            // integer ALUs, two multipliers, four NEON pipes. `count_ones`:
            // fmov + cnt + addv + fmov; `trailing_zeros`: rbit + clz.
            ops: hyp(&[
                (Alu, c(1000, 250)),
                (Cmp, c(1000, 250)),
                (Select, c(1000, 250)),
                (ShiftImm, c(1000, 250)),
                (ShiftVar, c(1000, 250)),
                (Rotate, c(1000, 250)),
                (Mul, c(3000, 375)),
                (MulWide, c(3000, 500)),
                (Div, c(8000, 2000)),
                (Popcnt, c(9000, 1000)),
                (Lzcnt, c(1000, 250)),
                (Tzcnt, c(2000, 500)),
                (Bzhi, c(2000, 500)),
                (Pext, c(40000, 20000)),
                (Bswap, c(1000, 250)),
                (Cast, c(0, 50)),
                (Load, c(4000, 333)),
                (Store, c(0, 500)),
                (Branch, c(0, 500)),
                (Call, c(2000, 1500)),
            ]),
            intrinsics: hyp_named(&[
                ("vsha256hq_u32", c(4000, 2000)),
                ("vsha256h2q_u32", c(4000, 2000)),
                ("vsha256su0q_u32", c(2000, 1000)),
                ("vsha256su1q_u32", c(3000, 1000)),
            ]),
            // NEON: add/eor 2 cycles, 4 pipes; a 32-bit rotate is shl + sri
            vector: hyp(&[
                (Alu, c(2000, 280)),
                (Cmp, c(2000, 280)),
                (Select, c(2000, 280)),
                (ShiftImm, c(2000, 500)),
                (Rotate, c(4000, 1000)),
                (Mul, c(4000, 500)),
                (Load, c(4000, 500)),
                (Store, c(0, 500)),
                (Cast, c(2000, 280)),
            ]),
            branch_miss: (13000, Status::Hypothesis),
            seed: "M5: design measurements ($O/par, $O/run_*)",
        },
        (_, "zen5") | (_, "zen4") => {
            let zen5 = uarch == "zen5";
            // Zen 4 and Zen 5 (published tables; Zen 5 is overridden by its
            // measured tuning file). Without LZCNT/POPCNT/BMI1: bsr + xor +
            // cmov, a 12-instruction SWAR popcount, bsf + cmov.
            let v1 = level == Level::X86V1;
            let v4 = level == Level::X86V4;
            Table {
                arch: "x86_64",
                level,
                uarch: if zen5 { "zen5" } else { "zen4" },
                cycle_ps: if zen5 { 223 } else { 222 },
                ops: hyp(&[
                    (Alu, c(1000, 250)),
                    (Cmp, c(1000, 250)),
                    (Select, c(1000, 250)),
                    (ShiftImm, c(1000, 250)),
                    (ShiftVar, if v1 { c(1000, 500) } else { c(1000, 500) }),
                    (Rotate, c(1000, 250)),
                    (Mul, c(3000, 1000)),
                    (MulWide, c(3000, 1000)),
                    (Div, c(14000, 7000)),
                    (Popcnt, if v1 { c(10000, 3500) } else { c(1000, 250) }),
                    (Lzcnt, if v1 { c(3000, 750) } else { c(1000, 250) }),
                    (Tzcnt, if v1 { c(2000, 750) } else { c(2000, 500) }),
                    (Bzhi, if v1 { c(3000, 750) } else { c(1000, 500) }),
                    // pext: 3 cycles on Zen 4/5, but v3_scalar also runs on
                    // Zen 2/3 (microcoded, up to ~250 cycles)
                    (Pext, if v4 { c(3000, 1000) } else { c(250000, 250000) }),
                    (Bswap, c(1000, 250)),
                    (Cast, c(0, 50)),
                    (Load, c(4000, 333)),
                    (Store, c(0, 500)),
                    (Branch, c(0, 500)),
                    (Call, c(2000, 1500)),
                ]),
                intrinsics: hyp_named(&[
                    ("_mm_sha256rnds2_epu32", c(4000, 2000)),
                    ("_mm_sha256msg1_epu32", c(2000, 500)),
                    ("_mm_sha256msg2_epu32", c(3000, 2000)),
                ]),
                vector: hyp(&[(Alu, c(1000, 250)), (Cmp, c(1000, 250)), (Select, c(1000, 500)), (ShiftImm, c(1000, 500)), (Rotate, c(2000, 1000)), (Mul, c(3000, 500)), (Load, c(4000, 500)), (Store, c(0, 500)), (Cast, c(1000, 500))]),
                branch_miss: (15000, Status::Hypothesis),
                seed: if zen5 { "Zen 5: published tables (overridden by tuning-x86_64-zen5.json)" } else { "Zen 4: published tables (hypothesis until a host round measures it)" },
            }
        }
        _ => {
            // Sapphire Rapids (Golden Cove; published tables): lzcnt, tzcnt
            // and popcnt have 3-cycle latency; shl by cl is two uops.
            let v1 = level == Level::X86V1;
            let v4 = level == Level::X86V4;
            Table {
                arch: "x86_64",
                level,
                uarch: "spr",
                cycle_ps: 263,
                ops: hyp(&[
                    (Alu, c(1000, 200)),
                    (Cmp, c(1000, 200)),
                    (Select, c(1000, 500)),
                    (ShiftImm, c(1000, 500)),
                    (ShiftVar, if v1 { c(2000, 1000) } else { c(1000, 500) }),
                    (Rotate, c(1000, 500)),
                    (Mul, c(3000, 1000)),
                    (MulWide, c(4000, 1000)),
                    (Div, c(15000, 10000)),
                    (Popcnt, if v1 { c(12000, 4000) } else { c(3000, 1000) }),
                    (Lzcnt, if v1 { c(5000, 1000) } else { c(3000, 1000) }),
                    (Tzcnt, if v1 { c(4000, 1000) } else { c(3000, 1000) }),
                    (Bzhi, if v1 { c(3000, 1000) } else { c(1000, 500) }),
                    (Pext, if v4 { c(3000, 1000) } else { c(250000, 250000) }),
                    (Bswap, c(1000, 500)),
                    (Cast, c(0, 50)),
                    (Load, c(5000, 333)),
                    (Store, c(0, 500)),
                    (Branch, c(0, 500)),
                    (Call, c(2000, 1500)),
                ]),
                intrinsics: hyp_named(&[
                    ("_mm_sha256rnds2_epu32", c(6000, 3000)),
                    ("_mm_sha256msg1_epu32", c(3000, 1000)),
                    ("_mm_sha256msg2_epu32", c(3000, 1000)),
                ]),
                vector: hyp(&[(Alu, c(1000, 333)), (Cmp, c(1000, 500)), (Select, c(1000, 500)), (ShiftImm, c(1000, 500)), (Rotate, c(2000, 1000)), (Mul, c(5000, 500)), (Load, c(6000, 500)), (Store, c(0, 500)), (Cast, c(1000, 500))]),
                branch_miss: (17000, Status::Hypothesis),
                seed: "Sapphire Rapids: published tables (hypothesis until a host round measures it)",
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_follow_features() {
        let f = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(Level::of("x86_64", &f(&["sha", "sse2"])), Level::X86V1);
        assert_eq!(Level::of("x86_64", &f(&["popcnt", "lzcnt", "bmi1", "bmi2"])), Level::X86V3);
        assert_eq!(Level::of("x86_64", &f(&["avx512f", "popcnt", "lzcnt", "bmi1", "bmi2"])), Level::X86V4);
        assert_eq!(Level::of("aarch64", &f(&["sha2"])), Level::Aarch64);
    }

    #[test]
    fn every_table_prices_every_op() {
        for level in [Level::X86V1, Level::X86V3, Level::X86V4, Level::Aarch64] {
            for u in uarchs(level) {
                let t = seed(level, u);
                for op in OPS {
                    assert!(t.ops.contains_key(op), "{level:?}/{u}: {op:?}");
                }
                // the feature-only levels make the bit counts cheap
                if level != Level::X86V1 && t.arch == "x86_64" {
                    assert!(t.op(Op::Popcnt).lat <= 3 * MC);
                } else if t.arch == "x86_64" {
                    assert!(t.op(Op::Popcnt).lat >= 10 * MC);
                }
                // pext only in v4
                if level != Level::X86V4 && t.arch == "x86_64" {
                    assert!(t.op(Op::Pext).lat >= 100 * MC);
                }
            }
        }
    }
}
