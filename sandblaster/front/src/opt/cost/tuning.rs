//! Tuning evidence as cost-model input (optimizer design §10.2, §19.3;
//! plan O8).
//!
//! The committed tuning files (`sandblaster/targets/evidence/
//! tuning-<arch>-<uarch>.json`, schema `sandblaster-tuning-evidence/1`,
//! embedded as `sandblaster_targets::evidence::tuning::COMMITTED`) override
//! the seeded [`super::tables`] entries of their microarchitecture: the
//! per-instruction latencies and throughputs (`op.<name>.latency_cycles`,
//! `.throughput_cycles`) and the cycle time. Each overridden entry becomes
//! `Measured`.
//!
//! **Determinism.** The [`Tuning::hash`] (FNV-1a over every file's name and
//! bytes) is part of the optimizer's determinism key: with `PROFILE.json`
//! it is the only input besides the source, the variant set, the options
//! and the optimizer version that may change a choice (design §17, DESIGN
//! §8.2 item 10). It keys the proof cache and is written to the report.
//! Tuning changes **choices only**: a table ranks candidates that are each
//! kernel-checked, and never enables dispatch (design §19 "Gating").

use sandblaster_targets::json::Json;

use super::tables::{self, Cost, Level, MC, Op, Table};

/// One tuning file.
#[derive(Clone, Debug, PartialEq)]
pub struct TuningFile {
    pub name: String,
    pub arch: String,
    pub uarch: String,
    /// `(key, value)` of every measured value, sorted by key.
    pub values: Vec<(String, f64)>,
}

impl TuningFile {
    fn get(&self, key: &str) -> Option<f64> {
        self.values.binary_search_by(|(k, _)| k.as_str().cmp(key)).ok().map(|i| self.values[i].1)
    }
}

/// The tuning evidence the cost model reads.
#[derive(Clone, Debug, PartialEq)]
pub struct Tuning {
    pub files: Vec<TuningFile>,
    /// FNV-1a 64 over every file's name and text (see the module docs).
    pub hash: u64,
}

impl Default for Tuning {
    fn default() -> Tuning {
        Tuning::committed()
    }
}

fn fnv(h: &mut u64, bytes: &[u8]) {
    for b in bytes {
        *h ^= u64::from(*b);
        *h = h.wrapping_mul(0x100_0000_01b3);
    }
}

impl Tuning {
    /// The committed files.
    pub fn committed() -> Tuning {
        Tuning::from_texts(sandblaster_targets::evidence::tuning::COMMITTED.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect()).unwrap_or_else(|e| panic!("committed tuning evidence is invalid: {e}"))
    }

    /// The committed files, parsed once per process.
    pub fn shared() -> std::sync::Arc<Tuning> {
        static T: std::sync::OnceLock<std::sync::Arc<Tuning>> = std::sync::OnceLock::new();
        T.get_or_init(|| std::sync::Arc::new(Tuning::committed())).clone()
    }

    /// No tuning evidence (every table entry a seeded hypothesis).
    pub fn none() -> Tuning {
        Tuning::from_texts(vec![]).unwrap()
    }

    /// Tuning from `(file name, text)` pairs; each text must pass the
    /// evidence crate's validator.
    pub fn from_texts(mut texts: Vec<(String, String)>) -> Result<Tuning, String> {
        texts.sort();
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut files = Vec::new();
        for (name, text) in &texts {
            fnv(&mut h, name.as_bytes());
            fnv(&mut h, &[0]);
            fnv(&mut h, text.as_bytes());
            fnv(&mut h, &[0]);
            let s = sandblaster_targets::evidence::tuning::check(text).map_err(|e| format!("{name}: {}", e.join("; ")))?;
            if s.dry_run {
                return Err(format!("{name}: a dry run is not tuning evidence"));
            }
            let doc = sandblaster_targets::json::parse(text).map_err(|e| format!("{name}: {e}"))?;
            let mut values: Vec<(String, f64)> = match doc.get("values") {
                Some(Json::Obj(m)) => m.iter().filter_map(|(k, _)| sandblaster_targets::evidence::tuning::value(&doc, k).map(|v| (k.clone(), v))).collect(),
                _ => vec![],
            };
            values.sort_by(|a, b| a.0.cmp(&b.0));
            files.push(TuningFile { name: name.clone(), arch: s.arch.name().to_string(), uarch: s.uarch.clone(), values });
        }
        Ok(Tuning { files, hash: h })
    }

    /// The file of `arch`/`uarch`, if committed.
    pub fn file(&self, arch: &str, uarch: &str) -> Option<&TuningFile> {
        self.files.iter().find(|f| f.arch == arch && f.uarch == uarch)
    }

    /// The tables of a level, one per microarchitecture, with this tuning
    /// applied.
    pub fn tables(&self, level: Level) -> Vec<Table> {
        tables::uarchs(level)
            .iter()
            .map(|u| {
                let mut t = tables::seed(level, u);
                if let Some(f) = self.file(t.arch, t.uarch) {
                    apply(&mut t, f);
                }
                t
            })
            .collect()
    }

    /// A short hexadecimal form of [`Tuning::hash`] (reports).
    pub fn hash_hex(&self) -> String {
        format!("{:016x}", self.hash)
    }
}

/// `cycles` (a tuning value) in milli-cycles.
fn mc(cycles: f64) -> u64 {
    (cycles * MC as f64).round().max(0.0) as u64
}

fn op_cost(f: &TuningFile, name: &str) -> Option<Cost> {
    Some(Cost { lat: mc(f.get(&format!("op.{name}.latency_cycles"))?), tp: mc(f.get(&format!("op.{name}.throughput_cycles"))?) })
}

/// Overrides `t`'s entries from `f` (see the module docs).
fn apply(t: &mut Table, f: &TuningFile) {
    if let Some(ns) = f.get("cycle_ns") {
        t.cycle_ps = (ns * 1000.0).round() as u64;
    }
    let scalar_ext = t.level != Level::X86V1;
    if t.arch == "x86_64" {
        if let Some(c) = op_cost(f, "add_r64") {
            t.set_op(Op::Alu, c);
            t.set_op(Op::Cmp, c);
        }
        if let Some(c) = op_cost(f, "imul_r64") {
            t.set_op(Op::Mul, c);
        }
        if let Some(c) = op_cost(f, "mulx_r64") {
            t.set_op(Op::MulWide, c);
        }
        // the one-instruction forms exist only where the set has the features
        if scalar_ext {
            for (op, name) in [(Op::Lzcnt, "lzcnt_r64"), (Op::Tzcnt, "tzcnt_r64"), (Op::Popcnt, "popcnt_r64"), (Op::ShiftVar, "shlx_r64"), (Op::Bzhi, "bzhi_r64")] {
                if let Some(c) = op_cost(f, name) {
                    t.set_op(op, c);
                }
            }
        }
        if t.level == Level::X86V4
            && let Some(c) = op_cost(f, "pext_r64")
        {
            t.set_op(Op::Pext, c);
        }
        for (model, name) in [("_mm_sha256rnds2_epu32", "sha256rnds2"), ("_mm_sha256msg1_epu32", "sha256msg1"), ("_mm_sha256msg2_epu32", "sha256msg2")] {
            if let Some(c) = op_cost(f, name) {
                t.set_intrinsic(model, c);
            }
        }
        if let Some(c) = op_cost(f, "paddd_xmm") {
            t.set_vec(Op::Alu, c);
        }
    } else {
        if let Some(c) = op_cost(f, "add_x") {
            t.set_op(Op::Alu, c);
            t.set_op(Op::Cmp, c);
        }
        if let Some(c) = op_cost(f, "mul_x") {
            t.set_op(Op::Mul, c);
        }
        if let Some(c) = op_cost(f, "clz_x") {
            t.set_op(Op::Lzcnt, c);
            // trailing_zeros = rbit + clz
            if let Some(r) = op_cost(f, "rbit_x") {
                t.set_op(Op::Tzcnt, Cost { lat: r.lat + c.lat, tp: r.tp + c.tp });
            }
        }
        // count_ones = fmov + cnt + addv + fmov: the measured `cnt` plus the
        // transfers and the reduction (7 cycles, 3 extra µops; seeded)
        if let Some(c) = op_cost(f, "cnt_v8b") {
            t.set_op(Op::Popcnt, Cost { lat: c.lat + 7 * MC, tp: c.tp + 750 });
        }
        if let Some(c) = op_cost(f, "add_v4s") {
            t.set_vec(Op::Alu, c);
        }
        if let Some(c) = op_cost(f, "eor_v16b") {
            t.set_vec(Op::Cmp, c);
            t.set_vec(Op::Select, c);
        }
        for (model, name) in [("vsha256hq_u32", "sha256h"), ("vsha256h2q_u32", "sha256h"), ("vsha256su0q_u32", "sha256su0"), ("vsha256su1q_u32", "sha256su1")] {
            if let Some(c) = op_cost(f, name) {
                t.set_intrinsic(model, c);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opt::cost::tables::Status;

    #[test]
    fn committed_tuning_overrides_its_microarchitectures() {
        let t = Tuning::committed();
        assert!(t.file("x86_64", "zen5").is_some() && t.file("aarch64", "m5").is_some());
        let v3 = t.tables(Level::X86V3);
        let zen5 = v3.iter().find(|x| x.uarch == "zen5").unwrap();
        assert_eq!(zen5.ops[&Op::Lzcnt].1, Status::Measured);
        assert!(zen5.op(Op::Lzcnt).lat <= 1100);
        let spr = v3.iter().find(|x| x.uarch == "spr").unwrap();
        assert_eq!(spr.ops[&Op::Lzcnt].1, Status::Hypothesis);
        // v1 keeps the multi-instruction forms (bsr + fixup) even on Zen 5
        let v1 = t.tables(Level::X86V1);
        let z = v1.iter().find(|x| x.uarch == "zen5").unwrap();
        assert_eq!(z.ops[&Op::Lzcnt].1, Status::Hypothesis);
        assert!(z.op(Op::Popcnt).lat >= 10 * MC);
        let m5 = &t.tables(Level::Aarch64)[0];
        assert_eq!(m5.intrinsics["vsha256hq_u32"].1, Status::Measured);
        assert!(m5.measured_entries() >= 8);
    }

    #[test]
    fn the_hash_covers_every_byte() {
        let a = Tuning::committed();
        assert_eq!(a.hash, Tuning::committed().hash);
        assert_ne!(a.hash, Tuning::none().hash);
        let mut texts: Vec<(String, String)> = sandblaster_targets::evidence::tuning::COMMITTED.iter().map(|(n, t)| (n.to_string(), t.to_string())).collect();
        texts[0].1 = texts[0].1.replacen("\"value\": 0.", "\"value\": 1.", 1);
        let b = Tuning::from_texts(texts).unwrap();
        assert_ne!(a.hash, b.hash);
    }
}
