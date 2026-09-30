//! Known-answer tests of the x86_64 **feature-only** scalar sets
//! (design §13.2: `v3-scalar` = LZCNT, BMI1, BMI2, POPCNT).
//!
//! Feature-only clones use Rust primitives compiled under
//! `#[target_feature]`, so they need no intrinsic model; but on a CPU
//! without LZCNT/BMI1 the `lzcnt`/`tzcnt` encodings (F3-prefixed BSR/BSF)
//! silently execute as `bsr`/`bsf` and return different values, so a
//! feature-detection bug gives wrong answers instead of faults. The
//! dispatch glue therefore runs a known-answer self-test before selecting
//! such a set (design §13.2), and the host kit records these tests as
//! evidence per CPU (design §19.1: "then BMI/LZCNT/POPCNT (known-answer
//! tests)").
//!
//! This module holds the **specification** of the tests (safe code): per
//! operation its feature, the instructions it must compile to, an
//! independent bit-loop reference, and a table of known answers (fixed
//! inputs and expected outputs, including 0, all-ones and single bits).
//! The hardware side (the `#[target_feature]` functions that execute the
//! instructions, which need `unsafe` to call) is in the evidence binary.
//! [`kat_hash`] ties recorded results to this table: editing a known answer
//! or a reference makes the recorded KAT evidence stale.
#![forbid(unsafe_code)]

use crate::fips;

/// One known-answer-tested operation.
#[derive(Clone, Copy, Debug)]
pub struct KatSpec {
    /// Operation name (also the evidence record name): `lzcnt_u64`, ...
    pub name: &'static str,
    /// The x86 target feature it needs (`lzcnt`, `bmi1`, `bmi2`, `popcnt`).
    pub feature: &'static str,
    /// The instruction mnemonics the hardware function must contain
    /// (checked on the disassembly by the host kit).
    pub instructions: &'static [&'static str],
    /// Number of meaningful arguments (1 or 2; the second is ignored for 1).
    pub arity: u8,
    /// The reference: an independent bit-loop definition from the SDM
    /// Operation section.
    pub reference: fn(u64, u64) -> u64,
    /// Known answers `(a, b, expected)`.
    pub known: &'static [(u64, u64, u64)],
}

/// The variant set the feature-only KATs guard.
pub const SET: &str = "v3-scalar";

// ---------------------------------------------------------------------------
// References (bit loops; deliberately not the Rust primitives, which may
// themselves compile to the instruction under test).

/// LZCNT r64: count of leading zero bits, 64 for 0.
pub fn ref_lzcnt64(a: u64, _: u64) -> u64 {
    let mut n = 0;
    let mut i = 64;
    while i > 0 {
        i -= 1;
        if (a >> i) & 1 == 1 {
            break;
        }
        n += 1;
    }
    n
}

/// LZCNT r32 on the low 32 bits: 32 for 0.
pub fn ref_lzcnt32(a: u64, _: u64) -> u64 {
    ref_lzcnt64(a & 0xffff_ffff, 0) - 32
}

/// TZCNT r64: count of trailing zero bits, 64 for 0.
pub fn ref_tzcnt64(a: u64, _: u64) -> u64 {
    let mut n = 0;
    while n < 64 && (a >> n) & 1 == 0 {
        n += 1;
    }
    n
}

/// TZCNT r32 on the low 32 bits: 32 for 0.
pub fn ref_tzcnt32(a: u64, _: u64) -> u64 {
    ref_tzcnt64(a & 0xffff_ffff, 0).min(32)
}

/// ANDN: `!a & b`.
pub fn ref_andn(a: u64, b: u64) -> u64 {
    let mut r = 0;
    for i in 0..64 {
        if (a >> i) & 1 == 0 && (b >> i) & 1 == 1 {
            r |= 1 << i;
        }
    }
    r
}

/// BLSI: isolate the lowest set bit (0 for 0).
pub fn ref_blsi(a: u64, _: u64) -> u64 {
    for i in 0..64 {
        if (a >> i) & 1 == 1 {
            return 1 << i;
        }
    }
    0
}

/// BLSMSK: mask up to and including the lowest set bit (all ones for 0).
pub fn ref_blsmsk(a: u64, _: u64) -> u64 {
    let mut r = 0;
    for i in 0..64 {
        r |= 1 << i;
        if (a >> i) & 1 == 1 {
            break;
        }
    }
    r
}

/// BLSR: clear the lowest set bit.
pub fn ref_blsr(a: u64, _: u64) -> u64 {
    a ^ ref_blsi(a, 0)
}

/// BEXTR r64 with control `b` (START = b[7:0], LEN = b[15:8]):
/// bits `START+LEN-1 : START` of `a`, zero-extended; bits above 63 are 0.
pub fn ref_bextr(a: u64, b: u64) -> u64 {
    let start = b & 0xff;
    let len = (b >> 8) & 0xff;
    let mut r = 0;
    for i in 0..64u64 {
        let src = start + i;
        if i < len && src < 64 && (a >> src) & 1 == 1 {
            r |= 1 << i;
        }
    }
    r
}

/// BZHI r64 with index `b[7:0]`: clear the bits at positions ≥ N (no change
/// when N ≥ 64).
pub fn ref_bzhi(a: u64, b: u64) -> u64 {
    let n = b & 0xff;
    let mut r = 0;
    for i in 0..64u64 {
        if i < n && (a >> i) & 1 == 1 {
            r |= 1 << i;
        }
    }
    r
}

/// PDEP: deposit the low bits of `a` at the set bits of mask `b`.
pub fn ref_pdep(a: u64, b: u64) -> u64 {
    let (mut r, mut k) = (0u64, 0u32);
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            if (a >> k) & 1 == 1 {
                r |= 1 << i;
            }
            k += 1;
        }
    }
    r
}

/// PEXT: gather the bits of `a` at the set bits of mask `b` into the low bits.
pub fn ref_pext(a: u64, b: u64) -> u64 {
    let (mut r, mut k) = (0u64, 0u32);
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            if (a >> i) & 1 == 1 {
                r |= 1 << k;
            }
            k += 1;
        }
    }
    r
}

/// Schoolbook 64×64 → 128-bit product by shifts and adds.
fn wide_mul(a: u64, b: u64) -> (u64, u64) {
    let (mut lo, mut hi) = (0u64, 0u64);
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            let (pl, ph) = if i == 0 { (a, 0) } else { (a << i, a >> (64 - i)) };
            let (nl, carry) = lo.overflowing_add(pl);
            lo = nl;
            hi = hi.wrapping_add(ph).wrapping_add(u64::from(carry));
        }
    }
    (lo, hi)
}

/// MULX high half.
pub fn ref_mulx_hi(a: u64, b: u64) -> u64 {
    wide_mul(a, b).1
}

/// MULX low half.
pub fn ref_mulx_lo(a: u64, b: u64) -> u64 {
    wide_mul(a, b).0
}

/// SHLX r64: `a << (b mod 64)`.
pub fn ref_shlx(a: u64, b: u64) -> u64 {
    let n = b & 63;
    let mut r = 0;
    for i in 0..64 {
        if i >= n && (a >> (i - n)) & 1 == 1 {
            r |= 1 << i;
        }
    }
    r
}

/// SHRX r64: logical `a >> (b mod 64)`.
pub fn ref_shrx(a: u64, b: u64) -> u64 {
    let n = b & 63;
    let mut r = 0;
    for i in 0..64 {
        if i + n < 64 && (a >> (i + n)) & 1 == 1 {
            r |= 1 << i;
        }
    }
    r
}

/// SARX r64: arithmetic `a >> (b mod 64)`.
pub fn ref_sarx(a: u64, b: u64) -> u64 {
    let n = b & 63;
    let sign = a >> 63;
    let mut r = 0;
    for i in 0..64 {
        let bit = if i + n < 64 { (a >> (i + n)) & 1 } else { sign };
        r |= bit << i;
    }
    r
}

/// RORX r64 by 13 (the immediate the hardware function uses).
pub fn ref_rorx13(a: u64, _: u64) -> u64 {
    let mut r = 0;
    for i in 0..64 {
        if (a >> ((i + 13) % 64)) & 1 == 1 {
            r |= 1 << i;
        }
    }
    r
}

/// POPCNT r64.
pub fn ref_popcnt64(a: u64, _: u64) -> u64 {
    (0..64).map(|i| (a >> i) & 1).sum()
}

/// POPCNT r32 on the low 32 bits.
pub fn ref_popcnt32(a: u64, _: u64) -> u64 {
    (0..32).map(|i| (a >> i) & 1).sum()
}

// ---------------------------------------------------------------------------
// The table

const M: u64 = u64::MAX;

/// Every known-answer-tested operation, in recording order.
pub static KATS: &[KatSpec] = &[
    KatSpec {
        name: "lzcnt_u64",
        feature: "lzcnt",
        instructions: &["lzcnt"],
        arity: 1,
        reference: ref_lzcnt64,
        known: &[(0, 0, 64), (1, 0, 63), (1 << 63, 0, 0), (M, 0, 0), (0x0000_0001_0000_0000, 0, 31), (0x00ff, 0, 56)],
    },
    KatSpec {
        name: "lzcnt_u32",
        feature: "lzcnt",
        instructions: &["lzcnt"],
        arity: 1,
        reference: ref_lzcnt32,
        known: &[(0, 0, 32), (1, 0, 31), (0x8000_0000, 0, 0), (0xffff_ffff, 0, 0), (0x0001_0000, 0, 15)],
    },
    KatSpec {
        name: "tzcnt_u64",
        feature: "bmi1",
        instructions: &["tzcnt"],
        arity: 1,
        reference: ref_tzcnt64,
        known: &[(0, 0, 64), (1, 0, 0), (1 << 63, 0, 63), (M, 0, 0), (0x0000_0001_0000_0000, 0, 32), (0x0100, 0, 8)],
    },
    KatSpec {
        name: "tzcnt_u32",
        feature: "bmi1",
        instructions: &["tzcnt"],
        arity: 1,
        reference: ref_tzcnt32,
        known: &[(0, 0, 32), (1, 0, 0), (0x8000_0000, 0, 31), (0x0001_0000, 0, 16)],
    },
    KatSpec {
        name: "andn_u64",
        feature: "bmi1",
        instructions: &["andn"],
        arity: 2,
        reference: ref_andn,
        known: &[(0, M, M), (M, M, 0), (0xff00, 0x0ff0, 0x00f0), (0, 0, 0)],
    },
    KatSpec {
        name: "bextr_u64",
        feature: "bmi1",
        instructions: &["bextr"],
        arity: 2,
        reference: ref_bextr,
        known: &[
            (0x1234_5678_9abc_def0, 4 | (8 << 8), 0xef),
            (M, 60 | (8 << 8), 0xf),
            (M, 64 | (8 << 8), 0),
            (M, 0, 0),
            (0x8000_0000_0000_0000, 63 | (1 << 8), 1),
            (M, 0 | (200 << 8), M),
        ],
    },
    KatSpec {
        name: "blsi_u64",
        feature: "bmi1",
        instructions: &["blsi"],
        arity: 1,
        reference: ref_blsi,
        known: &[(0, 0, 0), (0b1011_0000, 0, 0b1_0000), (1 << 63, 0, 1 << 63), (M, 0, 1)],
    },
    KatSpec {
        name: "blsmsk_u64",
        feature: "bmi1",
        instructions: &["blsmsk"],
        arity: 1,
        reference: ref_blsmsk,
        known: &[(0, 0, M), (0b1011_0000, 0, 0b1_1111), (1 << 63, 0, M), (1, 0, 1)],
    },
    KatSpec {
        name: "blsr_u64",
        feature: "bmi1",
        instructions: &["blsr"],
        arity: 1,
        reference: ref_blsr,
        known: &[(0, 0, 0), (0b1011_0000, 0, 0b1010_0000), (1 << 63, 0, 0), (M, 0, M - 1)],
    },
    KatSpec {
        name: "bzhi_u64",
        feature: "bmi2",
        instructions: &["bzhi"],
        arity: 2,
        reference: ref_bzhi,
        known: &[(M, 0, 0), (M, 1, 1), (M, 63, M >> 1), (M, 64, M), (M, 255, M), (M, 0x100 | 4, 0xf), (0x1234, 8, 0x34)],
    },
    KatSpec {
        name: "pdep_u64",
        feature: "bmi2",
        instructions: &["pdep"],
        arity: 2,
        reference: ref_pdep,
        known: &[(0, M, 0), (M, 0, 0), (M, 0xf0f0, 0xf0f0), (0b101, 0x8000_0000_0000_0101, 0x8000_0000_0000_0001), (0x1234_5678, 0xff00_fff0, 0x4500_6780)],
    },
    KatSpec {
        name: "pext_u64",
        feature: "bmi2",
        instructions: &["pext"],
        arity: 2,
        reference: ref_pext,
        known: &[
            (M, 0, 0),
            (0, M, 0),
            (0x1234_5678, 0xff00_fff0, 0x0001_2567),
            (0x7f7f_7f7f_7f7f_7f7f, 0x7f7f_7f7f_7f7f_7f7f, (1 << 56) - 1),
            (1 << 63, 1 << 63, 1),
        ],
    },
    KatSpec {
        name: "mulx_hi_u64",
        feature: "bmi2",
        instructions: &["mulx"],
        arity: 2,
        reference: ref_mulx_hi,
        known: &[(M, M, M - 1), (1 << 32, 1 << 32, 1), (M, 1, 0), (0, M, 0)],
    },
    KatSpec {
        name: "mulx_lo_u64",
        feature: "bmi2",
        instructions: &["mulx"],
        arity: 2,
        reference: ref_mulx_lo,
        known: &[(M, M, 1), (1 << 32, 1 << 32, 0), (M, 1, M), (3, 5, 15)],
    },
    KatSpec {
        name: "shlx_u64",
        feature: "bmi2",
        instructions: &["shlx"],
        arity: 2,
        reference: ref_shlx,
        known: &[(1, 0, 1), (1, 63, 1 << 63), (1, 64, 1), (M, 4, M << 4), (0x8000_0000_0000_0001, 65, 2)],
    },
    KatSpec {
        name: "shrx_u64",
        feature: "bmi2",
        instructions: &["shrx"],
        arity: 2,
        reference: ref_shrx,
        known: &[(1 << 63, 63, 1), (M, 4, M >> 4), (M, 64, M), (2, 1, 1)],
    },
    KatSpec {
        name: "sarx_u64",
        feature: "bmi2",
        instructions: &["sarx"],
        arity: 2,
        reference: ref_sarx,
        known: &[(1 << 63, 63, M), (1 << 62, 62, 1), (M, 17, M), (0x8000_0000_0000_0000, 1, 0xc000_0000_0000_0000)],
    },
    KatSpec {
        name: "rorx13_u64",
        feature: "bmi2",
        instructions: &["rorx"],
        arity: 1,
        reference: ref_rorx13,
        known: &[(1 << 13, 0, 1), (1, 0, 1 << 51), (0, 0, 0), (M, 0, M)],
    },
    KatSpec {
        name: "popcnt_u64",
        feature: "popcnt",
        instructions: &["popcnt"],
        arity: 1,
        reference: ref_popcnt64,
        known: &[(0, 0, 0), (M, 0, 64), (0x5555_5555_5555_5555, 0, 32), (1 << 63, 0, 1), (0x8000_0000_0000_0001, 0, 2)],
    },
    KatSpec {
        name: "popcnt_u32",
        feature: "popcnt",
        instructions: &["popcnt"],
        arity: 1,
        reference: ref_popcnt32,
        known: &[(0, 0, 0), (0xffff_ffff, 0, 32), (M, 0, 32), (0x8000_0001, 0, 2)],
    },
];

/// The features the KATs cover, in order.
pub const FEATURES: [&str; 4] = ["lzcnt", "bmi1", "bmi2", "popcnt"];

/// Look a KAT up by name.
pub fn find(name: &str) -> Option<&'static KatSpec> {
    KATS.iter().find(|k| k.name == name)
}

/// `sha256:<hex>` of the KAT table: every name, feature, instruction list,
/// arity and known answer, plus the reference evaluated on a fixed probe
/// set (so editing a reference changes the hash too).
pub fn kat_hash() -> String {
    let mut text = String::new();
    let probes = [0u64, 1, 2, 3, 0x80, 0xff, 0x100, 0x7fff_ffff, 0x8000_0000, 1 << 63, u64::MAX, 0x0123_4567_89ab_cdef];
    for k in KATS {
        text.push_str(&format!("{} {} {:?} {}\n", k.name, k.feature, k.instructions, k.arity));
        for (a, b, e) in k.known {
            text.push_str(&format!("{a:#x} {b:#x} {e:#x}\n"));
        }
        for &a in &probes {
            for &b in &probes {
                text.push_str(&format!("{:x},", (k.reference)(a, b)));
            }
        }
        text.push('\n');
    }
    format!("sha256:{}", fips::hex(&fips::sha256(text.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answers_agree_with_the_references() {
        for k in KATS {
            assert!(FEATURES.contains(&k.feature), "{}", k.name);
            assert!(!k.known.is_empty() && !k.instructions.is_empty());
            for &(a, b, e) in k.known {
                assert_eq!((k.reference)(a, b), e, "{}({a:#x}, {b:#x})", k.name);
            }
        }
        let mut names: Vec<_> = KATS.iter().map(|k| k.name).collect();
        names.dedup();
        assert_eq!(names.len(), KATS.len());
    }

    #[test]
    fn references_agree_with_rust_primitives() {
        let mut r = crate::rng::Rng::new(7);
        for _ in 0..20_000 {
            let (a, b) = (r.next_u64(), r.next_u64());
            let a = if a & 3 == 0 { a >> (a % 64) } else { a };
            assert_eq!(ref_lzcnt64(a, 0), u64::from(a.leading_zeros()));
            assert_eq!(ref_lzcnt32(a, 0), u64::from((a as u32).leading_zeros()));
            assert_eq!(ref_tzcnt64(a, 0), u64::from(a.trailing_zeros()));
            assert_eq!(ref_tzcnt32(a, 0), u64::from((a as u32).trailing_zeros()));
            assert_eq!(ref_andn(a, b), !a & b);
            assert_eq!(ref_blsi(a, 0), a & a.wrapping_neg());
            assert_eq!(ref_blsmsk(a, 0), a ^ a.wrapping_sub(1));
            assert_eq!(ref_blsr(a, 0), a & a.wrapping_sub(1));
            assert_eq!(ref_shlx(a, b), a << (b & 63));
            assert_eq!(ref_shrx(a, b), a >> (b & 63));
            assert_eq!(ref_sarx(a, b), ((a as i64) >> (b & 63)) as u64);
            assert_eq!(ref_rorx13(a, 0), a.rotate_right(13));
            let p = u128::from(a) * u128::from(b);
            assert_eq!(ref_mulx_lo(a, b), p as u64);
            assert_eq!(ref_mulx_hi(a, b), (p >> 64) as u64);
            assert_eq!(ref_popcnt64(a, 0), u64::from(a.count_ones()));
            assert_eq!(ref_popcnt32(a, 0), u64::from((a as u32).count_ones()));
            let n = b & 0xff;
            assert_eq!(ref_bzhi(a, b), if n >= 64 { a } else { a & ((1u64 << n) - 1) });
            let (start, len) = (b & 0xff, (b >> 8) & 0xff);
            let bextr = if start >= 64 { 0 } else if len >= 64 { a >> start } else { (a >> start) & ((1u64 << len) - 1) };
            assert_eq!(ref_bextr(a, b), bextr);
            // pdep/pext are inverse on the mask.
            assert_eq!(ref_pext(ref_pdep(a, b), b), a & ((1u128 << b.count_ones()) - 1) as u64);
        }
    }

    #[test]
    fn hash_is_stable_and_sensitive() {
        let h = kat_hash();
        assert!(h.starts_with("sha256:") && h.len() == 7 + 64);
        assert_eq!(h, kat_hash());
    }
}
