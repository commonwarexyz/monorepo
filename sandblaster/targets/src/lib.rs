//! Executable reference models of target intrinsics (DESIGN.md §9.2).
//!
//! This crate is the executable half of sandblaster's **target semantics
//! library** (TCB item 4 in DESIGN.md §1.1). For every hardware intrinsic the
//! QMDB SHA-256 kernels need, it contains a pure, safe, intrinsic-free Rust
//! function that is a lane-level transcription of the vendor pseudocode (Arm
//! Architecture Reference Manual for aarch64 NEON/SHA2, Intel SDM for
//! x86_64 SSE/SSSE3/SSE4.1/SHA-NI), and the same lane-level definition
//! transcribed into kernel core text as a `DefKind::Intrinsic` global
//! (`core/aarch64.core`, `core/x86_64.core`), which the front end loads and
//! every proof is about. The mathematical statement of each model is in
//! `MODELS.md` next to this crate (normative); the chain hardware ↔ Rust model
//! ↔ core model is tested end to end and recorded in the evidence files.
//!
//! Layout:
//!
//! * [`aarch64`] — NEON and SHA2 models over `[u8; 16]`, `[u8; 8]`,
//!   `[u32; 4]` lane arrays (lane 0 at the lowest address, §9.2).
//! * [`x86_64`] — SSE2/SSSE3/SSE4.1 and SHA-NI models over `__m128i`
//!   represented canonically as `[u8; 16]` little-endian, with typed views
//!   (`view_u32(v)[i] = from_le_bytes(v[4i..4i+4])`, §9.2); and the
//!   AVX/AVX2, AVX-512F/BW/VL/DQ, IFMA, GFNI, VBMI/VBMI2 and
//!   VPOPCNTDQ/BITALG models over `__m256i = [u8; 32]`, `__m512i = [u8; 64]`
//!   and `__mmaskN = uN` (MODELS.md §10).
//! * [`reference`] — independent (non-SDM) implementations of the
//!   256/512-bit models, the local cross-check of their transcriptions.
//! * [`fips`] — a plain FIPS 180-4 SHA-256 (the portable reference that the
//!   hardware kernels are proven equal to, §9.7).
//! * [`compress`] — full SHA-256 compressions assembled from the models in the
//!   standard intrinsic sequences (the `sha2` crate's aarch64 and x86 SHA-NI
//!   backends), used by the consistency tests.
//! * [`consistency`] — portable checks that the SHA models agree with FIPS
//!   180-4 rounds / schedule steps / compressions (this is the only
//!   validation available for SHA-NI on this machine).
//! * [`diff`] — the differential-testing harness (input generators with
//!   corner values, counters, mismatch reports) and [`hw`] — the real
//!   intrinsics, cfg-gated per architecture, compared against the models.
//! * [`coretext`] — the core-text models: [`coretext::core_text`], the
//!   registry of core globals and signatures for the elaborator
//!   ([`coretext::CoreModel`], [`coretext::find_by_path`], the load/store
//!   helpers [`coretext::CORE_HELPERS`]) and the core hashes of the evidence
//!   records. Dependency-free.
//! * `kernel` (feature `kernel`) — loading the core models into a kernel
//!   `Env`, building calls (`kernel::Kit::apply`), and the K-style
//!   cross-checks: kernel evaluation of every core model == its executable
//!   model (≥ 1000 random inputs + corners + every immediate), and the SHA-256
//!   compressions assembled in core text from the core models == a core-text
//!   FIPS 180-4 compression == the executable models.
//! * [`registry`] — the list of models with their feature requirements,
//!   source items and pseudocode references; [`evidence`] — per-model source
//!   and core hashes and the evidence records `evidence/<arch>.json` (fail
//!   closed: the dispatcher must not select a variant whose models lack
//!   hardware evidence or a current kernel cross-check).
//! * [`json`] — a minimal JSON reader for the evidence records; [`rng`] — a
//!   deterministic PRNG.
//!
//! The model modules forbid `unsafe`; only [`hw`] (which calls the real
//! intrinsics, loads/stores through pointers and transmutes between lane
//! arrays and vector types) uses it. The machine probe of [`evidence`] shells
//! out to `sysctl`/`sw_vers` instead of calling `sysctlbyname`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod aarch64;
pub mod compress;
pub mod consistency;
pub mod coretext;
pub mod diff;
pub mod evidence;
pub mod fips;
#[allow(unsafe_code)]
pub mod hw;
pub mod json;
#[cfg(feature = "kernel")]
pub mod kernel;
pub mod reference;
pub mod registry;
pub mod rng;
pub mod x86_64;
