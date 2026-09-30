//! Automatic parallelism (optimizer design §14; plan O10 builds the lane
//! functor, O11 the site discovery and decisions).
//!
//! * [`tiles`]: lane targets (AVX-512 ×16, AVX2 ×8, NEON ×4) and the tile
//!   table with its lanewise lemmas.
//! * [`lift`]: the lane functor Φ — a lane site `[g(ā₀), …, g(ā_{N−1})]`
//!   becomes one vector kernel, linked by a kernel-checked `lane_equiv`
//!   lemma built as a congruence chain (O(scalar DAG) proof).
//! * [`search`]: the SIMD search lowering (P12) — a byte search with an
//!   early exit gets a NEON variant testing 16 bytes per step, linked by an
//!   instance of a kernel-checked lemma library.
//! * [`seqeq`]: the SIMD `seq::eq` candidate — proven equal to the word
//!   form and priced against it.

pub mod cquote;
pub mod lift;
pub mod search;
pub mod seqeq;
pub mod sites;
pub mod tiles;

/// One lane kernel considered at a lane site (plan O10), for reports and
/// tests (the report shows it as a variant of its site).
#[derive(Clone, Debug)]
pub struct LaneReport {
    pub site: String,
    pub callee: String,
    pub target: String,
    pub lanes: usize,
    /// The lifted function's name (`s__<target>`).
    pub kernel: String,
    /// The proof's statistics, or why the kernel was not built.
    pub proof: Result<lift::LaneStats, String>,
    /// The kernel's cost per call (milli-cycles, the target's tables).
    pub lifted_cost: u64,
    /// The site's best existing code's cost per call, and what it is.
    pub site_cost: u64,
    pub site_best: String,
    /// Picked by the cost model (≥ 3% cheaper).
    pub chosen: bool,
    pub dispatched: bool,
    /// The evidence record name of the kernel (`lanes:<target>:<hash>`,
    /// the hash of its emitted text: [`lane_fingerprint`]) and whether a
    /// host has run it.
    pub lane_set: String,
    /// sha256 (hex) of the kernel item's printed tokens
    /// ([`LaneFingerprint::kernel_tokens`]); the round trip checks the
    /// emitted kernel against it.
    pub kernel_tokens: String,
    /// sha256 (hex) of the kernel's core text (the lane functor's plan),
    /// for reports: it does not name the evidence.
    pub core_hash: String,
    pub host_evidence: Result<String, String>,
    pub note: String,
}

impl Default for LaneReport {
    fn default() -> LaneReport {
        LaneReport {
            site: String::new(),
            callee: String::new(),
            target: String::new(),
            lanes: 0,
            kernel: String::new(),
            proof: Err("not attempted".into()),
            lifted_cost: 0,
            site_cost: 0,
            site_best: String::new(),
            chosen: false,
            dispatched: false,
            lane_set: String::new(),
            kernel_tokens: String::new(),
            core_hash: String::new(),
            host_evidence: Err("not attempted".into()),
            note: String::new(),
        }
    }
}

/// What a lane kernel's evidence record is keyed by (plan O10, §9.2): the
/// code a host compiles when it runs the kernel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaneFingerprint {
    /// sha256 (hex) of the kernel item's tokens as printed
    /// (`roundtrip::lane_item_tokens`: doc comments and visibility left
    /// out).
    pub kernel_tokens: String,
    /// sha256 (hex) of the whole emission text: the format tag, the target,
    /// the compiler ([`sandblaster_targets::evidence::BUILD_RUSTC`]), the
    /// kernel's tokens, and the tokens of every load/store helper and
    /// checked-arithmetic helper it calls.
    pub emission: String,
    /// The evidence record name, `lanes:<target>:<emission[..32]>`.
    pub set: String,
}

/// The fingerprint of the lane kernel `id` of `krate` on `target` (the
/// target's name): computed from the kernel as the optimized printer prints
/// it ([`crate::canon::lane_kernel_text`]) and from the helper templates as
/// printed ([`crate::canon::helper_fn_text`], [`crate::canon::rt_module`]).
/// The round trip checks that the emitted kernel has exactly these tokens,
/// and compares the printed helpers verbatim with the same templates, so
/// the set name always describes the emitted code.
pub fn lane_fingerprint(krate: &crate::hir::Crate, id: crate::hir::ItemId, target: &str) -> Result<LaneFingerprint, String> {
    use std::fmt::Write as _;
    let sha = |s: &str| sandblaster_targets::fips::hex(&sandblaster_targets::fips::sha256(s.as_bytes()));
    let t = crate::canon::lane_kernel_text(krate, id);
    let tokens = crate::roundtrip::lane_kernel_tokens(&t.item)?;
    let mut text = format!("sandblaster-lane-kernel/2\ntarget {target}\nrustc {}\nkernel {tokens}\n", sandblaster_targets::evidence::BUILD_RUSTC);
    for h in &t.helpers {
        let _ = writeln!(text, "helper {}", crate::roundtrip::template_tokens(&crate::canon::helper_fn_text(krate, *h, 0))?);
    }
    if !t.chk.is_empty() {
        let _ = writeln!(text, "rt {}", crate::roundtrip::template_tokens(&crate::canon::rt_module(&t.chk))?);
    }
    let emission = sha(&text);
    let set = format!("{}{target}:{}", sandblaster_targets::evidence::LANE_SET_PREFIX, &emission[..32]);
    Ok(LaneFingerprint { kernel_tokens: sha(&tokens), emission, set })
}
