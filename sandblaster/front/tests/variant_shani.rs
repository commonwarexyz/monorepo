//! `VariantEquiv` of the x86_64 SHA-NI variant (DESIGN.md §9.3, §9.8):
//! `crate::sha256::compress_shani == crate::sha256::compress`, proven by
//! `BvRefl` on the elaborated `sandblaster/fixtures/qmdb/sandblaster/sha256.rs` for
//! `x86_64-apple-darwin` (the proof does not need the hardware: it
//! evaluates the core-text intrinsic models symbolically).
//!
//! * The real variant proves directly (no transparent copy), in well under
//!   a second and a few MB of heap. It failed before `bvnorm` recorded
//!   distributed low chunks (rule 7, `lows`): the final `_mm_blend_epi16`
//!   regroups the bytes of each output sum into 16-bit words and back, and
//!   the normalizer could not return the low byte and low half to the sum.
//! * Deliberately wrong variants (a blend mask, a shuffle constant, a byte
//!   of the byte-swap mask, an `alignr` amount or operand order) are each
//!   first shown wrong by kernel evaluation on the FIPS 180-4 "abc" block,
//!   then **rejected** by `BvRefl`.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sandblaster_front::driver;
use sandblaster_front::elab::{self, ProverChain};
use sandblaster_front::loader::MemFs;
use sandblaster_front::opt::variant;
use sandblaster_front::target::TargetInfo;
use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::Lvl;
use sandblaster_kernel::value::{Budget, VEnv};

/// One elaboration at a time (heap measurements are per process).
static SERIAL: Mutex<()> = Mutex::new(());

/// `compress(INITIAL, pad("abc"))`: SHA-256("abc") (FIPS 180-4 B.1).
const ABC: [u32; 8] = [0xba78_16bf, 0x8f01_cfea, 0x4141_40de, 0x5dae_2223, 0xb003_61a3, 0x9617_7a9c, 0xb410_ff61, 0xf200_15ad];
const INITIAL: [u32; 8] = [0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19];

fn sha256_src() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sandblaster/fixtures/qmdb/sandblaster/sha256.rs")).unwrap()
}

struct Attempt {
    /// `compress_shani` on the "abc" block, by kernel evaluation.
    abc: [u32; 8],
    proof: Result<variant::Equiv, String>,
    time: Duration,
    /// Heap growth of the process during the proof (bytes, peak − before).
    heap: usize,
}

/// Elaborates `src` as `sha256` of a one-module crate for x86_64, evaluates
/// the variant on the "abc" block and attempts its `VariantEquiv`.
fn attempt(src: &str) -> Attempt {
    let mut fs = MemFs::new();
    fs.insert("q/mod.rs", "#![forbid(unsafe_code)]\npub mod sha256;\n");
    fs.insert("q/sha256.rs", src);
    let c = driver::check(Path::new("q/mod.rs"), &fs, &TargetInfo::x86_64_apple_darwin());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    elab::with_big_stack(|| {
        let mut chain = ProverChain::standard();
        let mut out = elab::elaborate(k, &mut chain, &elab::Options { exec_only: true, ..Default::default() });
        let gv = out.env.lookup_global("crate::sha256::compress_shani").expect("the variant is elaborated");
        let gp = out.env.lookup_global("crate::sha256::compress").expect("the portable function is elaborated");
        let abc = eval_abc(&out.env);
        let before = sandblaster_memguard::allocated();
        let t = Instant::now();
        let proof = variant::prove(&mut out.env, gv, gp, 2_000_000_000);
        let time = t.elapsed();
        let heap = sandblaster_memguard::peak().saturating_sub(before);
        Attempt { abc, proof, time, heap }
    })
}

/// `crate::sha256::compress_shani(INITIAL, pad("abc"))` by kernel evaluation
/// (the intrinsic models compute on closed data, §5.6).
fn eval_abc(env: &Env) -> [u32; 8] {
    let mut block = [0u8; 64];
    block[..3].copy_from_slice(b"abc");
    block[3] = 0x80;
    block[63] = 24;
    let blk = format!("pair(Array U8 64usize, {}, refl(Int, 64int))", block.iter().rev().fold("Nil[U8]".to_string(), |acc, b| format!("Cons[U8]({b}u8, {acc})")));
    let st = format!("pair(Array U32 8usize, {}, refl(Int, 8int))", INITIAL.iter().rev().fold("Nil[U32]".to_string(), |acc, w| format!("Cons[U32]({w}u32, {acc})")));
    core::array::from_fn(|i| {
        let src = format!("array::index U32 8usize (crate::sha256::compress_shani ({st}) ({blk})) {i}usize .refl(Bool, true)");
        let t = env.parse_term(&[], &src).unwrap_or_else(|e| panic!("{e}"));
        let v = env.eval(&VEnv::default(), Lvl(0), &t, &mut Budget { steps: 1 << 32 }).unwrap();
        let s = env.print_term(&[], &env.quote(Lvl(0), &v, false));
        s.strip_suffix("u32").and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("word {i} is not a literal: {s}"))
    })
}

#[test]
fn compress_shani_variant_equiv_is_proven() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let a = attempt(&sha256_src());
    assert_eq!(a.abc, ABC, "compress_shani computes SHA-256(\"abc\")");
    // directly against the portable function (no transparent copy needed)
    a.proof.unwrap_or_else(|e| panic!("VariantEquiv(compress_shani, compress) not proven: {e}"));
    println!("VariantEquiv(compress_shani, compress): {:?}, heap +{} KiB", a.time, a.heap >> 10);
    // far from the multi-GB paths of whole-hash equalities (DESIGN.md §9.8)
    assert!(a.time < Duration::from_secs(60), "{:?}", a.time);
    assert!(a.heap < 2 << 30, "heap +{} MiB", a.heap >> 20);
}

/// Each mutation changes one constant of the variant; each mutant computes
/// a wrong digest and must be rejected by `BvRefl`.
#[test]
fn wrong_shani_variants_are_rejected() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let src = sha256_src();
    let mutations: [(&str, &str, &str); 8] = [
        ("final blend mask swapped", "let dcba = _mm_blend_epi16::<0xF0>(feba, dchg);", "let dcba = _mm_blend_epi16::<0x0F>(feba, dchg);"),
        ("final blend mask, one word", "let dcba = _mm_blend_epi16::<0xF0>(feba, dchg);", "let dcba = _mm_blend_epi16::<0xF1>(feba, dchg);"),
        ("state packing blend mask", "let cdgh_in = _mm_blend_epi16::<0xF0>(efgh, cdab);", "let cdgh_in = _mm_blend_epi16::<0xCC>(efgh, cdab);"),
        ("state packing shuffle constant", "let cdab = _mm_shuffle_epi32::<0xB1>(dcba);", "let cdab = _mm_shuffle_epi32::<0x1B>(dcba);"),
        ("round-pair wk shuffle constant", "_mm_shuffle_epi32::<0x0E>(wk)", "_mm_shuffle_epi32::<0x0B>(wk)"),
        ("byte-swap mask", "const BSWAP32_MASK: [u8; 16] = [3, 2, 1, 0,", "const BSWAP32_MASK: [u8; 16] = [2, 3, 1, 0,"),
        ("schedule alignr amount", "_mm_alignr_epi8::<4>(w3, w2)", "_mm_alignr_epi8::<8>(w3, w2)"),
        ("final alignr operand order", "let hgef = _mm_alignr_epi8::<8>(dchg, feba);", "let hgef = _mm_alignr_epi8::<8>(feba, dchg);"),
    ];
    for (what, from, to) in mutations {
        assert_eq!(src.matches(from).count(), 1, "{what}: `{from}` must occur once");
        let a = attempt(&src.replacen(from, to, 1));
        assert_ne!(a.abc, ABC, "{what}: the mutant must compute a wrong digest");
        match &a.proof {
            Ok(_) => panic!("UNSOUND: BvRefl accepts a wrong SHA-NI variant ({what})"),
            Err(e) => {
                // Rejected because the normal forms differ (not by the
                // one-width-per-class guard, whose message starts the same).
                let differ = e.contains("bvrefl: the sides are not equal modulo word algebra") && e.contains("normal forms differ");
                assert!(differ || e.contains("rejected by the tripwire"), "{what}: {e}");
                println!("{what}: rejected in {:?}", a.time);
            }
        }
    }
}
