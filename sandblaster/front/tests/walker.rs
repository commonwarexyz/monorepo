//! The walker (`crate::mir::simproof`, untrusted): theorems of lifted
//! functions against the literal reading of their MIR
//! (`docs/checked-structuring.md` §5), on the three crates' code.
//!
//! * `Subtree::reconstruct_digest` (the verifier's core: non-tail
//!   self-recursion, an `Option<&mut Vec>` cell passed down both calls,
//!   `?`, the hasher) with every lifted function it calls;
//! * a fuel-dependent callee: varint's `UInt<u32>::read_cfg` over the loop of
//!   `read::<u32>`;
//! * negative twins: a changed constant of `reconstruct_digest`'s MIR breaks
//!   its theorem, and the walk's failure names the function, the path of
//!   splits and both sides; the per-function budget stops a walk where it is.

use std::path::Path;

use sandblaster_front::mir::checked::{self, Entry, Prover};
use sandblaster_front::mir::ir;
use sandblaster_front::target::TargetInfo;

const M: &str = "commonware_storage::merkle";
const F: &str = "commonware_storage::merkle::mmr::Family";

fn thm(key: &str, s: &str) -> Entry {
    Entry::Fn { key: key.into(), s_global: s.into() }
}

/// What a test changes before proving.
#[derive(Default)]
struct Opts {
    /// `(key substring, old constant, new constant)`: the MIR changed first.
    fault: Option<(&'static str, i128, i128)>,
    /// The step budget of the last entry's walk.
    max_steps: Option<usize>,
}

/// Proves `entries` against the reading of `keys` in `root`'s first
/// extraction (after elaborating the items named by `items`): the result of
/// each entry, in order, stopping at the first failure.
fn prove(root: &str, items: &[&str], keys: &[String], entries: Vec<Entry>, opts: Opts) -> Vec<Result<checked::Proven, String>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(root);
    let c = sandblaster_front::driver::check(&root, &sandblaster_front::loader::RealFs, &TargetInfo::host());
    assert!(c.ok(), "{}", c.render());
    let k = c.krate.as_ref().unwrap();
    let (mm, contracts) = (c.lift_facts.mir_loaded[0].clone(), c.lift_facts.mir_contracts.clone());
    let items: Vec<String> = items.iter().map(|s| s.to_string()).collect();
    let keys = keys.to_vec();
    sandblaster_front::elab::with_big_stack(move || {
        let mut out = checked::elaborate_names(k, &items);
        let mut m: ir::Sbmir = mm.loaded.m.clone();
        if let Some((pat, old, new)) = opts.fault {
            let n = fault(&mut m, pat, old, new);
            assert!(n > 0, "the fault changed nothing");
        }
        let lit = checked::load_literal(&mut out.env, &m, &mm.loaded.names, &keys, None).unwrap_or_else(|e| panic!("{e}"));
        let mut pv = Prover::new(&mut out.env, &m, &mm.loaded.names, &lit, &out.pre_commit, &contracts);
        let mut res = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            if i + 1 == entries.len()
                && let Some(n) = opts.max_steps
            {
                pv.max_steps = n;
            }
            let r = pv.prove(e);
            let stop = r.is_err();
            res.push(r);
            if stop {
                break;
            }
        }
        res
    })
}

/// Every integer constant `old` of the statements of the functions whose
/// key contains `pat` becomes `new`; the number changed.
fn fault(m: &mut ir::Sbmir, pat: &str, old: i128, new: i128) -> usize {
    let mut n = 0;
    for (_, f) in m.fns.iter_mut().filter(|(k, _)| k.contains(pat)) {
        for st in f.blocks.iter_mut().flat_map(|b| b.stmts.iter_mut()) {
            if let ir::Stmt::Assign(_, rv, _) = st {
                let ops: Vec<&mut ir::Operand> = match rv {
                    ir::Rvalue::Bin(_, a, b) | ir::Rvalue::Checked(_, a, b) => vec![a, b],
                    ir::Rvalue::Use(a) => vec![a],
                    _ => vec![],
                };
                for o in ops {
                    if let ir::Operand::Const(c) = o
                        && let ir::Const::Int(t, x) = c.value().clone()
                        && x == old
                    {
                        *c = ir::Const::Int(t, new);
                        n += 1;
                    }
                }
            }
        }
    }
    n
}

/// `reconstruct_digest`'s MIR key.
fn rd_key() -> String {
    format!("{M}::proof::Subtree::<{F}>::reconstruct_digest::<commonware_cryptography::sha256::Digest, {M}::hasher::Standard<commonware_cryptography::Sha256>, std::iter::Copied<std::slice::Iter<'_, &[u8]>>>")
}

/// The theorems of `reconstruct_digest` and of every lifted function it
/// calls, callees first.
fn verifier_chain() -> Vec<Entry> {
    let h = format!("<{M}::hasher::Standard<commonware_cryptography::Sha256> as {M}::hasher::Hasher<{F}>>");
    vec![
        thm(&format!("{M}::position::Position::<{F}>::new"), "crate::merkle::position::Position::new"),
        thm(&format!("{M}::location::Location::<{F}>::new"), "crate::merkle::location::Location::new"),
        thm(&format!("<{M}::position::Position<{F}> as std::ops::Deref>::deref"), "crate::merkle::position::Position::deref"),
        thm(&format!("<{M}::position::Position<{F}> as std::ops::Sub<u64>>::sub"), "crate::merkle::position::Position::sub__u64"),
        thm(&format!("<{M}::location::Location<{F}> as std::ops::Add<u64>>::add"), "crate::merkle::location::Location::add__u64"),
        thm(&format!("<{M}::location::Location<{F}> as std::cmp::Ord>::cmp"), "crate::merkle::location::Location::cmp"),
        thm(&format!("<{M}::location::Location<{F}> as std::cmp::PartialOrd>::partial_cmp"), "crate::merkle::location::Location::partial_cmp"),
        thm(&format!("<{F} as {M}::Family>::children"), "crate::merkle::mmr::Family::children"),
        thm(&format!("{M}::proof::Subtree::<{F}>::leaf_end"), "crate::merkle::proof::Subtree::leaf_end"),
        thm(&format!("{M}::proof::Subtree::<{F}>::is_before"), "crate::merkle::proof::Subtree::is_before"),
        thm(&format!("{M}::proof::Subtree::<{F}>::is_outside"), "crate::merkle::proof::Subtree::is_outside"),
        thm(&format!("{M}::proof::Subtree::<{F}>::children"), "crate::merkle::proof::Subtree::children"),
        thm(&format!("{M}::hasher::Standard::<commonware_cryptography::Sha256>::hash"), "crate::merkle::hasher::Standard::hash"),
        thm(&format!("{h}::leaf_digest"), "crate::merkle::hasher::Standard::leaf_digest"),
        thm(&format!("{h}::node_digest"), "crate::merkle::hasher::Standard::node_digest"),
        thm(&rd_key(), "crate::merkle::proof::Subtree::reconstruct_digest"),
    ]
}

const VERIFIER: &str = "../../storage/sandblaster/verifier/mod.rs";
const VERIFIER_ITEMS: &[&str] = &["reconstruct_digest", "^words::", "^stdlib::", "^sha256::"];

#[test]
fn reconstruct_digest_is_proven_with_every_function_it_calls() {
    let res = prove(VERIFIER, VERIFIER_ITEMS, &[rd_key()], verifier_chain(), Opts::default());
    assert_eq!(res.len(), 16);
    for r in &res {
        if let Err(e) = r {
            panic!("{}", &e[..e.len().min(4000)]);
        }
    }
    // the self-recursion: both self-calls by the induction hypothesis, on
    // each presence of the collected digests
    let rd = res.last().unwrap().as_ref().unwrap();
    assert!(rd.stats.contains("inductions: 4"), "{}", rd.stats);
}

#[test]
fn a_changed_constant_of_reconstruct_digest_breaks_its_theorem_where_it_reads() {
    // `*cursor += 1` read as `+= 2`: the theorem fails, and the failure names
    // the function, the path to the tail and both sides
    let res = prove(VERIFIER, VERIFIER_ITEMS, &[rd_key()], verifier_chain(), Opts { fault: Some(("reconstruct_digest", 1, 2)), ..Default::default() });
    let e = res.last().unwrap().as_ref().expect_err("the faulted reading must not be proven");
    assert!(e.contains("walk of `crate::merkle::proof::Subtree::reconstruct_digest`"), "{e}");
    assert!(e.contains("in `crate::merkle::proof::Subtree::reconstruct_digest` at ") && e.contains("S-split on crate::merkle::proof::Subtree::is_outside"), "{e}");
    assert!(e.contains("literal side:") && e.contains("structured side:"), "{e}");
}

#[test]
fn the_budget_stops_a_walk_and_names_where() {
    let res = prove(VERIFIER, VERIFIER_ITEMS, &[rd_key()], verifier_chain(), Opts { max_steps: Some(40), ..Default::default() });
    assert_eq!(res.len(), 16);
    let e = res.last().unwrap().as_ref().expect_err("the budget must stop the walk");
    assert!(e.contains("budget of 40 steps is exhausted") && e.contains("in `crate::merkle::proof::Subtree::reconstruct_digest` at "), "{e}");
}

#[test]
fn a_fuel_dependent_callee_is_used_at_its_need() {
    let v = "commonware_codec::varint";
    let read = format!("{v}::read::<u32, &[u8]>");
    let read_cfg = format!("<{v}::UInt<u32> as commonware_codec::codec::Read>::read_cfg::<&[u8]>");
    let slots = vec![("l14".into(), "p0".into()), ("l2".into(), "p1".into()), ("c0".into(), "p2".into()), ("l1".into(), "code".into())];
    let res = prove(
        "../../codec/sandblaster/varint/mod.rs",
        &["read__u32", "read__u32__loop0", "UInt__u32::read_cfg"],
        &[format!("{v}::Decoder::<u32>::new"), format!("{v}::Decoder::<u32>::feed"), read.clone(), read_cfg.clone()],
        vec![
            thm(&format!("{v}::Decoder::<u32>::new"), "crate::varint::Decoder__u32::new"),
            thm(&format!("{v}::Decoder::<u32>::feed"), "crate::varint::Decoder__u32::feed"),
            Entry::Helper { key: read.clone(), s_global: "crate::varint::read__u32__loop0".into(), header: 10, slots },
            thm(&read, "crate::varint::read__u32"),
            // `read_cfg` calls the loop through `read::<u32>`: its fuel need
            // is `read::<u32>`'s, and the callee lemma applies at it
            thm(&read_cfg, "crate::varint::UInt__u32::read_cfg"),
        ],
        Opts::default(),
    );
    for r in &res {
        if let Err(e) = r {
            panic!("{}", &e[..e.len().min(4000)]);
        }
    }
    assert_eq!(res.len(), 5);
}
