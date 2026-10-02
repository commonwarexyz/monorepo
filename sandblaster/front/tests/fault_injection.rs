//! Fault injection (`docs/checked-structuring.md`, amendment (f)): the
//! theorems `L::thm::f` catch a misreading of rustc's MIR on either side.
//!
//! * **Per MIR construct** (the literal side): one construct of the MIR the
//!   literal reading L reads is changed — the structured reading S, read
//!   from the unchanged MIR, stays as it was — and the theorem of the
//!   function that contains it (or runs it, for a library instance) must
//!   fail, for its own reason (not because a callee failed), while the
//!   module's other theorems still hold. Constructs: an integer constant, a
//!   comparison, a bit operation, a checked operation, an assertion's
//!   expected value, a switch's targets, an aggregate's variant, a `&mut`
//!   borrow's place, a call's arguments, a statement, a `goto`, the return
//!   place, a shift (unsigned and signed) and an intrinsic in library MIR, a
//!   discriminant's switch in library MIR, a unary operator, a cast, and a
//!   leaf call's argument. The mutations are grouped into batches whose
//!   targets are independent (the three instances of `Decoder::<U>::feed`,
//!   of `un_zigzag`, ..), one kernel environment per batch.
//! * **The two historical structuring bugs** (the structured side),
//!   re-injected into `read.rs` behind `lift::test_hook`: a value snapshot
//!   restoring a variable after an in-place write, and a matched field's
//!   write-back taken before two pushes (the verifier's
//!   `reconstruct_digest`: no law or proof speaks of `collected`, so the
//!   proofs pass on the misreading; the theorem does not).
//! * **Amendment (b)**: a structured reading that adds a precondition the
//!   declared contract lacks gets no theorem (the statement refuses it).

use std::path::Path;
use std::sync::Arc;

use sandblaster_front::driver::gates::{theorem_gate, GateReport};
use sandblaster_front::driver::Checked;
use sandblaster_front::lift::test_hook::{self, WrongRule};
use sandblaster_front::lift::LiftFacts;
use sandblaster_front::mir::checked::{self, GateOptions, ModuleTheorems};
use sandblaster_front::mir::ir::{self, AggKind, Callee, Const, Operand, Place, Proj, Rvalue, Stmt, Term, Ty};
use sandblaster_front::target::TargetInfo;

const VARINT: &str = "../../codec/sandblaster/varint/mod.rs";
const VERIFIER: &str = "../../storage/sandblaster/verifier/mod.rs";

/// A crate as the front end reads it (with a wrong reading rule).
fn read_crate(root: &str, hook: Option<WrongRule>) -> Checked {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(root);
    test_hook::set(hook);
    let c = sandblaster_front::driver::check(&root, &sandblaster_front::loader::RealFs, &TargetInfo::host());
    test_hook::set(None);
    assert!(c.ok(), "{}", c.render());
    c
}

/// The gate's theorems on the structured reading of `c`'s lifted functions
/// (and of the prover's bridges and library, as the build elaborates them),
/// with the MIR the literal reading reads taken from `facts`.
fn theorems(c: &Checked, facts: &LiftFacts) -> ModuleTheorems {
    let mut reps = sandblaster_front::elab::with_big_stack(move || {
        let k = c.krate.as_ref().unwrap();
        let mut items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
        items.extend(["^words::", "^stdlib::", "^sha256::"].map(String::from));
        let mut out = checked::elaborate_names(k, &items);
        checked::prove_lifted(&mut out, facts, &GateOptions::default())
    });
    assert_eq!(reps.len(), 1, "one lifted MIR module");
    reps.remove(0)
}

/// The outcome of `global`'s theorem: `Ok` proven, `Err` why not.
fn outcome<'m>(m: &'m ModuleTheorems, global: &str) -> Result<(), &'m str> {
    if let Some(o) = m.outcomes.iter().find(|o| o.is_fn && o.global == global) {
        return o.result.as_ref().map(|_| ()).map_err(|e| e.as_str());
    }
    m.missing.iter().find(|(g, _)| g == global).map(|(_, why)| Err(why.as_str())).unwrap_or_else(|| panic!("no theorem planned for `{global}`"))
}

// ---------------------------------------------------------------------------
// per construct
// ---------------------------------------------------------------------------

/// One mutation: the MIR instance it changes, what it is, the change (which
/// checks the shape it expects first), and the lifted function whose
/// theorem must fail.
struct Mutation {
    key: &'static str,
    construct: &'static str,
    change: fn(&mut ir::Fn),
    target: &'static str,
}

fn feed(w: &str) -> String {
    format!("commonware_codec::varint::Decoder::<{w}>::feed")
}

fn stmt(f: &mut ir::Fn, b: usize, i: usize) -> &mut Stmt {
    &mut f.blocks[b].stmts[i]
}

fn rvalue(f: &mut ir::Fn, b: usize, i: usize) -> &mut Rvalue {
    match stmt(f, b, i) {
        Stmt::Assign(_, rv, _) => rv,
        other => panic!("bb{b}[{i}] is no assignment: {other:?}"),
    }
}

// `Decoder::<U>::feed` (the same blocks at every width)

/// `byte == 0` reads `byte == 1`.
fn const_int(f: &mut ir::Fn) {
    let Rvalue::Bin(op, _, Operand::Const(c)) = rvalue(f, 1, 1) else { panic!("bb1[1]") };
    assert_eq!(op, "eq");
    assert_eq!(*c, Const::Int(Ty::Int(false, 8), 0));
    *c = Const::Int(Ty::Int(false, 8), 1);
}

/// `self.bits_read > 0` reads `>=`.
fn comparison(f: &mut ir::Fn) {
    let Rvalue::Bin(op, ..) = rvalue(f, 2, 1) else { panic!("bb2[1]") };
    assert_eq!(op, "gt");
    *op = "ge".into();
}

/// `byte & DATA_BITS_MASK` reads `|`.
fn bit_operation(f: &mut ir::Fn) {
    let Rvalue::Bin(op, ..) = rvalue(f, 11, 1) else { panic!("bb11[1]") };
    assert_eq!(op, "and");
    *op = "or".into();
}

/// `U::SIZE * BITS_PER_BYTE` (checked) reads `+`.
fn checked_operation(f: &mut ir::Fn) {
    let Rvalue::Checked(op, ..) = rvalue(f, 0, 0) else { panic!("bb0[0]") };
    assert_eq!(op, "mul");
    *op = "add".into();
}

/// The overflow assertion expects `true` (its flag is `false` on every input).
fn assertion(f: &mut ir::Fn) {
    let Term::Assert(_, expected, _, _) = &mut f.blocks[0].term else { panic!("bb0's terminator") };
    assert!(!*expected);
    *expected = true;
}

/// `if byte == 0 ..`'s switch with its targets swapped.
fn switch_targets(f: &mut ir::Fn) {
    let Term::Switch(_, arms, otherwise) = &mut f.blocks[1].term else { panic!("bb1's terminator") };
    assert_eq!((arms.as_slice(), *otherwise), (&[(0u128, 4usize)][..], 2));
    (arms[0].1, *otherwise) = (2, 4);
}

/// `Error::InvalidVarint(U::SIZE)` reads `Error::ExtraData(U::SIZE)`.
fn aggregate_variant(f: &mut ir::Fn) {
    let Rvalue::Agg(AggKind::Adt(_, v), _) = rvalue(f, 10, 0) else { panic!("bb10[0]") };
    assert_eq!(*v, 2);
    *v = 1;
}

/// `&mut self.result` reads `&mut _28` (a local of the same type).
fn borrow_place(f: &mut ir::Fn) {
    let Rvalue::Ref(k, p) = rvalue(f, 11, 0) else { panic!("bb11[0]") };
    assert_eq!((k.as_str(), p.local, p.proj.len()), ("mut", 1, 2));
    *p = Place { local: 28, proj: vec![] };
}

/// `max_bits.checked_sub(self.bits_read)` reads its arguments swapped.
fn call_arguments(f: &mut ir::Fn) {
    let Term::Call(Callee::Fn(k), args, _, _) = &mut f.blocks[4].term else { panic!("bb4's terminator") };
    assert!(k.ends_with("checked_sub"));
    args.swap(0, 1);
}

/// `self.bits_read += DATA_BITS_PER_BYTE`'s write through `self` is dropped.
fn statement(f: &mut ir::Fn) {
    let Stmt::Assign(p, _, _) = stmt(f, 17, 0) else { panic!("bb17[0]") };
    assert_eq!((p.local, p.proj.first()), (1, Some(&Proj::Deref)));
    f.blocks[17].stmts.remove(0);
}

/// The `InvalidVarint` path's `goto` to the return goes to the block before it.
fn goto_target(f: &mut ir::Fn) {
    assert!(matches!(f.blocks[3].term, Term::Goto(18)));
    f.blocks[3].term = Term::Goto(17);
}

/// `return Ok(Some(self.result))`'s assignment of the return place is dropped.
fn return_place(f: &mut ir::Fn) {
    let Stmt::Assign(p, _, _) = stmt(f, 15, 2) else { panic!("bb15[2]") };
    assert_eq!(p.local, 0);
    f.blocks[15].stmts.remove(2);
}

// `<iN as SPrim>::un_zigzag`, `as_zigzag` and library instances

/// `-(value & 1)` reads `value & 1`.
fn unary(f: &mut ir::Fn) {
    let rv = rvalue(f, 2, 0);
    let Rvalue::Un(op, x) = rv.clone() else { panic!("bb2[0]") };
    assert_eq!(op, "neg");
    *rv = Rvalue::Use(x);
}

/// `(value >> 1) as iN` reads a transmute (which L does not read for a word).
fn cast(f: &mut ir::Fn) {
    let Rvalue::Cast(kind, ..) = rvalue(f, 1, 1) else { panic!("bb1[1]") };
    assert_eq!(kind, "int-to-int");
    *kind = "transmute".into();
}

/// core's `<u32 as Shl<usize>>::shl` reads `>>`.
fn shift(f: &mut ir::Fn) {
    let Rvalue::Bin(op, ..) = rvalue(f, 1, 0) else { panic!("bb1[0]") };
    assert_eq!(op, "shl");
    *op = "shr".into();
}

/// core's `<&i64 as Shr<usize>>::shr` (signed: arithmetic) reads `<<`.
fn signed_shift(f: &mut ir::Fn) {
    let site = f.blocks.iter_mut().flat_map(|b| b.stmts.iter_mut()).find_map(|s| match s {
        Stmt::Assign(_, Rvalue::Bin(op, _, _), _) if op == "shr" => Some(op),
        _ => None,
    });
    *site.expect("a `shr`") = "shl".into();
}

/// core's `u8::leading_zeros` reads the `cttz` intrinsic.
fn intrinsic(f: &mut ir::Fn) {
    let Term::Call(Callee::Intrinsic(n, _), ..) = &mut f.blocks[0].term else { panic!("bb0's terminator") };
    assert_eq!(n, "ctlz");
    *n = "cttz".into();
}

/// core's `Option::<usize>::unwrap` switches on the discriminant with the
/// arms swapped (`Some` panics).
fn discriminant_switch(f: &mut ir::Fn) {
    let Term::Switch(_, arms, _) = &mut f.blocks[0].term else { panic!("bb0's terminator") };
    assert_eq!(arms.as_slice(), &[(0u128, 2usize), (1, 3)][..]);
    (arms[0].1, arms[1].1) = (3, 2);
}

/// `write::<u32>`'s `buf.put_u8(value.as_u8())` puts the byte `0`.
fn leaf_argument(f: &mut ir::Fn) {
    let Term::Call(Callee::Leaf(p, _), args, _, _) = &mut f.blocks[4].term else { panic!("bb4's terminator") };
    assert!(p.ends_with("put_u8"));
    args[1] = Operand::Const(Const::Int(Ty::Int(false, 8), 0));
}

fn batches() -> Vec<Vec<Mutation>> {
    let f16: &'static str = Box::leak(feed("u16").into_boxed_str());
    let f32: &'static str = Box::leak(feed("u32").into_boxed_str());
    let f64: &'static str = Box::leak(feed("u64").into_boxed_str());
    let m = |key, construct, change, target| Mutation { key, construct, change, target };
    vec![
        vec![
            m(f16, "integer constant", const_int, "crate::varint::Decoder__u16::feed"),
            m(f32, "comparison", comparison, "crate::varint::Decoder__u32::feed"),
            m(f64, "bit operation", bit_operation, "crate::varint::Decoder__u64::feed"),
            m("<i16 as commonware_codec::varint::sealed::SPrim>::un_zigzag", "unary operator", unary, "crate::varint::SPrim__i16__un_zigzag"),
            m("<i32 as commonware_codec::varint::sealed::SPrim>::un_zigzag", "cast", cast, "crate::varint::SPrim__i32__un_zigzag"),
        ],
        vec![
            m(f16, "checked operation", checked_operation, "crate::varint::Decoder__u16::feed"),
            m(f32, "assertion", assertion, "crate::varint::Decoder__u32::feed"),
            m(f64, "switch", switch_targets, "crate::varint::Decoder__u64::feed"),
        ],
        vec![
            m(f16, "aggregate", aggregate_variant, "crate::varint::Decoder__u16::feed"),
            m(f32, "mutable borrow", borrow_place, "crate::varint::Decoder__u32::feed"),
            m(f64, "call", call_arguments, "crate::varint::Decoder__u64::feed"),
        ],
        vec![
            m(f16, "statement", statement, "crate::varint::Decoder__u16::feed"),
            m(f32, "goto", goto_target, "crate::varint::Decoder__u32::feed"),
            m(f64, "return place", return_place, "crate::varint::Decoder__u64::feed"),
        ],
        vec![
            m("<u32 as std::ops::Shl<usize>>::shl", "shift (library MIR)", shift, "crate::varint::Decoder__u32::feed"),
            m("<&i64 as std::ops::Shr<usize>>::shr", "signed shift (library MIR)", signed_shift, "crate::varint::SPrim__i64__as_zigzag"),
            m("commonware_codec::varint::write::<u32, &mut [u8]>", "leaf call", leaf_argument, "crate::varint::write__u32"),
        ],
        vec![m("core::num::<impl u8>::leading_zeros", "intrinsic (library MIR)", intrinsic, "crate::varint::Decoder__u16::feed")],
        vec![m("std::option::Option::<usize>::unwrap", "discriminant switch (library MIR)", discriminant_switch, "crate::varint::Decoder__u32::feed")],
    ]
}

#[test]
fn a_mutated_mir_construct_breaks_the_theorem_of_the_function_that_runs_it() {
    let c = read_crate(VARINT, None);
    let mut caught = Vec::new();
    for batch in batches() {
        let mut facts = c.lift_facts.clone();
        let mut loaded = (*facts.mir_loaded[0].loaded).clone();
        for mu in &batch {
            let f = loaded.m.fns.get_mut(mu.key).unwrap_or_else(|| panic!("no MIR instance `{}`", mu.key));
            (mu.change)(f);
        }
        facts.mir_loaded[0].loaded = Arc::new(loaded);
        let m = theorems(&c, &facts);
        for mu in &batch {
            match outcome(&m, mu.target) {
                Ok(()) => panic!("{} changed in `{}`: the theorem of `{}` still holds", mu.construct, mu.key, mu.target),
                Err(why) => {
                    assert!(!why.starts_with("not attempted"), "{}: `{}` failed only through a callee: {why}", mu.construct, mu.target);
                    caught.push(format!("{}: {}", mu.construct, mu.target));
                }
            }
        }
        // the module's other theorems are untouched (the unsigned codec of
        // another width, the sizes)
        for g in ["crate::varint::size__u32", "crate::varint::UPrim__u16__as_u8", "crate::varint::SPrim__i16__as_zigzag"] {
            if batch.iter().any(|mu| mu.target == g) {
                continue;
            }
            assert_eq!(outcome(&m, g), Ok(()), "`{g}` is not touched by {:?}", batch.iter().map(|mu| mu.construct).collect::<Vec<_>>());
        }
    }
    eprintln!("caught: {caught:#?}");
    assert_eq!(caught.len(), 19);
}

// ---------------------------------------------------------------------------
// the historical structuring bugs, and amendment (b)
// ---------------------------------------------------------------------------

/// The gate on `c`: its `mir-theorem` errors and whether it passed.
fn gate(c: &Checked) -> (Vec<String>, bool) {
    sandblaster_front::elab::with_big_stack(move || {
        let k = c.krate.as_ref().unwrap();
        let mut items: Vec<String> = c.lift_facts.mir_contracts.iter().map(|x| x.global.trim_start_matches("crate::").to_string()).chain(c.lift_facts.mir_helpers.iter().map(|x| x.global.trim_start_matches("crate::").to_string())).collect();
        items.extend(["^words::", "^stdlib::", "^sha256::"].map(String::from));
        let mut out = checked::elaborate_names(k, &items);
        let mut g = GateReport::default();
        theorem_gate(&mut out, k, c, &mut g);
        let errs: Vec<String> = g.diags.list.iter().filter(|d| d.kind == sandblaster_front::diag::DiagKind::MirTheorem).map(|d| d.msg.clone()).collect();
        (errs, g.passed())
    })
}

/// Historical bug 2: `reconstruct_digest`'s pushes into the matched field of
/// `collected` are written back from a copy taken before them. The
/// structured reading still elaborates and its proofs pass; the theorem fails.
#[test]
fn a_write_back_taken_before_two_pushes_fails_reconstruct_digest() {
    let c = read_crate(VERIFIER, Some(WrongRule::WritebackSnapshot));
    let (errs, passed) = gate(&c);
    assert!(!passed, "the misread module must not pass the gate");
    assert!(errs.iter().any(|e| e.starts_with("`crate::merkle::proof::Subtree::reconstruct_digest` has no kernel-checked theorem") && !e.contains("not attempted")), "{errs:#?}");
    // and only the function the misreading touches
    assert!(!errs.iter().any(|e| e.starts_with("`crate::merkle::hasher::Standard::node_digest`")), "{errs:#?}");
}

/// Historical bug 1: before a variable changes in place (an element of
/// `write`'s byte array written), its own value is snapshotted with the
/// values that read it, so the reads after the write restore the old array.
/// On varint the misreading also breaks the structured reading's own proofs
/// (the loop helper of `write` is rejected); the gate fails independently:
/// `write::<uN>` gets no theorem, its loop lemma having none, and nothing
/// else breaks. The MMR and the verifier have no in-place write this
/// misreading changes (their theorems all hold under it).
#[test]
fn a_snapshot_restoring_a_variable_after_an_in_place_write_fails_its_theorems() {
    let c = read_crate(VARINT, Some(WrongRule::SnapshotOwnValue));
    let (errs, passed) = gate(&c);
    assert!(!passed, "a misread module must not pass the gate");
    for w in ["u16", "u32", "u64"] {
        let f = format!("`crate::varint::write__{w}` has no kernel-checked theorem");
        assert!(errs.iter().any(|e| e.starts_with(&f) && e.contains(&format!("write__{w}::loop#0"))), "{f}: {errs:#?}");
    }
    // only `write` and the functions that call it
    assert!(errs.iter().all(|e| e.contains("write")), "{errs:#?}");
}

/// Amendment (b): a structured reading carrying a precondition the declared
/// contract does not state gets no theorem (the statement refuses it), so
/// an untrusted structurer cannot make a theorem vacuous.
#[test]
fn a_precondition_the_declared_contract_lacks_is_refused() {
    let c = read_crate(VARINT, Some(WrongRule::ExtraRequires));
    // the declared contract is the skeleton's and the attachments' only
    let feed = c.lift_facts.mir_contracts.iter().find(|k| k.global == "crate::varint::Decoder__u32::feed").expect("feed's contract");
    assert!(!feed.requires.iter().any(|r| r.contains("true")), "{:?}", feed.requires);
    let (errs, passed) = gate(&c);
    assert!(!passed);
    let refused: Vec<&String> = errs.iter().filter(|e| e.contains("which its declared contract") && e.contains("does not state")).collect();
    // (the hook reads the private free functions with the extra clause)
    for f in ["size__u64", "read__u32", "write__u16", "size__u16"] {
        assert!(refused.iter().any(|e| e.starts_with(&format!("`crate::varint::{f}`"))), "{f}: {errs:#?}");
    }
    // a function read without it still has its theorem
    assert!(!errs.iter().any(|e| e.starts_with("`crate::varint::Decoder__u32::feed`")), "{errs:#?}");
}
