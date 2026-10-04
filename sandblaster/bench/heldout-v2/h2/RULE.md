# H2 sampling rule, version 2 (H2-v2)

```
rule    = h2-v2
seed    = 7bc58f68b25930aa17c68e7c870edb9a
written = 2026-10-02T20:12:14Z (seed drawn with `openssl rand -hex 16`)
source  = monorepo commit 2b3ec7cdc1f3d4fbd5c3001d385350477b140981
```

H2-v2 is the rule-sampled half of held-out v2. It is real monorepo code,
taken by this rule from crates that development does not touch. This rule
and its seed were written before any candidate was enumerated, and before
any source file in the scope (§1) was read for this purpose. Version 1
(`sandblaster/bench/heldout/h2/RULE.md`) is retired to the development set
(`sandblaster/bench/heldout/README.md`). This rule reuses its text where it
can and widens its pool, so that a wider reader can reach 40 functions.

**Order of work.** This file is frozen now, before the reader and optimizer
work. The evaluation stage samples H2-v2 after that work, with this rule
unchanged. Nothing below may change once enumeration starts. If the probe
fails on every candidate for an infrastructural reason (a wrong path, the
toolchain, a template bug), the probe may be fixed. Each such fix is
written to `PROBE-LOG.md` (beside this file) with its reason, applies to
every candidate alike, never changes a criterion and never targets one
function. A change of criterion is a new rule version, with new files, and
leaves this one frozen.

**Source.** Every scope file is read as it is at the source commit above.
Before enumerating, the sampler checks that each scope file in its tree has
the same content as at that commit. If a file differs, the sampler reads
the commit's version instead. `sample-manifest.toml` records the SHA-256 of each
sampled function's file, and of every callee file lifted with it.

## 0. Quarantine: what development must not look at

Development means reader, elaborator, optimizer and lowering work done
before H2-v2 is sampled. It MUST NOT look at code in the scope of §1:
- the source files of the scope crates and scope modules;
- their MIR, or any extraction, probe or lift output made from them;
- any refusal or diagnostic produced on them.

Development MUST NOT run this rule's enumeration or probe either. The same
holds for held-out v2's blind H1 set (`../h1/`): development does not read
its code, and nothing is run on it before the evaluation stage.

Development works only against:
- held-out v1, now development (`sandblaster/bench/heldout/`, including its
  H2 probe and rejection rows);
- the development corpus (`sandblaster/front/tests/opt_corpus`, the QMDB
  port and its fixtures, the MIR fixtures);
- core and std patterns (the std/core MIR the reader reads, and small
  programs written to exercise them);
- `commonware-codec`;
- `commonware-cryptography` outside the hash cores, where the hash cores are
  `cryptography/src/{sha256,blake3,keccak256,crc32,lthash}`;
- `commonware-coding`;
- `commonware-storage` outside the scope modules of §1.

Some crates are reached from those through dependencies:
`commonware-utils`, `commonware-math`, `commonware-parallel`,
`commonware-runtime`, `commonware-formatting`, `commonware-invariants`,
`commonware-conformance` and the macro crates. They are neither scope nor
development. Development may read their code only where a development lift
reaches it as a callee. It never takes them as a target of their own.

Why the scope is safe from callee reach: §1 takes exactly the workspace
library crates and storage modules that no development crate or module
depends on, directly or transitively. A development lift that follows its
callees therefore never enters the scope.

The review rule applies (DESIGN.md §8.2 item 11). A change motivated by
scope code is not merged. If scope code is looked at before sampling, the
look is written to `PROBE-LOG.md`. Every scope file that was looked at
leaves the scope before enumeration: its functions are excluded, with
reason `excluded: seen during development`. This exclusion is
per file and is applied before the seeded order exists.

## 1. Scope

The scope is every workspace library crate, and every module of
`commonware-storage`, that lies outside the dependency closure of the
development crates (`[dependencies]` of each `Cargo.toml`, and for storage
the `crate::` imports between its top-level modules), at the source commit.
Tooling crates are left out: the sandblaster toolchain, examples, fuzz,
benchmarks, deployer, conformance, macro and proc-macro crates. Computed at
the source commit:

| package | modules in scope (paths are the crate's `src/` files) |
| --- | --- |
| `commonware-actor` | the whole crate |
| `commonware-broadcast` | the whole crate |
| `commonware-collector` | the whole crate |
| `commonware-consensus` | the whole crate |
| `commonware-glue` | the whole crate |
| `commonware-p2p` | the whole crate |
| `commonware-resolver` | the whole crate |
| `commonware-stream` | the whole crate |
| `commonware-storage` | `archive`, `cache`, `ordinal`, `queue`, `rmap` (`src/archive/**`, `src/cache/**`, `src/ordinal/**`, `src/queue/**`, `src/rmap/**`) |

The closure, for the record:
- codec depends on no other library crate in the table.
- cryptography reaches utils, math, parallel and formatting.
- coding reaches those, plus codec, cryptography and storage.
- storage reaches runtime. Inside storage, the development modules (`merkle`,
  `bmt`, `bitmap`, `qmdb`, `utils`) import `journal`, `metadata`, `index`
  and `translator`, and `journal` imports `freezer`.

So `journal`, `freezer`, `metadata`, `index` and `translator` are
development, and `ordinal`, `archive`, `cache`, `queue` and `rmap` are
not reached. No crate in the table is a dependency of a development crate.

Unlike v1, consensus is not restricted to arithmetic signatures. No part of
consensus is a target, and the purity criteria of §3 apply to it like to
every scope crate.

## 2. Exclusions

A function is excluded when any of these holds. The first that holds is the
reason given.

1. **Target areas.** Its signature or body names a target area by any of
   these tokens: `varint`, `merkle`, `mmr`, `bmt`, `qmdb`, `sha256`,
   `Sha256`, `blake3`, `Blake3`, `keccak`, `Keccak`, `bls12381`, `ed25519`,
   `reed_solomon`, `ReedSolomon`. The areas themselves (codec `varint`;
   storage `merkle`/`mmr`/`bmt`/`qmdb`; cryptography; coding) are outside
   the scope anyway.
2. **The corpus.** Its name equals the last segment of any
   `sandblaster/front/tests/opt_corpus/corpus.toml` `functions` entry.
3. **The §15 workloads.** Its name equals the last segment of a function the
   workload matrix of `sandblaster/docs/optimizer-design.md` §15 names in
   code font: `parse`, `shape_go`, `shape`, `cswap`, `mul_by_014`,
   `verify_many`, `mul`.
4. **Test, mock or fuzz code:**
   - a `#[test]` function;
   - an item under a `cfg` attribute that mentions `test`, `mocks`,
     `test-utils`, `fuzzing` or `arbitrary`;
   - a file with a path component (directory or file stem) named `tests`,
     `test`, `mocks`, `mock`, `test_utils`, `fuzz`, `benches`, `bench`,
     or `examples`.
5. **Held-out v1.** Its id (§4) equals the id of any row of
   `sandblaster/bench/heldout/h2/candidates.tsv`. Those functions were
   probed under v1 and their refusals were read, so they are development.
6. **Seen during development** (§0): its file left the scope.

## 3. Candidates

Enumeration takes every `fn` item written in a scope file:
- at module level;
- in a module-level inherent `impl` block;
- in a module-level trait `impl` block (`impl Trait for Type`).

It skips:
- functions inside inline `mod x { .. }` blocks and inside macro invocations
  or `macro_rules!` bodies, which are not items of the file as written;
- a trait's own items, both its required methods (no body) and its provided
  methods (no `Self` to read them at).

Enumeration is lexical: comments, strings and character literals are
stripped first. It never reads a function for any purpose other than these
criteria.

A function is a candidate when all of these hold:

- **No I/O and no shared state.** Its signature and body name none of:
  - `io`, `fs`, `net`, `File`, `TcpStream`, `TcpListener`, `UdpSocket`;
  - `println`, `eprintln`, `print`, `eprint`, `dbg`;
  - `tokio`, `futures`, `spawn`, `thread`, `Instant`, `SystemTime`;
  - `Clock`, `Spawner`, `Storage`, `Blob`, `Network`, `Sink`, `Stream`,
    `Metrics`, `metrics`, `Context`;
  - `tracing`, `trace`, `debug`, `info`, `warn`, `error` (as macros, that
    is, followed by `!`);
  - `rand`, `Rng`, `RngCore`, `CryptoRng`, `rng`;
  - `Cell`, `RefCell`, `Mutex`, `RwLock`, `Arc`, `Rc`, `atomic`, `Atomic*`;
  - `mpsc`, `oneshot`, `Sender`, `Receiver`;
  - `static mut`.
- **No unsafe.** It is not an `unsafe fn` or `extern fn`, and its body has no
  `unsafe` block.
- **No async.** It is not an `async fn`, and its body has no `async` or
  `.await`.
- **No trait objects.** Its signature and body have no `dyn`.
- **No closure parameters.** No parameter's type, and no bound of a type
  parameter, names `Fn`, `FnMut` or `FnOnce`.
- **Has a body.**

Unlike v1, generic functions, functions of generic `impl` blocks,
`impl Trait` parameters and trait-impl methods are candidates. A generic
candidate is read at the instance §3.1 chooses. Each rejection is written to
`rejections.tsv` with its reason (the first criterion that fails).

### 3.1 The rule-chosen instance

A candidate with type or const parameters (the `impl` block's first, then
the function's, in declaration order) is read at one instance. Each
`impl Trait` parameter counts as an anonymous type parameter at its
position. Lifetime parameters are erased. The instance is chosen
mechanically, the same way for every candidate:

1. **Each type parameter's list** is the fixed primitive list:
   `u64, u32, u8, usize, i64, bool, (), [u8; 32], Vec<u8>, Vec<u64>, String`.
   After it come the workspace types that implement every trait bound of the
   parameter (as rustc's trait solver says, at the source commit). Only
   types that are non-generic, public and defined outside test, mock and
   fuzz code count. They are taken in the seeded order of
   `sha256("<seed>:instance:<full type path>")`, and at most 16 of them.
2. **Each const parameter's list:** `usize` and the other integer types take
   `32, 1, 8, 64`; `bool` takes `false, true`; `char` takes `'a'`.
3. **The combinations** are taken in lexicographic order of the
   parameters' lists. For each, the sampler generates one monomorphic
   wrapper that calls the candidate at that combination and asks rustc to
   type-check it. The instance is the first combination that type-checks.
   At most 256 combinations are checked. If none type-checks, the candidate
   is rejected with `no instance (RULE.md 3.1)`.
4. The instance is recorded in `candidates.tsv`. It is given to extraction
   through the toolchain's instance mechanism (`extract.sh --instance` and
   `--inject` of the generated wrapper module, as the MMR's extraction does),
   with nothing else per function.

A non-generic method of a trait impl needs no instance: its `Self` and the
trait's arguments are fixed by the impl.

## 4. Order and sample: the committed seed

```
seed = 7bc58f68b25930aa17c68e7c870edb9a
```

A candidate's id is one of:
- `<package>::<module path>::<fn>` for a free function;
- `<package>::<module path>::<Type>::<method>` for an inherent method;
- `<package>::<module path>::<Type as Trait>::<method>` for a trait-impl
  method.

`<Type>` and `<Trait>` are written as in the source, with generic arguments
removed. If two impls would give the same id, the later one in the file
gets the suffix `#2`, `#3` and so on in file order.

The seeded order sorts candidates by `sha256("<seed>:<id>")`, as lowercase
hex, ascending. Any tie is broken by id.

Candidates are probed (§5) in the seeded order. **The sample is the first 40
candidates in the seeded order that pass §5.** This is a uniform random
sample of the accepted set. Probing may stop once 40 have passed. Candidates
after the 40th accepted one are written as `not probed (sample full)`.

If fewer than 40 pass, H2-v2 is every candidate that passed, and the
shortfall is reported. The rule is not widened. A wider rule is version 3,
with new files.

## 5. The probe: extraction, callee closure, size and the exec-only reader

The probe runs on the candidate as written, with the sandblaster toolchain
at the evaluation commit and its default options. It edits no source file,
and it chooses nothing per function. Its steps, in order (the first failure
is the reason):

1. **Extraction.** `sandblaster/mirx/extract.sh` (the pinned nightly of
   `sandblaster/mirx/rust-toolchain.toml`, default features) extracts:
   - the candidate's module;
   - the module of every function in its callee closure (step 2);
   - for a generic candidate, the instance of §3.1.

   The options are:
   - `--items` names the candidate's item and the closure's items;
   - `--skip-fns` names the other methods of the types involved;
   - `--stubs` stubs the verifying build scripts of the workspace crates it
     depends on (commonware-codec's `varint.rs` and commonware-storage's
     `mmr-lowered__merkle__mmr__iterator.rs`, each by its source, as the
     mirx README does for the MMR).

   The candidate passes when the `.sbmir` has a root for it.
2. **Callee closure.** The closure is computed from the extracted MIR, at
   the instance. It holds every workspace function (any workspace crate)
   that the candidate reaches by calls rustc resolves statically. It also
   holds the same-crate `const` items that the candidate and those functions
   read. Calls into std and core are not part of the closure: the reader
   reads them as it reads any std/core MIR.

   The closure is capped at 32 functions in at most 12 files. Past the cap,
   the candidate is rejected with `callee closure too large (RULE.md 5.2)`.
   A call the closure cannot resolve (a trait method at an unknown type)
   rejects it with `unresolved call (RULE.md 5.2)`.
3. **Size.** The candidate's own MIR body, at the instance, has a loop or at
   least 10 statements.
   - A loop is a cycle in its control-flow graph (a back edge of a
     depth-first walk from `bb0`) or a direct call of itself.
   - Statements are the non-terminator lines of its basic blocks. The
     terminators are `goto`, `switch`, `call`, `return`, `unreachable`,
     `assert`, `drop` and `resume`.
   - Callees do not count toward the size.
4. **Reader.** A generated DSL root declares in place every file of the
   candidate and its closure:
   - it mirrors each crate's module path, with
     `#[lift(mir = .., in_place, items = "<items>")]`;
   - `unverified_fns` lists the other methods of the types involved;
   - `unverified_impls` lists the other traits implemented for them in those
     files;
   - it re-exports the candidate when it is declared plain `pub`.

   `driver::check` must accept the root with no error. This is the lift and
   the MIR reading (`mir::load`, `mir::read`).
5. **Exec-only elaboration.** `elab::elaborate` runs with
   `Options { exec_only: true, .. }` and no laws, as `tests/opt_qmdb.rs` and
   `driver::stage::lower_in_place` run it. Every definition elaborated from
   the candidate (its own and its `__` helpers) must have status `Checked`.
   Callees in the closure may be `Checked` or read opaquely, as the reader
   decides for every function alike. Only the candidate's own definitions
   must be `Checked`. That is what the optimizer takes as input
   (`opt::Ctx::checked`).

The probe stops before the optimizer. `crate::opt::optimize` is never
called, and no optimizer output or timing is produced or read while
sampling.

## 6. What is frozen

`sandblaster/bench/heldout-v2/manifest.toml` records:
- for H1-v2: the paths and each file's SHA-256;
- for H2-v2: this rule's SHA-256, the seed and the source commit.

G6 freezes that manifest as recorded now, so sampling never edits it.
Sampling writes the sample to a new file, `h2/sample-manifest.toml`. It
lists each sampled function, its instance, and the SHA-256 of its file and
of its callee files.

`sandblaster/tools/gates/g6.sh` freezes every file under
`sandblaster/bench/heldout-v2/` except a generated `REPORT.md` and Python
caches. The files the sampling stage writes (`sample.py`, `probe.py`,
`candidates.tsv`, `rejections.tsv`, `probe.tsv`, `sample.tsv`,
`PROBE-LOG.md`, `sample-manifest.toml`, `roots/`, `mir/`) are new files, which G6 records once
written. They are never edits of these.

When an H2-v2 result drives an optimizer change, that function moves to the
development set. Its replacement is the next accepted candidate in the
seeded order.
