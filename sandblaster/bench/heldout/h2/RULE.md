# H2 sampling rule

H2 is the rule-sampled half of the held-out evaluation (fairness audit of
2026-10-02, evaluation protocol item 1, "H2"). It is real monorepo code,
taken by the rule below from crates that no milestone targets. This file was
written, and its seed fixed, before any candidate was enumerated or read
(2026-10-02T17:52Z). Nothing below may change after enumeration starts. If
the probe fails on every candidate for an infrastructural reason (a wrong
path, the toolchain, a template bug), the probe may be fixed. Each such fix
is written to `PROBE-LOG.md` with its reason, and it applies to every
candidate alike. Such a fix never changes a criterion, and it never targets
one function.

Source commit: the monorepo at `729ecd2a215bf034d1f70464a3f75730558ce505`.
The in-scope crates have no uncommitted change there. `manifest.toml`
records each sampled file's SHA-256.

## 1. Scope

Only these crates and modules (paths are the crate's `src/` files):

| package | modules in scope |
| --- | --- |
| `commonware-utils` | the whole crate |
| `commonware-math` | the whole crate |
| `commonware-stream` | the whole crate |
| `commonware-p2p` | the whole crate |
| `commonware-consensus` | arithmetic only: functions whose non-`self` parameters and result are all built from integers, `bool`, `char`, `()`, shared or `&mut` references to these, slices and arrays of these, tuples of these, and `Option`/`Result` of these. A `self` receiver of any type is allowed. |
| `commonware-storage` | `journal`, `ordinal` and `freezer` (`src/journal/**`, `src/ordinal/**`, `src/freezer/**`) |

"Off the hot paths" for consensus: no milestone, corpus program or §15
workload names a consensus function. The arithmetic criterion above is the
whole consensus selection, and nothing else in consensus is removed by hand.

## 2. Exclusions

A function is excluded when any of these holds:

1. It lies in a target area: codec `varint`; storage
   `merkle`/`mmr`/`bmt`/`qmdb`; cryptography `sha256`/`bls12381`/`ed25519`;
   coding `reed_solomon`. These crates and modules are outside the scope
   above anyway. Inside the scope, a function is also excluded when its
   signature or body names one of them, by any of these tokens: `varint`,
   `merkle`, `mmr`, `bmt`, `qmdb`, `sha256`, `Sha256`, `bls12381`,
   `ed25519`, `reed_solomon`, `ReedSolomon`.
2. It is in `sandblaster/front/tests/opt_corpus/corpus.toml` (no monorepo
   function is, since its programs are `crate::` items of the corpus crate).
   It is also excluded when its name equals the last segment of any
   corpus.toml `functions` entry.
3. It is in the §15 workload matrix (`sandblaster/docs/optimizer-design.md`
   §15: QMDB, Reed–Solomon, curve25519, BLS/VROOM; all outside the scope).
   It is also excluded when its name equals the last segment of a function
   the matrix names in code font: `parse`, `shape_go`, `shape`, `cswap`,
   `mul_by_014`, `verify_many`, `mul` (from `F::mul`).
4. It is test, mock or fuzz code:
   - a `#[test]` function;
   - an item under a `cfg` attribute that mentions `test`, `mocks`,
     `test-utils`, `fuzzing` or `arbitrary`;
   - a file with a path component (directory or file stem) named `tests`,
     `test`, `mocks`, `mock`, `test_utils`, `fuzz`, `benches`, `bench` or
     `examples`.

## 3. Candidates: pure, monomorphic functions

Enumeration takes every `fn` item written in a scope file at module level
or in a module-level `impl` block. It skips functions inside inline
`mod x { .. }` blocks and inside macro invocations (`cfg_if!`,
`macro_rules!` bodies): they are not items of the file as written. The
script that enumerates is `sample.py`, and it is lexical (comments, strings
and character literals are stripped first).

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
  - `static mut`.
- **No unsafe.** It is not an `unsafe fn` or `extern fn`, and its body has
  no `unsafe` block.
- **No async.** It is not an `async fn`, and its body has no `async` or
  `.await`.
- **No trait objects.** Its signature and body have no `dyn`.
- **Monomorphic.** It has no type or const parameters, and neither does its
  enclosing `impl`; lifetime parameters are allowed. No parameter has an
  `impl Trait` type. The reason: a generic function needs an instance chosen
  for its extraction, and choosing one would be a per-function decision.
- **A free function or an inherent method.** Not a method of a trait impl
  and not a trait's provided method. Lifting a trait impl needs a model of
  the trait, which would again be a per-function choice.

Each rejection is written to `rejections.tsv` with its reason. The first
criterion that fails is the reason given.

## 4. Order and sample: the committed seed

```
seed = 6da19874a074881c6db6d18cf32b096f
```

A candidate's id is `<package>::<module path>::<fn>`, or
`<package>::<module path>::<Type>::<method>` for a method. The seeded order
sorts candidates by `sha256("<seed>:<id>")`, as lowercase hex, ascending.
Ties are impossible in practice; any tie is broken by id.

Candidates are probed (§5) in the seeded order. **The sample is the first 40
candidates in the seeded order that pass §5.** This is a uniform random
sample of the accepted set: probing everything and then drawing 40 in seeded
order picks the same 40. Probing may stop once 40 have passed. Candidates
after the 40th accepted one are written as `not probed (sample full)`.

If fewer than 40 pass, H2 is every candidate that passed, and the shortfall
is reported. This stage does not widen the rule; the coordinator decides.

## 5. The probe: size, extraction and the exec-only reader

The probe runs on the candidate as written. It edits no source file, and it
chooses nothing per function. Its steps, in order (the first failure is the
reason):

1. **Extraction.** `sandblaster/mirx/extract.sh` (the pinned nightly of
   `sandblaster/mirx/rust-toolchain.toml`, default features) extracts the
   candidate's module:
   - `--items` names the candidate's item: the function itself, or for a
     method its self type. Every other module the module path covers gets
     an empty list.
   - `--skip-fns` names the type's other methods.
   - `--stubs` stubs the verifying build scripts of the workspace crates it
     depends on: commonware-codec's `varint.rs` and commonware-storage's
     `mmr-lowered__merkle__mmr__iterator.rs`, each by its source, as the
     mirx README does for the MMR.

   The candidate passes this step when the `.sbmir` has a root for it.
2. **Size.** The root's MIR body has a loop, or at least 10 statements.
   - A loop is a cycle in its control-flow graph (a back edge of a
     depth-first walk from `bb0`) or a direct call of itself.
   - Statements are the non-terminator lines of its basic blocks. The
     terminators are `goto`, `switch`, `call`, `return`, `unreachable`,
     `assert`, `drop` and `resume`.
3. **Reader.** A generated DSL root declares the candidate's file in place:
   - it mirrors the crate's module path, with
     `#[lift(mir = .., in_place, items = "<item>")]`;
   - for a method, `unverified_fns` lists the type's other methods and
     `unverified_impls` lists the traits implemented for it in that file;
   - it re-exports the item.

   `driver::check` must accept the root with no error. This is the lift and
   the MIR reading (`mir::load`, `mir::read`).
4. **Exec-only elaboration.** `elab::elaborate` with
   `Options { exec_only: true, .. }`, as `tests/opt_qmdb.rs` and
   `driver::stage::lower_in_place` run it, with no laws. Every definition
   elaborated from the candidate (its own and its `__` helpers) must have
   status `Checked`. That is what the optimizer takes as input
   (`opt::Ctx::checked`).

The probe stops before the optimizer. `crate::opt::optimize` is never
called, and no optimizer output or timing is produced or read while
sampling.

## 6. What is frozen

`manifest.toml` (in `sandblaster/bench/heldout/`) records both halves:
- for H1: the paths, the source commit, and each file's SHA-256;
- for H2: the paths, the source commit, each file's SHA-256, the seed, and
  this rule's SHA-256.

`sandblaster/tools/gates/g6.sh` freezes every file under
`sandblaster/bench/heldout/`. When an H result drives an optimizer change,
that function moves to the development set. Its replacement is the next
accepted candidate in the seeded order (protocol item 3).
