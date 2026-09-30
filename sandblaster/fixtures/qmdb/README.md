# QMDB fixture

The QMDB current-membership verifier ported to sandblaster (DESIGN.md §11),
kept here as a test fixture of the toolchain's own suites (elaboration, the
optimizer, the §15 gates, the x86 and host-set harnesses). It is not a crate
and nothing in the monorepo links it.

| Path | What |
| --- | --- |
| `sandblaster/` | the DSL sources, laws, proofs, spec and the two locks (`SPEC.lock` for `mod.rs`, N = 32; `SPEC.n1.lock` for `n1.rs`, N = 1) |
| `fixtures/`, `fixtures-n1/`, `fixtures-n32/` | proof fixtures and their expected verdicts |
| `vectors/` | SHA-256 known answers (`#[examples]` of the spec) |
| `PROFILE.json` | the recorded loop profile the optimizer's cost model reads |
| `baseline/src/fixture.rs`, `baseline/tests/data/bend_verify.json` | the fixture loader and the Bend 2 oracle corpus the optimizer tests compile against |

The rest of the original port stayed behind in the toolchain's previous
repository: the generated crate and its CLI, the baseline crate, the
benchmark, oracle and reference crates.

The two locks were already out of date with the toolchain before the move
(their `semantics`, `builtins` and `target` hashes predate it). The rename
changed them only textually; because entry and root hashes carry the
project name as a domain tag, they now read as malformed instead of
mismatched. Re-accept them with `sandblaster spec --accept` when QMDB is
next locked.
