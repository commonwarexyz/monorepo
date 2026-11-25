# commonware-p2p Kani proofs

Proof harnesses for the subchannel prefix of the muxer in `commonware-p2p`
(`p2p/src/utils/mux.rs`), checked with [Kani](https://github.com/model-checking/kani), a
bounded model checker for Rust. A harness that passes holds for every input inside its stated
bounds, not for a sample. The harnesses are run by hand or by a scheduled job, not by CI.

`kani/` is its own workspace with its own `Cargo.lock`. It is not a member of the repository
workspace, so `cargo` commands run for the repository workspace do not build or run it, and
the repository `Cargo.lock` does not name it. Every module and every dependency is behind
`cfg(kani)`: under a plain `cargo build` the package is empty.

The harnesses call the public API of `commonware-p2p` only. They change no production code and
copy none.

## How Kani harnesses are marked

As in `codec/fuzz/experimental/kani`: the package is `<crate>/fuzz/experimental/kani/` and its
name ends with `-kani`; `Cargo.toml` has the table `[package.metadata.kani]` with the Kani
release as `version` and the number of harnesses as `harnesses`; and the name of every harness
starts with `kani_`.

List the harnesses:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path p2p/fuzz/experimental/kani/Cargo.toml list
```

## Installing Kani

The harnesses are written for Kani 0.68.0 (the `version` of the marker):

```bash
cargo install --locked kani-verifier --version 0.68.0
cargo kani setup
```

## Running

Run from the repository root and pass the manifest:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path p2p/fuzz/experimental/kani/Cargo.toml
```

`RUSTFLAGS="--cap-lints=warn"` is required. The repository denies warnings, and under Kani's
compiler `commonware-utils` (a dependency of `commonware-p2p`) raises the lint
`semicolon_in_expressions_from_non_local_macros`, because Kani's standard library defines its
own `assert!`. The flag turns lints of the dependencies into warnings. It does not change what
Kani checks.

A passing run exits with status 0 and ends with:

```text
Complete - 2 successfully verified harnesses, 0 failures, 2 total.
```

Check two more things, because the exit status does not cover them:

1. **The count.** The total equals `harnesses` in the marker. A harness that is no longer
   compiled is missing from the run without any error.
2. **The cover checks.** Every line `** n of m cover properties satisfied` has `n` equal to
   `m`. Kani reports a harness as `SUCCESSFUL` also when a cover check is unsatisfied, and
   then the harness may prove less than it says.

A harness that runs out of time is printed as `VERIFICATION:- FAILED` with the line
`CBMC timed out`: that is no answer, not a failed check. A failed check prints
`Failed Checks:` with the assertion.

Useful options:

| Option | Effect |
| ------ | ------ |
| `--harness kani_mux_parse` | Run the harnesses whose name contains this text. |
| `-Z unstable-options --harness-timeout 20m` | Stop each harness after this time. |
| `-Z concrete-playback --concrete-playback=print` | Print a unit test with the input of each failed check and of each satisfied cover check. |
| `--features consistency` | Also assert the implementation-consistency checks (see below). |

Kani has no `--locked` option. Check the lock file before a run with
`cargo metadata --locked --manifest-path p2p/fuzz/experimental/kani/Cargo.toml`.

## Proofs

Each proof states contracts that the documentation gives or, where the documentation is
silent, that a test asserts. The quoted sentences, the bounds and what is left unasserted are
in the header of each module in `src/`.

| Module | Harnesses | What is proven | Time |
| ------ | --------- | -------------- | ---- |
| `mux_parse` | `kani_mux_parse` | For every byte string up to 12 bytes: `parse` does not panic; it returns a subchannel and payload exactly when a decoder written in the harness from the documented varint rules (7 data bits per byte, least significant group first, at most 10 bytes, no zero byte after the first, no bit beyond 64) accepts a prefix, with the same subchannel, and the payload is the rest of the message; it fails exactly when that decoder refuses. | about 30 s |
| `mux_prefixed` | `kani_mux_prefixed` | For every payload size up to `usize::MAX - 10` and every subchannel: `prefixed` does not overflow, covers the payload with that subchannel's prefix, and adds exactly the 10 bytes of the longest prefix. | under 1 s |

Times are Kani's verification time on a 16-core laptop; the build adds about a minute on the
first run.

### Contract and consistency

The default build asserts the quoted contracts. It is the gate: a failure is a difference
between the code and a quoted contract. The varint rules that `kani_mux_parse` checks come from
the documentation, comments and tests of `commonware-codec`, which the module header names one
by one, because the muxer's layout names a varint and nothing more.

Checks stronger than the documentation, here the error kind of a refused prefix, are asserted
only with `--features consistency`. A valid change of the implementation may fail them, so a
failure there is a reason to look, not a defect.

### Not covered

- **The muxer itself** (`Muxer`, `MuxHandle`, `SubSender`, `SubReceiver`, the backup queue):
  asynchronous actors and channels. Async and concurrent code stays with fuzzing on the
  deterministic runtime and with tests.
- **Payloads above `usize::MAX - 10` in `prefixed`**: the addition overflows there, and the
  documentation states no domain, so nothing is claimed.
- **Messages longer than 12 bytes in `parse`**: the prefix decoder never looks past the tenth
  byte, so a longer message only has a longer payload.

### Limits

- A proof holds inside its bounds: the input lengths and loop bounds in the module header.
- `usize` is 64 bits, as on the machine that runs Kani. Nothing here speaks for 32-bit
  targets.
- `kani_mux_parse` trusts its own reference decoder. A planted bug in that decoder (accepting
  a zero byte after the first) makes the harness fail, so the comparison is not blind; that
  the decoder states the rules correctly is checked by reading its header.
- A proof is as sound as Kani, CBMC and the solver.

## Changing the harnesses

- Name a new harness `kani_...` and raise `harnesses` in `Cargo.toml`.
- Put the quoted contract above the assertion. A check with no quote goes behind the
  `consistency!` macro. A quoted test supports what it asserts and no more.
- Give every result arm a `kani::cover!` check, so that an arm that is no longer reached is
  seen.

### The lock file

`Cargo.lock` also records the repository crates that the harnesses depend on. When their
versions or dependencies change, refresh the lock and commit it:

```bash
cargo metadata --manifest-path p2p/fuzz/experimental/kani/Cargo.toml --format-version 1 > /dev/null
```
