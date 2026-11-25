# commonware-stream Kani proofs

Proof harnesses for the CUPS record sizes of `commonware-stream`
(`stream/src/cups/protocol.rs`), checked with
[Kani](https://github.com/model-checking/kani), a bounded model checker for Rust. A harness
that passes holds for every input inside its stated bounds, not for a sample. The harnesses
are run by hand or by a scheduled job, not by CI.

`kani/` is its own workspace with its own `Cargo.lock`. It is not a member of the repository
workspace, so `cargo` commands run for the repository workspace do not build or run it, and
the repository `Cargo.lock` does not name it. Every module and every dependency is behind
`cfg(kani)`: under a plain `cargo build` the package is empty.

The harnesses call the public API of `commonware-stream` only. They change no production code
and copy none.

## How Kani harnesses are marked

As in `codec/fuzz/experimental/kani`: the package is `<crate>/fuzz/experimental/kani/` and its
name ends with `-kani`; `Cargo.toml` has the table `[package.metadata.kani]` with the Kani
release as `version` and the number of harnesses as `harnesses`; and the name of every harness
starts with `kani_`.

List the harnesses:

```bash
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path stream/fuzz/experimental/kani/Cargo.toml list
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
RUSTFLAGS="--cap-lints=warn" cargo kani --manifest-path stream/fuzz/experimental/kani/Cargo.toml
```

`RUSTFLAGS="--cap-lints=warn"` is required. The repository denies warnings, and under Kani's
compiler `commonware-utils` (a dependency of `commonware-stream`) raises the lint
`semicolon_in_expressions_from_non_local_macros`, because Kani's standard library defines its
own `assert!`. The flag turns lints of the dependencies into warnings. It does not change what
Kani checks.

A passing run exits with status 0 and ends with:

```text
Complete - 6 successfully verified harnesses, 0 failures, 6 total.
```

Check two more things, because the exit status does not cover them:

1. **The count.** The total equals `harnesses` in the marker. A harness that is no longer
   compiled is missing from the run without any error.
2. **The cover checks.** For every harness whose name does not end with `_panics`, every line
   `** n of m cover properties satisfied` has `n` equal to `m`. Kani reports a harness as
   `SUCCESSFUL` also when a cover check is unsatisfied, and then the harness may prove less
   than it says.

### Harnesses that must panic

`kani_cups_header_len_panics` and `kani_cups_record_len_panics` prove that every input of a
class panics. Kani's `#[kani::should_panic]` alone shows only that some input panics, so each
of these harnesses has one cover check right after the call: Kani cuts a path at a panic, so
the check is reachable only if some input of the class returns. Such a harness passes when
Kani prints both

```text
 ** 0 of 1 cover properties satisfied (1 unreachable)
VERIFICATION:- SUCCESSFUL (encountered one or more panics as expected)
```

A satisfied cover there means that an input of the class returned: the harness fails, although
Kani's summary counts it as verified. Each has a partner `<name>_control` over a class that
also holds an input that returns. The partner passes when its cover is satisfied (`1 of 1`) and
Kani prints the same `SUCCESSFUL (encountered one or more panics as expected)`: it shows that the
cover check can see a returning input. The method shows that every input of the class panics,
not which panic fires. The line `Failed Checks: This is a placeholder message` that Kani prints
for these four harnesses is the expected panic.

A harness that runs out of time is printed as `VERIFICATION:- FAILED` with the line
`CBMC timed out`: that is no answer, not a failed check. A failed check prints
`Failed Checks:` with the assertion.

Useful options:

| Option | Effect |
| ------ | ------ |
| `--harness kani_cups_header_len` | Run the harnesses whose name contains this text. |
| `-Z unstable-options --harness-timeout 20m` | Stop each harness after this time. |
| `-Z concrete-playback --concrete-playback=print` | Print a unit test with the input of each failed check and of each satisfied cover check. |
| `--features consistency` | Also assert the implementation-consistency checks (see below). |

Kani has no `--locked` option. Check the lock file before a run with
`cargo metadata --locked --manifest-path stream/fuzz/experimental/kani/Cargo.toml`.

## Proofs

Each proof states contracts that the documentation gives or, where the documentation is
silent, that a test asserts. The quoted sentences, the bounds and what is left unasserted are
in the header of each module in `src/`.

| Module | Harnesses | What is proven | Time |
| ------ | --------- | -------------- | ---- |
| `cups_sizes` | `kani_cups_header_len`, `kani_cups_record_len` | For both versions and every payload length up to `u32::MAX` minus the tag size: `header_len` is the size of the canonical varint of the length plus the tag (V0) or the 4 bytes of the length plus the tag (V1), as the record layout gives it; `record_len` is that header plus the payload plus the tag, with no overflow; `Cups::MAX_SIZE` is `u32::MAX` minus the tag size. | under 1 s each |
| `cups_sizes` | `kani_cups_header_len_panics`, `kani_cups_record_len_panics`, each with `_control` | For both versions and every length above `u32::MAX` minus the tag size (any `usize`): both functions panic. | under 1 s each |

All harnesses use the cipher `ChaCha20Poly1305` (tag of 16 bytes). Times are Kani's
verification time on a 16-core laptop; the build adds a few minutes on the first run.

### Contract and consistency

The default build asserts the quoted contracts. It is the gate: a failure is a difference
between the code and a quoted contract. The record layout comes from the module documentation
of `cups`; the size of a varint comes from the documentation of `commonware-codec`, and the
harnesses compute it themselves rather than calling the codec.

Checks stronger than the documentation are asserted only with `--features consistency`. A
valid change of the implementation may fail them, so a failure there is a reason to look, not
a defect. The proofs here fix their results exactly, so this package has none yet.

### Not covered

Decision, 2026-11-24: these proofs use the public API only, with no change to production code
and no copy of private code. What would need private access is left out:

- **`validate_frame_len`** (`stream/src/utils/codec.rs`): the function is crate-private. The
  public `send_frame` reaches it, but see "Left out for cost"; its branch for lengths above
  `u32::MAX` would in any case need a message of more than 4 GiB.
- **`recv_length`** (private, async) and the receive half of CUPS (`Receiver`, the private
  `recv_record`, `open`): private.
- **The send half of CUPS** (`Sender`, the private `encrypted_frame_len`, `append_header`,
  `seal`): private or async with a cipher. The sizes it uses are `record_len` and
  `header_len`, which are proven here.

Left out for cost:

- **`recv_frame`** (`stream/src/utils/codec.rs`, public, async): a harness that polls it once
  over a ready mock stream builds under Kani but gave no answer within 35 minutes for a 6-byte
  stream and within 22 minutes for a 3-byte stream. It stays with the `e2e` fuzz target of
  `stream/fuzz`, which drives it with adversarial streams.
- **`send_frame`** (`stream/src/utils/codec.rs`, public, async): a harness that polls it once
  over a ready mock sink, for every `max_message_size` and a sink that accepts or is closed,
  builds under Kani but gave no answer: with messages of up to 4 bytes the solver passed 12 GB
  and was stopped; with messages of up to 2 bytes it ran out of a 30-minute limit
  (`CBMC timed out`). The limit check and the prefix stay with the crate's tests
  (`test_send_frame`, `test_send_frame_too_large`, `test_send_recv_at_max_message_size` in
  `stream/src/utils/codec.rs`) and the `e2e` fuzz target. The varint encoding itself is proven
  in `codec/fuzz/experimental/kani`.

Left out because no input on a 64-bit host reaches it:

- **The second panic of `record_len`**, a record size that does not fit a `usize`: it needs a
  32-bit `usize`.

### Limits

- A proof holds inside its bounds: the input lengths and loop bounds in the module header.
- `usize` is 64 bits, as on the machine that runs Kani. Nothing here speaks for 32-bit
  targets.
- The size functions are proven for the cipher `ChaCha20Poly1305`, the only `Cipher` in the
  repository, and for the handshake type `()`, which they do not use.
- A proof is as sound as Kani, CBMC and the solver.

## Changing the harnesses

- Name a new harness `kani_...` and raise `harnesses` in `Cargo.toml`. A harness that must
  panic is named `kani_..._panics`, has exactly one cover check after the call, and has a
  `kani_..._panics_control` partner.
- Put the quoted contract above the assertion. A check with no quote goes behind the
  `consistency!` macro. A quoted test supports what it asserts and no more.
- Give every result arm a `kani::cover!` check, so that an arm that is no longer reached is
  seen.

### The lock file

`Cargo.lock` also records the repository crates that the harnesses depend on. When their
versions or dependencies change, refresh the lock and commit it:

```bash
cargo metadata --manifest-path stream/fuzz/experimental/kani/Cargo.toml --format-version 1 > /dev/null
```
