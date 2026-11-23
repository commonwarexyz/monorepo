# commonware-codec Kani proofs

Proof harnesses for the `commonware-codec` crate, checked with
[Kani](https://github.com/model-checking/kani), a bounded model checker for Rust. A harness
that passes holds for every input inside its stated bounds, not for a sample. The harnesses
are run by hand or by a scheduled job, not by CI.

`kani/` is its own workspace with its own `Cargo.lock`. It is not a member of the repository
workspace, so `cargo` commands run for the repository workspace do not build or run it, and
the repository `Cargo.lock` does not name it. Every module and every dependency is behind
`cfg(kani)`: under a plain `cargo build` the package is empty.

## How Kani harnesses are marked

Three marks agree, so that a person or a script can find the Kani harnesses and run them
without any libFuzzer target:

1. **The path and the package name.** The package is `<crate>/fuzz/experimental/kani/` and
   its name ends with `-kani`.
2. **A marker in the manifest.** `Cargo.toml` has the table `[package.metadata.kani]`, with
   the Kani release as `version` and the number of harnesses as `harnesses`. A libFuzzer
   package has `cargo-fuzz = true` instead, and never this table.
3. **The harness names.** The name of every harness starts with `kani_`.

Find every Kani package, from the repository root. The search looks only at
`<crate>/fuzz/experimental/kani/Cargo.toml`, where `<crate>` is one or two folders below the
root (`codec`, `cryptography/curve25519`). A copy of a package in a deeper folder is not found:

```bash
find . -mindepth 5 -maxdepth 6 -path '*/fuzz/experimental/kani/Cargo.toml' \
    -exec grep -l '^\[package\.metadata\.kani\]' {} +
```

List the harnesses of this one:

```bash
cargo kani --manifest-path codec/fuzz/experimental/kani/Cargo.toml list
```

## Installing Kani

Kani is not a dependency of the repository. The harnesses are written for Kani 0.68.0 (the
`version` of the marker). Both commands install into the home directory: the two binaries in
`~/.cargo/bin`, the Kani bundle in `~/.kani`, and the compiler Kani uses as a `rustup`
toolchain.

```bash
cargo install --locked kani-verifier --version 0.68.0
cargo kani setup
```

## Running

Run from the repository root and pass the manifest:

```bash
cargo kani --manifest-path codec/fuzz/experimental/kani/Cargo.toml -j 4 --output-format terse
```

A passing run exits with status 0 and ends with:

```text
Complete - 89 successfully verified harnesses, 0 failures, 89 total.
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
| `--harness kani_p4_usize_read` | Run the harnesses whose name contains this text. |
| `-Z unstable-options --harness-timeout 20m` | Stop each harness after this time. |
| `-Z unstable-options --export-json results.json` | Write the result of every harness and every check to a file. |
| `-Z concrete-playback --concrete-playback=print` | Print a unit test with the input of each failed check and of each satisfied cover check. |
| `--features consistency` | Also assert the implementation-consistency checks (see below). |

Kani has no `--locked` option. Check the lock file before a run with
`cargo metadata --locked --manifest-path codec/fuzz/experimental/kani/Cargo.toml`.

## Proofs

Each proof states contracts that the documentation of `commonware-codec` gives or, where the
documentation is silent, that a test of `commonware-codec` asserts. The quoted sentences, the
bounds and what is left unasserted are in the header of each module in `src/`.

| Module | Harnesses | What is proven |
| ------ | --------- | -------------- |
| `p1_varint_decode` | `kani_p1_decode_{u16,u32,u64,u128}`, `kani_p1_max_sizes_match_codec` | For every byte string up to one byte past the longest varint: decoding does not panic, fails only with `EndOfBuffer` or `InvalidVarint`, and accepts only the canonical encoding of the value it returns. |
| `p2_varint_roundtrip` | `kani_p2_roundtrip_{u16,u32,u64,u128,i16,i32,i64,i128}` | For every value of the type: the encoding has the size `encode_size` gives and decoding gives the value back. For unsigned values that size is minimal. Signed values use ZigZag. |
| `p3_stream_decoder` | `kani_p3_stream_{u16,u32,u64,u128}` | For every byte sequence fed to a new decoder: it does not panic, asks for more only after a continuation byte, fails only with `InvalidVarint`, and stops within the longest varint. |
| `p4_range` | `kani_p4_range_contains`, `kani_p4_usize_read` | `RangeCfg::contains` is interval membership for every pair of bounds. For every byte string up to 6 bytes and every range, a decoded `usize` length is inside the caller's range. |
| `p5_length_math` | `kani_p5_at_least_items`, `kani_p5_max_items_size`, `kani_p5_ensure_zeros` | The length check does not overflow, the size bound is an upper bound, and the padding check accepts exactly a zero region. |
| `p6_varint_uint14` | `kani_p6_decode_uint14`, `kani_p6_stream_uint14` | The properties of `p1` and `p3` for a 14-bit `Uint`, a width that is a multiple of 7 bits. |
| `p7_net` | `kani_p7_{ipv4,ipv6,socket_addr_v4,socket_addr_v6,ip_addr,socket_addr}_{decode,roundtrip}`, `kani_p7_sizes` | Network addresses. In the `_decode` harnesses, for every byte string up to one byte past the longest encoding: decoding does not panic, accepts only the tags 4 and 6, reads exactly the bytes of the value it returns, and fails only with `EndOfBuffer` or, for another tag, `Invalid`. In the `_roundtrip` harnesses, for every value (an IPv6 socket address: with flow information 0 and scope id 0): the written length is `encode_size`, at most `MAX_ENCODE_SIZE`, and the value decodes to itself. `kani_p7_sizes`: the size constants are the sums of their parts. |
| `p8_exact_decode` | `kani_p8_exact_{u8,u16,u32,u64,u128,i8,i16,i32,i64,i128,f32,f64}`, `kani_p8_exact_nonzero_{u16,u32,u64}`, `kani_p8_exact_array_{u8_4,u16_2}`, `kani_p8_exact_uint14`, `kani_p8_exact_usize` | `decode` accepts exactly what `write` produced. For every value (of `usize`: every value up to `u32::MAX`, the largest the codec encodes): the whole encoding gives the value, a cut encoding fails with `EndOfBuffer`, and the encoding followed by 1 or 2 more bytes fails with `ExtraData` of that count. For every byte string up to 2 bytes past the longest encoding: an accepted input is what `write` gives for the value. For the fixed-size types (every type here but `usize`), `encode_fixed` and `decode_fixed` agree with `write` and `decode`. |
| `p9_fixed_width` | `kani_p9_int_{u8,u16,u32,u64,u128,i8,i16,i32,i64,i128}`, `kani_p9_float_{f32,f64}`, `kani_p9_nonzero_{u16,u32,u64}`, `kani_p9_array_{u8_5,u16_3,nested,empty}`, `kani_p9_tuple_{pair,varint,nested,twelve}`, `kani_p9_uint_{14,72,256}`, `kani_p9_uint_14_refuses_spare_bits` | Fixed-width integers and floats, arrays, tuples and `Uint`. From values, in every harness but `kani_p9_array_empty` and `kani_p9_uint_14_refuses_spare_bits`: for every value, the written length is the exact size, the bytes are big-endian and the parts are in order, `encode_size` is the sum of the parts, and the value decodes to itself. From bytes, in the integer, float, `NonZero` and `kani_p9_uint_{14,72,256}` harnesses, in `kani_p9_array_{u8_5,u16_3,nested}` and in `kani_p9_tuple_{pair,varint}`: for every byte string up to one byte past the size, decoding does not panic and accepts only the value the bytes spell. `kani_p9_tuple_nested` and `kani_p9_tuple_twelve` take no arbitrary bytes: they start from values, and `kani_p9_tuple_twelve` also reads its own encoding cut by one byte. `kani_p9_array_empty`: an array of no elements writes nothing and reads nothing, from 0 or 1 bytes. `kani_p9_uint_14_refuses_spare_bits`: of every 2 bytes, exactly those with a bit beyond the width are refused. |
| `p10_tags` | `kani_p10_bool_tag`, `kani_p10_option_tag` | The tag byte of `bool` and of `Option`: 0 and 1 are accepted, every other byte fails with `InvalidBool`. |
| `p11_modes` | `kani_p11_mode_new`, `kani_p11_modes_{1,3}`, `kani_p11_modes_append` | `Mode` and `Modes`. `kani_p11_mode_new`: a mode is a seven-bit value. `kani_p11_modes_{1,3}`, for packets of at most 1 and 3 modes: for every list of modes, the packet omits trailing zero modes, has the size `encode_size` gives and decodes to itself, and a list of zeros gives no packet; for every byte string up to one byte past the maximum, decoding does not panic and accepts only a packet that `write` produces. `kani_p11_modes_append`: for every list of 2 modes, an appended zero mode leaves the encoding as it was. |

### Contract and consistency

The default build asserts the quoted contracts. It is the gate: a failure is a difference
between the code and a quoted contract. Some items rest on a comment in the code or on a
test of `commonware-codec` and not on API documentation: the documentation does not give
the byte layout of an address, an array or a tuple, or the tags of `IpAddr`. The module
headers say which items these are. A test supports what it asserts and no more: where a
test asserts only that decoding fails, the gate asserts that it fails, and the kind of the
error is a consistency check.

Some harnesses also hold checks that are stronger than the documentation, for example the
exact payload of an error. They are asserted only with `--features consistency`. A valid
change of the implementation may fail them, so a failure there is a reason to look, not a
defect.

### Limits

- A proof holds inside its bounds: the input lengths and loop bounds in the module header.
- `usize` is 64 bits, as on the machine that runs Kani. Nothing here speaks for 32-bit
  targets.
- The proofs cover the listed functions on stack data. Heap-backed types (`Vec`, `Bytes`) are
  not covered.
- A generic implementation is proven for the types it is listed with. Arrays, tuples, `Uint`
  and `Modes` are proven for the lengths, shapes and widths in the module headers, not for
  all of them.
- An IPv6 socket address round-trips only with flow information 0 and scope id 0: the
  encoding has no bytes for the two fields (see `p7_net`).
- Which error kinds a function may return is read from the description of each kind in
  `codec/src/error.rs`. The documentation has no list of kinds per function.
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
cargo metadata --manifest-path codec/fuzz/experimental/kani/Cargo.toml --format-version 1 > /dev/null
```
