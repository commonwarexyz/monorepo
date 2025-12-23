# Fuzzing

### Getting Started

The following docs outline how to run the `cargo-fuzz` fuzzer setup in the `codec` crate, but apply to all crates where fuzzing is enabled.

To run the fuzzer, [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) is needed (e.g. `cargo install cargo-fuzz`). 

A fuzz target can then be run with:

```bash
# Run with empty starting corpus and default libfuzzer options
$ cd codec/fuzz
$ cargo +nightly fuzz run roundtrip

# Run 25 workers with a custom timeout, max input len and pre-specified corpus
$ nohup cargo +nightly fuzz run roundtrip corpus/roundtrip/ -j 25 -a -- -max_len=5000 -timeout=1 -workers=25 & 

# Print available fuzzer options
$ cargo +nightly fuzz run roundtrip --help 
```

> [!NOTE]
> If using the [`justfile`](./justfile), all fuzz tests for a given directory can be ran using 
> `just fuzz <dir> <max_time>`.

### Coverage

To explore coverage information, the following tools are required:

```bash
$ rustup component add llvm-tools-preview # Required to generate coverage report data
```

**NOTE: The `llvm-tools-preview` crate installs various llvm utilities, with matching versions needed to share data between the CLI utils. If a version _not_ installed via `cargo` is used, then the `--version` should be checked on each `llvm-*` should be checked to ensure data output compatibility**

The coverage report can then be generated with:

```bash
# Run the fuzzer with the given corpus to generate coverage data
$ cargo +nightly fuzz coverage roundtrip corpus/roundtrip/ 

# Generate a text version output of the coverage data
$ llvm-cov show -instr-profile=coverage/<BIN>/coverage.profdata target/<ARCH>/coverage/<ARCH>/release/<BIN> > coverage.txt 
$ llvm-cov show -instr-profile=coverage/roundtrip/coverage.profdata target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/roundtrip > coverage.txt # Codec roundtrip bin example on ubuntu

# Prints a CLI readable coverage report
$ llvm-cov report -instr-profile=coverage/<BIN>/coverage.profdata ../target/<ARCH>/coverage/<ARCH>/release/<BIN> 
$ llvm-cov report -instr-profile=coverage/roundtrip/coverage.profdata target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/roundtrip # Codec roundtrip bin example on ubuntu
```

For more information on the available report outputs see:
- [`llvm-cov` docs](https://llvm.org/docs/CommandGuide/llvm-cov.html)
- [Instrumentation Coverage of Rust](https://doc.rust-lang.org/rustc/instrument-coverage.html#installing-llvm-coverage-tools)


### Test Case Minimization

The following commands are exposed directly by `cargo-fuzz`:

```bash
$ cargo +nightly fuzz cmin roundtrip corpus/roundtrip/ # Minimize the corpus discovered so far in `corpus/roundtrip`
$ cargo +nightly fuzz tmin mycrashfile # Attempt to minimize a specific crash case called `mycrashfile` for debugging root causes
```
