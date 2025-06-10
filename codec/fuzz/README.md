## Codec Fuzzing

_All of the following commands are run from the `codec/fuzz` directory, and have been tested on Ubuntu 24.02_

### Getting Started

To run the fuzzer, [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) is needed (e.g. `cargo install cargo-fuzz`). 

A fuzz target can then be run with:

```bash
$ cargo fuzz run codec # Run with empty starting corpus and default libfuzzer options
$ nohup cargo fuzz run codec fuzz/corpus/codec_roundtrip/ -j 25 -a -- -max_len=5000 -timeout=1 -workers=25 & # Run 25 workers with a custom timeout, max input len and pre-specified corpus
$ cargo fuzz run codec --help # Print available fuzzer options
```

### Coverage

To explore coverage information, the following tools are required:

```bash
$ rustup component add llvm-tools-preview # Required to generate coverage report data
```

**NOTE: The `llvm-tools-preview` crate installs various llvm utilities, with matching versions needed to share data between the CLI utils. If a version _not_ installed via `cargo` is used, then the `--version` should be checked on each `llvm-*` should be checked to ensure data output compatibility**

The coverage report can then be generated with:

```bash
$ cargo fuzz coverage codec corpus/codec/ # Run the fuzzer with the given corpus to generate coverage data
$ llvm-cov show ../target/<ARCH>/coverage/<ARCH>/release/codec -instr-profile=coverage/codec/coverage.profdata > coverage.txt # Generate a text version output of the coverage data
$ llvm-cov show ../target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/codec -instr-profile=coverage/codec/coverage.profdata > coverage.txt # Example on Ubuntu
```

For more information on the available report outputs see:
- [`llvm-cov` docs](https://llvm.org/docs/CommandGuide/llvm-cov.html)
- [Instrumentation Coverage of Rust](https://doc.rust-lang.org/rustc/instrument-coverage.html#installing-llvm-coverage-tools)


### Test Case Minimization

The following commands are exposed directly by `cargo-fuzz`:

```bash
$ cargo fuzz cmin codec corpus/codec/ # Minimize the corpus discovered so far in `corpus/codec`
$ cargo fuzz tmin mycrashfile # Attempt to minimize a specific crash case for debugging root causes
```