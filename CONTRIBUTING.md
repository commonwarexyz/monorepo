# Setting Expectations

External contributors are encouraged to submit issues and pull requests to this repository. That being said, not all issues will be addressed nor will all correct pull requests be merged.

The Commonware Library provides robust, high-performance primitives and contributions that do not directly advance this work will not be considered. This includes (but is not limited to):

- Introducing an external dependency
- Implementing optional functionality
- Adding complex algorithms that provide marginal performance improvements
- Refactoring for the sake of refactoring
- Trivial changes from accounts farming contribution metrics (especially when aided by an LLM)
- New primitives and/or dialects that are ecosystem-specific

# Development workflow

> [!NOTE]
> Common commands are aliased in a [`justfile`](https://github.com/casey/just) for convenience. Refer to
> [Just's installation guide](https://github.com/casey/just?tab=readme-ov-file#installation), or run
> `cargo install just` on any platform.

This repository uses the default cargo and clippy formatting rules for `.rs` files, treating warnings as errors. To check linting, run:

```bash
$ just lint
```

To fix formatting automatically, run:

```bash
$ just fix-fmt
```

Before making a PR, to run all lints and tests, run:

```bash
$ just pre-pr
```

Use `just test -p <crate>` for routine development and reserve workspace-wide tests for changes that need them. The root [agent guidance](AGENTS.md) records the always-applicable repository constraints.

When creating a new crate, follow the `lib.rs` header conventions used across the workspace: crates that support `no_std` gate `std` behind a feature flag or `cfg(test)` (e.g. `#![cfg_attr(not(any(feature = "std", test)), no_std)]`), and every crate sets the Commonware logos:

```rust
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
```

For component-specific test and conformance guidance, see:

- [Deterministic runtime and recovery tests](runtime/TESTING.md)
- [Simulated network tests](p2p/TESTING.md)
- [Storage tests](storage/TESTING.md)
- [Conformance tests](conformance/TESTING.md)

## Benchmark authoring

Benchmarks use Criterion and live with the module they measure. The benchmark dashboard parses their names, so follow these rules exactly.

### Layout

Use one file per operation and an entry point for the module:

```text
crate/src/module/
  mod.rs
  benches/
    bench.rs
    operation_a.rs
    operation_b.rs
```

Register the binary in the crate's `Cargo.toml`:

```toml
[[bench]]
name = "module"
harness = false
path = "src/module/benches/bench.rs"
```

`name` becomes the first segment of a benchmark name.

### Example

```rust
use criterion::{criterion_group, Criterion};
use std::hint::black_box;

fn bench_operation_name(c: &mut Criterion) {
    for n in [10, 100, 1000] {
        c.bench_function(
            &format!("{}/n={n}", module_path!()),
            |b| {
                b.iter(|| black_box(/* benchmarked call */));
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_operation_name,
}
```

In `benches/bench.rs`:

```rust
use criterion::criterion_main;

mod operation_name;

criterion_main!(operation_name::benches);
```

### Naming

CI enforces names with `.github/scripts/lint_benchmark_names.py`:

1. Use `module_path!()` for the `module::operation` prefix.
2. Use `key=value` parameters, such as `size=1024`.
3. Separate parameters with spaces, not commas.
4. Use exactly one `/`, between the operation and parameters.

Examples:

```text
bls12381::combine_signatures/sigs=100
ed25519::signature_generation/ns_len=9 msg_len=32
bloomfilter::insert/hasher=sha256 item_size=32 fp_rate=10%
bitmap::count_ones/size=1024 chunk_size=8
rational::log2_ceil/value=1:2 precision=4
```

## Tracing spans

Tracing spans are discrete, time-bounded units of work exported to OTLP. They are deliberately separate from runtime context: the context tree records task ownership, while a trace follows a request across actor boundaries.

### Naming

- Use fully descriptive dot-separated names, such as `component.processor.verify`; never use `::`.
- Include the component and operation, not the call site. Runtime-context labels do not form part of a span name.
- Keep type variants with the type path, such as `qmdb.any.unordered.batch.merkleize`; put operation variants under the operation prefix, such as `marshal.coding.certify.embedded`.

### Instrumenting work

- Prefer `#[tracing::instrument(name = "...", level = "info", skip_all)]` on the reusable function doing the work. Add fields explicitly.
- In `fields(...)`, write `index = index` to record a variable; a bare `index` declares an empty field.
- Use manual spans only for one-off, call-site-dependent work. Do not repeat a span name at multiple call sites: extract an instrumented wrapper instead.
- Never hold an `entered()` guard across an `.await`.

### Span boundaries

- A span should have a clear start and end and normally last well under a minute. Create one span per long-lived loop iteration.
- Use child spans for progress boundaries rather than log-only progress events.
- On latency-sensitive paths, separately instrument lock acquisition, channel or stream pulls, and fsyncs.

### Actor boundaries, levels, and errors

Implicit tracing context does not cross a mailbox. Carry the caller-created `Span` in the message and re-enter it with `.instrument(span)` while processing. At dequeue, create a child span so queue wait and processing time are separate.

Use `info` for lifecycle and per-block work; use `debug` or `trace` for chatty or large-data spans. Record errors only on root spans, avoiding the same failure at every stack level.

# Releases

Releases are automatically published to `cargo` by [GitHub Actions](.github/workflows/publish.yml) whenever a version update is merged into the `main` branch.

To increment the patch version of all crates (and update the corresponding minimum required version in `workspace.dependencies`), run:

```bash
./scripts/bump_versions.sh
```

# Licensing and Copyright

You agree that any work submitted to this repository shall be dual-licensed under the included [Apache 2.0](./LICENSE-APACHE) and [MIT](./LICENSE-MIT) licenses, without any additional terms or conditions. Additionally, you agree to release your copyright interest in said work to the public domain, such that anyone is free to use, modify, and distribute your contributions without restriction.

# Support

Looking to discuss a potential contribution or get feedback? Reach out on [GitHub Discussions](https://github.com/commonwarexyz/monorepo/discussions)!
