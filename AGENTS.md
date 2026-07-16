# Commonware agent guidance

Commonware is a Rust workspace of high-performance distributed-systems primitives for adversarial environments. Make the smallest complete change that solves the task, and follow nearby code before introducing a new pattern.

## Non-negotiable design constraints

- Treat every externally supplied value as adversarial.
- Correctness is the top priority. Maintainability and style are important, but should not be detrimental to performance.
- Protocol primitives must remain runtime-agnostic. Do not introduce direct `tokio` usage outside runtime-owning code, runtime utilities, command-line paths, benches, or tests. Use the traits in `runtime/src/lib.rs` instead.
- Use `commonware_macros::select!` for concurrent operations. Async trait methods return `impl Future<Output = Result<T, Error>> + Send`; add `Send + 'static` bounds where required.
- Implement core mechanisms and algorithms inside the workspace rather than adding a dependency for them. On hot paths, prefer `Bytes`, cheap `Arc` clones, and static dispatch over allocations and dynamic dispatch.
- Namespace strings must be globally unique and have the form `_COMMONWARE_<CRATE>_<OPERATION>`. Changing one is a breaking change.
- Keep unsafe code minimal, prefer safe abstractions, and document every unsafe block with `// SAFETY:`.

## Public API and compatibility

All public APIs need a stability annotation. Use `#[stability(LEVEL)]`, `stability_scope!`, or `stability_mod!`; exported macros require the manual `cfg(not(any(..., commonware_stability_RESERVED)))` form.

- At ALPHA, breaking API, wire, and storage changes are allowed. Do not add compatibility shims.
- At BETA and above, wire and storage changes require a migration path.
- Run `just check-stability` and, when useful, `just unstable-public` after changing public APIs.
- Add codec conformance coverage for new encoded public types, and regenerate fixtures only for deliberate format changes.

Document public APIs clearly. Use `//!` for module docs, `///` for items, and include `# Examples` or `# Safety` where relevant. Keep comments concise, above the code they explain, and use plain ASCII characters. Do not write comments that narrate a change (e.g. "used to call bar() here") or describe implementation-specific behavior on a trait definition.

## Tests and validation

Use `just` commands, which run tests through `nextest`. Start with the narrowest useful check:

```bash
just test -p <crate> <test_name>  # focused iteration
just test -p <crate>              # changed crate
just clippy -p <crate>            # changed crate linting
just lint                         # workspace-wide lint, docs, and stability checks
just pre-pr                       # before opening a PR
```

Avoid a workspace build or test unless the change needs it. For platform-specific runtime changes, also run the applicable io_uring checks on Linux. Run `just udeps` after dependency changes, the WASM build after cryptography/utils/storage changes, and `just miri <module>::` after adding unsafe code.

Async protocol tests must use the deterministic runtime. Use `commonware_utils::test_rng()` or `TestRng::new(seed)` rather than entropy-backed RNGs. Test recovery and malicious-input paths where they apply.

## Local conventions

- Keep `mod.rs` minimal, use `cfg_if!` for platform-specific implementations, and put imports at module scope.
- Use `thiserror` for error types.
- Label runtime actors with `context.child(...)`; use `context.shared(true).spawn()` for CPU-intensive work in async code.
- Benchmark names use `module_path!()` and the format `module::operation/key=value key=value`.
- When diagnosing a bug, add a failing test before claiming the cause. Mutable storage-operation failures are fatal: do not keep using that database instance or report its inconsistent state as a defect.

## Task-specific guides

Read the relevant guide only when the task needs it:

- [Contributor workflow](CONTRIBUTING.md#development-workflow)
- [Benchmark authoring](CONTRIBUTING.md#benchmark-authoring)
- [Tracing spans](CONTRIBUTING.md#tracing-spans)
- [Deterministic runtime and recovery tests](runtime/TESTING.md)
- [Simulated network tests](p2p/TESTING.md)
- [Storage tests](storage/TESTING.md)
- [Conformance tests](conformance/TESTING.md)

The root [README](README.md) lists primitives, examples, stability-level definitions, and product documentation.
