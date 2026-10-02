# commonware-simd

[![Crates.io](https://img.shields.io/crates/v/commonware-simd.svg)](https://crates.io/crates/commonware-simd)
[![Docs.rs](https://docs.rs/commonware-simd/badge.svg)](https://docs.rs/commonware-simd)

Abstract over SIMD operations.

## Code generation

Run `just check-simd-codegen` to inspect release consumers compiled as a separate
integration-test crate, without LTO. The check covers each emulated backend, native
NEON on AArch64, runtime dispatch, nested operations, and an outlined consumer
frame. It emits LLVM IR and assembly and rejects residual calls in fixed-size and
runtime-sized vector computations. Use `just check-simd-codegen --target <target>` to check
another installed target; `just test -p commonware-simd --test codegen` runs the
same consumers against scalar expectations.

On AArch64, `just check-simd-codegen --feature-scopes` also compiles callers with
NEON disabled to expose feature boundaries hidden by the target's default
features. This is a compile-only diagnostic because disabling baseline NEON
violates the target ABI. It permits root feature detection and entry into a native
scope, then rejects calls inside that scope. Do not execute that diagnostic binary.

Inline annotations on primitive methods expose their bodies to downstream
optimizers. Keep annotations only where removing them changes consumer code
generation, and document the reason at the method. Larger consumer algorithms can
still be outlined; these probes establish the behavior of the tested compositions,
not an inlining guarantee for every algorithm. An outlined consumer frame should
call the token's `execute` method at each bulk computation boundary to reenter the
selected feature scope. The operation adapter and vector loop must inline into
that scope to avoid a feature-gated call per vector; inspect real consumer code
when introducing larger kernels or additional call layers.

The annotation audit used Rust 1.95 and 1.98, release builds without LTO, and
separate consumers with both one and sixteen codegen units:

| Methods | Annotation | Reason |
| --- | --- | --- |
| Emulated load, store, add | `inline` | Removing the hint leaves primitive calls in downstream loops. |
| Emulated splat, execute, shared generic helpers, operation defaults | None | These bodies already inline in the consumer probes. |
| Native load/store helpers and vector adapters | `inline` | Removes primitive calls and propagates caller length facts. |
| Native splat helper and adapter | `inline` | Removes broadcast calls before the loop. |
| Native private add helper | None | Removing its hint leaves identical calls and instructions. |
| Native execution adapters and dispatch | `inline` | Keeps unannotated consumer loops inside the native feature scope, including outlined-frame reentry. |
| Native constructor | None | Detection stays at the root; no hint is needed inside vector loops. |
| Consistency and fuzz helpers | None | These checks do not need a kernel inlining contract. |

Removing any one of the native execution or dispatch hints can outline a
runtime-sized consumer kernel into a baseline feature scope when using sixteen
codegen units. These hints were checked together with unannotated consumer
operation bodies; annotating the consumer can mask this interaction.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.
