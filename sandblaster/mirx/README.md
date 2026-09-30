# sandblaster-mirx

A rustc driver that writes rustc's MIR of one module of a crate to a
`.sbmir` file, the input of the MIR reading (`sandblaster/front/src/mir`,
`docs/mir-lift.md` §20). It is not part of the workspace build: it needs
`rustc_public` (rustc-dev), so it builds with the pinned nightly of
`rust-toolchain.toml` — the nightly of the stable release the monorepo
builds with (1.98). The `.sbmir` output is checked in next to the module's
laws, so the workspace itself never needs a nightly.

```text
sandblaster/mirx/extract.sh commonware-codec varint codec/sandblaster/varint/varint.sbmir \
    --exclude u128,i128 --stub varint.rs=codec/sandblaster/varint/varint.rs
```

* `--exclude` names the sealed-trait impl types whose instances are not
  extracted (the module's `#[lift(unverified = ..)]`).
* `--stub out.rs=src.rs` replaces the crate's build script for the
  extraction by one that writes `src.rs` minus its leading `//!` lines to
  `OUT_DIR/out.rs` (what `compile_module` emits in module mode); spans in
  that file are mapped back to `src.rs`.

Re-run it whenever the module's source changes (the build refuses a stale
extraction by the sources' SHA-256) or when the workspace moves to another
stable release (the build refuses MIR of another release; bump the channel
in `rust-toolchain.toml`).

The driver is trusted as a printer (DESIGN.md §1.1 item 8): it transcribes
rustc's data and writes `(unsupported "..")` for anything it does not
transcribe, which the reader refuses.
