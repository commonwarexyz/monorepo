//! Verifies the varint module (`rustoleum/varint/`: the original
//! `varint.rs` as-is, its laws, proofs and `SPEC.lock`) and writes it to
//! `OUT_DIR/varint.rs` for the module file `src/varint.rs`. A failing proof
//! or gate, or a module file that is not exactly the source's docs and the
//! include line, fails this crate's build.
fn main() {
    rustoleum::build::compile_module("rustoleum/varint/mod.rs", "src/varint.rs");
}
