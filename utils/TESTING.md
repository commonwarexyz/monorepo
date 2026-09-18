# Testing utilities

Run the bitmap's native tests with:

```sh
just test -p commonware-utils bitmap::
```

## Verus proofs

The inline proof in [bitmap](src/bitmap/mod.rs) verifies the production `ones_iter_from` constructor, word loading, and `OnesIter::next`. QMDB uses this scanner to select active operations during floor raising; ordinal storage uses it to select records for replay.

For a coherent, unchanged bitmap snapshot, the proof establishes that:

- Iteration returns exactly the set bits in `[max(pos, pruned_bits), len)`, in strictly ascending order, without duplicates.
- Every call and the complete traversal terminate. Once exhausted, subsequent calls return `None`.
- Chunk accesses, slices, shifts, and integer arithmetic stay within their bounds.

The specification defines bit values from the snapshot's chunk bytes. It permits small and irregular chunk widths, nonzero unused tail bits, and sparse bitmaps pruned near `u64::MAX`. An already-exhausted scan needs no chunk-index bound; a nonempty scan requires its absolute chunk indices to fit `usize`.

The input contract also requires a nonzero chunk width whose bit count fits `usize`, consistent pruning metadata, and complete active chunks. The layout bound follows the pinned Rust compiler's [object-size limit](https://github.com/rust-lang/rust/blob/8bab26f4f68e0e26f0bb7960be334d5b520ea452/compiler/rustc_abi/src/lib.rs#L607); revisit that bound when changing the compiler pin. Verus checks arithmetic with its default [32-bit or 64-bit pointer-width model](https://verus-lang.github.io/verus/guide/integers.html).

`Readable` methods must terminate and return the declared snapshot's data. Concrete reader implementations, bitmap mutations, and synchronization are outside this proof. For an interior-mutable source, the caller must prevent mutation throughout iteration; QMDB's [shared bitmap scan](../storage/src/qmdb/bitmap.rs) holds a read guard for this purpose. The theorem does not establish complete QMDB or replay lifecycle correctness.

Verification trusts Verus and its bundled `vstd` specifications. The byte-conversion bridge uses `vstd::bytes::u64_from_le_bytes`, whose body calls the same native `u64::from_le_bytes` on the eight loaded bytes. Keep that bridge aligned with the native expression. The proof uses the direct `next` contract; it does not verify the standard iterator adaptors or derived `Clone` implementations.

When changing the proof, check that executable mistakes still fail verification: skipping the starting bit, keeping the previous chunk at a chunk boundary, yielding a bit twice, wrapping an advancing offset, and omitting the final-word mask. Apply these checks to the actual scanner body.

### Running

Install the official [Verus release `0.2026.08.23.fbbbbcf`](https://github.com/verus-lang/verus/releases/tag/release/0.2026.08.23.fbbbbcf), including its bundled `cargo-verus`, then run:

```sh
rustup toolchain install 1.97.1 --profile minimal
VERUS_BIN=/path/to/verus just test-verus
```

`VERUS_BIN` defaults to `verus` on `PATH`. The recipe verifies the actual `commonware-utils` library through `cargo-verus focus`, with the optional `verus` feature and `--no-cheating`. This rejects local `assume`, `admit`, and `external_body` escapes while using the trusted standard-library specifications. Ordinary builds omit the ghost code and do not activate the verifier dependency.

The [CI workflow](../.github/workflows/verus.yml) pins the verifier archive and its SHA-256 and runs the same command on pull requests, merge groups, and pushes to `main`. Native bitmap and storage-consumer tests complement the proof by exercising concrete readers and their callers.
