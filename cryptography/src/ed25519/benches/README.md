# Ed25519 batch comparison

`batch_verify` compares three paths on identical signed fixtures:

- `backend=dalek`: the existing vendored verifier, compiled directly into the benchmark.
- `backend=curve25519`: the in-tree verifier, even when its backend is portable.
- `backend=dispatch`: the public `ed25519::Batch` API, selecting the in-tree verifier on
  SIMD hosts and dalek otherwise.

The matrix includes 1, 32, 1,000, 16,384, and 100,000 signatures; one, up to 32, or all
distinct signers; 32- and 256-byte messages; and sequential or eight-thread execution.
Messages differ within each batch. Signing and fixture generation are never timed.

`mode=verify` times only verification and teardown. `mode=queued` also times batch
construction, framing, and queuing using cached keys. `mode=decoded` additionally times
eager public-key decoding, matching the public API's validation boundary. The in-tree
verifier decompresses each distinct key again during verification; it does not retain
the dalek key cache. Signatures are already decoded in every mode.

Build without running measurements:

```sh
just build --release -p commonware-cryptography --bench ed25519
```

Run an initial eight-thread, distinct-key comparison:

```sh
cargo bench -p commonware-cryptography --bench ed25519 -- \
  'batch_verify/sigs=1000 signers=1000 bytes=32 conc=8 backend=.* mode=(verify|queued)$'
```

Repeat with `sigs=16384 signers=16384` and `sigs=100000 signers=100000`, then compare
`signers=1`, `signers=32`, `conc=1`, `bytes=256`, and `mode=decoded`. Criterion filters
select measurements, but fixture construction still runs for the full matrix.

Force the in-tree portable backend on the same machine:

```sh
cargo bench -p commonware-cryptography --bench ed25519 \
  --features commonware-cryptography-curve25519/portable -- \
  'batch_verify/sigs=1000 signers=1000 bytes=32 conc=8 backend=.* mode=(verify|queued)$'
```

The `portable` feature also makes public dispatch use dalek. It is an explicit override
of runtime dispatch; merely omitting compiler target features does not force portable
execution. The accelerated x86 backend requires both AVX-512F and AVX-512 IFMA. AArch64
uses NEON unless `portable` is enabled.

Record the commit, `rustc -Vv`, CPU model/features, compiler flags, and feature selection
with each result. Keep those settings identical between implementations. Repeat runs
on an otherwise idle host, including representative small and repeated-signer batches.
Do not infer application throughput from decompression timings alone; follow with the
Constantinople harness using identical validator, thread, transaction, and key-reuse
settings. Certificate verification and individual verification still use dalek.

No performance improvement is established until these comparisons are run on the
deployment hardware. In particular, NEON needs separate measurement from AVX-512.
