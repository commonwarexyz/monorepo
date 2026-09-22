# Joint G1 decoding on Vroom

Branch `gv/vroom-batch-decode` starts at PR [#4811](https://github.com/commonwarexyz/monorepo/pull/4811),
commit `5a68b8f417f14073f1a00fe5958c8d0ba7e82d44`, and merges the complete
`gv/batch-subgroup-check` research history through `7bc86b2b1`.

The native port lives in
[`group/subgroup/decompression.rs`](src/bls12381/group/subgroup/decompression.rs).
It is compiled only for tests, like the original codecs. It is an executable
experiment, not a public wire format. Existing `G1::from_bytes` and
`G1::batch_from_bytes` retain their standard compressed encoding and identity
semantics.

## What transfers

| Insight | Integration |
| --- | --- |
| Pair joint compression | Two G1 points in 96 bytes, one sixth root for a generic pair |
| Triple joint compression | Three G1 points in 144 bytes, one sixth root for a generic triple |
| Interleaved root chains | Four independent chains share Vroom's `batch_reduce_expand` calls |
| Batch inversion | Denominator and coordinate recovery each use one field inversion per batch |
| Exceptional fibers | Canonical pair/orbit fallback and standard singleton tails preserve 48 bytes per point |
| Complete subgroup checking | Reuse the PR's native q47/q19 certified recursive checker unchanged |
| Complete receiver benchmarks | Parse bytes, validate curve points, sample fresh challenges, check subgroup membership, return native G1 values |

The native root loop stays inside a single `WithBackend` entry, with arithmetic
helpers inlined into it. It uses Vroom's typed RNS values directly. Canonical
field parsing, equality, root selection, and sign selection use field-value
semantics; redundant residue representations are never compared as raw limbs.
The ninth-root constant is converted from canonical limbs, not copied from
blst's Montgomery representation.

Every radicand receives its own sixth-power check. Computing a root of a product
cannot certify the individual radicands. Every recovered point receives an
on-curve check before the subgroup checker starts. No partially validated G1
vector is published. Decode buffers use fallible reservations. Only the trusted
fixture encoder uses infallible allocations.

These joint formats require nonidentity points with nonzero x and y. This
covers every nonidentity prime-subgroup G1 point. They are different from the
standard compressed encoding and cannot accelerate bytes already sent in that
format. The triple generic chart excludes same-orbit pairs; exceptional pairs
have a unique fallback encoding. Tails of one and two points are included in
the measured decode path.

The PR already contains a stronger certified subgroup construction than the
older prototype: its full q47 graph supports chunks up to 4,879,681 points,
with the q19 certified inner circuit. Its exact bound script reports 129.13 bits
for the graph path and 128.38 bits across all batch sizes. The older truncated
graph and negative experiments remain in `cryptography/src/.../research` as
research history; the native decoder does not call them. A fourth point per
sixth root at the same wire size still needs a new algebraic construction.

## Validation

The focused tests cover the fixed exponent and ninth root, interleaved versus
individual roots, rejection when only the product is a sixth power, pair and
triple tails, both exceptional fibers, canonical encodings under mutations,
malformed final records before randomness, and order-three/order-eleven
subgroup pollution at several positions. Both implementations check identical
wire vectors for G, 2G, ..., 7G, independently generated with integer field
arithmetic.

```sh
just test -p commonware-cryptography-bls --release decompression::
just test -p commonware-cryptography --release decompression::
python3 cryptography/bls/scripts/subgroup.py
just test -p commonware-cryptography-bls --release large_receiver_uses_certified_subgroup_check --run-ignored only --no-capture
```

## Benchmark boundary

Run one process without other tests or builds running:

```sh
COMMONWARE_DECODE_COUNTS=1000,6000,100000 \
just test -p commonware-cryptography-bls --release \
  decompression::receive::measure_wire_to_points --run-ignored only --no-capture
```

`COMMONWARE_DECODE_METHODS=standard_batch,triple_roots4` selects a subset.
Available methods are `standard_individual`, `standard_batch`, `pair_roots4`,
`triple_roots1`, `triple_roots4`, and `blst_individual`.

Each workload uses the same deterministic random, distinct subgroup points in
all formats. blst generates the fixtures outside timing. Native timed paths use
only native arithmetic. `standard_batch` calls the PR's public
`G1::batch_from_bytes` directly, starting from a flat byte slice with no copied
or predecoded input. All methods include parsing, on-curve validation,
allocations, and subgroup checks. Batched methods include fresh RNG setup and
all graph/certificate setup. The output is a complete native G1 vector ready
for MSM/pairing verification; the external blst control returns blst points.
Criterion drops output vectors after the timed interval.

Sender encoding, fixture generation, network transfer, and the subsequent proof
verification equation are excluded. Each format uses exactly 48 bytes per point.
Criterion uses 10 flat samples, a 1-second warmup, and a 3-second requested
measurement window; slow cases automatically take longer. Reports are written
to `target/criterion`. Results must identify the selected Vroom backend: local
ARM timings exercise the portable backend and do not predict AVX-512 speedups.

For an otherwise idle Linux EC2 host with AVX-512 IFMA, run
`bash cryptography/bls/scripts/bench_decode.sh`. The runner checks both required
CPU features, records the commit/compiler/CPU, runs focused tests, pins the
benchmark to CPU 0 (override with `COMMONWARE_DECODE_CPU`), and saves the log in
`target/decode-benchmark`. It does not provision instances or read AWS keys.
The benchmark itself also reports the selected backend and refuses to run
without AVX-512 when `COMMONWARE_REQUIRE_AVX512` is set.
