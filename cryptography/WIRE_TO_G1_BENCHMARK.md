# From received bytes to validated G1 points

The complete optimized receiver takes **368.174 ms for 100,000 BLS12-381 G1
points**, versus **884.159 ms** with standard decoding and the existing batch
subgroup checker, and **2976.020 ms** with standard per-point checked decoding.
These are measured complete calls, not sums of separately timed stages.

The optimized path is **2.40x faster than the existing batched path** (58.4%
less time), and **8.08x faster than per-point checked decoding**. Both wire
formats occupy 48 bytes per point: 4.8 MB for this batch.

## Boundary and implementations

The timed operation receives an in-memory byte slice containing the point
payload and returns `Some(Vec<G1>)` only after encoding, curve, and subgroup
validation succeed. Invalid input returns `None`. The returned points can be
used by the proof verifier's group arithmetic and pairing operations.

The interval includes parsing, canonical encoding checks, decompression,
on-curve validation, output allocation, fresh challenge generation, all graph
and certificate setup, subgroup checking, and temporary scratch destruction.
It stops with the returned points still available; output destruction is
outside the interval. There is no prepaid verification circuit or cached
subgroup result.

Point generation and sender serialization happen before measurement. Network
transport, enclosing proof-message framing, and proof verification equations
are outside this receiver-side G1 benchmark. The workload contains only G1
points, not G2 points.

The private prototype is in
[`receive.rs`](src/bls12381/primitives/subgroup/research/decompression/receive.rs):

| Method | Wire encoding | Validation |
| --- | --- | --- |
| `standard_individual` | Standard compressed G1 | `G1::read` for every point, including its exact subgroup check |
| `standard_batched` | Standard compressed G1 | `G1::read_unchecked`, then `batch_in_g1` at target 128 |
| `triple_batched` | Joint triples, four root lanes | Triple decoding, then the same `batch_in_g1` at target 128 |
| `optimized` | Joint triples, four root lanes | Triple decoding, then the certified recursive graph checker for 100,000 through 3,000,000 points; the existing target-128 checker otherwise |

The graph path uses the complete truncated q47 outer graph and effective-column
certified q19 recursion, with the derived bound in
[`SUBGROUP_CASCADE.md`](SUBGROUP_CASCADE.md). The lower crossover is a
conservative choice from the prior measurements, not a claimed optimal
threshold. The upper limit preserves the range of the research soundness
argument. Both randomized checkers target false acceptance below `2^-128`;
the per-point baseline uses exact checks. Fresh private randomness is required
outside reproducible benchmarks.

## Measurements

One serial run on the local Apple ARM macOS machine, Rust 1.97.1, release build.
All formats encode the same deterministically generated random nonzero scalar
multiples of the generator. Every path is checked against those original points
before timing. No other builds or tests ran during measurement.

Criterion 0.8.2 uses ten flat samples, one second of warmup, and a three-second
measurement target per case. Slow cases automatically extend measurement to
obtain all ten samples. Each timed invocation constructs a fresh `TestRng`
with an advancing seed. All samples, including outliers, are retained.

The table reports Criterion **mean estimates**, in milliseconds:

| G1 points | Standard, individual checks | Standard, batch check | Optimized receiver | Speedup over standard batch |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 29.592 | 12.050 | **7.588** | 1.59x |
| 6,000 | 177.451 | 58.536 | **30.309** | 1.93x |
| 100,000 | 2976.020 | 884.159 | **368.174** | 2.40x |

At 100,000 points, the control using triple decoding with the existing batch
checker takes **404.241 ms**. Connecting the certified recursive checker saves
another **8.9%** of the complete receiver time. The two triple variants use the
same checker below 100,000 points, so the redundant control is omitted there.

Criterion's 95% confidence intervals for the mean at 100,000 points:

| Method | Mean | 95% interval |
| --- | ---: | ---: |
| Standard, individual checks | 2976.020 ms | 2970.520-2981.315 ms |
| Standard, batch check | 884.159 ms | 881.626-887.680 ms |
| Triples, existing batch check | 404.241 ms | 402.644-406.119 ms |
| Optimized receiver | 368.174 ms | 365.427-372.225 ms |

The optimized receiver averages **3.68 microseconds per point**, or about
**272,000 validated points per second**. These results establish serial CPU
latency for this workload, not parallel throughput or full proof-verification
time. They should not be combined arithmetically with earlier runs using
different inputs or sampling methods.

## Reproduction and status

Run only this timing test while measuring:

```sh
just test -p commonware-cryptography --release \
  decompression::receive::measure_wire_to_points --run-ignored only --no-capture
```

Criterion runs inside an ignored test to retain access to the private research
implementations. It writes raw samples and estimates under `target/criterion`.
The production codec, public APIs, and shipping verification path are unchanged.

The optimized representation requires an agreed batch format; it cannot consume
existing standard compressed point bytes. It keeps their size but changes their
meaning. The subgroup argument and joint codecs remain research prototypes.

The integration tests check round trips, exceptional pairs, incomplete triples,
malformed encodings, order-three and order-eleven pollution, and rejection of an
order-eleven nonmember in the final one-point tail of a 100,000-point batch.
The latter exercises the complete graph path from wire bytes through rejection.

Validation: all 760 tests selected by the default crate profile passed (57
skipped), as did Clippy and formatting checks. The Criterion timing test also
completed successfully. The WASM build remains blocked because the local C
compiler cannot compile blst for `wasm32-unknown-unknown`. No public API,
production algorithm, dependency, or unsafe code was added by this benchmark.
