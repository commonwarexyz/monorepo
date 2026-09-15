# Bajillion flat-MMR benchmark artifacts: September 15, 2026

This directory contains the encoded-byte checks and Criterion measurements for
the flat activity and payout MMR implementation. All 12 selectors completed
successfully from one frozen source snapshot and one optimized benchmark binary.

| Artifact | Contents |
| --- | --- |
| [bytes.csv](bytes.csv) | Long-form encoded-byte results from all checked fixtures. |
| [timings.csv](timings.csv) | Criterion median point estimates and 95% confidence intervals in nanoseconds. |
| [samples.jsonl.gz](samples.jsonl.gz) | Raw Criterion benchmark metadata, estimates, iteration counts, and sample times. |
| [raw-checks.jsonl.gz](raw-checks.jsonl.gz) | Every relevant line emitted by the four untimed size/transition checks. |
| [manifest.json](manifest.json) | Commands, dimensions, source, lockfile, binary, log, table, and archive hashes. |
| [source-inputs.tar.gz](source-inputs.tar.gz) | Base patch, exact lockfile, and untracked source inputs; no binaries. |

## Encoded bytes

All sizes are actual codec outputs before transport or chain transaction
framing. The 184-byte close descriptor is the 176-byte `RootBundle` plus the
8-byte withdrawal/outflow total. The Header plus exact-quorum certificate is
101 bytes. Their combined publication payload is 285 bytes. These are separate
from the encoded operator Dealing.

The signed transition matrix is selected in `bytes.csv` with
`source=native-transition-check,record=pipeline,N=1024,payment_rows=128`:

| H | Payment rows | W | Dealing | Source metadata | SourceProof | Descriptor |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 128 | 0 | 13,107 | 7,731 | 7,809 | 184 |
| 0 | 128 | 1,024 | 43,571 | 206,260 | 206,339 | 184 |
| 1,024 | 128 | 0 | 13,107 | 7,731 | 7,841 | 184 |
| 1,024 | 128 | 1,024 | 43,571 | 206,260 | 206,339 | 184 |

A `SourceProof` transmits the complete source metadata: context, terminal
sequences, outgoing leaves, and signed withdrawals. `source_metadata` is that
frame alone; `source_proof` adds its length prefix and native Commit opening;
`source_plus_claim` adds the optional payout claim. It excludes transaction
envelopes and is not part of the original operator Dealing.

The compact claim fixture's encoded output frame is 30 bytes (`394 - 364` for
`H=0,W=1024`). The signed-pipeline fixture uses a different output value and its
frame is 25 bytes (`389 - 364`). The aggregation checks derive these values from
matching emitted claim/opening rows and reject a changed or ambiguous result.
The two fixture-specific output sizes must not be substituted for one another.

Compact activity rows use
`source=native-sizes,record=activity,metric=lookup`, with
`H=0,1024,65536` and `R=0,1,2,128,1024`. Cases cover presence, empty-range
absence, adjacent interior absence, and left/right edge absence. Compact payout
rows use `source=native-sizes,record=payout,metric=artifact`, with the same `H`
values and `W=0,1,512,1024` for `N=1024`. Cases cover first, middle, and last
new outputs, historical outputs at old and refreshed heads, and an older output
after append and floor advancement. `W=0` is a Commit proof, not a withdrawal
claim. `metric=opening` excludes the output and `metric=head` is the independently
encoded 48-byte log head.

Complete profile-0 challenges are selected with
`source=challenge-sizes,record=challenge`: debit is 623 bytes, entry is 674
bytes, and fork is 417 bytes. The omitted-payer case is a separate 641-byte
challenge with a 432-byte activity absence proof. Profile 0 is
`N=1024,A=1024,B=512,K=1` and performs actual nonzero balance updates.

## Native transition timings

Values are median milliseconds with the Criterion 95% confidence interval in
brackets. All four cases use `N=1024`, 128 self-payment rows, 16 Rayon workers,
and deterministic-memory storage. Individual rows are independently sampled,
overlap, and must not be summed.

| Phase | H=0,W=0 | H=0,W=1024 | H=1024,W=0 | H=1024,W=1024 |
| --- | ---: | ---: | ---: | ---: |
| Native prepare state/logs | 0.049 [0.048, 0.050] | 0.725 [0.705, 0.742] | 0.046 [0.044, 0.050] | 0.717 [0.701, 0.744] |
| Decode | 1.982 [1.979, 1.984] | 15.722 [15.702, 15.737] | 1.991 [1.971, 2.007] | 15.702 [15.688, 15.712] |
| Validate + prepare state/logs | 1.562 [1.539, 1.588] | 3.390 [3.228, 3.532] | 1.672 [1.639, 1.796] | 3.328 [3.308, 3.499] |
| Apply state/logs | 0.016 [0.016, 0.017] | 0.240 [0.235, 0.251] | 0.022 [0.021, 0.025] | 0.269 [0.244, 0.273] |
| Commit state/logs in memory | 0.052 [0.051, 0.053] | 0.232 [0.215, 0.241] | 0.074 [0.067, 0.078] | 0.261 [0.244, 0.267] |
| Decode + validate + apply | 3.543 [3.519, 3.579] | 19.352 [19.242, 19.440] | 3.727 [3.574, 3.796] | 19.375 [19.297, 19.497] |
| Decode + validate + apply + memory commit | 3.634 [3.580, 3.659] | 19.555 [19.475, 19.636] | 3.789 [3.763, 3.845] | 19.595 [19.530, 19.711] |

The fixed predecessor is restored before each timer. Fixture construction,
signing, cloning native prepare inputs, and rewind are also outside the timers.
`native_prepare_state_logs` starts from derived mutations, exact activity Guards
and metadata, and payout outputs. `validate_prepare_state_logs` starts from a
decoded Dealing and includes cryptographic validation and all native batches.
The two complete-pipeline rows start from encoded Dealing bytes and end after all
three stores apply, with the latter additionally calling `Replica::commit`.
The terminal validator persists its checkpoint and vote in a local QMDB outside
these timers, so they do not measure the full path to publishing an ACK.

The transition history and measured payments are valid zero-net self-payments.
They exercise native state/log transitions but are not evidence for profile 0's
nonzero balance updates. `W` counts independently signed full-exit requests from
the same key prefix; their authorizations are separate inputs and are not bytes
in the Dealing. `activity_rows=max(payment_rows,W)` includes withdrawal-only
accounts. A full `W=N` close deletes every balance.

## Source verification timings

The source selector fixes `payment_rows=128`. Proofs are constructed outside the
timers; verification authenticates the complete metadata. Values are median
milliseconds and 95% confidence intervals.

| Case | H | W | Source verify | Source + account/claim verify |
| --- | ---: | ---: | ---: | ---: |
| Current | 0 | 0 | 4.025 [4.024, 4.027] | 4.026 [4.022, 4.030] |
| Current | 0 | 1,024 | 35.780 [35.769, 35.809] | 35.747 [35.720, 35.766] |
| Current | 1,024 | 0 | 3.999 [3.998, 4.000] | 4.008 [4.003, 4.010] |
| Current | 1,024 | 1,024 | 35.683 [35.644, 35.705] | 35.665 [35.638, 35.707] |
| Refreshed after append/floor | 0 | 0 | 4.025 [4.023, 4.026] | 4.019 [4.014, 4.029] |
| Refreshed after append/floor | 0 | 1,024 | 35.790 [35.765, 35.813] | 35.755 [35.729, 35.801] |
| Refreshed after append/floor | 1,024 | 0 | 4.000 [3.998, 4.002] | 3.995 [3.993, 4.000] |
| Refreshed after append/floor | 1,024 | 1,024 | 35.623 [35.595, 35.645] | 35.643 [35.620, 35.658] |

The account/claim boundary includes SourceProof authentication, an account
lookup, and the optional payout claim. Because these columns are independently
sampled overlapping timers, small inversions between their estimates are not
subtraction opportunities.

## Profile and certificate timings

| Operation | Workload | Median ms [95% CI] |
| --- | --- | ---: |
| Prepare | profile 0, `E=1024` | 0.678 [0.667, 0.698] |
| Receive and apply | profile 0, `E=1024`, consecutive epochs, 16 workers | 7.695 [7.629, 8.064] |
| Adjudicate debit | profile 0, bounded decode plus adjudication | 0.172 [0.172, 0.172] |
| Adjudicate entry | profile 0, bounded decode plus adjudication | 0.203 [0.203, 0.203] |
| Adjudicate fork | profile 0, bounded decode plus adjudication | 0.199 [0.199, 0.200] |
| Sign vote | prepared Header, 100-validator fixture | 0.071 [0.071, 0.071] |
| Verify certificate | exact quorum, `n=100,f=33,q=67` | 0.455 [0.454, 0.455] |

Prepare times Dealing preparation from already signed terminal inputs. Cloning
those inputs and constructing the fixture occur outside the timer. Receive-apply
starts from encoded Dealing bytes, performs decode, validation, vote signing, and applies
Current plus both logs. It advances consecutive epochs in one native replica.

## Dimensions, samples, and storage boundary

`N` is the live-account count. `H` is prior activity rows or payout outputs,
excluding Commit markers. In source/transition workloads, `H=1024` is one prior
signed epoch. `R` is the current row count in compact activity fixtures and the
self-payment count in transition fixtures. `W` is the current payout-output or
signed-withdrawal count. `A`, `B`, and `K` are profile senders, recipient pool,
and recipients per sender. Reported operation counts include bootstrap and
epoch Commit markers.

The archive contains 163 Criterion benchmarks and 2,940 samples:

| Group | Benchmarks | Samples each |
| --- | ---: | ---: |
| Compact activity verification | 48 | 20 |
| Compact payout verification | 64 | 20 |
| Source verification boundaries | 16 | 20 |
| Native transition phases | 28 | 10 |
| Challenge adjudication | 3 | 20 |
| Prepare, receive-apply, sign-vote, certificate verify | 4 | 10 |

Criterion used a 0.25-second warmup and one-second measurement target for each
benchmark. Compact proof artifacts were decoded and constructed before their
verification timers. Native Commit uses the deterministic runtime's in-memory
storage and includes native journal processing; it is not durable SSD I/O. No
chain admission, SQL, network transfer, application checkpoint or vote persistence,
or SSD I/O is measured by the native transition groups.

## Host and reproduction

The serial run started at `2026-09-15T08:56:26Z` and ended at
`2026-09-15T09:02:45.197268Z`. It ran locally on an Apple M5 Pro (`Mac17,8`),
18 logical CPUs, 64 GiB RAM, macOS 26.5.1, using
`rustc 1.98.1 (48a229cea 2026-09-01)` for `aarch64-apple-darwin`. Rayon uses 16
workers where the benchmark label or scope specifies it. The selectors ran
serially, but the machine was not isolated and ordinary background processes
were present.

No `RUSTFLAGS`, Cargo profile, or Cargo build override was set. The compiler
wrapper only removes `CARGO_TARGET_DIR` from its child environment and invokes
`sccache`; it adds no compiler flags. All selectors used the same optimized
benchmark binary, SHA-256
`6a2401d1bfb1a21b623bc1d12c96d998a414e5670e4ea0460ec711aa8b6ad75e`.

To reproduce, obtain base commit
`c71324e3c4619e10e8f6ebe619484f782547ff7e`, extract
`source-inputs.tar.gz` separately, apply `tracked.patch` to the base checkout,
restore the archived untracked files at their relative paths, and use the
archived `Cargo.lock`. Verify all source hashes in `manifest.json`, then execute
its commands with the recorded environment matrices. The source archive has no
binaries or local process logs; the measured binary identity and every command
log are retained by SHA-256. Generated Criterion plot HTML is intentionally not
published.

The archive pins the measured source. Subsequent benchmark edits only clarify
comments and leave the executable code unchanged.
