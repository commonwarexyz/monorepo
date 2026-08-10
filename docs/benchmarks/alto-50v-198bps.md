---
title: "Alto 50-Validator Benchmark: 198.1 Blocks Per Second"
description: "An archival record of the Alto analyzer reporting 198.1 finalized blocks per nominal second across 50 validators in 10 AWS regions."
date: "August 10th, 2026"
published-time: "2026-08-10T00:00:00Z"
modified-time: "2026-08-10T00:00:00Z"
author: "Commonware"
url: "https://commonware.xyz/benchmarks/alto-50v-198bps"
image: "https://commonware.xyz/imgs/pipelining-simplex.png"
---

This page reconstructs an Alto benchmark run from the evidence that survived after the cluster was destroyed. It is an archival record, not a reproducible benchmark package. The raw captures, dashboards, deployment assets, and exact deployed Alto source tree were not preserved.

The surviving analyzer output supports the reported rate and latency distributions. It does not support a comparison against another protocol configuration.

## Result

On August 5th, 2026, 50 Alto validators ran across 10 AWS regions with a 5ms block target. The workload used header-only blocks with no transactions or execution.

The throughput capture contained 189 samples from a nominal one-second Tokio timer. These samples define 188 timer intervals between the first and last observation. The raw tick timestamps were not preserved. The finalized height increased from 196,305 to 233,554:

```text
(233,554 - 196,305) / (189 - 1) = 198.13 finalized blocks per nominal second
```

The analyzer rounded this result to 198.1 blocks per nominal second. The view increased by the same amount, so the capture observed one successful view per finalized block.

| Metric | Result |
|---|---:|
| Once-per-second samples | 189 |
| Measured intervals | 188 nominal one-second timer intervals |
| Finalized height increase | 37,249 blocks |
| View increase | 37,249 views |
| Analyzer-reported finalized block rate | 198.1 per nominal second |
| Successful views per block | 1.00 |
| Per-second median block spacing | 5ms in 189 of 189 samples |
| Zero-block samples | 0 of 189 |
| Rounded worst per-second average spacing | 7ms |

The analyzer flagged four samples near expected 10,000-view term boundaries. Its detector used zero-based integer division while protocol terms are one-indexed. The selected samples probably contain the transitions, but the deleted raw data prevents exact attribution. They contained 155 to 163 blocks, compared with the 200-block target. The following samples contained 189 to 200 blocks. No sample contained zero blocks.

The inspector derived each block-spacing observation by dividing the timestamp change by the corresponding height change. This averages across multiple heights when delivery skips directly to a later height. The raw stream is unavailable, so this record cannot rule out such gaps. The surviving output directly establishes that all 189 reporting-window medians were 5ms.

## Finality

A separate capture on the same cluster measured 3,736 finalizations about one hour later. The measurement began at the leader-stamped block timestamp and ended when an external client received the finalization certificate.

The path included delivery from a validator to the indexer, through a WebSocket, and then to the external client. The observer's clock was checked, but the validator clock offsets were not preserved. The values measure external-observer end-to-end latency with unknown cross-clock error. They are not a strict upper bound on consensus-network finality.

| Percentile | Finality |
|---|---:|
| Minimum | 276ms |
| p1 | 282ms |
| p10 | 292ms |
| p25 | 296ms |
| p50 | 300ms |
| p75 | 305ms |
| p90 | 310ms |
| p99 | 376ms |
| Maximum | 416ms |

The external client's clock was checked against `time.apple.com` immediately before the capture. The observed offset was +3.6ms with a reported uncertainty of +/-4.8ms.

The cluster's own `finalization_latency` metric reported roughly 90ms, but that metric started at view entry rather than proposal. This record excludes it.

## Deployment

The cluster tag was `92e68f61-9093-43d0-81fe-56dbae2b024b`. The cluster contained 50 validators and one monitoring host.

Each of the following AWS regions hosted five validators:

- `us-west-1`
- `us-east-1`
- `eu-west-1`
- `eu-north-1`
- `eu-central-1`
- `ap-northeast-1`
- `ap-northeast-2`
- `ap-south-1`
- `ap-southeast-2`
- `sa-east-1`

Validators used `c7gd.4xlarge` instances with 8 worker threads and 16 signature-verification threads. The monitoring host used a `c8g.4xlarge` instance. The validator binary was an optimized aarch64 release build with debug information.

The deployment used the following additional limits:

| Setting | Value |
|---|---:|
| Message backlog | 16,384 |
| Mailbox size | 16,384 |
| Deque size | 1,000 |
| Validator storage | 25GB |

Validator-to-validator network routing was not preserved. Three `us-east-1` validators uploaded data to the indexer over private addresses. The throughput and finality measurements came from one external client subscribed to that indexer.

## Consensus Configuration

| Setting | Value |
|---|---:|
| Block target | 5ms |
| Leader early wake | 1ms before the pacing deadline |
| Stable-leader term length | 10,000 views |
| Stall timeout | 12s |
| Optimistic views | 100 |
| Leader timeout | 1s |
| Certification timeout | 2s |
| Nullify retry | 10s |
| Activity window | 256 views |
| Skip timeout | 11s |
| Fetch timeout | 2s |
| Marshal resolver timeout | 10s |

The forwarding policy was not preserved.

## Workload

Blocks contained only a context, parent digest, height, timestamp, and block digest. The run offered no transactions and performed no transaction execution. Application verification checked timestamp monotonicity and skew. Marshal checked the height and parent digest. Consensus artifacts were journaled to disk, and blocks were disseminated over the P2P network.

This workload measures consensus cadence. It does not measure transaction throughput.

## Source Revisions

The Alto binary was based on commit `b0b477871a3ead89882af1208806ef73c2ee3e8f` on branch `bc/optimistic`, plus uncommitted changes. A later worktree status showed 14 modified files, but it is not an exact snapshot of the deployed source. The known run-defining edits set the block target to 5ms, woke the leader 1ms before its pacing deadline, set the term length to 10,000 views, and set the tracing sample rate to 0.1. A leader timestamp could therefore lead its wall clock by as much as 1ms. No snapshot of the complete deployed Alto tree survives.

The Commonware dependency used revision `19af3c69d87c79a043cf6a8b3b4ebb640be3caf2`. This was a local-only committed revision retained under the local tag `keep-alto-pin` at the time this record was assembled.

The exact Rust flags and feature selection were not preserved.

## Surviving Analyzer Output

The following output was copied verbatim from the surviving session transcript:

```text
189s captured, heights 196305..233554, views 329781..367030
blocks/s: 198.1   views/s: 198.1   views/block: 1.00
zero-block seconds: 0/189   p50=5ms: 189/189
worst avg-second: 7ms   seconds avg>20ms: 0
term boundaries crossed at seconds: [1, 51, 101, 152]
  boundary ~s1: blocks around: [199, 200, 163, 200], avgs: [5.1, 5.1, 6.2, 5.1]
  boundary ~s51: blocks around: [202, 200, 163, 198], avgs: [5.0, 5.0, 6.3, 5.0]
  boundary ~s101: blocks around: [205, 200, 159, 189], avgs: [5.0, 5.0, 5.0, 6.2]
  boundary ~s152: blocks around: [195, 202, 155, 198], avgs: [5.0, 5.0, 6.7, 5.0]
```

The finality summary also survives:

```text
n=3736  min=276  p1=282  p10=292  p25=296  p50=300  p75=305  p90=310  p99=376  max=416 (ms)
histogram: 250-299ms: 1694 | 300-349ms: 1974 | 350-399ms: 45 | 400-449ms: 23
```

## Limitations

- The raw per-second throughput and finality captures were deleted.
- The Grafana and Prometheus data were destroyed with the cluster.
- The deployment assets and per-validator configuration files were deleted.
- The Alto worktree was dirty, and its exact patch was not preserved.
- The Commonware revision was local-only.
- Throughput and finality came from one external observer through an indexer.
- CPU, memory, and network utilization were not preserved.
- The run used no transaction workload.
- No rotating-leader, stable-only, or other ablation ran under the same deployment.

This evidence supports one claim: the archived analyzer reported 198.1 finalized blocks per nominal second with 5ms reporting-window median block spacing. It does not establish transaction throughput or how much any individual optimization improved the baseline.
