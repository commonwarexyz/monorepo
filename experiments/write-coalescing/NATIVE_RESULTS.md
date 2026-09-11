# Native write coalescing results

Measured on 2026-09-06 against Commonware
`73509b407aca65e3ad9bb2c6d34e4dc0e0c216a3`, using Rust 1.98.0 and locked
dependencies. The comparison covers the ordinary Tokio storage backend and
contributes evidence for [issue #3440](https://github.com/commonwarexyz/monorepo/issues/3440).

**Coalescing helps some small writes with many fragments and hurts some larger
writes.** Input allocation and reuse also change the result. The measurements
identify regions worth investigating before choosing a heuristic; they do not
establish a universal threshold or an application speedup.

Three builds compare the existing backend with heap and pool coalescing inside
its blocking closure. Allocation, copying, cleanup, and returning buffers to the
pool are included. All variants receive the same prepared fragments and retain
the backend's existing synchronization behavior.

## Main observations

Ratios are candidate throughput divided by vectored throughput. Values above
1 favor coalescing. Brackets show percentile 95% bootstrap intervals from seven
paired process repetitions. These examples use buffered writes and one reused
input allocation.

| Write shape | Linux heap | Linux pool | macOS heap | macOS pool |
| --- | ---: | ---: | ---: | ---: |
| 4 KiB, 256 segments | 1.600 [1.587, 1.613] | 1.665 [1.658, 1.671] | 1.753 [1.716, 1.797] | 1.924 [1.895, 1.950] |
| 64 KiB, 256 segments | 1.256 [1.248, 1.264] | 1.243 [1.237, 1.249] | 1.282 [1.247, 1.322] | 1.091 [1.058, 1.120] |
| 1 MiB, 256 segments | 0.889 [0.881, 0.896] | 0.885 [0.878, 0.890] | 0.819 [0.797, 0.840] | 0.811 [0.785, 0.837] |
| 1 MiB, 1025 segments | 1.068 [1.059, 1.075] | 1.086 [1.077, 1.096] | 0.934 [0.907, 0.965] | 0.948 [0.914, 0.978] |

![Throughput ratios across the primary matrix][chart]

At 4 KiB with 256 segments, pool throughput increased by about 66% on Linux and
92% on macOS. Process CPU cost per completed write fell to 0.602 and 0.519 of
baseline. At 1 MiB with the same segment count, pool throughput fell by about
12% and 19%, while CPU cost rose to 1.130 and 1.225 of baseline.
[The full tables][tables] include baseline rates, CPU costs,
and intervals for all 64 candidate comparisons per platform.

The one segment controls remain close to baseline. One Linux heap control
shows a 0.8% loss with an interval excluding 1. Small effects remain sensitive
to build layout and residual variation.

## Input allocation, reuse, and synchronization

With 1 MiB and 1025 segments on macOS, heap coalescing changes from 0.934 of
baseline with one reused source to 1.454 [1.389, 1.508] when rotating through
16 MiB of input. Pool coalescing changes from 0.948 to 1.536 [1.492, 1.577].
Separate allocations for the same fragments instead produce ratios of 0.760
and 0.779. Total bytes and fragment count alone do not determine the outcome.

Linux is less sensitive in that selected case: heap ratios are 1.068 for one
reused allocation, 1.053 for rotating input, and 1.088 for separate allocations.
These are observations about the complete machines and runtimes. The comparison
does not isolate an operating system effect.

### Possible mechanisms and implications

Input allocation and reuse describe the source buffers, not reuse of the pool
used for coalescing. The source fragments are prepared before timing. Separate
allocations therefore do not mean that every measured write allocates fresh
input fragments. The allocation and copying performed by coalescing remain
inside timing.

Changing where source bytes reside and which addresses are accessed on
successive writes can change memory access costs even when byte count and
fragment count are unchanged. Reusing one prepared input may favor cache
residency. Separate allocations can change locality and buffer ownership
bookkeeping. Rotating inputs changes the sequence and working set of source
accesses.

These are plausible mechanisms, not established causes of the observed
reversal. The controls do not isolate cache residency, allocation layout, or
ownership overhead. They show sensitivity to the input pattern, not which
underlying cost caused it.

Each ratio compares policies under the same input pattern. A larger ratio does
not establish higher absolute throughput than a different input pattern.

A rule based only on total bytes and fragment count would make the same
decision for these input patterns, despite their different winners on macOS.
This does not rule out a useful heuristic. Candidate thresholds need evaluation
across representative input patterns, particularly around the decision
boundary, before adoption.

### Synchronization and control coverage

Synchronized 4 KiB writes with 1025 segments reach ratios of 1.630 for heap and
1.693 for pool on Linux. The macOS ratios are 1.039 and 1.049, with wider
intervals. These six synchronization cases and five allocation and reuse
controls vary selected workloads; they are not a full concurrency or cache
matrix. Rotating 16 MiB does not guarantee that input is absent from every CPU
cache.

## Measurement conditions

| Property | Native Linux | Native macOS |
| --- | --- | --- |
| CPU | AMD EPYC 8024P, 8 physical cores and 16 threads | Apple M1 Pro, 8 performance and 2 efficiency cores |
| Memory | 64 GB class; no active swap | 32 GiB |
| OS | Ubuntu 24.04 LTS, Linux 6.8.0-88-generic | macOS 26.5.2, build 25F84 |
| Storage | Two 960 GB Dell DC NVMe PM9A3 drives, firmware 1.0.0; ext4 on MD RAID1 | Internal SSD with APFS; about 72 GiB free |
| CPU placement | CPUs 4, 5, 6, 7, sharing one L3 cache | Ordinary scheduler placement |
| Power and load | Performance governor; boost and SMT enabled | AC power; ordinary desktop applications remained running |
| Execution | Dedicated physical server | Native executable |

Each platform ran 32 cases, three policies, and seven repetitions, for 672
trials. Each trial used a fresh process, 200 ms warmup, and a requested one
second measured interval. One caller kept one write outstanding. The 64 MiB
file was populated and synchronized before cyclic overwrites began. Main
timings used no fault interposer or profiler.

Completed bytes are divided by the actual elapsed interval, including deadline
overshoot. Buffered rates describe this bounded cached overwrite workload. For
example, the macOS baseline reaches about 9236 MiB/s for 1 MiB with 256 segments;
that is not sustained SSD throughput. Process CPU time includes all process
threads but excludes some background kernel and device work.

## Pilots and uncertainty

The initial Linux comparison of the baseline binary with itself exposed
roughly 10% variation while the server was synchronizing its RAID mirror and
the selected cores crossed two L3 caches. The mirror resynchronization was
frozen, then CPU placement was restricted to four physical cores sharing one
L3 cache. All three pilots are retained.

| Linux pilot | Conditions | Individual throughput ratio range |
| --- | --- | ---: |
| `aa.jsonl` | Resynchronization active; CPUs 1, 2, 3, 4 | 0.888 to 1.107 |
| `aa-isolated.jsonl` | Resynchronization frozen; same CPUs | 0.895 to 1.111 |
| `aa-same-cache.jsonl` | Resynchronization frozen; CPUs 4, 5, 6, 7 | 0.994 to 1.005 |

The final Linux pilot's synchronized case has interval [0.99491, 0.99861],
excluding 1 even though both labels run the identical binary. Effects of a few
tenths of a percent remain suspect. The environment changes preceded the main
matrix; no main trial was excluded because it was slow or unfavorable.

The RAID mirror remained incomplete and frozen throughout measurement, with
both members present and writes using the RAID1 path. The retained preparation
and final state records describe this condition. It limits transfer of the
storage results to other configurations.

The final macOS pilot has mean throughput ratios of 0.982 [0.959, 1.004],
1.011 [0.999, 1.031], and 0.993 [0.970, 1.015] across its three cases. It used the
same binaries as the grid. An earlier pilot before a lint cleanup and rebuild
is retained with its own manifest. Small macOS effects deserve additional
caution given the desktop load and storage state.

The analysis resamples paired blocks 10,000 times and reports geometric mean
ratios. Seven repetitions provide limited precision. Intervals are conditional
on one build and one machine per platform; they are not simultaneous guarantees
across the grid or intervals over a population of machines.

## Correctness and interpretation

Every main trial checked the expected contents of all final written slots and
the exact logical file length. Warmup used different contents. Final readback
cannot prove that every earlier overwrite occurred or establish crash
durability.

The native Linux records contain 180 correctness checks across three builds,
covering paged inputs, two concurrency settings, both synchronization modes,
and normal, missing, short, interrupted, and zero progress writes. Each
platform also has 96 uniform smoke trials. Their timings are excluded from
performance analysis.

The complete dataset audit checks the frozen inventory and order, paired
inputs, commands, recorded binary identities, verification counts, and metric
arithmetic. Both main grids have passing archived audits.

Linux synchronization follows the backend's existing `RWF_DSYNC` or final
data synchronization path; macOS follows its existing write and `sync_all`
path. The Linux device metadata reports no volatile write cache and write
through queues. These observations describe the exercised software contract
and visible storage configuration, without constituting a power failure test.

The measured tradeoff includes copying, allocation, buffer ownership, runtime
dispatch, and kernel work. It does not isolate each cost. Networking,
`io_uring`, complete application performance, and heuristic selection remain
outside this experiment.

The [reproducibility archive][archive] preserves the full experiment at commit
`918838255e1d4bf106356e1d16118c28506467cc`. See [the protocol][protocol] for commands
and [the evidence inventory][inventory] for the retained records.

[archive]: https://github.com/diegomrsantos/monorepo/tree/918838255e1d4bf106356e1d16118c28506467cc
[chart]: https://raw.githubusercontent.com/diegomrsantos/monorepo/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/results/native/throughput-grid.png
[tables]: https://github.com/diegomrsantos/monorepo/blob/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/results/native/TABLES.md
[protocol]: BACKEND_PROTOCOL.md
[inventory]: https://github.com/diegomrsantos/monorepo/blob/918838255e1d4bf106356e1d16118c28506467cc/experiments/write-coalescing/results/native/ARTIFACTS.md
