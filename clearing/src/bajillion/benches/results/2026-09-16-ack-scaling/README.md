# Bajillion active-payer scaling with GiB journal sections

All cases have one million live accounts, a fixed pool of 512 recipients, and
one recipient per payer. Withdrawals and earlier closes are zero. Each mean
uses three samples with no warmup.

| Active payers | Operator dealing | Operator preparation | Validator durable vote |
| ---: | ---: | ---: | ---: |
| 1,000 | 102,795 B | 1.15 ms | 14.0 ms |
| 10,000 | 1,027,491 B | 12.1 ms | 70.7 ms |
| 100,000 | 10,274,964 B | 140 ms | 581 ms |
| 1,000,000 | 102,750,004 B | 1.60 s | 6.14 s |

The durable-vote timer starts from an encoded dealing and includes sealing,
signing, validation, concurrent durable commits of the three public QMDBs,
then the private checkpoint and signing decision. Each sample starts from an
open, durable predecessor. Fixture construction, copying, opening, raw reopen
verification, cleanup, and networking are outside the timer. All twelve reopen
checks passed. The fixtures fit in RAM and the filesystem cache is retained.
All fixtures use benchmark limits, since one million accounts exceed the deployed
genesis bound.

Operator preparation starts from detached inputs and ends at the prepared
dealing. Activity verification starts from decoded inputs and ends at the
resolved lookup. The activity microbenchmarks contain standalone account Rows
without payment Entries, at 1,000, 10,000, 100,000, and 1,000,000 Rows. Each
activity sample times 1,000 lookups, and the reported value is the mean of three
per-lookup sample means. Complete challenge sizes use the payment workloads in
the table. This collection does not remeasure the older payout, historical
activity, or state-proof tables.

The host was an AWS c8a.4xlarge with 16 AMD EPYC 9R45 vCPUs and 32 GiB RAM,
running Ubuntu 24.04.4, Linux 7.0.0-1012-aws, and Rust 1.98.1. Storage was an
encrypted, network-attached 160 GiB gp3 EBS SSD with ext4, provisioned for
6,000 IOPS and 250 MiB/s. Each vote waited for filesystem durability barriers.
Validation and public stores shared one adaptive 16-worker Rayon pool, with
two runtime I/O workers. No tracing or competing build ran during measurement.

The four databases shared one native 1 GiB physical-page cache budget
(262,144 pages). Physical pages were 4,096 bytes, with 4,084-byte payloads
obtained through `paged::page_size(4096)`. Cache metadata is additional to the
page budget. State/activity operation and Merkle write buffers requested
256 MiB to cover the complete million-payer batch. Payout/private write buffers
and all replay buffers were 8 MiB. Public operation sections held up to
33,554,432 operations, with 67,108,864 nodes per Merkle blob. Full state and
dense-activity sections occupy about 2.29 GiB and 2.10 GiB physically, and full
Merkle blobs about 2.01 GiB. Capacities do not preallocate full sections. Every
case used fresh storage with this geometry.

The benchmark harness executed 22 build, size, and measurement commands
successfully, from 2026-09-16T06:05:13Z through 06:30:02Z. Builds were serial,
and ACK cases ran from the largest payer count to the smallest. `manifest.json`
records every command, source identity, binary hash, environment, and output
hash. `timings.csv` and `bytes.csv` contain the aggregated results.
`samples.jsonl.gz` and `raw-checks.jsonl.gz` preserve their underlying records.
`measurements.json` contains the blog inputs, and `measurements.provenance.json`
maps every numeric value to those records. No measurements are inferred from
command wall times.

The measured source is based on commit
`8cdc7e7e54df4428d38d92ec9c3537be5c8eb07b`. `source-inputs.tar.gz` contains the
exact `Cargo.lock`, `source.patch.gz`, and `untracked-source.tar.gz` captured
by the harness. Apply the decompressed patch to that base and extract the
untracked files to reproduce the measured tree. The manifest records all three
input hashes and the reconstructed source fingerprint. Results directories
are excluded from that fingerprint.

The clearing binary SHA-256 is
`006cc9fb5e2e9650af54440d73f3ba3400cb68944eed1137cf7e23a34363118e`.
The durable-ACK binary SHA-256 is
`306d4ae07525d45a33e6bf0deb39f34ccbf6945f4563d77eafc3c5379211019a`.
The original source archive, complete source-file hashes, Linux binaries,
build logs, per-command telemetry, diagnostic traces, and AWS inventory remain
in the session scratchpad under `ack-scaling-optimization`. Earlier result
directories retain their original configurations and measurements.
