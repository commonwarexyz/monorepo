# Bajillion durable-vote measurements: September 16, 2026

Each workload starts with one million live accounts. A is active payers, B is
the recipient pool, and K is recipients per payer. Withdrawals and earlier
closes are both zero. Every mean uses three untraced samples with no warmup.

| A | B | K | Raw samples (ns) | Mean |
| ---: | ---: | ---: | --- | ---: |
| 1,024 | 512 | 1 | 35471286, 37134436, 35333744 | 36.0 ms |
| 1,024 | 512 | 8 | 80232074, 79705070, 78807533 | 79.6 ms |
| 1,024 | 8 | 8 | 76486180, 76837471, 76963382 | 76.8 ms |
| 1,000,000 | 512 | 1 | 29399925462, 29190254769, 29292890467 | 29.3 s |

The timer starts from an encoded dealing and includes sealing, signing,
validation, concurrent native commits of the three public QMDBs, and the
subsequent private checkpoint and signing decision. Every sample starts from
an open, durable predecessor. Fixture construction, copying, opening, native
reopen verification, cleanup, and networking are outside the timer. All twelve
samples reopened successfully. The fixture uses explicit benchmark limits.

The host was a c8a.4xlarge with 16 AMD EPYC 9R45 vCPUs and 32 GiB RAM, running
Ubuntu 24.04.4. Storage was an encrypted, network-attached 160 GiB gp3 EBS SSD
with ext4, provisioned at 6,000 IOPS and 250 MiB/s. Each measured vote waited for
the filesystem durability barriers. Validation and public stores shared one
adaptive 16-worker Rayon pool, with two runtime workers. Three 16 KiB native
caches served state, the two logs together, and the private checkpoint. The
fixtures fit in RAM.

Activity and payout journals used 4,096 operations per section and 4,096 Merkle
nodes per blob. State geometry remained 4,096 operations and nodes per blob.
Native pages were 1,024 bytes, with 16 pages per cache and 2,048-byte log and
private I/O buffers. These physical capacities require fresh storage.

`samples.jsonl.gz` retains every raw metadata and sample record. `timings.csv`
contains the arithmetic means. `manifest.json` binds the commands, source,
binary, toolchain, host, storage, sample values, and artifact hashes.
The measured source is commit `8cdc7e7e54df4428d38d92ec9c3537be5c8eb07b` with
`source.patch` applied. The frozen source archive, Linux binary, complete build
logs, per-case telemetry, and AWS inventory remain in the session scratchpad.
The earlier benchmark directory retains its original measurements and inputs.
