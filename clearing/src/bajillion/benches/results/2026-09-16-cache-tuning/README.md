# Bajillion durable-vote measurements with aligned pages and a shared cache

All workloads start with one million live accounts. A is active payers, B is
the recipient pool, and K is recipients per payer. Withdrawals and earlier
closes are zero. Every mean uses three samples with no warmup.

| A | B | K | Raw samples (ns) | Mean |
| ---: | ---: | ---: | --- | ---: |
| 1,024 | 512 | 1 | 28408435, 31619906, 27353059 | 29.1 ms |
| 1,024 | 512 | 8 | 83016453, 86951138, 83679847 | 84.5 ms |
| 1,024 | 8 | 8 | 81466195, 86371765, 81363514 | 83.1 ms |
| 1,000,000 | 512 | 1 | 29224310447, 28970228179, 28995778677 | 29.1 s |

The timer starts from an encoded dealing and includes sealing, signing,
validation, concurrent native commits of the three public QMDBs, then the
private checkpoint and signing decision. Every sample starts from an open,
durable predecessor. Fixture construction, copying, opening, native reopen
verification, cleanup, and networking are outside the timer. All twelve samples
reopened successfully. Large dealings use explicit benchmark limits.

The host was a c8a.4xlarge with 16 AMD EPYC 9R45 vCPUs and 32 GiB RAM, running
Ubuntu 24.04.4. Storage was an encrypted, network-attached 160 GiB gp3 EBS SSD
with ext4, provisioned at 6,000 IOPS and 250 MiB/s. Each vote waited for the
filesystem durability barriers. Validation and public stores shared one
adaptive 16-worker Rayon pool, with two runtime workers. The fixtures fit in RAM.

One native cache was shared by state, activity, payouts, and the private
checkpoint. Its 1 GiB physical-page budget supplied 262,144 pages. Each physical
page was 4,096 bytes, with a 4,084-byte payload derived by `paged::page_size`.
Cache metadata is additional to that page budget. All four databases used
8 MiB write/replay buffers. State and log journals retained 4,096-operation
sections and 4,096-node Merkle blobs. Each case used fresh storage with this
geometry.

`samples.jsonl.gz` preserves all metadata and sample records. `timings.csv`
contains arithmetic means. `manifest.json` binds the source, binary, commands,
toolchain, host, storage, sample values, and artifact hashes. The measured source
is commit `8cdc7e7e54df4428d38d92ec9c3537be5c8eb07b` plus `source.patch`.
The frozen archive, full source-file hashes, Linux binary, build logs, per-case
telemetry, and AWS inventory are retained in the session scratchpad. Dependencies
were prepared from the preceding source before the final build. Earlier result
directories preserve the previous configurations and measurements.
