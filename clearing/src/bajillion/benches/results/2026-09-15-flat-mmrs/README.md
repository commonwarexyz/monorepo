# Bajillion million-account benchmark artifacts: September 15, 2026

This directory contains the completed publication subset: every successfully
completed activity, payout, and preparation Criterion record, three short
durable-ACK profiles, and all completed encoded-size checks. It explicitly omits
the interrupted fourth preparation profile; verify-claim, adjudication,
sign-vote, and certificate-verification timings; dense durable ACK; and full-exit
durable ACK. This is not a complete benchmark matrix.

| Artifact | Contents |
| --- | --- |
| [bytes.csv](bytes.csv) | Encoded byte results emitted by completed check commands. |
| [timings.csv](timings.csv) | Arithmetic sample means for 77 Criterion records and three durable-ACK profiles. |
| [samples.jsonl.gz](samples.jsonl.gz) | Raw Criterion metadata, estimates, iterations and times, plus raw ACK records. |
| [raw-checks.jsonl.gz](raw-checks.jsonl.gz) | Source command and exact emitted line for every byte row. |
| [manifest.json](manifest.json) | Scope, omissions, source, binary, host, raw-evidence paths, and artifact hashes. |
| [source-inputs.tar.gz](source-inputs.tar.gz) | Exact Cargo.lock, tracked patch, and untracked-source archive used for the measured binaries. |

## Statistics and completed timing scope

Each Criterion `mean_ns` is the equal-weight arithmetic mean of its 20 per-sample ratios, `mean(times_i / iters_i)`. It is not a bootstrap median, confidence interval, or pooled iteration-weighted rate. Each durable-ACK `mean_ns` is the arithmetic mean of three raw timer values; these profiles used zero warmup samples.

The retained Criterion subset contains the complete selected activity-proof and payout-proof families plus three preparation profiles:

| Preparation profile | Samples | Arithmetic mean |
| --- | ---: | ---: |
| `N=1000000 A=1000000 B=512 K=1 E=1000000` | 20 | 1.6126350934 s |
| `N=1000000 A=1024 B=512 K=1 E=1024` | 20 | 1.16289775 ms |
| `N=1000000 A=1024 B=512 K=8 E=8192` | 20 | 3.2958474 ms |

Preparation times only `prepare_dealing`. The measured binary rebuilt the million-account fixture once per Criterion sample outside the returned elapsed interval. A later setup-only source patch hoists detached immutable inputs for future runs; it does not change production code, timer boundaries, or these measured values, and it is not represented as part of the measured binary.

The durable timer begins with an encoded dealing and covers seal, signing, validation, concurrent durable commits of Current, Activity, and Payout, then the private Compact QMDB checkpoint and Ballot durability barrier. It does not include fixture/key/baseline construction or the subsequent same-Runner raw reopen verification. The public commit is the selected recovery contract and is not a full maintenance sync.

| Durable-ACK profile | Raw samples (ns) | Arithmetic mean |
| --- | --- | ---: |
| `N=1000000 A=1024 B=512 K=1 W=0 H=0` | 276117278, 276964412, 275402922 | 276.161537333 ms |
| `N=1000000 A=1024 B=512 K=8 W=0 H=0` | 1155153371, 1150354468, 1150134307 | 1.151880715333 s |
| `N=1000000 A=1024 B=8 K=8 W=0 H=0` | 1152286810, 1150308349, 1155347904 | 1.152647687667 s |

All nine ACK samples report `reopen_verified=true`. The fixture uses explicit benchmark limits; exact `context_limits` remain in the raw records. These local storage measurements do not claim to exercise deployed terminal transport or body-size limits.

The interrupted fourth preparation profile, verify-claim, adjudication, sign-vote, certificate verification, dense `N=A=1000000` ACK, and `W=1000000` full-exit ACK have no published timing row.

## Host, storage, and production geometry

Measurements ran serially on an AWS c8a.4xlarge with 16 AMD EPYC 9R45 vCPUs, 32 GiB RAM, Ubuntu 24.04.4, and rustc 1.98.1. The ext4 volume was a 160 GiB gp3 device provisioned for 6,000 IOPS and 250 MiB/s.

The ACK records retain the actual storage geometry: 128 activity/payout log operations per section, 1,024 log Merkle nodes per blob, 4,096 Current operations per blob, 4,096 Current Merkle nodes per blob, 1,024-byte native pages, 16 pages in each of three native caches (state, the two logs together, and the private checkpoint), and 2,048-byte log and private I/O buffers. They used one adaptive 16-worker Rayon pool, two Tokio I/O workers, and three concurrent public stores.

## Provenance and retained evidence

The measured binaries came from HEAD `1bd5f46162be55ed5858a63adf3e20d78814dc5f` and compiled-source fingerprint `4b0e3134888282c902cfe319107e7233fb7d1bd35a42dcc53058e8ddddd7c7ca` over 1,668 files. Binary SHA-256 values are:

- Criterion: `d4eab40b648c34030baae562f183c6de44a49a32b97820425f44e002e3ee97b7`
- durable ACK: `3007a1d67af28292d24e7c292f1f1ce1a3594e6879cc7abf4d76fdf5d9b91144`

The final setup-only `prepare.rs` source has SHA-256 `ccf5b4c843b5cb8e901faf0caddb82f20f9664112cb24aff399ddff43c9c01b4` and landed after these binaries were built. `manifest.json` binds every published artifact and each ACK raw file by SHA-256. Full command directories, telemetry, incomplete attempts, source snapshots, and copied binaries remain in the local session scratchpad paths recorded there.
