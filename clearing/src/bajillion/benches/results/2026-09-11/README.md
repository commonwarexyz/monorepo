# Bajillion benchmark results

Host: `designated-c8a.4xlarge` (AMD EPYC 9R45); toolchain: `rustc 1.98.1 (48a229cea 2026-09-01)`. Reference: `3a3b934662d1`. QMDB: `b93fed3ae2ad` plus `final-candidate.patch`. Full source, patch and binary hashes are in manifest.json.

N is the number of live accounts, A the number of senders, R the recipient pool size, and K the recipients per sender. W counts signed withdrawals in the disk sensitivity runs.

The tables report direct sample medians. Paired memory runs use 16 Rayon workers and 100 validators on this host. Workload keys, opening balances and transfer graph match; native validation contracts differ. Raw samples, warmups, logical oracles, Criterion iterations/times/estimates and byte joins are retained in samples.jsonl.gz.

Prepare/apply starts from signed terminal inputs and includes reference transpose/row/prefix derivation, native preparation and encoding, and reusable successor state; sender signature material and maintained reference checksum partials are outside timing.

Receive means encoded bytes through validation, vote and applied state for one validator: the reference selects and fixes the validator with the largest encoded dealing, while every QMDB validator receives the same packet. These are individual receiver timings, not mean validator latency or aggregate committee work. Memory runs exclude durability. Candidate validation includes native balance reads and root preparation; reference resident expansion is separate. Candidate validation and vote are nested within verify-and-vote: do not add overlapping rows or infer components by subtraction.

Filesystem rows additionally include native QMDB commit, excluding accepted-close/evidence journals, SQL, network and publication. They use aligned 4096-byte physical pages and a 4 MiB native cache. First-touch clears the actual native page cache after reopen; OS cache and native tails remain uncontrolled. Whole-receive Blob requested reads are not device reads or per-phase I/O costs.

The initial one-sample preflight is diagnostic only and is excluded from these tables.

| N | A | R | K | Operation | Reference ms | QMDB ms |
|---:|---:|---:|---:|---|---:|---:|
| 1024 | 1024 | 512 | 1 | prepare-apply | 6.050459 | 5.401967 |
| 1024 | 1024 | 512 | 1 | receive-phases | 136.895978 | 63.639953 |
| 1024 | 1024 | 512 | 8 | prepare-apply | 8.651694 | 9.462079 |
| 1024 | 1024 | 512 | 8 | receive-phases | 772.461875 | 66.022468 |
| 10000 | 10000 | 512 | 1 | prepare-apply | 25.849242 | 30.176387 |
| 10000 | 10000 | 512 | 1 | receive-phases | 962.700617 | 582.664896 |
| 100000 | 100000 | 512 | 1 | prepare-apply | 274.793398 | 325.796547 |
| 100000 | 100000 | 512 | 1 | receive-phases | 9162.362071 | 5810.221234 |
| 1000000 | 1024 | 8 | 8 | prepare-apply | 291.028530 | 7.414424 |
| 1000000 | 1024 | 8 | 8 | receive-phases | 977.811788 | 64.971489 |
| 1000000 | 1024 | 512 | 1 | prepare-apply | 291.890838 | 5.661363 |
| 1000000 | 1024 | 512 | 1 | receive-phases | 229.234454 | 64.490745 |
| 1000000 | 1024 | 512 | 8 | prepare-apply | 292.068637 | 7.562782 |
| 1000000 | 1024 | 512 | 8 | receive-phases | 1003.890266 | 66.762533 |
| 1000000 | 1000000 | 512 | 1 | prepare-apply | 2760.074137 | 4043.225399 |
| 1000000 | 1000000 | 512 | 1 | receive-phases | 91166.410276 | 58851.922733 |

| Candidate N | A | R | K | Decode ms | Validate ms | Vote ms | Apply ms | Receive ms |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1024 | 1024 | 512 | 1 | 54.543528 | 8.342631 | 0.101421 | 0.225383 | 63.639953 |
| 1024 | 1024 | 512 | 8 | 55.032395 | 10.399425 | 0.099136 | 0.239393 | 66.022468 |
| 10000 | 10000 | 512 | 1 | 531.343782 | 46.476191 | 0.103552 | 2.096856 | 582.664896 |
| 100000 | 100000 | 512 | 1 | 5321.339695 | 467.933679 | 0.098391 | 20.596316 | 5810.221234 |
| 1000000 | 1024 | 8 | 8 | 54.040053 | 10.331668 | 0.097456 | 0.271564 | 64.971489 |
| 1000000 | 1024 | 512 | 1 | 55.009732 | 8.821586 | 0.098486 | 0.279409 | 64.490745 |
| 1000000 | 1024 | 512 | 8 | 55.186360 | 10.894749 | 0.100476 | 0.294368 | 66.762533 |
| 1000000 | 1000000 | 512 | 1 | 53305.730969 | 5281.599436 | 0.104961 | 266.230627 | 58851.922733 |

Phase medians are summarized independently and need not add to the total median. The nested verify-and-vote row remains in results.json.

| Disk N | A | W | Condition | Receive through QMDB commit ms | Commit ms |
|---:|---:|---:|---|---:|---:|
| 64 | 64 | 4 | disk-receive-first-touch | 8.139416 | 2.914300 |
| 64 | 64 | 4 | disk-receive-steady | 8.104646 | 2.965315 |
| 10000 | 10000 | 0 | disk-receive-first-touch | 704.211566 | 78.012601 |
| 10000 | 10000 | 0 | disk-receive-steady | 700.414719 | 77.074221 |
| 1000000 | 1024 | 0 | disk-receive-first-touch | 76.254889 | 7.246871 |
| 1000000 | 1024 | 0 | disk-receive-steady | 74.946969 | 7.303511 |

Full phase, artifact and disk medians with exact operation labels and encoded bytes are in results.json. Source and binary identities are in manifest.json.

## Reproduce

Extract reproduction.tar.gz. Obtain disposable exports of the pinned commits recorded in manifest.json, verify their archive hashes, and apply final-candidate.patch to the candidate. With the recorded Rust toolchain, run:

```sh
python3 build.py --reference ../reference --candidate ../qmdb --candidate-patch final-candidate.patch --jobs 8
python3 run.py --phase receive-essential --output results/receive-essential --external-host YOUR_QUIET_HOST --execute
```

Repeat the recorded phases prepare-essential, artifacts and certificate. For disk and disk-withdrawals, also pass --disk-root with a fresh real-filesystem directory. Stop builds before timing. Each phase manifest retains the exact arguments and complete task inventory. The reproduction archive contains measured custom Rust/Python sources and the candidate patch; native exports and binaries are identified by hash rather than duplicated here. The diagnostic preflight used earlier binaries, whose identities remain separate. RUNNER-CHANGE.json and runner-only.patch preserve the original harness identity and the direct Criterion --bench invocation correction; completed preparation/receive binaries and data are unchanged.
