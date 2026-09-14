# Bajillion benchmark results: September 11, 2026

Archived measurements of the revisions below, using their recorded benchmark
harnesses. The [current benchmark guide](../../README.md) describes later code.

| Measurement input | Value |
| --- | --- |
| Host | `designated-c8a.4xlarge`, AMD EPYC 9R45 |
| Toolchain | `rustc 1.98.1 (48a229cea 2026-09-01)` |
| Sliced reference | `3a3b934662d1` |
| QMDB candidate | `b93fed3ae2ad` plus `final-candidate.patch` |
| Memory-run configuration | 16 Rayon workers, 100 validators |

[manifest.json](manifest.json) records full source, patch, binary, and archive
hashes. [samples.jsonl.gz](samples.jsonl.gz) retains samples, warmups, logical
oracles, Criterion iterations and estimates, and encoded byte joins.

`N` is live accounts, `A` senders, `R` recipient pool size, `K` recipients per
sender, and `W` signed withdrawals. Tables show direct sample medians and exclude
the diagnostic one-sample preflight.

## Memory timings

Both variants use matching keys, opening balances, and transfer graphs, with
their respective validation contracts.

- **Prepare/apply:** signed terminal inputs through preparation, encoding, and
  reusable successor state. Reference transpose/row/prefix derivation is timed;
  sender signature material and maintained reference checksum partials are not.
- **Receive:** encoded bytes through validation, vote, and applied state for one
  validator. The reference uses the validator with the largest encoded dealing;
  each QMDB validator receives the same packet.

Memory runs exclude durability.

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

## QMDB receive phases

Validation includes native balance reads and root preparation. The reference's
resident expansion is measured separately. Phase medians are independent and
need not sum to the receive median. [results.json](results.json) also retains the
nested verify-and-vote timer, which includes validation and voting.

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

## Filesystem timings

These runs extend receive through native QMDB commit. They exclude accepted-close
and evidence journals, SQL, network, and publication. Physical pages are aligned
to 4096 bytes, with a 4 MiB native cache.

First-touch clears the native page cache after reopen; OS cache and native tails
remain uncontrolled. Blob requested-read counters cover the whole receive and
measure logical requests, not device reads or per-phase I/O.

| Disk N | A | W | Condition | Receive through QMDB commit ms | Commit ms |
|---:|---:|---:|---|---:|---:|
| 64 | 64 | 4 | disk-receive-first-touch | 8.139416 | 2.914300 |
| 64 | 64 | 4 | disk-receive-steady | 8.104646 | 2.965315 |
| 10000 | 10000 | 0 | disk-receive-first-touch | 704.211566 | 78.012601 |
| 10000 | 10000 | 0 | disk-receive-steady | 700.414719 | 77.074221 |
| 1000000 | 1024 | 0 | disk-receive-first-touch | 76.254889 | 7.246871 |
| 1000000 | 1024 | 0 | disk-receive-steady | 74.946969 | 7.303511 |

[results.json](results.json) contains the full phase, artifact, and disk medians,
with exact operation labels and encoded sizes.

## Reproduce

Extract [reproduction.tar.gz](reproduction.tar.gz) and work from its directory.
Obtain disposable exports of the pinned commits in [manifest.json](manifest.json),
verify their archive hashes, and apply `final-candidate.patch` to the QMDB export.
With the recorded toolchain:

```sh
python3 build.py --reference ../reference --candidate ../qmdb --candidate-patch final-candidate.patch --jobs 8
python3 run.py --phase receive-essential --output results/receive-essential --external-host YOUR_QUIET_HOST --execute
```

Repeat for `prepare-essential`, `artifacts`, and `certificate`. For `disk` and
`disk-withdrawals`, also supply `--disk-root` with a fresh real-filesystem
directory. Stop builds before timing. Each phase manifest records its arguments
and task inventory.

The reproduction archive contains the custom Rust/Python harness and candidate
patch. Native source exports and binaries are identified by hash. Preflight
binary identities are recorded separately. The archive's `RUNNER-CHANGE.json`
and `runner-only.patch` document the direct Criterion `--bench` invocation
correction; completed preparation/receive binaries and samples are unchanged.
