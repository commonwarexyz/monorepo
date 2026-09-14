# Bajillion benchmarks

Measure close construction, validator processing, and proof verification with a
100-validator committee and an adaptive 16-worker Rayon pool.

## Run

From the repository root:

```sh
COMMONWARE_CLEARING_PROFILE=0 COMMONWARE_CLEARING_BENCH=receive-apply \
  cargo bench -p commonware-clearing --features bench --bench bajillion -- --test
COMMONWARE_CLEARING_PROFILE=0 COMMONWARE_CLEARING_BENCH=sizes \
  cargo bench -p commonware-clearing --features bench --bench bajillion
```

The first command checks a small profile without collecting timings. Omit
`-- --test` to measure it. The second checks encoded artifact sizes and is
untimed. Select one profile and one group per process.

## Workloads

`N` counts live accounts, `A` senders, `B` the recipient pool, and `K` recipients
per sender. There are `A * K` directed payment pairs; a small sender set may touch
fewer than `B` recipients.

| Default profile | N | A | B | K |
| --- | ---: | ---: | ---: | ---: |
| `0`: dense | 1,024 | 1,024 | 512 | 1 |
| `1`: sparse | 1,024 | 128 | 512 | 8 |
| `2`: zero-net balances | 512 | 512 | 512 | 1 |

`COMMONWARE_CLEARING_PROFILE` accepts an index or an exact label such as
`N=1024 A=1024 B=512 K=1`. With `RUSTFLAGS='--cfg full_bench'`, 14 profiles cover:

- Dense activity: 1,024, 10,000, 100,000, or 1,000,000 live accounts, all sending.
- Sparse activity: 1,000,000 live accounts with 1,024, 10,000, or 100,000 senders.

Each uses `K=1` or `K=8` and a 512-account recipient pool. See
[fixtures.rs](fixtures.rs) for the index order.

## Timed phases

```text
Operator:   signed activity --> prepare --> fanout

Validator:  dealing --> decode --> validate-close --> sign-vote --> apply
            [---------------------- seal --------------------]
            [---------------------- receive-apply ---------------------]
```

`prepare` assembles and encodes signed activity without reading QMDB. The
operator's proof-serving QMDB is separate from this timer. `fanout` creates 100
references to the same encoded `Bytes`, without network transfer.

`validate-close` starts from decoded inputs and includes balance reads, signature
checks, and root preparation. `seal` adds decoding and a vote. `receive-apply`
also advances QMDB; `apply` has no separate selector. These independently sampled
groups overlap and should not be added or subtracted to derive phase costs.

Other `COMMONWARE_CLEARING_BENCH` selectors:

| Group | Work |
| --- | --- |
| `initialize` | Build canonical genesis, excluding key generation. |
| `sign-vote` | Sign an already prepared header. |
| `assemble-certificate` / `verify-certificate` | Assemble or check an exact-quorum certificate. |
| `verify-ack` | Verify authorizations and receipts, including receipt decode-and-verify. |
| `verify-claim` | Verify withdrawal claims and Current account openings. |
| `adjudicate` | Decode and adjudicate a bounded challenge. |
| `settlement` | Admission, queue, finalization, and hard-fault operations. |
| `sizes` | Check encoded artifacts and calculator parity. |
| `challenge-sizes` | Check close and challenge artifacts, excluding withdrawal trees, state history, and calculator cases. |
| `state-sizes` | Check Current exclusion encodings through bootstrap, funding, deletion, reopen, and historical roots. |

The last three groups are untimed. `challenge-sizes` and `state-sizes` require
explicit selection.

## State and storage

`receive-apply` advances consecutive epochs in one native Current database.
Terminal signing and dealing encoding happen outside the timer; live accounts
are not rebuilt between closes. Even zero-net activity applies a canonical batch
and may append QMDB maintenance operations. History remains unpruned. A
historical proof is checked after advancement, outside the timer; reconstructing
that view can scale with the retained operation window.

Storage runs in memory under the deterministic runtime. The `bench` feature uses
real Rayon workers, with a 1 ns executor cycle; elapsed time includes scheduling.
The timers exclude journal commit/sync, application evidence persistence, SQL,
transport, and transaction framing. Use a quiet external host and matching
compiler, runtime, and workload settings for comparative measurements.

For size comparisons, a Header plus certificate is 101 bytes in this
100-validator SHA-256 fixture. Three roots and the withdrawal total add 104 bytes,
before chain transaction framing. `W=1` and `W=N` fixtures measure claim proofs;
they do not execute full `W=N` withdrawal transitions. Complete Current openings
and known-key lookups use separate encodings.

## Archived measurements

The [September 11 archive](results/2026-09-11/README.md) compares pinned QMDB and
sliced-reference revisions on a c8a.4xlarge. It retains phase medians, filesystem
runs, proof sizes, samples, and reproduction inputs. Those historical harnesses
have different timer boundaries, including a predecoded reference slice-seal
phase. Use the current harness above to measure later revisions.
