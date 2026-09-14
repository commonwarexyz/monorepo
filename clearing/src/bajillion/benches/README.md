# Bajillion benchmarks

Measure close construction, validator processing, and proof verification. Each
run uses 100 validators and an adaptive 16-worker Rayon pool.

## Run a small profile

From the repository root:

```sh
COMMONWARE_CLEARING_PROFILE=0 COMMONWARE_CLEARING_BENCH=receive-apply \
  cargo bench -p commonware-clearing --features bench --bench bajillion -- --test
COMMONWARE_CLEARING_PROFILE=0 COMMONWARE_CLEARING_BENCH=sizes \
  cargo bench -p commonware-clearing --features bench --bench bajillion
```

`-- --test` runs a Criterion group in test mode without collecting timings. Omit it
for a measurement run. `sizes` verifies actual encoded artifacts and is untimed.
Select one profile and one group per process.

## Choose a workload

Profile labels use `N` for live accounts, `A` for senders, `B` for the recipient
pool, and `K` for recipients per sender. There are `A * K` directed payment pairs.
A small sender set may touch fewer than `B` recipients.

| Default profile | N | A | B | K |
| --- | ---: | ---: | ---: | ---: |
| `0`: dense | 1,024 | 1,024 | 512 | 1 |
| `1`: sparse | 1,024 | 128 | 512 | 8 |
| `2`: zero-net balances | 512 | 512 | 512 | 1 |

`COMMONWARE_CLEARING_PROFILE` accepts an index or an exact printed label such as
`N=1024 A=1024 B=512 K=1`. With `RUSTFLAGS='--cfg full_bench'`, the 14 profiles are:

- Dense: 1,024, 10,000, 100,000, or 1,000,000 live accounts, all sending.
- Sparse: 1,000,000 live accounts with 1,024, 10,000, or 100,000 senders.

Each runs with `K=1` and `K=8`, over a 512-account recipient pool. See
[the fixtures](fixtures.rs) for the full index order.

## What the timers include

```text
  OPERATOR
  frozen inputs --> prepare --> fanout --> apply
  [--------------- prepare-apply --------------]

  VALIDATOR
  dealing --> decode --> validate-close --> sign-vote --> apply
  [---------------------- seal --------------------]
  [---------------------- receive-apply ---------------------]
```

`prepare` includes encoding the dealing. `fanout` creates 100 references to the
same encoded `Bytes`; it performs no network transfer. `validate-close` starts
from decoded inputs and includes balance reads, signature checks, and root
preparation. `seal` adds decoding and a vote. `apply` advances QMDB and is included
in the two enclosing `*-apply` groups, not exposed as a separate selector.

The phase groups are independent measurements. Do not subtract one from another
to infer an isolated cost, or compare this encoded-input `seal` directly with the
older reference's predecoded slice-seal timer.

Additional selectors for `COMMONWARE_CLEARING_BENCH`:

| Group | Work |
| --- | --- |
| `initialize` | Build canonical genesis; exclude key generation. |
| `sign-vote` | Sign an already prepared header. |
| `assemble-certificate` / `verify-certificate` | Assemble or check an exact-quorum certificate. |
| `verify-ack` | Verify authorizations and receipts, including receipt decode-and-verify. |
| `verify-claim` | Verify withdrawal claims and Current account openings. |
| `adjudicate` | Decode and adjudicate a bounded challenge. |
| `settlement` | Admission, queue, finalization, and hard-fault operations. |
| `sizes` | Check encoded dealings, receipts, certificates, claims, state proofs, and calculator parity. |
| `challenge-sizes` | Check close and challenge artifacts, skipping withdrawal trees, state history, and calculator cases. |
| `state-sizes` | Check Current exclusion encodings across bootstrap, funding, deletion, reopen, and historical roots. |

The last three are untimed. `challenge-sizes` and `state-sizes` run only when
selected explicitly.

## State and measurement scope

Fixtures initialize one native Current database. The `*-apply` groups advance
consecutive epochs against it, regenerating terminal signatures outside the
timer. They do not rebuild all live accounts between closes. Zero-net activity
still applies a canonical batch; QMDB maintenance can append operations even
when no balance changes. History remains unpruned, so each epoch has a different
predecessor state.

After advancement, the harness checks a historical proof without including that
query in the timer. Historical view reconstruction can scale with the retained
operation window and should be measured separately.

Storage is in memory under the deterministic runtime. The `bench` feature enables
real Rayon workers, and executor polling uses the minimum supported 1 ns cycle.
Elapsed time includes scheduling overhead. Journal commit/sync, application
evidence persistence, SQL, transport, and transaction framing are excluded.
Publication runs need a quiet external machine and matched compiler, runtime,
and workload settings for both variants; local runs check correctness and sizes.

Report complete artifacts: in the 100-validator SHA-256 fixture, Header plus
certificate is 101 bytes. The three roots and withdrawal total add 104 bytes;
chain transaction framing is additional. `W=1` and `W=N` claim fixtures measure
proofs, not full `W=N` withdrawal transitions. Complete Current openings and
known-key lookups have separate encodings.

## Archived measurements

The [September 11 archive](results/2026-09-11/README.md) compares the pinned QMDB
and sliced-reference revisions on one c8a.4xlarge. It includes phase medians,
filesystem commit runs, proof sizes, samples, and reproduction inputs. Its
[manifest](results/2026-09-11/manifest.json) identifies the measured sources and
hashes the archived files, including that README. Use the current harness above
to measure later revisions.
