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
untimed. Payout measurements use native keyless MMR Append and Commit encodings,
including bootstrap and epoch Commit gaps. They cover 0, 1, and N new outputs
after 0, 1,024, and 65,536 historical outputs. Empty epochs report their Commit
proof separately; Commit positions are never withdrawal claims. Payer-vector
proofs retain the BMT format. Select one profile and one group per process.

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
also applies Current and both native logs. The `native-transition` selector below isolates native preparation, application, and commit. These independently sampled
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

`receive-apply` advances consecutive epochs in one native Replica containing Current and both logs.
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
100-validator SHA-256 fixture. The encoded RootBundle is 176 bytes; its withdrawal total adds 8 bytes.
These 184 descriptor bytes are separate from the operator dealing, before chain
transaction framing. The original `sizes` group constructs native `W=1` and `W=N` claim fixtures.
The `native-transition` group executes signed Close withdrawals through actual
balance deletion and payout append, including a full `W=N` exit. Complete Current openings
and known-key lookups use separate encodings.

## Archived measurements

The [September 11 archive](results/2026-09-11/README.md) compares pinned QMDB and
sliced-reference revisions on a c8a.4xlarge. It retains phase medians, filesystem
runs, proof sizes, samples, and reproduction inputs. Those historical harnesses
have different timer boundaries, including a predecoded reference slice-seal
phase. Use the current harness above to measure later revisions.

## Independent native history and epoch sweeps

Six explicit selectors avoid the unrelated calculator-parity corpus:

| Selector | Output or timed work |
| --- | --- |
| `native-sizes` | Encoded activity lookups and payout artifacts; verifies every fixture. |
| `native-proofs` | Criterion verification latency on those decoded, already constructed artifacts. |
| `native-source-sizes` | Actual signed-close metadata and full SourceProof sizes, current and refreshed. |
| `native-source-proofs` | Source verification and source plus account/claim verification. |
| `native-transition-check` | Encoded dealing/descriptor sizes and native operation counts; checks two transitions with rewind between them. |
| `native-transition` | Criterion native prepare, decode, validate+prepare, apply, memory commit, and complete encoded-dealing pipeline phases. |

Dimensions are comma-separated integer lists, independent of the original
`COMMONWARE_CLEARING_PROFILE` selector:

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `COMMONWARE_CLEARING_HISTORY` | `0,1024,65536` | Prior activity rows or prior payout outputs, excluding Commit markers. |
| `COMMONWARE_CLEARING_ROWS` | `0,1,2,128,1024` | Current activity rows for proof sweeps; self-payment rows for transition sweeps. |
| `COMMONWARE_CLEARING_ACCOUNTS` | `1024` | One live account count, and the full-exit output count. |
| `COMMONWARE_CLEARING_PAYOUTS` | `0,1,N/2,N` | Current payout output count, at most N. |

Proof workloads sweep H x R and H x W separately. Activity cases include
zero-net presence, adjacent interior absence, left/right edge absence, and an
empty range. Absence proves one epoch's range, even when the account appears in
prior history. Payout cases include first/middle/last new outputs, an old
historical output at its old and current heads, and an issued output refreshed
after later appends and a signed floor advance. The latter retains retained native rows
and Merkle nodes; it does not claim that a pruned validator can serve old proofs.
W=0 measures the native Commit proof, not a payout claim. The proof fixture's
H outputs/rows occupy one prior epoch when H is nonzero. Native operation counts
and floors are printed explicitly.


Transition history consists of valid zero-net self-payment closes, up to N rows
per epoch. The measured close has R self-payers and W signed full-exit requests
from the same key prefix, so `payment_rows=R` and `activity_rows=max(R,W)` are
reported separately and checked against the certified range. W=N removes every
balance. H excludes the historical Commit markers; the output includes the
history epoch count and all three predecessor/successor operation counts.
`context_bytes`, `source_metadata_bytes`, verified `source_proof_bytes`, and `payout_commit_bytes` report their actual encodings separately
from operator dealing bytes and the 184-byte roots/withdrawal-total descriptor.

`native-transition` restores a fixed predecessor through native rewind between
iterations; fixture construction, signing, cloning native prepare inputs, and
rewind are outside timers. `native_prepare_state_logs` starts with already
derived mutations, exact activity Guards and metadata, and payout outputs. `validate_prepare_state_logs` starts with a
decoded dealing and includes cryptographic validation and all native batches.
`decode_validate_apply` starts with complete encoded dealing bytes and ends after
all three stores apply. Its `_commit_memory` counterpart also calls native
Replica::commit. Individual phase groups overlap the complete pipeline and must
not be summed as independently sampled data. No vote, chain admission, SQL,
network transfer, application evidence persistence, or SSD I/O is measured.
Commit uses the deterministic runtime's in-memory storage, including native
journal processing; it is not a durable SSD measurement.

Small correctness sweep (no timing statistics):

```sh
COMMONWARE_CLEARING_ACCOUNTS=8 COMMONWARE_CLEARING_HISTORY=0,8 \
COMMONWARE_CLEARING_ROWS=0,1,2,4 COMMONWARE_CLEARING_PAYOUTS=0,1,4,8 \
COMMONWARE_CLEARING_BENCH=native-sizes \
  cargo bench -p commonware-clearing --features bench --bench bajillion -- --test
```

Use `native-transition-check` to check the complete pipeline, or select
`native-proofs` / `native-transition` with `-- --test` to exercise their Criterion
entry points once. Omit `--test` only when collecting timings on the intended
host. Proof groups default to 20 Criterion samples and transition groups to 10;
Criterion CLI options can override this. Preserve raw Criterion estimates and
host/build metadata with publication results. Sizes are exact encoder outputs;
no large-workload runtime capacity claim follows from size arithmetic alone.

## Native source custody

`native-source-sizes` uses the signed transition workload to encode and verify
`SourceProof` separately from compact account lookups and payout claims. It
measures the current source and the same source refreshed after another empty
close advances both native floors. `source_metadata_bytes` is the original
context, terminal sequences, outgoing leaves, and signed withdrawals inside the
activity Commit. `source_proof_bytes` includes that complete byte frame, its
length prefix, and the native Commit opening. `source_plus_claim_bytes` is the
sum of that frame and the payout claim; it excludes transaction envelopes.
The original operator dealing does not contain this source-proof frame.

`native-source-proofs` times source authentication alone and source authentication
plus the account lookup and optional payout claim. Sources and proofs are built
outside the timers; each timed source verification decodes and authenticates the
full metadata. Both selectors use the same N/H/payment-row/W dimensions as
`native-transition`, including its history of one or more signed epochs.

The raw `native-proofs` and `native-sizes` fixtures use empty opaque activity
metadata to isolate compact Guard and payout proof encodings. Their H>0 history
is one prior native batch. They do not represent complete source proofs. All
reported operation counts include the bootstrap and epoch Commit markers.
Activity records are variable Guard or Metadata records; payout Appends contain
WithdrawalOutput directly and payout Commits carry no metadata.

The executable source workload currently limits each metadata frame to 16 MiB
through the native journal codec configuration. Larger proposed profiles must
respect that bound; the small smoke matrix is not evidence of their capacity.
