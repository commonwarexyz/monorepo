# Bajillion benchmarks

Each process uses 100 validators and one adaptive strategy with 16 workers. Default profiles are dense N=1024/K=1, sparse N=1024 with 128 senders/K=8, and zero-net N=512/K=1. `RUSTFLAGS='--cfg full_bench'` selects 14 profiles: dense N=1024/10k/100k/1M and sparse N=1M with 1024/10k/100k senders, each K1/K8. The recipient pool is 512 accounts; a small sender set may touch fewer recipients. `COMMONWARE_CLEARING_PROFILE` accepts a profile index or the printed `N=... A=... B=... K=...` label.

Build and run a local correctness smoke:

```sh
cargo bench -p commonware-clearing --features bench --bench bajillion --no-run
COMMONWARE_CLEARING_PROFILE=0 COMMONWARE_CLEARING_BENCH=receive-apply \
  cargo bench -p commonware-clearing --features bench --bench bajillion -- --test
COMMONWARE_CLEARING_PROFILE=0 COMMONWARE_CLEARING_BENCH=sizes \
  cargo bench -p commonware-clearing --features bench --bench bajillion
```

Select `verify-ack`, `assemble-certificate`, `verify-certificate`, `verify-claim`, `adjudicate`, or `settlement` for receipt/authorization, certificate and acceptance checks. Add `-- --test` to exercise a Criterion group without a measurement run. `sizes` is untimed encoded-artifact verification. Sizes come from actual Rust encodings; the compiled activity/output BMT wrappers determine their wire lengths.

`challenge-sizes` runs the same real close preparation and validation, packet/receipt checks, and complete challenge artifacts, plus a standalone external-payout proof tree. It skips withdrawal-output trees, Current application/historical queries, and calculator cases. This explicit selector is not included again in the default suite. The payout proof object excludes its finalized-batch identifier and transaction framing; its tree fixture does not measure a full external-payout transition.

`state-sizes` checks complete Current exclusion encodings across native bootstrap, empty genesis, funding, deletion of all accounts, native reopen, and an earlier empty root. It verifies zero liability uses absent CommitFloor metadata and binds historical requests to the retained root and operation count. This selector is untimed.

| Group | Measured work |
|---|---|
| initialize | Canonical genesis construction in one Current database; key generation excluded |
| prepare | Clone frozen terminal inputs, derive activity/balances/output trees, merkleize a real batch and encode the shared dealing; no application |
| fanout | Clone already encoded Bytes for 100 recipient packet references; no encoding or transport |
| decode | Bounded dealing decode, including strict key decoding |
| validate-close | Predecoded dealing through full relation/signature validation and PreparedClose; no signing/application |
| seal | Owned encoded dealing through decode, validation and vote; no application |
| sign-vote | Sign an already prepared header; no decode, relation validation or application |
| prepare-apply | Preparation, encoding, 100 packet references and actual Current database advancement |
| receive-apply | Owned encoded dealing through decode, validation, vote and actual Current database advancement |
| verify-ack | Existing receipt/authorization verification plus encoded receipt decode-and-verify |
| verify-claim | Amount/close output claims at W=1/W=N and Current account-opening verification |
| adjudicate | Bounded encoded challenge decode and adjudication |
| settlement | Actual queue, admission, finalization and hard-fault operations with QMDB state proofs |

Fixtures open native state, prepare canonical genesis from the configured accounts, and apply it once. `State::open` recovers the head from native root, operation count, liability metadata and active-key count; the application wrapper does not rescan already-applied history. The advancement groups process consecutive epochs against that database per Criterion batch. They regenerate only terminal signatures/context between closes, and retain the live database. `receive-apply` prepares the operator's encoded packet outside its timer. Each sequence retains the first accepted root and native operation count, then checks historical proof availability after later advancement, outside elapsed capture. Setup never rebuilds all live accounts between closes. A zero-net close has no logical balance writes but still applies a canonical batch; QMDB maintenance may append additional operations. Sample sequences retain unpruned history, so these timings are not repeated measurements of one identical predecessor state.

The deterministic runtime supplies in-memory storage. The `bench` feature enables `commonware-runtime/external` for the real 16-worker Rayon pool. The benchmark target requires this opt-in; ordinary crate tests keep their existing runtime features. The benchmark runner uses the minimum supported cycle (`SYSTEM_TIME_PRECISION`, 1 ns). The external executor sleeps between polls; observed scheduling overhead remains part of elapsed time and must match the reference runtime when comparing paths. Journal commit/sync, application evidence persistence, transport and transaction framing are excluded. Historical view reconstruction and proof generation are separate from head advancement. Historical queries build an ephemeral native view from retained operations and can scale with the target active operation window; that work belongs entirely in the query measurement. `seal` includes decode in this implementation and cannot be compared as though it were the older predecoded slice-seal benchmark. Do not infer isolated costs by subtracting these different paths.

The 101-byte encoded header-plus-certificate remains a certified commitment, not complete settlement admission. Output-claim fixtures at W1/WN are proof verification/size cases, not measured WN withdrawal transitions. Complete Current account openings, known-key lookups and proof components are labeled separately. Calculator parity samples use actual production dealing encoding for the declared graph/key-placement scenario.

Published latency requires a designated quiet external machine after builds/tests stop, with the same compiler and configuration for both variants. Local runs provide correctness and encoded-size evidence only.
