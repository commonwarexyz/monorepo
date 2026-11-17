# commonware-consensus-fuzz

This is a fuzzer for the `commonware-consensus` crate protocols and data structures,
designed to test protocol correctness under adversarial conditions.

## Data Structures Fuzzing

Implemented using `cargo-fuzz`. The following fuzz targets are available:
- `simplex_elector`
- `simplex_messages`
- `attributable_map`

## Simplex Fuzzing

### Architecture

The fuzzer operates by simulating a Byzantine environment:

1. **Correct Nodes**: Multiple correct nodes that follow the protocol correctly
2. **Byzantine Node (Disrupter)**: A single malicious node that attempts to disrupt consensus

The Byzantine node is called "Disrupter" because, rather than implementing sophisticated attack strategies,
it exposes mutation-based adversarial behaviors that can be used to test the protocol's resilience:
- Mutates received messages from correct nodes
- Generates new messages based on information extracted from legitimate protocol messages
- Sends malformed or malicious messages back to the network

The test execution continues until the correct nodes successfully produce the target number of blocks,
if possible in the current configuration, demonstrating the protocol's resilience.

### Invariant Checking

After test completion, the framework verifies that all invariants defined
in the `invariants` [module](./src/invariants.rs) hold true for correct nodes at each view.
This ensures protocol safety properties are maintained despite a byzantine node.

### Running Tests

#### Unit Tests

Run deterministic tests with a fixed seed:
```bash
cargo test -p commonware-consensus-fuzz test_
```

#### Property-Based Tests

Run proptest-based tests that explore many seeds:
```bash
cargo test -p commonware-consensus-fuzz property_test
```

Reproduce a failure with a specific seed:
```bash
PROPTEST_CASES=1 PROPTEST_SEED=<seed> cargo test -p commonware-consensus-fuzz property_test_ed25519 -- --nocapture
```

#### Continuous Fuzzing

Run continuous fuzzing for a specific target:
```bash
cargo fuzz run simplex_ed25519
```

Available fuzz targets (standard mode):
- `simplex_ed25519`
- `simplex_secp256r1`
- `simplex_bls12381_multisig_minpk`
- `simplex_bls12381_multisig_minsig`
- `simplex_bls12381_threshold_minpk`
- `simplex_bls12381_threshold_minsig`

Available fuzz targets (twin mode with mutating adversary):
- `simplex_ed25519_twin`
- `simplex_secp256r1_twin`
- `simplex_bls12381_multisig_minpk_twin`
- `simplex_bls12381_multisig_minsig_twin`
- `simplex_bls12381_threshold_minpk_twin`
- `simplex_bls12381_threshold_minsig_twin`

Reproduce a failure from a crash file:
```bash
cargo fuzz run simplex_ed25519 artifacts/simplex_ed25519/<crash_file>
```

## Multimmit Fuzzing

Multimmit campaigns exercise protocol histories, recovery, and adversarial certificates. Inputs
bound the work of each execution; longer campaigns explore more executions rather than allowing
one schedule to grow without limit.

- `multimmit_machine` drives the real synchronous machine with a bounded three-replica action
  schedule. Inputs cover observation and verification ordering, malformed completions, persistence
  acknowledgement and crash cuts, timers, application work, resolver results, aggregation,
  signing, publication delivery, and typed-obligation discharge. The interpreter checks journal
  replay, output safety, signature exposure, publication lifetime, resource bounds, and historical
  convergence after every applicable action. The input layout and the four-byte opcode table live
  on `exercise` and `World::apply_encoded` in
  [`machine/testing/world/fuzz.rs`](../src/multimmit/machine/testing/world/fuzz.rs).
- `multimmit_twins` runs independent engines with shared Byzantine identities. Randomized
  partitions and delivery schedules exercise equivocation and selective disclosure. Agreement
  checks compare honest finalization evidence; a fair suffix requires progress on honest producer
  chains. Twin processes count as one committee identity, not additional voting weight.
- `multimmit_artifacts` builds signed certificate transcripts across linked views, then changes
  their attribution, context, and support. An independent oracle checks acceptance, and real
  cryptographic verification must agree with and without cached constituent messages.
- `multimmit_algebra` grows attributed vote pools across multiple leader proposals. Materialized
  ancestry and support counts independently check safe tips, incremental finality, and settledness.
- `multimmit_marshal` compares multi-chain sweeps with an explicitly enumerated sequence. Partial
  iteration, replay, and successive history openings must preserve the dense output sequence and
  reject conflicting reconciliation references. This is an ordering-state campaign, not a test of
  physical storage failures or the delivery actor's durable acknowledgement implementation.
- `multimmit_wire` decodes each network plane under protocol bounds and requires accepted frames
  to re-encode canonically. This malformed-byte coverage complements structured signed inputs.
- `multimmit_engine_minpk` and `multimmit_engine_minsig` share one byte-driven harness over six
  production engines. At most sixteen actions schedule bounded reloads and persistent,
  independently healable simulated-network faults around a committee-wide same-storage reopen.
  Recovery can also be interrupted while application custody verification is pending. A
  final lossless suffix requires every engine and producer chain to advance while an independent
  reporter oracle checks exact finality compatibility, stable signing subjects, observed
  certificate-share quorums, and configured state ceilings. Each campaign has a deterministic
  one-minute runtime deadline.

Run all consensus targets through the existing CI entry point:

```bash
just fuzz consensus/fuzz 60
```

For a longer campaign, select a target and keep its corpus between runs:

```bash
cargo +nightly fuzz run multimmit_twins --fuzz-dir consensus/fuzz -- -max_total_time=3600
```

Replay saved failures with the same target and input file. Short CI runs and long campaigns use
the same oracles. Deterministic tests also exercise representative schedules and check selected
oracles against deliberately inconsistent evidence.

Progress assertions apply only after the harness restores fair communication and the required
application service. Safety checks apply during the adversarial prefix as well. Symbolic machine
journal cuts check exact replay and persist-before-expose; engine restarts exercise real stores.
Neither `multimmit_machine` nor the `multimmit_engine_*` campaigns model arbitrary torn disk writes
outside the storage contract.
