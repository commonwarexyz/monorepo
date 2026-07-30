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
- `simplex_id`
- `simplex_cert_mock`
- `simplex_bls12381_multisig_minpk`
- `simplex_bls12381_threshold_minsig`

Available fuzz targets (faulty messaging):
- `simplex_id_faulty_msg`
- `simplex_cert_mock_faulty_msg`

Available fuzz targets (faulty network):
- `simplex_id_faulty_net`
- `simplex_cert_mock_faulty_net`

Available fuzz targets (twins mutator):
- `simplex_ed25519_shuffled_twins_mutator`
- `simplex_id_twins_mutator`
- `simplex_cert_mock_twins_mutator`

Available fuzz targets (twins campaign):
- `simplex_id_twins_campaign`
- `simplex_cert_mock_twins_campaign`

Available fuzz targets (node driver):
- `simplex_id_node`
- `simplex_id_node_recovery`
- `simplex_id_node_recovery_stable_term`
- `simplex_cert_mock_node`
- `simplex_cert_mock_node_recovery`

Available fuzz targets (ByzzFuzz):
- `simplex_id_byzzfuzz`
- `simplex_cert_mock_byzzfuzz`

Reproduce a failure from a crash file:
```bash
cargo fuzz run simplex_ed25519 fuzz/artifacts/simplex_ed25519/<crash_file>
```

## Marshal Fuzzing

The standard-wrapper targets exercise proposal, verification, certification,
broadcast, and application-result transitions using structured libFuzzer input:

```bash
cargo fuzz run marshal_actor_standard_inline_cert_mock
cargo fuzz run marshal_actor_standard_deferred_cert_mock
cargo fuzz run marshal_e2e_standard_app_cert_mock_twins
cargo fuzz run marshal_e2e_standard_deferred_id_twins_split_header
cargo fuzz run marshal_e2e_standard_inline_id_twins_split_header
```

The inline and deferred targets include split-header equivocation in their
action space. The multi-node targets are Byzantine Twins mutators over the
end-to-end standard stack. The general Twins target shares one corpus across
the Basic and Faulty applications with both Inline and Deferred wrappers.
Three honest validators each run
`Simplex -> Inline|Deferred -> Marshal -> Application`; the compromised
identity runs one full Simplex engine over the same real marshal/application
data plane and the existing `Disrupter` on its secondary half. The `Disrupter`
can preserve an observed payload digest while mutating its proposal header.

The shared fuzz-layer Twins helpers sample leaders and recipient partitions for
an adversarial prefix, then restore full synchrony. The target checks that every
honest marshal makes post-prefix progress, preserves in-order delivery, and
agrees on every delivered height. It also passively observes each honest
marshal wrapper and asserts that certification never reuses a rejection caused
by verifying the same `(round, digest)` under a different header context.

The Marshal Twins observation wrappers forward automaton completions through
spawned tasks. Changes to that forwarding can alter deterministic scheduling,
so saved artifacts from these targets must be re-triaged against the new
execution before a non-reproduction is classified as fixed.
