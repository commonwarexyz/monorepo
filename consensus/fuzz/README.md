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
cargo fuzz run simplex_cert_mock
```

Available fuzz targets (standard mode):
- `simplex_cert_mock`
- `simplex_cert_mock_audit_notarize_omission`

Available fuzz targets (faulty network):
- `simplex_cert_mock_faulty_net`

Available fuzz targets (twins mutator):
- `simplex_cert_mock_twins_mutator`
- `simplex_cert_mock_shuffled_twins_mutator`

Available fuzz targets (twins campaign):
- `simplex_cert_mock_twins_campaign`

Available fuzz targets (node driver):
- `simplex_cert_mock_node`
- `simplex_cert_mock_node_recovery`
- `simplex_cert_mock_node_recovery_stable_term`

Available fuzz targets (ByzzFuzz):
- `simplex_cert_mock_byzzfuzz`

Reproduce a failure from a crash file:
```bash
cargo fuzz run simplex_cert_mock fuzz/artifacts/simplex_cert_mock/<crash_file>
```

## Marshal Fuzzing

The marshal end-to-end targets exercise proposal, verification, certification,
broadcast, and application-result transitions through real Simplex stacks:

```bash
cargo fuzz run marshal_e2e_standard_deferred_cert_mock_disrupter
cargo fuzz run marshal_e2e_coding_cert_mock_disrupter
cargo fuzz run marshal_e2e_standard_app_cert_mock_twins
cargo fuzz run marshal_e2e_coding_app_cert_mock_twins
cargo fuzz run marshal_e2e_standard_deferred_cert_mock_twins_split_header
cargo fuzz run marshal_e2e_standard_inline_cert_mock_twins_split_header
cargo fuzz run marshal_e2e_standard_deferred_cert_mock_poison
cargo fuzz run marshal_e2e_standard_deferred_cert_mock_scenarios
```

The disrupter targets check post-prefix liveness over the standard deferred and
coding marshal stacks. The Twins targets are Byzantine mutators over the
end-to-end standard and coding stacks, and the split-header variants include
proposal-header equivocation in their action space. The general Standard Twins
target shares one corpus across the Basic and Faulty applications with both
Inline and Deferred wrappers. The Coding Twins targets share the application
axis but use Coding's Marshaled adapter directly; Deferred and Inline do not
apply. The fuzz targets use `SimplexCertificateMock` to avoid repeating the
same harnesses across multiple mock schemes.
Three honest validators each run
`Simplex -> Inline|Deferred|Marshaled -> Marshal -> Application`; the
compromised identity runs one full Simplex engine over the same real
marshal/application data plane plus a Byzantine secondary. On Standard, the
secondary is the existing `Disrupter`, which can preserve an observed payload
digest while mutating its proposal header. Coding uses a Commitment-typed
secondary that signs both an observed proposal and a conflicting commitment
with the compromised identity's key.

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
