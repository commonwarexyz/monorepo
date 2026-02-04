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

Override the seed via environment variable:
```bash
FUZZ_SEED=42 cargo test -p commonware-consensus-fuzz test_
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

### Debugging

For verbose output:
```bash
RUST_BACKTRACE=1 FUZZ_SEED=42 cargo test -p commonware-consensus-fuzz test_name -- --show-output
```
