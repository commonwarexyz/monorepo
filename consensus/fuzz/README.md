# commonware-consensus fuzzing

Fuzzers for the `commonware-consensus` crate protocols and data structures,
designed to test protocol correctness under adversarial conditions.

## Layout

`consensus/fuzz/` is a plain directory. The fuzzers live in five packages under it:

| Package | Crate | Contents |
| ------- | ----- | -------- |
| [`core/`](./core) | `commonware-consensus-fuzz-core` | Shared harness library: simulated network, Disrupter, twins network, fuzz input types, and mutation strategies. Library only, no fuzz targets. |
| [`simplex/`](./simplex) | `commonware-consensus-fuzz-simplex` | Simplex consensus harnesses: mode dispatch, invariants, happens-before and state coverage, ByzzFuzz, Mallory, and chaos. |
| [`marshal/`](./marshal) | `commonware-consensus-fuzz-marshal` | Marshal store, end-to-end, and scenario harnesses. |
| [`structures/`](./structures) | `commonware-consensus-fuzz-structures` | Data-structure and message targets. Self-contained, no library. |
| [`aggregation/`](./aggregation) | `commonware-consensus-fuzz-aggregation` | Aggregation engine and decode harnesses. |

`simplex`, `marshal`, and `aggregation` depend on `core`. `structures` depends only on
the published crates.

## Running

Every target-bearing package is its own `cargo-fuzz` project, and none of them is
named `fuzz`.
`cargo fuzz` resolves `<cwd-or-ancestor>/fuzz/Cargo.toml` when it is not told otherwise,
and `consensus/fuzz/` holds no manifest, so a bare `cargo fuzz run <target>` does not work
from `consensus/` or from a package directory. Pass `--fuzz-dir`:

```bash
cargo +nightly fuzz run --fuzz-dir consensus/fuzz/simplex simplex_cert_mock
cargo +nightly fuzz list --fuzz-dir consensus/fuzz/marshal
```

The sanitizer build needs nightly, and the repository root is pinned to stable. Prefer the
nightly CI pins in `NIGHTLY_VERSION` ([`.github/workflows/slow.yml`](../../.github/workflows/slow.yml)):
a newer nightly can fail to build the workspace on a lint that does not fire on the pinned
version.

Or use `just`, which builds every target in the package once and then runs each for
`max_time` seconds. It takes its toolchain from the same `NIGHTLY_VERSION` variable,
defaulting to `nightly`:

```bash
NIGHTLY_VERSION=<pinned> just fuzz consensus/fuzz/simplex 60
```

Reproduce a failure from a crash file. Artifacts are written under the package that owns
the target:

```bash
cargo +nightly fuzz run --fuzz-dir consensus/fuzz/simplex simplex_cert_mock \
    consensus/fuzz/simplex/artifacts/simplex_cert_mock/<crash_file>
```

## Targets

### `simplex` (`--fuzz-dir consensus/fuzz/simplex`)

- `simplex_cert_mock`
- `simplex_cert_mock_audit`
- `simplex_cert_mock_audit_notarize_omission`
- `simplex_cert_mock_byzantine_first_leader`
- `simplex_cert_mock_byzzfuzz`
- `simplex_cert_mock_chaos`
- `simplex_cert_mock_chaos_twins`
- `simplex_cert_mock_faulty_net`
- `simplex_cert_mock_hb`
- `simplex_cert_mock_hb_state_cov`
- `simplex_cert_mock_mallory`
- `simplex_cert_mock_shuffled_twins_mutator`
- `simplex_cert_mock_state_cov`
- `simplex_cert_mock_twins_campaign`
- `simplex_cert_mock_twins_campaign_audit`
- `simplex_cert_mock_twins_campaign_hb`
- `simplex_cert_mock_twins_campaign_state_cov`
- `simplex_cert_mock_twins_mutator`
- `simplex_cert_mock_twins_mutator_audit`
- `simplex_cert_mock_twins_mutator_hb`
- `simplex_cert_mock_twins_mutator_state_cov`

### `marshal` (`--fuzz-dir consensus/fuzz/marshal`)

- `marshal_actor_standard_store_cert_mock`
- `marshal_e2e_coding_app_cert_mock_twins`
- `marshal_e2e_coding_cert_mock_disrupter`
- `marshal_e2e_standard_app_cert_mock_twins`
- `marshal_e2e_standard_deferred_cert_mock_block_dissemination`
- `marshal_e2e_standard_deferred_cert_mock_disrupter`
- `marshal_e2e_standard_deferred_cert_mock_poison`
- `marshal_e2e_standard_deferred_cert_mock_scenarios`
- `marshal_e2e_standard_deferred_cert_mock_twins_split_header`
- `marshal_e2e_standard_inline_cert_mock_twins_split_header`
- `marshal_scenario_standard_deferred_cert_mock`
- `marshal_scenario_standard_inline_cert_mock`

### `structures` (`--fuzz-dir consensus/fuzz/structures`)

- `attributable_map`
- `simplex_elector`
- `simplex_messages`
- `simplex_reporter_filtering`

### `aggregation` (`--fuzz-dir consensus/fuzz/aggregation`)

- `aggregation_cert_mock`
- `aggregation_decode`

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
in the `invariants` [module](./simplex/src/invariants.rs) hold true for correct nodes at each view.
This ensures protocol safety properties are maintained despite a byzantine node.

## Marshal Fuzzing

The marshal end-to-end targets exercise proposal, verification, certification,
broadcast, and application-result transitions through real Simplex stacks:

```bash
cargo +nightly fuzz run --fuzz-dir consensus/fuzz/marshal marshal_e2e_standard_deferred_cert_mock_disrupter
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

## Running Tests

### Unit Tests

Run deterministic tests with a fixed seed:
```bash
cargo test -p commonware-consensus-fuzz-core
cargo test -p commonware-consensus-fuzz-simplex test_
cargo test -p commonware-consensus-fuzz-marshal
```

### Property-Based Tests

Run proptest-based tests that explore many seeds:
```bash
cargo test -p commonware-consensus-fuzz-simplex property_test
```

Reproduce a failure with a specific seed:
```bash
PROPTEST_CASES=1 PROPTEST_SEED=<seed> cargo test -p commonware-consensus-fuzz-simplex property_test_certificate_mock_connected -- --nocapture
```

Proptest keys its regression file to the source file holding the tests, so saved seeds
live at [`simplex/proptest-regressions/lib.txt`](./simplex/proptest-regressions/lib.txt).
