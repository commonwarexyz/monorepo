# commonware-consensus fuzzing

Fuzzers for the `commonware-consensus` crate protocols and data structures,
designed to test protocol correctness under adversarial conditions.

## Layout

`consensus/fuzz/experimental/` is a plain directory. The fuzzers live in five packages under it.
The parent `consensus/fuzz/` is the `commonware-consensus-fuzz` package with the consensus
fuzz targets of `main`; see [its README](../README.md).

| Package | Crate | Contents |
| ------- | ----- | -------- |
| [`core/`](./core) | `commonware-consensus-fuzz-core` | Shared harness library: simulated network, Disrupter, twins network, fuzz input types, and mutation strategies. Library only, no fuzz targets. |
| [`simplex/`](./simplex) | `commonware-consensus-fuzz-simplex` | Simplex consensus harnesses: mode dispatch, invariants, happens-before and state coverage, ByzzFuzz, Mallory, and chaos. |
| [`marshal/`](./marshal) | `commonware-consensus-fuzz-marshal` | Marshal store, end-to-end, and scenario harnesses. |
| [`structures/`](./structures) | `commonware-consensus-fuzz-structures` | Data-structure and message targets. Self-contained, no library. |
| [`aggregation/`](./aggregation) | `commonware-consensus-fuzz-aggregation` | Aggregation engine and decode harnesses. |

`simplex`, `marshal`, and `aggregation` depend on `core`. `structures` depends only on
the published crates.

[`COMPONENTS.md`](./COMPONENTS.md) catalogs the reusable harness and test components.

## Running

Every target-bearing package is its own `cargo-fuzz` project, and none of them is
named `fuzz`.
`cargo fuzz` resolves `<cwd-or-ancestor>/fuzz/Cargo.toml` when it is not told otherwise,
and `consensus/fuzz/experimental/` holds no manifest, so a bare `cargo fuzz run <target>` from
`consensus/` runs a target of `consensus/fuzz/` instead, and one from a package directory does not
work. Pass `--fuzz-dir`:

```bash
cargo +nightly fuzz run --fuzz-dir consensus/fuzz/experimental/simplex exp_simplex_cert_mock
cargo +nightly fuzz list --fuzz-dir consensus/fuzz/experimental/marshal
```

The sanitizer build needs nightly, and the repository root is pinned to stable. Prefer the
nightly CI pins as `nightly` under `[tools]` in [`.github/toolchains.toml`](../../../.github/toolchains.toml):
a newer nightly can fail to build the workspace on a lint that does not fire on the pinned
version.

Or use `just`, which builds every target in the package once and then runs each for
`max_time` seconds. It takes its toolchain from the `NIGHTLY_VERSION` variable,
defaulting to the CI pin:

```bash
NIGHTLY_VERSION=<pinned> just fuzz consensus/fuzz/experimental/simplex 60
```

The `simplex` package splits its targets into two build partitions, `twins` (every
target with `twins` in its name) and `base` (everything else). Each is a feature that the targets list
in `required-features`, so `features=<partition>` builds and runs only that group. CI runs
one job per partition to keep each job from compiling binaries it never fuzzes:

```bash
NIGHTLY_VERSION=<pinned> just features=twins fuzz consensus/fuzz/experimental/simplex 60
```

The local [`justfile`](./justfile) works across all packages here without naming one,
and defaults to the CI nightly pin. Any other recipe falls back to the root justfile:

```bash
cd consensus/fuzz/experimental
just list                                  # every target, grouped by package
just build                                 # build every target; `just build simplex` for one package
just features=twins build simplex          # build one partition
just run exp_simplex_cert_mock                 # fuzz one target, whichever package defines it
just run exp_simplex_cert_mock -- -max_total_time=60
just run exp_simplex_cert_mock simplex/artifacts/exp_simplex_cert_mock/<crash_file>
```

Reproduce a failure from a crash file. Artifacts are written under the package that owns
the target:

```bash
cargo +nightly fuzz run --fuzz-dir consensus/fuzz/experimental/simplex exp_simplex_cert_mock \
    consensus/fuzz/experimental/simplex/artifacts/exp_simplex_cert_mock/<crash_file>
```

## Targets

### `simplex` (`--fuzz-dir consensus/fuzz/experimental/simplex`)

- `exp_simplex_cert_mock`
- `exp_simplex_cert_mock_audit`
- `exp_simplex_cert_mock_audit_notarize_omission`
- `exp_simplex_cert_mock_byzantine_first_leader`
- `exp_simplex_cert_mock_byzzfuzz`
- `exp_simplex_cert_mock_chaos`
- `exp_simplex_cert_mock_chaos_twins`
- `exp_simplex_cert_mock_faulty_net`
- `exp_simplex_cert_mock_flood`
- `exp_simplex_cert_mock_hb`
- `exp_simplex_cert_mock_hb_state_cov`
- `exp_simplex_cert_mock_mallory`
- `exp_simplex_cert_mock_shuffled_twins_mutator`
- `exp_simplex_cert_mock_state_cov`
- `exp_simplex_cert_mock_twins_campaign`
- `exp_simplex_cert_mock_twins_campaign_audit`
- `exp_simplex_cert_mock_twins_campaign_hb`
- `exp_simplex_cert_mock_twins_campaign_state_cov`
- `exp_simplex_cert_mock_twins_mutator`
- `exp_simplex_cert_mock_twins_mutator_audit`
- `exp_simplex_cert_mock_twins_mutator_hb`
- `exp_simplex_cert_mock_twins_mutator_state_cov`
- `exp_simplex_ed25519_equivocation_evidence`

### `marshal` (`--fuzz-dir consensus/fuzz/experimental/marshal`)

- `exp_marshal_actor_standard_store_cert_mock`
- `exp_marshal_e2e_coding_app_cert_mock_twins`
- `exp_marshal_e2e_coding_cert_mock_disrupter`
- `exp_marshal_e2e_coding_cert_mock_poison`
- `exp_marshal_e2e_standard_app_cert_mock_twins`
- `exp_marshal_e2e_standard_deferred_cert_mock_block_dissemination`
- `exp_marshal_e2e_standard_deferred_cert_mock_disrupter`
- `exp_marshal_e2e_standard_deferred_cert_mock_poison`
- `exp_marshal_e2e_standard_deferred_cert_mock_scenarios`
- `exp_marshal_e2e_standard_deferred_cert_mock_twins_split_header`
- `exp_marshal_e2e_standard_inline_cert_mock_twins_split_header`
- `exp_marshal_scenario_standard_deferred_cert_mock`
- `exp_marshal_scenario_standard_inline_cert_mock`

### `structures` (`--fuzz-dir consensus/fuzz/experimental/structures`)

- `exp_automaton_defaults`
- `exp_simplex_messages`
- `exp_simplex_reporter_filtering`
- `exp_simplex_threshold_vrf`

### `aggregation` (`--fuzz-dir consensus/fuzz/experimental/aggregation`)

- `exp_aggregation_cert_mock`
- `exp_aggregation_decode`

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
cargo +nightly fuzz run --fuzz-dir consensus/fuzz/experimental/marshal exp_marshal_e2e_standard_deferred_cert_mock_disrupter
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
cargo test -p commonware-consensus fuzz::
```

### Adversary Smoke Tests

Every Byzantine actor counts its actions under its own label through
`commonware_consensus_fuzz_core::byzantine`: a message the simulated network
accepted from the actor's sender, a twin secondary message the split forwarder
addressed to a node other than the twin, or a receiver-side forgery such as the
certificate poison. The counts never gate a fuzz run. Each target with a
Byzantine actor has a smoke test that runs one fixed input and requires the actor
the target exists for to have acted, so a change that silences it (a twin
secondary the split routes to nobody, a gossip engine that dies before it sends)
fails there even while another actor of the same run keeps sending. Honest
configurations must count nothing.
```bash
cargo test -p commonware-consensus-fuzz-simplex adversary_smoke
cargo test -p commonware-consensus-fuzz-marshal
```

### Property-Based Tests

Run minifuzz tests that explore 100 cases each:
```bash
cargo test -p commonware-consensus-fuzz-simplex minifuzz_
```

The seeds of earlier failures run in `test_connected_regression_seeds`.

Reproduce a failure by passing the reported `MINIFUZZ_BRANCH` token to the same test:
```bash
MINIFUZZ_BRANCH=0x... cargo test -p commonware-consensus-fuzz-simplex minifuzz_certificate_mock_connected -- --nocapture
```
