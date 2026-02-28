# Patches

This directory holds minimal, focused patches applied to the Commonware monorepo to enable fuzzing and test extraction. These are applied by `setup.sh` and kept small to ease review and upstreaming.

## Layout
- `*.patch` — Patch files applied automatically by `setup.sh`.
- `raw/` — File replacements copied verbatim into the monorepo.
- `optional/` — Extra patches not applied by default.

## Naming
Patches are split by responsibility (e.g., runtime, p2p, resolver) to keep changes isolated and reversible.

## Patch Index
- `buffered_fp_oom.patch` — Stabilizes buffered broadcast tests under fuzzing.
- `consensus_fuzzing_feature.patch` — Adds/extends fuzzing features and deps for consensus.
- `deterministic_runtime.patch` — Enables deterministic runtime hooks needed for fuzzing.
- `macros_fuzzable_test.patch` — Adds the `#[fuzzable_test]` macro.
- `p2p_fuzzing.patch` — Enables fuzzing hooks and deps in p2p.
- `resolver_checked_sender_import.patch` — Keeps resolver fetcher building under fuzzing.
- `resolver_fetcher_encode.patch` — Encodes fetcher messages for checked senders.
- `runtime_fuzzing.patch` — Enables fuzzing features in runtime.
