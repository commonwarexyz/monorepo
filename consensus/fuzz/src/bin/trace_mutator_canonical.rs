//! Canonical-events variant of `trace_mutator`.
//!
//! Operates on `commonware_consensus::simplex::replay::Trace` (typed
//! canonical events) throughout: mutations via
//! `trace_mutator::canonical::mutate_once`, TLC feedback via
//! `tracing::tlc_encoder::encode_from_trace`, Quint validation via
//! `quint_model::validate_and_extract_expected_canonical`. No
//! `TraceData` on the hot path.
//!
//! Runs alongside the legacy `trace_mutator` binary during migration.
//! Seeds must be canonical JSON — use
//! `bin/convert_trace` to migrate legacy `TraceData` JSON first.
//!
//! Environment:
//!   * `CANONICAL_MUTATION_SEEDS_FOLDER` (falls back to
//!     `MUTATION_SEEDS_FOLDER`, then default
//!     `artifacts/canonical_tlc_mutator/`)
//!   * `CANONICAL_MUTATED_TRACES_DIR` (falls back to
//!     `MUTATED_TRACES_DIR`, then default
//!     `artifacts/canonical_mutated_traces/`)
//!   * `TLC_URL`, `MUTATOR_ITERATIONS`, `MUTATOR_RESEED_FREQ`,
//!     `MUTATOR_SEED_POPULATION_SIZE`, `MUTATOR_FAULTS`,
//!     `MUTATOR_SEED`, `MUTATOR_MUT_PER_TRACE` — same meanings as
//!     the legacy binary.

fn main() {
    commonware_consensus_fuzz::trace_mutator::canonical::run_canonical();
}
