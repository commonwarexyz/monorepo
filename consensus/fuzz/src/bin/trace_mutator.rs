//! Trace-native TLC-feedback mutator binary.
//!
//! Operates on `commonware_consensus::simplex::replay::Trace` throughout:
//! mutations via `trace_mutator::mutate_once`, TLC feedback via
//! `tracing::tlc_encoder::encode_from_trace`, Quint validation via
//! `quint_model::validate_and_extract_expected`.
//!
//! Environment:
//!   * `MUTATION_SEEDS_FOLDER` (default `artifacts/tlc_mutator/`)
//!   * `MUTATED_TRACES_DIR` (default `artifacts/mutated_traces/`)
//!   * `TLC_URL`, `MUTATOR_ITERATIONS`, `MUTATOR_RESEED_FREQ`,
//!     `MUTATOR_SEED_POPULATION_SIZE`, `MUTATOR_FAULTS`,
//!     `MUTATOR_SEED`, `MUTATOR_MUT_PER_TRACE`.

fn main() {
    commonware_consensus_fuzz::trace_mutator::run();
}
