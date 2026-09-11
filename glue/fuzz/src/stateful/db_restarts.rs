//! The database-adapter driver: the restart cluster over every QMDB adapter
//! class the glue `Stateful` actor supports.
//!
//! The structured input selects one adapter class; the rest of the run is the
//! restart driver, unchanged: four correct identities over the real stack, a
//! bounded crash/restart schedule with storage retained, and the same chain,
//! database-state, verdict, panic, and reproducibility predicates. The
//! selection is dispatched statically here, so each backend runs its own
//! monomorphized cluster and no trait object sits on the exercised path.

use super::{
    backend::{Any, Current, ImmutableCompact, ImmutableStandard, KeylessCompact, KeylessStandard},
    input::{DatabaseKind, StatefulDbRestartsFuzzInput},
    restarts,
    runner::{self, RunReport},
};

/// Label this driver reports under.
const TARGET: &str = "glue-stateful-db-restarts";

/// libFuzzer entry point.
pub fn fuzz_stateful_cert_mock_restarts_db(input: StatefulDbRestartsFuzzInput) {
    let raw_bytes = input.raw_bytes.clone();
    runner::report(&raw_bytes, || run_stateful_db_restarts(input));
}

/// Run one restart schedule over the selected database backend and return
/// what it measured.
///
/// A run is fully determined by its input bytes.
pub fn run_stateful_db_restarts(input: StatefulDbRestartsFuzzInput) -> RunReport {
    let (database, controls) = input.into_controls();
    match database {
        DatabaseKind::Any => restarts::execute::<Any>(TARGET, controls),
        DatabaseKind::Current => restarts::execute::<Current>(TARGET, controls),
        DatabaseKind::ImmutableStandard => restarts::execute::<ImmutableStandard>(TARGET, controls),
        DatabaseKind::ImmutableCompact => restarts::execute::<ImmutableCompact>(TARGET, controls),
        DatabaseKind::KeylessStandard => restarts::execute::<KeylessStandard>(TARGET, controls),
        DatabaseKind::KeylessCompact => restarts::execute::<KeylessCompact>(TARGET, controls),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::NUM_IDENTITIES;
    use commonware_consensus::types::TermLength;
    use commonware_utils::NZU32;

    fn tape(seed: u8) -> Vec<u8> {
        (0..96u8)
            .map(|byte| byte.wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn input(
        database: DatabaseKind,
        required_heights: u8,
        term_length: u32,
        restarts: u8,
        seed: u8,
    ) -> StatefulDbRestartsFuzzInput {
        StatefulDbRestartsFuzzInput {
            database,
            required_heights,
            term_length: TermLength::new(NZU32!(term_length)),
            restarts,
            raw_bytes: tape(seed),
        }
    }

    /// Runs one fixed input and asserts the checks were not vacuous: at least
    /// one restart executed and every comparison count is non-zero.
    fn measured(input: StatefulDbRestartsFuzzInput) -> RunReport {
        let database = input.database;
        let report = run_stateful_db_restarts(input);
        println!("{report}");
        assert!(
            report.measured(),
            "run measured nothing and must not be counted as passing: {report}"
        );
        assert!(
            report.counts.restarts > 0,
            "restart schedule executed nothing: {report}"
        );
        assert_eq!(report.counts.correct_nodes, NUM_IDENTITIES as usize);
        assert_eq!(report.target, "glue-stateful-db-restarts");
        assert_eq!(report.database, label(database));
        report
    }

    /// The label each adapter reports under.
    const fn label(database: DatabaseKind) -> &'static str {
        match database {
            DatabaseKind::Any => "any",
            DatabaseKind::Current => "current",
            DatabaseKind::ImmutableStandard => "immutable-standard",
            DatabaseKind::ImmutableCompact => "immutable-compact",
            DatabaseKind::KeylessStandard => "keyless-standard",
            DatabaseKind::KeylessCompact => "keyless-compact",
        }
    }

    /// One measured restart run for every database backend.
    #[test]
    fn every_backend_survives_restarts() {
        for (index, database) in DatabaseKind::ALL.into_iter().enumerate() {
            measured(input(database, 3, 1, 2, index as u8));
        }
    }

    /// The `any` backend behind the boundary measures exactly what the
    /// restart target measures for the same controls.
    #[test]
    fn any_matches_the_restart_target() {
        let controls = input(DatabaseKind::Any, 3, 2, 2, 21);
        let direct = crate::stateful::run_stateful_restarts(controls.clone().into_controls().1);
        let dispatched = run_stateful_db_restarts(controls);
        assert_eq!(direct.outcome, dispatched.outcome);
        assert_eq!(direct.counts, dispatched.counts);
    }

    /// `current` runs the keyed workload against its canonical root while the
    /// stateful actor checks its operations sync target; both must hold across
    /// restarts and lazy recovery.
    #[test]
    fn current_holds_canonical_state_across_restarts() {
        measured(input(DatabaseKind::Current, 4, 2, 3, 5));
    }

    /// Forks and restarts over the immutable adapters, whose workload never
    /// writes a key twice.
    #[test]
    fn immutable_forks_and_restarts_hold_invariants() {
        measured(input(DatabaseKind::ImmutableStandard, 5, 3, 3, 9));
        measured(input(DatabaseKind::ImmutableCompact, 5, 3, 3, 13));
    }

    /// Forks and restarts over the keyless adapters.
    #[test]
    fn keyless_forks_and_restarts_hold_invariants() {
        measured(input(DatabaseKind::KeylessStandard, 5, 3, 3, 17));
        measured(input(DatabaseKind::KeylessCompact, 5, 3, 3, 23));
    }

    /// I6: a replayed input fails, or passes, identically, for every backend.
    #[test]
    fn replay_is_reproducible() {
        for (index, database) in DatabaseKind::ALL.into_iter().enumerate() {
            let first = run_stateful_db_restarts(input(database, 2, 2, 1, 40 + index as u8));
            let second = run_stateful_db_restarts(input(database, 2, 2, 1, 40 + index as u8));
            assert_eq!(first, second, "replaying an input changed what it measured");
        }
    }

    /// P5: the byte tape never reaches `Debug` output; its length may.
    #[test]
    fn debug_elides_the_tape() {
        let mut input = input(DatabaseKind::KeylessCompact, 1, 1, 1, 0);
        input.raw_bytes = vec![0xAB; 1024];
        let rendered = format!("{input:?}");
        assert!(rendered.contains("database: KeylessCompact"));
        assert!(rendered.contains("raw_bytes_len: 1024"));
        assert!(!rendered.contains("171"));
    }
}
