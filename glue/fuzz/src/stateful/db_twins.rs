//! The database-adapter twins driver: the twins cluster over every QMDB
//! adapter class the glue `Stateful` actor supports.
//!
//! The structured input selects one adapter class; the rest of the run is the
//! twins driver, unchanged: five engines over four identities, the compromised
//! identity's channels split per the selected scenario, the correct
//! application on its primary half and the faulty one on its secondary, and
//! the same chain, database-state, verdict, panic, and reproducibility
//! predicates. The selection is dispatched statically here, so each backend
//! runs its own monomorphized cluster and no trait object sits on the
//! exercised path.

use super::{
    backend::{Any, Current, ImmutableCompact, ImmutableStandard, KeylessCompact, KeylessStandard},
    input::{DatabaseKind, StatefulDbTwinsFuzzInput},
    runner::{self, RunReport},
    twins,
};

/// Label this driver reports under.
const TARGET: &str = "glue-stateful-db-twins";

/// libFuzzer entry point.
pub fn fuzz_stateful_cert_mock_twins_db(input: StatefulDbTwinsFuzzInput) {
    let raw_bytes = input.raw_bytes.clone();
    runner::report(&raw_bytes, || run_stateful_db_twins(input));
}

/// Run one twins scenario over the selected database backend and return what
/// it measured.
///
/// A run is fully determined by its input bytes.
pub fn run_stateful_db_twins(input: StatefulDbTwinsFuzzInput) -> RunReport {
    let (database, controls) = input.into_controls();
    match database {
        DatabaseKind::Any => twins::execute::<Any>(TARGET, controls),
        DatabaseKind::Current => twins::execute::<Current>(TARGET, controls),
        DatabaseKind::ImmutableStandard => twins::execute::<ImmutableStandard>(TARGET, controls),
        DatabaseKind::ImmutableCompact => twins::execute::<ImmutableCompact>(TARGET, controls),
        DatabaseKind::KeylessStandard => twins::execute::<KeylessStandard>(TARGET, controls),
        DatabaseKind::KeylessCompact => twins::execute::<KeylessCompact>(TARGET, controls),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::{
        MAX_REQUIRED_HEIGHTS, MAX_TERM_LENGTH, NUM_IDENTITIES, app::FaultArming,
    };
    use commonware_consensus::types::TermLength;
    use commonware_utils::NZU32;

    /// Every deviation the faulty application may take.
    const ALL_FAULTS: FaultArming = FaultArming {
        reject_verification: true,
        abstain_verification: true,
        divergent_proposal: true,
        decline_proposal: true,
    };

    fn tape(seed: u8) -> Vec<u8> {
        (0..96u8)
            .map(|byte| byte.wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn input(
        database: DatabaseKind,
        case_selector: u16,
        sustained: bool,
        required_heights: u8,
        term_length: u32,
        seed: u8,
    ) -> StatefulDbTwinsFuzzInput {
        StatefulDbTwinsFuzzInput {
            database,
            case_selector,
            sustained,
            faults: ALL_FAULTS,
            required_heights,
            term_length: TermLength::new(NZU32!(term_length)),
            raw_bytes: tape(seed),
        }
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

    /// Runs one fixed input and asserts the checks were not vacuous: the
    /// three correct nodes were observed and every comparison count is
    /// non-zero.
    fn measured(input: StatefulDbTwinsFuzzInput) -> RunReport {
        let database = input.database;
        let report = run_stateful_db_twins(input);
        println!("{report}");
        assert!(
            report.measured(),
            "run measured nothing and must not be counted as passing: {report}"
        );
        assert_eq!(report.counts.correct_nodes, NUM_IDENTITIES as usize - 1);
        assert_eq!(report.counts.restarts, 0);
        assert_eq!(report.target, "glue-stateful-db-twins");
        assert_eq!(report.database, label(database));
        report
    }

    /// One measured twins run for every database backend, with every fault
    /// armed.
    #[test]
    fn every_backend_holds_invariants() {
        for (index, database) in DatabaseKind::ALL.into_iter().enumerate() {
            measured(input(database, 0, false, 2, 1, index as u8));
        }
    }

    /// The `any` backend behind the boundary measures exactly what the twins
    /// target measures for the same controls.
    #[test]
    fn any_matches_the_twins_target() {
        let controls = input(DatabaseKind::Any, 2, false, 2, 3, 11);
        let direct = crate::stateful::run_stateful_twins(controls.clone().into_controls().1);
        let dispatched = run_stateful_db_twins(controls);
        assert_eq!(direct.outcome, dispatched.outcome);
        assert_eq!(direct.counts, dispatched.counts);
    }

    /// Several scenarios per backend, sustained and sampled, with varied
    /// terms and tapes distinct from the twins target's own regression runs.
    /// Every run must measure something: three correct nodes compared on
    /// chain, database state, and verdicts.
    #[test]
    fn selected_cases_hold_invariants() {
        for (index, database) in DatabaseKind::ALL.into_iter().enumerate() {
            for case_selector in [1u16, 3, 6] {
                let report = run_stateful_db_twins(input(
                    database,
                    case_selector,
                    case_selector % 2 == 1,
                    u8::try_from(case_selector % u16::from(MAX_REQUIRED_HEIGHTS)).expect("fits")
                        + 1,
                    u32::from(case_selector % MAX_TERM_LENGTH as u16) + 1,
                    100 + (index as u8) * 8 + u8::try_from(case_selector).expect("fits"),
                ));
                println!("{database:?} case {case_selector}: {report}");
                assert!(
                    report.measured(),
                    "{database:?} case {case_selector} measured nothing: {report}"
                );
                assert_eq!(
                    report.counts.correct_nodes,
                    NUM_IDENTITIES as usize - 1,
                    "{database:?} case {case_selector}: {report}"
                );
            }
        }
    }

    /// I6: a replayed input fails, or passes, identically, for every backend.
    #[test]
    fn replay_is_reproducible() {
        for (index, database) in DatabaseKind::ALL.into_iter().enumerate() {
            let first = run_stateful_db_twins(input(database, 4, true, 2, 2, 60 + index as u8));
            let second = run_stateful_db_twins(input(database, 4, true, 2, 2, 60 + index as u8));
            assert_eq!(first, second, "replaying an input changed what it measured");
        }
    }

    /// P5: the byte tape never reaches `Debug` output; its length may.
    #[test]
    fn debug_elides_the_tape() {
        let mut input = input(DatabaseKind::Current, 0, false, 1, 1, 0);
        input.raw_bytes = vec![0xAB; 1024];
        let rendered = format!("{input:?}");
        assert!(rendered.contains("database: Current"));
        assert!(rendered.contains("raw_bytes_len: 1024"));
        assert!(!rendered.contains("171"));
    }
}
