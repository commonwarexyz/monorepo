pub mod dependency;
pub mod error;
pub mod inheritance;
pub mod marker;
pub mod output;
pub mod scanner;
pub mod validator;

use error::Error;
use output::StatusReport;
use scanner::CrateScan;
use std::collections::BTreeMap;
use std::path::Path;
use validator::Conflict;

pub const CORE_CRATES: &[&str] = &[
    "broadcast",
    "codec",
    "coding",
    "collector",
    "conformance",
    "consensus",
    "cryptography",
    "deployer",
    "macros",
    "math",
    "p2p",
    "parallel",
    "resolver",
    "runtime",
    "storage",
    "stream",
    "utils",
];

pub const LTS_EXCLUDED_CRATES: &[&str] = &["conformance"];

pub fn run(repo_root: &Path) -> Result<(StatusReport, Vec<Conflict>), Error> {
    let mut all_scans: BTreeMap<String, CrateScan> = BTreeMap::new();

    for crate_name in CORE_CRATES {
        let crate_path = repo_root.join(crate_name);
        if crate_path.exists() {
            let scan = scanner::scan_crate(&crate_path, crate_name)?;
            all_scans.insert(crate_name.to_string(), scan);
        }
    }

    for scan in all_scans.values_mut() {
        inheritance::apply_inheritance(&mut scan.modules);
    }

    let mut conflicts = Vec::new();

    for (crate_name, scan) in &all_scans {
        conflicts.extend(validator::check_redundant_markers(
            crate_name,
            &scan.modules,
        ));
    }

    conflicts.extend(validator::check_lts_violations(
        &all_scans,
        LTS_EXCLUDED_CRATES,
    ));

    let report = output::generate_report(&all_scans);

    Ok((report, conflicts))
}
