//! `evidence::withhold` (a process-wide, downgrade-only test hook): while a
//! guard lives the named models have no evidence for [`evidence::validation`]
//! (what the optimizer's gate and dispatcher ask), and dropping every guard
//! restores the committed verdict. Its own test binary, because the hook is
//! process-wide and `tests/evidence.rs` expects every model validated.

use sandblaster_targets::evidence::{self, Validation};
use sandblaster_targets::registry::Arch;

const RNDS2: &str = "_mm_sha256rnds2_epu32";
const MSG1: &str = "_mm_sha256msg1_epu32";

#[test]
fn withheld_models_are_missing_until_every_guard_is_dropped() {
    let native = Validation::Validated { executor: "native".into() };
    assert_eq!(evidence::validation(Arch::X86_64, RNDS2), native);
    let g1 = evidence::withhold(Arch::X86_64, &[RNDS2]);
    assert!(matches!(evidence::validation(Arch::X86_64, RNDS2), Validation::Missing(r) if r.contains("withheld")));
    assert!(!evidence::is_validated(Arch::X86_64, RNDS2));
    // only the named model of the named architecture
    assert_eq!(evidence::validation(Arch::X86_64, MSG1), native);
    assert!(evidence::is_validated(Arch::Aarch64, "vsha256hq_u32"));
    // the committed record itself is unchanged
    let file = evidence::load(Arch::X86_64).unwrap();
    let m = Arch::X86_64.models().iter().find(|m| m.name == RNDS2).unwrap();
    assert_eq!(evidence::validation_in(&file, m), native);
    // guards nest
    let g2 = evidence::withhold(Arch::X86_64, &[RNDS2, MSG1]);
    drop(g1);
    assert!(!evidence::is_validated(Arch::X86_64, RNDS2) && !evidence::is_validated(Arch::X86_64, MSG1));
    drop(g2);
    assert_eq!(evidence::validation(Arch::X86_64, RNDS2), native);
    assert_eq!(evidence::validation(Arch::X86_64, MSG1), native);
}
