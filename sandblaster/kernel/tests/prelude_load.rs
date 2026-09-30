use sandblaster_kernel::api::*;

#[test]
fn prelude_loads() {
    match Env::try_with_prelude() {
        Ok(_) => {}
        Err(e) => panic!("{}", e),
    }
}

/// The hardware intrinsic models (sandblaster/targets/core) must check
/// against the kernel: the front end loads them silently (a failure would
/// only defer the hardware variants), so their acceptance is pinned here —
/// in particular under the phase-4 relevance discipline.
#[test]
fn target_models_load() {
    for (name, src) in [
        ("aarch64.core", include_str!("../../targets/core/aarch64.core")),
        ("x86_64.core", include_str!("../../targets/core/x86_64.core")),
    ] {
        let mut env = Env::with_prelude();
        let mut b = sandblaster_kernel::value::Budget { steps: 1_000_000_000 };
        if let Err(e) = env.load_core(src, &mut b) {
            panic!("{name}: {e}");
        }
    }
}
