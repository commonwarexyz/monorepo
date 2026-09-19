use super::fuzz::Plan;

#[test]
fn minifuzz_portable_contract() {
    commonware_invariants::minifuzz::Builder::default()
        .with_seed(0)
        .with_search_limit(100)
        .test(|u| Plan::PortableContract.run(u));
}

#[test]
fn minifuzz_dispatched_contract() {
    commonware_invariants::minifuzz::Builder::default()
        .with_seed(0)
        .with_search_limit(100)
        .test(|u| Plan::DispatchedContract.run(u));
}

#[test]
fn minifuzz_backend_matches_portable() {
    eprintln!(
        "Ocelot kernel differential backend: {}",
        super::selected_name()
    );
    commonware_invariants::minifuzz::Builder::default()
        .with_seed(0)
        .with_search_limit(100)
        .test(|u| Plan::BackendMatchesPortable.run(u));
}
