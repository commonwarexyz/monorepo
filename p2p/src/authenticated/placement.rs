/// Returns false until every network has spawned a peer, then asserts that actors report Thread
/// and per-peer, per-dial, and per-handshake tasks report Shared.
pub(super) fn assert_thread_placement(metrics: &str, networks: &[&str]) -> bool {
    let spawned: Vec<_> = metrics
        .lines()
        .filter(|line| line.starts_with("runtime_tasks_spawned_total{"))
        .collect();
    let series = |name: &str| {
        let label = format!("name=\"{name}\"");
        spawned
            .iter()
            .copied()
            .filter(move |line| line.contains(&label))
    };
    if networks
        .iter()
        .any(|network| series(&format!("{network}_spawner_peer")).next().is_none())
    {
        return false;
    }
    for network in networks {
        for actor in [
            "",
            "_tracker",
            "_router",
            "_spawner",
            "_listener",
            "_dialer",
        ] {
            let name = format!("{network}{actor}");
            assert!(series(&name).next().is_some(), "missing {name}: {metrics}");
            assert!(
                series(&name).all(|line| line.contains("execution=\"Thread\"")),
                "{name}: {metrics}"
            );
        }
        for task in ["_spawner_peer", "_dialer_dialer", "_listener_handshaker"] {
            let name = format!("{network}{task}");
            assert!(
                series(&name).all(|line| line.contains("execution=\"Shared\"")),
                "{name}: {metrics}"
            );
        }
    }
    for task in ["_dialer_dialer", "_listener_handshaker"] {
        assert!(
            networks
                .iter()
                .any(|network| series(&format!("{network}{task}")).next().is_some()),
            "missing {task}: {metrics}"
        );
    }
    true
}
