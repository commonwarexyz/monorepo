use commonware_runtime::{Clock, Metrics, deterministic};
use std::time::Duration;

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
            assert_execution(metrics, &name, "Thread", true);
        }
        for task in ["_spawner_peer", "_dialer_dialer", "_listener_handshaker"] {
            let name = format!("{network}{task}");
            assert_execution(metrics, &name, "Shared", false);
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

/// Asserts the execution label of every series for a task and whether it must exist.
pub(crate) fn assert_execution(metrics: &str, name: &str, execution: &str, required: bool) {
    let label = format!("name=\"{name}\"");
    let mut series = metrics
        .lines()
        .filter(|line| line.starts_with("runtime_tasks_spawned_total{") && line.contains(&label))
        .peekable();
    assert!(
        !required || series.peek().is_some(),
        "missing {name}: {metrics}"
    );
    assert!(
        series.all(|line| line.contains(&format!("execution=\"{execution}\""))),
        "{name}: {metrics}"
    );
}

/// Starts both authenticated networks and waits for their placement checks.
pub(super) async fn start_and_check(context: &deterministic::Context, start: impl FnOnce()) {
    start();
    while !assert_thread_placement(&context.encode(), &["network0", "network1"]) {
        context.sleep(Duration::from_millis(100)).await;
    }
}
