//! Communicate with a fixed set of authenticated peers.
//!
//! [discovery] operates under the assumption that peer addresses aren't known in
//! advance, and that they need to be discovered. Bootstrappers are used to
//! connect to the network and discover peers.
//!
//! [lookup] operates under the assumption that peer addresses are known in advance,
//! and that they can be looked up by their identifiers.

mod channels;
mod connection;
mod data;
pub use crate::sizing::peer_set_limit;
pub use data::{MAX_PAYLOAD_OVERHEAD, max_size};
pub(crate) mod dialing;
pub mod discovery;
pub mod lookup;
mod mailbox;
pub use mailbox::Mailbox;
mod relay;
mod router;
mod stream;
mod throttle;

#[cfg(test)]
fn assert_thread_placement(metrics: &str, networks: &[&str]) -> bool {
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
