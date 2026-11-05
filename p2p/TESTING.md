# Simulated network testing

Use `p2p/src/simulated` to test authenticated links and adverse conditions. Start the network, register each protocol channel, then configure links explicitly:

```rust
let (network, mut oracle) = Network::new(
    context.child("network"),
    Config {
        max_size: 1024 * 1024,
        max_peers_per_set: NZUsize!(2),
        disconnect_on_block: true,
        tracked_peer_sets: NZUsize!(1),
    },
);
network.start();

let (vote_sender, vote_receiver) = oracle
    .control(pk.clone())
    .register(0, quota)
    .await
    .unwrap();
let (certificate_sender, certificate_receiver) = oracle
    .control(pk)
    .register(1, quota)
    .await
    .unwrap();

oracle.add_link(pk1, pk2, Link {
    latency: Duration::from_millis(10),
    jitter: Duration::from_millis(3),
    success_rate: commonware_utils::probability!(0.95),
}).await.unwrap();
```

## Peer sets

Two peers exchange messages only while each tracks the other. In most tests, track every peer through the network-wide manager, which all peers follow:

```rust
oracle.manager().track(0, Set::try_from([pk1.clone(), pk2.clone()]).unwrap());
```

When nodes move through peer sets at different times, such as epochs in a reshare, give each node its own manager with `oracle.control(pk).manager()` (or `socket_manager()` for lookup) and track that node's sets through it. Each node then follows only its own sets, as on an authenticated network, and `tracked_peer_sets` limits each node's sets separately. Each call starts the node's sets empty, as a restart does, so call it once each time the node starts and clone the manager for the components that share it.

## Adversarial scenarios

Exercise partitions, latency, jitter, and loss when they affect the protocol. For Byzantine tests, substitute the relevant mock actor and verify the expected fault or block outcome.

Monitor progress with supervisors or metrics rather than time alone. Run a scenario twice with the same seed when its state is meant to be deterministic.
