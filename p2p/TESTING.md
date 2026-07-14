# Simulated network testing

Use `p2p/src/simulated` to test authenticated links and adverse conditions. Start the network, register each protocol channel, then configure links explicitly:

```rust
let (network, mut oracle) = Network::new(
    context.child("network"),
    Config {
        max_size: 1024 * 1024,
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
    success_rate: 0.95,
}).await.unwrap();
```

## Adversarial scenarios

Exercise partitions, latency, jitter, and loss when they affect the protocol. For Byzantine tests, substitute the relevant mock actor and verify the expected fault or block outcome.

Monitor progress with supervisors or metrics rather than time alone. Run a scenario twice with the same seed when its state is meant to be deterministic.
