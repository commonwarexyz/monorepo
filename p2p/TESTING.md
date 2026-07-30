# Deterministic network testing

Use authenticated lookup over `commonware_runtime::deterministic::network` for protocol tests.
Configure transport links, construct one lookup network per peer, track the peers' endpoints, and
register each protocol channel before starting the lookup networks:

```rust
let transport = deterministic::network::Oracle::new(Default::default());
transport.set_link(
    endpoint_1,
    endpoint_2,
    deterministic::network::Link::new(Duration::from_millis(10))
        .with_jitter(Duration::from_millis(3)),
)?;

let (mut network, mut oracle) = p2p::utils::mocks::lookup(
    context.child("peer"),
    &transport,
    crypto,
    endpoint_1,
    b"_COMMONWARE_EXAMPLE_LOOKUP",
    1024 * 1024,
);
oracle.track(0, tracked_peers);
let (vote_sender, vote_receiver) = network.register(0, quota, backlog);
let (certificate_sender, certificate_receiver) = network.register(1, quota, backlog);
network.start();
```

## Adversarial scenarios

Exercise partitions, latency, jitter, failures, and bandwidth constraints when they affect the
protocol. Use the deterministic transport oracle for topology and impairment changes. Use the
lookup oracle for membership changes and blocking. For Byzantine tests, substitute the relevant
mock actor and verify the expected fault or block outcome.

Monitor progress with supervisors or metrics rather than time alone. Run a scenario twice with the same seed when its state is meant to be deterministic.
