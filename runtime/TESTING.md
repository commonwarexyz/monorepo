# Deterministic runtime testing

Use the deterministic runtime for async protocol tests. It makes scheduling, time, failure injection, and state recovery reproducible. Use `commonware_utils::test_rng()` for test data, and for independent streams use `TestRng::new(seed)`.

## Basic async test

```rust
#[test]
fn test_async_behavior() {
    let runner = deterministic::Runner::seeded(42);
    runner.start(|context| async move {
        let handle = context.child("worker").spawn(|context| async move {
            context.sleep(Duration::from_secs(1)).await;
        });

        context.sleep(Duration::from_millis(100)).await;

        select! {
            result = handle => { /* handle result */ },
            _ = context.sleep(Duration::from_secs(5)) => panic!("timeout"),
        }
    });
}
```

Label actors with `context.child("role")`. Use a seeded runner for repeatability and a timeout when testing a bounded operation:

```rust
let cfg = deterministic::Config::new()
    .with_seed(seed)
    .with_timeout(Some(Duration::from_secs(30)));
let runner = deterministic::Runner::new(cfg);
```

## Recovery

Use `start_and_recover` to exercise unclean shutdown and restart paths:

```rust
let mut checkpoint = None;
loop {
    let runner = if let Some(checkpoint) = checkpoint.take() {
        deterministic::Runner::from(checkpoint)
    } else {
        deterministic::Runner::timed(Duration::from_secs(30))
    };

    let (complete, next_checkpoint) = runner.start_and_recover(f);
    if complete {
        break;
    }
    checkpoint = Some(next_checkpoint);
}
```

## Verification checklist

- Check determinism with `context.auditor().state()` when relevant.
- Monitor progress with supervisors or metrics rather than time alone.
- For shutdown, assert the task-prefix count becomes non-zero before shutdown and zero afterward.
- Run a scenario twice with the same seed when its state is meant to be deterministic.
- Include recovery cases when the changed component has those boundaries.

# io_uring runtime testing

The `iouring` runtime is available on Linux behind the `iouring` feature. It has distinct test surfaces:

- Focused driver, network, and storage tests drive a real ring directly through the `iouring::testing::TestLoop` harness (`block_on`, `poll_once`, and `shutdown`). Use `just test -p commonware-runtime --features iouring <test_name>` for focused iteration.
- Runtime lifecycle and end-to-end tests start a real `iouring::Runner`. The shared network stress test also uses a real runner. Its `#[test_group("slow")]` annotation gives it the `_slow_` suffix, so it is excluded from the default nextest profile and selected by `just test -p commonware-runtime --features iouring --profile slow`.
- Tests backed by the runtime's configured ring through `TestLoop` or `Runner` require Linux 6.1 or newer because those rings use `IORING_SETUP_SINGLE_ISSUER` and `IORING_SETUP_DEFER_TASKRUN`. Low-level tests that call `IoUring::new` directly do not inherit those setup flags and depend on the io_uring operations they exercise. Pure state and arithmetic helper tests construct no ring. All of these tests still require a Linux target because the `iouring` module is Linux-only.
- The wake protocol's Loom tests run with `just test-loom --features iouring`. They require a Linux target because the `iouring` module is Linux-only, but they use userspace mutexes, condition variables, and counters to model the futex and eventfd portions of the protocol. They do not construct a ring or require Linux 6.1, and they do not model io_uring submission, CQE ordering, `io_uring_enter`, or wake-poll rearming.
