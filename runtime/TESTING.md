# Deterministic runtime testing

Use the deterministic runtime for async protocol tests. It makes scheduling, time, failure injection, and state recovery reproducible. Use `commonware_utils::test_rng()` for test data; for independent streams use `TestRng::new(seed)`.

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

## Native io_uring tests

Native runtime integration tests run on Linux 6.1 or newer with io_uring enabled
by the host. They use real rings and are separate from deterministic protocol
tests. Run the focused backend tests, then the shared runtime contracts:

```bash
just test -p commonware-runtime --features iouring iouring::
just test -p commonware-runtime --features iouring
just test -p commonware-runtime --features iouring --profile slow
```

Task, admission, operation-result, and sleeper state tests avoid constructing a
ring where possible. Keep size-one ring tests to exercise staging, independent
timer progress, retained completions, and cancellation under capacity pressure.
Use synchronization to gate race order. A timeout guards against a hung test,
but does not establish that the intended race occurred.

Foreign-wake Loom models cover the userspace publication protocol, including
empty-to-nonempty batches, transfer counts, delayed signaling, both wait modes,
and closure. They do not model kernel CQE ordering or `io_uring_enter`. Real-ring
tests cover those service and rearm boundaries. The Loom recipe already enables
release mode:

```bash
just test-loom --features iouring
just miri iouring::task:: -p commonware-runtime --features iouring
just miri utils::handle::tests::local_task_context_replacement_does_not_replace_abort_waker -p commonware-runtime --features iouring
```

Miri applies to pinned task cells and pure local-state tests, not tests that
create rings. On macOS, check all runtime targets with `--features iouring` to
verify that the Linux implementation compiles out. Feature-enabled doctests
remain part of the fast CI matrix.
