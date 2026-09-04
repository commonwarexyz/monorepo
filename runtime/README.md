# commonware-runtime

[![Crates.io](https://img.shields.io/crates/v/commonware-runtime.svg)](https://crates.io/crates/commonware-runtime)
[![Docs.rs](https://docs.rs/commonware-runtime/badge.svg)](https://docs.rs/commonware-runtime)

Execute asynchronous tasks with a configurable scheduler.

## Status 

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

## Native io_uring runtime

On Linux 6.1 or newer, enable `iouring` to use the ALPHA native runtime:

```rust
use commonware_runtime::{Runner as _, Spawner, Supervisor, iouring};

let config = iouring::Config::default().with_ring_config(iouring::RingConfig {
    size: 1024,
    ..Default::default()
});
iouring::Runner::new(config).start(|context| async move {
    let task = context.child("worker").spawn(|_| async { 42 });
    assert_eq!(task.await.unwrap(), 42);
});
```

One ordinary worker polls tasks and drives its ring on the thread calling
`Runner::start`. The root future can borrow local data and need not be `Send`.
Spawned futures remain concrete inside a single pinned task allocation.
`dedicated()` and `shared(true)` each create a supervised thread with its own
ring. They are suitable for blocking work, but there is no shared blocking pool.

An ordinary spawn targets the originating context's worker. Contexts delivered
to one-off workers are rebound before their user closures run, so their ordinary
children run there. Handles can be awaited or aborted from other threads.
Blobs, listeners, and connection halves can move between workers between I/O
operations. An I/O future binds on its first poll, including while waiting for
capacity. Polling registered work on another live worker is rejected. Foreign
destruction routes cancellation to its original worker. Cached network access
and synchronous storage metadata operations do not require a current worker.

The rounded ring size bounds admitted logical requests. It defaults to 1024
(128 in runtime unit tests), rounds upward to a power of two, and cannot exceed
32,768. `RingConfig::default()` uses 128. FIFO admission reserves released slots
before waking callers, and completed ordinary results no longer consume waiter
capacity. Sleepers and admission deadlines are independent of the ring, so
timeouts can progress while the ring is full. Application dependency cycles
still require deadlines or cancellation. The runtime cannot infer which pending
operation must be cancelled to free capacity.

The operation wheel uses a 5 ms tick by default. Its horizon follows the largest
network timeout, with a limit of 30 years and 1,048,576 wheel slots. Invalid
configuration is rejected before startup resources are acquired. Idle workers
use the existing adaptive spinner and hybrid futex/eventfd wake path. Disable
spinning with `with_idle_spinner(iouring::SpinnerConfig::disabled())` when CPU
usage matters more than sparse wake latency.

Shutdown closes admission, aborts supervised tasks, and waits for kernel
retirement. Admitted writes and syncs finish even if their callers were dropped.
`start_sync().await` admits the sync before returning its completion handle.
Dropping or aborting that handle only stops observation. The runner joins all
one-off threads before returning, with no configured shutdown time limit.
Escaped storage resources retain the directory hold until their resources and
requests are released. Nested native runners on the same thread are rejected
before acquiring another directory hold.

Tokio always uses its own storage and network adapters. The `iouring` feature
compiles on other platforms with the Linux implementation excluded. See
[runtime testing](TESTING.md) for native tests and userspace wake-model coverage.
