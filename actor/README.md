# commonware-actor

[![Crates.io](https://img.shields.io/crates/v/commonware-actor.svg)](https://crates.io/crates/commonware-actor)
[![Docs.rs](https://docs.rs/commonware-actor/badge.svg)](https://docs.rs/commonware-actor)

Coordinate actors with explicit ingress types and lane-aware control loops.

`commonware-actor` is a small, static actor SDK for Commonware primitives.
It emphasizes explicit ingress APIs, deterministic control loops, and no per-event
dynamic dispatch on hot paths.

It is designed for two execution styles:

- driver mode with [`service::ServiceBuilder`] + [`service::ActorService`]
- manual mode with the same [`Request`] / [`Tell`] / mailbox ingress types

This keeps ingress types uniform without forcing one internal loop shape everywhere.

## What This Crate Provides

- Ingress declarations with generated wrappers ([`ingress!`])
- Explicit dispatch helper ([`dispatch!`]) preserving [`ControlFlow`] semantics
- Bounded and unbounded mailbox APIs ([`mailbox::Mailbox`], [`mailbox::UnboundedMailbox`])
- Single-lane and multi-lane drivers ([`service::ServiceBuilder`], [`service::ActorService`])
- Static source registration ([`sources!`], tuple-based [`source::SourceSet`] impls)
- Built-in source adapters: [`source::recv`], [`source::deadline`], [`source::option_future`], [`source::pool_next`], [`source::handle`], [`source::poll_fn`]

## What This Crate Does Not Provide

- Supervision trees, registries, or framework-managed actor discovery
- Runtime-specific scheduling APIs outside the Commonware runtime traits
- Dynamic source registries or per-event trait-object dispatch

## `ingress!` Macro

`ingress!` declares ingress, typed wrappers, and a typed mailbox wrapper.

- optional first token can be `MailboxName,` (or `MailboxName<...>,`) to set mailbox type name.
- `tell` and `ask` define ingress items.
- `pub tell` / `pub ask` expose generated convenience methods on the mailbox
  (`UpperCamelCase` variant names become `lower_snake_case` methods).
  `pub tell` items also generate `*_lossy` variants that return `bool`.

```rust
commonware_actor::ingress! {
    CounterMailbox,

    // Internal wrappers (no generated mailbox methods)
    tell LocalTick;

    // Public API on CounterMailbox
    pub tell Increment { amount: u64 };
    pub ask Get -> u64;
}

// Generated mailbox API includes:
// - CounterMailbox::increment(amount)
// - CounterMailbox::get()
```

## Quickstart (Single Lane)

```rust,no_run
use commonware_actor::{dispatch, service::ServiceBuilder, Actor};
use commonware_runtime::{deterministic, ContextCell, Metrics, Runner};
use std::ops::ControlFlow;

commonware_actor::ingress! {
    CounterMailbox,

    pub tell Increment { amount: u64 };
    pub ask Get -> u64;
    pub tell Stop;
}

#[derive(Default)]
struct Counter {
    total: u64,
}

impl Actor<ContextCell<deterministic::Context>> for Counter {
    type Ingress = CounterMailboxMessage;
    type Init = ();

    async fn on_ingress(
        &mut self,
        _context: &ContextCell<deterministic::Context>,
        message: Self::Ingress,
    ) -> ControlFlow<()> {
        dispatch!(message, {
            CounterMailboxMessage::Increment { amount } => {
                self.total += amount;
            },
            CounterMailboxMessage::Get { response } => {
                let _ = response.send(self.total);
            },
            CounterMailboxMessage::Stop => {
                ControlFlow::Break(())
            },
        })
    }
}

let runner = deterministic::Runner::default();
runner.start(|context| async move {
    let actor = Counter::default();
    let (mut mailbox, control) = ServiceBuilder::new(actor)
        .build(context.with_label("counter"));
    let handle = control.start();

    mailbox.tell(Increment { amount: 5 }).await.unwrap();
    assert_eq!(mailbox.ask(Get).await.unwrap(), 5);

    mailbox.tell(Stop).await.unwrap();
    let _ = handle.await;
});
```

## Priority Lanes

Use [`service::ServiceBuilder`] when you need multiple ingress lanes. Lane polling is
declaration-order biased by `with_lane(...)`.

For simple one-lane actors, use `build(...)` or `build_with_capacity(...)`.
Use `with_unbounded_lane(...)` for lanes that should never block on enqueue.

```rust,compile_fail
let (lanes, control) = ServiceBuilder::new(actor)
    .with_lane(Lane::Control, 32)
    .with_lane(Lane::High, 256)
    .with_unbounded_lane(Lane::Low)
    .build(context.with_label("peer"));
```

## Sources and Builder Poll Order

The driver polls branches in this order each iteration:

1. shutdown signal
2. configured branches in builder declaration order

So `with_sources(...).with_lane(...)` prioritizes sources over lanes, while
`with_lane(...).with_sources(...)` prioritizes lanes over sources.

```rust,compile_fail
// Source branch before lane branch
ServiceBuilder::new(actor)
    .with_sources(source)
    .with_lane(0usize, 128)
    .build(context);

// Lane branch before source branch
ServiceBuilder::new(actor)
    .with_lane(0usize, 128)
    .with_sources(source)
    .build(context);
```

Within each branch, polling is declaration-order biased:

- lanes: first declared lane first
- sources: first declared source first (`sources!(a, b, c)` polls `a`, then `b`, then `c`)

## Built-in Source Adapters

- `recv(rx, map)`: maps `mpsc::Receiver<T>` messages into ingress
- `deadline(arm, emit)`: dynamic timer source driven by actor state
- `option_future(arm, map)`: polls one optional future in place
- `pool_next(get_pool, map)`: polls next completion from [`commonware_utils::futures::AbortablePool`]
- `handle(get_handle, map)`: polls an optional runtime task `Handle`
- `poll_fn(f)`: custom adapter for unusual cases

## Writing Custom Sources

Most actors should start with built-in adapters. When those are not enough, you have two options:

1. Use [`source::poll_fn`] for local, one-off source behavior.
2. Implement [`source::Source`] for reusable source types.

Custom source contract:

- return `Poll::Ready` with `Some(ingress)` to emit one event
- return `Poll::Pending` when temporarily idle
- return `Poll::Ready` with `None` only when permanently exhausted

Important: once a source returns `None`, the service shuts down the actor loop.

```rust,compile_fail
use commonware_actor::{source, sources, service::ServiceBuilder};
use core::task::Poll;

let custom = source::poll_fn(|actor: &mut ActorState, _context: &Context, _cx| {
    if actor.ready {
        actor.ready = false;
        Poll::Ready(Some(Ingress::Tick))
    } else {
        Poll::Pending
    }
});

let (_lanes, _service) = ServiceBuilder::new(actor)
    .with_sources(sources!(custom))
    .with_lane(0usize, 64)
    .build(context);
```

## Manual Mode

Manual loops use the same ingress and mailbox types.

```rust,no_run
use commonware_actor::{mailbox::Mailbox, oneshot};
use commonware_runtime::{deterministic, Runner, Spawner};
use commonware_utils::channel::mpsc;

enum Ingress {
    TellVariant,
    RequestVariant { response: oneshot::Sender<u64> },
    Stop,
}

let runner = deterministic::Runner::default();
runner.start(|context| async move {
    let (tx, mut rx) = mpsc::channel::<Ingress>(128);
    let mailbox = Mailbox::new(tx);

    let handle = context.spawn(move |_context| async move {
        while let Some(message) = rx.recv().await {
            match message {
                Ingress::TellVariant => {}
                Ingress::RequestVariant { response } => {
                    let _ = response.send(7);
                }
                Ingress::Stop => break,
            }
        }
    });

    drop(mailbox);
    let _ = handle.await;
});
```

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

[`ControlFlow`]: std::ops::ControlFlow
