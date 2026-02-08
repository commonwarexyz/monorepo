# commonware-actor

[![Crates.io](https://img.shields.io/crates/v/commonware-actor.svg)](https://crates.io/crates/commonware-actor)
[![Docs.rs](https://docs.rs/commonware-actor/badge.svg)](https://docs.rs/commonware-actor)

Coordinate actors with explicit ingress types and lane-aware control loops.

`commonware-actor` is a small, static actor SDK for Commonware primitives.
It emphasizes explicit ingress APIs, deterministic control loops, and no per-event
dynamic dispatch on hot paths.

It is designed for two execution styles:

- driver mode with [`service::ServiceBuilder`] + [`service::ActorService`]
- manual mode with the same [`Ask`] / [`Tell`] / mailbox ingress types

This keeps ingress types uniform without forcing one internal loop shape everywhere.

## What This Crate Provides

- Ingress declarations with generated wrappers ([`ingress!`])
- Bounded and unbounded mailbox APIs ([`mailbox::Mailbox`], [`mailbox::UnboundedMailbox`])
- Single-lane and multi-lane drivers ([`service::ServiceBuilder`], [`service::ActorService`])
- Actor-defined external ingress via [`Actor::on_external`]

## What This Crate Does Not Provide

- Supervision trees, registries, or framework-managed actor discovery
- Runtime-specific scheduling APIs outside the Commonware runtime traits
- Dynamic source registries managed by the framework

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
use commonware_actor::{service::ServiceBuilder, Actor};
use commonware_runtime::{deterministic, Metrics, Runner, Spawner};
use commonware_utils::channel::fallible::OneshotExt;

commonware_actor::ingress! {
    CounterMailbox,

    pub tell Increment { amount: u64 };
    pub ask Get -> u64;
}

#[derive(Default)]
struct Counter {
    total: u64,
}

impl<E: Spawner> Actor<E> for Counter {
    type Mailbox = CounterMailbox;
    type Ingress = CounterMailboxMessage;
    type Error = std::convert::Infallible;
    type Init = ();

    async fn on_ingress(
        &mut self,
        _context: &mut E,
        _init: &mut Self::Init,
        message: Self::Ingress,
    ) -> Result<(), Self::Error> {
        match message {
            CounterMailboxMessage::Increment { amount } => {
                self.total += amount;
            }
            CounterMailboxMessage::Get { response } => {
                response.send_lossy(self.total);
            }
        }
        Ok(())
    }
}

let runner = deterministic::Runner::default();
runner.start(|context| async move {
    let actor = Counter::default();
    let (mut mailbox, service) = ServiceBuilder::new(actor)
        .build(context.with_label("counter"));
    service.start();

    mailbox.increment(5).await.unwrap();
    assert_eq!(mailbox.get().await.unwrap(), 5);
});
```

## Priority Lanes

Use [`service::ServiceBuilder`] when you need multiple ingress lanes. Lane polling is
declaration-order biased by `with_lane(...)`. All lanes in a multi-lane service must
be the same kind (all bounded or all unbounded).

For simple one-lane actors, use `build(...)` or `build_with_capacity(...)`.

```rust,ignored
let (lanes, service) = ServiceBuilder::new(actor)
    .with_lane(Lane::Control, 32)
    .with_lane(Lane::High, 256)
    .with_lane(Lane::Low, 512)
    .build(context.with_label("peer"))
    .expect("build failed");
```

## Iteration Lifecycle

The driver runs these phases each iteration:

1. [`Actor::preprocess`] (optional housekeeping)
2. biased select over:
   - shutdown signal
   - configured lanes in declaration order
   - actor-defined [`Actor::on_external`] future
3. [`Actor::on_ingress`] dispatch (if message received)
4. [`Actor::postprocess`] (optional post-processing)

Within the select, polling is declaration-order biased:

- lanes: first declared lane first

Use `Actor::on_external` for per-iteration external input mapping:

```rust,ignored
impl Actor<MyContext> for MyActor {
    type Ingress = Ingress;
    type Init = MyInit;

    async fn on_external(
        &mut self,
        context: &mut MyContext,
        init: &mut Self::Init,
    ) -> Option<Self::Ingress> {
        commonware_macros::select! {
            _ = context.sleep(std::time::Duration::from_secs(1)) => {
                Some(Ingress::Timeout)
            },
            n = init.rx.recv() => {
                n.map(|n| Ingress::Input { n })
            },
        }
    }
}
```

- `Some(ingress)` emits one ingress event
- `None` stops the actor loop

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

