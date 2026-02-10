# commonware-actor

[![Crates.io](https://img.shields.io/crates/v/commonware-actor.svg)](https://crates.io/crates/commonware-actor)
[![Docs.rs](https://docs.rs/commonware-actor/badge.svg)](https://docs.rs/commonware-actor)

Coordinate actors with protocol-driven ingress and lane-aware control loops.

## Declare incoming messages with `ingress!`

`ingress!` is the Actors' entrypoint. You describe what events an actor will handle, and the macro generates:

- ingress enums used by the actor implementation (read-only vs read-write)
- wrapper message types for `tell`/`ask`/`subscribe`
- a typed mailbox with convenience methods for `pub` messages

### Message kinds

- `tell`: fire-and-forget message
- `ask`: request/response message that does not mutate state
- `ask read_write`: request/response message that may mutate state
- `subscribe`: enqueue a read-write request that returns a `oneshot::Receiver<T>` immediately

### Visibility and generated methods

- `pub` messages generate mailbox methods
- non-`pub` messages still exist in generated enums, but no public mailbox helper is emitted

For a bounded mailbox, generated `pub tell` methods are async and return `Result<(), MailboxError>`.
For an unbounded mailbox, generated `pub tell` methods are sync and return `Result<(), MailboxError>`.

Generated method sets for `pub` items:

- `pub tell X`: `x`, `x_lossy`, and `try_x` (bounded only)
- `pub ask X`: `x` and `x_timeout`
- `pub subscribe X`: `x` (lossy enqueue) and `try_x` (delivery-checked enqueue)

### Example

```rust
use commonware_actor::ingress;

ingress! {
    CounterMailbox,

    pub tell Increment { amount: u64 };
    pub ask Get -> u64;
    pub ask read_write AddAndGet { amount: u64 } -> u64;
    pub subscribe WaitForNext -> u64;
}
```

The declaration above generates a mailbox API with the shape:

- `CounterMailbox::increment(...)`
- `CounterMailbox::get(...)`
- `CounterMailbox::add_and_get(...)`
- `CounterMailbox::wait_for_next(...)`
- `CounterMailbox::try_wait_for_next(...)`

and corresponding generated ingress enums used by [`Actor`]:

- `CounterMailboxMessage` (Enum of `ReadOnly` and `ReadWrite` messages)
- `CounterMailboxReadOnlyMessage` (`Get`)
- `CounterMailboxReadWriteMessage` (`Increment`, `AddAndGet`, `WaitForNext`)

## The `Actor` Trait

An [`Actor`] defines lifecycle hooks and message handlers.

At minimum, you provide:

- `type Mailbox`: generated mailbox type from `ingress!`
- `type Ingress`: generated envelope enum (`<MailboxName>Message`)
- `type Error`: fatal handler error type
- `type Args`: startup payload (`()` when unused)
- `type Snapshot`: cheap clone used for concurrent read-only handlers
- `snapshot(...)`
- `on_readonly(...)`
- `on_read_write(...)`

### Minimal actor example

```rust,no_run
use commonware_actor::{ingress, service::ServiceBuilder, Actor};
use commonware_runtime::{deterministic, Metrics, Runner, Spawner};
use commonware_utils::channel::fallible::OneshotExt;

ingress! {
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
    type Args = ();
    type Snapshot = u64;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.total
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: CounterMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            CounterMailboxReadOnlyMessage::Get { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: CounterMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            CounterMailboxReadWriteMessage::Increment { amount } => {
                self.total += amount;
                Ok(())
            }
        }
    }
}

let runner = deterministic::Runner::default();
runner.start(|context| async move {
    let actor = Counter::default();
    let (mut mailbox, service) = ServiceBuilder::new(actor)
        .build(context.with_label("counter"));
    service.start();

    mailbox.increment(5).await.expect("increment failed");
    assert_eq!(mailbox.get().await.expect("get failed"), 5);
});
```

### Execution model

- read-only ingress runs concurrently on snapshots
- read-write ingress runs serially on actor state
- read-write handling is fenced behind read-only work dispatched before the write arrived
- returning `Err` from `on_readonly` or `on_read_write` is fatal but `on_shutdown` is still called after draining in-flight reads

`subscribe` detail:

- `method` is intentionally lossy: it always returns a receiver, even if enqueue fails on a closed mailbox
- `try_method` is delivery-checked and returns `Result<Receiver<_>, MailboxError>`

Optional hooks:

- `on_startup`, `on_shutdown`
- `preprocess`, `postprocess`
- `on_external` to map external signals into read-write ingress

### External Signals

`Actor::on_external` lets an actor translate non-mailbox events into normal ingress.

```rust
use commonware_actor::{ingress, service::ServiceBuilder, Actor};
use commonware_macros::select;
use commonware_runtime::{deterministic, Clock, Metrics, Runner, Spawner};
use commonware_utils::channel::{fallible::OneshotExt, mpsc};
use std::time::Duration;

ingress! {
    ExternalMailbox,

    tell Tick;
    tell SetFromChannel { value: u64 };
    pub ask Value -> u64;
}

struct ExternalActor {
    value: u64,
}

impl<E: Spawner + Clock> Actor<E> for ExternalActor {
    type Mailbox = ExternalMailbox;
    type Ingress = ExternalMailboxMessage;
    type Error = std::convert::Infallible;
    type Args = mpsc::Receiver<u64>;
    type Snapshot = u64;

    fn snapshot(&self, _args: &Self::Args) -> Self::Snapshot {
        self.value
    }

    async fn on_readonly(
        _context: E,
        snapshot: Self::Snapshot,
        message: ExternalMailboxReadOnlyMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ExternalMailboxReadOnlyMessage::Value { response } => {
                response.send_lossy(snapshot);
                Ok(())
            }
        }
    }

    async fn on_read_write(
        &mut self,
        _context: &mut E,
        _args: &mut Self::Args,
        message: ExternalMailboxReadWriteMessage,
    ) -> Result<(), Self::Error> {
        match message {
            ExternalMailboxReadWriteMessage::SetFromChannel { value } => {
                self.value = value;
                Ok(())
            }
            ExternalMailboxReadWriteMessage::Tick => {
                self.value += 1;
                Ok(())
            }
        }
    }

    async fn on_external(
        &mut self,
        context: &mut E,
        args: &mut Self::Args,
    ) -> Option<ExternalMailboxReadWriteMessage> {
        select! {
            _ = context.sleep(Duration::from_secs(1)) => {
                Some(ExternalMailboxReadWriteMessage::Tick)
            },
            value = args.recv() => {
                value.map(|value| ExternalMailboxReadWriteMessage::SetFromChannel { value })
            },
        }
    }
}

let runner = deterministic::Runner::default();
runner.start(|context| async move {
    let actor = ExternalActor { value: 0 };
    let (mut mailbox, service) = ServiceBuilder::new(actor)
        .build(context.with_label("external"));

    let (tx, rx) = mpsc::channel(8);
    service.start_with(rx);

    tx.send(42).await.expect("send failed");
    context.sleep(Duration::from_millis(5)).await;
    assert_eq!(mailbox.value().await.expect("ask failed"), 42);
});
```

## The `ServiceBuilder`

[`service::ServiceBuilder`] constructs mailboxes and the actor service loop driver.

### Single lane

- `build(...)`: bounded mailbox with default capacity
- `build_with_capacity(...)`: bounded mailbox with explicit `NonZeroUsize` capacity
- `build_unbounded(...)`: unbounded mailbox

```rust,ignore
use commonware_actor::service::ServiceBuilder;
use std::num::NonZeroUsize;

# let context = unimplemented!();
# let actor = unimplemented!();
let (_mailbox, _service) = ServiceBuilder::new(actor)
    .build_with_capacity(context, NonZeroUsize::new(128).expect("non-zero"));
```

### Multi lane (priority by declaration order)

Use lanes when you want separate queues (for example, control vs data).
Lane polling is declaration-order biased.

```rust,ignore
use commonware_actor::service::ServiceBuilder;
use std::num::NonZeroUsize;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Lane {
    Control,
    Data,
}

# let context = unimplemented!();
# let actor = unimplemented!();
let (_lanes, _service) = ServiceBuilder::new(actor)
    .with_lane(Lane::Control, NonZeroUsize::new(32).expect("non-zero"))
    .with_lane(Lane::Data, NonZeroUsize::new(256).expect("non-zero"))
    .build(context)
    .expect("duplicate lanes");
```

### Graceful shutdown behavior

On graceful exits (runtime stop signal, lane closure, or `on_external` exhaustion):

- in-flight read-only tasks are drained first
- then `on_shutdown` runs once

## Manual mode

You can also use [`mailbox::Mailbox`] and [`mailbox::UnboundedMailbox`] directly with your own loop.
`ingress!` still helps because it gives you typed message wrappers and conversion traits.

## Status

Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.
