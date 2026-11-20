// aux-build:commonware_actor.rs
// aux-build:commonware_p2p.rs
// aux-build:commonware_utils.rs
// aux-build:futures_util.rs
// aux-build:tokio.rs
// edition:2021

// The auxiliary crates stand in for the real ones under the same crate names, so
// the fixtures exercise the definition paths the lint matches.

extern crate commonware_actor;
extern crate commonware_p2p;
extern crate commonware_utils;
extern crate futures_util;
extern crate tokio;

use commonware_p2p::Receiver as _;
use core::{
    future::{Pending, pending, ready},
    pin::Pin,
};
use futures_util::future::FutureExt;

// Stands in for `futures::StreamExt`. The lint matches `next` by name and receiver.
trait StreamExt {
    type Item;

    fn next(&mut self) -> Pending<Option<Self::Item>> {
        pending()
    }
}

impl<T> StreamExt for commonware_utils::channel::mpsc::Receiver<T> {
    type Item = T;
}

impl<T> StreamExt for commonware_utils::channel::ring::Receiver<T> {
    type Item = T;
}

// Lookalikes in this crate share the names but not the definition paths.
mod lookalike {
    pub mod channel {
        pub mod mpsc {
            pub struct Receiver;

            impl Receiver {
                pub fn recv(&mut self) -> core::future::Pending<Option<u8>> {
                    core::future::pending()
                }
            }
        }
    }

    pub trait Receiver {
        fn recv(&mut self) -> core::future::Pending<u8> {
            core::future::pending()
        }
    }

    pub struct Other;

    impl Receiver for Other {}

    pub mod oneshot {
        pub struct Receiver;

        impl core::future::Future for Receiver {
            type Output = Result<u8, ()>;

            fn poll(
                self: core::pin::Pin<&mut Self>,
                _: &mut core::task::Context<'_>,
            ) -> core::task::Poll<Self::Output> {
                core::task::Poll::Pending
            }
        }
    }

    pub mod watch {
        pub struct Receiver;

        impl Receiver {
            pub async fn changed(&mut self) -> Result<(), ()> {
                core::future::pending().await
            }
        }
    }
}

struct Holder {
    receiver: Box<commonware_utils::channel::mpsc::Receiver<u8>>,
}

macro_rules! probe {
    ($receiver:expr) => {
        $receiver.recv().now_or_never()
    };
}

fn generic<R: commonware_p2p::Receiver>(receiver: &mut R) {
    // Bad: the trait method on any type.
    let _ = receiver.recv().now_or_never();
}

fn main() {
    let mut mpsc = commonware_utils::channel::mpsc::Receiver::<u8>::new();
    let mut unbounded = commonware_utils::channel::mpsc::UnboundedReceiver::<u8>::new();
    let mut ring = commonware_utils::channel::ring::Receiver::<u8>::new();
    let mut mailbox = commonware_actor::mailbox::Receiver::<u8>::new();
    let mut unreliable = commonware_actor::mailbox::UnreliableReceiver::<u8>::new();
    let mut tokio_mpsc = tokio::sync::mpsc::Receiver::<u8>::new();
    let mut tokio_unbounded = tokio::sync::mpsc::UnboundedReceiver::<u8>::new();
    let mut simulated = commonware_p2p::simulated::Receiver;
    let mut authenticated = commonware_p2p::authenticated::Receiver;
    let mut holder = Holder {
        receiver: Box::new(commonware_utils::channel::mpsc::Receiver::new()),
    };

    // Bad: each budgeted receiver.
    let _ = mpsc.recv().now_or_never();
    let _ = unbounded.recv().now_or_never();
    let _ = ring.recv().now_or_never();
    let _ = mailbox.recv().now_or_never();
    let _ = unreliable.recv().now_or_never();
    let _ = tokio_mpsc.recv().now_or_never();
    let _ = tokio_unbounded.recv().now_or_never();
    let _ = simulated.recv().now_or_never();
    let _ = authenticated.recv().now_or_never();
    generic(&mut simulated);

    // Bad: `next`, qualified calls, auto-deref, and macros.
    let _ = mpsc.next().now_or_never();
    let _ = ring.next().now_or_never();
    let _ = FutureExt::now_or_never(mpsc.recv());
    let _ = futures_util::future::FutureExt::now_or_never(ring.recv());
    let _ = commonware_utils::channel::mpsc::Receiver::recv(&mut mpsc).now_or_never();
    let _ = holder.receiver.recv().now_or_never();
    let reference = &mut &mut mailbox;
    let _ = reference.recv().now_or_never();
    assert!(tokio_mpsc.recv().now_or_never().is_none());
    let _ = probe!(unbounded);

    // Good: `try_recv` takes no budget.
    let _ = mpsc.try_recv();
    let _ = ring.try_recv();
    let _ = simulated.try_recv();

    // Good: other futures are out of scope.
    let _ = ready(1).now_or_never();
    let _ = mpsc.closed().now_or_never();

    // Good: the probe does not apply directly to the receive call.
    let future = mpsc.recv();
    let _ = future.now_or_never();
    let _ = Box::pin(mpsc.recv());

    // Good: rustc does not report lints in macros of other crates.
    let _ = commonware_utils::probe!(ring);

    // Good: lookalikes defined elsewhere.
    let _ = lookalike::channel::mpsc::Receiver.recv().now_or_never();
    let _ = lookalike::Receiver::recv(&mut lookalike::Other).now_or_never();

    oneshot();
    watch();
}

fn oneshot() {
    let mut oneshot = commonware_utils::channel::oneshot::Receiver::<u8>::new();
    let mut tokio_oneshot = tokio::sync::oneshot::Receiver::<u8>::new();

    // Bad: each oneshot receiver, by value, by reference, boxed, and pinned.
    let _ = commonware_utils::channel::oneshot::Receiver::<u8>::new().now_or_never();
    let _ = tokio::sync::oneshot::Receiver::<u8>::new().now_or_never();
    let _ = (&mut oneshot).now_or_never();
    let _ = (&mut tokio_oneshot).now_or_never();
    let _ = (&mut &mut oneshot).now_or_never();
    let _ = Box::new(tokio::sync::oneshot::Receiver::<u8>::new()).now_or_never();
    let _ = Pin::new(&mut oneshot).now_or_never();
    let _ = Box::pin(tokio::sync::oneshot::Receiver::<u8>::new()).now_or_never();
    let _ = FutureExt::now_or_never(&mut tokio_oneshot);
    assert!((&mut oneshot).now_or_never().is_none());

    // Good: `try_recv` takes no budget.
    let _ = oneshot.try_recv();
    let _ = tokio_oneshot.try_recv();

    // Good: the probe does not apply directly to the receiver.
    let _ = async { (&mut oneshot).await }.now_or_never();

    // Good: lookalikes defined elsewhere.
    let _ = lookalike::oneshot::Receiver.now_or_never();
}

fn watch() {
    let mut watch = commonware_utils::channel::watch::Receiver::<u8>::new();
    let mut tokio_watch = tokio::sync::watch::Receiver::<u8>::new();
    let mut boxed = Box::new(tokio::sync::watch::Receiver::<u8>::new());

    // Bad: `changed` on each watch receiver, qualified calls, and auto-deref.
    let _ = watch.changed().now_or_never();
    let _ = tokio_watch.changed().now_or_never();
    let _ = FutureExt::now_or_never(watch.changed());
    let _ = tokio::sync::watch::Receiver::changed(&mut tokio_watch).now_or_never();
    let _ = boxed.changed().now_or_never();
    assert!(watch.changed().now_or_never().is_none());

    // Bad: `wait_for` on each watch receiver.
    let _ = watch.wait_for(|value| *value > 0).now_or_never();
    let _ = tokio_watch.wait_for(|value| *value > 0).now_or_never();

    // Good: `has_changed` takes no budget.
    let _ = watch.has_changed();
    let _ = tokio_watch.has_changed();

    // Good: the probe does not apply directly to the `changed` call.
    let changed = watch.changed();
    let _ = changed.now_or_never();
    let _ = Box::pin(tokio_watch.changed());
    let wait = watch.wait_for(|value| *value > 0);
    let _ = wait.now_or_never();

    // Good: lookalikes defined elsewhere.
    let _ = lookalike::watch::Receiver.changed().now_or_never();
}
