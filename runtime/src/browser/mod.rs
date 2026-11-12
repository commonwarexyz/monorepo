//! A runtime for browser pages that connects them to each other over
//! [WebRTC](https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API) data channels.
//!
//! Tasks run on the page's event loop. The runtime implements [crate::Spawner], [crate::Clock],
//! and [crate::Metrics], draws randomness from the browser, and connects pages to each other
//! with a [Sink] and [Stream]. It has no storage and cannot open sockets, so it does not
//! implement [crate::Storage] or [crate::Network].
//!
//! # Running
//!
//! A page cannot block its event loop, so [Runner::start] is an async function and [Runner]
//! does not implement [crate::Runner].
//!
//! The event loop runs a woken task before it handles its next event. A task that keeps waking
//! itself without waiting for a timer or a connection stops the page from handling anything
//! else. A loop over [crate::reschedule] is one such task.
//!
//! [crate::Spawner::dedicated] and [crate::Spawner::shared] change nothing, because every task
//! shares the event loop.
//!
//! # Threads
//!
//! The runtime runs on the thread that started it and does not compile with the `atomics`
//! target feature. Without that feature a module cannot be shared between threads, and
//! `wasm-bindgen` treats JavaScript values as [Send] and [Sync]. Tasks may therefore hold
//! JavaScript values.
//!
//! # Panics
//!
//! When the module is built to unwind, a panic in any task panics the runtime. This target
//! aborts on panic by default. An abort stops the task that panicked without releasing what it
//! held, and events that arrive later can still run other tasks. Treat a panic as fatal to the
//! page.
//!
//! # Time
//!
//! [crate::Clock::current] reads the device's wall clock. Sleeps follow the page's monotonic
//! clock. On most devices that clock stops while the device is suspended.
//!
//! A browser may run a timer late. It runs the timers of a hidden page about once per second.
//!
//! # Connecting
//!
//! Two pages connect by exchanging one description each. A description lists the addresses its
//! page can be reached at. The application carries each description to the other page however
//! it likes, such as through a server both pages know or in a string their users pass along.
//!
//! ```text
//!  Page A                                                  Page B
//!    |                                                       |
//!    |  Context::offer                                       |
//!    |------------------------ offer ----------------------->|  carried by the application
//!    |                                       Context::answer |
//!    |<----------------------- answer -----------------------|  carried by the application
//!    |  Offering::connect                 Answering::connect |
//!    |                                                       |
//!    |<============== Sink and Stream to each other ========>|  direct between the browsers
//! ```
//!
//! Without a STUN server, a description lists only the addresses of the device's own network
//! interfaces. Unless one of those is public, they reach the page only from the same device or
//! local network. A page behind a NAT learns its public address from a STUN server named in
//! its [Config]. A STUN server reports the address a request arrived from and carries none of
//! the connection's traffic.
//!
//! The runtime contacts no server unless one is configured. It never relays a connection, so
//! pages whose networks keep them from reaching each other directly cannot connect.
//!
//! A STUN server that does not respond can delay a description by tens of seconds. The other
//! page may never complete the exchange. No step has a deadline of its own, so callers must put
//! one on each step. Dropping a step abandons the connection.
//!
//! # Connections
//!
//! A connection is an ordered, reliable stream of bytes that the browsers encrypt. Each browser
//! authenticates the other only by the description its page received. A page that must know who
//! it reached has to authenticate it over the connection.
//!
//! WebRTC gives a page no way to slow down a peer that sends faster than the page reads. A
//! connection therefore holds at most the receive buffer size set in its [Config] beyond its
//! pending read, and closes when its peer sends more. A protocol that moves more than that must
//! let the reader set the pace, for example by sending only what the reader has requested.
//!
//! A connection closes when its [Sink] and [Stream] are both dropped. Dropping one of them
//! tells the peer nothing. Reads and sends have no deadline of their own. When a peer
//! disappears without closing, the browser may take tens of seconds to notice.
//!
//! ```text
//!  what happened                          Stream::recv                 Sink::send
//!  -------------                          ------------                 ----------
//!  peer closed, or the transport failed   buffered bytes, RecvFailed,  SendFailed, then Closed
//!                                         then Closed
//!  peer sent text, or more than the       buffered bytes, RecvFailed,  SendFailed, then Closed
//!  receive buffer allows                  then Closed
//!  pending read dropped                   Closed                       unaffected
//!  pending send dropped                   unaffected                   Closed
//!  one half dropped                       the other half is unaffected
//!  both halves dropped                    the connection closes
//! ```
//!
//! # Example
//!
//! ```no_run
//! use commonware_runtime::{IoBuf, Sink as _, Stream as _, browser};
//!
//! # async fn exchange(_offer: String) -> String { unimplemented!() }
//! # async fn example() {
//! browser::Runner::default()
//!     .start(|context| async move {
//!         // Describe this page and learn the other page's answer.
//!         let (offer, offering) = context.offer().await.unwrap();
//!         let answer = exchange(offer).await;
//!
//!         // Connect and greet the other page.
//!         let (mut sink, mut stream) = offering.connect(answer).await.unwrap();
//!         sink.send(IoBuf::from(b"hello")).await.unwrap();
//!         let _reply = stream.recv(5).await.unwrap();
//!     })
//!     .await;
//! # }
//! ```

#[cfg(target_feature = "atomics")]
compile_error!("the browser runtime runs on one thread and cannot be built with atomics");

mod runtime;
pub use runtime::*;
mod timer;
mod webrtc;
pub use webrtc::{Answering, Offering, Sink, Stream};
