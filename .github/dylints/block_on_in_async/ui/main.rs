// aux-build:futures_core.rs
// aux-build:futures_executor.rs
// edition:2021

// The auxiliary crates stand in for the real ones under the same crate names, so
// the fixtures exercise the definition paths the lint matches.

extern crate futures_core;
extern crate futures_executor;

use core::{
    future::{Future, ready},
    pin::Pin,
    task::{Context, Poll},
};
use futures_executor::block_on;

// A lookalike in this crate shares the name but not the definition path.
fn lookalike<F: Future>(_: F) -> F::Output {
    unimplemented!()
}

macro_rules! run {
    ($future:expr) => {
        block_on($future)
    };
}

// Bad: an async function body.
async fn async_function() {
    let _ = block_on(ready(1));
    let _ = futures_executor::block_on(ready(2));
    let _ = run!(ready(3));
}

struct Polled;

impl Future for Polled {
    type Output = u8;

    // Bad: a Future poll method.
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u8> {
        Poll::Ready(block_on(ready(4)))
    }
}

impl futures_core::Stream for Polled {
    type Item = u8;

    // Bad: a Stream poll method.
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<u8>> {
        Poll::Ready(Some(block_on(ready(5))))
    }

    // Good: not a poll method.
    fn size_hint(&self) -> (usize, Option<usize>) {
        (block_on(ready(18usize)), None)
    }
}

impl Polled {
    // Good: an inherent method is not a task poll.
    fn poll_inherent(&mut self) -> u8 {
        block_on(ready(6))
    }
}

trait Other {
    fn poll_other(&mut self) -> u8;
}

impl Other for Polled {
    // Good: a poll method of another trait.
    fn poll_other(&mut self) -> u8 {
        block_on(ready(7))
    }
}

// Good: a synchronous function, such as a test.
fn synchronous() -> u8 {
    block_on(ready(8))
}

fn main() {
    // Bad: an async block and an async closure.
    let _ = async {
        let _ = block_on(ready(9));
    };
    let _ = async || {
        let _ = block_on(ready(10));
    };

    // Bad: an async block inside a synchronous closure.
    let _ = || async {
        let _ = block_on(ready(11));
    };

    let _ = async {
        // Good: a synchronous closure may run on another thread.
        let _ = std::thread::spawn(|| block_on(ready(12)));

        // Good: a nested function item has its own synchronous body.
        fn nested() -> u8 {
            block_on(ready(13))
        }

        // Good: a lookalike and awaiting.
        let _ = lookalike(ready(14));
        let _ = ready(15).await;

        // Good: a function value is not a call here.
        let _ = [ready(16)].map(block_on);

        // Good: rustc does not report lints in macros of other crates.
        let _ = futures_executor::run!(ready(19));
    };

    // Good: the main function is synchronous.
    let _ = block_on(ready(17));
    let _ = synchronous();
}
