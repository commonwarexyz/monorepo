// aux-build:commonware_runtime.rs
// compile-flags: --edition=2024
#![allow(unused_must_use)]
extern crate commonware_runtime;

use commonware_runtime::{Spawner, Supervisor};

#[derive(Clone)]
struct Context;

impl Context {
    fn shared(self, _: bool) -> Self {
        self
    }

    fn dedicated(self) -> Self {
        self
    }
}

impl Spawner for Context {
    fn spawn(self, f: impl FnOnce()) -> std::future::Ready<()> {
        f();
        std::future::ready(())
    }
}

impl Supervisor for Context {
    fn child(&self, _: &'static str) -> Self {
        Self
    }

    fn with_attribute(self, _: &'static str, _: &'static str) -> Self {
        self
    }
}

struct Unrelated;

impl Unrelated {
    fn child(&self, _: &'static str) -> Self {
        Self
    }
}

trait Other {
    fn child(&self, _: &'static str) -> Self;
}

struct OtherContext;

impl Other for OtherContext {
    fn child(&self, _: &'static str) -> Self {
        Self
    }
}

struct Holder {
    context: Context,
}

impl Holder {
    fn child(&self) -> Context {
        self.context.child("field")
    }
}

struct MetricsOnly;

impl Supervisor for MetricsOnly {
    fn child(&self, _: &'static str) -> Self {
        Self
    }
    fn with_attribute(self, _: &'static str, _: &'static str) -> Self {
        self
    }
}

impl Holder {
    fn start(&self) {
        self.context.child("a").spawn(|| {});
    }
}

async fn correct_generic<E: Spawner + Supervisor>(context: E) {
    context.child("a").child("b").spawn(|| {}).await;
    context.child("a").spawn(|| {});
}

async fn awaited(context: Context) {
    context.child("a").child("b").spawn(|| {}).await;
    let _ = (
        context.child("a").child("b").spawn(|| {}),
        std::future::ready(()),
    )
        .1
        .await;
    let _ = (
        context.child("a").child("b").spawn(|| {}),
        std::future::ready(()).await,
    );
}

#[rustfmt::skip]
fn main() {
    let _ = Unrelated.child("first").child("second");
    let _ = OtherContext.child("first").child("second");
    let _ = MetricsOnly.child("first").child("second");
    let ctx = Context;
    let bound = ctx.child("a").child("b");
    bound.spawn(|| {});
    let _ = ctx.child("metrics").child("only").with_attribute("key", "value");
    let holder = Holder { context: Context };
    let _ = holder.child();
    holder.start();
    let _ = correct_generic(Context);
    let _ = awaited(Context);

    ctx.child("statement").child("worker").spawn(|| {});
    let _handle = ctx.child("handle").child("worker").spawn(|| {});
    ctx.child("attributed").with_attribute("key", "value").child("worker").spawn(|| {});
    ctx.child("shared").shared(true).child("worker").spawn(|| {});
    ctx.child("dedicated").dedicated().child("worker").spawn(|| {});
}
