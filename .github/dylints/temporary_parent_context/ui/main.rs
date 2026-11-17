// aux-build:commonware_runtime.rs
extern crate commonware_runtime;

use commonware_runtime::Supervisor;

#[derive(Clone)]
struct Context;

impl Context {
    fn shared(self, _: bool) -> Self {
        self
    }

    fn dedicated(self) -> Self {
        self
    }

    fn spawn(self, _: impl FnOnce()) {}
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

#[rustfmt::skip]
fn main() {
    let _ = Unrelated.child("first").child("second");
    let _ = OtherContext.child("first").child("second");
    let ctx = Context;
    let _ = ctx.child("single");
    let bound = ctx.child("bound");
    let _ = bound.child("worker");
    let holder = Holder { context: Context };
    let _ = holder.child();
    let _ = ctx.clone().child("cloned");

    let _ = ctx.child("direct").child("worker");
    let _ = ctx.child("attributed").with_attribute("key", "value").child("worker");
    let _ = ctx
        .child("multiline")
        .child("worker");
    let child = ctx.child("binding").child("worker");
    child.spawn(|| {});
    ctx.child("spawning").child("worker").spawn(|| {});
    let _ = ctx.child("first").child("second").child("third");
    let _ = ctx.child("shared").shared(true).child("worker");
    let _ = ctx.child("dedicated").dedicated().child("worker");
    let _ = ctx.child("clone").clone().child("worker");
}
