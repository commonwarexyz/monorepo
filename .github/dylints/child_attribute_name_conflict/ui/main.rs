#[derive(Clone, Copy)]
struct Context;

impl Context {
    fn child(&self, _: &'static str) -> Self {
        Self
    }

    fn with_attribute(self, _: &'static str, _: impl core::fmt::Display) -> Self {
        self
    }

    fn spawn(self) -> Self {
        self
    }

    fn shared(self, _: bool) -> Self {
        self
    }

    fn with_span(self) -> Self {
        self
    }
}

#[rustfmt::skip]
fn main() {
    let context = Context;
    let _ = context.child("peer").with_attribute("index", 0);
    let _ = context.child("peer").with_attribute("peer", 1);
    let _ = context
        .child("validator")
        .with_attribute("validator", 2);
    let _ = context.with_attribute("worker", 3).child("worker");
    let _ = context.child("a").child("b").with_attribute("b", 4);
    let _ = context.child("multi").with_attribute("index", 5).with_attribute("multi", 6);
    let _ = context
        .child("nested")
        .shared(false)
        .with_span()
        .with_attribute("nested", 7);
    let _ = context
        .child("service")
        .with_attribute("service", 8)
        .spawn();
}
