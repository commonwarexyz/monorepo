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
    let _ = context
        .child("service")
        .with_attribute("service", 4)
        .spawn();
}
