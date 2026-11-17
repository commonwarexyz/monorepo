// aux-build:commonware_runtime.rs
// compile-flags: --edition=2024
#![feature(super_let)]
#![allow(unused_must_use, dead_code, unused_braces)]
extern crate commonware_runtime;

use commonware_runtime::{Spawner, Supervisor};
use std::future::{Ready, ready};

#[derive(Clone)]
struct Context;

impl Spawner for Context {
    fn shared(self, _: bool) -> Self {
        self
    }

    fn dedicated(self) -> Self {
        self
    }

    fn spawn(self, f: impl FnOnce()) -> Ready<()> {
        f();
        ready(())
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

/// A `child` method that is not the runtime's.
struct Unrelated;

impl Unrelated {
    fn child(&self, _: &'static str) -> Self {
        Self
    }

    fn spawn(self, _: impl FnOnce()) {}
}

/// A `Supervisor` without a `Spawner`, as metrics-only mocks are.
struct MetricsOnly;

impl Supervisor for MetricsOnly {
    fn child(&self, _: &'static str) -> Self {
        Self
    }

    fn with_attribute(self, _: &'static str, _: &'static str) -> Self {
        self
    }
}

/// Moves the context somewhere that outlives the statement.
trait Keep: Sized {
    fn keep(self, kept: &mut Vec<Self>) -> &Self;
}

impl Keep for Context {
    fn keep(self, kept: &mut Vec<Self>) -> &Self {
        kept.push(self);
        kept.last().unwrap()
    }
}

struct Holder {
    context: Context,
}

struct Wrapper {
    handle: Ready<()>,
}

impl Wrapper {
    async fn wait(self) {
        self.handle.await
    }
}

fn block_on<F: Future>(_: F) {}

// The handle goes unused while the temporary parent closes: each of these fires.

fn discarded(ctx: &Context) {
    ctx.child("a").child("b").spawn(|| {});
}

fn bound(ctx: &Context) {
    let _handle = ctx.child("a").child("b").spawn(|| {});
}

fn tail(ctx: &Context) -> Ready<()> {
    ctx.child("a").child("b").spawn(|| {})
}

fn returned(ctx: &Context) -> Ready<()> {
    return ctx.child("a").child("b").spawn(|| {});
}

fn closure(ctx: &Context) {
    let _spawn = || ctx.child("a").child("b").spawn(|| {});
}

fn modifiers(ctx: &Context) {
    ctx.child("a")
        .with_attribute("k", "v")
        .child("b")
        .spawn(|| {});
    ctx.child("a").shared(true).child("b").spawn(|| {});
    ctx.child("a").child("b").dedicated().spawn(|| {});
}

fn generic<E: Spawner + Supervisor>(ctx: &E) {
    ctx.child("a").child("b").spawn(|| {});
}

impl Holder {
    fn field(&self) {
        self.context.child("a").child("b").spawn(|| {});
    }
}

// Correct code: none of these fire.

async fn awaited(ctx: &Context) {
    ctx.child("a").child("b").spawn(|| {}).await;
    let _ = (ctx.child("a").child("b").spawn(|| {}), ready(())).1.await;
    Wrapper {
        handle: ctx.child("a").child("b").spawn(|| {}),
    }
    .wait()
    .await;
    match ctx.child("a").child("b").spawn(|| {}) {
        handle => handle.await,
    }
    if let Some(handle) = Some(ctx.child("a").child("b").spawn(|| {})) {
        handle.await;
    }
}

fn blocked(ctx: &Context) {
    block_on(ctx.child("a").child("b").spawn(|| {}));
}

fn not_spawned(ctx: &Context) {
    let bound = ctx.child("a").child("b");
    let _metrics = ctx.child("a").child("b").with_attribute("k", "v");
    let _ = MetricsOnly.child("a").child("b");
    Unrelated.child("a").child("b").spawn(|| {});
    bound.spawn(|| {});
}

fn single_child(holder: &Holder, ctx: &Context) {
    holder.context.child("a").spawn(|| {});
    ctx.clone().child("a").spawn(|| {});
}

fn kept(ctx: &Context, kept: &mut Vec<Context>) {
    ctx.child("a").keep(kept).child("b").spawn(|| {});
}

// Temporaries and macros.

/// Traits named like the runtime's, from another crate.
mod local {
    pub trait Supervisor: Sized {
        fn child(&self, name: &'static str) -> Self;
    }

    pub trait Spawner: Sized {
        fn spawn(self, f: impl FnOnce());
    }

    pub struct Local;

    impl Supervisor for Local {
        fn child(&self, _: &'static str) -> Self {
            Self
        }
    }

    impl Spawner for Local {
        fn spawn(self, _: impl FnOnce()) {}
    }

    pub fn same_names(local: &Local) {
        local.child("a").child("b").spawn(|| {});
    }
}

macro_rules! chain {
    ($ctx:expr) => {
        $ctx.child("a").child("b").spawn(|| {})
    };
}

#[rustfmt::skip]
async fn temporaries(ctx: &Context) {
    // Fires: the block drops the parent before `block_on` gets the handle.
    block_on({ ctx.child("a").child("b").spawn(|| {}) });

    // Silent: a `super let` keeps its temporaries until the end of the statement.
    block_on({
        super let handle = ctx.child("a").child("b").spawn(|| {});
        handle
    });

    // Silent: the chain comes from a macro.
    chain!(ctx);
}

fn main() {}
