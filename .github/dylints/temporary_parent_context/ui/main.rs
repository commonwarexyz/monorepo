// aux-build:commonware_runtime.rs
// compile-flags: --edition=2024
#![allow(unused_must_use, dead_code)]
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
}

/// Traits named like the runtime's, from another crate.
mod local {
    pub trait Supervisor: Sized {
        fn child(&self, name: &'static str) -> Self;
    }

    pub struct Local;

    impl Supervisor for Local {
        fn child(&self, _: &'static str) -> Self {
            Self
        }
    }

    pub fn same_names(local: &Local) {
        let _ = local.child("a").child("b");
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

macro_rules! chain {
    ($ctx:expr) => {
        $ctx.child("a").child("b")
    };
}

// The parent of each of these children is a temporary, so each fires.

async fn fires(ctx: &Context) {
    let _bound = ctx.child("a").child("b");
    ctx.child("a").child("b").spawn(|| {});
    ctx.child("a").child("b").spawn(|| {}).await;
    let _metrics = ctx.child("a").with_attribute("k", "v").child("b");
    let _shared = ctx.child("a").shared(true).child("b");
    let _dedicated = ctx.child("a").dedicated().child("b");
}

fn generic<E: Supervisor>(ctx: &E) {
    let _ = ctx.child("a").child("b");
}

impl Holder {
    fn field(&self) {
        let _ = self.context.child("a").child("b");
    }
}

// None of these fire.

fn silent(holder: &Holder, ctx: &Context, kept: &mut Vec<Context>) {
    let parent = ctx.child("a");
    let _ = parent.child("b");
    let _ = holder.context.child("a");
    let _ = ctx.child("a").keep(kept).child("b");
    let _ = Unrelated.child("a").child("b");
    let _ = chain!(ctx);
}

fn main() {}
