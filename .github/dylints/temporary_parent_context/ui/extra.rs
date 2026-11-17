// aux-build:commonware_runtime.rs
// aux-build:old_macros.rs
// compile-flags: --edition=2024
#![feature(super_let)]
#![allow(
    unused_must_use,
    dead_code,
    unused_unsafe,
    unused_assignments,
    unused_variables,
    unused_labels,
    unused_braces,
    irrefutable_let_patterns
)]
extern crate commonware_runtime;
extern crate old_macros;

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

/// A runtime Supervisor whose spawn is not the runtime's.
struct MetricsOnly;

impl Supervisor for MetricsOnly {
    fn child(&self, _: &'static str) -> Self {
        Self
    }

    fn with_attribute(self, _: &'static str, _: &'static str) -> Self {
        self
    }
}

impl MetricsOnly {
    fn spawn(self, _: impl FnOnce()) {}
}

/// Traits with the runtime's names that live in another crate.
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
        // SILENT: not the runtime's traits.
        local.child("a").child("b").spawn(|| {});
    }
}

struct Wrapper {
    handle: Ready<()>,
}

trait Wrap: Sized {
    fn wrap(self) -> Wrapper;
}

impl Wrap for Ready<()> {
    fn wrap(self) -> Wrapper {
        Wrapper { handle: self }
    }
}

fn block_on<F: Future>(_: F) {}

macro_rules! chain {
    ($ctx:expr) => {
        $ctx.child("a").child("b").spawn(|| {})
    };
}

macro_rules! statement {
    ($e:expr) => {
        $e;
    };
}

// Every one of these is a defect, so each should fire.

#[rustfmt::skip]
fn block_tails(ctx: &Context, flag: bool) {
    // FIRE: plain block tail.
    let _plain = { ctx.child("a").child("b").spawn(|| {}) };
    // FIRE: if branch tail.
    let _branch = if flag {
        ctx.child("a").child("b").spawn(|| {})
    } else {
        ready(())
    };
    // FIRE: match arm block tail.
    let _arm = match flag {
        _ => {
            ctx.child("a").child("b").spawn(|| {})
        }
    };
    // FIRE: unsafe block tail.
    let _unsafe = unsafe { ctx.child("a").child("b").spawn(|| {}) };
    // FIRE: labeled block tail.
    let _labeled = 'label: { ctx.child("a").child("b").spawn(|| {}) };
    // FIRE: async block tail.
    let _async = async { ctx.child("a").child("b").spawn(|| {}) };
    // FIRE: block tail used in the same statement (edition 2024 drops the parent first).
    block_on({ ctx.child("a").child("b").spawn(|| {}) });
}

fn let_else(ctx: &Context) {
    // FIRE
    let _handle = ctx.child("a").child("b").spawn(|| {}) else {
        return;
    };
}

fn three(ctx: &Context) {
    // FIRE
    ctx.child("a").child("b").child("c").spawn(|| {});
}

fn underscore(ctx: &Context) {
    // FIRE
    let _ = ctx.child("a").child("b").spawn(|| {});
}

#[rustfmt::skip]
fn closure_block(ctx: &Context) {
    // FIRE
    let _spawn = || {
        ctx.child("a").child("b").spawn(|| {})
    };
}

fn boxed(ctx: &Box<Context>) {
    // FIRE: receiver reached through auto-deref.
    ctx.child("a").child("b").spawn(|| {});
}

async fn async_tail(ctx: &Context) -> Ready<()> {
    // FIRE
    ctx.child("a").child("b").spawn(|| {})
}

fn macro_statement(ctx: &Context) {
    // FIRE: the macro turns the handle into a discarded statement.
    statement!(ctx.child("a").child("b").spawn(|| {}));
}

// Missed defects and correct code: none of these should fire.

fn used_in_statement(ctx: &Context, handles: &mut Vec<Ready<()>>) {
    // SILENT (missed defect): pushed into a collection.
    handles.push(ctx.child("a").child("b").spawn(|| {}));
    // SILENT (missed defect): a method wraps the handle.
    let _wrapped = ctx.child("a").child("b").spawn(|| {}).wrap();
    // SILENT (missed defect): stored in a struct literal.
    let _stored = Wrapper {
        handle: ctx.child("a").child("b").spawn(|| {}),
    };
    // SILENT (missed defect): assigned.
    let mut slot = ready(());
    slot = ctx.child("a").child("b").spawn(|| {});
    // SILENT (missed defect): match arm value without a block.
    let _arm = match () {
        () => ctx.child("a").child("b").spawn(|| {}),
    };
    // SILENT (missed defect): break value.
    let _broken = loop {
        break ctx.child("a").child("b").spawn(|| {});
    };
    // SILENT (missed defect): borrowed handle.
    let _borrowed = &ctx.child("a").child("b").spawn(|| {});
}

fn moved_parent(ctx: Context) {
    // SILENT (missed defect): the parent is moved into the chain.
    ctx.with_attribute("k", "v").child("b").spawn(|| {});
}

fn qualified(ctx: &Context) {
    // SILENT (missed defects): not method-call chains.
    Spawner::spawn(ctx.child("a").child("b"), || {});
    Supervisor::child(&ctx.child("a"), "b").spawn(|| {});
    (&ctx.child("a")).child("b").spawn(|| {});
}

fn expanded(ctx: &Context) {
    // SILENT (missed defect): the chain comes from a macro.
    chain!(ctx);
}

fn unrelated_spawn() {
    // SILENT: runtime children, unrelated spawn.
    MetricsOnly.child("a").child("b").spawn(|| {});
}

async fn old_edition_block(ctx: &Context) {
    // SILENT (correct code): the block comes from a macro of an older edition, so the
    // temporaries of its tail live until the end of this statement.
    old_macros::wrap!(ctx.child("a").child("b").spawn(|| {})).await;
    block_on(old_macros::wrap!(ctx.child("a").child("b").spawn(|| {})));
}

fn super_let(ctx: &Context) {
    // SILENT (correct code): the temporaries of a super let initializer live until
    // the end of the statement enclosing its block.
    block_on({
        super let handle = ctx.child("a").child("b").spawn(|| {});
        handle
    });
}

fn main() {}
