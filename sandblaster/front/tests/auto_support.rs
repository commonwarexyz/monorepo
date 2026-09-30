//! Shared helpers for the `auto` tests (included by the `auto_*.rs` test
//! crates with `#[path = "auto_support.rs"] mod support;`): environments
//! with the prelude and the prelude lemmas, goals written in core text
//! (DESIGN.md §5.12), and a prover driver that re-checks every produced
//! term with the kernel.
#![allow(dead_code)]

use std::rc::Rc;

use sandblaster_front::auto::{Auto, AutoConfig};
use sandblaster_front::prover::{AutoFailure, FactOrigin, FactRef, Goal, Hint, ObligationId, ObligationKind, Prover};
use sandblaster_front::span::Span;
use sandblaster_kernel::api::{Ctx, CtxEntry, Env};
use sandblaster_kernel::term::{Lvl, Name, Rel, Tm};
use sandblaster_kernel::value::{Budget, V};

/// Run `f` on a thread with a large stack (the kernel and the search are
/// recursive), with an environment holding the prelude and the lemmas.
pub fn run<T: Send + 'static>(f: impl FnOnce(&mut Env) -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 30)
        .spawn(move || {
            sandblaster_kernel::util::set_stack_limit(900 << 20);
            let mut env = Env::with_prelude();
            if let Err(e) = sandblaster_front::auto::lemmas::load(&mut env) {
                panic!("prelude lemmas failed to load: {e}");
            }
            f(&mut env)
        })
        .expect("spawn")
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e))
}

/// A budget for kernel calls of the tests themselves (loading definitions,
/// re-checking terms).
pub fn budget() -> Budget {
    Budget { steps: 2_000_000_000 }
}

/// The budget of one `auto` call: the elaborator's default goal budget
/// (20M steps, `elab::Options::goal_budget`), overridable with
/// `AUTO_TEST_BUDGET`.
pub fn goal_budget() -> Budget {
    let steps = std::env::var("AUTO_TEST_BUDGET").ok().and_then(|s| s.parse().ok()).unwrap_or(20_000_000);
    Budget { steps }
}

/// A goal context built from core-text binders `(name, type)`; a leading
/// `.` marks an irrelevant binder (a fact). `name := value : type` binders
/// are written as `("name", "type", Some("value"))` through [`GoalBuilder::def`].
#[derive(Clone)]
pub struct GoalBuilder<'e> {
    pub env: &'e Env,
    pub ctx: Ctx,
    pub names: Vec<&'static str>,
    pub facts: Vec<FactRef>,
    pub hints: Vec<Hint>,
}

impl<'e> GoalBuilder<'e> {
    pub fn new(env: &'e Env) -> Self {
        GoalBuilder { env, ctx: Ctx::default(), names: Vec::new(), facts: Vec::new(), hints: Vec::new() }
    }

    pub fn parse(&self, src: &str) -> Tm {
        self.env.parse_term(&self.names, src).unwrap_or_else(|e| panic!("parse `{src}`: {e}"))
    }

    pub fn eval(&self, t: &Tm) -> V {
        self.env.eval(&self.env.ctx_venv(&self.ctx), self.ctx.depth(), t, &mut budget()).expect("eval")
    }

    /// Add a binder.
    pub fn bind(mut self, name: &str, ty: &str) -> Self {
        let rel = if name.starts_with('.') { Rel::Irr } else { Rel::Rel };
        let n: &'static str = Box::leak(name.trim_start_matches('.').to_string().into_boxed_str());
        let tyv = self.eval(&self.parse(ty));
        let lvl = self.ctx.depth();
        if rel == Rel::Irr {
            self.facts.push(FactRef { lvl, origin: FactOrigin::PathCond, span: Span::DUMMY });
        }
        self.ctx = self.ctx.push(CtxEntry { name: Rc::from(n), rel, ty: tyv, def: None });
        self.names.push(n);
        self
    }

    /// Add several binders.
    pub fn binds(mut self, bs: &[(&str, &str)]) -> Self {
        for (n, t) in bs {
            self = self.bind(n, t);
        }
        self
    }

    /// Add a relevant let-bound binder `name : ty := val`.
    pub fn def(mut self, name: &str, ty: &str, val: &str) -> Self {
        let n: &'static str = Box::leak(name.to_string().into_boxed_str());
        let tyv = self.eval(&self.parse(ty));
        let vv = self.eval(&self.parse(val));
        self.ctx = self.ctx.push(CtxEntry { name: Rc::from(n), rel: Rel::Rel, ty: tyv, def: Some(sandblaster_kernel::value::Arg::Rel(vv)) });
        self.names.push(n);
        self
    }

    pub fn hint(mut self, h: Hint) -> Self {
        self.hints.push(h);
        self
    }

    /// The goal with the given target.
    pub fn goal(&self, target: &str) -> Goal {
        let t = self.eval(&self.parse(target));
        Goal {
            id: ObligationId(0),
            kind: ObligationKind::Assert,
            span: Span::DUMMY,
            ctx: self.ctx.clone(),
            facts: self.facts.clone(),
            target: t,
            hints: self.hints.clone(),
        }
    }

    pub fn names(&self) -> Vec<Name> {
        self.names.iter().map(|n| Rc::from(*n)).collect()
    }
}

/// Prove with the default configuration and re-check the term with the
/// kernel (independently of `auto`'s own self-check).
pub fn prove(env: &Env, g: &Goal) -> Result<Tm, AutoFailure> {
    prove_with(env, g, AutoConfig::default())
}

pub fn prove_with(env: &Env, g: &Goal, cfg: AutoConfig) -> Result<Tm, AutoFailure> {
    let mut auto = Auto::with_config(cfg);
    let mut b = goal_budget();
    let t = auto.prove(env, g, &mut b)?;
    if let Err(e) = env.check(&g.ctx, &t, &g.target, &mut budget()) {
        panic!("kernel rejected auto's term: {e}\nterm: {}", env.print_term(&ctx_names(&g.ctx), &t));
    }
    Ok(t)
}

pub fn ctx_names(ctx: &Ctx) -> Vec<Name> {
    ctx.entries.iter().map(|e| e.name.clone()).collect()
}

/// Assert that a goal is proved (kernel-checked); print the failure
/// otherwise.
pub fn assert_proves(env: &Env, g: &Goal) -> Tm {
    match prove(env, g) {
        Ok(t) => t,
        Err(f) => panic!("auto failed:\n  goal: {}\n  facts: {:#?}\n  stuck: {:#?}\n  tried: {:#?}", f.goal, f.facts, f.stuck, f.tried),
    }
}

/// Assert that a goal is **not** proved.
pub fn assert_fails(env: &Env, g: &Goal) -> AutoFailure {
    match prove(env, g) {
        Ok(t) => panic!("auto proved a goal that should fail: {}", env.print_term(&ctx_names(&g.ctx), &t)),
        Err(f) => f,
    }
}

/// Level of a named binder.
pub fn lvl(b: &GoalBuilder<'_>, name: &str) -> Lvl {
    Lvl(b.names.iter().position(|n| *n == name).expect("binder") as u32)
}

impl<'e> GoalBuilder<'e> {
    /// A `linarith` proof term (core text) of `goal` from hypothesis
    /// binders `hyps` (by name), with the certificate found by `auto`'s
    /// simplex — for proofs embedded in goal types (proof slots).
    pub fn lin(&self, hyps: &[&str], goal: &str) -> String {
        let mut hs = Vec::new();
        for h in hyps {
            let l = self.names.iter().position(|n| n == h).expect("hyp binder");
            let ty = &self.ctx.entries[l].ty;
            let stated = self.env.quote_typed(&self.ctx, ty, None, false);
            hs.push((self.parse(h), stated));
        }
        let g = self.parse(goal);
        let sys = self.env.linearize(&self.ctx, &hs, &g, &mut budget()).expect("linearize");
        let cert = sandblaster_front::auto::simplex::certificate(&sys).unwrap_or_else(|| panic!("no certificate for {goal}"));
        let t = std::rc::Rc::new(sandblaster_kernel::term::Term::Linarith { hyps: hs, goal: g, cert });
        self.env.print_term(&self.names(), &t)
    }
}
