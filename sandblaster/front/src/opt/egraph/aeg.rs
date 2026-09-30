//! The acyclic e-graph of one straight-line region (optimizer design §10.1;
//! plan O8).
//!
//! A region is the quoted value of a straight-line residual: a term tree
//! over the function's parameters (no binders it descends into). Its
//! subterms are hash-consed into **classes** — structurally equal subterms
//! (irrelevant proof arguments ignored) share one class — so the region is a
//! DAG. Rewrites only ever add an alternative to an existing class whose
//! children are strict descendants of it, so the graph stays acyclic by
//! construction: extraction is a bottom-up pass, never a fixpoint.
//!
//! Only primitive applications, literals and parameters are nodes; any
//! other subterm (an opaque call, a constructor, a match) is a **leaf**
//! class keyed by its fingerprint and compared by α-equivalence, so the
//! aegraph never rewrites inside it. The graph is bounded: at most
//! [`MAX_NODES`] classes (design §17: 10^4 e-nodes), else it is not built.

use std::collections::HashMap;

use sandblaster_kernel::api::Env;
use sandblaster_kernel::term::{Idx, PrimOp, Term, Tm, Width};

use super::rules::{Hist, KINDS, kind};

/// The aegraph's node budget (design §17).
pub const MAX_NODES: usize = 10_000;

pub type Class = u32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    Prim(PrimOp),
    Lit(Width, String),
    /// A parameter (de Bruijn index at the region's root).
    Var(u32),
    /// Any other subterm (its fingerprint and a disambiguating index).
    Leaf(u64, u32),
}

#[derive(Clone, Debug)]
pub struct Node {
    pub op: Op,
    pub kids: Vec<Class>,
    /// The region's subterm this class stands for (the first occurrence).
    pub term: Tm,
    /// The value's machine width, when known.
    pub width: Option<Width>,
    /// Primitive nodes in the subtree (tree count, saturating).
    pub size: u32,
    pub hist: Hist,
}

/// The e-graph (see the module docs).
#[derive(Default)]
pub struct EGraph {
    pub nodes: Vec<Node>,
    memo: HashMap<(Op, Vec<Class>), Class>,
    leaves: Vec<Tm>,
}

impl EGraph {
    /// Builds the graph of `root` (a term at depth `params`, whose
    /// parameter `i` has width `param_width(i)`); `None` over budget.
    pub fn build(env: &Env, root: &Tm, param_width: &dyn Fn(u32) -> Option<Width>) -> Option<(EGraph, Class)> {
        let mut g = EGraph::default();
        let c = g.add(env, root, param_width)?;
        Some((g, c))
    }

    fn intern(&mut self, op: Op, kids: Vec<Class>, term: &Tm, width: Option<Width>) -> Option<Class> {
        if let Some(c) = self.memo.get(&(op.clone(), kids.clone())) {
            return Some(*c);
        }
        if self.nodes.len() >= MAX_NODES {
            return None;
        }
        let mut hist: Hist = [0; KINDS];
        let mut size = 0u32;
        if let Op::Prim(p) = &op {
            hist[kind(p)] = 1;
            size = 1;
        }
        for k in &kids {
            let n = &self.nodes[*k as usize];
            size = size.saturating_add(n.size);
            for (h, x) in hist.iter_mut().zip(n.hist.iter()) {
                *h = h.saturating_add(*x);
            }
        }
        let c = self.nodes.len() as Class;
        self.nodes.push(Node { op: op.clone(), kids: kids.clone(), term: term.clone(), width, size, hist });
        self.memo.insert((op, kids), c);
        Some(c)
    }

    fn add(&mut self, env: &Env, t: &Tm, pw: &dyn Fn(u32) -> Option<Width>) -> Option<Class> {
        match &**t {
            Term::Prim { op, args, .. } => {
                let mut kids = Vec::with_capacity(args.len());
                for a in args {
                    kids.push(self.add(env, a, pw)?);
                }
                let width = match sandblaster_kernel::prim::prim_sig(*op)?.result {
                    sandblaster_kernel::prim::PrimTy::Int(w) => Some(w),
                    sandblaster_kernel::prim::PrimTy::Bool => None,
                };
                self.intern(Op::Prim(*op), kids, t, width)
            }
            Term::Lit { w, n } => self.intern(Op::Lit(*w, n.to_string()), vec![], t, Some(*w)),
            Term::Var(Idx(i)) => self.intern(Op::Var(*i), vec![], t, pw(*i)),
            _ => {
                // a leaf: α-equivalent leaves share a class
                let fp = crate::elab::tm::fingerprint(t);
                let mut k = 0u32;
                for (i, l) in self.leaves.iter().enumerate() {
                    if crate::elab::tm::fingerprint(l) == fp {
                        if env.alpha_eq_relevant(l, t, &|a, b| a == b) {
                            return self.memo.get(&(Op::Leaf(fp, i as u32), vec![])).copied();
                        }
                        k += 1;
                    }
                }
                let _ = k;
                let idx = self.leaves.len() as u32;
                self.leaves.push(t.clone());
                self.intern(Op::Leaf(fp, idx), vec![], t, None)
            }
        }
    }

    /// How often each class occurs below `root` (tree count, capped), in
    /// class order.
    pub fn occurrences(&self, root: Class) -> Vec<(Class, u32)> {
        let mut count: Vec<u32> = vec![0; self.nodes.len()];
        // counts by path multiplicity: process classes top-down in reverse
        // creation order (children are created before parents)
        let mut paths: Vec<u64> = vec![0; self.nodes.len()];
        paths[root as usize] = 1;
        for c in (0..=root as usize).rev() {
            let p = paths[c];
            if p == 0 {
                continue;
            }
            count[c] = u32::try_from(p.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
            for k in &self.nodes[c].kids {
                paths[*k as usize] = paths[*k as usize].saturating_add(p);
            }
        }
        count.into_iter().enumerate().filter(|(_, n)| *n > 0).map(|(c, n)| (c as Class, n)).collect()
    }

    /// Whether `a` is `b` or below it.
    pub fn below(&self, a: Class, b: Class) -> bool {
        if a > b {
            return false;
        }
        let mut seen = vec![false; b as usize + 1];
        let mut stack = vec![b];
        while let Some(c) = stack.pop() {
            if c == a {
                return true;
            }
            if c < a || std::mem::replace(&mut seen[c as usize], true) {
                continue;
            }
            stack.extend(self.nodes[c as usize].kids.iter().copied());
        }
        false
    }
}
