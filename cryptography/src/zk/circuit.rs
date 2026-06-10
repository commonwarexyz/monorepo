//! Utilities for creating arithmetic circuits.

use commonware_math::algebra::{Additive, Field, Multiplicative, Object, Ring};
use commonware_utils::sync::Mutex;
use std::{
    fmt,
    marker::PhantomData,
    ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CircuitIdx {
    Constant(u32),
    Witness(u32),
    Node(u32),
}

pub(crate) enum CircuitNode {
    Add(CircuitIdx, CircuitIdx),
    Mul(CircuitIdx, CircuitIdx),
}

pub struct Circuit<F> {
    pub(crate) witnesses: u32,
    pub(crate) constants: Vec<F>,
    pub(crate) nodes: Vec<CircuitNode>,
    pub(crate) assertions: Vec<(CircuitIdx, CircuitIdx)>,
}

impl<F> Default for Circuit<F> {
    fn default() -> Self {
        Self {
            witnesses: 0,
            constants: Vec::new(),
            nodes: Vec::new(),
            assertions: Vec::new(),
        }
    }
}

impl<F> Circuit<F> {
    const fn next_witness(&mut self) -> CircuitIdx {
        let next = CircuitIdx::Witness(self.witnesses);
        self.witnesses += 1;
        next
    }

    fn next_constant(&mut self, x: F) -> CircuitIdx {
        let next = CircuitIdx::Constant(self.constants.len() as u32);
        self.constants.push(x);
        next
    }

    fn next_node(&mut self, n: CircuitNode) -> CircuitIdx {
        let next = CircuitIdx::Node(self.nodes.len() as u32);
        self.nodes.push(n);
        next
    }
}

/// A circuit together with concrete values for every witness and every node.
///
/// Populated incrementally by [`build_with_values`] as the circuit is
/// constructed in prover mode. Witness indices resolve to `witnesses[i]`, and
/// node indices to `nodes[i]`.
pub struct ValuedCircuit<F> {
    pub(crate) circuit: Circuit<F>,
    pub(crate) witnesses: Vec<F>,
    pub(crate) nodes: Vec<F>,
}

#[doc(hidden)]
impl<F> Index<CircuitIdx> for ValuedCircuit<F> {
    type Output = F;

    fn index(&self, index: CircuitIdx) -> &Self::Output {
        match index {
            CircuitIdx::Constant(i) => &self.circuit.constants[i as usize],
            CircuitIdx::Witness(i) => &self.witnesses[i as usize],
            CircuitIdx::Node(i) => &self.nodes[i as usize],
        }
    }
}

impl<F: PartialEq> ValuedCircuit<F> {
    /// Checks whether the values assigned to this circuit satisfy its assertions.
    #[must_use]
    pub fn is_satisfied(&self) -> bool {
        self.circuit
            .assertions
            .iter()
            .all(|&(a, b)| self[a] == self[b])
    }
}

struct ValuesBuilder<F> {
    witnesses: Vec<F>,
    nodes: Vec<F>,
}

/// A snapshot of the circuit's storage during prover-mode construction, passed
/// to recipe closures so they can compute values from already-allocated
/// witnesses, constants, and node outputs.
///
/// Holds locks on the underlying state for its lifetime, so closures receiving
/// a view must not call back into the [`Context`].
#[derive(Clone, Copy)]
pub struct Values<'a, F> {
    constants: &'a [F],
    witnesses: &'a [F],
    nodes: &'a [F],
}

#[doc(hidden)]
impl<'a, F> Index<CircuitIdx> for Values<'a, F> {
    type Output = F;

    fn index(&self, index: CircuitIdx) -> &Self::Output {
        match index {
            CircuitIdx::Witness(id) => &self.witnesses[id as usize],
            CircuitIdx::Constant(id) => &self.constants[id as usize],
            CircuitIdx::Node(id) => &self.nodes[id as usize],
        }
    }
}

struct ContextInner<F> {
    values: Option<Mutex<ValuesBuilder<F>>>,
    circuit: Mutex<Circuit<F>>,
}

pub struct Context<'ctx, F> {
    inner: &'ctx ContextInner<F>,
    /// Make this struct invariant in 'ctx, so two Contexts from different
    /// `build` calls have incompatible types.
    _brand: PhantomData<fn(&'ctx ()) -> &'ctx ()>,
}

impl<F> Clone for Context<'_, F> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<F> Copy for Context<'_, F> {}

impl<'ctx, F> Context<'ctx, F> {
    fn allocate_constant(self, combine: impl Fn(&[F]) -> F) -> CircuitIdx {
        let mut circuit = self.inner.circuit.lock();
        let combined = combine(&circuit.constants);
        circuit.next_constant(combined)
    }

    fn allocate(
        self,
        init: impl for<'a> FnOnce(Values<'a, F>) -> Option<F>,
        reserve: impl FnOnce(&mut Circuit<F>) -> CircuitIdx,
    ) -> CircuitIdx {
        let mut circuit = self.inner.circuit.lock();
        if let Some(values) = &self.inner.values {
            let mut values = values.lock();
            let value = init(Values {
                constants: &circuit.constants,
                witnesses: &values.witnesses,
                nodes: &values.nodes,
            });
            let idx = reserve(&mut circuit);
            match idx {
                CircuitIdx::Witness(_) => {
                    values
                        .witnesses
                        .push(value.expect("witness allocations populate prover assignments"));
                }
                CircuitIdx::Node(_) => {
                    values
                        .nodes
                        .push(value.expect("node allocations populate prover assignments"));
                }
                CircuitIdx::Constant(_) => {
                    assert!(
                        value.is_none(),
                        "constants do not populate prover assignments"
                    );
                }
            }
            return idx;
        }

        reserve(&mut circuit)
    }

    /// Push a node into the circuit. In prover mode, `init` runs with read
    /// access to the current circuit values so it can compute the node's
    /// value, which is appended in lockstep with the node.
    fn node(self, n: CircuitNode, init: impl for<'a> FnOnce(Values<'a, F>) -> F) -> CircuitIdx {
        self.allocate(|values| Some(init(values)), |circuit| circuit.next_node(n))
    }

    fn assert_eq(self, a: CircuitIdx, b: CircuitIdx) {
        self.inner.circuit.lock().assertions.push((a, b));
    }

    /// Allocate a fresh witness slot. In prover mode, `init` runs with read
    /// access to the current circuit values to compute the witness value.
    fn witness(self, init: impl for<'a> FnOnce(Values<'a, F>) -> F) -> CircuitIdx {
        self.allocate(|values| Some(init(values)), Circuit::next_witness)
    }
}

impl<'ctx, F> Context<'ctx, F> {
    fn constant(self, x: F) -> CircuitIdx {
        self.allocate(|_| None, |circuit| circuit.next_constant(x))
    }
}

#[derive(Clone)]
enum VarInner<'ctx, F> {
    Native(F),
    Circuit {
        ctx: Context<'ctx, F>,
        idx: CircuitIdx,
    },
}

#[derive(Clone)]
pub struct Var<'ctx, F> {
    inner: VarInner<'ctx, F>,
}

impl<F: fmt::Debug> fmt::Debug for Var<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            VarInner::Native(value) => f.debug_tuple("Native").field(value).finish(),
            VarInner::Circuit { ctx, idx } => {
                let ctx_ptr = ctx.inner as *const ContextInner<F>;
                f.debug_struct("Circuit")
                    .field("ctx", &ctx_ptr)
                    .field("idx", idx)
                    .finish()
            }
        }
    }
}

impl<F: PartialEq> PartialEq for Var<'_, F> {
    fn eq(&self, other: &Self) -> bool {
        match (&self.inner, &other.inner) {
            (VarInner::Native(a), VarInner::Native(b)) => a == b,
            (VarInner::Circuit { idx: a_idx, .. }, VarInner::Circuit { idx: b_idx, .. }) => {
                a_idx == b_idx
            }
            _ => false,
        }
    }
}

impl<F: Eq> Eq for Var<'_, F> {}

impl<'ctx, F> Var<'ctx, F> {
    pub fn witness(ctx: Context<'ctx, F>, init: impl for<'a> FnOnce(Values<'a, F>) -> F) -> Self {
        Self {
            inner: VarInner::Circuit {
                ctx,
                idx: ctx.witness(init),
            },
        }
    }

    pub fn constant(ctx: Context<'ctx, F>, value: F) -> Self {
        Self {
            inner: VarInner::Circuit {
                ctx,
                idx: ctx.constant(value),
            },
        }
    }

    pub fn assert_eq(&self, other: &Self)
    where
        F: Clone + PartialEq,
    {
        match (&self.inner, &other.inner) {
            (VarInner::Native(a), VarInner::Native(b)) => {
                assert!(a == b, "asserted equality between distinct native vars");
            }
            (VarInner::Native(a), VarInner::Circuit { ctx, idx })
            | (VarInner::Circuit { ctx, idx }, VarInner::Native(a)) => {
                ctx.assert_eq(Self::constant(*ctx, a.clone()).circuit_idx(), *idx);
            }
            (VarInner::Circuit { ctx, idx: a }, VarInner::Circuit { idx: b, .. }) => {
                ctx.assert_eq(*a, *b);
            }
        }
    }

    fn circuit_idx(&self) -> CircuitIdx {
        match self.inner {
            VarInner::Circuit { idx, .. } => idx,
            VarInner::Native(_) => panic!("expected circuit-backed var"),
        }
    }
}

impl<'ctx, F: Clone> Var<'ctx, F> {
    pub fn value(&self, values: Values<'_, F>) -> F {
        match &self.inner {
            VarInner::Native(value) => value.clone(),
            VarInner::Circuit { idx, .. } => values[*idx].clone(),
        }
    }

    /// Combine `self` and `other` with a commutative binary operation.
    ///
    /// `combine` is the value-level operation used both for the all-native case
    /// and for prover-mode node evaluation. `node` is the circuit node
    /// constructor (for example `CircuitNode::Add` or `CircuitNode::Mul`).
    fn merge(
        self,
        other: &Self,
        combine: impl Fn(&F, &F) -> F,
        node: fn(CircuitIdx, CircuitIdx) -> CircuitNode,
    ) -> Self {
        let (ctx, a_idx, b_idx) = match (self.inner, &other.inner) {
            (VarInner::Native(a), VarInner::Native(b)) => {
                return Self {
                    inner: VarInner::Native(combine(&a, b)),
                }
            }
            (VarInner::Native(ref a), &VarInner::Circuit { ctx, idx: b_idx })
            | (VarInner::Circuit { ctx, idx: b_idx }, &VarInner::Native(ref a)) => {
                (ctx, Self::constant(ctx, a.clone()).circuit_idx(), b_idx)
            }
            (VarInner::Circuit { ctx, idx: a }, &VarInner::Circuit { idx: b, .. }) => (ctx, a, b),
        };
        if let (CircuitIdx::Constant(a_idx), CircuitIdx::Constant(b_idx)) = (a_idx, b_idx) {
            return Self {
                inner: VarInner::Circuit {
                    ctx,
                    idx: ctx.allocate_constant(|constants| {
                        combine(&constants[a_idx as usize], &constants[b_idx as usize])
                    }),
                },
            };
        }
        let new_idx = ctx.node(node(a_idx, b_idx), move |v| combine(&v[a_idx], &v[b_idx]));
        Self {
            inner: VarInner::Circuit { ctx, idx: new_idx },
        }
    }
}

impl<'ctx, F: Object> Object for Var<'ctx, F> {}

impl<'ctx, F: Additive> Add<&Self> for Var<'ctx, F> {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self {
        self.merge(rhs, |a, b| a.clone() + b, CircuitNode::Add)
    }
}

impl<'ctx, F: Additive> AddAssign<&Self> for Var<'ctx, F> {
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.clone() + rhs;
    }
}

impl<'ctx, F: Additive + Ring> Neg for Var<'ctx, F> {
    type Output = Self;
    fn neg(self) -> Self {
        match self.inner {
            VarInner::Native(a) => Self {
                inner: VarInner::Native(-a),
            },
            VarInner::Circuit {
                ctx,
                idx: CircuitIdx::Constant(idx),
            } => Self {
                inner: VarInner::Circuit {
                    ctx,
                    idx: ctx.allocate_constant(|constants| -constants[idx as usize].clone()),
                },
            },
            VarInner::Circuit { ctx, idx } => {
                let minus_one = Var::constant(ctx, -F::one()).circuit_idx();
                let new_idx = ctx.node(CircuitNode::Mul(minus_one, idx), move |v| -v[idx].clone());
                Self {
                    inner: VarInner::Circuit { ctx, idx: new_idx },
                }
            }
        }
    }
}

impl<'ctx, F: Additive + Ring> Sub<&Self> for Var<'ctx, F> {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        self + &(-rhs.clone())
    }
}

impl<'ctx, F: Additive + Ring> SubAssign<&Self> for Var<'ctx, F> {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = self.clone() - rhs;
    }
}

impl<'ctx, F: Multiplicative> Mul<&Self> for Var<'ctx, F> {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self {
        self.merge(rhs, |a, b| a.clone() * b, CircuitNode::Mul)
    }
}

impl<'ctx, F: Multiplicative> MulAssign<&Self> for Var<'ctx, F> {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = self.clone() * rhs;
    }
}

impl<'ctx, F: Additive + Ring> Additive for Var<'ctx, F> {
    fn zero() -> Self {
        Self {
            inner: VarInner::Native(F::zero()),
        }
    }
}

impl<'ctx, F: Multiplicative> Multiplicative for Var<'ctx, F> {}

impl<'ctx, F: Ring> Ring for Var<'ctx, F> {
    fn one() -> Self {
        Self {
            inner: VarInner::Native(F::one()),
        }
    }
}

impl<'ctx, F: Field> Field for Var<'ctx, F> {
    fn inv(&self) -> Self {
        match &self.inner {
            VarInner::Native(c) => Self {
                inner: VarInner::Native(c.inv()),
            },
            &VarInner::Circuit { ctx, .. } => {
                // Prover supplies the inverse via the oracle; verifier just
                // allocates the slot.
                let inv = Self::witness(ctx, |v| self.value(v).inv());
                (inv.clone() * self).assert_eq(&Self::one());
                inv
            }
        }
    }
}

/// Build a circuit without computing a witness assignment (verifier mode).
pub fn build<F: Ring + PartialEq>(f: impl for<'ctx> FnOnce(Context<'ctx, F>)) -> Circuit<F> {
    let inner = ContextInner {
        values: None,
        circuit: Mutex::new(Circuit::default()),
    };
    f(Context {
        inner: &inner,
        _brand: PhantomData,
    });
    inner.circuit.into_inner()
}

/// Build a circuit while simultaneously computing the assignment (prover mode).
pub fn build_with_values<F: Ring + PartialEq>(
    f: impl for<'ctx> FnOnce(Context<'ctx, F>),
) -> ValuedCircuit<F> {
    let inner = ContextInner {
        values: Some(Mutex::new(ValuesBuilder {
            witnesses: Vec::new(),
            nodes: Vec::new(),
        })),
        circuit: Mutex::new(Circuit::default()),
    };
    f(Context {
        inner: &inner,
        _brand: PhantomData,
    });
    let circuit = inner.circuit.into_inner();
    let values = inner.values.unwrap().into_inner();
    ValuedCircuit {
        circuit,
        witnesses: values.witnesses,
        nodes: values.nodes,
    }
}

#[commonware_macros::stability(ALPHA)]
#[cfg(any(test, feature = "fuzz"))]
pub mod fuzz {
    use super::*;
    use arbitrary::{Arbitrary, Unstructured};
    use commonware_math::test::F;

    #[derive(Debug)]
    enum Op {
        Witness(F),
        Constant(F),
        Zero,
        One,
        Add(usize, usize),
        Sub(usize, usize),
        Mul(usize, usize),
        Neg(usize),
        Inv(usize),
        AssertEq(usize, usize),
    }

    /// A random sequence of circuit operations, together with whether the
    /// circuit they build should be satisfied.
    ///
    /// Values are drawn from a small range so that assertions have a decent
    /// chance of holding, exercising both outcomes.
    #[derive(Debug)]
    pub struct Plan {
        ops: Vec<Op>,
        satisfied: bool,
    }

    impl Arbitrary<'_> for Plan {
        fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
            let mut ops = Vec::new();
            let mut values: Vec<F> = Vec::new();
            let mut is_native: Vec<bool> = Vec::new();
            let mut satisfied = true;
            for _ in 0..u.int_in_range(1..=32)? {
                let kind = if values.is_empty() {
                    u.int_in_range(0..=3)?
                } else {
                    u.int_in_range(0..=9)?
                };
                if kind <= 3 {
                    let v = F::from(u.int_in_range::<u8>(0..=4)?);
                    let (op, value, native) = match kind {
                        0 => (Op::Witness(v), v, false),
                        1 => (Op::Constant(v), v, false),
                        2 => (Op::Zero, F::zero(), true),
                        _ => (Op::One, F::one(), true),
                    };
                    ops.push(op);
                    values.push(value);
                    is_native.push(native);
                    continue;
                }
                let a = u.int_in_range(0..=values.len() - 1)?;
                let b = u.int_in_range(0..=values.len() - 1)?;
                let merged = is_native[a] && is_native[b];
                let (op, value, native) = match kind {
                    4 => (Op::Add(a, b), values[a] + &values[b], merged),
                    5 => (Op::Sub(a, b), values[a] - &values[b], merged),
                    6 => (Op::Mul(a, b), values[a] * &values[b], merged),
                    7 => (Op::Neg(a), -values[a], is_native[a]),
                    8 => {
                        // Inverting a circuit-backed zero constrains z * 0 = 1,
                        // which is unsatisfiable. Native vars add no constraint.
                        if !is_native[a] && values[a] == F::zero() {
                            satisfied = false;
                        }
                        (Op::Inv(a), values[a].inv(), is_native[a])
                    }
                    _ => {
                        // Asserting equality between two unequal native vars is
                        // a panic by design, so the plan must avoid it.
                        if merged && values[a] != values[b] {
                            continue;
                        }
                        ops.push(Op::AssertEq(a, b));
                        satisfied = satisfied && values[a] == values[b];
                        continue;
                    }
                };
                ops.push(op);
                values.push(value);
                is_native.push(native);
            }
            Ok(Self { ops, satisfied })
        }
    }

    impl Plan {
        /// Check that satisfaction matches the natively computed expectation.
        pub fn run(self, _u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            assert_eq!(
                self.build().is_satisfied(),
                self.satisfied(),
                "plan: {self:?}"
            );
            Ok(())
        }

        /// Whether the circuit built by [`Self::build`] should be satisfied.
        pub const fn satisfied(&self) -> bool {
            self.satisfied
        }

        /// Build the circuit, along with its prover assignment.
        pub fn build(&self) -> ValuedCircuit<F> {
            build_with_values(|ctx| {
                let mut vars: Vec<Var<'_, F>> = Vec::new();
                for op in &self.ops {
                    let var = match *op {
                        Op::Witness(v) => Var::witness(ctx, move |_| v),
                        Op::Constant(v) => Var::constant(ctx, v),
                        Op::Zero => Var::zero(),
                        Op::One => Var::one(),
                        Op::Add(a, b) => vars[a].clone() + &vars[b],
                        Op::Sub(a, b) => vars[a].clone() - &vars[b],
                        Op::Mul(a, b) => vars[a].clone() * &vars[b],
                        Op::Neg(a) => -vars[a].clone(),
                        Op::Inv(a) => vars[a].inv(),
                        Op::AssertEq(a, b) => {
                            vars[a].assert_eq(&vars[b]);
                            continue;
                        }
                    };
                    vars.push(var);
                }
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_invariants::minifuzz;
    use commonware_math::test::F;

    #[test]
    fn test_is_satisfied_matches_native_evaluation_minifuzz() {
        minifuzz::test(|u| u.arbitrary::<fuzz::Plan>()?.run(u));
    }

    #[test]
    fn test_is_satisfied_cubic() {
        // Constrain a witness `x` to satisfy `x^3 + x + 5 = 35`.
        let cubic = |x_value: u64| {
            build_with_values(move |ctx| {
                let x = Var::witness(ctx, move |_| F::from(x_value));
                let out = x.clone() * &x * &x + &x + &Var::constant(ctx, F::from(5u64));
                out.assert_eq(&Var::constant(ctx, F::from(35u64)));
            })
        };
        assert!(cubic(3).is_satisfied());
        assert!(!cubic(4).is_satisfied());
    }
}
