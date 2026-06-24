//! Utilities for creating arithmetic circuits.
//!
//! A [`Circuit`] holds the additions and multiplications making up a
//! computation over a ring `F`, along with assertions that two values in
//! the computation are equal. The inputs to the computation are constants,
//! or witnesses, whose values are chosen by the prover. Proof systems
//! consume circuits to prove that the assertions hold, without revealing
//! the witnesses.
//!
//! Circuits are built by writing plain Rust over [`Var`], which implements
//! the algebra traits from [`commonware_math`]. This allows the same code to
//! be generic over `F` and `Var<F>`. The building code runs in one of two
//! modes:
//!
//! - [`build`] records only the circuit itself (verifier mode),
//! - [`build_with_values`] also computes every value in the computation as
//!   the circuit is constructed (prover mode).
//!
//! Because both modes run the same code, the prover and the verifier
//! construct the same circuit.
//!
//! # Example
//!
//! ```
//! use commonware_cryptography::zk::circuit::{build_with_values, Var};
//! use commonware_math::test::F;
//!
//! // Constrain a witness `x` to satisfy `x^3 + x + 5 = 35`.
//! let (valued, _) = build_with_values(|ctx| {
//!     let x = Var::witness(ctx, |_| F::from(3u64));
//!     let out = x.clone() * &x * &x + &x + &Var::constant(ctx, F::from(5u64));
//!     out.assert_eq(&Var::constant(ctx, F::from(35u64)));
//!     Vec::new()
//! });
//! assert!(valued.is_satisfied());
//! ```
//!
//! # Caveats
//!
//! ## Witness Closures
//!
//! The `init` closure passed to [`Var::witness`] must not use the
//! [`Context`], for example by creating new vars: the build deadlocks,
//! hanging without an error. Compute the witness value using only the
//! [`Values`] view the closure receives.
//!
//! ## Inversion
//!
//! [`Field::inv`] requires that inverting zero produce zero. Circuit-backed
//! vars deviate: inverting zero adds an unsatisfiable constraint instead,
//! with no error when building. Generic code relying on `inv(0) = 0` will
//! produce circuits that can never be satisfied.

use commonware_math::algebra::{Additive, Field, Multiplicative, Object, Ring};
use commonware_utils::sync::Mutex;
use std::{
    fmt,
    marker::PhantomData,
    ops::{
        Add, AddAssign, BitAnd, BitOr, Div, DivAssign, Index, Mul, MulAssign, Neg, Not, Sub,
        SubAssign,
    },
};

/// Identifies a value in a [`Circuit`]: a constant, a witness, or the
/// output of an operation.
///
/// Witnesses are numbered in allocation order, letting callers name
/// specific witnesses after building, for example to choose which values a
/// proof system should commit to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CircuitIdx {
    Constant(u32),
    Witness(u32),
    Node(u32),
}

/// An addition or multiplication of two earlier values.
pub(crate) enum CircuitNode {
    Add(CircuitIdx, CircuitIdx),
    Mul(CircuitIdx, CircuitIdx),
}

/// An arithmetic circuit over `F`.
///
/// Create one with [`build`] or [`build_with_values`]. On its own, a
/// circuit only describes constraints; proving and verifying that they hold
/// is the job of a proof system consuming it.
//
// Exposing the structure of the circuit directly (here and in CircuitNode
// and ValuedCircuit) is not ideal: proof systems would be better served by
// an abstraction over it. We should wait until we have a few different
// backends before designing one, so that we don't freeze an abstraction
// that won't work for all of our use cases. In the meantime, exposing the
// structure at the crate pub level is not harmful.
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

/// A circuit together with concrete values for its whole computation.
///
/// Produced by [`build_with_values`]. Use [`Self::is_satisfied`] to check
/// whether the values satisfy the circuit's assertions.
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

/// A view of the values assigned so far during prover-mode construction.
///
/// A view is passed to witness `init` closures, which read the values of
/// earlier vars with [`Var::value`]. This is how a prover supplies values
/// that are cheaper to verify than to compute with circuit operations, such
/// as inverses: compute the value natively, then constrain it with
/// assertions.
///
/// Closures receiving a view must not call back into the [`Context`], for
/// example by creating new vars: doing so deadlocks.
///
/// # Example
///
/// ```
/// use commonware_cryptography::zk::circuit::{build_with_values, Var};
/// use commonware_math::{
///     algebra::{Field, Ring},
///     test::F,
/// };
///
/// let (valued, _) = build_with_values(|ctx| {
///     let x = Var::witness(ctx, |_| F::from(3u64));
///     // The prover computes the inverse natively...
///     let inv = Var::witness(ctx, {
///         let x = x.clone();
///         move |v| x.value(v).inv()
///     });
///     // ...and the circuit checks it with a single multiplication.
///     (x * &inv).assert_eq(&Var::one());
///     Vec::new()
/// });
/// assert!(valued.is_satisfied());
/// ```
pub struct Values<'a, F> {
    constants: &'a [F],
    witnesses: &'a [F],
    nodes: &'a [F],
}

// Manual `Copy`/`Clone` so they hold for any `F`: the derived versions would
// add a spurious `F: Copy`/`F: Clone` bound, but `Values` only holds slices.
impl<F> Clone for Values<'_, F> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<F> Copy for Values<'_, F> {}

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

/// A handle for recording operations into a circuit being built.
///
/// A context is passed to the closure given to [`build`] or
/// [`build_with_values`], and is captured by the [`Var`]s created from it.
/// Contexts are `Copy`, so they can be passed around freely; vars from two
/// different builds cannot be mixed.
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
        // Both locks are held while `init` runs, so an `init` closure that
        // calls back into the Context deadlocks. This is why Values forbids
        // doing so.
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

/// A value in a circuit being built.
///
/// Vars are created with [`Self::witness`] and [`Self::constant`], combined
/// with the usual arithmetic operators, and constrained with
/// [`Self::assert_eq`]. Vars implement the algebra traits from
/// [`commonware_math`], so code written against [`Ring`] or [`Field`] runs
/// unchanged over circuit values.
///
/// Values produced by [`Additive::zero`] and [`Ring::one`] are "native":
/// they live outside the circuit until combined with a circuit value. This
/// is visible in two places: equality compares what vars refer to, not what
/// they evaluate to (a native var is never equal to a circuit-backed var,
/// even when their values agree), and [`Self::assert_eq`] panics on two
/// unequal native vars. Generic code that branches on equality may
/// therefore behave differently over vars than over plain values.
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
    /// Allocate a fresh witness.
    ///
    /// In prover mode, `init` receives the values assigned so far, and must
    /// return the value of this witness. In verifier mode, `init` does not
    /// run.
    ///
    /// `init` must not use the [`Context`]: doing so deadlocks. See
    /// [`Values`].
    pub fn witness(ctx: Context<'ctx, F>, init: impl for<'a> FnOnce(Values<'a, F>) -> F) -> Self {
        Self {
            inner: VarInner::Circuit {
                ctx,
                idx: ctx.witness(init),
            },
        }
    }

    /// Create a "native" var holding a value outside any circuit.
    ///
    /// Like the vars produced by [`Additive::zero`] and [`Ring::one`], a
    /// native var lives outside the circuit until it is combined with a
    /// circuit-backed var, at which point it is folded in as a constant. This
    /// is convenient for fixed constants (such as curve parameters) that are
    /// the same in every circuit and so do not need a [`Context`] to create.
    pub const fn native(value: F) -> Self {
        Self {
            inner: VarInner::Native(value),
        }
    }

    /// Create a var with a fixed, public value.
    pub fn constant(ctx: Context<'ctx, F>, value: F) -> Self {
        Self {
            inner: VarInner::Circuit {
                ctx,
                idx: ctx.constant(value),
            },
        }
    }

    /// Assert that this var equals `other`.
    ///
    /// The constraint must hold for the circuit to be satisfied.
    ///
    /// # Panics
    ///
    /// Panics if both vars are native and their values differ, since there
    /// is no circuit to record the failure in.
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
    /// The value of this var, under a prover-mode assignment.
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

/// Division by `rhs`, computed as a single multiplication constraint.
///
/// Rather than inverting `rhs` and multiplying (which costs two
/// multiplications), the prover supplies the quotient `q = self / rhs` as a
/// witness and the circuit constrains `q * rhs == self`.
///
/// # Caveats
///
/// Like [`Field::inv`] on a circuit-backed var, this deviates from the
/// `inv(0) = 0` field contract: dividing by a circuit-backed `rhs` of zero
/// adds an unsatisfiable constraint when `self != 0`. Worse, `0 / 0`
/// constrains `q * 0 == 0`, which holds for *any* `q`, leaving the quotient
/// unconstrained. Only use `/` where `rhs` is known to be nonzero.
impl<'ctx, F: Field> Div<&Self> for Var<'ctx, F> {
    type Output = Self;

    fn div(self, rhs: &Self) -> Self {
        let &ctx = match (&self.inner, &rhs.inner) {
            (VarInner::Native(a), VarInner::Native(b)) => {
                return Self {
                    inner: VarInner::Native(a.clone() * &b.inv()),
                }
            }
            (VarInner::Circuit { ctx, .. }, _) | (_, VarInner::Circuit { ctx, .. }) => ctx,
        };
        let q = { Self::witness(ctx, |v| self.value(v) * &rhs.value(v).inv()) };
        (q.clone() * rhs).assert_eq(&self);
        q
    }
}

impl<'ctx, F: Field> DivAssign<&Self> for Var<'ctx, F> {
    fn div_assign(&mut self, rhs: &Self) {
        *self = self.clone() / rhs;
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

/// Unlike the [`Field::inv`] contract, inverting a circuit-backed zero does
/// not produce zero: it adds an unsatisfiable constraint to the circuit.
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

/// A circuit value constrained to be `0` or `1`.
///
/// A `BoolVar` wraps a [`Var`] together with a guarantee that it holds a
/// boolean: every constructor either produces a value that is boolean by
/// construction, or adds the constraint `b * (1 - b) == 0` enforcing it.
/// Holding that guarantee in the type lets later operations skip
/// re-checking: [`Self::select`] and the boolean combinators below are sound
/// precisely because their inputs are already known to be boolean.
///
/// The motivating use is scalar multiplication in a circuit, where a scalar
/// is decomposed into bits (each a `BoolVar`) and a point is accumulated by
/// conditionally adding with [`Self::select`].
///
/// # Native Vars
///
/// Like [`Var`], a `BoolVar` built from a native value (see
/// [`Self::constant`]) lives outside the circuit until combined with a
/// circuit-backed value. [`Self::assert`] on a native, non-boolean var
/// therefore panics rather than recording an unsatisfiable constraint, in
/// keeping with the native-var semantics described on [`Var`].
///
/// # Example
///
/// ```
/// use commonware_cryptography::zk::circuit::{build_with_values, BoolVar, Var};
/// use commonware_math::test::F;
///
/// // Use a bit to choose between two values, then check the choice.
/// let (valued, _) = build_with_values(|ctx| {
///     let bit = BoolVar::witness(ctx, |_| true);
///     let a = Var::constant(ctx, F::from(7u64));
///     let b = Var::constant(ctx, F::from(9u64));
///     bit.select(&a, &b).assert_eq(&Var::constant(ctx, F::from(7u64)));
///     Vec::new()
/// });
/// assert!(valued.is_satisfied());
/// ```
#[derive(Clone)]
pub struct BoolVar<'ctx, F> {
    var: Var<'ctx, F>,
}

impl<F: fmt::Debug> fmt::Debug for BoolVar<'_, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BoolVar").field(&self.var).finish()
    }
}

impl<'ctx, F> BoolVar<'ctx, F> {
    /// The underlying [`Var`], whose value is `0` or `1`.
    pub const fn var(&self) -> &Var<'ctx, F> {
        &self.var
    }

    /// Consume this `BoolVar`, returning the underlying [`Var`].
    #[allow(clippy::missing_const_for_fn)]
    pub fn into_var(self) -> Var<'ctx, F> {
        self.var
    }
}

impl<'ctx, F: Ring> BoolVar<'ctx, F> {
    /// Create a boolean constant with a fixed, public value.
    ///
    /// Like [`Var::native`], the value lives outside the circuit until it is
    /// combined with a circuit-backed var. No constraint is added: the value
    /// is boolean by construction.
    pub fn constant(value: bool) -> Self {
        Self {
            var: Var::native(if value { F::one() } else { F::zero() }),
        }
    }

    /// Assert that this var equals `other`.
    pub fn assert_eq(&self, other: &Self) {
        self.var.assert_eq(other.var());
    }
}

impl<'ctx, F: Ring + PartialEq> BoolVar<'ctx, F> {
    /// Allocate a fresh boolean witness, constrained to be `0` or `1`.
    ///
    /// In prover mode, `init` receives the values assigned so far and must
    /// return the bit's value. In verifier mode, `init` does not run. The
    /// constraint `b * (1 - b) == 0` is added in both modes.
    ///
    /// `init` must not use the [`Context`]: doing so deadlocks. See
    /// [`Values`].
    pub fn witness(
        ctx: Context<'ctx, F>,
        init: impl for<'a> FnOnce(Values<'a, F>) -> bool,
    ) -> Self {
        let var = Var::witness(ctx, |v| if init(v) { F::one() } else { F::zero() });
        Self::enforce(&var);
        Self { var }
    }

    /// Constrain an arbitrary var to be boolean and wrap it.
    ///
    /// Adds the constraint `var * (1 - var) == 0`, which holds exactly when
    /// `var` is `0` or `1`.
    ///
    /// # Panics
    ///
    /// Panics if `var` is a native var whose value is not `0` or `1`, since
    /// there is no circuit to record the failed constraint in. See
    /// [`Var::assert_eq`].
    pub fn assert(var: Var<'ctx, F>) -> Self {
        Self::enforce(&var);
        Self { var }
    }

    /// Add the booleanity constraint `var * var == var` (equivalently
    /// `var * (1 - var) == 0`).
    fn enforce(var: &Var<'ctx, F>) {
        (var.clone() * var).assert_eq(var);
    }
}

impl<'ctx, F: Ring> BoolVar<'ctx, F> {
    /// Select between two vars based on this bit.
    ///
    /// Returns `on_true` when the bit is `1` and `on_false` when it is `0`,
    /// computed as `on_false + b * (on_true - on_false)` with a single
    /// multiplication.
    pub fn select(&self, on_true: &Var<'ctx, F>, on_false: &Var<'ctx, F>) -> Var<'ctx, F> {
        on_false.clone() + &(self.var.clone() * &(on_true.clone() - on_false))
    }
}

impl<'ctx, F: Ring> Not for BoolVar<'ctx, F> {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self {
            var: Var::one() - &self.var,
        }
    }
}

impl<'ctx, F: Ring> BitAnd for BoolVar<'ctx, F> {
    type Output = Self;

    // Over 0/1, boolean `and` IS multiplication, so `self.var * &rhs.var` is
    // correct. But clippy's `suspicious_arithmetic_impl` lint assumes any
    // operator impl that uses a *different* operator internally (here, `*` inside
    // `BitAnd`) is a copy-paste typo. That heuristic is wrong: it has no notion
    // of the algebra, so it flags correct code and forces this `#[allow]`. The
    // lint gives confident, authoritative advice that is simply false, which is
    // why its designer now resides in the Eighth Circle of Hell,
    // among the fraudulent counselors (Inferno XXVI) who misused their cleverness
    // to advise others into error, each concealed within a tongue of flame.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self {
            var: self.var * &rhs.var,
        }
    }
}

impl<'ctx, F: Ring> BitOr for BoolVar<'ctx, F> {
    type Output = Self;

    // Boolean `or` over 0/1 is `a + b - a * b`, which is correct. Same lint, same
    // false alarm over the `+`/`-`/`*`, same `#[allow]`. See `bitand` above for
    // why the lint's designer is doing time in the Eighth Circle of Hell.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            var: self.var.clone() + &rhs.var - &(self.var * &rhs.var),
        }
    }
}

/// Build a circuit without computing an assignment (verifier mode).
///
/// Witness `init` closures do not run in this mode.
///
/// The closure returns the vars whose circuit indices the caller wants back
/// (e.g. the committed outputs of a circuit); the returned indices are in the
/// same order. Return an empty vec to ignore this.
///
/// # Panics
///
/// Panics if any returned var is native (not backed by the circuit).
pub fn build<F: Ring + PartialEq>(
    f: impl for<'ctx> FnOnce(Context<'ctx, F>) -> Vec<Var<'ctx, F>>,
) -> (Circuit<F>, Vec<CircuitIdx>) {
    let inner = ContextInner {
        values: None,
        circuit: Mutex::new(Circuit::default()),
    };
    let indices = f(Context {
        inner: &inner,
        _brand: PhantomData,
    })
    .iter()
    .map(Var::circuit_idx)
    .collect();
    (inner.circuit.into_inner(), indices)
}

/// Build a circuit while simultaneously computing the assignment (prover mode).
///
/// Each witness's value comes from the `init` closure passed to
/// [`Var::witness`].
///
/// The closure returns the vars whose circuit indices the caller wants back
/// (e.g. the committed outputs of a circuit); the returned indices are in the
/// same order. Return an empty vec to ignore this.
///
/// # Panics
///
/// Panics if any returned var is native (not backed by the circuit).
pub fn build_with_values<F: Ring + PartialEq>(
    f: impl for<'ctx> FnOnce(Context<'ctx, F>) -> Vec<Var<'ctx, F>>,
) -> (ValuedCircuit<F>, Vec<CircuitIdx>) {
    let inner = ContextInner {
        values: Some(Mutex::new(ValuesBuilder {
            witnesses: Vec::new(),
            nodes: Vec::new(),
        })),
        circuit: Mutex::new(Circuit::default()),
    };
    let indices = f(Context {
        inner: &inner,
        _brand: PhantomData,
    })
    .iter()
    .map(Var::circuit_idx)
    .collect();
    let circuit = inner.circuit.into_inner();
    let values = inner.values.unwrap().into_inner();
    (
        ValuedCircuit {
            circuit,
            witnesses: values.witnesses,
            nodes: values.nodes,
        },
        indices,
    )
}

/// Fuzzing utilities, comparing circuit satisfaction against native
/// evaluation of the same operations.
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
                Vec::new()
            })
            .0
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
                Vec::new()
            })
            .0
        };
        assert!(cubic(3).is_satisfied());
        assert!(!cubic(4).is_satisfied());
    }

    #[test]
    fn test_bool_witness_enforces_booleanity() {
        // A boolean witness from a `bool` is always satisfiable.
        for b in [false, true] {
            let (valued, _) = build_with_values(move |ctx| {
                BoolVar::<F>::witness(ctx, move |_| b);
                Vec::new()
            });
            assert!(valued.is_satisfied());
        }

        // A var that is not 0 or 1 fails the booleanity constraint.
        let (bad, _) = build_with_values(|ctx| {
            let two = Var::witness(ctx, |_| F::from(2u64));
            BoolVar::assert(two);
            Vec::new()
        });
        assert!(!bad.is_satisfied());

        // 0 and 1 pass `from_var`.
        for v in [0u64, 1u64] {
            let (valued, _) = build_with_values(move |ctx| {
                let x = Var::witness(ctx, move |_| F::from(v));
                BoolVar::assert(x);
                Vec::new()
            });
            assert!(valued.is_satisfied());
        }
    }

    #[test]
    fn test_bool_select() {
        // `select` returns `on_true` when the bit is set, else `on_false`.
        for b in [false, true] {
            let (valued, _) = build_with_values(move |ctx| {
                let bit = BoolVar::witness(ctx, move |_| b);
                let on_true = Var::witness(ctx, |_| F::from(7u64));
                let on_false = Var::witness(ctx, |_| F::from(9u64));
                let selected = bit.select(&on_true, &on_false);
                let expected = if b { F::from(7u64) } else { F::from(9u64) };
                selected.assert_eq(&Var::constant(ctx, expected));
                Vec::new()
            });
            assert!(valued.is_satisfied());
        }
    }

    #[test]
    fn test_bool_combinators_truth_tables() {
        for a in [false, true] {
            for b in [false, true] {
                let (valued, _) = build_with_values::<F>(move |ctx| {
                    let a_var = BoolVar::witness(ctx, move |_| a);
                    let b_var = BoolVar::witness(ctx, move |_| b);
                    (!a_var.clone()).assert_eq(&BoolVar::constant(!a));
                    (a_var.clone() & b_var.clone()).assert_eq(&BoolVar::constant(a & b));
                    (a_var | b_var).assert_eq(&BoolVar::constant(a | b));
                    Vec::new()
                });
                assert!(valued.is_satisfied());
            }
        }
    }

    #[test]
    fn test_bool_constant() {
        let (valued, _) = build_with_values(|ctx| {
            // A native boolean constant folds in correctly when combined.
            let t = BoolVar::<F>::constant(true);
            let f = BoolVar::<F>::constant(false);
            let x = Var::witness(ctx, |_| F::from(5u64));
            t.select(&x, &Var::zero())
                .assert_eq(&Var::constant(ctx, F::from(5u64)));
            f.select(&x, &Var::zero()).assert_eq(&Var::zero());
            Vec::new()
        });
        assert!(valued.is_satisfied());
    }
}
