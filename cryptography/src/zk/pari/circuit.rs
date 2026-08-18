//! Conversion of the generic circuit DSL into PARI square constraints.

use crate::{
    bls12381::primitives::group::Scalar,
    zk::circuit::{Circuit, CircuitIdx, CircuitNode, ValuedCircuit},
};
use commonware_codec::Encode;
use commonware_math::algebra::{Additive, FieldNTT, Ring};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const DIGEST_NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_ZK_PARI_RELATION_DIGEST";

/// Errors produced while compiling a generic circuit for PARI.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum Error {
    #[error("the committed input vector is empty")]
    EmptyCommittedInputs,
    #[error("duplicate public input selection: {0:?}")]
    DuplicatePublic(CircuitIdx),
    #[error("duplicate committed input selection: {0:?}")]
    DuplicateCommitted(CircuitIdx),
    #[error("an input is both public and committed: {0:?}")]
    PublicCommittedOverlap(CircuitIdx),
    #[error("a constant cannot be a committed input: {0:?}")]
    CommittedConstant(CircuitIdx),
    #[error("invalid {context} circuit index: {index:?}")]
    InvalidIndex {
        context: &'static str,
        index: CircuitIdx,
    },
    #[error("node {node} refers to non-earlier node {dependency}")]
    NonTopologicalNode { node: usize, dependency: u32 },
    #[error("circuit size arithmetic overflow")]
    SizeOverflow,
    #[error("constraint domain 2^{log_size} exceeds the scalar field maximum 2^{max_log_size}")]
    DomainTooLarge { log_size: u32, max_log_size: u8 },
    #[error("unable to allocate the compiled relation")]
    AllocationFailed,
    #[error("valued circuit {kind} length is {actual}, expected {expected}")]
    ValuedShape {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("compiled valued relation does not match the expected shape and digest")]
    RelationMismatch,
}

/// Ordered public and committed selections from a generic circuit.
///
/// PARI currently supports exactly one non-empty committed input vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputLayout {
    public: Vec<CircuitIdx>,
    committed: Vec<CircuitIdx>,
}

impl InputLayout {
    /// Create a checked input layout.
    pub fn new(public: Vec<CircuitIdx>, committed: Vec<CircuitIdx>) -> Result<Self, super::Error> {
        Self::checked(public, committed).map_err(Into::into)
    }

    fn checked(public: Vec<CircuitIdx>, committed: Vec<CircuitIdx>) -> Result<Self, Error> {
        if committed.is_empty() {
            return Err(Error::EmptyCommittedInputs);
        }

        let mut public_set = BTreeSet::new();
        for &idx in &public {
            if !public_set.insert(idx) {
                return Err(Error::DuplicatePublic(idx));
            }
        }

        let mut committed_set = BTreeSet::new();
        for &idx in &committed {
            if matches!(idx, CircuitIdx::Constant(_)) {
                return Err(Error::CommittedConstant(idx));
            }
            if !committed_set.insert(idx) {
                return Err(Error::DuplicateCommitted(idx));
            }
            if public_set.contains(&idx) {
                return Err(Error::PublicCommittedOverlap(idx));
            }
        }

        Ok(Self { public, committed })
    }

    /// Public inputs in their declared order.
    pub fn public(&self) -> &[CircuitIdx] {
        &self.public
    }

    /// Committed inputs in their declared order.
    pub fn committed(&self) -> &[CircuitIdx] {
        &self.committed
    }
}

/// One constraint row stored sparsely, enforcing `(squared . z)^2 = linear . z`.
///
/// Entries are sorted by strictly ascending column and never hold a zero
/// coefficient, so every row has exactly one representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SparseRow {
    pub(super) squared: Vec<(u32, Scalar)>,
    pub(super) linear: Vec<(u32, Scalar)>,
}

/// A square relation whose rows enforce `(A z)^2 = B z`.
///
/// Rows are stored sparsely; every row past `rows.len()` up to the padded
/// domain size is implicitly zero and trivially satisfied.
pub struct Relation {
    size: usize,
    public_inputs: usize,
    committed_start: usize,
    committed_inputs: usize,
    rows: Vec<SparseRow>,
    digest: [u8; 32],
    value_sources: Vec<ValueSource>,
}

impl Relation {
    /// Compile a generic arithmetic circuit into a canonical square relation.
    pub fn compile(circuit: &Circuit<Scalar>, layout: &InputLayout) -> Result<Self, super::Error> {
        compile(circuit, layout).map_err(Into::into)
    }

    /// Compile concrete circuit values into a prover witness.
    pub fn witness(
        &self,
        valued: &ValuedCircuit<Scalar>,
        layout: &InputLayout,
        opening: super::Opening,
    ) -> Result<super::Witness, super::Error> {
        let assignment = compile_valued(valued, layout, self)?;
        Ok(super::Witness {
            assignment,
            opening,
        })
    }

    /// Size of the padded radix-2 constraint domain.
    pub const fn domain_size(&self) -> usize {
        self.size
    }

    /// Number of assignment variables, including all explicit padding.
    pub const fn num_vars(&self) -> usize {
        self.size
    }

    pub(super) const fn size(&self) -> usize {
        self.size
    }

    /// Number of selected public values, excluding the leading constant one.
    pub const fn public_inputs(&self) -> usize {
        self.public_inputs
    }

    /// Number of values in the committed input vector.
    pub const fn committed_inputs(&self) -> usize {
        self.committed_inputs
    }

    pub(super) const fn committed_start(&self) -> usize {
        self.committed_start
    }

    /// Return the sparse constraint rows.
    pub(super) fn rows(&self) -> &[SparseRow] {
        &self.rows
    }

    /// Canonical digest binding keys and witnesses to this relation.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Check an assignment against every row. Padding rows past the stored
    /// rows are all-zero and satisfied by construction.
    #[cfg(test)]
    pub(super) fn is_satisfied(&self, assignment: &Assignment) -> bool {
        if assignment.relation_digest != self.digest || assignment.values.len() != self.size {
            return false;
        }

        self.rows.iter().all(|row| {
            let a_value = dot(&row.squared, &assignment.values);
            let b_value = dot(&row.linear, &assignment.values);
            a_value.clone() * &a_value == b_value
        })
    }
}

/// Concrete values matching a compiled relation.
#[derive(Clone)]
pub(super) struct Assignment {
    values: Vec<Scalar>,
    public_inputs: usize,
    committed_start: usize,
    committed_inputs: usize,
    relation_digest: [u8; 32],
}

impl Assignment {
    pub(super) fn assignment(&self) -> &[Scalar] {
        &self.values
    }

    /// Return the public assignment, including the fixed leading one.
    pub(super) fn public_assignment(&self) -> &[Scalar] {
        &self.values[..1 + self.public_inputs]
    }

    /// Return selected public values without the fixed leading one.
    pub(super) fn public_inputs(&self) -> &[Scalar] {
        &self.values[1..1 + self.public_inputs]
    }

    pub(super) fn committed_inputs(&self) -> &[Scalar] {
        &self.values[self.committed_start..self.committed_start + self.committed_inputs]
    }

    pub(super) const fn relation_digest(&self) -> &[u8; 32] {
        &self.relation_digest
    }

    pub(super) fn values(&self) -> &[Scalar] {
        self.assignment()
    }

    pub(super) fn public_values(&self) -> &[Scalar] {
        self.public_inputs()
    }

    pub(super) fn committed_values(&self) -> &[Scalar] {
        self.committed_inputs()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LinearCombination {
    terms: BTreeMap<usize, Scalar>,
}

impl LinearCombination {
    const fn zero() -> Self {
        Self {
            terms: BTreeMap::new(),
        }
    }

    fn coordinate(column: usize) -> Self {
        let mut out = Self::zero();
        out.insert(column, Scalar::one());
        out
    }

    fn constant(value: Scalar) -> Self {
        let mut out = Self::zero();
        out.insert(0, value);
        out
    }

    fn insert(&mut self, column: usize, coefficient: Scalar) {
        if coefficient == Scalar::zero() {
            return;
        }
        let coefficient = self
            .terms
            .get(&column)
            .cloned()
            .map_or(coefficient.clone(), |current| current + &coefficient);
        if coefficient == Scalar::zero() {
            self.terms.remove(&column);
        } else {
            self.terms.insert(column, coefficient);
        }
    }

    fn add(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for (&column, coefficient) in &other.terms {
            out.insert(column, coefficient.clone());
        }
        out
    }

    fn sub(&self, other: &Self) -> Self {
        let mut out = self.clone();
        for (&column, coefficient) in &other.terms {
            out.insert(column, -coefficient.clone());
        }
        out
    }

    fn scale(&self, scalar: &Scalar) -> Self {
        if *scalar == Scalar::zero() {
            return Self::zero();
        }
        let terms = self
            .terms
            .iter()
            .map(|(&column, coefficient)| (column, coefficient.clone() * scalar))
            .collect();
        Self { terms }
    }
}

struct Row {
    squared: LinearCombination,
    linear: LinearCombination,
}

#[derive(Clone)]
enum ValueSource {
    One,
    Circuit(CircuitIdx),
    DifferenceSquare(CircuitIdx, CircuitIdx),
    Zero,
}

struct Compiler<'a> {
    circuit: &'a Circuit<Scalar>,
    layout: &'a InputLayout,
    witness_columns: Vec<usize>,
    node_expressions: Vec<LinearCombination>,
    rows: Vec<Row>,
    value_sources: Vec<ValueSource>,
    next_column: usize,
    committed_start: usize,
}

impl<'a> Compiler<'a> {
    fn new(circuit: &'a Circuit<Scalar>, layout: &'a InputLayout) -> Result<Self, Error> {
        validate_circuit(circuit, layout)?;

        let public_end = checked_add(1, layout.public.len())?;
        let committed_start = public_end;
        let committed_end = checked_add(committed_start, layout.committed.len())?;
        let witnesses = usize::try_from(circuit.witnesses).map_err(|_| Error::SizeOverflow)?;
        let next_column = checked_add(committed_end, witnesses)?;

        let additional_columns = circuit
            .nodes
            .len()
            .checked_mul(2)
            .ok_or(Error::SizeOverflow)?;
        let value_capacity = next_column
            .checked_add(additional_columns)
            .ok_or(Error::SizeOverflow)?;
        let mut value_sources = Vec::new();
        value_sources
            .try_reserve_exact(value_capacity)
            .map_err(|_| Error::AllocationFailed)?;
        value_sources.push(ValueSource::One);
        value_sources.extend(layout.public.iter().copied().map(ValueSource::Circuit));
        value_sources.extend(layout.committed.iter().copied().map(ValueSource::Circuit));
        value_sources.extend(
            (0..circuit.witnesses)
                .map(CircuitIdx::Witness)
                .map(ValueSource::Circuit),
        );

        let mut witness_columns = Vec::new();
        witness_columns
            .try_reserve_exact(witnesses)
            .map_err(|_| Error::AllocationFailed)?;
        witness_columns.extend(committed_end..next_column);
        let mut node_expressions = Vec::new();
        node_expressions
            .try_reserve_exact(circuit.nodes.len())
            .map_err(|_| Error::AllocationFailed)?;

        let node_rows = circuit
            .nodes
            .len()
            .checked_mul(2)
            .ok_or(Error::SizeOverflow)?;
        let selected_rows = layout
            .committed
            .len()
            .checked_add(layout.public.len())
            .ok_or(Error::SizeOverflow)?;
        let row_capacity = node_rows
            .checked_add(circuit.assertions.len())
            .and_then(|n| n.checked_add(selected_rows))
            .ok_or(Error::SizeOverflow)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(row_capacity)
            .map_err(|_| Error::AllocationFailed)?;

        Ok(Self {
            circuit,
            layout,
            witness_columns,
            node_expressions,
            rows,
            value_sources,
            next_column,
            committed_start,
        })
    }

    fn compile(mut self) -> Result<Relation, Error> {
        self.compile_nodes()?;
        self.compile_assertions()?;
        self.link_inputs()?;
        self.finish()
    }

    fn compile_nodes(&mut self) -> Result<(), Error> {
        for (node_index, node) in self.circuit.nodes.iter().enumerate() {
            let (left_index, right_index) = match *node {
                CircuitNode::Add(left, right) | CircuitNode::Mul(left, right) => (left, right),
            };
            let left = self.expression(left_index)?;
            let right = self.expression(right_index)?;

            let expression = match node {
                CircuitNode::Add(_, _) => left.add(&right),
                CircuitNode::Mul(_, _) => {
                    let node_u32 = u32::try_from(node_index).map_err(|_| Error::SizeOverflow)?;
                    let output = self.allocate(ValueSource::Circuit(CircuitIdx::Node(node_u32)))?;
                    let output_expression = LinearCombination::coordinate(output);
                    if left == right {
                        self.rows.push(Row {
                            squared: left,
                            linear: output_expression.clone(),
                        });
                    } else {
                        let difference =
                            self.allocate(ValueSource::DifferenceSquare(left_index, right_index))?;
                        let difference_expression = LinearCombination::coordinate(difference);
                        self.rows.push(Row {
                            squared: left.sub(&right),
                            linear: difference_expression.clone(),
                        });
                        self.rows.push(Row {
                            squared: left.add(&right),
                            linear: difference_expression
                                .add(&output_expression.scale(&Scalar::from(4u64))),
                        });
                    }
                    output_expression
                }
            };
            self.node_expressions.push(expression);
        }
        Ok(())
    }

    fn compile_assertions(&mut self) -> Result<(), Error> {
        for &(left, right) in &self.circuit.assertions {
            self.rows.push(Row {
                squared: self.expression(left)?.sub(&self.expression(right)?),
                linear: LinearCombination::zero(),
            });
        }
        Ok(())
    }

    fn link_inputs(&mut self) -> Result<(), Error> {
        for (position, &idx) in self.layout.public.iter().enumerate() {
            let column = checked_add(1, position)?;
            self.rows.push(Row {
                squared: LinearCombination::coordinate(column).sub(&self.expression(idx)?),
                linear: LinearCombination::zero(),
            });
        }

        // These rows keep the committed columns of A linearly independent, as
        // commitment binding requires: expressions never reference committed
        // columns (each is a fresh copy of a circuit value expressed over
        // witness columns and constants), so each row below is the only row
        // with a nonzero entry in its committed column.
        for (position, &idx) in self.layout.committed.iter().enumerate() {
            let column = checked_add(self.committed_start, position)?;
            self.rows.push(Row {
                squared: LinearCombination::coordinate(column).sub(&self.expression(idx)?),
                linear: LinearCombination::zero(),
            });
        }
        Ok(())
    }

    fn expression(&self, idx: CircuitIdx) -> Result<LinearCombination, Error> {
        match idx {
            CircuitIdx::Constant(i) => self
                .circuit
                .constants
                .get(i as usize)
                .cloned()
                .map(LinearCombination::constant),
            CircuitIdx::Witness(i) => self
                .witness_columns
                .get(i as usize)
                .copied()
                .map(LinearCombination::coordinate),
            CircuitIdx::Node(i) => self.node_expressions.get(i as usize).cloned(),
        }
        .ok_or(Error::InvalidIndex {
            context: "expression",
            index: idx,
        })
    }

    fn allocate(&mut self, source: ValueSource) -> Result<usize, Error> {
        let column = self.next_column;
        self.next_column = self.next_column.checked_add(1).ok_or(Error::SizeOverflow)?;
        self.value_sources.push(source);
        Ok(column)
    }

    fn finish(mut self) -> Result<Relation, Error> {
        let required = self.next_column.max(self.rows.len()).max(1);
        let size = required
            .checked_next_power_of_two()
            .ok_or(Error::SizeOverflow)?;
        let log_size = size.ilog2();
        if log_size > u32::from(Scalar::MAX_LG_ROOT_ORDER) {
            return Err(Error::DomainTooLarge {
                log_size,
                max_log_size: Scalar::MAX_LG_ROOT_ORDER,
            });
        }

        self.value_sources
            .try_reserve_exact(size - self.value_sources.len())
            .map_err(|_| Error::AllocationFailed)?;
        self.value_sources.resize(size, ValueSource::Zero);

        let mut rows = Vec::new();
        rows.try_reserve_exact(self.rows.len())
            .map_err(|_| Error::AllocationFailed)?;
        for row in &self.rows {
            rows.push(SparseRow {
                squared: to_sparse(&row.squared)?,
                linear: to_sparse(&row.linear)?,
            });
        }

        let digest = relation_digest(size, &rows, self.layout)?;
        Ok(Relation {
            size,
            public_inputs: self.layout.public.len(),
            committed_start: self.committed_start,
            committed_inputs: self.layout.committed.len(),
            rows,
            digest,
            value_sources: self.value_sources,
        })
    }
}

/// Compile an unvalued circuit into a canonical square relation.
pub(super) fn compile(circuit: &Circuit<Scalar>, layout: &InputLayout) -> Result<Relation, Error> {
    Compiler::new(circuit, layout)?.compile()
}

/// Compile values and cross-check them against an expected relation.
pub(super) fn compile_valued(
    valued: &ValuedCircuit<Scalar>,
    layout: &InputLayout,
    expected: &Relation,
) -> Result<Assignment, Error> {
    let expected_witnesses =
        usize::try_from(valued.circuit.witnesses).map_err(|_| Error::SizeOverflow)?;
    if valued.witnesses.len() != expected_witnesses {
        return Err(Error::ValuedShape {
            kind: "witness",
            expected: expected_witnesses,
            actual: valued.witnesses.len(),
        });
    }
    if valued.nodes.len() != valued.circuit.nodes.len() {
        return Err(Error::ValuedShape {
            kind: "node",
            expected: valued.circuit.nodes.len(),
            actual: valued.nodes.len(),
        });
    }

    let compiled = compile(&valued.circuit, layout)?;
    if compiled.size != expected.size
        || compiled.public_inputs != expected.public_inputs
        || compiled.committed_start != expected.committed_start
        || compiled.committed_inputs != expected.committed_inputs
        || compiled.rows != expected.rows
        || compiled.digest != expected.digest
    {
        return Err(Error::RelationMismatch);
    }

    let mut values: Vec<Scalar> = Vec::new();
    values
        .try_reserve_exact(compiled.size)
        .map_err(|_| Error::AllocationFailed)?;
    for source in &compiled.value_sources {
        let value = match *source {
            ValueSource::One => Scalar::one(),
            ValueSource::Circuit(idx) => circuit_value(valued, idx)?,
            ValueSource::DifferenceSquare(left, right) => {
                let difference = circuit_value(valued, left)? - &circuit_value(valued, right)?;
                difference.clone() * &difference
            }
            ValueSource::Zero => Scalar::zero(),
        };
        values.push(value);
    }

    Ok(Assignment {
        values,
        public_inputs: compiled.public_inputs,
        committed_start: compiled.committed_start,
        committed_inputs: compiled.committed_inputs,
        relation_digest: compiled.digest,
    })
}

fn validate_circuit(circuit: &Circuit<Scalar>, layout: &InputLayout) -> Result<(), Error> {
    for &idx in layout.public.iter().chain(&layout.committed) {
        validate_index(circuit, idx, "input layout")?;
    }

    for (node, operation) in circuit.nodes.iter().enumerate() {
        let (left, right) = match *operation {
            CircuitNode::Add(left, right) | CircuitNode::Mul(left, right) => (left, right),
        };
        for dependency in [left, right] {
            validate_index(circuit, dependency, "node dependency")?;
            if let CircuitIdx::Node(dependency) = dependency
                && dependency as usize >= node
            {
                return Err(Error::NonTopologicalNode { node, dependency });
            }
        }
    }

    for &(left, right) in &circuit.assertions {
        validate_index(circuit, left, "assertion")?;
        validate_index(circuit, right, "assertion")?;
    }
    Ok(())
}

const fn validate_index(
    circuit: &Circuit<Scalar>,
    idx: CircuitIdx,
    context: &'static str,
) -> Result<(), Error> {
    let valid = match idx {
        CircuitIdx::Constant(i) => (i as usize) < circuit.constants.len(),
        CircuitIdx::Witness(i) => i < circuit.witnesses,
        CircuitIdx::Node(i) => (i as usize) < circuit.nodes.len(),
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidIndex {
            context,
            index: idx,
        })
    }
}

fn circuit_value(valued: &ValuedCircuit<Scalar>, idx: CircuitIdx) -> Result<Scalar, Error> {
    let value = match idx {
        CircuitIdx::Constant(i) => valued.circuit.constants.get(i as usize),
        CircuitIdx::Witness(i) => valued.witnesses.get(i as usize),
        CircuitIdx::Node(i) => valued.nodes.get(i as usize),
    };
    value.cloned().ok_or(Error::InvalidIndex {
        context: "valued assignment",
        index: idx,
    })
}

/// Dot a sparse row with a full assignment. Callers guarantee every stored
/// column index is in range for `values`.
pub(super) fn dot(entries: &[(u32, Scalar)], values: &[Scalar]) -> Scalar {
    entries
        .iter()
        .fold(Scalar::zero(), |acc, (column, coefficient)| {
            acc + &(coefficient.clone() * &values[*column as usize])
        })
}

fn checked_add(left: usize, right: usize) -> Result<usize, Error> {
    left.checked_add(right).ok_or(Error::SizeOverflow)
}

/// Convert a compiled linear combination into sorted sparse entries.
///
/// `LinearCombination` stores its terms in a `BTreeMap` and strips zero
/// coefficients on insert, so the output is canonical by construction.
fn to_sparse(combination: &LinearCombination) -> Result<Vec<(u32, Scalar)>, Error> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(combination.terms.len())
        .map_err(|_| Error::AllocationFailed)?;
    for (&column, coefficient) in &combination.terms {
        let column = u32::try_from(column).map_err(|_| Error::SizeOverflow)?;
        entries.push((column, coefficient.clone()));
    }
    Ok(entries)
}

fn relation_digest(
    size: usize,
    rows: &[SparseRow],
    layout: &InputLayout,
) -> Result<[u8; 32], Error> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIGEST_NAMESPACE);
    hash_usize(&mut hasher, size)?;
    hash_usize(&mut hasher, rows.len())?;
    hash_indices(&mut hasher, &layout.public)?;
    hash_indices(&mut hasher, &layout.committed)?;
    for row in rows {
        hasher.update(b"A");
        hash_entries(&mut hasher, &row.squared)?;
        hasher.update(b"B");
        hash_entries(&mut hasher, &row.linear)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_entries(hasher: &mut blake3::Hasher, entries: &[(u32, Scalar)]) -> Result<(), Error> {
    hash_usize(hasher, entries.len())?;
    for (column, coefficient) in entries {
        hasher.update(&column.to_be_bytes());
        hasher.update(&coefficient.encode());
    }
    Ok(())
}

fn hash_usize(hasher: &mut blake3::Hasher, value: usize) -> Result<(), Error> {
    let value = u64::try_from(value).map_err(|_| Error::SizeOverflow)?;
    hasher.update(&value.to_be_bytes());
    Ok(())
}

fn hash_indices(hasher: &mut blake3::Hasher, indices: &[CircuitIdx]) -> Result<(), Error> {
    hash_usize(hasher, indices.len())?;
    for &idx in indices {
        let (tag, index) = match idx {
            CircuitIdx::Constant(index) => (0u8, index),
            CircuitIdx::Witness(index) => (1u8, index),
            CircuitIdx::Node(index) => (2u8, index),
        };
        hasher.update(&[tag]);
        hasher.update(&index.to_be_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::circuit::{Var, build, build_with_values};
    use commonware_math::algebra::Field;

    fn scalar(value: u64) -> Scalar {
        Scalar::from(value)
    }

    fn committed_a_rank(relation: &Relation) -> usize {
        let columns = relation.committed_inputs;
        let mut matrix = vec![vec![Scalar::zero(); columns]; relation.size];
        for (row, entries) in relation.rows.iter().enumerate() {
            for (column, coefficient) in &entries.squared {
                let column = *column as usize;
                if let Some(offset) = column.checked_sub(relation.committed_start)
                    && offset < columns
                {
                    matrix[row][offset] = coefficient.clone();
                }
            }
        }
        let mut rank = 0;
        for column in 0..columns {
            let Some(pivot) =
                (rank..matrix.len()).find(|&row| matrix[row][column] != Scalar::zero())
            else {
                continue;
            };
            matrix.swap(rank, pivot);
            let inverse = matrix[rank][column].inv();
            for value in &mut matrix[rank][column..] {
                *value *= &inverse;
            }
            let normalized = matrix[rank].clone();
            for (row, values) in matrix.iter_mut().enumerate() {
                if row == rank {
                    continue;
                }
                let factor = values[column].clone();
                for (value, pivot_value) in values[column..].iter_mut().zip(&normalized[column..]) {
                    *value -= &(pivot_value.clone() * &factor);
                }
            }
            rank += 1;
        }
        rank
    }

    #[test]
    fn arithmetic_assignment_satisfies_square_relation() {
        let (valued, selected) = build_with_values(|ctx| {
            let x = Var::witness(ctx, |_| scalar(3));
            let y = Var::witness(ctx, |_| scalar(4));
            let square = x.clone() * &x;
            let product = (x.clone() + &y) * &square;
            product.assert_eq(&Var::constant(ctx, scalar(63)));
            vec![x, y, product]
        });
        let layout = InputLayout::new(vec![selected[2]], vec![selected[0], selected[1]])
            .expect("layout is valid");
        let relation = compile(&valued.circuit, &layout).expect("circuit should compile");
        let assignment =
            compile_valued(&valued, &layout, &relation).expect("values should compile");

        assert!(relation.is_satisfied(&assignment));
        assert_eq!(assignment.public_assignment(), &[scalar(1), scalar(63)]);
        assert_eq!(assignment.committed_inputs(), &[scalar(3), scalar(4)]);
        assert!(relation.size.is_power_of_two());
        assert!(relation.rows.len() <= relation.size);
        for row in &relation.rows {
            for entries in [&row.squared, &row.linear] {
                assert!(entries.iter().all(|(column, coefficient)| {
                    (*column as usize) < relation.size && *coefficient != Scalar::zero()
                }));
                assert!(entries.windows(2).all(|pair| pair[0].0 < pair[1].0));
            }
        }
    }

    #[test]
    fn public_copy_is_linked() {
        let (valued, selected) = build_with_values(|ctx| {
            let x = Var::witness(ctx, |_| scalar(2));
            let y = Var::witness(ctx, |_| scalar(5));
            let sum = x.clone() + &y;
            vec![x, sum]
        });
        let layout =
            InputLayout::new(vec![selected[1]], vec![selected[0]]).expect("layout is valid");
        let relation = compile(&valued.circuit, &layout).expect("circuit should compile");
        let mut assignment =
            compile_valued(&valued, &layout, &relation).expect("values should compile");
        assert!(relation.is_satisfied(&assignment));

        assignment.values[1] = scalar(8);
        assert!(!relation.is_satisfied(&assignment));
    }

    #[test]
    fn committed_link_rows_keep_duplicate_expressions_full_rank() {
        let (valued, selected) = build_with_values(|ctx| {
            let x = Var::witness(ctx, |_| scalar(7));
            let y = Var::witness(ctx, |_| scalar(11));
            let left = x.clone() + &y;
            let right = y + &x;
            vec![left, right]
        });
        assert_ne!(selected[0], selected[1]);
        let layout = InputLayout::new(Vec::new(), selected).expect("layout is valid");
        let relation = compile(&valued.circuit, &layout).expect("circuit should compile");
        let assignment =
            compile_valued(&valued, &layout, &relation).expect("values should compile");

        assert!(relation.is_satisfied(&assignment));
        assert_eq!(assignment.committed_inputs(), &[scalar(18), scalar(18)]);
        assert_eq!(committed_a_rank(&relation), relation.committed_inputs);
    }

    #[test]
    fn layout_order_is_assignment_order() {
        let (valued, selected) = build_with_values(|ctx| {
            let a = Var::witness(ctx, |_| scalar(3));
            let b = Var::witness(ctx, |_| scalar(5));
            let c = a.clone() + &b;
            let d = a.clone() * &b;
            vec![a, b, c, d]
        });
        let layout = InputLayout::new(
            vec![selected[1], selected[0]],
            vec![selected[3], selected[2]],
        )
        .expect("layout is valid");
        let relation = compile(&valued.circuit, &layout).expect("circuit should compile");
        let assignment =
            compile_valued(&valued, &layout, &relation).expect("values should compile");

        assert_eq!(assignment.public_inputs(), &[scalar(5), scalar(3)]);
        assert_eq!(assignment.committed_inputs(), &[scalar(15), scalar(8)]);
        assert_eq!(assignment.assignment()[0], scalar(1));
        assert_eq!(assignment.relation_digest(), relation.digest());
    }

    #[test]
    fn invalid_layouts_are_rejected() {
        let witness = CircuitIdx::Witness(0);
        let other = CircuitIdx::Witness(1);
        let constant = CircuitIdx::Constant(0);
        assert_eq!(
            InputLayout::checked(Vec::new(), Vec::new()),
            Err(Error::EmptyCommittedInputs)
        );
        assert_eq!(
            InputLayout::checked(vec![witness, witness], vec![other]),
            Err(Error::DuplicatePublic(witness))
        );
        assert_eq!(
            InputLayout::checked(Vec::new(), vec![witness, witness]),
            Err(Error::DuplicateCommitted(witness))
        );
        assert_eq!(
            InputLayout::checked(vec![witness], vec![witness]),
            Err(Error::PublicCommittedOverlap(witness))
        );
        assert_eq!(
            InputLayout::checked(Vec::new(), vec![constant]),
            Err(Error::CommittedConstant(constant))
        );

        let (circuit, _) = build::<Scalar>(|ctx| {
            vec![Var::witness(ctx, |_| {
                unreachable!("unvalued closure is not run")
            })]
        });
        let invalid = CircuitIdx::Witness(1);
        let layout = InputLayout::new(Vec::new(), vec![invalid]).expect("shape is valid");
        assert_eq!(
            compile(&circuit, &layout).err(),
            Some(Error::InvalidIndex {
                context: "input layout",
                index: invalid,
            })
        );
    }

    #[test]
    fn valued_and_unvalued_compilation_match() {
        let build_circuit = |with_values: bool| {
            if with_values {
                let (valued, selected) = build_with_values(|ctx| {
                    let x = Var::witness(ctx, |_| scalar(6));
                    let y = Var::witness(ctx, |_| scalar(9));
                    let sum = x.clone() + &y;
                    (x.clone() * &sum).assert_eq(&Var::constant(ctx, scalar(90)));
                    vec![x, sum]
                });
                (Some(valued), None, selected)
            } else {
                let (circuit, selected) = build(|ctx| {
                    let x = Var::<Scalar>::witness(ctx, |_| unreachable!("not evaluated"));
                    let y = Var::<Scalar>::witness(ctx, |_| unreachable!("not evaluated"));
                    let sum = x.clone() + &y;
                    (x.clone() * &sum).assert_eq(&Var::constant(ctx, scalar(90)));
                    vec![x, sum]
                });
                (None, Some(circuit), selected)
            }
        };

        let (valued, _, valued_selected) = build_circuit(true);
        let (_, circuit, circuit_selected) = build_circuit(false);
        assert_eq!(valued_selected, circuit_selected);
        let layout = InputLayout::new(vec![circuit_selected[1]], vec![circuit_selected[0]])
            .expect("layout is valid");
        let valued = valued.expect("valued branch");
        let verifier_relation =
            compile(&circuit.expect("unvalued branch"), &layout).expect("circuit should compile");
        let prover_relation = compile(&valued.circuit, &layout).expect("circuit should compile");
        assert_eq!(verifier_relation.digest, prover_relation.digest);
        assert_eq!(verifier_relation.size, prover_relation.size);
        assert_eq!(verifier_relation.rows, prover_relation.rows);

        let assignment = compile_valued(&valued, &layout, &verifier_relation)
            .expect("relation shape and digest should match");
        assert!(verifier_relation.is_satisfied(&assignment));
    }

    #[test]
    fn valued_compilation_rejects_wrong_relation() {
        let (valued, selected) = build_with_values(|ctx| {
            let x = Var::witness(ctx, |_| scalar(2));
            vec![x]
        });
        let layout = InputLayout::new(Vec::new(), selected).expect("layout is valid");
        let (other, other_selected) = build::<Scalar>(|ctx| {
            let x = Var::witness(ctx, |_| unreachable!("not evaluated"));
            let y = x.clone() * &x;
            vec![y]
        });
        let other_layout = InputLayout::new(Vec::new(), other_selected).expect("layout is valid");
        let other_relation = compile(&other, &other_layout).expect("circuit should compile");
        assert_eq!(
            compile_valued(&valued, &layout, &other_relation).err(),
            Some(Error::RelationMismatch)
        );
    }
}
