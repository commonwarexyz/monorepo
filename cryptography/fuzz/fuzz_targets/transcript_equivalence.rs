#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::transcript::{Summary, Transcript};
use libfuzzer_sys::fuzz_target;

const MIN_DATA_SIZE: usize = 32;
const MAX_DATA_SIZE: usize = 2048;
const MAX_OPERATIONS: usize = 50;
const MIN_SPLITS: usize = 1;
const MAX_SPLITS: usize = 16;

/// Represents a commit operation with data and split indices.
/// The indices represent how to split the data before appending.
/// For example, data="ABCDEF" with indices=[2, 4] means:
/// - append("AB")
/// - append("CD")
/// - append("EF")
/// - commit()
#[derive(Debug, Clone)]
struct CommitOperation {
    data: Vec<u8>,
    /// Indices where to split the data. Always sorted and within bounds.
    split_indices: Vec<usize>,
}

fn split_indices(u: &mut Unstructured<'_>, data_len: usize) -> arbitrary::Result<Vec<usize>> {
    // Valid split positions are between bytes: [1, data_len-1]
    if data_len < 2 {
        return Ok(Vec::new());
    }

    let max_splits = MAX_SPLITS.min(data_len - 1);
    // Enforce at least MIN_SPLITS split to avoid the "always empty" case under minimization
    let k = u.int_in_range(MIN_SPLITS..=max_splits)?;

    let mut splits = Vec::with_capacity(k);
    let mut lo = 1;
    for i in 0..k {
        // ensure space for the remaining (k - i - 1) splits
        let hi = (data_len - 1) - (k - i - 1);
        let idx = u.int_in_range(lo..=hi)?;
        splits.push(idx);
        lo = idx + 1;
    }
    Ok(splits)
}

impl<'a> Arbitrary<'a> for CommitOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(MIN_DATA_SIZE..=MAX_DATA_SIZE)?;
        let data = u.bytes(len)?.to_vec();
        let split_indices = split_indices(u, data.len())?;

        Ok(CommitOperation {
            data,
            split_indices,
        })
    }
}

impl CommitOperation {
    /// Check if two Commit are semantically equivalent
    fn is_equivalent(&self, other: &CommitOperation) -> bool {
        // Two commit operations are equivalent if they commit the same data
        // regardless of how it was split with append operations
        self.data == other.data
    }

    /// Apply this operation to a transcript
    fn apply(&self, transcript: &mut Transcript) {
        assert!(
            self.split_indices.is_sorted(),
            "Split indices must be sorted"
        );
        assert!(
            self.split_indices.iter().all(|&idx| idx < self.data.len()),
            "Split indices must be within bounds"
        );
        assert!(
            !self.split_indices.is_empty(),
            "Empty split indices are not allowed"
        );

        // Split the data according to indices
        let mut last_idx = 0;

        for &idx in &self.split_indices {
            if idx > last_idx {
                transcript.append(&self.data[last_idx..idx]);
                last_idx = idx;
            }
        }

        // Append remaining data
        if last_idx < self.data.len() {
            transcript.append(&self.data[last_idx..]);
        }

        transcript.commit(&[] as &[u8]);
    }
}

#[derive(Debug, Clone)]
enum FuzzedOperation {
    /// Commit with potential splits via append
    Commit(CommitOperation),
}

impl<'a> Arbitrary<'a> for FuzzedOperation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // For now we only use Commit operations
        Ok(FuzzedOperation::Commit(CommitOperation::arbitrary(u)?))
    }
}

impl FuzzedOperation {
    /// Check if two operations are semantically equivalent
    fn is_equivalent(&self, other: &FuzzedOperation) -> bool {
        match (self, other) {
            (FuzzedOperation::Commit(a), FuzzedOperation::Commit(b)) => a.is_equivalent(b),
        }
    }
}

#[derive(Debug)]
struct TranscriptSequence {
    namespace: Vec<u8>,
    operations: Vec<FuzzedOperation>,
}

impl<'a> Arbitrary<'a> for TranscriptSequence {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate namespace with bounded size
        let namespace_len = u.int_in_range(0..=MAX_DATA_SIZE)?;
        let mut namespace = Vec::with_capacity(namespace_len);
        for _ in 0..namespace_len {
            namespace.push(u8::arbitrary(u)?);
        }

        // Generate operations with bounded count
        let num_operations = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = Vec::with_capacity(num_operations);
        for _ in 0..num_operations {
            operations.push(FuzzedOperation::arbitrary(u)?);
        }

        Ok(TranscriptSequence {
            namespace,
            operations,
        })
    }
}

impl TranscriptSequence {
    /// Check if two sequences are semantically equivalent
    fn is_equivalent(&self, other: &TranscriptSequence) -> bool {
        if self.namespace != other.namespace {
            return false;
        }

        if self.operations.len() != other.operations.len() {
            return false;
        }

        self.operations
            .iter()
            .zip(&other.operations)
            .all(|(a, b)| a.is_equivalent(b))
    }

    /// Execute the sequence and return the final summary
    fn execute(&self) -> Summary {
        assert!(
            !self.operations.is_empty(),
            "Empty sequences cannot be executed"
        );
        let mut transcript = Transcript::new(&self.namespace);

        for op in &self.operations {
            match op {
                FuzzedOperation::Commit(op) => {
                    op.apply(&mut transcript);
                }
            }
        }

        transcript.summarize()
    }
}

#[derive(Debug)]
struct FuzzInput {
    sequence1: TranscriptSequence,
    sequence2: TranscriptSequence,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(FuzzInput {
            sequence1: TranscriptSequence::arbitrary(u)?,
            sequence2: TranscriptSequence::arbitrary(u)?,
        })
    }
}

fn fuzz(input: FuzzInput) {
    let s1 = input.sequence1.execute();
    let s2 = input.sequence2.execute();
    let are_equivalent = input.sequence1.is_equivalent(&input.sequence2);

    if are_equivalent {
        assert_eq!(s1, s2, "Equivalent sequences produced different summaries");
    } else {
        assert_ne!(s1, s2, "Non-equivalent sequences produced same summaries");
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
