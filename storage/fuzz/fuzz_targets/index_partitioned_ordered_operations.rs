#![no_main]

//! Apply index operations and ordered navigation to a partitioned ordered index and check every
//! read, and the final key and item gauges, against a model keyed by the partition prefix plus the
//! translated sub-key. Grinds and repeated inserts spill partitions past their sorted arrays, and
//! cursor deletes empty them back. The input picks the sub-key translator, so partitions sort and
//! spill both integer and array translated keys.

use arbitrary::{Arbitrary, Unstructured};
use commonware_runtime::{Metrics as _, Runner, Supervisor as _, deterministic};
use commonware_storage::{
    index::partitioned::ordered::Index,
    translator::{Cap, EightCap, FourCap, OneCap, OrderedTranslator, TwoCap},
};
use commonware_storage_fuzz::{
    index::{Model, Navigation, Operation},
    stream,
};
use libfuzzer_sys::fuzz_target;

/// The fewest operations an input applies, so even the shortest inputs grind, spill and revisit
/// keys.
const MIN_OPERATIONS: usize = 32;

/// The most operations an input applies.
const MAX_OPERATIONS: usize = 128;

/// The translator applied to the key bytes after the partition prefix.
#[derive(Arbitrary, Debug)]
enum SubKeyTranslator {
    OneCap,
    TwoCap,
    FourCap,
    EightCap,
    Cap3,
    Cap6,
}

#[derive(Arbitrary, Debug)]
enum IndexOperation {
    Unordered(Operation),
    Ordered(Navigation),
}

#[derive(Debug)]
struct FuzzInput {
    translator: SubKeyTranslator,
    operations: Vec<IndexOperation>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let stream = stream(u)?;
        let u = &mut Unstructured::new(&stream);
        Ok(Self {
            translator: u.arbitrary()?,
            operations: (0..u.int_in_range(MIN_OPERATIONS..=MAX_OPERATIONS)?)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
        })
    }
}

/// Run the operations on a `P`-byte-prefix index whose translator `T` keeps `cap` sub-key bytes.
fn fuzz_prefix<T: OrderedTranslator + Default, const P: usize>(input: &FuzzInput, cap: usize) {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut index = Index::<_, u64, P>::new(context.child("index"), T::default());
        let mut model = Model::new(P + cap);

        for op in &input.operations {
            match op {
                IndexOperation::Unordered(op) => model.apply(&mut index, op),
                IndexOperation::Ordered(nav) => model.navigate(&index, nav),
            }
        }

        model.assert_index(&index);
        model.assert_metrics(&context.encode());
    });
}

fn fuzz_translator<T: OrderedTranslator + Default>(input: &FuzzInput, cap: usize) {
    // One prefix byte crowds keys into few partitions so they spill sooner. Two bytes route short
    // keys by right-padding them into the prefix, which must keep the partition order lexicographic.
    fuzz_prefix::<T, 1>(input, cap);
    fuzz_prefix::<T, 2>(input, cap);
}

fn fuzz(input: FuzzInput) {
    match input.translator {
        SubKeyTranslator::OneCap => fuzz_translator::<OneCap>(&input, 1),
        SubKeyTranslator::TwoCap => fuzz_translator::<TwoCap>(&input, 2),
        SubKeyTranslator::FourCap => fuzz_translator::<FourCap>(&input, 4),
        SubKeyTranslator::EightCap => fuzz_translator::<EightCap>(&input, 8),
        SubKeyTranslator::Cap3 => fuzz_translator::<Cap<3>>(&input, 3),
        SubKeyTranslator::Cap6 => fuzz_translator::<Cap<6>>(&input, 6),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
