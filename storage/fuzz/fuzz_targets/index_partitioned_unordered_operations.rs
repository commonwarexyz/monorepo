#![no_main]

//! Apply index operations to a partitioned unordered index and check every read, and the final
//! key and item gauges, against a model keyed by the partition prefix plus the translated sub-key.
//! The input picks the sub-key translator, so partitions hash both integer and array translated
//! keys.

use arbitrary::Arbitrary;
use commonware_runtime::{Metrics as _, Runner, Supervisor as _, deterministic};
use commonware_storage::{
    index::partitioned::unordered::Index,
    translator::{Cap, EightCap, FourCap, OneCap, Translator, TwoCap},
};
use commonware_storage_fuzz::index::{Model, Operation};
use libfuzzer_sys::fuzz_target;

/// Prefix bytes that select a partition. Each of the `2^(8*P)` partitions is a hash sub-index, so
/// `P=2` is too heavy to build per input.
const PREFIX: usize = 1;

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
struct FuzzInput {
    translator: SubKeyTranslator,
    operations: Vec<Operation>,
}

/// Run the operations on an index whose translator `T` keeps `cap` sub-key bytes.
fn fuzz_translator<T: Translator + Default>(input: &FuzzInput, cap: usize) {
    let runner = deterministic::Runner::default();
    runner.start(|context| async move {
        let mut index = Index::<_, u64, PREFIX>::new(context.child("index"), T::default());
        let mut model = Model::new(PREFIX + cap);

        for op in &input.operations {
            model.apply(&mut index, op);
        }

        model.assert_index(&index);
        model.assert_metrics(&context.encode());
    });
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
