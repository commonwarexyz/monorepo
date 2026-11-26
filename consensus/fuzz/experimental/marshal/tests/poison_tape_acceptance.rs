use arbitrary::Unstructured;
use commonware_consensus::simplex::ForwardPolicy;
use commonware_consensus_fuzz_marshal::marshal::{
    MarshalDisrupterInput,
    poison_tape::{FuzzInput, coding},
};

const BASE_BYTES: [u8; 16] = [
    0x3c, 0x07, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x21, 0xfd, 0x07, 0xab, 0xe4, 0xe0, 0xb6,
];
const FIXED_TAPES: [u8; 8] = [2, 44, 76, 102, 111, 172, 207, 242];
const MAX_RAW_BYTES: usize = 32_768;

fn decode<T: for<'a> arbitrary::Arbitrary<'a>>(bytes: &[u8]) -> T {
    T::arbitrary(&mut Unstructured::new(bytes)).expect("the input must decode")
}

fn fixed_input(tape: u8) -> FuzzInput {
    let base = decode::<MarshalDisrupterInput>(&BASE_BYTES);
    assert_eq!(base.required_containers, 7);
    assert!(matches!(base.forwarding, ForwardPolicy::Disabled));
    FuzzInput {
        raw_bytes: vec![tape],
        base,
    }
}

fn assert_same_base(actual: &MarshalDisrupterInput, expected: &MarshalDisrupterInput) {
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

fn assert_decode(bytes: &[u8]) {
    let actual = decode::<FuzzInput>(bytes);
    let expected = decode::<MarshalDisrupterInput>(bytes);
    assert_eq!(actual.raw_bytes, bytes[..bytes.len().min(MAX_RAW_BYTES)]);
    assert_same_base(&actual.base, &expected);
}

#[test]
fn poison_tape_at_001_at_002_public_entries_accept_a_constructed_value() {
    let input = fixed_input(FIXED_TAPES[0]);
    let _ = coding::run(input.clone());
    coding::fuzz(input);
}

#[test]
fn poison_tape_at_004_at_013_tape_first_decoding_preserves_the_base() {
    assert_decode(&[]);
    assert_decode(&[0; 64]);
    assert_decode(&[0xff; 64]);

    for byte in 0..=u8::MAX {
        let input = decode::<FuzzInput>(&[byte]);
        assert_eq!(input.raw_bytes, [byte]);
        assert_same_base(&input.base, &decode::<MarshalDisrupterInput>(&[byte]));
    }

    for length in [15, 16, 17, 32_768, 32_769] {
        let bytes = (0..length)
            .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
            .collect::<Vec<_>>();
        assert_decode(&bytes);
    }

    for case in 0..1_000usize {
        let length = case.wrapping_mul(73) % 257;
        let bytes = (0..length)
            .map(|index| {
                (case as u8)
                    .wrapping_mul(29)
                    .wrapping_add((index as u8).wrapping_mul(101))
            })
            .collect::<Vec<_>>();
        assert_decode(&bytes);
    }
}

macro_rules! fixed_case {
    ($name:ident, $tape:expr) => {
        #[test]
        fn $name() {
            let _ = coding::run(fixed_input($tape));
        }
    };
}

fixed_case!(poison_tape_at_007_f2_1, 2);
fixed_case!(poison_tape_at_007_f2_2, 44);
fixed_case!(poison_tape_at_007_f2_3, 76);
fixed_case!(poison_tape_at_007_f2_4, 102);
fixed_case!(poison_tape_at_007_f2_5, 111);
fixed_case!(poison_tape_at_007_f2_6, 172);
fixed_case!(poison_tape_at_007_f2_7, 207);
fixed_case!(poison_tape_at_007_f2_8, 242);

#[test]
fn poison_tape_at_005_at_009_at_011_at_012_scenarios_pass_and_replay() {
    let empty = decode::<FuzzInput>(&[]);
    let old_empty = decode::<MarshalDisrupterInput>(&[]);
    assert!(empty.raw_bytes.is_empty());
    assert_same_base(&empty.base, &old_empty);
    assert_eq!(empty.base.required_containers, 1);
    assert!(matches!(empty.base.forwarding, ForwardPolicy::Disabled));
    coding::fuzz(empty);

    let first = coding::run(fixed_input(FIXED_TAPES[0]));
    let second = coding::run(fixed_input(FIXED_TAPES[0]));
    assert_eq!(first, second);
}
