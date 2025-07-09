#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, EncodeFixed, FixedSize};
use commonware_utils::array::{prefixed_u64::U64 as PrefixedU64, FixedBytes, U64};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    TestFixedBytes { data: Vec<u8> },
    TestU64 { value: u64 },
    TestPrefixed { prefix: u8, value: u64 },
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::TestFixedBytes { data } => match data.len() {
            1 => test_fixed_bytes::<1>(&data),
            2 => test_fixed_bytes::<2>(&data),
            4 => test_fixed_bytes::<4>(&data),
            8 => test_fixed_bytes::<8>(&data),
            16 => test_fixed_bytes::<16>(&data),
            32 => test_fixed_bytes::<32>(&data),
            64 => test_fixed_bytes::<64>(&data),
            128 => test_fixed_bytes::<128>(&data),
            256 => test_fixed_bytes::<256>(&data),
            512 => test_fixed_bytes::<512>(&data),
            _ => (),
        },

        FuzzInput::TestU64 { value } => {
            let u64_array = U64::new(value);
            assert_eq!(u64_array.to_u64(), value);

            let from_u64: U64 = value.into();
            assert_eq!(from_u64.to_u64(), value);

            let bytes = value.to_be_bytes();
            let from_bytes: U64 = bytes.into();
            assert_eq!(from_bytes.to_u64(), value);

            let as_ref: &[u8] = u64_array.as_ref();
            assert_eq!(as_ref.len(), 8);
            assert_eq!(as_ref, &bytes);

            let encoded: [u8; U64::SIZE] = u64_array.encode_fixed();
            assert_eq!(encoded.len(), U64::SIZE);

            let decoded = U64::decode(&encoded[..]).unwrap();
            assert_eq!(decoded.to_u64(), value);

            let short_data = &encoded[..encoded.len().saturating_sub(1)];
            assert!(U64::decode(short_data).is_err());
        }

        FuzzInput::TestPrefixed { prefix, value } => {
            let prefixed = PrefixedU64::new(prefix, value);
            assert_eq!(prefixed.prefix(), prefix);
            assert_eq!(prefixed.to_u64(), value);

            let as_ref: &[u8] = prefixed.as_ref();
            assert_eq!(as_ref.len(), 9);
            assert_eq!(as_ref[0], prefix);
            assert_eq!(&as_ref[1..], &value.to_be_bytes());

            let encoded: [u8; PrefixedU64::SIZE] = prefixed.encode_fixed();
            assert_eq!(encoded.len(), PrefixedU64::SIZE);

            let decoded = PrefixedU64::decode(&encoded[..]).unwrap();
            assert_eq!(decoded.prefix(), prefix);
            assert_eq!(decoded.to_u64(), value);

            let short_data = &encoded[..encoded.len().saturating_sub(1)];
            assert!(PrefixedU64::decode(short_data).is_err());
        }
    }
}

fn test_fixed_bytes<const N: usize>(data: &[u8]) {
    if data.len() == N {
        let array: [u8; N] = data[..N].try_into().unwrap();
        let fixed = FixedBytes::<N>::new(array);

        let as_ref: &[u8] = fixed.as_ref();
        assert_eq!(as_ref, &array);

        assert_eq!(&*fixed, &array);

        let display = format!("{fixed}");
        assert!(!display.is_empty());

        let encoded: [u8; N] = fixed.encode_fixed();
        assert_eq!(encoded.len(), N);

        let decoded = FixedBytes::<N>::decode(&encoded[..]).unwrap();
        assert_eq!(fixed.as_ref(), decoded.as_ref());

        let short_data = &encoded[..N - 1];
        assert!(FixedBytes::<N>::decode(short_data).is_err());
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
