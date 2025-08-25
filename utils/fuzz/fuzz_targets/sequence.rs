#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode, EncodeFixed, FixedSize};
use commonware_utils::sequence::{prefixed_u64::U64 as PrefixedU64, FixedBytes, U32, U64};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    TestFixedBytes { data: Vec<u8> },
    TestU64 { value: u64 },
    TestU32 { value: u32 },
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
            assert_eq!(u64_array, value.into());

            let from_u64: U64 = value.into();
            assert_eq!(from_u64, value.into());

            let bytes = value.to_be_bytes();
            let from_bytes: U64 = bytes.into();
            assert_eq!(from_bytes, value.into());

            let as_ref: &[u8] = u64_array.as_ref();
            assert_eq!(as_ref.len(), 8);
            assert_eq!(as_ref, &bytes);

            let encoded: [u8; U64::SIZE] = u64_array.encode_fixed();
            assert_eq!(encoded.len(), U64::SIZE);

            let decoded = U64::decode(&encoded[..]).unwrap();
            assert_eq!(decoded, value.into());

            let short_data = &encoded[..encoded.len().saturating_sub(1)];
            assert!(U64::decode(short_data).is_err());

            let back_to_u64: u64 = u64_array.clone().into();
            assert_eq!(back_to_u64, value);

            let back_to_u64_ref: u64 = (&u64_array).into();
            assert_eq!(back_to_u64_ref, value);

            let deref_slice: &[u8] = &u64_array;
            assert_eq!(deref_slice.len(), 8);
            assert_eq!(deref_slice, &bytes);

            let debug_str = format!("{u64_array:?}");
            assert_eq!(debug_str, value.to_string());

            let display_str = format!("{u64_array}");
            assert_eq!(display_str, value.to_string());

            assert_eq!(u64_array.len(), 8);
            assert_eq!(u64_array[0], bytes[0]);
        }

        FuzzInput::TestU32 { value } => {
            let array = U32::new(value);
            assert_eq!(value, U32::decode(array.as_ref()).unwrap().into());

            let vec = array.to_vec();
            assert_eq!(value, U32::decode(vec.as_ref()).unwrap().into());

            let original = U32::new(value);
            let encoded = original.encode();
            assert_eq!(encoded.len(), U32::SIZE);
            assert_eq!(encoded, original.as_ref());
            let decoded = U32::decode(encoded).unwrap();
            assert_eq!(original, decoded);

            let bytes_array = value.to_be_bytes();
            let from_array: U32 = bytes_array.into();
            assert_eq!(from_array, value.into());

            let from_u32: U32 = value.into();
            assert_eq!(from_u32, U32::new(value));

            let back_to_u32: u32 = array.clone().into();
            assert_eq!(back_to_u32, value);

            let back_to_u32_ref: u32 = (&array).into();
            assert_eq!(back_to_u32_ref, value);

            let deref_slice: &[u8] = &array;
            assert_eq!(deref_slice.len(), 4);
            assert_eq!(deref_slice, &bytes_array);

            let debug_str = format!("{array:?}");
            assert_eq!(debug_str, value.to_string());

            let display_str = format!("{array}");
            assert_eq!(display_str, value.to_string());

            assert_eq!(array.len(), 4);
            assert_eq!(array[0], bytes_array[0]);
        }

        FuzzInput::TestPrefixed { prefix, value } => {
            let prefixed = PrefixedU64::new(prefix, value);
            assert_eq!(prefixed.prefix(), prefix);
            assert_eq!(prefixed.value(), value);

            let as_ref: &[u8] = prefixed.as_ref();
            assert_eq!(as_ref.len(), 9);
            assert_eq!(as_ref[0], prefix);
            assert_eq!(&as_ref[1..], &value.to_be_bytes());

            let encoded: [u8; PrefixedU64::SIZE] = prefixed.encode_fixed();
            assert_eq!(encoded.len(), PrefixedU64::SIZE);

            let decoded = PrefixedU64::decode(&encoded[..]).unwrap();
            assert_eq!(decoded.prefix(), prefix);
            assert_eq!(decoded.value(), value);

            let short_data = &encoded[..encoded.len().saturating_sub(1)];
            assert!(PrefixedU64::decode(short_data).is_err());

            let bytes_array: [u8; PrefixedU64::SIZE] = encoded;
            let from_array: PrefixedU64 = bytes_array.into();
            assert_eq!(from_array.prefix(), prefix);
            assert_eq!(from_array.value(), value);
            assert_eq!(from_array, prefixed);

            let as_ref_slice: &[u8] = prefixed.as_ref();
            assert_eq!(as_ref_slice, &encoded);
            assert_eq!(as_ref_slice.len(), PrefixedU64::SIZE);

            let deref_slice: &[u8] = &prefixed;
            assert_eq!(deref_slice.len(), 9);
            assert_eq!(deref_slice, &encoded);
            assert_eq!(deref_slice[0], prefix);

            let debug_str = format!("{prefixed:?}");
            let expected_debug = format!("{prefix}:{value}");
            assert_eq!(debug_str, expected_debug);

            let display_str = format!("{prefixed}");
            assert_eq!(display_str, expected_debug);

            assert_eq!(prefixed.len(), 9);
            assert_eq!(prefixed[0], prefix);
            assert_eq!(prefixed[1], value.to_be_bytes()[0]);

            assert_eq!(prefixed.as_ref(), &*prefixed);
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
