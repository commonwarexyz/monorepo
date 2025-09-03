#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::{
    from_hex, from_hex_formatted, hex, max_faults, modulo, quorum, quorum_from_slice, union,
    union_unique, NZUsize, NonZeroDuration, NZU32, NZU64,
};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Hex { data: Vec<u8> },
    FromHex { hex_str: String },
    FromHexFormatted { hex_str: String },
    MaxFaults { n: u32 },
    Quorum { n: u32 },
    QuorumFromSlice { a: Vec<u8> },
    Union { a: Vec<u8>, b: Vec<u8> },
    UnionUnique { namespace: Vec<u8>, msg: Vec<u8> },
    Modulo { bytes: Vec<u8>, n: u64 },
    NZUsize { v: usize },
    NZU32 { v: u32 },
    NZU64 { v: u64 },
    NonZeroDuration { millis: u64 },
}

fn fuzz(input: FuzzInput) {
    match input {
        FuzzInput::NZUsize { v } => {
            if v != 0 {
                let _ = NZUsize!(v).get() == v;
            }
        }

        FuzzInput::NZU32 { v } => {
            if v != 0 {
                let _ = NZU32!(v).get() == v;
            }
        }

        FuzzInput::NZU64 { v } => {
            if v != 0 {
                let _ = NZU64!(v).get() == v;
            }
        }

        FuzzInput::NonZeroDuration { millis } => {
            let duration = Duration::from_millis(millis);

            let nz_duration = NonZeroDuration::new(duration);
            if let Some(nz_duration) = nz_duration {
                assert_eq!(nz_duration.get(), duration);

                let converted: Duration = nz_duration.into();
                assert_eq!(converted, duration);

                let nz_duration = NonZeroDuration::new_panic(duration);
                assert_eq!(nz_duration.get(), duration);
            }
        }

        FuzzInput::Hex { data } => {
            let hex_str = hex(&data);
            if let Some(decoded) = from_hex(&hex_str) {
                assert_eq!(decoded, data);
            }
        }

        FuzzInput::FromHex { hex_str } => {
            if !hex_str.is_empty() && !hex_str.chars().any(|c| c.is_ascii_hexdigit()) {
                assert_eq!(from_hex(&hex_str), None)
            } else if let Some(decoded) = from_hex(&hex_str) {
                let re_encoded = hex(&decoded);
                assert_eq!(from_hex(&re_encoded), Some(decoded));
            }
        }

        FuzzInput::FromHexFormatted { hex_str } => {
            let result = from_hex_formatted(&hex_str);

            if let Some(decoded) = result.clone() {
                let clean_hex = hex(&decoded);
                assert_eq!(from_hex(&clean_hex), Some(decoded));
            }

            let with_prefix = format!("0x{hex_str}");
            from_hex_formatted(&with_prefix);
        }

        FuzzInput::MaxFaults { n } => {
            if n == 0 {
                return;
            }
            let faults = max_faults(n);
            assert_eq!(faults, (n.saturating_sub(1)) / 3);

            let q = quorum(n);
            assert_eq!(q + faults, n);
        }

        FuzzInput::Quorum { n } => {
            if n == 0 {
                return;
            }
            let q = quorum(n);
            let faults = max_faults(n);

            assert_eq!(q, n - faults);
        }

        FuzzInput::QuorumFromSlice { a } => {
            let l = a.len() as u32;
            if l == 0 {
                return;
            }
            let q = quorum_from_slice(a.as_slice());
            assert_eq!(q, quorum(l));
        }

        FuzzInput::Union { a, b } => {
            let result = union(&a, &b);

            assert_eq!(result.len(), a.len() + b.len());
            if !a.is_empty() {
                assert_eq!(&result[..a.len()], &a[..]);
            }
            if !b.is_empty() {
                assert_eq!(&result[a.len()..], &b[..]);
            }

            let empty_a = union(&[], &b);
            assert_eq!(empty_a, b);

            let empty_b = union(&a, &[]);
            assert_eq!(empty_b, a);
        }

        FuzzInput::UnionUnique { namespace, msg } => {
            let result = union_unique(&namespace, &msg);

            assert!(!result.is_empty());
            assert!(result.len() > namespace.len() + msg.len());

            let result2 = union_unique(&namespace, &msg);
            assert_eq!(result, result2);

            let empty_ns = union_unique(&[], &msg);
            assert!(!empty_ns.is_empty());

            let empty_msg = union_unique(&namespace, &[]);
            assert!(!empty_msg.is_empty());
        }

        FuzzInput::Modulo { bytes, n } => {
            if n == 0 {
                return;
            }

            let result = modulo(&bytes, n);

            assert!(result < n);
            assert_eq!(modulo(&[], n), 0);

            let result2 = modulo(&bytes, n);
            assert_eq!(result, result2);

            if n == 1 {
                assert_eq!(result, 0);
            }

            let zeros = vec![0u8; bytes.len()];
            assert_eq!(modulo(&zeros, n), 0);
        }
    }
}

fuzz_target!(|op: FuzzInput| {
    fuzz(op);
});
