#![no_main]

use arbitrary::Arbitrary;
use commonware_utils::{
    from_hex, from_hex_formatted, hex, max_faults, modulo, quorum, union, union_unique,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum LibFunction {
    Hex { data: Vec<u8> },
    FromHex { hex_str: String },
    FromHexFormatted { hex_str: String },
    MaxFaults { n: u32 },
    Quorum { n: u32 },
    Union { a: Vec<u8>, b: Vec<u8> },
    UnionUnique { namespace: Vec<u8>, msg: Vec<u8> },
    Modulo { bytes: Vec<u8>, n: u64 },
}

fuzz_target!(|operation: LibFunction| {
    match operation {
        LibFunction::Hex { data } => {
            let hex_str = hex(&data);

            assert_eq!(hex_str.len(), data.len() * 2);
            assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));

            if !data.is_empty() {
                if let Some(decoded) = from_hex(&hex_str) {
                    assert_eq!(decoded, data);
                }
            }
        }

        LibFunction::FromHex { hex_str } => {
            let result = from_hex(&hex_str);

            if let Some(decoded) = result {
                let re_encoded = hex(&decoded);
                assert_eq!(from_hex(&re_encoded), Some(decoded));
            }
        }

        LibFunction::FromHexFormatted { hex_str } => {
            let result = from_hex_formatted(&hex_str);

            if let Some(decoded) = result.clone() {
                let clean_hex = hex(&decoded);
                assert_eq!(from_hex(&clean_hex), Some(decoded));
            }

            let with_prefix = format!("0x{hex_str}");
            from_hex_formatted(&with_prefix);
        }

        LibFunction::MaxFaults { n } => {
            if n == 0 {
                return;
            }
            let faults = max_faults(n);

            assert_eq!(faults, (n.saturating_sub(1)) / 3);

            assert!(faults <= (n.saturating_sub(1)) / 3);

            let q = quorum(n);
            assert_eq!(q + faults, n);
        }

        LibFunction::Quorum { n } => {
            if n == 0 {
                return;
            }
            let q = quorum(n);
            let faults = max_faults(n);

            assert_eq!(q, n - faults);

            if faults > 0 {
                assert!(q > 2 * faults);
            }
        }

        LibFunction::Union { a, b } => {
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

        LibFunction::UnionUnique { namespace, msg } => {
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

        LibFunction::Modulo { bytes, n } => {
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
});
