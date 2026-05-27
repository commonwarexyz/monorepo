#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::Secret;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    a: [u8; 32],
    b: [u8; 32],
}

fuzz_target!(|input: FuzzInput| {
    let FuzzInput { a, b } = input;

    let sa = Secret::new(a);
    let sb = Secret::new(b);

    // Debug and Display must never reveal the wrapped bytes.
    assert_eq!(format!("{sa:?}"), "Secret([REDACTED])");
    assert_eq!(format!("{sa}"), "[REDACTED]");

    // `expose` yields the wrapped value unchanged.
    sa.expose(|v| assert_eq!(v, &a));

    // Constant-time equality must agree with plain comparison.
    assert_eq!(sa == sb, a == b);

    // Clone preserves contents and equality.
    let clone = sa.clone();
    assert!(clone == sa);
    clone.expose(|v| assert_eq!(v, &a));

    // `expose_unwrap` returns the original value (and zeroizes the source).
    assert_eq!(sb.expose_unwrap(), b);
});
