#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_utils::hostname::{Error, Hostname, MAX_HOSTNAME_LABEL_LEN, MAX_HOSTNAME_LEN};
use libfuzzer_sys::fuzz_target;

const KNOWN_GOOD: &[&str] = &[
    "a",
    "localhost",
    "example.com",
    "sub.example.com",
    "deep.sub.example.com",
    "my-host",
    "a-b-c.d-e-f.com",
    "1host.2example.3com",
    "Example.COM",
];

/// Reference validator that mirrors the documented RFC 1035/1123 rules.
///
/// Returns the same error variant the production validator should produce for
/// a given input, so the fuzz target can detect divergence in either direction.
fn classify(s: &str) -> Result<(), Error> {
    if s.is_empty() {
        return Err(Error::Empty);
    }
    if s.len() > MAX_HOSTNAME_LEN {
        return Err(Error::TooLong);
    }
    for label in s.split('.') {
        if label.is_empty() {
            return Err(Error::EmptyLabel);
        }
        if label.len() > MAX_HOSTNAME_LABEL_LEN {
            return Err(Error::LabelTooLong);
        }
        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return Err(Error::InvalidCharacter);
            }
        }
        if label.starts_with('-') {
            return Err(Error::LabelStartsWithHyphen);
        }
        if label.ends_with('-') {
            return Err(Error::LabelEndsWithHyphen);
        }
    }
    Ok(())
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    raw: String,
    bytes: Vec<u8>,
}

fn fuzz(input: FuzzInput) {
    // 1. Validation parity: production validator must agree with the oracle on
    //    every input.
    let expected = classify(&input.raw);
    let actual = Hostname::new(input.raw.clone()).map(|_| ());
    assert_eq!(
        actual, expected,
        "validator/oracle divergence on {:?}",
        input.raw
    );

    // 2. Round-trip: every accepted hostname must encode and decode to itself.
    if let Ok(h) = Hostname::new(input.raw.clone()) {
        let encoded = h.encode();
        let decoded = Hostname::decode(encoded).expect("valid hostname round-trips");
        assert_eq!(decoded, h);
        assert_eq!(decoded.as_str(), input.raw);
    }

    // 3. Known-good corpus must always be accepted.
    for &good in KNOWN_GOOD {
        Hostname::new(good).unwrap_or_else(|e| panic!("known-good {good:?} rejected: {e:?}"));
    }

    // 4. Wire decoding: a length-prefixed arbitrary byte payload must accept iff
    //    the bytes form valid UTF-8 that is also a valid hostname per the oracle.
    //    We encode bytes as a Vec<u8> (which is the same wire format Hostname
    //    uses) then decode through Hostname::decode and assert consistency.
    let bytes = input.bytes;
    if bytes.len() <= MAX_HOSTNAME_LEN {
        let encoded = bytes.encode();
        let decoded = Hostname::decode(encoded);
        let expected_ok = core::str::from_utf8(&bytes)
            .ok()
            .is_some_and(|s| classify(s).is_ok());
        assert_eq!(
            decoded.is_ok(),
            expected_ok,
            "codec/oracle divergence on bytes={:?}",
            bytes
        );
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
