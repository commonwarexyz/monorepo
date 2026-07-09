# Conformance testing

Conformance tests protect wire and storage formats by hashing deterministic output and comparing it with `conformance.toml` fixtures.

## Commands

```bash
just test-conformance
just test-conformance -p commonware-codec -p commonware-cryptography
```

Regenerate fixtures only after deliberately changing a format and verifying the result:

```bash
just regenerate-conformance
just regenerate-conformance -p commonware-codec -p commonware-storage
```

Regeneration is an explicit approval of the new format. Do not use it merely to make a failing test pass.

## New codec types

New encoded public types should have an `arbitrary::Arbitrary` implementation behind the `arbitrary` feature and a conformance test in the module's test block:

```rust
#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for MyType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(my_instance)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "arbitrary")]
    mod conformance {
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<MyType>,
            CodecConformance<MyType2> => 1024,
        }
    }
}
```

The optional number is the number of generated cases. Missing fixtures are added automatically by the test framework; changed hashes fail the test until they are intentionally regenerated.
