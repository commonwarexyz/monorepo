use super::*;
use crate::{BanderScalar, Bls12381, BlsScalar, Curve25519};
use arbitrary::{Arbitrary, Unstructured};

const REGISTER_COUNT: usize = 8;
const RANDOM_REGISTER_COUNT: usize = REGISTER_COUNT - 3;
const MAX_OPERATIONS: usize = 12;

/// A modulus-specific bounded RNS fuzzing operation.
#[derive(Clone, Copy, Debug, Arbitrary)]
pub enum Plan {
    /// Exercise the BLS12-381 base field.
    Bls12381,
    /// Exercise the BLS12-381 scalar field.
    BlsScalar,
    /// Exercise the Banderwagon scalar field.
    BanderScalar,
    /// Exercise the Curve25519 base field.
    Curve25519,
}

impl Plan {
    /// Runs the operation with the best backend supported by this CPU.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        let inputs: [Input; RANDOM_REGISTER_COUNT] = u.arbitrary()?;
        let count = u.int_in_range(1..=MAX_OPERATIONS)?;
        let operations = (0..count)
            .map(|_| u.arbitrary())
            .collect::<arbitrary::Result<Vec<Operation>>>()?;

        struct Run<'a> {
            plan: Plan,
            inputs: &'a [Input; RANDOM_REGISTER_COUNT],
            operations: &'a [Operation],
        }

        impl WithBackend for Run<'_> {
            type Output = ();

            fn call<B: Backend>(self, backend: B) {
                match self.plan {
                    Plan::Bls12381 => {
                        matches_portable::<Bls12381, _>(self.inputs, self.operations, backend)
                    }
                    Plan::BlsScalar => {
                        matches_portable::<BlsScalar, _>(self.inputs, self.operations, backend)
                    }
                    Plan::BanderScalar => {
                        matches_portable::<BanderScalar, _>(self.inputs, self.operations, backend)
                    }
                    Plan::Curve25519 => {
                        matches_portable::<Curve25519, _>(self.inputs, self.operations, backend)
                    }
                }
            }
        }

        with_backend(Run {
            plan: self,
            inputs: &inputs,
            operations: &operations,
        });
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Arbitrary)]
struct Input {
    bytes: [u8; 48],
    mode: u8,
}

#[derive(Clone, Copy, Debug, Arbitrary)]
enum Operation {
    Add {
        output: u8,
        left: u8,
        right: u8,
    },
    Subtract {
        output: u8,
        left: u8,
        right: u8,
    },
    Negate {
        output: u8,
        input: u8,
    },
    Multiply {
        output: u8,
        left: u8,
        right: u8,
    },
    DelayedSum {
        output: u8,
        inputs: [u8; 4],
    },
    ScaledProduct {
        output: u8,
        left: u8,
        right: u8,
        select: u8,
    },
    OffsetDifference {
        output: u8,
        left: u8,
        right: u8,
    },
    SumOfProducts {
        output: u8,
        left: [u8; 4],
        right: [u8; 4],
    },
    SignedSum {
        output: u8,
        left: [u8; 4],
        right: [u8; 4],
        signs: u8,
    },
}

impl Operation {
    fn apply<P: Modulus, B: Backend>(
        &self,
        ring: &Ring<P, B>,
        registers: &mut [Standard<P>; REGISTER_COUNT],
    ) -> (Standard<P>, &'static str) {
        // Read every operand before replacing the output register, including when the output
        // aliases an input.
        let (output, value, property) = match *self {
            Self::Add {
                output,
                left,
                right,
            } => (
                output,
                ring.add(registers[register(left)], registers[register(right)]),
                "addition",
            ),
            Self::Subtract {
                output,
                left,
                right,
            } => (
                output,
                ring.sub(registers[register(left)], registers[register(right)]),
                "subtraction",
            ),
            Self::Negate { output, input } => (
                output,
                ring.standard_negate(registers[register(input)]),
                "negation",
            ),
            Self::Multiply {
                output,
                left,
                right,
            } => (
                output,
                ring.mul(registers[register(left)], registers[register(right)]),
                "multiplication",
            ),
            Self::DelayedSum { output, inputs } => {
                let [a, b, c, d] = inputs.map(register);
                let value = ring.batch_reduce_expand(&[ring.ready::<800>(
                    ring.prep_left(registers[a]) * registers[b]
                        + ring.prep_left(registers[c]) * registers[d],
                )])[0];
                (output, value, "delayed product sum")
            }
            Self::ScaledProduct {
                output,
                left,
                right,
                select,
            } => {
                let products =
                    scaled_product(ring, registers[register(left)], registers[register(right)]);
                let choice = usize::from(select) % products.len();
                (output, products[choice], "scaled product")
            }
            Self::OffsetDifference {
                output,
                left,
                right,
            } => {
                let product = (ring.prep_left(registers[register(left)])
                    * registers[register(right)])
                .complete();
                let value = ring.batch_reduce_expand(&[
                    ring.ready::<800>(ring.wide_offset::<80, 1440>() - product)
                ])[0];
                (output, value, "offset product difference")
            }
            Self::SumOfProducts {
                output,
                left,
                right,
            } => {
                let left = left.map(|index| Element::from(registers[register(index)]));
                let right = right.map(|index| Element::from(registers[register(index)]));
                (
                    output,
                    ring.sum_of_products(&left, &right),
                    "sum of products",
                )
            }
            Self::SignedSum {
                output,
                left,
                right,
                signs,
            } => {
                let left = left.map(|index| Element::from(registers[register(index)]));
                let right = right.map(|index| Element::from(registers[register(index)]));
                let terms: [SignedTerm<'_, P>; 4] =
                    array::from_fn(|i| (&left[i], &right[i], Choice::from((signs >> i) & 1)));
                (output, ring.signed_sum(&[terms])[0], "signed sum")
            }
        };

        registers[register(output)] = value;
        (value, property)
    }
}

const fn register(index: u8) -> usize {
    index as usize % REGISTER_COUNT
}

fn maximum<P: Modulus>() -> Standard<P> {
    let mut words = P::PARAMETERS.modulus;
    words[0] -= 1;
    Standard::from(Element::<P>::from_raw(&words).expect("p - 1 is canonical"))
}

fn assert_matches<P: Modulus>(selected: Standard<P>, portable: Standard<P>, property: &str) {
    assert_eq!(selected.halves, portable.halves, "{property}: RNS lanes");
    assert_eq!(
        Element::from(selected),
        Element::from(portable),
        "{property}: field value"
    );
}

fn assert_field_eq<P: Modulus>(actual: Standard<P>, expected: Standard<P>, property: &str) {
    assert_eq!(Element::from(actual), Element::from(expected), "{property}");
}

#[cfg(test)]
fn fixed_edges_match_portable<P: Modulus, B: Backend>(
    selected: &Ring<P, B>,
    portable: &Ring<P, kernel::Portable>,
) {
    let zero = Standard::ZERO;
    let maximum = maximum::<P>();
    assert_matches(
        selected.mul(maximum, maximum),
        portable.mul(maximum, maximum),
        "maximum product",
    );
    assert_eq!(
        bool::from(selected.is_zero(zero)),
        bool::from(portable.is_zero(zero)),
        "zero predicate"
    );

    let empty: [Element<P>; 0] = [];
    assert_matches(
        selected.sum_of_products(&empty, &empty),
        portable.sum_of_products(&empty, &empty),
        "empty sum of products",
    );
    let empty_signed: [SignedTerm<'_, P>; 0] = [];
    assert_matches(
        selected.signed_sum(&[empty_signed])[0],
        portable.signed_sum(&[empty_signed])[0],
        "empty signed sum",
    );

    // Seventeen products cross the public sixteen-product reduction boundary.
    let maximum = Element::from(maximum);
    let carry_left = [maximum; 17];
    let carry_right = [maximum; 17];
    assert_matches(
        selected.sum_of_products(&carry_left, &carry_right),
        portable.sum_of_products(&carry_left, &carry_right),
        "chunked maximum sum of products",
    );

    // Thirty-three signed terms cross the public thirty-two-term reduction boundary.
    let signed = [(&maximum, &maximum, Choice::from(0)); 33];
    assert_matches(
        selected.signed_sum(&[signed])[0],
        portable.signed_sum(&[signed])[0],
        "chunked maximum signed sum",
    );
}

fn scaled_product<P: Modulus, B: Backend>(
    ring: &Ring<P, B>,
    left: Standard<P>,
    right: Standard<P>,
) -> [Standard<P>; 2] {
    let product = (ring.prep_left(left) * right).complete();
    let doubled = ring.batch_reduce_expand(&[ring.ready::<800>(product.scale::<2>())])[0];
    let small = ring.batch_reduce(&[ring.ready::<800>(product)])[0];
    let expanded = ring.batch_expand(&[ring.prep_expand(small.scale::<6>())]);
    let sextupled = ring
        .batch_reduce_expand(&[ring.ready::<800>(ring.prep_left(expanded[0]) * Standard::ONE)])[0];
    [doubled, sextupled]
}

fn input_value<P: Modulus, B: Backend>(ring: &Ring<P, B>, input: &Input) -> Standard<P> {
    // Canonical decoding is backend-independent and owns rejection. Malformed encodings become
    // zero rather than entering the RNS computation as an invalid carrier.
    if input.mode & 1 == 1 {
        let mut encoding = P::ZERO_ENCODING;
        let length = encoding.as_ref().len();
        encoding
            .as_mut()
            .copy_from_slice(&input.bytes[input.bytes.len() - length..]);
        return Element::<P>::from_bytes(&encoding)
            .map(Standard::from)
            .unwrap_or(Standard::ZERO);
    }

    let radix = Standard::from(
        Element::<P>::from_raw(&[0, 0, 1]).expect("every supported modulus exceeds 2^128"),
    );
    let mut result = Standard::ZERO;
    for chunk in input.bytes.as_chunks::<16>().0 {
        let chunk = u128::from_be_bytes(*chunk);
        let chunk = Standard::from(
            Element::<P>::from_raw(&[chunk as u64, (chunk >> 64) as u64])
                .expect("every supported modulus exceeds 2^128"),
        );
        result = ring.add(ring.mul(result, radix), chunk);
    }
    result
}

fn check_properties<P: Modulus, B: Backend>(
    ring: &Ring<P, B>,
    inputs: &[Input; RANDOM_REGISTER_COUNT],
    registers: &[Standard<P>; REGISTER_COUNT],
) {
    // Canonical conversion and the public byte reducer must agree with the admitted values and
    // the independently scheduled 128-bit Horner reduction.
    for value in registers {
        let element = Element::from(*value);
        assert_eq!(
            Element::<P>::from_bytes(&element.to_bytes()),
            Some(element),
            "canonical roundtrip"
        );
    }
    for input in inputs {
        let reduced = Standard::from(Element::<P>::from_bytes_mod_order(&input.bytes));
        let composed = input_value(
            ring,
            &Input {
                bytes: input.bytes,
                mode: 0,
            },
        );
        assert_field_eq(composed, reduced, "byte reduction composition");
    }

    // Closed operations must satisfy the field identities over the admitted RNS values.
    let [a, b, c] = [registers[3], registers[4], registers[5]];
    let zero = Standard::ZERO;
    let one = Standard::ONE;
    assert_field_eq(ring.add(a, zero), a, "additive identity");
    assert_field_eq(
        ring.add(a, ring.standard_negate(a)),
        zero,
        "additive inverse",
    );
    assert_field_eq(ring.add(a, b), ring.add(b, a), "addition commutes");
    assert_field_eq(
        ring.add(ring.add(a, b), c),
        ring.add(a, ring.add(b, c)),
        "addition associates",
    );
    assert_field_eq(
        ring.sub(a, b),
        ring.add(a, ring.standard_negate(b)),
        "subtraction equals addition of the inverse",
    );
    assert_field_eq(ring.mul(a, one), a, "multiplicative identity");
    assert_field_eq(ring.mul(a, zero), zero, "multiplication by zero");
    assert_field_eq(ring.mul(a, b), ring.mul(b, a), "multiplication commutes");
    assert_field_eq(
        ring.mul(ring.mul(a, b), c),
        ring.mul(a, ring.mul(b, c)),
        "multiplication associates",
    );
    assert_field_eq(
        ring.mul(ring.add(a, b), c),
        ring.add(ring.mul(a, c), ring.mul(b, c)),
        "multiplication distributes",
    );
    assert_field_eq(
        Standard::from(Element::from(a).square()),
        ring.mul(a, a),
        "square equals self product",
    );

    // Fused and scaled schedules must equal their compositions from closed operations.
    let left: [Element<P>; 4] = array::from_fn(|i| Element::from(registers[i + 3]));
    let right: [Element<P>; 4] = array::from_fn(|i| Element::from(registers[i + 4]));
    let ordinary = left
        .iter()
        .zip(&right)
        .fold(Standard::ZERO, |sum, (left, right)| {
            ring.add(sum, ring.mul(Standard::from(*left), Standard::from(*right)))
        });
    assert_field_eq(
        ring.sum_of_products(&left, &right),
        ordinary,
        "fused sum of products",
    );

    let signs = inputs[0].bytes[0];
    let terms: [SignedTerm<'_, P>; 4] =
        array::from_fn(|i| (&left[i], &right[i], Choice::from((signs >> i) & 1)));
    let ordinary_signed = terms
        .iter()
        .fold(Standard::ZERO, |sum, (left, right, negative)| {
            let product = ring.mul(Standard::from(**left), Standard::from(**right));
            if bool::from(*negative) {
                ring.sub(sum, product)
            } else {
                ring.add(sum, product)
            }
        });
    assert_field_eq(
        ring.signed_sum(&[terms])[0],
        ordinary_signed,
        "signed sum of products",
    );

    let product = ring.mul(a, b);
    let [doubled, sextupled] = scaled_product(ring, a, b);
    assert_field_eq(doubled, ring.add(product, product), "doubled wide product");
    let ordinary_sextupled = (0..6).fold(Standard::ZERO, |sum, _| ring.add(sum, product));
    assert_field_eq(sextupled, ordinary_sextupled, "sextupled expanded product");
}

fn matches_portable<P: Modulus, B: Backend>(
    inputs: &[Input; RANDOM_REGISTER_COUNT],
    operations: &[Operation],
    backend: B,
) {
    let selected_ring = Ring::<P, B>::new(backend);
    let portable_ring = Ring::<P, _>::new(kernel::Portable);

    let mut selected = [Standard::ZERO; REGISTER_COUNT];
    selected[1] = Standard::ONE;
    selected[2] = maximum::<P>();
    let mut portable = selected;
    for (i, input) in inputs.iter().enumerate() {
        selected[i + 3] = input_value(&selected_ring, input);
        portable[i + 3] = input_value(&portable_ring, input);
        assert_matches(selected[i + 3], portable[i + 3], "input reduction");
    }

    check_properties(&selected_ring, inputs, &selected);

    for operation in operations {
        let (selected_output, property) = operation.apply(&selected_ring, &mut selected);
        let (portable_output, _) = operation.apply(&portable_ring, &mut portable);
        assert_matches(selected_output, portable_output, property);
    }
}

#[cfg(test)]
fn minifuzz(plan: Plan) {
    commonware_invariants::minifuzz::Builder::default()
        .with_seed(0)
        .with_search_limit(32)
        .test(|u| plan.run(u));
}

#[cfg(test)]
#[test]
fn minifuzz_bls12381() {
    minifuzz(Plan::Bls12381);
}

#[cfg(test)]
#[test]
fn minifuzz_bls_scalar() {
    minifuzz(Plan::BlsScalar);
}

#[cfg(test)]
#[test]
fn minifuzz_bander_scalar() {
    minifuzz(Plan::BanderScalar);
}

#[cfg(test)]
#[test]
fn minifuzz_curve25519() {
    minifuzz(Plan::Curve25519);
}

#[cfg(test)]
struct CheckFixedEdges;

#[cfg(test)]
impl WithBackend for CheckFixedEdges {
    type Output = ();

    fn call<B: Backend>(self, backend: B) {
        fixed_edges_match_portable(
            &Ring::<Bls12381, _>::new(backend),
            &Ring::<Bls12381, _>::new(kernel::Portable),
        );
        fixed_edges_match_portable(
            &Ring::<BlsScalar, _>::new(backend),
            &Ring::<BlsScalar, _>::new(kernel::Portable),
        );
        fixed_edges_match_portable(
            &Ring::<BanderScalar, _>::new(backend),
            &Ring::<BanderScalar, _>::new(kernel::Portable),
        );
        fixed_edges_match_portable(
            &Ring::<Curve25519, _>::new(backend),
            &Ring::<Curve25519, _>::new(kernel::Portable),
        );
    }
}

#[cfg(test)]
#[test]
fn fixed_edges_match_portable_backend() {
    with_backend(CheckFixedEdges);
}

#[cfg(test)]
fn check<P: Modulus, B: Backend>(backend: B) {
    let ring = Ring::<P, B>::new(backend);
    let a = Standard::from(Element::<P>::from_u64(123));
    let b = Standard::from(Element::<P>::from_u64(456));
    let product = (ring.prep_left(a) * b).complete();
    let small = ring.batch_reduce(&[ring.ready::<800>(product)])[0];
    let ordinary = ring.prep_expand(small);
    let scaled = ring.prep_expand(small.scale::<6>());
    let shifted = ring.prep_expand(small.scale::<3>() - small.scale::<2>());
    let (ordinary, scaled, shifted) = ring.batch_expand(&(ordinary, scaled, shifted));
    let results = ring.batch_reduce_expand(&[
        ring.ready::<800>(ring.prep_left(ordinary) * Standard::ONE),
        ring.ready::<800>(ring.prep_left(scaled) * Standard::ONE),
        ring.ready::<800>(ring.prep_left(shifted) * Standard::ONE),
    ]);
    assert_eq!(Element::from(results[0]), Element::from_u64(123 * 456));
    assert_eq!(Element::from(results[1]), Element::from_u64(6 * 123 * 456));
    assert_eq!(Element::from(results[2]), Element::from_u64(123 * 456));

    let difference = ring.wide_offset::<80, 1440>() - product;
    let negative = ring.prep_left(ring.negate(a)) * b;
    let values =
        ring.batch_reduce_expand(&[ring.ready::<800>(difference), ring.ready::<800>(negative)]);
    let expected = Element::<P>::from_u64(123 * 456).neg();
    assert_eq!(Element::from(values[0]), expected);
    assert_eq!(Element::from(values[1]), expected);

    let zero = Wide::<P, Range<0, 1>, Range<0, 0>> {
        halves: [RawWide {
            high: [u64::MAX; LANES],
            low: [1 << WORD; LANES],
        }; 2],
        marker: PhantomData,
    };
    let reduced = ring.batch_reduce_expand(&[ring.ready::<1>(zero)])[0];
    assert!(bool::from(ring.is_zero(reduced)));

    let none: [Ready<P, 800>; 0] = [];
    assert!(ring.batch_reduce_expand(&none).is_empty());
}

#[cfg(test)]
struct Check;
#[cfg(test)]
impl WithBackend for Check {
    type Output = ();
    fn call<B: Backend>(self, backend: B) {
        check::<Bls12381, _>(backend);
        check::<BlsScalar, _>(backend);
        check::<BanderScalar, _>(backend);
        check::<Curve25519, _>(backend);
    }
}

#[cfg(test)]
#[test]
fn delayed_reduction_preserves_integer_intervals() {
    Check.call(kernel::Portable);
    with_backend(Check);
}

#[cfg(test)]
fn offset_bounds<P: Modulus>() {
    let ring = Ring::<P, _>::new(kernel::Portable);
    for halves in [
        ring.wide_offset::<0, 1932>().halves,
        ring.wide_offset::<80, 1440>().halves,
        ring.wide_offset::<128, 32>().halves,
    ]
    .into_iter()
    .zip([0i128, 80, 128])
    {
        let (halves, e) = halves;
        for (half, moduli) in halves
            .into_iter()
            .zip([&P::PARAMETERS.m.moduli, &P::PARAMETERS.n.moduli])
        {
            for ((high, low), &q) in half.high.into_iter().zip(half.low).zip(moduli) {
                let word = 1i128 << WORD;
                let combined = (high as i64 as i128) * word + low as i128;
                let squared = i128::from(q) * i128::from(q);
                assert!((e * squared..=(e + 1) * squared).contains(&combined));
                assert!((e * word..=(e + 1) * word).contains(&(low as i128)));
            }
        }
    }
}

#[cfg(test)]
#[test]
fn reference_offsets_satisfy_both_wide_bounds() {
    offset_bounds::<Bls12381>();
    offset_bounds::<BlsScalar>();
    offset_bounds::<BanderScalar>();
    offset_bounds::<Curve25519>();
}

#[cfg(test)]
#[test]
#[should_panic]
fn oversized_offset_is_rejected_before_construction() {
    let extent = core::hint::black_box(1 << 20);
    let _ = wide_offset::<Bls12381>(extent, 0);
}
