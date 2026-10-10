//! Externally drivable property checks for Ocelot kernels.

use super::{Kernel, WithKernel, portable::Portable, with_kernel};
use crate::ocelot::field::gf8::GF8;
use arbitrary::{Arbitrary, Unstructured};

const GUARD_LEN: usize = 8;
const INPUT_GUARD: u8 = 0xcc;
const OUTPUT_GUARD: u8 = 0xa5;

/// Property checks for Ocelot kernel implementations and dispatch.
#[derive(Debug, Arbitrary)]
pub enum Plan {
    /// Check the portable kernel contract.
    PortableContract,
    /// Check the contract of the kernel selected for this CPU.
    DispatchedContract,
    /// Compare the kernel selected for this CPU against the portable backend.
    BackendMatchesPortable,
}

impl Plan {
    /// Run this property check using bytes from `u`.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::PortableContract => fuzz_contract(u, Portable),
            Self::DispatchedContract => with_kernel(FuzzContract { u }),
            Self::BackendMatchesPortable => with_kernel(FuzzComparison { u }),
        }
    }
}

struct Run(u8);

impl WithKernel for Run {
    type Output = (usize, u8);

    fn call<K: Kernel>(self, kernel: K) -> Self::Output {
        let input = vec![1; K::LANES];
        let input = kernel.load(&input);
        let product = kernel.gf8_mul_constant(input, kernel.splat(self.0));
        (K::LANES, kernel.xor_fold(product))
    }
}

fn store<K: Kernel>(kernel: K, value: K::Vector) -> Vec<u8> {
    let mut out = vec![0; K::LANES];
    kernel.store(value, &mut out);
    out
}

fn gf8_mul(a: u8, b: u8) -> u8 {
    u8::from(GF8::from(a) * GF8::from(b))
}

fn fuzz_contract<K: Kernel>(u: &mut Unstructured<'_>, kernel: K) -> arbitrary::Result<()> {
    assert!(K::LANES > 0, "LANES must be positive");
    assert!(
        K::PARTIAL_GRANULARITY > 0,
        "PARTIAL_GRANULARITY must be positive"
    );
    assert!(
        K::LANES.is_multiple_of(K::PARTIAL_GRANULARITY),
        "PARTIAL_GRANULARITY must divide LANES"
    );

    let mut a = vec![0; K::LANES];
    let mut b = vec![0; K::LANES];
    u.fill_buffer(&mut a)?;
    u.fill_buffer(&mut b)?;
    let constant = u.arbitrary::<u8>()?;

    for offset in 0..GUARD_LEN {
        let mut input = vec![INPUT_GUARD; offset + K::LANES + GUARD_LEN];
        input[offset..offset + K::LANES].copy_from_slice(&a);
        let value = kernel.load(&input[offset..offset + K::LANES]);

        let mut output = vec![OUTPUT_GUARD; offset + K::LANES + GUARD_LEN];
        kernel.store(value, &mut output[offset..offset + K::LANES]);
        assert_eq!(&output[..offset], vec![OUTPUT_GUARD; offset]);
        assert_eq!(&output[offset..offset + K::LANES], a);
        assert_eq!(&output[offset + K::LANES..], vec![OUTPUT_GUARD; GUARD_LEN]);
    }

    for len in (K::PARTIAL_GRANULARITY..=K::LANES).step_by(K::PARTIAL_GRANULARITY) {
        for offset in 0..GUARD_LEN {
            let mut input = vec![INPUT_GUARD; offset + len + GUARD_LEN];
            input[offset..offset + len].copy_from_slice(&a[..len]);
            let value = kernel.load_partial(&input[offset..offset + len]);

            let mut loaded = vec![OUTPUT_GUARD; offset + K::LANES + GUARD_LEN];
            kernel.store(value, &mut loaded[offset..offset + K::LANES]);
            assert_eq!(&loaded[..offset], vec![OUTPUT_GUARD; offset]);
            assert_eq!(&loaded[offset..offset + len], &a[..len]);
            assert!(
                loaded[offset + len..offset + K::LANES]
                    .iter()
                    .all(|&byte| byte == 0),
                "inactive lanes must be zero"
            );
            assert_eq!(&loaded[offset + K::LANES..], vec![OUTPUT_GUARD; GUARD_LEN]);

            let mut output = vec![OUTPUT_GUARD; offset + len + GUARD_LEN];
            kernel.store_partial(value, &mut output[offset..offset + len]);
            assert_eq!(&output[..offset], vec![OUTPUT_GUARD; offset]);
            assert_eq!(&output[offset..offset + len], &a[..len]);
            assert_eq!(&output[offset + len..], vec![OUTPUT_GUARD; GUARD_LEN]);
        }
    }

    let a_vec = kernel.load(&a);
    let b_vec = kernel.load(&b);
    assert_eq!(
        store(kernel, kernel.xor(a_vec, b_vec)),
        a.iter().zip(&b).map(|(&a, &b)| a ^ b).collect::<Vec<_>>()
    );
    assert_eq!(
        kernel.xor_fold(a_vec),
        a.iter().copied().fold(0, |fold, byte| fold ^ byte)
    );
    assert_eq!(
        store(kernel, kernel.gf8_mul_vec(a_vec, b_vec)),
        a.iter()
            .zip(&b)
            .map(|(&a, &b)| gf8_mul(a, b))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        store(
            kernel,
            kernel.gf8_mul_constant(a_vec, kernel.splat(constant))
        ),
        a.iter().map(|&a| gf8_mul(a, constant)).collect::<Vec<_>>()
    );

    let expected_fold = if K::LANES % 2 == 0 { 0 } else { constant };
    assert_eq!(kernel.run(Run(constant)), (K::LANES, expected_fold));
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct Results {
    roundtrip: Vec<u8>,
    xor: Vec<u8>,
    xor_fold: u8,
    product: Vec<u8>,
    constant_product: Vec<u8>,
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn evaluate<K: Kernel>(kernel: K, a: &[u8], b: &[u8], constant: u8) -> Results {
    assert_eq!(a.len(), b.len());
    assert!(a.len().is_multiple_of(K::LANES));

    let mut results = Results {
        roundtrip: Vec::with_capacity(a.len()),
        xor: Vec::with_capacity(a.len()),
        xor_fold: 0,
        product: Vec::with_capacity(a.len()),
        constant_product: Vec::with_capacity(a.len()),
    };
    let constant = kernel.splat(constant);
    for (a, b) in a.chunks_exact(K::LANES).zip(b.chunks_exact(K::LANES)) {
        let a = kernel.load(a);
        let b = kernel.load(b);
        results.roundtrip.extend(store(kernel, a));
        results.xor.extend(store(kernel, kernel.xor(a, b)));
        results.xor_fold ^= kernel.xor_fold(a);
        results
            .product
            .extend(store(kernel, kernel.gf8_mul_vec(a, b)));
        results
            .constant_product
            .extend(store(kernel, kernel.gf8_mul_constant(a, constant)));
    }
    results
}

fn fuzz_matches_portable<K: Kernel>(u: &mut Unstructured<'_>, kernel: K) -> arbitrary::Result<()> {
    let len = K::LANES.max(Portable::LANES);
    assert!(len.is_multiple_of(K::LANES));
    assert!(len.is_multiple_of(Portable::LANES));
    let mut a = vec![0; len];
    let mut b = vec![0; len];
    u.fill_buffer(&mut a)?;
    u.fill_buffer(&mut b)?;
    let constant = u.arbitrary::<u8>()?;

    assert_eq!(
        evaluate(kernel, &a, &b, constant),
        evaluate(Portable, &a, &b, constant)
    );
    Ok(())
}

struct FuzzContract<'a, 'b> {
    u: &'a mut Unstructured<'b>,
}

impl WithKernel for FuzzContract<'_, '_> {
    type Output = arbitrary::Result<()>;

    fn call<K: Kernel>(self, kernel: K) -> Self::Output {
        fuzz_contract(self.u, kernel)
    }
}

struct FuzzComparison<'a, 'b> {
    u: &'a mut Unstructured<'b>,
}

impl WithKernel for FuzzComparison<'_, '_> {
    type Output = arbitrary::Result<()>;

    fn call<K: Kernel>(self, kernel: K) -> Self::Output {
        fuzz_matches_portable(self.u, kernel)
    }
}
