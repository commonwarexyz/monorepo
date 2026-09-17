//! VROOM field-operation throughput against blst, plus an end-to-end X25519 comparison against
//! the existing specialized Curve25519 implementation. Fixture construction and equivalence
//! checks are not timed.

use blst::{blst_fp, blst_fr, blst_scalar};
use commonware_cryptography_vroom::{Bls12381, BlsScalar, Element, Modulus};
use core::{array, mem::MaybeUninit};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

type Fp381 = Element<Bls12381>;
type Fr255 = Element<BlsScalar>;

fn element<P: Modulus>(tag: u8) -> Element<P> {
    let bytes = array::from_fn::<_, 64, _>(|i| tag.wrapping_add((i as u8).wrapping_mul(37)));
    Element::from_bytes_mod_order(&bytes)
}

fn blst_fp_from_bytes(bytes: &[u8; 48]) -> blst_fp {
    let mut output = blst_fp::default();
    // SAFETY: `bytes` spans the 48 bytes read by blst, and `output` is valid for writes.
    unsafe { blst::blst_fp_from_bendian(&mut output, bytes.as_ptr()) };
    output
}

fn blst_fp_to_bytes(value: &blst_fp) -> [u8; 48] {
    let mut output = [0; 48];
    // SAFETY: `output` spans the 48 bytes written by blst, and `value` is initialized.
    unsafe { blst::blst_bendian_from_fp(output.as_mut_ptr(), value) };
    output
}

fn blst_fr_from_bytes(bytes: &[u8; 32]) -> blst_fr {
    let mut scalar = blst_scalar::default();
    let mut output = blst_fr::default();
    // SAFETY: `bytes` spans the 32 bytes read by blst, and both outputs are valid for writes.
    // The canonical scalar is converted into blst's Montgomery representation before use.
    unsafe {
        blst::blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
        blst::blst_fr_from_scalar(&mut output, &scalar);
    }
    output
}

fn blst_fr_to_bytes(value: &blst_fr) -> [u8; 32] {
    let mut scalar = blst_scalar::default();
    let mut output = [0; 32];
    // SAFETY: both blst values are valid, and `output` spans the 32 bytes written by blst.
    unsafe {
        blst::blst_scalar_from_fr(&mut scalar, value);
        blst::blst_bendian_from_scalar(output.as_mut_ptr(), &scalar);
    }
    output
}

macro_rules! blst_binary {
    ($name:ident, $element:ty, $operation:path) => {
        #[inline]
        fn $name(a: &$element, b: &$element) -> $element {
            let mut output = MaybeUninit::<$element>::uninit();
            // SAFETY: the inputs are initialized field elements and the operation initializes
            // every byte of its output before `assume_init`.
            unsafe {
                $operation(output.as_mut_ptr(), a, b);
                output.assume_init()
            }
        }
    };
}

macro_rules! blst_unary {
    ($name:ident, $element:ty, $operation:path) => {
        #[inline]
        fn $name(a: &$element) -> $element {
            let mut output = MaybeUninit::<$element>::uninit();
            // SAFETY: the input is an initialized field element and the operation initializes
            // every byte of its output before `assume_init`.
            unsafe {
                $operation(output.as_mut_ptr(), a);
                output.assume_init()
            }
        }
    };
}

blst_binary!(blst_fp_add, blst_fp, blst::blst_fp_add);
blst_binary!(blst_fp_sub, blst_fp, blst::blst_fp_sub);
blst_binary!(blst_fp_mul, blst_fp, blst::blst_fp_mul);
blst_unary!(blst_fp_square, blst_fp, blst::blst_fp_sqr);
blst_unary!(blst_fp_invert, blst_fp, blst::blst_fp_inverse);
blst_binary!(blst_fr_add, blst_fr, blst::blst_fr_add);
blst_binary!(blst_fr_sub, blst_fr, blst::blst_fr_sub);
blst_binary!(blst_fr_mul, blst_fr, blst::blst_fr_mul);
blst_unary!(blst_fr_square, blst_fr, blst::blst_fr_sqr);
blst_unary!(blst_fr_invert, blst_fr, blst::blst_fr_inverse);

fn blst_fp_sum_of_products<const N: usize>(a: &[blst_fp; N], b: &[blst_fp; N]) -> blst_fp {
    assert!(N > 0);
    let mut sum = blst_fp_mul(&a[0], &b[0]);
    for i in 1..N {
        let product = blst_fp_mul(&a[i], &b[i]);
        sum = blst_fp_add(&sum, &product);
    }
    sum
}

fn blst_fr_sum_of_products<const N: usize>(a: &[blst_fr; N], b: &[blst_fr; N]) -> blst_fr {
    assert!(N > 0);
    let mut sum = blst_fr_mul(&a[0], &b[0]);
    for i in 1..N {
        let product = blst_fr_mul(&a[i], &b[i]);
        sum = blst_fr_add(&sum, &product);
    }
    sum
}

macro_rules! bench_binary {
    ($c:ident, $name:literal, $a:ident, $b:ident, $blst_a:ident, $blst_b:ident, $method:ident, $blst_operation:ident) => {
        $c.bench_function(
            &format!(concat!("{}::", $name, "/impl=vroom"), module_path!()),
            |bencher| {
                bencher.iter(|| black_box(black_box(&$a).$method(*black_box(&$b))));
            },
        );
        $c.bench_function(
            &format!(concat!("{}::", $name, "/impl=blst"), module_path!()),
            |bencher| {
                bencher
                    .iter(|| black_box($blst_operation(black_box(&$blst_a), black_box(&$blst_b))));
            },
        );
    };
}

macro_rules! bench_unary {
    ($c:ident, $name:literal, $a:ident, $blst_a:ident, $method:ident, $blst_operation:ident $(, $unwrap:ident)?) => {
        $c.bench_function(
            &format!(concat!("{}::", $name, "/impl=vroom"), module_path!()),
            |bencher| {
                bencher.iter(|| black_box((*black_box(&$a)).$method()$(.$unwrap())?));
            },
        );
        $c.bench_function(
            &format!(concat!("{}::", $name, "/impl=blst"), module_path!()),
            |bencher| {
                bencher.iter(|| black_box($blst_operation(black_box(&$blst_a))));
            },
        );
    };
}

macro_rules! field_benches {
    (
        $module:ident,
        element = $element:ty,
        modulus = $modulus:ty,
        tags = ($left_tag:literal, $right_tag:literal),
        from_bytes = $from_bytes:ident,
        to_bytes = $to_bytes:ident,
        add = $add:ident,
        sub = $sub:ident,
        mul = $mul:ident,
        square = $square:ident,
        invert = $invert:ident,
        sum_of_products = $sum_of_products:ident
    ) => {
        mod $module {
            use super::*;

            fn bench_sum_of_products<const N: usize>(c: &mut Criterion) {
                let a: [$element; N] = array::from_fn(|i| element::<$modulus>((2 * i + 1) as u8));
                let b: [$element; N] = array::from_fn(|i| element::<$modulus>((2 * i + 2) as u8));
                let blst_a = a.map(|value| $from_bytes(&value.to_bytes()));
                let blst_b = b.map(|value| $from_bytes(&value.to_bytes()));
                assert_eq!(
                    <$element>::sum_of_products(&a, &b).to_bytes(),
                    $to_bytes(&$sum_of_products(&blst_a, &blst_b))
                );

                c.bench_function(
                    &format!("{}::sum_of_products/terms={N} impl=vroom", module_path!()),
                    |bencher| {
                        bencher.iter(|| {
                            black_box(<$element>::sum_of_products(black_box(&a), black_box(&b)))
                        });
                    },
                );
                c.bench_function(
                    &format!("{}::sum_of_products/terms={N} impl=blst", module_path!()),
                    |bencher| {
                        bencher.iter(|| {
                            black_box($sum_of_products(black_box(&blst_a), black_box(&blst_b)))
                        });
                    },
                );
            }

            pub fn bench(c: &mut Criterion) {
                let a = element::<$modulus>($left_tag);
                let b = element::<$modulus>($right_tag);
                let blst_a = $from_bytes(&a.to_bytes());
                let blst_b = $from_bytes(&b.to_bytes());

                assert_eq!(a.to_bytes(), $to_bytes(&blst_a));
                assert_eq!(b.to_bytes(), $to_bytes(&blst_b));
                assert_eq!(a.add(b).to_bytes(), $to_bytes(&$add(&blst_a, &blst_b)));
                assert_eq!(a.sub(b).to_bytes(), $to_bytes(&$sub(&blst_a, &blst_b)));
                assert_eq!(a.mul(b).to_bytes(), $to_bytes(&$mul(&blst_a, &blst_b)));
                assert_eq!(a.square().to_bytes(), $to_bytes(&$square(&blst_a)));
                assert_eq!(a.invert().unwrap().to_bytes(), $to_bytes(&$invert(&blst_a)));

                bench_binary!(c, "add", a, b, blst_a, blst_b, add, $add);
                bench_binary!(c, "sub", a, b, blst_a, blst_b, sub, $sub);
                bench_binary!(c, "mul", a, b, blst_a, blst_b, mul, $mul);
                bench_unary!(c, "square", a, blst_a, square, $square);
                bench_unary!(c, "invert", a, blst_a, invert, $invert, unwrap);

                bench_sum_of_products::<2>(c);
                bench_sum_of_products::<4>(c);
                bench_sum_of_products::<8>(c);
                bench_sum_of_products::<16>(c);
            }
        }
    };
}

field_benches! {
    fp381,
    element = Fp381,
    modulus = Bls12381,
    tags = (11, 173),
    from_bytes = blst_fp_from_bytes,
    to_bytes = blst_fp_to_bytes,
    add = blst_fp_add,
    sub = blst_fp_sub,
    mul = blst_fp_mul,
    square = blst_fp_square,
    invert = blst_fp_invert,
    sum_of_products = blst_fp_sum_of_products
}

field_benches! {
    fr255,
    element = Fr255,
    modulus = BlsScalar,
    tags = (29, 211),
    from_bytes = blst_fr_from_bytes,
    to_bytes = blst_fr_to_bytes,
    add = blst_fr_add,
    sub = blst_fr_sub,
    mul = blst_fr_mul,
    square = blst_fr_square,
    invert = blst_fr_invert,
    sum_of_products = blst_fr_sum_of_products
}

mod x25519 {
    use commonware_cryptography_curve25519::key_exchange::SecretKey;
    use commonware_cryptography_vroom::{Curve25519, Element};
    use commonware_math::algebra::Random;
    use commonware_utils::TestRng;
    use criterion::Criterion;
    use rand_core::Rng as _;
    use std::hint::black_box;
    use subtle::{Choice, ConditionallySelectable};
    use zeroize::Zeroizing;

    type F = Element<Curve25519>;

    const BASEPOINT_BE: [u8; 32] = {
        let mut bytes = [0; 32];
        bytes[31] = 9;
        bytes
    };

    fn vroom_public_key(scalar: &[u8; 32]) -> [u8; 32] {
        let mut scalar = Zeroizing::new(*scalar);
        scalar[0] &= 0b1111_1000;
        scalar[31] &= 0b0111_1111;
        scalar[31] |= 0b0100_0000;

        let x1 = F::from_bytes(&BASEPOINT_BE).unwrap();
        let mut x2 = F::ONE;
        let mut z2 = F::ZERO;
        let mut x3 = x1;
        let mut z3 = F::ONE;
        let a24 = F::from_u64(121665);
        let mut swap = Choice::from(0);

        for bit_index in (0..255).rev() {
            let bit = Choice::from((scalar[bit_index / 8] >> (bit_index % 8)) & 1);
            swap ^= bit;
            F::conditional_swap(&mut x2, &mut x3, swap);
            F::conditional_swap(&mut z2, &mut z3, swap);
            swap = bit;

            let a = x2.add(z2);
            let aa = a.square();
            let b = x2.sub(z2);
            let bb = b.square();
            let e = aa.sub(bb);
            let c = x3.add(z3);
            let d = x3.sub(z3);
            let da = d.mul(a);
            let cb = c.mul(b);
            x3 = da.add(cb).square();
            z3 = x1.mul(da.sub(cb).square());
            x2 = aa.mul(bb);
            z2 = e.mul(aa.add(a24.mul(e)));
        }

        let x2 = F::conditional_select(&x2, &x3, swap);
        let z2 = F::conditional_select(&z2, &z3, swap);
        let mut result = x2
            .mul(z2.invert().expect("basepoint multiplication is nonzero"))
            .to_bytes();
        result.reverse();
        result
    }

    fn fixture(seed: u64) -> ([u8; 32], SecretKey) {
        let mut scalar_rng = TestRng::new(seed);
        let mut scalar = [0; 32];
        scalar_rng.fill_bytes(&mut scalar);

        let mut key_rng = TestRng::new(seed);
        let secret = SecretKey::random(&mut key_rng);
        assert_eq!(secret.public_key().as_ref(), &vroom_public_key(&scalar));
        (scalar, secret)
    }

    pub fn bench(c: &mut Criterion) {
        for seed in [0, 1, 42, u64::MAX] {
            black_box(fixture(seed));
        }
        let (scalar, secret) = fixture(0);

        c.bench_function(
            &format!("{}::public_key/impl=specialized", module_path!()),
            |bencher| {
                bencher.iter(|| black_box(black_box(&secret).public_key()));
            },
        );
        c.bench_function(
            &format!("{}::public_key/impl=vroom", module_path!()),
            |bencher| {
                bencher.iter(|| black_box(vroom_public_key(black_box(&scalar))));
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = fp381::bench, fr255::bench, x25519::bench
}
criterion_main!(benches);
