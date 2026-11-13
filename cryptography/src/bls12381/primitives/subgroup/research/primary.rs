//! The order-three component only. This is NOT a G1 subgroup verifier.
//!
//! Descent maps curve addition to multiplication modulo cubes. The remaining
//! cofactor is invisible to this map and needs a separate, complete check.
//! See `cryptography/SUBGROUP_DESCENT.md` for the derivation and limitations.

use super::*;

const Q: u32 = 47;
const BUCKETS: usize = Q.pow(3) as usize;

const CUBE_EXPONENT: [u64; 6] = [
    0x9354ffffffffe38e,
    0x0a395554e5c6aaaa,
    0xcd104635a790520c,
    0xcc27c3d6fbd7063f,
    0x190937e76bc3e447,
    0x08ab05f8bdd54cde,
];

fn character(value: &blst_fp) -> blst_fp {
    let mut result = G1::generator().as_blst_p1().z;
    for word in CUBE_EXPONENT.iter().rev() {
        for bit in (0..64).rev() {
            result = fp_sqr(&result);
            if word & (1 << bit) != 0 {
                result = fp_mul(&result, value);
            }
        }
    }
    result
}

fn representative(point: &blst_p1_affine, negate: bool) -> blst_fp {
    let one = G1::generator().as_blst_p1().z;
    let two = fp_add(&one, &one);
    let value = if negate {
        fp_add(&point.y, &two)
    } else {
        fp_sub(&point.y, &two)
    };
    if fp_is_zero(&value) {
        // At (0,2), 16 represents 1/4 modulo cubes. It also represents the
        // inverse class at (0,-2), where the negative representative vanishes.
        fp_sqr(&fp_sqr(&two))
    } else {
        value
    }
}

fn combinations(values: &[blst_fp], ids: &[u32], width: u32) -> Vec<blst_fp> {
    assert_eq!(values.len(), ids.len());
    assert!((1..=MAX_WIDTH).contains(&width));
    let one = G1::generator().as_blst_p1().z;
    let mut slots = vec![one; folded(width)];
    for (value, &id) in values.iter().zip(ids) {
        let bucket = (id & !ID_NEGATE) as usize;
        if bucket != 0 {
            // Squaring is inversion in the quotient by cubes, not in Fp*.
            let value = if id & ID_NEGATE == 0 {
                *value
            } else {
                fp_sqr(value)
            };
            slots[bucket] = fp_mul(&slots[bucket], &value);
        }
    }
    let mut result = Vec::with_capacity(width as usize);
    for remaining in (1..=width).rev() {
        let half = 3usize.pow(remaining - 1);
        let mut product = one;
        for value in &slots[half.div_ceil(2)..=(3 * half - 1) / 2] {
            product = fp_mul(&product, value);
        }
        result.push(product);
        if remaining > 1 {
            let mut next = vec![one; folded(remaining - 1)];
            for a in 1..=(half - 1) / 2 {
                next[a] = fp_mul(
                    &fp_mul(&slots[a], &slots[half + a]),
                    &fp_sqr(&slots[half - a]),
                );
            }
            slots = next;
        }
    }
    result
}

fn inner(values: &[blst_fp], rng: &mut impl CryptoRng) -> bool {
    let widths = spread(combinations_for_security(111), 8);
    let mut trits = Trits::new(rng);
    widths.into_iter().all(|width| {
        let ids = trits.fill(width, values.len());
        combinations(values, &ids, width)
            .iter()
            .all(|value| fp_is_one(&character(value)))
    })
}

/// Test only the order-three component with error below 2^-128.
///
/// Inputs must already be on-curve and fixed before fresh private randomness
/// is drawn. Passing this filter does not establish G1 membership.
pub(super) fn check_order_three(points: &[G1], rng: &mut impl CryptoRng) -> (bool, [Duration; 4]) {
    assert!(points.len() <= Q.pow(4) as usize);
    let start = Instant::now();
    let affine = to_affine(points);
    let normalized = start.elapsed();
    if affine.is_empty() {
        return (
            true,
            [normalized, Duration::ZERO, Duration::ZERO, Duration::ZERO],
        );
    }
    let start = Instant::now();
    let ids = super::two::draw_ids::<Q>(affine.len(), rng);
    let sampled = start.elapsed();
    let one = G1::generator().as_blst_p1().z;
    let mut compressed = Duration::ZERO;
    let mut checked = Duration::ZERO;
    for pass in &ids {
        let start = Instant::now();
        let mut products = vec![one; BUCKETS];
        for (point, &id) in affine.iter().zip(pass) {
            let bucket = (id & !ID_NEGATE) as usize;
            products[bucket] = fp_mul(
                &products[bucket],
                &representative(point, id & ID_NEGATE != 0),
            );
        }
        compressed += start.elapsed();
        let start = Instant::now();
        let valid = inner(&products, rng);
        checked += start.elapsed();
        if !valid {
            return (false, [normalized, sampled, compressed, checked]);
        }
    }
    (true, [normalized, sampled, compressed, checked])
}

#[test]
fn descent_handles_torsion_signs_and_group_addition() {
    let mut carry = 1u128;
    for (&word, &modulus) in CUBE_EXPONENT.iter().zip(&MODULUS) {
        let product = u128::from(word) * 3 + carry;
        assert_eq!(product as u64, modulus);
        carry = product >> 64;
    }
    assert_eq!(carry, 0);
    let generator = G1::generator();
    let one = generator.as_blst_p1().z;
    let torsion = order_three();
    let chi = |point: G1| {
        if point == G1::zero() {
            one
        } else {
            character(&representative(&to_affine(&[point])[0], false))
        }
    };
    assert!(fp_is_one(&chi(generator)));
    assert!(!fp_is_one(&chi(torsion)));
    let mut point = generator;
    for _ in 0..12 {
        for other in [
            G1::zero(),
            generator,
            torsion,
            -torsion,
            generator + &torsion,
        ] {
            assert!(fp_eq(
                &chi(point + &other),
                &fp_mul(&chi(point), &chi(other))
            ));
        }
        let affine = to_affine(&[point])[0];
        assert!(fp_is_one(&character(&fp_mul(
            &representative(&affine, false),
            &representative(&affine, true)
        ))));
        point += &generator;
        point += &torsion;
    }
    for point in [torsion, -torsion] {
        let affine = to_affine(&[point])[0];
        assert!(!fp_is_zero(&representative(&affine, false)));
        assert!(!fp_is_zero(&representative(&affine, true)));
        assert!(fp_eq(
            &character(&representative(&affine, true)),
            &chi(-point)
        ));
    }
}

#[test]
fn multiplicative_collapse_matches_independent_digit_oracle() {
    let one = G1::generator().as_blst_p1().z;
    let two = fp_add(&one, &one);
    let mut rng = test_rng();
    for width in [1, 2, 3, 4, 5, 8, 9] {
        let ids = Trits::new(&mut rng).fill(width, 250);
        let mut power = one;
        let values: Vec<_> = (0..ids.len())
            .map(|_| {
                power = fp_mul(&power, &two);
                power
            })
            .collect();
        let actual = combinations(&values, &ids, width);
        for row in 0..width {
            let mut direct = one;
            let offset = (3i32.pow(width) - 1) / 2;
            for (value, &id) in values.iter().zip(&ids) {
                let unsigned = (id & !ID_NEGATE) as i32;
                let signed = if id & ID_NEGATE == 0 {
                    unsigned
                } else {
                    -unsigned
                };
                let digit = ((signed + offset) / 3i32.pow(row)) % 3 - 1;
                let factor = match digit {
                    -1 => fp_sqr(value),
                    0 => one,
                    1 => *value,
                    _ => unreachable!(),
                };
                direct = fp_mul(&direct, &factor);
            }
            assert!(fp_eq(
                &character(&actual[(width - 1 - row) as usize]),
                &character(&direct)
            ));
        }
    }
}

#[test]
fn order_three_filter_is_deliberately_not_a_subgroup_check() {
    let bad = order_eleven();
    assert_ne!(bad, G1::zero());
    assert!(!bad.in_subgroup());
    let mut sum = G1::zero();
    for _ in 0..11 {
        sum += &bad;
    }
    assert_eq!(sum, G1::zero());
    let points = vec![G1::generator() + &bad; 4096];
    assert!(check_order_three(&points, &mut test_rng()).0);
    assert!(!super::effective::check(&points, &mut test_rng()));
}

#[test]
fn order_three_filter_rejects_polluted_batches() {
    let generator = G1::generator();
    let bad = order_three();
    assert!(check_order_three(&[], &mut test_rng()).0);
    assert!(check_order_three(&[G1::zero(); 16], &mut test_rng()).0);
    for count in [0, 1, 2, 3, 8, 12, 32] {
        let mut points = vec![generator; 4096];
        for (i, point) in points.iter_mut().take(count).enumerate() {
            *point += &if i % 2 == 0 { bad } else { -bad };
        }
        points.extend([G1::zero(); 16]);
        assert_eq!(check_order_three(&points, &mut test_rng()).0, count == 0);
    }
    assert!(!check_order_three(&[bad], &mut test_rng()).0);
    assert!(!check_order_three(&[-bad], &mut test_rng()).0);
}
