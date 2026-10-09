use super::{super::integer::Poly, *};

fn constant(value: i64) -> Poly {
    let mut p = Poly::zero(9, 3);
    for j in 0..3 {
        p.words[j * 512] = ((i128::from(value) >> (31 * j)) as u32) & 0x7fff_ffff;
    }
    p
}

#[test]
fn restoring_division_includes_full_width_numerators() {
    let numerators = [0, 1, (1 << 64) - 1, 1 << 64, 1 << 127, u128::MAX];
    let divisors = [1, 2, 3, (1 << 64) - 1, 1 << 64, (1 << 127) - 1];
    for n in numerators {
        for d in divisors {
            assert_eq!(div_rem(n, d), Some((n / d, n % d)));
        }
    }
    assert_eq!(div_rem(1, 0), None);
    assert_eq!(div_rem(1, 1 << 127), None);
}

#[test]
fn rounding_uses_even_ties_on_both_sides() {
    for x in -10..10 {
        let half = i128::from(x) * ONE + ONE / 2;
        assert_eq!(round(half), Some(x + (x & 1)));
        assert_eq!(round(half - 1), Some(x));
        assert_eq!(round(half + 1), Some(x + 1));
    }
    assert_eq!(round(i128::from(K_LIMIT) * ONE), Some(K_LIMIT));
    assert_eq!(round(i128::from(K_LIMIT + 1) * ONE), None);
}

#[test]
fn weighted_projection_and_exact_certificate_disagree_with_euclidean_reduction() {
    let small = Pair {
        f: constant(1),
        g: constant(36),
    };
    let big = Pair {
        f: constant(0),
        g: constant(12289),
    };
    let (u, k) = Projection::new(&small, true)
        .unwrap()
        .quotient(&big, 0)
        .unwrap();
    assert_eq!(k[0], 171);
    assert!(k[1..].iter().all(|&x| x == 0));
    assert!(certify(&small, &big, &u, &k).is_some());
    let (wrong_u, wrong_k) = Projection::new(&small, false)
        .unwrap()
        .quotient(&big, 0)
        .unwrap();
    assert_eq!(wrong_k[0], 341);
    assert!(certify(&small, &big, &wrong_u, &wrong_k).is_none());

    let mut wrong = k.clone();
    wrong[0] += 1;
    assert!(certify(&small, &big, &u, &wrong).is_none());
    let mut corrupted = u;
    corrupted[73] += ONE;
    assert!(certify(&small, &big, &corrupted, &k).is_none());
}

#[test]
fn exact_certificate_accepts_even_ties_and_rejects_singular_domain() {
    let small = Pair {
        f: constant(2),
        g: constant(0),
    };
    for (numerator, nearest) in [(1, 0), (3, 2), (-1, 0), (-3, -2)] {
        let big = Pair {
            f: constant(numerator),
            g: constant(0),
        };
        let (u, k) = Projection::new(&small, true)
            .unwrap()
            .quotient(&big, 0)
            .unwrap();
        assert_eq!(k[0], nearest);
        assert!(certify(&small, &big, &u, &k).is_some());
    }
    let zero = Pair {
        f: constant(0),
        g: constant(0),
    };
    assert!(Projection::new(&zero, true).is_none());
}

#[test]
fn fft_roundtrip_retains_integer_coefficients_and_rejects_overflow() {
    let mut a: Vec<_> = (0..512)
        .map(|i| i128::from((i * 73) % 255 - 127) * ONE)
        .collect();
    let original = a.clone();
    fft(9, &mut a, false).unwrap();
    fft(9, &mut a, true).unwrap();
    for (&a, &b) in a.iter().zip(&original) {
        assert!((a - b).abs() < 1 << 20);
    }
    let mut bad = vec![i128::MAX; 512];
    assert!(fft(9, &mut bad, false).is_none());
}
