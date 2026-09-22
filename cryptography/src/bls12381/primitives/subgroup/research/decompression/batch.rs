//! Independent sixth-root chains interleaved on one core.

use super::*;

fn extract<const N: usize>(inputs: &[blst_fp; N]) -> Option<[blst_fp; N]> {
    if inputs.iter().any(fp_is_zero) {
        return None;
    }
    let squares = inputs.map(|a| fp_sqr(&a));
    let mut powers = [*inputs; 16];
    for index in 1..powers.len() {
        for (lane, square) in squares.iter().enumerate() {
            powers[index][lane] = fp_mul(&powers[index - 1][lane], square);
        }
    }
    let mut roots = powers[(SIXTH_ROOT[0].1 / 2) as usize];
    for &(squares, power) in &SIXTH_ROOT[1..] {
        for _ in 0..squares {
            for root in &mut roots {
                *root = fp_sqr(root);
            }
        }
        for (root, power) in roots.iter_mut().zip(&powers[(power / 2) as usize]) {
            *root = fp_mul(root, power);
        }
    }
    let correction = cube(&fp_sqr(&ROOT_NINE));
    for (root, input) in roots.iter_mut().zip(inputs) {
        let mut sixth = cube(&fp_sqr(root));
        if !fp_eq(&sixth, input) {
            *root = fp_mul(root, &ROOT_NINE);
            sixth = fp_mul(&sixth, &correction);
            if !fp_eq(&sixth, input) {
                *root = fp_mul(root, &ROOT_NINE);
                sixth = fp_mul(&sixth, &correction);
                if !fp_eq(&sixth, input) {
                    return None;
                }
            }
        }
    }
    Some(roots)
}

fn run<const N: usize>(inputs: &[blst_fp]) -> Option<Vec<blst_fp>> {
    assert!(N > 0);
    let mut output = Vec::with_capacity(inputs.len());
    for chunk in inputs.chunks(N) {
        let mut lanes = [MONTGOMERY_ONE; N];
        lanes[..chunk.len()].copy_from_slice(chunk);
        output.extend_from_slice(&extract(&lanes)?[..chunk.len()]);
    }
    Some(output)
}

pub(super) fn fill_roots(points: &mut [blst_p1], pending: &[(usize, blst_fp)]) -> Option<()> {
    for chunk in pending.chunks(4) {
        let mut lanes = [MONTGOMERY_ONE; 4];
        for (lane, &(_, radicand)) in lanes.iter_mut().zip(chunk) {
            *lane = radicand;
        }
        for (&(index, _), root) in chunk.iter().zip(extract(&lanes)?) {
            points[index].z = root;
        }
    }
    Some(())
}

#[test]
fn batched_roots_match_independent_roots() {
    let inputs: Vec<_> = to_affine(&benchmark_points(33))
        .iter()
        .map(|point| cube(&fp_sqr(&point.x)))
        .collect();
    let expected: Vec<_> = inputs.iter().map(|a| sixth_root(a).unwrap()).collect();
    for len in 0..=inputs.len() {
        for roots in [
            run::<1>(&inputs[..len]),
            run::<2>(&inputs[..len]),
            run::<4>(&inputs[..len]),
            run::<8>(&inputs[..len]),
            run::<16>(&inputs[..len]),
        ] {
            let roots = roots.unwrap();
            assert_eq!(roots.len(), len);
            for (root, expected) in roots.iter().zip(&expected[..len]) {
                assert!(fp_eq(root, expected));
            }
        }
    }
    for index in 0..inputs.len() {
        for invalid in [blst_fp::default(), fp_neg(&inputs[index]), ROOT_NINE] {
            let mut bad = inputs.clone();
            bad[index] = invalid;
            assert!(run::<4>(&bad).is_none());
        }
    }
}

#[test]
fn batched_decoding_matches_independent_decoding() {
    let mut points = benchmark_points(35);
    points[3] = points[2];
    points[9] = -points[8];
    points[25] += &order_eleven();
    for len in 0..=points.len() {
        let bytes = encode_pairs(&points[..len]);
        assert_eq!(decode_pairs_with::<true>(&bytes).unwrap(), points[..len]);
    }
    let bytes = encode_pairs(&points);
    let mut rng = test_rng();
    for _ in 0..256 {
        let mut mutated = bytes.clone();
        let offset = rng.next_u32() as usize % mutated.len();
        mutated[offset] ^= 1 << (rng.next_u32() % 8);
        assert_eq!(decode_pairs_with::<true>(&mutated), decode_pairs(&mutated));
    }
    let decoded = decode_pairs_with::<true>(&bytes).unwrap();
    assert!(!batch_in_g1(&decoded, 128, &Sequential, &mut test_rng()));
}

#[test]
fn root_of_product_does_not_certify_individual_roots() {
    let mut inverse = [ROOT_NINE];
    batch_invert(&mut inverse, &mut Vec::new());
    let product = fp_mul(&ROOT_NINE, &inverse[0]);
    assert!(fp_is_one(&product));
    assert!(sixth_root(&product).is_some());
    assert!(sixth_root(&ROOT_NINE).is_none());
    assert!(sixth_root(&inverse[0]).is_none());
    assert!(extract(&[ROOT_NINE, inverse[0]]).is_none());
}

#[test]
#[ignore = "manual serial sixth-root timing"]
fn measure_root_batching() {
    let inputs: Vec<_> = to_affine(&benchmark_points(20_000))
        .iter()
        .map(|point| cube(&fp_sqr(&point.x)))
        .collect();
    let mut timings: [Vec<Duration>; 6] = core::array::from_fn(|_| Vec::new());
    for repetition in 0..7 {
        for offset in 0..6 {
            let method = (offset + repetition) % 6;
            let start = Instant::now();
            let roots = match method {
                0 => inputs.iter().map(sixth_root).collect::<Option<Vec<_>>>(),
                1 => run::<1>(&inputs),
                2 => run::<2>(&inputs),
                3 => run::<4>(&inputs),
                4 => run::<8>(&inputs),
                5 => run::<16>(&inputs),
                _ => unreachable!(),
            };
            black_box(roots.unwrap());
            timings[method].push(start.elapsed());
        }
    }
    for (method, times) in timings.iter_mut().enumerate() {
        times.sort_unstable();
        eprintln!(
            "roots={} lanes={} median_ms={:.3}",
            inputs.len(),
            [0, 1, 2, 4, 8, 16][method],
            times[3].as_secs_f64() * 1000.0
        );
    }
}
