//! An inner check with exact treatment of one- and two-input kernels.

use super::*;

fn exceptions(widths: &[u32], ids: &[Vec<u32>]) -> Vec<usize> {
    assert_eq!(widths.len(), ids.len());
    assert!(widths.iter().sum::<u32>() <= 79);
    let n = ids.first().map_or(0, Vec::len);
    let mut columns = vec![0i128; n];
    let mut factor = 1i128;
    for (&width, pass) in widths.iter().zip(ids) {
        assert_eq!(pass.len(), n);
        for (column, &id) in columns.iter_mut().zip(pass) {
            let value = i128::from(id & !ID_NEGATE);
            *column += factor * if id & ID_NEGATE == 0 { value } else { -value };
        }
        factor *= 3i128.pow(width);
    }
    exception_indices(columns.into_iter().map(i128::unsigned_abs))
}

pub(super) fn exception_indices(values: impl IntoIterator<Item = u128>) -> Vec<usize> {
    let mut columns: Vec<_> = values
        .into_iter()
        .enumerate()
        .map(|(index, value)| (value, index))
        .collect();
    columns.sort_unstable();
    let mut marked = Vec::new();
    let mut start = 0;
    while start < columns.len() {
        let mut end = start + 1;
        while end < columns.len() && columns[end].0 == columns[start].0 {
            end += 1;
        }
        if columns[start].0 == 0 || end - start > 1 {
            marked.extend(columns[start..end].iter().map(|&(_, index)| index));
        }
        start = end;
    }
    marked
}

fn checked_columns(affine: &[blst_p1_affine], widths: &[u32], ids: &[Vec<u32>]) -> bool {
    let one = G1::generator().as_blst_p1().z;
    exceptions(widths, ids).into_iter().all(|index| {
        let point = affine[index];
        G1::from_blst_p1(blst_p1 {
            x: point.x,
            y: point.y,
            z: one,
        })
        .in_subgroup()
    })
}

pub(super) fn check<const SECURITY: usize>(points: &[G1], rng: &mut impl CryptoRng) -> bool {
    assert!(matches!(SECURITY, 96 | 99));
    let Some(widths) = plan(points.len(), combinations_for_security(SECURITY)) else {
        return points.iter().all(G1::in_subgroup);
    };
    let affine = to_affine(points);
    let mut trits = Trits::new(rng);
    let ids: Vec<_> = widths
        .iter()
        .map(|&m| trits.fill(m, affine.len()))
        .collect();
    if !checked_columns(&affine, &widths, &ids) {
        return false;
    }
    // Keep all inputs and their iid columns after exact-checking exceptions.
    let mut round = Round::new(*widths.iter().max().expect("positive target"));
    widths
        .iter()
        .zip(&ids)
        .all(|(&width, pass)| round.run(&affine, pass, width))
}

#[test]
fn packed_columns_preserve_global_sign() {
    let mut ids = vec![Vec::new(), Vec::new()];
    for value in -121i32..=121 {
        let low = (value + 4).rem_euclid(9) - 4;
        let high = (value - low) / 9;
        for (pass, part) in [low, high].into_iter().enumerate() {
            ids[pass].push(part.unsigned_abs() | if part < 0 { ID_NEGATE } else { 0 });
        }
    }
    let mut marked = exceptions(&[2, 3], &ids);
    marked.sort_unstable();
    assert_eq!(marked, (0..243).collect::<Vec<_>>());
    let positive: Vec<Vec<_>> = ids.iter().map(|pass| pass[122..].to_vec()).collect();
    assert!(exceptions(&[2, 3], &positive).is_empty());
    let mixed = [vec![1, 1], vec![1, 1 | ID_NEGATE]];
    assert!(exceptions(&[1, 1], &mixed).is_empty());
}

#[test]
fn exact_exceptions_check_polluted_duplicate_copies() {
    let generator = G1::generator();
    let bad = order_three();
    let points = [generator, generator + &bad];
    for ids in [vec![1, 1], vec![1, 1 | ID_NEGATE], vec![1, 0]] {
        assert!(!checked_columns(&to_affine(&points), &[1], &[ids]));
    }
    assert!(checked_columns(
        &to_affine(&[generator; 3]),
        &[1],
        &[vec![0, 1, 1 | ID_NEGATE]],
    ));
}

#[test]
fn certified_inner_rejects_adversarial_batches() {
    assert_eq!(combinations_for_security(96), 61);
    let generator = G1::generator();
    let bad = order_three();
    assert!(check::<96>(&[], &mut test_rng()));
    assert!(check::<96>(&[G1::zero(); 16], &mut test_rng()));
    for count in [0, 1, 2, 3, 4, 8, 12, 32, 1598] {
        let mut points = vec![generator; 4096];
        for (i, point) in points.iter_mut().take(count).enumerate() {
            *point += &if i % 2 == 0 { bad } else { -bad };
        }
        assert_eq!(check::<96>(&points, &mut test_rng()), count == 0);
        assert_eq!(check::<99>(&points, &mut test_rng()), count == 0);
    }
}
