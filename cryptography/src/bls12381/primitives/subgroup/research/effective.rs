//! Certify sparse kernels of the complete recursive linear circuit.
//!
//! The effective integer coefficients lie in [-2,2]. Modulo-three independence
//! certifies two-column independence for the BLS12-381 cofactor, which has no
//! factors two, five, or seven. This is not a generic odd-cofactor argument.

use super::*;

const Q: u32 = 19;
const BUCKETS: usize = Q.pow(3) as usize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Column {
    positive: u64,
    negative: u64,
}

impl Column {
    fn signed(self, negate: bool) -> Self {
        if negate {
            Self {
                positive: self.negative,
                negative: self.positive,
            }
        } else {
            self
        }
    }

    fn plus(self, other: Self) -> Self {
        let zero = !(self.positive | self.negative);
        let other_zero = !(other.positive | other.negative);
        Self {
            positive: (zero & other.positive)
                | (self.positive & other_zero)
                | (self.negative & other.negative),
            negative: (zero & other.negative)
                | (self.negative & other_zero)
                | (self.positive & other.positive),
        }
    }

    fn canonical(self) -> u128 {
        let forward = (u128::from(self.positive) << 64) | u128::from(self.negative);
        let backward = (u128::from(self.negative) << 64) | u128::from(self.positive);
        forward.min(backward)
    }
}

fn columns(widths: &[u32], ids: &[Vec<u32>]) -> Vec<Column> {
    assert_eq!(widths.len(), ids.len());
    assert!(widths.iter().sum::<u32>() <= 64);
    let mut columns = vec![Column::default(); ids.first().map_or(0, Vec::len)];
    let mut offset = 0;
    for (&width, pass) in widths.iter().zip(ids) {
        assert_eq!(pass.len(), columns.len());
        for (&id, column) in pass.iter().zip(&mut columns) {
            let mut value = (id & !ID_NEGATE) as i32;
            if id & ID_NEGATE != 0 {
                value = -value;
            }
            for bit in offset..offset + width {
                let digit = value.rem_euclid(3);
                match digit {
                    1 => column.positive |= 1 << bit,
                    2 => column.negative |= 1 << bit,
                    _ => {}
                }
                value = (value - if digit == 2 { -1 } else { digit }) / 3;
            }
            assert_eq!(value, 0);
        }
        offset += width;
    }
    columns
}

fn effective_columns(
    graph_ids: &[Vec<u32>; 2],
    positions: &[usize],
    columns: &[Column],
    buckets: usize,
) -> Vec<Column> {
    assert_eq!(positions.len(), 2 * buckets);
    assert_eq!(graph_ids[0].len(), graph_ids[1].len());
    graph_ids[0]
        .iter()
        .zip(&graph_ids[1])
        .map(|(&left, &right)| {
            let mut sum = Column::default();
            for (pass, id) in [left, right].into_iter().enumerate() {
                let position = positions[pass * buckets + (id & !ID_NEGATE) as usize];
                if position != usize::MAX {
                    sum = sum.plus(columns[position].signed(id & ID_NEGATE != 0));
                }
            }
            sum
        })
        .collect()
}

fn in_subgroup(point: blst_p1_affine) -> bool {
    G1::from_blst_p1(blst_p1 {
        x: point.x,
        y: point.y,
        z: G1::generator().as_blst_p1().z,
    })
    .in_subgroup()
}

fn checked_effective(affine: &[blst_p1_affine], columns: Vec<Column>) -> bool {
    super::pair::exception_indices(columns.into_iter().map(Column::canonical))
        .into_iter()
        .all(|index| in_subgroup(affine[index]))
}

pub(super) fn check(points: &[G1], rng: &mut impl CryptoRng) -> bool {
    assert!(points.len() <= Q.pow(4) as usize);
    let affine = to_affine(points);
    let graph_ids = super::two::draw_ids::<Q>(affine.len(), rng);
    let mut round = Round::new(9);
    round.widen(9);
    let mut compressed = Vec::with_capacity(2 * BUCKETS);
    let mut positions = vec![usize::MAX; 2 * BUCKETS];
    for (pass, ids) in graph_ids.iter().enumerate() {
        round.accumulate(&affine, ids);
        for bucket in 0..BUCKETS {
            if round.live[bucket] {
                positions[pass * BUCKETS + bucket] = compressed.len();
                compressed.push(round.sums[bucket]);
            }
        }
    }
    let Some(widths) = plan(compressed.len(), combinations_for_security(99)) else {
        return compressed.into_iter().all(in_subgroup);
    };
    let mut trits = Trits::new(rng);
    let ids: Vec<_> = widths
        .iter()
        .map(|&width| trits.fill(width, compressed.len()))
        .collect();
    let columns = columns(&widths, &ids);
    let effective = effective_columns(&graph_ids, &positions, &columns, BUCKETS);
    if !checked_effective(&affine, effective) {
        return false;
    }
    // Exact checks only restrict acceptance; preserve the entire sampled circuit.
    let mut final_round = Round::new(*widths.iter().max().expect("positive target"));
    widths
        .iter()
        .zip(&ids)
        .all(|(&width, pass)| final_round.run(&compressed, pass, width))
}

// A one-shot, input-independent circuit. All graph buckets retain their final
// coefficient columns, including buckets whose eventual curve sum is zero.
// Thus exact exceptions can be certified before any input point is available.
pub(super) struct Prepared {
    graph_ids: [Vec<u32>; 2],
    widths: Vec<u32>,
    ids: Vec<Vec<u32>>,
    exceptions: Vec<usize>,
    graph_round: Round,
    final_round: Round,
    affine: Vec<blst_p1_affine>,
    inputs: Vec<usize>,
    compressed: Vec<blst_p1_affine>,
    outputs: Vec<usize>,
    filtered: Vec<u32>,
}

impl Prepared {
    pub(super) fn new(n: usize, rng: &mut impl CryptoRng) -> Self {
        assert!(n <= Q.pow(4) as usize);
        let graph_ids = super::two::draw_ids::<Q>(n, rng);
        let widths = plan(2 * BUCKETS, combinations_for_security(99)).expect("batched final stage");
        let mut trits = Trits::new(rng);
        let ids: Vec<_> = widths
            .iter()
            .map(|&width| trits.fill(width, 2 * BUCKETS))
            .collect();
        let positions: Vec<_> = (0..2 * BUCKETS).collect();
        let effective = effective_columns(&graph_ids, &positions, &columns(&widths, &ids), BUCKETS);
        let exceptions =
            super::pair::exception_indices(effective.into_iter().map(Column::canonical));
        let mut graph_round = Round::new(9);
        graph_round.widen(9);
        let final_round = Round::new(*widths.iter().max().expect("positive target"));
        Self {
            graph_ids,
            widths,
            ids,
            exceptions,
            graph_round,
            final_round,
            affine: Vec::with_capacity(n),
            inputs: Vec::with_capacity(n),
            compressed: Vec::with_capacity(2 * BUCKETS),
            outputs: Vec::with_capacity(2 * BUCKETS),
            filtered: Vec::with_capacity(n.max(2 * BUCKETS)),
        }
    }

    fn compress(&mut self, points: &[blst_p1_affine], state: &[u8]) {
        for (index, (&point, &state)) in points.iter().zip(state).enumerate() {
            if state != EMPTY {
                self.affine.push(point);
                self.inputs.push(index);
            }
        }
        for (pass, ids) in self.graph_ids.iter().enumerate() {
            self.filtered.clear();
            self.filtered
                .extend(self.inputs.iter().map(|&index| ids[index]));
            self.graph_round.accumulate(&self.affine, &self.filtered);
            for bucket in 0..BUCKETS {
                if self.graph_round.live[bucket] {
                    self.compressed.push(self.graph_round.sums[bucket]);
                    self.outputs.push(pass * BUCKETS + bucket);
                }
            }
        }
    }

    pub(super) fn check(mut self, points: &[blst_p1_affine], state: &[u8]) -> bool {
        assert_eq!(points.len(), self.graph_ids[0].len());
        assert_eq!(points.len(), state.len());
        assert!(!state.contains(&BUSY));
        if !self
            .exceptions
            .iter()
            .all(|&index| state[index] == EMPTY || in_subgroup(points[index]))
        {
            return false;
        }
        self.compress(points, state);
        for (&width, ids) in self.widths.iter().zip(&self.ids) {
            self.filtered.clear();
            self.filtered
                .extend(self.outputs.iter().map(|&index| ids[index]));
            if !self
                .final_round
                .run(&self.compressed, &self.filtered, width)
            {
                return false;
            }
        }
        true
    }
}

#[test]
fn prepared_circuit_preserves_identity_positions_and_final_coefficients() {
    let generator = G1::generator();
    let three = order_three();
    let eleven = order_eleven();
    let points = [
        generator,
        -generator,
        G1::zero(),
        three,
        -three,
        eleven,
        generator + &eleven,
        -generator,
    ];
    let affine: Vec<_> = points
        .iter()
        .map(|point| {
            if *point == G1::zero() {
                blst_p1_affine::default()
            } else {
                to_affine(&[*point])[0]
            }
        })
        .collect();
    let state: Vec<_> = points
        .iter()
        .map(|point| if *point == G1::zero() { EMPTY } else { FILLED })
        .collect();
    let mut prepared = Prepared::new(points.len(), &mut test_rng());
    assert_eq!(prepared.widths.iter().sum::<u32>(), 63);
    // Force cancellations in two graph buckets, plus an absent original input.
    prepared.graph_ids = [
        vec![0, 0, 1, 2, 2, 3, 3, 4],
        vec![0, 1, 2, 3, 4, 5, 5, 6 | ID_NEGATE],
    ];
    let mut expected = vec![G1::zero(); 2 * BUCKETS];
    for (pass, ids) in prepared.graph_ids.iter().enumerate() {
        for (point, &id) in points.iter().zip(ids) {
            let out = &mut expected[pass * BUCKETS + (id & !ID_NEGATE) as usize];
            if id & ID_NEGATE == 0 {
                *out += point;
            } else {
                *out -= point;
            }
        }
    }
    prepared.compress(&affine, &state);
    assert!(!prepared.inputs.contains(&2));
    assert!(!prepared.outputs.contains(&0));
    assert!(!prepared.outputs.contains(&2));
    let mut actual = vec![G1::zero(); 2 * BUCKETS];
    for (&index, &point) in prepared.outputs.iter().zip(&prepared.compressed) {
        actual[index] = G1::from_blst_p1(blst_p1 {
            x: point.x,
            y: point.y,
            z: MONTGOMERY_ONE,
        });
    }
    assert_eq!(actual, expected);
    let expected: Vec<_> = expected
        .into_iter()
        .enumerate()
        .filter(|(_, point)| *point != G1::zero())
        .collect();
    for (&width, ids) in prepared.widths.iter().zip(&prepared.ids) {
        let filtered: Vec<_> = prepared.outputs.iter().map(|&index| ids[index]).collect();
        let _ = prepared
            .final_round
            .run(&prepared.compressed, &filtered, width);
        for row in 0..width {
            let mut direct = G1::zero();
            for &(index, point) in &expected {
                let id = ids[index];
                let value = (id & !ID_NEGATE) as i32 * if id & ID_NEGATE == 0 { 1 } else { -1 };
                let digit = ((value + (3i32.pow(width) - 1) / 2) / 3i32.pow(row)) % 3 - 1;
                match digit {
                    1 => direct += &point,
                    -1 => direct -= &point,
                    _ => {}
                }
            }
            let actual =
                prepared.final_round.marginals[row as usize]
                    .first()
                    .map_or(G1::zero(), |&slot| {
                        let point = prepared.final_round.sums[slot as usize];
                        G1::from_blst_p1(blst_p1 {
                            x: point.x,
                            y: point.y,
                            z: MONTGOMERY_ONE,
                        })
                    });
            assert_eq!(actual, direct);
        }
    }
}

#[test]
fn prepared_certificate_checks_original_dense_input_indices() {
    for bad in [order_three(), order_eleven()] {
        for value in [0, 1] {
            let mut prepared = Prepared::new(3, &mut test_rng());
            prepared.graph_ids = [vec![0, 1, 2], vec![0, 1, 2]];
            for pass in &mut prepared.ids {
                pass.fill(value);
            }
            let positions: Vec<_> = (0..2 * BUCKETS).collect();
            let effective = effective_columns(
                &prepared.graph_ids,
                &positions,
                &columns(&prepared.widths, &prepared.ids),
                BUCKETS,
            );
            prepared.exceptions =
                super::pair::exception_indices(effective.into_iter().map(Column::canonical));
            let mut marked = prepared.exceptions.clone();
            marked.sort_unstable();
            assert_eq!(marked, [0, 1, 2]);
            let mut affine = vec![blst_p1_affine::default()];
            affine.extend(to_affine(&[G1::generator(), G1::generator() + &bad]));
            assert!(!prepared.check(&affine, &[EMPTY, FILLED, FILLED]));
        }
    }
}

#[test]
fn bit_planes_match_ternary_arithmetic() {
    let from_digit = |digit| Column {
        positive: u64::from(digit == 1),
        negative: u64::from(digit == 2),
    };
    for a in 0..3 {
        for b in 0..3 {
            assert_eq!(from_digit(a).plus(from_digit(b)), from_digit((a + b) % 3));
        }
        assert_eq!(from_digit(a).signed(true), from_digit((3 - a) % 3));
    }
    let mut ids = vec![Vec::new()];
    for value in -40i32..=40 {
        ids[0].push(value.unsigned_abs() | if value < 0 { ID_NEGATE } else { 0 });
    }
    for (index, column) in columns(&[4], &ids).into_iter().enumerate() {
        assert_eq!(column.positive & column.negative, 0);
        let recovered: i32 = (0..4)
            .map(|bit| {
                (((column.positive >> bit) & 1) as i32 - ((column.negative >> bit) & 1) as i32)
                    * 3i32.pow(bit)
            })
            .sum();
        assert_eq!(recovered, index as i32 - 40);
    }
}

#[test]
fn effective_certificate_marks_original_copies_and_omissions() {
    let one = Column {
        positive: 1,
        negative: 0,
    };
    let two = one.signed(true);
    let graph_ids = [vec![0, 0, 0], vec![0, ID_NEGATE, 1]];
    let effective = effective_columns(&graph_ids, &[0, usize::MAX, 1, usize::MAX], &[one, two], 2);
    let effective: Vec<_> = effective.into_iter().map(Column::canonical).collect();
    assert_eq!(effective[0], 0);
    assert_eq!(effective[1], one.canonical());
    assert_eq!(effective[2], one.canonical());
    assert_eq!(super::pair::exception_indices(effective), [0, 1, 2]);
}

#[test]
fn recursive_effective_check_rejects_adversarial_inputs() {
    let generator = G1::generator();
    let bad = order_three();
    assert!(check(&[], &mut test_rng()));
    assert!(check(&[G1::zero(); 16], &mut test_rng()));
    for count in [0, 1, 2, 3, 4, 8, 12, 13, 32, 1254] {
        let mut points = vec![generator; 4096];
        for (i, point) in points.iter_mut().take(count).enumerate() {
            *point += &if i % 2 == 0 { bad } else { -bad };
        }
        points.extend([G1::zero(); 16]);
        assert_eq!(check(&points, &mut test_rng()), count == 0);
    }
}

#[test]
fn effective_columns_match_the_complete_group_circuit() {
    let generator = G1::generator();
    let one = generator.as_blst_p1().z;
    let bad = order_three();
    let mut rng = test_rng();
    let graph_ids = super::two::draw_ids::<3>(81, &mut rng);
    let mut point = generator;
    let mut points: Vec<_> = (0..81)
        .map(|i| {
            point += &generator;
            if i % 3 == 0 { point + &bad } else { point }
        })
        .collect();
    let mut replacements = [generator, generator, -(generator + &generator)].into_iter();
    for (point, &id) in points.iter_mut().zip(&graph_ids[0]) {
        if id & !ID_NEGATE == 0 {
            let replacement = replacements.next().unwrap();
            *point = if id & ID_NEGATE == 0 {
                replacement
            } else {
                -replacement
            };
        }
    }
    assert!(replacements.next().is_none());
    let affine = to_affine(&points);
    assert_eq!(affine.len(), points.len());
    let mut round = Round::new(4);
    round.widen(4);
    let mut positions = vec![usize::MAX; 54];
    let mut compressed = Vec::new();
    for (pass, ids) in graph_ids.iter().enumerate() {
        round.accumulate(&affine, ids);
        for bucket in 0..27 {
            if round.live[bucket] {
                positions[pass * 27 + bucket] = compressed.len();
                let point = round.sums[bucket];
                compressed.push(G1::from_blst_p1(blst_p1 {
                    x: point.x,
                    y: point.y,
                    z: one,
                }));
            }
        }
    }
    assert_eq!(positions[0], usize::MAX);
    let widths = [2, 3];
    let mut trits = Trits::new(&mut rng);
    let ids: Vec<_> = widths
        .iter()
        .map(|&width| trits.fill(width, compressed.len()))
        .collect();
    let effective = effective_columns(&graph_ids, &positions, &columns(&widths, &ids), 27);
    let mut digits = vec![Vec::new(); compressed.len()];
    for (&width, pass) in widths.iter().zip(&ids) {
        let half = (3i32.pow(width) - 1) / 2;
        for (digits, &id) in digits.iter_mut().zip(pass) {
            let value = (id & !ID_NEGATE) as i32 * if id & ID_NEGATE == 0 { 1 } else { -1 };
            for bit in 0..width {
                digits.push((((value + half) / 3i32.pow(bit)) % 3 - 1) as i8);
            }
        }
    }
    let mut saw_double = false;
    for row in 0..5 {
        let mut direct = G1::zero();
        for (point, digits) in compressed.iter().zip(&digits) {
            if digits[row] == 1 {
                direct += point;
            }
            if digits[row] == -1 {
                direct -= point;
            }
        }
        let mut composed = G1::zero();
        for (index, point) in points.iter().enumerate() {
            let mut coefficient = 0i8;
            for (pass, ids) in graph_ids.iter().enumerate() {
                let id = ids[index];
                let position = positions[pass * 27 + (id & !ID_NEGATE) as usize];
                if position != usize::MAX {
                    coefficient += digits[position][row] * if id & ID_NEGATE == 0 { 1 } else { -1 };
                }
            }
            saw_double |= coefficient.abs() == 2;
            assert_eq!(
                (effective[index].positive >> row) & 1,
                u64::from(coefficient.rem_euclid(3) == 1)
            );
            assert_eq!(
                (effective[index].negative >> row) & 1,
                u64::from(coefficient.rem_euclid(3) == 2)
            );
            for _ in 0..coefficient.unsigned_abs() {
                if coefficient > 0 {
                    composed += point;
                } else {
                    composed -= point;
                }
            }
        }
        assert_eq!(direct, composed);
    }
    assert!(saw_double);
    let polluted = to_affine(&[generator, generator + &bad]);
    let column = Column {
        positive: 1,
        negative: 0,
    };
    assert!(!checked_effective(&polluted, vec![column, column]));
    assert!(!checked_effective(
        &polluted,
        vec![column, Column::default()]
    ));
}
