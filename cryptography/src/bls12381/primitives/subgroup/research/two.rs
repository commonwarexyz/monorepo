//! Two-pass compression on a fixed algebraic graph of girth eight.
//!
//! The graph is public; its injective input assignment and endpoint signs are
//! freshly randomized. See `cryptography/SUBGROUP_TWO_PASS.md` for the proof.

use super::*;
use commonware_utils::{ScriptedRng, TestRng};

#[path = "blocks.rs"]
mod blocks;

fn uniform_below(bound: u32, mut draw: impl FnMut() -> u64) -> u32 {
    assert!(bound > 0);
    let bound = u64::from(bound);
    let limit = u64::MAX - u64::MAX % bound;
    loop {
        let word = draw();
        if word < limit {
            return (word % bound) as u32;
        }
    }
}

fn sample_edges(universe: u32, n: usize, mut choose: impl FnMut(u32) -> u32) -> Vec<u32> {
    assert!(n <= universe as usize);
    if n == 0 {
        return Vec::new();
    }
    let mut edges: Vec<_> = (0..universe).collect();
    for i in 0..n {
        let remaining = universe - i as u32;
        let offset = choose(remaining);
        assert!(offset < remaining);
        edges.swap(i, i + offset as usize);
    }
    edges.truncate(n);
    edges
}

fn endpoints<const Q: u32>(edge: u32) -> [u32; 2] {
    truncated_endpoints::<Q, Q>(edge)
}

fn truncated_endpoints<const Q: u32, const D: u32>(edge: u32) -> [u32; 2] {
    let left = edge / D;
    let (u, v, w, t) = (left / (Q * Q), left / Q % Q, left % Q, edge % D);
    let right = (t * Q + (u * t + Q - v) % Q) * Q + (u * t * t + Q - w) % Q;
    [left, right]
}

fn signed_ids<const Q: u32>(edges: &[u32], rng: &mut impl CryptoRng) -> [Vec<u32>; 2] {
    signed_ids_with::<Q, Q>(edges, rng)
}

fn signed_ids_with<const Q: u32, const D: u32>(
    edges: &[u32],
    rng: &mut impl CryptoRng,
) -> [Vec<u32>; 2] {
    let mut ids = [
        Vec::with_capacity(edges.len()),
        Vec::with_capacity(edges.len()),
    ];
    for &edge in edges {
        let buckets = truncated_endpoints::<Q, D>(edge);
        let signs = rng.next_u32();
        for pass in 0..2 {
            ids[pass].push(buckets[pass] | (((signs >> pass) & 1) * ID_NEGATE));
        }
    }
    ids
}

pub(super) fn draw_ids<const Q: u32>(n: usize, rng: &mut impl CryptoRng) -> [Vec<u32>; 2] {
    let edges = sample_edges(Q.pow(4), n, |bound| uniform_below(bound, || rng.next_u64()));
    signed_ids::<Q>(&edges, rng)
}

fn two_pass_check<const Q: u32, const SPLIT: bool>(
    points: &[G1],
    rng: &mut impl CryptoRng,
) -> (bool, [Duration; 4]) {
    two_pass_check_with::<Q, SPLIT, _>(points, rng, |points, rng| {
        batch_in_g1(points, 111, &Sequential, rng)
    })
}

fn recursive_inner<const SPLIT: bool>(points: &[G1], rng: &mut impl CryptoRng) -> bool {
    assert!(points.len() <= 31u32.pow(4) as usize);
    let affine = to_affine(points);
    let ids = draw_ids::<31>(affine.len(), rng);
    let mut round = Round::new(11);
    round.widen(11);
    let mut sums = Vec::with_capacity(2 * 31usize.pow(3));
    for pass in &ids {
        let compressed = compress_round_with_buckets(&mut round, &affine, pass, 31usize.pow(3));
        if SPLIT {
            if !batch_in_g1(&compressed, 99, &Sequential, rng) {
                return false;
            }
        } else {
            sums.extend(compressed);
        }
    }
    SPLIT || batch_in_g1(&sums, 114, &Sequential, rng)
}

fn two_pass_check_with<const Q: u32, const SPLIT: bool, R: CryptoRng>(
    points: &[G1],
    rng: &mut R,
    check: impl FnMut(&[G1], &mut R) -> bool,
) -> (bool, [Duration; 4]) {
    graph_check_with::<Q, Q, SPLIT, _>(points, rng, check)
}

fn graph_check_with<const Q: u32, const D: u32, const SPLIT: bool, R: CryptoRng>(
    points: &[G1],
    rng: &mut R,
    mut check: impl FnMut(&[G1], &mut R) -> bool,
) -> (bool, [Duration; 4]) {
    assert!(matches!((Q, D), (47, 47) | (53, 53) | (47, 43)));
    assert!(
        D == Q || SPLIT,
        "truncated graph requires split composition"
    );
    let universe = Q * Q * D * D;
    assert!(points.len() <= universe as usize);
    let start = Instant::now();
    let affine = to_affine(points);
    let normalized = start.elapsed();
    let start = Instant::now();
    let edges = sample_edges(universe, affine.len(), |bound| {
        uniform_below(bound, || rng.next_u64())
    });
    let ids = signed_ids_with::<Q, D>(&edges, rng);
    drop(edges);
    let sampled = start.elapsed();
    let start = Instant::now();
    let buckets = (Q * Q * D) as usize;
    let mut round = Round::new(12);
    round.widen(12);
    let mut sums = Vec::with_capacity(if SPLIT { 0 } else { 2 * buckets });
    let mut compressed = start.elapsed();
    let mut checked = Duration::ZERO;
    for pass in &ids {
        let start = Instant::now();
        let pass_sums = compress_round_with_buckets(&mut round, &affine, pass, buckets);
        if SPLIT {
            compressed += start.elapsed();
            let start = Instant::now();
            let valid = check(&pass_sums, rng);
            checked += start.elapsed();
            if !valid {
                return (false, [normalized, sampled, compressed, checked]);
            }
        } else {
            sums.extend(pass_sums);
            compressed += start.elapsed();
        }
    }
    let start = Instant::now();
    let valid = SPLIT || batch_in_g1(&sums, 129, &Sequential, rng);
    checked += start.elapsed();
    (valid, [normalized, sampled, compressed, checked])
}

#[test]
fn uniform_sampler_rejects_incomplete_residue_class() {
    let bound = 7;
    let limit = u64::MAX - u64::MAX % u64::from(bound);
    let mut words = [u64::MAX, limit, limit - 1].into_iter();
    assert_eq!(uniform_below(bound, || words.next().unwrap()), bound - 1);
    assert!(words.next().is_none());
    assert_eq!(uniform_below(1, || 17), 0);
    for residue in 0..bound {
        assert_eq!(uniform_below(bound, || u64::from(residue)), residue);
    }
}

#[test]
fn partial_shuffle_enumerates_every_injection_once() {
    let mut injections = std::collections::BTreeSet::new();
    for a in 0..4 {
        for b in 0..3 {
            for c in 0..2 {
                let mut offsets = [a, b, c].into_iter();
                let edges = sample_edges(4, 3, |_| offsets.next().unwrap());
                assert!(injections.insert(edges));
            }
        }
    }
    assert_eq!(injections.len(), 24);
    assert!(sample_edges(4, 0, |_| panic!("empty injection draws nothing")).is_empty());
    assert_eq!(sample_edges(4, 4, |_| 0), [0, 1, 2, 3]);
    let mut rng = test_rng();
    let mut edges = sample_edges(1000, 1000, |bound| uniform_below(bound, || rng.next_u64()));
    edges.sort_unstable();
    assert_eq!(edges, (0..1000).collect::<Vec<_>>());
}

#[test]
fn endpoint_signs_use_separate_bits() {
    let mut rng = ScriptedRng::new([0, 1, 2, 3]);
    let ids = signed_ids::<3>(&[0; 4], &mut rng);
    assert_eq!(ids[0], [0, ID_NEGATE, 0, ID_NEGATE]);
    assert_eq!(ids[1], [0, 0, ID_NEGATE, ID_NEGATE]);
}

fn graph<const Q: u32>() -> Vec<Vec<usize>> {
    let buckets = Q.pow(3) as usize;
    let mut graph = vec![Vec::new(); 2 * buckets];
    for edge in 0..Q.pow(4) {
        let [left, right] = endpoints::<Q>(edge);
        let (left, right) = (left as usize, right as usize + buckets);
        graph[left].push(right);
        graph[right].push(left);
    }
    graph
}

fn check_graph<const Q: u32>() {
    let graph = graph::<Q>();
    for neighbors in &graph {
        let mut distinct = neighbors.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), Q as usize);
    }
    let mut girth = usize::MAX;
    for root in 0..graph.len() {
        let mut distance = vec![usize::MAX; graph.len()];
        let mut parent = vec![usize::MAX; graph.len()];
        let mut queue = vec![root];
        distance[root] = 0;
        let mut index = 0;
        while index < queue.len() {
            let vertex = queue[index];
            index += 1;
            if distance[vertex] == 4 {
                continue;
            }
            for &neighbor in &graph[vertex] {
                if distance[neighbor] == usize::MAX {
                    distance[neighbor] = distance[vertex] + 1;
                    parent[neighbor] = vertex;
                    queue.push(neighbor);
                } else if parent[vertex] != neighbor {
                    girth = girth.min(distance[vertex] + distance[neighbor] + 1);
                }
            }
        }
    }
    assert_eq!(girth, 8);
}

#[test]
fn algebraic_graph_is_regular_and_has_girth_eight() {
    check_graph::<3>();
    check_graph::<5>();
    check_graph::<7>();
}

fn check_full_parameters<const Q: u32>() {
    let buckets = Q.pow(3) as usize;
    let mut degree = [vec![0u32; buckets], vec![0u32; buckets]];
    for edge in 0..Q.pow(4) {
        let [left, right] = endpoints::<Q>(edge);
        assert!(left < buckets as u32 && right < buckets as u32);
        assert_eq!(left, edge / Q);
        // The right first coordinate distinguishes all neighbors of a left
        // vertex, so no two edge codes describe the same endpoint pair.
        assert_eq!(right / (Q * Q), edge % Q);
        degree[0][left as usize] += 1;
        degree[1][right as usize] += 1;
    }
    assert!(degree.iter().flatten().all(|&count| count == Q));
}

#[test]
fn full_parameter_graphs_are_simple_bounded_and_regular() {
    check_full_parameters::<19>();
    check_full_parameters::<31>();
    check_full_parameters::<47>();
    check_full_parameters::<53>();
}

#[test]
fn truncated_graph_is_a_regular_subgraph() {
    let buckets = 47 * 47 * 43;
    let mut degree = [vec![0u32; buckets], vec![0u32; buckets]];
    for edge in 0..47 * 47 * 43 * 43 {
        let actual = truncated_endpoints::<47, 43>(edge);
        assert_eq!(actual, endpoints::<47>((edge / 43) * 47 + edge % 43));
        assert_eq!(actual[0], edge / 43);
        assert_eq!(actual[1] / (47 * 47), edge % 43);
        for pass in 0..2 {
            assert!((actual[pass] as usize) < buckets);
            degree[pass][actual[pass] as usize] += 1;
        }
    }
    assert!(degree.iter().flatten().all(|&count| count == 43));
}

#[test]
fn recursive_check_rejects_adversarial_inputs() {
    assert_eq!(combinations_for_security(114), 72);
    assert_eq!(combinations_for_security(99), 63);
    let generator = G1::generator();
    let bad = order_three();
    for count in [0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 32, 2046] {
        let mut points = vec![generator; 4096];
        for (i, point) in points.iter_mut().take(count).enumerate() {
            *point += &if i % 2 == 0 { bad } else { -bad };
        }
        points.extend([G1::zero(); 16]);
        assert_eq!(
            recursive_inner::<false>(&points, &mut test_rng()),
            count == 0
        );
        assert_eq!(
            recursive_inner::<true>(&points, &mut test_rng()),
            count == 0
        );
        assert_eq!(
            two_pass_check_with::<47, true, _>(&points, &mut test_rng(), recursive_inner::<false>)
                .0,
            count == 0
        );
        assert_eq!(
            two_pass_check_with::<47, true, _>(&points, &mut test_rng(), recursive_inner::<true>).0,
            count == 0
        );
        assert_eq!(
            two_pass_check_with::<47, true, _>(&points, &mut test_rng(), super::pair::check::<96>)
                .0,
            count == 0
        );
        assert_eq!(
            graph_check_with::<47, 43, true, _>(&points, &mut test_rng(), super::pair::check::<99>)
                .0,
            count == 0
        );
    }
    assert!(recursive_inner::<false>(&[], &mut test_rng()));
    assert!(recursive_inner::<false>(&[G1::zero(); 8], &mut test_rng()));
    assert!(recursive_inner::<true>(&[], &mut test_rng()));
    assert!(recursive_inner::<true>(&[G1::zero(); 8], &mut test_rng()));
}

#[test]
fn effective_outer_check_rejects_adversarial_inputs() {
    let generator = G1::generator();
    let bad = order_three();
    for count in [0, 1, 2, 3, 7, 8, 12, 32, 3102] {
        let mut points = vec![generator; 4096];
        for (i, point) in points.iter_mut().take(count).enumerate() {
            *point += &if i % 2 == 0 { bad } else { -bad };
        }
        points.extend([G1::zero(); 16]);
        assert_eq!(
            two_pass_check_with::<47, true, _>(&points, &mut test_rng(), super::effective::check).0,
            count == 0
        );
        assert_eq!(
            graph_check_with::<47, 43, true, _>(&points, &mut test_rng(), super::effective::check)
                .0,
            count == 0
        );
    }
}

#[test]
fn eight_cycle_has_exact_endpoint_sign_probability() {
    let cycle = [0, 27, 28, 25, 24, 78, 79, 1];
    let mut vanished = 0;
    for signs in 0u32..1 << 16 {
        let mut sums = [[0u8; 27]; 2];
        for (i, edge) in cycle.into_iter().enumerate() {
            for (pass, bucket) in endpoints::<3>(edge).into_iter().enumerate() {
                // Either sign of a fixed order-three element.
                let value = 1 + ((signs >> (2 * i + pass)) & 1) as u8;
                sums[pass][bucket as usize] = (sums[pass][bucket as usize] + value) % 3;
            }
        }
        vanished += usize::from(sums.iter().flatten().all(|&sum| sum == 0));
    }
    assert_eq!(vanished, 256);
}

#[test]
fn graph_compression_matches_direct_group_sums() {
    let generator = G1::generator();
    let bad = order_three();
    let points: Vec<_> = (0..81)
        .map(|i| match i % 4 {
            0 => generator,
            1 => -generator,
            2 => bad,
            _ => generator + &bad,
        })
        .collect();
    let affine = to_affine(&points);
    let ids = draw_ids::<3>(points.len(), &mut test_rng());
    let mut round = Round::new(4);
    round.widen(4);
    for pass in &ids {
        let mut expected = [G1::zero(); 27];
        for (point, &id) in points.iter().zip(pass) {
            let bucket = (id & !ID_NEGATE) as usize;
            if id & ID_NEGATE == 0 {
                expected[bucket] += point;
            } else {
                expected[bucket] -= point;
            }
        }
        let expected: Vec<_> = expected.into_iter().filter(|p| *p != G1::zero()).collect();
        assert_eq!(
            compress_round_with_buckets(&mut round, &affine, pass, 27),
            expected
        );
    }
}

#[test]
fn two_pass_checks_adversarial_inputs() {
    let generator = G1::generator();
    let bad = order_three();
    assert!(!bad.in_subgroup());
    assert_eq!(bad + &bad + &bad, G1::zero());
    for points in [vec![], vec![G1::zero(); 16], vec![generator]] {
        assert!(two_pass_check::<47, false>(&points, &mut test_rng()).0);
        assert!(two_pass_check::<53, false>(&points, &mut test_rng()).0);
        assert!(two_pass_check::<47, true>(&points, &mut test_rng()).0);
        assert!(two_pass_check::<53, true>(&points, &mut test_rng()).0);
    }
    for count in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 32, 3102] {
        let mut points = vec![generator; 4096];
        for (i, point) in points.iter_mut().take(count).enumerate() {
            *point += &if i % 2 == 0 { bad } else { -bad };
        }
        points.extend([G1::zero(); 16]);
        assert_eq!(
            two_pass_check::<47, false>(&points, &mut test_rng()).0,
            count == 0
        );
        assert_eq!(
            two_pass_check::<53, false>(&points, &mut test_rng()).0,
            count == 0
        );
        assert_eq!(
            two_pass_check::<47, true>(&points, &mut test_rng()).0,
            count == 0
        );
        assert_eq!(
            two_pass_check::<53, true>(&points, &mut test_rng()).0,
            count == 0
        );
    }
}

#[test]
fn effective_outer_check_rejects_order_eleven_inputs() {
    let bad = order_eleven();
    for count in [1, 2, 8] {
        let mut points = vec![G1::generator(); 4096];
        for (i, point) in points.iter_mut().take(count).enumerate() {
            *point += &if i % 2 == 0 { bad } else { -bad };
        }
        let (full, _) =
            graph_check_with::<47, 47, true, _>(&points, &mut test_rng(), super::effective::check);
        let (truncated, _) =
            graph_check_with::<47, 43, true, _>(&points, &mut test_rng(), super::effective::check);
        assert!(!full);
        assert!(!truncated);
    }
}

#[test]
#[ignore = "manual research benchmark"]
fn measure_two_pass() {
    measure_algorithms("measure_two_pass", &[0, 1, 2, 3]);
}

#[test]
#[ignore = "manual research benchmark"]
fn measure_cascade() {
    measure_algorithms("measure_cascade", &[0, 1, 3, 6, 7, 8, 9]);
}

#[test]
#[ignore = "manual research benchmark; the order-three filter is incomplete"]
fn measure_order_three() {
    measure_algorithms("measure_order_three", &[0, 9, 20]);
}

fn measure_algorithms(operation: &str, algorithms: &[u32]) {
    let points = benchmark_points(3_000_000);
    for n in [100_000, 1_000_000, 3_000_000] {
        for repeat in 0..4 {
            for index in 0..algorithms.len() {
                let index = if repeat % 2 == 0 {
                    index
                } else {
                    algorithms.len() - 1 - index
                };
                let algorithm = algorithms[index];
                let mut rng = TestRng::new(repeat);
                let start = Instant::now();
                let (valid, phases) = match algorithm {
                    0 => (
                        batch_in_g1(&points[..n], 128, &Sequential, &mut rng),
                        [Duration::ZERO; 4],
                    ),
                    1 => {
                        let shape = if n < 3_000_000 { (15, 15) } else { (17, 14) };
                        let (valid, phases, _) = super::three::three_pass_exceptions(
                            &points[..n],
                            shape.0,
                            shape.1,
                            &mut rng,
                        );
                        (valid, phases)
                    }
                    2 => two_pass_check::<47, false>(&points[..n], &mut rng),
                    3 => two_pass_check::<47, true>(&points[..n], &mut rng),
                    6 => two_pass_check_with::<47, true, _>(
                        &points[..n],
                        &mut rng,
                        recursive_inner::<true>,
                    ),
                    7 => graph_check_with::<47, 43, true, _>(
                        &points[..n],
                        &mut rng,
                        super::pair::check::<96>,
                    ),
                    8 => two_pass_check_with::<47, true, _>(
                        &points[..n],
                        &mut rng,
                        super::effective::check,
                    ),
                    9 => graph_check_with::<47, 43, true, _>(
                        &points[..n],
                        &mut rng,
                        super::effective::check,
                    ),
                    20 => super::primary::check_order_three(&points[..n], &mut rng),
                    _ => unreachable!(),
                };
                assert!(valid);
                let component = if algorithm == 20 {
                    "order_three_only"
                } else {
                    "complete"
                };
                eprintln!(
                    "{}::{operation}/n={n} repeat={repeat} algorithm={algorithm} component={component} elapsed={:?} phases={phases:?}",
                    module_path!(),
                    start.elapsed()
                );
            }
        }
    }
}
