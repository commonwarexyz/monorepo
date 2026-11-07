//! Fuse the two graph accumulations in collision-free (u,t) blocks.
//!
//! Scheduling preserves the sampled input-to-edge map and both endpoint signs.
//! Blocks of the same color (u+t) mod D have distinct outputs on both sides,
//! so they share inversion batches without retry lists or per-block flushes.
//! See `cryptography/SUBGROUP_PRECOMPUTATION.md` for measurements and scope.

use super::*;

struct Schedule {
    offsets: Vec<usize>,
    indices: Vec<u32>,
}

impl Schedule {
    fn new<const Q: u32, const D: u32>(edges: &[u32]) -> Self {
        let block = |edge: u32| {
            let u = edge / (D * Q * Q);
            let t = edge % D;
            (((u + t) % D) * D + u) as usize
        };
        let mut offsets = vec![0; D.pow(2) as usize + 1];
        for &edge in edges {
            offsets[block(edge) + 1] += 1;
        }
        for i in 1..offsets.len() {
            offsets[i] += offsets[i - 1];
        }
        let mut cursors = offsets.clone();
        let mut indices = vec![0; edges.len()];
        for (index, &edge) in edges.iter().enumerate() {
            let cursor = &mut cursors[block(edge)];
            indices[*cursor] = index as u32;
            *cursor += 1;
        }
        // Preserve block locality inside each color, but flush only between
        // colors: all blocks of one color write disjoint left AND right slabs.
        let offsets = offsets.into_iter().step_by(D as usize).collect();
        Self { offsets, indices }
    }
}

struct Accumulator {
    buckets: usize,
    sums: Vec<blst_p1_affine>,
    state: Vec<u8>,
    pending: Pending,
}

impl Accumulator {
    fn new(buckets: usize) -> Self {
        Self {
            buckets,
            sums: vec![blst_p1_affine::default(); 2 * buckets],
            state: vec![EMPTY; 2 * buckets],
            pending: Pending::new(),
        }
    }

    fn queue(&mut self, points: &[blst_p1_affine], index: u32, bucket: usize, negate: bool) {
        let point = &points[index as usize];
        debug_assert_ne!(self.state[bucket], BUSY, "color outputs must be distinct");
        if self.state[bucket] == EMPTY {
            self.sums[bucket] = if negate { neg_affine(point) } else { *point };
            self.state[bucket] = FILLED;
            return;
        }
        let held = &self.sums[bucket];
        let mut flags = if negate { OP_NEGATE } else { 0 };
        let denominator = if fp_eq(&held.x, &point.x) {
            let two_y = if negate {
                fp_sub(&held.y, &point.y)
            } else {
                fp_add(&held.y, &point.y)
            };
            if fp_is_zero(&two_y) {
                self.state[bucket] = EMPTY;
                return;
            }
            flags |= DOUBLE;
            two_y
        } else if negate {
            fp_sub(&held.x, &point.x)
        } else {
            fp_sub(&point.x, &held.x)
        };
        self.pending.push(bucket as u32 | flags, index, denominator);
        self.state[bucket] = BUSY;
        if self.pending.is_full() {
            self.flush(points);
        }
    }

    fn flush(&mut self, points: &[blst_p1_affine]) {
        absorb(points, &mut self.sums, &mut self.state, &mut self.pending);
    }

    fn accumulate(&mut self, points: &[blst_p1_affine], ids: &[Vec<u32>; 2], schedule: &Schedule) {
        assert!(points.len() <= ids[0].len());
        assert_eq!(ids[0].len(), ids[1].len());
        self.state.fill(EMPTY);
        for range in schedule.offsets.windows(2) {
            let block = &schedule.indices[range[0]..range[1]];
            for (position, &index) in block.iter().enumerate() {
                if let Some(&ahead) = block.get(position + PREFETCH_DISTANCE)
                    && (ahead as usize) < points.len()
                {
                    prefetch(points, ahead as usize);
                }
                // Restricting a uniform injection to a prefix is still uniform.
                // This permits identity removal after one-shot preparation.
                if index as usize >= points.len() {
                    continue;
                }
                for (pass, ids) in ids.iter().enumerate() {
                    let id = ids[index as usize];
                    let bucket = pass * self.buckets + (id & !ID_NEGATE) as usize;
                    self.queue(points, index, bucket, id & ID_NEGATE != 0);
                }
            }
            // A later color may revisit either side's outputs.
            self.flush(points);
        }
    }

    fn points(&self, pass: usize) -> Vec<G1> {
        let start = pass * self.buckets;
        self.sums[start..start + self.buckets]
            .iter()
            .zip(&self.state[start..start + self.buckets])
            .filter(|&(_, &state)| state != EMPTY)
            .map(|(point, _)| {
                G1::from_blst_p1(blst_p1 {
                    x: point.x,
                    y: point.y,
                    z: MONTGOMERY_ONE,
                })
            })
            .collect()
    }
}

// Consume a preparation exactly once. Its randomness must remain private until
// the corresponding batch is fixed; preparations must never be reused.
struct Prepared {
    n: usize,
    ids: [Vec<u32>; 2],
    schedule: Schedule,
    accumulator: Accumulator,
}

impl Prepared {
    fn new<const D: u32>(n: usize, rng: &mut impl CryptoRng) -> Self {
        assert!(matches!(D, 43 | 47));
        let edges = sample_edges(47 * 47 * D * D, n, |bound| {
            uniform_below(bound, || rng.next_u64())
        });
        let ids = signed_ids_with::<47, D>(&edges, rng);
        let schedule = Schedule::new::<47, D>(&edges);
        drop(edges);
        Self {
            n,
            ids,
            schedule,
            accumulator: Accumulator::new((47 * 47 * D) as usize),
        }
    }

    fn check(mut self, points: &[G1], rng: &mut impl CryptoRng) -> (bool, [Duration; 4]) {
        assert_eq!(points.len(), self.n);
        let start = Instant::now();
        let affine = to_affine(points);
        let normalized = start.elapsed();
        let start = Instant::now();
        self.accumulator
            .accumulate(&affine, &self.ids, &self.schedule);
        let mut compressed = start.elapsed();
        let mut checked = Duration::ZERO;
        for pass in 0..2 {
            let start = Instant::now();
            let sums = self.accumulator.points(pass);
            compressed += start.elapsed();
            let start = Instant::now();
            let valid = super::super::effective::check(&sums, rng);
            checked += start.elapsed();
            if !valid {
                return (false, [normalized, Duration::ZERO, compressed, checked]);
            }
        }
        (true, [normalized, Duration::ZERO, compressed, checked])
    }
}

struct PreparedBatch {
    outer: Prepared,
    inner: [super::super::effective::Prepared; 2],
}

impl PreparedBatch {
    fn new(n: usize, rng: &mut impl CryptoRng) -> Self {
        let outer = Prepared::new::<43>(n, rng);
        let inner = core::array::from_fn(|_| {
            super::super::effective::Prepared::new(outer.accumulator.buckets, rng)
        });
        Self { outer, inner }
    }

    fn check(self, points: &[G1]) -> (bool, [Duration; 4]) {
        let Self { mut outer, inner } = self;
        assert_eq!(points.len(), outer.n);
        let start = Instant::now();
        let affine = to_affine(points);
        let normalized = start.elapsed();
        let start = Instant::now();
        outer
            .accumulator
            .accumulate(&affine, &outer.ids, &outer.schedule);
        let compressed = start.elapsed();
        let start = Instant::now();
        let buckets = outer.accumulator.buckets;
        for (pass, inner) in inner.into_iter().enumerate() {
            let range = pass * buckets..(pass + 1) * buckets;
            if !inner.check(
                &outer.accumulator.sums[range.clone()],
                &outer.accumulator.state[range],
            ) {
                return (
                    false,
                    [normalized, Duration::ZERO, compressed, start.elapsed()],
                );
            }
        }
        (
            true,
            [normalized, Duration::ZERO, compressed, start.elapsed()],
        )
    }
}

// Control for separating the benefit of preparation from block scheduling.
// Keep the generic outer accumulator, but feed affine slots to prepared inners.
struct PreparedGenericBatch {
    n: usize,
    ids: [Vec<u32>; 2],
    round: Round,
    inner: [super::super::effective::Prepared; 2],
}

impl PreparedGenericBatch {
    fn new(n: usize, rng: &mut impl CryptoRng) -> Self {
        let edges = sample_edges(47 * 47 * 43 * 43, n, |bound| {
            uniform_below(bound, || rng.next_u64())
        });
        let ids = signed_ids_with::<47, 43>(&edges, rng);
        drop(edges);
        let inner =
            core::array::from_fn(|_| super::super::effective::Prepared::new(47 * 47 * 43, rng));
        let mut round = Round::new(12);
        round.widen(12);
        Self {
            n,
            ids,
            round,
            inner,
        }
    }

    fn check(self, points: &[G1]) -> (bool, [Duration; 4]) {
        let Self {
            n,
            ids,
            mut round,
            inner,
        } = self;
        assert_eq!(points.len(), n);
        let start = Instant::now();
        let affine = to_affine(points);
        let normalized = start.elapsed();
        let mut compressed = Duration::ZERO;
        let mut checked = Duration::ZERO;
        for (ids, inner) in ids.iter().zip(inner) {
            let start = Instant::now();
            round.accumulate(&affine, &ids[..affine.len()]);
            compressed += start.elapsed();
            let start = Instant::now();
            let valid = inner.check(&round.sums[..47 * 47 * 43], &round.state[..47 * 47 * 43]);
            checked += start.elapsed();
            if !valid {
                return (false, [normalized, Duration::ZERO, compressed, checked]);
            }
        }
        (true, [normalized, Duration::ZERO, compressed, checked])
    }
}

#[test]
fn blocks_are_matchings_on_both_sides() {
    fn verify<const Q: u32, const D: u32>() {
        let side = (Q * Q) as usize;
        for u in 0..D {
            for t in 0..D {
                let mut seen = vec![false; side];
                for v in 0..Q {
                    for w in 0..Q {
                        let edge = ((u * Q + v) * Q + w) * D + t;
                        let [left, right] = truncated_endpoints::<Q, D>(edge);
                        assert_eq!(left, (u * Q + v) * Q + w);
                        assert_eq!(right / (Q * Q), t);
                        let right = right as usize % side;
                        assert!(!seen[right]);
                        seen[right] = true;
                    }
                }
                assert!(seen.into_iter().all(|seen| seen));
            }
        }
    }
    verify::<3, 3>();
    verify::<19, 19>();
    verify::<47, 47>();
    verify::<47, 43>();
}

fn compare<const Q: u32, const D: u32>(points: &[G1], edges: &[u32], rng: &mut impl CryptoRng) {
    let affine = to_affine(points);
    assert_eq!(affine.len(), edges.len());
    let ids = signed_ids_with::<Q, D>(edges, rng);
    let schedule = Schedule::new::<Q, D>(edges);
    let mut permutation = schedule.indices.clone();
    permutation.sort_unstable();
    assert_eq!(permutation, (0..edges.len() as u32).collect::<Vec<_>>());
    let buckets = (Q * Q * D) as usize;
    for range in schedule.offsets.windows(2) {
        let mut seen = vec![false; 2 * buckets];
        for &index in &schedule.indices[range[0]..range[1]] {
            for (pass, ids) in ids.iter().enumerate() {
                let bucket = pass * buckets + (ids[index as usize] & !ID_NEGATE) as usize;
                assert!(!seen[bucket]);
                seen[bucket] = true;
            }
        }
    }
    let mut accumulator = Accumulator::new(buckets);
    let width = (1..=MAX_WIDTH).find(|&m| folded(m) >= buckets).unwrap();
    let mut round = Round::new(width);
    round.widen(width);
    // Reuse the buffers to check that cancelled and previously live slots reset.
    for _ in 0..2 {
        accumulator.accumulate(&affine, &ids, &schedule);
        assert!(!accumulator.state.contains(&BUSY));
        for (pass, ids) in ids.iter().enumerate() {
            let mut direct = vec![G1::zero(); buckets];
            for (point, &id) in points.iter().zip(ids) {
                let bucket = (id & !ID_NEGATE) as usize;
                if id & ID_NEGATE == 0 {
                    direct[bucket] += point;
                } else {
                    direct[bucket] -= point;
                }
            }
            let direct: Vec<_> = direct.into_iter().filter(|p| *p != G1::zero()).collect();
            assert_eq!(accumulator.points(pass), direct);
            assert_eq!(
                compress_round_with_buckets(&mut round, &affine, ids, buckets),
                direct
            );
        }
    }
}

#[test]
fn fused_blocks_match_direct_and_generic_sums() {
    let generator = G1::generator();
    let three = order_three();
    let eleven = order_eleven();
    for seed in 0..4 {
        let mut rng = TestRng::new(seed);
        for n in [0, 1, 2, 40, 81] {
            let edges = sample_edges(81, n, |bound| uniform_below(bound, || rng.next_u64()));
            let points: Vec<_> = (0..n)
                .map(|i| match i % 6 {
                    0 => generator,
                    1 => -generator,
                    2 => three,
                    3 => -three,
                    4 => eleven,
                    _ => generator + &eleven,
                })
                .collect();
            compare::<3, 3>(&points, &edges, &mut rng);
        }
    }
    // Entire blocks exercise multiple full shared-inversion queues, repeated
    // points, doublings, and cancellations across block boundaries.
    let edges: Vec<_> = (0..47 * 47)
        .flat_map(|vw| (0..4).map(move |t| vw * 43 + t))
        .collect();
    let points: Vec<_> = (0..edges.len())
        .map(|i| match i % 4 {
            0 | 1 => generator,
            2 => three,
            _ => -generator,
        })
        .collect();
    compare::<47, 43>(&points, &edges, &mut test_rng());
    let torsion = vec![three; 81];
    compare::<3, 3>(
        &torsion,
        &(0..81).collect::<Vec<_>>(),
        &mut ScriptedRng::new([0; 81]),
    );
}

#[test]
fn fused_check_rejects_adversarial_batches() {
    for bad in [order_three(), order_eleven()] {
        for count in [0, 1, 2, 8, 31] {
            let mut points = vec![G1::generator(); 4096];
            for (i, point) in points.iter_mut().take(count).enumerate() {
                *point += &if i % 2 == 0 { bad } else { -bad };
            }
            let mut original_rng = TestRng::new(13);
            let mut blocked_rng = TestRng::new(13);
            let original = graph_check_with::<47, 43, true, _>(
                &points,
                &mut original_rng,
                super::super::effective::check,
            )
            .0;
            let blocked = Prepared::new::<43>(points.len(), &mut blocked_rng)
                .check(&points, &mut blocked_rng)
                .0;
            assert_eq!(original, count == 0);
            assert_eq!(blocked, original);
            assert_eq!(original_rng.next_u64(), blocked_rng.next_u64());
            points.extend([G1::zero(); 16]);
            assert_eq!(
                Prepared::new::<47>(points.len(), &mut test_rng())
                    .check(&points, &mut test_rng())
                    .0,
                count == 0
            );
        }
    }
    for points in [vec![], vec![G1::zero(); 16]] {
        assert!(
            Prepared::new::<43>(points.len(), &mut test_rng())
                .check(&points, &mut test_rng())
                .0
        );
    }
}

#[test]
fn prepared_batch_rejects_adversarial_inputs_and_identity_padding() {
    for bad in [order_three(), order_eleven()] {
        for count in [0, 1, 2, 8, 31] {
            // Prepare before constructing the points, including identities
            // interleaved with live inputs rather than only appended.
            let prepared = PreparedBatch::new(4096, &mut test_rng());
            let generic = PreparedGenericBatch::new(4096, &mut test_rng());
            let mut points = vec![G1::generator(); 4096];
            for (i, point) in points.iter_mut().enumerate() {
                if i % 4 == 0 {
                    *point = G1::zero();
                }
            }
            for i in 0..count {
                points[4 * i + 1] += &if i % 2 == 0 { bad } else { -bad };
            }
            assert_eq!(prepared.check(&points).0, count == 0);
            assert_eq!(generic.check(&points).0, count == 0);
        }
    }
    for points in [vec![], vec![G1::zero(); 16], vec![G1::generator()]] {
        assert!(
            PreparedBatch::new(points.len(), &mut test_rng())
                .check(&points)
                .0
        );
        assert!(
            PreparedGenericBatch::new(points.len(), &mut test_rng())
                .check(&points)
                .0
        );
    }
}

#[test]
#[ignore = "manual research benchmark"]
fn measure_blocks() {
    let points = benchmark_points(100_000);
    for repeat in 0..8 {
        for index in 0..4 {
            let variant = if repeat % 2 == 0 { index } else { 3 - index };
            let mut rng = TestRng::new(repeat);
            let start = Instant::now();
            let (valid, phases, prepared, online) = if variant == 3 {
                let prepared = PreparedGenericBatch::new(points.len(), &mut rng);
                let preparation = start.elapsed();
                let online = Instant::now();
                let (valid, phases) = prepared.check(&points);
                (valid, phases, preparation, online.elapsed())
            } else if variant == 2 {
                let prepared = PreparedBatch::new(points.len(), &mut rng);
                let preparation = start.elapsed();
                let online = Instant::now();
                let (valid, phases) = prepared.check(&points);
                (valid, phases, preparation, online.elapsed())
            } else if variant == 1 {
                let prepared = Prepared::new::<43>(points.len(), &mut rng);
                let preparation = start.elapsed();
                let online = Instant::now();
                let (valid, phases) = prepared.check(&points, &mut rng);
                (valid, phases, preparation, online.elapsed())
            } else {
                let (valid, phases) = graph_check_with::<47, 43, true, _>(
                    &points,
                    &mut rng,
                    super::super::effective::check,
                );
                (valid, phases, Duration::ZERO, start.elapsed())
            };
            assert!(valid);
            let variant = ["baseline", "blocks", "prepared_blocks", "prepared_generic"][variant];
            eprintln!(
                "{}::measure_blocks/n={} repeat={repeat} variant={variant} total={:?} preparation={prepared:?} online={online:?} phases={phases:?}",
                module_path!(),
                points.len(),
                start.elapsed()
            );
        }
    }
}

#[test]
#[ignore = "manual research benchmark; prepare before constructing each batch"]
fn measure_prepared_arrival() {
    const N: usize = 100_000;
    for repeat in 0..8 {
        let start = Instant::now();
        let mut prepared = Some(PreparedGenericBatch::new(N, &mut TestRng::new(repeat)));
        let preparation = start.elapsed();
        // Point generation is excluded. It occurs after preparation, touching
        // fresh input memory instead of executing immediately on warm scratch.
        let points = benchmark_points(N);
        for index in 0..2 {
            let use_prepared = (index + repeat) % 2 != 0;
            let start = Instant::now();
            let (valid, phases) = if use_prepared {
                prepared
                    .take()
                    .expect("one use per challenge")
                    .check(&points)
            } else {
                graph_check_with::<47, 43, true, _>(
                    &points,
                    &mut TestRng::new(repeat),
                    super::super::effective::check,
                )
            };
            let online = start.elapsed();
            let setup = if use_prepared {
                preparation
            } else {
                Duration::ZERO
            };
            let variant = if use_prepared {
                "prepared_generic"
            } else {
                "baseline"
            };
            assert!(valid);
            eprintln!(
                "{}::measure_prepared_arrival/n={N} repeat={repeat} variant={variant} total={:?} preparation={setup:?} online={online:?} phases={phases:?}",
                module_path!(),
                setup + online
            );
        }
    }
}
