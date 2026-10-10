//! Independent exact eight-cycle counts for the truncated graph.

// An independent enumeration solves the two cycle equations for four u values.
// Adjacent t values are different. Four distinct t values give a unique pair
// of ratios, three distinct ones are impossible, and two must alternate.
fn cycles_algebraic<const Q: usize>(us: &[usize], ts: &[usize]) -> u64 {
    let mut inverse = vec![0; Q];
    for (x, inverse) in inverse.iter_mut().enumerate().skip(1) {
        *inverse = (1..Q).find(|&y| x * y % Q == 1).unwrap();
    }
    let mut allowed = vec![0u64; Q * Q];
    let mut alternating = 0u64;
    for &u0 in us {
        for &u1 in us {
            if u0 == u1 {
                continue;
            }
            let scale = inverse[(u1 + Q - u0) % Q];
            for &u2 in us {
                if u2 == u1 {
                    continue;
                }
                let u3 = (u0 + Q + u2 - u1) % Q;
                if us.contains(&u3) {
                    alternating += 1;
                }
                for &u3 in us {
                    if u3 == u2 || u3 == u0 {
                        continue;
                    }
                    let r = (u2 + Q - u0) * scale % Q;
                    let s = (u3 + Q - u0) * scale % Q;
                    allowed[r * Q + s] += 1;
                }
            }
        }
    }
    let mut ordered = alternating * (ts.len() * (ts.len() - 1)) as u64;
    for &t0 in ts {
        for &t1 in ts {
            if t1 == t0 {
                continue;
            }
            for &t2 in ts {
                if t2 == t0 || t2 == t1 {
                    continue;
                }
                for &t3 in ts {
                    if t3 == t0 || t3 == t1 || t3 == t2 {
                        continue;
                    }
                    let a = (t1 + Q - t2) % Q;
                    let b = (t2 + Q - t3) % Q;
                    let c = (t1 + Q - t0) % Q;
                    let inv = inverse[a * b * (t3 + Q - t1) % Q];
                    let r = c * b * (t2 + t3 + 2 * Q - t1 - t0) * inv % Q;
                    let s = a * c * (t0 + Q - t2) * inv % Q;
                    ordered += allowed[r * Q + s];
                }
            }
        }
    }
    assert_eq!(ordered * (Q * Q) as u64 % 8, 0);
    ordered * (Q * Q) as u64 / 8
}

fn cycles<const Q: usize>(us: &[usize], ts: &[usize]) -> u64 {
    let mut uv = vec![vec![0; us.len()]; ts.len()];
    let mut uw = uv.clone();
    for (ti, &t) in ts.iter().enumerate() {
        for (ui, &u) in us.iter().enumerate() {
            uv[ti][ui] = u * t % Q;
            uw[ti][ui] = u * t * t % Q;
        }
    }
    let mut counts = vec![0u16; us.len() * Q * Q];
    let mut pairs = 0u64;
    for u0 in 0..us.len() {
        counts.fill(0);
        for u1 in 0..us.len() {
            if u1 == u0 {
                continue;
            }
            for t1 in 0..ts.len() {
                for t2 in 0..ts.len() {
                    if t2 == t1 {
                        continue;
                    }
                    let v = (uv[t1][u1] + 2 * Q - uv[t1][u0] - uv[t2][u1]) % Q;
                    let w = (uw[t1][u1] + 2 * Q - uw[t1][u0] - uw[t2][u1]) % Q;
                    for u2 in 0..us.len() {
                        if u2 == u1 {
                            continue;
                        }
                        let vv = (v + uv[t2][u2]) % Q;
                        let ww = (w + uw[t2][u2]) % Q;
                        let index = (u2 * Q + vv) * Q + ww;
                        pairs += u64::from(counts[index]);
                        counts[index] += 1;
                    }
                }
            }
        }
    }
    let rooted = pairs * (Q * Q) as u64;
    assert_eq!(rooted % 4, 0);
    rooted / 4
}

#[test]
fn eight_cycle_counts_agree() {
    let q3: Vec<_> = (0..3).collect();
    assert_eq!(cycles::<3>(&q3, &q3), 81);
    assert_eq!(cycles_algebraic::<3>(&q3, &q3), 81);
    let q5: Vec<_> = (0..5).collect();
    assert_eq!(cycles::<5>(&q5, &q5), 12500);
    assert_eq!(cycles_algebraic::<5>(&q5, &q5), 12500);
    let symbols: Vec<_> = (0..43).collect();
    let expected = 1_263_308_051_793;
    assert_eq!(cycles::<47>(&symbols, &symbols), expected);
    assert_eq!(cycles_algebraic::<47>(&symbols, &symbols), expected);
}
