//! Exact concentration checks in cyclic and noncyclic groups of exponent three.

fn add(mut first: usize, mut second: usize, rank: u32) -> usize {
    let mut result = 0;
    let mut place = 1;
    for _ in 0..rank {
        result += ((first % 3 + second % 3) % 3) * place;
        first /= 3;
        second /= 3;
        place *= 3;
    }
    result
}

fn check_moment(rank: u32, moment: usize, bound: u64) -> usize {
    let order = 3usize.pow(rank);
    let addition: Vec<Vec<_>> = (0..order)
        .map(|first| (0..order).map(|second| add(first, second, rank)).collect())
        .collect();
    let mut values = vec![1; moment];
    let mut tested = 0;
    let mut worst = 0;
    loop {
        // Counts enumerate all four choices: either sign in either bucket.
        let mut distribution = vec![0u64; order * order];
        distribution[0] = 1;
        for &value in &values {
            let mut next = vec![0u64; order * order];
            // In a group of exponent three, the negative of T is 2*T.
            let negative = addition[value][value];
            for (index, &count) in distribution.iter().enumerate() {
                let (first, second) = (index / order, index % order);
                for signed in [value, negative] {
                    next[addition[first][signed] * order + second] += count;
                    next[first * order + addition[second][signed]] += count;
                }
            }
            distribution = next;
        }
        assert_eq!(distribution.iter().sum::<u64>(), 4u64.pow(moment as u32));
        let largest = *distribution.iter().max().unwrap();
        assert!(largest <= bound, "rank={rank} inputs={values:?}");
        worst = worst.max(largest);
        tested += 1;

        // Input permutations have the same distribution, so enumerate every
        // nonzero multiset, including mixed values and repeated inputs.
        let Some(index) = values.iter().rposition(|&value| value < order - 1) else {
            break;
        };
        let next = values[index] + 1;
        values[index..].fill(next);
    }
    assert_eq!(worst, bound);
    tested
}

#[test]
fn fourth_moment_order_three() {
    // At B=2, the fourth-moment bound is 36/4^4.
    assert_eq!(check_moment(1, 4, 36), 5);
}

#[test]
fn sixth_moment_order_three() {
    // At B=2, the sixth-moment bound is 484/4^6, including order-three returns.
    assert_eq!(check_moment(1, 6, 484), 7);
}

#[test]
fn fourth_moment_noncyclic_order_nine() {
    assert_eq!(check_moment(2, 4, 36), 330);
}

#[test]
fn sixth_moment_noncyclic_order_nine() {
    assert_eq!(check_moment(2, 6, 484), 1716);
}
