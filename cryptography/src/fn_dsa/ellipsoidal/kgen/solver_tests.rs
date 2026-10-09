use super::*;
use fn_dsa_comm::shake::SHAKE256;

#[path = "solver_fixture.rs"]
mod fixture;

#[test]
fn complete_solver_matches_independent_integer_oracle() {
    let big = solve(&fixture::F, &fixture::G).unwrap();
    let big_f = big.f.small_values().unwrap();
    let big_g = big.g.small_values().unwrap();
    for i in 0..512 {
        assert_eq!(big_f[i], i64::from(fixture::BIG_F[i]));
        assert_eq!(big_g[i], i64::from(fixture::BIG_G[i]));
    }
    let small = Pair::small(9, &fixture::F, &fixture::G);
    let (u, k) = Projection::new(&small, true)
        .unwrap()
        .quotient(&big, 0)
        .unwrap();
    assert!(k.iter().all(|&x| x == 0));
    assert!(certify(&small, &big, &u, &k).is_some());
    let (u, k) = Projection::new(&small, false)
        .unwrap()
        .quotient(&big, 0)
        .unwrap();
    assert!(k.iter().any(|&x| x != 0));
    assert!(certify(&small, &big, &u, &k).is_none());
}

struct SeededRng(SHAKE256);

impl SeededRng {
    fn new(seed: &[u8]) -> Self {
        let mut state = SHAKE256::new();
        state.inject(seed);
        state.flip();
        Self(state)
    }
}

impl RngCore for SeededRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }
    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.extract(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), fn_dsa_comm::RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[test]
fn complete_solver_returns_exact_weighted_solutions() {
    let mut rng = SeededRng::new(b"bounded ellipsoidal NTRU solver test");
    let mut successes = 0;
    for trial in 0..16 {
        let f = sample_f(&mut rng);
        let g = sample_g(&mut rng);
        if g.iter().map(|&x| i32::from(x).pow(2)).sum::<i32>() > 303032 {
            continue;
        }
        let Some(big) = solve(&f, &g) else {
            std::eprintln!("trial {trial}: rejected");
            continue;
        };
        let bf = big.f.small_values().unwrap();
        let bg = big.g.small_values().unwrap();
        assert!(exact_equation(&f, &g, &bf, &bg));
        assert!(
            bf.iter()
                .chain(bg.iter())
                .all(|&x| (-2047..=2047).contains(&x))
        );
        let small = Pair::small(9, &f, &g);
        let (u, k) = Projection::new(&small, true)
            .unwrap()
            .quotient(&big, 0)
            .unwrap();
        assert!(certify(&small, &big, &u, &k).is_some());
        assert!(k.iter().all(|&x| x == 0));
        std::eprintln!(
            "trial {trial}: Fmax={} Gmax={} G>127={}",
            bf.iter().map(|x| x.abs()).max().unwrap(),
            bg.iter().map(|x| x.abs()).max().unwrap(),
            bg.iter().filter(|x| x.abs() > 127).count()
        );
        successes += 1;
        if successes == 3 {
            break;
        }
    }
    assert_eq!(successes, 3);
}

#[test]
fn invalid_input_is_rejected_before_recursion() {
    let mut f = [0; 512];
    f[..233].fill(1);
    let mut g = [0; 512];
    g[0] = 1;
    f[0] = 2;
    assert!(solve(&f, &g).is_none());
    f[0] = 0;
    assert!(solve(&f, &g).is_none());
    f[0] = 1;
    g[0] = 2;
    assert!(solve(&f, &g).is_none());
    g[0] = i8::MIN;
    assert!(solve(&f, &g).is_none());
    g.fill(127);
    assert!(solve(&f, &g).is_none());
}

#[test]
fn exact_determinant_rejects_a_modular_only_solution() {
    let mut f = [0; 512];
    let g = [0; 512];
    let big_f = [0; 512];
    let mut big_g = [0; 512];
    f[0] = 1;
    big_g[0] = 12289;
    assert!(exact_equation(&f, &g, &big_f, &big_g));
    big_g[511] = 12289;
    assert!(!exact_equation(&f, &g, &big_f, &big_g));
}
