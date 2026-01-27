use std::panic::{catch_unwind, RefUnwindSafe, UnwindSafe};

use arbitrary::Unstructured;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore as _, SeedableRng};

enum Error {
    NoDisplay,
    String(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::NoDisplay => write!(f, "<not displayable>"),
            Error::String(s) => write!(f, "{}", s),
        }
    }
}

fn try_catch<T>(f: impl FnOnce() -> T + UnwindSafe) -> Result<T, Error> {
    // Save the current panic hook and install a silent one
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let result = catch_unwind(f).map_err(|e| {
        if let Some(s) = e.downcast_ref::<String>() {
            Error::String(s.to_string())
        } else if let Some(s) = e.downcast_ref::<&'static str>() {
            Error::String(s.to_string())
        } else {
            Error::NoDisplay
        }
    });

    // Restore the previous hook
    std::panic::set_hook(prev_hook);
    result
}

type Property = dyn Fn(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error>;

struct Randomness {
    seed: u64,
    cache: Vec<u8>,
    rng: ChaCha8Rng,
}

impl Randomness {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            cache: Vec::with_capacity(1 << 16),
            rng: ChaCha8Rng::seed_from_u64(seed),
        }
    }

    fn sample(&mut self, seed: u64, len: usize) -> &[u8] {
        if seed != self.seed {
            self.seed = seed;
            self.rng = ChaCha8Rng::seed_from_u64(seed);
            self.cache.clear();
        }
        {
            let mut buffer = [0u8; 64];
            while self.cache.len() < len {
                self.rng.fill_bytes(&mut buffer);
                self.cache.extend_from_slice(&buffer);
            }
        }
        &self.cache[..len]
    }
}

#[derive(Copy, Clone)]
struct Branch {
    seed: u32,
    size: u32,
}

impl Branch {
    fn grow(self) -> Self {
        Self {
            seed: self.seed,
            size: self.size.saturating_add(1)
        }
    }

    fn sample(self, rand: &mut Randomness) -> &[u8] {
        rand.sample(self.seed.into(), self.size as usize)
    }
}

impl std::fmt::Display for Branch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}{:08x}", self.seed, self.size)
    }
}

struct Builder {
    search_limit: u64,
}

impl Builder {
    fn new() -> Self {
        Self { search_limit: 100 }
    }

    fn test(
        self,
        s: impl Fn(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error> + RefUnwindSafe,
    ) {
        let mut branch = Branch { seed: 0, size: 0 };
        let mut rand = Randomness::new(0);
        for _ in 0..self.search_limit {
            let data = branch.sample(&mut rand);
            if let Err(e) = try_catch(|| s(&mut Unstructured::new(data))) {
                panic!("failure (MINIFUZZ_BRANCH = {}):\n{}", branch, e)
            }
            branch = branch.grow();
        }
        eprintln!("failed to find, final: {}", branch);
    }
}

pub fn test(
    s: impl Fn(&mut arbitrary::Unstructured<'_>) -> Result<(), arbitrary::Error> + RefUnwindSafe,
) {
    Builder::new().test(s)
}

#[cfg(test)]
mod test {
    use arbitrary::Arbitrary;

    #[derive(Arbitrary)]
    struct Plan {
        x: u8,
    }

    #[test]
    fn test_foo() {
        super::test(|u| {
            let plan = Plan::arbitrary(u)?;
            eprintln!("X {}", plan.x);
            assert_ne!(plan.x, 1);
            Ok(())
        });
    }
}
