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

#[derive(Copy, Clone)]
struct Branch {
    seed: u32,
    thread: u32,
    size: u32,
}

impl Branch {
    fn grow(self) -> Self {
        Self {
            seed: self.seed,
            thread: self.thread.wrapping_add(1),
            size: self.size.saturating_add(1),
        }
    }

    fn sample(self, buf: &mut Vec<u8>) {
        let combined_seed = ((self.seed as u64) << 32) | (self.thread as u64);
        let mut rng = ChaCha8Rng::seed_from_u64(combined_seed);
        buf.clear();
        let mut chunk = [0u8; 64];
        while buf.len() < self.size as usize {
            rng.fill_bytes(&mut chunk);
            buf.extend_from_slice(&chunk);
        }
        buf.truncate(self.size as usize);
    }
}

impl std::fmt::Display for Branch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:08x}{:08x}{:08x}", self.seed, self.thread, self.size)
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
        let mut branch = Branch {
            seed: 0,
            thread: 0,
            size: 0,
        };
        let mut buf = Vec::new();
        for _ in 0..self.search_limit {
            branch.sample(&mut buf);
            if let Err(e) = try_catch(|| s(&mut Unstructured::new(&buf))) {
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
    use arbitrary::Unstructured;

    enum Plan {
        Leaf(u8),
        Branch(bool, Box<Plan>),
    }

    impl Plan {
        fn generate(u: &mut Unstructured<'_>, depth: usize) -> arbitrary::Result<Self> {
            if depth == 0 {
                Ok(Plan::Leaf(u.arbitrary()?))
            } else {
                let b: bool = u.arbitrary()?;
                let child = Plan::generate(u, depth - 1)?;
                Ok(Plan::Branch(b, Box::new(child)))
            }
        }

        fn follow_path(&self, path: &mut impl Iterator<Item = bool>) -> Option<u8> {
            match self {
                Plan::Leaf(v) => Some(*v),
                Plan::Branch(b, child) => {
                    if *b == path.next()? {
                        child.follow_path(path)
                    } else {
                        None
                    }
                }
            }
        }
    }

    fn search_haystack(depth: usize) {
        super::test(|u| {
            let plan = Plan::generate(u, depth)?;
            let mut path = [true, false].into_iter().cycle();
            if let Some(leaf) = plan.follow_path(&mut path) {
                assert_ne!(leaf, 77);
            }
            Ok(())
        });
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_0() {
        search_haystack(0);
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_1() {
        search_haystack(1);
    }

    #[test]
    #[should_panic]
    fn search_haystack_depth_2() {
        search_haystack(2);
    }
}
