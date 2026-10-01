
// the open trait lives in a host module the lift does not read (as
// `crate::merkle::Family` does for the storage crate)
use super::Fam;
use core::marker::PhantomData;

pub struct Small;
pub struct Big;

impl Fam for Small {
    const MAX: u64 = 100;
    fn cap(x: u64) -> u64 {
        if x > Self::MAX { Self::MAX } else { x }
    }
}

impl Fam for Big {
    const MAX: u64 = 7;
    fn cap(x: u64) -> u64 {
        x % 9
    }
}

pub struct P<F: Fam>(u64, PhantomData<F>);

impl<F: Fam> P<F> {
    pub fn new(x: u64) -> Self {
        Self(F::cap(x), PhantomData)
    }
    pub fn get(&self) -> u64 {
        self.0
    }
    pub fn room(x: u64) -> u64 {
        F::MAX - F::cap(x)
    }
}
