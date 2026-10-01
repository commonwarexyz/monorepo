use crate::{Fam, HashFn, Word};

use core::marker::PhantomData;

pub struct Tag<F: Fam>(pub u64, PhantomData<F>);

impl<F: Fam> Tag<F> {
    pub const fn new(x: u64) -> Self {
        Self(x, PhantomData)
    }
}

pub fn keep<D: Word, F: Fam>(d: D, t: Tag<F>) -> Result<D, u8> {
    if t.0 == 0 {
        Err(1u8)
    } else {
        Ok(d)
    }
}

pub fn digest<H: HashFn>(x: u64) -> H::Out {
    H::f(x)
}
