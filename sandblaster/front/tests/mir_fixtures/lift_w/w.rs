mod sealed {
    pub trait Prim: Copy + PartialOrd {
        fn low(self) -> u8;
    }
    impl Prim for u16 {
        fn low(self) -> u8 { self as u8 }
    }
    impl Prim for u32 {
        fn low(self) -> u8 { self as u8 }
    }
}
pub use sealed::Prim;

#[derive(Debug, Clone)]
pub struct Wrap<T: Prim>(pub T);

impl<T: Prim> Wrap<T> {
    pub fn bits(&self) -> usize {
        size_of::<T>() * 8
    }
    pub fn low(&self) -> u8 {
        self.0.low()
    }
}

#[derive(Debug, Clone)]
pub struct Counter {
    n: u32,
}

impl Counter {
    pub fn new() -> Self {
        Self { n: 0 }
    }
    pub fn bump(&mut self) -> u32 {
        self.n = self.n.wrapping_add(1);
        self.n
    }
    pub fn chunks(&self, bits: usize) -> usize {
        bits.div_ceil(7)
    }
}
