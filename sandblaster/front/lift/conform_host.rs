// The host traits the lift knows (`lift::HOST_TRAITS`), with the
// signatures the lift assumes (commonware-codec's): the root of the lift
// conformance harness (`sandblaster_front::conform`). The harness root also
// mounts every `#[lift(host)]` model module and re-exports its items, and
// declares the lifted module (its source as-is, plus the harness child
// module). `SIZE` is `size_of` here, as the lift reads it; the emitted
// module's tail checks the host's own `SIZE` values with rustc.

pub trait Buf: bytes::Buf {}
impl<T: bytes::Buf> Buf for T {}

pub trait FixedSize {
    const SIZE: usize;
}

macro_rules! __fixed_size {
    ($($t:ty),*) => { $(impl FixedSize for $t { const SIZE: usize = ::core::mem::size_of::<$t>(); })* };
}
__fixed_size!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, bool);

pub trait EncodeSize {
    fn encode_size(&self) -> usize;
}

pub trait Write {
    fn write(&self, buf: &mut impl bytes::BufMut);
}
