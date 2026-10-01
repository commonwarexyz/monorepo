//! A host crate whose `src/a.rs` a test of `sandblaster/front/tests` lifts in place.
#![allow(dead_code, unused_imports)]
pub trait Fam {}
pub trait Word: Copy {}
impl Word for u64 {}
pub trait HashFn {
    type Out;
    fn f(x: u64) -> Self::Out;
}
impl Fam for fx_hosts::Mark {}
impl HashFn for fx_hosts::Hw {
    type Out = u64;
    fn f(x: u64) -> u64 {
        x ^ 7
    }
}
/// The instances `a.rs` is verified at (the test's `host.rs` models them).
pub mod host {
    pub type Mark = fx_hosts::Mark;
    pub type W = u64;
    pub type Hw = fx_hosts::Hw;
}
mod a;
