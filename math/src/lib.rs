//! Mathematical utilities and operations.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod algebra;
pub mod fields {
    pub mod goldilocks;
}
pub mod ntt;
pub mod poly;
#[cfg(test)]
pub mod test;
