//! Executable Kani model for the proposed UNO protocol.
//!
//! This crate is intentionally isolated from the production workspace. It models disk bytes and
//! protocol transitions; it is not linked into `commonware-runtime` and makes no claim that the
//! checked-in R13 codec implements the proposed format.

#![forbid(unsafe_code)]
#![cfg_attr(not(any(test, kani)), allow(dead_code))]

mod codec;
mod composed;
mod protocol;
