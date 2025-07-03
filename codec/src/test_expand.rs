//! Simple test to examine macro expansion

use crate::{Write, EncodeSize};

#[derive(Write, EncodeSize)]
struct TestStruct {
    #[codec(varint)]
    a: u32,
    b: bool,
}