//! Debug test for derive macros in tests directory

use commonware_codec::{EncodeSize, Read, ReadExt, Write};

#[derive(Debug, Clone, PartialEq, Read, Write, EncodeSize)]
enum SimpleEnum {
    Unit,
    Tuple(u32),
    Struct { field: u16 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug() {
        let _value = SimpleEnum::Unit;
    }
}
