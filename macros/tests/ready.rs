use commonware_macros::ready;

// All items at level 4 so they're always available
#[ready(4)]
const fn level_4_fn() -> u8 {
    4
}

#[ready(4)]
struct Level4Struct {
    value: u32,
}

#[ready(4)]
impl Level4Struct {
    const fn new() -> Self {
        Self { value: 42 }
    }
}

#[ready(4)]
mod level_4_module {
    pub const fn inner() -> u32 {
        100
    }
}

#[test]
fn test_level_4_items_compile() {
    assert_eq!(level_4_fn(), 4);
    let s = Level4Struct::new();
    assert_eq!(s.value, 42);
    assert_eq!(level_4_module::inner(), 100);
}

// Test that lower-level items are excluded at higher readiness levels
// These items and their tests are gated together using ready(2)
#[ready(2)]
mod level_2_tests {
    use commonware_macros::ready;

    #[ready(2)]
    const fn level_2_fn() -> u8 {
        2
    }

    #[ready(2)]
    struct Level2Struct {
        value: u32,
    }

    #[ready(2)]
    impl Level2Struct {
        const fn new() -> Self {
            Self { value: 22 }
        }
    }

    #[test]
    fn test_level_2_items_compile() {
        assert_eq!(level_2_fn(), 2);
        let s = Level2Struct::new();
        assert_eq!(s.value, 22);
    }
}
