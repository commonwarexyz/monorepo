use commonware_macros::{ready, ready_scope};

// All items at level 4 so they're always available
#[ready(EPSILON)]
const fn level_4_fn() -> u8 {
    4
}

#[ready(EPSILON)]
struct Level4Struct {
    value: u32,
}

#[ready(EPSILON)]
impl Level4Struct {
    const fn new() -> Self {
        Self { value: 42 }
    }
}

#[ready(EPSILON)]
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
#[ready(GAMMA)]
mod level_2_tests {
    use commonware_macros::ready;

    #[ready(GAMMA)]
    const fn level_2_fn() -> u8 {
        2
    }

    #[ready(GAMMA)]
    struct Level2Struct {
        value: u32,
    }

    #[ready(GAMMA)]
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

// Test ready_scope! macro at level 4 (always available)
ready_scope!(EPSILON {
    const fn scope_level_4_fn() -> u8 {
        44
    }

    struct ScopeLevel4Struct {
        value: u32,
    }

    impl ScopeLevel4Struct {
        const fn new() -> Self {
            Self { value: 444 }
        }
    }
});

#[test]
fn test_ready_scope_level_4() {
    assert_eq!(scope_level_4_fn(), 44);
    let s = ScopeLevel4Struct::new();
    assert_eq!(s.value, 444);
}

// Test ready_scope! at level 2 (excluded at levels 3, 4)
#[ready(GAMMA)]
mod ready_scope_level_2_tests {
    use commonware_macros::ready_scope;

    ready_scope!(GAMMA {
        pub const fn scope_level_2_fn() -> u8 {
            22
        }

        pub struct ScopeLevel2Struct {
            pub value: u32,
        }

        impl ScopeLevel2Struct {
            pub const fn new() -> Self {
                Self { value: 222 }
            }
        }
    });

    #[test]
    fn test_ready_scope_level_2() {
        assert_eq!(scope_level_2_fn(), 22);
        let s = ScopeLevel2Struct::new();
        assert_eq!(s.value, 222);
    }
}
