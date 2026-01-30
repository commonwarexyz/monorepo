use commonware_macros::{stability, stability_scope};

// All items at level 4 so they're always available
#[stability(EPSILON)]
const fn level_4_fn() -> u8 {
    4
}

#[stability(EPSILON)]
struct Level4Struct {
    value: u32,
}

#[stability(EPSILON)]
impl Level4Struct {
    const fn new() -> Self {
        Self { value: 42 }
    }
}

#[stability(EPSILON)]
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

// Test that lower-level items are excluded at higher stability levels
// These items and their tests are gated together using stability(2)
#[stability(BETA)]
mod level_2_tests {
    use commonware_macros::stability;

    #[stability(BETA)]
    const fn level_2_fn() -> u8 {
        2
    }

    #[stability(BETA)]
    struct Level2Struct {
        value: u32,
    }

    #[stability(BETA)]
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

// Test stability_scope! macro at level 4 (always available)
stability_scope!(EPSILON {
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
fn test_stability_scope_level_4() {
    assert_eq!(scope_level_4_fn(), 44);
    let s = ScopeLevel4Struct::new();
    assert_eq!(s.value, 444);
}

// Test stability_scope! at level 2 (excluded at levels 3, 4)
#[stability(BETA)]
mod stability_scope_level_2_tests {
    use commonware_macros::stability_scope;

    stability_scope!(BETA {
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
    fn test_stability_scope_level_2() {
        assert_eq!(scope_level_2_fn(), 22);
        let s = ScopeLevel2Struct::new();
        assert_eq!(s.value, 222);
    }
}

// Test stability_scope! with cfg predicate
stability_scope!(EPSILON, cfg(test) {
    const fn cfg_scope_fn() -> u8 {
        55
    }

    struct CfgScopeStruct {
        value: u32,
    }

    impl CfgScopeStruct {
        const fn new() -> Self {
            Self { value: 555 }
        }
    }
});

#[test]
fn test_stability_scope_with_cfg() {
    assert_eq!(cfg_scope_fn(), 55);
    let s = CfgScopeStruct::new();
    assert_eq!(s.value, 555);
}

// Test stability_scope! with cfg at GAMMA level
#[stability(BETA)]
mod stability_scope_with_cfg_level_2_tests {
    use commonware_macros::stability_scope;

    stability_scope!(BETA, cfg(test) {
        pub const fn cfg_scope_level_2_fn() -> u8 {
            33
        }
    });

    #[test]
    fn test_stability_scope_with_cfg_level_2() {
        assert_eq!(cfg_scope_level_2_fn(), 33);
    }
}
