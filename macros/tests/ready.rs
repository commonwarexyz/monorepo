use commonware_macros::ready;

#[ready(0)]
const fn level_0() -> u8 {
    0
}

#[ready(1)]
const fn level_1() -> u8 {
    1
}

#[ready(2)]
const fn level_2() -> u8 {
    2
}

#[ready(3)]
const fn level_3() -> u8 {
    3
}

#[ready(4)]
const fn level_4() -> u8 {
    4
}

#[ready(2)]
struct StableStruct {
    value: u32,
}

#[ready(2)]
impl StableStruct {
    const fn new() -> Self {
        Self { value: 42 }
    }
}

#[ready(0)]
mod experimental_module {
    pub const fn inner() -> u32 {
        100
    }
}

#[test]
fn test_all_levels_compile() {
    #[cfg(not(min_readiness_1))]
    assert_eq!(level_0(), 0);

    #[cfg(not(min_readiness_2))]
    assert_eq!(level_1(), 1);

    #[cfg(not(min_readiness_3))]
    assert_eq!(level_2(), 2);

    #[cfg(not(min_readiness_4))]
    assert_eq!(level_3(), 3);

    assert_eq!(level_4(), 4);
}

#[test]
fn test_struct_and_impl() {
    #[cfg(not(min_readiness_3))]
    {
        let s = StableStruct::new();
        assert_eq!(s.value, 42);
    }
}

#[test]
fn test_module() {
    #[cfg(not(min_readiness_1))]
    assert_eq!(experimental_module::inner(), 100);
}
