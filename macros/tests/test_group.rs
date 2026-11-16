#[cfg(test)]
mod tests {
    use commonware_macros::test_group;

    #[test_group("slow")]
    mod grouped {
        pub(super) const VALUE: u32 = 7;
    }

    #[test]
    fn test_inline_module_is_renamed() {
        assert_eq!(grouped_slow_::VALUE, grouped::VALUE);
    }
}
