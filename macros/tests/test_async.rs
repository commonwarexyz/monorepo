#[cfg(test)]
mod tests {
    use commonware_macros::test_async;

    #[test_async]
    async fn test_async_fn() {
        assert_eq!(2 + 2, 4);
    }

    #[test_async]
    #[should_panic(expected = "This test will panic")]
    async fn test_async_panic() {
        panic!("This test will panic");
    }
}
