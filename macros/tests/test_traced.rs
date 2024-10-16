#[cfg(test)]
mod tests {
    use commonware_macros::test_traced;
    use tracing::{debug, error, info};

    #[test_traced(level = "INFO")]
    fn test_info_level() {
        info!("This is an info log");
        debug!("This is a debug log (won't be shown)");
        assert_eq!(2 + 2, 4);
    }

    #[test_traced]
    fn test_default_level() {
        debug!("This is a debug log");
        assert_eq!(3 * 3, 9);
    }

    #[test_traced(level = "ERROR")]
    fn test_error_level() {
        error!("This is an error log");
        assert_eq!(5 * 2, 10);
    }

    #[test_traced(timeout = 1)]
    #[should_panic(expected = "timed out")]
    fn test_timeout() {
        info!("This test will take 5 seconds");
        std::thread::sleep(std::time::Duration::from_secs(5));
        assert_eq!(7 + 7, 21);
    }

    #[test_traced(timeout = 1)]
    fn test_useless_timeout() {
        assert_eq!(11 + 11, 22);
    }
}
