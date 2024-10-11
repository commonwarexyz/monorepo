#[cfg(test)]
mod tests {
    use commonware_macros::test_with_logging;
    use tracing::{debug, error, info};

    #[test_with_logging("INFO")]
    fn test_info_level() {
        info!("This is an info log");
        debug!("This is a debug log (won't be shown)");
        assert_eq!(2 + 2, 4);
    }

    #[test_with_logging]
    fn test_default_level() {
        debug!("This is a debug log");
        assert_eq!(3 * 3, 9);
    }

    #[test_with_logging("ERROR")]
    fn test_error_level() {
        error!("This is an error log");
        assert_eq!(5 * 2, 10);
    }
}
