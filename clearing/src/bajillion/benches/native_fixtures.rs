use std::env;

/// Explicit comma-separated dimensions avoid coupling cumulative history to epoch size.
pub(crate) fn dimension(name: &str, default: &[usize]) -> Vec<usize> {
    let mut values = env::var(name).map_or_else(
        |_| default.to_vec(),
        |value| {
            value
                .split(',')
                .map(|part| {
                    part.trim()
                        .parse()
                        .unwrap_or_else(|_| panic!("invalid {name}"))
                })
                .collect()
        },
    );
    values.sort_unstable();
    values.dedup();
    assert!(!values.is_empty(), "{name} must not be empty");
    values
}

pub(crate) fn histories() -> Vec<usize> {
    dimension("COMMONWARE_CLEARING_HISTORY", &[0, 1024, 65_536])
}

pub(crate) fn rows() -> Vec<usize> {
    dimension("COMMONWARE_CLEARING_ROWS", &[0, 1, 2, 128, 1024])
}

pub(crate) fn accounts() -> usize {
    let values = dimension("COMMONWARE_CLEARING_ACCOUNTS", &[1024]);
    assert_eq!(values.len(), 1, "select one live account count per process");
    assert!(values[0] > 0);
    values[0]
}

pub(crate) fn payouts(accounts: usize) -> Vec<usize> {
    let values = dimension(
        "COMMONWARE_CLEARING_PAYOUTS",
        &[0, 1, accounts / 2, accounts],
    );
    assert!(values.iter().all(|count| *count <= accounts));
    values
}
