use clap::{value_parser, Arg, Command};

/// Returns the version of the crate.
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn main() {
    // Parse arguments
    let matches = Command::new("commonware-simulator")
        .about("TBA")
        .version(crate_version())
        .arg(
            Arg::new("peers")
                .long("peers")
                .required(true)
                .value_parser(value_parser!(u64))
                .help("Number of peers to simulate"),
        )
        .arg(
            Arg::new("regions")
                .long("regions")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(String))
                .help("Regions to simulate"),
        )
        .arg(
            Arg::new("message-processing-time")
                .long("message-processing-time")
                .required(true)
                .value_parser(value_parser!(u64))
                .help("Message processing time in milliseconds"),
        )
        .get_matches();
}
