//! Commonware Deployer CLI

use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;
use tracing::error;

mod ec2;

/// Returns the version of the crate.
pub fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Flag for verbose output
const VERBOSE_FLAG: &str = "verbose";

/// Entrypoint for the Commonware Deployer CLI
#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Define application
    let matches = Command::new("deployer")
        .version(crate_version())
        .about("Deploy infrastructure across cloud providers.")
        .arg(
            Arg::new(VERBOSE_FLAG)
                .short('v')
                .long(VERBOSE_FLAG)
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new(ec2::CMD)
                .about("Deploy a custom binary (and configuration) to any number of EC2 instances across multiple regions. Collect metrics and logs from all instances via a private network.")
                .subcommand(
                    Command::new(ec2::CREATE_CMD)
                        .about("Deploy EC2 instances across multiple regions from a YAML configuration file.")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .required(true)
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
                        ),
                )
                .subcommand(
                    Command::new(ec2::UPDATE_CMD)
                        .about("Update binaries (and configurations) in-place on all instances.")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .required(true)
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
                        ),
                )
                .subcommand(
                    Command::new(ec2::AUTHORIZE_CMD)
                        .about("Add the deployer's public IP (or the one provided) to all security groups.")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .required(true)
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
                        )
                        .arg(
                            Arg::new("ip")
                                .long("ip")
                                .help("IPv4 address to add to security groups instead of the current IP. If not provided, the current public IPv4 address will be used.")
                                .value_parser(clap::value_parser!(String)),
                        ),
                )
                .subcommand(
                    Command::new(ec2::DESTROY_CMD)
                        .about("Destroy all resources associated with a given deployment.")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .required(true)
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
                        ),
                )
        )
        .get_matches();

    // Create logger
    let level = if matches.get_flag(VERBOSE_FLAG) {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    // Parse subcommands
    if let Some(ec2_matches) = matches.subcommand_matches(ec2::CMD) {
        match ec2_matches.subcommand() {
            Some((ec2::CREATE_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                if let Err(e) = ec2::create(config_path).await {
                    error!(error=?e, "failed to create EC2 deployment");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((ec2::UPDATE_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                if let Err(e) = ec2::update(config_path).await {
                    error!(error=?e, "failed to update EC2 deployment");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((ec2::AUTHORIZE_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                let ip = matches.get_one::<String>("ip").cloned();
                if let Err(e) = ec2::authorize(config_path, ip).await {
                    error!(error=?e, "failed to authorize EC2 deployment");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((ec2::DESTROY_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                if let Err(e) = ec2::destroy(config_path).await {
                    error!(error=?e, "failed to destroy EC2 deployment");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((cmd, _)) => {
                error!(cmd, "invalid subcommand");
            }
            None => {
                error!("no subcommand provided");
            }
        }
    } else if let Some(cmd) = matches.subcommand_name() {
        error!(cmd, "invalid subcommand");
    } else {
        error!("no subcommand provided");
    }
    std::process::ExitCode::FAILURE
}
