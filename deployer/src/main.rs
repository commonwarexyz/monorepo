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
                    Command::new(ec2::REFRESH_CMD)
                        .about("Add the deployer's current IP to all security groups (if not already present).")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .required(true)
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
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
            Some((ec2::REFRESH_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                if let Err(e) = ec2::refresh(config_path).await {
                    error!(error=?e, "failed to refresh EC2 deployment");
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
