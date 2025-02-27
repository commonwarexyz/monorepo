//! TODO

use clap::{Arg, ArgAction, Command};
use commonware_utils::crate_version;
use std::{error::Error, path::PathBuf};
use tracing::error;

mod ec2;

/// Flag for verbose output
const VERBOSE_FLAG: &str = "verbose";

/// Entrypoint for the Commonware Deployer CLI
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Define application
    let matches = Command::new("deployer")
        .version(crate_version())
        .about("TBD")
        .arg(
            Arg::new(VERBOSE_FLAG)
                .short('v')
                .long(VERBOSE_FLAG)
                .action(ArgAction::SetTrue),
        )
        .subcommand(
            Command::new(ec2::CMD)
                .about("TBD")
                .subcommand(
                    Command::new(ec2::CREATE_CMD)
                        .about(
                            "Sets up EC2 instances and deploys files with monitoring and logging",
                        )
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
                        .about("Deletes all deployed resources")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .required(true)
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
                        ),
                ),
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
                    return Ok(());
                }
            }
            Some((ec2::DESTROY_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                if let Err(e) = ec2::destroy(config_path).await {
                    error!(error=?e, "failed to destroy EC2 deployment");
                } else {
                    return Ok(());
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
    std::process::exit(1);
}
