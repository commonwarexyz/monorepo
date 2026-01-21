//! Commonware Deployer CLI

use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;
use tracing::error;

mod aws;

/// Returns the version of the crate.
pub const fn crate_version() -> &'static str {
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
            Command::new(aws::CMD)
                .about("Deploy a custom binary (and configuration) to any number of EC2 instances across multiple regions. Collect metrics and logs from all instances via a private network.")
                .subcommand(
                    Command::new(aws::CREATE_CMD)
                        .about("Deploy EC2 instances across multiple regions from a YAML configuration file.")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .required(true)
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
                        )
                        .arg(
                            Arg::new("concurrency")
                                .long("concurrency")
                                .default_value(aws::DEFAULT_CONCURRENCY)
                                .help("Maximum instances to configure at once (must be >= 1)")
                                .value_parser(clap::builder::RangedU64ValueParser::<usize>::new().range(1..)),
                        ),
                )
                .subcommand(
                    Command::new(aws::UPDATE_CMD)
                        .about("Update binaries (and configurations) in-place on all instances.")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .required(true)
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
                        )
                        .arg(
                            Arg::new("concurrency")
                                .long("concurrency")
                                .default_value(aws::DEFAULT_CONCURRENCY)
                                .help("Maximum instances to update at once (must be >= 1)")
                                .value_parser(clap::builder::RangedU64ValueParser::<usize>::new().range(1..)),
                        ),
                )
                .subcommand(
                    Command::new(aws::AUTHORIZE_CMD)
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
                    Command::new(aws::DESTROY_CMD)
                        .about("Destroy all resources associated with a given deployment.")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
                        )
                        .arg(
                            Arg::new("tag")
                                .long("tag")
                                .help("Deployment tag (uses persisted metadata)")
                                .value_parser(clap::value_parser!(String)),
                        )
                        .group(
                            clap::ArgGroup::new("target")
                                .args(["config", "tag"])
                                .required(true),
                        ),
                )
                .subcommand(
                    Command::new(aws::LIST_CMD)
                        .about("List all active deployments (created but not destroyed)."),
                )
                .subcommand(
                    Command::new(aws::CLEAN_CMD)
                        .about("Delete the shared S3 bucket and all its contents."),
                )
                .subcommand(
                    Command::new(aws::PROFILE_CMD)
                        .about("Capture a CPU profile from a running instance using samply.")
                        .arg(
                            Arg::new("config")
                                .long("config")
                                .required(true)
                                .help("Path to YAML config file")
                                .value_parser(clap::value_parser!(PathBuf)),
                        )
                        .arg(
                            Arg::new("instance")
                                .long("instance")
                                .required(true)
                                .help("Name of instance to profile")
                                .value_parser(clap::value_parser!(String)),
                        )
                        .arg(
                            Arg::new("duration")
                                .long("duration")
                                .default_value("30")
                                .help("Profile duration in seconds")
                                .value_parser(clap::value_parser!(u64)),
                        )
                        .arg(
                            Arg::new("binary")
                                .long("binary")
                                .required(true)
                                .help("Path to local binary with debug symbols for symbolication")
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
    if let Some(ec2_matches) = matches.subcommand_matches(aws::CMD) {
        match ec2_matches.subcommand() {
            Some((aws::CREATE_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                let concurrency = *matches.get_one::<usize>("concurrency").unwrap();
                if let Err(e) = aws::create(config_path, concurrency).await {
                    error!(error=?e, "failed to create EC2 deployment");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((aws::UPDATE_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                let concurrency = *matches.get_one::<usize>("concurrency").unwrap();
                if let Err(e) = aws::update(config_path, concurrency).await {
                    error!(error=?e, "failed to update EC2 deployment");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((aws::AUTHORIZE_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                let ip = matches.get_one::<String>("ip").cloned();
                if let Err(e) = aws::authorize(config_path, ip).await {
                    error!(error=?e, "failed to authorize EC2 deployment");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((aws::DESTROY_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config");
                let tag = matches.get_one::<String>("tag").map(|s| s.as_str());
                if let Err(e) = aws::destroy(config_path, tag).await {
                    error!(error=?e, "failed to destroy EC2 deployment");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((aws::LIST_CMD, _)) => {
                if let Err(e) = aws::list() {
                    error!(error=?e, "failed to list deployments");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((aws::CLEAN_CMD, _)) => {
                if let Err(e) = aws::clean().await {
                    error!(error=?e, "failed to clean S3 bucket");
                } else {
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Some((aws::PROFILE_CMD, matches)) => {
                let config_path = matches.get_one::<PathBuf>("config").unwrap();
                let instance = matches.get_one::<String>("instance").unwrap();
                let duration = *matches.get_one::<u64>("duration").unwrap();
                let binary = matches.get_one::<PathBuf>("binary").unwrap();
                if let Err(e) = aws::profile(config_path, instance, duration, binary).await {
                    error!(error=?e, "failed to profile instance");
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
