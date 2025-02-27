use clap::{App, Arg, SubCommand};
use commonware_utils::crate_version;
use std::error::Error;
use tracing::error;

mod ec2;

const VERBOSE_FLAG: &str = "verbose";

/// Main entry point for the Commonware Deployer CLI
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Define CLI application structure
    let matches = App::new("deployer")
        .version(crate_version())
        .about("TBD")
        .arg(Arg::with_name(VERBOSE_FLAG).short("v").long(VERBOSE_FLAG))
        .subcommand(
            SubCommand::with_name(ec2::CMD)
                .about("TBD")
                .subcommand(
                    SubCommand::with_name(ec2::CREATE_CMD)
                        .about(
                            "Sets up EC2 instances and deploys files with monitoring and logging",
                        )
                        .arg(
                            Arg::with_name("config")
                                .long("config")
                                .takes_value(true)
                                .required(true)
                                .help("Path to YAML config file"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name(ec2::DESTROY_CMD)
                        .about("Deletes all deployed resources")
                        .arg(
                            Arg::with_name("tag")
                                .long("tag")
                                .takes_value(true)
                                .required(true)
                                .help("Deployment tag"),
                        )
                        .arg(
                            Arg::with_name("config")
                                .long("config")
                                .takes_value(true)
                                .required(true)
                                .help("Path to YAML config file"),
                        ),
                ),
        )
        .get_matches();

    // Create logger
    let level = if matches.is_present(VERBOSE_FLAG) {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    // Handle ec2 subcommands
    if let Some(ec2_matches) = matches.subcommand_matches(ec2::CMD) {
        match ec2_matches.subcommand() {
            (ec2::CREATE_CMD, Some(sub_m)) => {
                let config_path = sub_m.value_of("config").unwrap();
                let tag = ec2::create(config_path).await?;
                println!("Deployment tag: {}", tag);
            }
            (ec2::DESTROY_CMD, Some(sub_m)) => {
                let tag = sub_m.value_of("tag").unwrap();
                let config_path = sub_m.value_of("config").unwrap();
                ec2::destroy(tag, config_path).await?;
            }
            _ => error!(
                "Invalid subcommand. Use {:?} or {:?}.",
                ec2::CREATE_CMD,
                ec2::DESTROY_CMD
            ),
        }
    } else {
        error!("Invalid subcommand. Use {:?}.", ec2::CMD);
    }

    Ok(())
}
