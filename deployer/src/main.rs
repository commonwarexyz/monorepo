use clap::{App, Arg, SubCommand};
use commonware_utils::crate_version;
use std::error::Error;

mod ec2;

/// Main entry point for the Commonware Deployer CLI
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Define CLI application structure
    let matches = App::new("deployer")
        .version(crate_version())
        .about("TBD")
        .subcommand(
            SubCommand::with_name("ec2")
                .about("TBD")
                .subcommand(
                    SubCommand::with_name("setup")
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
                    SubCommand::with_name("teardown")
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

    // Handle ec2 subcommands
    if let Some(ec2_matches) = matches.subcommand_matches("ec2") {
        match ec2_matches.subcommand() {
            ("setup", Some(sub_m)) => {
                let config_path = sub_m.value_of("config").unwrap();
                let tag = ec2::setup(config_path).await?;
                println!("Deployment tag: {}", tag);
            }
            ("teardown", Some(sub_m)) => {
                let tag = sub_m.value_of("tag").unwrap();
                let config_path = sub_m.value_of("config").unwrap();
                ec2::teardown(tag, config_path).await?;
            }
            _ => println!("Invalid command. Use 'setup' or 'teardown'."),
        }
    } else {
        println!("Invalid command. Use 'ec2'.");
    }

    Ok(())
}
