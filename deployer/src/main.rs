mod aws;
mod services;
mod setup;
mod teardown;
mod utils;

use clap::{App, Arg, SubCommand};
use std::error::Error;

/// Main entry point for the Commonware Deployer CLI
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Define CLI application structure
    let matches = App::new("deployer")
        .version("1.0")
        .about("Deploys a binary and config to EC2 instances across AWS regions with monitoring and logging")
        .subcommand(
            SubCommand::with_name("setup")
                .about("Sets up EC2 instances and deploys files with monitoring and logging")
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
        )
        .get_matches();

    // Fetch the deployer's public IP
    let deployer_ip = reqwest::get("https://ipv4.icanhazip.com")
        .await?
        .text()
        .await?
        .trim()
        .to_string();
    println!("Deployer IP: {}", deployer_ip);

    // Handle subcommands
    match matches.subcommand() {
        ("setup", Some(sub_m)) => {
            let config_path = sub_m.value_of("config").unwrap();
            let tag = setup::setup(config_path, &deployer_ip).await?;
            println!("Deployment tag: {}", tag);
        }
        ("teardown", Some(sub_m)) => {
            let tag = sub_m.value_of("tag").unwrap();
            let config_path = sub_m.value_of("config").unwrap();
            teardown::teardown(tag, config_path).await?;
        }
        _ => println!("Invalid command. Use 'setup' or 'teardown'."),
    }

    Ok(())
}
