use clap::{value_parser, Arg, Command};
use commonware_cryptography::{Ed25519, Scheme};
use commonware_deployer::InstanceConfig;
use commonware_flood::Config;
use rand::{rngs::OsRng, seq::IteratorRandom};

const BINARY_NAME: &str = "flood";
const PORT: u16 = 4545;

fn main() {
    // Parse arguments
    let matches = Command::new("setup")
        .about("generate configuration files")
        .arg(
            Arg::new("peers")
                .required(true)
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("bootstrappers")
                .long("bootstrappers")
                .required(true)
                .value_parser(value_parser!(usize)),
        )
        .arg(
            Arg::new("regions")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("instance_type")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("dashboard")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("output")
                .long("directory to output configuration files")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .get_matches();

    // Generate peers
    let peers = *matches.get_one::<usize>("peers").unwrap();
    let bootstrappers = *matches.get_one::<usize>("bootstrappers").unwrap();
    assert!(
        bootstrappers <= peers,
        "Bootstrappers must be less than peers"
    );
    let peer_schemes = (0..peers)
        .map(|_| Ed25519::new(&mut OsRng))
        .collect::<Vec<_>>();
    let allowed_peers: Vec<String> = peer_schemes
        .iter()
        .map(|scheme| scheme.public_key().to_string())
        .collect();
    let bootstrappers = allowed_peers
        .iter()
        .choose_multiple(&mut OsRng, bootstrappers)
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();

    // Generate instance configurations
    let regions = matches.get_many::<String>("regions").unwrap();
    let instance_type = matches.get_one::<String>("instance_type").unwrap();
    let mut instance_configs = Vec::new();
    let mut peer_configs = Vec::new();
    for scheme in peer_schemes {
        // Create peer config
        let name = scheme.public_key().to_string();
        let peer_config_file = format!("{}.yaml", name);
        let peer_config = Config {
            private_key: scheme.private_key().to_string(),
            port: PORT,
            allowed_peers: allowed_peers.clone(),
            bootstrappers: bootstrappers.clone(),
            message_size: 1024,
        };
        peer_configs.push((peer_config_file.clone(), peer_config));

        // Create instance config
        let region = regions.clone().choose(&mut OsRng).unwrap().clone();
        let instance = InstanceConfig {
            name: name.clone(),
            region,
            instance_type: instance_type.clone(),
            binary: BINARY_NAME.to_string(),
            config: peer_config_file,
        };
        instance_configs.push(instance);
    }

    // Generate root config file
    let dashboard = matches.get_one::<String>("dashboard").unwrap().clone();
    let config = commonware_deployer::Config {
        instances: instance_configs,
        monitoring: commonware_deployer::MonitoringConfig {
            instance_type: instance_type.clone(),
            dashboard,
        },
        ports: vec![commonware_deployer::PortConfig {
            protocol: "tcp".to_string(),
            port: PORT,
            cidr: "0.0.0.0/0".to_string(),
        }],
    };

    // Write configuration files
    let output = matches.get_one::<String>("output").unwrap();
    std::fs::create_dir_all(output).unwrap();
    for (peer_config_file, peer_config) in peer_configs {
        let path = format!("{}/{}.yaml", output, peer_config_file);
        let file = std::fs::File::create(path).unwrap();
        serde_yaml::to_writer(file, &peer_config).unwrap();
    }
    let path = format!("{}/config.yaml", output);
    let file = std::fs::File::create(path).unwrap();
    serde_yaml::to_writer(file, &config).unwrap();
}
