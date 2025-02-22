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
                .long("peers")
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
                .long("regions")
                .required(true)
                .value_delimiter(',')
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("instance_type")
                .long("instance-type")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("storage_size")
                .long("storage-size")
                .required(true)
                .value_parser(value_parser!(i32)),
        )
        .arg(
            Arg::new("storage_class")
                .long("storage-class")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("dashboard")
                .long("dashboard")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            Arg::new("output")
                .long("output")
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
    let regions = matches
        .get_many::<String>("regions")
        .unwrap()
        .cloned()
        .collect::<Vec<_>>();
    let instance_type = matches.get_one::<String>("instance_type").unwrap();
    let storage_size = *matches.get_one::<i32>("storage_size").unwrap();
    let storage_class = matches.get_one::<String>("storage_class").unwrap();
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
        let region_index = (0..regions.len()).choose(&mut OsRng).unwrap();
        let region = regions[region_index].clone();
        let instance = InstanceConfig {
            name: name.clone(),
            region,
            instance_type: instance_type.clone(),
            storage_size,
            storage_class: storage_class.clone(),
            binary: BINARY_NAME.to_string(),
            config: peer_config_file,
        };
        instance_configs.push(instance);
    }

    // Generate root config file
    let config = commonware_deployer::Config {
        instances: instance_configs,
        monitoring: commonware_deployer::MonitoringConfig {
            instance_type: instance_type.clone(),
            storage_size,
            storage_class: storage_class.clone(),
            dashboard: "dashboard.json".to_string(),
        },
        ports: vec![commonware_deployer::PortConfig {
            protocol: "tcp".to_string(),
            port: PORT,
            cidr: "0.0.0.0/0".to_string(),
        }],
    };

    // Write configuration files
    let raw_current_dir = std::env::current_dir().unwrap();
    let current_dir = raw_current_dir.to_str().unwrap();
    let output = matches.get_one::<String>("output").unwrap();
    let output = format!("{}/{}", current_dir, output);
    assert!(
        !std::path::Path::new(&output).exists(),
        "Output directory already exists"
    );
    std::fs::create_dir_all(output.clone()).unwrap();
    let dashboard = matches.get_one::<String>("dashboard").unwrap().clone();
    println!("{}/{}", current_dir, dashboard);
    std::fs::copy(
        format!("{}/{}", current_dir, dashboard),
        format!("{}/dashboard.json", output),
    )
    .unwrap();
    for (peer_config_file, peer_config) in peer_configs {
        let path = format!("{}/{}", output, peer_config_file);
        let file = std::fs::File::create(path).unwrap();
        serde_yaml::to_writer(file, &peer_config).unwrap();
    }
    let path = format!("{}/config.yaml", output);
    let file = std::fs::File::create(path).unwrap();
    serde_yaml::to_writer(file, &config).unwrap();
}
