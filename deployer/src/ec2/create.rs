use crate::ec2::{aws::*, services::*, utils::*, Config, InstanceConfig, Peer, Peers};
use futures::future::join_all;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;
use tokio::process::Command;
use tracing::{debug, info};

/// Directory for caching downloaded artifacts
const CACHE_DIR: &str = "/tmp/deployer-cache";

/// Represents a deployed instance with its configuration and public IP
#[derive(Clone)]
pub struct Deployment {
    pub instance: InstanceConfig,
    pub ip: String,
}

/// Represents AWS resources created in a specific region
pub struct RegionResources {
    pub vpc_id: String,
    pub vpc_cidr: String,
    pub route_table_id: String,
    pub subnet_id: String,
    pub regular_sg_id: Option<String>,
    pub monitoring_sg_id: Option<String>,
}

/// Sets up EC2 instances, deploys files, and configures monitoring and logging
pub async fn create(config: &PathBuf) -> Result<(), Box<dyn Error>> {
    // Load configuration from YAML file
    let config: Config = {
        let config_file = File::open(config)?;
        serde_yaml::from_reader(config_file)?
    };
    let tag = &config.tag;
    info!(tag = tag.as_str(), "loaded configuration");

    // Get public IP address of the deployer
    let deployer_ip = get_public_ip().await?;
    info!(ip = deployer_ip.as_str(), "recovered public IP");

    // Create a temporary directory for local files
    let temp_dir = format!("deployer-{}", tag);
    let temp_dir = PathBuf::from("/tmp").join(temp_dir);
    std::fs::create_dir_all(&temp_dir)?;
    let temp_dir_path = temp_dir.to_str().unwrap();
    info!(path = temp_dir_path, "created temporary directory");

    // Ensure cache directory exists
    std::fs::create_dir_all(CACHE_DIR)?;
    info!(cache_dir = CACHE_DIR, "created artifact cache");

    // Download monitoring artifacts
    info!("downloading monitoring artifacts");
    let prometheus_url = format!(
        "https://github.com/prometheus/prometheus/releases/download/v{}/prometheus-{}.linux-arm64.tar.gz",
        PROMETHEUS_VERSION, PROMETHEUS_VERSION
    );
    let prometheus_tar = temp_dir.join("prometheus.tar.gz");
    download_and_cache(CACHE_DIR, &prometheus_url, &prometheus_tar).await?;
    debug!(version = PROMETHEUS_VERSION, "downloaded prometheus");
    let grafana_url = format!(
        "https://dl.grafana.com/oss/release/grafana_{}_arm64.deb",
        GRAFANA_VERSION
    );
    let grafana_deb = temp_dir.join("grafana.deb");
    download_and_cache(CACHE_DIR, &grafana_url, &grafana_deb).await?;
    debug!(version = GRAFANA_VERSION, "downloaded grafana");
    let loki_url = format!(
        "https://github.com/grafana/loki/releases/download/v{}/loki-linux-arm64.zip",
        LOKI_VERSION
    );
    let loki_zip = temp_dir.join("loki.zip");
    download_and_cache(CACHE_DIR, &loki_url, &loki_zip).await?;
    debug!(version = LOKI_VERSION, "downloaded loki");
    let promtail_url = format!(
        "https://github.com/grafana/loki/releases/download/v{}/promtail-linux-arm64.zip",
        PROMTAIL_VERSION
    );
    let promtail_zip = temp_dir.join("promtail.zip");
    download_and_cache(CACHE_DIR, &promtail_url, &promtail_zip).await?;
    debug!(version = PROMTAIL_VERSION, "downloaded promtail");

    // Generate SSH key pair
    let key_name = format!("deployer-{}", tag);
    let private_key_path = temp_dir.join(format!("id_rsa_{}", tag));
    let public_key_path = temp_dir.join(format!("id_rsa_{}.pub", tag));
    let output = Command::new("ssh-keygen")
        .arg("-t")
        .arg("rsa")
        .arg("-b")
        .arg("4096")
        .arg("-f")
        .arg(private_key_path.to_str().unwrap())
        .arg("-N")
        .arg("")
        .output()
        .await?;
    if !output.status.success() {
        return Err(format!("failed to generate SSH key: {:?}", output).into());
    }
    let public_key = std::fs::read_to_string(&public_key_path)?;
    let private_key = private_key_path.to_str().unwrap();

    // Determine unique regions
    let mut regions: BTreeSet<String> = config.instances.iter().map(|i| i.region.clone()).collect();
    regions.insert(MONITORING_REGION.to_string());

    // Determine instance types by region
    let mut instance_types_by_region: HashMap<String, HashSet<String>> = HashMap::new();
    for instance in &config.instances {
        instance_types_by_region
            .entry(instance.region.clone())
            .or_default()
            .insert(instance.instance_type.clone());
    }
    instance_types_by_region
        .entry(MONITORING_REGION.to_string())
        .or_default()
        .insert(config.monitoring.instance_type.clone());

    // Initialize resources for each region
    info!(?regions, "initializing resources");
    let mut vpc_cidrs = HashMap::new();
    let mut subnet_cidrs = HashMap::new();
    let mut ec2_clients = HashMap::new();
    let mut region_resources = HashMap::new();
    for (idx, region) in regions.iter().enumerate() {
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;
        ec2_clients.insert(region.clone(), ec2_client);
        debug!(region = region.as_str(), "created EC2 client");

        let instance_types: Vec<String> =
            instance_types_by_region[region].iter().cloned().collect();
        let az = find_availability_zone(&ec2_clients[region], &instance_types).await?;
        debug!(
            az = az.as_str(),
            region = region.as_str(),
            "selected availability zone"
        );

        let vpc_cidr = format!("10.{}.0.0/16", idx);
        vpc_cidrs.insert(region.clone(), vpc_cidr.clone());
        let vpc_id = create_vpc(&ec2_clients[region], &vpc_cidr, tag).await?;
        debug!(
            vpc = vpc_id.as_str(),
            region = region.as_str(),
            "created VPC"
        );

        let igw_id = create_and_attach_igw(&ec2_clients[region], &vpc_id, tag).await?;
        debug!(
            igw = igw_id.as_str(),
            vpc = vpc_id.as_str(),
            region = region.as_str(),
            "created and attached IGW"
        );

        let route_table_id =
            create_route_table(&ec2_clients[region], &vpc_id, &igw_id, tag).await?;
        debug!(
            route_table = route_table_id.as_str(),
            vpc = vpc_id.as_str(),
            region = region.as_str(),
            "created route table"
        );

        let subnet_cidr = format!("10.{}.1.0/24", idx);
        subnet_cidrs.insert(region.clone(), subnet_cidr.clone());
        let subnet_id = create_subnet(
            &ec2_clients[region],
            &vpc_id,
            &route_table_id,
            &subnet_cidr,
            &az,
            tag,
        )
        .await?;
        debug!(
            subnet = subnet_id.as_str(),
            vpc = vpc_id.as_str(),
            region = region.as_str(),
            "created subnet"
        );

        let monitoring_sg_id = if *region == MONITORING_REGION {
            let sg_id =
                create_security_group_monitoring(&ec2_clients[region], &vpc_id, &deployer_ip, tag)
                    .await?;
            debug!(
                sg = sg_id.as_str(),
                vpc = vpc_id.as_str(),
                region = region.as_str(),
                "created monitoring security group"
            );
            Some(sg_id)
        } else {
            None
        };

        import_key_pair(&ec2_clients[region], &key_name, &public_key).await?;
        debug!(
            key = key_name.as_str(),
            region = region.as_str(),
            "imported key pair"
        );

        info!(
            vpc = vpc_id.as_str(),
            subnet = subnet_id.as_str(),
            subnet_cidr = subnet_cidr.as_str(),
            region = region.as_str(),
            "initialized resources"
        );
        region_resources.insert(
            region.clone(),
            RegionResources {
                vpc_id,
                vpc_cidr: vpc_cidr.clone(),
                route_table_id,
                subnet_id,
                regular_sg_id: None,
                monitoring_sg_id,
            },
        );
    }
    info!(?regions, "initialized resources");

    // Setup VPC peering connections
    info!("initializing VPC peering connections");
    let monitoring_region = MONITORING_REGION.to_string();
    let monitoring_resources = region_resources.get(&monitoring_region).unwrap();
    let monitoring_vpc_id = &monitoring_resources.vpc_id;
    let monitoring_cidr = &monitoring_resources.vpc_cidr;
    let regular_regions: HashSet<String> =
        config.instances.iter().map(|i| i.region.clone()).collect();
    for region in &regions {
        if region != &monitoring_region && regular_regions.contains(region) {
            let regular_resources = region_resources.get(region).unwrap();
            let regular_vpc_id = &regular_resources.vpc_id;
            let regular_cidr = &regular_resources.vpc_cidr;
            let peer_id = create_vpc_peering_connection(
                &ec2_clients[&monitoring_region],
                monitoring_vpc_id,
                regular_vpc_id,
                region,
                tag,
            )
            .await?;
            debug!(
                peer = peer_id.as_str(),
                monitoring = monitoring_vpc_id.as_str(),
                regular = regular_vpc_id.as_str(),
                region = region.as_str(),
                "created VPC peering connection"
            );
            wait_for_vpc_peering_connection(&ec2_clients[&monitoring_region], &peer_id).await?;
            debug!(
                peer = peer_id.as_str(),
                region = region.as_str(),
                "VPC peering connection is active"
            );
            accept_vpc_peering_connection(&ec2_clients[&monitoring_region], &peer_id).await?;
            debug!(
                peer = peer_id.as_str(),
                region = region.as_str(),
                "accepted VPC peering connection"
            );
            add_route(
                &ec2_clients[&monitoring_region],
                &monitoring_resources.route_table_id,
                regular_cidr,
                &peer_id,
            )
            .await?;
            add_route(
                &ec2_clients[region],
                &regular_resources.route_table_id,
                monitoring_cidr,
                &peer_id,
            )
            .await?;
            debug!(
                peer = peer_id.as_str(),
                monitoring = monitoring_vpc_id.as_str(),
                regular = regular_vpc_id.as_str(),
                region = region.as_str(),
                "added routes for VPC peering connection"
            );
        }
    }
    info!("initialized VPC peering connections");

    // Launch monitoring instance
    info!("launching monitoring instance");
    let monitoring_ip;
    let monitoring_private_ip;
    let monitoring_sg_id;
    {
        let monitoring_ec2_client = &ec2_clients[&monitoring_region];
        let ami_id = find_latest_ami(monitoring_ec2_client).await?;
        let monitoring_instance_type = InstanceType::try_parse(&config.monitoring.instance_type)
            .expect("Invalid instance type");
        let monitoring_storage_class =
            VolumeType::try_parse(&config.monitoring.storage_class).expect("Invalid storage class");
        monitoring_sg_id = monitoring_resources
            .monitoring_sg_id
            .as_ref()
            .unwrap()
            .clone();
        let monitoring_instance_id = launch_instances(
            monitoring_ec2_client,
            &ami_id,
            monitoring_instance_type,
            config.monitoring.storage_size,
            monitoring_storage_class,
            &key_name,
            &monitoring_resources.subnet_id,
            &monitoring_sg_id,
            1,
            "monitoring",
            tag,
        )
        .await?[0]
            .clone();
        monitoring_ip =
            wait_for_instances_running(monitoring_ec2_client, &[monitoring_instance_id.clone()])
                .await?[0]
                .clone();
        monitoring_private_ip =
            get_private_ip(monitoring_ec2_client, &monitoring_instance_id).await?;
    }
    info!(ip = monitoring_ip.as_str(), "launched monitoring instance");

    // Create regular security groups
    info!("creating security groups");
    for (region, resources) in region_resources.iter_mut() {
        let regular_sg_id = create_security_group_regular(
            &ec2_clients[region],
            &resources.vpc_id,
            &deployer_ip,
            &monitoring_ip,
            tag,
            &config.ports,
        )
        .await?;
        debug!(
            sg = regular_sg_id.as_str(),
            vpc = resources.vpc_id.as_str(),
            region = region.as_str(),
            "created regular security group"
        );
        resources.regular_sg_id = Some(regular_sg_id);
    }
    info!("created security groups");

    // Launch regular instances
    info!("launching regular instances");
    let mut launch_futures = Vec::new();
    for instance in &config.instances {
        let key_name = key_name.clone();
        let region = instance.region.clone();
        let resources = region_resources.get(&region).unwrap();
        let ec2_client = ec2_clients.get(&region).unwrap();
        let ami_id = find_latest_ami(ec2_client).await?;
        let instance_type =
            InstanceType::try_parse(&instance.instance_type).expect("Invalid instance type");
        let storage_class =
            VolumeType::try_parse(&instance.storage_class).expect("Invalid storage class");
        let regular_sg_id = resources.regular_sg_id.as_ref().unwrap();
        let tag = tag.clone();
        let future = async move {
            let instance_id = launch_instances(
                ec2_client,
                &ami_id,
                instance_type,
                instance.storage_size,
                storage_class,
                &key_name,
                &resources.subnet_id,
                regular_sg_id,
                1,
                &instance.name,
                &tag,
            )
            .await?[0]
                .clone();
            let ip =
                wait_for_instances_running(ec2_client, &[instance_id.clone()]).await?[0].clone();
            debug!(
                ip = ip.as_str(),
                instance = instance.name.as_str(),
                "launched instance"
            );
            Ok::<Deployment, Box<dyn Error>>(Deployment {
                instance: instance.clone(),
                ip,
            })
        };
        launch_futures.push(future);
    }
    let deployments: Vec<Deployment> = join_all(launch_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    info!("launched regular instances");

    // Generate peers.yaml
    let peers = Peers {
        peers: deployments
            .iter()
            .map(|d| Peer {
                name: d.instance.name.clone(),
                region: d.instance.region.clone(),
                ip: d.ip.clone(),
            })
            .collect(),
    };
    let peers_yaml = serde_yaml::to_string(&peers)?;
    let peers_path = temp_dir.join("peers.yaml");
    std::fs::write(&peers_path, peers_yaml)?;

    // Write systemd service files
    let prometheus_service_path = temp_dir.join("prometheus.service");
    std::fs::write(&prometheus_service_path, PROMETHEUS_SERVICE)?;
    let promtail_service_path = temp_dir.join("promtail.service");
    std::fs::write(&promtail_service_path, PROMTAIL_SERVICE)?;
    let loki_service_path = temp_dir.join("loki.service");
    std::fs::write(&loki_service_path, LOKI_SERVICE)?;
    let binary_service_path = temp_dir.join("binary.service");
    std::fs::write(&binary_service_path, BINARY_SERVICE)?;

    // Configure monitoring instance
    info!("configuring monitoring instance");
    let instances: Vec<(&str, &str)> = deployments
        .iter()
        .map(|d| (d.instance.name.as_str(), d.ip.as_str()))
        .collect();
    let prom_config = generate_prometheus_config(&instances);
    let prom_path = temp_dir.join("prometheus.yml");
    std::fs::write(&prom_path, prom_config)?;
    let datasources_path = temp_dir.join("datasources.yml");
    std::fs::write(&datasources_path, DATASOURCES_YML)?;
    let all_yaml_path = temp_dir.join("all.yml");
    std::fs::write(&all_yaml_path, ALL_YML)?;
    let loki_config_path = temp_dir.join("loki.yml");
    std::fs::write(&loki_config_path, LOKI_CONFIG)?;
    scp_file(
        private_key,
        prom_path.to_str().unwrap(),
        &monitoring_ip,
        "/home/ubuntu/prometheus.yml",
    )
    .await?;
    scp_file(
        private_key,
        datasources_path.to_str().unwrap(),
        &monitoring_ip,
        "/home/ubuntu/datasources.yml",
    )
    .await?;
    scp_file(
        private_key,
        all_yaml_path.to_str().unwrap(),
        &monitoring_ip,
        "/home/ubuntu/all.yml",
    )
    .await?;
    scp_file(
        private_key,
        &config.monitoring.dashboard,
        &monitoring_ip,
        "/home/ubuntu/dashboard.json",
    )
    .await?;
    scp_file(
        private_key,
        loki_config_path.to_str().unwrap(),
        &monitoring_ip,
        "/home/ubuntu/loki.yml",
    )
    .await?;
    scp_file(
        private_key,
        prometheus_tar.to_str().unwrap(),
        &monitoring_ip,
        "/home/ubuntu/prometheus.tar.gz",
    )
    .await?;
    scp_file(
        private_key,
        grafana_deb.to_str().unwrap(),
        &monitoring_ip,
        "/home/ubuntu/grafana.deb",
    )
    .await?;
    scp_file(
        private_key,
        loki_zip.to_str().unwrap(),
        &monitoring_ip,
        "/home/ubuntu/loki.zip",
    )
    .await?;
    scp_file(
        private_key,
        prometheus_service_path.to_str().unwrap(),
        &monitoring_ip,
        "/home/ubuntu/prometheus.service",
    )
    .await?;
    scp_file(
        private_key,
        loki_service_path.to_str().unwrap(),
        &monitoring_ip,
        "/home/ubuntu/loki.service",
    )
    .await?;
    ssh_execute(
        private_key,
        &monitoring_ip,
        &install_monitoring_cmd(PROMETHEUS_VERSION),
    )
    .await?;
    poll_service_status(private_key, &monitoring_ip, "prometheus").await?;
    poll_service_status(private_key, &monitoring_ip, "loki").await?;
    poll_service_status(private_key, &monitoring_ip, "grafana-server").await?;
    info!("configured monitoring instance");

    // Configure regular instances
    info!("configuring regular instances");
    let mut start_futures = Vec::new();
    for deployment in &deployments {
        let temp_dir = temp_dir.clone();
        let instance = deployment.instance.clone();
        let ip = deployment.ip.clone();
        let monitoring_private_ip = monitoring_private_ip.clone();
        let peers_path = peers_path.clone();
        let promtail_zip = promtail_zip.clone();
        let promtail_service_path = promtail_service_path.clone();
        let binary_service_path = binary_service_path.clone();
        let future = async move {
            scp_file(private_key, &instance.binary, &ip, "/home/ubuntu/binary").await?;
            scp_file(
                private_key,
                &instance.config,
                &ip,
                "/home/ubuntu/config.conf",
            )
            .await?;
            scp_file(
                private_key,
                peers_path.to_str().unwrap(),
                &ip,
                "/home/ubuntu/peers.yaml",
            )
            .await?;
            scp_file(
                private_key,
                promtail_zip.to_str().unwrap(),
                &ip,
                "/home/ubuntu/promtail.zip",
            )
            .await?;
            let promtail_config_path = temp_dir.join(format!("promtail_{}.yml", instance.name));
            std::fs::write(
                &promtail_config_path,
                promtail_config(&monitoring_private_ip, &instance.name),
            )?;
            scp_file(
                private_key,
                promtail_config_path.to_str().unwrap(),
                &ip,
                "/home/ubuntu/promtail.yml",
            )
            .await?;
            scp_file(
                private_key,
                promtail_service_path.to_str().unwrap(),
                &ip,
                "/home/ubuntu/promtail.service",
            )
            .await?;
            scp_file(
                private_key,
                binary_service_path.to_str().unwrap(),
                &ip,
                "/home/ubuntu/binary.service",
            )
            .await?;
            ssh_execute(private_key, &ip, SETUP_PROMTAIL_CMD).await?;
            poll_service_status(private_key, &ip, "promtail").await?;
            ssh_execute(private_key, &ip, INSTALL_BINARY_CMD).await?;
            poll_service_status(private_key, &ip, "binary").await?;
            debug!(
                ip = ip.as_str(),
                instance = instance.name.as_str(),
                "configured instance"
            );
            Ok::<String, Box<dyn Error>>(ip)
        };
        start_futures.push(future);
    }
    let all_regular_ips = join_all(start_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    info!("configured regular instances");

    // Update monitoring security group to restrict Loki port (3100)
    info!("updating monitoring security group to allow traffic from regular instances");
    let monitoring_ec2_client = &ec2_clients[&monitoring_region];
    if regular_regions.contains(&monitoring_region) {
        let regular_sg_id = region_resources[&monitoring_region]
            .regular_sg_id
            .clone()
            .unwrap();
        monitoring_ec2_client
            .authorize_security_group_ingress()
            .group_id(&monitoring_sg_id)
            .ip_permissions(
                IpPermission::builder()
                    .ip_protocol("tcp")
                    .from_port(3100)
                    .to_port(3100)
                    .user_id_group_pairs(
                        UserIdGroupPair::builder()
                            .group_id(regular_sg_id.clone())
                            .build(),
                    )
                    .build(),
            )
            .send()
            .await?;
        debug!(
            monitoring = monitoring_sg_id.as_str(),
            regular = regular_sg_id.as_str(),
            region = monitoring_region.as_str(),
            "linked monitoring and regular security groups in monitoring region"
        );
    }
    for region in &regions {
        if region != &monitoring_region && regular_regions.contains(region) {
            let regular_cidr = &region_resources[region].vpc_cidr;
            monitoring_ec2_client
                .authorize_security_group_ingress()
                .group_id(&monitoring_sg_id)
                .ip_permissions(
                    IpPermission::builder()
                        .ip_protocol("tcp")
                        .from_port(3100)
                        .to_port(3100)
                        .ip_ranges(IpRange::builder().cidr_ip(regular_cidr).build())
                        .build(),
                )
                .send()
                .await?;
            debug!(
                monitoring = monitoring_sg_id.as_str(),
                regular = regular_cidr.as_str(),
                region = region.as_str(),
                "opened monitoring part to traffic from regular VPC"
            );
        }
    }
    info!("updated monitoring security group");
    info!(
        monitoring = monitoring_ip.as_str(),
        ips = ?all_regular_ips,
        "deployment complete"
    );
    Ok(())
}
