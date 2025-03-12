//! `create` subcommand for `ec2`

use crate::ec2::{
    aws::*, deployer_directory, services::*, utils::*, Config, Error, InstanceConfig, Peer, Peers,
    CREATED_FILE_NAME, MONITORING_NAME, MONITORING_REGION,
};
use futures::future::try_join_all;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::net::IpAddr;
use std::path::PathBuf;
use tokio::process::Command;
use tracing::info;

/// Represents a deployed instance with its configuration and public IP
#[derive(Clone)]
pub struct Deployment {
    pub instance: InstanceConfig,
    pub id: String,
    pub ip: String,
}

/// Represents AWS resources created in a specific region
pub struct RegionResources {
    pub vpc_id: String,
    pub vpc_cidr: String,
    pub route_table_id: String,
    pub subnet_id: String,
    pub binary_sg_id: Option<String>,
    pub monitoring_sg_id: Option<String>,
}

/// Sets up EC2 instances, deploys files, and configures monitoring and logging
pub async fn create(config: &PathBuf) -> Result<(), Error> {
    // Load configuration from YAML file
    let config: Config = {
        let config_file = File::open(config)?;
        serde_yaml::from_reader(config_file)?
    };
    let tag = &config.tag;
    info!(tag = tag.as_str(), "loaded configuration");

    // Create a temporary directory for local files
    let temp_dir = deployer_directory(tag);
    if temp_dir.exists() {
        return Err(Error::CreationAttempted);
    }
    std::fs::create_dir_all(&temp_dir)?;
    info!(path = ?temp_dir, "created temporary directory");

    // Ensure no instance is duplicated or named MONITORING_NAME
    let mut instance_names = HashSet::new();
    for instance in &config.instances {
        if instance_names.contains(&instance.name) || instance.name == MONITORING_NAME {
            return Err(Error::InvalidInstanceName(instance.name.clone()));
        }
        instance_names.insert(instance.name.clone());
    }

    // Get public IP address of the deployer
    let deployer_ip = get_public_ip().await?;
    info!(ip = deployer_ip.as_str(), "recovered public IP");

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
        return Err(Error::KeygenFailed);
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
        // Create client for region
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;
        ec2_clients.insert(region.clone(), ec2_client);
        info!(region = region.as_str(), "created EC2 client");

        // Assert all instance types are ARM-based
        let instance_types: Vec<String> =
            instance_types_by_region[region].iter().cloned().collect();
        assert_arm64_support(&ec2_clients[region], &instance_types).await?;

        // Find availability zone that supports all instance types
        let az = find_availability_zone(&ec2_clients[region], &instance_types).await?;
        info!(
            az = az.as_str(),
            region = region.as_str(),
            "selected availability zone"
        );

        // Create VPC, IGW, route table, subnet, security groups, and key pair
        let vpc_cidr = format!("10.{}.0.0/16", idx);
        vpc_cidrs.insert(region.clone(), vpc_cidr.clone());
        let vpc_id = create_vpc(&ec2_clients[region], &vpc_cidr, tag).await?;
        info!(
            vpc = vpc_id.as_str(),
            region = region.as_str(),
            "created VPC"
        );
        let igw_id = create_and_attach_igw(&ec2_clients[region], &vpc_id, tag).await?;
        info!(
            igw = igw_id.as_str(),
            vpc = vpc_id.as_str(),
            region = region.as_str(),
            "created and attached IGW"
        );
        let route_table_id =
            create_route_table(&ec2_clients[region], &vpc_id, &igw_id, tag).await?;
        info!(
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
        info!(
            subnet = subnet_id.as_str(),
            vpc = vpc_id.as_str(),
            region = region.as_str(),
            "created subnet"
        );

        // Create monitoring security group in monitoring region
        let monitoring_sg_id = if *region == MONITORING_REGION {
            let sg_id =
                create_security_group_monitoring(&ec2_clients[region], &vpc_id, &deployer_ip, tag)
                    .await?;
            info!(
                sg = sg_id.as_str(),
                vpc = vpc_id.as_str(),
                region = region.as_str(),
                "created monitoring security group"
            );
            Some(sg_id)
        } else {
            None
        };

        // Import key pair
        import_key_pair(&ec2_clients[region], &key_name, &public_key).await?;
        info!(
            key = key_name.as_str(),
            region = region.as_str(),
            "imported key pair"
        );

        // Store resources for region
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
                binary_sg_id: None,
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
    let binary_regions: HashSet<String> =
        config.instances.iter().map(|i| i.region.clone()).collect();
    for region in &regions {
        if region != &monitoring_region && binary_regions.contains(region) {
            let binary_resources = region_resources.get(region).unwrap();
            let binary_vpc_id = &binary_resources.vpc_id;
            let binary_cidr = &binary_resources.vpc_cidr;
            let peer_id = create_vpc_peering_connection(
                &ec2_clients[&monitoring_region],
                monitoring_vpc_id,
                binary_vpc_id,
                region,
                tag,
            )
            .await?;
            info!(
                peer = peer_id.as_str(),
                monitoring = monitoring_vpc_id.as_str(),
                binary = binary_vpc_id.as_str(),
                region = region.as_str(),
                "created VPC peering connection"
            );
            wait_for_vpc_peering_connection(&ec2_clients[region], &peer_id).await?;
            info!(
                peer = peer_id.as_str(),
                region = region.as_str(),
                "VPC peering connection is available"
            );
            accept_vpc_peering_connection(&ec2_clients[region], &peer_id).await?;
            info!(
                peer = peer_id.as_str(),
                region = region.as_str(),
                "accepted VPC peering connection"
            );
            add_route(
                &ec2_clients[&monitoring_region],
                &monitoring_resources.route_table_id,
                binary_cidr,
                &peer_id,
            )
            .await?;
            add_route(
                &ec2_clients[region],
                &binary_resources.route_table_id,
                monitoring_cidr,
                &peer_id,
            )
            .await?;
            info!(
                peer = peer_id.as_str(),
                monitoring = monitoring_vpc_id.as_str(),
                binary = binary_vpc_id.as_str(),
                region = region.as_str(),
                "added routes for VPC peering connection"
            );
        }
    }
    info!("initialized VPC peering connections");

    // Launch monitoring instance
    info!("launching monitoring instance");
    let monitoring_instance_id;
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
        monitoring_instance_id = launch_instances(
            monitoring_ec2_client,
            &ami_id,
            monitoring_instance_type,
            config.monitoring.storage_size,
            monitoring_storage_class,
            &key_name,
            &monitoring_resources.subnet_id,
            &monitoring_sg_id,
            1,
            MONITORING_NAME,
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

    // Create binary security groups
    info!("creating security groups");
    for (region, resources) in region_resources.iter_mut() {
        let binary_sg_id = create_security_group_binary(
            &ec2_clients[region],
            &resources.vpc_id,
            &deployer_ip,
            &monitoring_ip,
            tag,
            &config.ports,
        )
        .await?;
        info!(
            sg = binary_sg_id.as_str(),
            vpc = resources.vpc_id.as_str(),
            region = region.as_str(),
            "created binary security group"
        );
        resources.binary_sg_id = Some(binary_sg_id);
    }
    info!("created security groups");

    // Launch binary instances
    info!("launching binary instances");
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
        let binary_sg_id = resources.binary_sg_id.as_ref().unwrap();
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
                binary_sg_id,
                1,
                &instance.name,
                &tag,
            )
            .await?[0]
                .clone();
            let ip =
                wait_for_instances_running(ec2_client, &[instance_id.clone()]).await?[0].clone();
            info!(
                ip = ip.as_str(),
                instance = instance.name.as_str(),
                "launched instance"
            );
            Ok::<Deployment, Error>(Deployment {
                instance: instance.clone(),
                id: instance_id,
                ip,
            })
        };
        launch_futures.push(future);
    }
    let deployments: Vec<Deployment> = try_join_all(launch_futures).await?;
    info!("launched binary instances");

    // Generate peers.yaml
    let peers = Peers {
        peers: deployments
            .iter()
            .map(|d| Peer {
                name: d.instance.name.clone(),
                region: d.instance.region.clone(),
                ip: d.ip.clone().parse::<IpAddr>().unwrap(),
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

    // Add BBR configuration file
    let bbr_conf_path = temp_dir.join("99-bbr.conf");
    std::fs::write(&bbr_conf_path, BBR_CONF)?;

    // Write logrotate configuration file
    let logrotate_conf_path = temp_dir.join("logrotate.conf");
    std::fs::write(&logrotate_conf_path, LOGROTATE_CONF)?;

    // Configure monitoring instance
    info!("configuring monitoring instance");
    wait_for_instances_ready(&ec2_clients[&monitoring_region], &[monitoring_instance_id]).await?;
    let instances: Vec<(&str, &str, &str)> = deployments
        .iter()
        .map(|d| {
            (
                d.instance.name.as_str(),
                d.ip.as_str(),
                d.instance.region.as_str(),
            )
        })
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
    enable_bbr(private_key, &monitoring_ip, bbr_conf_path.to_str().unwrap()).await?;
    ssh_execute(
        private_key,
        &monitoring_ip,
        &install_monitoring_cmd(PROMETHEUS_VERSION, GRAFANA_VERSION, LOKI_VERSION),
    )
    .await?;
    poll_service_active(private_key, &monitoring_ip, "prometheus").await?;
    poll_service_active(private_key, &monitoring_ip, "loki").await?;
    poll_service_active(private_key, &monitoring_ip, "grafana-server").await?;
    info!("configured monitoring instance");

    // Configure binary instances
    info!("configuring binary instances");
    let mut start_futures = Vec::new();
    for deployment in &deployments {
        let temp_dir = temp_dir.clone();
        let instance = deployment.instance.clone();
        wait_for_instances_ready(&ec2_clients[&instance.region], &[deployment.id.clone()]).await?;
        let ip = deployment.ip.clone();
        let monitoring_private_ip = monitoring_private_ip.clone();
        let peers_path = peers_path.clone();
        let logrotate_conf_path = logrotate_conf_path.clone();
        let bbr_conf_path = bbr_conf_path.clone();
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
            let promtail_config_path = temp_dir.join(format!("promtail_{}.yml", instance.name));
            std::fs::write(
                &promtail_config_path,
                promtail_config(
                    &monitoring_private_ip,
                    &instance.name,
                    ip.as_str(),
                    instance.region.as_str(),
                ),
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
            scp_file(
                private_key,
                logrotate_conf_path.to_str().unwrap(),
                &ip,
                "/home/ubuntu/logrotate.conf",
            )
            .await?;
            enable_bbr(private_key, &ip, bbr_conf_path.to_str().unwrap()).await?;
            ssh_execute(private_key, &ip, &setup_promtail_cmd(PROMTAIL_VERSION)).await?;
            poll_service_active(private_key, &ip, "promtail").await?;
            ssh_execute(private_key, &ip, INSTALL_BINARY_CMD).await?;
            poll_service_active(private_key, &ip, "binary").await?;
            info!(
                ip = ip.as_str(),
                instance = instance.name.as_str(),
                "configured instance"
            );
            Ok::<String, Error>(ip)
        };
        start_futures.push(future);
    }
    let all_binary_ips = try_join_all(start_futures).await?;
    info!("configured binary instances");

    // Update monitoring security group to restrict Loki port (3100)
    info!("updating monitoring security group to allow traffic from binary instances");
    let monitoring_ec2_client = &ec2_clients[&monitoring_region];
    if binary_regions.contains(&monitoring_region) {
        let binary_sg_id = region_resources[&monitoring_region]
            .binary_sg_id
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
                            .group_id(binary_sg_id.clone())
                            .build(),
                    )
                    .build(),
            )
            .send()
            .await
            .map_err(|err| err.into_service_error())?;
        info!(
            monitoring = monitoring_sg_id.as_str(),
            binary = binary_sg_id.as_str(),
            region = monitoring_region.as_str(),
            "linked monitoring and binary security groups in monitoring region"
        );
    }
    for region in &regions {
        if region != &monitoring_region && binary_regions.contains(region) {
            let binary_cidr = &region_resources[region].vpc_cidr;
            monitoring_ec2_client
                .authorize_security_group_ingress()
                .group_id(&monitoring_sg_id)
                .ip_permissions(
                    IpPermission::builder()
                        .ip_protocol("tcp")
                        .from_port(3100)
                        .to_port(3100)
                        .ip_ranges(IpRange::builder().cidr_ip(binary_cidr).build())
                        .build(),
                )
                .send()
                .await
                .map_err(|err| err.into_service_error())?;
            info!(
                monitoring = monitoring_sg_id.as_str(),
                binary = binary_cidr.as_str(),
                region = region.as_str(),
                "opened monitoring part to traffic from binary VPC"
            );
        }
    }
    info!("updated monitoring security group");

    // Mark deployment as complete
    File::create(temp_dir.join(CREATED_FILE_NAME))?;
    info!(
        monitoring = monitoring_ip.as_str(),
        binary = ?all_binary_ips,
        "deployment complete"
    );
    Ok(())
}
