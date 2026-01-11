//! `create` subcommand for `ec2`

use crate::ec2::{
    aws::*, deployer_directory, s3::*, services::*, utils::*, Config, Error, Host, Hosts,
    InstanceConfig, CREATED_FILE_NAME, LOGS_PORT, MONITORING_NAME, MONITORING_REGION,
    PROFILES_PORT, TRACES_PORT,
};
use futures::future::try_join_all;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fs::File,
    net::IpAddr,
    path::PathBuf,
    slice,
    time::Duration,
};
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
    let tag_directory = deployer_directory(tag);
    if tag_directory.exists() {
        return Err(Error::CreationAttempted);
    }
    std::fs::create_dir_all(&tag_directory)?;
    info!(path = ?tag_directory, "created tag directory");

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
    let key_name = format!("deployer-{tag}");
    let private_key_path = tag_directory.join(format!("id_rsa_{tag}"));
    let public_key_path = tag_directory.join(format!("id_rsa_{tag}.pub"));
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

    // Setup S3 bucket and cache observability tools
    info!("setting up S3 cache bucket");
    let s3_client = create_s3_client(Region::new(MONITORING_REGION)).await;
    ensure_bucket_exists(&s3_client, S3_BUCKET_NAME, MONITORING_REGION).await?;

    // Cache observability tools if not already cached
    info!("checking and caching observability tools");
    let tools_to_cache = [
        (
            prometheus_s3_key(PROMETHEUS_VERSION),
            prometheus_download_url(PROMETHEUS_VERSION),
        ),
        (
            grafana_s3_key(GRAFANA_VERSION),
            grafana_download_url(GRAFANA_VERSION),
        ),
        (loki_s3_key(LOKI_VERSION), loki_download_url(LOKI_VERSION)),
        (
            pyroscope_s3_key(PYROSCOPE_VERSION),
            pyroscope_download_url(PYROSCOPE_VERSION),
        ),
        (
            tempo_s3_key(TEMPO_VERSION),
            tempo_download_url(TEMPO_VERSION),
        ),
        (
            node_exporter_s3_key(NODE_EXPORTER_VERSION),
            node_exporter_download_url(NODE_EXPORTER_VERSION),
        ),
        (
            promtail_s3_key(PROMTAIL_VERSION),
            promtail_download_url(PROMTAIL_VERSION),
        ),
    ];

    for (s3_key, download_url) in &tools_to_cache {
        if !object_exists(&s3_client, S3_BUCKET_NAME, s3_key).await? {
            info!(
                key = s3_key.as_str(),
                "tool not cached, downloading and uploading"
            );
            let temp_path = tag_directory.join(s3_key.replace('/', "_"));
            download_file(download_url, &temp_path).await?;
            upload_file(&s3_client, S3_BUCKET_NAME, s3_key, &temp_path).await?;
            // Clean up temp file
            std::fs::remove_file(&temp_path)?;
        } else {
            info!(key = s3_key.as_str(), "tool already cached");
        }
    }
    info!("observability tools cached");

    // Generate pre-signed URLs for tools (valid for 6 hours)
    info!("generating pre-signed URLs for tools");
    let presign_duration = Duration::from_secs(6 * 60 * 60);
    let prometheus_url = presign_url(
        &s3_client,
        S3_BUCKET_NAME,
        &prometheus_s3_key(PROMETHEUS_VERSION),
        presign_duration,
    )
    .await?;
    let grafana_url = presign_url(
        &s3_client,
        S3_BUCKET_NAME,
        &grafana_s3_key(GRAFANA_VERSION),
        presign_duration,
    )
    .await?;
    let loki_url = presign_url(
        &s3_client,
        S3_BUCKET_NAME,
        &loki_s3_key(LOKI_VERSION),
        presign_duration,
    )
    .await?;
    let pyroscope_url = presign_url(
        &s3_client,
        S3_BUCKET_NAME,
        &pyroscope_s3_key(PYROSCOPE_VERSION),
        presign_duration,
    )
    .await?;
    let tempo_url = presign_url(
        &s3_client,
        S3_BUCKET_NAME,
        &tempo_s3_key(TEMPO_VERSION),
        presign_duration,
    )
    .await?;
    let node_exporter_url = presign_url(
        &s3_client,
        S3_BUCKET_NAME,
        &node_exporter_s3_key(NODE_EXPORTER_VERSION),
        presign_duration,
    )
    .await?;
    let promtail_url = presign_url(
        &s3_client,
        S3_BUCKET_NAME,
        &promtail_s3_key(PROMTAIL_VERSION),
        presign_duration,
    )
    .await?;
    info!("generated pre-signed URLs for tools");

    // Upload instance binaries and configs to S3 concurrently
    info!("uploading instance binaries and configs to S3");
    let binary_config_results: Vec<(String, [String; 2])> =
        try_join_all(config.instances.iter().map(|instance| async {
            let binary_key = binary_s3_key(tag, &instance.name);
            let config_key = config_s3_key(tag, &instance.name);
            let urls: [String; 2] = try_join_all([
                upload_and_presign(
                    &s3_client,
                    S3_BUCKET_NAME,
                    &binary_key,
                    std::path::Path::new(&instance.binary),
                    presign_duration,
                ),
                upload_and_presign(
                    &s3_client,
                    S3_BUCKET_NAME,
                    &config_key,
                    std::path::Path::new(&instance.config),
                    presign_duration,
                ),
            ])
            .await?
            .try_into()
            .unwrap();
            Ok::<_, Error>((instance.name.clone(), urls))
        }))
        .await?;

    let mut instance_binary_urls: HashMap<String, String> = HashMap::new();
    let mut instance_config_urls: HashMap<String, String> = HashMap::new();
    for (name, [binary_url, config_url]) in binary_config_results {
        instance_binary_urls.insert(name.clone(), binary_url);
        instance_config_urls.insert(name, config_url);
    }
    info!("uploaded all instance binaries and configs");

    // Initialize resources for each region
    info!(?regions, "initializing resources");
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
        let vpc_cidr = format!("10.{idx}.0.0/16");
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
        let subnet_cidr = format!("10.{idx}.1.0/24");
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
            None,
        )
        .await?[0]
            .clone();
        monitoring_ip = wait_for_instances_running(
            monitoring_ec2_client,
            slice::from_ref(&monitoring_instance_id),
        )
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
                None,
            )
            .await?[0]
                .clone();
            let ip = wait_for_instances_running(ec2_client, slice::from_ref(&instance_id)).await?
                [0]
            .clone();
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

    // Write systemd service files
    let prometheus_service_path = tag_directory.join("prometheus.service");
    std::fs::write(&prometheus_service_path, PROMETHEUS_SERVICE)?;
    let loki_service_path = tag_directory.join("loki.service");
    std::fs::write(&loki_service_path, LOKI_SERVICE)?;
    let pyroscope_service_path = tag_directory.join("pyroscope.service");
    std::fs::write(&pyroscope_service_path, PYROSCOPE_SERVICE)?;
    let tempo_service_path = tag_directory.join("tempo.service");
    std::fs::write(&tempo_service_path, TEMPO_SERVICE)?;
    let promtail_service_path = tag_directory.join("promtail.service");
    std::fs::write(&promtail_service_path, PROMTAIL_SERVICE)?;
    let node_exporter_service_path = tag_directory.join("node_exporter.service");
    std::fs::write(&node_exporter_service_path, NODE_EXPORTER_SERVICE)?;
    let pyroscope_agent_service_path = tag_directory.join("pyroscope-agent.service");
    std::fs::write(&pyroscope_agent_service_path, PYROSCOPE_AGENT_SERVICE)?;
    let pyroscope_agent_timer_path = tag_directory.join("pyroscope-agent.timer");
    std::fs::write(&pyroscope_agent_timer_path, PYROSCOPE_AGENT_TIMER)?;
    let binary_service_path = tag_directory.join("binary.service");
    std::fs::write(&binary_service_path, BINARY_SERVICE)?;

    // Write logrotate configuration file
    let logrotate_conf_path = tag_directory.join("logrotate.conf");
    std::fs::write(&logrotate_conf_path, LOGROTATE_CONF)?;

    // Add BBR configuration file
    let bbr_conf_path = tag_directory.join("99-bbr.conf");
    std::fs::write(&bbr_conf_path, BBR_CONF)?;

    // Configure monitoring instance
    info!("configuring monitoring instance");
    wait_for_instances_ready(&ec2_clients[&monitoring_region], &[monitoring_instance_id]).await?;

    // Generate and upload monitoring config files to S3
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

    // Write config files locally
    let prom_config = generate_prometheus_config(&instances);
    let prom_path = tag_directory.join("prometheus.yml");
    std::fs::write(&prom_path, &prom_config)?;

    let datasources_path = tag_directory.join("datasources.yml");
    std::fs::write(&datasources_path, DATASOURCES_YML)?;

    let all_yaml_path = tag_directory.join("all.yml");
    std::fs::write(&all_yaml_path, ALL_YML)?;

    let loki_config_path = tag_directory.join("loki.yml");
    std::fs::write(&loki_config_path, LOKI_CONFIG)?;

    let pyroscope_config_path = tag_directory.join("pyroscope.yml");
    std::fs::write(&pyroscope_config_path, PYROSCOPE_CONFIG)?;

    let tempo_yml_path = tag_directory.join("tempo.yml");
    std::fs::write(&tempo_yml_path, TEMPO_CONFIG)?;

    // Upload all monitoring config files to S3 concurrently (including BBR config)
    let dashboard_path = std::path::PathBuf::from(&config.monitoring.dashboard);
    let bbr_key = bbr_s3_key(tag);
    let [
        bbr_conf_url,
        prometheus_config_url,
        datasources_url,
        all_yml_url,
        dashboard_url,
        loki_yml_url,
        pyroscope_yml_url,
        tempo_yml_url,
        prometheus_service_url,
        loki_service_url,
        pyroscope_service_url,
        tempo_service_url,
        monitoring_node_exporter_service_url,
    ]: [String; 13] = try_join_all([
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &bbr_key,
            &bbr_conf_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &prometheus_config_s3_key(tag),
            &prom_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "datasources.yml"),
            &datasources_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "all.yml"),
            &all_yaml_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &dashboard_s3_key(tag),
            &dashboard_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "loki.yml"),
            &loki_config_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "pyroscope.yml"),
            &pyroscope_config_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "tempo.yml"),
            &tempo_yml_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "prometheus.service"),
            &prometheus_service_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "loki.service"),
            &loki_service_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "pyroscope.service"),
            &pyroscope_service_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "tempo.service"),
            &tempo_service_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_static_s3_key(tag, "node_exporter.service"),
            &node_exporter_service_path,
            presign_duration,
        ),
    ])
    .await?
    .try_into()
    .unwrap();

    info!("uploaded monitoring config files to S3");

    // Install and configure monitoring services
    enable_bbr(private_key, &monitoring_ip, &bbr_conf_url).await?;
    let monitoring_urls = MonitoringUrls {
        prometheus_bin: prometheus_url,
        grafana_bin: grafana_url,
        loki_bin: loki_url,
        pyroscope_bin: pyroscope_url,
        tempo_bin: tempo_url,
        node_exporter_bin: node_exporter_url.clone(),
        prometheus_config: prometheus_config_url,
        datasources_yml: datasources_url,
        all_yml: all_yml_url,
        dashboard: dashboard_url,
        loki_yml: loki_yml_url,
        pyroscope_yml: pyroscope_yml_url,
        tempo_yml: tempo_yml_url,
        prometheus_service: prometheus_service_url,
        loki_service: loki_service_url,
        pyroscope_service: pyroscope_service_url,
        tempo_service: tempo_service_url,
        node_exporter_service: monitoring_node_exporter_service_url,
    };
    ssh_execute(
        private_key,
        &monitoring_ip,
        &install_monitoring_cmd(&monitoring_urls, PROMETHEUS_VERSION),
    )
    .await?;
    ssh_execute(private_key, &monitoring_ip, start_monitoring_services_cmd()).await?;
    poll_service_active(private_key, &monitoring_ip, "node_exporter").await?;
    poll_service_active(private_key, &monitoring_ip, "prometheus").await?;
    poll_service_active(private_key, &monitoring_ip, "loki").await?;
    poll_service_active(private_key, &monitoring_ip, "pyroscope").await?;
    poll_service_active(private_key, &monitoring_ip, "tempo").await?;
    poll_service_active(private_key, &monitoring_ip, "grafana-server").await?;
    info!("configured monitoring instance");

    // Generate hosts.yaml
    let hosts = Hosts {
        monitoring: monitoring_private_ip.clone().parse::<IpAddr>().unwrap(),
        hosts: deployments
            .iter()
            .map(|d| Host {
                name: d.instance.name.clone(),
                region: d.instance.region.clone(),
                ip: d.ip.clone().parse::<IpAddr>().unwrap(),
            })
            .collect(),
    };
    let hosts_yaml = serde_yaml::to_string(&hosts)?;
    let hosts_path = tag_directory.join("hosts.yaml");
    std::fs::write(&hosts_path, &hosts_yaml)?;

    // Upload shared static service files to S3 concurrently (once for all instances)
    info!("uploading binary instance static files to S3");
    let [
        promtail_service_url,
        instance_node_exporter_service_url,
        binary_service_url,
        logrotate_conf_url,
        pyroscope_agent_service_url,
        pyroscope_agent_timer_url,
    ]: [String; 6] = try_join_all([
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &instance_static_s3_key(tag, "promtail.service"),
            &promtail_service_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &instance_static_s3_key(tag, "node_exporter.service"),
            &node_exporter_service_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &instance_static_s3_key(tag, "binary.service"),
            &binary_service_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &instance_static_s3_key(tag, "logrotate.conf"),
            &logrotate_conf_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &instance_static_s3_key(tag, "pyroscope-agent.service"),
            &pyroscope_agent_service_path,
            presign_duration,
        ),
        upload_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &instance_static_s3_key(tag, "pyroscope-agent.timer"),
            &pyroscope_agent_timer_path,
            presign_duration,
        ),
    ])
    .await?
    .try_into()
    .unwrap();

    // Write per-instance config files locally
    info!("uploading per-instance config files to S3");
    let mut per_instance_paths: Vec<(String, std::path::PathBuf, std::path::PathBuf)> = Vec::new();
    for deployment in &deployments {
        let instance = &deployment.instance;
        let ip = &deployment.ip;

        let promtail_cfg =
            promtail_config(&monitoring_private_ip, &instance.name, ip, &instance.region);
        let promtail_path = tag_directory.join(format!("promtail_{}.yml", instance.name));
        std::fs::write(&promtail_path, &promtail_cfg)?;

        let pyroscope_script =
            generate_pyroscope_script(&monitoring_private_ip, &instance.name, ip, &instance.region);
        let pyroscope_path = tag_directory.join(format!("pyroscope-agent_{}.sh", instance.name));
        std::fs::write(&pyroscope_path, &pyroscope_script)?;

        per_instance_paths.push((instance.name.clone(), promtail_path, pyroscope_path));
    }

    // Upload all per-instance files concurrently and build InstanceUrls
    let mut instance_urls_map: HashMap<String, InstanceUrls> =
        try_join_all(per_instance_paths.iter().map(
            |(name, promtail_path, pyroscope_path)| async {
                let [hosts_url, promtail_config_url, pyroscope_script_url]: [String; 3] =
                    try_join_all([
                        upload_and_presign(
                            &s3_client,
                            S3_BUCKET_NAME,
                            &hosts_s3_key(tag, name),
                            &hosts_path,
                            presign_duration,
                        ),
                        upload_and_presign(
                            &s3_client,
                            S3_BUCKET_NAME,
                            &promtail_config_s3_key(tag, name),
                            promtail_path,
                            presign_duration,
                        ),
                        upload_and_presign(
                            &s3_client,
                            S3_BUCKET_NAME,
                            &pyroscope_script_s3_key(tag, name),
                            pyroscope_path,
                            presign_duration,
                        ),
                    ])
                    .await?
                    .try_into()
                    .unwrap();

                Ok::<_, Error>((
                    name.clone(),
                    InstanceUrls {
                        binary: instance_binary_urls[name].clone(),
                        config: instance_config_urls[name].clone(),
                        hosts: hosts_url,
                        promtail_bin: promtail_url.clone(),
                        promtail_config: promtail_config_url,
                        promtail_service: promtail_service_url.clone(),
                        node_exporter_bin: node_exporter_url.clone(),
                        node_exporter_service: instance_node_exporter_service_url.clone(),
                        binary_service: binary_service_url.clone(),
                        logrotate_conf: logrotate_conf_url.clone(),
                        pyroscope_script: pyroscope_script_url,
                        pyroscope_service: pyroscope_agent_service_url.clone(),
                        pyroscope_timer: pyroscope_agent_timer_url.clone(),
                    },
                ))
            },
        ))
        .await?
        .into_iter()
        .collect();
    info!("uploaded all instance config files to S3");

    // Configure binary instances
    info!("configuring binary instances");
    let mut start_futures = Vec::new();
    for deployment in &deployments {
        let instance = deployment.instance.clone();
        wait_for_instances_ready(
            &ec2_clients[&instance.region],
            slice::from_ref(&deployment.id),
        )
        .await?;
        let ip = deployment.ip.clone();
        let bbr_url = bbr_conf_url.clone();
        let urls = instance_urls_map.remove(&instance.name).unwrap();
        let future = async move {
            enable_bbr(private_key, &ip, &bbr_url).await?;
            ssh_execute(
                private_key,
                &ip,
                &install_binary_cmd(&urls, instance.profiling),
            )
            .await?;
            poll_service_active(private_key, &ip, "promtail").await?;
            poll_service_active(private_key, &ip, "node_exporter").await?;
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
                    .from_port(LOGS_PORT as i32)
                    .to_port(LOGS_PORT as i32)
                    .user_id_group_pairs(
                        UserIdGroupPair::builder()
                            .group_id(binary_sg_id.clone())
                            .build(),
                    )
                    .build(),
            )
            .ip_permissions(
                IpPermission::builder()
                    .ip_protocol("tcp")
                    .from_port(PROFILES_PORT as i32)
                    .to_port(PROFILES_PORT as i32)
                    .user_id_group_pairs(
                        UserIdGroupPair::builder()
                            .group_id(binary_sg_id.clone())
                            .build(),
                    )
                    .build(),
            )
            .ip_permissions(
                IpPermission::builder()
                    .ip_protocol("tcp")
                    .from_port(TRACES_PORT as i32)
                    .to_port(TRACES_PORT as i32)
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
                        .from_port(LOGS_PORT as i32)
                        .to_port(LOGS_PORT as i32)
                        .ip_ranges(IpRange::builder().cidr_ip(binary_cidr).build())
                        .build(),
                )
                .ip_permissions(
                    IpPermission::builder()
                        .ip_protocol("tcp")
                        .from_port(PROFILES_PORT as i32)
                        .to_port(PROFILES_PORT as i32)
                        .ip_ranges(IpRange::builder().cidr_ip(binary_cidr).build())
                        .build(),
                )
                .ip_permissions(
                    IpPermission::builder()
                        .ip_protocol("tcp")
                        .from_port(TRACES_PORT as i32)
                        .to_port(TRACES_PORT as i32)
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
    File::create(tag_directory.join(CREATED_FILE_NAME))?;
    info!(
        monitoring = monitoring_ip.as_str(),
        binary = ?all_binary_ips,
        "deployment complete"
    );
    Ok(())
}
