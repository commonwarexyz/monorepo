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
};
use tokio::process::Command;
use tracing::{debug, info};

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
    info!(bucket = S3_BUCKET_NAME, "setting up S3 cache bucket");
    let s3_client = create_s3_client(Region::new(MONITORING_REGION)).await;
    ensure_bucket_exists(&s3_client, S3_BUCKET_NAME, MONITORING_REGION).await?;

    // Cache observability tools (if not already cached) and generate pre-signed URLs concurrently
    info!("checking, caching, and generating pre-signed URLs for observability tools");
    let cache_tool = |s3_key: String, download_url: String| {
        let tag_directory = tag_directory.clone();
        let s3_client = s3_client.clone();
        async move {
            if !object_exists(&s3_client, S3_BUCKET_NAME, &s3_key).await? {
                debug!(
                    key = s3_key.as_str(),
                    "tool not cached, downloading and uploading"
                );
                let temp_path = tag_directory.join(s3_key.replace('/', "_"));
                download_file(&download_url, &temp_path).await?;
                let url = upload_and_presign(
                    &s3_client,
                    S3_BUCKET_NAME,
                    &s3_key,
                    &temp_path,
                    PRESIGN_DURATION,
                )
                .await?;
                std::fs::remove_file(&temp_path)?;
                Ok::<_, Error>(url)
            } else {
                debug!(key = s3_key.as_str(), "tool already cached");
                presign_url(&s3_client, S3_BUCKET_NAME, &s3_key, PRESIGN_DURATION).await
            }
        }
    };
    let [prometheus_url, grafana_url, loki_url, pyroscope_url, tempo_url, node_exporter_url, promtail_url]: [String; 7] =
        try_join_all([
            cache_tool(prometheus_bin_s3_key(PROMETHEUS_VERSION), prometheus_download_url(PROMETHEUS_VERSION)),
            cache_tool(grafana_bin_s3_key(GRAFANA_VERSION), grafana_download_url(GRAFANA_VERSION)),
            cache_tool(loki_bin_s3_key(LOKI_VERSION), loki_download_url(LOKI_VERSION)),
            cache_tool(pyroscope_bin_s3_key(PYROSCOPE_VERSION), pyroscope_download_url(PYROSCOPE_VERSION)),
            cache_tool(tempo_bin_s3_key(TEMPO_VERSION), tempo_download_url(TEMPO_VERSION)),
            cache_tool(node_exporter_bin_s3_key(NODE_EXPORTER_VERSION), node_exporter_download_url(NODE_EXPORTER_VERSION)),
            cache_tool(promtail_bin_s3_key(PROMTAIL_VERSION), promtail_download_url(PROMTAIL_VERSION)),
        ])
        .await?
        .try_into()
        .unwrap();
    info!("observability tools ready");

    // Compute hashes for binaries and configs, grouping by hash for deduplication
    info!("computing hashes for instance binaries and configs");
    let mut binary_hashes: HashMap<String, String> = HashMap::new(); // hash -> path
    let mut config_hashes: HashMap<String, String> = HashMap::new(); // hash -> path
    let mut instance_binary_hash: HashMap<String, String> = HashMap::new(); // instance -> hash
    let mut instance_config_hash: HashMap<String, String> = HashMap::new(); // instance -> hash

    for instance in &config.instances {
        let binary_hash = hash_file(std::path::Path::new(&instance.binary))?;
        let config_hash = hash_file(std::path::Path::new(&instance.config))?;
        binary_hashes.insert(binary_hash.clone(), instance.binary.clone());
        config_hashes.insert(config_hash.clone(), instance.config.clone());
        instance_binary_hash.insert(instance.name.clone(), binary_hash);
        instance_config_hash.insert(instance.name.clone(), config_hash);
    }
    info!(
        unique_binaries = binary_hashes.len(),
        unique_configs = config_hashes.len(),
        "computed hashes"
    );

    // Upload unique binaries and configs to S3 (deduplicated by hash)
    info!("uploading unique binaries and configs to S3");
    let binary_keys: Vec<_> = binary_hashes
        .keys()
        .map(|hash| binary_s3_key(tag, hash))
        .collect();
    let binary_paths: Vec<_> = binary_hashes.values().collect();
    let mut binary_uploads = Vec::new();
    for (key, path) in binary_keys.iter().zip(binary_paths.iter()) {
        binary_uploads.push(cache_file_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            key,
            std::path::Path::new(path),
            PRESIGN_DURATION,
        ));
    }

    let config_keys: Vec<_> = config_hashes
        .keys()
        .map(|hash| config_s3_key(tag, hash))
        .collect();
    let config_paths: Vec<_> = config_hashes.values().collect();
    let mut config_uploads = Vec::new();
    for (key, path) in config_keys.iter().zip(config_paths.iter()) {
        config_uploads.push(cache_file_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            key,
            std::path::Path::new(path),
            PRESIGN_DURATION,
        ));
    }

    let (binary_results, config_results): (Vec<String>, Vec<String>) =
        tokio::try_join!(async { try_join_all(binary_uploads).await }, async {
            try_join_all(config_uploads).await
        },)?;

    // Build hash -> URL maps
    let binary_hash_to_url: HashMap<String, String> =
        binary_hashes.keys().cloned().zip(binary_results).collect();
    let config_hash_to_url: HashMap<String, String> =
        config_hashes.keys().cloned().zip(config_results).collect();

    // Map instance names to URLs via their hashes
    let mut instance_binary_urls: HashMap<String, String> = HashMap::new();
    let mut instance_config_urls: HashMap<String, String> = HashMap::new();
    for instance in &config.instances {
        let binary_hash = &instance_binary_hash[&instance.name];
        let config_hash = &instance_config_hash[&instance.name];
        instance_binary_urls.insert(
            instance.name.clone(),
            binary_hash_to_url[binary_hash].clone(),
        );
        instance_config_urls.insert(
            instance.name.clone(),
            config_hash_to_url[config_hash].clone(),
        );
    }
    info!("uploaded all instance binaries and configs");

    // Initialize resources for each region concurrently
    info!(?regions, "initializing resources");
    let region_init_futures: Vec<_> = regions
        .iter()
        .enumerate()
        .map(|(idx, region)| {
            let region = region.clone();
            let tag = tag.clone();
            let deployer_ip = deployer_ip.clone();
            let key_name = key_name.clone();
            let public_key = public_key.clone();
            let instance_types: Vec<String> =
                instance_types_by_region[&region].iter().cloned().collect();

            async move {
                // Create client for region
                let ec2_client = create_ec2_client(Region::new(region.clone())).await;
                debug!(region = region.as_str(), "created EC2 client");

                // Assert all instance types are ARM-based
                assert_arm64_support(&ec2_client, &instance_types).await?;

                // Find availability zone that supports all instance types
                let az = find_availability_zone(&ec2_client, &instance_types).await?;
                debug!(
                    az = az.as_str(),
                    region = region.as_str(),
                    "selected availability zone"
                );

                // Create VPC, IGW, route table, subnet, security groups, and key pair
                let vpc_cidr = format!("10.{idx}.0.0/16");
                let vpc_id = create_vpc(&ec2_client, &vpc_cidr, &tag).await?;
                debug!(
                    vpc = vpc_id.as_str(),
                    region = region.as_str(),
                    "created VPC"
                );
                let igw_id = create_and_attach_igw(&ec2_client, &vpc_id, &tag).await?;
                debug!(
                    igw = igw_id.as_str(),
                    vpc = vpc_id.as_str(),
                    region = region.as_str(),
                    "created and attached IGW"
                );
                let route_table_id =
                    create_route_table(&ec2_client, &vpc_id, &igw_id, &tag).await?;
                debug!(
                    route_table = route_table_id.as_str(),
                    vpc = vpc_id.as_str(),
                    region = region.as_str(),
                    "created route table"
                );
                let subnet_cidr = format!("10.{idx}.1.0/24");
                let subnet_id = create_subnet(
                    &ec2_client,
                    &vpc_id,
                    &route_table_id,
                    &subnet_cidr,
                    &az,
                    &tag,
                )
                .await?;
                debug!(
                    subnet = subnet_id.as_str(),
                    vpc = vpc_id.as_str(),
                    region = region.as_str(),
                    "created subnet"
                );

                // Create monitoring security group in monitoring region
                let monitoring_sg_id = if region == MONITORING_REGION {
                    let sg_id =
                        create_security_group_monitoring(&ec2_client, &vpc_id, &deployer_ip, &tag)
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

                // Import key pair
                import_key_pair(&ec2_client, &key_name, &public_key).await?;
                debug!(
                    key = key_name.as_str(),
                    region = region.as_str(),
                    "imported key pair"
                );

                debug!(
                    vpc = vpc_id.as_str(),
                    subnet = subnet_id.as_str(),
                    subnet_cidr = subnet_cidr.as_str(),
                    region = region.as_str(),
                    "initialized resources"
                );

                Ok::<_, Error>((
                    region,
                    ec2_client,
                    RegionResources {
                        vpc_id,
                        vpc_cidr,
                        route_table_id,
                        subnet_id,
                        binary_sg_id: None,
                        monitoring_sg_id,
                    },
                ))
            }
        })
        .collect();

    let region_results = try_join_all(region_init_futures).await?;
    let (ec2_clients, mut region_resources): (HashMap<_, _>, HashMap<_, _>) = region_results
        .into_iter()
        .map(|(region, client, resources)| ((region.clone(), client), (region, resources)))
        .unzip();
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
            debug!(
                peer = peer_id.as_str(),
                monitoring = monitoring_vpc_id.as_str(),
                binary = binary_vpc_id.as_str(),
                region = region.as_str(),
                "created VPC peering connection"
            );
            wait_for_vpc_peering_connection(&ec2_clients[region], &peer_id).await?;
            debug!(
                peer = peer_id.as_str(),
                region = region.as_str(),
                "VPC peering connection is available"
            );
            accept_vpc_peering_connection(&ec2_clients[region], &peer_id).await?;
            debug!(
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
            debug!(
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
        debug!(
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

    // Cache ALL static config files globally (these don't change between deployments)
    // This includes both monitoring and binary instance static files
    info!("caching static config files");
    let [
        bbr_conf_url,
        datasources_url,
        all_yml_url,
        loki_yml_url,
        pyroscope_yml_url,
        tempo_yml_url,
        prometheus_service_url,
        loki_service_url,
        pyroscope_service_url,
        tempo_service_url,
        monitoring_node_exporter_service_url,
        promtail_service_url,
        binary_service_url,
        logrotate_conf_url,
        pyroscope_agent_service_url,
        pyroscope_agent_timer_url,
    ]: [String; 16] = try_join_all([
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &bbr_config_s3_key(), BBR_CONF.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &grafana_datasources_s3_key(), DATASOURCES_YML.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &grafana_dashboards_s3_key(), ALL_YML.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &loki_config_s3_key(), LOKI_CONFIG.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &pyroscope_config_s3_key(), PYROSCOPE_CONFIG.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &tempo_config_s3_key(), TEMPO_CONFIG.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &prometheus_service_s3_key(), PROMETHEUS_SERVICE.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &loki_service_s3_key(), LOKI_SERVICE.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &pyroscope_service_s3_key(), PYROSCOPE_SERVICE.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &tempo_service_s3_key(), TEMPO_SERVICE.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &node_exporter_service_s3_key(), NODE_EXPORTER_SERVICE.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &promtail_service_s3_key(), PROMTAIL_SERVICE.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &binary_service_s3_key(), BINARY_SERVICE.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &logrotate_config_s3_key(), LOGROTATE_CONF.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &pyroscope_agent_service_s3_key(), PYROSCOPE_AGENT_SERVICE.as_bytes(), PRESIGN_DURATION),
        cache_content_and_presign(&s3_client, S3_BUCKET_NAME, &pyroscope_agent_timer_s3_key(), PYROSCOPE_AGENT_TIMER.as_bytes(), PRESIGN_DURATION),
    ])
    .await?
    .try_into()
    .unwrap();

    // Upload deployment-specific monitoring config files (deduplicated by hash)
    info!("uploading deployment-specific config files");
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
    let prom_path = tag_directory.join("prometheus.yml");
    std::fs::write(&prom_path, &prom_config)?;
    let prom_hash = hash_file(&prom_path)?;
    let dashboard_path = std::path::PathBuf::from(&config.monitoring.dashboard);
    let dashboard_hash = hash_file(&dashboard_path)?;
    let [prometheus_config_url, dashboard_url]: [String; 2] = try_join_all([
        cache_file_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_s3_key(tag, &prom_hash),
            &prom_path,
            PRESIGN_DURATION,
        ),
        cache_file_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            &monitoring_s3_key(tag, &dashboard_hash),
            &dashboard_path,
            PRESIGN_DURATION,
        ),
    ])
    .await?
    .try_into()
    .unwrap();
    info!("uploaded deployment-specific config files to S3");

    // Generate hosts.yaml and upload once (shared by all instances)
    info!("uploading per-instance config files to S3");
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
    let hosts_hash = hash_file(&hosts_path)?;
    let hosts_url = cache_file_and_presign(
        &s3_client,
        S3_BUCKET_NAME,
        &hosts_s3_key(tag, &hosts_hash),
        &hosts_path,
        PRESIGN_DURATION,
    )
    .await?;

    // Write per-instance config files locally, compute hashes, and deduplicate
    let mut promtail_hashes: HashMap<String, std::path::PathBuf> = HashMap::new();
    let mut pyroscope_hashes: HashMap<String, std::path::PathBuf> = HashMap::new();
    let mut instance_promtail_hash: HashMap<String, String> = HashMap::new();
    let mut instance_pyroscope_hash: HashMap<String, String> = HashMap::new();

    for deployment in &deployments {
        let instance = &deployment.instance;
        let ip = &deployment.ip;

        let promtail_cfg =
            promtail_config(&monitoring_private_ip, &instance.name, ip, &instance.region);
        let promtail_path = tag_directory.join(format!("promtail_{}.yml", instance.name));
        std::fs::write(&promtail_path, &promtail_cfg)?;
        let promtail_hash = hash_file(&promtail_path)?;

        let pyroscope_script =
            generate_pyroscope_script(&monitoring_private_ip, &instance.name, ip, &instance.region);
        let pyroscope_path = tag_directory.join(format!("pyroscope-agent_{}.sh", instance.name));
        std::fs::write(&pyroscope_path, &pyroscope_script)?;
        let pyroscope_hash = hash_file(&pyroscope_path)?;

        promtail_hashes.insert(promtail_hash.clone(), promtail_path);
        pyroscope_hashes.insert(pyroscope_hash.clone(), pyroscope_path);
        instance_promtail_hash.insert(instance.name.clone(), promtail_hash);
        instance_pyroscope_hash.insert(instance.name.clone(), pyroscope_hash);
    }

    info!(
        unique_promtail = promtail_hashes.len(),
        unique_pyroscope = pyroscope_hashes.len(),
        "computed per-instance config hashes"
    );

    // Upload unique promtail and pyroscope configs
    let promtail_keys: Vec<_> = promtail_hashes
        .keys()
        .map(|hash| promtail_s3_key(tag, hash))
        .collect();
    let promtail_paths: Vec<_> = promtail_hashes.values().collect();
    let mut promtail_uploads = Vec::new();
    for (key, path) in promtail_keys.iter().zip(promtail_paths.iter()) {
        promtail_uploads.push(cache_file_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            key,
            path,
            PRESIGN_DURATION,
        ));
    }

    let pyroscope_keys: Vec<_> = pyroscope_hashes
        .keys()
        .map(|hash| pyroscope_s3_key(tag, hash))
        .collect();
    let pyroscope_paths: Vec<_> = pyroscope_hashes.values().collect();
    let mut pyroscope_uploads = Vec::new();
    for (key, path) in pyroscope_keys.iter().zip(pyroscope_paths.iter()) {
        pyroscope_uploads.push(cache_file_and_presign(
            &s3_client,
            S3_BUCKET_NAME,
            key,
            path,
            PRESIGN_DURATION,
        ));
    }

    let (promtail_results, pyroscope_results): (Vec<String>, Vec<String>) =
        tokio::try_join!(async { try_join_all(promtail_uploads).await }, async {
            try_join_all(pyroscope_uploads).await
        },)?;

    // Build hash -> URL maps
    let promtail_hash_to_url: HashMap<String, String> = promtail_hashes
        .keys()
        .cloned()
        .zip(promtail_results)
        .collect();
    let pyroscope_hash_to_url: HashMap<String, String> = pyroscope_hashes
        .keys()
        .cloned()
        .zip(pyroscope_results)
        .collect();

    // Build instance URLs map
    let mut instance_urls_map: HashMap<String, InstanceUrls> = HashMap::new();
    for deployment in &deployments {
        let name = &deployment.instance.name;
        let promtail_hash = &instance_promtail_hash[name];
        let pyroscope_hash = &instance_pyroscope_hash[name];

        instance_urls_map.insert(
            name.clone(),
            InstanceUrls {
                binary: instance_binary_urls[name].clone(),
                config: instance_config_urls[name].clone(),
                hosts: hosts_url.clone(),
                promtail_bin: promtail_url.clone(),
                promtail_config: promtail_hash_to_url[promtail_hash].clone(),
                promtail_service: promtail_service_url.clone(),
                node_exporter_bin: node_exporter_url.clone(),
                node_exporter_service: monitoring_node_exporter_service_url.clone(),
                binary_service: binary_service_url.clone(),
                logrotate_conf: logrotate_conf_url.clone(),
                pyroscope_script: pyroscope_hash_to_url[pyroscope_hash].clone(),
                pyroscope_service: pyroscope_agent_service_url.clone(),
                pyroscope_timer: pyroscope_agent_timer_url.clone(),
            },
        );
    }
    info!("uploaded all instance config files to S3");

    // Build monitoring URLs struct for SSH configuration
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
        node_exporter_service: monitoring_node_exporter_service_url.clone(),
    };

    // Configure monitoring and binary instances in parallel
    info!("configuring monitoring and binary instances");

    // Prepare binary instance configuration futures
    let mut binary_futures = Vec::new();
    for deployment in &deployments {
        let instance = deployment.instance.clone();
        let deployment_id = deployment.id.clone();
        let ec2_client = ec2_clients[&instance.region].clone();
        let ip = deployment.ip.clone();
        let bbr_url = bbr_conf_url.clone();
        let urls = instance_urls_map.remove(&instance.name).unwrap();
        let future = async move {
            wait_for_instances_ready(&ec2_client, slice::from_ref(&deployment_id)).await?;
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
        binary_futures.push(future);
    }

    // Run monitoring and binary configuration in parallel
    let (_, all_binary_ips) = tokio::try_join!(
        async {
            // Configure monitoring instance
            let monitoring_ec2_client = &ec2_clients[&monitoring_region];
            wait_for_instances_ready(
                monitoring_ec2_client,
                slice::from_ref(&monitoring_instance_id),
            )
            .await?;
            enable_bbr(private_key, &monitoring_ip, &bbr_conf_url).await?;
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
            Ok::<(), Error>(())
        },
        async {
            // Configure binary instances
            let all_binary_ips = try_join_all(binary_futures).await?;
            info!("configured binary instances");
            Ok::<Vec<String>, Error>(all_binary_ips)
        }
    )?;

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
        debug!(
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
            debug!(
                monitoring = monitoring_sg_id.as_str(),
                binary = binary_cidr.as_str(),
                region = region.as_str(),
                "opened monitoring port to traffic from binary VPC"
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
