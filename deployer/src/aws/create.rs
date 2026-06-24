//! `create` subcommand for `ec2`

use crate::aws::{
    deployer_directory,
    ec2::{self, *},
    images,
    s3::{self, *},
    services::*,
    utils::*,
    Architecture, Config, Error, Host, Hosts, InstanceConfig, Ips, Metadata, CREATED_FILE_NAME,
    LOGS_PORT, METADATA_FILE_NAME, MONITORING_NAME, MONITORING_REGION, PROFILES_PORT, TRACES_PORT,
};
use commonware_cryptography::{Hasher as _, Sha256};
use futures::{
    future::try_join_all,
    stream::{self, StreamExt, TryStreamExt},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::File,
    net::IpAddr,
    path::PathBuf,
    slice,
    time::Instant,
};
use tokio::process::Command;
use tracing::info;

/// Maximum number of instance IDs per DescribeInstances API call
const MAX_DESCRIBE_BATCH: usize = 1000;

/// Pre-signed URLs for tools per architecture
struct ToolUrls {
    docker: String,
    libjemalloc: String,
    logrotate: String,
}

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
    pub subnets: Vec<(String, String)>,
    pub az_support: BTreeMap<String, BTreeSet<String>>,
    pub binary_sg_id: Option<String>,
    pub monitoring_sg_id: Option<String>,
}

/// Validates storage options before create allocates AWS resources.
fn validate_storage_config(config: &Config) -> Result<(), Error> {
    // Treat monitoring and binary instances uniformly because both launch an EBS volume.
    let storage_configs = std::iter::once((
        MONITORING_NAME,
        config.monitoring.storage_class.as_str(),
        config.monitoring.storage_size,
        config.monitoring.storage_iops,
        config.monitoring.storage_throughput,
    ))
    .chain(config.instances.iter().map(|instance| {
        (
            instance.name.as_str(),
            instance.storage_class.as_str(),
            instance.storage_size,
            instance.storage_iops,
            instance.storage_throughput,
        )
    }));

    // Reject bad storage settings before key, S3, VPC, or instance resources are created.
    for (target, storage_class, storage_size, storage_iops, storage_throughput) in storage_configs {
        let storage_class = parse_storage_class(target, storage_class)?;
        validate_storage_options(
            target,
            &storage_class,
            storage_size,
            storage_iops,
            storage_throughput,
        )?;
    }
    Ok(())
}

/// Sets up EC2 instances, deploys files, and configures monitoring and logging
pub async fn create(config: &PathBuf, concurrency: usize) -> Result<(), Error> {
    // Load configuration from YAML file
    let config: Config = {
        let config_file = File::open(config)?;
        serde_yaml::from_reader(config_file)?
    };
    let tag = &config.tag;
    info!(tag = tag.as_str(), "loaded configuration");

    // Ensure no instance is duplicated or named MONITORING_NAME
    let mut instance_names = HashSet::new();
    for instance in &config.instances {
        if !instance_names.insert(&instance.name) {
            return Err(Error::DuplicateInstanceName(instance.name.clone()));
        }
        if instance.name == MONITORING_NAME {
            return Err(Error::InvalidInstanceName(instance.name.clone()));
        }
    }

    // Validate storage settings before allocating any AWS resources.
    validate_storage_config(&config)?;

    // Determine unique regions
    let mut regions: BTreeSet<String> = config.instances.iter().map(|i| i.region.clone()).collect();
    regions.insert(MONITORING_REGION.to_string());

    // Validate that all regions are enabled (before writing anything to disk)
    let ec2_client = ec2::create_client(Region::new(MONITORING_REGION)).await;
    let enabled_regions = ec2::get_enabled_regions(&ec2_client).await?;
    let disabled: Vec<_> = regions
        .iter()
        .filter(|r| !enabled_regions.contains(*r))
        .cloned()
        .collect();
    if !disabled.is_empty() {
        return Err(Error::RegionsNotEnabled(disabled));
    }
    info!(?regions, "validated all regions are enabled");

    // Create a temporary directory for local files
    let tag_directory = deployer_directory(Some(tag));
    if tag_directory.exists() {
        return Err(Error::CreationAttempted);
    }
    std::fs::create_dir_all(&tag_directory)?;
    info!(path = ?tag_directory, "created tag directory");

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

    // Persist deployment metadata early to enable `destroy --tag` on failure
    let metadata = Metadata {
        tag: tag.clone(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        regions: regions.iter().cloned().collect(),
        instance_count: config.instances.len(),
    };
    let metadata_file = File::create(tag_directory.join(METADATA_FILE_NAME))?;
    serde_yaml::to_writer(metadata_file, &metadata)?;
    info!("persisted deployment metadata");

    // Collect instance types by region (for availability zone selection) and unique types (for architecture detection)
    let mut instance_types_by_region: HashMap<String, HashSet<String>> = HashMap::new();
    let mut unique_instance_types: HashSet<String> = HashSet::new();
    instance_types_by_region
        .entry(MONITORING_REGION.to_string())
        .or_default()
        .insert(config.monitoring.instance_type.clone());
    unique_instance_types.insert(config.monitoring.instance_type.clone());
    for instance in &config.instances {
        instance_types_by_region
            .entry(instance.region.clone())
            .or_default()
            .insert(instance.instance_type.clone());
        unique_instance_types.insert(instance.instance_type.clone());
    }

    // Detect architecture for each unique instance type (architecture is global, not region-specific)
    info!("detecting architectures for instance types");
    let ec2_client = ec2::create_client(Region::new(MONITORING_REGION)).await;
    let mut arch_by_instance_type: HashMap<String, Architecture> = HashMap::new();
    for instance_type in &unique_instance_types {
        let arch = detect_architecture(&ec2_client, instance_type).await?;
        info!(
            architecture = %arch,
            instance_type = instance_type.as_str(),
            "detected architecture"
        );
        arch_by_instance_type.insert(instance_type.clone(), arch);
    }

    // Detect which binary instance types expose automatically attached EC2 NVMe instance store
    let binary_instance_types: BTreeSet<String> = config
        .instances
        .iter()
        .map(|instance| instance.instance_type.clone())
        .collect();
    let mut nvme_supported_by_instance_type = HashMap::new();
    for instance_type in &binary_instance_types {
        let supported = supports_nvme_instance_storage(&ec2_client, instance_type).await?;
        info!(
            instance_type = instance_type.as_str(),
            supported, "detected NVMe instance-store support"
        );
        nvme_supported_by_instance_type.insert(instance_type.clone(), supported);
    }

    // Build per-instance architecture map and collect architectures needed
    let monitoring_architecture = arch_by_instance_type[&config.monitoring.instance_type];
    let mut instance_architectures: HashMap<String, Architecture> = HashMap::new();
    let mut architectures_needed: HashSet<Architecture> = HashSet::new();
    architectures_needed.insert(monitoring_architecture);
    for instance in &config.instances {
        let arch = arch_by_instance_type[&instance.instance_type];
        instance_architectures.insert(instance.name.clone(), arch);
        architectures_needed.insert(arch);
    }

    // Setup S3 bucket and cache tools
    let bucket_name = get_bucket_name();
    info!(bucket = bucket_name.as_str(), "setting up S3 bucket");
    let s3_client = s3::create_client(Region::new(MONITORING_REGION)).await;
    ensure_bucket_exists(&s3_client, &bucket_name, MONITORING_REGION).await?;

    // Cache tools for each architecture needed
    info!("uploading tools to S3");
    let cache_tool = |s3_key: String, download_url: String| {
        let tag_directory = tag_directory.clone();
        let s3_client = s3_client.clone();
        let bucket_name = bucket_name.clone();
        async move {
            if object_exists(&s3_client, &bucket_name, &s3_key).await? {
                info!(key = s3_key.as_str(), "tool already in S3");
                return presign_url(&s3_client, &bucket_name, &s3_key, PRESIGN_DURATION).await;
            }
            info!(
                key = s3_key.as_str(),
                "tool not in S3, downloading and uploading"
            );
            let temp_path = tag_directory.join(s3_key.replace('/', "_"));
            download_file(&download_url, &temp_path).await?;
            let url = cache_and_presign(
                &s3_client,
                &bucket_name,
                &s3_key,
                UploadSource::File(&temp_path),
                PRESIGN_DURATION,
            )
            .await?;
            std::fs::remove_file(&temp_path)?;
            Ok::<_, Error>(url)
        }
    };

    let node_exporter_dashboard_url = cache_tool(
        grafana_node_exporter_dashboard_s3_key(GRAFANA_NODE_EXPORTER_DASHBOARD_VERSION),
        grafana_node_exporter_dashboard_download_url(GRAFANA_NODE_EXPORTER_DASHBOARD_VERSION),
    )
    .await?;
    let mut tool_urls_by_arch: HashMap<Architecture, ToolUrls> = HashMap::new();
    for arch in &architectures_needed {
        let [docker_url, libjemalloc_url, logrotate_url]: [String; 3] = try_join_all([
            cache_tool(
                docker_bin_s3_key(DOCKER_VERSION, *arch),
                docker_download_url(DOCKER_VERSION, *arch),
            ),
            cache_tool(
                libjemalloc_bin_s3_key(LIBJEMALLOC2_VERSION, *arch),
                libjemalloc_download_url(LIBJEMALLOC2_VERSION, *arch),
            ),
            cache_tool(
                logrotate_bin_s3_key(LOGROTATE_VERSION, *arch),
                logrotate_download_url(LOGROTATE_VERSION, *arch),
            ),
        ])
        .await?
        .try_into()
        .unwrap();
        tool_urls_by_arch.insert(
            *arch,
            ToolUrls {
                docker: docker_url,
                libjemalloc: libjemalloc_url,
                logrotate: logrotate_url,
            },
        );
    }
    info!("tools uploaded");

    // Cache required container images as `docker save` tarballs in S3 (one per architecture).
    // Instances `docker load` these via pre-signed URLs, so they never authenticate against a
    // registry. Distinct images are cached concurrently, but a single image's architectures are
    // cached sequentially: `docker pull --platform`/`docker save` share docker's per-tag local
    // image store, so caching two architectures of the same image at once would corrupt the save.
    info!("caching container images in S3");
    let mut arches_by_image: HashMap<&'static str, HashSet<Architecture>> = HashMap::new();
    for image in monitoring_images() {
        arches_by_image
            .entry(image)
            .or_default()
            .insert(monitoring_architecture);
    }
    for instance in &config.instances {
        let arch = arch_by_instance_type[&instance.instance_type];
        for image in binary_images() {
            arches_by_image.entry(image).or_default().insert(arch);
        }
    }
    let cached = try_join_all(arches_by_image.into_iter().map(|(image, arches)| {
        let s3_client = s3_client.clone();
        let bucket_name = bucket_name.clone();
        let tag_directory = tag_directory.clone();
        async move {
            let mut urls = Vec::new();
            for arch in arches {
                let url =
                    images::cache_image(&s3_client, &bucket_name, &tag_directory, image, arch)
                        .await?;
                urls.push((arch, image, url));
            }
            Ok::<_, Error>(urls)
        }
    }))
    .await?;
    let mut image_urls_by_arch: HashMap<Architecture, HashMap<&'static str, String>> =
        HashMap::new();
    for (arch, image, url) in cached.into_iter().flatten() {
        image_urls_by_arch
            .entry(arch)
            .or_default()
            .insert(image, url);
    }
    info!("container images cached in S3");

    // Upload unique binaries and configs to S3 (deduplicated by digest)
    info!("uploading unique binaries and configs to S3");
    let instance_file_urls =
        s3::upload_instance_files(&s3_client, &bucket_name, tag, &config.instances).await?;
    let instance_binary_urls = instance_file_urls.binary_urls;
    let instance_config_urls = instance_file_urls.config_urls;
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
                let ec2_client = ec2::create_client(Region::new(region.clone())).await;
                info!(region = region.as_str(), "created EC2 client");

                // Find which AZs support which instance types
                let az_support = find_az_instance_support(&ec2_client, &instance_types).await?;
                let mut azs: Vec<String> = az_support.keys().cloned().collect();
                azs.sort();
                info!(?azs, region = region.as_str(), "found availability zones");

                // Create VPC, IGW, route table
                let vpc_cidr = format!("10.{idx}.0.0/16");
                let vpc_id = create_vpc(&ec2_client, &vpc_cidr, &tag).await?;
                info!(
                    vpc = vpc_id.as_str(),
                    region = region.as_str(),
                    "created VPC"
                );
                let igw_id = create_and_attach_igw(&ec2_client, &vpc_id, &tag).await?;
                info!(
                    igw = igw_id.as_str(),
                    vpc = vpc_id.as_str(),
                    region = region.as_str(),
                    "created and attached IGW"
                );
                let route_table_id =
                    create_route_table(&ec2_client, &vpc_id, &igw_id, &tag).await?;
                info!(
                    route_table = route_table_id.as_str(),
                    vpc = vpc_id.as_str(),
                    region = region.as_str(),
                    "created route table"
                );

                // Create a subnet in each AZ concurrently
                let subnet_futures: Vec<_> = azs
                    .iter()
                    .enumerate()
                    .map(|(az_idx, az)| {
                        let ec2_client = ec2_client.clone();
                        let vpc_id = vpc_id.clone();
                        let route_table_id = route_table_id.clone();
                        let tag = tag.clone();
                        let az = az.clone();
                        let region = region.clone();
                        async move {
                            let subnet_cidr = format!("10.{idx}.{az_idx}.0/24");
                            let subnet_id = create_subnet(
                                &ec2_client,
                                &vpc_id,
                                &route_table_id,
                                &subnet_cidr,
                                &az,
                                &tag,
                            )
                            .await?;
                            info!(
                                subnet = subnet_id.as_str(),
                                az = az.as_str(),
                                region = region.as_str(),
                                "created subnet"
                            );
                            Ok::<(String, String), Error>((az, subnet_id))
                        }
                    })
                    .collect();
                let subnets = try_join_all(subnet_futures).await?;

                // Create monitoring security group in monitoring region
                let monitoring_sg_id = if region == MONITORING_REGION {
                    let sg_id =
                        create_security_group_monitoring(&ec2_client, &vpc_id, &deployer_ip, &tag)
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
                import_key_pair(&ec2_client, &key_name, &public_key).await?;
                info!(
                    key = key_name.as_str(),
                    region = region.as_str(),
                    "imported key pair"
                );

                info!(
                    vpc = vpc_id.as_str(),
                    subnet_count = subnets.len(),
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
                        subnets,
                        az_support,
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

    // Select AZs for grouped instances after subnets and AZ support are known.
    let availability_zone_groups =
        select_availability_zone_groups(&config.instances, &region_resources)?;

    // Create binary security groups (without monitoring IP - added later for parallel launch)
    info!("creating binary security groups");
    let binary_sg_futures: Vec<_> = region_resources
        .iter()
        .map(|(region, resources)| {
            let region = region.clone();
            let ec2_client = ec2_clients[&region].clone();
            let vpc_id = resources.vpc_id.clone();
            let deployer_ip = deployer_ip.clone();
            let tag = tag.clone();
            let ports = config.ports.clone();
            async move {
                let binary_sg_id =
                    create_security_group_binary(&ec2_client, &vpc_id, &deployer_ip, &tag, &ports)
                        .await?;
                info!(
                    sg = binary_sg_id.as_str(),
                    vpc = vpc_id.as_str(),
                    region = region.as_str(),
                    "created binary security group"
                );
                Ok::<_, Error>((region, binary_sg_id))
            }
        })
        .collect();
    for (region, binary_sg_id) in try_join_all(binary_sg_futures).await? {
        region_resources.get_mut(&region).unwrap().binary_sg_id = Some(binary_sg_id);
    }
    info!("created binary security groups");

    // Setup VPC peering connections concurrently
    info!("initializing VPC peering connections");
    let monitoring_region = MONITORING_REGION.to_string();
    let monitoring_resources = region_resources.get(&monitoring_region).unwrap();
    let monitoring_vpc_id = &monitoring_resources.vpc_id;
    let monitoring_cidr = &monitoring_resources.vpc_cidr;
    let monitoring_route_table_id = &monitoring_resources.route_table_id;
    let binary_regions: HashSet<String> =
        config.instances.iter().map(|i| i.region.clone()).collect();
    let peering_futures: Vec<_> = regions
        .iter()
        .filter(|region| *region != &monitoring_region && binary_regions.contains(*region))
        .map(|region| {
            let region = region.clone();
            let monitoring_ec2_client = ec2_clients[&monitoring_region].clone();
            let binary_ec2_client = ec2_clients[&region].clone();
            let monitoring_vpc_id = monitoring_vpc_id.clone();
            let monitoring_cidr = monitoring_cidr.clone();
            let monitoring_route_table_id = monitoring_route_table_id.clone();
            let binary_resources = region_resources.get(&region).unwrap();
            let binary_vpc_id = binary_resources.vpc_id.clone();
            let binary_cidr = binary_resources.vpc_cidr.clone();
            let binary_route_table_id = binary_resources.route_table_id.clone();
            let tag = tag.clone();
            async move {
                let peer_id = create_vpc_peering_connection(
                    &monitoring_ec2_client,
                    &monitoring_vpc_id,
                    &binary_vpc_id,
                    &region,
                    &tag,
                )
                .await?;
                info!(
                    peer = peer_id.as_str(),
                    monitoring = monitoring_vpc_id.as_str(),
                    binary = binary_vpc_id.as_str(),
                    region = region.as_str(),
                    "created VPC peering connection"
                );
                wait_for_vpc_peering_connection(&binary_ec2_client, &peer_id).await?;
                info!(
                    peer = peer_id.as_str(),
                    region = region.as_str(),
                    "VPC peering connection is available"
                );
                accept_vpc_peering_connection(&binary_ec2_client, &peer_id).await?;
                info!(
                    peer = peer_id.as_str(),
                    region = region.as_str(),
                    "accepted VPC peering connection"
                );
                add_route(
                    &monitoring_ec2_client,
                    &monitoring_route_table_id,
                    &binary_cidr,
                    &peer_id,
                )
                .await?;
                add_route(
                    &binary_ec2_client,
                    &binary_route_table_id,
                    &monitoring_cidr,
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
                Ok::<_, Error>(())
            }
        })
        .collect();
    try_join_all(peering_futures).await?;
    info!("initialized VPC peering connections");

    // Prepare launch configurations for all instances
    info!("launching instances");
    let monitoring_ec2_client = &ec2_clients[&monitoring_region];
    let monitoring_ami_id = find_latest_ami(monitoring_ec2_client, monitoring_architecture).await?;
    let monitoring_instance_type =
        InstanceType::try_parse(&config.monitoring.instance_type).expect("Invalid instance type");
    let monitoring_storage_class =
        parse_storage_class(MONITORING_NAME, &config.monitoring.storage_class)?;
    let monitoring_sg_id = monitoring_resources
        .monitoring_sg_id
        .as_ref()
        .unwrap()
        .clone();
    let monitoring_subnets = monitoring_resources.subnets.clone();
    let monitoring_az_support = monitoring_resources.az_support.clone();

    // Lookup AMI IDs for binary instances
    let mut ami_cache: HashMap<(String, Architecture), String> = HashMap::new();
    ami_cache.insert(
        (monitoring_region.clone(), monitoring_architecture),
        monitoring_ami_id.clone(),
    );
    info!(
        region = monitoring_region.as_str(),
        architecture = %monitoring_architecture,
        ami_id = monitoring_ami_id.as_str(),
        "selected AMI"
    );
    let mut binary_launch_configs = Vec::new();
    for instance in &config.instances {
        let region = instance.region.clone();
        let resources = region_resources.get(&region).unwrap();
        let ec2_client = ec2_clients.get(&region).unwrap();
        let arch = instance_architectures[&instance.name];
        let ami_id = match ami_cache.get(&(region.clone(), arch)) {
            Some(id) => id.clone(),
            None => {
                let id = find_latest_ami(ec2_client, arch).await?;
                ami_cache.insert((region.clone(), arch), id.clone());
                info!(
                    region = region.as_str(),
                    architecture = %arch,
                    ami_id = id.as_str(),
                    "selected AMI"
                );
                id
            }
        };
        binary_launch_configs.push((instance, ec2_client, resources, ami_id, arch));
    }

    // Launch monitoring instance (uses start_idx=0 since there's only one)
    let monitoring_launch_future = {
        let key_name = key_name.clone();
        let tag = tag.clone();
        let sg_id = monitoring_sg_id.clone();
        async move {
            let (mut ids, az) = launch_instances(
                monitoring_ec2_client,
                &monitoring_ami_id,
                monitoring_instance_type,
                config.monitoring.storage_size,
                monitoring_storage_class,
                config.monitoring.storage_iops,
                config.monitoring.storage_throughput,
                &key_name,
                &monitoring_subnets,
                &monitoring_az_support,
                0,
                &sg_id,
                1,
                MONITORING_NAME,
                &tag,
            )
            .await?;
            let instance_id = ids.remove(0);
            info!(
                instance_id = instance_id.as_str(),
                az = az.as_str(),
                "launched monitoring instance"
            );
            Ok::<String, Error>(instance_id)
        }
    };

    // Launch binary instances, distributing ungrouped instances across AZs by using instance index
    // as start_idx. Grouped instances receive a single-AZ subnet list from grouped_subnets so all
    // local group members stay colocated.
    let binary_launch_futures = binary_launch_configs.iter().enumerate().map(
        |(idx, (instance, ec2_client, resources, ami_id, _arch))| {
            let key_name = key_name.clone();
            let instance_type =
                InstanceType::try_parse(&instance.instance_type).expect("Invalid instance type");
            let binary_sg_id = resources.binary_sg_id.as_ref().unwrap();
            let tag = tag.clone();
            let instance_name = instance.name.clone();
            let region = instance.region.clone();
            let subnets = grouped_subnets(instance, resources, &availability_zone_groups);
            let az_support = resources.az_support.clone();
            async move {
                let storage_class = parse_storage_class(&instance.name, &instance.storage_class)?;
                let (mut ids, az) = launch_instances(
                    ec2_client,
                    ami_id,
                    instance_type,
                    instance.storage_size,
                    storage_class,
                    instance.storage_iops,
                    instance.storage_throughput,
                    &key_name,
                    &subnets,
                    &az_support,
                    idx,
                    binary_sg_id,
                    1,
                    &instance.name,
                    &tag,
                )
                .await?;
                let instance_id = ids.remove(0);
                info!(
                    instance_id = instance_id.as_str(),
                    instance = instance_name.as_str(),
                    az = az.as_str(),
                    "launched instance"
                );
                Ok::<(String, String, InstanceConfig), Error>((
                    instance_id,
                    region,
                    (*instance).clone(),
                ))
            }
        },
    );

    // Wait for all launches to complete (get instance IDs)
    let (monitoring_instance_id, binary_launches) = tokio::try_join!(
        monitoring_launch_future,
        try_join_all(binary_launch_futures)
    )?;
    info!("instances requested");

    // Group binary instances by region for batched DescribeInstances calls
    let mut instances_by_region: HashMap<String, Vec<(String, InstanceConfig)>> = HashMap::new();
    for (instance_id, region, instance_config) in binary_launches {
        instances_by_region
            .entry(region)
            .or_default()
            .push((instance_id, instance_config));
    }

    // Wait for instances to be running, batched by region
    let wait_futures = instances_by_region
        .into_iter()
        .flat_map(|(region, instances)| {
            let ec2_client = ec2_clients[&region].clone();
            instances
                .chunks(MAX_DESCRIBE_BATCH)
                .map(move |chunk| {
                    let ec2_client = ec2_client.clone();
                    let chunk: Vec<_> = chunk.to_vec();
                    let region = region.clone();
                    async move {
                        let instance_ids: Vec<String> =
                            chunk.iter().map(|(id, _)| id.clone()).collect();
                        let ips = wait_for_instances_running(&ec2_client, &instance_ids).await?;
                        info!(
                            region = region.as_str(),
                            count = chunk.len(),
                            "instances running in region"
                        );
                        let deployments: Vec<Deployment> = chunk
                            .into_iter()
                            .zip(ips)
                            .map(|((instance_id, instance_config), ip)| Deployment {
                                instance: instance_config,
                                id: instance_id,
                                ip,
                            })
                            .collect();
                        Ok::<Vec<Deployment>, Error>(deployments)
                    }
                })
                .collect::<Vec<_>>()
        });

    // Wait for monitoring instance and all binary instances in parallel
    let (monitoring_ips, binary_deployment_batches) = tokio::try_join!(
        async {
            wait_for_instances_running(
                monitoring_ec2_client,
                slice::from_ref(&monitoring_instance_id),
            )
            .await
            .map_err(Error::AwsEc2)
        },
        try_join_all(wait_futures)
    )?;
    let monitoring_ip = monitoring_ips[0].clone();
    let monitoring_private_ip =
        get_private_ip(monitoring_ec2_client, &monitoring_instance_id).await?;
    let deployments: Vec<Deployment> = binary_deployment_batches.into_iter().flatten().collect();
    info!(ip = monitoring_ip.as_str(), "monitoring instance running");
    info!("launched instances");

    // Add monitoring IP rules to binary security groups (for Prometheus scraping).
    // This happens after instance launch but before instance configuration, so there's
    // no window where Prometheus would try to scrape unconfigured instances.
    info!("adding monitoring ingress rules");
    for (region, resources) in region_resources.iter() {
        let binary_sg_id = resources.binary_sg_id.as_ref().unwrap();
        add_monitoring_ingress(&ec2_clients[region], binary_sg_id, &monitoring_ip).await?;
    }
    info!("added monitoring ingress rules");

    // Cache static config files globally (these don't change between deployments)
    info!("uploading config files to S3");
    let [
        datasources_url,
        all_yml_url,
        loki_yml_url,
        pyroscope_yml_url,
        tempo_yml_url,
        pyroscope_agent_service_url,
        pyroscope_agent_timer_url,
    ]: [String; 7] = try_join_all([
        cache_and_presign(&s3_client, &bucket_name, &grafana_datasources_s3_key(), UploadSource::Static(DATASOURCES_YML.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, &bucket_name, &grafana_dashboards_s3_key(), UploadSource::Static(ALL_YML.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, &bucket_name, &loki_config_s3_key(), UploadSource::Static(LOKI_CONFIG.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, &bucket_name, &pyroscope_config_s3_key(), UploadSource::Static(PYROSCOPE_CONFIG.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, &bucket_name, &tempo_config_s3_key(), UploadSource::Static(TEMPO_CONFIG.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, &bucket_name, &pyroscope_agent_service_s3_key(), UploadSource::Static(PYROSCOPE_AGENT_SERVICE.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, &bucket_name, &pyroscope_agent_timer_s3_key(), UploadSource::Static(PYROSCOPE_AGENT_TIMER.as_bytes()), PRESIGN_DURATION),
    ])
    .await?
    .try_into()
    .unwrap();

    // Cache binary_service per architecture
    let mut binary_service_urls_by_arch: HashMap<Architecture, String> = HashMap::new();
    for arch in &architectures_needed {
        let binary_service_content = binary_service(*arch);
        let temp_path = tag_directory.join(format!("binary-{}.service", arch.as_str()));
        std::fs::write(&temp_path, &binary_service_content)?;
        let binary_service_url = cache_and_presign(
            &s3_client,
            &bucket_name,
            &binary_service_s3_key_for_arch(*arch),
            UploadSource::File(&temp_path),
            PRESIGN_DURATION,
        )
        .await?;
        std::fs::remove_file(&temp_path)?;
        binary_service_urls_by_arch.insert(*arch, binary_service_url);
    }

    // Upload deployment-specific monitoring config files (deduplicated by digest)
    let instances: Vec<(&str, &str, &str, &str, bool)> = deployments
        .iter()
        .map(|d| {
            let arch = instance_architectures[&d.instance.name];
            (
                d.instance.name.as_str(),
                d.ip.as_str(),
                d.instance.region.as_str(),
                arch.as_str(),
                d.instance.metrics,
            )
        })
        .collect();
    let prom_config = generate_prometheus_config(&instances);
    let prom_digest = Sha256::hash(prom_config.as_bytes()).to_string();
    let prom_path = tag_directory.join("prometheus.yml");
    std::fs::write(&prom_path, &prom_config)?;
    let dashboard_path = std::path::PathBuf::from(&config.monitoring.dashboard);
    let dashboard_digest = hash_file(&dashboard_path).await?;
    let [prometheus_config_url, dashboard_url]: [String; 2] = try_join_all([
        cache_and_presign(
            &s3_client,
            &bucket_name,
            &monitoring_s3_key(tag, &prom_digest),
            UploadSource::File(&prom_path),
            PRESIGN_DURATION,
        ),
        cache_and_presign(
            &s3_client,
            &bucket_name,
            &monitoring_s3_key(tag, &dashboard_digest),
            UploadSource::File(&dashboard_path),
            PRESIGN_DURATION,
        ),
    ])
    .await?
    .try_into()
    .unwrap();

    // Generate hosts.yaml and upload once (shared by all instances)
    let hosts = Hosts {
        monitoring: Ips {
            public: monitoring_ip.clone().parse::<IpAddr>().unwrap(),
            private: monitoring_private_ip.clone().parse::<IpAddr>().unwrap(),
        },
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
    let hosts_digest = Sha256::hash(hosts_yaml.as_bytes()).to_string();
    let hosts_path = tag_directory.join("hosts.yaml");
    std::fs::write(&hosts_path, &hosts_yaml)?;
    let hosts_url = cache_and_presign(
        &s3_client,
        &bucket_name,
        &hosts_s3_key(tag, &hosts_digest),
        UploadSource::File(&hosts_path),
        PRESIGN_DURATION,
    )
    .await?;

    // Write per-instance config files locally and compute digests
    let mut promtail_digests: BTreeMap<String, std::path::PathBuf> = BTreeMap::new();
    let mut pyroscope_digests: BTreeMap<String, std::path::PathBuf> = BTreeMap::new();
    let mut instance_promtail_digest: HashMap<String, String> = HashMap::new();
    let mut instance_pyroscope_digest: HashMap<String, String> = HashMap::new();
    for deployment in &deployments {
        let instance = &deployment.instance;
        let ip = &deployment.ip;
        let arch = instance_architectures[&instance.name].as_str();

        let promtail_cfg = promtail_config(
            &monitoring_private_ip,
            &instance.name,
            ip,
            &instance.region,
            arch,
        );
        let promtail_digest = Sha256::hash(promtail_cfg.as_bytes()).to_string();
        let promtail_path = tag_directory.join(format!("promtail_{}.yml", instance.name));
        std::fs::write(&promtail_path, &promtail_cfg)?;

        let pyroscope_script = generate_pyroscope_script(
            &monitoring_private_ip,
            &instance.name,
            ip,
            &instance.region,
            arch,
        );
        let pyroscope_digest = Sha256::hash(pyroscope_script.as_bytes()).to_string();
        let pyroscope_path = tag_directory.join(format!("pyroscope-agent_{}.sh", instance.name));
        std::fs::write(&pyroscope_path, &pyroscope_script)?;

        promtail_digests
            .entry(promtail_digest.clone())
            .or_insert(promtail_path);
        pyroscope_digests
            .entry(pyroscope_digest.clone())
            .or_insert(pyroscope_path);
        instance_promtail_digest.insert(instance.name.clone(), promtail_digest);
        instance_pyroscope_digest.insert(instance.name.clone(), pyroscope_digest);
    }

    // Upload unique promtail and pyroscope configs
    let (promtail_digest_to_url, pyroscope_digest_to_url): (
        HashMap<String, String>,
        HashMap<String, String>,
    ) = tokio::try_join!(
        async {
            Ok::<_, Error>(
                try_join_all(promtail_digests.iter().map(|(digest, path)| {
                    let s3_client = s3_client.clone();
                    let bucket_name = bucket_name.clone();
                    let digest = digest.clone();
                    let key = promtail_s3_key(tag, &digest);
                    let path = path.clone();
                    async move {
                        let url = cache_and_presign(
                            &s3_client,
                            &bucket_name,
                            &key,
                            UploadSource::File(&path),
                            PRESIGN_DURATION,
                        )
                        .await?;
                        Ok::<_, Error>((digest, url))
                    }
                }))
                .await?
                .into_iter()
                .collect(),
            )
        },
        async {
            Ok::<_, Error>(
                try_join_all(pyroscope_digests.iter().map(|(digest, path)| {
                    let s3_client = s3_client.clone();
                    let bucket_name = bucket_name.clone();
                    let digest = digest.clone();
                    let key = pyroscope_s3_key(tag, &digest);
                    let path = path.clone();
                    async move {
                        let url = cache_and_presign(
                            &s3_client,
                            &bucket_name,
                            &key,
                            UploadSource::File(&path),
                            PRESIGN_DURATION,
                        )
                        .await?;
                        Ok::<_, Error>((digest, url))
                    }
                }))
                .await?
                .into_iter()
                .collect(),
            )
        },
    )?;

    // Build instance URLs map with architecture-specific tool URLs
    let mut instance_urls_map: HashMap<String, (InstanceUrls, Architecture)> = HashMap::new();
    for deployment in &deployments {
        let name = &deployment.instance.name;
        let arch = instance_architectures[name];
        let promtail_digest = &instance_promtail_digest[name];
        let pyroscope_digest = &instance_pyroscope_digest[name];
        let tool_urls = &tool_urls_by_arch[&arch];

        instance_urls_map.insert(
            name.clone(),
            (
                InstanceUrls {
                    binary: instance_binary_urls[name].clone(),
                    config: instance_config_urls[name].clone(),
                    hosts: hosts_url.clone(),
                    promtail_config: promtail_digest_to_url[promtail_digest].clone(),
                    binary_service: binary_service_urls_by_arch[&arch].clone(),
                    pyroscope_script: pyroscope_digest_to_url[pyroscope_digest].clone(),
                    pyroscope_service: pyroscope_agent_service_url.clone(),
                    pyroscope_timer: pyroscope_agent_timer_url.clone(),
                    docker_tgz: tool_urls.docker.clone(),
                    libjemalloc_deb: tool_urls.libjemalloc.clone(),
                    logrotate_deb: tool_urls.logrotate.clone(),
                    images: binary_images()
                        .map(|image| (image, image_urls_by_arch[&arch][image].clone()))
                        .collect(),
                },
                arch,
            ),
        );
    }
    info!("uploaded config files to S3");

    // Build monitoring URLs struct for SSH configuration
    let tool_urls = &tool_urls_by_arch[&monitoring_architecture];
    let monitoring_urls = MonitoringUrls {
        docker_tgz: tool_urls.docker.clone(),
        prometheus_config: prometheus_config_url,
        datasources_yml: datasources_url,
        all_yml: all_yml_url,
        dashboard: dashboard_url,
        node_exporter_dashboard: node_exporter_dashboard_url,
        loki_yml: loki_yml_url,
        pyroscope_yml: pyroscope_yml_url,
        tempo_yml: tempo_yml_url,
        images: monitoring_images()
            .map(|image| {
                (
                    image,
                    image_urls_by_arch[&monitoring_architecture][image].clone(),
                )
            })
            .collect(),
    };

    // Prepare binary instance configuration futures
    info!("configuring monitoring and binary instances");
    let binary_configs: Vec<_> = deployments
        .iter()
        .map(|deployment| {
            let instance = deployment.instance.clone();
            let deployment_id = deployment.id.clone();
            let ec2_client = ec2_clients[&instance.region].clone();
            let ip = deployment.ip.clone();
            let nvme = nvme_supported_by_instance_type[&instance.instance_type];
            let (urls, arch) = instance_urls_map.remove(&instance.name).unwrap();
            (instance, deployment_id, ec2_client, ip, urls, arch, nvme)
        })
        .collect();
    let binary_futures = binary_configs.into_iter().map(
        |(instance, deployment_id, ec2_client, ip, urls, arch, nvme)| async move {
            let start = Instant::now();

            wait_for_instances_ready(&ec2_client, slice::from_ref(&deployment_id)).await?;
            let deploy = format!("{:.1}s", start.elapsed().as_secs_f64());

            let download_start = Instant::now();
            if let Some(apt_cmd) = install_binary_apt_cmd(instance.profiling, nvme) {
                ssh_execute(private_key, &ip, &apt_cmd).await?;
            }
            if nvme {
                ssh_execute(private_key, &ip, &nvme_setup_cmd()).await?;
            }
            ssh_execute(private_key, &ip, &install_binary_download_cmd(&urls)).await?;
            let download = format!("{:.1}s", download_start.elapsed().as_secs_f64());

            let setup_start = Instant::now();
            ssh_execute(
                private_key,
                &ip,
                &install_binary_setup_cmd(instance.profiling, arch),
            )
            .await?;
            let setup = format!("{:.1}s", setup_start.elapsed().as_secs_f64());

            let start_time = Instant::now();
            poll_service_active(private_key, &ip, "binary").await?;
            for service in binary_image_services() {
                poll_service_active(private_key, &ip, service).await?;
            }
            let start_dur = format!("{:.1}s", start_time.elapsed().as_secs_f64());

            info!(
                ip,
                instance = instance.name.as_str(),
                deploy,
                download,
                setup,
                start = start_dur,
                "configured instance"
            );
            Ok::<String, Error>(ip)
        },
    );

    // Run monitoring and binary configuration in parallel
    let (_, all_binary_ips) = tokio::try_join!(
        async {
            // Configure monitoring instance
            let start = Instant::now();

            let monitoring_ec2_client = &ec2_clients[&monitoring_region];
            wait_for_instances_ready(
                monitoring_ec2_client,
                slice::from_ref(&monitoring_instance_id),
            )
            .await?;
            let deploy = format!("{:.1}s", start.elapsed().as_secs_f64());

            let download_start = Instant::now();
            ssh_execute(
                private_key,
                &monitoring_ip,
                &install_monitoring_download_cmd(&monitoring_urls),
            )
            .await?;
            let download = format!("{:.1}s", download_start.elapsed().as_secs_f64());

            let setup_start = Instant::now();
            ssh_execute(private_key, &monitoring_ip, &install_monitoring_setup_cmd()).await?;
            ssh_execute(
                private_key,
                &monitoring_ip,
                &start_monitoring_services_cmd(),
            )
            .await?;
            let setup = format!("{:.1}s", setup_start.elapsed().as_secs_f64());

            let start_time = Instant::now();
            for service in monitoring_image_services() {
                poll_service_active(private_key, &monitoring_ip, service).await?;
            }
            let start_dur = format!("{:.1}s", start_time.elapsed().as_secs_f64());

            info!(
                ip = monitoring_ip.as_str(),
                deploy,
                download,
                setup,
                start = start_dur,
                "configured monitoring instance"
            );
            Ok::<(), Error>(())
        },
        async {
            // Configure binary instances (limited concurrency to avoid SSH overload)
            let all_binary_ips: Vec<String> = stream::iter(binary_futures)
                .buffer_unordered(concurrency)
                .try_collect()
                .await?;
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

/// Region-scoped availability zone group identifier.
///
/// Group names are intentionally scoped by region because subnets and AZ support are region-local.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct AvailabilityZoneGroupKey {
    region: String,
    group: String,
}

/// Selects one mutually-supported AZ for each region/group pair.
///
/// The returned AZ supports every instance type used by the group in that region. Reusing the
/// same group name in another region produces a separate selection.
fn select_availability_zone_groups(
    instances: &[InstanceConfig],
    resources: &HashMap<String, RegionResources>,
) -> Result<HashMap<AvailabilityZoneGroupKey, String>, Error> {
    // Collect the instance types per region/group pair so the same group name can be reused
    // independently in different regions.
    let mut groups: HashMap<AvailabilityZoneGroupKey, BTreeSet<String>> = HashMap::new();
    for instance in instances {
        let Some(group) = &instance.availability_zone_group else {
            continue;
        };
        groups
            .entry(AvailabilityZoneGroupKey {
                region: instance.region.clone(),
                group: group.clone(),
            })
            .or_default()
            .insert(instance.instance_type.clone());
    }

    let mut selected = HashMap::new();
    for (key, instance_types) in groups {
        let resources = resources
            .get(&key.region)
            .expect("region resources initialized for instance region");
        let az = select_group_availability_zone(resources, &instance_types).ok_or_else(|| {
            Error::AvailabilityZoneGroupUnsupported {
                region: key.region.clone(),
                group: key.group.clone(),
                instance_types: instance_types.iter().cloned().collect(),
            }
        })?;
        info!(
            region = key.region.as_str(),
            group = key.group.as_str(),
            az = az.as_str(),
            ?instance_types,
            "selected availability zone group"
        );
        selected.insert(key, az);
    }
    Ok(selected)
}

/// Returns the first subnet AZ that supports every requested instance type.
fn select_group_availability_zone(
    resources: &RegionResources,
    instance_types: &BTreeSet<String>,
) -> Option<String> {
    resources
        .subnets
        .iter()
        .map(|(az, _)| az)
        .find(|az| {
            resources
                .az_support
                .get(*az)
                .is_some_and(|supported| instance_types.is_subset(supported))
        })
        .cloned()
}

/// Returns the subnets an instance may launch into.
///
/// Ungrouped instances can use any region subnet. Grouped instances are restricted to their
/// selected AZ so all members of the local region/group stay colocated.
fn grouped_subnets(
    instance: &InstanceConfig,
    resources: &RegionResources,
    groups: &HashMap<AvailabilityZoneGroupKey, String>,
) -> Vec<(String, String)> {
    let Some(group) = &instance.availability_zone_group else {
        return resources.subnets.clone();
    };
    let az = groups
        .get(&AvailabilityZoneGroupKey {
            region: instance.region.clone(),
            group: group.clone(),
        })
        .expect("availability zone group selected before launch");
    resources
        .subnets
        .iter()
        .filter(|(subnet_az, _)| subnet_az == az)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        grouped_subnets, select_availability_zone_groups, select_group_availability_zone,
        validate_storage_config, RegionResources,
    };
    use crate::aws::{Config, Error, InstanceConfig, MonitoringConfig};
    use std::collections::{BTreeSet, HashMap};

    fn instance(
        name: &str,
        region: &str,
        instance_type: &str,
        group: Option<&str>,
    ) -> InstanceConfig {
        InstanceConfig {
            name: name.to_string(),
            region: region.to_string(),
            availability_zone_group: group.map(str::to_string),
            instance_type: instance_type.to_string(),
            storage_size: 10,
            storage_class: "gp3".to_string(),
            storage_iops: None,
            storage_throughput: None,
            binary: "binary".to_string(),
            config: "config.yaml".to_string(),
            metrics: true,
            profiling: false,
        }
    }

    fn config(monitoring: MonitoringConfig, instances: Vec<InstanceConfig>) -> Config {
        Config {
            tag: "tag".to_string(),
            monitoring,
            instances,
            ports: Vec::new(),
        }
    }

    fn monitoring(storage_class: &str, storage_iops: Option<i32>) -> MonitoringConfig {
        MonitoringConfig {
            instance_type: "c8g.4xlarge".to_string(),
            storage_size: 10,
            storage_class: storage_class.to_string(),
            storage_iops,
            storage_throughput: None,
            dashboard: "dashboard.json".to_string(),
        }
    }

    fn resources_in(region: &str) -> RegionResources {
        RegionResources {
            vpc_id: "vpc".to_string(),
            vpc_cidr: "10.0.0.0/16".to_string(),
            route_table_id: "rt".to_string(),
            subnets: vec![
                (format!("{region}a"), "subnet-a".to_string()),
                (format!("{region}b"), "subnet-b".to_string()),
            ],
            az_support: HashMap::from([
                (
                    format!("{region}a"),
                    BTreeSet::from(["c8g.4xlarge".to_string()]),
                ),
                (
                    format!("{region}b"),
                    BTreeSet::from(["c8g.4xlarge".to_string(), "c8g.2xlarge".to_string()]),
                ),
            ])
            .into_iter()
            .collect(),
            binary_sg_id: None,
            monitoring_sg_id: None,
        }
    }

    #[test]
    fn monitoring_io2_requires_storage_iops() {
        let cfg = config(monitoring("io2", None), Vec::new());

        let err = validate_storage_config(&cfg).expect_err("io2 requires storage_iops");

        assert!(matches!(
            err,
            Error::MissingStorageIops {
                target,
                storage_class,
            } if target == "monitoring" && storage_class == "io2"
        ));
    }

    #[test]
    fn instance_io1_requires_storage_iops() {
        let mut instance = instance("worker", "us-east-1", "c8g.4xlarge", None);
        instance.storage_class = "io1".to_string();
        let cfg = config(monitoring("gp3", None), vec![instance]);

        let err = validate_storage_config(&cfg).expect_err("io1 requires storage_iops");

        assert!(matches!(
            err,
            Error::MissingStorageIops {
                target,
                storage_class,
            } if target == "worker" && storage_class == "io1"
        ));
    }

    #[test]
    fn gp3_storage_iops_must_be_in_range() {
        let cfg = config(monitoring("gp3", Some(0)), Vec::new());

        let err = validate_storage_config(&cfg).expect_err("gp3 storage_iops is too low");

        assert!(matches!(
            err,
            Error::InvalidStorageIops {
                target,
                storage_class,
                storage_iops,
            } if target == "monitoring" && storage_class == "gp3" && storage_iops == 0
        ));
    }

    #[test]
    fn io1_storage_iops_must_be_in_range() {
        let mut instance = instance("worker", "us-east-1", "c8g.4xlarge", None);
        instance.storage_class = "io1".to_string();
        instance.storage_iops = Some(64_001);
        let cfg = config(monitoring("gp3", None), vec![instance]);

        let err = validate_storage_config(&cfg).expect_err("io1 storage_iops is too high");

        assert!(matches!(
            err,
            Error::InvalidStorageIops {
                target,
                storage_class,
                storage_iops,
            } if target == "worker" && storage_class == "io1" && storage_iops == 64_001
        ));
    }

    #[test]
    fn io1_storage_iops_are_capped_by_storage_size() {
        let mut instance = instance("worker", "us-east-1", "c8g.4xlarge", None);
        instance.storage_class = "io1".to_string();
        instance.storage_size = 10;
        instance.storage_iops = Some(64_000);
        let cfg = config(monitoring("gp3", None), vec![instance]);

        let err = validate_storage_config(&cfg).expect_err("io1 storage_iops exceeds size ratio");

        assert!(matches!(
            err,
            Error::InvalidStorageIops {
                target,
                storage_class,
                storage_iops,
            } if target == "worker" && storage_class == "io1" && storage_iops == 64_000
        ));
    }

    #[test]
    fn io2_storage_iops_must_be_in_range() {
        let cfg = config(monitoring("io2", Some(256_001)), Vec::new());

        let err = validate_storage_config(&cfg).expect_err("io2 storage_iops is too high");

        assert!(matches!(
            err,
            Error::InvalidStorageIops {
                target,
                storage_class,
                storage_iops,
            } if target == "monitoring" && storage_class == "io2" && storage_iops == 256_001
        ));
    }

    #[test]
    fn unsupported_storage_class_rejects_storage_iops() {
        let cfg = config(monitoring("gp2", Some(3_000)), Vec::new());

        let err = validate_storage_config(&cfg).expect_err("gp2 does not accept storage_iops");

        assert!(matches!(
            err,
            Error::InvalidStorageIops {
                target,
                storage_class,
                storage_iops,
            } if target == "monitoring" && storage_class == "gp2" && storage_iops == 3_000
        ));
    }

    #[test]
    fn gp3_does_not_require_storage_iops() {
        let cfg = config(
            monitoring("gp3", None),
            vec![instance("worker", "us-east-1", "c8g.4xlarge", None)],
        );

        validate_storage_config(&cfg).expect("gp3 has default IOPS");
    }

    #[test]
    fn io2_accepts_storage_iops() {
        let cfg = config(monitoring("io2", Some(10_000)), Vec::new());

        validate_storage_config(&cfg).expect("io2 with storage_iops is valid");
    }

    // Throughput validation covers the gp3-only API field and gp3 ratio limits.
    #[test]
    fn storage_throughput_must_be_in_gp3_range() {
        let mut monitoring = monitoring("gp3", None);
        monitoring.storage_throughput = Some(124);
        let cfg = config(monitoring, Vec::new());

        let err = validate_storage_config(&cfg).expect_err("storage_throughput is too low");

        assert!(matches!(
            err,
            Error::InvalidStorageThroughput {
                target,
                storage_throughput,
            } if target == "monitoring" && storage_throughput == 124
        ));
    }

    #[test]
    fn storage_throughput_requires_gp3() {
        let mut instance = instance("worker", "us-east-1", "c8g.4xlarge", None);
        instance.storage_class = "io2".to_string();
        instance.storage_iops = Some(10_000);
        instance.storage_throughput = Some(250);
        let cfg = config(monitoring("gp3", None), vec![instance]);

        let err = validate_storage_config(&cfg).expect_err("throughput is only valid for gp3");

        assert!(matches!(
            err,
            Error::UnsupportedStorageThroughput {
                target,
                storage_class,
            } if target == "worker" && storage_class == "io2"
        ));
    }

    #[test]
    fn gp3_accepts_storage_throughput() {
        let mut monitoring = monitoring("gp3", None);
        monitoring.storage_throughput = Some(250);
        let cfg = config(monitoring, Vec::new());

        validate_storage_config(&cfg).expect("gp3 throughput is valid");
    }

    #[test]
    fn gp3_storage_throughput_is_capped_by_iops() {
        let mut monitoring = monitoring("gp3", None);
        monitoring.storage_throughput = Some(2_000);
        let cfg = config(monitoring, Vec::new());

        let err = validate_storage_config(&cfg).expect_err("gp3 throughput exceeds default IOPS");

        assert!(matches!(
            err,
            Error::InvalidStorageThroughput {
                target,
                storage_throughput,
            } if target == "monitoring" && storage_throughput == 2_000
        ));
    }

    #[test]
    fn az_group_selects_mutually_supported_zone() {
        let resources = resources_in("us-east-1");
        let requested = BTreeSet::from(["c8g.4xlarge".to_string(), "c8g.2xlarge".to_string()]);

        let az = select_group_availability_zone(&resources, &requested)
            .expect("one AZ supports every requested type");

        assert_eq!(az, "us-east-1b");
    }

    #[test]
    fn grouped_instances_are_restricted_to_selected_subnet() {
        let instances = vec![
            instance(
                "chain-indexer",
                "us-east-1",
                "c8g.4xlarge",
                Some("indexers"),
            ),
            instance(
                "metadata-indexer",
                "us-east-1",
                "c8g.2xlarge",
                Some("indexers"),
            ),
        ];
        let resources = HashMap::from([("us-east-1".to_string(), resources_in("us-east-1"))]);
        let groups = select_availability_zone_groups(&instances, &resources)
            .expect("group should have a mutually-supported AZ");

        let subnets = grouped_subnets(&instances[0], &resources["us-east-1"], &groups);

        assert_eq!(
            subnets,
            vec![("us-east-1b".to_string(), "subnet-b".to_string())]
        );
    }

    #[test]
    fn ungrouped_instances_keep_all_subnets() {
        let resources = resources_in("us-east-1");
        let instance = instance("worker", "us-east-1", "c8g.4xlarge", None);

        let subnets = grouped_subnets(&instance, &resources, &HashMap::new());

        assert_eq!(subnets, resources.subnets);
    }

    #[test]
    fn group_without_mutually_supported_zone_is_rejected() {
        let instances = vec![
            instance(
                "chain-indexer",
                "us-east-1",
                "c8g.4xlarge",
                Some("indexers"),
            ),
            instance(
                "metadata-indexer",
                "us-east-1",
                "m8g.large",
                Some("indexers"),
            ),
        ];
        let resources = HashMap::from([("us-east-1".to_string(), resources_in("us-east-1"))]);

        let err = select_availability_zone_groups(&instances, &resources)
            .expect_err("group should require one AZ supporting every instance type");

        assert!(matches!(
            err,
            Error::AvailabilityZoneGroupUnsupported {
                region,
                group,
                instance_types,
            } if region == "us-east-1"
                && group == "indexers"
                && instance_types == vec!["c8g.4xlarge".to_string(), "m8g.large".to_string()]
        ));
    }

    #[test]
    fn group_name_can_be_reused_across_regions() {
        let instances = vec![
            instance(
                "chain-indexer",
                "us-east-1",
                "c8g.4xlarge",
                Some("indexers"),
            ),
            instance(
                "metadata-indexer",
                "us-west-2",
                "c8g.4xlarge",
                Some("indexers"),
            ),
        ];
        let resources = HashMap::from([
            ("us-east-1".to_string(), resources_in("us-east-1")),
            ("us-west-2".to_string(), resources_in("us-west-2")),
        ]);

        let groups = select_availability_zone_groups(&instances, &resources)
            .expect("same group name in different regions should be independent");

        let east_subnets = grouped_subnets(&instances[0], &resources["us-east-1"], &groups);
        let west_subnets = grouped_subnets(&instances[1], &resources["us-west-2"], &groups);

        assert_eq!(
            east_subnets,
            vec![("us-east-1a".to_string(), "subnet-a".to_string())]
        );
        assert_eq!(
            west_subnets,
            vec![("us-west-2a".to_string(), "subnet-a".to_string())]
        );
    }
}
