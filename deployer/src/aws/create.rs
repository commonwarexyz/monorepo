//! `create` subcommand for `ec2`

use crate::aws::{
    deployer_directory,
    ec2::{self, *},
    s3::{self, *},
    services::*,
    utils::*,
    Architecture, Config, Error, Host, Hosts, InstanceConfig, Metadata, CREATED_FILE_NAME,
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

/// Pre-signed URLs for observability tools per architecture
struct ToolUrls {
    prometheus: String,
    grafana: String,
    loki: String,
    pyroscope: String,
    tempo: String,
    node_exporter: String,
    promtail: String,
    libjemalloc: String,
    logrotate: String,
    jq: String,
    libfontconfig: String,
    unzip: String,
    adduser: String,
    musl: String,
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

/// Sets up EC2 instances, deploys files, and configures monitoring and logging
pub async fn create(config: &PathBuf, concurrency: usize) -> Result<(), Error> {
    // Load configuration from YAML file
    let config: Config = {
        let config_file = File::open(config)?;
        serde_yaml::from_reader(config_file)?
    };
    let tag = &config.tag;
    info!(tag = tag.as_str(), "loaded configuration");

    // Create a temporary directory for local files
    let tag_directory = deployer_directory(Some(tag));
    if tag_directory.exists() {
        return Err(Error::CreationAttempted);
    }
    std::fs::create_dir_all(&tag_directory)?;
    info!(path = ?tag_directory, "created tag directory");

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

    // Setup S3 bucket and cache observability tools
    info!(bucket = BUCKET_NAME, "setting up S3 bucket");
    let s3_client = s3::create_client(Region::new(MONITORING_REGION)).await;
    ensure_bucket_exists(&s3_client, BUCKET_NAME, MONITORING_REGION).await?;

    // Cache observability tools for each architecture needed
    info!("uploading observability tools to S3");
    let cache_tool = |s3_key: String, download_url: String| {
        let tag_directory = tag_directory.clone();
        let s3_client = s3_client.clone();
        async move {
            if object_exists(&s3_client, BUCKET_NAME, &s3_key).await? {
                info!(key = s3_key.as_str(), "tool already in S3");
                return presign_url(&s3_client, BUCKET_NAME, &s3_key, PRESIGN_DURATION).await;
            }
            info!(
                key = s3_key.as_str(),
                "tool not in S3, downloading and uploading"
            );
            let temp_path = tag_directory.join(s3_key.replace('/', "_"));
            download_file(&download_url, &temp_path).await?;
            let url = cache_and_presign(
                &s3_client,
                BUCKET_NAME,
                &s3_key,
                UploadSource::File(&temp_path),
                PRESIGN_DURATION,
            )
            .await?;
            std::fs::remove_file(&temp_path)?;
            Ok::<_, Error>(url)
        }
    };

    // Cache adduser (arch-independent) once before the loop
    let adduser_url = cache_tool(
        adduser_bin_s3_key(ADDUSER_VERSION),
        adduser_download_url(ADDUSER_VERSION),
    )
    .await?;

    // Cache tools for each architecture and store URLs per-architecture
    let mut tool_urls_by_arch: HashMap<Architecture, ToolUrls> = HashMap::new();
    for arch in &architectures_needed {
        let [prometheus_url, grafana_url, loki_url, pyroscope_url, tempo_url, node_exporter_url, promtail_url,
             libjemalloc_url, logrotate_url, jq_url, libfontconfig_url, unzip_url, musl_url]: [String; 13] =
            try_join_all([
                cache_tool(prometheus_bin_s3_key(PROMETHEUS_VERSION, *arch), prometheus_download_url(PROMETHEUS_VERSION, *arch)),
                cache_tool(grafana_bin_s3_key(GRAFANA_VERSION, *arch), grafana_download_url(GRAFANA_VERSION, *arch)),
                cache_tool(loki_bin_s3_key(LOKI_VERSION, *arch), loki_download_url(LOKI_VERSION, *arch)),
                cache_tool(pyroscope_bin_s3_key(PYROSCOPE_VERSION, *arch), pyroscope_download_url(PYROSCOPE_VERSION, *arch)),
                cache_tool(tempo_bin_s3_key(TEMPO_VERSION, *arch), tempo_download_url(TEMPO_VERSION, *arch)),
                cache_tool(node_exporter_bin_s3_key(NODE_EXPORTER_VERSION, *arch), node_exporter_download_url(NODE_EXPORTER_VERSION, *arch)),
                cache_tool(promtail_bin_s3_key(PROMTAIL_VERSION, *arch), promtail_download_url(PROMTAIL_VERSION, *arch)),
                cache_tool(libjemalloc_bin_s3_key(LIBJEMALLOC2_VERSION, *arch), libjemalloc_download_url(LIBJEMALLOC2_VERSION, *arch)),
                cache_tool(logrotate_bin_s3_key(LOGROTATE_VERSION, *arch), logrotate_download_url(LOGROTATE_VERSION, *arch)),
                cache_tool(jq_bin_s3_key(JQ_VERSION, *arch), jq_download_url(JQ_VERSION, *arch)),
                cache_tool(libfontconfig_bin_s3_key(LIBFONTCONFIG1_VERSION, *arch), libfontconfig_download_url(LIBFONTCONFIG1_VERSION, *arch)),
                cache_tool(unzip_bin_s3_key(UNZIP_VERSION, *arch), unzip_download_url(UNZIP_VERSION, *arch)),
                cache_tool(musl_bin_s3_key(MUSL_VERSION, *arch), musl_download_url(MUSL_VERSION, *arch)),
            ])
            .await?
            .try_into()
            .unwrap();
        tool_urls_by_arch.insert(
            *arch,
            ToolUrls {
                prometheus: prometheus_url,
                grafana: grafana_url,
                loki: loki_url,
                pyroscope: pyroscope_url,
                tempo: tempo_url,
                node_exporter: node_exporter_url,
                promtail: promtail_url,
                libjemalloc: libjemalloc_url,
                logrotate: logrotate_url,
                jq: jq_url,
                libfontconfig: libfontconfig_url,
                unzip: unzip_url,
                adduser: adduser_url.clone(),
                musl: musl_url,
            },
        );
    }
    info!("observability tools uploaded");

    // Collect unique binary and config paths (dedup before hashing)
    let mut unique_binary_paths: BTreeSet<String> = BTreeSet::new();
    let mut unique_config_paths: BTreeSet<String> = BTreeSet::new();
    for instance in &config.instances {
        unique_binary_paths.insert(instance.binary.clone());
        unique_config_paths.insert(instance.config.clone());
    }

    // Compute digests concurrently for unique files only
    let unique_paths: Vec<String> = unique_binary_paths
        .iter()
        .chain(unique_config_paths.iter())
        .cloned()
        .collect();
    let path_to_digest = hash_files(unique_paths).await?;

    // Build dedup maps from digests
    let mut binary_digests: BTreeMap<String, String> = BTreeMap::new(); // digest -> path
    let mut config_digests: BTreeMap<String, String> = BTreeMap::new(); // digest -> path
    let mut instance_binary_digest: HashMap<String, String> = HashMap::new(); // instance -> digest
    let mut instance_config_digest: HashMap<String, String> = HashMap::new(); // instance -> digest
    for instance in &config.instances {
        let binary_digest = path_to_digest[&instance.binary].clone();
        let config_digest = path_to_digest[&instance.config].clone();
        binary_digests.insert(binary_digest.clone(), instance.binary.clone());
        config_digests.insert(config_digest.clone(), instance.config.clone());
        instance_binary_digest.insert(instance.name.clone(), binary_digest);
        instance_config_digest.insert(instance.name.clone(), config_digest);
    }

    // Upload unique binaries and configs to S3 (deduplicated by digest)
    info!("uploading unique binaries and configs to S3");
    let (binary_digest_to_url, config_digest_to_url): (
        HashMap<String, String>,
        HashMap<String, String>,
    ) = tokio::try_join!(
        async {
            Ok::<_, Error>(
                try_join_all(binary_digests.iter().map(|(digest, path)| {
                    let s3_client = s3_client.clone();
                    let digest = digest.clone();
                    let key = binary_s3_key(tag, &digest);
                    let path = path.clone();
                    async move {
                        let url = cache_and_presign(
                            &s3_client,
                            BUCKET_NAME,
                            &key,
                            UploadSource::File(path.as_ref()),
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
                try_join_all(config_digests.iter().map(|(digest, path)| {
                    let s3_client = s3_client.clone();
                    let digest = digest.clone();
                    let key = config_s3_key(tag, &digest);
                    let path = path.clone();
                    async move {
                        let url = cache_and_presign(
                            &s3_client,
                            BUCKET_NAME,
                            &key,
                            UploadSource::File(path.as_ref()),
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

    // Map instance names to URLs via their digests
    let mut instance_binary_urls: HashMap<String, String> = HashMap::new();
    let mut instance_config_urls: HashMap<String, String> = HashMap::new();
    for instance in &config.instances {
        let binary_digest = &instance_binary_digest[&instance.name];
        let config_digest = &instance_config_digest[&instance.name];
        instance_binary_urls.insert(
            instance.name.clone(),
            binary_digest_to_url[binary_digest].clone(),
        );
        instance_config_urls.insert(
            instance.name.clone(),
            config_digest_to_url[config_digest].clone(),
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
        VolumeType::try_parse(&config.monitoring.storage_class).expect("Invalid storage class");
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

    // Launch binary instances, distributing across AZs by using instance index as start_idx
    let binary_launch_futures = binary_launch_configs.iter().enumerate().map(
        |(idx, (instance, ec2_client, resources, ami_id, _arch))| {
            let key_name = key_name.clone();
            let instance_type =
                InstanceType::try_parse(&instance.instance_type).expect("Invalid instance type");
            let storage_class =
                VolumeType::try_parse(&instance.storage_class).expect("Invalid storage class");
            let binary_sg_id = resources.binary_sg_id.as_ref().unwrap();
            let tag = tag.clone();
            let instance_name = instance.name.clone();
            let region = instance.region.clone();
            let subnets = resources.subnets.clone();
            let az_support = resources.az_support.clone();
            async move {
                let (mut ids, az) = launch_instances(
                    ec2_client,
                    ami_id,
                    instance_type,
                    instance.storage_size,
                    storage_class,
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
        prometheus_service_url,
        loki_service_url,
        pyroscope_service_url,
        tempo_service_url,
        monitoring_node_exporter_service_url,
        promtail_service_url,
        logrotate_conf_url,
        pyroscope_agent_service_url,
        pyroscope_agent_timer_url,
    ]: [String; 14] = try_join_all([
        cache_and_presign(&s3_client, BUCKET_NAME, &grafana_datasources_s3_key(), UploadSource::Static(DATASOURCES_YML.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &grafana_dashboards_s3_key(), UploadSource::Static(ALL_YML.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &loki_config_s3_key(), UploadSource::Static(LOKI_CONFIG.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &pyroscope_config_s3_key(), UploadSource::Static(PYROSCOPE_CONFIG.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &tempo_config_s3_key(), UploadSource::Static(TEMPO_CONFIG.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &prometheus_service_s3_key(), UploadSource::Static(PROMETHEUS_SERVICE.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &loki_service_s3_key(), UploadSource::Static(LOKI_SERVICE.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &pyroscope_service_s3_key(), UploadSource::Static(PYROSCOPE_SERVICE.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &tempo_service_s3_key(), UploadSource::Static(TEMPO_SERVICE.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &node_exporter_service_s3_key(), UploadSource::Static(NODE_EXPORTER_SERVICE.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &promtail_service_s3_key(), UploadSource::Static(PROMTAIL_SERVICE.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &logrotate_config_s3_key(), UploadSource::Static(LOGROTATE_CONF.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &pyroscope_agent_service_s3_key(), UploadSource::Static(PYROSCOPE_AGENT_SERVICE.as_bytes()), PRESIGN_DURATION),
        cache_and_presign(&s3_client, BUCKET_NAME, &pyroscope_agent_timer_s3_key(), UploadSource::Static(PYROSCOPE_AGENT_TIMER.as_bytes()), PRESIGN_DURATION),
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
            BUCKET_NAME,
            &binary_service_s3_key_for_arch(*arch),
            UploadSource::File(&temp_path),
            PRESIGN_DURATION,
        )
        .await?;
        std::fs::remove_file(&temp_path)?;
        binary_service_urls_by_arch.insert(*arch, binary_service_url);
    }

    // Upload deployment-specific monitoring config files (deduplicated by digest)
    let instances: Vec<(&str, &str, &str, &str)> = deployments
        .iter()
        .map(|d| {
            let arch = instance_architectures[&d.instance.name];
            (
                d.instance.name.as_str(),
                d.ip.as_str(),
                d.instance.region.as_str(),
                arch.as_str(),
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
            BUCKET_NAME,
            &monitoring_s3_key(tag, &prom_digest),
            UploadSource::File(&prom_path),
            PRESIGN_DURATION,
        ),
        cache_and_presign(
            &s3_client,
            BUCKET_NAME,
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
    let hosts_digest = Sha256::hash(hosts_yaml.as_bytes()).to_string();
    let hosts_path = tag_directory.join("hosts.yaml");
    std::fs::write(&hosts_path, &hosts_yaml)?;
    let hosts_url = cache_and_presign(
        &s3_client,
        BUCKET_NAME,
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
                    let digest = digest.clone();
                    let key = promtail_s3_key(tag, &digest);
                    let path = path.clone();
                    async move {
                        let url = cache_and_presign(
                            &s3_client,
                            BUCKET_NAME,
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
                    let digest = digest.clone();
                    let key = pyroscope_s3_key(tag, &digest);
                    let path = path.clone();
                    async move {
                        let url = cache_and_presign(
                            &s3_client,
                            BUCKET_NAME,
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

    // Build instance URLs map (using architecture-specific tool URLs)
    let mut instance_urls_map: HashMap<String, (InstanceUrls, Architecture)> = HashMap::new();
    for deployment in &deployments {
        let name = &deployment.instance.name;
        let arch = instance_architectures[name];
        let promtail_digest = &instance_promtail_digest[name];
        let pyroscope_digest = &instance_pyroscope_digest[name];
        let tool_urls = &tool_urls_by_arch[&arch];
        let jq_deb = if deployment.instance.profiling {
            Some(tool_urls.jq.clone())
        } else {
            None
        };

        instance_urls_map.insert(
            name.clone(),
            (
                InstanceUrls {
                    binary: instance_binary_urls[name].clone(),
                    config: instance_config_urls[name].clone(),
                    hosts: hosts_url.clone(),
                    promtail_bin: tool_urls.promtail.clone(),
                    promtail_config: promtail_digest_to_url[promtail_digest].clone(),
                    promtail_service: promtail_service_url.clone(),
                    node_exporter_bin: tool_urls.node_exporter.clone(),
                    node_exporter_service: monitoring_node_exporter_service_url.clone(),
                    binary_service: binary_service_urls_by_arch[&arch].clone(),
                    logrotate_conf: logrotate_conf_url.clone(),
                    pyroscope_script: pyroscope_digest_to_url[pyroscope_digest].clone(),
                    pyroscope_service: pyroscope_agent_service_url.clone(),
                    pyroscope_timer: pyroscope_agent_timer_url.clone(),
                    libjemalloc_deb: tool_urls.libjemalloc.clone(),
                    logrotate_deb: tool_urls.logrotate.clone(),
                    unzip_deb: tool_urls.unzip.clone(),
                    jq_deb,
                },
                arch,
            ),
        );
    }
    info!("uploaded config files to S3");

    // Build monitoring URLs struct for SSH configuration (using monitoring architecture)
    let tool_urls = &tool_urls_by_arch[&monitoring_architecture];
    let monitoring_urls = MonitoringUrls {
        prometheus_bin: tool_urls.prometheus.clone(),
        grafana_bin: tool_urls.grafana.clone(),
        loki_bin: tool_urls.loki.clone(),
        pyroscope_bin: tool_urls.pyroscope.clone(),
        tempo_bin: tool_urls.tempo.clone(),
        node_exporter_bin: tool_urls.node_exporter.clone(),
        libfontconfig_deb: tool_urls.libfontconfig.clone(),
        unzip_deb: tool_urls.unzip.clone(),
        adduser_deb: tool_urls.adduser.clone(),
        musl_deb: tool_urls.musl.clone(),
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

    // Prepare binary instance configuration futures
    info!("configuring monitoring and binary instances");
    let binary_configs: Vec<_> = deployments
        .iter()
        .map(|deployment| {
            let instance = deployment.instance.clone();
            let deployment_id = deployment.id.clone();
            let ec2_client = ec2_clients[&instance.region].clone();
            let ip = deployment.ip.clone();
            let (urls, arch) = instance_urls_map.remove(&instance.name).unwrap();
            (instance, deployment_id, ec2_client, ip, urls, arch)
        })
        .collect();
    let binary_futures = binary_configs.into_iter().map(
        |(instance, deployment_id, ec2_client, ip, urls, arch)| async move {
            let start = Instant::now();

            wait_for_instances_ready(&ec2_client, slice::from_ref(&deployment_id)).await?;
            let wait_ready_ms = start.elapsed().as_millis();

            let bbr_start = Instant::now();
            enable_bbr(private_key, &ip).await?;
            let bbr_ms = bbr_start.elapsed().as_millis();

            let apt_ms = if let Some(apt_cmd) = install_binary_apt_cmd(instance.profiling) {
                let apt_start = Instant::now();
                ssh_execute(private_key, &ip, apt_cmd).await?;
                apt_start.elapsed().as_millis()
            } else {
                0
            };

            let download_start = Instant::now();
            ssh_execute(private_key, &ip, &install_binary_download_cmd(&urls)).await?;
            let download_ms = download_start.elapsed().as_millis();

            let setup_start = Instant::now();
            ssh_execute(
                private_key,
                &ip,
                &install_binary_setup_cmd(instance.profiling, arch),
            )
            .await?;
            let setup_ms = setup_start.elapsed().as_millis();

            let poll_start = Instant::now();
            poll_service_active(private_key, &ip, "promtail").await?;
            poll_service_active(private_key, &ip, "node_exporter").await?;
            poll_service_active(private_key, &ip, "binary").await?;
            let poll_ms = poll_start.elapsed().as_millis();

            let total_ms = start.elapsed().as_millis();
            info!(
                ip = ip.as_str(),
                instance = instance.name.as_str(),
                wait_ready_ms,
                bbr_ms,
                apt_ms,
                download_ms,
                setup_ms,
                poll_ms,
                total_ms,
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
            let wait_ready_ms = start.elapsed().as_millis();

            let bbr_start = Instant::now();
            enable_bbr(private_key, &monitoring_ip).await?;
            let bbr_ms = bbr_start.elapsed().as_millis();

            let download_start = Instant::now();
            ssh_execute(
                private_key,
                &monitoring_ip,
                &install_monitoring_download_cmd(&monitoring_urls),
            )
            .await?;
            let download_ms = download_start.elapsed().as_millis();

            let setup_start = Instant::now();
            ssh_execute(
                private_key,
                &monitoring_ip,
                &install_monitoring_setup_cmd(PROMETHEUS_VERSION, monitoring_architecture),
            )
            .await?;
            let setup_ms = setup_start.elapsed().as_millis();

            let services_start = Instant::now();
            ssh_execute(private_key, &monitoring_ip, start_monitoring_services_cmd()).await?;
            let services_ms = services_start.elapsed().as_millis();

            let poll_start = Instant::now();
            poll_service_active(private_key, &monitoring_ip, "node_exporter").await?;
            poll_service_active(private_key, &monitoring_ip, "prometheus").await?;
            poll_service_active(private_key, &monitoring_ip, "loki").await?;
            poll_service_active(private_key, &monitoring_ip, "pyroscope").await?;
            poll_service_active(private_key, &monitoring_ip, "tempo").await?;
            poll_service_active(private_key, &monitoring_ip, "grafana-server").await?;
            let poll_ms = poll_start.elapsed().as_millis();

            let total_ms = start.elapsed().as_millis();
            info!(
                ip = monitoring_ip.as_str(),
                wait_ready_ms,
                bbr_ms,
                download_ms,
                setup_ms,
                services_ms,
                poll_ms,
                total_ms,
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
