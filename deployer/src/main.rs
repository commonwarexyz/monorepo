use aws_config::{BehaviorVersion, Region};
use aws_sdk_ec2::error::BuildError;
use aws_sdk_ec2::primitives::Blob;
use aws_sdk_ec2::types::{
    BlockDeviceMapping, EbsBlockDevice, Filter, InstanceStateName, InstanceType, IpPermission,
    IpRange, ResourceType, Tag, TagSpecification, UserIdGroupPair, VolumeType,
};
use aws_sdk_ec2::{Client as Ec2Client, Error as Ec2Error};
use clap::{App, Arg, SubCommand};
use commonware_deployer::{Config, InstanceConfig, Peer, Peers, PortConfig};
use futures::future::join_all;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use tempdir::TempDir;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

const MONITORING_REGION: &str = "us-east-1";
const PROMETHEUS_VERSION: &str = "2.30.3";
const LOKI_VERSION: &str = "2.9.2";
const PROMTAIL_VERSION: &str = "2.9.2";
const DATASOURCES_YML: &str = r#"
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    url: http://localhost:9090
    access: proxy
    isDefault: true
  - name: Loki
    type: loki
    url: http://localhost:3100
    access: proxy
    isDefault: false
"#;
const ALL_YML: &str = r#"
apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    options:
      path: /var/lib/grafana/dashboards
"#;

#[derive(Clone)]
struct Deployment {
    instance: InstanceConfig,
    ip: String,
}

struct RegionResources {
    vpc_id: String,
    vpc_cidr: String,
    route_table_id: String,
    subnet_id: String,
    regular_sg_id: Option<String>,
    monitoring_sg_id: Option<String>,
}

// TODO: change name to ec2
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("deployer")
        .version("1.0")
        .about("Deploys a binary and config to EC2 instances across AWS regions with monitoring and logging")
        .subcommand(
            SubCommand::with_name("setup")
                .about("Sets up EC2 instances and deploys files with monitoring and logging")
                .arg(Arg::with_name("config").long("config").takes_value(true).required(true).help("Path to YAML config file"))
        )
        .subcommand(
            SubCommand::with_name("teardown")
                .about("Deletes all deployed resources")
                .arg(Arg::with_name("tag").long("tag").takes_value(true).required(true).help("Deployment tag"))
                .arg(Arg::with_name("config").long("config").takes_value(true).required(true).help("Path to YAML config file"))
        )
        .get_matches();

    // Determine deployer IP
    let deployer_ip = reqwest::get("http://ipv4.icanhazip.com")
        .await?
        .text()
        .await?
        .trim()
        .to_string();
    println!("Deployer IP: {}", deployer_ip);

    match matches.subcommand() {
        ("setup", Some(sub_m)) => {
            // Load config
            let config_path = sub_m.value_of("config").unwrap();
            let config_file = File::open(config_path)?;
            let config: Config = serde_yaml::from_reader(config_file)?;

            // Generate unique tag
            let tag = Uuid::new_v4().to_string();
            println!("Deployment tag: {}", tag);

            // Create temp directory
            let temp_dir = TempDir::new("deployer")?;
            println!("Temp directory: {:?}", temp_dir.path());

            // Generate SSH key pair
            let key_name = format!("deployer-{}", tag);
            let private_key_path = temp_dir.path().join(format!("id_rsa_{}", tag));
            let public_key_path = temp_dir.path().join(format!("id_rsa_{}.pub", tag));

            // Generate SSH key pair
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
                return Err(format!("Failed to generate SSH key: {:?}", output).into());
            }

            // Read public key
            let public_key = std::fs::read_to_string(&public_key_path)?;
            let private_key = private_key_path.to_str().unwrap();

            // Determine unique regions
            let mut regions: BTreeSet<String> =
                config.instances.iter().map(|i| i.region.clone()).collect();
            regions.insert(MONITORING_REGION.to_string());
            println!("Regions: {:?}", regions);

            // Create CIDR block for each region
            let mut vpc_cidrs = HashMap::new();
            let mut subnet_cidrs = HashMap::new();
            let mut ec2_clients = HashMap::new();
            let mut region_resources = HashMap::new();
            for (idx, region) in regions.iter().enumerate() {
                // Create EC2 client for region
                ec2_clients.insert(
                    region.clone(),
                    create_ec2_client(Region::new(region.clone())).await,
                );
                println!("Created EC2 client for region: {}", region);
                let ec2_client = ec2_clients.get(region).unwrap();

                // Create VPC, IGW, and Route Table
                let vpc_cidr = format!("10.{}.0.0/16", idx);
                vpc_cidrs.insert(region.clone(), vpc_cidr.clone());
                let vpc_id = create_vpc(ec2_client, &vpc_cidr, &tag).await?;
                let igw_id = create_and_attach_igw(ec2_client, &vpc_id, &tag).await?;
                let route_table_id = create_route_table(ec2_client, &vpc_id, &igw_id, &tag).await?;
                println!("Created VPC, IGW, and Route Table for region: {}", region);

                // Create Subnet
                let subnet_cidr = format!("10.{}.1.0/24", idx);
                subnet_cidrs.insert(region.clone(), subnet_cidr.clone());
                let subnet_id =
                    create_subnet(ec2_client, &vpc_id, &route_table_id, &subnet_cidr, &tag).await?;
                println!("Created Subnet for region: {}", region);

                // Create monitoring security group in monitoring region
                let monitoring_sg_id = if *region == MONITORING_REGION {
                    let sg_id =
                        create_security_group_monitoring(ec2_client, &vpc_id, &deployer_ip, &tag)
                            .await?;
                    println!("Created Monitoring Security Group for region: {}", region);
                    Some(sg_id)
                } else {
                    None
                };

                // Import key pair to the region
                import_key_pair(ec2_client, &key_name, &public_key).await?;

                // Store region resources
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

            // Setup VPC peering connections
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
                        &tag,
                    )
                    .await?;
                    accept_vpc_peering_connection(&ec2_clients[region], &peer_id).await?;
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
                }
            }

            // Launch monitoring instance
            let monitoring_region = MONITORING_REGION.to_string();
            let monitoring_resources = region_resources.get(&monitoring_region).unwrap();
            let monitoring_ec2_client = &ec2_clients[&monitoring_region];
            let ami_id = find_latest_ami(monitoring_ec2_client).await?;
            let monitoring_instance_type =
                InstanceType::try_parse(&config.monitoring.instance_type)
                    .expect("Invalid instance type");
            let monitoring_storage_class = VolumeType::try_parse(&config.monitoring.storage_class)
                .expect("Invalid storage class");
            let monitoring_instance_id = launch_instances(
                monitoring_ec2_client,
                &ami_id,
                monitoring_instance_type,
                config.monitoring.storage_size,
                monitoring_storage_class,
                &key_name,
                &monitoring_resources.subnet_id,
                monitoring_resources.monitoring_sg_id.as_ref().unwrap(),
                1,
                &tag,
            )
            .await?[0]
                .clone();
            let monitoring_ip = wait_for_instances_running(
                monitoring_ec2_client,
                &[monitoring_instance_id.clone()],
            )
            .await?[0]
                .clone();
            let monitoring_private_ip =
                get_private_ip(monitoring_ec2_client, &monitoring_instance_id).await?;

            // Create regular security groups for each region
            for (region, resources) in region_resources.iter_mut() {
                let ec2_client = &ec2_clients[region];
                let regular_sg_id = create_security_group_regular(
                    ec2_client,
                    &resources.vpc_id,
                    &deployer_ip,
                    &monitoring_ip,
                    &tag,
                    &config.ports,
                )
                .await?;
                resources.regular_sg_id = Some(regular_sg_id);
            }

            // Launch regular instances
            let temp_dir = TempDir::new("deployer")?;
            let mut launch_futures = Vec::new();
            for instance in &config.instances {
                let key_name = key_name.clone();
                let region = instance.region.clone();
                let resources = region_resources.get(&region).unwrap();
                let ec2_client = ec2_clients.get(&region).unwrap();
                let ami_id = find_latest_ami(ec2_client).await?;
                let instance_type = InstanceType::try_parse(&instance.instance_type)
                    .expect("Invalid instance type");
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
                        &tag,
                    )
                    .await?[0]
                        .clone();
                    let ip = wait_for_instances_running(ec2_client, &[instance_id.clone()]).await?
                        [0]
                    .clone();
                    Ok::<Deployment, Box<dyn Error>>(Deployment {
                        instance: instance.clone(),
                        ip,
                    })
                };
                launch_futures.push(future);
            }

            // Collect deployments
            let deployments: Vec<Deployment> = join_all(launch_futures)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;

            // Create peers.yaml with all IPs
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
            let peers_path = temp_dir.path().join("peers.yaml");
            std::fs::write(&peers_path, peers_yaml)?;

            // Configure monitoring instance
            let all_ips: Vec<String> = deployments.iter().map(|d| d.ip.clone()).collect();
            let prom_config = generate_prometheus_config(&all_ips);
            let prom_path = temp_dir.path().join("prometheus.yml");
            std::fs::write(&prom_path, prom_config)?;
            let datasources_path = temp_dir.path().join("datasources.yml");
            std::fs::write(&datasources_path, DATASOURCES_YML)?;
            let all_yaml_path = temp_dir.path().join("all.yml");
            std::fs::write(&all_yaml_path, ALL_YML)?;
            let loki_config = r#"
auth_enabled: false
server:
  http_listen_port: 3100
chunk_store_config:
  max_look_back_period: 0s
table_manager:
  retention_deletes_enabled: false
  retention_period: 0s
"#;
            let loki_config_path = temp_dir.path().join("loki.yml");
            std::fs::write(&loki_config_path, loki_config)?;
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

            let install_monitoring_cmd = format!(
                r#"
sudo apt-get update -y
sudo apt-get install -y wget curl unzip
wget https://github.com/prometheus/prometheus/releases/download/v{}/prometheus-{}.linux-arm64.tar.gz
tar xvfz prometheus-{}.linux-arm64.tar.gz
sudo mv prometheus-{}.linux-arm64 /opt/prometheus
wget https://github.com/grafana/loki/releases/download/v{}/loki-linux-arm64.zip
unzip loki-linux-arm64.zip
sudo mv loki-linux-arm64 /opt/loki/loki
sudo mkdir -p /etc/loki
sudo mv /home/ubuntu/loki.yml /etc/loki/loki.yml
sudo chown root:root /etc/loki/loki.yml
curl https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
sudo apt-get update -y
sudo apt-get install -y grafana
sudo mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards
sudo mv /home/ubuntu/prometheus.yml /opt/prometheus/prometheus.yml
sudo mv /home/ubuntu/datasources.yml /etc/grafana/provisioning/datasources/datasources.yml
sudo mv /home/ubuntu/all.yml /etc/grafana/provisioning/dashboards/all.yml
sudo mv /home/ubuntu/dashboard.json /var/lib/grafana/dashboards/dashboard.json
sudo chown -R grafana:grafana /etc/grafana /var/lib/grafana
nohup /opt/prometheus/prometheus --config.file=/opt/prometheus/prometheus.yml &
nohup /opt/loki/loki -config.file=/etc/loki/loki.yml &
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
"#,
                PROMETHEUS_VERSION,
                PROMETHEUS_VERSION,
                PROMETHEUS_VERSION,
                PROMETHEUS_VERSION,
                LOKI_VERSION
            );
            ssh_execute(private_key, &monitoring_ip, &install_monitoring_cmd).await?;

            // Configure regular instances
            let temp_dir_path = temp_dir.path();
            let mut start_futures = Vec::new();
            for deployment in &deployments {
                let instance = deployment.instance.clone();
                let ip = deployment.ip.clone();
                let monitoring_private_ip = monitoring_private_ip.clone();
                let peers_path = peers_path.clone();
                let future = async move {
                    // Upload binary, config, and peers
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

                    // Create log file and start binary with logging
                    let create_log_cmd = "sudo touch /var/log/binary.log && sudo chown ubuntu:ubuntu /var/log/binary.log";
                    ssh_execute(private_key, &ip, create_log_cmd).await?;
                    let run_cmd = "chmod +x /home/ubuntu/binary && nohup /home/ubuntu/binary --peers /home/ubuntu/peers.yaml --config /home/ubuntu/config.conf > /var/log/binary.log 2>&1 &";
                    ssh_execute(private_key, &ip, run_cmd).await?;

                    // Install and configure Promtail
                    let promtail_config = format!(
                        r#"
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /tmp/positions.yaml
clients:
  - url: http://{}:3100/loki/api/v1/push
scrape_configs:
  - job_name: binary_logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: binary
          instance: {}
          __path__: /var/log/binary.log
"#,
                        monitoring_private_ip, instance.name
                    );
                    let promtail_config_path =
                        temp_dir_path.join(format!("promtail_{}.yml", instance.name));
                    std::fs::write(&promtail_config_path, promtail_config)?;
                    scp_file(
                        private_key,
                        promtail_config_path.to_str().unwrap(),
                        &ip,
                        "/home/ubuntu/promtail.yml",
                    )
                    .await?;
                    let install_promtail_cmd = format!(
                        r#"
wget https://github.com/grafana/loki/releases/download/v{}/promtail-linux-arm64.zip
unzip promtail-linux-arm64.zip
sudo mv promtail-linux-arm64 /opt/promtail/promtail
sudo mkdir -p /etc/promtail
sudo mv /home/ubuntu/promtail.yml /etc/promtail/promtail.yml
sudo chown root:root /etc/promtail/promtail.yml
nohup /opt/promtail/promtail -config.file=/etc/promtail/promtail.yml &
"#,
                        PROMTAIL_VERSION
                    );
                    ssh_execute(private_key, &ip, &install_promtail_cmd).await?;

                    Ok::<String, Box<dyn Error>>(ip)
                };
                start_futures.push(future);
            }
            let all_regular_ips = join_all(start_futures)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;

            // Update Monitoring Security Group to Restrict Port 3100
            let monitoring_resources = region_resources.get(&monitoring_region).unwrap();
            let monitoring_sg_id = monitoring_resources.monitoring_sg_id.as_ref().unwrap();
            let monitoring_ec2_client = &ec2_clients[&monitoring_region];

            if regular_regions.contains(&monitoring_region) {
                let regular_sg_id = region_resources[&monitoring_region]
                    .regular_sg_id
                    .clone()
                    .unwrap();
                monitoring_ec2_client
                    .authorize_security_group_ingress()
                    .group_id(monitoring_sg_id)
                    .ip_permissions(
                        IpPermission::builder()
                            .ip_protocol("tcp")
                            .from_port(3100)
                            .to_port(3100)
                            .user_id_group_pairs(
                                UserIdGroupPair::builder().group_id(regular_sg_id).build(),
                            )
                            .build(),
                    )
                    .send()
                    .await?;
            }
            for region in &regions {
                if region != &monitoring_region && regular_regions.contains(region) {
                    let regular_cidr = &region_resources[region].vpc_cidr;
                    monitoring_ec2_client
                        .authorize_security_group_ingress()
                        .group_id(monitoring_sg_id)
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
                }
            }

            println!("Monitoring instance IP: {}", monitoring_ip);
            println!("Deployed to: {:?}", all_regular_ips);
            println!("Deployment tag: {}", tag);
        }
        ("teardown", Some(sub_m)) => {
            // Load tag config
            let tag = sub_m.value_of("tag").unwrap().to_string();
            let config_path = sub_m.value_of("config").unwrap();
            let config_file = File::open(config_path)?;
            let config: Config = serde_yaml::from_reader(config_file)?;
            println!("Deployment tag: {}", tag);

            // Populate all regions
            let mut all_regions = HashSet::new();
            all_regions.insert(MONITORING_REGION.to_string());
            for instance in &config.instances {
                all_regions.insert(instance.region.clone());
            }
            println!("Regions: {:?}", all_regions);

            // Teardown resources
            for region in all_regions {
                // Create EC2 client for region
                let region = Region::new(region);
                let ec2_client = create_ec2_client(region.clone()).await;

                // Delete instances
                let instance_ids = find_instances_by_tag(&ec2_client, &tag).await?;
                if !instance_ids.is_empty() {
                    println!("Terminating instances: {:?}", instance_ids);
                    terminate_instances(&ec2_client, &instance_ids).await?;
                    wait_for_instances_terminated(&ec2_client, &instance_ids).await?;
                }

                // Delete security groups
                let sg_ids = find_security_groups_by_tag(&ec2_client, &tag).await?;
                for sg_id in sg_ids {
                    println!("Deleting security group: {}", sg_id);
                    delete_security_group(&ec2_client, &sg_id).await?;
                }

                // Delete subnets
                let subnet_ids = find_subnets_by_tag(&ec2_client, &tag).await?;
                for subnet_id in subnet_ids {
                    println!("Deleting subnet: {}", subnet_id);
                    delete_subnet(&ec2_client, &subnet_id).await?;
                }

                // Delete route tables
                let route_table_ids = find_route_tables_by_tag(&ec2_client, &tag).await?;
                for rt_id in route_table_ids {
                    println!("Deleting route table: {}", rt_id);
                    delete_route_table(&ec2_client, &rt_id).await?;
                }

                // Delete VPC peering connections
                let peering_ids = find_vpc_peering_by_tag(&ec2_client, &tag).await?;
                for peering_id in peering_ids {
                    println!("Deleting VPC peering connection: {}", peering_id);
                    delete_vpc_peering(&ec2_client, &peering_id).await?;
                }

                // Delete internet gateways
                let igw_ids = find_igws_by_tag(&ec2_client, &tag).await?;
                for igw_id in igw_ids {
                    println!("Detaching and deleting internet gateway: {}", igw_id);
                    let vpc_id = find_vpc_by_igw(&ec2_client, &igw_id).await?;
                    detach_igw(&ec2_client, &igw_id, &vpc_id).await?;
                    delete_igw(&ec2_client, &igw_id).await?;
                }

                // Delete VPCs
                let vpc_ids = find_vpcs_by_tag(&ec2_client, &tag).await?;
                for vpc_id in vpc_ids {
                    println!("Deleting VPC: {}", vpc_id);
                    delete_vpc(&ec2_client, &vpc_id).await?;
                }

                // Delete key pair
                let key_name = format!("deployer-{}", tag);
                println!("Deleting key pair {} for region {}", key_name, region);
                delete_key_pair(&ec2_client, &key_name).await?;
            }
            println!("Teardown complete for tag: {}", tag);
        }
        _ => println!("Invalid command. Use 'setup' or 'teardown'."),
    }

    Ok(())
}

// Helper functions remain the same as in the original code
async fn create_ec2_client(region: Region) -> Ec2Client {
    let config = aws_config::defaults(BehaviorVersion::v2024_03_28())
        .region(region)
        .load()
        .await;
    Ec2Client::new(&config)
}

async fn import_key_pair(
    client: &Ec2Client,
    key_name: &str,
    public_key: &str,
) -> Result<(), Ec2Error> {
    let blob = Blob::new(public_key.as_bytes());
    client
        .import_key_pair()
        .key_name(key_name)
        .public_key_material(blob)
        .send()
        .await?;
    Ok(())
}

async fn delete_key_pair(client: &Ec2Client, key_name: &str) -> Result<(), Ec2Error> {
    client.delete_key_pair().key_name(key_name).send().await?;
    Ok(())
}

async fn find_latest_ami(client: &Ec2Client) -> Result<String, Ec2Error> {
    let resp = client
        .describe_images()
        .filters(
            Filter::builder()
                .name("name")
                .values("ubuntu/images/hvm-ssd/ubuntu-noble-24.04-arm64-server-*")
                .build(),
        )
        .filters(
            Filter::builder()
                .name("root-device-type")
                .values("ebs")
                .build(),
        )
        .owners("099720109477") // Canonical's AWS account ID
        .send()
        .await?;
    let mut images = resp.images.unwrap_or_default();
    if images.is_empty() {
        return Err(Ec2Error::from(BuildError::other(
            "No matching AMI found".to_string(),
        )));
    }
    images.sort_by(|a, b| b.creation_date().cmp(&a.creation_date()));
    let latest_ami = images[0].image_id().unwrap();
    Ok(latest_ami.to_string())
}

async fn create_vpc(client: &Ec2Client, cidr_block: &str, tag: &str) -> Result<String, Ec2Error> {
    let resp = client
        .create_vpc()
        .cidr_block(cidr_block)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Vpc)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    Ok(resp.vpc.unwrap().vpc_id.unwrap())
}

async fn create_and_attach_igw(
    client: &Ec2Client,
    vpc_id: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let igw_resp = client
        .create_internet_gateway()
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::InternetGateway)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let igw_id = igw_resp
        .internet_gateway
        .unwrap()
        .internet_gateway_id
        .unwrap();
    client
        .attach_internet_gateway()
        .internet_gateway_id(&igw_id)
        .vpc_id(vpc_id)
        .send()
        .await?;
    Ok(igw_id)
}

async fn create_route_table(
    client: &Ec2Client,
    vpc_id: &str,
    igw_id: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let rt_resp = client
        .create_route_table()
        .vpc_id(vpc_id)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::RouteTable)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let rt_id = rt_resp.route_table.unwrap().route_table_id.unwrap();
    client
        .create_route()
        .route_table_id(&rt_id)
        .destination_cidr_block("0.0.0.0/0")
        .gateway_id(igw_id)
        .send()
        .await?;
    Ok(rt_id)
}

async fn create_subnet(
    client: &Ec2Client,
    vpc_id: &str,
    route_table_id: &str,
    subnet_cidr: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let subnet_resp = client
        .create_subnet()
        .vpc_id(vpc_id)
        .cidr_block(subnet_cidr)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Subnet)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let subnet_id = subnet_resp.subnet.unwrap().subnet_id.unwrap();
    client
        .associate_route_table()
        .route_table_id(route_table_id)
        .subnet_id(&subnet_id)
        .send()
        .await?;
    Ok(subnet_id)
}

async fn create_security_group_monitoring(
    client: &Ec2Client,
    vpc_id: &str,
    deployer_ip: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let sg_resp = client
        .create_security_group()
        .group_name(tag)
        .description("Security group for monitoring instance")
        .vpc_id(vpc_id)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::SecurityGroup)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let sg_id = sg_resp.group_id.unwrap();
    client
        .authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(0)
                .to_port(65535)
                .ip_ranges(
                    IpRange::builder()
                        .cidr_ip(format!("{}/32", deployer_ip))
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;
    Ok(sg_id)
}

async fn create_security_group_regular(
    client: &Ec2Client,
    vpc_id: &str,
    deployer_ip: &str,
    monitoring_ip: &str,
    tag: &str,
    ports: &[PortConfig],
) -> Result<String, Ec2Error> {
    let sg_resp = client
        .create_security_group()
        .group_name(format!("{}-regular", tag))
        .description("Security group for regular instances")
        .vpc_id(vpc_id)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::SecurityGroup)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let sg_id = sg_resp.group_id.unwrap();
    let mut builder = client
        .authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(0)
                .to_port(65535)
                .ip_ranges(
                    IpRange::builder()
                        .cidr_ip(format!("{}/32", deployer_ip))
                        .build(),
                )
                .build(),
        )
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(9080)
                .to_port(9080)
                .ip_ranges(
                    IpRange::builder()
                        .cidr_ip(format!("{}/32", monitoring_ip))
                        .build(),
                )
                .build(),
        )
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(9100)
                .to_port(9100)
                .ip_ranges(
                    IpRange::builder()
                        .cidr_ip(format!("{}/32", monitoring_ip))
                        .build(),
                )
                .build(),
        );
    for port in ports {
        builder = builder.ip_permissions(
            IpPermission::builder()
                .ip_protocol(&port.protocol)
                .from_port(port.port as i32)
                .to_port(port.port as i32)
                .ip_ranges(IpRange::builder().cidr_ip(&port.cidr).build())
                .build(),
        );
    }

    builder.send().await?;
    Ok(sg_id)
}

#[allow(clippy::too_many_arguments)]
async fn launch_instances(
    client: &Ec2Client,
    ami_id: &str,
    instance_type: InstanceType,
    storage_size: i32,
    storage_class: VolumeType,
    key_name: &str,
    subnet_id: &str,
    sg_id: &str,
    count: i32,
    tag: &str,
) -> Result<Vec<String>, Ec2Error> {
    let resp = client
        .run_instances()
        .image_id(ami_id)
        .instance_type(instance_type)
        .key_name(key_name)
        .min_count(count)
        .max_count(count)
        .subnet_id(subnet_id)
        .security_group_ids(sg_id)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Instance)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/sda1")
                .ebs(
                    EbsBlockDevice::builder()
                        .volume_size(storage_size)
                        .volume_type(storage_class)
                        .delete_on_termination(true)
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;
    Ok(resp
        .instances
        .unwrap()
        .into_iter()
        .map(|i| i.instance_id.unwrap())
        .collect())
}

async fn wait_for_instances_running(
    client: &Ec2Client,
    instance_ids: &[String],
) -> Result<Vec<String>, Ec2Error> {
    loop {
        let resp = client
            .describe_instances()
            .set_instance_ids(Some(instance_ids.to_vec()))
            .send()
            .await?;
        let reservations = resp.reservations.unwrap();
        let instances = reservations[0].instances.as_ref().unwrap();
        if instances.iter().all(|i| {
            *i.state.as_ref().unwrap().name.as_ref().unwrap() == InstanceStateName::Running
        }) {
            return Ok(instances
                .iter()
                .map(|i| i.public_ip_address.as_ref().unwrap().clone())
                .collect());
        }
        sleep(Duration::from_secs(5)).await;
    }
}

async fn get_private_ip(client: &Ec2Client, instance_id: &str) -> Result<String, Ec2Error> {
    let resp = client
        .describe_instances()
        .instance_ids(instance_id)
        .send()
        .await?;
    let reservations = resp.reservations.unwrap();
    let instance = &reservations[0].instances.as_ref().unwrap()[0];
    Ok(instance.private_ip_address.as_ref().unwrap().clone())
}

async fn create_vpc_peering_connection(
    client: &Ec2Client,
    requester_vpc_id: &str,
    peer_vpc_id: &str,
    peer_region: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let resp = client
        .create_vpc_peering_connection()
        .vpc_id(requester_vpc_id)
        .peer_vpc_id(peer_vpc_id)
        .peer_region(peer_region)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::VpcPeeringConnection)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    Ok(resp
        .vpc_peering_connection
        .unwrap()
        .vpc_peering_connection_id
        .unwrap())
}

async fn accept_vpc_peering_connection(client: &Ec2Client, peer_id: &str) -> Result<(), Ec2Error> {
    client
        .accept_vpc_peering_connection()
        .vpc_peering_connection_id(peer_id)
        .send()
        .await?;
    Ok(())
}

async fn add_route(
    client: &Ec2Client,
    route_table_id: &str,
    destination_cidr: &str,
    peer_id: &str,
) -> Result<(), Ec2Error> {
    client
        .create_route()
        .route_table_id(route_table_id)
        .destination_cidr_block(destination_cidr)
        .vpc_peering_connection_id(peer_id)
        .send()
        .await?;
    Ok(())
}

async fn find_vpc_peering_by_tag(client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = client
        .describe_vpc_peering_connections()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .vpc_peering_connections
        .unwrap_or_default()
        .into_iter()
        .map(|p| p.vpc_peering_connection_id.unwrap())
        .collect())
}

async fn delete_vpc_peering(client: &Ec2Client, peering_id: &str) -> Result<(), Ec2Error> {
    client
        .delete_vpc_peering_connection()
        .vpc_peering_connection_id(peering_id)
        .send()
        .await?;
    Ok(())
}

fn generate_prometheus_config(ips: &[String]) -> String {
    let mut config = String::from(
        r#"
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
"#,
    );
    for ip in ips {
        config.push_str(&format!(
            r#"
  - job_name: 'binary-{}'
    static_configs:
      - targets: ['{}:9100']
"#,
            ip, ip
        ));
    }
    config
}

async fn scp_file(
    key_file: &str,
    local_path: &str,
    ip: &str,
    remote_path: &str,
) -> Result<(), Box<dyn Error>> {
    let status = Command::new("scp")
        .arg("-i")
        .arg(key_file)
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg(local_path)
        .arg(format!("ubuntu@{}:{}", ip, remote_path))
        .status()
        .await?;
    if !status.success() {
        return Err("SCP failed".into());
    }
    Ok(())
}

async fn ssh_execute(key_file: &str, ip: &str, command: &str) -> Result<(), Box<dyn Error>> {
    let status = Command::new("ssh")
        .arg("-i")
        .arg(key_file)
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg(format!("ubuntu@{}", ip))
        .arg(command)
        .status()
        .await?;
    if !status.success() {
        return Err("SSH failed".into());
    }
    Ok(())
}

async fn find_instances_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_instances()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .reservations
        .unwrap_or_default()
        .into_iter()
        .flat_map(|r| r.instances.unwrap_or_default())
        .map(|i| i.instance_id.unwrap())
        .collect())
}

async fn terminate_instances(
    ec2_client: &Ec2Client,
    instance_ids: &[String],
) -> Result<(), Ec2Error> {
    if instance_ids.is_empty() {
        return Ok(());
    }
    ec2_client
        .terminate_instances()
        .set_instance_ids(Some(instance_ids.to_vec()))
        .send()
        .await?;
    Ok(())
}

async fn wait_for_instances_terminated(
    ec2_client: &Ec2Client,
    instance_ids: &[String],
) -> Result<(), Ec2Error> {
    loop {
        let resp = ec2_client
            .describe_instances()
            .set_instance_ids(Some(instance_ids.to_vec()))
            .send()
            .await?;
        let instances = resp
            .reservations
            .unwrap_or_default()
            .into_iter()
            .flat_map(|r| r.instances.unwrap_or_default())
            .collect::<Vec<_>>();
        if instances.iter().all(|i| {
            *i.state.as_ref().unwrap().name.as_ref().unwrap() == InstanceStateName::Terminated
        }) {
            return Ok(());
        }
        sleep(Duration::from_secs(5)).await;
    }
}

async fn find_security_groups_by_tag(
    ec2_client: &Ec2Client,
    tag: &str,
) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_security_groups()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .security_groups
        .unwrap_or_default()
        .into_iter()
        .map(|sg| sg.group_id.unwrap())
        .collect())
}

async fn delete_security_group(ec2_client: &Ec2Client, sg_id: &str) -> Result<(), Ec2Error> {
    ec2_client
        .delete_security_group()
        .group_id(sg_id)
        .send()
        .await?;
    Ok(())
}

async fn find_route_tables_by_tag(
    ec2_client: &Ec2Client,
    tag: &str,
) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_route_tables()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .route_tables
        .unwrap_or_default()
        .into_iter()
        .map(|rt| rt.route_table_id.unwrap())
        .collect())
}

async fn delete_route_table(ec2_client: &Ec2Client, rt_id: &str) -> Result<(), Ec2Error> {
    ec2_client
        .delete_route_table()
        .route_table_id(rt_id)
        .send()
        .await?;
    Ok(())
}

async fn find_igws_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_internet_gateways()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .internet_gateways
        .unwrap_or_default()
        .into_iter()
        .map(|igw| igw.internet_gateway_id.unwrap())
        .collect())
}

async fn find_vpc_by_igw(ec2_client: &Ec2Client, igw_id: &str) -> Result<String, Ec2Error> {
    let resp = ec2_client
        .describe_internet_gateways()
        .internet_gateway_ids(igw_id)
        .send()
        .await?;
    Ok(resp.internet_gateways.unwrap()[0]
        .attachments
        .as_ref()
        .unwrap()[0]
        .vpc_id
        .as_ref()
        .unwrap()
        .clone())
}

async fn detach_igw(ec2_client: &Ec2Client, igw_id: &str, vpc_id: &str) -> Result<(), Ec2Error> {
    ec2_client
        .detach_internet_gateway()
        .internet_gateway_id(igw_id)
        .vpc_id(vpc_id)
        .send()
        .await?;
    Ok(())
}

async fn delete_igw(ec2_client: &Ec2Client, igw_id: &str) -> Result<(), Ec2Error> {
    ec2_client
        .delete_internet_gateway()
        .internet_gateway_id(igw_id)
        .send()
        .await?;
    Ok(())
}

async fn find_subnets_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_subnets()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .subnets
        .unwrap_or_default()
        .into_iter()
        .map(|subnet| subnet.subnet_id.unwrap())
        .collect())
}

async fn delete_subnet(ec2_client: &Ec2Client, subnet_id: &str) -> Result<(), Ec2Error> {
    ec2_client
        .delete_subnet()
        .subnet_id(subnet_id)
        .send()
        .await?;
    Ok(())
}

async fn find_vpcs_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_vpcs()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .vpcs
        .unwrap_or_default()
        .into_iter()
        .map(|vpc| vpc.vpc_id.unwrap())
        .collect())
}

async fn delete_vpc(ec2_client: &Ec2Client, vpc_id: &str) -> Result<(), Ec2Error> {
    ec2_client.delete_vpc().vpc_id(vpc_id).send().await?;
    Ok(())
}
