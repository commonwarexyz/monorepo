use aws_config::Region;
use aws_sdk_ec2::error::BuildError;
use aws_sdk_ec2::types::{
    Filter, InstanceStateName, InstanceType, IpPermission, IpRange, ResourceType, Tag,
    TagSpecification, UserIdGroupPair,
};
use aws_sdk_ec2::{Client as Ec2Client, Error as Ec2Error};
use clap::{App, Arg, SubCommand};
use futures::future::join_all;
use reqwest;
use serde::Deserialize;
use std::collections::HashSet;
use std::error::Error;
use std::path::Path;
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

#[derive(Deserialize, Clone)]
struct InstanceConfig {
    name: String,
    region: String,
    instance_type: String,
    binary: String,
    config: String,
}

#[derive(Deserialize, Clone)]
struct MonitoringConfig {
    instance_type: String,
    dashboard: String,
}

#[derive(Deserialize, Clone)]
struct KeyConfig {
    name: String,
    file: String,
}

#[derive(Deserialize, Clone)]
struct Config {
    instances: Vec<InstanceConfig>,
    key: KeyConfig,
    monitoring: MonitoringConfig,
}

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
    let deployer_ip = reqwest::blocking::get("http://icanhazip.com")?
        .text()?
        .trim()
        .to_string();

    match matches.subcommand() {
        ("setup", Some(sub_m)) => {
            let config_path = sub_m.value_of("config").unwrap();
            let config_file = std::fs::File::open(config_path)?;
            let config: Config = serde_yaml::from_reader(config_file)?;

            let tag = Uuid::new_v4().to_string();
            let monitoring_region = Region::new(MONITORING_REGION);
            let monitoring_ec2_client = create_ec2_client(monitoring_region).await;
            let ami_id = find_latest_ami(&monitoring_ec2_client).await?;
            let vpc_id = create_vpc(&monitoring_ec2_client, &tag).await?;
            let igw_id = create_and_attach_igw(&monitoring_ec2_client, &vpc_id, &tag).await?;
            let route_table_id =
                create_route_table(&monitoring_ec2_client, &vpc_id, &igw_id, &tag).await?;
            let subnet_id =
                create_subnet(&monitoring_ec2_client, &vpc_id, &route_table_id, &tag).await?;
            let sg_monitoring = create_security_group_monitoring(
                &monitoring_ec2_client,
                &vpc_id,
                &deployer_ip,
                &tag,
            )
            .await?;
            let monitoring_instance_type =
                InstanceType::try_parse(&config.monitoring.instance_type)
                    .expect("Invalid instance type");
            let monitoring_instance_id = launch_instances(
                &monitoring_ec2_client,
                &ami_id,
                monitoring_instance_type,
                &config.key.name,
                &subnet_id,
                &sg_monitoring,
                1,
                &tag,
            )
            .await?[0]
                .clone();
            let monitoring_ip = wait_for_instances_running(
                &monitoring_ec2_client,
                &[monitoring_instance_id.clone()],
            )
            .await?[0]
                .clone();

            // Configure monitoring instance with Prometheus, Grafana, and Loki
            let prom_config = generate_prometheus_config(&[]); // Will update with IPs later if needed
            let temp_dir = TempDir::new("deployer")?;
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
                &config.key.file,
                prom_path.to_str().unwrap(),
                &monitoring_ip,
                "/home/ubuntu/prometheus.yml",
            )
            .await?;
            scp_file(
                &config.key.file,
                datasources_path.to_str().unwrap(),
                &monitoring_ip,
                "/home/ubuntu/datasources.yml",
            )
            .await?;
            scp_file(
                &config.key.file,
                all_yaml_path.to_str().unwrap(),
                &monitoring_ip,
                "/home/ubuntu/all.yml",
            )
            .await?;
            scp_file(
                &config.key.file,
                &config.monitoring.dashboard,
                &monitoring_ip,
                "/home/ubuntu/dashboard.json",
            )
            .await?;
            scp_file(
                &config.key.file,
                loki_config_path.to_str().unwrap(),
                &monitoring_ip,
                "/home/ubuntu/loki.yml",
            )
            .await?;

            let install_monitoring_cmd = format!(
                r#"
sudo apt-get update -y
sudo apt-get install -y wget curl unzip
wget https://github.com/prometheus/prometheus/releases/download/v{}/prometheus-{}.linux-amd64.tar.gz
tar xvfz prometheus-{}.linux-amd64.tar.gz
sudo mv prometheus-{}.linux-amd64 /opt/prometheus
wget https://github.com/grafana/loki/releases/download/v{}/loki-linux-amd64.zip
unzip loki-linux-amd64.zip
sudo mv loki-linux-amd64 /opt/loki/loki
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
            ssh_execute(&config.key.file, &monitoring_ip, &install_monitoring_cmd).await?;

            // Deploy regular instances
            let tempdir_path = temp_dir.path();
            let mut deploy_futures = Vec::new();
            for instance in &config.instances {
                let deployer_ip = deployer_ip.clone();
                let instance = instance.clone();
                let config = config.clone();
                let tag = tag.clone();
                let monitoring_ip = monitoring_ip.clone();
                let instance_type = InstanceType::try_parse(&instance.instance_type)
                    .expect("Invalid instance type");
                let region = Region::new(instance.region);
                let future = async move {
                    let ec2_client = create_ec2_client(region).await;
                    let ami_id = find_latest_ami(&ec2_client).await?;
                    let vpc_id = create_vpc(&ec2_client, &tag).await?;
                    let igw_id = create_and_attach_igw(&ec2_client, &vpc_id, &tag).await?;
                    let route_table_id =
                        create_route_table(&ec2_client, &vpc_id, &igw_id, &tag).await?;
                    let subnet_id =
                        create_subnet(&ec2_client, &vpc_id, &route_table_id, &tag).await?;
                    let sg_regular =
                        create_security_group_regular(&ec2_client, &vpc_id, &deployer_ip, &tag)
                            .await?;
                    let instance_id = launch_instances(
                        &ec2_client,
                        &ami_id,
                        instance_type,
                        &config.key.name,
                        &subnet_id,
                        &sg_regular,
                        1,
                        &tag,
                    )
                    .await?[0]
                        .clone();
                    let ip = wait_for_instances_running(&ec2_client, &[instance_id.clone()])
                        .await?[0]
                        .clone();

                    // Upload binary and config
                    scp_file(
                        &config.key.file,
                        &instance.binary,
                        &ip,
                        "/home/ubuntu/binary",
                    )
                    .await?;
                    scp_file(
                        &config.key.file,
                        &instance.config,
                        &ip,
                        "/home/ubuntu/config.conf",
                    )
                    .await?;

                    // Create log file and start binary with logging
                    let create_log_cmd = "sudo touch /var/log/binary.log && sudo chown ubuntu:ubuntu /var/log/binary.log";
                    ssh_execute(&config.key.file, &ip, create_log_cmd).await?;
                    let run_cmd = "chmod +x /home/ubuntu/binary && nohup /home/ubuntu/binary --config /home/ubuntu/config.conf > /var/log/binary.log 2>&1 &";
                    ssh_execute(&config.key.file, &ip, run_cmd).await?;

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
                        monitoring_ip, instance.name
                    );
                    let promtail_config_path =
                        tempdir_path.join(format!("promtail_{}.yml", instance.name));
                    std::fs::write(&promtail_config_path, promtail_config)?;
                    scp_file(
                        &config.key.file,
                        promtail_config_path.to_str().unwrap(),
                        &ip,
                        "/home/ubuntu/promtail.yml",
                    )
                    .await?;
                    let install_promtail_cmd = format!(
                        r#"
wget https://github.com/grafana/loki/releases/download/v{}/promtail-linux-amd64.zip
unzip promtail-linux-amd64.zip
sudo mv promtail-linux-amd64 /opt/promtail/promtail
sudo mkdir -p /etc/promtail
sudo mv /home/ubuntu/promtail.yml /etc/promtail/promtail.yml
sudo chown root:root /etc/promtail/promtail.yml
nohup /opt/promtail/promtail -config.file=/etc/promtail/promtail.yml &
"#,
                        PROMTAIL_VERSION
                    );
                    ssh_execute(&config.key.file, &ip, &install_promtail_cmd).await?;

                    Ok::<String, Box<dyn Error>>(ip)
                };
                deploy_futures.push(future);
            }
            let all_regular_ips = join_all(deploy_futures)
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;

            println!("Monitoring instance IP: {}", monitoring_ip);
            println!("Deployed to: {:?}", all_regular_ips);
            println!("Deployment tag: {}", tag);
        }
        ("teardown", Some(sub_m)) => {
            let tag = sub_m.value_of("tag").unwrap().to_string();

            // Read config file
            let config_path = sub_m.value_of("config").unwrap();
            let config_file = std::fs::File::open(config_path)?;
            let config: Config = serde_yaml::from_reader(config_file)?;
            let mut all_regions = HashSet::new();
            all_regions.insert(MONITORING_REGION.to_string());
            for instance in &config.instances {
                all_regions.insert(instance.region.clone());
            }

            // Iterate over all regions
            for region in all_regions {
                let region = Region::new(region);
                let ec2_client = create_ec2_client(region).await;
                let instance_ids = find_instances_by_tag(&ec2_client, &tag).await?;
                if !instance_ids.is_empty() {
                    terminate_instances(&ec2_client, &instance_ids).await?;
                    wait_for_instances_terminated(&ec2_client, &instance_ids).await?;
                }
                let sg_ids = find_security_groups_by_tag(&ec2_client, &tag).await?;
                for sg_id in sg_ids {
                    delete_security_group(&ec2_client, &sg_id).await?;
                }
                let route_table_ids = find_route_tables_by_tag(&ec2_client, &tag).await?;
                for rt_id in route_table_ids {
                    delete_route_table(&ec2_client, &rt_id).await?;
                }
                let igw_ids = find_igws_by_tag(&ec2_client, &tag).await?;
                for igw_id in igw_ids {
                    let vpc_id = find_vpc_by_igw(&ec2_client, &igw_id).await?;
                    detach_igw(&ec2_client, &igw_id, &vpc_id).await?;
                    delete_igw(&ec2_client, &igw_id).await?;
                }
                let subnet_ids = find_subnets_by_tag(&ec2_client, &tag).await?;
                for subnet_id in subnet_ids {
                    delete_subnet(&ec2_client, &subnet_id).await?;
                }
                let vpc_ids = find_vpcs_by_tag(&ec2_client, &tag).await?;
                for vpc_id in vpc_ids {
                    delete_vpc(&ec2_client, &vpc_id).await?;
                }
            }
            println!("Teardown complete for tag: {}", tag);
        }
        _ => println!("Invalid command. Use 'setup' or 'teardown'."),
    }

    Ok(())
}

// ### Helper Functions

async fn create_ec2_client(region: Region) -> Ec2Client {
    let config = aws_config::from_env().region(region).load().await;
    Ec2Client::new(&config)
}

async fn find_latest_ami(client: &Ec2Client) -> Result<String, Ec2Error> {
    let resp = client
        .describe_images()
        .filters(
            Filter::builder()
                .name("name")
                .values("ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*")
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
    let latest_ami = images[0].image_id().unwrap().clone();
    Ok(latest_ami.to_string())
}

async fn create_vpc(client: &Ec2Client, tag: &str) -> Result<String, Ec2Error> {
    let resp = client
        .create_vpc()
        .cidr_block("10.0.0.0/16")
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
    tag: &str,
) -> Result<String, Ec2Error> {
    let subnet_resp = client
        .create_subnet()
        .vpc_id(vpc_id)
        .cidr_block("10.0.1.0/24")
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
                .from_port(22)
                .to_port(22)
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
                .from_port(9090)
                .to_port(9090)
                .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
                .build(),
        )
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(3000)
                .to_port(3000)
                .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
                .build(),
        )
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(3100)
                .to_port(3100)
                .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
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
    tag: &str,
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
    client
        .authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(22)
                .to_port(22)
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
                .ip_ranges(IpRange::builder().cidr_ip("0.0.0.0/0").build())
                .build(),
        )
        .send()
        .await?;
    Ok(sg_id)
}

async fn launch_instances(
    client: &Ec2Client,
    ami_id: &str,
    instance_type: InstanceType,
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
