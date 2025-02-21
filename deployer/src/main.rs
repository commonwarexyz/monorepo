use aws_config::meta::region::RegionProviderChain;
use aws_sdk_ec2::model::{Filter, IpPermission, IpRange, ResourceType, Tag, TagSpecification};
use aws_sdk_ec2::{Client as Ec2Client, Error as Ec2Error};
use clap::{App, Arg, SubCommand};
use futures::future::join_all;
use reqwest;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;
use tempdir::TempDir;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use uuid::Uuid;

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");

const PROMETHEUS_VERSION: &str = "2.30.3";
const DATASOURCES_YML: &str = r#"
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    url: http://localhost:9090
    access: proxy
    isDefault: true
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

#[derive(Deserialize)]
struct Config {
    monitoring: MonitoringConfig,
    instances: Vec<InstanceConfig>,
}

#[derive(Deserialize)]
struct MonitoringConfig {
    region: String,
    instance_type: String,
    key_name: String,
    key_file: String,
    deployer_ip: Option<String>,
    dashboard: String,
}

#[derive(Deserialize)]
struct InstanceConfig {
    name: String,
    region: String,
    binary: String,
    config: String,
    instance_type: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("deployer")
        .version(PKG_VERSION)
        .about("Deploys individually specified EC2 instances with monitoring")
        .subcommand(
            SubCommand::with_name("create")
                .about("Sets up EC2 instances and deploys files with monitoring")
                .arg(Arg::with_name("config").long("config").takes_value(true).required(true).help("Path to YAML config file"))
        )
        .subcommand(
            SubCommand::with_name("destroy")
                .about("Deletes all deployed resources")
                .arg(Arg::with_name("tag").long("tag").takes_value(true).required(true).help("Deployment tag"))
        )
        .get_matches();

    match matches.subcommand() {
        ("setup", Some(sub_m)) => {
            let config_path = sub_m.value_of("config").unwrap();
            let config_file = std::fs::File::open(config_path)?;
            let mut config: Config = serde_yaml::from_reader(config_file)?;
            config.monitoring.deployer_ip = Some(config.monitoring.deployer_ip.unwrap_or_else(|| {
                reqwest::get("http://icanhazip.com").await.unwrap().text().await.unwrap().trim().to_string()
            }));

            let tag = format!("my-deployment-{}", Uuid::new_v4());

            // Collect unique regions
            let mut unique_regions = HashSet::new();
            unique_regions.insert(config.monitoring.region.clone());
            for instance in &config.instances {
                unique_regions.insert(instance.region.clone());
            }

            // Create network resources for each region
            let mut network_resources = HashMap::new();
            for region in &unique_regions {
                let ec2_client = create_ec2_client(region).await;
                let ami_id = find_latest_ami(&ec2_client).await?;
                let vpc_id = create_vpc(&ec2_client, &tag).await?;
                let igw_id = create_and_attach_igw(&ec2_client, &vpc_id, &tag).await?;
                let route_table_id = create_route_table(&ec2_client, &vpc_id, &igw_id, &tag).await?;
                let subnet_id = create_subnet(&ec2_client, &vpc_id, &route_table_id, &tag).await?;
                network_resources.insert(region.clone(), (ami_id, vpc_id, subnet_id, route_table_id));
            }

            // Deploy monitoring instance
            let monitoring_region = &config.monitoring.region;
            let (ami_id, vpc_id, subnet_id, _) = network_resources.get(monitoring_region).unwrap();
            let ec2_client = create_ec2_client(monitoring_region).await;
            let sg_monitoring = create_security_group_monitoring(&ec2_client, vpc_id, config.monitoring.deployer_ip.as_ref().unwrap(), &tag).await?;
            let monitoring_instance_id = launch_instances(&ec2_client, ami_id, &config.monitoring.instance_type, &config.monitoring.key_name, subnet_id, &[sg_monitoring.clone()], 1, &tag).await?[0].clone();
            let monitoring_ip = wait_for_instances_running(&ec2_client, &[monitoring_instance_id.clone()]).await?[0].clone();

            // Group and deploy regular instances
            let mut instances_by_region: HashMap<String, Vec<InstanceConfig>> = HashMap::new();
            for instance in config.instances {
                instances_by_region.entry(instance.region.clone()).or_insert_with(Vec::new).push(instance);
            }

            let mut all_regular_ips = Vec::new();
            for (region, instances) in &instances_by_region {
                let ec2_client = create_ec2_client(region).await;
                let (ami_id, vpc_id, subnet_id, _) = network_resources.get(region).unwrap();
                let sg_regular = create_security_group_regular(&ec2_client, vpc_id, config.monitoring.deployer_ip.as_ref().unwrap(), &tag).await?;
                for instance in instances {
                    let instance_id = launch_instances(&ec2_client, ami_id, &instance.instance_type, &config.monitoring.key_name, subnet_id, &[sg_regular.clone()], 1, &tag).await?[0].clone();
                    let ip = wait_for_instances_running(&ec2_client, &[instance_id.clone()]).await?[0].clone();
                    all_regular_ips.push((instance.name.clone(), region.clone(), ip.clone()));
                    scp_file(&config.monitoring.key_file, &instance.binary, &ip, "/home/ubuntu/binary").await?;
                    scp_file(&config.monitoring.key_file, &instance.config, &ip, "/home/ubuntu/config.conf").await?;
                    let run_cmd = "chmod +x /home/ubuntu/binary && nohup /home/ubuntu/binary --config /home/ubuntu/config.conf &";
                    ssh_execute(&config.monitoring.key_file, &ip, run_cmd).await?;
                }
            }

            // Update security groups
            let mut all_instance_ips = vec![monitoring_ip.clone()];
            all_instance_ips.extend(all_regular_ips.iter().map(|(_, _, ip)| ip.clone()));
            for region in &unique_regions {
                let ec2_client = create_ec2_client(region).await;
                let sg_monitoring_opt = if *region == monitoring_region { Some(sg_monitoring.clone()) } else { None };
                let sg_regular = network_resources.get(region).map(|(_, vpc_id, _, _)| create_security_group_regular(&ec2_client, vpc_id, config.monitoring.deployer_ip.as_ref().unwrap(), &tag)).transpose().await?;
                if let Some(sg) = sg_monitoring_opt {
                    for ip in &all_instance_ips {
                        add_sg_rule(&ec2_client, &sg, ip).await?;
                    }
                }
                if let Some(sg) = sg_regular {
                    for ip in &all_instance_ips {
                        add_sg_rule(&ec2_client, &sg, ip).await?;
                    }
                }
            }

            // Configure monitoring
            let regular_ips = all_regular_ips.iter().map(|(_, _, ip)| ip.clone()).collect::<Vec<_>>();
            let prom_config = generate_prometheus_config(&regular_ips);
            let temp_dir = TempDir::new("deployer")?;
            let prom_path = temp_dir.path().join("prometheus.yml");
            std::fs::write(&prom_path, prom_config)?;
            let datasources_path = temp_dir.path().join("datasources.yml");
            std::fs::write(&datasources_path, DATASOURCES_YML)?;
            let all_yaml_path = temp_dir.path().join("all.yml");
            std::fs::write(&all_yaml_path, ALL_YML)?;
            scp_file(&config.monitoring.key_file, prom_path.to_str().unwrap(), &monitoring_ip, "/home/ubuntu/prometheus.yml").await?;
            scp_file(&config.monitoring.key_file, datasources_path.to_str().unwrap(), &monitoring_ip, "/home/ubuntu/datasources.yml").await?;
            scp_file(&config.monitoring.key_file, all_yaml_path.to_str().unwrap(), &monitoring_ip, "/home/ubuntu/all.yml").await?;
            scp_file(&config.monitoring.key_file, &config.monitoring.dashboard, &monitoring_ip, "/home/ubuntu/dashboard.json").await?;

            let install_cmd = format!(
                r#"
sudo apt-get update -y
sudo apt-get install -y wget curl
wget https://github.com/prometheus/prometheus/releases/download/v{}/prometheus-{}.linux-amd64.tar.gz
tar xvfz prometheus-{}.linux-amd64.tar.gz
sudo mv prometheus-{}.linux-amd64 /opt/prometheus
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
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
"#,
                PROMETHEUS_VERSION, PROMETHEUS_VERSION, PROMETHEUS_VERSION, PROMETHEUS_VERSION
            );
            ssh_execute(&config.monitoring.key_file, &monitoring_ip, &install_cmd).await?;

            // Output results
            println!("Monitoring instance IP: {}", monitoring_ip);
            println!("Deployed instances:");
            for (name, region, ip) in all_regular_ips {
                println!("  {} ({}): {}", name, region, ip);
            }
            println!("Deployment tag: {}", tag);
        }
        ("teardown", Some(sub_m)) => {
            let tag = sub_m.value_of("tag").unwrap().to_string();
            let all_regions = vec!["us-east-1", "us-west-2", "eu-west-1"]; // Adjust based on your regions
            for region in all_regions {
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

async fn create_ec2_client(region: &str) -> Ec2Client {
    let region_provider = RegionProviderChain::default_provider().or_else(aws_config::Region::new(region.to_string()));
    let config = aws_config::from_env().region(region_provider).load().await;
    Ec2Client::new(&config)
}

async fn find_latest_ami(ec2_client: &Ec2Client) -> Result<String, Ec2Error> {
    let resp = ec2_client.describe_images()
        .filters(Filter::builder().name("name").values("ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*").build())
        .filters(Filter::builder().name("root-device-type").values("ebs").build())
        .filters(Filter::builder().name("virtualization-type").values("hvm").build())
        .owners("099720109477") // Canonical's AWS account ID
        .send()
        .await?;
    let mut images = resp.images.unwrap_or_default();
    images.sort_by(|a, b| b.creation_date.cmp(&a.creation_date));
    Ok(images[0].image_id.as_ref().unwrap().clone())
}

async fn create_vpc(ec2_client: &Ec2Client, tag: &str) -> Result<String, Ec2Error> {
    let resp = ec2_client.create_vpc()
        .cidr_block("10.0.0.0/16")
        .tag_specifications(TagSpecification::builder()
            .resource_type(ResourceType::Vpc)
            .tags(Tag::builder().key("deployer").value(tag).build())
            .build())
        .send()
        .await?;
    Ok(resp.vpc.unwrap().vpc_id.unwrap())
}

async fn create_and_attach_igw(ec2_client: &Ec2Client, vpc_id: &str, tag: &str) -> Result<String, Ec2Error> {
    let resp = ec2_client.create_internet_gateway()
        .tag_specifications(TagSpecification::builder()
            .resource_type(ResourceType::InternetGateway)
            .tags(Tag::builder().key("deployer").value(tag).build())
            .build())
        .send()
        .await?;
    let igw_id = resp.internet_gateway.unwrap().internet_gateway_id.unwrap();
    ec2_client.attach_internet_gateway()
        .internet_gateway_id(&igw_id)
        .vpc_id(vpc_id)
        .send()
        .await?;
    Ok(igw_id)
}

async fn create_route_table(ec2_client: &Ec2Client, vpc_id: &str, igw_id: &str, tag: &str) -> Result<String, Ec2Error> {
    let resp = ec2_client.create_route_table()
        .vpc_id(vpc_id)
        .tag_specifications(TagSpecification::builder()
            .resource_type(ResourceType::RouteTable)
            .tags(Tag::builder().key("deployer").value(tag).build())
            .build())
        .send()
        .await?;
    let route_table_id = resp.route_table.unwrap().route_table_id.unwrap();
    ec2_client.create_route()
        .route_table_id(&route_table_id)
        .destination_cidr_block("0.0.0.0/0")
        .gateway_id(igw_id)
        .send()
        .await?;
    Ok(route_table_id)
}

async fn create_subnet(ec2_client: &Ec2Client, vpc_id: &str, route_table_id: &str, tag: &str) -> Result<String, Ec2Error> {
    let resp = ec2_client.create_subnet()
        .vpc_id(vpc_id)
        .cidr_block("10.0.1.0/24")
        .tag_specifications(TagSpecification::builder()
            .resource_type(ResourceType::Subnet)
            .tags(Tag::builder().key("deployer").value(tag).build())
            .build())
        .send()
        .await?;
    let subnet_id = resp.subnet.unwrap().subnet_id.unwrap();
    ec2_client.associate_route_table()
        .route_table_id(route_table_id)
        .subnet_id(&subnet_id)
        .send()
        .await?;
    Ok(subnet_id)
}

async fn create_security_group_monitoring(ec2_client: &Ec2Client, vpc_id: &str, deployer_ip: &str, tag: &str) -> Result<String, Ec2Error> {
    let sg = ec2_client.create_security_group()
        .group_name(format!("monitor-sg-{}", tag))
        .description("Security group for monitoring instance")
        .vpc_id(vpc_id)
        .tag_specifications(TagSpecification::builder()
            .resource_type(ResourceType::SecurityGroup)
            .tags(Tag::builder().key("deployer").value(tag).build())
            .build())
        .send()
        .await?;
    let sg_id = sg.group_id.unwrap();
    ec2_client.authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(22)
            .to_port(22)
            .ip_ranges(IpRange::builder().cidr_ip(format!("{}/32", deployer_ip)).build())
            .build())
        .ip_permissions(IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(3000)
            .to_port(3000)
            .ip_ranges(IpRange::builder().cidr_ip(format!("{}/32", deployer_ip)).build())
            .build())
        .send()
        .await?;
    Ok(sg_id)
}

async fn create_security_group_regular(ec2_client: &Ec2Client, vpc_id: &str, deployer_ip: &str, tag: &str) -> Result<String, Ec2Error> {
    let sg = ec2_client.create_security_group()
        .group_name(format!("regular-sg-{}", tag))
        .description("Security group for regular instances")
        .vpc_id(vpc_id)
        .tag_specifications(TagSpecification::builder()
            .resource_type(ResourceType::SecurityGroup)
            .tags(Tag::builder().key("deployer").value(tag).build())
            .build())
        .send()
        .await?;
    let sg_id = sg.group_id.unwrap();
    ec2_client.authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(22)
            .to_port(22)
            .ip_ranges(IpRange::builder().cidr_ip(format!("{}/32", deployer_ip)).build())
            .build())
        .send()
        .await?;
    Ok(sg_id)
}

async fn launch_instances(ec2_client: &Ec2Client, ami_id: &str, instance_type: &str, key_name: &str, subnet_id: &str, security_group_ids: &[String], count: i32, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client.run_instances()
        .image_id(ami_id)
        .instance_type(instance_type)
        .key_name(key_name)
        .subnet_id(subnet_id)
        .security_group_ids(&security_group_ids)
        .min_count(count)
        .max_count(count)
        .tag_specifications(TagSpecification::builder()
            .resource_type(ResourceType::Instance)
            .tags(Tag::builder().key("deployer").value(tag).build())
            .build())
        .send()
        .await?;
    let instance_ids = resp.instances.unwrap().into_iter()
        .map(|i| i.instance_id.unwrap())
        .collect();
    Ok(instance_ids)
}

async fn wait_for_instances_running(ec2_client: &Ec2Client, instance_ids: &[String]) -> Result<Vec<String>, Ec2Error> {
    loop {
        let resp = ec2_client.describe_instances()
            .instance_ids(&instance_ids)
            .send()
            .await?;
        let instances = resp.reservations.unwrap_or_default()
            .into_iter()
            .flat_map(|r| r.instances.unwrap_or_default())
            .collect::<Vec<_>>();
        if instances.len() == instance_ids.len() && instances.iter().all(|i| i.state.as_ref().unwrap().name.as_ref().unwrap() == "running") {
            return Ok(instances.into_iter()
                .map(|i| i.public_ip_address.unwrap())
                .collect());
        }
        sleep(Duration::from_secs(5)).await;
    }
}

async fn add_sg_rule(ec2_client: &Ec2Client, sg_id: &str, ip: &str) -> Result<(), Ec2Error> {
    ec2_client.authorize_security_group_ingress()
        .group_id(sg_id)
        .ip_permissions(IpPermission::builder()
            .ip_protocol("tcp")
            .from_port(9090)
            .to_port(9090)
            .ip_ranges(IpRange::builder().cidr_ip(format!("{}/32", ip)).build())
            .build())
        .send()
        .await
        .or_else(|e| if e.code() == Some("InvalidPermission.Duplicate") { Ok(()) } else { Err(e) })?;
    Ok(())
}

async fn scp_file(key_file: &str, src: &str, ip: &str, dest: &str) -> Result<(), Box<dyn Error>> {
    let status = Command::new("scp")
        .arg("-i")
        .arg(key_file)
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg(src)
        .arg(format!("ubuntu@{}:{}", ip, dest))
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
        return Err("SSH command failed".into());
    }
    Ok(())
}

fn generate_prometheus_config(ips: &[String]) -> String {
    let targets = ips.iter().map(|ip| format!("'{}:9090'", ip)).collect::<Vec<_>>().join(", ");
    format!(
        r#"
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'my-app'
    static_configs:
      - targets: [{}]
"#,
        targets
    )
}

async fn find_instances_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client.describe_instances()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp.reservations.unwrap_or_default()
        .into_iter()
        .flat_map(|r| r.instances.unwrap_or_default())
        .map(|i| i.instance_id.unwrap())
        .collect())
}

async fn terminate_instances(ec2_client: &Ec2Client, instance_ids: &[String]) -> Result<(), Ec2Error> {
    if instance_ids.is_empty() { return Ok(()); }
    ec2_client.terminate_instances()
        .set_instance_ids(Some(instance_ids.to_vec()))
        .send()
        .await?;
    Ok(())
}

async fn wait_for_instances_terminated(ec2_client: &Ec2Client, instance_ids: &[String]) -> Result<(), Ec2Error> {
    loop {
        let resp = ec2_client.describe_instances()
            .instance_ids(&instance_ids)
            .send()
            .await?;
        let instances = resp.reservations.unwrap_or_default()
            .into_iter()
            .flat_map(|r| r.instances.unwrap_or_default())
            .collect::<Vec<_>>();
        if instances.iter().all(|i| i.state.as_ref().unwrap().name.as_ref().unwrap() == "terminated") {
            return Ok(());
        }
        sleep(Duration::from_secs(5)).await;
    }
}

async fn find_security_groups_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client.describe_security_groups()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp.security_groups.unwrap_or_default()
        .into_iter()
        .map(|sg| sg.group_id.unwrap())
        .collect())
}

async fn delete_security_group(ec2_client: &Ec2Client, sg_id: &str) -> Result<(), Ec2Error> {
    ec2_client.delete_security_group()
        .group_id(sg_id)
        .send()
        .await?;
    Ok(())
}

async fn find_route_tables_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client.describe_route_tables()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp.route_tables.unwrap_or_default()
        .into_iter()
        .map(|rt| rt.route_table_id.unwrap())
        .collect())
}

async fn delete_route_table(ec2_client: &Ec2Client, rt_id: &str) -> Result<(), Ec2Error> {
    ec2_client.delete_route_table()
        .route_table_id(rt_id)
        .send()
        .await?;
    Ok(())
}

async fn find_igws_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client.describe_internet_gateways()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp.internet_gateways.unwrap_or_default()
        .into_iter()
        .map(|igw| igw.internet_gateway_id.unwrap())
        .collect())
}

async fn find_vpc_by_igw(ec2_client: &Ec2Client, igw_id: &str) -> Result<String, Ec2Error> {
    let resp = ec2_client.describe_internet_gateways()
        .internet_gateway_ids(igw_id)
        .send()
        .await?;
    Ok(resp.internet_gateways.unwrap()[0].attachments.as_ref().unwrap()[0].vpc_id.as_ref().unwrap().clone())
}

async fn detach_igw(ec2_client: &Ec2Client, igw_id: &str, vpc_id: &str) -> Result<(), Ec2Error> {
    ec2_client.detach_internet_gateway()
        .internet_gateway_id(igw_id)
        .vpc_id(vpc_id)
        .send()
        .await?;
    Ok(())
}

async fn delete_igw(ec2_client: &Ec2Client, igw_id: &str) -> Result<(), Ec2Error> {
    ec2_client.delete_internet_gateway()
        .internet_gateway_id(igw_id)
        .send()
        .await?;
    Ok(())
}

async fn find_subnets_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client.describe_subnets()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp.subnets.unwrap_or_default()
        .into_iter()
        .map(|subnet| subnet.subnet_id.unwrap())
        .collect())
}

async fn delete_subnet(ec2_client: &Ec2Client, subnet_id: &str) -> Result<(), Ec2Error> {
    ec2_client.delete_subnet()
        .subnet_id(subnet_id)
        .send()
        .await?;
    Ok(())
}

async fn find_vpcs_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client.describe_vpcs()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp.vpcs.unwrap_or_default()
        .into_iter()
        .map(|vpc| vpc.vpc_id.unwrap())
        .collect())
}

async fn delete_vpc(ec2_client: &Ec2Client, vpc_id: &str) -> Result<(), Ec2Error> {
    ec2_client.delete_vpc()
        .vpc_id(vpc_id)
        .send()
        .await?;
    Ok(())
}