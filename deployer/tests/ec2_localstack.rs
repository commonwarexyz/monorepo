#![cfg(feature = "aws")]

mod common;

use aws_config::{BehaviorVersion, Region};
use aws_sdk_ec2::Client as Ec2Client;
use common::{LocalStackContainer, TestFiles, cleanup_deployer_dir};
use commonware_deployer::{Config, Host, Hosts, InstanceConfig, MonitoringConfig, PortConfig};
use serial_test::serial;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use testcontainers::{clients, core::WaitFor, GenericImage};

const LOCALSTACK_IMAGE: &str = "localstack/localstack";
const LOCALSTACK_VERSION: &str = "latest";

struct LocalStackTestContext {
    _container: testcontainers::ContainerAsync<GenericImage>,
    sdk_config: SdkConfig,
    test_dir: PathBuf,
}

impl LocalStackTestContext {
    async fn new(test_name: &str) -> Self {
        let docker = clients::Cli::default();
        
        let container = docker.run(
            GenericImage::new(LOCALSTACK_IMAGE, LOCALSTACK_VERSION)
                .with_exposed_port(4566)
                .with_env_var("SERVICES", "ec2,ssm,sts,iam")
                .with_env_var("DEBUG", "1")
                .with_env_var("AWS_DEFAULT_REGION", "us-east-1")
                .with_wait_for(WaitFor::message_on_stdout("Ready.")),
        );

        let host_port = container.get_host_port_ipv4(4566);
        let localstack_endpoint = format!("http://localhost:{}", host_port);

        let sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(&localstack_endpoint)
            .credentials_provider(aws_config::credentials::Credentials::new(
                "test",
                "test",
                None,
                None,
                "static",
            ))
            .load()
            .await;

        let test_dir = std::env::temp_dir().join(format!("deployer_test_{}", test_name));
        std::fs::create_dir_all(&test_dir).unwrap();

        Self {
            _container: container,
            sdk_config,
            test_dir,
        }
    }

    fn create_test_config(&self, tag: &str) -> Config {
        Config {
            tag: tag.to_string(),
            monitoring: MonitoringConfig {
                instance_type: "t4g.small".to_string(),
                storage_size: 10,
                storage_class: "gp2".to_string(),
                dashboard: self.test_dir.join("dashboard.json").to_string(),
            },
            instances: vec![
                InstanceConfig {
                    name: "test-node-1".to_string(),
                    region: "us-east-1".to_string(),
                    instance_type: "t4g.small".to_string(),
                    storage_size: 10,
                    storage_class: "gp2".to_string(),
                    binary: self.test_dir.join("test-binary").to_string(),
                    config: self.test_dir.join("test-config.conf").to_string(),
                    profiling: false,
                },
                InstanceConfig {
                    name: "test-node-2".to_string(),
                    region: "us-west-2".to_string(),
                    instance_type: "t4g.small".to_string(),
                    storage_size: 10,
                    storage_class: "gp2".to_string(),
                    binary: self.test_dir.join("test-binary").to_string(),
                    config: self.test_dir.join("test-config.conf").to_string(),
                    profiling: true,
                },
            ],
            ports: vec![PortConfig {
                protocol: "tcp".to_string(),
                port: 8080,
                cidr: "0.0.0.0/0".to_string(),
            }],
        }
    }

    async fn ec2_client(&self) -> Ec2Client {
        Ec2Client::new(&self.sdk_config)
    }

    fn cleanup(&self) {
        if self.test_dir.exists() {
            std::fs::remove_dir_all(&self.test_dir).ok();
        }
    }
}

impl Drop for LocalStackTestContext {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[tokio::test]
#[serial]
async fn test_vpc_creation() {
    let ctx = LocalStackTestContext::new("vpc_creation").await;
    let ec2_client = ctx.ec2_client().await;

    // Create a VPC
    let vpc_response = ec2_client
        .create_vpc()
        .cidr_block("10.0.0.0/16")
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::Vpc)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value("test-vpc")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    let vpc_id = vpc_response.vpc().unwrap().vpc_id().unwrap();

    // Verify VPC exists
    let describe_response = ec2_client
        .describe_vpcs()
        .vpc_ids(vpc_id)
        .send()
        .await
        .unwrap();

    assert_eq!(describe_response.vpcs().len(), 1);
    assert_eq!(
        describe_response.vpcs()[0].cidr_block().unwrap(),
        "10.0.0.0/16"
    );
}

#[tokio::test]
#[serial]
async fn test_security_group_creation() {
    let ctx = LocalStackTestContext::new("security_group").await;
    let ec2_client = ctx.ec2_client().await;

    // First create a VPC
    let vpc_response = ec2_client
        .create_vpc()
        .cidr_block("10.0.0.0/16")
        .send()
        .await
        .unwrap();

    let vpc_id = vpc_response.vpc().unwrap().vpc_id().unwrap();

    // Create a security group
    let sg_response = ec2_client
        .create_security_group()
        .group_name("test-sg")
        .description("Test security group")
        .vpc_id(vpc_id)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::SecurityGroup)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value("test-sg")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    let sg_id = sg_response.group_id().unwrap();

    // Add ingress rule
    let _ingress_response = ec2_client
        .authorize_security_group_ingress()
        .group_id(sg_id)
        .ip_permissions(
            aws_sdk_ec2::types::IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(22)
                .to_port(22)
                .ip_ranges(
                    aws_sdk_ec2::types::IpRange::builder()
                        .cidr_ip("0.0.0.0/0")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    // Verify security group exists
    let describe_response = ec2_client
        .describe_security_groups()
        .group_ids(sg_id)
        .send()
        .await
        .unwrap();

    assert_eq!(describe_response.security_groups().len(), 1);
    assert_eq!(
        describe_response.security_groups()[0].group_name().unwrap(),
        "test-sg"
    );
}

#[tokio::test]
#[serial]
async fn test_instance_launch() {
    let ctx = LocalStackTestContext::new("instance_launch").await;
    let ec2_client = ctx.ec2_client().await;

    // Create VPC
    let vpc_response = ec2_client
        .create_vpc()
        .cidr_block("10.0.0.0/16")
        .send()
        .await
        .unwrap();

    let vpc_id = vpc_response.vpc().unwrap().vpc_id().unwrap();

    // Create subnet
    let subnet_response = ec2_client
        .create_subnet()
        .vpc_id(vpc_id)
        .cidr_block("10.0.1.0/24")
        .availability_zone("us-east-1a")
        .send()
        .await
        .unwrap();

    let subnet_id = subnet_response.subnet().unwrap().subnet_id().unwrap();

    // Create security group
    let sg_response = ec2_client
        .create_security_group()
        .group_name("test-instance-sg")
        .description("Test instance security group")
        .vpc_id(vpc_id)
        .send()
        .await
        .unwrap();

    let sg_id = sg_response.group_id().unwrap();

    // Launch instance
    let instance_response = ec2_client
        .run_instances()
        .image_id("ami-12345678") // LocalStack accepts any AMI ID
        .instance_type(aws_sdk_ec2::types::InstanceType::T4gSmall)
        .min_count(1)
        .max_count(1)
        .security_group_ids(sg_id)
        .subnet_id(subnet_id)
        .tag_specifications(
            aws_sdk_ec2::types::TagSpecification::builder()
                .resource_type(aws_sdk_ec2::types::ResourceType::Instance)
                .tags(
                    aws_sdk_ec2::types::Tag::builder()
                        .key("Name")
                        .value("test-instance")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(instance_response.instances().len(), 1);
    
    let instance_id = instance_response.instances()[0].instance_id().unwrap();

    // Verify instance exists
    let describe_response = ec2_client
        .describe_instances()
        .instance_ids(instance_id)
        .send()
        .await
        .unwrap();

    assert_eq!(describe_response.reservations().len(), 1);
    assert_eq!(describe_response.reservations()[0].instances().len(), 1);
}

#[tokio::test]
#[serial]
async fn test_multi_region_setup() {
    let ctx = LocalStackTestContext::new("multi_region").await;
    
    // Test creating resources in multiple regions
    let regions = vec!["us-east-1", "us-west-2"];
    
    for (index, region) in regions.iter().enumerate() {
        let regional_config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(*region))
            .endpoint_url("http://localhost:4566")
            .credentials_provider(aws_config::credentials::Credentials::new(
                "test",
                "test",
                None,
                None,
                "static",
            ))
            .load()
            .await;
        
        let ec2_client = Ec2Client::new(&regional_config);
        
        // Create VPC with region-specific CIDR
        let cidr = format!("10.{}.0.0/16", index);
        let vpc_response = ec2_client
            .create_vpc()
            .cidr_block(&cidr)
            .tag_specifications(
                aws_sdk_ec2::types::TagSpecification::builder()
                    .resource_type(aws_sdk_ec2::types::ResourceType::Vpc)
                    .tags(
                        aws_sdk_ec2::types::Tag::builder()
                            .key("Name")
                            .value(format!("test-vpc-{}", region))
                            .build(),
                    )
                    .build(),
            )
            .send()
            .await
            .unwrap();
        
        assert!(vpc_response.vpc().is_some());
    }
}

#[tokio::test]
#[serial]
async fn test_create_hosts_yaml() {
    let monitoring_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 10));
    let hosts = Hosts {
        monitoring: monitoring_ip,
        hosts: vec![
            Host {
                name: "node1".to_string(),
                region: "us-east-1".to_string(),
                ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 20)),
            },
            Host {
                name: "node2".to_string(),
                region: "us-west-2".to_string(),
                ip: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 20)),
            },
        ],
    };
    
    let yaml = serde_yaml::to_string(&hosts).unwrap();
    assert!(yaml.contains("monitoring: 10.0.1.10"));
    assert!(yaml.contains("name: node1"));
    assert!(yaml.contains("region: us-east-1"));
}

// Helper to create test files
fn create_test_files(test_dir: &PathBuf) {
    // Create test binary (just a simple shell script for testing)
    let test_binary_content = r#"#!/bin/bash
echo "Test binary running"
while true; do
    sleep 10
done
"#;
    std::fs::write(test_dir.join("test-binary"), test_binary_content).unwrap();
    
    // Create test config
    let test_config = r#"# Test configuration
port = 8080
log_level = "info"
"#;
    std::fs::write(test_dir.join("test-config.conf"), test_config).unwrap();
    
    // Create test dashboard
    let test_dashboard = r#"{
  "dashboard": {
    "title": "Test Dashboard",
    "panels": []
  }
}"#;
    std::fs::write(test_dir.join("dashboard.json"), test_dashboard).unwrap();
}

#[tokio::test]
#[serial]
async fn test_config_serialization() {
    let ctx = LocalStackTestContext::new("config_serialization").await;
    create_test_files(&ctx.test_dir);
    
    let config = ctx.create_test_config("test-deployment");
    
    // Serialize to YAML
    let yaml = serde_yaml::to_string(&config).unwrap();
    
    // Deserialize back
    let deserialized: Config = serde_yaml::from_str(&yaml).unwrap();
    
    assert_eq!(deserialized.tag, "test-deployment");
    assert_eq!(deserialized.instances.len(), 2);
    assert_eq!(deserialized.ports.len(), 1);
    assert_eq!(deserialized.monitoring.instance_type, "t4g.small");
}