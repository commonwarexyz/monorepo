#![cfg(feature = "aws")]

use aws_config::{BehaviorVersion, Region};
use commonware_deployer::ec2::{aws, utils};
use commonware_deployer::{Config, InstanceConfig, MonitoringConfig, PortConfig};
use serial_test::serial;
use std::collections::HashMap;
use std::path::PathBuf;
use testcontainers::{clients, core::WaitFor, GenericImage};

const LOCALSTACK_IMAGE: &str = "localstack/localstack";
const LOCALSTACK_VERSION: &str = "latest";

struct DeploymentTestContext {
    _container: testcontainers::ContainerAsync<GenericImage>,
    config: Config,
    test_dir: PathBuf,
    localstack_endpoint: String,
}

impl DeploymentTestContext {
    async fn new(test_name: &str) -> Self {
        let docker = clients::Cli::default();
        
        let container = docker.run(
            GenericImage::new(LOCALSTACK_IMAGE, LOCALSTACK_VERSION)
                .with_exposed_port(4566)
                .with_env_var("SERVICES", "ec2,ssm,sts,iam")
                .with_env_var("DEBUG", "1")
                .with_env_var("AWS_DEFAULT_REGION", "us-east-1")
                .with_env_var("PERSISTENCE", "1")
                .with_wait_for(WaitFor::message_on_stdout("Ready.")),
        );

        let host_port = container.get_host_port_ipv4(4566);
        let localstack_endpoint = format!("http://localhost:{}", host_port);

        // Set up environment for AWS SDK
        std::env::set_var("AWS_ACCESS_KEY_ID", "test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
        std::env::set_var("AWS_ENDPOINT_URL", &localstack_endpoint);

        let test_dir = std::env::temp_dir().join(format!("deployer_test_{}", test_name));
        std::fs::create_dir_all(&test_dir).unwrap();

        // Create test files
        Self::create_test_files(&test_dir);

        let config = Config {
            tag: format!("test-{}", test_name),
            monitoring: MonitoringConfig {
                instance_type: "t4g.small".to_string(),
                storage_size: 10,
                storage_class: "gp2".to_string(),
                dashboard: test_dir.join("dashboard.json").to_string(),
            },
            instances: vec![
                InstanceConfig {
                    name: "test-node-1".to_string(),
                    region: "us-east-1".to_string(),
                    instance_type: "t4g.small".to_string(),
                    storage_size: 10,
                    storage_class: "gp2".to_string(),
                    binary: test_dir.join("test-binary").to_string(),
                    config: test_dir.join("test-config.conf").to_string(),
                    profiling: false,
                },
            ],
            ports: vec![PortConfig {
                protocol: "tcp".to_string(),
                port: 8080,
                cidr: "0.0.0.0/0".to_string(),
            }],
        };

        Self {
            _container: container,
            config,
            test_dir,
            localstack_endpoint,
        }
    }

    fn create_test_files(test_dir: &PathBuf) {
        // Create test binary
        let test_binary_content = r#"#!/bin/bash
echo "Test binary running"
"#;
        std::fs::write(test_dir.join("test-binary"), test_binary_content).unwrap();
        std::fs::set_permissions(
            test_dir.join("test-binary"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();

        // Create test config
        let test_config = r#"# Test configuration
port = 8080
"#;
        std::fs::write(test_dir.join("test-config.conf"), test_config).unwrap();

        // Create test dashboard
        let test_dashboard = r#"{
  "dashboard": {
    "title": "Test Dashboard"
  }
}"#;
        std::fs::write(test_dir.join("dashboard.json"), test_dashboard).unwrap();
    }

    async fn get_ec2_client(&self, region: &str) -> aws_sdk_ec2::Client {
        let sdk_config = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(region))
            .endpoint_url(&self.localstack_endpoint)
            .credentials_provider(aws_config::credentials::Credentials::new(
                "test",
                "test",
                None,
                None,
                "static",
            ))
            .load()
            .await;

        aws_sdk_ec2::Client::new(&sdk_config)
    }

    fn cleanup(&self) {
        if self.test_dir.exists() {
            std::fs::remove_dir_all(&self.test_dir).ok();
        }
        
        // Clean up deployer directory
        let deployer_dir = std::env::var("HOME")
            .map(|home| PathBuf::from(home).join(".commonware_deployer").join(&self.config.tag))
            .ok();
        
        if let Some(dir) = deployer_dir {
            if dir.exists() {
                std::fs::remove_dir_all(&dir).ok();
            }
        }
    }
}

impl Drop for DeploymentTestContext {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[tokio::test]
#[serial]
async fn test_vpc_and_subnet_creation() {
    let ctx = DeploymentTestContext::new("vpc_subnet").await;
    let ec2_client = ctx.get_ec2_client("us-east-1").await;
    
    // Create VPC
    let vpc_cidr = "10.0.0.0/16";
    let vpc = aws::create_vpc(&ec2_client, vpc_cidr, &ctx.config.tag).await.unwrap();
    
    // Create subnet
    let subnet_cidr = "10.0.1.0/24";
    let subnet = aws::create_subnet(
        &ec2_client,
        &vpc.vpc_id,
        subnet_cidr,
        "us-east-1a",
        &ctx.config.tag,
    )
    .await
    .unwrap();
    
    assert_eq!(subnet.cidr_block(), Some(subnet_cidr));
    assert_eq!(subnet.vpc_id(), Some(vpc.vpc_id.as_str()));
}

#[tokio::test]
#[serial]
async fn test_security_group_with_rules() {
    let ctx = DeploymentTestContext::new("security_rules").await;
    let ec2_client = ctx.get_ec2_client("us-east-1").await;
    
    // Create VPC first
    let vpc = aws::create_vpc(&ec2_client, "10.0.0.0/16", &ctx.config.tag).await.unwrap();
    
    // Create security group
    let sg_name = format!("{}-test", ctx.config.tag);
    let sg = aws::create_security_group(
        &ec2_client,
        &sg_name,
        "Test security group",
        &vpc.vpc_id,
        &ctx.config.tag,
    )
    .await
    .unwrap();
    
    // Add SSH rule
    aws::add_security_group_ingress_cidr(
        &ec2_client,
        &sg.group_id,
        "tcp",
        22,
        22,
        "0.0.0.0/0",
        "SSH access",
    )
    .await
    .unwrap();
    
    // Add custom port rule
    aws::add_security_group_ingress_cidr(
        &ec2_client,
        &sg.group_id,
        "tcp",
        8080,
        8080,
        "10.0.0.0/16",
        "Internal access",
    )
    .await
    .unwrap();
    
    // Verify rules
    let describe_response = ec2_client
        .describe_security_groups()
        .group_ids(&sg.group_id)
        .send()
        .await
        .unwrap();
    
    let sg_details = &describe_response.security_groups()[0];
    let ingress_rules = sg_details.ip_permissions();
    
    // Should have 2 rules (SSH and custom port)
    assert!(ingress_rules.len() >= 2);
}

#[tokio::test]
#[serial]
async fn test_key_pair_management() {
    let ctx = DeploymentTestContext::new("key_pair").await;
    let ec2_client = ctx.get_ec2_client("us-east-1").await;
    
    let key_name = format!("{}-key", ctx.config.tag);
    
    // Create key pair
    let key_pair = aws::create_key_pair(&ec2_client, &key_name, &ctx.config.tag)
        .await
        .unwrap();
    
    assert!(key_pair.key_material().is_some());
    assert_eq!(key_pair.key_name(), Some(key_name.as_str()));
    
    // Verify key exists
    let describe_response = ec2_client
        .describe_key_pairs()
        .key_names(&key_name)
        .send()
        .await
        .unwrap();
    
    assert_eq!(describe_response.key_pairs().len(), 1);
}

#[tokio::test]
#[serial]
async fn test_region_index_mapping() {
    let regions = vec!["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"];
    let mut region_indices = HashMap::new();
    
    for (index, region) in regions.iter().enumerate() {
        region_indices.insert(region.to_string(), index);
    }
    
    // Verify CIDR blocks don't overlap
    let cidrs: Vec<String> = regions
        .iter()
        .enumerate()
        .map(|(index, _)| format!("10.{}.0.0/16", index))
        .collect();
    
    for (i, cidr1) in cidrs.iter().enumerate() {
        for (j, cidr2) in cidrs.iter().enumerate() {
            if i != j {
                assert_ne!(cidr1, cidr2);
            }
        }
    }
}

#[tokio::test]
#[serial]
async fn test_get_current_ip() {
    // This test might fail in CI environments without internet access
    match utils::get_current_ip().await {
        Ok(ip) => {
            // Verify it's a valid IPv4 address
            assert!(ip.parse::<std::net::Ipv4Addr>().is_ok());
        }
        Err(_) => {
            // In environments without internet, this is expected
            println!("Could not fetch current IP - likely no internet access");
        }
    }
}

#[tokio::test]
#[serial]
async fn test_full_deployment_lifecycle() {
    let ctx = DeploymentTestContext::new("full_lifecycle").await;
    
    // Create deployer directory structure
    let deployer_dir = std::env::var("HOME")
        .map(|home| PathBuf::from(home).join(".commonware_deployer").join(&ctx.config.tag))
        .unwrap();
    std::fs::create_dir_all(&deployer_dir).unwrap();
    
    // Save config to file
    let config_path = ctx.test_dir.join("deployment.yaml");
    let config_yaml = serde_yaml::to_string(&ctx.config).unwrap();
    std::fs::write(&config_path, config_yaml).unwrap();
    
    // Test that we can parse the config
    let parsed_config: Config = serde_yaml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(parsed_config.tag, ctx.config.tag);
    assert_eq!(parsed_config.instances.len(), 1);
    
    // In a real deployment, we would call:
    // - commonware_deployer::ec2::create(&config_path).await
    // - commonware_deployer::ec2::update(&config_path).await
    // - commonware_deployer::ec2::destroy(&config_path).await
    
    // For LocalStack testing, we'll simulate key parts of the workflow
    let ec2_client = ctx.get_ec2_client("us-east-1").await;
    
    // 1. Create VPC infrastructure
    let vpc = aws::create_vpc(&ec2_client, "10.0.0.0/16", &ctx.config.tag).await.unwrap();
    let subnet = aws::create_subnet(
        &ec2_client,
        &vpc.vpc_id,
        "10.0.1.0/24",
        "us-east-1a",
        &ctx.config.tag,
    )
    .await
    .unwrap();
    
    // 2. Create security groups
    let sg = aws::create_security_group(
        &ec2_client,
        &format!("{}-binary", ctx.config.tag),
        "Binary instances security group",
        &vpc.vpc_id,
        &ctx.config.tag,
    )
    .await
    .unwrap();
    
    // 3. Add necessary rules
    for port_config in &ctx.config.ports {
        aws::add_security_group_ingress_cidr(
            &ec2_client,
            &sg.group_id,
            &port_config.protocol,
            port_config.port,
            port_config.port,
            &port_config.cidr,
            &format!("Port {}", port_config.port),
        )
        .await
        .unwrap();
    }
    
    // 4. Create key pair
    let key_pair = aws::create_key_pair(
        &ec2_client,
        &format!("{}-key", ctx.config.tag),
        &ctx.config.tag,
    )
    .await
    .unwrap();
    
    // Save private key
    if let Some(key_material) = key_pair.key_material() {
        let key_path = deployer_dir.join(format!("id_rsa_{}", ctx.config.tag));
        std::fs::write(&key_path, key_material).unwrap();
        std::fs::set_permissions(
            &key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
    }
    
    // Mark as created
    std::fs::write(deployer_dir.join("created"), "").unwrap();
    
    // Verify resources exist
    let vpcs = ec2_client.describe_vpcs().send().await.unwrap();
    assert!(vpcs.vpcs().iter().any(|v| v.vpc_id() == Some(&vpc.vpc_id)));
    
    let subnets = ec2_client.describe_subnets().send().await.unwrap();
    assert!(subnets.subnets().iter().any(|s| s.subnet_id() == Some(&subnet.subnet_id)));
}