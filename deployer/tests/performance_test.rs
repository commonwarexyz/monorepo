#![cfg(feature = "aws")]

mod common;

use aws_sdk_ec2::types::{InstanceType, ResourceType, Tag, TagSpecification};
use common::{LocalStackContainer, TestFiles};
use serial_test::serial;
use std::time::{Duration, Instant};

#[tokio::test]
#[serial]
async fn test_vpc_creation_performance() {
    let container = LocalStackContainer::new().await;
    let ec2_client = container.ec2_client("us-east-1").await;
    
    let start = Instant::now();
    
    // Create 10 VPCs
    for i in 0..10 {
        let cidr = format!("10.{}.0.0/16", i);
        let _vpc = ec2_client
            .create_vpc()
            .cidr_block(&cidr)
            .tag_specifications(
                TagSpecification::builder()
                    .resource_type(ResourceType::Vpc)
                    .tags(
                        Tag::builder()
                            .key("Name")
                            .value(format!("perf-test-vpc-{}", i))
                            .build(),
                    )
                    .build(),
            )
            .send()
            .await
            .unwrap();
    }
    
    let duration = start.elapsed();
    
    // VPC creation should be fast even with 10 VPCs
    assert!(duration < Duration::from_secs(5), 
        "VPC creation took too long: {:?}", duration);
}

#[tokio::test]
#[serial]
async fn test_parallel_instance_launch_performance() {
    let container = LocalStackContainer::new().await;
    let ec2_client = container.ec2_client("us-east-1").await;
    
    // Create VPC and subnet first
    let vpc = ec2_client
        .create_vpc()
        .cidr_block("10.0.0.0/16")
        .send()
        .await
        .unwrap();
    
    let subnet = ec2_client
        .create_subnet()
        .vpc_id(vpc.vpc().unwrap().vpc_id().unwrap())
        .cidr_block("10.0.1.0/24")
        .availability_zone("us-east-1a")
        .send()
        .await
        .unwrap();
    
    let sg = ec2_client
        .create_security_group()
        .group_name("perf-test-sg")
        .description("Performance test security group")
        .vpc_id(vpc.vpc().unwrap().vpc_id().unwrap())
        .send()
        .await
        .unwrap();
    
    let start = Instant::now();
    
    // Launch 5 instances in parallel
    let mut tasks = Vec::new();
    for i in 0..5 {
        let ec2_client = ec2_client.clone();
        let subnet_id = subnet.subnet().unwrap().subnet_id().unwrap().to_string();
        let sg_id = sg.group_id().unwrap().to_string();
        
        let task = tokio::spawn(async move {
            ec2_client
                .run_instances()
                .image_id("ami-12345678")
                .instance_type(InstanceType::T4gSmall)
                .min_count(1)
                .max_count(1)
                .security_group_ids(&sg_id)
                .subnet_id(&subnet_id)
                .tag_specifications(
                    TagSpecification::builder()
                        .resource_type(ResourceType::Instance)
                        .tags(
                            Tag::builder()
                                .key("Name")
                                .value(format!("perf-test-instance-{}", i))
                                .build(),
                        )
                        .build(),
                )
                .send()
                .await
        });
        
        tasks.push(task);
    }
    
    // Wait for all instances to launch
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    
    let duration = start.elapsed();
    
    // Parallel instance launch should complete quickly
    assert!(duration < Duration::from_secs(3), 
        "Parallel instance launch took too long: {:?}", duration);
}

#[tokio::test]
#[serial]
async fn test_resource_cleanup_performance() {
    let container = LocalStackContainer::new().await;
    let ec2_client = container.ec2_client("us-east-1").await;
    
    // Create resources
    let vpc = ec2_client
        .create_vpc()
        .cidr_block("10.0.0.0/16")
        .send()
        .await
        .unwrap();
    
    let vpc_id = vpc.vpc().unwrap().vpc_id().unwrap();
    
    // Create multiple subnets
    let mut subnet_ids = Vec::new();
    for i in 0..5 {
        let subnet = ec2_client
            .create_subnet()
            .vpc_id(vpc_id)
            .cidr_block(format!("10.0.{}.0/24", i))
            .availability_zone("us-east-1a")
            .send()
            .await
            .unwrap();
        
        subnet_ids.push(subnet.subnet().unwrap().subnet_id().unwrap().to_string());
    }
    
    // Create security groups
    let mut sg_ids = Vec::new();
    for i in 0..5 {
        let sg = ec2_client
            .create_security_group()
            .group_name(format!("cleanup-test-sg-{}", i))
            .description("Cleanup test security group")
            .vpc_id(vpc_id)
            .send()
            .await
            .unwrap();
        
        sg_ids.push(sg.group_id().unwrap().to_string());
    }
    
    let start = Instant::now();
    
    // Delete all subnets in parallel
    let mut tasks = Vec::new();
    for subnet_id in subnet_ids {
        let ec2_client = ec2_client.clone();
        tasks.push(tokio::spawn(async move {
            ec2_client.delete_subnet().subnet_id(subnet_id).send().await
        }));
    }
    
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    
    // Delete all security groups
    let mut tasks = Vec::new();
    for sg_id in sg_ids {
        let ec2_client = ec2_client.clone();
        tasks.push(tokio::spawn(async move {
            ec2_client.delete_security_group().group_id(sg_id).send().await
        }));
    }
    
    for task in tasks {
        task.await.unwrap().ok(); // Some might fail due to dependencies
    }
    
    // Delete VPC
    ec2_client.delete_vpc().vpc_id(vpc_id).send().await.unwrap();
    
    let duration = start.elapsed();
    
    // Cleanup should be fast
    assert!(duration < Duration::from_secs(5), 
        "Resource cleanup took too long: {:?}", duration);
}

#[tokio::test]
#[serial]
async fn test_large_deployment_simulation() {
    let container = LocalStackContainer::new().await;
    let _test_files = TestFiles::create("large_deployment");
    
    let start = Instant::now();
    
    // Simulate creating resources for a large deployment across multiple regions
    let regions = vec!["us-east-1", "us-west-2", "eu-west-1"];
    
    for region in regions {
        let ec2_client = container.ec2_client(region).await;
        
        // Create VPC
        let vpc = ec2_client
            .create_vpc()
            .cidr_block("10.0.0.0/16")
            .send()
            .await
            .unwrap();
        
        let vpc_id = vpc.vpc().unwrap().vpc_id().unwrap();
        
        // Create subnet
        let _subnet = ec2_client
            .create_subnet()
            .vpc_id(vpc_id)
            .cidr_block("10.0.1.0/24")
            .availability_zone(format!("{}a", region))
            .send()
            .await
            .unwrap();
        
        // Create security group
        let _sg = ec2_client
            .create_security_group()
            .group_name(format!("large-deploy-sg-{}", region))
            .description("Large deployment security group")
            .vpc_id(vpc_id)
            .send()
            .await
            .unwrap();
    }
    
    let duration = start.elapsed();
    
    // Multi-region deployment setup should complete reasonably fast
    assert!(duration < Duration::from_secs(10), 
        "Large deployment simulation took too long: {:?}", duration);
    
    cleanup_deployer_dir("large_deployment");
}