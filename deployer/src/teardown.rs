use crate::aws::*;
use commonware_deployer::Config;
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;
use uuid::Uuid;

/// Tears down all resources associated with the deployment tag
pub async fn teardown(tag: &str, config_path: &str) -> Result<(), Box<dyn Error>> {
    println!("Deployment tag: {}", tag);

    // Load configuration
    let config_file = File::open(config_path)?;
    let config: Config = serde_yaml::from_reader(config_file)?;

    // Determine all regions involved
    let mut all_regions = HashSet::new();
    all_regions.insert(MONITORING_REGION.to_string());
    for instance in &config.instances {
        all_regions.insert(instance.region.clone());
    }
    println!("Regions: {:?}", all_regions);

    // First pass: Delete instances, security groups, subnets, route tables, peering, IGWs, and key pairs
    for region in all_regions.clone() {
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;

        let instance_ids = find_instances_by_tag(&ec2_client, tag).await?;
        if !instance_ids.is_empty() {
            println!("Terminating instances({}): {:?}", region, instance_ids);
            terminate_instances(&ec2_client, &instance_ids).await?;
            wait_for_instances_terminated(&ec2_client, &instance_ids).await?;
            println!("Terminated instances({}): {:?}", region, instance_ids);
        }

        let sg_ids = find_security_groups_by_tag(&ec2_client, tag).await?;
        for sg_id in sg_ids {
            println!("Deleting security group({}): {}", region, sg_id);
            delete_security_group(&ec2_client, &sg_id).await?;
            println!("Deleted security group({}): {}", region, sg_id);
        }

        let subnet_ids = find_subnets_by_tag(&ec2_client, tag).await?;
        for subnet_id in subnet_ids {
            println!("Deleting subnet({}): {}", region, subnet_id);
            delete_subnet(&ec2_client, &subnet_id).await?;
            println!("Deleted subnet({}): {}", region, subnet_id);
        }

        let route_table_ids = find_route_tables_by_tag(&ec2_client, tag).await?;
        for rt_id in route_table_ids {
            println!("Deleting route table({}): {}", region, rt_id);
            delete_route_table(&ec2_client, &rt_id).await?;
            println!("Deleted route table({}): {}", region, rt_id);
        }

        let peering_ids = find_vpc_peering_by_tag(&ec2_client, tag).await?;
        for peering_id in peering_ids {
            println!(
                "Deleting VPC peering connection({}): {}",
                region, peering_id
            );
            delete_vpc_peering(&ec2_client, &peering_id).await?;
            wait_for_vpc_peering_deletion(&ec2_client, &peering_id).await?;
            println!("Deleted VPC peering connection({}): {}", region, peering_id);
        }

        let igw_ids = find_igws_by_tag(&ec2_client, tag).await?;
        for igw_id in igw_ids {
            println!(
                "Detaching and deleting internet gateway({}): {}",
                region, igw_id
            );
            let vpc_id = find_vpc_by_igw(&ec2_client, &igw_id).await?;
            detach_igw(&ec2_client, &igw_id, &vpc_id).await?;
            delete_igw(&ec2_client, &igw_id).await?;
            println!(
                "Detached and deleted internet gateway({}): {}",
                region, igw_id
            );
        }

        let key_name = format!("deployer-{}", tag);
        println!("Deleting key pair({}): {}", region, key_name);
        delete_key_pair(&ec2_client, &key_name).await?;
        println!("Deleted key pair({}): {}", region, key_name);
    }

    // Second pass: Delete VPCs after dependencies are removed
    for region in all_regions {
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;
        let vpc_ids = find_vpcs_by_tag(&ec2_client, tag).await?;
        for vpc_id in vpc_ids {
            println!("Deleting VPC({}): {}", region, vpc_id);
            delete_vpc(&ec2_client, &vpc_id).await?;
            println!("Deleted VPC({}): {}", region, vpc_id);
        }
    }

    // Delete temp directory
    let temp_dir = format!("deployer-{}", Uuid::new_v4());
    let temp_dir = PathBuf::from("/tmp").join(temp_dir);
    std::fs::remove_dir_all(&temp_dir)?;
    println!("Deleted temp directory: {:?}", temp_dir);

    println!("Teardown complete for tag: {}", tag);
    Ok(())
}
