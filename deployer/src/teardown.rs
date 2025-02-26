use crate::aws::*;
use commonware_deployer::Config;
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;

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

        // If in the monitoring region, we need to revoke the ingress rule
        let security_groups = find_security_groups_by_tag(&ec2_client, tag).await?;
        if region == MONITORING_REGION && !security_groups.is_empty() {
            // Find the monitoring security group (named `tag`)
            let monitoring_sg = security_groups
                .iter()
                .find(|sg| sg.group_name() == Some(tag))
                .expect("Monitoring security group not found")
                .group_id()
                .unwrap();

            // Find the regular security group (named `{tag}-regular`)
            let regular_sg = security_groups
                .iter()
                .find(|sg| sg.group_name() == Some(&format!("{}-regular", tag)))
                .expect("Regular security group not found")
                .group_id()
                .unwrap();

            // Revoke ingress rule from monitoring security group to regular security group
            println!(
                "Revoking ingress rule from monitoring security group({}) to regular security group({})",
                monitoring_sg, regular_sg
            );
            let ip_permission = IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(3100)
                .to_port(3100)
                .user_id_group_pairs(UserIdGroupPair::builder().group_id(regular_sg).build())
                .build();
            if let Err(e) = ec2_client
                .revoke_security_group_ingress()
                .group_id(monitoring_sg)
                .ip_permissions(ip_permission)
                .send()
                .await
            {
                println!("Error revoking ingress rule: {:?}", e);
            } else {
                println!(
                "Revoked ingress rule from monitoring security group({}) to regular security group({})",
                monitoring_sg, regular_sg
            );
            }
        }

        let sgs = find_security_groups_by_tag(&ec2_client, tag).await?;
        for sg in sgs {
            let sg_id = sg.group_id().unwrap();
            println!(
                "Waiting for ENIs to detach from security group({}): {}",
                region, sg_id
            );
            wait_for_enis_deleted(&ec2_client, sg_id).await?;
            println!("Deleting security group({}): {}", region, sg_id);
            delete_security_group(&ec2_client, sg_id).await?;
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
    let temp_dir = format!("deployer-{}", tag);
    let temp_dir = PathBuf::from("/tmp").join(temp_dir);
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)?;
        println!("Deleted temp directory: {:?}", temp_dir);
    }

    println!("Teardown complete: {}", tag);
    Ok(())
}
