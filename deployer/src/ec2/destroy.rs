use crate::ec2::{aws::*, Config};
use std::collections::HashSet;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Tears down all resources associated with the deployment tag
pub async fn destroy(config_path: &str) -> Result<(), Box<dyn Error>> {
    // Load configuration
    let config: Config = {
        let config_file = File::open(config_path)?;
        serde_yaml::from_reader(config_file)?
    };
    let tag = &config.tag;
    info!(tag = tag.as_str(), "loaded configuration");

    // Determine all regions involved
    let mut all_regions = HashSet::new();
    all_regions.insert(MONITORING_REGION.to_string());
    for instance in &config.instances {
        all_regions.insert(instance.region.clone());
    }

    // First pass: Delete instances, security groups, subnets, route tables, peering, IGWs, and key pairs
    info!(regions=?all_regions, "removing resources");
    for region in all_regions.clone() {
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;
        debug!(region = region.as_str(), "created EC2 client");

        let instance_ids = find_instances_by_tag(&ec2_client, tag).await?;
        if !instance_ids.is_empty() {
            terminate_instances(&ec2_client, &instance_ids).await?;
            wait_for_instances_terminated(&ec2_client, &instance_ids).await?;
            debug!(
                region = region.as_str(),
                ?instance_ids,
                "terminated instances"
            );
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
                warn!(%e, "failed to revoke ingress rule between monitoring and regular security groups");
            } else {
                debug!(
                    monitoring_sg,
                    regular_sg,
                    "revoking ingress rule between monitoring and regular security groups"
                );
            }
        }

        // Remove network resources
        let sgs = find_security_groups_by_tag(&ec2_client, tag).await?;
        for sg in sgs {
            let sg_id = sg.group_id().unwrap();
            wait_for_enis_deleted(&ec2_client, sg_id).await?;
            debug!(
                region = region.as_str(),
                sg_id, "ENIs deleted from security group"
            );
            delete_security_group(&ec2_client, sg_id).await?;
            debug!(region = region.as_str(), sg_id, "deleted security group");
        }

        let subnet_ids = find_subnets_by_tag(&ec2_client, tag).await?;
        for subnet_id in subnet_ids {
            delete_subnet(&ec2_client, &subnet_id).await?;
            debug!(region = region.as_str(), subnet_id, "deleted subnet");
        }

        let route_table_ids = find_route_tables_by_tag(&ec2_client, tag).await?;
        for rt_id in route_table_ids {
            delete_route_table(&ec2_client, &rt_id).await?;
            debug!(region = region.as_str(), rt_id, "deleted route table");
        }

        let peering_ids = find_vpc_peering_by_tag(&ec2_client, tag).await?;
        for peering_id in peering_ids {
            delete_vpc_peering(&ec2_client, &peering_id).await?;
            wait_for_vpc_peering_deletion(&ec2_client, &peering_id).await?;
            debug!(
                region = region.as_str(),
                peering_id, "deleted VPC peering connection"
            );
        }

        let igw_ids = find_igws_by_tag(&ec2_client, tag).await?;
        for igw_id in igw_ids {
            let vpc_id = find_vpc_by_igw(&ec2_client, &igw_id).await?;
            detach_igw(&ec2_client, &igw_id, &vpc_id).await?;
            debug!(
                region = region.as_str(),
                igw_id, vpc_id, "detached internet gateway"
            );
            delete_igw(&ec2_client, &igw_id).await?;
            debug!(region = region.as_str(), igw_id, "deleted internet gateway");
        }

        let key_name = format!("deployer-{}", tag);
        delete_key_pair(&ec2_client, &key_name).await?;
        debug!(region = region.as_str(), key_name, "deleted key pair");
    }

    // Second pass: Delete VPCs after dependencies are removed
    for region in &all_regions {
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;
        debug!(region = region.as_str(), "created EC2 client");
        let vpc_ids = find_vpcs_by_tag(&ec2_client, tag).await?;
        for vpc_id in vpc_ids {
            delete_vpc(&ec2_client, &vpc_id).await?;
            debug!(region = region.as_str(), vpc_id, "deleted VPC");
        }
    }
    info!(regions = ?all_regions, "resources removed");

    // Delete temp directory
    let temp_dir = format!("deployer-{}", tag);
    let temp_dir = PathBuf::from("/tmp").join(temp_dir);
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir)?;
        info!(
            dir = temp_dir.to_str().unwrap(),
            "removed temporary directory"
        );
    }
    info!(tag = tag.as_str(), "destruction complete");
    Ok(())
}
