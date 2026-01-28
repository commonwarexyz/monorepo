//! `destroy` subcommand for `ec2`

use crate::aws::{
    deployer_directory,
    ec2::{self, *},
    s3::{self, delete_prefix, is_no_such_bucket_error, Region, BUCKET_NAME, DEPLOYMENTS_PREFIX},
    Config, Error, Metadata, DESTROYED_FILE_NAME, LOGS_PORT, METADATA_FILE_NAME, MONITORING_REGION,
    PROFILES_PORT, TRACES_PORT,
};
use futures::future::try_join_all;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    path::PathBuf,
};
use tracing::{info, warn};

/// Tears down all resources associated with the deployment tag
pub async fn destroy(config: Option<&PathBuf>, tag: Option<&str>) -> Result<(), Error> {
    // Determine tag and regions from either config file or metadata
    let (tag, all_regions) = if let Some(config_path) = config {
        let config: Config = {
            let config_file = File::open(config_path)?;
            serde_yaml::from_reader(config_file)?
        };
        let mut regions = HashSet::new();
        regions.insert(MONITORING_REGION.to_string());
        for instance in &config.instances {
            regions.insert(instance.region.clone());
        }
        (config.tag, regions)
    } else if let Some(tag) = tag {
        let tag_directory = deployer_directory(Some(tag));
        let metadata_path = tag_directory.join(METADATA_FILE_NAME);
        if !metadata_path.exists() {
            return Err(Error::MetadataNotFound(tag.to_string()));
        }
        let metadata: Metadata = {
            let file = File::open(&metadata_path)?;
            serde_yaml::from_reader(file)?
        };
        (tag.to_string(), metadata.regions.into_iter().collect())
    } else {
        return Err(Error::MissingTagOrConfig);
    };
    info!(tag = tag.as_str(), "loaded configuration");

    // Ensure deployment directory exists
    let tag_directory = deployer_directory(Some(&tag));
    if !tag_directory.exists() {
        return Err(Error::DeploymentDoesNotExist(tag.clone()));
    }

    // Ensure not already destroyed
    let destroyed_file = tag_directory.join(DESTROYED_FILE_NAME);
    if destroyed_file.exists() {
        warn!("infrastructure already destroyed");
        return Ok(());
    }

    // Clean up S3 deployment data (preserves cached tools)
    info!(bucket = BUCKET_NAME, "cleaning up S3 deployment data");
    let s3_client = s3::create_client(Region::new(MONITORING_REGION)).await;
    let deployment_prefix = format!("{}/{}/", DEPLOYMENTS_PREFIX, &tag);
    match delete_prefix(&s3_client, BUCKET_NAME, &deployment_prefix).await {
        Ok(()) => {
            info!(
                bucket = BUCKET_NAME,
                prefix = deployment_prefix.as_str(),
                "deleted S3 deployment data"
            );
        }
        Err(e) => {
            if is_no_such_bucket_error(&e) {
                info!(
                    bucket = BUCKET_NAME,
                    "bucket does not exist, skipping S3 cleanup"
                );
            } else {
                warn!(bucket = BUCKET_NAME, %e, "failed to delete S3 deployment data, continuing with destroy");
            }
        }
    }

    // First pass: Delete instances, security groups, subnets, route tables, peering, IGWs, and key pairs
    info!(regions=?all_regions, "removing resources");
    let jobs = all_regions.iter().map(|region| {
        let region = region.clone();
        let tag = tag.clone();
        async move {
            let ec2_client = ec2::create_client(Region::new(region.clone())).await;
            info!(region = region.as_str(), "created EC2 client");

            let instance_ids = find_instances_by_tag(&ec2_client, &tag).await?;
            if !instance_ids.is_empty() {
                terminate_instances(&ec2_client, &instance_ids).await?;
                wait_for_instances_terminated(&ec2_client, &instance_ids).await?;
                info!(
                    region = region.as_str(),
                    ?instance_ids,
                    "terminated instances"
                );
            }

            // If in the monitoring region, we need to revoke the ingress rule
            let security_groups = find_security_groups_by_tag(&ec2_client, &tag).await?;
            let has_monitoring_sg = security_groups
                .iter()
                .any(|sg| sg.group_name() == Some(&tag));
            let has_binary_sg = security_groups
                .iter()
                .any(|sg| sg.group_name() == Some(&format!("{tag}-binary")));
            if region == MONITORING_REGION && has_monitoring_sg && has_binary_sg {
                // Find the monitoring security group (named `tag`)
                let monitoring_sg = security_groups
                    .iter()
                    .find(|sg| sg.group_name() == Some(&tag))
                    .expect("Monitoring security group not found")
                    .group_id()
                    .unwrap();

                // Find the binary security group (named `{tag}-binary`)
                let binary_sg = security_groups
                    .iter()
                    .find(|sg| sg.group_name() == Some(&format!("{tag}-binary")))
                    .expect("Regular security group not found")
                    .group_id()
                    .unwrap();

                // Revoke ingress rule from monitoring security group to binary security group
                let logging_permission = IpPermission::builder()
                    .ip_protocol("tcp")
                    .from_port(LOGS_PORT as i32)
                    .to_port(LOGS_PORT as i32)
                    .user_id_group_pairs(UserIdGroupPair::builder().group_id(binary_sg).build())
                    .build();
                if let Err(e) = ec2_client
                    .revoke_security_group_ingress()
                    .group_id(monitoring_sg)
                    .ip_permissions(logging_permission)
                    .send()
                    .await
                {
                    warn!(%e, "failed to revoke logs ingress rule between monitoring and binary security groups");
                } else {
                    info!(
                        monitoring_sg,
                        binary_sg,
                        "revoked logs ingress rule between monitoring and binary security groups"
                    );
                }

                // Revoke ingress rule from monitoring security group to binary security group
                let profiling_permission = IpPermission::builder()
                    .ip_protocol("tcp")
                    .from_port(PROFILES_PORT as i32)
                    .to_port(PROFILES_PORT as i32)
                    .user_id_group_pairs(UserIdGroupPair::builder().group_id(binary_sg).build())
                    .build();
                if let Err(e) = ec2_client
                    .revoke_security_group_ingress()
                    .group_id(monitoring_sg)
                    .ip_permissions(profiling_permission)
                    .send()
                    .await
                {
                    warn!(%e, "failed to revoke profiles ingress rule between monitoring and binary security groups");
                } else {
                    info!(
                        monitoring_sg,
                        binary_sg,
                        "revoked profiles ingress rule between monitoring and binary security groups"
                    );
                }

                // Revoke ingress rule from monitoring security group to binary security group
                let tracing_permission = IpPermission::builder()
                    .ip_protocol("tcp")
                    .from_port(TRACES_PORT as i32)
                    .to_port(TRACES_PORT as i32)
                    .user_id_group_pairs(UserIdGroupPair::builder().group_id(binary_sg).build())
                    .build();
                if let Err(e) = ec2_client
                    .revoke_security_group_ingress()
                    .group_id(monitoring_sg)
                    .ip_permissions(tracing_permission)
                    .send()
                    .await
                {
                    warn!(%e, "failed to revoke traces ingress rule between monitoring and binary security groups");
                } else {
                    info!(
                        monitoring_sg,
                        binary_sg,
                        "revoked traces ingress rule between monitoring and binary security groups"
                    );
                }
            }

            // Remove network resources
            let sgs = find_security_groups_by_tag(&ec2_client, &tag).await?;
            for sg in sgs {
                let sg_id = sg.group_id().unwrap();
                wait_for_enis_deleted(&ec2_client, sg_id).await?;
                info!(
                    region = region.as_str(),
                    sg_id, "ENIs deleted from security group"
                );
                delete_security_group(&ec2_client, sg_id).await?;
                info!(region = region.as_str(), sg_id, "deleted security group");
            }

            let subnet_ids = find_subnets_by_tag(&ec2_client, &tag).await?;
            for subnet_id in subnet_ids {
                delete_subnet(&ec2_client, &subnet_id).await?;
                info!(region = region.as_str(), subnet_id, "deleted subnet");
            }

            let route_table_ids = find_route_tables_by_tag(&ec2_client, &tag).await?;
            for rt_id in route_table_ids {
                delete_route_table(&ec2_client, &rt_id).await?;
                info!(region = region.as_str(), rt_id, "deleted route table");
            }

            let peering_ids = find_vpc_peering_by_tag(&ec2_client, &tag).await?;
            for peering_id in peering_ids {
                delete_vpc_peering(&ec2_client, &peering_id).await?;
                wait_for_vpc_peering_deletion(&ec2_client, &peering_id).await?;
                info!(
                    region = region.as_str(),
                    peering_id, "deleted VPC peering connection"
                );
            }

            let igw_ids = find_igws_by_tag(&ec2_client, &tag).await?;
            for igw_id in igw_ids {
                if let Some(vpc_id) = find_vpc_by_igw(&ec2_client, &igw_id).await? {
                    detach_igw(&ec2_client, &igw_id, &vpc_id).await?;
                    info!(
                        region = region.as_str(),
                        igw_id, vpc_id, "detached internet gateway"
                    );
                }
                delete_igw(&ec2_client, &igw_id).await?;
                info!(region = region.as_str(), igw_id, "deleted internet gateway");
            }

            let key_name = format!("deployer-{tag}");
            delete_key_pair(&ec2_client, &key_name).await?;
            info!(region = region.as_str(), key_name, "deleted key pair");
            Ok::<_, Error>((region, ec2_client))
        }
    });
    let ec2_clients: HashMap<String, Ec2Client> = try_join_all(jobs).await?.into_iter().collect();

    // Second pass: Delete VPCs after dependencies are removed
    let vpc_jobs = ec2_clients.into_iter().map(|(region, ec2_client)| {
        let tag = tag.clone();
        async move {
            let vpc_ids = find_vpcs_by_tag(&ec2_client, &tag).await?;
            for vpc_id in vpc_ids {
                delete_vpc(&ec2_client, &vpc_id).await?;
                info!(region = region.as_str(), vpc_id, "deleted VPC");
            }
            Ok::<(), Error>(())
        }
    });
    try_join_all(vpc_jobs).await?;
    info!(regions = ?all_regions, "resources removed");

    // Write destruction file
    File::create(destroyed_file)?;

    // We don't delete the temporary directory to prevent re-deployment of the same tag
    info!(tag = tag.as_str(), "destruction complete");
    Ok(())
}
