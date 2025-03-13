//! `refresh` subcommand for `ec2`

use crate::ec2::utils::get_public_ip;
use crate::ec2::{
    aws::*, deployer_directory, Config, Error, CREATED_FILE_NAME, DESTROYED_FILE_NAME,
    MONITORING_REGION,
};
use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;
use tracing::info;

/// Adds the deployer's current IP to all security groups if not already present.
pub async fn refresh(config_path: &PathBuf) -> Result<(), Error> {
    // Load configuration
    let config: Config = {
        let config_file = File::open(config_path)?;
        serde_yaml::from_reader(config_file)?
    };
    let tag = &config.tag;
    info!(tag = tag.as_str(), "loaded configuration");

    // Check deployment status
    let temp_dir = deployer_directory(tag);
    if !temp_dir.exists() {
        return Err(Error::DeploymentDoesNotExist(tag.clone()));
    }
    let created_file = temp_dir.join(CREATED_FILE_NAME);
    if !created_file.exists() {
        return Err(Error::DeploymentNotComplete(tag.clone()));
    }
    let destroyed_file = temp_dir.join(DESTROYED_FILE_NAME);
    if destroyed_file.exists() {
        return Err(Error::DeploymentAlreadyDestroyed(tag.clone()));
    }

    // Get deployer's current public IP
    let deployer_ip = get_public_ip().await?;
    info!(ip = deployer_ip.as_str(), "recovered public IP");

    // Determine all regions involved
    let mut all_regions = HashSet::new();
    all_regions.insert(MONITORING_REGION.to_string());
    for instance in &config.instances {
        all_regions.insert(instance.region.clone());
    }

    // Update security groups in each region
    for region in all_regions {
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;
        info!(region = region.as_str(), "created EC2 client");

        let security_groups = find_security_groups_by_tag(&ec2_client, tag).await?;
        for sg in security_groups {
            let sg_id = sg.group_id().unwrap();
            let mut already_allowed = false;

            // Check existing permissions
            if let Some(permissions) = sg.ip_permissions() {
                for perm in permissions {
                    if perm.ip_protocol() == Some("tcp")
                        && perm.from_port() == Some(0)
                        && perm.to_port() == Some(65535)
                    {
                        if let Some(ip_ranges) = perm.ip_ranges() {
                            for ip_range in ip_ranges {
                                if ip_range.cidr_ip() == Some(&format!("{}/32", &deployer_ip)) {
                                    already_allowed = true;
                                    break;
                                }
                            }
                        }
                        if already_allowed {
                            break;
                        }
                    }
                }
            }

            // Add ingress rule if not already allowed
            if !already_allowed {
                ec2_client
                    .authorize_security_group_ingress()
                    .group_id(sg_id)
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
                info!(sg_id, "added ingress rule for deployer IP");
            } else {
                info!(sg_id, "deployer IP already allowed");
            }
        }
    }

    info!("security groups refreshed");
    Ok(())
}
