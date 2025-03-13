//! `refresh` subcommand for `ec2`

use crate::ec2::utils::{
    exact_cidr, get_public_ip, DEPLOYER_MAX_PORT, DEPLOYER_MIN_PORT, DEPLOYER_PROTOCOL,
};
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
    info!(ip = deployer_ip, "deployer public IP");

    // Determine all regions involved
    let mut all_regions = HashSet::new();
    all_regions.insert(MONITORING_REGION.to_string());
    for instance in &config.instances {
        all_regions.insert(instance.region.clone());
    }

    // Update security groups in each region
    let mut changes = Vec::new();
    for region in all_regions {
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;
        info!(region = region.as_str(), "created EC2 client");

        // Iterate over all security groups
        let security_groups = find_security_groups_by_tag(&ec2_client, tag).await?;
        for sg in security_groups {
            // Check existing permissions
            let sg_id = sg.group_id().unwrap();
            let mut already_allowed = false;
            for perm in sg.ip_permissions() {
                // We enforce an exact match to avoid accidentally skipping because
                // of an ingress rule with different ports or protocols.
                if perm.ip_protocol() == Some(DEPLOYER_PROTOCOL)
                    && perm.from_port() == Some(DEPLOYER_MIN_PORT)
                    && perm.to_port() == Some(DEPLOYER_MAX_PORT)
                {
                    for ip_range in perm.ip_ranges() {
                        if ip_range.cidr_ip() == Some(&exact_cidr(&deployer_ip)) {
                            already_allowed = true;
                            break;
                        }
                    }
                    if already_allowed {
                        break;
                    }
                }
            }

            // Add ingress rule if not already allowed
            if already_allowed {
                info!(sg_id, "deployer IP already allowed");
                continue;
            }
            ec2_client
                .authorize_security_group_ingress()
                .group_id(sg_id)
                .ip_permissions(
                    IpPermission::builder()
                        .ip_protocol(DEPLOYER_PROTOCOL)
                        .from_port(DEPLOYER_MIN_PORT)
                        .to_port(DEPLOYER_MAX_PORT)
                        .ip_ranges(IpRange::builder().cidr_ip(exact_cidr(&deployer_ip)).build())
                        .build(),
                )
                .send()
                .await
                .map_err(|err| err.into_service_error())?;
            info!(sg_id, "added ingress rule for deployer IP");
            changes.push(sg_id.to_string());
        }
    }
    info!(?changes, "deployer IP refreshed");
    Ok(())
}
