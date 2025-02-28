use crate::ec2::{aws::*, utils::*, Config, InstanceConfig, MONITORING_NAME, MONITORING_REGION};
use aws_sdk_ec2::types::Filter;
use futures::future::try_join_all;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::path::PathBuf;
use tracing::{error, info};

/// Updates the binary and configuration on all regular nodes
pub async fn update(config_path: &PathBuf) -> Result<(), Box<dyn Error>> {
    // Load config
    let config: Config = {
        let config_file = File::open(config_path)?;
        serde_yaml::from_reader(config_file)?
    };
    let tag = &config.tag;
    info!(tag = tag.as_str(), "loaded configuration");

    // Construct private key path (assumes it exists from create command)
    let private_key_path = format!("/tmp/deployer-{}/id_rsa_{}", tag, tag);
    if !PathBuf::from(&private_key_path).exists() {
        return Err(format!("private key not found: {}", private_key_path).into());
    }

    // Create a map from instance name to InstanceConfig for lookup
    let instance_map: HashMap<String, InstanceConfig> = config
        .instances
        .iter()
        .map(|i| (i.name.clone(), i.clone()))
        .collect();

    // Determine all regions (regular + monitoring)
    let mut regions = config
        .instances
        .iter()
        .map(|i| i.region.clone())
        .collect::<std::collections::HashSet<_>>();
    regions.insert(MONITORING_REGION.to_string());

    // Collect all regular instances across regions
    let mut regular_instances = Vec::new();
    for region in &regions {
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;
        let resp = ec2_client
            .describe_instances()
            .filters(Filter::builder().name("tag:deployer").values(tag).build())
            .send()
            .await?;
        for reservation in resp.reservations.unwrap_or_default() {
            for instance in reservation.instances.unwrap_or_default() {
                if let Some(tags) = &instance.tags {
                    if let Some(name_tag) = tags.iter().find(|t| t.key.as_deref() == Some("name")) {
                        if name_tag.value.as_deref() != Some(MONITORING_NAME) {
                            if let Some(public_ip) = &instance.public_ip_address {
                                regular_instances
                                    .push((name_tag.value.clone().unwrap(), public_ip.clone()));
                                info!(
                                    region,
                                    name = name_tag.value.clone().unwrap(),
                                    ip = public_ip,
                                    "found instance"
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    // Update each regular instance concurrently
    let mut futures = Vec::new();
    for (name, ip) in regular_instances {
        if let Some(instance_config) = instance_map.get(&name) {
            let private_key = private_key_path.clone();
            let binary_path = instance_config.binary.clone();
            let config_path = instance_config.config.clone();
            let ip = ip.clone();
            let future = async move {
                update_instance(&private_key, &ip, &binary_path, &config_path).await?;
                info!(name, "instance updated");
                Ok::<(), Box<dyn Error>>(())
            };
            futures.push(future);
        } else {
            error!(name, "instance config not found in config file");
        }
    }

    // Await all updates and handle errors
    try_join_all(futures).await?;
    info!("update complete");
    Ok(())
}

/// Updates a single instance with new binary and config
async fn update_instance(
    private_key: &str,
    ip: &str,
    binary_path: &str,
    config_path: &str,
) -> Result<(), Box<dyn Error>> {
    // Stop the binary service
    ssh_execute(private_key, ip, "sudo systemctl stop binary").await?;

    // Wait for the service to become inactive
    poll_service_inactive(private_key, ip, "binary").await?;

    // Push the latest binary and config
    scp_file(private_key, binary_path, ip, "/home/ubuntu/binary").await?;
    scp_file(private_key, config_path, ip, "/home/ubuntu/config.conf").await?;

    // Ensure the binary is executable
    ssh_execute(private_key, ip, "chmod +x /home/ubuntu/binary").await?;

    // Restart the binary service
    ssh_execute(private_key, ip, "sudo systemctl start binary").await?;

    // Verify the service is active (optional but recommended for reliability)
    poll_service_active(private_key, ip, "binary").await?;

    info!(ip, "successfully updated instance");
    Ok(())
}
