//! `update` subcommand for `ec2`

use crate::ec2::{
    aws::*, deployer_directory, s3::*, services::*, utils::*, Config, Error, InstanceConfig,
    CREATED_FILE_NAME, DESTROYED_FILE_NAME, MONITORING_NAME, MONITORING_REGION,
};
use aws_sdk_ec2::types::Filter;
use futures::future::try_join_all;
use std::{collections::HashMap, fs::File, path::PathBuf, time::Duration};
use tracing::{error, info};

/// Updates the binary and configuration on all binary nodes
pub async fn update(config_path: &PathBuf) -> Result<(), Error> {
    // Load config
    let config: Config = {
        let config_file = File::open(config_path)?;
        serde_yaml::from_reader(config_file)?
    };
    let tag = &config.tag;
    info!(tag = tag.as_str(), "loaded configuration");

    // Ensure created file exists
    let tag_directory = deployer_directory(tag);
    let created_file = tag_directory.join(CREATED_FILE_NAME);
    if !created_file.exists() {
        return Err(Error::DeploymentNotComplete(tag.clone()));
    }

    // Ensure destroyed file does not exist
    let destroyed_file = tag_directory.join(DESTROYED_FILE_NAME);
    if destroyed_file.exists() {
        return Err(Error::DeploymentAlreadyDestroyed(tag.clone()));
    }

    // Construct private key path (assumes it exists from create command)
    let private_key_path = tag_directory.join(format!("id_rsa_{tag}"));
    if !private_key_path.exists() {
        return Err(Error::PrivateKeyNotFound);
    }

    // Create a map from instance name to InstanceConfig for lookup
    let instance_map: HashMap<String, InstanceConfig> = config
        .instances
        .iter()
        .map(|i| (i.name.clone(), i.clone()))
        .collect();

    // Upload updated binaries and configs to S3 and generate pre-signed URLs
    info!("uploading updated binaries and configs to S3");
    let s3_client = create_s3_client(Region::new(MONITORING_REGION)).await;
    let presign_duration = Duration::from_secs(6 * 60 * 60);
    let mut instance_binary_urls: HashMap<String, String> = HashMap::new();
    let mut instance_config_urls: HashMap<String, String> = HashMap::new();
    for instance in &config.instances {
        let binary_key = binary_s3_key(tag, &instance.name);
        let config_key = config_s3_key(tag, &instance.name);

        upload_file(
            &s3_client,
            S3_BUCKET_NAME,
            &binary_key,
            std::path::Path::new(&instance.binary),
        )
        .await?;
        upload_file(
            &s3_client,
            S3_BUCKET_NAME,
            &config_key,
            std::path::Path::new(&instance.config),
        )
        .await?;

        let binary_url =
            presign_url(&s3_client, S3_BUCKET_NAME, &binary_key, presign_duration).await?;
        let config_url =
            presign_url(&s3_client, S3_BUCKET_NAME, &config_key, presign_duration).await?;

        instance_binary_urls.insert(instance.name.clone(), binary_url);
        instance_config_urls.insert(instance.name.clone(), config_url);
        info!(
            instance = instance.name.as_str(),
            "uploaded binary and config"
        );
    }
    info!("uploaded all updated binaries and configs");

    // Determine all regions (binary + monitoring)
    let mut regions = config
        .instances
        .iter()
        .map(|i| i.region.clone())
        .collect::<std::collections::HashSet<_>>();
    regions.insert(MONITORING_REGION.to_string());

    // Collect all binary instances across regions
    let mut binary_instances = Vec::new();
    for region in &regions {
        let ec2_client = create_ec2_client(Region::new(region.clone())).await;
        let resp = ec2_client
            .describe_instances()
            .filters(Filter::builder().name("tag:deployer").values(tag).build())
            .send()
            .await
            .map_err(|err| err.into_service_error())?;
        for reservation in resp.reservations.unwrap_or_default() {
            for instance in reservation.instances.unwrap_or_default() {
                if let Some(tags) = &instance.tags {
                    if let Some(name_tag) = tags.iter().find(|t| t.key.as_deref() == Some("name")) {
                        if name_tag.value.as_deref() != Some(MONITORING_NAME) {
                            if let Some(public_ip) = &instance.public_ip_address {
                                binary_instances
                                    .push((name_tag.value.clone().unwrap(), public_ip.clone()));
                                info!(
                                    region,
                                    name = name_tag.value.clone().unwrap(),
                                    ip = public_ip,
                                    "found instance"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Update each binary instance concurrently
    let mut futures = Vec::new();
    for (name, ip) in binary_instances {
        if instance_map.contains_key(&name) {
            let private_key = private_key_path.to_str().unwrap();
            let binary_url = instance_binary_urls[&name].clone();
            let config_url = instance_config_urls[&name].clone();
            let future = async move {
                update_instance(private_key, &ip, &binary_url, &config_url).await?;
                info!(name, ip, "updated instance");
                Ok::<(), Error>(())
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

/// Updates a single instance with new binary and config via S3 pre-signed URLs
async fn update_instance(
    private_key: &str,
    ip: &str,
    binary_url: &str,
    config_url: &str,
) -> Result<(), Error> {
    // Stop the binary service
    ssh_execute(private_key, ip, "sudo systemctl stop binary").await?;

    // Wait for the service to become inactive
    poll_service_inactive(private_key, ip, "binary").await?;

    // Remove the existing binary and config (to ensure new copy is used)
    ssh_execute(private_key, ip, "rm -f /home/ubuntu/binary").await?;
    ssh_execute(private_key, ip, "rm -f /home/ubuntu/config.conf").await?;

    // Download the latest binary and config from S3 via pre-signed URLs
    let download_cmd = format!(
        "wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/binary '{}' && wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/config.conf '{}'",
        binary_url, config_url
    );
    ssh_execute(private_key, ip, &download_cmd).await?;

    // Ensure the binary is executable
    ssh_execute(private_key, ip, "chmod +x /home/ubuntu/binary").await?;

    // Restart the binary service
    ssh_execute(private_key, ip, "sudo systemctl start binary").await?;

    // Verify the service is active (optional but recommended for reliability)
    poll_service_active(private_key, ip, "binary").await?;
    Ok(())
}
