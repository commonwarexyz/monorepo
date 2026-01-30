//! `profile` subcommand for `ec2`

use crate::aws::{
    deployer_directory,
    ec2::{self, *},
    s3::{self, *},
    services::*,
    utils::{download_file, scp_download, ssh_execute},
    Config, Error, CREATED_FILE_NAME, DESTROYED_FILE_NAME, MONITORING_REGION,
};
use aws_sdk_ec2::types::Filter;
use std::{
    fs::File,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::process::Command;
use tracing::info;

/// Captures a CPU profile from a running instance using samply
pub async fn profile(
    config_path: &PathBuf,
    instance_name: &str,
    duration: u64,
    binary_path: &Path,
) -> Result<(), Error> {
    // Load config
    let config: Config = {
        let config_file = File::open(config_path)?;
        serde_yaml::from_reader(config_file)?
    };
    let tag = &config.tag;
    info!(tag = tag.as_str(), "loaded configuration");

    // Find the instance config to get its instance_type and region
    let instance_config = config
        .instances
        .iter()
        .find(|i| i.name == instance_name)
        .ok_or_else(|| Error::InstanceNotFound(instance_name.to_string()))?;
    let instance_region = &instance_config.region;
    let instance_type = &instance_config.instance_type;

    // Ensure created file exists
    let tag_directory = deployer_directory(Some(tag));
    let created_file = tag_directory.join(CREATED_FILE_NAME);
    if !created_file.exists() {
        return Err(Error::DeploymentNotComplete(tag.clone()));
    }

    // Ensure destroyed file does not exist
    let destroyed_file = tag_directory.join(DESTROYED_FILE_NAME);
    if destroyed_file.exists() {
        return Err(Error::DeploymentAlreadyDestroyed(tag.clone()));
    }

    // Construct private key path
    let private_key_path = tag_directory.join(format!("id_rsa_{tag}"));
    if !private_key_path.exists() {
        return Err(Error::PrivateKeyNotFound);
    }
    let private_key = private_key_path.to_str().unwrap();

    // Query AWS to find the instance IP
    let ec2_client = ec2::create_client(Region::new(instance_region.clone())).await;
    let resp = ec2_client
        .describe_instances()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .filters(
            Filter::builder()
                .name("tag:name")
                .values(instance_name)
                .build(),
        )
        .filters(
            Filter::builder()
                .name("instance-state-name")
                .values("running")
                .build(),
        )
        .send()
        .await
        .map_err(|err| err.into_service_error())?;
    let instance_ip = resp
        .reservations
        .unwrap_or_default()
        .into_iter()
        .flat_map(|r| r.instances.unwrap_or_default())
        .filter_map(|i| i.public_ip_address)
        .next()
        .ok_or_else(|| Error::InstanceNotFound(instance_name.to_string()))?;
    info!(
        instance = instance_name,
        ip = instance_ip.as_str(),
        "found instance"
    );

    // Detect architecture from instance type
    let arch = detect_architecture(&ec2_client, instance_type).await?;
    info!(architecture = %arch, "detected architecture");

    // Cache samply binary in S3 if needed and get presigned URL
    let bucket_name = get_bucket_name();
    let s3_client = s3::create_client(Region::new(MONITORING_REGION)).await;
    ensure_bucket_exists(&s3_client, &bucket_name, MONITORING_REGION).await?;

    // Cache samply archive in S3 (like other tools, we cache the archive and extract on the instance)
    let samply_s3_key = samply_bin_s3_key(SAMPLY_VERSION, arch);
    let samply_url = if object_exists(&s3_client, &bucket_name, &samply_s3_key).await? {
        info!(key = samply_s3_key.as_str(), "samply already in S3");
        presign_url(&s3_client, &bucket_name, &samply_s3_key, PRESIGN_DURATION).await?
    } else {
        info!(
            key = samply_s3_key.as_str(),
            "samply not in S3, downloading and uploading"
        );
        let download_url = samply_download_url(SAMPLY_VERSION, arch);
        let temp_archive = tag_directory.join("samply.tar.xz");

        // Download the archive
        download_file(&download_url, &temp_archive).await?;

        // Upload archive to S3
        let url = cache_and_presign(
            &s3_client,
            &bucket_name,
            &samply_s3_key,
            UploadSource::File(&temp_archive),
            PRESIGN_DURATION,
        )
        .await?;

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_archive);

        url
    };

    // Build the remote profiling script
    let profile_script = format!(
        r#"set -e

# Download and extract samply if not present
if [ ! -f /home/ubuntu/samply ]; then
    {WGET} -O /tmp/samply.tar.xz '{samply_url}'
    tar -xJf /tmp/samply.tar.xz -C /home/ubuntu --strip-components=1
    chmod +x /home/ubuntu/samply
    rm /tmp/samply.tar.xz
fi

# Get binary PID
PID=$(systemctl show --property MainPID binary.service | cut -d= -f2)
if [ -z "$PID" ] || [ "$PID" -eq 0 ]; then
    echo "ERROR: binary.service not running" >&2
    exit 1
fi

echo "Profiling PID $PID for {duration} seconds..."

# Record profile (use timeout with SIGINT so samply saves the profile)
rm -f /tmp/profile.json
sudo timeout -s INT {duration}s /home/ubuntu/samply record -p $PID -s -o /tmp/profile.json || true
sudo chown ubuntu:ubuntu /tmp/profile.json

echo "Profile captured successfully"
"#
    );

    // Run the profiling script on the remote instance
    info!(
        instance = instance_name,
        duration = duration,
        "starting profile capture"
    );
    ssh_execute(private_key, &instance_ip, &profile_script).await?;
    info!("profile capture complete");

    // Download the profile locally via scp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let profile_path = format!("/tmp/profile-{}-{}.json", instance_name, timestamp);
    scp_download(
        private_key,
        &instance_ip,
        "/tmp/profile.json",
        &profile_path,
    )
    .await?;
    info!(profile = profile_path.as_str(), "downloaded profile");

    // Create a temp directory with a copy of the debug binary named "binary"
    // (samply looks for symbols by filename, and the remote binary is named "binary")
    let binary_path = binary_path
        .canonicalize()
        .map_err(|e| Error::Symbolication(format!("failed to resolve binary path: {}", e)))?;
    let symbol_dir = format!("/tmp/symbols-{}-{}", instance_name, timestamp);
    std::fs::create_dir_all(&symbol_dir)?;
    let binary_copy_path = format!("{}/binary", symbol_dir);
    std::fs::copy(&binary_path, &binary_copy_path)
        .map_err(|e| Error::Symbolication(format!("failed to copy binary: {}", e)))?;

    // Use samply load with --symbol-dir to open the profile with symbols
    info!(
        binary = ?binary_path,
        symbol_dir = symbol_dir.as_str(),
        "opening profile with samply"
    );
    let mut cmd = Command::new("samply");
    cmd.arg("load")
        .arg(&profile_path)
        .arg("--symbol-dir")
        .arg(&symbol_dir);

    let status = cmd.status().await?;
    if !status.success() {
        return Err(Error::Symbolication("samply load failed".to_string()));
    }

    Ok(())
}
