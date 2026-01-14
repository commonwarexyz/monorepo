//! `profile` subcommand for `ec2`

use crate::ec2::{
    aws::*,
    deployer_directory,
    s3::*,
    services::*,
    utils::{download_file, scp_download, ssh_execute},
    Config, Error, CREATED_FILE_NAME, DESTROYED_FILE_NAME, MONITORING_REGION,
};
use aws_sdk_ec2::types::Filter;
use std::{
    fs::File,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
};
use tracing::info;

/// Captures a CPU profile from a running instance using samply
pub async fn profile(
    config_path: &PathBuf,
    instance_name: &str,
    duration: u64,
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

    // Construct private key path
    let private_key_path = tag_directory.join(format!("id_rsa_{tag}"));
    if !private_key_path.exists() {
        return Err(Error::PrivateKeyNotFound);
    }
    let private_key = private_key_path.to_str().unwrap();

    // Query AWS to find the instance IP
    let ec2_client = create_ec2_client(Region::new(instance_region.clone())).await;
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
    let s3_client = create_s3_client(Region::new(MONITORING_REGION)).await;
    ensure_bucket_exists(&s3_client, S3_BUCKET_NAME, MONITORING_REGION).await?;

    // Cache samply archive in S3 (like other tools, we cache the archive and extract on the instance)
    let samply_s3_key = samply_bin_s3_key(SAMPLY_VERSION, arch);
    let samply_url = if object_exists(&s3_client, S3_BUCKET_NAME, &samply_s3_key).await? {
        info!(key = samply_s3_key.as_str(), "samply already in S3");
        presign_url(&s3_client, S3_BUCKET_NAME, &samply_s3_key, PRESIGN_DURATION).await?
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
            S3_BUCKET_NAME,
            &samply_s3_key,
            UploadSource::File(&temp_archive),
            PRESIGN_DURATION,
        )
        .await?;

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_archive);

        url
    };
    info!("samply archive ready");

    // Build the remote profiling script
    let profile_script = format!(
        r#"
set -e

# Download and extract samply if not present
if [ ! -f /home/ubuntu/samply ]; then
    wget -q --tries=10 --retry-connrefused --waitretry=5 -O /tmp/samply.tar.xz '{samply_url}'
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
    let local_path = format!("/tmp/profile-{}-{}.json", instance_name, timestamp);
    scp_download(private_key, &instance_ip, "/tmp/profile.json", &local_path).await?;

    info!(path = local_path.as_str(), "profile saved locally");

    // Read the profile file
    let profile_content = std::fs::read(&local_path)?;

    // Start a local HTTP server on a random port
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    info!(port = port, "started local server for profile");

    // Build the Firefox Profiler URL with from-url parameter
    let local_url = format!("http://127.0.0.1:{}/profile.json", port);
    let profiler_url = format!(
        "https://profiler.firefox.com/from-url/{}",
        urlencoding::encode(&local_url)
    );

    // Open Firefox Profiler in the default browser
    #[cfg(target_os = "macos")]
    let open_cmd = "open";
    #[cfg(target_os = "linux")]
    let open_cmd = "xdg-open";
    #[cfg(target_os = "windows")]
    let open_cmd = "start";

    let _ = Command::new(open_cmd).arg(&profiler_url).spawn();
    info!("Firefox Profiler opened");

    // Serve the profile file (handle both preflight OPTIONS and GET requests)
    loop {
        let (mut socket, _) = listener.accept().await?;
        let mut buf = [0u8; 1024];
        let n = socket.read(&mut buf).await?;
        let request = String::from_utf8_lossy(&buf[..n]);

        // CORS headers for Firefox Profiler
        let cors_headers = "Access-Control-Allow-Origin: *\r\n\
                           Access-Control-Allow-Methods: GET, OPTIONS\r\n\
                           Access-Control-Allow-Headers: *\r\n";

        if request.starts_with("OPTIONS") {
            // Preflight request
            let response =
                format!("HTTP/1.1 204 No Content\r\n{cors_headers}Content-Length: 0\r\n\r\n");
            socket.write_all(response.as_bytes()).await?;
        } else if request.starts_with("GET") {
            // Serve the profile
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 {cors_headers}\r\n",
                profile_content.len()
            );
            socket.write_all(response.as_bytes()).await?;
            socket.write_all(&profile_content).await?;
            info!("profile served to Firefox Profiler");
            break;
        }
    }

    Ok(())
}
