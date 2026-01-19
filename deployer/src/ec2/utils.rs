//! Utility functions for interacting with EC2 instances

use crate::ec2::Error;
use commonware_macros::ready;
use std::path::Path;
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    process::Command,
    time::{sleep, Duration},
};
use tracing::{info, warn};

/// Maximum number of SSH connection attempts before failing
pub const MAX_SSH_ATTEMPTS: usize = 30;

/// Maximum number of polling attempts for service status
pub const MAX_POLL_ATTEMPTS: usize = 30;

/// Interval between retries
pub const RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Protocol for deployer ingress
pub const DEPLOYER_PROTOCOL: &str = "tcp";

/// Minimum port for deployer ingress
pub const DEPLOYER_MIN_PORT: i32 = 0;

/// Maximum port for deployer ingress
pub const DEPLOYER_MAX_PORT: i32 = 65535;

/// Fetch the current machine's public IPv4 address
#[ready(0)]
pub async fn get_public_ip() -> Result<String, Error> {
    // icanhazip.com is maintained by Cloudflare as of 6/6/2021 (https://major.io/p/a-new-future-for-icanhazip/)
    let result = reqwest::get("https://ipv4.icanhazip.com")
        .await?
        .text()
        .await?
        .trim()
        .to_string();
    Ok(result)
}

/// Executes a command on a remote instance via SSH with retries
#[ready(0)]
pub async fn ssh_execute(key_file: &str, ip: &str, command: &str) -> Result<(), Error> {
    for _ in 0..MAX_SSH_ATTEMPTS {
        let output = Command::new("ssh")
            .arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{ip}"))
            .arg(command)
            .output()
            .await?;
        if output.status.success() {
            return Ok(());
        }
        warn!(error = ?String::from_utf8_lossy(&output.stderr), "SSH failed");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::SshFailed)
}

/// Polls the status of a systemd service on a remote instance until active
#[ready(0)]
pub async fn poll_service_active(key_file: &str, ip: &str, service: &str) -> Result<(), Error> {
    for _ in 0..MAX_POLL_ATTEMPTS {
        let output = Command::new("ssh")
            .arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{ip}"))
            .arg(format!("systemctl is-active {service}"))
            .output()
            .await?;
        let parsed = String::from_utf8_lossy(&output.stdout);
        let parsed = parsed.trim();
        if parsed == "active" {
            return Ok(());
        }
        if service == "binary" && parsed == "failed" {
            warn!(service, "service failed to start (check logs and update)");
            return Ok(());
        }
        warn!(error = ?String::from_utf8_lossy(&output.stderr), service, "active status check failed");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::ServiceTimeout(ip.to_string(), service.to_string()))
}

/// Polls the status of a systemd service on a remote instance until it becomes inactive
#[ready(0)]
pub async fn poll_service_inactive(key_file: &str, ip: &str, service: &str) -> Result<(), Error> {
    for _ in 0..MAX_POLL_ATTEMPTS {
        let output = Command::new("ssh")
            .arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{ip}"))
            .arg(format!("systemctl is-active {service}"))
            .output()
            .await?;
        let parsed = String::from_utf8_lossy(&output.stdout);
        let parsed = parsed.trim();
        if parsed == "inactive" {
            return Ok(());
        }
        if service == "binary" && parsed == "failed" {
            warn!(service, "service was never active");
            return Ok(());
        }
        warn!(error = ?String::from_utf8_lossy(&output.stderr), service, "inactive status check failed");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::ServiceTimeout(ip.to_string(), service.to_string()))
}

/// Enables BBR on a remote instance by downloading config from S3 and applying sysctl settings.
#[ready(0)]
pub async fn enable_bbr(key_file: &str, ip: &str, bbr_conf_url: &str) -> Result<(), Error> {
    let download_cmd = format!(
        "wget -q --tries=10 --retry-connrefused --waitretry=5 -O /home/ubuntu/99-bbr.conf '{}'",
        bbr_conf_url
    );
    ssh_execute(key_file, ip, &download_cmd).await?;
    ssh_execute(
        key_file,
        ip,
        "sudo mv /home/ubuntu/99-bbr.conf /etc/sysctl.d/99-bbr.conf",
    )
    .await?;
    ssh_execute(key_file, ip, "sudo sysctl -p /etc/sysctl.d/99-bbr.conf").await?;
    Ok(())
}

/// Converts an IP address to a CIDR block
#[ready(0)]
pub fn exact_cidr(ip: &str) -> String {
    format!("{ip}/32")
}

/// Maximum number of download attempts before failing
pub const MAX_DOWNLOAD_ATTEMPTS: usize = 10;

/// Downloads a file from a URL to a local path with retries
#[ready(0)]
pub async fn download_file(url: &str, dest: &Path) -> Result<(), Error> {
    for attempt in 1..=MAX_DOWNLOAD_ATTEMPTS {
        match download_file_once(url, dest).await {
            Ok(()) => {
                info!(url = url, dest = ?dest, "downloaded file");
                return Ok(());
            }
            Err(e) => {
                warn!(
                    url = url,
                    attempt = attempt,
                    error = ?e,
                    "download attempt failed"
                );
                if attempt < MAX_DOWNLOAD_ATTEMPTS {
                    sleep(RETRY_INTERVAL).await;
                }
            }
        }
    }
    Err(Error::DownloadFailed(url.to_string()))
}

async fn download_file_once(url: &str, dest: &Path) -> Result<(), Error> {
    let response = reqwest::get(url).await?;
    if !response.status().is_success() {
        return Err(Error::DownloadFailed(format!(
            "HTTP {}: {}",
            response.status(),
            url
        )));
    }

    let bytes = response.bytes().await?;

    // Create parent directory if it doesn't exist
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let mut file = File::create(dest).await?;
    file.write_all(&bytes).await?;
    file.flush().await?;

    Ok(())
}
