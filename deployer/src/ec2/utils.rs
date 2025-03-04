use crate::ec2::Error;
use commonware_cryptography::hash;
use commonware_utils::hex;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use tracing::warn;

/// Maximum number of SSH connection attempts before failing
pub const MAX_SSH_ATTEMPTS: usize = 30;

/// Maximum number of polling attempts for service status
pub const MAX_POLL_ATTEMPTS: usize = 30;

/// Interval between retries
pub const RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Fetch the public IPv4 address of a machine
pub async fn get_public_ip() -> Result<String, Error> {
    let result = reqwest::get("https://ipv4.icanhazip.com")
        .await?
        .text()
        .await?
        .trim()
        .to_string();
    Ok(result)
}

/// Downloads a file from a URL to a local destination
async fn download_file(url: &str, dest: &Path) -> Result<(), Error> {
    let response = reqwest::get(url).await?;
    let bytes = response.bytes().await?;
    std::fs::write(dest, bytes)?;
    Ok(())
}

/// Downloads a file from a URL if it does not exist in the cache directory
pub async fn download_and_cache(cache_dir: &str, url: &str, dest: &Path) -> Result<(), Error> {
    let cache_key = hex(&hash(url.to_string().as_bytes()));
    let cache_path = PathBuf::from(cache_dir).join(cache_key);
    if !cache_path.exists() {
        download_file(url, &cache_path).await?;
    }
    std::fs::copy(cache_path, dest)?;
    Ok(())
}

/// Copies a local file to a remote instance via SCP with retries
pub async fn scp_file(
    key_file: &str,
    local_path: &str,
    ip: &str,
    remote_path: &str,
) -> Result<(), Error> {
    for _ in 0..MAX_SSH_ATTEMPTS {
        let output = Command::new("scp")
            .arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(local_path)
            .arg(format!("ubuntu@{}:{}", ip, remote_path))
            .output()
            .await?;
        if output.status.success() {
            return Ok(());
        }
        warn!(error = ?String::from_utf8_lossy(&output.stderr), "SCP failed");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::ScpFailed)
}

/// Executes a command on a remote instance via SSH with retries
pub async fn ssh_execute(key_file: &str, ip: &str, command: &str) -> Result<(), Error> {
    for _ in 0..MAX_SSH_ATTEMPTS {
        let output = Command::new("ssh")
            .arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{}", ip))
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
pub async fn poll_service_active(key_file: &str, ip: &str, service: &str) -> Result<(), Error> {
    for _ in 0..MAX_POLL_ATTEMPTS {
        let output = Command::new("ssh")
            .arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{}", ip))
            .arg(format!("systemctl is-active {}", service))
            .output()
            .await?;
        if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "active" {
            return Ok(());
        }
        warn!(error = ?String::from_utf8_lossy(&output.stderr), service, "active status check failed");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::ServiceTimeout(ip.to_string(), service.to_string()))
}

/// Polls the status of a systemd service on a remote instance until it becomes inactive
pub async fn poll_service_inactive(key_file: &str, ip: &str, service: &str) -> Result<(), Error> {
    for _ in 0..MAX_POLL_ATTEMPTS {
        let output = Command::new("ssh")
            .arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{}", ip))
            .arg(format!("systemctl is-active {}", service))
            .output()
            .await?;
        if String::from_utf8_lossy(&output.stdout).trim() == "inactive" {
            return Ok(());
        }
        warn!(error = ?String::from_utf8_lossy(&output.stderr), service, "inactive status check failed");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::ServiceTimeout(ip.to_string(), service.to_string()))
}
