//! Utility functions for interacting with EC2 instances

use crate::ec2::Error;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use tracing::warn;

/// Maximum number of SSH connection attempts before failing
pub const MAX_SSH_ATTEMPTS: usize = 30;

/// Maximum number of polling attempts for service status
pub const MAX_POLL_ATTEMPTS: usize = 30;

/// Interval between retries
pub const RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Fetch the current machine's public IPv4 address
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
        let parsed = String::from_utf8_lossy(&output.stdout);
        let parsed = parsed.trim();
        if parsed == "inactive" || parsed == "failed" {
            return Ok(());
        }
        warn!(error = ?String::from_utf8_lossy(&output.stderr), service, "inactive status check failed");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::ServiceTimeout(ip.to_string(), service.to_string()))
}

/// Enables BBR on a remote instance by copying and applying sysctl settings.
pub async fn enable_bbr(key_file: &str, ip: &str, bbr_conf_local_path: &str) -> Result<(), Error> {
    scp_file(
        key_file,
        bbr_conf_local_path,
        ip,
        "/home/ubuntu/99-bbr.conf",
    )
    .await?;
    ssh_execute(
        key_file,
        ip,
        "sudo mv /home/ubuntu/99-bbr.conf /etc/sysctl.d/99-bbr.conf",
    )
    .await?;
    ssh_execute(key_file, ip, "sudo sysctl -p /etc/sysctl.d/99-bbr.conf").await?;
    Ok(())
}
