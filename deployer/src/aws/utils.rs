//! Utility functions for interacting with EC2 instances

use crate::aws::Error;
use std::{path::Path, process::Output};
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    process::Command,
    time::{sleep, timeout, Duration},
};
use tracing::{info, warn};

/// Maximum number of SSH connection attempts before failing
pub const MAX_SSH_ATTEMPTS: usize = 30;

/// Maximum number of polling attempts for service status
pub const MAX_POLL_ATTEMPTS: usize = 30;

/// Interval between retries
pub const RETRY_INTERVAL: Duration = Duration::from_secs(15);

/// Maximum time to wait for a non-polling SSH command to complete
pub const SSH_COMMAND_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Maximum time to wait for a service status poll to complete
pub const SSH_POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum time to wait for an SCP download to complete
pub const SCP_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Protocol for deployer ingress
pub const DEPLOYER_PROTOCOL: &str = "tcp";

/// Minimum port for deployer ingress
pub const DEPLOYER_MIN_PORT: i32 = 0;

/// Maximum port for deployer ingress
pub const DEPLOYER_MAX_PORT: i32 = 65535;

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

/// Executes a command on a remote instance via SSH with retries
pub async fn ssh_execute(key_file: &str, ip: &str, command: &str) -> Result<(), Error> {
    ssh_execute_with_timeout(key_file, ip, command, SSH_COMMAND_TIMEOUT).await
}

/// Executes a command on a remote instance via SSH with retries and a per-attempt timeout
pub async fn ssh_execute_with_timeout(
    key_file: &str,
    ip: &str,
    command: &str,
    command_timeout: Duration,
) -> Result<(), Error> {
    for _ in 0..MAX_SSH_ATTEMPTS {
        let mut cmd = Command::new("ssh");
        cmd.arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{ip}"))
            .arg(command);
        let output = match command_output(cmd, "ssh", ip, command_timeout).await {
            Ok(output) => output,
            Err(err @ Error::CommandTimeout { .. }) => {
                warn!(ip, error = ?err, "SSH command timed out");
                sleep(RETRY_INTERVAL).await;
                continue;
            }
            Err(err) => return Err(err),
        };
        if output.status.success() {
            return Ok(());
        }
        warn!(ip, stderr = ?String::from_utf8_lossy(&output.stderr), stdout = ?String::from_utf8_lossy(&output.stdout), "SSH command failed");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::SshFailed)
}

/// Polls the status of a systemd service on a remote instance until active
pub async fn poll_service_active(key_file: &str, ip: &str, service: &str) -> Result<(), Error> {
    for _ in 0..MAX_POLL_ATTEMPTS {
        let mut cmd = Command::new("ssh");
        cmd.arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{ip}"))
            .arg(format!("systemctl is-active {service}"));
        let output = match command_output(cmd, "ssh", ip, SSH_POLL_TIMEOUT).await {
            Ok(output) => output,
            Err(err @ Error::CommandTimeout { .. }) => {
                warn!(service, error = ?err, "service status poll timed out");
                sleep(RETRY_INTERVAL).await;
                continue;
            }
            Err(err) => return Err(err),
        };
        let parsed = String::from_utf8_lossy(&output.stdout);
        let parsed = parsed.trim();
        if parsed == "active" {
            return Ok(());
        }
        if service == "binary" && parsed == "failed" {
            warn!(service, "service failed to start (check logs and update)");
            return Ok(());
        }
        warn!(status = parsed, service, "service not yet active");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::ServiceTimeout(ip.to_string(), service.to_string()))
}

/// Polls the status of a systemd service on a remote instance until it becomes inactive
pub async fn poll_service_inactive(key_file: &str, ip: &str, service: &str) -> Result<(), Error> {
    for _ in 0..MAX_POLL_ATTEMPTS {
        let mut cmd = Command::new("ssh");
        cmd.arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{ip}"))
            .arg(format!("systemctl is-active {service}"));
        let output = match command_output(cmd, "ssh", ip, SSH_POLL_TIMEOUT).await {
            Ok(output) => output,
            Err(err @ Error::CommandTimeout { .. }) => {
                warn!(service, error = ?err, "service status poll timed out");
                sleep(RETRY_INTERVAL).await;
                continue;
            }
            Err(err) => return Err(err),
        };
        let parsed = String::from_utf8_lossy(&output.stdout);
        let parsed = parsed.trim();
        if parsed == "inactive" {
            return Ok(());
        }
        if service == "binary" && parsed == "failed" {
            warn!(service, "service was never active");
            return Ok(());
        }
        warn!(status = parsed, service, "service not yet inactive");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::ServiceTimeout(ip.to_string(), service.to_string()))
}

/// Downloads a file from a remote instance via SCP with retries
pub async fn scp_download(
    key_file: &str,
    ip: &str,
    remote_path: &str,
    local_path: &str,
) -> Result<(), Error> {
    for _ in 0..MAX_SSH_ATTEMPTS {
        let mut cmd = Command::new("scp");
        cmd.arg("-i")
            .arg(key_file)
            .arg("-o")
            .arg("IdentitiesOnly=yes")
            .arg("-o")
            .arg("ServerAliveInterval=600")
            .arg("-o")
            .arg("StrictHostKeyChecking=no")
            .arg(format!("ubuntu@{ip}:{remote_path}"))
            .arg(local_path);
        let output = match command_output(cmd, "scp", ip, SCP_DOWNLOAD_TIMEOUT).await {
            Ok(output) => output,
            Err(err @ Error::CommandTimeout { .. }) => {
                warn!(ip, error = ?err, "SCP timed out");
                sleep(RETRY_INTERVAL).await;
                continue;
            }
            Err(err) => return Err(err),
        };
        if output.status.success() {
            return Ok(());
        }
        warn!(error = ?String::from_utf8_lossy(&output.stderr), "SCP failed");
        sleep(RETRY_INTERVAL).await;
    }
    Err(Error::SshFailed)
}

async fn command_output(
    mut command: Command,
    program: &str,
    ip: &str,
    command_timeout: Duration,
) -> Result<Output, Error> {
    command.kill_on_drop(true);
    match timeout(command_timeout, command.output()).await {
        Ok(output) => Ok(output?),
        Err(_) => Err(Error::CommandTimeout {
            program: program.to_string(),
            ip: ip.to_string(),
            seconds: command_timeout.as_secs(),
        }),
    }
}

/// Converts an IP address to a CIDR block
pub fn exact_cidr(ip: &str) -> String {
    format!("{ip}/32")
}

/// Maximum number of download attempts before failing
pub const MAX_DOWNLOAD_ATTEMPTS: usize = 10;

/// Downloads a file from a URL to a local path with retries
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
