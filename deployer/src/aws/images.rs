//! Caches container images as gzipped `docker save` tarballs in S3.
//!
//! Instances download these tarballs via pre-signed URLs and `docker load` them, so they never
//! authenticate against a registry (no piped token, no IAM role, no credential helper).

use crate::aws::{
    s3::{cache_and_presign, object_exists, presign_url, UploadSource, PRESIGN_DURATION},
    services::{image_s3_key, sanitize_image},
    Architecture, Error,
};
use aws_sdk_s3::Client as S3Client;
use std::{path::Path, process::Stdio};
use tokio::process::Command;
use tracing::info;

/// Caches a single image (for one architecture) as a gzipped tarball in S3 and returns a
/// pre-signed download URL. Skips the `docker save` work if the tarball is already cached.
pub(crate) async fn cache_image(
    s3_client: &S3Client,
    bucket: &str,
    tag_directory: &Path,
    image: &'static str,
    architecture: Architecture,
) -> Result<String, Error> {
    let key = image_s3_key(image, architecture);
    if object_exists(s3_client, bucket, &key).await? {
        info!(image, architecture = %architecture, "image already cached in S3");
        return presign_url(s3_client, bucket, &key, PRESIGN_DURATION).await;
    }

    info!(image, architecture = %architecture, "caching image to S3");
    let stem = format!("{}-{}", sanitize_image(image), architecture.as_str());
    let tar_path = tag_directory.join(format!("{stem}.tar"));
    let gz_path = tag_directory.join(format!("{stem}.tar.gz"));
    let tar_str = tar_path.to_string_lossy().into_owned();
    let platform = format!("linux/{}", architecture.as_str());

    // Remove any local copy first so the store holds exactly the platform we pull, then `docker
    // save` exports that platform regardless of the deployer's image store type (the containerd
    // store can otherwise keep several platforms under one tag and save the wrong one). Pulling the
    // platform explicitly also lets the deployer build tarballs for any target architecture; pull
    // and save never run the image, so the deployer's own architecture is irrelevant.
    let _ = run_command("docker", &["image", "rm", "-f", image]).await;
    run_command("docker", &["pull", "--platform", &platform, image]).await?;
    run_command("docker", &["save", image, "-o", tar_str.as_str()]).await?;
    // `gzip -f` replaces the tar with `{tar}.gz` (== gz_path).
    run_command("gzip", &["-f", tar_str.as_str()]).await?;

    let url = cache_and_presign(
        s3_client,
        bucket,
        &key,
        UploadSource::File(&gz_path),
        PRESIGN_DURATION,
    )
    .await?;
    let _ = std::fs::remove_file(&gz_path);
    Ok(url)
}

async fn run_command(program: &str, args: &[&str]) -> Result<(), Error> {
    let command = format!("{program} {}", args.join(" "));
    let output = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await?;
    if output.status.success() {
        return Ok(());
    }

    let mut stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        if !stderr.is_empty() {
            stderr.push('\n');
        }
        stderr.push_str(&stdout);
    }
    Err(Error::CommandFailed { command, stderr })
}
