//! AWS ECR SDK wrappers and image cache mirroring.

use crate::aws::{services::ImageCache, Error};
use aws_config::{BehaviorVersion, Region};
use aws_sdk_ecr::{
    config::retry::ReconnectMode,
    operation::{
        create_repository::CreateRepositoryError, delete_repository::DeleteRepositoryError,
        describe_images::DescribeImagesError,
    },
    types::ImageIdentifier,
    Client as EcrClient,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{collections::HashMap, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};
use tracing::info;

#[derive(Debug)]
struct CachedImage {
    upstream: &'static str,
    repository: String,
    tag: String,
    reference: String,
}

/// Creates an ECR client for the specified AWS region.
pub(crate) async fn create_client(region: Region) -> EcrClient {
    let retry = aws_config::retry::RetryConfig::adaptive()
        .with_max_attempts(u32::MAX)
        .with_initial_backoff(Duration::from_millis(500))
        .with_max_backoff(Duration::from_secs(30))
        .with_reconnect_mode(ReconnectMode::ReconnectOnTransientError);
    let config = aws_config::defaults(BehaviorVersion::v2026_01_12())
        .region(region)
        .retry_config(retry)
        .load()
        .await;
    EcrClient::new(&config)
}

/// Mirrors required public images into ECR and returns the regional cache mapping.
pub(crate) async fn cache_images(
    client: &EcrClient,
    region: &str,
    repository_prefix: &str,
    images: &[&'static str],
) -> Result<ImageCache, Error> {
    let (registry, password) = ecr_login(client).await?;

    let mut refs = HashMap::new();
    let mut logged_in = false;
    for image in images {
        let cached = cached_image(&registry, repository_prefix, image)?;
        ensure_repository(client, &cached.repository).await?;
        if image_exists(client, &cached.repository, &cached.tag).await? {
            info!(
                region,
                upstream = cached.upstream,
                image = cached.reference.as_str(),
                "image already cached in ECR"
            );
        } else {
            info!(
                region,
                upstream = cached.upstream,
                image = cached.reference.as_str(),
                "mirroring image to ECR"
            );
            if !logged_in {
                docker_login(&registry, &password).await?;
                logged_in = true;
            }
            mirror_image(cached.upstream, &cached.reference).await?;
        }
        refs.insert(*image, cached.reference);
    }

    Ok(ImageCache::new(registry, password, refs))
}

/// Deletes all ECR repositories used for the shared image cache.
pub(crate) async fn delete_cache(client: &EcrClient, repository_prefix: &str) -> Result<(), Error> {
    let mut repositories = Vec::new();
    let mut next_token = None;
    let repository_prefix_with_slash = format!("{repository_prefix}/");
    loop {
        let mut request = client.describe_repositories();
        if let Some(token) = next_token {
            request = request.next_token(token);
        }
        let output = request.send().await.map_err(|e| Error::AwsEcr {
            operation: "DescribeRepositories",
            repository: None,
            source: Box::new(aws_sdk_ecr::Error::from(e.into_service_error())),
        })?;
        repositories.extend(
            output
                .repositories()
                .iter()
                .filter_map(|repository| repository.repository_name())
                .filter(|name| {
                    *name == repository_prefix || name.starts_with(&repository_prefix_with_slash)
                })
                .map(str::to_string),
        );
        next_token = output.next_token().map(str::to_string);
        if next_token.is_none() {
            break;
        }
    }

    for repository in repositories {
        match client
            .delete_repository()
            .repository_name(&repository)
            .force(true)
            .send()
            .await
        {
            Ok(_) => {
                info!(
                    repository = repository.as_str(),
                    "deleted ECR cache repository"
                );
            }
            Err(e) => {
                let service_err = e.into_service_error();
                if matches!(
                    service_err,
                    DeleteRepositoryError::RepositoryNotFoundException(_)
                ) {
                    continue;
                }
                return Err(Error::AwsEcr {
                    operation: "DeleteRepository",
                    repository: Some(repository),
                    source: Box::new(aws_sdk_ecr::Error::from(service_err)),
                });
            }
        }
    }

    Ok(())
}

async fn ecr_login(client: &EcrClient) -> Result<(String, String), Error> {
    let output = client
        .get_authorization_token()
        .send()
        .await
        .map_err(|e| Error::AwsEcr {
            operation: "GetAuthorizationToken",
            repository: None,
            source: Box::new(aws_sdk_ecr::Error::from(e.into_service_error())),
        })?;
    let auth = output
        .authorization_data()
        .first()
        .ok_or(Error::EcrAuthorizationTokenMissing)?;
    let token = auth
        .authorization_token()
        .ok_or(Error::EcrAuthorizationTokenMissing)?;
    let endpoint = auth
        .proxy_endpoint()
        .ok_or(Error::EcrProxyEndpointMissing)?;
    let registry = endpoint
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string();

    let decoded = STANDARD.decode(token)?;
    let decoded = String::from_utf8(decoded).map_err(|_| Error::EcrAuthorizationTokenInvalid)?;
    let password = decoded
        .strip_prefix("AWS:")
        .ok_or(Error::EcrAuthorizationTokenInvalid)?
        .to_string();

    Ok((registry, password))
}

async fn ensure_repository(client: &EcrClient, repository: &str) -> Result<(), Error> {
    match client
        .create_repository()
        .repository_name(repository)
        .send()
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            let service_err = e.into_service_error();
            if matches!(
                service_err,
                CreateRepositoryError::RepositoryAlreadyExistsException(_)
            ) {
                return Ok(());
            }
            Err(Error::AwsEcr {
                operation: "CreateRepository",
                repository: Some(repository.to_string()),
                source: Box::new(aws_sdk_ecr::Error::from(service_err)),
            })
        }
    }
}

async fn image_exists(client: &EcrClient, repository: &str, tag: &str) -> Result<bool, Error> {
    let image_id = ImageIdentifier::builder().image_tag(tag).build();
    match client
        .describe_images()
        .repository_name(repository)
        .image_ids(image_id)
        .send()
        .await
    {
        Ok(output) => Ok(!output.image_details().is_empty()),
        Err(e) => {
            let service_err = e.into_service_error();
            if matches!(
                service_err,
                DescribeImagesError::ImageNotFoundException(_)
                    | DescribeImagesError::RepositoryNotFoundException(_)
            ) {
                return Ok(false);
            }
            Err(Error::AwsEcr {
                operation: "DescribeImages",
                repository: Some(repository.to_string()),
                source: Box::new(aws_sdk_ecr::Error::from(service_err)),
            })
        }
    }
}

async fn docker_login(registry: &str, password: &str) -> Result<(), Error> {
    run_docker(
        &["login", "--username", "AWS", "--password-stdin", registry],
        Some(password),
    )
    .await
}

async fn mirror_image(source: &str, target: &str) -> Result<(), Error> {
    run_docker(
        &["buildx", "imagetools", "create", "--tag", target, source],
        None,
    )
    .await
}

async fn run_docker(args: &[&str], stdin: Option<&str>) -> Result<(), Error> {
    let command = format!("docker {}", args.join(" "));
    let mut child = {
        let mut cmd = Command::new("docker");
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }
        cmd.spawn()?
    };

    if let Some(stdin) = stdin {
        let mut child_stdin = child.stdin.take().ok_or(Error::DockerStdinUnavailable)?;
        child_stdin.write_all(stdin.as_bytes()).await?;
    }

    let output = child.wait_with_output().await?;
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
    Err(Error::DockerCommandFailed { command, stderr })
}

fn cached_image(
    registry: &str,
    repository_prefix: &str,
    upstream: &'static str,
) -> Result<CachedImage, Error> {
    let (name, tag) = image_name_and_tag(upstream)?;
    let (source, path) = repository_path(name)?;
    let repository = format!("{repository_prefix}/{source}/{path}");
    let reference = format!("{registry}/{repository}:{tag}");
    Ok(CachedImage {
        upstream,
        repository,
        tag,
        reference,
    })
}

fn image_name_and_tag(upstream: &str) -> Result<(&str, String), Error> {
    let (name, tag) = upstream
        .rsplit_once(':')
        .ok_or_else(|| Error::InvalidImage(upstream.to_string()))?;
    if name.is_empty() || tag.is_empty() || upstream.contains('@') {
        return Err(Error::InvalidImage(upstream.to_string()));
    }
    Ok((name, tag.to_string()))
}

fn repository_path(name: &str) -> Result<(&'static str, String), Error> {
    let mut parts = name.splitn(2, '/');
    let first = parts
        .next()
        .ok_or_else(|| Error::InvalidImage(name.to_string()))?;
    let path = parts.next();
    match path {
        Some("") => Err(Error::InvalidImage(name.to_string())),
        Some(path) if first == "ghcr.io" => Ok(("ghcr", path.to_string())),
        Some(_) if first.contains('.') || first.contains(':') || first == "localhost" => {
            Err(Error::UnsupportedImageRegistry(first.to_string()))
        }
        Some(_) => Ok(("docker-hub", name.to_string())),
        None if first.contains('.') || first.contains(':') || first == "localhost" => {
            Err(Error::InvalidImage(name.to_string()))
        }
        None => Ok(("docker-hub", format!("library/{name}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_docker_hub_org_image() {
        let image = cached_image(
            "123.dkr.ecr.us-east-1.amazonaws.com",
            "commonware-deployer-cache",
            "prom/prometheus:v3.2.0",
        )
        .unwrap();
        assert_eq!(
            image.repository,
            "commonware-deployer-cache/docker-hub/prom/prometheus"
        );
        assert_eq!(image.tag, "v3.2.0");
        assert_eq!(
            image.reference,
            "123.dkr.ecr.us-east-1.amazonaws.com/commonware-deployer-cache/docker-hub/prom/prometheus:v3.2.0"
        );
    }

    #[test]
    fn test_cached_docker_hub_library_image() {
        let image = cached_image(
            "123.dkr.ecr.us-east-1.amazonaws.com",
            "commonware-deployer-cache",
            "busybox:1.37.0",
        )
        .unwrap();
        assert_eq!(
            image.repository,
            "commonware-deployer-cache/docker-hub/library/busybox"
        );
        assert_eq!(
            image.reference,
            "123.dkr.ecr.us-east-1.amazonaws.com/commonware-deployer-cache/docker-hub/library/busybox:1.37.0"
        );
    }

    #[test]
    fn test_cached_ghcr_image() {
        let image = cached_image(
            "123.dkr.ecr.us-east-1.amazonaws.com",
            "commonware-deployer-cache",
            "ghcr.io/clabby/tracer-web:0.1.1",
        )
        .unwrap();
        assert_eq!(
            image.repository,
            "commonware-deployer-cache/ghcr/clabby/tracer-web"
        );
        assert_eq!(image.tag, "0.1.1");
        assert_eq!(
            image.reference,
            "123.dkr.ecr.us-east-1.amazonaws.com/commonware-deployer-cache/ghcr/clabby/tracer-web:0.1.1"
        );
    }

    #[test]
    fn test_unsupported_registry() {
        let err = cached_image(
            "123.dkr.ecr.us-east-1.amazonaws.com",
            "commonware-deployer-cache",
            "quay.io/org/image:v1",
        )
        .unwrap_err();
        assert!(matches!(err, Error::UnsupportedImageRegistry(registry) if registry == "quay.io"));
    }
}
