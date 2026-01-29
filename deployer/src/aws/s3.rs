//! AWS S3 SDK function wrappers for caching deployer artifacts

use crate::aws::Error;
use aws_config::BehaviorVersion;
pub use aws_config::Region;
use aws_sdk_s3::{
    config::retry::ReconnectMode,
    operation::head_object::HeadObjectError,
    presigning::PresigningConfig,
    primitives::ByteStream,
    types::{BucketLocationConstraint, CreateBucketConfiguration, Delete, ObjectIdentifier},
    Client as S3Client,
};
use commonware_cryptography::{Hasher as _, Sha256};
use futures::stream::{self, StreamExt, TryStreamExt};
use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{debug, info};

/// Path to the deployer config file that stores the bucket name.
fn config_path() -> PathBuf {
    let home = std::env::var("HOME").expect("$HOME is not configured");
    PathBuf::from(home).join(".commonware-deployer")
}

/// Gets the bucket name, generating one if it doesn't exist.
/// The bucket name is stored in ~/.commonware-deployer.
pub fn get_bucket_name() -> String {
    let path = config_path();

    if let Ok(contents) = std::fs::read_to_string(&path) {
        let name = contents.trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }

    let suffix = &uuid::Uuid::new_v4().simple().to_string()[..16];
    let bucket_name = format!("commonware-deployer-{suffix}");

    std::fs::write(&path, &bucket_name).expect("failed to write bucket config");

    bucket_name
}

/// Prefix for tool binaries: tools/binaries/{tool}/{version}/{platform}/{filename}
pub const TOOLS_BINARIES_PREFIX: &str = "tools/binaries";

/// Prefix for tool configs: tools/configs/{deployer_version}/{component}/{file}
pub const TOOLS_CONFIGS_PREFIX: &str = "tools/configs";

/// Prefix for per-deployment data
pub const DEPLOYMENTS_PREFIX: &str = "deployments";

/// Maximum buffer size for file hashing (32MB)
pub const MAX_HASH_BUFFER_SIZE: usize = 32 * 1024 * 1024;

/// Maximum number of concurrent file hash operations
pub const MAX_CONCURRENT_HASHES: usize = 8;

/// Duration for pre-signed URLs (6 hours)
pub const PRESIGN_DURATION: Duration = Duration::from_secs(6 * 60 * 60);

/// Common wget prefix with retry settings for S3 downloads
///
/// Retries on connection failures and HTTP errors:
/// - 404: Not Found (S3 eventual consistency)
/// - 408: Request Timeout
/// - 429: Too Many Requests (rate limiting)
/// - 500: Internal Server Error
/// - 502: Bad Gateway
/// - 503: Service Unavailable
/// - 504: Gateway Timeout
pub const WGET: &str =
    "wget -q --tries=10 --retry-connrefused --retry-on-http-error=404,408,429,500,502,503,504 --waitretry=5";

/// Creates an S3 client for the specified AWS region
pub async fn create_client(region: Region) -> S3Client {
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
    S3Client::new(&config)
}

/// Ensures the S3 bucket exists, creating it if necessary
pub async fn ensure_bucket_exists(
    client: &S3Client,
    bucket_name: &str,
    region: &str,
) -> Result<(), Error> {
    // Check if bucket exists by trying to get its location
    match client.head_bucket().bucket(bucket_name).send().await {
        Ok(_) => {
            info!(bucket = bucket_name, "bucket already exists");
            return Ok(());
        }
        Err(e) => {
            // Check for region header before consuming the error
            let bucket_region = e
                .raw_response()
                .and_then(|r| r.headers().get("x-amz-bucket-region"))
                .map(|s| s.to_string());

            let service_err = e.into_service_error();
            if service_err.is_not_found() {
                // 404: bucket doesn't exist, we need to create it
                debug!(bucket = bucket_name, "bucket not found, will create");
            } else if let Some(bucket_region) = bucket_region {
                // Bucket exists in a different region - proceed with cross-region access
                info!(
                    bucket = bucket_name,
                    bucket_region = bucket_region.as_str(),
                    client_region = region,
                    "bucket exists in different region, using cross-region access"
                );
                return Ok(());
            } else {
                // 403 or other error without region header: access denied
                return Err(Error::S3BucketForbidden {
                    bucket: bucket_name.to_string(),
                    reason: super::BucketForbiddenReason::AccessDenied,
                });
            }
        }
    }

    // Create the bucket (us-east-1 must not have a location constraint)
    let mut request = client.create_bucket().bucket(bucket_name);
    if region != "us-east-1" {
        let location_constraint = BucketLocationConstraint::from(region);
        let bucket_config = CreateBucketConfiguration::builder()
            .location_constraint(location_constraint)
            .build();
        request = request.create_bucket_configuration(bucket_config);
    }

    match request.send().await {
        Ok(_) => {
            info!(bucket = bucket_name, region = region, "created bucket");
        }
        Err(e) => {
            let service_err = e.into_service_error();
            let s3_err = aws_sdk_s3::Error::from(service_err);
            match &s3_err {
                aws_sdk_s3::Error::BucketAlreadyExists(_)
                | aws_sdk_s3::Error::BucketAlreadyOwnedByYou(_) => {
                    info!(bucket = bucket_name, "bucket already exists");
                }
                _ => {
                    return Err(Error::AwsS3 {
                        bucket: bucket_name.to_string(),
                        operation: super::S3Operation::CreateBucket,
                        source: Box::new(s3_err),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Checks if an object exists in S3
pub async fn object_exists(client: &S3Client, bucket: &str, key: &str) -> Result<bool, Error> {
    match client.head_object().bucket(bucket).key(key).send().await {
        Ok(_) => Ok(true),
        Err(e) => {
            let service_err = e.into_service_error();
            if matches!(service_err, HeadObjectError::NotFound(_)) {
                Ok(false)
            } else {
                Err(Error::AwsS3 {
                    bucket: bucket.to_string(),
                    operation: super::S3Operation::HeadObject,
                    source: Box::new(aws_sdk_s3::Error::from(service_err)),
                })
            }
        }
    }
}

/// Uploads a ByteStream to S3 with unlimited retries for transient failures.
/// Takes a closure that produces the ByteStream, allowing re-creation on retry.
async fn upload_with_retry<F, Fut>(client: &S3Client, bucket: &str, key: &str, make_body: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<ByteStream, Error>>,
{
    let mut attempt = 0u32;
    loop {
        let body = match make_body().await {
            Ok(b) => b,
            Err(e) => {
                debug!(
                    bucket = bucket,
                    key = key,
                    attempt = attempt + 1,
                    error = %e,
                    "failed to create body, retrying"
                );
                attempt = attempt.saturating_add(1);
                let backoff = Duration::from_millis(500 * (1 << attempt.min(10)));
                tokio::time::sleep(backoff).await;
                continue;
            }
        };

        match client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(body)
            .send()
            .await
        {
            Ok(_) => {
                debug!(bucket = bucket, key = key, "uploaded to S3");
                return;
            }
            Err(e) => {
                debug!(
                    bucket = bucket,
                    key = key,
                    attempt = attempt + 1,
                    error = %e,
                    "upload failed, retrying"
                );
                attempt = attempt.saturating_add(1);
                let backoff = Duration::from_millis(500 * (1 << attempt.min(10)));
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Source for S3 upload
pub enum UploadSource<'a> {
    File(&'a Path),
    Static(&'static [u8]),
}

/// Caches content to S3 if it doesn't exist, then returns a pre-signed URL
#[must_use = "the pre-signed URL should be used to download the content"]
pub async fn cache_and_presign(
    client: &S3Client,
    bucket: &str,
    key: &str,
    source: UploadSource<'_>,
    expires_in: Duration,
) -> Result<String, Error> {
    if !object_exists(client, bucket, key).await? {
        debug!(key = key, "not in S3, uploading");
        match source {
            UploadSource::File(path) => {
                let path = path.to_path_buf();
                upload_with_retry(client, bucket, key, || {
                    let path = path.clone();
                    async move {
                        ByteStream::from_path(path)
                            .await
                            .map_err(|e| Error::Io(std::io::Error::other(e)))
                    }
                })
                .await;
            }
            UploadSource::Static(content) => {
                upload_with_retry(client, bucket, key, || async {
                    Ok(ByteStream::from_static(content))
                })
                .await;
            }
        }
    }
    presign_url(client, bucket, key, expires_in).await
}

/// Computes the SHA256 hash of a file and returns it as a hex string.
/// Uses spawn_blocking internally to avoid blocking the async runtime.
pub async fn hash_file(path: &Path) -> Result<String, Error> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(&path)?;
        let file_size = file.metadata()?.len() as usize;
        let buffer_size = file_size.min(MAX_HASH_BUFFER_SIZE);
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; buffer_size];
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }
        Ok(hasher.finalize().to_string())
    })
    .await
    .map_err(|e| Error::Io(std::io::Error::other(e)))?
}

/// Computes SHA256 hashes for multiple files concurrently.
/// Returns a map from file path to hex-encoded digest.
pub async fn hash_files(paths: Vec<String>) -> Result<HashMap<String, String>, Error> {
    stream::iter(paths.into_iter().map(|path| async move {
        let digest = hash_file(Path::new(&path)).await?;
        Ok::<_, Error>((path, digest))
    }))
    .buffer_unordered(MAX_CONCURRENT_HASHES)
    .try_collect()
    .await
}

/// Generates a pre-signed URL for downloading an object from S3
#[must_use = "the pre-signed URL should be used to download the object"]
pub async fn presign_url(
    client: &S3Client,
    bucket: &str,
    key: &str,
    expires_in: Duration,
) -> Result<String, Error> {
    let presigning_config = PresigningConfig::expires_in(expires_in)?;

    let presigned_request = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .presigned(presigning_config)
        .await?;

    Ok(presigned_request.uri().to_string())
}

/// Deletes all objects under a prefix in S3 using batch delete (up to 1000 objects per request)
pub async fn delete_prefix(client: &S3Client, bucket: &str, prefix: &str) -> Result<(), Error> {
    let mut continuation_token: Option<String> = None;
    let mut deleted_count = 0;

    loop {
        let mut request = client.list_objects_v2().bucket(bucket).prefix(prefix);

        if let Some(token) = continuation_token {
            request = request.continuation_token(token);
        }

        let response = request.send().await.map_err(|e| Error::AwsS3 {
            bucket: bucket.to_string(),
            operation: super::S3Operation::ListObjects,
            source: Box::new(aws_sdk_s3::Error::from(e.into_service_error())),
        })?;

        // Collect object identifiers for batch delete
        if let Some(objects) = response.contents {
            let identifiers: Vec<ObjectIdentifier> = objects
                .into_iter()
                .filter_map(|obj| obj.key)
                .map(|key| ObjectIdentifier::builder().key(key).build())
                .collect::<Result<Vec<_>, _>>()?;

            if !identifiers.is_empty() {
                let count = identifiers.len();
                let delete = Delete::builder().set_objects(Some(identifiers)).build()?;

                client
                    .delete_objects()
                    .bucket(bucket)
                    .delete(delete)
                    .send()
                    .await
                    .map_err(|e| Error::AwsS3 {
                        bucket: bucket.to_string(),
                        operation: super::S3Operation::DeleteObjects,
                        source: Box::new(aws_sdk_s3::Error::from(e.into_service_error())),
                    })?;

                deleted_count += count;
            }
        }

        if response.is_truncated == Some(true) {
            continuation_token = response.next_continuation_token;
        } else {
            break;
        }
    }

    info!(
        bucket = bucket,
        prefix = prefix,
        count = deleted_count,
        "deleted objects from S3"
    );
    Ok(())
}

/// Deletes a bucket (must be empty first)
pub async fn delete_bucket(client: &S3Client, bucket: &str) -> Result<(), Error> {
    client
        .delete_bucket()
        .bucket(bucket)
        .send()
        .await
        .map_err(|e| Error::AwsS3 {
            bucket: bucket.to_string(),
            operation: super::S3Operation::DeleteBucket,
            source: Box::new(aws_sdk_s3::Error::from(e.into_service_error())),
        })?;
    info!(bucket = bucket, "deleted bucket");
    Ok(())
}

/// Deletes all objects in a bucket and then deletes the bucket itself
pub async fn delete_bucket_and_contents(client: &S3Client, bucket: &str) -> Result<(), Error> {
    // First delete all objects (no prefix means all objects)
    delete_prefix(client, bucket, "").await?;

    // Then delete the bucket
    delete_bucket(client, bucket).await?;

    Ok(())
}

/// Checks if an error is a "bucket does not exist" error
pub fn is_no_such_bucket_error(error: &Error) -> bool {
    match error {
        Error::AwsS3 { source, .. } => {
            matches!(source.as_ref(), aws_sdk_s3::Error::NoSuchBucket(_))
        }
        _ => false,
    }
}
