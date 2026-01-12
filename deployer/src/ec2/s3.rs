//! AWS S3 SDK function wrappers for caching deployer artifacts

use crate::ec2::Error;
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
use commonware_cryptography::{Hasher, Sha256};
use std::{io::Read, path::Path, time::Duration};
use tracing::info;

/// S3 bucket name for caching deployer artifacts
pub const S3_BUCKET_NAME: &str = "commonware-deployer-cache";

/// S3 prefix for tool binaries: tools/binaries/{tool}/{version}/{platform}/{filename}
pub const S3_TOOLS_BINARIES_PREFIX: &str = "tools/binaries";

/// S3 prefix for tool configs: tools/configs/{deployer_version}/{component}/{file}
pub const S3_TOOLS_CONFIGS_PREFIX: &str = "tools/configs";

/// Target platform for prebuilt binaries
// TODO (#2779): Add multi-architecture support
pub const TARGET_PLATFORM: &str = "linux-arm64";

/// S3 prefix for per-deployment data
pub const S3_DEPLOYMENTS_PREFIX: &str = "deployments";

/// Duration for pre-signed URLs (6 hours)
pub const PRESIGN_DURATION: Duration = Duration::from_secs(6 * 60 * 60);

/// Creates an S3 client for the specified AWS region
pub async fn create_s3_client(region: Region) -> S3Client {
    let retry = aws_config::retry::RetryConfig::adaptive()
        .with_max_attempts(u32::MAX)
        .with_initial_backoff(Duration::from_millis(500))
        .with_max_backoff(Duration::from_secs(30))
        .with_reconnect_mode(ReconnectMode::ReconnectOnTransientError);
    let config = aws_config::defaults(BehaviorVersion::v2025_08_07())
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
            // If it's a 404, we need to create it
            let service_err = e.into_service_error();
            if !service_err.is_not_found() {
                return Err(aws_sdk_s3::Error::from(service_err).into());
            }
        }
    }

    // Create the bucket
    let location_constraint = BucketLocationConstraint::from(region);
    let bucket_config = CreateBucketConfiguration::builder()
        .location_constraint(location_constraint)
        .build();

    // Note: us-east-1 doesn't require location constraint
    let mut request = client.create_bucket().bucket(bucket_name);
    if region != "us-east-1" {
        request = request.create_bucket_configuration(bucket_config);
    }

    request
        .send()
        .await
        .map_err(|e| aws_sdk_s3::Error::from(e.into_service_error()))?;
    info!(bucket = bucket_name, region = region, "created bucket");
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
                Err(aws_sdk_s3::Error::from(service_err).into())
            }
        }
    }
}

/// Uploads a file to S3
pub async fn upload_file(
    client: &S3Client,
    bucket: &str,
    key: &str,
    path: &Path,
) -> Result<(), Error> {
    let body = ByteStream::from_path(path)
        .await
        .map_err(std::io::Error::other)?;

    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(body)
        .send()
        .await
        .map_err(|e| aws_sdk_s3::Error::from(e.into_service_error()))?;

    info!(bucket = bucket, key = key, "uploaded file to S3");
    Ok(())
}

/// Uploads a file to S3 and returns a pre-signed URL for downloading it
#[must_use = "the pre-signed URL should be used to download the file"]
pub async fn upload_and_presign(
    client: &S3Client,
    bucket: &str,
    key: &str,
    path: &Path,
    expires_in: Duration,
) -> Result<String, Error> {
    upload_file(client, bucket, key, path).await?;
    presign_url(client, bucket, key, expires_in).await
}

/// Caches content to S3 if it doesn't exist, then returns a pre-signed URL
#[must_use = "the pre-signed URL should be used to download the content"]
pub async fn cache_content_and_presign(
    client: &S3Client,
    bucket: &str,
    key: &str,
    content: &'static [u8],
    expires_in: Duration,
) -> Result<String, Error> {
    if !object_exists(client, bucket, key).await? {
        info!(key = key, "static content not cached, uploading");
        let body = ByteStream::from_static(content);
        client
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .map_err(|e| aws_sdk_s3::Error::from(e.into_service_error()))?;
    }
    presign_url(client, bucket, key, expires_in).await
}

/// Computes the SHA256 hash of a file and returns it as a hex string
pub fn hash_file(path: &Path) -> Result<String, Error> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(hasher.finalize().to_string())
}

/// Caches a file to S3 by hash if it doesn't exist, then returns a pre-signed URL
#[must_use = "the pre-signed URL should be used to download the file"]
pub async fn cache_file_and_presign(
    client: &S3Client,
    bucket: &str,
    key: &str,
    path: &Path,
    expires_in: Duration,
) -> Result<String, Error> {
    if !object_exists(client, bucket, key).await? {
        info!(key = key, "file not cached, uploading");
        upload_file(client, bucket, key, path).await?;
    }
    presign_url(client, bucket, key, expires_in).await
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

        let response = request
            .send()
            .await
            .map_err(|e| aws_sdk_s3::Error::from(e.into_service_error()))?;

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
                    .map_err(|e| aws_sdk_s3::Error::from(e.into_service_error()))?;

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
        .map_err(|e| aws_sdk_s3::Error::from(e.into_service_error()))?;
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
        Error::AwsS3(aws_err) => {
            matches!(aws_err.as_ref(), aws_sdk_s3::Error::NoSuchBucket(_))
        }
        _ => false,
    }
}
