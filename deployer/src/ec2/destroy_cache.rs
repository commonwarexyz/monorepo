//! `destroy-cache` subcommand for `ec2`

use crate::ec2::{
    s3::{create_s3_client, delete_bucket_and_contents, S3_BUCKET_NAME},
    Error, MONITORING_REGION,
};
use aws_config::Region;
use tracing::info;

/// Destroys the shared S3 cache bucket and all its contents
pub async fn destroy_cache() -> Result<(), Error> {
    info!("destroying S3 cache bucket");

    // Create S3 client in the monitoring region (where bucket is located)
    let s3_client = create_s3_client(Region::new(MONITORING_REGION)).await;

    // Delete all objects and the bucket itself
    match delete_bucket_and_contents(&s3_client, S3_BUCKET_NAME).await {
        Ok(()) => {
            info!(bucket = S3_BUCKET_NAME, "destroyed S3 cache bucket");
        }
        Err(e) => {
            // Check if bucket doesn't exist
            let err_str = format!("{:?}", e);
            if err_str.contains("NoSuchBucket") {
                info!(
                    bucket = S3_BUCKET_NAME,
                    "bucket does not exist, nothing to destroy"
                );
                return Ok(());
            }
            return Err(e);
        }
    }

    Ok(())
}
