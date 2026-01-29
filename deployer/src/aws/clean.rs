//! `clean` subcommand for `ec2`

use crate::aws::{
    s3::{self, delete_bucket_and_contents, get_bucket_name, is_no_such_bucket_error},
    Error, MONITORING_REGION,
};
use aws_config::Region;
use tracing::info;

/// Deletes the shared S3 cache bucket and all its contents
pub async fn clean() -> Result<(), Error> {
    let bucket_name = get_bucket_name();
    info!(bucket = bucket_name.as_str(), "cleaning S3 bucket");

    // Create S3 client in the monitoring region (where bucket is located)
    let s3_client = s3::create_client(Region::new(MONITORING_REGION)).await;

    // Delete all objects and the bucket itself
    match delete_bucket_and_contents(&s3_client, &bucket_name).await {
        Ok(()) => {
            info!(bucket = bucket_name.as_str(), "cleaned S3 bucket");
        }
        Err(e) => {
            if is_no_such_bucket_error(&e) {
                info!(
                    bucket = bucket_name.as_str(),
                    "bucket does not exist, nothing to clean"
                );
                return Ok(());
            }
            return Err(e);
        }
    }

    Ok(())
}
