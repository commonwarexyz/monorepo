//! `clean` subcommand for `ec2`

use crate::aws::{
    cloudfront,
    s3::{self, delete_bucket_and_contents, is_no_such_bucket_error, BUCKET_NAME},
    Error, MONITORING_REGION,
};
use aws_config::Region;
use tracing::info;

/// Deletes the shared S3 cache bucket, CloudFront distribution, and all contents
pub async fn clean() -> Result<(), Error> {
    // Delete CloudFront distribution first (it references the S3 bucket)
    info!("cleaning CloudFront distribution");
    let cf_client = cloudfront::create_client(Region::new(MONITORING_REGION)).await;
    cloudfront::delete_distribution(&cf_client).await?;

    // Delete S3 bucket
    info!(bucket = BUCKET_NAME, "cleaning S3 bucket");
    let s3_client = s3::create_client(Region::new(MONITORING_REGION)).await;

    match delete_bucket_and_contents(&s3_client, BUCKET_NAME).await {
        Ok(()) => {
            info!(bucket = BUCKET_NAME, "cleaned S3 bucket");
        }
        Err(e) => {
            if is_no_such_bucket_error(&e) {
                info!(
                    bucket = BUCKET_NAME,
                    "bucket does not exist, nothing to clean"
                );
                return Ok(());
            }
            return Err(e);
        }
    }

    Ok(())
}
