//! CloudFront distribution management for accelerating S3 downloads
//!
//! Creates and manages a CloudFront distribution with Origin Access Control (OAC)
//! to serve cached content from S3 with edge caching and signed URLs.

use crate::aws::{deployer_directory, s3::BUCKET_NAME, Error};
use aws_config::BehaviorVersion;
use aws_sdk_cloudfront::{
    config::retry::ReconnectMode,
    types::{
        CustomHeaders, DefaultCacheBehavior, DistributionConfig, KeyGroupConfig, Origin,
        OriginAccessControlConfig, OriginAccessControlOriginTypes,
        OriginAccessControlSigningBehaviors, OriginAccessControlSigningProtocols, Origins,
        PriceClass, PublicKeyConfig, S3OriginConfig, TrustedKeyGroups, ViewerProtocolPolicy,
    },
    Client as CloudFrontClient,
};
pub use aws_config::Region;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rsa::{
    pkcs1v15::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
    sha2::Sha256,
    signature::{SignatureEncoding, Signer},
    RsaPrivateKey,
};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, info};

const CLOUDFRONT_DIR: &str = "cloudfront";
const PRIVATE_KEY_FILE: &str = "key.pem";
const KEY_PAIR_ID_FILE: &str = "key_pair_id";
const DISTRIBUTION_ID_FILE: &str = "distribution_id";
const DISTRIBUTION_DOMAIN_FILE: &str = "distribution_domain";
const KEY_GROUP_ID_FILE: &str = "key_group_id";

const DISTRIBUTION_COMMENT: &str = "commonware-deployer-cache";
const OAC_NAME: &str = "commonware-deployer-oac";
const KEY_GROUP_NAME: &str = "commonware-deployer-keys";
const PUBLIC_KEY_NAME: &str = "commonware-deployer-key";

const CACHING_OPTIMIZED_POLICY_ID: &str = "658327ea-f89d-4fab-a63d-7e88639e58f6";

pub struct CloudFrontConfig {
    pub distribution_id: String,
    pub domain_name: String,
    pub key_pair_id: String,
    pub private_key: RsaPrivateKey,
}

pub async fn create_client(region: Region) -> CloudFrontClient {
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
    CloudFrontClient::new(&config)
}

fn cloudfront_dir() -> PathBuf {
    deployer_directory(None).join(CLOUDFRONT_DIR)
}

fn load_cached_config() -> Option<CloudFrontConfig> {
    let dir = cloudfront_dir();
    let distribution_id = fs::read_to_string(dir.join(DISTRIBUTION_ID_FILE)).ok()?;
    let domain_name = fs::read_to_string(dir.join(DISTRIBUTION_DOMAIN_FILE)).ok()?;
    let key_pair_id = fs::read_to_string(dir.join(KEY_PAIR_ID_FILE)).ok()?;
    let private_key_pem = fs::read_to_string(dir.join(PRIVATE_KEY_FILE)).ok()?;
    let private_key = RsaPrivateKey::from_pkcs8_pem(&private_key_pem).ok()?;
    Some(CloudFrontConfig {
        distribution_id: distribution_id.trim().to_string(),
        domain_name: domain_name.trim().to_string(),
        key_pair_id: key_pair_id.trim().to_string(),
        private_key,
    })
}

fn save_cached_config(config: &CloudFrontConfig) -> Result<(), Error> {
    let dir = cloudfront_dir();
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(DISTRIBUTION_ID_FILE), &config.distribution_id)?;
    fs::write(dir.join(DISTRIBUTION_DOMAIN_FILE), &config.domain_name)?;
    fs::write(dir.join(KEY_PAIR_ID_FILE), &config.key_pair_id)?;
    let private_key_pem = config
        .private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::CloudFrontKeyGeneration(e.to_string()))?;
    fs::write(dir.join(PRIVATE_KEY_FILE), private_key_pem.as_str())?;
    Ok(())
}

fn save_key_group_id(key_group_id: &str) -> Result<(), Error> {
    let dir = cloudfront_dir();
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(KEY_GROUP_ID_FILE), key_group_id)?;
    Ok(())
}

fn load_key_group_id() -> Option<String> {
    let dir = cloudfront_dir();
    fs::read_to_string(dir.join(KEY_GROUP_ID_FILE))
        .ok()
        .map(|s| s.trim().to_string())
}

async fn find_existing_distribution(
    client: &CloudFrontClient,
) -> Result<Option<(String, String)>, Error> {
    let mut marker: Option<String> = None;
    loop {
        let mut req = client.list_distributions();
        if let Some(m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.map_err(|e| Error::AwsCloudFront {
            operation: super::CloudFrontOperation::ListDistributions,
            source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
        })?;

        if let Some(list) = resp.distribution_list {
            for dist in list.items() {
                if dist.comment() == DISTRIBUTION_COMMENT {
                    let id = dist.id().to_string();
                    let domain = dist.domain_name().to_string();
                    return Ok(Some((id, domain)));
                }
            }
            if list.next_marker.is_some() {
                marker = list.next_marker.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }
    Ok(None)
}

async fn find_existing_oac(client: &CloudFrontClient) -> Result<Option<String>, Error> {
    let mut marker: Option<String> = None;
    loop {
        let mut req = client.list_origin_access_controls();
        if let Some(m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.map_err(|e| Error::AwsCloudFront {
            operation: super::CloudFrontOperation::ListOriginAccessControls,
            source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
        })?;

        if let Some(list) = resp.origin_access_control_list {
            for oac in list.items() {
                if oac.name() == OAC_NAME {
                    return Ok(Some(oac.id().to_string()));
                }
            }
            if list.next_marker.is_some() {
                marker = list.next_marker.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }
    Ok(None)
}

async fn create_oac(client: &CloudFrontClient) -> Result<String, Error> {
    let config = OriginAccessControlConfig::builder()
        .name(OAC_NAME)
        .description("OAC for commonware-deployer S3 bucket")
        .signing_protocol(OriginAccessControlSigningProtocols::Sigv4)
        .signing_behavior(OriginAccessControlSigningBehaviors::Always)
        .origin_access_control_origin_type(OriginAccessControlOriginTypes::S3)
        .build()
        .map_err(|e| Error::CloudFrontConfiguration(e.to_string()))?;

    let resp = client
        .create_origin_access_control()
        .origin_access_control_config(config)
        .send()
        .await
        .map_err(|e| Error::AwsCloudFront {
            operation: super::CloudFrontOperation::CreateOriginAccessControl,
            source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
        })?;

    let oac = resp
        .origin_access_control
        .ok_or_else(|| Error::CloudFrontConfiguration("OAC created but not returned".to_string()))?;
    let id = oac.id().to_string();
    Ok(id)
}

async fn ensure_oac_exists(client: &CloudFrontClient) -> Result<String, Error> {
    if let Some(id) = find_existing_oac(client).await? {
        info!(id = id.as_str(), "found existing OAC");
        return Ok(id);
    }
    let id = create_oac(client).await?;
    info!(id = id.as_str(), "created OAC");
    Ok(id)
}

async fn find_existing_public_key(client: &CloudFrontClient) -> Result<Option<String>, Error> {
    let mut marker: Option<String> = None;
    loop {
        let mut req = client.list_public_keys();
        if let Some(m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.map_err(|e| Error::AwsCloudFront {
            operation: super::CloudFrontOperation::ListPublicKeys,
            source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
        })?;

        if let Some(list) = resp.public_key_list {
            for key in list.items() {
                if key.name() == PUBLIC_KEY_NAME {
                    return Ok(Some(key.id().to_string()));
                }
            }
            if list.next_marker.is_some() {
                marker = list.next_marker.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }
    Ok(None)
}

async fn find_existing_key_group(client: &CloudFrontClient) -> Result<Option<String>, Error> {
    let mut marker: Option<String> = None;
    loop {
        let mut req = client.list_key_groups();
        if let Some(m) = marker {
            req = req.marker(m);
        }
        let resp = req.send().await.map_err(|e| Error::AwsCloudFront {
            operation: super::CloudFrontOperation::ListKeyGroups,
            source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
        })?;

        if let Some(list) = resp.key_group_list {
            for group in list.items() {
                if let Some(kg) = &group.key_group {
                    if let Some(cfg) = &kg.key_group_config {
                        if cfg.name() == KEY_GROUP_NAME {
                            return Ok(Some(kg.id().to_string()));
                        }
                    }
                }
            }
            if list.next_marker.is_some() {
                marker = list.next_marker.clone();
            } else {
                break;
            }
        } else {
            break;
        }
    }
    Ok(None)
}

async fn create_key_pair_and_group(
    client: &CloudFrontClient,
) -> Result<(String, RsaPrivateKey), Error> {
    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| Error::CloudFrontKeyGeneration(e.to_string()))?;

    let public_key_pem = private_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| Error::CloudFrontKeyGeneration(e.to_string()))?;

    let public_key_config = PublicKeyConfig::builder()
        .name(PUBLIC_KEY_NAME)
        .encoded_key(&public_key_pem)
        .caller_reference(format!(
            "commonware-deployer-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ))
        .build()
        .map_err(|e| Error::CloudFrontConfiguration(e.to_string()))?;

    let create_key_resp = client
        .create_public_key()
        .public_key_config(public_key_config)
        .send()
        .await
        .map_err(|e| Error::AwsCloudFront {
            operation: super::CloudFrontOperation::CreatePublicKey,
            source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
        })?;

    let public_key = create_key_resp
        .public_key
        .ok_or_else(|| {
            Error::CloudFrontConfiguration("Public key created but not returned".to_string())
        })?;
    let public_key_id = public_key.id().to_string();
    info!(id = public_key_id.as_str(), "created public key");

    let key_group_config = KeyGroupConfig::builder()
        .name(KEY_GROUP_NAME)
        .items(&public_key_id)
        .build()
        .map_err(|e| Error::CloudFrontConfiguration(e.to_string()))?;

    let create_group_resp = client
        .create_key_group()
        .key_group_config(key_group_config)
        .send()
        .await
        .map_err(|e| Error::AwsCloudFront {
            operation: super::CloudFrontOperation::CreateKeyGroup,
            source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
        })?;

    let key_group = create_group_resp
        .key_group
        .ok_or_else(|| {
            Error::CloudFrontConfiguration("Key group created but not returned".to_string())
        })?;
    let key_group_id = key_group.id().to_string();
    info!(id = key_group_id.as_str(), "created key group");

    save_key_group_id(&key_group_id)?;

    Ok((public_key_id, private_key))
}

async fn ensure_key_pair_exists(
    client: &CloudFrontClient,
) -> Result<(String, String, RsaPrivateKey), Error> {
    let dir = cloudfront_dir();
    let key_path = dir.join(PRIVATE_KEY_FILE);
    let key_pair_id_path = dir.join(KEY_PAIR_ID_FILE);

    if key_path.exists() && key_pair_id_path.exists() {
        let private_key_pem = fs::read_to_string(&key_path)?;
        let key_pair_id = fs::read_to_string(&key_pair_id_path)?.trim().to_string();

        if let Ok(private_key) = RsaPrivateKey::from_pkcs8_pem(&private_key_pem) {
            if let Some(existing_id) = find_existing_public_key(client).await? {
                if existing_id == key_pair_id {
                    if let Some(key_group_id) = find_existing_key_group(client).await? {
                        info!(
                            key_pair_id = key_pair_id.as_str(),
                            key_group_id = key_group_id.as_str(),
                            "using existing key pair and group"
                        );
                        return Ok((key_pair_id, key_group_id, private_key));
                    }
                }
            }
        }
    }

    let (key_pair_id, private_key) = create_key_pair_and_group(client).await?;
    let key_group_id = load_key_group_id()
        .ok_or_else(|| Error::CloudFrontConfiguration("Key group ID not saved".to_string()))?;

    fs::create_dir_all(&dir)?;
    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::CloudFrontKeyGeneration(e.to_string()))?;
    fs::write(&key_path, private_key_pem.as_str())?;
    fs::write(&key_pair_id_path, &key_pair_id)?;

    Ok((key_pair_id, key_group_id, private_key))
}

async fn create_distribution(
    client: &CloudFrontClient,
    oac_id: &str,
    key_group_id: &str,
) -> Result<(String, String, String), Error> {
    let origin_id = "S3-commonware-deployer-cache";
    let origin_domain = format!("{BUCKET_NAME}.s3.amazonaws.com");

    let s3_origin_config = S3OriginConfig::builder()
        .origin_access_identity("")
        .build();

    let origin = Origin::builder()
        .id(origin_id)
        .domain_name(&origin_domain)
        .s3_origin_config(s3_origin_config)
        .origin_access_control_id(oac_id)
        .custom_headers(CustomHeaders::builder().quantity(0).build().map_err(|e| {
            Error::CloudFrontConfiguration(e.to_string())
        })?)
        .build()
        .map_err(|e| Error::CloudFrontConfiguration(e.to_string()))?;

    let origins = Origins::builder()
        .quantity(1)
        .items(origin)
        .build()
        .map_err(|e| Error::CloudFrontConfiguration(e.to_string()))?;

    let trusted_key_groups = TrustedKeyGroups::builder()
        .enabled(true)
        .quantity(1)
        .items(key_group_id)
        .build()
        .map_err(|e| Error::CloudFrontConfiguration(e.to_string()))?;

    let default_cache_behavior = DefaultCacheBehavior::builder()
        .target_origin_id(origin_id)
        .viewer_protocol_policy(ViewerProtocolPolicy::HttpsOnly)
        .cache_policy_id(CACHING_OPTIMIZED_POLICY_ID)
        .trusted_key_groups(trusted_key_groups)
        .compress(true)
        .build()
        .map_err(|e| Error::CloudFrontConfiguration(e.to_string()))?;

    let caller_reference = format!(
        "commonware-deployer-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );

    let dist_config = DistributionConfig::builder()
        .origins(origins)
        .default_cache_behavior(default_cache_behavior)
        .comment(DISTRIBUTION_COMMENT)
        .caller_reference(caller_reference)
        .enabled(true)
        .price_class(PriceClass::PriceClassAll)
        .build()
        .map_err(|e| Error::CloudFrontConfiguration(e.to_string()))?;

    let resp = client
        .create_distribution()
        .distribution_config(dist_config)
        .send()
        .await
        .map_err(|e| Error::AwsCloudFront {
            operation: super::CloudFrontOperation::CreateDistribution,
            source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
        })?;

    let dist = resp.distribution.ok_or_else(|| {
        Error::CloudFrontConfiguration("Distribution created but not returned".to_string())
    })?;

    let id = dist.id().to_string();
    let domain = dist.domain_name().to_string();
    let arn = dist.arn().to_string();

    info!(
        id = id.as_str(),
        domain = domain.as_str(),
        arn = arn.as_str(),
        "created CloudFront distribution"
    );

    Ok((id, domain, arn))
}

pub async fn wait_for_distribution_deployed(
    client: &CloudFrontClient,
    distribution_id: &str,
) -> Result<(), Error> {
    info!(
        id = distribution_id,
        "waiting for CloudFront distribution to deploy (this may take 10-15 minutes on first creation)"
    );

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(30 * 60);

    loop {
        interval.tick().await;

        if start.elapsed() > timeout {
            return Err(Error::CloudFrontDistributionTimeout);
        }

        let resp = client
            .get_distribution()
            .id(distribution_id)
            .send()
            .await
            .map_err(|e| Error::AwsCloudFront {
                operation: super::CloudFrontOperation::GetDistribution,
                source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
            })?;

        if let Some(dist) = resp.distribution {
            let status = dist.status();
            debug!(
                id = distribution_id,
                status = status,
                elapsed_secs = start.elapsed().as_secs(),
                "distribution status"
            );
            if status == "Deployed" {
                info!(
                    id = distribution_id,
                    elapsed_secs = start.elapsed().as_secs(),
                    "CloudFront distribution deployed"
                );
                return Ok(());
            }
        }
    }
}

pub async fn ensure_distribution_exists(
    client: &CloudFrontClient,
    s3_client: &aws_sdk_s3::Client,
) -> Result<CloudFrontConfig, Error> {
    if let Some(config) = load_cached_config() {
        if find_existing_distribution(client).await?.is_some() {
            info!(
                distribution_id = config.distribution_id.as_str(),
                domain = config.domain_name.as_str(),
                "using cached CloudFront configuration"
            );
            return Ok(config);
        }
    }

    if let Some((id, domain)) = find_existing_distribution(client).await? {
        info!(
            id = id.as_str(),
            domain = domain.as_str(),
            "found existing CloudFront distribution"
        );

        let (key_pair_id, _key_group_id, private_key) = ensure_key_pair_exists(client).await?;

        let config = CloudFrontConfig {
            distribution_id: id,
            domain_name: domain,
            key_pair_id,
            private_key,
        };
        save_cached_config(&config)?;
        return Ok(config);
    }

    info!("creating new CloudFront distribution");

    let oac_id = ensure_oac_exists(client).await?;
    let (key_pair_id, key_group_id, private_key) = ensure_key_pair_exists(client).await?;
    let (distribution_id, domain_name, distribution_arn) =
        create_distribution(client, &oac_id, &key_group_id).await?;

    update_bucket_policy(s3_client, &distribution_arn).await?;

    wait_for_distribution_deployed(client, &distribution_id).await?;

    let config = CloudFrontConfig {
        distribution_id,
        domain_name,
        key_pair_id,
        private_key,
    };
    save_cached_config(&config)?;

    Ok(config)
}

async fn update_bucket_policy(
    s3_client: &aws_sdk_s3::Client,
    distribution_arn: &str,
) -> Result<(), Error> {
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudFrontServicePrincipal",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudfront.amazonaws.com"
                },
                "Action": "s3:GetObject",
                "Resource": format!("arn:aws:s3:::{BUCKET_NAME}/*"),
                "Condition": {
                    "StringEquals": {
                        "AWS:SourceArn": distribution_arn
                    }
                }
            }
        ]
    });

    s3_client
        .put_bucket_policy()
        .bucket(BUCKET_NAME)
        .policy(policy.to_string())
        .send()
        .await
        .map_err(|e| Error::AwsS3 {
            bucket: BUCKET_NAME.to_string(),
            operation: super::S3Operation::PutBucketPolicy,
            source: Box::new(aws_sdk_s3::Error::from(e.into_service_error())),
        })?;

    info!(
        bucket = BUCKET_NAME,
        "updated S3 bucket policy for CloudFront"
    );
    Ok(())
}

pub fn sign_url(config: &CloudFrontConfig, key: &str, expires_in: Duration) -> String {
    let url = format!("https://{}/{}", config.domain_name, key);
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + expires_in.as_secs();

    let policy = serde_json::json!({
        "Statement": [{
            "Resource": url,
            "Condition": {
                "DateLessThan": {
                    "AWS:EpochTime": expires
                }
            }
        }]
    });

    let policy_json = policy.to_string();
    let policy_b64 = cloudfront_base64_encode(policy_json.as_bytes());

    let signing_key = SigningKey::<Sha256>::new(config.private_key.clone());
    let signature: rsa::pkcs1v15::Signature = signing_key.sign(policy_json.as_bytes());
    let signature_b64 = cloudfront_base64_encode(&signature.to_bytes());

    format!(
        "{}?Policy={}&Signature={}&Key-Pair-Id={}",
        url, policy_b64, signature_b64, config.key_pair_id
    )
}

fn cloudfront_base64_encode(data: &[u8]) -> String {
    BASE64
        .encode(data)
        .replace('+', "-")
        .replace('/', "~")
        .replace('=', "_")
}

pub async fn delete_distribution(client: &CloudFrontClient) -> Result<(), Error> {
    let Some((dist_id, _domain)) = find_existing_distribution(client).await? else {
        info!("no CloudFront distribution found to delete");
        return Ok(());
    };

    info!(
        id = dist_id.as_str(),
        "disabling CloudFront distribution for deletion"
    );

    let get_resp = client
        .get_distribution_config()
        .id(&dist_id)
        .send()
        .await
        .map_err(|e| Error::AwsCloudFront {
            operation: super::CloudFrontOperation::GetDistribution,
            source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
        })?;

    let etag = get_resp.e_tag.ok_or_else(|| {
        Error::CloudFrontConfiguration("No ETag returned for distribution config".to_string())
    })?;

    let dist_config = get_resp.distribution_config.ok_or_else(|| {
        Error::CloudFrontConfiguration("No distribution config returned".to_string())
    })?;

    if dist_config.enabled() {
        let disabled_config = DistributionConfig::builder()
            .caller_reference(dist_config.caller_reference())
            .set_origins(dist_config.origins.clone())
            .set_default_cache_behavior(dist_config.default_cache_behavior.clone())
            .comment(dist_config.comment())
            .enabled(false)
            .set_aliases(dist_config.aliases.clone())
            .set_default_root_object(dist_config.default_root_object.clone())
            .set_cache_behaviors(dist_config.cache_behaviors.clone())
            .set_custom_error_responses(dist_config.custom_error_responses.clone())
            .set_logging(dist_config.logging.clone())
            .set_price_class(dist_config.price_class.clone())
            .set_viewer_certificate(dist_config.viewer_certificate.clone())
            .set_restrictions(dist_config.restrictions.clone())
            .set_web_acl_id(dist_config.web_acl_id.clone())
            .set_http_version(dist_config.http_version.clone())
            .set_is_ipv6_enabled(dist_config.is_ipv6_enabled)
            .build()
            .map_err(|e| {
                Error::CloudFrontConfiguration(format!("Failed to build disabled config: {e}"))
            })?;

        client
            .update_distribution()
            .id(&dist_id)
            .if_match(&etag)
            .distribution_config(disabled_config)
            .send()
            .await
            .map_err(|e| Error::AwsCloudFront {
                operation: super::CloudFrontOperation::UpdateDistribution,
                source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
            })?;

        info!(
            id = dist_id.as_str(),
            "disabled distribution, waiting for deployment"
        );

        wait_for_distribution_deployed(client, &dist_id).await?;

        let get_resp = client
            .get_distribution_config()
            .id(&dist_id)
            .send()
            .await
            .map_err(|e| Error::AwsCloudFront {
                operation: super::CloudFrontOperation::GetDistribution,
                source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
            })?;

        let etag = get_resp.e_tag.ok_or_else(|| {
            Error::CloudFrontConfiguration("No ETag returned for disabled distribution".to_string())
        })?;

        client
            .delete_distribution()
            .id(&dist_id)
            .if_match(&etag)
            .send()
            .await
            .map_err(|e| Error::AwsCloudFront {
                operation: super::CloudFrontOperation::DeleteDistribution,
                source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
            })?;
    } else {
        client
            .delete_distribution()
            .id(&dist_id)
            .if_match(&etag)
            .send()
            .await
            .map_err(|e| Error::AwsCloudFront {
                operation: super::CloudFrontOperation::DeleteDistribution,
                source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
            })?;
    }

    info!(id = dist_id.as_str(), "deleted CloudFront distribution");

    if let Some(key_group_id) = find_existing_key_group(client).await? {
        let get_resp = client
            .get_key_group()
            .id(&key_group_id)
            .send()
            .await
            .map_err(|e| Error::AwsCloudFront {
                operation: super::CloudFrontOperation::ListKeyGroups,
                source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
            })?;

        if let Some(etag) = get_resp.e_tag {
            client
                .delete_key_group()
                .id(&key_group_id)
                .if_match(&etag)
                .send()
                .await
                .map_err(|e| Error::AwsCloudFront {
                    operation: super::CloudFrontOperation::DeleteKeyGroup,
                    source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
                })?;
            info!(id = key_group_id.as_str(), "deleted key group");
        }
    }

    if let Some(public_key_id) = find_existing_public_key(client).await? {
        let get_resp = client
            .get_public_key()
            .id(&public_key_id)
            .send()
            .await
            .map_err(|e| Error::AwsCloudFront {
                operation: super::CloudFrontOperation::GetPublicKey,
                source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
            })?;

        if let Some(etag) = get_resp.e_tag {
            client
                .delete_public_key()
                .id(&public_key_id)
                .if_match(&etag)
                .send()
                .await
                .map_err(|e| Error::AwsCloudFront {
                    operation: super::CloudFrontOperation::DeletePublicKey,
                    source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
                })?;
            info!(id = public_key_id.as_str(), "deleted public key");
        }
    }

    if let Some(oac_id) = find_existing_oac(client).await? {
        let get_resp = client
            .get_origin_access_control()
            .id(&oac_id)
            .send()
            .await
            .map_err(|e| Error::AwsCloudFront {
                operation: super::CloudFrontOperation::GetOriginAccessControl,
                source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
            })?;

        if let Some(etag) = get_resp.e_tag {
            client
                .delete_origin_access_control()
                .id(&oac_id)
                .if_match(&etag)
                .send()
                .await
                .map_err(|e| Error::AwsCloudFront {
                    operation: super::CloudFrontOperation::DeleteOriginAccessControl,
                    source: Box::new(aws_sdk_cloudfront::Error::from(e.into_service_error())),
                })?;
            info!(id = oac_id.as_str(), "deleted OAC");
        }
    }

    let dir = cloudfront_dir();
    if dir.exists() {
        fs::remove_dir_all(&dir)?;
        info!("removed CloudFront local configuration");
    }

    Ok(())
}
