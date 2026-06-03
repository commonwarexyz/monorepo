//! `attach` subcommand for `ec2`

use crate::aws::{
    deployer_directory,
    ec2::{self, Region},
    utils::ssh_attach,
    Error, Metadata, CREATED_FILE_NAME, DESTROYED_FILE_NAME, METADATA_FILE_NAME,
};
use std::{
    fs::{self, File},
    net::IpAddr,
};
use tracing::info;

#[derive(Clone, Debug, Eq, PartialEq)]
struct InstanceMatch {
    tag: String,
    region: String,
    ip: String,
}

/// Opens an interactive SSH session to a deployed instance.
pub async fn attach(ip: &str) -> Result<(), Error> {
    let ip = normalize_ip(ip)?;

    let mut matches = Vec::new();
    for metadata in load_active_deployments()? {
        matches.extend(find_matches(&metadata, &ip).await?);
    }

    let instance = select_match(&ip, matches)?;
    let key_path = deployer_directory(Some(&instance.tag)).join(format!("id_rsa_{}", instance.tag));
    if !key_path.exists() {
        return Err(Error::PrivateKeyNotFound);
    }

    info!(
        tag = instance.tag.as_str(),
        region = instance.region.as_str(),
        ip = instance.ip.as_str(),
        "attaching to instance"
    );
    ssh_attach(key_path.to_str().unwrap(), &instance.ip).await
}

fn normalize_ip(ip: &str) -> Result<String, Error> {
    Ok(ip.parse::<IpAddr>()?.to_string())
}

fn load_active_deployments() -> Result<Vec<Metadata>, Error> {
    let deployer_dir = deployer_directory(None);
    if !deployer_dir.exists() {
        return Ok(Vec::new());
    }

    let mut deployments: Vec<Metadata> = Vec::new();
    for entry in fs::read_dir(&deployer_dir)? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        if path.join(DESTROYED_FILE_NAME).exists() {
            continue;
        }
        if !path.join(CREATED_FILE_NAME).exists() {
            continue;
        }

        let metadata_path = path.join(METADATA_FILE_NAME);
        let Ok(file) = File::open(&metadata_path) else {
            continue;
        };
        let Ok(metadata) = serde_yaml::from_reader(file) else {
            continue;
        };
        deployments.push(metadata);
    }
    deployments.sort_by(|a, b| a.tag.cmp(&b.tag));
    Ok(deployments)
}

async fn find_matches(metadata: &Metadata, ip: &str) -> Result<Vec<InstanceMatch>, Error> {
    let mut matches = Vec::new();
    for region in &metadata.regions {
        let ec2_client = ec2::create_client(Region::new(region.clone())).await;
        let resp = ec2_client
            .describe_instances()
            .filters(
                aws_sdk_ec2::types::Filter::builder()
                    .name("tag:deployer")
                    .values(&metadata.tag)
                    .build(),
            )
            .filters(
                aws_sdk_ec2::types::Filter::builder()
                    .name("instance-state-name")
                    .values("running")
                    .build(),
            )
            .send()
            .await
            .map_err(|err| err.into_service_error())?;

        for instance in resp
            .reservations
            .unwrap_or_default()
            .into_iter()
            .flat_map(|reservation| reservation.instances.unwrap_or_default())
        {
            if instance.public_ip_address.as_deref() != Some(ip) {
                continue;
            }
            matches.push(InstanceMatch {
                tag: metadata.tag.clone(),
                region: region.clone(),
                ip: ip.to_string(),
            });
        }
    }
    Ok(matches)
}

fn select_match(ip: &str, mut matches: Vec<InstanceMatch>) -> Result<InstanceMatch, Error> {
    matches.sort_by(|a, b| {
        a.tag
            .cmp(&b.tag)
            .then_with(|| a.region.cmp(&b.region))
            .then_with(|| a.ip.cmp(&b.ip))
    });
    matches
        .into_iter()
        .next()
        .ok_or_else(|| Error::InstanceNotFound(ip.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{normalize_ip, select_match, InstanceMatch};

    fn instance(tag: &str, region: &str, ip: &str) -> InstanceMatch {
        InstanceMatch {
            tag: tag.to_string(),
            region: region.to_string(),
            ip: ip.to_string(),
        }
    }

    #[test]
    fn test_select_match() {
        let selected = select_match("1.1.1.1", vec![instance("a", "us-east-1", "1.1.1.1")])
            .expect("match missing");
        assert_eq!(selected.tag, "a");
    }

    #[test]
    fn test_normalize_ip() {
        assert_eq!(
            normalize_ip("2001:db8:0:0::1").expect("failed to parse ip"),
            "2001:db8::1"
        );
    }

    #[test]
    fn test_select_match_missing() {
        let err = select_match("1.1.1.1", Vec::new()).expect_err("missing match selected");
        assert_eq!(err.to_string(), "instance not found: 1.1.1.1");
    }
}
