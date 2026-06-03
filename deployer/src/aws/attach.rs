//! `attach` subcommand for `ec2`

use crate::aws::{
    deployer_directory, utils::ssh_attach, Error, Hosts, Metadata, CREATED_FILE_NAME,
    DESTROYED_FILE_NAME, METADATA_FILE_NAME, MONITORING_REGION,
};
use std::{
    fs::{self, File},
    net::IpAddr,
};
use tracing::{info, warn};

const HOSTS_FILE_NAME: &str = "hosts.yaml";

#[derive(Clone, Debug, Eq, PartialEq)]
struct InstanceMatch {
    tag: String,
    region: String,
    ip: String,
}

/// Opens an interactive SSH session to a deployed instance.
pub async fn attach(ip: &str) -> Result<(), Error> {
    let ip = normalize_ip(ip)?;

    for metadata in load_active_deployments()? {
        if let Some(instance) = find_match(&metadata, &ip) {
            return attach_to_instance(&instance).await;
        }
    }

    Err(Error::InstanceNotFound(ip))
}

async fn attach_to_instance(instance: &InstanceMatch) -> Result<(), Error> {
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

fn find_match(metadata: &Metadata, ip: &str) -> Option<InstanceMatch> {
    let hosts_path = deployer_directory(Some(&metadata.tag)).join(HOSTS_FILE_NAME);
    let file = match File::open(&hosts_path) {
        Ok(file) => file,
        Err(error) => {
            warn!(
                tag = metadata.tag.as_str(),
                path = ?hosts_path,
                ?error,
                "failed to open hosts file while looking for attach target"
            );
            return None;
        }
    };
    let hosts = match serde_yaml::from_reader::<_, Hosts>(file) {
        Ok(hosts) => hosts,
        Err(error) => {
            warn!(
                tag = metadata.tag.as_str(),
                path = ?hosts_path,
                ?error,
                "failed to parse hosts file while looking for attach target"
            );
            return None;
        }
    };
    find_host_match(&metadata.tag, hosts, ip)
}

fn find_host_match(tag: &str, hosts: Hosts, ip: &str) -> Option<InstanceMatch> {
    if hosts.monitoring.public.to_string() == ip {
        return Some(InstanceMatch {
            tag: tag.to_string(),
            region: MONITORING_REGION.to_string(),
            ip: ip.to_string(),
        });
    }

    hosts
        .hosts
        .into_iter()
        .find(|host| host.ip.to_string() == ip)
        .map(|host| InstanceMatch {
            tag: tag.to_string(),
            region: host.region,
            ip: ip.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::{find_host_match, normalize_ip, InstanceMatch};
    use crate::aws::{Host, Hosts, MonitoringIps, MONITORING_REGION};
    use std::net::IpAddr;

    fn instance(tag: &str, region: &str, ip: &str) -> InstanceMatch {
        InstanceMatch {
            tag: tag.to_string(),
            region: region.to_string(),
            ip: ip.to_string(),
        }
    }

    #[test]
    fn test_normalize_ip() {
        assert_eq!(
            normalize_ip("2001:db8:0:0::1").expect("failed to parse ip"),
            "2001:db8::1"
        );
    }

    #[test]
    fn test_instance_match() {
        let selected = instance("a", "us-east-1", "1.1.1.1");
        assert_eq!(selected.tag, "a");
    }

    #[test]
    fn test_find_host_match() {
        let hosts = Hosts {
            monitoring: MonitoringIps {
                public: "2.2.2.2".parse::<IpAddr>().unwrap(),
                private: "10.0.0.1".parse::<IpAddr>().unwrap(),
            },
            hosts: vec![Host {
                name: "node".to_string(),
                region: "us-east-1".to_string(),
                ip: "1.1.1.1".parse::<IpAddr>().unwrap(),
            }],
        };
        let selected = find_host_match("tag", hosts, "1.1.1.1").expect("match missing");
        assert_eq!(selected.tag, "tag");
        assert_eq!(selected.region, "us-east-1");
    }

    #[test]
    fn test_find_monitoring_match() {
        let hosts = Hosts {
            monitoring: MonitoringIps {
                public: "2.2.2.2".parse::<IpAddr>().unwrap(),
                private: "10.0.0.1".parse::<IpAddr>().unwrap(),
            },
            hosts: Vec::new(),
        };
        let selected = find_host_match("tag", hosts, "2.2.2.2").expect("match missing");
        assert_eq!(selected.tag, "tag");
        assert_eq!(selected.region, MONITORING_REGION);
    }
}
