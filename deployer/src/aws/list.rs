//! `list` subcommand for `ec2`

use crate::aws::{
    DeploymentMetadata, Error, CREATED_FILE_NAME, DESTROYED_FILE_NAME, METADATA_FILE_NAME,
};
use std::fs::{self, File};
use tracing::info;

pub async fn list() -> Result<(), Error> {
    let base_dir = std::env::var("HOME").expect("$HOME is not configured");
    let deployer_dir = std::path::PathBuf::from(format!("{base_dir}/.commonware_deployer"));

    if !deployer_dir.exists() {
        info!("no deployments found");
        return Ok(());
    }

    let mut active = Vec::new();
    for entry in fs::read_dir(&deployer_dir)? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }

        let created = path.join(CREATED_FILE_NAME);
        let destroyed = path.join(DESTROYED_FILE_NAME);
        if !created.exists() || destroyed.exists() {
            continue;
        }

        let metadata_path = path.join(METADATA_FILE_NAME);
        if metadata_path.exists() {
            let file = File::open(&metadata_path)?;
            active.push(serde_yaml::from_reader::<_, DeploymentMetadata>(file)?);
        } else {
            let tag = path.file_name().unwrap().to_string_lossy().to_string();
            active.push(DeploymentMetadata {
                tag,
                created_at: 0,
                regions: vec!["unknown".to_string()],
                instance_names: vec![],
            });
        }
    }

    if active.is_empty() {
        info!("no active deployments");
    } else {
        active.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        for d in &active {
            info!(
                tag = d.tag.as_str(),
                created_at = d.created_at,
                regions = ?d.regions,
                instances = d.instance_names.len(),
            );
        }
    }
    Ok(())
}
