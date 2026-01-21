//! `list` subcommand for `ec2`

use crate::aws::{
    deployer_directory, Metadata, Error, CREATED_FILE_NAME, DESTROYED_FILE_NAME,
    METADATA_FILE_NAME,
};
use std::fs::{self, File};
use tracing::info;

/// Lists all active deployments (created but not destroyed)
pub fn list() -> Result<(), Error> {
    // Check if deployer directory exists
    let deployer_dir = deployer_directory(None);
    if !deployer_dir.exists() {
        info!("no deployments found");
        return Ok(());
    }

    // Collect active deployments
    let mut active = Vec::new();
    for entry in fs::read_dir(&deployer_dir)? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }

        // Skip incomplete or destroyed deployments
        let created = path.join(CREATED_FILE_NAME);
        let destroyed = path.join(DESTROYED_FILE_NAME);
        if !created.exists() || destroyed.exists() {
            continue;
        }

        // Load metadata if available, otherwise use directory name as tag
        let metadata_path = path.join(METADATA_FILE_NAME);
        if metadata_path.exists() {
            let file = File::open(&metadata_path)?;
            active.push(serde_yaml::from_reader::<_, Metadata>(file)?);
        } else {
            let Some(tag) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let tag = tag.to_string();
            active.push(Metadata {
                tag,
                created_at: 0,
                regions: vec!["unknown".to_string()],
                instance_names: vec![],
            });
        }
    }

    // Display results sorted by creation time (newest first)
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
