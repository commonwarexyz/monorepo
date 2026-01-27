//! `list` subcommand for `ec2`

use crate::aws::{deployer_directory, Error, Metadata, DESTROYED_FILE_NAME, METADATA_FILE_NAME};
use chrono::{DateTime, Local, Utc};
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

        // Skip destroyed deployments
        let destroyed = path.join(DESTROYED_FILE_NAME);
        if destroyed.exists() {
            continue;
        }

        // Load metadata (skip if missing or malformed)
        let metadata_path = path.join(METADATA_FILE_NAME);
        let Ok(file) = File::open(&metadata_path) else {
            continue;
        };
        let Ok(metadata) = serde_yaml::from_reader::<_, Metadata>(file) else {
            continue;
        };
        active.push(metadata);
    }

    // Display results sorted by creation time (newest first)
    if active.is_empty() {
        info!("no active deployments");
    } else {
        active.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        for d in &active {
            let created_at = DateTime::<Utc>::from_timestamp(d.created_at as i64, 0).map(|dt| {
                dt.with_timezone(&Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string()
            });
            info!(
                tag = d.tag.as_str(),
                created_at,
                regions = ?d.regions,
                instances = d.instance_count,
            );
        }
    }
    Ok(())
}
