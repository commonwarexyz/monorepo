//! Analyze dependencies between modules.

mod cargo;

use crate::parser::Workspace;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalyzeError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// All dependencies in the workspace.
#[derive(Debug, Clone)]
pub struct Dependencies {
    /// Map from crate name to its dependencies
    pub crate_deps: HashMap<String, Vec<String>>,
}

/// Analyze the workspace to extract all dependencies.
pub fn analyze(workspace: &Workspace) -> Result<Dependencies, AnalyzeError> {
    let mut crate_deps = HashMap::new();

    for (crate_name, krate) in &workspace.crates {
        crate_deps.insert(crate_name.clone(), krate.dependencies.clone());
    }

    Ok(Dependencies { crate_deps })
}
