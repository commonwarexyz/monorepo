//! Database-specific modules for the sync example.

pub mod any;
pub mod immutable;

/// Database type to sync.
#[derive(Debug, Clone, Copy)]
pub enum DatabaseType {
    Any,
    Immutable,
}

impl std::str::FromStr for DatabaseType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "any" => Ok(DatabaseType::Any),
            "immutable" => Ok(DatabaseType::Immutable),
            _ => Err(format!(
                "Invalid database type: '{}'. Must be 'any' or 'immutable'",
                s
            )),
        }
    }
}

impl DatabaseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseType::Any => "any",
            DatabaseType::Immutable => "immutable",
        }
    }
}
