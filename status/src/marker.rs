use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

static MARKER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"//!\s*@(beta|gamma|lts)\("([^"]+)"\)"#).unwrap());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    Alpha,
    Beta,
    Gamma,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Markers {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gamma: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lts: Option<String>,
}

impl Markers {
    pub const fn is_empty(&self) -> bool {
        self.beta.is_none() && self.gamma.is_none() && self.lts.is_none()
    }

    pub const fn is_lts(&self) -> bool {
        self.lts.is_some()
    }

    pub const fn current_stage(&self) -> Stage {
        if self.gamma.is_some() {
            Stage::Gamma
        } else if self.beta.is_some() {
            Stage::Beta
        } else {
            Stage::Alpha
        }
    }
}

pub fn parse_markers(content: &str) -> Markers {
    let mut markers = Markers::default();

    for cap in MARKER_PATTERN.captures_iter(content) {
        let marker_type = &cap[1];
        let version = cap[2].to_string();

        match marker_type {
            "beta" => markers.beta = Some(version),
            "gamma" => markers.gamma = Some(version),
            "lts" => markers.lts = Some(version),
            _ => {}
        }
    }

    markers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_marker() {
        let content = r#"//! @beta("0.1.0")"#;
        let markers = parse_markers(content);
        assert_eq!(markers.beta, Some("0.1.0".to_string()));
        assert_eq!(markers.gamma, None);
        assert_eq!(markers.lts, None);
    }

    #[test]
    fn test_parse_multiple_markers() {
        let content = r#"
//! @beta("0.1.0")
//! @gamma("0.2.0")
//! @lts("0.3.0")
"#;
        let markers = parse_markers(content);
        assert_eq!(markers.beta, Some("0.1.0".to_string()));
        assert_eq!(markers.gamma, Some("0.2.0".to_string()));
        assert_eq!(markers.lts, Some("0.3.0".to_string()));
    }

    #[test]
    fn test_current_stage() {
        let alpha = Markers::default();
        assert_eq!(alpha.current_stage(), Stage::Alpha);

        let beta = Markers {
            beta: Some("0.1.0".to_string()),
            ..Default::default()
        };
        assert_eq!(beta.current_stage(), Stage::Beta);

        let gamma = Markers {
            beta: Some("0.1.0".to_string()),
            gamma: Some("0.2.0".to_string()),
            ..Default::default()
        };
        assert_eq!(gamma.current_stage(), Stage::Gamma);
    }
}
