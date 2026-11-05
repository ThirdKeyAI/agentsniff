//! Tripwire paths: URLs a person never requests because they are planted
//! only where machines read (HTML comments, hidden links, JSON-LD,
//! `robots.txt` `Disallow`). Any client that asks for one is denied and
//! held in the rate tracker's penalty box.

use serde::{Deserialize, Serialize};

use super::GateAction;

const MAX_PATHS: usize = 1000;
const MAX_PATH_BYTES: usize = 256;
const MAX_PENALTY_SECS: u64 = 7 * 86_400;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GateTripwireConfig {
    /// Paths to trap. An entry ending in `/` matches every path under it;
    /// any other entry matches the request path exactly. Query strings are
    /// never compared, and no decoding is applied on either side.
    pub paths: Vec<String>,
    /// Action for the request that hits a tripwire: challenge or block.
    pub action: GateAction,
    /// How long the client's rate key stays in the penalty box afterwards.
    pub penalty_secs: u64,
}

impl Default for GateTripwireConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            action: GateAction::Block,
            penalty_secs: 3600,
        }
    }
}

impl GateTripwireConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.paths.len() > MAX_PATHS {
            anyhow::bail!("gate.tripwires.paths may list at most {MAX_PATHS} paths");
        }
        for path in &self.paths {
            if !path.starts_with('/') {
                anyhow::bail!("gate.tripwires path {path:?} must start with /");
            }
            if path.len() > MAX_PATH_BYTES {
                anyhow::bail!("gate.tripwires path {path:?} is longer than {MAX_PATH_BYTES} bytes");
            }
            if !path.bytes().all(|b| b.is_ascii_graphic()) {
                anyhow::bail!(
                    "gate.tripwires path {path:?} must be printable ASCII without spaces"
                );
            }
        }
        if self.action == GateAction::Allow {
            anyhow::bail!("gate.tripwires.action must be challenge or block");
        }
        if self.penalty_secs > MAX_PENALTY_SECS {
            anyhow::bail!("gate.tripwires.penalty_secs must be at most {MAX_PENALTY_SECS}");
        }
        Ok(())
    }

    /// The configured entry `path` trips, if any.
    pub fn matches(&self, path: &str) -> Option<&str> {
        self.paths
            .iter()
            .find(|p| {
                if p.ends_with('/') {
                    path.starts_with(p.as_str())
                } else {
                    path == p.as_str()
                }
            })
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(paths: &[&str]) -> GateTripwireConfig {
        GateTripwireConfig {
            paths: paths.iter().map(|p| p.to_string()).collect(),
            ..GateTripwireConfig::default()
        }
    }

    #[test]
    fn tripwire_match_is_exact_or_prefix() {
        let c = config(&["/.internal/export.csv", "/private-area/"]);
        assert_eq!(
            c.matches("/.internal/export.csv"),
            Some("/.internal/export.csv")
        );
        assert_eq!(c.matches("/.internal/export.csv/"), None);
        assert_eq!(c.matches("/%2einternal/export.csv"), None);
        assert_eq!(c.matches("/private-area/anything"), Some("/private-area/"));
        assert_eq!(c.matches("/private-area"), None);
        assert_eq!(c.matches("/accounts"), None);
    }

    #[test]
    fn tripwire_config_is_validated() {
        assert!(config(&[]).validate().is_ok());
        assert!(config(&["/ok"]).validate().is_ok());
        assert!(config(&["no-slash"]).validate().is_err());
        assert!(config(&["/has space"]).validate().is_err());
        assert!(config(&[&format!("/{}", "a".repeat(300))])
            .validate()
            .is_err());
        let mut allow = config(&["/ok"]);
        allow.action = GateAction::Allow;
        assert!(allow.validate().is_err());
        let mut long = config(&["/ok"]);
        long.penalty_secs = 8 * 86_400;
        assert!(long.validate().is_err());
    }
}
