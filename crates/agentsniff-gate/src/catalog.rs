//! Known AI-agent HTTP clients, loaded from the signed `agent_clients.json`
//! dataset plus operator-supplied `gate.custom_agents`.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::webbotauth::origin_of;

/// Agent kinds a catalog entry may declare.
pub const AGENT_KINDS: &[&str] = &[
    "cloud_browser_agent",
    "user_triggered_agent",
    "crawler",
    "other",
];

/// Provenance tiers a catalog entry may declare, most trusted first.
/// `lab_observed` means the identifiers were captured on an origin we control
/// with a per-run nonce URL, so attribution is exact.
pub const AGENT_STATUSES: &[&str] = &[
    "lab_observed",
    "operator_documented",
    "cdn_directory",
    "third_party_reported",
];

/// Catalog ids that were renamed when entries were split by surface. A
/// policy naming the old id is refused at startup with the new one, instead
/// of silently matching nothing.
pub const RENAMED_AGENT_IDS: &[(&str, &str)] = &[
    ("meta_muse", "meta_muse_browser"),
    ("xai_grok_agent", "xai_grok_bot"),
    ("openai_chatgpt_agent", "openai_chatgpt_cloud_browser"),
];

/// Longest user-agent prefix inspected. Real browser strings are well under this.
pub const MAX_USER_AGENT_BYTES: usize = 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AgentEntry {
    pub id: String,
    pub name: String,
    pub operator: String,
    pub kind: String,
    pub user_agent_tokens: Vec<String>,
    pub signature_agents: Vec<String>,
    pub operator_asns: Vec<u32>,
    pub status: String,
    pub confidence: String,
    pub notes: String,
    pub sources: Vec<String>,
    /// Other names readers know the agent by (product names, old ids).
    pub aliases: Vec<String>,
    /// `YYYY-MM-DD` the identifiers were last checked against a live source,
    /// or empty when they never were.
    pub last_confirmed: String,
}

#[derive(Debug, Clone, Default)]
pub struct AgentCatalog {
    agents: Vec<AgentEntry>,
    automation_tokens: Vec<String>,
    hosting_asns: HashMap<u32, String>,
    cdn_egress_asns: HashMap<u32, String>,
    operator_asns: HashMap<u32, usize>,
    signature_agents: HashMap<String, usize>,
    library_ja4: HashMap<String, String>,
    pub chrome_stable_major: Option<u32>,
}

/// Agent ids end up in response headers and logs, so keep them to a safe alphabet.
pub fn valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn valid_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= 64 && token.bytes().all(|c| c.is_ascii_graphic())
}

/// Case-insensitive token match on identifier boundaries, so `GPTBot` does
/// not fire inside `NotGPTBotX`. A token that starts or ends with punctuation
/// (`muse-`, `curl/`) is already delimited on that side.
pub fn contains_token(haystack: &str, token: &str) -> bool {
    let hay = haystack.to_ascii_lowercase();
    let needle = token.to_ascii_lowercase();
    let hay_bytes = hay.as_bytes();
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() {
        return false;
    }
    let check_before = needle_bytes[0].is_ascii_alphanumeric();
    let check_after = needle_bytes[needle_bytes.len() - 1].is_ascii_alphanumeric();
    hay.match_indices(needle.as_str()).any(|(start, _)| {
        let end = start + needle_bytes.len();
        let before_ok =
            !check_before || start == 0 || !hay_bytes[start - 1].is_ascii_alphanumeric();
        let after_ok =
            !check_after || end == hay_bytes.len() || !hay_bytes[end].is_ascii_alphanumeric();
        before_ok && after_ok
    })
}

impl AgentCatalog {
    /// Build from the `agent_clients` dataset value and the separately signed
    /// `tls_fingerprints` dataset.
    pub fn from_values(
        agent_clients: &serde_json::Value,
        tls_fingerprints: &serde_json::Value,
    ) -> anyhow::Result<Self> {
        let agents: Vec<AgentEntry> = match agent_clients.get("agents") {
            Some(value) => serde_json::from_value(value.clone())?,
            None => anyhow::bail!("agent_clients dataset has no agents"),
        };
        let mut catalog = Self {
            chrome_stable_major: agent_clients
                .pointer("/browser_baseline/chrome_stable_major")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()),
            ..Self::default()
        };
        for token in agent_clients
            .get("automation_user_agent_tokens")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
        {
            if !valid_token(token) {
                anyhow::bail!("invalid automation user-agent token {token:?}");
            }
            catalog.automation_tokens.push(token.to_string());
        }
        for entry in agent_clients
            .get("hosting_asns")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(asn) = entry
                .get("asn")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
            {
                let name = entry
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("hosting provider");
                catalog.hosting_asns.insert(asn, name.to_string());
            }
        }
        for entry in agent_clients
            .get("cdn_egress_asns")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(asn) = entry
                .get("asn")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
            {
                let name = entry
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("CDN");
                catalog.cdn_egress_asns.insert(asn, name.to_string());
            }
        }
        for fingerprint in tls_fingerprints
            .get("fingerprints")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let (Some(ja4), Some(library)) = (
                fingerprint.get("ja4").and_then(serde_json::Value::as_str),
                fingerprint
                    .get("library")
                    .and_then(serde_json::Value::as_str),
            ) {
                catalog
                    .library_ja4
                    .insert(ja4.to_ascii_lowercase(), library.to_string());
            }
        }
        catalog.add_agents(agents)?;
        Ok(catalog)
    }

    /// Append operator-defined agents. Ids must not collide with the catalog.
    pub fn add_agents(&mut self, entries: Vec<AgentEntry>) -> anyhow::Result<()> {
        let mut ids: HashSet<String> = self.agents.iter().map(|a| a.id.clone()).collect();
        for mut entry in entries {
            if !valid_agent_id(&entry.id) {
                anyhow::bail!("agent id {:?} must be 1-64 chars of [a-z0-9_]", entry.id);
            }
            if !ids.insert(entry.id.clone()) {
                anyhow::bail!("duplicate agent id {}", entry.id);
            }
            if !AGENT_KINDS.contains(&entry.kind.as_str()) {
                anyhow::bail!(
                    "agent {} has unknown kind {:?} (expected one of {})",
                    entry.id,
                    entry.kind,
                    AGENT_KINDS.join(", ")
                );
            }
            if !entry.status.is_empty() && !AGENT_STATUSES.contains(&entry.status.as_str()) {
                anyhow::bail!(
                    "agent {} has unknown status {:?} (expected one of {})",
                    entry.id,
                    entry.status,
                    AGENT_STATUSES.join(", ")
                );
            }
            if !entry.last_confirmed.is_empty()
                && chrono::NaiveDate::parse_from_str(&entry.last_confirmed, "%Y-%m-%d").is_err()
            {
                anyhow::bail!(
                    "agent {} has last_confirmed {:?}, expected YYYY-MM-DD",
                    entry.id,
                    entry.last_confirmed
                );
            }
            if let Some(token) = entry.user_agent_tokens.iter().find(|t| !valid_token(t)) {
                anyhow::bail!("agent {} has invalid user-agent token {token:?}", entry.id);
            }
            if entry.name.is_empty() {
                entry.name = entry.id.clone();
            }
            let index = self.agents.len();
            for url in &entry.signature_agents {
                let origin = origin_of(url).ok_or_else(|| {
                    anyhow::anyhow!("agent {} has invalid signature agent {url:?}", entry.id)
                })?;
                self.signature_agents.insert(origin, index);
            }
            for asn in &entry.operator_asns {
                self.operator_asns.insert(*asn, index);
            }
            self.agents.push(entry);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.agents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&AgentEntry> {
        self.agents.iter().find(|a| a.id == id)
    }

    /// First catalog agent whose user-agent token appears in `user_agent`.
    pub fn match_user_agent(&self, user_agent: &str) -> Option<(&AgentEntry, &str)> {
        if user_agent.is_empty() {
            return None;
        }
        self.agents.iter().find_map(|agent| {
            agent
                .user_agent_tokens
                .iter()
                .find(|token| contains_token(user_agent, token))
                .map(|token| (agent, token.as_str()))
        })
    }

    pub fn match_signature_agent(&self, url: &str) -> Option<&AgentEntry> {
        let origin = origin_of(url)?;
        self.signature_agents
            .get(&origin)
            .map(|index| &self.agents[*index])
    }

    pub fn automation_token(&self, user_agent: &str) -> Option<&str> {
        self.automation_tokens
            .iter()
            .find(|token| contains_token(user_agent, token))
            .map(String::as_str)
    }

    pub fn hosting_asn(&self, asn: u32) -> Option<&str> {
        self.hosting_asns.get(&asn).map(String::as_str)
    }

    /// CDN egress network that cloud browser agents exit from (Cloudflare, Fastly).
    pub fn cdn_egress_asn(&self, asn: u32) -> Option<&str> {
        self.cdn_egress_asns.get(&asn).map(String::as_str)
    }

    pub fn operator_asn_agent(&self, asn: u32) -> Option<&AgentEntry> {
        self.operator_asns
            .get(&asn)
            .map(|index| &self.agents[*index])
    }

    pub fn library_for_ja4(&self, ja4: &str) -> Option<&str> {
        self.library_ja4
            .get(&ja4.trim().to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// True for user agents that claim to be a mainstream browser.
pub fn is_browser_like(user_agent: &str) -> bool {
    user_agent.starts_with("Mozilla/5.0")
        && ["Chrome/", "Safari/", "Firefox/", "Edg/"]
            .iter()
            .any(|marker| user_agent.contains(marker))
}

/// True for user agents that claim Chrome on desktop Linux: the profile the
/// ChatGPT cloud browser, Muse, and Grok Bot present. Android Chrome and
/// ChromeOS carry their own platform tokens and are excluded.
pub fn is_desktop_linux_chrome(user_agent: &str) -> bool {
    chrome_major(user_agent).is_some()
        && user_agent.contains("Linux")
        && !user_agent.contains("Android")
}

/// Chrome major version from a user agent, if it claims Chrome.
pub fn chrome_major(user_agent: &str) -> Option<u32> {
    let bytes = user_agent.as_bytes();
    user_agent
        .match_indices("Chrome/")
        .find_map(|(start, marker)| {
            if start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
                // HeadlessChrome/ is reported separately as an automation token.
                return None;
            }
            let digits: String = user_agent[start + marker.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .take(4)
                .collect();
            digits.parse().ok()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_boundaries() {
        assert!(contains_token(
            "Mozilla/5.0 (compatible; GPTBot/1.2)",
            "GPTBot"
        ));
        assert!(!contains_token("NotGPTBotX/1.0", "GPTBot"));
        assert!(contains_token("muse-agent/1.0", "muse-"));
        assert!(!contains_token("amuse-park/1.0", "muse-"));
        assert!(contains_token("curl/8.5.0", "curl/"));
        assert!(contains_token("Go-http-client/1.1", "go-http-client"));
    }

    #[test]
    fn chrome_versions() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36";
        assert_eq!(chrome_major(ua), Some(139));
        assert!(is_browser_like(ua));
        assert_eq!(chrome_major("Mozilla/5.0 HeadlessChrome/120.0.0.0"), None);
        assert!(!is_browser_like("Go-http-client/1.1"));
    }

    #[test]
    fn catalog_rejects_unknown_status_and_bad_dates() {
        fn entry(status: &str, last_confirmed: &str) -> AgentEntry {
            AgentEntry {
                id: "x_agent".into(),
                kind: "crawler".into(),
                status: status.into(),
                last_confirmed: last_confirmed.into(),
                ..AgentEntry::default()
            }
        }
        let mut ok = AgentCatalog::default();
        ok.add_agents(vec![entry("lab_observed", "2026-11-04")])
            .unwrap();
        let mut blank = AgentCatalog::default();
        blank.add_agents(vec![entry("", "")]).unwrap();
        let mut bad_status = AgentCatalog::default();
        assert!(bad_status.add_agents(vec![entry("rumor", "")]).is_err());
        let mut bad_date = AgentCatalog::default();
        assert!(bad_date
            .add_agents(vec![entry("cdn_directory", "yesterday")])
            .is_err());
    }

    #[test]
    fn desktop_linux_chrome() {
        assert!(is_desktop_linux_chrome(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
        ));
        assert!(!is_desktop_linux_chrome(
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36"
        ));
        assert!(!is_desktop_linux_chrome(
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
        ));
        assert!(!is_desktop_linux_chrome(
            "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"
        ));
    }
}
