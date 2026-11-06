//! Inbound AI-agent gate: per-request allow / challenge / block decisions for
//! a reverse proxy's forward-auth hook (nginx `auth_request`, Envoy
//! `ext_authz`, Traefik ForwardAuth, Caddy `forward_auth`).
//!
//! The scanner looks outward from a network; the gate looks at clients coming
//! in. It reuses AgentSniff's split between presence evidence and verified
//! identity: user-agent tokens and `Signature-Agent` claims identify which
//! agent a request *says* it is, only a Web Bot Auth signature checked against
//! an operator-pinned key says who it *is*, and behavior signals catch agents
//! that do not identify themselves at all.

pub mod catalog;
pub mod cidr;
pub mod rate;
pub mod sfv;
pub mod tripwire;
pub mod webbotauth;

pub use cidr::{canonical_ip, IpCidr};
pub use webbotauth::origin_of;

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::HeaderMap;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use agentsniff_signatures::{SignatureData, VerificationStatus};
use catalog::{AgentCatalog, AgentEntry, MAX_USER_AGENT_BYTES};
use rate::{address_key, GateRateConfig, RateKey, RateTracker, RateVerdict};
use tripwire::GateTripwireConfig;
use webbotauth::{SignedRequest, WebBotAuthConfig, WebBotAuthOutcome, WebBotAuthVerifier};

/// Attribution for a request that carries a Web Bot Auth claim, or a
/// `Signature-Agent` header, naming no catalog agent. It can be given its own
/// entry in `gate.agent_actions`.
pub const UNIDENTIFIED_SIGNED_AGENT: &str = "unidentified_signed_agent";

/// `localhost` or a loopback IP literal: the hosts that may listen without a token.
pub fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateAction {
    Allow,
    Challenge,
    Block,
}

impl GateAction {
    pub fn as_str(self) -> &'static str {
        match self {
            GateAction::Allow => "allow",
            GateAction::Challenge => "challenge",
            GateAction::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateMode {
    /// Decide and log, but always answer allow. The default for rollout.
    Monitor,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GateConfig {
    pub mode: GateMode,
    pub host: String,
    pub port: u16,
    /// Shared secret the proxy sends in `X-AgentSniff-Gate-Token`. Required
    /// for a non-loopback listener; prefer `AGENTSNIFF_GATE_TOKEN`.
    pub token: String,
    /// Peers whose forwarded headers (client IP, host, URI, JA4, ASN) are trusted.
    pub trusted_proxies: Vec<String>,
    /// Header carrying the client IP: `x-forwarded-for` (walked right to
    /// left past trusted proxies) or a single-value header such as `x-real-ip`.
    pub client_ip_header: String,
    /// Header the edge sets to the client's JA4 TLS fingerprint. Empty disables.
    pub ja4_header: String,
    /// Header the edge sets to the client's origin ASN. Empty disables.
    pub asn_header: String,

    /// Action for any request attributed to a catalog agent.
    pub default_agent_action: GateAction,
    /// Per-kind overrides (`cloud_browser_agent`, `user_triggered_agent`, `crawler`).
    pub kind_actions: HashMap<String, GateAction>,
    /// Per-agent-id overrides; these win over kind overrides.
    pub agent_actions: HashMap<String, GateAction>,
    /// Agents allowed through when, and only when, their Web Bot Auth
    /// signature verifies against a pinned key.
    pub allow_verified_agents: Vec<String>,
    pub custom_agents: Vec<AgentEntry>,

    /// Behavior score (0-1, noisy-OR) at which unattributed traffic is challenged.
    pub challenge_threshold: f64,
    /// Behavior score at which unattributed traffic is blocked.
    pub block_threshold: f64,
    /// Chrome majors behind the catalog baseline before a UA counts as stale.
    pub stale_browser_lag: u32,
    pub rate: GateRateConfig,
    /// Paths only machines find; a client that requests one is denied and
    /// held in the penalty box.
    pub tripwires: GateTripwireConfig,
    pub web_bot_auth: WebBotAuthConfig,

    pub challenge_status: u16,
    pub block_status: u16,
    /// Decision log destination: empty or `-` for stdout, `off`, or a file path.
    pub decision_log: String,
    /// Also log allowed requests (verbose).
    pub log_allows: bool,
    /// Send score, agent, assurance and reason headers on challenge and block
    /// responses too. Most proxies relay a denial's headers to the client,
    /// which tells an evader what to change, so this is off by default; allow
    /// responses always carry them for the upstream application.
    pub deny_details: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            mode: GateMode::Monitor,
            host: "127.0.0.1".into(),
            port: 9091,
            token: String::new(),
            trusted_proxies: vec!["127.0.0.1/32".into(), "::1/128".into()],
            client_ip_header: "x-forwarded-for".into(),
            ja4_header: "x-ja4".into(),
            asn_header: "x-asn".into(),
            default_agent_action: GateAction::Block,
            kind_actions: HashMap::new(),
            agent_actions: HashMap::new(),
            allow_verified_agents: Vec::new(),
            custom_agents: Vec::new(),
            challenge_threshold: 0.5,
            block_threshold: 0.8,
            stale_browser_lag: 6,
            rate: GateRateConfig::default(),
            tripwires: GateTripwireConfig::default(),
            web_bot_auth: WebBotAuthConfig::default(),
            challenge_status: 401,
            block_status: 403,
            decision_log: String::new(),
            log_allows: false,
            deny_details: false,
        }
    }
}

impl GateConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.token.is_empty() && self.token.len() < 32 {
            anyhow::bail!("gate.token must contain at least 32 bytes");
        }
        let loopback = is_loopback_host(&self.host);
        if !loopback && self.token.is_empty() {
            anyhow::bail!(
                "refusing to bind the gate to {} without AGENTSNIFF_GATE_TOKEN",
                self.host
            );
        }
        if !(0.0 < self.challenge_threshold
            && self.challenge_threshold <= self.block_threshold
            && self.block_threshold <= 1.0)
        {
            anyhow::bail!(
                "gate thresholds must satisfy 0 < challenge_threshold <= block_threshold <= 1"
            );
        }
        for (name, status) in [
            ("challenge_status", self.challenge_status),
            ("block_status", self.block_status),
        ] {
            if !(400..500).contains(&status) {
                anyhow::bail!("gate.{name} must be a 4xx status, got {status}");
            }
        }
        for proxy in &self.trusted_proxies {
            IpCidr::parse(proxy)?;
        }
        self.rate.validate()?;
        self.tripwires.validate()?;
        self.web_bot_auth.validate()?;
        Ok(())
    }
}

/// How an attribution was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Assurance {
    /// Web Bot Auth signature verified against an operator-pinned key.
    TrustedVerified,
    /// The request names the agent (user agent or Signature-Agent) without proof.
    SelfDeclared,
    /// Inferred from behavior or origin only.
    Suspected,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AgentAttribution {
    pub id: String,
    pub name: String,
    pub operator: String,
    pub kind: String,
    pub assurance: Assurance,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GateSignal {
    pub id: &'static str,
    pub weight: f64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GateDecision {
    pub request_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub mode: GateMode,
    /// What the proxy is told to do.
    pub action: GateAction,
    /// What enforce mode would do; differs from `action` only in monitor mode.
    pub would_action: GateAction,
    pub score: f64,
    pub agent: Option<AgentAttribution>,
    pub signals: Vec<GateSignal>,
    pub client_ip: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub user_agent: String,
}

/// The original request, as reconstructed from the forward-auth call.
pub struct RequestFacts {
    pub client_ip: IpAddr,
    pub method: String,
    pub scheme: String,
    pub authority: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub ja4: Option<String>,
    pub asn: Option<u32>,
    /// The resolved client address is one of the trusted proxies: the proxy
    /// did not forward the client's address. Rate limits are skipped rather
    /// than applied to every client behind that proxy at once.
    pub client_ip_is_proxy: bool,
}

pub struct GateEngine {
    config: GateConfig,
    catalog: AgentCatalog,
    verifier: WebBotAuthVerifier,
    rate: RateTracker,
}

/// Truncate to at most `max` bytes on a char boundary.
pub fn truncate(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn noisy_or(signals: &[GateSignal]) -> f64 {
    1.0 - signals
        .iter()
        .map(|s| 1.0 - s.weight.clamp(0.0, 1.0))
        .product::<f64>()
}

impl GateEngine {
    pub fn new(config: GateConfig, mut catalog: AgentCatalog) -> anyhow::Result<Self> {
        config.validate()?;
        catalog.add_agents(config.custom_agents.clone())?;
        let verifier = WebBotAuthVerifier::new(config.web_bot_auth.clone())?;
        let pinned_ids: Vec<&str> = config
            .web_bot_auth
            .trusted_keys
            .iter()
            .map(|k| k.agent_id.as_str())
            .collect();
        if catalog.get(UNIDENTIFIED_SIGNED_AGENT).is_some() {
            anyhow::bail!("agent id {UNIDENTIFIED_SIGNED_AGENT} is reserved");
        }
        for id in config
            .agent_actions
            .keys()
            .chain(config.allow_verified_agents.iter())
            .chain(config.web_bot_auth.trusted_keys.iter().map(|k| &k.agent_id))
            .chain(config.custom_agents.iter().map(|a| &a.id))
        {
            if let Some((old, new)) = catalog::RENAMED_AGENT_IDS.iter().find(|(old, _)| old == id) {
                anyhow::bail!("gate policy names agent id {old:?}, which is now {new:?}");
            }
        }
        for id in config
            .agent_actions
            .keys()
            .chain(config.allow_verified_agents.iter())
        {
            let reserved = id == UNIDENTIFIED_SIGNED_AGENT && config.agent_actions.contains_key(id);
            if !reserved && catalog.get(id).is_none() && !pinned_ids.contains(&id.as_str()) {
                anyhow::bail!("gate policy names unknown agent id {id:?}");
            }
        }
        for id in &config.allow_verified_agents {
            if !pinned_ids.contains(&id.as_str()) {
                anyhow::bail!(
                    "allow_verified_agents lists {id:?} but web_bot_auth.trusted_keys has no key for it"
                );
            }
        }
        for kind in config.kind_actions.keys() {
            if !catalog::AGENT_KINDS.contains(&kind.as_str()) {
                anyhow::bail!("gate.kind_actions has unknown kind {kind:?}");
            }
        }
        let rate = RateTracker::new(config.rate.clone());
        Ok(Self {
            config,
            catalog,
            verifier,
            rate,
        })
    }

    /// Load the catalog from signed datasets, refusing unverified data.
    pub fn from_signatures(config: GateConfig, signatures: &SignatureData) -> anyhow::Result<Self> {
        for dataset in ["agent_clients", "tls_fingerprints"] {
            let status = signatures.verification_status.get(dataset).copied();
            if status != Some(VerificationStatus::Verified) {
                anyhow::bail!(
                    "the {dataset} dataset is not verified ({status:?}); refusing to start the gate. \
                     Run `agentsniff update-signatures`, or re-sign with scripts/resign_signatures.py"
                );
            }
        }
        let catalog =
            AgentCatalog::from_values(&signatures.agent_clients, &signatures.tls_fingerprints)?;
        Self::new(config, catalog)
    }

    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    pub fn catalog(&self) -> &AgentCatalog {
        &self.catalog
    }

    pub fn trusted_key_count(&self) -> usize {
        self.verifier.trusted_key_count()
    }

    /// The action a catalog agent id resolves to: `agent_actions`, then the
    /// kind's `kind_actions` (or `other`), then `default_agent_action`.
    pub fn agent_policy(&self, id: &str) -> GateAction {
        self.policy_for(self.catalog.get(id), id)
    }

    pub fn evaluate(&self, facts: &RequestFacts) -> GateDecision {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.evaluate_at(facts, now, Instant::now())
    }

    fn policy_for(&self, entry: Option<&AgentEntry>, id: &str) -> GateAction {
        if let Some(action) = self.config.agent_actions.get(id) {
            return *action;
        }
        let kind = entry.map_or("other", |e| e.kind.as_str());
        if let Some(action) = self.config.kind_actions.get(kind) {
            return *action;
        }
        self.config.default_agent_action
    }

    fn attribution(&self, id: &str, assurance: Assurance) -> AgentAttribution {
        match self.catalog.get(id) {
            Some(entry) => AgentAttribution {
                id: entry.id.clone(),
                name: entry.name.clone(),
                operator: entry.operator.clone(),
                kind: entry.kind.clone(),
                assurance,
            },
            None => AgentAttribution {
                id: id.to_string(),
                name: id.to_string(),
                operator: String::new(),
                kind: "other".into(),
                assurance,
            },
        }
    }

    pub fn evaluate_at(&self, facts: &RequestFacts, now_unix: i64, now: Instant) -> GateDecision {
        let user_agent = facts
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|ua| truncate(ua.trim(), MAX_USER_AGENT_BYTES))
            .unwrap_or("");
        let mut signals: Vec<GateSignal> = Vec::new();
        let mut agent: Option<AgentAttribution> = None;

        // 1. Velocity applies to everyone, verified agents included.
        let mut rate_action = None;
        let rate_key = if self.config.rate.enabled && !facts.client_ip_is_proxy {
            let address = address_key(facts.client_ip, self.config.rate.ipv6_prefix);
            Some(match self.config.rate.key {
                RateKey::Ip => address,
                RateKey::IpUserAgent => format!("{address}\u{0}{}", truncate(user_agent, 256)),
            })
        } else {
            None
        };
        if self.config.rate.enabled && facts.client_ip_is_proxy {
            signals.push(GateSignal {
                id: "client_ip_unresolved",
                weight: 0.0,
                detail: "client address resolved to a trusted proxy, so rate limits were skipped; \
                         set the client IP header at the proxy"
                    .into(),
            });
        } else if let Some(key) = rate_key.as_deref() {
            match self.rate.observe(key, now) {
                RateVerdict::Within { .. } => {}
                RateVerdict::Burst { rate } => {
                    signals.push(GateSignal {
                        id: "burst_velocity",
                        weight: 1.0,
                        detail: format!(
                            "~{rate:.0} requests in {}ms (limit {})",
                            self.config.rate.burst_window_ms, self.config.rate.burst_limit
                        ),
                    });
                    rate_action = Some(self.config.rate.action);
                }
                RateVerdict::Sustained { rate } => {
                    signals.push(GateSignal {
                        id: "sustained_rate",
                        weight: 1.0,
                        detail: format!(
                            "~{rate:.0} requests in {}s (limit {})",
                            self.config.rate.sustained_window_secs,
                            self.config.rate.sustained_limit
                        ),
                    });
                    rate_action = Some(self.config.rate.action);
                }
                RateVerdict::Penalized { remaining_secs } => {
                    signals.push(GateSignal {
                        id: "rate_penalty",
                        weight: 1.0,
                        detail: format!("rate penalty, {remaining_secs}s remaining"),
                    });
                    rate_action = Some(self.config.rate.action);
                }
            }
        }

        // 1b. Tripwires: paths only machines find. Deny this request and hold
        // the client, verified or not, so the sequence shows in the log.
        if let Some(path) = self.config.tripwires.matches(&facts.path) {
            signals.push(GateSignal {
                id: "tripwire_hit",
                weight: 1.0,
                detail: format!(
                    "requested tripwire path {}; ja4={} asn={}",
                    truncate(path, 128),
                    facts.ja4.as_deref().map_or("-", |j| truncate(j, 64)),
                    facts
                        .asn
                        .map_or_else(|| "-".to_string(), |a| format!("AS{a}"))
                ),
            });
            let action = self.config.tripwires.action;
            rate_action = Some(rate_action.map_or(action, |r: GateAction| r.max(action)));
            if let Some(key) = rate_key.as_deref() {
                self.rate.penalize(
                    key,
                    now,
                    Duration::from_secs(self.config.tripwires.penalty_secs),
                );
            }
        }

        // 2. Web Bot Auth: the only path to verified identity.
        let signed = SignedRequest {
            method: &facts.method,
            scheme: &facts.scheme,
            authority: &facts.authority,
            path: &facts.path,
            query: facts.query.as_deref(),
            headers: &facts.headers,
        };
        let mut agent_action = None;
        match self.verifier.verify(&signed, now_unix) {
            WebBotAuthOutcome::Verified {
                agent_id, keyid, ..
            } => {
                signals.push(GateSignal {
                    id: "web_bot_auth_verified",
                    weight: 0.0,
                    detail: format!("signature verified for keyid {}", truncate(&keyid, 64)),
                });
                let action = if self.config.allow_verified_agents.contains(&agent_id) {
                    GateAction::Allow
                } else {
                    self.policy_for(self.catalog.get(&agent_id), &agent_id)
                };
                agent = Some(self.attribution(&agent_id, Assurance::TrustedVerified));
                agent_action = Some(action);
            }
            WebBotAuthOutcome::Unverified {
                reason,
                signature_agent,
                ..
            } => {
                signals.push(GateSignal {
                    id: "web_bot_auth_unverified",
                    weight: 0.0,
                    detail: format!("signed agent request did not verify: {reason}"),
                });
                let entry = signature_agent
                    .as_deref()
                    .and_then(|url| self.catalog.match_signature_agent(url));
                let id = entry.map_or(UNIDENTIFIED_SIGNED_AGENT, |e| e.id.as_str());
                agent = Some(self.attribution(id, Assurance::SelfDeclared));
                agent_action = Some(self.policy_for(entry, id));
            }
            WebBotAuthOutcome::Absent => {
                // Signature-Agent with no signature still says "I am an agent".
                if let Some(url) = webbotauth::declared_signature_agent(&facts.headers) {
                    signals.push(GateSignal {
                        id: "unsigned_signature_agent",
                        weight: 0.0,
                        detail: format!(
                            "Signature-Agent {} without a Web Bot Auth signature",
                            truncate(&url, 128)
                        ),
                    });
                    let entry = self.catalog.match_signature_agent(&url);
                    let id = entry.map_or(UNIDENTIFIED_SIGNED_AGENT, |e| e.id.as_str());
                    agent = Some(self.attribution(id, Assurance::SelfDeclared));
                    agent_action = Some(self.policy_for(entry, id));
                }
            }
        }

        // 3. Self-declared user agents. An unverified claim does not switch
        // this off: the stricter of the two policies applies, so an unsigned
        // Signature-Agent cannot lift a block on the agent the user agent names.
        let verified = agent
            .as_ref()
            .is_some_and(|a| a.assurance == Assurance::TrustedVerified);
        if !verified {
            if let Some((entry, token)) = self.catalog.match_user_agent(user_agent) {
                signals.push(GateSignal {
                    id: "known_agent_user_agent",
                    weight: 0.0,
                    detail: format!("user agent contains {token}"),
                });
                let ua_action = self.policy_for(Some(entry), &entry.id);
                agent_action = Some(agent_action.map_or(ua_action, |a| a.max(ua_action)));
                if agent
                    .as_ref()
                    .is_none_or(|a| a.id == UNIDENTIFIED_SIGNED_AGENT)
                {
                    agent = Some(self.attribution(&entry.id, Assurance::SelfDeclared));
                }
            }
        }

        // 4. Behavior and origin, for everything short of verified identity.
        // A claim cannot switch these checks off.
        let mut heuristic: Vec<GateSignal> = Vec::new();
        if !verified {
            let mut suspected = None;
            self.behavior_signals(facts, user_agent, &mut heuristic, &mut suspected);
            if agent.is_none() {
                agent = suspected;
            }
        }
        let score = noisy_or(&heuristic);
        signals.extend(heuristic);

        let score_action = if score >= self.config.block_threshold {
            GateAction::Block
        } else if score >= self.config.challenge_threshold {
            GateAction::Challenge
        } else {
            GateAction::Allow
        };
        // A verified agent is decided by policy. A claimed agent gets the
        // stricter of its policy and the behavior score, so naming an agent
        // never softens an outcome. A rate violation only makes it stricter.
        let base = match agent_action {
            Some(action) if verified => action,
            Some(action) => action.max(score_action),
            None => score_action,
        };
        let would_action = rate_action.map_or(base, |r| r.max(base));
        let action = match self.config.mode {
            GateMode::Enforce => would_action,
            GateMode::Monitor => GateAction::Allow,
        };

        GateDecision {
            request_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            mode: self.config.mode,
            action,
            would_action,
            score: (score * 1000.0).round() / 1000.0,
            agent,
            signals,
            client_ip: facts.client_ip.to_string(),
            method: truncate(&facts.method, 16).to_string(),
            host: truncate(&facts.authority, 255).to_string(),
            path: truncate(&facts.path, 256).to_string(),
            user_agent: truncate(user_agent, 256).to_string(),
        }
    }

    fn behavior_signals(
        &self,
        facts: &RequestFacts,
        user_agent: &str,
        out: &mut Vec<GateSignal>,
        agent: &mut Option<AgentAttribution>,
    ) {
        let browser_like = catalog::is_browser_like(user_agent);
        if user_agent.is_empty() {
            out.push(GateSignal {
                id: "missing_user_agent",
                weight: 0.5,
                detail: "no User-Agent header".into(),
            });
        } else if let Some(token) = self.catalog.automation_token(user_agent) {
            out.push(GateSignal {
                id: "automation_client",
                weight: 0.5,
                detail: format!("user agent contains {token}"),
            });
        }

        if browser_like {
            let has_language = facts.headers.contains_key("accept-language");
            let has_fetch_metadata = facts.headers.contains_key("sec-fetch-mode")
                || facts.headers.contains_key("sec-fetch-site");
            if !has_language && !has_fetch_metadata {
                out.push(GateSignal {
                    id: "browser_ua_without_browser_headers",
                    weight: 0.5,
                    detail: "claims a browser but sends neither Accept-Language nor Sec-Fetch-*"
                        .into(),
                });
            } else if !has_language {
                out.push(GateSignal {
                    id: "missing_accept_language",
                    weight: 0.25,
                    detail: "browser user agent without Accept-Language".into(),
                });
            }

            if let (Some(major), Some(baseline)) = (
                catalog::chrome_major(user_agent),
                self.catalog.chrome_stable_major,
            ) {
                let lag = baseline.saturating_sub(major);
                if self.config.stale_browser_lag > 0 && lag >= self.config.stale_browser_lag {
                    let very = lag >= self.config.stale_browser_lag * 2;
                    out.push(GateSignal {
                        id: "stale_browser_version",
                        weight: if very { 0.4 } else { 0.25 },
                        detail: format!("Chrome {major}, {lag} majors behind stable {baseline}"),
                    });
                }
            }
        }

        if let Some(asn) = facts.asn {
            if let Some(entry) = self.catalog.operator_asn_agent(asn) {
                // A non-browser client from an operator network is at least as
                // suspect as one from a plain hosting network.
                out.push(GateSignal {
                    id: "agent_operator_network",
                    weight: if browser_like { 0.6 } else { 0.25 },
                    detail: format!(
                        "request from AS{asn}, the network {} runs {} on",
                        entry.operator, entry.name
                    ),
                });
                if browser_like {
                    *agent = Some(self.attribution(&entry.id, Assurance::Suspected));
                }
            } else if let Some(provider) = self.catalog.hosting_asn(asn) {
                out.push(GateSignal {
                    id: "hosting_network",
                    weight: if browser_like { 0.35 } else { 0.25 },
                    detail: format!("origin AS{asn} is a hosting or proxy network: {provider}"),
                });
            } else if let Some(provider) = self.catalog.cdn_egress_asn(asn) {
                // Private Relay exits from the same CDNs but only for Safari,
                // so the Linux Chrome test already excludes it. WARP users on
                // Linux Chrome are the known false positive: challenge, never
                // block, on this signal alone.
                if catalog::is_desktop_linux_chrome(user_agent) {
                    out.push(GateSignal {
                        id: "cdn_egress_browser",
                        weight: 0.5,
                        detail: format!(
                            "Chrome on Linux from AS{asn} ({provider}), a CDN egress that cloud \
                             browser agents exit from"
                        ),
                    });
                }
            }
        }

        if let Some(ja4) = facts.ja4.as_deref() {
            if let Some(library) = self.catalog.library_for_ja4(ja4) {
                if browser_like {
                    out.push(GateSignal {
                        id: "tls_user_agent_mismatch",
                        weight: 0.5,
                        detail: format!(
                            "claims a browser but its TLS fingerprint matches {library}"
                        ),
                    });
                } else {
                    out.push(GateSignal {
                        id: "tls_client_library",
                        weight: 0.3,
                        detail: format!("TLS fingerprint matches {library}"),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_policy_follows_agent_then_kind_then_default() {
        let mut config = GateConfig::default();
        config
            .kind_actions
            .insert("crawler".into(), GateAction::Challenge);
        config
            .kind_actions
            .insert("other".into(), GateAction::Challenge);
        config
            .agent_actions
            .insert("openai_crawlers".into(), GateAction::Allow);
        let s = agentsniff_signatures::SignatureData::load_embedded();
        let engine = GateEngine::from_signatures(config, &s).unwrap();
        assert_eq!(engine.agent_policy("openai_crawlers"), GateAction::Allow);
        assert_eq!(
            engine.agent_policy("anthropic_crawlers"),
            GateAction::Challenge
        );
        assert_eq!(
            engine.agent_policy("openai_chatgpt_user"),
            GateAction::Block
        );
        assert_eq!(
            engine.agent_policy(UNIDENTIFIED_SIGNED_AGENT),
            GateAction::Challenge
        );
        assert_eq!(
            origin_of("https://ChatGPT.com/x"),
            Some("https://chatgpt.com".into())
        );
    }
}
