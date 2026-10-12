//! Fail-closed AgentPin credential verification.
//!
//! Discovery documents are public metadata, not proof that the scanned
//! service controls a private key. This module verifies a *presented*
//! AgentPin credential against an explicit, out-of-band trust bundle and a
//! persistent TOFU pin store. It deliberately performs no network fetches:
//! callers choose the trust material, and untrusted JWT claims cannot trigger
//! SSRF or unbounded downloads.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use agentpin::credential::validate_credential_against_discovery;
use agentpin::delegation::{verify_attestation, verify_chain_depth};
use agentpin::discovery::{find_agent_by_id, find_key_by_kid, validate_discovery_document};
use agentpin::jwk::{jwk_to_verifying_key, Jwk};
use agentpin::jwt::decode_jwt_unverified;
use agentpin::pinning::{check_pinning, KeyPinStore, PinningResult};
use agentpin::types::bundle::TrustBundle;
use agentpin::types::capability::Capability;
use agentpin::types::constraint::Constraints;
use agentpin::types::credential::{DelegationRole, JwtPayload};
use agentpin::types::discovery::{AgentStatus, DiscoveryDocument, EntityType};
use agentpin::types::revocation::RevocationDocument;
use agentpin::verification::{verify_credential_offline, KeyPinningStatus, VerifierConfig};
use chrono::{DateTime, Utc};
use serde::Serialize;

const AGENTPIN_VERSION: &str = "0.1";
const MAX_CREDENTIAL_TTL_SECS: i64 = 86_400;
const DEFAULT_AGENT_TTL_SECS: u64 = 86_400;
pub const MAX_AGENTPIN_CREDENTIAL_BYTES: usize = 64 * 1024;
pub const MAX_AGENTPIN_STATE_BYTES: usize = 4 * 1024 * 1024;

/// Read a security-sensitive input without allowing unbounded allocation.
pub fn read_bounded<R: Read>(reader: R, limit: usize, label: &str) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| anyhow::anyhow!("failed to read {label}: {error}"))?;
    if bytes.len() > limit {
        anyhow::bail!("{label} exceeds the {limit}-byte limit");
    }
    Ok(bytes)
}

pub fn read_bounded_path(path: &Path, limit: usize, label: &str) -> anyhow::Result<Vec<u8>> {
    let file = fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("failed to open {}: {error}", path.display()))?;
    read_bounded(file, limit, label)
}

pub fn expand_user_path(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

pub fn load_agentpin_trust_bundle(path: &Path) -> anyhow::Result<TrustBundle> {
    let bytes = read_bounded_path(path, MAX_AGENTPIN_STATE_BYTES, "AgentPin trust bundle")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid AgentPin trust bundle: {error}"))
}

pub fn load_agentpin_pins(path: &Path) -> anyhow::Result<KeyPinStore> {
    if !path.exists() {
        return Ok(KeyPinStore::new());
    }
    let bytes = read_bounded_path(path, MAX_AGENTPIN_STATE_BYTES, "AgentPin pin store")?;
    let json = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("AgentPin pin store must be UTF-8"))?;
    KeyPinStore::from_json(json)
        .map_err(|error| anyhow::anyhow!("invalid AgentPin pin store: {error}"))
}

/// Atomically persist TOFU pins with owner-only permissions on Unix.
pub fn save_agentpin_pins(path: &Path, pins: &KeyPinStore) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid AgentPin pin-store path"))?;
    let temp_path = parent.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let write_result = (|| -> anyhow::Result<()> {
        let mut file = options.open(&temp_path)?;
        file.write_all(pins.to_json()?.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        #[cfg(windows)]
        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(&temp_path, path)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result
}

/// Policy controls for strict AgentPin verification.
#[derive(Debug, Clone)]
pub struct AgentpinVerificationPolicy {
    /// Clock skew allowed for credential and key timestamps.
    pub clock_skew_secs: i64,
    /// Absolute credential lifetime cap, regardless of the agent declaration.
    pub max_ttl_secs: i64,
}

impl Default for AgentpinVerificationPolicy {
    fn default() -> Self {
        Self {
            clock_skew_secs: 60,
            max_ttl_secs: MAX_CREDENTIAL_TTL_SECS,
        }
    }
}

/// A delegation entry that was cryptographically checked.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedDelegation {
    pub domain: String,
    pub role: String,
    pub agent_id: String,
    pub kid: String,
    pub verified: bool,
}

/// Machine-readable AgentPin verification result.
#[derive(Debug, Clone, Serialize)]
pub struct AgentpinVerificationReport {
    pub valid: bool,
    pub identity_assurance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Constraints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery_constraints: Option<Constraints>,
    pub signature_verified: bool,
    pub revocation_checked: bool,
    pub delegation_verified: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegation_chain: Vec<VerifiedDelegation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pinning: Option<KeyPinningStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl AgentpinVerificationReport {
    fn failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            valid: false,
            identity_assurance: "invalid".to_string(),
            agent_id: None,
            issuer: None,
            kid: None,
            jti: None,
            capabilities: Vec::new(),
            constraints: None,
            discovery_constraints: None,
            signature_verified: false,
            revocation_checked: false,
            delegation_verified: false,
            delegation_chain: Vec::new(),
            key_pinning: None,
            error_code: Some(code.into()),
            error_message: Some(message.into()),
            warnings: Vec::new(),
        }
    }
}

type CheckResult<T> = Result<T, (String, String)>;

fn failure(code: &str, message: impl Into<String>) -> (String, String) {
    (code.to_string(), message.into())
}

fn parse_timestamp(value: &str, field: &str) -> CheckResult<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| failure("DISCOVERY_INVALID", format!("{field} is not RFC 3339")))
}

fn validate_domain(domain: &str) -> CheckResult<()> {
    if domain.is_empty()
        || domain.len() > 253
        || domain != domain.to_ascii_lowercase()
        || domain.parse::<std::net::IpAddr>().is_ok()
        || domain.contains(['/', ':', '@'])
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(failure(
            "DOMAIN_MISMATCH",
            format!("'{domain}' is not a canonical DNS domain"),
        ));
    }
    Ok(())
}

fn validate_key_material(key: &Jwk) -> CheckResult<()> {
    if key.use_ != "sig"
        || key
            .key_ops
            .as_ref()
            .is_some_and(|operations| !operations.iter().any(|operation| operation == "verify"))
    {
        return Err(failure(
            "DISCOVERY_INVALID",
            format!(
                "key '{}' is not authorized for signature verification",
                key.kid
            ),
        ));
    }
    if key.kid.trim().is_empty() || key.kid.len() > 128 {
        return Err(failure(
            "DISCOVERY_INVALID",
            "discovery key identifiers must contain 1-128 bytes",
        ));
    }
    jwk_to_verifying_key(key).map_err(|error| {
        failure(
            "DISCOVERY_INVALID",
            format!("key '{}' is invalid: {error}", key.kid),
        )
    })?;
    if let Some(expiration) = &key.exp {
        parse_timestamp(expiration, "public_keys[].exp")?;
    }
    Ok(())
}

fn validate_key_for_use(key: &Jwk, now: DateTime<Utc>, skew_secs: i64) -> CheckResult<()> {
    validate_key_material(key)?;
    if let Some(expiration) = &key.exp {
        let expiration = parse_timestamp(expiration, "public_keys[].exp")?;
        if expiration.timestamp() <= now.timestamp() - skew_secs {
            return Err(failure(
                "KEY_EXPIRED",
                format!("key '{}' has expired", key.kid),
            ));
        }
    }
    Ok(())
}

fn validate_endpoint(document: &DiscoveryDocument) -> CheckResult<()> {
    let Some(endpoint) = document.revocation_endpoint.as_deref() else {
        // The AgentPin default well-known revocation URL applies when omitted.
        return Ok(());
    };
    let url = reqwest::Url::parse(endpoint).map_err(|_| {
        failure(
            "DISCOVERY_INVALID",
            "revocation_endpoint is not a valid URL",
        )
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(failure(
            "DISCOVERY_INVALID",
            "revocation_endpoint must be an HTTPS URL without user information",
        ));
    }
    Ok(())
}

fn validate_a2a_endpoint(document: &DiscoveryDocument) -> CheckResult<()> {
    let Some(endpoint) = document.a2a_endpoint.as_deref() else {
        return Ok(());
    };
    let url = reqwest::Url::parse(endpoint)
        .map_err(|_| failure("DISCOVERY_INVALID", "a2a_endpoint is not a valid URL"))?;
    let expected_host = document.entity.trim_end_matches('.');
    let actual_host = url.host_str().map(|host| host.trim_end_matches('.'));
    if url.scheme() != "https"
        || actual_host != Some(expected_host)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(failure(
            "DISCOVERY_INVALID",
            "a2a_endpoint must use HTTPS on the discovery entity domain",
        ));
    }
    Ok(())
}

fn validate_agent_id(agent_id: &str, domain: &str) -> bool {
    agent_id
        .strip_prefix(&format!("urn:agentpin:{domain}:"))
        .is_some_and(|name| !name.is_empty() && !name.chars().any(char::is_whitespace))
}

fn validate_capability_claim(capability: &Capability) -> Result<(), String> {
    let Some((action, resource)) = capability.0.split_once(':') else {
        return Err("capability must be in 'action:resource' format".to_string());
    };
    if action.is_empty() || resource.is_empty() {
        return Err("capability action and resource must be non-empty".to_string());
    }
    if action == "admin" && resource == "*" {
        return Err(
            "admin:* wildcard is not allowed; admin capabilities must be explicitly scoped"
                .to_string(),
        );
    }

    const CORE_ACTIONS: &[&str] = &["read", "write", "delete", "execute", "admin", "delegate"];
    if !CORE_ACTIONS.contains(&action) {
        let labels: Vec<_> = action.split('.').collect();
        if labels.len() < 2
            || labels.iter().any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(format!(
                "custom action '{action}' must use a lowercase reverse-domain prefix"
            ));
        }
    }
    if !resource.bytes().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'*' | b'-' | b'_' | b'/')
    }) {
        return Err("capability resource contains unsupported characters".to_string());
    }
    Ok(())
}

fn validate_document(
    document: &DiscoveryDocument,
    expected_entity: &str,
    now: DateTime<Utc>,
    skew_secs: i64,
) -> CheckResult<()> {
    validate_domain(expected_entity)?;
    validate_discovery_document(document, expected_entity).map_err(|error| {
        failure(
            "DISCOVERY_INVALID",
            format!("discovery validation failed: {error}"),
        )
    })?;
    validate_endpoint(document)?;
    validate_a2a_endpoint(document)?;

    let updated_at = parse_timestamp(&document.updated_at, "updated_at")?;
    if updated_at.timestamp() > now.timestamp() + skew_secs {
        return Err(failure(
            "DISCOVERY_INVALID",
            "discovery updated_at is in the future",
        ));
    }

    let mut kids = HashSet::new();
    for key in &document.public_keys {
        if key.kid.trim().is_empty() || !kids.insert(key.kid.as_str()) {
            return Err(failure(
                "DISCOVERY_INVALID",
                "discovery key identifiers must be non-empty and unique",
            ));
        }
        validate_key_material(key)?;
    }

    let mut agent_ids = HashSet::new();
    for agent in &document.agents {
        if !agent_ids.insert(agent.agent_id.as_str())
            || !validate_agent_id(&agent.agent_id, expected_entity)
            || agent.name.trim().is_empty()
            || agent.name.chars().count() > 128
            || agent
                .description
                .as_ref()
                .is_some_and(|description| description.chars().count() > 1024)
        {
            return Err(failure(
                "DISCOVERY_INVALID",
                "agent declarations must have unique domain-bound IDs and valid names",
            ));
        }
        let deployer_fields = (
            agent
                .agent_type
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            agent
                .maker_attestation
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
        );
        let fields_match_entity = match document.entity_type {
            EntityType::Maker => deployer_fields == (false, false),
            EntityType::Deployer => deployer_fields == (true, true),
            EntityType::Both => deployer_fields.0 == deployer_fields.1,
        };
        if !fields_match_entity {
            return Err(failure(
                "DISCOVERY_INVALID",
                format!(
                    "agent '{}' has invalid maker/deployer declaration fields",
                    agent.agent_id
                ),
            ));
        }
        if let Some(ttl) = agent.credential_ttl_max {
            if !(60..=DEFAULT_AGENT_TTL_SECS).contains(&ttl) {
                return Err(failure(
                    "DISCOVERY_INVALID",
                    format!(
                        "agent '{}' has an invalid credential_ttl_max",
                        agent.agent_id
                    ),
                ));
            }
        }
        for capability in &agent.capabilities {
            validate_capability_claim(capability).map_err(|message| {
                failure(
                    "DISCOVERY_INVALID",
                    format!(
                        "agent '{}' capability is invalid: {message}",
                        agent.agent_id
                    ),
                )
            })?;
        }
    }
    Ok(())
}

fn validate_revocation_document(
    document: &RevocationDocument,
    expected_entity: &str,
    now: DateTime<Utc>,
    skew_secs: i64,
) -> CheckResult<()> {
    if document.agentpin_version != AGENTPIN_VERSION || document.entity != expected_entity {
        return Err(failure(
            "DISCOVERY_INVALID",
            "revocation document version or entity does not match discovery",
        ));
    }
    let updated_at = parse_timestamp(&document.updated_at, "revocation.updated_at")?;
    if updated_at.timestamp() > now.timestamp() + skew_secs {
        return Err(failure(
            "DISCOVERY_INVALID",
            "revocation updated_at is in the future",
        ));
    }
    Ok(())
}

fn find_bundle_documents<'a>(
    bundle: &'a TrustBundle,
    domain: &str,
) -> CheckResult<(&'a DiscoveryDocument, &'a RevocationDocument)> {
    let discovery_matches: Vec<_> = bundle
        .documents
        .iter()
        .filter(|document| document.entity == domain)
        .collect();
    let revocation_matches: Vec<_> = bundle
        .revocations
        .iter()
        .filter(|document| document.entity == domain)
        .collect();
    if discovery_matches.len() != 1 {
        return Err(failure(
            "DISCOVERY_FETCH_FAILED",
            format!("trust bundle must contain exactly one discovery document for '{domain}'"),
        ));
    }
    if revocation_matches.len() != 1 {
        return Err(failure(
            "DISCOVERY_FETCH_FAILED",
            format!("trust bundle must contain exactly one revocation document for '{domain}'"),
        ));
    }
    Ok((discovery_matches[0], revocation_matches[0]))
}

fn validate_payload(payload: &JwtPayload, document: &DiscoveryDocument) -> CheckResult<()> {
    if payload.agentpin_version != AGENTPIN_VERSION {
        return Err(failure(
            "ALGORITHM_REJECTED",
            format!(
                "unsupported credential AgentPin version '{}'",
                payload.agentpin_version
            ),
        ));
    }
    if payload.jti.trim().is_empty() || payload.jti.len() > 256 {
        return Err(failure(
            "DISCOVERY_INVALID",
            "credential jti must be non-empty and at most 256 bytes",
        ));
    }
    if !validate_agent_id(&payload.sub, &payload.iss) {
        return Err(failure(
            "DOMAIN_MISMATCH",
            "credential subject is not bound to its issuer domain",
        ));
    }
    for capability in &payload.capabilities {
        validate_capability_claim(capability).map_err(|message| {
            failure(
                "CAPABILITY_EXCEEDED",
                format!("credential capability is invalid: {message}"),
            )
        })?;
    }

    let agent = find_agent_by_id(document, &payload.sub).ok_or_else(|| {
        failure(
            "AGENT_NOT_FOUND",
            format!("agent '{}' is absent from discovery", payload.sub),
        )
    })?;
    let lifetime = payload.exp.checked_sub(payload.iat).ok_or_else(|| {
        failure(
            "CREDENTIAL_EXPIRED",
            "credential lifetime cannot be represented safely",
        )
    })?;
    let declared_ttl = agent.credential_ttl_max.unwrap_or(DEFAULT_AGENT_TTL_SECS) as i64;
    if lifetime <= 0 || lifetime > declared_ttl {
        return Err(failure(
            "CREDENTIAL_EXPIRED",
            format!("credential lifetime {lifetime}s exceeds agent maximum {declared_ttl}s"),
        ));
    }
    Ok(())
}

fn verify_delegations(
    payload: &JwtPayload,
    issuer_document: &DiscoveryDocument,
    bundle: &TrustBundle,
    pins: &mut KeyPinStore,
    policy: &AgentpinVerificationPolicy,
    now: DateTime<Utc>,
) -> CheckResult<Vec<VerifiedDelegation>> {
    let Some(chain) = payload.delegation_chain.as_ref() else {
        return Ok(Vec::new());
    };
    if chain.is_empty() {
        return Ok(Vec::new());
    }
    if chain.len() > 3 {
        return Err(failure(
            "DELEGATION_DEPTH_EXCEEDED",
            "delegation chain exceeds the protocol maximum depth of 3",
        ));
    }

    let issuer_agent = find_agent_by_id(issuer_document, &payload.sub).ok_or_else(|| {
        failure(
            "AGENT_NOT_FOUND",
            format!("agent '{}' is absent from discovery", payload.sub),
        )
    })?;
    if issuer_agent
        .agent_type
        .as_deref()
        .is_some_and(|agent_type| agent_type != chain[0].agent_id.as_str())
    {
        return Err(failure(
            "DELEGATION_INVALID",
            "issuer agent_type does not match the maker at the root of the delegation chain",
        ));
    }

    let mut max_depths = vec![issuer_document.max_delegation_depth];
    let mut seen = HashSet::new();
    let mut verified = Vec::with_capacity(chain.len());

    for (index, attestation) in chain.iter().enumerate() {
        if !seen.insert((attestation.domain.as_str(), attestation.agent_id.as_str())) {
            return Err(failure(
                "DELEGATION_INVALID",
                "delegation chain contains a cycle or duplicate entry",
            ));
        }

        let (document, revocation) = find_bundle_documents(bundle, &attestation.domain)?;
        validate_document(document, &attestation.domain, now, policy.clock_skew_secs)?;
        validate_revocation_document(revocation, &attestation.domain, now, policy.clock_skew_secs)?;

        let order_matches = matches!(
            (index, attestation.role),
            (0, DelegationRole::Maker) | (1.., DelegationRole::Deployer)
        );
        if !order_matches {
            return Err(failure(
                "DELEGATION_INVALID",
                "delegation chain must be ordered from one maker to zero or more deployers",
            ));
        }

        let role_matches = matches!(
            (attestation.role, document.entity_type),
            (DelegationRole::Maker, EntityType::Maker | EntityType::Both)
                | (
                    DelegationRole::Deployer,
                    EntityType::Deployer | EntityType::Both
                )
        );
        if !role_matches {
            return Err(failure(
                "DELEGATION_INVALID",
                format!(
                    "delegation role does not match entity '{}'",
                    attestation.domain
                ),
            ));
        }

        let agent = find_agent_by_id(document, &attestation.agent_id).ok_or_else(|| {
            failure(
                "DELEGATION_INVALID",
                format!(
                    "delegating agent '{}' is not declared",
                    attestation.agent_id
                ),
            )
        })?;
        let declaration_is_deployer =
            agent.agent_type.is_some() && agent.maker_attestation.is_some();
        if matches!(attestation.role, DelegationRole::Maker) == declaration_is_deployer {
            return Err(failure(
                "DELEGATION_INVALID",
                format!(
                    "delegation role does not match agent declaration '{}'",
                    attestation.agent_id
                ),
            ));
        }
        if matches!(attestation.role, DelegationRole::Deployer)
            && agent.agent_type.as_deref() != Some(chain[0].agent_id.as_str())
        {
            return Err(failure(
                "DELEGATION_INVALID",
                format!(
                    "delegating agent '{}' does not reference the chain's maker agent type",
                    attestation.agent_id
                ),
            ));
        }
        if agent.status != AgentStatus::Active {
            return Err(failure(
                "AGENT_INACTIVE",
                format!("delegating agent '{}' is not active", attestation.agent_id),
            ));
        }
        validate_credential_against_discovery(&payload.capabilities, &agent.capabilities)
            .map_err(|error| failure("CAPABILITY_EXCEEDED", error.to_string()))?;

        if revocation
            .revoked_agents
            .iter()
            .any(|entry| entry.agent_id == attestation.agent_id)
        {
            return Err(failure(
                "AGENT_INACTIVE",
                format!("delegating agent '{}' is revoked", attestation.agent_id),
            ));
        }
        if revocation
            .revoked_keys
            .iter()
            .any(|entry| entry.kid == attestation.kid)
        {
            return Err(failure(
                "KEY_REVOKED",
                format!("delegation key '{}' is revoked", attestation.kid),
            ));
        }

        let key = find_key_by_kid(document, &attestation.kid).ok_or_else(|| {
            failure(
                "KEY_NOT_FOUND",
                format!("delegation key '{}' is not declared", attestation.kid),
            )
        })?;
        validate_key_for_use(key, now, policy.clock_skew_secs)?;
        let verifying_key = jwk_to_verifying_key(key).map_err(|error| {
            failure(
                "KEY_NOT_FOUND",
                format!("delegation key '{}' is invalid: {error}", attestation.kid),
            )
        })?;

        let (delegatee_domain, delegatee_agent_id) = chain
            .get(index + 1)
            .map(|next| (next.domain.as_str(), next.agent_id.as_str()))
            .unwrap_or((payload.iss.as_str(), payload.sub.as_str()));
        verify_attestation(
            attestation,
            &verifying_key,
            delegatee_domain,
            delegatee_agent_id,
            &payload.capabilities,
        )
        .map_err(|error| failure("DELEGATION_INVALID", error.to_string()))?;
        let first_use = pins.get_domain(&attestation.domain).is_none();
        let pinning = check_pinning(pins, &attestation.domain, key)
            .map_err(|error| failure("KEY_PIN_MISMATCH", error.to_string()))?;
        if first_use && pinning == PinningResult::FirstUse {
            pin_active_rotation_keys(pins, document, now, policy.clock_skew_secs)?;
        }

        max_depths.push(document.max_delegation_depth);
        verified.push(VerifiedDelegation {
            domain: attestation.domain.clone(),
            role: match attestation.role {
                DelegationRole::Maker => "maker",
                DelegationRole::Deployer => "deployer",
            }
            .to_string(),
            agent_id: attestation.agent_id.clone(),
            kid: attestation.kid.clone(),
            verified: true,
        });
    }

    verify_chain_depth(chain.len(), &max_depths)
        .map_err(|error| failure("DELEGATION_DEPTH_EXCEEDED", error.to_string()))?;
    Ok(verified)
}

fn pin_active_rotation_keys(
    pins: &mut KeyPinStore,
    document: &DiscoveryDocument,
    now: DateTime<Utc>,
    skew_secs: i64,
) -> CheckResult<()> {
    for key in &document.public_keys {
        if let Some(expiration) = &key.exp {
            let expiration = parse_timestamp(expiration, "public_keys[].exp")?;
            if expiration.timestamp() <= now.timestamp() - skew_secs {
                continue;
            }
        }
        pins.add_key(&document.entity, key);
    }
    Ok(())
}

/// Verify a presented AgentPin credential against a pre-shared trust bundle.
///
/// The pin store is updated only after *all* checks succeed. A malformed or
/// invalid credential therefore cannot poison future TOFU decisions.
pub fn verify_credential_from_bundle(
    credential_jwt: &str,
    bundle: &TrustBundle,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    policy: &AgentpinVerificationPolicy,
) -> AgentpinVerificationReport {
    if !(0..=60).contains(&policy.clock_skew_secs)
        || !(1..=MAX_CREDENTIAL_TTL_SECS).contains(&policy.max_ttl_secs)
    {
        return AgentpinVerificationReport::failure(
            "POLICY_INVALID",
            "AgentPin policy requires 0-60 seconds of clock skew and a 1-86400 second TTL cap",
        );
    }
    if bundle.agentpin_bundle_version != AGENTPIN_VERSION {
        return AgentpinVerificationReport::failure(
            "DISCOVERY_INVALID",
            "unsupported trust bundle version",
        );
    }
    let now = Utc::now();
    let bundle_created_at = match parse_timestamp(&bundle.created_at, "bundle.created_at") {
        Ok(created_at) => created_at,
        Err((code, message)) => return AgentpinVerificationReport::failure(code, message),
    };
    if bundle_created_at.timestamp() > now.timestamp() + policy.clock_skew_secs {
        return AgentpinVerificationReport::failure(
            "DISCOVERY_INVALID",
            "trust bundle created_at is in the future",
        );
    }

    let (header, payload, _) = match decode_jwt_unverified(credential_jwt.trim()) {
        Ok(parts) => parts,
        Err(error) => {
            return AgentpinVerificationReport::failure(
                "ALGORITHM_REJECTED",
                format!("credential parse failed: {error}"),
            )
        }
    };
    let (discovery, revocation) = match find_bundle_documents(bundle, &payload.iss) {
        Ok(documents) => documents,
        Err((code, message)) => return AgentpinVerificationReport::failure(code, message),
    };
    for check in [
        validate_document(discovery, &payload.iss, now, policy.clock_skew_secs),
        validate_revocation_document(revocation, &payload.iss, now, policy.clock_skew_secs),
        validate_payload(&payload, discovery),
    ] {
        if let Err((code, message)) = check {
            return AgentpinVerificationReport::failure(code, message);
        }
    }

    let signing_key = match find_key_by_kid(discovery, &header.kid) {
        Some(key) => key,
        None => {
            return AgentpinVerificationReport::failure(
                "KEY_NOT_FOUND",
                format!("key '{}' is absent from discovery", header.kid),
            )
        }
    };
    if let Err((code, message)) = validate_key_for_use(signing_key, now, policy.clock_skew_secs) {
        return AgentpinVerificationReport::failure(code, message);
    }

    let mut working_pins = pin_store.clone();
    let issuer_first_use = working_pins.get_domain(&payload.iss).is_none();
    let config = VerifierConfig {
        clock_skew_secs: policy.clock_skew_secs,
        max_ttl_secs: policy.max_ttl_secs.min(MAX_CREDENTIAL_TTL_SECS),
        strict_capabilities: true,
    };
    let base = verify_credential_offline(
        credential_jwt.trim(),
        discovery,
        Some(revocation),
        &mut working_pins,
        audience,
        &config,
    );
    if !base.valid {
        return AgentpinVerificationReport::failure(
            base.error_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "SIGNATURE_INVALID".to_string()),
            base.error_message
                .unwrap_or_else(|| "AgentPin credential verification failed".to_string()),
        );
    }

    if issuer_first_use {
        if let Err((code, message)) =
            pin_active_rotation_keys(&mut working_pins, discovery, now, policy.clock_skew_secs)
        {
            return AgentpinVerificationReport::failure(code, message);
        }
    }

    let delegation_chain =
        match verify_delegations(&payload, discovery, bundle, &mut working_pins, policy, now) {
            Ok(chain) => chain,
            Err((code, message)) => return AgentpinVerificationReport::failure(code, message),
        };

    let warnings = base
        .warnings
        .into_iter()
        .filter(|warning| warning != "Delegation chain present but not verified in offline mode")
        .collect();
    let discovery_constraints =
        find_agent_by_id(discovery, &payload.sub).and_then(|agent| agent.constraints.clone());
    *pin_store = working_pins;
    AgentpinVerificationReport {
        valid: true,
        identity_assurance: "trusted_verified".to_string(),
        agent_id: Some(payload.sub),
        issuer: Some(payload.iss),
        kid: Some(header.kid),
        jti: Some(payload.jti),
        capabilities: payload
            .capabilities
            .into_iter()
            .map(|capability| capability.0)
            .collect(),
        constraints: payload.constraints,
        discovery_constraints,
        signature_verified: true,
        revocation_checked: true,
        delegation_verified: true,
        delegation_chain,
        key_pinning: base.key_pinning,
        error_code: None,
        error_message: None,
        warnings,
    }
}
